/*
 * card-pgp.c: Support for OpenPGP card
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *pgp_atrs[] = {
	"3b:fa:13:00:ff:81:31:80:45:00:31:c1:73:c0:01:00:00:90:00:b1",
	NULL
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations pgp_ops;
static struct sc_card_driver pgp_drv = {
	"OpenPGP Card",
	"openpgp",
	&pgp_ops
};

static int	pgp_get_pubkey(sc_card_t *, unsigned int, u8 *, size_t);

/*
 * The OpenPGP card doesn't have a file system, instead everything
 * is stored in data objects that are accessed through GET/PUT.
 *
 * However, much inside OpenSC's pkcs15 implementation is based on
 * the assumption that we have a file system. So we fake one here.
 *
 * Selecting the MF causes us to select the OpenPGP AID.
 *
 * Everything else is mapped to "file" IDs.
 */
struct blob {
	struct blob *	next;
	struct blob *	parent;
	sc_file_t *	file;
	unsigned int	id;
	unsigned char *	data;
	unsigned int	len;
	struct blob *	files;
};

static struct do_info {
	unsigned int	id;
	unsigned int	constructed : 1;
	int		(*get_fn)(sc_card_t *, unsigned int, u8 *, size_t);
	int		(*put_fn)(sc_card_t *, unsigned int, const u8 *, size_t);
} pgp_objects[] = {
      {	0x004f,		0,	sc_get_data,	sc_put_data	},
      {	0x005e,		1,	sc_get_data,	sc_put_data	},
      {	0x0065,		1,	sc_get_data,	sc_put_data	},
      {	0x006e,		1,	sc_get_data,	sc_put_data	},
      {	0x0073,		1,	sc_get_data,	sc_put_data	},
      {	0x007a,		1,	sc_get_data,	sc_put_data	},
      {	0x5f50,		0,	sc_get_data,	sc_put_data	},
      { 0xb600,		0,	pgp_get_pubkey,	NULL		},
      { 0xb800,		0,	pgp_get_pubkey,	NULL		},
      { 0xa400,		0,	pgp_get_pubkey,	NULL		},

      { 0 },
};

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))
struct pgp_priv_data {
	struct blob	mf;
	struct blob *	current;
};

static int
pgp_match_card(sc_card_t *card)
{
	int i, match = -1;

	for (i = 0; pgp_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = pgp_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int
pgp_init(sc_card_t *card)
{
        struct pgp_priv_data *priv;
        unsigned long	flags;
	sc_path_t	aid;
	sc_file_t	*file = NULL;
	int		r;

	priv = (struct pgp_priv_data *) calloc (1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->name = "OpenPGP";
	card->drv_data = priv;
	card->cla = 0x00;

	/* Is this correct? */
        flags = SC_ALGORITHM_RSA_RAW;
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
        flags |= SC_ALGORITHM_RSA_HASH_NONE;

	/* Is this correct? */
        _sc_card_add_rsa_alg(card, 512, flags, 0);
        _sc_card_add_rsa_alg(card, 768, flags, 0);
        _sc_card_add_rsa_alg(card, 1024, flags, 0);

	sc_format_path("D276:0001:2401", &aid);
	aid.type = SC_PATH_TYPE_DF_NAME;

	if ((r = iso_ops->select_file(card, &aid, &file)) < 0)
		return r;

	sc_format_path("3f00", &file->path);
	file->type = SC_FILE_TYPE_DF;
	file->id = 0x3f00;

	priv->mf.file = file;
	priv->mf.id = 0x3F00;

	priv->current = &priv->mf;
	return 0;
}

static int
pgp_finish(sc_card_t *card)
{
        struct pgp_priv_data *priv;

        if (card == NULL)
                return 0;
	priv = DRVDATA (card);

	/* XXX delete fake file hierarchy */

	free(priv);
	return 0;
}

static struct blob *
pgp_new_blob(struct blob *parent, unsigned int file_id,
		int file_type, const u8 *data, size_t len)
{
	sc_file_t	*file = sc_file_new();
	struct blob	*blob, **p;

	blob = (struct blob *) calloc(1, sizeof(*blob));
	blob->parent = parent;
	blob->id     = file_id;
	blob->file   = file;
	blob->len    = len;
	blob->data   = malloc(len);
	memcpy(blob->data, data, len);

	file->type   = file_type;
	file->path   = parent->file->path;
	file->size   = len;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	sc_append_file_id(&file->path, file_id);

	for (p = &parent->files; *p; p = &(*p)->next)
		;
	*p = blob;

	return blob;
}

/*
 * Enumerate contents of a data blob.
 * The OpenPGP card has a funny TLV encoding.
 */
static int
pgp_enumerate_blob(sc_card_t *card, struct blob *blob)
{
	const u8	*in, *end;

	in = blob->data;
	end = blob->data + blob->len;
	while (in < end) {
		unsigned int	tag, len, type = SC_FILE_TYPE_WORKING_EF;
		unsigned char	c;

		c = *in++;
		if (c == 0x00 || c == 0xFF)
			continue;

		tag = c;
		if (tag & 0x20)
			type = SC_FILE_TYPE_DF;
		while ((c & 0x1f) == 0x1f) {
			if (in >= end)
				goto eoc;
			c = *in++;
			tag = (tag << 8) | c;
		}

		if (in >= end)
			goto eoc;
		c = *in++;
		if (c < 0x80) {
			len = c;
		} else {
			len = 0;
			c &= 0x7F;
			while (c--) {
				if (in >= end)
					goto eoc;
				len = (len << 8) | *in++;
			}
		}

		/* Don't search past end of content */
		if (in + len > end)
			goto eoc;

		pgp_new_blob(blob, tag, type, in, len);
		in += len;
	}

	return 0;

eoc:	sc_error(card->ctx, "Unexpected end of contents\n");
	return SC_ERROR_OBJECT_NOT_VALID;
}

static int
pgp_get_blob(sc_card_t *card, struct blob *blob, unsigned int id,
		struct blob **ret)
{
        struct pgp_priv_data	*priv = DRVDATA(card);
	struct blob		*child;
	int			r;

again:
	for (child = blob->files; child; child = child->next) {
		if (child->id == id) {
			*ret = child;
			return 0;
		}
	}

	/* Blob not found. Are we a child of the MF, i.e. do
	 * we represent a proper data object? If so, try to
	 * read the object. If not, try to enumerate the
	 * contents of blob.
	 */
	if (blob->parent == NULL) {
		/* Try to read contents of data object */
		unsigned char	buffer[256];
		struct do_info	*doi;
		int		type = SC_FILE_TYPE_DF;

		r = SC_ERROR_FILE_NOT_FOUND;
		for (doi = pgp_objects; doi->id > 0; doi++) {
			if (doi->id != id)
				continue;

			if (!doi->constructed)
				type = SC_FILE_TYPE_WORKING_EF;

			/* If we fail to read an object, we treat it as
			 * if it's there anyway, just empty */
			card->ctx->suppress_errors++;
			r = doi->get_fn(card, id, buffer, sizeof(buffer));
			card->ctx->suppress_errors--;
			if (r < 0)
				r = 0;
			break;
		}
		if (r < 0)
			return r;

		*ret = pgp_new_blob(&priv->mf, id, type, buffer, r);
		return 0;
	}

	/* If already enumerated, stop now */
	if (blob->files != NULL)
		return SC_ERROR_FILE_NOT_FOUND;

	if ((r = pgp_enumerate_blob(card, blob)) < 0)
		return r;
	goto again;
}

static int
pgp_select_file(sc_card_t *card, const sc_path_t *path, sc_file_t **ret)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;
	sc_path_t	path_copy;
	unsigned int	n;
	int		r;

	if (path->type == SC_PATH_TYPE_DF_NAME)
		return iso_ops->select_file(card, path, ret);
	if (path->type != SC_PATH_TYPE_PATH)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (path->len < 2 || (path->len & 1))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!memcmp(path->value, "\x3f\x00", 2)) {
		memcpy(path_copy.value, path->value + 2, path->len - 2);
		path_copy.len = path->len - 2;
		path = &path_copy;
	}

	blob = &priv->mf;
	for (n = 0; n < path->len; n += 2) {
		r = pgp_get_blob(card, blob,
				(path->value[n] << 8) | path->value[n+1],
				&blob);
		if (r < 0) {
			priv->current = NULL;
			return r;
		}
	}

	priv->current = blob;

	if (ret)
		sc_file_dup(ret, blob->file);
	return 0;
}

static int
pgp_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;
	unsigned int	k;
	int		r;

	if ((blob = priv->current) == &priv->mf) {
		struct do_info *doi;

		for (k = 0, doi = pgp_objects; doi->id > 0; doi++) {
			if (k + 2 > buflen)
				break;
			buf[k++] = doi->id >> 8;
			buf[k++] = doi->id;
		}
		return k;
	}

	if (blob->file->type != SC_FILE_TYPE_DF)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (blob->files == NULL
	 && (r = pgp_enumerate_blob(card, blob)) < 0)
		return r;

	for (k = 0, blob = blob->files; blob; blob = blob->next) {
		if (k + 2 > buflen)
			break;
		buf[k++] = blob->id >> 8;
		buf[k++] = blob->id;
	}

	return k;
}

static int
pgp_read_binary(sc_card_t *card, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	struct pgp_priv_data *priv = DRVDATA(card);
	struct blob	*blob;

	if ((blob = priv->current) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;

	if (blob->file->type != SC_FILE_TYPE_WORKING_EF)
		return SC_ERROR_FILE_NOT_FOUND;

	if (idx > blob->len)
		return SC_ERROR_INCORRECT_PARAMETERS;

	if (idx + count > blob->len)
		count = blob->len - idx;

	memcpy(buf, blob->data + idx, count);
	return count;
}

static int
pgp_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_get_pubkey(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	u8		idbuf[2];
	int		r;

	idbuf[0] = tag >> 8;
	idbuf[1] = tag;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x47, 0x81, 0);
	apdu.lc = 2;
	apdu.data = idbuf;
	apdu.datalen = 2;
	apdu.le = (buf_len > 256)? 256 : 0;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	return apdu.resplen;
}

static int
pgp_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	int		r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
				0xCA, tag >> 8, tag);
	apdu.le = (buf_len <= 255)? buf_len : 256;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	return apdu.resplen;
}

static int
pgp_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t buf_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	if (data->pin_type != SC_AC_CHV)
		return SC_ERROR_INVALID_ARGUMENTS;

	data->pin_reference |= 0x80;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int
pgp_set_security_env(sc_card_t *card,
		const struct sc_security_env *env, int se_num)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_compute_signature(sc_card_t *card, const u8 *data,
                size_t data_len, u8 * out, size_t outlen)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_logout(sc_card_t *card)
{
	sc_error(card->ctx, "OpenPGP card: logout not supported\n");
	return SC_ERROR_NOT_SUPPORTED;
}

/* Driver binding stuff */
static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;

	pgp_ops = *iso_ops;
	pgp_ops.match_card	= pgp_match_card;
	pgp_ops.init		= pgp_init;
	pgp_ops.finish		= pgp_finish;
	pgp_ops.select_file	= pgp_select_file;
	pgp_ops.list_files	= pgp_list_files;
	pgp_ops.read_binary	= pgp_read_binary;
	pgp_ops.write_binary	= pgp_write_binary;
	pgp_ops.pin_cmd		= pgp_pin_cmd;
	pgp_ops.get_data	= pgp_get_data;
	pgp_ops.put_data	= pgp_put_data;
	pgp_ops.set_security_env= pgp_set_security_env;
	pgp_ops.compute_signature= pgp_compute_signature;
	pgp_ops.logout		= pgp_logout;

        return &pgp_drv;
}

struct sc_card_driver *
sc_get_openpgp_driver(void)
{
	return sc_get_driver();
}
