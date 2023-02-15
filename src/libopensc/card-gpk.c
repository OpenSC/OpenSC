/*
 * card-gpk: Driver for GPK 4000 cards
 *
 * Copyright (C) 2002  Olaf Kirch <okir@suse.de>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef ENABLE_OPENSSL	/* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "internal.h"
#include "cardctl.h"
#include "pkcs15.h"

#define GPK_SEL_MF		0x00
#define GPK_SEL_DF		0x01
#define GPK_SEL_EF		0x02
#define GPK_SEL_AID		0x04
#define GPK_FID_MF		0x3F00

#define GPK_FTYPE_SC		0x21

#define GPK_SIGN_RSA_MD5	0x11
#define GPK_SIGN_RSA_SHA	0x12
#define GPK_SIGN_RSA_SSL	0x18
#define GPK_VERIFY_RSA_MD5	0x21
#define GPK_VERIFY_RSA_SHA	0x22
#define GPK_AUTH_RSA_MD5	0x31
#define GPK_AUTH_RSA_SHA	0x32
#define GPK_AUTH_RSA_SSL	0x38
#define GPK_UNWRAP_RSA		0x77

#define GPK_MAX_PINS		8
#define GPK_HASH_CHUNK		62

/*
 * GPK4000 private data
 */
struct gpk_private_data {
	/* The GPK usually do file offsets in multiples of
	 * 4 bytes. This can be customized however. We
	 * should really query for this during gpk_init */
	unsigned int	offset_shift;
	unsigned int	offset_mask;
	unsigned int	locked : 1,
			sample_card : 1;

	/* access control bits of file most recently selected */
	unsigned short int ac[3];

	/* is non-zero if we should use secure messaging */
	unsigned	key_set   : 1;
	unsigned int	key_reference;
	u8		key[16];

	/* crypto related data from set_security_env */
	unsigned int	sec_algorithm;
	unsigned int	sec_hash_len;
	unsigned int	sec_mod_len;
	unsigned int	sec_padding;
};
#define DRVDATA(card)	((struct gpk_private_data *) ((card)->drv_data))

static int	gpk_get_info(sc_card_t *, int, int, u8 *, size_t);

/*
 * ATRs of GPK4000 cards courtesy of libscez
 */
static const struct sc_atr_table gpk_atrs[] = {
	{ "3B:27:00:80:65:A2:04:01:01:37", NULL, "GPK 4K", SC_CARD_TYPE_GPK_GPK4000_s, 0, NULL },
	{ "3B:27:00:80:65:A2:05:01:01:37", NULL, "GPK 4K", SC_CARD_TYPE_GPK_GPK4000_sp, 0, NULL },
	{ "3B:27:00:80:65:A2:0C:01:01:37", NULL, "GPK 4K", SC_CARD_TYPE_GPK_GPK4000_su256, 0, NULL },
	{ "3B:A7:00:40:14:80:65:A2:14:01:01:37", NULL, "GPK 4K", SC_CARD_TYPE_GPK_GPK4000_sdo, 0, NULL },
	{ "3B:A7:00:40:18:80:65:A2:08:01:01:52", NULL, "GPK 8K", SC_CARD_TYPE_GPK_GPK8000_8K, 0, NULL },
	{ "3B:A7:00:40:18:80:65:A2:09:01:01:52", NULL, "GPK 8K", SC_CARD_TYPE_GPK_GPK8000_16K, 0, NULL },
	{ "3B:A7:00:40:18:80:65:A2:09:01:02:52", NULL, "GPK 16K", SC_CARD_TYPE_GPK_GPK16000, 0, NULL },
	{ "3B:A7:00:40:18:80:65:A2:09:01:03:52", NULL, "GPK 16K", SC_CARD_TYPE_GPK_GPK16000, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

/*
 * Driver and card ops structures
 */
static struct sc_card_operations	gpk_ops, *iso_ops;
static struct sc_card_driver gpk_drv = {
	"Gemplus GPK",
	"gpk",
	&gpk_ops,
	NULL, 0, NULL
};

/*
 * return 1 if this driver can handle the card
 */
static int
gpk_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, gpk_atrs, &card->type);
	if (i < 0) {
		const u8 *hist_bytes = card->reader->atr_info.hist_bytes;

		/* Gemplus GPK docs say we can use just the 
		 * FMN and PRN fields of the historical bytes
		 * to recognize a GPK card
		 *  See Table 43, pp. 188
		 * We'll use the first 2 bytes as well
		 */

		if ((card->reader->atr_info.hist_bytes_len >= 7)
			&& (hist_bytes[0] == 0x80)
			&& (hist_bytes[1] == 0x65)
			&& (hist_bytes[2] == 0xa2)) {	/* FMN */
			if (hist_bytes[3] == 0x08) {	/* PRN? */
				card->type = SC_CARD_TYPE_GPK_GPK8000;
				return 1;
			}
			if (hist_bytes[3] == 0x09) {	/* PRN? */
				card->type = SC_CARD_TYPE_GPK_GPK16000;
				return 1;
			}
		}
		return 0;
	}
	return 1;
}

/*
 * Initialize the card struct
 */
static int
gpk_init(sc_card_t *card)
{
	struct gpk_private_data *priv;
	unsigned long	exponent, flags, kg;
	unsigned char info[13];

	card->drv_data = priv = calloc(1, sizeof(*priv));
	if (card->drv_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* read/write/update binary expect offset to be the
	 * number of 32 bit words.
	 * offset_shift is the shift value.
	 * offset_mask is the corresponding mask. */
	priv->offset_shift = 2;
	priv->offset_mask = 3;
	card->cla = 0x00;

	/* Set up algorithm info. GPK 16000 will do any RSA
	 * exponent, earlier ones are restricted to 0x10001 */
	flags = SC_ALGORITHM_RSA_HASH_MD5 | SC_ALGORITHM_RSA_HASH_SHA1
		| SC_ALGORITHM_RSA_HASH_MD5_SHA1;
	flags |= SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ANSI
		| SC_ALGORITHM_RSA_PAD_ISO9796;
	exponent = (card->type < SC_CARD_TYPE_GPK_GPK16000) ? 0x10001 : 0;
	kg = (card->type >= SC_CARD_TYPE_GPK_GPK8000) ? SC_ALGORITHM_ONBOARD_KEY_GEN : 0;
	_sc_card_add_rsa_alg(card,  512, flags|kg, exponent);
	_sc_card_add_rsa_alg(card,  768, flags, exponent);
	_sc_card_add_rsa_alg(card, 1024, flags|kg, exponent);

	/* Inspect the LOCK byte */
	if (gpk_get_info(card, 0x02, 0xA4, info, sizeof(info)) >= 0) {
		if (info[12] & 0x40) {
			priv->offset_shift = 0;
			priv->offset_mask = 0;
		}
		if (info[12] & 0x08) {
			priv->locked = 1;
		}
		/* Sample cards use a transport key of "TEST KEYTEST KEY" */
		if (!memcmp(info+5, "\x00\xff\x00", 3)) {
			priv->sample_card = 1;
		}
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	/* Make sure max send/receive size is 4 byte aligned and <256. */
	card->max_recv_size = 252;

	return SC_SUCCESS;
}

/*
 * Card is being closed; discard any private data etc
 */
static int
gpk_finish(sc_card_t *card)
{
	if (card->drv_data)
		free(card->drv_data);
	card->drv_data = NULL;
	return 0;
}

/*
 * Select a DF/EF
 */
static int
match_path(sc_card_t *card, unsigned short int **pathptr, size_t *pathlen,
		int need_info)
{
	unsigned short int	*curptr, *ptr;
	size_t		curlen, len;
	size_t		i;

	curptr = (unsigned short int *) card->cache.current_path.value;
	curlen = card->cache.current_path.len;
	ptr    = *pathptr;
	len    = *pathlen;

	if (curlen < 1 || len < 1)
		return 0;

	/* Make sure path starts with MF.
	 * Note the cached path should always begin with MF. */
	if (ptr[0] != GPK_FID_MF || curptr[0] != GPK_FID_MF)
		return 0;

	for (i = 1; i < len && i < curlen; i++) {
		if (ptr[i] != curptr[i])
			break;
	}

	if (len < curlen) {
		/* Caller asked us to select the DF, but the
		 * current file is some EF within the DF we're
		 * interested in. Say ACK */
		if (len == 2)
			goto okay;
		/* Anything else won't work */
		return 0;
	}

	/* In the case of an exact match:
	 * If the caller needs info on the file to be selected,
	 * make sure we at least select the file itself.
	 * If the DF matches the current DF, just return the
	 * FID */
	if (i == len && need_info) {
		if (i > 1) {
			*pathptr = ptr + len - 1;
			*pathlen = len - 1;
			return 1;
		}
		/* bummer */
		return 0;
	}

okay:
	*pathptr = ptr + i;
	*pathlen = len - i;
	return 1;
}

static void
ac_to_acl(unsigned int ac, sc_file_t *file, unsigned int op)
{
	unsigned int	npins, pin;

	npins = (ac >> 14) & 3;
	if (npins == 3) {
		sc_file_add_acl_entry(file, op, SC_AC_NEVER,
			       	SC_AC_KEY_REF_NONE);
		return;
	}

	sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	pin = ac & 0xFF;
	if (npins >= 1)
		sc_file_add_acl_entry(file, op, SC_AC_CHV, (pin >> 4) & 0xF);
	if (npins == 2)
		sc_file_add_acl_entry(file, op, SC_AC_CHV, pin & 0xF);

	/* Check whether secure messaging key is specified */
	if (ac & 0x3F00)
		sc_file_add_acl_entry(file, op, SC_AC_PRO, (ac & 0x3F00) >> 8);
}

/*
 * Convert ACLs requested by the application to access condition
 * bits supported by the GPK. Since these do not map 1:1 there's
 * some fuzz involved.
 */
static void
acl_to_ac(sc_file_t *file, unsigned int op, u8 *ac)
{
	const sc_acl_entry_t *acl;
	unsigned int	npins = 0;

	ac[0] = ac[1] = 0;

	if ((acl = sc_file_get_acl_entry(file, op)) == NULL)
		return;

	assert(acl->method != SC_AC_UNKNOWN);
	switch (acl->method) {
	case SC_AC_NEVER:
		ac[0] = 0xC0;
		return;
	case SC_AC_NONE:
		return;
	}

	while (acl) {
		if (acl->method == SC_AC_CHV) {
			/* Support up to 2 PINS only */
			if (++npins >= 2)
				continue;
			ac[1] >>= 4;
			ac[1] |= acl->key_ref << 4;
			ac[0] += 0x40;
		}
		if (acl->method == SC_AC_PRO) {
			ac[0] |= acl->key_ref & 0x1f;
		}
		acl = acl->next;
	}
}

static int
gpk_parse_fci(sc_card_t *card,
		const u8 *buf, size_t buflen,
		sc_file_t *file)
{
	const u8	*end, *next;
	unsigned int	tag, len;

	end = buf + buflen;
	for (; buf + 2 < end; buf = next) {
		next = buf + 2 + buf[1];
		if (next > end)
			break;
		tag = *buf++;
		len = *buf++;
		if (tag == 0x84) {
			/* unknown purpose - usually the name, but
			 * the content looks weird, such as
			 * 84 0D A0 00 00 00 18 0F 00 00 01 63 00 01 04
			 */
		} else
		if (tag == 0xC1 && len >= 2) {
			/* Seems to be the file id, followed by something
			 * C1 04 02 00 00 00 */
			file->id = (buf[0] << 8) | buf[1];
		} else
		if (tag == 0xC2) {
			/* unknown purpose
			 * C2 01 01
			 */
		}
	}

	return 0;
}

static int
gpk_parse_fileinfo(sc_card_t *card,
		const u8 *buf, size_t buflen,
		sc_file_t *file)
{
	const u8	*sp, *end, *next;
	int		i, rc;

	memset(file, 0, sizeof(*file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		sc_file_add_acl_entry(file, i, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);

	end = buf + buflen;
	for (sp = buf; sp + 2 < end; sp = next) {
		next = sp + 2 + sp[1];
		if (next > end)
			break;
		if (sp[0] == 0x84) {
			/* ignore if name is longer than what it should be */
			if (sp[1] > sizeof(file->name))
				continue;
			memset(file->name, 0, sizeof(file->name));
			memcpy(file->name, sp+2, sp[1]);
		} else
		if (sp[0] == 0x85) {
			unsigned int	ac[3], n;

			if (sp + 11 + 2*3 >= end)
				break;

			file->id = (sp[4] << 8) | sp[5];
			file->size = (sp[8] << 8) | sp[9];
			file->record_length = sp[7];

			/* Map ACLs. Note the third AC byte is
			 * valid of EFs only */
			for (n = 0; n < 3; n++)
				ac[n] = (sp[10+2*n] << 8) | sp[11+2*n];

			/* Examine file type */
			switch (sp[6] & 7) {
			case 0x01: case 0x02: case 0x03: case 0x04:
			case 0x05: case 0x06: case 0x07:
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = sp[6] & 7;
				ac_to_acl(ac[0], file, SC_AC_OP_UPDATE);
				ac_to_acl(ac[1], file, SC_AC_OP_WRITE);
				ac_to_acl(ac[2], file, SC_AC_OP_READ);
				break;
			case 0x00: /* 0x38 is DF */
				file->type = SC_FILE_TYPE_DF;
				/* Icky: the GPK uses different ACLs
				 * for creating data files and
				 * 'sensitive' i.e. key files */
				ac_to_acl(ac[0], file, SC_AC_OP_LOCK);
				ac_to_acl(ac[1], file, SC_AC_OP_CREATE);
				sc_file_add_acl_entry(file, SC_AC_OP_SELECT,
					SC_AC_NONE, SC_AC_KEY_REF_NONE);
				sc_file_add_acl_entry(file, SC_AC_OP_DELETE,
					SC_AC_NEVER, SC_AC_KEY_REF_NONE);
				sc_file_add_acl_entry(file, SC_AC_OP_REHABILITATE,
					SC_AC_NEVER, SC_AC_KEY_REF_NONE);
				sc_file_add_acl_entry(file, SC_AC_OP_INVALIDATE,
					SC_AC_NEVER, SC_AC_KEY_REF_NONE);
				sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES,
					SC_AC_NEVER, SC_AC_KEY_REF_NONE);
				break;
			}
		} else
		if (sp[0] == 0x6f) {
			/* oops - this is a directory with an IADF.
			 * This happens with the personalized GemSafe cards
			 * for instance. */
			file->type = SC_FILE_TYPE_DF;
			rc = gpk_parse_fci(card, sp + 2, sp[1], file);
			if (rc < 0)
				return rc;
		}
	}

	if (file->record_length)
		file->record_count = file->size / file->record_length;
	file->magic = SC_FILE_MAGIC;

	return 0;
}

static int
gpk_select(sc_card_t *card, int kind,
		const u8 *buf, size_t buflen,
		sc_file_t **file)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		resbuf[256];
	int		r;

	/* If we're about to select a DF, invalidate secure messaging keys */
	if (kind == GPK_SEL_MF || kind == GPK_SEL_DF) {
		memset(priv->key, 0, sizeof(priv->key));
		priv->key_set = 0;
	}

	/* do the apdu thing */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = 0xA4;
	apdu.p1 = kind;
	apdu.p2 = 0;
	apdu.data = buf;
	apdu.datalen = buflen;
	apdu.lc = apdu.datalen;

	if (file) {
		apdu.cse = SC_APDU_CASE_4_SHORT;
		apdu.resp = resbuf;
		apdu.resplen = sizeof(resbuf);
		apdu.le = sizeof(resbuf);
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Nothing we can say about it... invalidate
	 * path cache */
	if (kind == GPK_SEL_AID) {
		card->cache.current_path.len = 0;
	}

	if (file == NULL)
		return 0;
	*file = sc_file_new();

	r = gpk_parse_fileinfo(card, apdu.resp, apdu.resplen, *file);
	if (r < 0) {
		sc_file_free(*file);
		*file = NULL;
	}
	return r;
}

static int
gpk_select_id(sc_card_t *card, int kind, unsigned int fid,
		sc_file_t **file)
{
	sc_path_t	*cp = &card->cache.current_path;
	u8		fbuf[2];
	int		r;

	sc_log(card->ctx, 
		"gpk_select_id(0x%04X, kind=%u)\n", fid, kind);

	fbuf[0] = fid >> 8;
	fbuf[1] = fid & 0xff;

	r = gpk_select(card, kind, fbuf, 2, file);

	/* Fix up the path cache.
	 * NB we never cache the ID of an EF, just the DF path */
	if (r == 0) {
		unsigned short int	*path;

		switch (kind) {
		case GPK_SEL_MF:
			cp->len = 0;
			/* fallthru */
		case GPK_SEL_DF:
			if (cp->len + 1 > SC_MAX_PATH_SIZE / 2) {
				return SC_ERROR_INTERNAL;
			}
			path = (unsigned short int *) cp->value;
			path[cp->len++] = fid;
		}
	} else {
		cp->len = 0;
	}
	return r;
}

static int
gpk_select_file(sc_card_t *card, const sc_path_t *path,
		sc_file_t **file)
{
	unsigned short int	pathtmp[SC_MAX_PATH_SIZE/2];
	unsigned short int	*pathptr;
	size_t			pathlen, n;
	int			locked = 0, r = 0, use_relative = 0, retry = 1;
	u8			leaf_type;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* Handle the AID case first */
	if (path->type == SC_PATH_TYPE_DF_NAME) {
		if (path->len > 16)
			return SC_ERROR_INVALID_ARGUMENTS;
		r = gpk_select(card, GPK_SEL_AID,
					path->value, path->len, file);
		goto done;
	}

	/* Now we know we're dealing with 16bit FIDs, either as
	 * an absolute path name (SC_PATH_TYPE_PATH) or a relative
	 * FID (SC_PATH_TYPE_FILE_ID)
	 *
	 * The API should really tell us whether this is a DF or EF
	 * we're selecting. All we can do is read tea leaves...
	 */
	leaf_type = GPK_SEL_EF;

try_again:
	if ((path->len & 1) || path->len > sizeof(pathtmp))
		return SC_ERROR_INVALID_ARGUMENTS;
	pathptr = pathtmp;
	memset(pathtmp, 0, sizeof pathtmp);
	for (n = 0; n < path->len; n += 2)
		pathptr[n>>1] = (path->value[n] << 8)|path->value[n+1];
	pathlen = path->len >> 1;

	/* See whether we can skip an initial portion of the
	 * (absolute) path */
	if (path->type == SC_PATH_TYPE_PATH) {
		/* Do not retry selecting if this cannot be a DF */
		if ((pathptr[0] == GPK_FID_MF && pathlen > 2)
		 || (pathptr[0] != GPK_FID_MF && pathlen > 1))
			retry = 0;
		use_relative = match_path(card, &pathptr, &pathlen, file != 0);
		if (pathlen == 0)
			goto done;
	} else {
		/* SC_PATH_TYPE_FILEID */
		if (pathlen > 1)
			return SC_ERROR_INVALID_ARGUMENTS;
		use_relative = 1;
	}

	if (pathlen == 1 && pathptr[0] == GPK_FID_MF) {
		/* Select just the MF */
		leaf_type = GPK_SEL_MF;
	} else {
		if (!locked++) {
			r = sc_lock(card);
			LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		}

		/* Do we need to select the MF first? */
		if (!use_relative) {
			r = gpk_select_id(card, GPK_SEL_MF, GPK_FID_MF, NULL);
			if (r)
				sc_unlock(card);
			LOG_TEST_RET(card->ctx, r, "Unable to select MF");

			/* Consume the MF FID if it's there */
			if (pathptr[0] == GPK_FID_MF) {
				pathptr++;
				pathlen--;
			}
			if (pathlen == 0)
				goto done;
		}

		/* Next comes a DF, if at all.
		 * This loop can deal with nesting levels > 1 even
		 * though the GPK4000 doesn't support it. */
		while (pathlen > 1) {
			r = gpk_select_id(card, GPK_SEL_DF, pathptr[0], NULL);
			if (r)
				sc_unlock(card);
			LOG_TEST_RET(card->ctx, r, "Unable to select DF");
			pathptr++;
			pathlen--;
		}
	}

	/* Remaining component will be a DF or EF. How do we find out?
	 * All we can do is try */
	r = gpk_select_id(card, leaf_type, pathptr[0], file);
	if (r) {
		/* Did we guess EF, and were wrong? If so, invalidate
		 * path cache and try again; this time aiming for a DF */
		if (leaf_type == GPK_SEL_EF && retry) {
			card->cache.current_path.len = 0;
			leaf_type = GPK_SEL_DF;
			goto try_again;
		}
	}

done:
	if (locked)
		sc_unlock(card);
	return r;
}

/*
 * GPK versions of {read,write,update}_binary functions.
 * Required because by default the GPKs do word offsets
 */
static int
gpk_read_binary(sc_card_t *card, unsigned int offset,
		u8 *buf, size_t count, unsigned long flags)
{
	struct gpk_private_data *priv = DRVDATA(card);

	if (offset & priv->offset_mask) {
		sc_log(card->ctx,  "Invalid file offset (not a multiple of %d)",
				priv->offset_mask + 1);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	return iso_ops->read_binary(card, offset >> priv->offset_shift,
			buf, count, flags);
}

static int
gpk_write_binary(sc_card_t *card, unsigned int offset,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct gpk_private_data *priv = DRVDATA(card);

	if (offset & priv->offset_mask) {
		sc_log(card->ctx,  "Invalid file offset (not a multiple of %d)",
				priv->offset_mask + 1);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	return iso_ops->write_binary(card, offset >> priv->offset_shift,
			buf, count, flags);
}

static int
gpk_update_binary(sc_card_t *card, unsigned int offset,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct gpk_private_data *priv = DRVDATA(card);

	if (offset & priv->offset_mask) {
		sc_log(card->ctx,  "Invalid file offset (not a multiple of %d)",
				priv->offset_mask + 1);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	return iso_ops->update_binary(card, offset >> priv->offset_shift,
			buf, count, flags);
}

/*
 * Secure messaging
 */
static int
gpk_compute_crycks(sc_card_t *card, sc_apdu_t *apdu,
			u8 *crycks1)
{
	struct gpk_private_data *priv = DRVDATA(card);
	u8		in[8], out[8], block[64];
	unsigned int	len = 0, i;
	int             r = SC_SUCCESS, outl;
	EVP_CIPHER_CTX  *ctx = NULL;
	EVP_CIPHER      *alg = NULL;

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return SC_ERROR_INTERNAL;


	/* Fill block with 0x00 and then with the data. */
	memset(block, 0x00, sizeof(block));
	block[len++] = apdu->cla;
	block[len++] = apdu->ins;
	block[len++] = apdu->p1;
	block[len++] = apdu->p2;
	block[len++] = apdu->lc + 3;
	if (apdu->datalen + len > sizeof(block))
		i = sizeof(block) - len;
	else
		i = apdu->datalen;
	memcpy(block+len, apdu->data, i);
	len += i;

	/* Set IV */
	memset(in, 0x00, 8);

	alg = sc_evp_cipher(card->ctx, "DES-EDE-CBC");
	EVP_EncryptInit_ex(ctx, alg, NULL, priv->key, in);
	for (i = 0; i < len; i += 8) {
		if (!EVP_EncryptUpdate(ctx, out, &outl, &block[i], 8)) {
			r = SC_ERROR_INTERNAL;
			break;
		}
	}
	EVP_CIPHER_CTX_free(ctx);
	sc_evp_cipher_free(alg);

	memcpy((u8 *) (apdu->data + apdu->datalen), out + 5, 3);
	apdu->datalen += 3;
	apdu->lc += 3;
	apdu->le += 3;
	if (crycks1)
		memcpy(crycks1, out, 3);
	sc_mem_clear(in, sizeof(in));
	sc_mem_clear(out, sizeof(out));
	sc_mem_clear(block, sizeof(block));
	return r;
}

/*
 * Verify secure messaging response
 */
static int
gpk_verify_crycks(sc_card_t *card, sc_apdu_t *apdu, u8 *crycks)
{
	if (apdu->resplen < 3
	 || memcmp(apdu->resp + apdu->resplen - 3, crycks, 3)) {
		sc_log(card->ctx, 
			"Invalid secure messaging reply\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	apdu->resplen -= 3;
	return 0;
}

/*
 * Create a file or directory.
 * This is a bit tricky because we abuse the ef_structure
 * field to transport file types that are non-standard
 * (the GPK4000 has lots of bizarre file types).
 */
static int
gpk_create_file(sc_card_t *card, sc_file_t *file)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		data[28+3], crycks[3], resp[3];
	size_t		datalen, namelen;
	int		r;

	sc_log(card->ctx, 
		"gpk_create_file(0x%04X)\n", file->id);

	/* Prepare APDU */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x80;	/* assume no secure messaging */
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = 0xE0;
	apdu.p2  = 0x00;

	/* clear data */
	memset(data, 0, sizeof(data));
	datalen = 12;

	/* FID */
	data[0] = file->id >> 8;
	data[1] = file->id & 0xFF;

	/* encode ACLs */
	if (file->type == SC_FILE_TYPE_DF) {
		/* The GPK4000 has separate AC bits for
		 * creating sensitive files and creating
		 * data files. Since OpenSC has just the notion
		 * of "file" we use the same ACL for both AC words
		 */
		apdu.p1 = 0x01; /* create DF */
		data[2] = 0x38;
		acl_to_ac(file, SC_AC_OP_CREATE, data + 6);
		acl_to_ac(file, SC_AC_OP_CREATE, data + 8);
		if ((namelen = file->namelen) != 0) {
			if (namelen > 16)
				return SC_ERROR_INVALID_ARGUMENTS;
			memcpy(data+datalen, file->name, namelen);
			data[5] = namelen;
			datalen += namelen;
		}
	} else {
		apdu.p1 = 0x02; /* create EF */
		data[2] = file->ef_structure;
		data[3] = file->record_length;
		data[4] = file->size >> 8;
		data[5] = file->size & 0xff;
		acl_to_ac(file, SC_AC_OP_UPDATE, data + 6);
		acl_to_ac(file, SC_AC_OP_WRITE, data + 8);
		acl_to_ac(file, SC_AC_OP_READ, data + 10);
	}

	apdu.data = data;
	apdu.datalen = datalen;
	apdu.lc = datalen;

	if (priv->key_set) {
		apdu.cla = 0x84;
		apdu.cse = SC_APDU_CASE_4_SHORT;
		r = gpk_compute_crycks(card, &apdu, crycks);
		if (r)
			return r;
		apdu.resp = resp;
		apdu.resplen = sizeof(resp); /* XXX? */
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* verify secure messaging response */
	if (priv->key_set)
		r = gpk_verify_crycks(card, &apdu, crycks);

	return r;
}

/*
 * Set the secure messaging key following a Select FileKey
 */
static int
gpk_set_filekey(sc_card_t *card, const u8 *key, const u8 *challenge,
		const u8 *r_rn, u8 *kats)
{
	int			r = SC_SUCCESS, outl;
	EVP_CIPHER_CTX		* ctx = NULL;
	EVP_CIPHER		* alg = NULL;
	u8                      out[16];

	memcpy(out, key+8, 8);
	memcpy(out+8, key, 8);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return SC_ERROR_INTERNAL;

	alg = sc_evp_cipher(card->ctx, "DES-EDE");
	EVP_EncryptInit_ex(ctx, alg, NULL, key, NULL);
	if (!EVP_EncryptUpdate(ctx, kats, &outl, r_rn+4, 8))
		r = SC_ERROR_INTERNAL;

	if (!EVP_CIPHER_CTX_reset(ctx))
		r = SC_ERROR_INTERNAL;
	if (r == SC_SUCCESS) {
		EVP_CIPHER_CTX_reset(ctx);
		EVP_EncryptInit_ex(ctx, alg, NULL, out, NULL);
		if (!EVP_EncryptUpdate(ctx, kats+8, &outl, r_rn+4, 8))
			r = SC_ERROR_INTERNAL;
	if (!EVP_CIPHER_CTX_reset(ctx))
		r = SC_ERROR_INTERNAL;
	}
	memset(out, 0, sizeof(out));

	/* Verify Cryptogram presented by the card terminal
	 * XXX: what is the appropriate error code to return
	 * here? INVALID_ARGS doesn't seem quite right
	 */
	if (r == SC_SUCCESS) {
		EVP_CIPHER_CTX_reset(ctx);
		EVP_EncryptInit_ex(ctx, alg, NULL, kats, NULL);
		if (!EVP_EncryptUpdate(ctx, out, &outl, challenge, 8))
			r = SC_ERROR_INTERNAL;
		if (memcmp(r_rn, out+4, 4) != 0)
			r = SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_evp_cipher_free(alg);
	if (ctx)
	    EVP_CIPHER_CTX_free(ctx);

	sc_mem_clear(out, sizeof(out));
	return r;
}

/*
 * Verify a key presented by the user for secure messaging
 */
static int
gpk_select_key(sc_card_t *card, int key_sfi, const u8 *buf, size_t buflen)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		rnd[8], resp[258];
	int		r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (buflen != 16)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* now do the SelFk */
	RAND_bytes(rnd, sizeof(rnd));
	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x80;
	apdu.cse = SC_APDU_CASE_4_SHORT;
	apdu.ins = 0x28;
	apdu.p1  = 0;
	apdu.p2  = key_sfi;
	apdu.data = rnd;
	apdu.datalen = sizeof(rnd);
	apdu.lc = apdu.datalen;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = 12;
	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	if (apdu.resplen != 12) {
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	} else
	if ((r = gpk_set_filekey(card, buf, rnd, resp, priv->key)) == 0) {
		priv->key_set = 1;
		priv->key_reference = key_sfi;
	}

	sc_mem_clear(resp, sizeof(resp));
	return r;
}

/*
 * Select a security environment (Set Crypto Context in GPK docs).
 * When we get here, the PK file has already been selected.
 *
 * Issue: the GPK distinguishes between "signing" and
 * "card internal authentication". I don't know whether this
 * makes any difference in practice...
 *
 * Issue: it seems that sc_compute_signature() does not hash
 * the data for the caller. So what is the purpose of HASH_SHA
 * and other flags?
 */
static int
gpk_set_security_env(sc_card_t *card,
		const sc_security_env_t *env,
		int se_num)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	unsigned int	context, algorithm;
	unsigned int	file_id;
	u8		sysrec[7];
	int		r;

	/* According to several sources from GemPlus, they don't
	 * have off the shelf cards that do DSA. So I won't bother
	 * with implementing this stuff here. */
	algorithm = SC_ALGORITHM_RSA;
	if (env->flags & SC_SEC_ENV_ALG_PRESENT)
		algorithm = env->algorithm;
	if (algorithm != SC_ALGORITHM_RSA) {
		sc_log(card->ctx,  "Algorithm not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	priv->sec_algorithm = algorithm;

	/* If there's a key reference, it must be 0 */
	if ((env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	 && (env->key_ref_len != 1 || env->key_ref[0] != 0)) {
		sc_log(card->ctx,  "Unknown key referenced.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Right now, the OpenSC flags do not support any padding
	 * other than PKCS#1. */
	if (env->flags & SC_ALGORITHM_RSA_PAD_PKCS1)
		priv->sec_padding = 0;
	else if (env->flags & SC_ALGORITHM_RSA_PAD_ANSI)
		priv->sec_padding = 1;
	else if (env->flags & SC_ALGORITHM_RSA_PAD_ISO9796)
		priv->sec_padding = 2;
	else {
		sc_log(card->ctx,  "Padding algorithm not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		/* Again, the following may not make any difference
		 * because we don't do any hashing on-card. But
		 * what the hell, we have all those nice macros,
		 * so why not use them :) 
		 */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
			context = GPK_SIGN_RSA_SHA;
			priv->sec_hash_len = 20;
		} else
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1) {
			context = GPK_SIGN_RSA_SSL;
			priv->sec_hash_len = 36;
		} else
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5) {
			context = GPK_SIGN_RSA_MD5;
			priv->sec_hash_len = 16;
		} else {
			sc_log(card->ctx,  "Unsupported signature algorithm");
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;
	case SC_SEC_OPERATION_DECIPHER:
		context = GPK_UNWRAP_RSA;
		break;
	default:
		sc_log(card->ctx,  "Crypto operation not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Get the file ID */
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		if (env->file_ref.len != 2) {
			sc_log(card->ctx,  "File reference: invalid length.\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		file_id = (env->file_ref.value[0] << 8)
			| env->file_ref.value[1];
	} else {
		sc_log(card->ctx,  "File reference missing.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Select the PK file. The caller has already selected
	 * the DF. */
	r = gpk_select_id(card, GPK_SEL_EF, file_id, NULL);
	LOG_TEST_RET(card->ctx, r, "Failed to select PK file");

	/* Read the sys record of the PK file to find out the key length */
	r = sc_read_record(card, 1, sysrec, sizeof(sysrec),
			SC_RECORD_BY_REC_NR);
	LOG_TEST_RET(card->ctx, r, "Failed to read PK sysrec");
	if (r != 7 || sysrec[0] != 0) {
		sc_log(card->ctx,  "First record of file is not the sysrec");
		return SC_ERROR_OBJECT_NOT_VALID;
	}
	if (sysrec[5] != 0x00) {
		sc_log(card->ctx,  "Public key is not an RSA key");
		return SC_ERROR_OBJECT_NOT_VALID;
	}
	switch (sysrec[1]) {
	case 0x00: priv->sec_mod_len =  512 / 8; break;
	case 0x10: priv->sec_mod_len =  768 / 8; break;
	case 0x11: priv->sec_mod_len = 1024 / 8; break;
	default:
		sc_log(card->ctx,  "Unsupported modulus length");
		return SC_ERROR_OBJECT_NOT_VALID;
	}

	/* Now do SelectCryptoContext */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = 0x80;
	apdu.ins = 0xA6;
	apdu.p1  = file_id & 0x1f;
	apdu.p2  = context;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}

/*
 * Restore security environment
 * Not sure what this is supposed to do.
 */
static int
gpk_restore_security_env(sc_card_t *card, int se_num)
{
	return 0;
}

/*
 * Revert buffer (needed for all GPK crypto operations because
 * they want LSB byte order internally
 */
static int
reverse(u8 *out, size_t outlen, const u8 *in, size_t inlen)
{
	if (inlen > outlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	outlen = inlen;
	while (inlen--)
		*out++ = in[inlen];
	return outlen;
}

/*
 * Use the card's on-board hashing functions to hash some data
 */
#ifdef dontuse
static int
gpk_hash(sc_card_t *card, const u8 *data, size_t datalen)
{
	sc_apdu_t	apdu;
	unsigned int	count, chain, len;
	int		r;

	chain = 0x01;
	for (count = 0; count < datalen; count += len) {
		unsigned char	buffer[GPK_HASH_CHUNK+2];

		if ((len = datalen - count) > GPK_HASH_CHUNK)
			len = GPK_HASH_CHUNK;
		else
			chain |= 0x10;
		buffer[0] = 0x55;
		buffer[1] = len;
		memcpy(buffer+2, data + count, len);

		memset(&apdu, 0, sizeof(apdu));
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.cla = 0x80;
		apdu.ins = 0xDA;
		apdu.p1  = chain;
		apdu.p2  = len;
		apdu.lc  = len + 2;
		apdu.data= buffer;
		apdu.datalen = len + 2;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "Card returned error");
		chain = 0;
	}

	return 0;
}
#endif

/*
 * Send the hashed data to the card.
 */
static int
gpk_init_hashed(sc_card_t *card, const u8 *digest, unsigned int len)
{
	sc_apdu_t	apdu;
	u8		tsegid[64];
	int		r;

	r = reverse(tsegid, sizeof(tsegid), digest, len);
	LOG_TEST_RET(card->ctx, r, "Failed to reverse buffer");

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x80;
	apdu.ins = 0xEA;
	apdu.lc  = len;
	apdu.data= tsegid;
	apdu.datalen = len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}

/*
 * Compute a signature.
 * Note we hash everything manually and send it to the card.
 */
static int
gpk_compute_signature(sc_card_t *card, const u8 *data,
		size_t data_len, u8 * out, size_t outlen)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		cardsig[1024/8];
	int		r;

	if (data_len > priv->sec_mod_len) {
		sc_log(card->ctx, 
			 "Data length (%"SC_FORMAT_LEN_SIZE_T"u) does not match key modulus %u.\n",
			 data_len, priv->sec_mod_len);
		return SC_ERROR_INTERNAL;
	}
	if (sizeof(cardsig) < priv->sec_mod_len)
		return SC_ERROR_BUFFER_TOO_SMALL;

	r = gpk_init_hashed(card, data, data_len);
	LOG_TEST_RET(card->ctx, r, "Failed to send hash to card");

	/* Now sign the hash.
	 * The GPK has Internal Authenticate and PK_Sign. I am not
	 * sure what the difference between the two is. */
	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.cla = 0x80;
	apdu.ins = 0x86;
	apdu.p2  = priv->sec_padding;
	apdu.resp= cardsig;
	apdu.resplen = sizeof(cardsig);
	apdu.le  = priv->sec_mod_len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* The GPK returns the signature as little endian numbers.
	 * Need to revert these */
	r = reverse(out, outlen, cardsig, apdu.resplen);
	LOG_TEST_RET(card->ctx, r, "Failed to reverse signature");

	return r;
}

/*
 * Decrypt some RSA encrypted piece of data.
 * Due to legal restrictions, the GPK will not let you see the
 * full cleartext block, just the last N bytes.
 * The GPK documentation refers to N as the MaxSessionKey size,
 * probably because this feature limits the maximum size of an
 * SSL session key you will be able to decrypt using this card.
 */
static int
gpk_decipher(sc_card_t *card, const u8 *in, size_t inlen,
		u8 *out, size_t outlen)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		buffer[256];
	int		r;

	if (inlen != priv->sec_mod_len) {
		sc_log(card->ctx, 
			 "Data length (%"SC_FORMAT_LEN_SIZE_T"u) does not match key modulus %u.\n",
			 inlen, priv->sec_mod_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* First revert the cryptogram */
	r = reverse(buffer, sizeof(buffer), in, inlen);
	LOG_TEST_RET(card->ctx, r, "Cryptogram too large");
	in = buffer;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x1C, 0x00, 0x00);
	apdu.cla |= 0x80;
	apdu.lc   = inlen;
	apdu.data = in;
	apdu.datalen = inlen;
	apdu.le   = 256;		/* give me all you got :) */
	apdu.resp = buffer;
	apdu.resplen = sizeof(buffer);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Reverse the data we got back */
	r = reverse(out, outlen, buffer, apdu.resplen);
	LOG_TEST_RET(card->ctx, r, "Failed to reverse buffer");

	return r;
}

/*
 * Erase card
 */
static int
gpk_erase_card(sc_card_t *card)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	u8		offset;
	int		r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	switch (card->type) {
	case SC_CARD_TYPE_GPK_GPK4000_su256:
	case SC_CARD_TYPE_GPK_GPK4000_sdo:
		offset = 0x6B;  /* courtesy gemplus hotline */
		break;

	case SC_CARD_TYPE_GPK_GPK4000_s:
		offset = 7;
		break;

	case SC_CARD_TYPE_GPK_GPK8000:
	case SC_CARD_TYPE_GPK_GPK8000_8K:
	case SC_CARD_TYPE_GPK_GPK8000_16K:
	case SC_CARD_TYPE_GPK_GPK16000:
		offset = 0;
		break;

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = 0xDB;
	apdu.ins = 0xDE;
	apdu.p2  = offset;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	priv->key_set = 0;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

/*
 * Lock a file Access Condition.
 *
 * File must be selected, and we assume that any authentication
 * that needs to be presented in order to allow this operation
 * have been presented (ACs from the DF; AC1 for sensitive files,
 * AC2 for normal files).
 */
static int
gpk_lock(sc_card_t *card, struct sc_cardctl_gpk_lock *args)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_file_t	*file = args->file;
	sc_apdu_t	apdu;
	u8		data[8], crycks[3], resp[3];
	int		r;

	sc_log(card->ctx, 
		"gpk_lock(0x%04X, %u)\n", file->id, args->operation);

	memset(data, 0, sizeof(data));
	data[0] = file->id >> 8;
	data[1] = file->id;
	switch (args->operation) {
	case SC_AC_OP_UPDATE:
		data[2] = 0x40; break;
	case SC_AC_OP_WRITE:
		data[3] = 0x40; break;
	case SC_AC_OP_READ:
		data[4] = 0x40; break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x80;
	apdu.ins = 0x16;
	apdu.p1  = (file->type == SC_FILE_TYPE_DF)? 1 : 2;
	apdu.p2  = 0;
	apdu.lc  = 5;
	apdu.datalen = 5;
	apdu.data = data;

	if (priv->key_set) {
		apdu.cla = 0x84;
		apdu.cse = SC_APDU_CASE_4_SHORT;
		r = gpk_compute_crycks(card, &apdu, crycks);
		if (r)
			return r;
		apdu.resp = resp;
		apdu.resplen = sizeof(resp); /* XXX? */
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	if (priv->key_set)
		r = gpk_verify_crycks(card, &apdu, crycks);

	return r;
}

/*
 * Initialize the private portion of a public key file
 */
static int
gpk_pkfile_init(sc_card_t *card, struct sc_cardctl_gpk_pkinit *args)
{
	sc_apdu_t	apdu;
	int		r;

	sc_log(card->ctx, 
		"gpk_pkfile_init(%u)\n", args->privlen);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_1;
	apdu.cla = 0x80;
	apdu.ins = 0x12;
	apdu.p1  = args->file->id & 0x1F;
	apdu.p2  = args->privlen / 4;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}

/*
 * Initialize the private portion of a public key file
 */
static int
gpk_generate_key(sc_card_t *card, struct sc_cardctl_gpk_genkey *args)
{
	sc_apdu_t	apdu;
	int		r;
	u8		buffer[256];

	sc_log(card->ctx, 
		"gpk_generate_key(%u)\n", args->privlen);
	if (args->privlen != 512 && args->privlen != 1024) {
		sc_log(card->ctx, 
			"Key generation not supported for key length %d",
			args->privlen);
		return SC_ERROR_NOT_SUPPORTED;
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.cla = 0x80;
	apdu.ins = 0xD2;
	apdu.p1  = 0x80 | (args->fid & 0x1F);
	apdu.p2  = (args->privlen == 1024) ? 0x11 : 0;
	apdu.le  = args->privlen / 8 + 2;
	apdu.resp = buffer;
	apdu.resplen = 256;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	/* Return the public key, inverted.
	 * The first two bytes must be stripped off. */
	if (args->pubkey_len && apdu.resplen > 2) {
		r = reverse(args->pubkey, args->pubkey_len,
				buffer + 2, apdu.resplen - 2);
		LOG_TEST_RET(card->ctx, r, "Failed to reverse buffer");
		args->pubkey_len = r;
	}

	return r;
}

/*
 * Store a private key component
 */
static int
gpk_pkfile_load(sc_card_t *card, struct sc_cardctl_gpk_pkload *args)
{
	struct gpk_private_data *priv = DRVDATA(card);
	sc_apdu_t	apdu;
	unsigned int	n;
	u8		temp[256];
	int		r = SC_SUCCESS, outl;
	EVP_CIPHER_CTX  * ctx;
	EVP_CIPHER      * alg;

	sc_log(card->ctx,  "gpk_pkfile_load(fid=%04x, len=%d, datalen=%d)\n",
			args->file->id, args->len, args->datalen);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL)
		return SC_ERROR_INTERNAL;

	if (0) {
		sc_log_hex(card->ctx, "Sending (cleartext)",
				args->data, args->datalen);
	}

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = 0x80;
	apdu.ins = 0x18;
	apdu.p1  = args->file->id & 0x1F;
	apdu.p2  = args->len;
	apdu.lc  = args->datalen;

	/* encrypt the private key material */
	assert(args->datalen <= sizeof(temp));
	if (!priv->key_set) {
		sc_log(card->ctx,  "No secure messaging key set!\n");
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}

	alg = sc_evp_cipher(card->ctx, "DES-EDE");
	EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, priv->key, NULL);
	for (n = 0; n < args->datalen; n += 8) {
		if (!EVP_EncryptUpdate(ctx, temp+n, &outl, args->data + n, 8)) {
			r = SC_ERROR_INTERNAL;
			break;
		}
	}
	sc_evp_cipher_free(alg);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;

	apdu.data = temp;
	apdu.datalen = args->datalen;

	/* Forget the key. The card seems to forget it, too :) */
	priv->key_set = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * This function lets pkcs15init query for the transport key
 */
static int
gpk_get_default_key(sc_card_t *card, struct sc_cardctl_default_key *data)
{
	if (data->method == SC_AC_PRO && data->key_ref == 1) {
		if (data->len < 16)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(data->key_data, "TEST KEYTEST KEY", 16);
		data->len = 16;
		return 0;
	}
	return SC_ERROR_NO_DEFAULT_KEY;
}

/*
 * GetInfo call
 */
static int gpk_get_info(sc_card_t *card, int p1, int p2, u8 *buf,
		size_t buflen)
{
	sc_apdu_t	apdu;
	int	r, retry = 0;

	/* We may have to retry the get info command. It
	 * returns 6B00 if a previous command returned a 61xx response,
	 * but the host failed to collect the results.
	 *
	 * Note the additional sc_lock/sc_unlock pair, which
	 * is required to prevent sc_transmit_apdu from 
	 * calling logout(), which in turn does a SELECT MF
	 * without collecting the response :)
	 */
	r = sc_lock(card);
	LOG_TEST_RET(card->ctx, r, "sc_lock() failed");

	do {
		memset(&apdu, 0, sizeof(apdu));
		apdu.cse = SC_APDU_CASE_2_SHORT;
		apdu.cla = 0x80;
		apdu.ins = 0xC0;
		apdu.p1  = p1;
		apdu.p2  = p2;
		apdu.le  = buflen;
		apdu.resp = buf;
		apdu.resplen = buflen;

		if ((r = sc_transmit_apdu(card, &apdu)) < 0) {
			sc_log(card->ctx,  "APDU transmit failed: %s",
					sc_strerror(r));
			sc_unlock(card);
			return r;
		}
	} while (apdu.sw1 == 0x6B && apdu.sw2 == 0x00 && retry++ < 1);
	sc_unlock(card);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}

static int gpk_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	u8  rbuf[10];
	sc_apdu_t apdu;

	if (card->type != SC_CARD_TYPE_GPK_GPK16000)
		return SC_ERROR_NOT_SUPPORTED;

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* see if we have cached serial number */
	if (card->serialnr.len) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		return SC_SUCCESS;
	}
	/* get serial number via Get CSN */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xb8, 0x00, 0x00);
	apdu.cla |= 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le   = 8;
	apdu.lc   = 0;
	apdu.datalen = 0;
        r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	/* cache serial number */
	memcpy(card->serialnr.value, apdu.resp, apdu.resplen);
	card->serialnr.len = apdu.resplen;
	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

/*
 * Dispatch card_ctl calls
 */
static int
gpk_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_ERASE_CARD:
		return gpk_erase_card(card);
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return gpk_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_GPK_VARIANT:
		*(int *) ptr = card->type;
		return 0;
	case SC_CARDCTL_GPK_LOCK:
		return gpk_lock(card, (struct sc_cardctl_gpk_lock *) ptr);
	case SC_CARDCTL_GPK_PKINIT:
		return gpk_pkfile_init(card,
			       (struct sc_cardctl_gpk_pkinit *) ptr);
	case SC_CARDCTL_GPK_PKLOAD:
		return gpk_pkfile_load(card,
			       (struct sc_cardctl_gpk_pkload *) ptr);
	case SC_CARDCTL_GPK_IS_LOCKED:
		*(int *) ptr = DRVDATA(card)->locked;
		return 0;
	case SC_CARDCTL_GPK_GENERATE_KEY:
		return gpk_generate_key(card,
				(struct sc_cardctl_gpk_genkey *) ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return gpk_get_serialnr(card, (sc_serial_number_t *) ptr);
	}


	return SC_ERROR_NOT_SUPPORTED;
}

static int
gpk_build_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, struct sc_pin_cmd_data *data)
{
	static u8	sbuf[8];
	int		r;

	if (data->pin_type != SC_AC_CHV)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* XXX deal with secure messaging here */
	memset(apdu, 0, sizeof(*apdu));
	apdu->cse	= SC_APDU_CASE_3_SHORT;

	data->flags |= SC_PIN_CMD_NEED_PADDING;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		/* Copy PIN to buffer and pad */
		data->pin1.encoding = SC_PIN_ENCODING_ASCII;
		data->pin1.pad_length = 8;
		data->pin1.pad_char = 0x00;
		data->pin1.offset = 5;
		r = sc_build_pin(sbuf, 8, &data->pin1, 1);
		if (r < 0)
			return r;

		apdu->cla = 0x00;
		apdu->ins = 0x20;
		apdu->p1  = 0x00;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		/* Copy PINs to buffer, BCD-encoded, and pad */
		data->pin1.encoding = SC_PIN_ENCODING_BCD;
		data->pin1.pad_length = 8;
		data->pin1.pad_char = 0x00;
		data->pin1.offset = 5;
		data->pin2.encoding = SC_PIN_ENCODING_BCD;
		data->pin2.pad_length = 8;
		data->pin2.pad_char = 0x00;
		data->pin2.offset = 5 + 4;
		if ((r = sc_build_pin(sbuf, 4, &data->pin1, 1)) < 0
		 || (r = sc_build_pin(sbuf + 4, 4, &data->pin2, 1)) < 0)
			return r;

		apdu->cla = 0x80;
		apdu->ins = 0x24;
		apdu->p1  = (data->cmd == SC_PIN_CMD_CHANGE)? 0x00 : 0x01;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	apdu->p2	= data->pin_reference & 7;
	apdu->lc	= 8;
	apdu->datalen	= 8;
	apdu->data	= sbuf;

	return 0;
}

static int
gpk_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	sc_apdu_t apdu;
	int r;

	/* Special case - External Authenticate */
	if (data->cmd == SC_PIN_CMD_VERIFY
	 && data->pin_type == SC_AC_PRO)
		return gpk_select_key(card,
				data->pin_reference,
				data->pin1.data,
				data->pin1.len);

	r = gpk_build_pin_apdu(card, &apdu, data);
	if (r < 0)
		return r;

	data->apdu = &apdu;

	r = iso_ops->pin_cmd(card, data, tries_left);

	data->apdu = NULL;
	return r;
}

/*
 * Initialize the driver struct
 */
static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv;

	iso_drv = sc_get_iso7816_driver();
	iso_ops = iso_drv->ops;
	gpk_ops = *iso_ops;

	gpk_ops.match_card	= gpk_match_card;
	gpk_ops.init		= gpk_init;
	gpk_ops.finish		= gpk_finish;
	gpk_ops.select_file	= gpk_select_file;
	gpk_ops.read_binary	= gpk_read_binary;
	gpk_ops.write_binary	= gpk_write_binary;
	gpk_ops.update_binary	= gpk_update_binary;
	gpk_ops.create_file	= gpk_create_file;
	/* gpk_ops.check_sw	= gpk_check_sw; */
	gpk_ops.card_ctl	= gpk_card_ctl;
	gpk_ops.set_security_env= gpk_set_security_env;
	gpk_ops.restore_security_env= gpk_restore_security_env;
	gpk_ops.compute_signature= gpk_compute_signature;
	gpk_ops.decipher	= gpk_decipher;
	gpk_ops.pin_cmd		= gpk_pin_cmd;

	return &gpk_drv;
}

struct sc_card_driver *
sc_get_gpk_driver(void)
{
	return sc_get_driver();
}
#endif /* ENABLE_OPENSSL */
