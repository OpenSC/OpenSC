/*
 * pkcs15.c: PKCS #15 general functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>


/* Search key when looking for objects */
struct sc_pkcs15_search_key {
	const struct sc_pkcs15_id *	id;
	unsigned int			usage_mask, usage_value;
	unsigned int			flags_mask, flags_value;

	unsigned int			match_reference : 1;
	int				reference;
};

static int sc_pkcs15_bind_synthetic(struct sc_pkcs15_card *);

void sc_pkcs15_print_card(const struct sc_pkcs15_card *card)
{
	const char *flags[] = {
		"Read-only",
		"Login required",
		"PRN generation",
		"EID compliant"
	};
	int i;

	assert(card != NULL);
	printf("PKCS#15 Card [%s]:\n", card->label);
	printf("\tVersion        : %d\n", card->version);
	printf("\tSerial number  : %s\n", card->serial_number);
	printf("\tManufacturer ID: %s\n", card->manufacturer_id);
	printf("\tFlags          : ");
	for (i = 0; i < 4; i++) {
		int count = 0;
		if ((card->flags >> i) & 1) {
			if (count)
				printf(", ");
			printf("%s", flags[i]);
			count++;
		}
	}
	printf("\n");
}

static const struct sc_asn1_entry c_asn1_toki[] = {
	{ "version",        SC_ASN1_INTEGER,      ASN1_INTEGER, 0, NULL },
	{ "serialNumber",   SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, NULL },
	{ "manufacturerID", SC_ASN1_UTF8STRING,   ASN1_UTF8STRING, SC_ASN1_OPTIONAL, NULL },
	{ "label",	    SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL },
	{ "tokenflags",	    SC_ASN1_BIT_FIELD,   ASN1_BIT_STRING, 0, NULL },
	{ "seInfo",	    SC_ASN1_SEQUENCE,	  SC_ASN1_CONS | ASN1_SEQUENCE, SC_ASN1_OPTIONAL, NULL },
	{ "recordInfo",	    SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL },
	{ "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_tokeninfo[] = {
	{ "TokenInfo", SC_ASN1_STRUCT, SC_ASN1_CONS | ASN1_SEQUENCE, 0, NULL },
	{ NULL }
};

static void parse_tokeninfo(struct sc_pkcs15_card *card, const u8 * buf, size_t buflen)
{
	int r;
	u8 serial[128];
	size_t i;
	size_t serial_len = sizeof(serial);
	u8 mnfid[SC_PKCS15_MAX_LABEL_SIZE];
	size_t mnfid_len = sizeof(mnfid);
	u8 label[SC_PKCS15_MAX_LABEL_SIZE];
	size_t label_len = sizeof(label);
	size_t flags_len = sizeof(card->flags);
	struct sc_asn1_entry asn1_toki[9], asn1_tokeninfo[3];

	sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	sc_format_asn1_entry(asn1_toki + 0, &card->version, NULL, 0);
	sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 0);
	sc_format_asn1_entry(asn1_toki + 2, mnfid, &mnfid_len, 0);
	sc_format_asn1_entry(asn1_toki + 3, label, &label_len, 0);
	sc_format_asn1_entry(asn1_toki + 4, &card->flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 0);
	
	r = sc_asn1_decode(card->card->ctx, asn1_tokeninfo, buf, buflen, NULL, NULL);
	if (r) {
		sc_error(card->card->ctx,
			"ASN.1 parsing of EF(TokenInfo) failed: %s\n",
			sc_strerror(r));
		goto err;
	}
	card->version += 1;
	card->serial_number = (char *) malloc(serial_len * 2 + 1);
	card->serial_number[0] = 0;
	for (i = 0; i < serial_len; i++) {
		char byte[3];

		sprintf(byte, "%02X", serial[i]);
		strcat(card->serial_number, byte);
	}
	if (card->manufacturer_id == NULL) {
		if (asn1_toki[2].flags & SC_ASN1_PRESENT)
			card->manufacturer_id = strdup((char *) mnfid);
		else
			card->manufacturer_id = strdup("(unknown)");
	}
	if (card->label == NULL) {
		if (asn1_toki[3].flags & SC_ASN1_PRESENT)
			card->label = strdup((char *) label);
		else
			card->label = strdup("(unknown)");
	}
	return;
err:
	if (card->serial_number == NULL)
		card->serial_number = strdup("(unknown)");
	if (card->manufacturer_id == NULL)
		card->manufacturer_id = strdup("(unknown)");
	return;
}

int sc_pkcs15_encode_tokeninfo(struct sc_context *ctx,
			       struct sc_pkcs15_card *card,
			       u8 **buf, size_t *buflen)
{
	int r;
	u8 serial[128];
	size_t serial_len = 0;
	size_t mnfid_len;
	size_t label_len;
	size_t flags_len;
	int version = card->version;
	
	struct sc_asn1_entry asn1_toki[9], asn1_tokeninfo[2];

	sc_copy_asn1_entry(c_asn1_toki, asn1_toki);
	sc_copy_asn1_entry(c_asn1_tokeninfo, asn1_tokeninfo);
	version--;
	sc_format_asn1_entry(asn1_toki + 0, &version, NULL, 1);
	if (card->serial_number != NULL) {
		if (strlen(card->serial_number)/2 > sizeof(serial))
			return SC_ERROR_BUFFER_TOO_SMALL;
		serial_len = sizeof(serial);
		if (sc_hex_to_bin(card->serial_number, serial, &serial_len) < 0)
			return SC_ERROR_INVALID_ARGUMENTS;
		sc_format_asn1_entry(asn1_toki + 1, serial, &serial_len, 1);
	}
	if (card->manufacturer_id != NULL) {
		mnfid_len = strlen(card->manufacturer_id);
		sc_format_asn1_entry(asn1_toki + 2, card->manufacturer_id, &mnfid_len, 1);
	}
	if (card->label != NULL) {
		label_len = strlen(card->label);
		sc_format_asn1_entry(asn1_toki + 3, card->label, &label_len, 1);
	}
	if (card->flags) {
		flags_len = sizeof(card->flags);
		sc_format_asn1_entry(asn1_toki + 4, &card->flags, &flags_len, 1);
	}
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_tokeninfo, buf, buflen);
	if (r) {
		sc_error(ctx, "sc_asn1_encode() failed: %s\n", sc_strerror(r));
		return r;
	}
	return 0;
}

static const struct sc_asn1_entry c_asn1_ddo[] = {
	{ "oid",	   SC_ASN1_OBJECT, ASN1_OBJECT, 0, NULL },
	{ "odfPath",	   SC_ASN1_PATH, SC_ASN1_CONS | ASN1_SEQUENCE, SC_ASN1_OPTIONAL, NULL },
	{ "tokenInfoPath", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL },
	{ "unusedPath",    SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static int parse_ddo(struct sc_pkcs15_card *p15card, const u8 * buf, size_t buflen)
{
	struct sc_asn1_entry asn1_ddo[5];
	struct sc_path odf_path, ti_path;
	int r;

	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);
	sc_format_asn1_entry(asn1_ddo + 1, &odf_path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &ti_path, NULL, 0);

	r = sc_asn1_decode(p15card->card->ctx, asn1_ddo, buf, buflen, NULL, NULL);
	if (r) {
		sc_error(p15card->card->ctx, "DDO parsing failed: %s\n",
		      sc_strerror(r));
		return r;
	}
	if (asn1_ddo[1].flags & SC_ASN1_PRESENT) {
		p15card->file_odf = sc_file_new();
		if (p15card->file_odf == NULL)
			goto mem_err;
		p15card->file_odf->path = odf_path;
	}
	if (asn1_ddo[2].flags & SC_ASN1_PRESENT) {
		p15card->file_tokeninfo = sc_file_new();
		if (p15card->file_tokeninfo == NULL)
			goto mem_err;
		p15card->file_tokeninfo->path = ti_path;
	}
	return 0;
mem_err:
	if (p15card->file_odf != NULL) {
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
	}
	if (p15card->file_tokeninfo != NULL) {
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
	return SC_ERROR_OUT_OF_MEMORY;
}

#if 0
static int encode_ddo(struct sc_pkcs15_card *p15card, u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_ddo[5];
	int r;
	size_t label_len;
	
	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);

	sc_format_asn1_entry(asn1_ddo + 1, &card->file_odf.path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &card->file_tokeninfo.path, NULL, 0);

	r = sc_asn1_encode(ctx, asn1_dir, buf, buflen);
	if (r) {
		sc_error(ctx, "sc_asn1_encode() failed: %s\n",
		      sc_strerror(r));
		return r;
	}
	return 0;
}
#endif

int sc_pkcs15_create_dir(struct sc_pkcs15_card *p15card, struct sc_card *card)
{
#if 0
	struct sc_path path;
	struct sc_file file;
	u8 *buf;
	size_t bufsize;
	int r, i;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	SC_TEST_RET(card->ctx, r, "sc_select_file(MF) failed");
	r = encode_dir(card->ctx, p15card, &buf, &bufsize);
	SC_TEST_RET(card->ctx, r, "EF(DIR) encoding failed");
	memset(&file, 0, sizeof(file));
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		file.acl[i] = p15card->file_dir.acl[i];
	file.size = bufsize;
	file.type = SC_FILE_TYPE_WORKING_EF;
	file.ef_structure = SC_FILE_EF_TRANSPARENT;
	file.id = 0x2F00;
	file.status = SC_FILE_STATUS_ACTIVATED;
	sc_format_path("3F002F00", &path);
	i = card->ctx->log_errors;
	card->ctx->log_errors = 0;
	r = sc_select_file(card, &path, NULL);
	card->ctx->log_errors = i;
	if (r != 0) {
		r = sc_create_file(card, &file);
		if (r) {
			sc_perror(card->ctx, r, "Error creating EF(DIR)");
			free(buf);
			return r;
		}
		r = sc_select_file(card, &path, NULL);
		if (r) {
			sc_perror(card->ctx, r, "Error selecting EF(DIR)");
			free(buf);
			return r;
		}
	}
	r = sc_update_binary(card, 0, buf, bufsize, 0);
	free(buf);
	SC_TEST_RET(card->ctx, r, "Error updating EF(DIR)");
#endif
	return 0;
}

static const struct sc_asn1_entry c_asn1_odf[] = {
	{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL },
	{ "publicKeys",		 SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL },
	{ "trustedPublicKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, 0, NULL },
	{ "certificates",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL },
	{ "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL },
	{ "usefulCertificates",  SC_ASN1_STRUCT, SC_ASN1_CTX | 6 | SC_ASN1_CONS, 0, NULL },
	{ "dataObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL },
	{ "authObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const int odf_indexes[] = {
	SC_PKCS15_PRKDF,
	SC_PKCS15_PUKDF,
	SC_PKCS15_PUKDF_TRUSTED,
	SC_PKCS15_CDF,
	SC_PKCS15_CDF_TRUSTED,
	SC_PKCS15_CDF_USEFUL,
	SC_PKCS15_DODF,
	SC_PKCS15_AODF,
};

static int parse_odf(const u8 * buf, int buflen, struct sc_pkcs15_card *card)
{
	const u8 *p = buf;
	size_t left = buflen;
	int r, i;
	struct sc_path path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path },
		{ NULL }
	};
	struct sc_asn1_entry asn1_odf[9];
	
	sc_copy_asn1_entry(c_asn1_odf, asn1_odf);
	for (i = 0; asn1_odf[i].name != NULL; i++)
		sc_format_asn1_entry(asn1_odf + i, asn1_obj_or_path, NULL, 0);
	while (left > 0) {
		r = sc_asn1_decode_choice(card->card->ctx, asn1_odf, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		r = sc_pkcs15_add_df(card, odf_indexes[r], &path, NULL);
		if (r)
			return r;
	}
	return 0;
}

int sc_pkcs15_encode_odf(struct sc_context *ctx,
			 struct sc_pkcs15_card *p15card,
			 u8 **buf, size_t *buflen)
{
	struct sc_path path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path },
		{ NULL }
	};
	struct sc_asn1_entry *asn1_paths = NULL;
	struct sc_asn1_entry *asn1_odf = NULL;
	int df_count = 0, r, c = 0;
	const int nr_indexes = sizeof(odf_indexes)/sizeof(odf_indexes[0]);
	struct sc_pkcs15_df *df;
	
	df = p15card->df_list;
	while (df != NULL) {
		df_count++;
		df = df->next;
	};
	if (df_count == 0) {
		sc_error(ctx, "No DF's found.\n");
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	asn1_odf = (struct sc_asn1_entry *) malloc(sizeof(struct sc_asn1_entry) * (df_count + 1));
	if (asn1_odf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	asn1_paths = (struct sc_asn1_entry *) malloc(sizeof(struct sc_asn1_entry) * (df_count * 2));
	if (asn1_paths == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	for (df = p15card->df_list; df != NULL; df = df->next) {
		int j, type = -1;

		for (j = 0; j < nr_indexes; j++)
			if (odf_indexes[j] == df->type) {
				type = j;
				break;
			}
		if (type == -1) {
			sc_error(ctx, "Unsupported DF type.\n");
			continue;
		}
		asn1_odf[c] = c_asn1_odf[type];
		sc_format_asn1_entry(asn1_odf + c, asn1_paths + 2*c, NULL, 1);
		sc_copy_asn1_entry(asn1_obj_or_path, asn1_paths + 2*c);
		sc_format_asn1_entry(asn1_paths + 2*c, &df->path, NULL, 1);
		c++;
	}
	asn1_odf[c].name = NULL;
	r = sc_asn1_encode(ctx, asn1_odf, buf, buflen);
err:
	if (asn1_paths != NULL)
		free(asn1_paths);
	if (asn1_odf != NULL)
		free(asn1_odf);
	return r;
}

struct sc_pkcs15_card * sc_pkcs15_card_new()
{
	struct sc_pkcs15_card *p15card;
	
	p15card = (struct sc_pkcs15_card *) malloc(sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return NULL;
	memset(p15card, 0, sizeof(struct sc_pkcs15_card));
	p15card->magic = SC_PKCS15_CARD_MAGIC;
	return p15card;
}

void sc_pkcs15_card_free(struct sc_pkcs15_card *p15card)
{
	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	while (p15card->obj_list)
		sc_pkcs15_remove_object(p15card, p15card->obj_list);
	while (p15card->df_list)
		sc_pkcs15_remove_df(p15card, p15card->df_list);
	if (p15card->file_app != NULL)
		sc_file_free(p15card->file_app);
	if (p15card->file_tokeninfo != NULL)
		sc_file_free(p15card->file_tokeninfo);
	if (p15card->file_odf != NULL)
		sc_file_free(p15card->file_odf);
	p15card->magic = 0;
	if (p15card->label)
		free(p15card->label);
	if (p15card->serial_number)
		free(p15card->serial_number);
	if (p15card->manufacturer_id)
		free(p15card->manufacturer_id);
	free(p15card);
}

int sc_pkcs15_bind(struct sc_card *card,
		   struct sc_pkcs15_card **p15card_out)
{
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	int err;
	size_t len;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_path tmppath;
	struct sc_context *ctx;
	scconf_block *conf_block = NULL, **blocks;
	int i;

	assert(sc_card_valid(card) && p15card_out != NULL);
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, 1);
	p15card = sc_pkcs15_card_new();
	if (p15card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	p15card->card = card;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
			"framework", "pkcs15");
		if (blocks[0] != NULL)
			conf_block = blocks[0];
		free(blocks);
	}
	if (conf_block)
		p15card->opts.use_cache = scconf_get_bool(conf_block, "use_caching", 0);

	err = sc_lock(card);
	if (err) {
		sc_error(ctx, "sc_lock() failed: %s\n", sc_strerror(err));
		sc_pkcs15_card_free(p15card);
		SC_FUNC_RETURN(ctx, 1, err);
	}
	
	if (card->app_count < 0) {
		err = sc_enum_apps(card);
		if (err < 0 && err != SC_ERROR_FILE_NOT_FOUND) {
			sc_error(ctx, "unable to enumerate apps: %s\n", sc_strerror(err));
			goto error;
		}
	}
	p15card->file_app = sc_file_new();
	if (p15card->file_app == NULL) {
		err = SC_ERROR_OUT_OF_MEMORY;
		goto error;
	}
	sc_format_path("3F005015", &p15card->file_app->path);
	if (card->app_count > 0) {
		const struct sc_app_info *info;
		
		info = sc_find_pkcs15_app(card);
		if (info != NULL) {
			if (info->path.len)
				p15card->file_app->path = info->path;
			if (info->ddo != NULL)
				parse_ddo(p15card, info->ddo, info->ddo_len);
		}
	}

	/* Check if pkcs15 directory exists */
	i = ctx->log_errors;
	ctx->log_errors = 0;
	err = sc_select_file(card, &p15card->file_app->path, NULL);
	ctx->log_errors = 1;
	if (err < 0) {
		err = sc_pkcs15_bind_synthetic(p15card);
		if (err < 0)
			goto error;
		goto done;
	}

	if (p15card->file_odf == NULL) {
		tmppath = p15card->file_app->path;
		sc_append_path_id(&tmppath, (const u8 *) "\x50\x31", 2);
	} else {
		tmppath = p15card->file_odf->path;
		sc_file_free(p15card->file_odf);
		p15card->file_odf = NULL;
	}
	err = sc_select_file(card, &tmppath, &p15card->file_odf);
	if (err) /* FIXME: finish writing error reporting stuff */
		goto error;

	/* XXX: fix buffer overflow. Silently truncate ODF if it
	 * is too large.  --okir */
	if ((len = p15card->file_odf->size) > sizeof(buf))
		len = sizeof(buf);
	err = sc_read_binary(card, 0, buf, len, 0);
	if (err < 0)
		goto error;
	if (err < 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto error;
	}
	len = err;
	if (parse_odf(buf, len, p15card)) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		sc_error(card->ctx, "Unable to parse ODF\n");
		goto error;
	}
	if (p15card->file_tokeninfo == NULL) {
		tmppath = p15card->file_app->path;
		sc_append_path_id(&tmppath, (const u8 *) "\x50\x32", 2);
	} else {
		tmppath = p15card->file_tokeninfo->path;
		sc_file_free(p15card->file_tokeninfo);
		p15card->file_tokeninfo = NULL;
	}
	err = sc_select_file(card, &tmppath, &p15card->file_tokeninfo);
	if (err)
		goto error;

	if ((len = p15card->file_tokeninfo->size) > sizeof(buf))
		len = sizeof(buf);
	err = sc_read_binary(card, 0, buf, len, 0);
	if (err < 0)
		goto error;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto error;
	}
	parse_tokeninfo(p15card, buf, err);

done:
	*p15card_out = p15card;
	sc_unlock(card);
	return 0;
error:
	sc_unlock(card);
	sc_pkcs15_card_free(p15card);
	SC_FUNC_RETURN(ctx, 1, err);
}

int sc_pkcs15_bind_synthetic(struct sc_pkcs15_card *p15card)
{
	int ret = SC_ERROR_INTERNAL, i;
	struct sc_context *ctx = p15card->card->ctx;
	const scconf_list *clist, *tmp;
	scconf_block *conf_block = NULL, **blocks;

	SC_FUNC_CALLED(ctx, 1);

	assert(p15card);

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
			"framework", "pkcs15");
		if (blocks[0] != NULL)
			conf_block = blocks[0];
		free(blocks);
	}
	if (!conf_block)
		return SC_ERROR_INTERNAL;
	/* get the pkcs15_syn libs from the conf file */
	clist = scconf_find_list(conf_block, "pkcs15_syn");
	if (!clist)
		return SC_ERROR_INTERNAL;

	/* iterate trough the list given in the config file */
	for (tmp = clist; tmp != NULL; tmp = tmp->next) {
		int  r, tmp_r;
		void *handle = NULL, *func_handle;
		int  (*init_func)(sc_pkcs15_card_t *);

		if (ctx->debug >= 4) {
			sc_debug(ctx, "Loading: %s\n", tmp->data);
		}
		/* try to open dynamic library */
		r = sc_module_open(ctx, &handle, tmp->data);
		if (r != SC_SUCCESS)
			/* ignore error, try next one */
			continue;
		/* get a handle to the pkcs15 init function 
		 * XXX the init_func should not modify the contents of
		 * sc_pkcs15_card_t unless the card is really the one
		 * the driver is intended for -- Nils
		 */
		r = sc_module_get_address(ctx, handle, &func_handle, 
			"sc_pkcs15_init_func");
		init_func = (int (*)(sc_pkcs15_card_t *))func_handle;
		if (r != SC_SUCCESS || !init_func)
			return r;
		/* try to initialize synthetic pkcs15 structures */
		tmp_r = init_func(p15card);
		r = sc_module_close(ctx, handle);
		if (r != SC_SUCCESS)
			return r;
		if (tmp_r == SC_SUCCESS) {
			p15card->flags |= SC_PKCS15_CARD_FLAG_READONLY;
			p15card->magic  = 0x10203040;
			ret = SC_SUCCESS;
			break;
		}
		else if (tmp_r == SC_ERROR_WRONG_CARD) {
			/* wrong init_func => try next one (if existing) */
			if (ctx->debug >= 4) {
				sc_debug(ctx, "init_func failed => trying next one\n");
			}
			continue;
		}
		/* some internal/card error occured => exit */
		return tmp_r;
	}

	return ret;
}

int sc_pkcs15_detect(struct sc_card *card)
{
	int r;
	struct sc_path path;

	sc_format_path("NA0000063504B43532D3135", &path);
	r = sc_select_file(card, &path, NULL);
	if (r != 0)
		return 0;
	return 1;
}

int sc_pkcs15_unbind(struct sc_pkcs15_card *p15card)
{
	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	sc_pkcs15_card_free(p15card);
	return 0;
}

int sc_pkcs15_get_objects_cond(struct sc_pkcs15_card *p15card, int type,
			       int (* func)(struct sc_pkcs15_object *, void *),
                               void *func_arg,
			       struct sc_pkcs15_object **ret, int ret_size)
{
	const int prkey_df[] = { SC_PKCS15_PRKDF, -1 };
	const int pubkey_df[] = { SC_PKCS15_PUKDF, SC_PKCS15_PUKDF_TRUSTED, -1 };
	const int cert_df[] = { SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED, SC_PKCS15_CDF_USEFUL, -1 };
	const int data_df[] = { SC_PKCS15_DODF, -1 };
	const int auth_df[] = { SC_PKCS15_AODF, -1 };
	const int *dfs;
	sc_pkcs15_object_t *obj;
	int match_count = 0, i, r = 0;
	
	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		dfs = prkey_df;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		dfs = pubkey_df;
		break;
	case SC_PKCS15_TYPE_CERT:
		dfs = cert_df;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		dfs = data_df;
		break;
	case SC_PKCS15_TYPE_AUTH:
		dfs = auth_df;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	for (i = 0; dfs[i] != -1; i++) {
		struct sc_pkcs15_df *df = p15card->df_list;

		for (df = p15card->df_list; df != NULL; df = df->next) {
			if (df->type != dfs[i])
				continue;
			if (df->enumerated)
				continue;
			/* Enumerate the DF's, so p15card->obj_list is
			 * populated. */
			r = sc_pkcs15_parse_df(p15card, df);
			if (r < 0)
				break;
			SC_TEST_RET(p15card->card->ctx, r, "DF parsing failed");
			df->enumerated = 1;
		}
	}
	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		if (obj->type != type
		 && (obj->type & SC_PKCS15_TYPE_CLASS_MASK) != type)
			continue;
		if (func != NULL && func(obj, func_arg) <= 0)
			continue;
		/* Okay, we have a match. */
		match_count++;
		if (ret_size <= 0)
			continue;
		ret[match_count-1] = obj;
		if (ret_size <= match_count)
			break;
	}
	return match_count;
}

int sc_pkcs15_get_objects(struct sc_pkcs15_card *p15card, int type,
			  struct sc_pkcs15_object **ret, int ret_size)
{
        return sc_pkcs15_get_objects_cond(p15card, type, NULL, NULL, ret, ret_size);
}

static int compare_obj_id(struct sc_pkcs15_object *obj, const sc_pkcs15_id_t *id)
{
	void *data = obj->data;
	
	switch (obj->type) {
	case SC_PKCS15_TYPE_CERT_X509:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_cert_info *) data)->id, id);
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_pubkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_AUTH_PIN:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_pin_info *) data)->auth_id, id);
	case SC_PKCS15_TYPE_DATA_OBJECT:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_data_info *) data)->id, id);
	}
	return 0;
}

static int compare_obj_usage(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
	void		*data = obj->data;
	unsigned int	usage;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_DSA:
		usage = ((struct sc_pkcs15_prkey_info *) data)->usage;
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_DSA:
		usage = ((struct sc_pkcs15_pubkey_info *) data)->usage;
		break;
	default:
		return 0;
	}
	return (usage & mask & value) != 0;
}

static int compare_obj_flags(sc_pkcs15_object_t *obj, unsigned int mask, unsigned int value)
{
	void		*data = obj->data;
	unsigned int	flags;

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		flags = ((struct sc_pkcs15_pin_info *) data)->flags;
		break;
	default:
		return 0;
	}
	return !((flags ^ value) & mask);
}

static int compare_obj_reference(sc_pkcs15_object_t *obj, int value)
{
	void		*data = obj->data;
	int		reference;

	switch (obj->type) {
	case SC_PKCS15_TYPE_AUTH_PIN:
		reference = ((struct sc_pkcs15_pin_info *) data)->reference;
		break;
	default:
		return 0;
	}
	return reference == value;
}

static int compare_obj_key(struct sc_pkcs15_object *obj, void *arg)
{
	struct sc_pkcs15_search_key *sk = (struct sc_pkcs15_search_key *) arg;

	if (sk->id && !compare_obj_id(obj, sk->id))
		return 0;
	if (sk->usage_mask && !compare_obj_usage(obj, sk->usage_mask, sk->usage_value))
		return 0;
	if (sk->flags_mask && !compare_obj_flags(obj, sk->flags_mask, sk->flags_value))
		return 0;
	if (sk->match_reference && !compare_obj_reference(obj, sk->reference))
		return 0;
	return 1;
}

static int find_by_key(struct sc_pkcs15_card *p15card,
		       int type, struct sc_pkcs15_search_key *sk,
		       struct sc_pkcs15_object **out)
{
	int r;
	
	r = sc_pkcs15_get_objects_cond(p15card, type, compare_obj_key, sk, out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
}

static int find_by_id(struct sc_pkcs15_card *p15card,
		      int type, const struct sc_pkcs15_id *id,
		      struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.id = id;

	return find_by_key(p15card, type, &sk, out);
}

int sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *p15card,
			      const struct sc_pkcs15_id *id,
			      struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_CERT, id, out);
}

int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_id *id,
			       struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_PRKEY, id, out);
}

int sc_pkcs15_find_pubkey_by_id(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_id *id,
				struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_PUBKEY, id, out);
}

int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *p15card,
			     const struct sc_pkcs15_id *id,
			     struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_AUTH_PIN, id, out);
}

int sc_pkcs15_find_pin_by_reference(struct sc_pkcs15_card *p15card,
				int reference,
				struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.match_reference = 1;
	sk.reference = reference;

	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}

int sc_pkcs15_find_data_object_by_id(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_id *id,
				struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_DATA_OBJECT, id, out);
}

int sc_pkcs15_find_prkey_by_id_usage(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_id *id,
			       unsigned int usage,
			       struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.usage_mask = sk.usage_value = usage;
	sk.id = id;

	return find_by_key(p15card, SC_PKCS15_TYPE_PRKEY, &sk, out);
}

int sc_pkcs15_find_so_pin(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_object **out)
{
	struct sc_pkcs15_search_key sk;

	memset(&sk, 0, sizeof(sk));
	sk.flags_mask = sk.flags_value = SC_PKCS15_PIN_FLAG_SO_PIN;
	
	return find_by_key(p15card, SC_PKCS15_TYPE_AUTH_PIN, &sk, out);
}

int sc_pkcs15_add_object(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_object *p = p15card->obj_list;

	obj->next = obj->prev = NULL;
	if (p15card->obj_list == NULL) {
		p15card->obj_list = obj;
		return 0;
	}
	while (p->next != NULL)
 		p = p->next;
	p->next = obj;
	obj->prev = p;

	return 0;
}

void sc_pkcs15_remove_object(struct sc_pkcs15_card *p15card,
			     struct sc_pkcs15_object *obj)
{
	if (obj->prev == NULL)
		p15card->obj_list = obj->next;
	else
		obj->prev->next = obj->next;
	if (obj->next != NULL)
		obj->next->prev = obj->prev;
	if (obj->data)
		free(obj->data);
	if (obj->der.value)
		free(obj->der.value);
	free(obj);
}

int sc_pkcs15_add_df(struct sc_pkcs15_card *p15card,
		     int type, const sc_path_t *path,
		     const sc_file_t *file)
{
	struct sc_pkcs15_df *p = p15card->df_list, *newdf;

	newdf = (struct sc_pkcs15_df *) malloc(sizeof(struct sc_pkcs15_df));
	if (newdf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(newdf, 0, sizeof(struct sc_pkcs15_df));
	newdf->path = *path;
	newdf->type = type;
	if (file != NULL)
		sc_file_dup(&newdf->file, file);
	if (p15card->df_list == NULL) {
		p15card->df_list = newdf;
		return 0;
	}
	while (p->next != NULL)
 		p = p->next;
	p->next = newdf;
	newdf->prev = p;

	return 0;
}

void sc_pkcs15_remove_df(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_df *obj)
{
	if (obj->prev == NULL)
		p15card->df_list = obj->next;
	else
		obj->prev->next = obj->next;
	if (obj->next != NULL)
		obj->next->prev = obj->prev;
	if (obj->file)
		sc_file_free(obj->file);
	free(obj);
}

int sc_pkcs15_encode_df(struct sc_context *ctx,
			struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_df *df,
			u8 **buf_out, size_t *bufsize_out)
{
	u8 *buf = NULL, *tmp;
	size_t bufsize = 0, tmpsize;
	const struct sc_pkcs15_object *obj;
	int (* func)(struct sc_context *, const struct sc_pkcs15_object *obj,
		     u8 **buf, size_t *bufsize) = NULL;
	int r;

	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_encode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
	case SC_PKCS15_PUKDF_TRUSTED:
		func = sc_pkcs15_encode_pukdf_entry;
		break;
	case SC_PKCS15_CDF:
	case SC_PKCS15_CDF_TRUSTED:
	case SC_PKCS15_CDF_USEFUL:
		func = sc_pkcs15_encode_cdf_entry;
		break;
	case SC_PKCS15_DODF:
		func = sc_pkcs15_encode_dodf_entry;
		break;
	case SC_PKCS15_AODF:
		func = sc_pkcs15_encode_aodf_entry;
		break;
	}
	if (func == NULL) {
		sc_error(ctx, "unknown DF type: %d\n", df->type);
		*buf_out = NULL;
		*bufsize_out = 0;
		return 0;
	}
	for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
		if (obj->df != df)
			continue;
		r = func(ctx, obj, &tmp, &tmpsize);
		if (r) {
			free(buf);
			return r;
		}
		buf = (u8 *) realloc(buf, bufsize + tmpsize);
		memcpy(buf + bufsize, tmp, tmpsize);
		free(tmp);
		bufsize += tmpsize;
	}
	*buf_out = buf;
	*bufsize_out = bufsize;
	
	return 0;	
}

int sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card,
		       struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	u8 *buf;
        const u8 *p;
	size_t bufsize;
	int r;
	struct sc_pkcs15_object *obj = NULL;
	int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
		     const u8 **buf, size_t *bufsize) = NULL;

	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_decode_prkdf_entry;
		break;
	case SC_PKCS15_PUKDF:
		func = sc_pkcs15_decode_pukdf_entry;
		break;
	case SC_PKCS15_CDF:
	case SC_PKCS15_CDF_TRUSTED:
	case SC_PKCS15_CDF_USEFUL:
		func = sc_pkcs15_decode_cdf_entry;
		break;
	case SC_PKCS15_DODF:
		func = sc_pkcs15_decode_dodf_entry;
		break;
	case SC_PKCS15_AODF:
		func = sc_pkcs15_decode_aodf_entry;
		break;
	}
	if (func == NULL) {
		sc_error(ctx, "unknown DF type: %d\n", df->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (df->file != NULL)
		r = sc_pkcs15_read_file(p15card, &df->path,
					&buf, &bufsize, NULL);
	else
		r = sc_pkcs15_read_file(p15card, &df->path,
					&buf, &bufsize, &df->file);
	if (r < 0)
		return r;

	p = buf;
	do {
		const u8 *oldp;
		size_t obj_len;
		
		obj = (struct sc_pkcs15_object *) malloc(sizeof(struct sc_pkcs15_object));
		if (obj == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		memset(obj, 0, sizeof(struct sc_pkcs15_object));
		oldp = p;
		r = func(p15card, obj, &p, &bufsize);
		if (r) {
			free(obj);
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
				break;
			sc_perror(ctx, r, "Error decoding DF entry");
			goto ret;
		}
		obj_len = p - oldp;

		obj->der.value = (u8 *) malloc(obj_len);
		if (obj->der.value == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		memcpy(obj->der.value, oldp, obj_len);
		obj->der.len = obj_len;

		obj->df = df;
		r = sc_pkcs15_add_object(p15card, obj);
		if (r) {
			if (obj->data)
				free(obj->data);
			free(obj);
			sc_perror(ctx, r, "Error adding object");
			goto ret;
		}
	} while (bufsize && *p != 0x00);
ret:
	free(buf);
	return r;
}

int sc_pkcs15_read_file(struct sc_pkcs15_card *p15card,
			const struct sc_path *in_path,
			u8 **buf, size_t *buflen,
			struct sc_file **file_out)
{
	struct sc_file *file = NULL;
	struct sc_path tmp_path, *path = &tmp_path;
	u8	*data = NULL;
	size_t	len = 0, offset = 0;
	int	r = -1;

	assert(p15card != NULL && in_path != NULL && buf != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);

	if (in_path->type == SC_PATH_TYPE_FILE_ID)
	{
		/* in case of a FID prepend the application DF */
		memcpy(path, &p15card->file_app->path, sizeof(struct sc_path));
		sc_append_path(path, in_path);
		path->index = in_path->index;
		path->count = in_path->count;
	}
	else
		memcpy(path, in_path, sizeof(struct sc_path));
	
	if (p15card->opts.use_cache) {
		r = sc_pkcs15_read_cached_file(p15card, path, &data, &len);
	}
	if (r) {
		r = sc_lock(p15card->card);
		SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
		r = sc_select_file(p15card->card, path, &file);
		if (r) {
			sc_unlock(p15card->card);
			return r;
		}
		/* Handle the case where the ASN.1 Path object specified
		 * index and length values */
		if (path->count < 0) {
			len = file->size;
			offset = 0;
		} else {
			offset = path->index;
			len = path->count;
			/* Make sure we're within proper bounds */
			if (offset >= file->size
			 || offset + len >= file->size) {
				sc_unlock(p15card->card);
				return SC_ERROR_INVALID_ASN1_OBJECT;
			}
		}
		if (file_out != NULL)
			*file_out = file;
		else
			sc_file_free(file);
		data = (u8 *) malloc(len);
		if (data == NULL) {
			sc_unlock(p15card->card);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		r = sc_read_binary(p15card->card, offset, data, len, 0);
		if (r < 0) {
			sc_unlock(p15card->card);
			free(data);
			return r;
		}
		/* sc_read_binary may return less than requested */
		len = r;
		sc_unlock(p15card->card);
	}
	*buf = data;
	*buflen = len;
	return 0;
}

int sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1,
			 const struct sc_pkcs15_id *id2)
{
	assert(id1 != NULL && id2 != NULL);
	if (id1->len != id2->len)
		return 0;
	return memcmp(id1->value, id2->value, id1->len) == 0;
}

void sc_pkcs15_format_id(const char *str, struct sc_pkcs15_id *id)
{
	size_t len = sizeof(id->value);

	if (sc_hex_to_bin(str, id->value, &len) >= 0)
		id->len = len;
}

void sc_pkcs15_print_id(const struct sc_pkcs15_id *id)
{
	size_t i;

	for (i = 0; i < id->len; i++)
		printf("%02X", id->value[i]);
}

int sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out)
{
	out->len = sizeof(out->value);
	return sc_hex_to_bin(in, out->value, &out->len);
}
