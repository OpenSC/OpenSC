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
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

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
	{ "tokenflags",	    SC_ASN1_BIT_STRING,   ASN1_BIT_STRING, 0, NULL },
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
	int i, r;
	u8 serial[128];
	size_t serial_len = sizeof(serial);
	u8 mnfid[128];
	size_t mnfid_len = sizeof(mnfid);
	u8 label[128];
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
		error(card->card->ctx, "ASN.1 parsing failed: %s\n", sc_strerror(r));
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
	int i, r;
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
		for (i = 0; card->serial_number[i] != 0; i += 2) {
			int c;
			if (sscanf(&card->serial_number[i], "%02X", &c) != 1)
				return SC_ERROR_INVALID_ARGUMENTS;
			serial[i/2] = c & 0xFF;
			serial_len++;
		}
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
		flags_len = _sc_count_bit_string_size(&card->flags, sizeof(card->flags));
		sc_format_asn1_entry(asn1_toki + 4, &card->flags, &flags_len, 1);
	}
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_tokeninfo, buf, buflen);
	if (r) {
		error(ctx, "sc_asn1_encode() failed: %s\n", sc_strerror(r));
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

static const u8 *pkcs15_aid = (const u8 *) "\xA0\x00\x00\x00\x63PKCS-15";
static const size_t pkcs15_aid_len = 12;

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
		error(p15card->card->ctx, "DDO parsing failed: %s\n",
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
		error(ctx, "sc_asn1_encode() failed: %s\n",
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
		error(ctx, "No DF's found.\n");
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
			error(ctx, "Unsupported DF type.\n");
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

	assert(sc_card_valid(card) && p15card_out != NULL);
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, 1);
	p15card = sc_pkcs15_card_new();
	if (p15card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	p15card->card = card;

	/* FIXME: parse config file */
	p15card->opts.use_cache = 1;

	err = sc_lock(card);
	if (err) {
		error(ctx, "sc_lock() failed: %s\n", sc_strerror(err));
		goto error;
	}
	
	if (card->app_count < 0) {
		err = sc_enum_apps(card);
		if (err < 0 && err != SC_ERROR_FILE_NOT_FOUND) {
			error(ctx, "unable to enumerate apps: %s\n", sc_strerror(err));
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
		
		info = sc_find_app_by_aid(card, pkcs15_aid, pkcs15_aid_len);
		if (info != NULL) {
			if (info->path.len)
				p15card->file_app->path = info->path;
			if (info->ddo != NULL)
				parse_ddo(p15card, info->ddo, info->ddo_len);
		}
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
		error(card->ctx, "Unable to parse ODF\n");
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

	*p15card_out = p15card;
	sc_unlock(card);
	return 0;
error:
	sc_pkcs15_card_free(p15card);
	sc_unlock(card);
	SC_FUNC_RETURN(ctx, 1, err);
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

static int compare_obj_id(struct sc_pkcs15_object *obj, void *arg)
{
	void *data = obj->data;
	const struct sc_pkcs15_id *id = (const struct sc_pkcs15_id *) arg;
	
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
	}
	return 0;
}

static int find_by_id(struct sc_pkcs15_card *p15card,
		      int type, const struct sc_pkcs15_id *id,
		      struct sc_pkcs15_object **out)
{
	int r;
	
	r = sc_pkcs15_get_objects_cond(p15card, type, compare_obj_id, (void *) id, out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
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

static int compare_flags(struct sc_pkcs15_object *obj, void *arg)
{
	struct sc_pkcs15_pin_info *pin;
	unsigned int	*match = (unsigned int *) arg;

	assert (obj->type == SC_PKCS15_TYPE_AUTH_PIN);
	pin = (struct sc_pkcs15_pin_info *) obj->data;
	return (pin->flags & match[0]) == match[1];
}

int sc_pkcs15_find_so_pin(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_object **out)
{
	unsigned int	match[2];
	int r;
	
	/* The PIN flags are masked with the first word and
	 * compared to the second word. */
	match[0] = SC_PKCS15_PIN_FLAG_SO_PIN;
	match[1] = SC_PKCS15_PIN_FLAG_SO_PIN;

	r = sc_pkcs15_get_objects_cond(p15card,
			SC_PKCS15_TYPE_AUTH_PIN, compare_flags,
			match, out, 1);
	if (r < 0)
		return r;
	if (r == 0)
		return SC_ERROR_OBJECT_NOT_FOUND;
	return 0;
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
	case SC_PKCS15_AODF:
		func = sc_pkcs15_encode_aodf_entry;
		break;
	}
	if (func == NULL) {
		error(ctx, "unknown DF type: %d\n", df->type);
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
	case SC_PKCS15_AODF:
		func = sc_pkcs15_decode_aodf_entry;
		break;
	}
	if (func == NULL) {
		error(ctx, "unknown DF type: %d\n", df->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (df->file != NULL)
		r = sc_pkcs15_read_file(p15card, &df->path,
					&buf, &bufsize, NULL);
	else
		r = sc_pkcs15_read_file(p15card, &df->path,
					&buf, &bufsize, &df->file);
	p = buf;
	do {
		obj = (struct sc_pkcs15_object *) malloc(sizeof(struct sc_pkcs15_object));
		if (obj == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto ret;
		}
		memset(obj, 0, sizeof(struct sc_pkcs15_object));
		r = func(p15card, obj, &p, &bufsize);
		if (r) {
			free(obj);
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
				break;
			sc_perror(ctx, r, "Error decoding DF entry");
			goto ret;
		}
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
			const struct sc_path *path,
			u8 **buf, size_t *buflen,
			struct sc_file **file_out)
{
	struct sc_file *file;
	u8	*data = NULL;
	size_t	len = 0;
	int	r = -1;

	assert(p15card != NULL && path != NULL && buf != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);
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
		len = file->size;
		if (file_out != NULL)
			*file_out = file;
		else
			sc_file_free(file);
		data = (u8 *) malloc(len);
		if (data == NULL) {
			sc_unlock(p15card->card);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		r = sc_read_binary(p15card->card, 0, data, len, 0);
		if (r < 0) {
			sc_unlock(p15card->card);
			free(data);
			return r;
		}
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
	int len = 0;
	u8 *p = id->value;

	while (*str) {
		int byte;
		
		if (sscanf(str, "%02X", &byte) != 1)
			break;
		*p++ = byte;
		len++;
		str += 2;
	}
	id->len = len;
	return;
}

void sc_pkcs15_print_id(const struct sc_pkcs15_id *id)
{
	int i;

	for (i = 0; i < id->len; i++)
		printf("%02X", id->value[i]);
}

int sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out)
{
	out->len = sizeof(out->value);
	return sc_hex_to_bin(in, out->value, &out->len);
}
