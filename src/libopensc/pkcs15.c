/*
 * pkcs15.c: PKCS #15 general functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-internal.h"
#include "opensc-pkcs15.h"
#include "sc-asn1.h"
#include "sc-log.h"
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

void parse_tokeninfo(struct sc_pkcs15_card *card, const u8 * buf, size_t buflen)
{
	int i, r;
	u8 serial[128];
	int serial_len = sizeof(serial);
	u8 mnfid[128];
	int mnfid_len = sizeof(mnfid);
	u8 label[128];
	int label_len = sizeof(label);
	int flags_len = sizeof(card->flags);
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
	card->serial_number = malloc(serial_len * 2 + 1);
	card->serial_number[0] = 0;
	for (i = 0; i < serial_len; i++) {
		char byte[3];

		sprintf(byte, "%02X", serial[i]);
		strcat(card->serial_number, byte);
	}
	if (card->manufacturer_id == NULL) {
		if (asn1_tokeninfo[2].flags & SC_ASN1_PRESENT)
			card->manufacturer_id = strdup((char *) mnfid);
		else
			card->manufacturer_id = strdup("(unknown)");
	}
	if (card->label == NULL) {
		if (asn1_tokeninfo[3].flags & SC_ASN1_PRESENT)
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
	int serial_len = 0;
	int mnfid_len;
	int label_len;
	int flags_len;
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
		struct sc_pkcs15_df *df = NULL;
		struct sc_file *file;
		
		r = sc_asn1_decode_choice(card->card->ctx, asn1_odf, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		df = &card->df[odf_indexes[r]];
		if (df->count == SC_PKCS15_MAX_DFS) {
			error(card->card->ctx, "too many DF's on card\n");
			continue;
		}
		file = sc_file_new();
		if (file == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		file->path = path;
		df->file[df->count] = file;
		df->count++;
	}
	return 0;
}

int sc_pkcs15_encode_odf(struct sc_context *ctx,
				struct sc_pkcs15_card *card,
				u8 **buf, size_t *buflen)
{
	struct sc_path path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path },
		{ NULL }
	};
	struct sc_asn1_entry *asn1_paths = NULL;
	struct sc_asn1_entry *asn1_odf = NULL;
	int df_count = 0, i, r, c = 0;
	const int nr_indexes = sizeof(odf_indexes)/sizeof(odf_indexes[0]);
	
	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++)
		df_count += card->df[i].count;
	if (df_count == 0) {
		error(ctx, "No DF's found.\n");
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	asn1_odf = malloc(sizeof(struct sc_asn1_entry) * (df_count + 1));
	if (asn1_odf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	asn1_paths = malloc(sizeof(struct sc_asn1_entry) * (df_count * 2));
	if (asn1_paths == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++) {
		struct sc_pkcs15_df *df = &card->df[i];
		int j, type = -1;
		
		if (!df->count)
			continue;
		for (j = 0; j < nr_indexes; j++)
			if (odf_indexes[j] == i) {
				type = j;
				break;
			}
		if (type == -1) {
			error(ctx, "Unsupported DF type.\n");
			continue;
		}
		for (j = 0; j < df->count; j++) {
			asn1_odf[c] = c_asn1_odf[type];
			sc_format_asn1_entry(asn1_odf + c, asn1_paths + 2*c, NULL, 1);
			sc_copy_asn1_entry(asn1_obj_or_path, asn1_paths + 2*c);
			sc_format_asn1_entry(asn1_paths + 2*c, &df->file[j]->path, NULL, 1);
			c++;
		}
	}
	asn1_odf[df_count].name = NULL;
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
	int i;
	
	p15card = malloc(sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return NULL;
	memset(p15card, 0, sizeof(struct sc_pkcs15_card));
	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++)
		p15card->df[i].type = i;
	p15card->magic = SC_PKCS15_CARD_MAGIC;
	return p15card;
}

void sc_pkcs15_card_free(struct sc_pkcs15_card *p15card)
{
	int i, j;
	
	assert(p15card != NULL && p15card->magic == SC_PKCS15_CARD_MAGIC);
	for (j = 0; j < SC_PKCS15_DF_TYPE_COUNT; j++)
		for (i = 0; i < p15card->df[j].count; i++) {
			struct sc_pkcs15_object *p;
			if (p15card->df[j].file[i])
				sc_file_free(p15card->df[j].file[i]);
			p = p15card->df[j].obj[i];
			while (p != NULL) {
				struct sc_pkcs15_object *p2 = p->next;
				if (p->data != NULL)
					free(p->data);
				free(p);
				p = p2;
			}
		}
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
	int err, len;
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
	err = sc_read_binary(card, 0, buf, p15card->file_tokeninfo->size, 0);
	if (err < 0)
		goto error;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto error;
	}
	parse_tokeninfo(p15card, buf, err);

	p15card->use_cache = 1;

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
	int count = 0, i, r;
	
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
		int j;
		struct sc_pkcs15_df *df = &p15card->df[dfs[i]];

		if (!df->enumerated) {
			r = sc_lock(p15card->card);
			SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
			for (j = 0; j < df->count; j++) {
				r = sc_pkcs15_parse_df(p15card, df, j);
				if (r < 0)
					break;
			}
			sc_unlock(p15card->card);
			SC_TEST_RET(p15card->card->ctx, r, "DF parsing failed");
			df->enumerated = 1;
		}
		for (j = 0; j < df->count; j++) {
			struct sc_pkcs15_object *obj = df->obj[j];
			
			for (; obj != NULL; obj = obj->next) {
				if (obj->type != type)
					continue;
				if (func != NULL && func(obj, func_arg) <= 0)
					continue;
				count++;
			}
		}
	}
	if (count == 0)
		return 0;
	if (ret_size <= 0)
		return count;
	count = 0;
	for (i = 0; dfs[i] != -1; i++) {
		int j;
		struct sc_pkcs15_df *df = &p15card->df[dfs[i]];

		for (j = 0; j < df->count && count < ret_size; j++) {
			struct sc_pkcs15_object *obj = df->obj[j];

			for (; obj != NULL; obj = obj->next) {
				if (count >= ret_size)
					break;
				if (obj->type != type)
					continue;
				if (func != NULL && func(obj, func_arg) <= 0)
					continue;
				ret[count] = obj;
				count++;
			}
		}
	}
	return count;
}

int sc_pkcs15_get_objects(struct sc_pkcs15_card *p15card, int type,
			  struct sc_pkcs15_object **ret, int ret_size)
{
        return sc_pkcs15_get_objects_cond(p15card, type, NULL, NULL, ret, ret_size);
}

static int compare_obj_id(struct sc_pkcs15_object *obj, void *arg)
{
	void *data = obj->data;
	const struct sc_pkcs15_id *id = arg;
	
	switch (obj->type) {
	case SC_PKCS15_TYPE_CERT_X509:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_cert_info *) data)->id, id);
	case SC_PKCS15_TYPE_PRKEY_RSA:
		return sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) data)->id, id);
	case SC_PKCS15_TYPE_PUBKEY_RSA:
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
	return find_by_id(p15card, SC_PKCS15_TYPE_CERT_X509, id, out);
}

int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_id *id,
			       struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_PRKEY_RSA, id, out);
}

int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *p15card,
			     const struct sc_pkcs15_id *id,
			     struct sc_pkcs15_object **out)
{
	return find_by_id(p15card, SC_PKCS15_TYPE_AUTH_PIN, id, out);
}

int sc_pkcs15_add_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df,
                         int file_nr, struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_object *p = df->obj[file_nr];

	obj->next = NULL;
	if (p == NULL) {
		df->obj[file_nr] = obj;
		return 0;
	}
	while (p->next != NULL)
 		p = p->next;
	p->next = obj;
        
	return 0;
}                       

int sc_pkcs15_encode_df(struct sc_context *ctx,
			struct sc_pkcs15_df *df,
			int file_no,
			u8 **buf_out, size_t *bufsize_out)
{
	u8 *buf = NULL, *tmp;
	size_t bufsize = 0, tmpsize;
	int r;
	const struct sc_pkcs15_object *obj = df->obj[file_no];
	int (* func)(struct sc_context *, const struct sc_pkcs15_object *obj,
		     u8 **buf, size_t *bufsize) = NULL;
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
#if 0
		return SC_ERROR_INVALID_ARGUMENTS;
#else
		*buf_out = NULL;
		*bufsize_out = 0;
		return 0;
#endif
	}
	while (obj != NULL) {
		r = func(ctx, obj, &tmp, &tmpsize);
		if (r) {
			free(buf);
			return r;
		}
		buf = realloc(buf, bufsize + tmpsize);
		memcpy(buf + bufsize, tmp, tmpsize);
		free(tmp);
		bufsize += tmpsize;
		obj = obj->next;
	}
	*buf_out = buf;
	*bufsize_out = bufsize;
	
	return 0;	
}

static int create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_path path;
	int r, i;
	
	path = file->path;
	if (path.len < 2) {
		error(card->ctx, "file path too small\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	i = card->ctx->log_errors;
	card->ctx->log_errors = 0;
	r = sc_select_file(card, &path, NULL);
	card->ctx->log_errors = 1;
	if (r == 0) {
		sc_unlock(card);
		return 0;	/* File already exists */
	}
	path.len -= 2;
	r = sc_select_file(card, &path, NULL);
	if (r) {
		sc_perror(card->ctx, r, "Unable to select parent DF");
		sc_unlock(card);
		return r;
	}
	file->id = (path.value[path.len] << 8) | (path.value[path.len+1] & 0xFF);
	r = sc_create_file(card, file);
	if (r) {
		sc_perror(card->ctx, r, "sc_create_file()");
		sc_unlock(card);
		return r;
	}
	r = sc_select_file(card, &file->path, NULL);
	sc_unlock(card);
	SC_TEST_RET(card->ctx, r, "Unable to select created file");

	return r;
}

static int create_and_update_file(struct sc_pkcs15_card *p15card,
				  struct sc_card *card,
				  struct sc_file *inf, const u8 *buf,
				  size_t bufsize)
{
	struct sc_file *file;
	int r;

	sc_file_dup(&file, inf);
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->size = inf->size + bufsize;
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = create_file(card, file);
	sc_file_free(file);
	if (r) {
		sc_unlock(card);
		return r;
	}
	r = sc_update_binary(card, 0, buf, bufsize, 0);
	sc_unlock(card);
	if (r < 0) {
		sc_perror(card->ctx, r, "sc_update_binary() failed");
		return r;
	}
	if (r != bufsize) {
		error(card->ctx, "tried to write %d bytes, only wrote %d bytes",
		      bufsize, r);
		return -1;
	}
	return 0;
}

int sc_pkcs15_create(struct sc_pkcs15_card *p15card, struct sc_card *card)
{
	int r, i;
	u8 *tokinf_buf = NULL, *odf_buf = NULL;
	size_t tokinf_size, odf_size;

	if (p15card->file_app == NULL || p15card->file_odf == NULL ||
	    p15card->file_tokeninfo == NULL) {
		error(card->ctx, "Not all of the necessary files have been supplied\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (card->ctx->debug)
		debug(card->ctx, "creating EF(DIR)\n");
	r = sc_pkcs15_create_dir(p15card, card);
	SC_TEST_RET(card->ctx, r, "Error creating EF(DIR)");
	r = sc_pkcs15_encode_tokeninfo(card->ctx, p15card, &tokinf_buf, &tokinf_size);
	if (r) {
		sc_perror(card->ctx, r, "Error encoding EF(TokenInfo)");
		goto err;
	}
	if (card->ctx->debug)
		debug(card->ctx, "creating EF(TokenInfo)\n");
	r = create_and_update_file(p15card, card, p15card->file_tokeninfo, tokinf_buf, tokinf_size);
	if (r) {
		sc_perror(card->ctx, r, "Error creating EF(TokenInfo)");
		goto err;
	}
	free(tokinf_buf);
	tokinf_buf = NULL;
	
	if (card->ctx->debug)
		debug(card->ctx, "creating EF(ODF)\n");
	r = sc_pkcs15_encode_odf(card->ctx, p15card, &odf_buf, &odf_size);
	if (r) {
		sc_perror(card->ctx, r, "Error encoding EF(ODF)");
		goto err;
	}
	r = create_and_update_file(p15card, card, p15card->file_odf, odf_buf, odf_size);
	if (r) {
		sc_perror(card->ctx, r, "Error creating EF(ODF)");
		goto err;
	}
	free(odf_buf);
	odf_buf = NULL;

	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++) {
		struct sc_pkcs15_df *df = &p15card->df[i];
		int file_no;
		u8 *buf;
		size_t bufsize;
		
		if (df->count == 0)
			continue;
		for (file_no = 0; file_no < df->count; file_no++) {
			r = sc_pkcs15_encode_df(card->ctx, df, file_no, &buf, &bufsize);
			if (r) {
				sc_perror(card->ctx, r, "Error encoding EF(xDF)");
				goto err;
			}
			if (card->ctx->debug)
				debug(card->ctx, "creating DF %d of type %d\n", file_no, i);
			r = create_and_update_file(p15card, card, df->file[file_no], buf, bufsize);
			free(buf);
			if (r) {
				sc_perror(card->ctx, r, "Error creating EF(TokenInfo)");
				goto err;
			}
		}
	}
err:
	if (tokinf_buf)
		free(tokinf_buf);
	if (odf_buf)
		free(odf_buf);
	return r;
}

int sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card,
		       struct sc_pkcs15_df *df, int file_nr)
{
	struct sc_context *ctx = p15card->card->ctx;
	u8 buf[2048], *bufptr = buf;
        const u8 *p = buf;
	size_t bufsize = sizeof(buf);
	int r, cached_file = 0;
	struct sc_path path = df->file[file_nr]->path;
	struct sc_pkcs15_object *obj = NULL;
	int (* func)(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
		     const u8 **buf, size_t *bufsize) = NULL;

	switch (df->type) {
	case SC_PKCS15_PRKDF:
		func = sc_pkcs15_decode_prkdf_entry;
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
	if (p15card->use_cache) {
		r = sc_pkcs15_read_cached_file(p15card, &path,
					       &bufptr, &bufsize);
		if (r == 0)
			cached_file = 1;
	}
	if (cached_file == 0) {
		struct sc_file *file = NULL;
		size_t file_size;

		r = sc_lock(p15card->card);
		SC_TEST_RET(ctx, r, "sc_lock() failed");
		r = sc_select_file(p15card->card, &path, &file);
		if (r) {
			sc_perror(ctx, r, "sc_select_file() failed");
			sc_unlock(p15card->card);
			return r;
		}
		file_size = file->size;
		sc_file_free(file);
		if (file_size > sizeof(buf)) {
			error(ctx, "Buffer too small to handle DF contents\n");
			sc_unlock(p15card->card);
			return SC_ERROR_INTERNAL;
		}
		r = sc_read_binary(p15card->card, 0, buf, file_size, 0);
		sc_unlock(p15card->card);
		if (r < 0)
			return r;
		bufsize = file_size;
	}
	do {
		obj = malloc(sizeof(struct sc_pkcs15_object));
		if (obj == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		memset(obj, 0, sizeof(sizeof(struct sc_pkcs15_object)));
		r = func(p15card, obj, &p, &bufsize);
		if (r) {
			free(obj);
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
				break;
			sc_perror(ctx, r, "Error decoding DF entry");
			return r;
		}
		r = sc_pkcs15_add_object(p15card, df, file_nr, obj);
		if (r) {
			if (obj->data)
				free(obj->data);
			free(obj);
			sc_perror(ctx, r, "Error adding object");
			return r;
		}
	} while (bufsize && *p != 0x00);
	
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
