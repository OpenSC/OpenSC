/*
 * pkcs15.c: PKCS#15 general functions
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
	struct sc_asn1_entry asn1_toki[9], asn1_tokeninfo[2];

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
		if (asn1_tokeninfo[2].flags & SC_ASN1_PRESENT)
			card->manufacturer_id = strdup((char *) mnfid);
		else
			card->manufacturer_id = strdup("(unknown)");
	}
	return;
err:
	if (card->serial_number == NULL)
		card->serial_number = strdup("(unknown)");
	if (card->manufacturer_id == NULL)
		card->manufacturer_id = strdup("(unknown)");
	return;
}

int encode_tokeninfo(struct sc_pkcs15_card *card, u8 ** buf, size_t *buflen)
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
		flags_len = sc_count_bit_string_size(&card->flags, sizeof(card->flags));
		sc_format_asn1_entry(asn1_toki + 4, &card->flags, &flags_len, 1);
	}
	sc_format_asn1_entry(asn1_tokeninfo, asn1_toki, NULL, 1);

	r = sc_asn1_encode(card->card->ctx, asn1_tokeninfo, buf, buflen);
	if (r) {
		error(card->card->ctx, "sc_asn1_encode() failed: %s\n", sc_strerror(r));
		return r;
	}
	return 0;
}

int sc_pkcs15_create_tokeninfo(struct sc_pkcs15_card *card)
{
	int r;
	u8 *buf;
	size_t buflen;
	char line[10240];
	
	r = encode_tokeninfo(card, &buf, &buflen);
	if (r) {
		error(card->card->ctx, "Error encoding EF(TokenInfo): %s\n", sc_strerror(r));
		return r;
	}
	sc_hex_dump(card->card->ctx, buf, buflen, line, sizeof(line));
	printf("%s\n", line);
	return 0;
}

static const struct sc_asn1_entry c_asn1_ddo[] = {
	{ "oid",	   SC_ASN1_OBJECT, ASN1_OBJECT, 0, NULL },
	{ "odfPath",	   SC_ASN1_PATH, SC_ASN1_CONS | ASN1_SEQUENCE, SC_ASN1_OPTIONAL, NULL },
	{ "tokenInfoPath", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL },
	{ "unusedPath",    SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_dirrecord[] = {
	{ "aid",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 15, 0, NULL },
	{ "label", SC_ASN1_UTF8STRING,   SC_ASN1_APP | 16, SC_ASN1_OPTIONAL, NULL },
	{ "path",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 17, 0, NULL },
	{ "ddo",   SC_ASN1_STRUCT,       SC_ASN1_APP | 19 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};
/* FIXME: this should be decoded elsewhere */
static const struct sc_asn1_entry c_asn1_dir[] = {
	{ "dirRecord", SC_ASN1_STRUCT, SC_ASN1_APP | 1 | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const u8 *aidref = (const u8 *) "\xA0\x00\x00\x00\x63PKCS-15";
static const int aidref_len = 12;

static int parse_dir(const u8 * buf, size_t buflen, struct sc_pkcs15_card *card)
{
	struct sc_asn1_entry asn1_ddo[5], asn1_dirrecord[5], asn1_dir[2];
	int r;
	u8 aid[128], label[128], path[128];
	int aid_len = sizeof(aid), label_len = sizeof(label),
	    path_len = sizeof(path);
	
	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);
	sc_copy_asn1_entry(c_asn1_dirrecord, asn1_dirrecord);
	sc_copy_asn1_entry(c_asn1_dir, asn1_dir);
	sc_format_asn1_entry(asn1_dir + 0, asn1_dirrecord, NULL, 0);
	sc_format_asn1_entry(asn1_dirrecord + 0, aid, &aid_len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 1, label, &label_len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 2, path, &path_len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 3, asn1_ddo, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 1, &card->file_odf.path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &card->file_tokeninfo.path, NULL, 0);
	
	r = sc_asn1_decode(card->card->ctx, asn1_dir, buf, buflen, NULL, NULL);
	if (r) {
		error(card->card->ctx, "EF(DIR) parsing failed: %s\n",
		      sc_strerror(r));
		return r;
	}
	if (aid_len != aidref_len || memcmp(aidref, aid, aid_len) != 0) {
		error(card->card->ctx, "AID in EF(DIR) is invalid\n");
		return -1;
	}
	if (asn1_dirrecord[1].flags & SC_ASN1_PRESENT)
		card->label = strdup((char *) label);
	else
		card->label = strdup("(unknown)");
	if (path_len > SC_MAX_PATH_SIZE)
		return -1;
	memcpy(card->file_app.path.value, path, path_len);
	card->file_app.path.len = path_len;	
	card->file_app.path.type = SC_PATH_TYPE_PATH;
	
	return 0;
}

static int encode_dir(struct sc_pkcs15_card *card, u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_ddo[5], asn1_dirrecord[5], asn1_dir[2];
	struct sc_context *ctx = card->card->ctx;
	int r;
	size_t label_len;
	
	sc_copy_asn1_entry(c_asn1_ddo, asn1_ddo);
	sc_copy_asn1_entry(c_asn1_dirrecord, asn1_dirrecord);
	sc_copy_asn1_entry(c_asn1_dir, asn1_dir);
	sc_format_asn1_entry(asn1_dir + 0, asn1_dirrecord, NULL, 1);
	sc_format_asn1_entry(asn1_dirrecord + 0, (void *) aidref, (void *) &aidref_len, 1);
	if (card->label != NULL) {
		label_len = strlen(card->label);
		sc_format_asn1_entry(asn1_dirrecord + 1, card->label, &label_len, 1);
	}
	if (card->file_app.path.len == 0) {
		error(ctx, "Application path not set.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_asn1_entry(asn1_dirrecord + 2, card->file_app.path.value,
			     &card->file_app.path.len, 1);
#if 0
	/* FIXME: encode DDO */
	sc_format_asn1_entry(asn1_dirrecord + 3, asn1_ddo, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 1, &card->file_odf.path, NULL, 0);
	sc_format_asn1_entry(asn1_ddo + 2, &card->file_tokeninfo.path, NULL, 0);
#endif
	r = sc_asn1_encode(ctx, asn1_dir, buf, buflen);
	if (r) {
		error(card->card->ctx, "sc_asn1_encode() failed: %s\n",
		      sc_strerror(r));
		return r;
	}
	return 0;
}



/* FIXME: This should be done using sc_update_binary(),
 * and be generally wiser */
int sc_pkcs15_create_dir(struct sc_pkcs15_card *p15card)
{
	struct sc_card *card = p15card->card;
	struct sc_path path;
	u8 *buf;
	size_t bufsize;
	int r;
	char line[10240];
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	SC_TEST_RET(card->ctx, r, "sc_select_file(MF) failed");
	r = encode_dir(p15card, &buf, &bufsize);
	SC_TEST_RET(card->ctx, r, "EF(DIR) encoding failed");
	sc_hex_dump(p15card->card->ctx, buf, bufsize, line, sizeof(line));
	free(buf);
	printf("%s", line);
	
	return 0;
}

static const struct sc_asn1_entry c_asn1_odf[] = {
	{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, NULL },
	{ "certificates",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, NULL },
	{ "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, NULL },
	{ "dataObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, NULL },
	{ "authObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const int odf_indexes[] = {
	SC_PKCS15_PRKDF,
	SC_PKCS15_CDF,
	SC_PKCS15_CDF_TRUSTED,
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
	struct sc_asn1_entry asn1_odf[6];
	
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
		file = malloc(sizeof(struct sc_file));
		if (file == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		memset(file, 0, sizeof(struct sc_file));
		file->path = path;
		df->file[df->count] = file;
		df->count++;
	}
	return 0;
}

static int encode_odf(struct sc_pkcs15_card *card, u8 **buf, size_t *buflen)
{
	struct sc_path path;
	struct sc_asn1_entry asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path },
	};
	struct sc_asn1_entry *asn1_paths = NULL;
	struct sc_asn1_entry *asn1_odf = NULL;
	int df_count = 0, i, r, c = 0;
	const int nr_indexes = sizeof(odf_indexes)/sizeof(odf_indexes[0]);
	
	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++)
		df_count += card->df[i].count;
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
			error(card->card->ctx, "Unsupported DF type.\n");
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
	r = sc_asn1_encode(card->card->ctx, asn1_odf, buf, buflen);
err:
	if (asn1_paths != NULL)
		free(asn1_paths);
	if (asn1_odf != NULL)
		free(asn1_odf);
	return r;
}

int sc_pkcs15_create_odf(struct sc_pkcs15_card *p15card)
{
	u8 *buf;
	size_t buflen;
	char line[10240];
	int r;
	
	r = encode_odf(p15card, &buf, &buflen);
	SC_TEST_RET(p15card->card->ctx, r, "ODF encoding failed");
	sc_hex_dump(p15card->card->ctx, buf, buflen, line, sizeof(line));
	printf("ODF:\n%s", line);
	return 0;
}

static const struct sc_pkcs15_defaults * find_defaults(u8 *dir, int dirlen)
{
	/* FIXME: CODEME */
	return NULL;
}

int sc_pkcs15_bind(struct sc_card *card,
		   struct sc_pkcs15_card **p15card_out)
{
	unsigned char buf[MAX_BUFFER_SIZE];
	int err, len;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_path tmppath;
	const struct sc_pkcs15_defaults *defaults = NULL;
	struct sc_context *ctx;
	struct sc_file file;

	assert(sc_card_valid(card) && p15card_out != NULL);
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, 1);
	p15card = malloc(sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(p15card, 0, sizeof(struct sc_pkcs15_card));
	p15card->card = card;

	sc_format_path("2F00", &tmppath);
	err = sc_lock(card);
	if (err) {
		error(ctx, "sc_lock() failed: %s\n", sc_strerror(err));
		goto error;
	}
	err = sc_select_file(card, &tmppath, &file);
	if (err) {
		error(ctx, "Error selecting EF(DIR): %s\n", sc_strerror(err));
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto error;
	}
	err = sc_read_binary(card, 0, buf, file.size, 0);
	if (err < 0) {
		error(ctx, "Error reading EF(DIR): %s\n", sc_strerror(err));
		goto error;
	}
	if (err <= 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		error(ctx, "Error reading EF(DIR): too few bytes read\n");
		goto error;
	}
	len = err;
	if (parse_dir(buf, len, p15card)) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		error(ctx, "Error parsing EF(DIR)\n");
		goto error;
	}
	if (p15card->use_cache)
		defaults = find_defaults(buf, err);
	if (defaults == NULL) {
		if (p15card->file_odf.path.len == 0) {
			tmppath = p15card->file_app.path;
			memcpy(tmppath.value + tmppath.len, "\x50\x31", 2);
			tmppath.len += 2;
		} else
			tmppath = p15card->file_odf.path;
		
		err = sc_select_file(card, &tmppath, &file);
		if (err) /* FIXME: finish writing error stuff */
			goto error;
		err = sc_read_binary(card, 0, buf, file.size, 0);
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
		if (p15card->file_tokeninfo.path.len == 0) {
			tmppath.len -= 2;
			memcpy(tmppath.value + tmppath.len, "\x50\x32", 2);
			tmppath.len += 2;
		} else
			tmppath = p15card->file_tokeninfo.path;
	} else {
		defaults->defaults_func(p15card, defaults->arg);
		tmppath = p15card->file_tokeninfo.path;
	}
	err = sc_select_file(card, &tmppath, &file);
	if (err)
		goto error;
	err = sc_read_binary(card, 0, buf, file.size, 0);
	if (err < 0)
		goto error;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto error;
	}
	parse_tokeninfo(p15card, buf, err);

	p15card->use_cache = card->ctx->use_cache;

	*p15card_out = p15card;
	sc_unlock(card);
	return 0;
error:
	free(p15card);
	sc_unlock(card);
	SC_FUNC_RETURN(ctx, 1, err);
}

int sc_pkcs15_detect(struct sc_card *card)
{
	int r;
	struct sc_path path;
	struct sc_file file;

	sc_format_path("NA0000063504B43532D3135", &path);
	r = sc_select_file(card, &path, &file);
	if (r != 0)
		return 0;
	return 1;
}

int sc_pkcs15_unbind(struct sc_pkcs15_card *p15card)
{
	int i, j;
	
	assert(p15card != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	for (j = 0; j < SC_PKCS15_DF_TYPE_COUNT; j++)
		for (i = 0; i < p15card->df[j].count; i++)
			if (p15card->df[j].file[i])
				free(p15card->df[j].file[i]);
	free(p15card->label);
	free(p15card->serial_number);
	free(p15card->manufacturer_id);
	free(p15card);
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
