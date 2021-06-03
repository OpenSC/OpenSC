/*
 * dir.c: Stuff for handling EF(DIR)
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"

struct app_entry {
	const u8 *aid;
	size_t aid_len;
	const char *desc;
};

static const struct app_entry apps[] = {
	{ (const u8 *) "\xA0\x00\x00\x00\x63PKCS-15", 12, "PKCS #15" },
	{ (const u8 *) "\xA0\x00\x00\x01\x77PKCS-15", 12, "Belgian eID" },
	{ (const u8 *) "\x44\x46\x20\x69\x73\x73\x75\x65\x72", 9, "Portugal eID" },
	{ (const u8 *) "\xE8\x28\xBD\x08\x0F\xA0\x00\x00\x01\x67\x45\x53\x49\x47\x4E", 15, "ESIGN"},
	{ (const u8 *) "\xE8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x10", 13, "CPx IAS"},
	{ (const u8 *) "\xE8\x28\xBD\x08\x0F\x80\x25\x00\x00\x01\xFF\x00\x20", 13, "CPx IAS CL"},
	{ (const u8 *) "\xE8\x28\xBD\x08\x0F\xD2\x50\x45\x43\x43\x2D\x65\x49\x44", 14, "ECC eID"},
	{ (const u8 *) "\xE8\x28\xBD\x08\x0F\xD2\x50\x47\x65\x6E\x65\x72\x69\x63", 14, "ECC Generic PKI"},
};

static const struct sc_asn1_entry c_asn1_dirrecord[] = {
	{ "aid",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 15, 0, NULL, NULL },
	{ "label", SC_ASN1_UTF8STRING,   SC_ASN1_APP | 16, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "path",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 17, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "ddo",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 19 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dir[] = {
	{ "dirRecord", SC_ASN1_STRUCT, SC_ASN1_APP | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


static int
parse_dir_record(sc_card_t *card, u8 ** buf, size_t *buflen, int rec_nr)
{
	struct sc_context *ctx = card->ctx;
	struct sc_asn1_entry asn1_dirrecord[5], asn1_dir[2];
	scconf_block *conf_block = NULL;
	sc_app_info_t *app = NULL;
	struct sc_aid aid;
	u8 label[128], path[128], ddo[128];
	size_t label_len = sizeof(label) - 1, path_len = sizeof(path), ddo_len = sizeof(ddo);
	int r;

	LOG_FUNC_CALLED(ctx);
	aid.len = sizeof(aid.value);

	memset(label, 0, sizeof(label));
	sc_copy_asn1_entry(c_asn1_dirrecord, asn1_dirrecord);
	sc_copy_asn1_entry(c_asn1_dir, asn1_dir);
	sc_format_asn1_entry(asn1_dir + 0, asn1_dirrecord, NULL, 0);
	sc_format_asn1_entry(asn1_dirrecord + 0, aid.value, &aid.len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 1, label, &label_len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 2, path, &path_len, 0);
	sc_format_asn1_entry(asn1_dirrecord + 3, ddo, &ddo_len, 0);

	r = sc_asn1_decode(ctx, asn1_dir, *buf, *buflen, (const u8 **) buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		LOG_FUNC_RETURN(ctx, r);
	LOG_TEST_RET(ctx, r, "EF(DIR) parsing failed");

	conf_block = sc_get_conf_block(ctx, "framework", "pkcs15", 1);
	if (conf_block)   {
		scconf_block **blocks = NULL;
		char aid_str[SC_MAX_AID_STRING_SIZE];
		int ignore_app = 0;

		sc_bin_to_hex(aid.value, aid.len, aid_str, sizeof(aid_str), 0);
		blocks = scconf_find_blocks(card->ctx->conf, conf_block, "application", aid_str);
		if (blocks)   {
			ignore_app = (blocks[0] && scconf_get_str(blocks[0], "disable", 0));
                        free(blocks);
		 }

		if (ignore_app)   {
			sc_log(ctx, "Application '%s' ignored", aid_str);
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
	}

	app = calloc(1, sizeof(struct sc_app_info));
	if (app == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(&app->aid, &aid, sizeof(struct sc_aid));

	if (asn1_dirrecord[1].flags & SC_ASN1_PRESENT)
		app->label = strdup((char *) label);
	else
		app->label = NULL;

	if (asn1_dirrecord[2].flags & SC_ASN1_PRESENT && path_len > 0) {
		/* application path present: ignore AID */
		if (path_len > SC_MAX_PATH_SIZE) {
			free(app->label);
			free(app);
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "Application path is too long.");
		}
		memcpy(app->path.value, path, path_len);
		app->path.len = path_len;
		app->path.type = SC_PATH_TYPE_PATH;
	}
	else {
		/* application path not present: use AID as application path */
		memcpy(app->path.value, aid.value, aid.len);
		app->path.len = aid.len;
		app->path.type = SC_PATH_TYPE_DF_NAME;
	}

	if (asn1_dirrecord[3].flags & SC_ASN1_PRESENT) {
		app->ddo.value = malloc(ddo_len);
		if (app->ddo.value == NULL) {
			free(app->label);
			free(app);
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate DDO value");
		}
		memcpy(app->ddo.value, ddo, ddo_len);
		app->ddo.len = ddo_len;
	} else {
		app->ddo.value = NULL;
		app->ddo.len = 0;
	}

	app->rec_nr = rec_nr;
	card->app[card->app_count] = app;
	card->app_count++;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int sc_enum_apps(sc_card_t *card)
{
	struct sc_context *ctx = card->ctx;
	sc_path_t path;
	int ef_structure;
	size_t file_size, jj;
	int r, ii, idx;
	struct sc_file *ef_dir = NULL;

	LOG_FUNC_CALLED(ctx);

	sc_free_apps(card);
	card->app_count = 0;

	sc_format_path("3F002F00", &path);
	r = sc_select_file(card, &path, &ef_dir);
	if (r < 0)
		sc_file_free(ef_dir);
	LOG_TEST_RET(ctx, r, "Cannot select EF.DIR file");

	if (ef_dir->type != SC_FILE_TYPE_WORKING_EF) {
		sc_file_free(ef_dir);
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_CARD, "EF(DIR) is not a working EF.");
	}

	ef_structure = ef_dir->ef_structure;
	file_size = ef_dir->size;
	sc_file_free(ef_dir);
	if (ef_structure == SC_FILE_EF_TRANSPARENT) {
		u8 *buf = NULL, *p;
		size_t bufsize;

		if (file_size == 0)
			LOG_FUNC_RETURN(ctx, 0);
		if (file_size > MAX_FILE_SIZE)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		buf = malloc(file_size);
		if (buf == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		p = buf;
		r = sc_read_binary(card, 0, buf, file_size, 0);
		if (r < 0) {
			free(buf);
			LOG_TEST_RET(ctx, r, "sc_read_binary() failed");
		}
		bufsize = r;
		while (bufsize > 0) {
			if (card->app_count == SC_MAX_CARD_APPS) {
				sc_log(ctx, "Too many applications on card");
				break;
			}
			r = parse_dir_record(card, &p, &bufsize, -1);
			if (r)
				break;
		}
		if (buf)
			free(buf);

	}
	else {	/* record structure */
		unsigned char buf[256], *p;
		unsigned int rec_nr;
		size_t rec_size;

		/* Arbitrary set '16' as maximal number of records to check out:
		 * to avoid endless loop because of some incomplete cards/drivers */
		for (rec_nr = 1; rec_nr < 16; rec_nr++) {
			r = sc_read_record(card, rec_nr, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
			if (r == SC_ERROR_RECORD_NOT_FOUND)
				break;
			LOG_TEST_RET(ctx, r, "read_record() failed");

			if (card->app_count == SC_MAX_CARD_APPS) {
				sc_log(ctx, "Too many applications on card");
				break;
			}

			rec_size = r;
			p = buf;
			parse_dir_record(card, &p, &rec_size, (int)rec_nr);
		}
	}

	/* Move known PKCS#15 applications to the head of the list */
	for (ii=0, idx=0; ii<card->app_count; ii++)   {
		for (jj=0; jj < sizeof(apps)/sizeof(apps[0]); jj++) {
			if (apps[jj].aid_len != card->app[ii]->aid.len)
				continue;
			if (memcmp(apps[jj].aid, card->app[ii]->aid.value, apps[jj].aid_len))
				continue;
			break;
		}

		if (ii != idx && jj < sizeof(apps)/sizeof(apps[0]))   {
			struct sc_app_info *tmp = card->app[idx];

			card->app[idx] = card->app[ii];
			card->app[ii] = tmp;
			idx++;
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

void sc_free_apps(sc_card_t *card)
{
	int	i;

	for (i = 0; i < card->app_count; i++) {
		free(card->app[i]->label);
		free(card->app[i]->ddo.value);
		free(card->app[i]);
	}
	card->app_count = -1;
}

static int encode_dir_record(sc_context_t *ctx, const sc_app_info_t *app,
			     u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_dirrecord[5], asn1_dir[2];
	sc_app_info_t   tapp = *app;
	int r;
	size_t label_len;

	sc_copy_asn1_entry(c_asn1_dirrecord, asn1_dirrecord);
	sc_copy_asn1_entry(c_asn1_dir, asn1_dir);
	sc_format_asn1_entry(asn1_dir + 0, asn1_dirrecord, NULL, 1);
	sc_format_asn1_entry(asn1_dirrecord + 0, (void *) tapp.aid.value, (void *) &tapp.aid.len, 1);
	if (tapp.label != NULL) {
		label_len = strlen(tapp.label);
		sc_format_asn1_entry(asn1_dirrecord + 1, tapp.label, &label_len, 1);
	}
	if (tapp.path.len)
		sc_format_asn1_entry(asn1_dirrecord + 2, (void *) tapp.path.value,
				     (void *) &tapp.path.len, 1);
	if (tapp.ddo.value != NULL && tapp.ddo.len)
		sc_format_asn1_entry(asn1_dirrecord + 3, (void *) tapp.ddo.value,
				     (void *) &tapp.ddo.len, 1);
	r = sc_asn1_encode(ctx, asn1_dir, buf, buflen);
	LOG_TEST_RET(ctx, r, "Encode DIR record error");

	return SC_SUCCESS;
}

static int update_transparent(sc_card_t *card, sc_file_t *file)
{
	u8 *rec, *buf = NULL, *tmp;
	size_t rec_size, buf_size = 0;
	int i, r;

	for (i = 0; i < card->app_count; i++) {
		r = encode_dir_record(card->ctx, card->app[i], &rec, &rec_size);
		if (r) {
			if (buf)
				free(buf);
			return r;
		}
		if (!rec_size)
			continue;
		tmp = (u8 *) realloc(buf, buf_size + rec_size);
		if (!tmp) {
			if (rec)
				free(rec);
			if (buf)
				free(buf);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		buf = tmp;
		memcpy(buf + buf_size, rec, rec_size);
		buf_size += rec_size;
		free(rec);
		rec=NULL;
	}
	if (file->size > buf_size) {
		tmp = (u8 *) realloc(buf, file->size);
		if (!tmp) {
			free(buf);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		buf = tmp;
		memset(buf + buf_size, 0, file->size - buf_size);
		buf_size = file->size;
	}
	r = sc_update_binary(card, 0, buf, buf_size, 0);
	free(buf);
	LOG_TEST_RET(card->ctx, r, "Unable to update EF(DIR)");

	return SC_SUCCESS;
}

static int update_single_record(sc_card_t *card, sc_app_info_t *app)
{
	u8 *rec;
	size_t rec_size;
	int r;

	r = encode_dir_record(card->ctx, app, &rec, &rec_size);
	if (r)
		return r;
	if (app->rec_nr > 0)
		r = sc_update_record(card, (unsigned int)app->rec_nr, rec, rec_size, SC_RECORD_BY_REC_NR);
	else if (app->rec_nr == 0) {
		/* create new record entry */
		r = sc_append_record(card, rec, rec_size, 0);
		if (r == SC_ERROR_NOT_SUPPORTED) {
			/* if the card doesn't support APPEND RECORD we try a
			 * UPDATE RECORD on the next unused record (and hope
			 * that there is a record with this index).
			 */
			int rec_nr = 0, i;
			for(i = 0; i < card->app_count; i++)
				if (card->app[i]->rec_nr > rec_nr)
					rec_nr = card->app[i]->rec_nr;
			rec_nr++;
			r = sc_update_record(card, (unsigned int)rec_nr, rec, rec_size, SC_RECORD_BY_REC_NR);
		}
	} else {
		sc_log(card->ctx, "invalid record number\n");
		r = SC_ERROR_INTERNAL;
	}
	free(rec);
	LOG_TEST_RET(card->ctx, r, "Unable to update EF(DIR) record");
	return 0;
}

static int update_records(sc_card_t *card)
{
	int i, r;

	for (i = 0; i < card->app_count; i++) {
		r = update_single_record(card, card->app[i]);
		if (r)
			return r;
	}
	return 0;
}

int sc_update_dir(sc_card_t *card, sc_app_info_t *app)
{
	sc_path_t path;
	sc_file_t *file;
	int r;

	sc_format_path("3F002F00", &path);

	r = sc_select_file(card, &path, &file);
	LOG_TEST_RET(card->ctx, r, "unable to select EF(DIR)");

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT)
		r = update_transparent(card, file);
	else if (app == NULL)
		r = update_records(card);
	else
		r = update_single_record(card, app);
	sc_file_free(file);
	return r;
}
