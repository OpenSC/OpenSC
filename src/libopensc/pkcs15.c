/*
 * sc-pkcs15.c: PKCS#15 general functions
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

#include "opensc.h"
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

void parse_tokeninfo(struct sc_pkcs15_card *card, const u8 * buf, int buflen)
{
	int i, r;
	u8 serial[128];
	int serial_len = sizeof(serial);
	u8 mnfid[128];
	int mnfid_len = sizeof(mnfid);
	int flags_len = sizeof(card->flags);

	struct sc_asn1_struct asn1_tokeninfo[] = {
		{ "version",        SC_ASN1_INTEGER,      ASN1_INTEGER, 0, &card->version },
		{ "serialNumber",   SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, serial, &serial_len },
		{ "manufacturerID", SC_ASN1_UTF8STRING,   ASN1_UTF8STRING, SC_ASN1_OPTIONAL, mnfid, &mnfid_len },
		{ "label",	    SC_ASN1_UTF8STRING,   SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL },
		{ "tokenflags",	    SC_ASN1_BIT_STRING,   ASN1_BIT_STRING, 0, &card->flags, &flags_len },
		{ "seInfo",	    SC_ASN1_SEQUENCE,	  SC_ASN1_CONS | ASN1_SEQUENCE, SC_ASN1_OPTIONAL, NULL },
		{ "recordInfo",	    SC_ASN1_STRUCT,       SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL },
		{ "supportedAlgorithms", SC_ASN1_STRUCT,  SC_ASN1_CONS | SC_ASN1_CTX | 2, SC_ASN1_OPTIONAL, NULL },
		{ NULL }
	};

	buf = sc_asn1_verify_tag(buf, buflen, 0x30, &buflen);	/* SEQUENCE */
	if (buf == NULL) {
		error(card->card->ctx, "invalid EF(TokenInfo)\n");
		goto err;
	}
	r = sc_asn1_parse(card->card->ctx, asn1_tokeninfo, buf, buflen, NULL, NULL);
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
			card->manufacturer_id = strdup(mnfid);
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

static int parse_dir(const u8 * buf, int buflen, struct sc_pkcs15_card *card)
{
	const u8 *aidref = "\xA0\x00\x00\x00\x63PKCS-15";
	const int aidref_len = 12;
	int r;
	u8 aid[128], label[128], path[128];
	int aid_len = sizeof(aid), label_len = sizeof(label),
	    path_len = sizeof(path);
	
	struct sc_asn1_struct asn1_ddo[] = {
		{ "oid",	 SC_ASN1_OBJECT, ASN1_OBJECT, 0, NULL },
		{ "odfPath",	   SC_ASN1_PATH, SC_ASN1_CONS | ASN1_SEQUENCE, SC_ASN1_OPTIONAL, &card->file_odf.path },
		{ "tokenInfoPath", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, &card->file_tokeninfo.path },
		{ "unusedPath",    SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL },
		{ NULL }
	};
	struct sc_asn1_struct asn1_dir[] = {
		{ "aid",   SC_ASN1_OCTET_STRING, SC_ASN1_APP | 15, 0, aid, &aid_len },
		{ "label", SC_ASN1_UTF8STRING,   SC_ASN1_APP | 16, SC_ASN1_OPTIONAL, label, &label_len },
		{ "path",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 17, 0, path, &path_len },
		{ "ddo",   SC_ASN1_STRUCT,       SC_ASN1_APP | 19 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_ddo },
		{ NULL }
	};

	buf = sc_asn1_verify_tag(buf, buflen, 0x61, &buflen);
	if (buf == NULL) {
		error(card->card->ctx, "No [APPLICATION 1] tag in EF(DIR)\n");
		return -1;
	}
	r = sc_asn1_parse(card->card->ctx, asn1_dir, buf, buflen, NULL, NULL);
	if (r) {
		error(card->card->ctx, "EF(DIR) parsing failed: %s\n",
		      sc_strerror(r));
		return r;
	}
	if (aid_len != aidref_len || memcmp(aidref, aid, aid_len) != 0) {
		error(card->card->ctx, "AID in EF(DIR) is invalid\n");
		return -1;
	}
	if (asn1_dir[1].flags & SC_ASN1_PRESENT)
		card->label = strdup(label);
	else
		card->label = strdup("(unknown)");
	memcpy(card->file_app.path.value, path, path_len);
	card->file_app.path.len = path_len;	
	
	return 0;
}

static int parse_odf(const u8 * buf, int buflen, struct sc_pkcs15_card *card)
{
	const u8 *p = buf;
	int r, left = buflen;
	struct sc_path path;
	struct sc_asn1_struct asn1_obj_or_path[] = {
		{ "path", SC_ASN1_PATH, SC_ASN1_CONS | SC_ASN1_SEQUENCE, 0, &path },
		{ NULL }
	};
	struct sc_asn1_struct asn1_odf[] = {
		{ "privateKeys",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, asn1_obj_or_path },
		{ "certificates",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, 0, asn1_obj_or_path },
		{ "trustedCertificates", SC_ASN1_STRUCT, SC_ASN1_CTX | 5 | SC_ASN1_CONS, 0, asn1_obj_or_path },
		{ "dataObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 7 | SC_ASN1_CONS, 0, asn1_obj_or_path },
		{ "authObjects",	 SC_ASN1_STRUCT, SC_ASN1_CTX | 8 | SC_ASN1_CONS, 0, asn1_obj_or_path },
		{ NULL }
	};
	
	while (left > 0) {
		r = sc_asn1_parse_choice(card->card->ctx, asn1_odf, p, left, &p, &left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r < 0)
			return r;
		switch (r) {
		case 0:
			card->file_prkdf.path = path;
			break;
		case 1:
		case 2:
			if (card->cdf_count == SC_PKCS15_MAX_CDFS) {
				error(card->card->ctx, "too many CDFs on card\n");
				break;
			}
			card->file_cdf[card->cdf_count].path = path;
			card->cdf_count++;
			break;
		case 3:
			card->file_dodf.path = path;
			break;
		case 4:
			if (card->aodf_count == SC_PKCS15_MAX_AODFS) {
				error(card->card->ctx, "too many AODFs on card\n");
				break;
			}
			card->file_aodf[card->aodf_count].path = path;
			card->aodf_count++;
			break;
		}
	}
	return 0;
}

static const struct sc_pkcs15_defaults * find_defaults(u8 *dir, int dirlen)
{
	int i = 0;
	const struct sc_pkcs15_defaults *match = NULL;

	while (sc_card_table[i].atr != NULL) {
		u8 defdir[128];
		int len = sizeof(defdir);
		const struct sc_pkcs15_defaults *def = &sc_pkcs15_card_table[i];
		const char *dirp = def->ef_dir_dump;
		i++;

		if (dirp == NULL)
			break;
		if (sc_hex_to_bin(dirp, defdir, &len))
			continue;
		if (memcmp(dir, defdir, len) != 0)
			continue;
		match = def;
		break;
	}
	return match;
}

int sc_pkcs15_init(struct sc_card *card,
		   struct sc_pkcs15_card **p15card_out)
{
	unsigned char buf[MAX_BUFFER_SIZE];
	int err, len;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_path tmppath;
	const struct sc_pkcs15_defaults *defaults = NULL;

	assert(card != NULL && p15card_out != NULL);
	p15card = malloc(sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(p15card, 0, sizeof(struct sc_pkcs15_card));
	p15card->card = card;

	memcpy(tmppath.value, "\x2F\x00", 2);
	tmppath.len = 2;
	err = sc_select_file(card, &p15card->file_dir, &tmppath,
			     SC_SELECT_FILE_BY_PATH);
	if (err)
		goto error;
	err = sc_read_binary(card, 0, buf, p15card->file_dir.size);
	if (err < 0)
		goto error;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_CARD_NOT_FOUND;
		goto error;
	}
	len = err;
	if (parse_dir(buf, len, p15card)) {
		err = SC_ERROR_PKCS15_CARD_NOT_FOUND;
		goto error;
	}
	if (p15card->card->ctx->use_cache)
		defaults = find_defaults(buf, err);
	if (defaults == NULL) {
		if (p15card->file_odf.path.len == 0) {
			tmppath = p15card->file_app.path;
			memcpy(tmppath.value + tmppath.len, "\x50\x31", 2);
			tmppath.len += 2;
		} else
			tmppath = p15card->file_odf.path;
		err = sc_select_file(card, &p15card->file_odf, &tmppath,
				     SC_SELECT_FILE_BY_PATH);
		if (err)
			goto error;
		err = sc_read_binary(card, 0, buf, p15card->file_odf.size);
		if (err < 0)
			goto error;
		if (err < 2) {
			err = SC_ERROR_PKCS15_CARD_NOT_FOUND;
			goto error;
		}
		len = err;
		if (parse_odf(buf, len, p15card)) {
			err = SC_ERROR_PKCS15_CARD_NOT_FOUND;
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
	err = sc_select_file(card, &p15card->file_tokeninfo, &tmppath,
			     SC_SELECT_FILE_BY_PATH);
	if (err)
		goto error;
	err = sc_read_binary(card, 0, buf, p15card->file_tokeninfo.size);
	if (err < 0)
		goto error;
	if (err <= 2) {
		err = SC_ERROR_PKCS15_CARD_NOT_FOUND;
		goto error;
	}
	parse_tokeninfo(p15card, buf, err);
	*p15card_out = p15card;
	return 0;
error:
	free(p15card);
	return err;
}

int sc_pkcs15_destroy(struct sc_pkcs15_card *p15card)
{
	free(p15card->label);
	free(p15card->serial_number);
	free(p15card->manufacturer_id);
	free(p15card);
	return 0;
}

int sc_pkcs15_parse_common_object_attr(struct sc_pkcs15_common_obj_attr *attr,
				       const u8 * buf, int buflen)
{
	int taglen;
	const u8 *tag;

	tag = sc_asn1_find_tag(buf, buflen, 0x0C, &taglen);	/* UTF8STRING */
	if (tag != NULL && taglen < SC_PKCS15_MAX_LABEL_SIZE) {
		memcpy(attr->label, tag, taglen);
		attr->label[taglen] = 0;
	} else
		attr->label[0] = 0;
	tag = sc_asn1_find_tag(buf, buflen, 0x03, &taglen);	/* BIT STRING */
	if (tag != NULL) {
		if (sc_asn1_decode_bit_string(buf, buflen, &attr->flags,
					      sizeof(attr->flags)) < 0)
			attr->flags = 0;
	} else
		attr->flags = 0;
	tag = sc_asn1_find_tag(buf, buflen, 0x04, &taglen);	/* OCTET STRING */
	if (tag != NULL) {
		memcpy(attr->auth_id.value, tag, taglen);
		attr->auth_id.len = taglen;
	} else
		attr->auth_id.len = 0;

	/* FIXME: parse rest */
	attr->user_consent = 0;

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
