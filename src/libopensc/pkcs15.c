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

#include "sc.h"
#include "sc-pkcs15.h"
#include "sc-asn1.h"
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

static int extract_path(const u8 * buf, int buflen, struct sc_path *path)
{
	const u8 *tag;
	int taglen;

	tag = sc_asn1_verify_tag(buf, buflen, 0x30, &taglen);
	if (tag == NULL)
		return -1;
	tag = sc_asn1_verify_tag(tag, taglen, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		return -1;
	memcpy(path->value, tag, taglen);
	path->len = taglen;

	return 0;
}

void parse_tokeninfo(struct sc_pkcs15_card *card, const u8 * buf, int buflen)
{
	const u8 *tag, *p = buf;
	int i, taglen, left = buflen;

	p = sc_asn1_verify_tag(buf, buflen, 0x30, &left);	/* SEQUENCE */
	if (p == NULL)
		goto err;
	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);	/* INTEGER */
	if (tag == NULL)
		goto err;
	card->version = tag[0] + 1;
	tag = sc_asn1_skip_tag(&p, &left, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		goto err;
	card->serial_number = malloc(taglen * 2 + 1);
	card->serial_number[0] = 0;
	for (i = 0; i < taglen; i++) {
		char byte[3];

		sprintf(byte, "%02X", tag[i]);
		strcat(card->serial_number, byte);
	}
	tag = sc_asn1_skip_tag(&p, &left, 0x0C, &taglen);	/* UTF8 STRING */
	if (tag == NULL)
		goto err;
	card->manufacturer_id = malloc(taglen + 1);
	memcpy(card->manufacturer_id, tag, taglen);
	card->manufacturer_id[taglen] = 0;
	tag = sc_asn1_skip_tag(&p, &left, 0x80, &taglen);	/* Label */
	if (tag != NULL) {	/* skip this tag */
	}
	tag = sc_asn1_skip_tag(&p, &left, 0x03, &taglen);	/* BIT STRING */
	if (tag == NULL)
		goto err;
	sc_asn1_decode_bit_string(tag, taglen, &card->flags,
				  sizeof(card->flags));
	tag = sc_asn1_find_tag(p, left, 0xA2, &taglen);	/* supportedAlgo */
	if (tag == NULL)
		goto err;
	p = sc_asn1_skip_tag(&tag, &taglen, 0x30, &left);	/* SEQUENCE */
	if (p == NULL)
		goto err;
	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);	/* INTEGER */
	if (tag == NULL)
		goto err;
	card->alg_info[0].reference = tag[0];
	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);	/* INTEGER */
	if (tag == NULL)
		goto err;
	card->alg_info[0].algorithm = tag[0];
	tag = sc_asn1_find_tag(p, left, 0x03, &taglen); /* BIT STRING */ ;
	if (tag == NULL)
		goto err;
	sc_asn1_decode_bit_string(tag, taglen,
				  &card->alg_info[0].supported_operations,
				  sizeof(card->alg_info[0].
					 supported_operations));

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
	const u8 *tag;
	int taglen;
	const char *aid = "\xA0\x00\x00\x00\x63PKCS-15";
	const int aidlen = 12;

	buf = sc_asn1_verify_tag(buf, buflen, 0x61, &buflen);
	if (buf == NULL)
		return -1;

	tag = sc_asn1_skip_tag(&buf, &buflen, 0x4F, &taglen);
	if (taglen != aidlen || memcmp(aid, tag, aidlen) != 0)
		return -1;

	tag = sc_asn1_skip_tag(&buf, &buflen, 0x50, &taglen);
	if (taglen > 0) {
		card->label = malloc(taglen + 1);
		if (card->label != NULL) {
			memcpy(card->label, tag, taglen);
			card->label[taglen] = 0;
		}
	} else
		card->label = strdup("(unknown)");
	tag = sc_asn1_skip_tag(&buf, &buflen, 0x51, &taglen);
	if (tag == NULL)
		return -1;
	memcpy(card->file_app.path.value, tag, taglen);
	card->file_app.path.len = taglen;
	tag = sc_asn1_skip_tag(&buf, &buflen, 0x73, &taglen);
	if (taglen > 2) {
		/* FIXME: process DDO */
	}
	return 0;
}

static int parse_odf(const u8 * buf, int buflen, struct sc_pkcs15_card *card)
{
	const u8 *tag;
	int taglen;

	/* authObjects */
	if ((tag = sc_asn1_find_tag(buf, buflen, 0xA8, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_aodf.path))
		return -1;
	/* CDF #1 -- Card holder certificates */
	if ((tag = sc_asn1_find_tag(buf, buflen, 0xA4, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_cdf1.path))
		return -1;
	/* CDF #2 -- New certificates */
	tag += taglen;
	taglen += 2;
	if ((tag = sc_asn1_verify_tag(tag, taglen, 0xA4, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_cdf2.path))
		return -1;
	/* CDF #3 -- Trusted CA certificates */
	if ((tag = sc_asn1_find_tag(buf, buflen, 0xA5, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_cdf3.path))
		return -1;
	/* PrKDF */
	if ((tag = sc_asn1_find_tag(buf, buflen, 0xA0, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_prkdf.path))
		return -1;
	/* DODF */
	if ((tag = sc_asn1_find_tag(buf, buflen, 0xA7, &taglen)) == NULL)
		return -1;
	if (extract_path(tag, taglen, &card->file_dodf.path))
		return -1;
	return 0;
}

int sc_pkcs15_init(struct sc_card *card,
		   struct sc_pkcs15_card **p15card_out)
{
	unsigned char buf[MAX_BUFFER_SIZE];
	int err, len;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_path tmppath;

	assert(card != NULL && p15card_out != NULL);
	p15card = malloc(sizeof(struct sc_pkcs15_card));
	if (p15card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(p15card, 0, sizeof(struct sc_pkcs15_card));
	p15card->card = card;

	if (card->defaults != NULL && card->defaults->pkcs15_defaults_func != NULL) {
		card->defaults->pkcs15_defaults_func(p15card);
		err = sc_select_file(card, &p15card->file_tokeninfo,
				     &p15card->file_tokeninfo.path,
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
	}

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
	memcpy(&tmppath, &p15card->file_app.path, sizeof(struct sc_path));
	err = sc_select_file(card, &p15card->file_app, &p15card->file_app.path,
			     SC_SELECT_FILE_BY_PATH);
	if (err)
		goto error;
	memcpy(tmppath.value + tmppath.len, "\x50\x31", 2);
	tmppath.len += 2;
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
	tmppath.len -= 2;
	memcpy(tmppath.value + tmppath.len, "\x50\x32", 2);
	tmppath.len += 2;
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
	attr->auth_id.len = 0;
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
