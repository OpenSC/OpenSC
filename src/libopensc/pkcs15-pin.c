/*
 * sc-pkcs15-pin.c: PKCS#15 PIN functions
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
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int decode_pin_info(const u8 *buf,
			   int buflen, struct sc_pkcs15_pin_info *pin)
{
	const u8 *tag, *p = buf;
	int taglen, left = buflen;

	memset(pin, 0, sizeof(*pin));

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	sc_pkcs15_parse_common_object_attr(&pin->com_attr, tag, taglen);
	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	tag = sc_asn1_verify_tag(tag, taglen, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL || taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	if (taglen > SC_PKCS15_MAX_ID_SIZE)
		taglen = SC_PKCS15_MAX_ID_SIZE;
	memcpy(pin->auth_id.value, tag, taglen);
	pin->auth_id.len = taglen;

	p = sc_asn1_verify_tag(p, left, 0xA1, &left);	/* CONS */
	if (left == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	p = sc_asn1_verify_tag(p, left, 0x30, &left);
	if (left == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;

	tag = sc_asn1_skip_tag(&p, &left, 0x03, &taglen);
	if (taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	sc_asn1_decode_bit_string(tag, taglen, &pin->flags,
				  sizeof(pin->flags));

	tag = sc_asn1_skip_tag(&p, &left, 0x0A, &taglen);
	if (taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	pin->type = tag[0];

	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);
	if (taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	pin->min_length = tag[0];

	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);
	if (taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	pin->stored_length = tag[0];

	tag = sc_asn1_find_tag(p, left, 0x04, &taglen);
	if (taglen == 0)
		return SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND;
	pin->pad_char = tag[0];

	tag = sc_asn1_find_tag(p, left, 0x30, &taglen);
	if (taglen != 0) {
		tag = sc_asn1_find_tag(tag, taglen, 0x04, &taglen);
		if (taglen >= 0) {
			memcpy(pin->path.value, tag, taglen);
			pin->path.len = taglen;
		}
	}
	pin->magic = SC_PKCS15_PIN_MAGIC;

	return 0;
}

void sc_pkcs15_print_pin_info(const struct sc_pkcs15_pin_info *pin)
{
	char path[SC_MAX_PATH_SIZE * 2 + 1];
	int i;
	char *p;

	p = path;
	*p = 0;
	for (i = 0; i < pin->path.len; i++) {
		sprintf(p, "%02X", pin->path.value[i]);
		p += 2;
	}
	printf("PIN [%s]\n", pin->com_attr.label);
	printf("\tFlags     : %d\n", pin->com_attr.flags);
	printf("\tLength    : %d..%d\n", pin->min_length, pin->stored_length);
	printf("\tPad char  : ");
	sc_print_binary(stdout, &pin->pad_char, 1);
	printf("\n");
	printf("\tPath      : %s\n", path);
	printf("\tAuth ID   : ");
	sc_pkcs15_print_id(&pin->auth_id);
	printf("\n");
}

static int get_pins_from_file(struct sc_pkcs15_card *p15card,
			      struct sc_file *file)
{
	int r, taglen, left;
	const u8 *p, *tag;
	u8 buf[MAX_BUFFER_SIZE];

	r = sc_select_file(p15card->card, file, &file->path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(p15card->card, 0, buf, file->size);
	if (r < 0)
		return r;

	left = r;
	p = buf;
	while ((tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen)) != NULL) {
		if (p15card->pin_count >= SC_PKCS15_MAX_PINS)
			return SC_ERROR_TOO_MANY_OBJECTS;
		r = decode_pin_info(tag, taglen,
				    &p15card->pin_info[p15card->pin_count]);
		if (r)
			return r;

		p15card->pin_count++;
	}
	return 0;
}

int sc_pkcs15_enum_pins(struct sc_pkcs15_card *p15card)
{
	int r, i;
	struct sc_context *ctx = p15card->card->ctx;

	assert(p15card != NULL);
	SC_FUNC_CALLED(ctx);
	if (p15card->pin_count) {
		for (i = 0; i < p15card->pin_count; i++) {
			if (p15card->pin_info[i].magic != SC_PKCS15_PIN_MAGIC)
				break;
		}
		if (i == p15card->pin_count)
			return i;	/* Already enumerated */
	}
	for (i = 0; i < p15card->aodf_count; i++) {
		r = get_pins_from_file(p15card, &p15card->file_aodf[i]);
		SC_TEST_RET(ctx, r, "Failed to read PINs from AODF");
	}
	return p15card->pin_count;
}

int sc_pkcs15_verify_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *pincode, int pinlen)
{
	int r;
	struct sc_file file;
	struct sc_card *card;
	char pinbuf[SC_MAX_PIN_SIZE];

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;
	if (pinlen > pin->stored_length || pinlen < pin->min_length)
		return SC_ERROR_INVALID_PIN_LENGTH;
	card = p15card->card;
	r = sc_select_file(card, &file, &pin->path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;

	memset(pinbuf, pin->pad_char, pin->stored_length);
	memcpy(pinbuf, pincode, pinlen);
	r = sc_verify(card, pin->auth_id.value[0],
		      pinbuf, pin->stored_length, &pin->tries_left);
	memset(pinbuf, 0, pinlen);
	if (r)
		return r;

	return 0;
}

int sc_pkcs15_change_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 char *oldpin,
			 int oldpinlen, char *newpin, int newpinlen)
{
	int r;
	struct sc_file file;
	struct sc_card *card;
	u8 pinbuf[SC_MAX_PIN_SIZE * 2];

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;
	if ((oldpinlen > pin->stored_length)
	    || (newpinlen > pin->stored_length))
		return SC_ERROR_INVALID_ARGUMENTS;
	if ((oldpinlen < pin->min_length) || (newpinlen < pin->min_length))
		return SC_ERROR_INVALID_ARGUMENTS;
	card = p15card->card;
	r = sc_select_file(card, &file, &pin->path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;

	memset(pinbuf, pin->pad_char, pin->stored_length * 2);
	memcpy(pinbuf, oldpin, oldpinlen);
	memcpy(pinbuf + pin->stored_length, newpin, newpinlen);
	r = sc_change_reference_data(card, pin->auth_id.value[0], pinbuf,
				     pin->stored_length, pinbuf+pin->stored_length,
				     pin->stored_length, &pin->tries_left);
	memset(pinbuf, 0, pin->stored_length * 2);
	return r;
}

int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *card,
				  const struct sc_pkcs15_id *id,
				  struct sc_pkcs15_pin_info **pin_out)
{
	int r, i;
	
	r = sc_pkcs15_enum_pins(card);
	if (r < 0)
		return r;
	for (i = 0; i < card->pin_count; i++) {
		struct sc_pkcs15_pin_info *pin = &card->pin_info[i];
		if (sc_pkcs15_compare_id(&pin->auth_id, id) == 1) {
			*pin_out = pin;
			return 0;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}
