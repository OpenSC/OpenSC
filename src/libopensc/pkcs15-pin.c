/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#include "sc.h"
#include "sc-pkcs15.h"
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
	printf("PIN number %d: %s, path %s, pad char 0x%02X\n",
	       pin->auth_id.value[0], pin->com_attr.label,
	       path, pin->pad_char);
}

int sc_pkcs15_enum_pins(struct sc_pkcs15_card *p15card)
{
	int r, i;
	u8 buf[MAX_BUFFER_SIZE];
	const u8 *tag, *p;
	int taglen, buflen;

	assert(p15card != NULL);

	r = sc_select_file(p15card->card, &p15card->file_aodf,
			   &p15card->file_aodf.path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	r = sc_read_binary(p15card->card, 0, buf, p15card->file_aodf.size);
	if (r < 0)
		return r;
	buflen = r;
	p = buf;
	i = 0;
	p15card->pin_count = 0;
	while ((tag = sc_asn1_skip_tag(&p, &buflen, 0x30, &taglen)) != NULL) {

		r = decode_pin_info(tag, taglen,
				    &p15card->pin_info[p15card->
						       pin_count]);
		if (r)
			break;
		p15card->pin_count++;
		if (p15card->pin_count >= SC_PKCS15_MAX_PINS)
			break;
	}
	return p15card->pin_count;
}

int sc_pkcs15_verify_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 char *pincode, int pinlen)
{
	int r;
	struct sc_file file;
	struct sc_apdu apdu;
	struct sc_card *card;
	char pinbuf[SC_MAX_PIN_SIZE];
	char resp[MAX_BUFFER_SIZE];

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;
	if (pinlen > pin->stored_length || pinlen < pin->min_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	card = p15card->card;
	r = sc_select_file(card, &file, &pin->path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;

	sc_format_apdu(p15card->card, &apdu, SC_APDU_CASE_3_SHORT,
		       0x20, 0, pin->auth_id.value[0]);
	apdu.lc = pin->stored_length;
	apdu.data = pinbuf;
	apdu.datalen = pin->stored_length;
	apdu.resp = resp;
	apdu.resplen = 2;
	memset(pinbuf, pin->pad_char, pin->stored_length);

	memcpy(pinbuf, pincode, pinlen);
	r = sc_transmit_apdu(card, &apdu);
	memset(pinbuf, 0, pinlen);

	if (r)
		return r;
	if (apdu.resplen == 2) {
		if (apdu.resp[0] == 0x90 && apdu.resp[1] == 0x00)
			return 0;
		if (apdu.resp[0] == 0x63 && (apdu.resp[1] & 0xF0) == 0xC0) {
			pin->tries_left = apdu.resp[1] & 0x0F;
			return SC_ERROR_PIN_CODE_INCORRECT;
		}
	}
	return -1;
}

int sc_pkcs15_change_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 char *oldpin,
			 int oldpinlen, char *newpin, int newpinlen)
{
	int r;
	struct sc_file file;
	struct sc_apdu apdu;
	struct sc_card *card;
	char pinbuf[SC_MAX_PIN_SIZE * 2];
	char resp[MAX_BUFFER_SIZE];

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

	sc_format_apdu(p15card->card, &apdu, SC_APDU_CASE_3_SHORT,
		       0x24, 0, pin->auth_id.value[0]);
	apdu.lc = pin->stored_length * 2;
	apdu.data = pinbuf;
	apdu.datalen = pin->stored_length * 2;
	apdu.resp = resp;
	apdu.resplen = 2;
	memset(pinbuf, pin->pad_char, pin->stored_length * 2);

	memcpy(pinbuf, oldpin, oldpinlen);
	memcpy(pinbuf + pin->stored_length, newpin, newpinlen);
	r = sc_transmit_apdu(card, &apdu);
	memset(pinbuf, 0, pin->stored_length * 2);

	if (r)
		return r;
	if (apdu.resplen == 2) {
		if (apdu.resp[0] == 0x90 && apdu.resp[1] == 0x00)
			return 0;
		if (apdu.resp[0] == 0x63 && (apdu.resp[1] & 0xF0) == 0xC0) {
			pin->tries_left = apdu.resp[1] & 0x0F;
			return SC_ERROR_PIN_CODE_INCORRECT;
		}
	}
	return -1;
}
