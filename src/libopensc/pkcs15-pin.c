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

#include "sc-internal.h"
#include "opensc-pkcs15.h"
#include "sc-asn1.h"
#include "sc-log.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int parse_pin_info(struct sc_context *ctx,
			  struct sc_pkcs15_pin_info *pin,
			  const u8 ** buf, int *buflen)
{
	int r;
	struct sc_asn1_struct asn1_com_ao_attr[] = {
		{ "authId",       SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, &pin->auth_id },
		{ NULL }
	};
	int flags_len = sizeof(pin->flags);
        int padchar_len = 1;
	struct sc_asn1_struct asn1_pin_attr[] = {
		{ "pinFlags",	  SC_ASN1_BIT_STRING, ASN1_BIT_STRING, 0, &pin->flags, &flags_len},
		{ "pinType",      SC_ASN1_ENUMERATED, ASN1_ENUMERATED, 0, &pin->type },
		{ "minLength",    SC_ASN1_INTEGER, ASN1_INTEGER, 0, &pin->min_length },
		{ "storedLength", SC_ASN1_INTEGER, ASN1_INTEGER, 0, &pin->stored_length },
		{ "maxLength",    SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
		{ "pinReference", SC_ASN1_INTEGER, SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, &pin->reference },
		{ "padChar",      SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, SC_ASN1_OPTIONAL, &pin->pad_char, &padchar_len },
		{ "lastPinChange",SC_ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME, SC_ASN1_OPTIONAL, NULL },
		{ "path",         SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, &pin->path },
		{ NULL }
	};
	struct sc_asn1_struct asn1_type_pin_attr[] = {
		{ "pinAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_pin_attr},
		{ NULL }
	};
	struct sc_pkcs15_object pin_obj = { &pin->com_attr, asn1_com_ao_attr, NULL,
					    asn1_type_pin_attr };
	struct sc_asn1_struct asn1_pin[] = {
		{ "pin", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, &pin_obj },
		{ NULL }
	};

        pin->reference = 0;

	memset(pin, 0, sizeof(*pin));

	r = sc_asn1_parse(ctx, asn1_pin, *buf, *buflen, buf, buflen);
        if (r == 0)
		pin->magic = SC_PKCS15_PIN_MAGIC;

	return r;
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
	printf("\tPad char  : 0x%02X", pin->pad_char);
	printf("\n");
	printf("\tPath      : %s\n", path);
	printf("\tAuth ID   : ");
	sc_pkcs15_print_id(&pin->auth_id);
	printf("\n");
}

static int get_pins_from_file(struct sc_pkcs15_card *card,
			      struct sc_file *file)
{
	int r, bytes_left;
	u8 buf[2048];
	const u8 *p = buf;

	r = sc_select_file(card->card, &file->path, file);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(card->card, 0, buf, file->size, 0);
	if (r < 0)
		return r;
	bytes_left = r;
	do {
		struct sc_pkcs15_pin_info tmp;

		r = parse_pin_info(card->card->ctx,
				   &tmp, &p, &bytes_left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r)
			return r;
		if (card->pin_count >= SC_PKCS15_MAX_CERTS)
			return SC_ERROR_TOO_MANY_OBJECTS;
                card->pin_info[card->pin_count] = tmp;
		card->pin_count++;
	} while (bytes_left);

	return 0;

}

int sc_pkcs15_enum_pins(struct sc_pkcs15_card *p15card)
{
	int r, i;
	struct sc_context *ctx = p15card->card->ctx;

	assert(p15card != NULL);
	SC_FUNC_CALLED(ctx, 1);
	if (p15card->pin_count) {
		for (i = 0; i < p15card->pin_count; i++) {
			if (p15card->pin_info[i].magic != SC_PKCS15_PIN_MAGIC)
				break;
		}
		if (i == p15card->pin_count)
			return i;	/* Already enumerated */
	}
	p15card->pin_count = 0;
	r = sc_lock(p15card->card);
	SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
	for (i = 0; i < p15card->aodf_count; i++) {
		r = get_pins_from_file(p15card, &p15card->file_aodf[i]);
		if (r != 0)
			break;
	}
	sc_unlock(p15card->card);
	if (r != 0)
		return r;
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
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = sc_select_file(card, &pin->path, &file);
	if (r) {
		sc_unlock(card);
		return r;
	}
	memset(pinbuf, pin->pad_char, pin->stored_length);
	memcpy(pinbuf, pincode, pinlen);
	r = sc_verify(card, pin->auth_id.value[0],
		      pinbuf, pin->stored_length, &pin->tries_left);
	memset(pinbuf, 0, pinlen);
	sc_unlock(card);
	if (r)
		return r;

	return 0;
}

int sc_pkcs15_change_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *oldpin, int oldpinlen,
			 const u8 *newpin, int newpinlen)
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
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = sc_select_file(card, &pin->path, &file);
	if (r) {
		sc_unlock(card);
		return r;
	}
	memset(pinbuf, pin->pad_char, pin->stored_length * 2);
	memcpy(pinbuf, oldpin, oldpinlen);
	memcpy(pinbuf + pin->stored_length, newpin, newpinlen);
	r = sc_change_reference_data(card, pin->auth_id.value[0], pinbuf,
				     pin->stored_length, pinbuf+pin->stored_length,
				     pin->stored_length, &pin->tries_left);
	memset(pinbuf, 0, pin->stored_length * 2);
	sc_unlock(card);
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
