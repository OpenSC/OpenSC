/*
 * pkcs15-pin.c: PKCS #15 PIN functions
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
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const struct sc_asn1_entry c_asn1_com_ao_attr[] = {
	{ "authId",       SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_pin_attr[] = {
	{ "pinFlags",	  SC_ASN1_BIT_FIELD, ASN1_BIT_STRING, 0, NULL },
	{ "pinType",      SC_ASN1_ENUMERATED, ASN1_ENUMERATED, 0, NULL },
	{ "minLength",    SC_ASN1_INTEGER, ASN1_INTEGER, 0, NULL },
	{ "storedLength", SC_ASN1_INTEGER, ASN1_INTEGER, 0, NULL },
	{ "maxLength",    SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
	{ "pinReference", SC_ASN1_INTEGER, SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL },
	{ "padChar",      SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, SC_ASN1_OPTIONAL, NULL },
	{ "lastPinChange",SC_ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME, SC_ASN1_OPTIONAL, NULL },
	{ "path",         SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_type_pin_attr[] = {
	{ "pinAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_pin[] = {
	{ "pin", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

int sc_pkcs15_decode_aodf_entry(struct sc_pkcs15_card *p15card,
				struct sc_pkcs15_object *obj,
				const u8 ** buf, size_t *buflen)
{
        struct sc_context *ctx = p15card->card->ctx;
        struct sc_pkcs15_pin_info info;
	int r;
	size_t flags_len = sizeof(info.flags);
        size_t padchar_len = 1;
	struct sc_asn1_entry asn1_com_ao_attr[2], asn1_pin_attr[10], asn1_type_pin_attr[2];
	struct sc_asn1_entry asn1_pin[2];
	struct sc_asn1_pkcs15_object pin_obj = { obj, asn1_com_ao_attr, NULL, asn1_type_pin_attr };
        sc_copy_asn1_entry(c_asn1_pin, asn1_pin);
        sc_copy_asn1_entry(c_asn1_type_pin_attr, asn1_type_pin_attr);
        sc_copy_asn1_entry(c_asn1_pin_attr, asn1_pin_attr);
        sc_copy_asn1_entry(c_asn1_com_ao_attr, asn1_com_ao_attr);

	sc_format_asn1_entry(asn1_pin + 0, &pin_obj, NULL, 0);

	sc_format_asn1_entry(asn1_type_pin_attr + 0, asn1_pin_attr, NULL, 0);

	sc_format_asn1_entry(asn1_pin_attr + 0, &info.flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_pin_attr + 1, &info.type, NULL, 0);
	sc_format_asn1_entry(asn1_pin_attr + 2, &info.min_length, NULL, 0);
	sc_format_asn1_entry(asn1_pin_attr + 3, &info.stored_length, NULL, 0);
	sc_format_asn1_entry(asn1_pin_attr + 4, &info.max_length, NULL, 0);
	sc_format_asn1_entry(asn1_pin_attr + 5, &info.reference, NULL, 0);
	sc_format_asn1_entry(asn1_pin_attr + 6, &info.pad_char, &padchar_len, 0);
        /* We don't support lastPinChange yet. */
	sc_format_asn1_entry(asn1_pin_attr + 8, &info.path, NULL, 0);

	sc_format_asn1_entry(asn1_com_ao_attr + 0, &info.auth_id, NULL, 0);

        /* Fill in defaults */
        memset(&info, 0, sizeof(info));
	info.reference = 0;

	r = sc_asn1_decode(ctx, asn1_pin, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, r, "ASN.1 decoding failed");
	info.magic = SC_PKCS15_PIN_MAGIC;
	obj->type = SC_PKCS15_TYPE_AUTH_PIN;
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_OUT_OF_MEMORY);
	if (info.max_length == 0) {
		if (p15card->card->max_pin_len != 0)
			info.max_length = p15card->card->max_pin_len;
		else if (info.stored_length != 0)
			info.max_length = info.type != SC_PKCS15_PIN_TYPE_BCD ?
				info.stored_length : 2 * info.stored_length;
		else
			info.max_length = 8; /* shouldn't happen */
	}
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_aodf_entry(struct sc_context *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_ao_attr[2], asn1_pin_attr[10], asn1_type_pin_attr[2];
	struct sc_asn1_entry asn1_pin[2];
	struct sc_pkcs15_pin_info *pin =
                (struct sc_pkcs15_pin_info *) obj->data;
	struct sc_asn1_pkcs15_object pin_obj = { (struct sc_pkcs15_object *) obj,
						 asn1_com_ao_attr, NULL,
				   		 asn1_type_pin_attr };
	int r;
	size_t flags_len;
        size_t padchar_len = 1;

	sc_copy_asn1_entry(c_asn1_pin, asn1_pin);
        sc_copy_asn1_entry(c_asn1_type_pin_attr, asn1_type_pin_attr);
        sc_copy_asn1_entry(c_asn1_pin_attr, asn1_pin_attr);
        sc_copy_asn1_entry(c_asn1_com_ao_attr, asn1_com_ao_attr);

	sc_format_asn1_entry(asn1_pin + 0, &pin_obj, NULL, 1);

	sc_format_asn1_entry(asn1_type_pin_attr + 0, asn1_pin_attr, NULL, 1);

	flags_len = sizeof(pin->flags);
	sc_format_asn1_entry(asn1_pin_attr + 0, &pin->flags, &flags_len, 1);
	sc_format_asn1_entry(asn1_pin_attr + 1, &pin->type, NULL, 1);
	sc_format_asn1_entry(asn1_pin_attr + 2, &pin->min_length, NULL, 1);
	sc_format_asn1_entry(asn1_pin_attr + 3, &pin->stored_length, NULL, 1);
        if (pin->reference >= 0)
		sc_format_asn1_entry(asn1_pin_attr + 5, &pin->reference, NULL, 1);
	/* FIXME: check if pad_char present */
	sc_format_asn1_entry(asn1_pin_attr + 6, &pin->pad_char, &padchar_len, 1);
	sc_format_asn1_entry(asn1_pin_attr + 8, &pin->path, NULL, 1);

	sc_format_asn1_entry(asn1_com_ao_attr + 0, &pin->auth_id, NULL, 1);

        assert(pin->magic == SC_PKCS15_PIN_MAGIC);
	r = sc_asn1_encode(ctx, asn1_pin, buf, buflen);

	return r;
}

/*
 * Verify a PIN.
 *
 * If the code given to us has zero length, this means we
 * should ask the card reader to obtain the PIN from the
 * reader's PIN pad
 */
int sc_pkcs15_verify_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *pincode, size_t pinlen)
{
	int r;
	struct sc_card *card;
	struct sc_pin_cmd_data args;

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;

	/* prevent buffer overflow from hostile card */
	if (pin->max_length > SC_MAX_PIN_SIZE)
		return SC_ERROR_BUFFER_TOO_SMALL;

	/* If application gave us a PIN, make sure it's within
	 * the valid range */
	if (pinlen && (pinlen > pin->max_length || pinlen < pin->min_length))
		return SC_ERROR_INVALID_PIN_LENGTH;

	card = p15card->card;
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = sc_select_file(card, &pin->path, NULL);
	if (r) {
		sc_unlock(card);
		return r;
	}

	/* Initialize arguments */
	memset(&args, 0, sizeof(args));
	args.cmd = SC_PIN_CMD_VERIFY;
	args.pin_type = SC_AC_CHV;
	args.pin_reference = pin->reference;
	args.pin1.min_length = pin->min_length;
	args.pin1.max_length = pin->max_length;
	args.pin1.pad_char = pin->pad_char;

	if (pin->flags & SC_PKCS15_PIN_FLAG_NEEDS_PADDING)
		args.flags |= SC_PIN_CMD_NEED_PADDING;

	if (pinlen != 0) {
		/* Good old-fashioned PIN verification */
		args.pin1.data = pincode;
		args.pin1.len = pinlen;
	} else {
		/* Use the reader's PIN PAD */
		/* XXX need some sort of internationalization here */
		args.flags |= SC_PIN_CMD_USE_PINPAD;
		if (pin->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			args.pin1.prompt = "Please enter SO PIN";
		else
			args.pin1.prompt = "Please enter PIN";
	}

	r = sc_pin_cmd(card, &args, &pin->tries_left);

	sc_unlock(card);
	if (r)
		return r;

	return 0;
}

/*
 * Change a PIN.
 * FIXME: Edit this to use the new sc_pin_cmd call just as
 * above.
 */
int sc_pkcs15_change_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *oldpin, size_t oldpinlen,
			 const u8 *newpin, size_t newpinlen)
{
	int r;
	struct sc_card *card;
	u8 pinbuf[SC_MAX_PIN_SIZE * 2];

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;

	/* pin change with pin pad reader not yet supported */
	if ((p15card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) &&
		(oldpin == NULL || newpin == NULL || oldpinlen == 0 || newpinlen == 0))
			return SC_ERROR_NOT_SUPPORTED;

	if ((oldpinlen > pin->max_length)
	    || (newpinlen > pin->max_length))
		return SC_ERROR_INVALID_PIN_LENGTH;
	if ((oldpinlen < pin->min_length) || (newpinlen < pin->min_length))
		return SC_ERROR_INVALID_PIN_LENGTH;

	card = p15card->card;
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = sc_select_file(card, &pin->path, NULL);
	if (r) {
		sc_unlock(card);
		return r;
	}
	memset(pinbuf, pin->pad_char, pin->max_length * 2);
	memcpy(pinbuf, oldpin, oldpinlen);
	memcpy(pinbuf + pin->max_length, newpin, newpinlen);

	r = sc_change_reference_data(card, SC_AC_CHV, pin->reference, pinbuf,
				     pin->max_length, pinbuf+pin->max_length,
				     pin->max_length, &pin->tries_left);
	memset(pinbuf, 0, pin->max_length * 2);
	sc_unlock(card);
	return r;
}

/*
 * Unblock a PIN.
 */
int sc_pkcs15_unblock_pin(struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *puk, size_t puklen,
			 const u8 *newpin, size_t newpinlen)
{
	int r;
	struct sc_card *card;

	assert(p15card != NULL);
	if (pin->magic != SC_PKCS15_PIN_MAGIC)
		return SC_ERROR_OBJECT_NOT_VALID;

	/* pin change with pin pad reader not yet supported */
	if ((p15card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) &&
		(newpin == NULL || newpinlen == 0))
			return SC_ERROR_NOT_SUPPORTED;

	if (newpinlen > pin->max_length)
		return SC_ERROR_INVALID_PIN_LENGTH;
	if (newpinlen < pin->min_length)
		return SC_ERROR_INVALID_PIN_LENGTH;

	card = p15card->card;
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	r = sc_select_file(card, &pin->path, NULL);
	if (r) {
		sc_unlock(card);
		return r;
	}

        r = sc_reset_retry_counter (card, SC_AC_CHV, pin->reference,
				puk, puklen, newpin, newpinlen);
	sc_unlock(card);
	return r;
}
