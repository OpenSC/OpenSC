
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 */

#include "sc.h"
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

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
