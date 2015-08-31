/*
 * sec.c: Cryptography and security (ISO7816-8) functions
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "internal.h"

int sc_decipher(sc_card_t *card,
		const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
	int r;

	assert(card != NULL && crgram != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (card->ops->decipher == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->decipher(card, crgram, crgram_len, out, outlen);
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

int sc_compute_signature(sc_card_t *card,
			 const u8 * data, size_t datalen,
			 u8 * out, size_t outlen)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (card->ops->compute_signature == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->compute_signature(card, data, datalen, out, outlen);
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

int sc_set_security_env(sc_card_t *card,
			const sc_security_env_t *env,
			int se_num)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (card->ops->set_security_env == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->set_security_env(card, env, se_num);
        SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

int sc_restore_security_env(sc_card_t *card, int se_num)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (card->ops->restore_security_env == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->restore_security_env(card, se_num);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

int sc_verify(sc_card_t *card, unsigned int type, int ref, 
	      const u8 *pin, size_t pinlen, int *tries_left)
{
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = type;
	data.pin_reference = ref;
	data.pin1.data = pin;
	data.pin1.len = pinlen;

	return sc_pin_cmd(card, &data, tries_left);
}

int sc_logout(sc_card_t *card)
{
	if (card->ops->logout == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return card->ops->logout(card);
}

int sc_change_reference_data(sc_card_t *card, unsigned int type,
			     int ref, const u8 *old, size_t oldlen,
			     const u8 *newref, size_t newlen,
			     int *tries_left)
{
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;
	data.pin_type = type;
	data.pin_reference = ref;
	data.pin1.data = old;
	data.pin1.len = oldlen;
	data.pin2.data = newref;
	data.pin2.len = newlen;

	return sc_pin_cmd(card, &data, tries_left);
}

int sc_reset_retry_counter(sc_card_t *card, unsigned int type, int ref,
			   const u8 *puk, size_t puklen, const u8 *newref,
			   size_t newlen)
{
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_UNBLOCK;
	data.pin_type = type;
	data.pin_reference = ref;
	data.pin1.data = puk;
	data.pin1.len = puklen;
	data.pin2.data = newref;
	data.pin2.len = newlen;

	return sc_pin_cmd(card, &data, NULL);
}

/*
 * This is the new style pin command, which takes care of all PIN
 * operations.
 * If a PIN was given by the application, the card driver should
 * send this PIN to the card. If no PIN was given, the driver should
 * ask the reader to obtain the pin(s) via the pin pad
 */
int sc_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
		int *tries_left)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (card->ops->pin_cmd) {
		r = card->ops->pin_cmd(card, data, tries_left);
	} else if (!(data->flags & SC_PIN_CMD_USE_PINPAD)) {
		/* Card driver doesn't support new style pin_cmd, fall
		 * back to old interface */

		r = SC_ERROR_NOT_SUPPORTED;
		switch (data->cmd) {
		case SC_PIN_CMD_VERIFY:
			if (card->ops->verify != NULL)
				r = card->ops->verify(card,
					data->pin_type,
					data->pin_reference,
					data->pin1.data,
					(size_t) data->pin1.len,
					tries_left);
			break;
		case SC_PIN_CMD_CHANGE:
			if (card->ops->change_reference_data != NULL)
				r = card->ops->change_reference_data(card,
					data->pin_type,
					data->pin_reference,
					data->pin1.data,
					(size_t) data->pin1.len,
					data->pin2.data,
					(size_t) data->pin2.len,
					tries_left);
			break;
		case SC_PIN_CMD_UNBLOCK:
			if (card->ops->reset_retry_counter != NULL)
				r = card->ops->reset_retry_counter(card,
					data->pin_type,
					data->pin_reference,
					data->pin1.data,
					(size_t) data->pin1.len,
					data->pin2.data,
					(size_t) data->pin2.len);
			break;
		}
		if (r == SC_ERROR_NOT_SUPPORTED)
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unsupported PIN operation (%d)",
					data->cmd);
	} else {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Use of pin pad not supported by card driver");
		r = SC_ERROR_NOT_SUPPORTED;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

/*
 * This function will copy a PIN, convert and pad it as required
 *
 * Note about the SC_PIN_ENCODING_GLP encoding:
 * PIN buffers are allways 16 nibbles (8 bytes) and look like this:
 *   0x2 + len + pin_in_BCD + paddingnibbles
 * in which the paddingnibble = 0xF
 * E.g. if PIN = 12345, then sbuf = {0x24, 0x12, 0x34, 0x5F, 0xFF, 0xFF, 0xFF, 0xFF}
 * E.g. if PIN = 123456789012, then sbuf = {0x2C, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0xFF}
 * Reference: Global Platform - Card Specification - version 2.0.1' - April 7, 2000
 */
int sc_build_pin(u8 *buf, size_t buflen, struct sc_pin_cmd_pin *pin, int pad)
{
	size_t i = 0, j, pin_len = pin->len;

	if (pin->max_length && pin_len > pin->max_length)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (pin->encoding == SC_PIN_ENCODING_GLP) {
		while (pin_len > 0 && pin->data[pin_len - 1] == 0xFF)
			pin_len--;
		if (pin_len > 12)
			return SC_ERROR_INVALID_ARGUMENTS;
		for (i = 0; i < pin_len; i++) {
			if (pin->data[i] < '0' || pin->data[i] > '9')
				return SC_ERROR_INVALID_ARGUMENTS;
		}
		buf[0] = 0x20 | pin_len;
		buf++;
		buflen--;
	}

	/* PIN given by application, encode if required */
	if (pin->encoding == SC_PIN_ENCODING_ASCII) {
		if (pin_len > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(buf, pin->data, pin_len);
		i = pin_len;
	} else if (pin->encoding == SC_PIN_ENCODING_BCD || pin->encoding == SC_PIN_ENCODING_GLP) {
		if (pin_len > 2 * buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		for (i = j = 0; j < pin_len; j++) {
			buf[i] <<= 4;
			buf[i] |= pin->data[j] & 0xf;
			if (j & 1)
				i++;
		}
		if (j & 1) {
			buf[i] <<= 4;
			buf[i] |= pin->pad_char & 0xf;
			i++;
		}
	}

	/* Pad to maximum PIN length if requested */
	if (pad || pin->encoding == SC_PIN_ENCODING_GLP) {
		size_t pad_length = pin->pad_length;
		u8     pad_char   = pin->encoding == SC_PIN_ENCODING_GLP ? 0xFF : pin->pad_char;

		if (pin->encoding == SC_PIN_ENCODING_BCD)
			pad_length >>= 1;
		if (pin->encoding == SC_PIN_ENCODING_GLP)
			pad_length = 8;

		if (pad_length > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;

		if (pad_length && i < pad_length) {
			memset(buf + i, pad_char, pad_length - i);
			i = pad_length;
		}
	}

	return i;
}
