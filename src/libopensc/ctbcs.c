/*
 * ctbcs.c: Extended CTBCS commands, used for pcsc and ct-api readers
 *
 * Copyright (C) 2002  Olaf Kirch <okir@suse.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "ctbcs.h"

static void
ctbcs_init_apdu(sc_apdu_t *apdu, int cse, int ins, int p1, int p2)
{
	memset(apdu, 0, sizeof(*apdu));
	apdu->cse = cse;
	apdu->cla = 0x20;
	apdu->ins = ins;
	apdu->p1  = p1;
	apdu->p2  = p2;

	apdu->control = 1;
}

static int
ctbcs_build_perform_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data, u8 *buf, size_t buflen)
{
	const char *prompt;
	size_t count = 0, j = 0, len;
	u8 control;

	if (!apdu || !data || !buf)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_PERFORM_VERIFICATION,
			CTBCS_P1_INTERFACE1,
			0);

	prompt = data->pin1.prompt;
	if (prompt && *prompt) {
		len = strlen(prompt);
		if (len > 255 || len + 2 > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[count++] = CTBCS_TAG_PROMPT;
		buf[count++] = (u8)len;
		memcpy(buf + count, prompt, len);
		count += len;
	}

	/* card apdu must be last in packet */
	if (!data->apdu)
		return SC_ERROR_INTERNAL;
	if (count + 12 > buflen)
		return SC_ERROR_BUFFER_TOO_SMALL;

	j = count;
	buf[j++] = CTBCS_TAG_VERIFY_CMD;
	buf[j++] = 0x00;

	/* Control byte - length of PIN, and encoding */
	control = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII)
		control |= CTBCS_PIN_CONTROL_ENCODE_ASCII;
	else if (data->pin1.encoding != SC_PIN_ENCODING_BCD)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (data->pin1.min_length == data->pin1.max_length)
		control |= (data->pin1.min_length & 0x1F) << CTBCS_PIN_CONTROL_LEN_SHIFT;
	buf[j++] = control;
	buf[j++] = (u8)(data->pin1.offset + 1); /* Looks like offset is 1-based in CTBCS */
	buf[j++] = data->apdu->cla;
	buf[j++] = data->apdu->ins;
	buf[j++] = data->apdu->p1;
	buf[j++] = data->apdu->p2;

	if (data->flags & SC_PIN_CMD_NEED_PADDING) {
		len = data->pin1.pad_length;
		if (len > 255 || 2 + j + len > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[j++] = (u8)len;
		memset(buf+j, data->pin1.pad_char, len);
		j += len;
	}

	if (j - count - 2 > 255)
		return SC_ERROR_BUFFER_TOO_SMALL;
	buf[count+1] = (u8)(j - count - 2);
	count = j;

	apdu->lc = apdu->datalen = count;
	apdu->data = buf;

	return 0;
}

static int
ctbcs_build_modify_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data, u8 *buf, size_t buflen)
{
	const char *prompt;
	size_t count = 0, j = 0, len;
	u8 control;

	if (!apdu || !data || !buf)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_MODIFY_VERIFICATION,
			CTBCS_P1_INTERFACE1,
			0);

	prompt = data->pin1.prompt;
	if (prompt && *prompt) {
		len = strlen(prompt);
		if (len > 255 || len + 2 > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[count++] = CTBCS_TAG_PROMPT;
		buf[count++] = (u8)len;
		memcpy(buf + count, prompt, len);
		count += len;
	}

	/* card apdu must be last in packet */
	if (!data->apdu)
		return SC_ERROR_INTERNAL;
	if (count + 12 > buflen)
		return SC_ERROR_BUFFER_TOO_SMALL;

	j = count;
	buf[j++] = CTBCS_TAG_VERIFY_CMD;
	buf[j++] = 0x00;

	/* Control byte - length of PIN, and encoding */
	control = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII)
		control |= CTBCS_PIN_CONTROL_ENCODE_ASCII;
	else if (data->pin1.encoding != SC_PIN_ENCODING_BCD)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (data->pin1.min_length == data->pin1.max_length)
		control |= (data->pin1.min_length & 0x1F) << CTBCS_PIN_CONTROL_LEN_SHIFT;
	buf[j++] = control;
	buf[j++] = (u8)(data->pin1.offset + 1); /* Looks like offset is 1-based in CTBCS */
	buf[j++] = (u8)(data->pin2.offset + 1);
	buf[j++] = data->apdu->cla;
	buf[j++] = data->apdu->ins;
	buf[j++] = data->apdu->p1;
	buf[j++] = data->apdu->p2;

	if (data->flags & SC_PIN_CMD_NEED_PADDING) {
		len = data->pin1.pad_length + data->pin2.pad_length;
		if (len > 255 || 2 + j + len > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[j++] = (u8)len;
		memset(buf+j, data->pin1.pad_char, len);
		j += len;
	}

	if (j - count - 2 > 255)
		return SC_ERROR_BUFFER_TOO_SMALL;
	buf[count+1] = (u8)(j - count - 2);
	count = j;

	apdu->lc = apdu->datalen = count;
	apdu->data = buf;

	return 0;
}

int
ctbcs_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	sc_card_t dummy_card, *card;
	sc_apdu_t apdu;
	struct sc_card_operations ops;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, s;

	if (!reader || !data)
		return SC_ERROR_INVALID_ARGUMENTS;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		r = ctbcs_build_perform_verification_apdu(&apdu, data, sbuf, sizeof(sbuf));
		if (r != SC_SUCCESS)
			return r;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		r = ctbcs_build_modify_verification_apdu(&apdu, data, sbuf, sizeof(sbuf));
		if (r != SC_SUCCESS)
			return r;
		break;
	default:
		sc_log(reader->ctx,  "Unknown PIN command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	memset(&ops, 0, sizeof(ops));
	memset(&dummy_card, 0, sizeof(dummy_card));
	dummy_card.reader = reader;
	dummy_card.ctx = reader->ctx;
	r = sc_mutex_create(reader->ctx, &dummy_card.mutex);
	if (r != SC_SUCCESS)
		return r;
	dummy_card.ops   = &ops;
	card = &dummy_card;

	r = sc_transmit_apdu(card, &apdu);
	s = sc_mutex_destroy(reader->ctx, card->mutex);
	if (s != SC_SUCCESS) {
		sc_log(reader->ctx,  "unable to destroy mutex\n");
		return s;
	}
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	/* Calling Function may expect SW1/SW2 in data-apdu set... */
	if (data->apdu) {
		data->apdu->sw1 = apdu.sw1;
		data->apdu->sw2 = apdu.sw2;
	}

	/* Check CTBCS status word */
	switch (((unsigned int) apdu.sw1 << 8) | apdu.sw2) {
	case 0x9000:
		r = 0;
		break;
	case 0x6400: /* Input timed out */
		r = SC_ERROR_KEYPAD_TIMEOUT;
		break;
	case 0x6401: /* Input cancelled */
		r = SC_ERROR_KEYPAD_CANCELLED;
		break;
	case 0x6402: /* PINs did not match */
		r = SC_ERROR_KEYPAD_PIN_MISMATCH;
		break;
	case 0x6700: /* message too long */
		r = SC_ERROR_KEYPAD_MSG_TOO_LONG;
		break;
	default:
		r = SC_ERROR_CARD_CMD_FAILED;
		break;
	}
	LOG_TEST_RET(card->ctx, r, "PIN command failed");

	return 0;
}
