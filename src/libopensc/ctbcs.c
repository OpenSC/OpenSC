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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
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
ctbcs_build_perform_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data)
{
	const char *prompt;
	size_t buflen, count = 0, j = 0, len;
	static u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 control;

	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_PERFORM_VERIFICATION,
			CTBCS_P1_INTERFACE1,
			0);

	buflen = sizeof(buf);
	prompt = data->pin1.prompt;
	if (prompt && *prompt) {
		len = strlen(prompt);
		if (len + 2 > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[count++] = CTBCS_TAG_PROMPT;
		buf[count++] = len;
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
		control |= data->pin1.min_length << CTBCS_PIN_CONTROL_LEN_SHIFT;
	buf[j++] = control;
	buf[j++] = data->pin1.offset+1; /* Looks like offset is 1-based in CTBCS */
	buf[j++] = data->apdu->cla;
	buf[j++] = data->apdu->ins;
	buf[j++] = data->apdu->p1;
	buf[j++] = data->apdu->p2;

	if (data->flags & SC_PIN_CMD_NEED_PADDING) {
		len = data->pin1.pad_length;
		if (2 + j + len > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[j++] = len;
		memset(buf+j, data->pin1.pad_char, len);
		j += len;
	}

	buf[count+1] = j - count - 2;
	count = j;

	apdu->lc = apdu->datalen = count;
	apdu->data = buf;

	return 0;
}

static int
ctbcs_build_modify_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data)
{
	const char *prompt;
	size_t buflen, count = 0, j = 0, len;
	static u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 control;

	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_MODIFY_VERIFICATION,
			CTBCS_P1_INTERFACE1,
			0);

	buflen = sizeof(buf);
	prompt = data->pin1.prompt;
	if (prompt && *prompt) {
		len = strlen(prompt);
		if (len + 2 > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[count++] = CTBCS_TAG_PROMPT;
		buf[count++] = len;
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
		control |= data->pin1.min_length << CTBCS_PIN_CONTROL_LEN_SHIFT;
	buf[j++] = control;
	buf[j++] = data->pin1.offset+1; /* Looks like offset is 1-based in CTBCS */
	buf[j++] = data->pin2.offset+1;
	buf[j++] = data->apdu->cla;
	buf[j++] = data->apdu->ins;
	buf[j++] = data->apdu->p1;
	buf[j++] = data->apdu->p2;

	if (data->flags & SC_PIN_CMD_NEED_PADDING) {
		len = data->pin1.pad_length + data->pin2.pad_length;
		if (2 + j + len > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[j++] = len;
		memset(buf+j, data->pin1.pad_char, len);
		j += len;
	}

	buf[count+1] = j - count - 2;
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
	int r, s;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		r = ctbcs_build_perform_verification_apdu(&apdu, data);
		if (r != SC_SUCCESS)
			return r;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		r = ctbcs_build_modify_verification_apdu(&apdu, data);
		if (r != SC_SUCCESS)
			return r;
		break;
	default:
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "Unknown PIN command %d", data->cmd);
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
		sc_debug(reader->ctx, SC_LOG_DEBUG_NORMAL, "unable to destroy mutex\n");
		return s;
	}
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	
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
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "PIN command failed");

	/* Calling Function may expect SW1/SW2 in data-apdu set... */
	if (data->apdu) {
		data->apdu->sw1 = apdu.sw1;
		data->apdu->sw2 = apdu.sw2;
	}

	return 0;
}
