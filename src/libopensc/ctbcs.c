/*
 * ctbcs.c: Extended CTBCS commands, used for pcsc and ct-api readers
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
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
#include "ctbcs.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

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

int
ctbcs_build_input_apdu(sc_apdu_t *apdu, int echo, const char *prompt,
			u8 *rbuf, size_t rbuflen)
{
	ctbcs_init_apdu(apdu, SC_APDU_CASE_2_SHORT,
			CTBCS_INS_INPUT,
			CTBCS_P1_KEYPAD,
			echo? CTBCS_P2_INPUT_ECHO : CTBCS_P2_INPUT_ASTERISKS);

	if (prompt && *prompt) {
		apdu->cse = SC_APDU_CASE_4_SHORT;
		apdu->data = (u8 *) prompt;
		apdu->lc = apdu->datalen = strlen(prompt);
	}

	apdu->le = apdu->resplen = rbuflen;
	apdu->resp = rbuf;
	return 0;
}

int
ctbcs_build_output_apdu(sc_apdu_t *apdu, const char *message)
{
	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_INPUT,
			CTBCS_P1_DISPLAY,
			0);

	if (!message || !*message)
		message = " ";

	apdu->lc = apdu->datalen = strlen(message);

	return 0;
}

int
ctbcs_build_perform_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data)
{
	const char *prompt;
	size_t buflen, count = 0, j = 0, len;
	static u8 buf[254];
	u8 control;

	ctbcs_init_apdu(apdu,
			SC_APDU_CASE_3_SHORT,
			CTBCS_INS_PERFORM_VERIFICATION,
			CTBCS_P1_KEYPAD,
			0);

	buflen = sizeof(buf);
	prompt = data->pin1.prompt;
	if (prompt && *prompt) {
		len = strlen(prompt);
		if (count + len + 2 > buflen || len > 255)
			return SC_ERROR_BUFFER_TOO_SMALL;
		buf[count++] = CTBCS_TAG_PROMPT;
		buf[count++] = len;
		memcpy(buf + count, prompt, len);
		count += len;
	}

	/* card apdu must be last in packet */
	if (!data->apdu)
		return SC_ERROR_INTERNAL;
	if (count + 7 > buflen)
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
	buf[j++] = data->pin1.offset;
	buf[j++] = data->apdu->cla;
	buf[j++] = data->apdu->ins;
	buf[j++] = data->apdu->p1;
	buf[j++] = data->apdu->p2;

	if (data->flags & SC_PIN_CMD_NEED_PADDING) {
		len = data->pin1.pad_length;
		if (j + len > buflen || len > 256)
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
ctbcs_build_modify_verification_apdu(sc_apdu_t *apdu, struct sc_pin_cmd_data *data)
{
	/* to be implemented */
	return SC_ERROR_NOT_SUPPORTED;
}

int
ctbcs_pin_cmd(struct sc_reader *reader, sc_slot_info_t *slot,
	      struct sc_pin_cmd_data *data)
{
	struct sc_card dummy_card, *card;
	struct sc_apdu apdu;
	int r;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		r = ctbcs_build_perform_verification_apdu(&apdu, data);
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		r = ctbcs_build_modify_verification_apdu(&apdu, data);
		break;
	default:
		sc_error(reader->ctx, "unknown pin command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	memset(&dummy_card, 0, sizeof(dummy_card));
	dummy_card.reader = reader;
	dummy_card.slot = slot;
	dummy_card.ctx = reader->ctx;
	card = &dummy_card;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	
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
	SC_TEST_RET(card->ctx, r, "PIN command failed");

	return 0;
}
