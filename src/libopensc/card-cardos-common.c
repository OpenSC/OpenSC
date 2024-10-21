/*
 * card-cardos-common.c: Common code for CardOS based cards
 *
 * Copyright (C) 2024 Mario Haustein <mario.haustein@hrz.tu-chemnitz.de>
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "card-cardos-common.h"
#include "internal.h"

int
cardos_ec_compute_shared_value(struct sc_card *card,
		const u8 *crgram, size_t crgram_len,
		u8 *out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 *sbuf = NULL;

	if (card == NULL || crgram == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "CardOS compute shared value: in-len %" SC_FORMAT_LEN_SIZE_T "u, out-len %" SC_FORMAT_LEN_SIZE_T "u", crgram_len, outlen);

	/* Ensure public key is provided in uncompressed format (indicator byte
	 * 0x04 followed by X and Y coordinate. */
	if (crgram_len % 2 == 0 || crgram[0] != 0x04) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* strip indicator byte */
	crgram++;
	crgram_len--;

	sbuf = malloc(crgram_len + 2);
	if (sbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0xA6  Cmd: Control reference template for key agreement */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0xA6);
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;

	sbuf[0] = 0x9c; /* context specific ASN.1 tag */
	sbuf[1] = crgram_len;
	memcpy(sbuf + 2, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 2;
	apdu.datalen = crgram_len + 2;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, crgram_len + 2);
	free(sbuf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}
