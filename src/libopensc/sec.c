/*
 * sec.c: Cryptography and security (ISO7816-8) functions
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
#include "sc-log.h"
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

int sc_decipher(struct sc_card *card,
		const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && crgram != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf); /* FIXME */

	sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		int len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 2, len);
	}
	SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

int sc_compute_signature(struct sc_card *card,
			 const u8 * data, size_t datalen,
			 u8 * out, size_t outlen)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (card->ops->compute_signature == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->compute_signature(card, data, datalen, out, outlen);
        SC_FUNC_RETURN(card->ctx, 2, r);
}

int sc_set_security_env(struct sc_card *card,
			const struct sc_security_env *env,
			int se_num)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (card->ops->set_security_env == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->set_security_env(card, env, se_num);
        SC_FUNC_RETURN(card->ctx, 2, r);
}

int sc_restore_security_env(struct sc_card *card, int se_num)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (card->ops->restore_security_env == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->restore_security_env(card, se_num);
	SC_FUNC_RETURN(card->ctx, 2, r);
}

int sc_verify(struct sc_card *card, unsigned int type, int ref, 
	      const u8 *pin, size_t pinlen, int *tries_left)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
        if (card->ops->verify == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->verify(card, type, ref, pin, pinlen, tries_left);
        SC_FUNC_RETURN(card->ctx, 2, r);
}

int sc_change_reference_data(struct sc_card *card, unsigned int type,
			     int ref, const u8 *old, size_t oldlen,
			     const u8 *newref, size_t newlen,
			     int *tries_left)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 1);
	if (card->ops->change_reference_data == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->change_reference_data(card, type, ref, old, oldlen,
					     newref, newlen, tries_left);
	SC_FUNC_RETURN(card->ctx, 1, r);
}

int sc_reset_retry_counter(struct sc_card *card, unsigned int type, int ref,
			   const u8 *puk, size_t puklen, const u8 *newref,
			   size_t newlen)
{
	int r;

	assert(card != NULL);
	SC_FUNC_CALLED(card->ctx, 1);
	if (card->ops->reset_retry_counter == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->reset_retry_counter(card, type, ref, puk, puklen,
					   newref, newlen);
	SC_FUNC_RETURN(card->ctx, 1, r);
}
