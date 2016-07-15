/*
 * Copyright (C) 2010-2015 Frank Morgner
 *
 * This file is part of OpenSC.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libsm/iso-sm.h"
#include "libopensc/internal.h"
#include "libopensc/log.h"
#include "rw_sfid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ISO_READ_BINARY  0xB0
#define ISO_P1_FLAG_SFID 0x80
int read_binary_sfid(sc_card_t *card, unsigned char sfid,
		u8 **ef, size_t *ef_len)
{
	int r;
	size_t read = MAX_SM_APDU_RESP_SIZE;
	sc_apdu_t apdu;
	u8 *p;

	if (!card || !ef || !ef_len) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	*ef_len = 0;

	if (read > 0xff+1)
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_EXT,
				ISO_READ_BINARY, ISO_P1_FLAG_SFID|sfid, 0);
	else
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
				ISO_READ_BINARY, ISO_P1_FLAG_SFID|sfid, 0);

	p = realloc(*ef, read);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	*ef = p;
	apdu.resp = *ef;
	apdu.resplen = read;
	apdu.le = read;

	r = sc_transmit_apdu(card, &apdu);
	/* emulate the behaviour of sc_read_binary */
	if (r >= 0)
		r = apdu.resplen;

	while(1) {
		if (r >= 0 && ((size_t) r) != read) {
			*ef_len += r;
			break;
		}
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read EF.");
			goto err;
		}
		*ef_len += r;

		p = realloc(*ef, *ef_len + read);
		if (!p) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		*ef = p;

		r = sc_read_binary(card, *ef_len,
				*ef + *ef_len, read, 0);
	}

	r = SC_SUCCESS;

err:
	return r;
}

#define ISO_WRITE_BINARY  0xD0
int write_binary_sfid(sc_card_t *card, unsigned char sfid,
		u8 *ef, size_t ef_len)
{
	int r;
	size_t write = MAX_SM_APDU_DATA_SIZE, wrote = 0;
	sc_apdu_t apdu;
#ifdef ENABLE_SM
	struct iso_sm_ctx *iso_sm_ctx;
#endif

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

#ifdef ENABLE_SM
	iso_sm_ctx = card->sm_ctx.info.cmd_data;
	if (write > SC_MAX_APDU_BUFFER_SIZE-2
			|| (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT
				&& write > (((SC_MAX_APDU_BUFFER_SIZE-2
					/* for encrypted APDUs we usually get authenticated status
					 * bytes (4B), a MAC (11B) and a cryptogram with padding
					 * indicator (3B without data).  The cryptogram is always
					 * padded to the block size. */
					-18) / iso_sm_ctx->block_length)
					* iso_sm_ctx->block_length - 1)))
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_EXT,
				ISO_WRITE_BINARY, ISO_P1_FLAG_SFID|sfid, 0);
	else
#endif
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
				ISO_WRITE_BINARY, ISO_P1_FLAG_SFID|sfid, 0);

	if (write > ef_len) {
		apdu.datalen = ef_len;
		apdu.lc = ef_len;
	} else {
		apdu.datalen = write;
		apdu.lc = write;
	}
	apdu.data = ef;


	r = sc_transmit_apdu(card, &apdu);
	/* emulate the behaviour of sc_write_binary */
	if (r >= 0)
		r = apdu.datalen;

	while (1) {
		if (r < 0 || ((size_t) r) > ef_len) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not write EF.");
			goto err;
		}
		wrote += r;
		apdu.data += r;
		if (wrote >= ef_len)
			break;

		r = sc_write_binary(card, wrote, ef, write, 0);
	}

	r = SC_SUCCESS;

err:
	return r;
}
