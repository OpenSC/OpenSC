/*
 * gp.c: Global Platform Related functions
 *
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#include "internal.h"
#include "gp.h"

/* ISO 7816 CLA values */
#define GLOBAL_PLATFORM_CLASS   0x80

/* ISO 71816 INS values */
#define ISO7816_INS_GET_DATA    0xca

/* The AID of the Card Manager defined by Open Platform 2.0.1 specification */
static const struct sc_aid gp_card_manager = {
	{0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}, 7
};

/* The AID of the Issuer Security Domain defined by GlobalPlatform 2.3.1 specification. */
static const struct sc_aid gp_isd_rid = {
	{0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}, 7
};


/* Select AID */
int
gp_select_aid(struct sc_card *card, const struct sc_aid *aid)
{
	struct sc_apdu apdu;
	int rv;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x0C);
	apdu.lc = aid->len;
	apdu.data = aid->value;
	apdu.datalen = aid->len;

	rv = sc_transmit_apdu(card, &apdu);
	if (rv < 0)
		return rv;

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (rv < 0)
		return rv;

	return apdu.resplen;
}

/* Select the Open Platform Card Manager */
int
gp_select_card_manager(struct sc_card *card)
{
	int rv;

	LOG_FUNC_CALLED(card->ctx);
	rv = gp_select_aid(card, &gp_card_manager);
	LOG_FUNC_RETURN(card->ctx, rv);
}

/* Select Global Platform Card Manager */
int
gp_select_isd_rid(struct sc_card *card)
{
	int rv;

	LOG_FUNC_CALLED(card->ctx);
	rv = gp_select_aid(card, &gp_isd_rid);
	LOG_FUNC_RETURN(card->ctx, rv);
}

/* Get Card Production Life-Cycle information */
int
gp_get_cplc_data(struct sc_card *card, global_platform_cplc_data_t *cplc_data)
{
	size_t len = sizeof(global_platform_cplc_data_t);
	u8 *receive_buf = (u8 *)cplc_data;
	struct sc_apdu apdu;
	int rc;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, ISO7816_INS_GET_DATA, 0x9f, 0x7f);
	apdu.cla = GLOBAL_PLATFORM_CLASS;
	apdu.resp = receive_buf;
	apdu.resplen = len;
	apdu.le = len;

	rc = sc_transmit_apdu(card, &apdu);
	if (rc < 0)
		LOG_FUNC_RETURN(card->ctx, rc);

	rc = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (rc < 0)
		LOG_FUNC_RETURN(card->ctx, rc);

	/* We expect this will fill the whole structure in the argument.
	 * If we got something else, report error */
	if ((size_t)apdu.resplen < sizeof(global_platform_cplc_data_t)) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_CORRUPTED_DATA);
	}
	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}
