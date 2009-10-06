/*
 * card-gemsafeV2.c: Support for GemSafe Applet V2 PKCS#15 cards
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2007  Georges Bart <georges.bart@gmail.com>
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
#include <string.h>

static struct sc_card_operations gemsafeV2_ops;
static struct sc_card_driver gemsafeV2_drv = {
	"GemSafe V2 PKCS#15 card",
	"GemSafeV2",
	&gemsafeV2_ops,
	NULL, 0, NULL
};

static int gemsafeV2_finish(sc_card_t *card)
{
	return 0;
} /* gemsafeV2_finish */

static const u8 atr[] = { 0x3B, 0xFD, 0x94, 0x00, 0x00, 0x81, 0x31, 0x20, 0x43,
	0x80, 0x31, 0x80, 0x65, 0xB0, 0x83, 0x02, 0x04, 0x7E, 0x83, 0x00, 0x90,
	0x00, 0xB6 };

static int gemsafeV2_match_card(sc_card_t *card)
{
	/* FIXME */
	return memcmp(atr, card -> atr, sizeof(atr)) == 0;		/* correct ATR? */
} /* gemsafeV2_match_card */

static const u8 gemsafeV2_aid[] = {0xa0, 0x00, 0x00, 0x00, 0x18, 0x0c, 0x00,
	0x00, 0x01, 0x63, 0x42, 0x00};

static const u8 pin[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int gemsafeV2_init(sc_card_t *card)
{
	int rv;
	sc_apdu_t apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];

	card->name = "GemSafe V2 PKCS#15 card";
	card->cla = 0x00;
	card->drv_data = NULL;

	sc_debug(card -> ctx, "Test for GemSafe v2 card");

    /* test if we have a gemsafeV2 app DF */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0x04, 0x00);
	apdu.lc = sizeof(gemsafeV2_aid);
	apdu.le = 0;
	apdu.data = gemsafeV2_aid;
	apdu.datalen = sizeof(gemsafeV2_aid);
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (!((apdu.sw1 == 0x90) && (apdu.sw2 == 0x00)))
		return -1;

#if 1
	sc_debug(card -> ctx, "Force a verify PIN");
	/* verify pin */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x81);
	apdu.lc = sizeof(pin);
	apdu.le = 0;
	apdu.data = pin;
	apdu.datalen = sizeof(pin);
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (!((apdu.sw1 == 0x90) && (apdu.sw2 == 0x00)))
		return -1;
#endif

	return 0;
} /* gemsafeV2_init */

static int
gemsafeV2_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
    sc_apdu_t   apdu;
    int     r;
	u8 get_data[] = { 0xB6, 0x03, 0x83, 0x01, 0xff, 0x7F, 0x49, 0x80 };

    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x00, 0xFF);
	apdu.lc = sizeof(get_data);
    apdu.le = 256;
    apdu.resp = buf;
    apdu.resplen = buf_len;

	get_data[4] = tag;
	apdu.data = get_data;
	apdu.datalen = sizeof(get_data);

    r = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, r, "APDU transmit failed");
    r = sc_check_sw(card, apdu.sw1, apdu.sw2);
    SC_TEST_RET(card->ctx, r, "Card returned error");

    return apdu.resplen;
} /* gemsafeV2_get_data */

struct sc_card_driver * sc_get_gemsafeV2_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	gemsafeV2_ops = *iso_drv->ops;
	gemsafeV2_ops.get_data = gemsafeV2_get_data;
	gemsafeV2_ops.match_card = gemsafeV2_match_card;
	gemsafeV2_ops.init = gemsafeV2_init;
	gemsafeV2_ops.finish = gemsafeV2_finish;

	return &gemsafeV2_drv;
} /* sc_get_gemsafeV2_driver */

