/*
 * card-default.c: Support for cards with no driver
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

#include "config.h"

#include <string.h>

#include "internal.h"

static struct sc_card_operations default_ops;
static struct sc_card_driver default_drv = {
	"Default driver for unknown cards",
	"default",
	&default_ops,
	NULL, 0, NULL
};


static int
default_match_card(struct sc_card *card)
{
	return 1;		/* always match */
}


static int
autodetect_class(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int classes[] = { 0x00, 0xC0, 0xB0, 0xA0 };
	int class_count = sizeof(classes)/sizeof(int);
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;
	int i, r;

	LOG_FUNC_CALLED(ctx);

	for (i = 0; i < class_count; i++) {
		sc_log(ctx, "trying with 0x%02X", classes[i]);

		memset(&apdu, 0, sizeof(apdu));
		apdu.cla = classes[i];
		apdu.cse = SC_APDU_CASE_2_SHORT;
		apdu.ins = 0xC0;
		apdu.p1 = apdu.p2 = 0;
		apdu.datalen = 0;
		apdu.lc = 0;
		apdu.le = 256;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, r, "APDU transmit failed");

		if (apdu.sw1 == 0x6E)
			continue;
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
			break;
		if (apdu.sw1 == 0x61)
			break;

		sc_log(ctx, "got strange SWs: 0x%02X 0x%02X", apdu.sw1, apdu.sw2);
		break;
	}

	if (i == class_count)
		LOG_FUNC_RETURN(ctx, SC_ERROR_CLASS_NOT_SUPPORTED);

	card->cla = classes[i];
	sc_log(ctx, "detected CLA byte as 0x%02X", card->cla);
	if (apdu.resplen < 2) {
		sc_log(ctx, "SELECT FILE returned %d bytes", apdu.resplen);
	}
	else if (rbuf[0] == 0x6F) {
		sc_log(ctx, "SELECT FILE seems to behave according to ISO 7816-4\n");
	}
	else if (rbuf[0] == 0x00 && rbuf[1] == 0x00) {
		struct sc_card_driver *drv;
		sc_log(ctx, "SELECT FILE seems to return Schlumberger 'flex stuff");

		drv = sc_get_cryptoflex_driver();
		card->ops->select_file = drv->ops->select_file;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
default_init(struct sc_card *card)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);

	card->name = "Unsupported card";
	card->drv_data = NULL;
	r = autodetect_class(card);
	if (r) {
		sc_log(card->ctx, "unable to determine the right class byte");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	default_ops = *iso_drv->ops;
	default_ops.match_card = default_match_card;
	default_ops.init = default_init;

	return &default_drv;
}

struct sc_card_driver * sc_get_default_driver(void)
{
	return sc_get_driver();
}
