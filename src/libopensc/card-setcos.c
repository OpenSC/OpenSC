/*
 * sc-card-setec.c: Support for PKI cards by Setec
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

#include "opensc.h"

static const char *setec_atrs[] = {
	/* the current FINEID card has this ATR: */
	"3B:9F:94:40:1E:00:67:11:43:46:49:53:45:10:52:66:FF:81:90:00",
	NULL
};

static struct sc_card_operations setec_ops;
static const struct sc_card_driver setec_drv = {
	NULL,
	"Setec",
	&setec_ops
};

static int setec_finish(struct sc_card *card)
{
	return 0;
}

static int setec_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; setec_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		int len = sizeof(defatr);
		const char *atrp = setec_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int setec_init(struct sc_card *card)
{
	card->ops_data = NULL;
	card->cla = 0x00;

	return 0;
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	setec_ops = *iso_drv->ops;
	setec_ops.match_card = setec_match_card;
	setec_ops.init = setec_init;
        setec_ops.finish = setec_finish;

        return &setec_drv;
}

#if 1
const struct sc_card_driver * sc_get_setec_driver(void)
{
	return sc_get_driver();
}
#endif
