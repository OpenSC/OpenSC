/*
 * sc-card-multiflex.c: Support for Multiflex cards by Schlumberger
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

static const char *mflex_atrs[] = {
	"3B:19:14:55:90:01:02:02:00:05:04:B0",
	NULL
};

static struct sc_card_operations mflex_ops;
static const struct sc_card_driver mflex_drv = {
	NULL,
	"Schlumberger/Multiflex",
	&mflex_ops
};

static int mflex_finish(struct sc_card *card)
{
	return 0;
}

static int mflex_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; mflex_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		int len = sizeof(defatr);
		const char *atrp = mflex_atrs[i];

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

static int mflex_init(struct sc_card *card)
{
	card->ops_data = NULL;
	card->cla = 0xC0;

	return 0;
}

static int mflex_select_file(struct sc_card *card, const struct sc_path *path,
			     struct sc_file *file)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	mflex_ops = *iso_drv->ops;
	mflex_ops.match_card = mflex_match_card;
	mflex_ops.init = mflex_init;
        mflex_ops.finish = mflex_finish;
	mflex_ops.select_file = mflex_select_file;

        return &mflex_drv;
}

#if 1
const struct sc_card_driver * sc_get_mflex_driver(void)
{
	return sc_get_driver();
}
#endif
