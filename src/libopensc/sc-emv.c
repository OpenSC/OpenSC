/*
 * sc-emv.c: Functions specified by the EMV standard
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

static struct sc_card_operations emv_ops;
static const struct sc_card_driver emv_drv = {
	NULL,
	"EMV compatible cards",
	&emv_ops
};

static int emv_finish(struct sc_card *card)
{
	return 0;
}

static int emv_match_card(struct sc_card *card)
{
	int i, match = -1;
	const char *str = "BWAVANT";

	for (i = 0; i < card->atr_len - strlen(str); i++)
		if (memcmp(card->atr + i, str, strlen(str)) == 0) {
			match = 1;
			break;
		}
	
	if (match == 1)
		return 1;
	return 0;
}

static int emv_init(struct sc_card *card)
{
	card->ops_data = NULL;
	card->cla = 0x00;

	return 0;
}

static int emv_select_file(struct sc_card *card, const struct sc_path *path,
			   struct sc_file *file)
{
	int r;
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	const struct sc_card_operations *ops = iso_drv->ops;

	r = ops->select_file(card, path, file);
	if (file != NULL && path->len == 2 && memcmp(path->value, "\x3F\x00", 2) == 0)
		file->type = SC_FILE_TYPE_DF;
	return r;
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	emv_ops = *iso_drv->ops;
	emv_ops.match_card = emv_match_card;
	emv_ops.init = emv_init;
        emv_ops.finish = emv_finish;
	emv_ops.select_file = emv_select_file;

	return &emv_drv;
}

#if 1
const struct sc_card_driver * sc_get_emv_driver(void)
{
	return sc_get_driver();
}
#endif
