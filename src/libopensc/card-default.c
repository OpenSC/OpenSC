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

#if HAVE_CONFIG_H
#include "config.h"
#endif

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
default_init(struct sc_card *card)
{
	LOG_FUNC_CALLED(card->ctx);

	card->name = "Unsupported card";
	card->drv_data = NULL;

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
