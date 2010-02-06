/*
 * card-javacard.c: Recognize known blank JavaCards
 *
 * Copyright (C) 2010 Martin Paljak <martin@paljak.pri.ee>
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

static struct sc_atr_table javacard_atrs[] = {
	{"3b:db:18:00:80:b1:fe:45:1f:83:00:31:c0:64:c7:fc:10:00:01:90:00:fa", NULL, "Cosmo v7 64K dual/128K", SC_CARD_TYPE_JAVACARD, 0, NULL},
	{"3b:75:94:00:00:62:02:02:02:01", NULL, "Cyberflex 32K", SC_CARD_TYPE_JAVACARD, 0, NULL},
	{"3b:95:95:40:ff:ae:01:03:00:00", NULL, "Cyberflex v2 64K", SC_CARD_TYPE_JAVACARD, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations javacard_ops;
static struct sc_card_driver javacard_drv = {
	"JavaCard (without supported applet)",
	"javacard",
	&javacard_ops,
	NULL, 0, NULL
};

static int javacard_finish(sc_card_t * card)
{
	return SC_SUCCESS;
}

static int javacard_match_card(sc_card_t * card)
{
	if (_sc_match_atr(card, javacard_atrs, &card->type) < 0)
        	return 0;
	return 1;
}

static int javacard_init(sc_card_t * card)
{
	card->drv_data = NULL;

	return SC_SUCCESS;
}


static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	javacard_ops = *iso_drv->ops;
	javacard_ops.match_card = javacard_match_card;
	javacard_ops.select_file = NULL;
	javacard_ops.init = javacard_init;
	javacard_ops.finish = javacard_finish;

	return &javacard_drv;
}

struct sc_card_driver *sc_get_javacard_driver(void)
{
	return sc_get_driver();
}
