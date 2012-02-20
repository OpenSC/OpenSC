/*
 * card-npa.c: Recognize known German identity cards
 *
 * Copyright (C) 2011 Frank Morgner <morgner@informatik.hu-berlin.de>
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

static struct sc_atr_table npa_atrs[] = {
    {"3B:8A:80:01:80:31:F8:73:F7:41:E0:82:90:00:75", NULL, "German ID card (neuer Personalausweis, nPA)", SC_CARD_TYPE_NPA, 0, NULL},
    {"3B:84:80:01:00:00:90:00:95", NULL, "German ID card (Test neuer Personalausweis, Test nPA)", SC_CARD_TYPE_NPA_TEST, 0, NULL},
    {NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations npa_ops;
static struct sc_card_driver npa_drv = {
    "German ID card (neuer Personalausweis, nPA)",
    "npa",
    &npa_ops,
    NULL, 0, NULL
};

static int npa_match_card(sc_card_t * card)
{
    if (_sc_match_atr(card, npa_atrs, &card->type) < 0)
        return 0;
    return 1;
}

static int npa_init(sc_card_t * card)
{
    card->drv_data = NULL;
    card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_RNG;

    return SC_SUCCESS;
}

static struct sc_card_driver *npa_get_driver(void)
{
    struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

    npa_ops = *iso_drv->ops;
    npa_ops.match_card = npa_match_card;
    npa_ops.init = npa_init;

    return &npa_drv;
}

struct sc_card_driver *sc_get_npa_driver(void)
{
    return npa_get_driver();
}
