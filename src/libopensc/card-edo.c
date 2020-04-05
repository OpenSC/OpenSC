/*
 * Copyright (C) 2020 Piotr Majkrzak
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

#include "card-edo.h"
#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "sm/sm-eac.h"
#include <string.h>

static struct sc_card_operations edo_ops;
static struct sc_card_driver edo_drv = {
	"Polish eID card (e-dowód, eDO)",
	"edo",
	&edo_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table edo_atrs[] = {
	{ "3b:84:80:01:47:43:50:43:12", NULL, NULL, SC_CARD_TYPE_EDO, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static int edo_match_card(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, edo_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Polish eID card\n");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}


struct sc_card_driver* sc_get_edo_driver(void) {
	struct sc_card_driver* iso_drv = sc_get_iso7816_driver();

	edo_ops = *iso_drv->ops;
	edo_ops.match_card = edo_match_card;
// 	edo_ops.init = edo_init;
// 	edo_ops.finish = edo_finish;
// 	edo_ops.set_security_env = edo_set_security_env;
// 	edo_ops.pin_cmd = edo_pin_cmd;
// 	edo_ops.logout = edo_logout;

	return &edo_drv;
}

