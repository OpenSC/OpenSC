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
#include <stdlib.h>


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


static int edo_get_can(sc_card_t* card, struct establish_pace_channel_input* pace_input) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	char* can = getenv("EDO_CAN");

	if (!can || 6 != strlen(can)) {
		sc_log(card->ctx, "Missing or invalid EDO_CAN.\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	pace_input->pin_id = PACE_PIN_ID_CAN;
	pace_input->pin = (const unsigned char*)can;
	pace_input->pin_length = 6;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_unlock_esign(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct establish_pace_channel_input pace_input={};
	struct establish_pace_channel_output pace_output={};

	sc_log(card->ctx, "Will verify CAN first for unlocking eSign application.\n");

	if (SC_SUCCESS != edo_get_can(card, &pace_input)) {
		sc_log(card->ctx, "Error reading CAN.\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	if (SC_SUCCESS != perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02)) {
		sc_log(card->ctx, "Error verifying CAN.\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_init(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	EAC_init();

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;


	if (SC_SUCCESS != edo_unlock_esign(card)) {
		sc_log(card->ctx, "Error while unlocking esign.\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


struct sc_card_driver* sc_get_edo_driver(void) {
	struct sc_card_driver* iso_drv = sc_get_iso7816_driver();

	edo_ops = *iso_drv->ops;
	edo_ops.match_card = edo_match_card;
	edo_ops.init = edo_init;
// 	edo_ops.finish = edo_finish;
// 	edo_ops.set_security_env = edo_set_security_env;
// 	edo_ops.pin_cmd = edo_pin_cmd;
// 	edo_ops.logout = edo_logout;

	return &edo_drv;
}

