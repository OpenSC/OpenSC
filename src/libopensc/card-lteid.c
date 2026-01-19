/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "libopensc/asn1.h"
#include "sm/sm-eac.h"
#include <string.h>
#include <stdlib.h>

static struct sc_card_operations lteid_ops;

static struct sc_card_driver lteid_drv = {
	"Lithuanian eID card (asmens tapatybės kortelė)",
	"lteid",
	&lteid_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table lteid_atrs[] = {
	{ "3b:9d:18:81:31:fc:35:80:31:c0:69:4d:54:43:4f:53:73:02:06:05:d0", NULL, NULL, SC_CARD_TYPE_LTEID, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct {
	int len;
	struct sc_object_id oid;
} lteid_curves[] = {
	// secp384r1
	{384, {{1, 3, 132, 0, 34, -1}}}
};

struct lteid_buff {
	u8 val[SC_MAX_APDU_RESP_SIZE];
	size_t len;
};

#define SC_TRANSMIT_TEST_RET(card, apdu, text) \
	do { \
		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed"); \
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), text); \
	} while (0)


static int lteid_match_card(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, lteid_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Lithuanian eID card.");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int lteid_get_can(sc_card_t* card, struct establish_pace_channel_input* pace_input) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	const char* can;

	can = getenv("LTEID_CAN");

	if (!can || can[0] != '\0') {
		for (size_t i = 0; card->ctx->conf_blocks[i]; ++i) {
			scconf_block** blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "lteid");
			if (!blocks)
				continue;
			for (size_t j = 0; blocks[j]; ++j)
				if ((can = scconf_get_str(blocks[j], "can", NULL)))
					break;
			free(blocks);
		}
	}

	if (!can || 6 != strlen(can)) {
		sc_log(card->ctx, "Missing or invalid CAN. 6 digits required.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	pace_input->pin_id = PACE_PIN_ID_CAN;
	pace_input->pin = (const unsigned char*)can;
	pace_input->pin_length = 6;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_unlock(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);

	if (SC_SUCCESS != lteid_get_can(card, &pace_input)) {
		sc_log(card->ctx, "Error reading CAN.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	if (SC_SUCCESS != perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02)) {
		sc_log(card->ctx, "Error verifying CAN.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*! Initializes card driver.
 *
 * Card is known to support only short APDU-s.
 * Preinitialized keys are on secp384r1 curve.
 * PACE channel have to be established.
 */
static int lteid_init(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;

	for (size_t i = 0; i < sizeof lteid_curves / sizeof * lteid_curves; ++i) {
		LOG_TEST_RET(card->ctx, _sc_card_add_ec_alg(
			card, lteid_curves[i].len,
			SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE,
			0, &lteid_curves[i].oid
		), "Add EC alg failed");
	}

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	LOG_TEST_RET(card->ctx, lteid_unlock(card), "Unlock card failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int lteid_logout(sc_card_t* card) {
	sc_sm_stop(card);
	return lteid_unlock(card);
}

struct sc_card_driver* sc_get_lteid_driver(void)
{
	lteid_ops = *sc_get_iso7816_driver()->ops;
	lteid_ops.match_card = lteid_match_card;
	lteid_ops.init = lteid_init;
	// lteid_ops.select_file = lteid_select_file;
	// lteid_ops.set_security_env = lteid_set_security_env;
	// lteid_ops.compute_signature = lteid_compute_signature;
	lteid_ops.logout = lteid_logout;

	return &lteid_drv;
}

#else

#include "libopensc/opensc.h"

struct sc_card_driver* sc_get_lteid_driver(void) {
	return NULL;
}

#endif