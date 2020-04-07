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
#include "libopensc/asn1.h"
#include "sm/sm-eac.h"
#include <eac/eac.h>
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

	struct establish_pace_channel_input pace_input = {};
	struct establish_pace_channel_output pace_output = {};

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


struct edo_buff {
	u8 val[SC_MAX_APDU_RESP_SIZE];
	size_t len;
};


static int edo_select_root(struct sc_card* card) {
	LOG_FUNC_CALLED(card->ctx);
	static const u8 edo_aid_root[] = {0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x40};
	struct sc_apdu apdu;
	u8 buff[SC_MAX_APDU_RESP_SIZE];
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x04, 0x00, edo_aid_root, sizeof edo_aid_root, buff, sizeof buff);
	apdu.resplen = 255;
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_mf(struct sc_card* card, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x00, 0x00, NULL, 0, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_df(struct sc_card* card, const u8 path[2], struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x01, 0x04, path, 2, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_ef(struct sc_card* card, const u8 path[2], struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x02, 0x04, path, 2, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_file(struct sc_card* card, const struct sc_path* in_path, struct sc_file** file_out) {
	LOG_FUNC_CALLED(card->ctx);
	const u8* path;
	size_t pathlen;
	struct edo_buff buff;

	if (in_path->type != SC_PATH_TYPE_PATH && in_path->type != SC_PATH_TYPE_FILE_ID) {
		LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->select_file(card, in_path, file_out));
		//LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	path = in_path->value;
	pathlen = in_path->len;

	while (pathlen >= 2) {
		if (path[0] == 0x3F && path[1]  == 0x00) {
			LOG_TEST_RET(card->ctx, edo_select_mf(card, &buff), "MF select failed");
		} else if (path[0] == 0xAD) {
			LOG_TEST_RET(card->ctx, edo_select_df(card, path, &buff), "DF select failed");
		} else if (pathlen == 2) {
			LOG_TEST_RET(card->ctx, edo_select_ef(card, path, &buff), "EF select failed");
		}
		path += 2;
		pathlen -= 2;
	}

	{
		// iso7816.c file creation
		int r;
		unsigned int cla, tag;
		struct sc_file* file;
		const u8* buffer;
		size_t buffer_len;

		if (file_out && (buff.len == 0))   {
			/* For some cards 'SELECT' MF or DF_NAME do not return FCI. */

			file = sc_file_new();
			if (file == NULL)
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			file->path = *in_path;

			*file_out = file;
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

		}

		if (buff.len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		buffer = buff.val;
		r = sc_asn1_read_tag(&buffer, buff.len, &cla, &tag, &buffer_len);
		if (r == SC_SUCCESS)
			card->ops->process_fci(card, file, buffer, buffer_len);
		*file_out = file;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_init(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	EAC_init();

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;
	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	LOG_TEST_RET(card->ctx, edo_select_root(card), "Select Root AID failed");
	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Error while ennuming apps");

	if (SC_SUCCESS != edo_unlock_esign(card)) {
		sc_log(card->ctx, "Error while unlocking esign.\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


struct sc_card_driver* sc_get_edo_driver(void) {
	edo_ops = *sc_get_iso7816_driver()->ops;
	edo_ops.match_card = edo_match_card;
	edo_ops.init = edo_init;
	edo_ops.select_file = edo_select_file;
// 	edo_ops.finish = edo_finish;
// 	edo_ops.set_security_env = edo_set_security_env;
// 	edo_ops.pin_cmd = edo_pin_cmd;
// 	edo_ops.logout = edo_logout;

	return &edo_drv;
}

