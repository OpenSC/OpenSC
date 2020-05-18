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

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "libopensc/asn1.h"
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


static struct {
	int len;
	struct sc_object_id oid;
} edo_curves[] = {
	// secp384r1
	{384, {{1, 3, 132, 0, 34, -1}}}
};


static void edo_eac_init() {
	extern void EAC_init(void);
	static int initialized = 0;
	if (!initialized) {
		EAC_init();
		initialized = 1;
	}
}


static int edo_match_card(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, edo_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Polish eID card.");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}


static int edo_get_can(sc_card_t* card, struct establish_pace_channel_input* pace_input) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	const char* can;

	can = getenv("EDO_CAN");

	if (!can || can[0] != '\0') {
		for (size_t i = 0; card->ctx->conf_blocks[i]; ++i) {
			scconf_block** blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "edo");
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


static int edo_unlock(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);

	if (SC_SUCCESS != edo_get_can(card, &pace_input)) {
		sc_log(card->ctx, "Error reading CAN.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	if (SC_SUCCESS != perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02)) {
		sc_log(card->ctx, "Error verifying CAN.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


struct edo_buff {
	u8 val[SC_MAX_APDU_RESP_SIZE];
	size_t len;
};


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


static int edo_select_name(struct sc_card* card, const u8* name, size_t namelen, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 00, 0xA4, 0x04, 0x00, name, namelen, buff->val, sizeof buff->val);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");
	buff->len = apdu.resplen;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int edo_select_path(struct sc_card* card, const u8* path, size_t pathlen, struct edo_buff* buff) {
	LOG_FUNC_CALLED(card->ctx);
	while (pathlen >= 2) {
		if (path[0] == 0x3F && path[1]  == 0x00)
			LOG_TEST_RET(card->ctx, edo_select_mf(card, buff), "MF select failed");
		else if (path[0] == 0xDF)
			LOG_TEST_RET(card->ctx, edo_select_df(card, path, buff), "DF select failed");
		else if (pathlen == 2)
			LOG_TEST_RET(card->ctx, edo_select_ef(card, path, buff), "EF select failed");
		else
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		path += 2;
		pathlen -= 2;
	}
	if (pathlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Selects file specified by given path.
 *
 * Card does not support selecting file at once, that's why it have to be done in following way:
 * 1. Select AID if provided,
 * 2. Select MF if provided,
 * 3. Select DF until provided,
 * 4. Select EF if provided.
 */
static int edo_select_file(struct sc_card* card, const struct sc_path* in_path, struct sc_file** file_out) {
	LOG_FUNC_CALLED(card->ctx);
	struct edo_buff buff;

	switch (in_path->type) {
		case SC_PATH_TYPE_PATH:
		case SC_PATH_TYPE_FILE_ID:
			if (in_path->aid.len)
				LOG_TEST_RET(card->ctx, edo_select_name(card, in_path->aid.value, in_path->aid.len, &buff), "Select AID failed");
			if (in_path->len)
				LOG_TEST_RET(card->ctx, edo_select_path(card, in_path->value, in_path->len, &buff), "Select path failed");
			break;
		case SC_PATH_TYPE_DF_NAME:
			LOG_TEST_RET(card->ctx, edo_select_name(card, in_path->value, in_path->len, &buff), "Select AID failed");
			break;
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	if (file_out) {
		if (buff.len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		if (!(*file_out = sc_file_new()))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		(*file_out)->path = *in_path;
		LOG_TEST_RET(card->ctx, card->ops->process_fci(card, *file_out, buff.val, buff.len), "Process FCI failed");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Computes ECDSA signature.
 *
 * If ECDSA was used, the ASN.1 sequence of integers R,S returned by the
 * card needs to be converted to the raw concatenation of R,S for PKCS#11.
 */
static int edo_compute_signature(struct sc_card* card, const u8* data, size_t datalen, u8* out, size_t outlen) {
	LOG_FUNC_CALLED(card->ctx);
	u8 sig[SC_MAX_APDU_RESP_SIZE];
	LOG_TEST_RET(card->ctx, sc_get_iso7816_driver()->ops->compute_signature(card, data, datalen, sig, sizeof sig), "Internal signature failed");
	LOG_TEST_RET(card->ctx, sc_asn1_sig_value_sequence_to_rs(card->ctx, sig, sizeof sig, out, outlen), "ASN.1 conversion failed");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Sets security environment
 *
 * Card expects key file to be selected first, followed by the
 * set security env packet with: 0x80, 0x01, 0xcc, 0x84, 0x01, 0x80|x,
 * where x is the key reference byte.
 */
static int edo_set_security_env(struct sc_card* card, const struct sc_security_env* env, int se_num) {
	LOG_FUNC_CALLED(card->ctx);
	struct sc_apdu apdu;

	if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_SIGN && env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		u8 payload[] = {0x80, 0x01, 0xcc, 0x84, 0x01, 0x80 | env->key_ref[0]};
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6, payload, sizeof payload, NULL, 0);
	} else
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	LOG_TEST_RET(card->ctx, sc_select_file(card, &env->file_ref, NULL), "SELECT file failed");
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*! Initializes card driver.
 *
 * Card is known to support only short APDU-s.
 * Preinitialized keys are on secp384r1 curve.
 * PACE channel have to be established.
 */
static int edo_init(sc_card_t* card) {
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	edo_eac_init();

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;

	for (size_t i = 0; i < sizeof edo_curves / sizeof * edo_curves; ++i) {
		LOG_TEST_RET(card->ctx, _sc_card_add_ec_alg(
			card, edo_curves[i].len,
			SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE,
			0, &edo_curves[i].oid
		), "Add EC alg failed");
	}

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	LOG_TEST_RET(card->ctx, edo_unlock(card), "Unlock card failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


struct sc_card_driver* sc_get_edo_driver(void) {
	edo_ops = *sc_get_iso7816_driver()->ops;
	edo_ops.match_card = edo_match_card;
	edo_ops.init = edo_init;
	edo_ops.select_file = edo_select_file;
	edo_ops.set_security_env = edo_set_security_env;
	edo_ops.compute_signature = edo_compute_signature;

	return &edo_drv;
}

#else

#include "libopensc/opensc.h"

struct sc_card_driver* sc_get_edo_driver(void) {
	return NULL;
}

#endif
