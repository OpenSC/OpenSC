/*
 * Driver for EstEID card issued from December 2025.
 *
 * Copyright (C) 2025, Raul Metsma <raul@metsma.ee>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "asn1.h"
#include "gp.h"
#include "internal.h"

#define SIGNATURE_PAYLOAD_SIZE 0x30

static const struct sc_atr_table esteid_atrs[] = {
		{"3b:ff:96:00:00:80:31:fe:43:80:31:b8:53:65:49:44:64:b0:85:05:10:12:23:3f:1d", NULL, "EstEID 2025", SC_CARD_TYPE_ESTEID_2025, 0, NULL},
		{NULL,									 NULL, NULL,	   0,			      0, NULL}
};

static const struct sc_aid THALES_AID = {
		{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
		12
};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations esteid_ops;

static struct sc_card_driver esteid2025_driver = {"EstEID 2025", "esteid2025", &esteid_ops, NULL, 0, NULL};

#define SC_TRANSMIT_TEST_RET(card, apdu, text) \
	do { \
		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed"); \
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), text); \
	} while (0)

static int
esteid_match_card(sc_card_t *card)
{
	int i = _sc_match_atr(card, esteid_atrs, &card->type);

	if (i >= 0 && gp_select_aid(card, &THALES_AID) == SC_SUCCESS) {
		card->name = esteid_atrs[i].name;
		return 1;
	}
	return 0;
}

static int
esteid_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	u8 resp[SC_MAX_APDU_RESP_SIZE];
	size_t resplen = sizeof(resp);
	int r;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	// Only support full paths
	if (in_path->type != SC_PATH_TYPE_PATH) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x08, 0x04, in_path->value, in_path->len, resp, resplen);
	SC_TRANSMIT_TEST_RET(card, apdu, "SELECT failed");
	if (file_out != NULL) {
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		r = iso_ops->process_fci(card, file, resp, resplen);
		if (r != SC_SUCCESS) {
			sc_file_free(file);
		}
		LOG_TEST_RET(card->ctx, r, "Process fci failed");
		*file_out = file;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
esteid_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	struct sc_apdu apdu;
	u8 cse_crt_sig[] = {0x80, 0x01, 0x54, 0x84, 0x01, 0x00};
	u8 cse_crt_der[] = {0x84, 0x01, 0x00};

	LOG_FUNC_CALLED(card->ctx);

	if (env == NULL || env->key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	sc_log(card->ctx, "algo: %lu operation: %d keyref: %d", env->algorithm, env->operation, env->key_ref[0]);

	if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_SIGN) {
		cse_crt_sig[5] = env->key_ref[0];
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6, cse_crt_sig, sizeof(cse_crt_sig), NULL, 0);
	} else if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_DERIVE) {
		cse_crt_der[2] = env->key_ref[0];
		sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB8, cse_crt_der, sizeof(cse_crt_der), NULL, 0);
	} else {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	SC_TRANSMIT_TEST_RET(card, apdu, "SET SECURITY ENV failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
esteid_compute_signature(sc_card_t *card, const u8 *data, size_t datalen, u8 *out, size_t outlen)
{
	struct sc_apdu apdu;
	u8 sbuf[SIGNATURE_PAYLOAD_SIZE + 2] = {0x90, SIGNATURE_PAYLOAD_SIZE};
	size_t le = MIN(SC_MAX_APDU_RESP_SIZE, MIN(SIGNATURE_PAYLOAD_SIZE * 2, outlen));

	LOG_FUNC_CALLED(card->ctx);
	if (data == NULL || out == NULL || datalen > SIGNATURE_PAYLOAD_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	// left-pad if necessary
	memcpy(&sbuf[SIGNATURE_PAYLOAD_SIZE + 2 - datalen], data, MIN(datalen, SIGNATURE_PAYLOAD_SIZE));
	datalen = SIGNATURE_PAYLOAD_SIZE + 2;

	sc_format_apdu_ex(&apdu, 0x00, 0x2A, 0x90, 0xA0, sbuf, datalen, NULL, 0);
	SC_TRANSMIT_TEST_RET(card, apdu, "PSO Set Hash failed");

	sc_format_apdu_ex(&apdu, 0x00, 0x2A, 0x9E, 0x9A, NULL, 0, out, le);
	SC_TRANSMIT_TEST_RET(card, apdu, "PSO Compute Digital Signature failed");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

static int
esteid_get_pin_info(sc_card_t *card, struct sc_pin_cmd_data *data)
{
	const u8 get_pin_info[] = {0xA0, 0x03, 0x83, 0x01, data->pin_reference};
	struct sc_apdu apdu;
	u8 apdu_resp[SC_MAX_APDU_RESP_SIZE];
	size_t taglen;
	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu_ex(&apdu, 0x00, 0xCB, 0x00, 0xFF, get_pin_info, sizeof(get_pin_info), apdu_resp, sizeof(apdu_resp));
	SC_TRANSMIT_TEST_RET(card, apdu, "GET DATA(pin info) failed");
	if (apdu.resplen < 3 || apdu.resp[0] != 0xA0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	const u8 *tag = sc_asn1_find_tag(card->ctx, apdu_resp + 2, apdu.resplen - 2, 0xDF21, &taglen);
	if (tag == NULL || taglen == 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	data->pin1.tries_left = tag[0];
	data->pin1.max_tries = -1; // "no support, which means the one set in PKCS#15 emulation sticks
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
	tag += taglen;
	tag = sc_asn1_find_tag(card->ctx, tag, apdu.resplen - (tag - apdu_resp), 0xDF2F, &taglen);
	if (tag != NULL && taglen == 1 && tag[0] == 0x00) {
		data->pin1.logged_in |= SC_PIN_STATE_NEEDS_CHANGE;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
esteid_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "PIN CMD is %d", data->cmd);
	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		sc_log(card->ctx, "SC_PIN_CMD_GET_INFO for %d", data->pin_reference);
		LOG_FUNC_RETURN(card->ctx, esteid_get_pin_info(card, data));
	}
	LOG_FUNC_RETURN(card->ctx, iso_ops->pin_cmd(card, data, tries_left));
}

static int
esteid_init(sc_card_t *card)
{
	unsigned long flags, ext_flags;

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
	ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

	_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
esteid_logout(sc_card_t *card)
{
	return gp_select_aid(card, &THALES_AID);
}

struct sc_card_driver *
sc_get_esteid2025_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	esteid_ops = *iso_drv->ops;
	esteid_ops.match_card = esteid_match_card;
	esteid_ops.init = esteid_init;

	esteid_ops.select_file = esteid_select_file;

	esteid_ops.set_security_env = esteid_set_security_env;
	esteid_ops.compute_signature = esteid_compute_signature;
	esteid_ops.pin_cmd = esteid_pin_cmd;
	esteid_ops.logout = esteid_logout;

	return &esteid2025_driver;
}
