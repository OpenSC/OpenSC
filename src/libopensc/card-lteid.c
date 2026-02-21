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

#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "card-lteid.h"
#include "internal.h"
#include "opensc.h"
#include "sm/sm-eac.h"

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations lteid_ops;

static struct sc_card_driver lteid_drv = {
		"Lithuanian eID card (asmens tapatybės kortelė)", "lteid",
		&lteid_ops, NULL, 0, NULL};

static const struct sc_atr_table lteid_atrs[] = {
		{"3b:9d:18:81:31:fc:35:80:31:c0:69:4d:54:43:4f:53:73:02:06:05:d0", NULL, NULL, SC_CARD_TYPE_LTEID, 0, NULL},
		{NULL,							     NULL, NULL, 0,		      0, NULL}
};

#ifdef _WIN32
#define CAN_STORE_FILE "\\lteid_can"
#else
#define CAN_STORE_FILE "/lteid_can"
#endif

static int
lteid_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, lteid_atrs, &card->type) >= 0) {
		return 1;
	}
	return 0;
}

static int
lteid_get_stored_can(sc_card_t *card, unsigned char *can)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	char path[PATH_MAX];

	sc_get_cache_dir(card->ctx, path, sizeof(path));
	strcat(path, CAN_STORE_FILE);

	FILE *fd = fopen(path, "r");

	if (!fd) {
		LOG_FUNC_RETURN(card->ctx, 0);
	}

	if (LTEID_CAN_LENGTH != fread(can, 1, LTEID_CAN_LENGTH, fd)) {
		LOG_FUNC_RETURN(card->ctx, 0);
	}

	fclose(fd);

	LOG_FUNC_RETURN(card->ctx, 1);
}

static int
lteid_clear_stored_can(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	char path[PATH_MAX];

	sc_get_cache_dir(card->ctx, path, sizeof(path));
	strcat(path, CAN_STORE_FILE);

	if (unlink(path) == 0) {
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	} else {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
}

static int
lteid_get_can(sc_card_t *card, struct establish_pace_channel_input *pace_input)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	struct lteid_drv_data *drv_data = DRVDATA(card);
	int got_can = 0;

	drv_data->can_from_file = 0;

	// Try env variables first
	const char *can_from_env = getenv("LTEID_CAN");
	if (can_from_env && strlen(can_from_env) == LTEID_CAN_LENGTH) {
		got_can = 1;
		memcpy(drv_data->can, can_from_env, LTEID_CAN_LENGTH);
	}

	// Try getting one stored in file by lteid-tool
	if (!got_can && lteid_get_stored_can(card, drv_data->can)) {
		got_can = 1;
		drv_data->can_from_file = 1;
	}

	// Finally see if there is a default in configuration
	if (!got_can) {
		const char *can_from_config = NULL;

		for (size_t i = 0; card->ctx->conf_blocks[i]; ++i) {
			scconf_block **blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i], "card_driver", "lteid");
			if (!blocks)
				continue;
			for (size_t j = 0; blocks[j]; ++j)
				if ((can_from_config = scconf_get_str(blocks[j], "can", NULL)))
					break;
			free(blocks);
		}

		if (can_from_config && strlen(can_from_config) == LTEID_CAN_LENGTH) {
			got_can = 1;
			memcpy(drv_data->can, can_from_config, LTEID_CAN_LENGTH);
		}
	}

	if (!got_can) {
		sc_log(card->ctx, "Missing or invalid CAN. 6 digits required.");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
	}

	pace_input->pin_id = PACE_PIN_ID_CAN;
	pace_input->pin = drv_data->can;
	pace_input->pin_length = LTEID_CAN_LENGTH;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_perform_pace(struct sc_card *card, const int ref, const unsigned char *pin, size_t pinlen, int *tries_left)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = DRVDATA(card);
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};

	if (drv_data->pace && drv_data->pace_pin_ref != ref) {
		sc_log(card->ctx, "Re-opening PACE with pin ref 0x%02x. Previous pin ref: 0x%02x.", ref, drv_data->pace_pin_ref);
		sc_sm_stop(card);
	}

	if (ref == PACE_PIN_ID_CAN && !pin) {
		if (SC_SUCCESS != lteid_get_can(card, &pace_input)) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN);
		}
	} else {
		pace_input.pin_id = ref;
		pace_input.pin = pin;
		pace_input.pin_length = pinlen;
	}

	int rv = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);
	if (rv != SC_SUCCESS) {
		sc_log(card->ctx, "Error performing PACE for pin ref 0x%02x.", ref);

		drv_data->pace = 0;
		drv_data->pace_pin_ref = 0;

		// Special case after entering incorrect PACE PIN twice. Card locks with 1 PIN attempt remaining.
		if (ref == PACE_PIN_ID_PIN && rv == SC_ERROR_NO_CARD_SUPPORT) {
			rv = SC_ERROR_AUTH_METHOD_BLOCKED;
		}

		// When a CAN code authentication fails and CAN code comes from file store - clear it.
		// We don't want to make multiple attempts if code is wrong. User should run lteid-tool
		// again to set up the card.
		if (ref == PACE_PIN_ID_CAN && drv_data->can_from_file && rv != SC_ERROR_INTERNAL) {
			if (lteid_clear_stored_can(card)) {
				drv_data->can_from_file = 0;
			}
		}

		LOG_FUNC_RETURN(card->ctx, rv);
	}

	// Track PACE status
	drv_data->pace = 1;
	drv_data->pace_pin_ref = ref;

	free(pace_output.ef_cardaccess);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_unlock(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (SC_SUCCESS != lteid_perform_pace(card, PACE_PIN_ID_CAN, NULL, 0, NULL)) {
		sc_log(card->ctx, "Unlock with CAN code failed. No CAN found in environment, opensc.conf or cache.");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_init(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = calloc(1, sizeof(struct lteid_drv_data));

	if (drv_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	drv_data->pace = 0;
	drv_data->pace_pin_ref = 0;
	card->drv_data = drv_data;

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = 65535;
	card->max_recv_size = 65535;
	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO | SC_CARD_CAP_APDU_EXT;

	_sc_card_add_ec_alg(card, 384, SC_ALGORITHM_ECDSA_HASH_NONE | SC_ALGORITHM_ECDSA_RAW, 0, NULL);

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	LOG_TEST_RET(card->ctx, lteid_unlock(card), "Unlock card failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_sm_stop(card);

	free(card->drv_data);
	card->drv_data = NULL;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_logout(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_sm_stop(card);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	struct lteid_drv_data *drv_data = DRVDATA(card);
	int rv;

	// Authentication key refers to PACE PIN -> 0x3
	// Meanwhile, signing key refers to PIN.QES -> 0x81. This pin is verifiable via regular iso7816 cmd verify call.
	if (data->cmd == SC_PIN_CMD_VERIFY && (data->pin_reference == PACE_PIN_ID_PIN)) {
		rv = lteid_perform_pace(card, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_FUNC_RETURN(card->ctx, rv);
	}

	// PACE CAN code info: there's ACE2 file, but it does not contain any info about max or remaining attempts.
	if (data->cmd == SC_PIN_CMD_GET_INFO && (data->pin_reference == PACE_PIN_ID_CAN)) {
		data->pin1.max_tries = -1;
		data->pin1.tries_left = -1;
		if (tries_left) {
			*tries_left = -1;
		}
	}

	// PACE PIN and PUK codes: max and remaining attempts are stored in ACE3 and ACE4 files.
	if (data->cmd == SC_PIN_CMD_GET_INFO && (data->pin_reference == PACE_PIN_ID_PIN || data->pin_reference == PACE_PIN_ID_PUK)) {
		struct sc_apdu apdu;
		unsigned char buf[0xbe] = {0};
		u8 id[] = {0xac, 0x00};
		size_t taglen = 0;

		switch (data->pin_reference) {
		case PACE_PIN_ID_PIN:
			id[1] = 0xe3;
			break;
		case PACE_PIN_ID_PUK:
			id[1] = 0xe4;
			break;
		default:
			break;
		}

		sc_format_apdu_ex(&apdu, 0x00, 0xa4, 0x00, 0x04, id, sizeof(id), buf, sizeof(buf));

		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");

		const u8 *tag = sc_asn1_find_tag(card->ctx, buf, sizeof(buf), 0x62, &taglen);
		tag = sc_asn1_find_tag(card->ctx, tag, taglen, 0xa5, &taglen);
		tag = sc_asn1_find_tag(card->ctx, tag, taglen, 0xa2, &taglen);
		tag = sc_asn1_find_tag(card->ctx, tag, taglen, 0xa3, &taglen);
		tag = sc_asn1_find_tag(card->ctx, tag, taglen, 0x82, &taglen);

		if (tag && taglen == 2) {
			data->pin1.tries_left = tag[0];
			data->pin1.max_tries = tag[1];

			if (tries_left) {
				*tries_left = data->pin1.tries_left;
			}
		} else {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_FOUND);
		}

		if (drv_data->pace_pin_ref == data->pin_reference) {
			data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
		} else {
			data->pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
		}

		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	// Any other commands - fall back to regular iso7816 methods.
	// Mostly for PIN.QES(ID 0x81) which is a regular pin.
	rv = iso_ops->pin_cmd(card, data, tries_left);

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int
lteid_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num)
{
	LOG_FUNC_CALLED(card->ctx);

	struct sc_apdu apdu;

	if (env == NULL || env->key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	sc_log(card->ctx, "algo: %lu operation: %d keyref: %d", env->algorithm, env->operation, env->key_ref[0]);

	if (env->algorithm != SC_ALGORITHM_EC || env->operation != SC_SEC_OPERATION_SIGN)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	const u8 data[] = {0x84, 0x01, env->key_ref[0]};
	sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x41, 0xB6, data, sizeof(data), NULL, 0);

	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SET SECURITY ENV failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
lteid_compute_signature(struct sc_card *card, const u8 *data, size_t data_len, u8 *out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	// Usually this is called with 104 bytes buffer. But we expect card to return 96 byte hash.
	if (outlen < 96)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memset(out, 0, outlen);

	const int rv = iso_ops->compute_signature(card, data, data_len, out, 96);

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int
lteid_process_fci(struct sc_card *card, struct sc_file *file, const u8 *buf, size_t buflen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	int rv = iso_ops->process_fci(card, file, buf, buflen);

	if (rv != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, rv);
	}

	// Card reports most of the file size as 0, even if they're not empty.
	// This confuses PKCS#15 loader, and it fails to load/init keys/certs/pins/etc.
	// As a quick workaround - lets report size to be something large enough to fit any object.
	if (file->size == 0) {
		file->size = 2048;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

struct sc_card_driver *
sc_get_lteid_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	lteid_ops = *iso_ops;
	lteid_ops.match_card = lteid_match_card;
	lteid_ops.init = lteid_init;
	lteid_ops.finish = lteid_finish;
	lteid_ops.set_security_env = lteid_set_security_env;
	lteid_ops.compute_signature = lteid_compute_signature;
	lteid_ops.pin_cmd = lteid_pin_cmd;
	lteid_ops.logout = lteid_logout;
	lteid_ops.process_fci = lteid_process_fci;

	return &lteid_drv;
}

#else

#include "opensc.h"

struct sc_card_driver *
sc_get_lteid_driver(void)
{
	return NULL;
}

#endif