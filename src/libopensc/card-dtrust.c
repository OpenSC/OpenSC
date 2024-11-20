/*
 * card-dtrust.c: Support for (CardOS based) D-Trust Signature Cards
 *
 * Copyright (C) 2023 Mario Haustein <mario.haustein@hrz.tu-chemnitz.de>
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
 *
 * based on card-cardos.c
 */

/*
 * This are the support periods for the D-Trust cards. The end of life time is
 * set by the expiry of the underlying card operating system and sets the
 * validity limit of the issued certificates. After end of life, the code paths
 * for the affected products may be removed, as the cards are then not useful
 * anymore.
 *
 * 				Start of Sales	End of Sales	End of life
 * D-Trust Card 4.1/4.4		n/a		Nov 2024	Sep 2026
 * D-Trust Card 5.1/5.4		Nov 2023	n/a		Oct 2028
 * D-Trust Card 6.1/6.4		Summer 2025	n/a		n/a
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "libopensc/pace.h"

#include "asn1.h"
#include "card-cardos-common.h"
#include "internal.h"
#include "sm/sm-eac.h"

#include "card-dtrust.h"

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations dtrust_ops;

// clang-format off
static struct sc_card_driver dtrust_drv = {
	"D-Trust Signature Card",
	"dtrust",
	&dtrust_ops,
	NULL, 0, NULL
};
// clang-format on

struct dtrust_drv_data_t {
	/* track PACE state */
	unsigned char can : 1;
	/* save the current security environment */
	const sc_security_env_t *env;
};

// clang-format off
static const struct sc_atr_table dtrust_atrs[] = {
	/* D-Trust Signature Card v4.1 and v4.4 - CardOS 5.4
	 *
	 * The ATR was intentionally omitted from minidriver_registration[] within win32/customactions.cpp
	 * as it is identical to that of CardOS v5.4 and therefore already included.
	 * Any new ATR may need an entry in minidriver_registration[]. */
	{ "3b:d2:18:00:81:31:fe:58:c9:04:11", NULL, NULL, SC_CARD_TYPE_DTRUST_V4_1_STD, 0, NULL },


	/* D-Trust Signature Card v5.1 and v5.4 - CardOS 6.0
	 *
	 * These cards are dual interface cards. Thus they have separate ATRs. */

	/* contact based */
	{ "3b:d2:18:00:81:31:fe:58:cb:01:16", NULL, NULL, SC_CARD_TYPE_DTRUST_V5_1_STD, 0, NULL },

	/* contactless */
	{ "3b:82:80:01:cb:01:c9",             NULL, NULL, SC_CARD_TYPE_DTRUST_V5_1_STD, 0, NULL },
	{ "07:78:77:74:03:cb:01:09",          NULL, NULL, SC_CARD_TYPE_DTRUST_V5_1_STD, 0, NULL },

	{ NULL,                               NULL, NULL, 0,                            0, NULL }
};
// clang-format on

static struct sc_object_id oid_secp256r1 = {
		{1, 2, 840, 10045, 3, 1, 7, -1}
};
static struct sc_object_id oid_secp384r1 = {
		{1, 3, 132, 0, 34, -1}
};

static int
_dtrust_match_cardos(sc_card_t *card)
{
	int r;
	size_t prodlen;
	u8 buf[32];

	/* check OS version */
	r = sc_get_data(card, 0x0182, buf, 32);
	LOG_TEST_RET(card->ctx, r, "OS version check failed");

	if (card->type == SC_CARD_TYPE_DTRUST_V4_1_STD) {
		if (r != 2 || buf[0] != 0xc9 || buf[1] != 0x04)
			return SC_ERROR_WRONG_CARD;
	} else if (card->type == SC_CARD_TYPE_DTRUST_V5_1_STD) {
		if (r != 2 || buf[0] != 0xcb || buf[1] != 0x01)
			return SC_ERROR_WRONG_CARD;
	}

	/* check product name */
	r = sc_get_data(card, 0x0180, buf, 32);
	LOG_TEST_RET(card->ctx, r, "Product name check failed");

	prodlen = (size_t)r;
	if (card->type == SC_CARD_TYPE_DTRUST_V4_1_STD) {
		if (prodlen != strlen("CardOS V5.4     2019") + 1 || memcmp(buf, "CardOS V5.4     2019", prodlen))
			return SC_ERROR_WRONG_CARD;
	} else if (card->type == SC_CARD_TYPE_DTRUST_V5_1_STD) {
		if (prodlen != strlen("CardOS V6.0 2021") + 1 || memcmp(buf, "CardOS V6.0 2021", prodlen))
			return SC_ERROR_WRONG_CARD;
	}

	return SC_SUCCESS;
}

static int
_dtrust_match_profile(sc_card_t *card)
{
	sc_path_t cia_path;
	int r;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	size_t slen, plen;
	const u8 *sp, *pp;
	char *name;

	sc_format_path("5032", &cia_path);
	cia_path.aid.len = sizeof(cia_path.aid.value);
	r = sc_hex_to_bin("E8:28:BD:08:0F:A0:00:00:01:67:45:53:49:47:4E", (u8 *)&cia_path.aid.value, &cia_path.aid.len);
	LOG_TEST_RET(card->ctx, r, "Formatting AID failed");

	r = sc_select_file(card, &cia_path, NULL);
	LOG_TEST_RET(card->ctx, r, "Selecting CIA path failed");

	r = sc_read_binary(card, 0, buf, SC_MAX_APDU_BUFFER_SIZE, NULL);
	LOG_TEST_RET(card->ctx, r, "Reading CIA information failed");

	sp = sc_asn1_find_tag(card->ctx, buf, r, 0x30, &slen);
	if (sp == NULL)
		return SC_ERROR_WRONG_CARD;

	/* check vendor */
	pp = sc_asn1_find_tag(card->ctx, sp, slen, 0x0c, &plen);
	if (pp == NULL)
		return SC_ERROR_WRONG_CARD;

	if (plen != 16 || memcmp(pp, "D-TRUST GmbH (C)", 16))
		return SC_ERROR_WRONG_CARD;

	/* check profile */
	pp = sc_asn1_find_tag(card->ctx, sp, slen, 0x80, &plen);
	if (pp == NULL)
		return SC_ERROR_WRONG_CARD;

	/*
	 * The profile string contains (two) additional characters. They depend
	 * on the production process, but aren't relevant for determining the
	 * card profile.
	 */
	if (card->type == SC_CARD_TYPE_DTRUST_V4_1_STD) {
		if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.1 Std. RSA 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V4_1_STD;
		else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 4.1 Multi ECC 2", 28))
			card->type = SC_CARD_TYPE_DTRUST_V4_1_MULTI;
		else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.1 M100 ECC 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V4_1_M100;
		else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 4.4 Std. RSA 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V4_4_STD;
		else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 4.4 Multi ECC 2", 28))
			card->type = SC_CARD_TYPE_DTRUST_V4_4_MULTI;
		else
			return SC_ERROR_WRONG_CARD;
	} else if (card->type == SC_CARD_TYPE_DTRUST_V5_1_STD) {
		if (plen >= 27 && !memcmp(pp, "D-TRUST Card 5.1 Std. RSA 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V5_1_STD;
		else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 5.1 Multi ECC 2", 28))
			card->type = SC_CARD_TYPE_DTRUST_V5_1_MULTI;
		else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 5.1 M100 ECC 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V5_1_M100;
		else if (plen >= 27 && !memcmp(pp, "D-TRUST Card 5.4 Std. RSA 2", 27))
			card->type = SC_CARD_TYPE_DTRUST_V5_4_STD;
		else if (plen >= 28 && !memcmp(pp, "D-TRUST Card 5.4 Multi ECC 2", 28))
			card->type = SC_CARD_TYPE_DTRUST_V5_4_MULTI;
		else
			return SC_ERROR_WRONG_CARD;
	}

	name = malloc(plen + 1);
	if (name == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(name, pp, plen);
	name[plen] = '\0';
	card->name = name;

	sc_log(card->ctx, "found %s", card->name);

	return SC_SUCCESS;
}

static int
dtrust_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, dtrust_atrs, &card->type) < 0)
		return 0;

	if (_dtrust_match_cardos(card) != SC_SUCCESS)
		return 0;

	if (_dtrust_match_profile(card) != SC_SUCCESS)
		return 0;

	sc_log(card->ctx, "D-Trust Signature Card");

	return 1;
}

static int
_dtrust_get_serialnr(sc_card_t *card)
{
	int r;

	card->serialnr.len = SC_MAX_SERIALNR;
	r = sc_parse_ef_gdo(card, card->serialnr.value, &card->serialnr.len, NULL, 0);
	if (r < 0) {
		card->serialnr.len = 0;
		return r;
	}

	return SC_SUCCESS;
}

static int
dtrust_init(sc_card_t *card)
{
	struct dtrust_drv_data_t *drv_data;
	int r;
	const size_t data_field_length = 437;
	unsigned long flags, ext_flags;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->cla = 0x00;

	drv_data = calloc(1, sizeof(struct dtrust_drv_data_t));
	if (drv_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	drv_data->can = 0;
	card->drv_data = drv_data;

	r = _dtrust_get_serialnr(card);
	LOG_TEST_RET(card->ctx, r, "Error reading serial number.");

	card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_ISO7816_PIN_INFO;

	card->max_send_size = data_field_length - 6;
#ifdef _WIN32
	/* see card-cardos.c */
	if (card->reader->max_send_size == 255 && card->reader->max_recv_size == 256) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "resetting reader to use data_field_length");
		card->reader->max_send_size = data_field_length - 6;
		card->reader->max_recv_size = data_field_length - 3;
	}
#endif

	card->max_send_size = sc_get_max_send_size(card); /* see card-cardos.c */
	card->max_recv_size = data_field_length - 2;
	card->max_recv_size = sc_get_max_recv_size(card);

	flags = 0;
	r = SC_ERROR_WRONG_CARD;

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_STD:
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		flags |= SC_ALGORITHM_RSA_PAD_PSS;
		flags |= SC_ALGORITHM_RSA_PAD_OAEP;
		flags |= SC_ALGORITHM_RSA_HASH_SHA256;
		flags |= SC_ALGORITHM_RSA_HASH_SHA384;
		flags |= SC_ALGORITHM_RSA_HASH_SHA512;
		flags |= SC_ALGORITHM_MGF1_SHA256;
		flags |= SC_ALGORITHM_MGF1_SHA384;
		flags |= SC_ALGORITHM_MGF1_SHA512;

		_sc_card_add_rsa_alg(card, 3072, flags, 0);

		r = SC_SUCCESS;
		break;

	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		flags |= SC_ALGORITHM_ECDSA_RAW;
		flags |= SC_ALGORITHM_ECDH_CDH_RAW;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE;

		_sc_card_add_ec_alg(card, 256, flags, ext_flags, &oid_secp256r1);

		r = SC_SUCCESS;
		break;

	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		flags |= SC_ALGORITHM_ECDSA_RAW;
		flags |= SC_ALGORITHM_ECDH_CDH_RAW;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE;

		_sc_card_add_ec_alg(card, 384, flags, ext_flags, &oid_secp384r1);

		r = SC_SUCCESS;
		break;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	free((char *)card->name);
	free(card->drv_data);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
dtrust_select_app(struct sc_card *card, int ref)
{
	sc_path_t path;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (card->type) {
	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		switch (ref) {
		case DTRUST5_PIN_ID_QES:
			sc_format_path("3F000101", &path);
			break;

		case DTRUST5_PIN_ID_AUT:
			sc_format_path("3F000102", &path);
			break;

		default:
			sc_format_path("3F00", &path);
			break;
		}

		r = sc_select_file(card, &path, NULL);
		LOG_TEST_RET(card->ctx, r, "Selecting master file failed");
		break;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
dtrust_perform_pace(struct sc_card *card,
		int ref,
		const unsigned char *pin,
		size_t pinlen,
		int *tries_left)
{
	struct dtrust_drv_data_t *drv_data;
	int r;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;

	/* The PKCS#11 layer cannot provide a CAN. Instead we consider the
	 * following sources for CAN input.
	 *  1. A CAN provided by the caller
	 *  2. A cached CAN when the cache feature is enabled
	 *  3. If the reader supports the PACE protocol, we let it query for a
	 *     CAN on the pin pad.
	 *  4. Querying the user interactively if possible */
	if (ref == PACE_PIN_ID_CAN) {
		/* TODO: Query the CAN cache if no CAN is provided by the caller. */

		if (pin == NULL) {
			if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) {
				/* If no CAN is provided and the reader is
				 * PACE-capable, we leave pin == NULL to request the
				 * ready for querying the CAN on its pin pad. */
				sc_log(card->ctx, "Letting the reader prompt for the CAN on its pin pad.");
			} else {
				/* TODO: Request user input */
				sc_log(card->ctx, "Unable to query for the CAN. Aborting.");
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
			}
		}
	}

	/* Establish secure channel via PACE */
	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);

	pace_input.pin_id = ref;
	pace_input.pin = pin;
	pace_input.pin_length = pinlen;

	/* Select the right application for authentication. */
	r = dtrust_select_app(card, ref);
	LOG_TEST_RET(card->ctx, r, "Selecting application failed");

	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	/* We need to track whether we established a PACE channel with CAN.
	 * Checking against card->sm_ctx.sm_mode != SM_MODE_TRANSMIT is not
	 * sufficient as PACE-capable card readers handle secure messaging
	 * transparently and authenticating against non-CAN-PINs doesn't allow
	 * us to verify the QES or AUT-PIN. */
	if (ref == PACE_PIN_ID_CAN) {
		drv_data->can = r == SC_SUCCESS;
	}

	free(pace_output.ef_cardaccess);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	if (tries_left != NULL) {
		if (r != SC_SUCCESS &&
				pace_output.mse_set_at_sw1 == 0x63 &&
				(pace_output.mse_set_at_sw2 & 0xc0) == 0xc0) {
			*tries_left = pace_output.mse_set_at_sw2 & 0x0f;
		} else {
			*tries_left = -1;
		}
	}

	/* TODO: Put CAN into the cache if necessary. */

	return r;
}

static int
dtrust_pin_cmd_get_info(struct sc_card *card,
		struct sc_pin_cmd_data *data,
		int *tries_left)
{
	struct dtrust_drv_data_t *drv_data;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;

	switch (data->pin_reference) {
	case PACE_PIN_ID_CAN:
		/* unlimited number of retries */
		*tries_left = -1;
		data->pin1.max_tries = -1;
		data->pin1.tries_left = -1;
		r = SC_SUCCESS;
		break;

	case PACE_PIN_ID_PUK:
	case DTRUST5_PIN_ID_PIN_T:
	case DTRUST5_PIN_ID_PIN_T_AUT:
		/* Select the right application for authentication. */
		r = dtrust_select_app(card, data->pin_reference);
		LOG_TEST_RET(card->ctx, r, "Selecting application failed");

		/* FIXME: Doesn't work. Returns SW1=69 SW2=85 (Conditions of use not satisfied) instead. */
		data->pin1.max_tries = 3;
		r = eac_pace_get_tries_left(card, data->pin_reference, &data->pin1.tries_left);
		if (tries_left != NULL) {
			*tries_left = data->pin1.tries_left;
		}
		break;

	default:
		/* Check if CAN authentication is necessary */
		if (!drv_data->can) {
			/* Establish a secure channel with CAN to query PIN information. */
			r = dtrust_perform_pace(card, PACE_PIN_ID_CAN, NULL, 0, NULL);
			LOG_TEST_RET(card->ctx, r, "CAN authentication failed");

			/* Select the right application again. */
			r = dtrust_select_app(card, data->pin_reference);
			LOG_TEST_RET(card->ctx, r, "Selecting application failed");
		}

		/* Now query PIN information */
		r = iso_ops->pin_cmd(card, data, tries_left);
		break;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_pin_cmd_verify(struct sc_card *card,
		struct sc_pin_cmd_data *data,
		int *tries_left)
{
	struct dtrust_drv_data_t *drv_data;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;

	switch (data->pin_reference) {
	/* When the retry counter reaches 1 PACE-PINs become suspended. Before
	 * verifying a suspended PIN, the CAN has to verified. We go without
	 * verifying the CAN here, as this only matters for the PUK and the
	 * transport PIN. Neither PIN ist required during normal operation. The
	 * user has to resume a suspended PIN using dtrust-tool which manages
	 * CAN authentication. */
	case PACE_PIN_ID_CAN:
	case PACE_PIN_ID_PUK:
	case DTRUST5_PIN_ID_PIN_T:
	case DTRUST5_PIN_ID_PIN_T_AUT:
		/* Establish secure channel via PACE */
		r = dtrust_perform_pace(card, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		break;

	default:
		/* Check if CAN authentication is necessary */
		if (!drv_data->can) {
			/* Establish a secure channel with CAN to to verify the PINs. */
			r = dtrust_perform_pace(card, PACE_PIN_ID_CAN, NULL, 0, NULL);
			LOG_TEST_RET(card->ctx, r, "CAN authentication failed");

			/* Select the right application again. */
			r = dtrust_select_app(card, data->pin_reference);
			LOG_TEST_RET(card->ctx, r, "Selecting application failed");
		}

		/* Now verify the PIN */
		r = iso_ops->pin_cmd(card, data, tries_left);

		break;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_pin_cmd(struct sc_card *card,
		struct sc_pin_cmd_data *data,
		int *tries_left)
{
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* Upper layers may try to verify the PIN twice, first with PIN type
	 * SC_AC_CHV and then with PIN type SC_AC_CONTEXT_SPECIFIC. For the
	 * second attempt we first check by SC_PIN_CMD_GET_INFO whether a
	 * second PIN authentication is still necessary. If not, we simply
	 * return without a second verification attempt. Otherwise we perform
	 * the verification as requested. This only matters for pin pad readers
	 * to prevent the user from prompting the PIN twice. */
	if (data->cmd == SC_PIN_CMD_VERIFY && data->pin_type == SC_AC_CONTEXT_SPECIFIC) {
		struct sc_pin_cmd_data data2;

		sc_log(card->ctx, "Checking if verification of PIN 0x%02x is necessary.", data->pin_reference);

		memset(&data2, 0, sizeof(struct sc_pin_cmd_data));
		data2.pin_reference = data->pin_reference;
		data2.pin1 = data->pin1;

		/* Check verification state */
		data2.cmd = SC_PIN_CMD_GET_INFO;
		data2.pin_type = data->pin_type;
		r = dtrust_pin_cmd(card, &data2, tries_left);

		if (data2.pin1.logged_in == SC_PIN_STATE_LOGGED_IN) {
			/* Return if we are already authenticated */
			sc_log(card->ctx, "PIN 0x%02x already verified. Skipping authentication.", data->pin_reference);

			data->pin1 = data2.pin1;
			LOG_FUNC_RETURN(card->ctx, r);
		}

		sc_log(card->ctx, "Additional verification of PIN 0x%02x is necessary.", data->pin_reference);
	}

	/* No special handling for D-Trust Card 4.1/4.4 */
	if (card->type >= SC_CARD_TYPE_DTRUST_V4_1_STD && card->type <= SC_CARD_TYPE_DTRUST_V4_4_MULTI) {
		r = iso_ops->pin_cmd(card, data, tries_left);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	switch (data->cmd) {
	case SC_PIN_CMD_GET_INFO:
		r = dtrust_pin_cmd_get_info(card, data, tries_left);
		break;

	case SC_PIN_CMD_VERIFY:
		r = dtrust_pin_cmd_verify(card, data, tries_left);
		break;

	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
dtrust_set_security_env(sc_card_t *card,
		const sc_security_env_t *env,
		int se_num)
{
	struct dtrust_drv_data_t *drv_data;

	if (card == NULL || env == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;
	drv_data->env = env;

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || env->key_ref_len != 1) {
		sc_log(card->ctx, "No or invalid key reference");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/*
	 * The card does not support to set a security environment. Instead a
	 * predefined template has to be loaded via MSE RESTORE which depends
	 * on the algorithm used.
	 */

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02) {
			se_num = 0x31;
		} else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_OAEP) {
			switch (env->algorithm_flags & SC_ALGORITHM_MGF1_HASHES) {
			case SC_ALGORITHM_MGF1_SHA256:
				se_num = 0x32;
				break;
			case SC_ALGORITHM_MGF1_SHA384:
				se_num = 0x33;
				break;
			case SC_ALGORITHM_MGF1_SHA512:
				se_num = 0x34;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	case SC_SEC_OPERATION_SIGN:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01) {
			switch (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) {
			case SC_ALGORITHM_RSA_HASH_SHA256:
				se_num = 0x25;
				break;
			case SC_ALGORITHM_RSA_HASH_SHA384:
				se_num = 0x26;
				break;
			case SC_ALGORITHM_RSA_HASH_SHA512:
				se_num = 0x27;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
			/*
			 * According to the specification the message digest has
			 * to match the hash function used for the PSS scheme.
			 * We don't enforce this constraint here as the output
			 * is valid in all cases as long as the message digest
			 * is calculated in software and not on the card.
			 */

			switch (env->algorithm_flags & SC_ALGORITHM_MGF1_HASHES) {
			case SC_ALGORITHM_MGF1_SHA256:
				se_num = 0x19;
				break;
			case SC_ALGORITHM_MGF1_SHA384:
				se_num = 0x1A;
				break;
			case SC_ALGORITHM_MGF1_SHA512:
				se_num = 0x1B;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW) {
			switch (card->type) {
			case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
			case SC_CARD_TYPE_DTRUST_V4_1_M100:
			case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
				/* ECDSA on SHA-256 hashes. Other hashes will work though. */
				se_num = 0x21;
				break;

			case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
			case SC_CARD_TYPE_DTRUST_V5_1_M100:
			case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
				/* ECDSA on SHA-384 hashes. Other hashes will work though. */
				se_num = 0x22;
				break;

			default:
				return SC_ERROR_NOT_SUPPORTED;
			}
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	case SC_SEC_OPERATION_DERIVE:
		if (env->algorithm_flags & SC_ALGORITHM_ECDH_CDH_RAW) {
			se_num = 0x39;
		} else {
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	return iso_ops->restore_security_env(card, se_num);
}

static int
dtrust_compute_signature(struct sc_card *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	struct dtrust_drv_data_t *drv_data;
	unsigned long flags;
	size_t buflen = 0, tmplen;
	u8 *buf = NULL;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;
	flags = drv_data->env->algorithm_flags;

	/*
	 * PKCS#1 padded signatures require some special handling. When using
	 * the PKCS#1 scheme, first a digest info OID is prepended to the
	 * message digest. Afterward this resulting octet string is padded to
	 * the length of the key modulus. The card performs padding, but
	 * requires the digest info to be prepended in software.
	 */

	/* Only PKCS#1 signature scheme requires special handling */
	if (!(flags & SC_ALGORITHM_RSA_PAD_PKCS1))
		return iso_ops->compute_signature(card, data, data_len, out, outlen);

	/*
	 * We have to clear the padding flag, because padding is done in
	 * hardware. We are keeping the hash algorithm flags, to ensure the
	 * digest info is prepended before padding.
	 */
	flags &= ~SC_ALGORITHM_RSA_PAD_PKCS1;
	flags |= SC_ALGORITHM_RSA_PAD_NONE;

	/* 32 Bytes should be enough to prepend the digest info */
	buflen = data_len + 32;
	buf = sc_mem_secure_alloc(buflen);
	if (buf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	tmplen = buflen;

	/* Prepend digest info */
	r = sc_pkcs1_encode(card->ctx, flags, data, data_len, buf, &tmplen, 0, NULL);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Prepending digest info failed");

	/* Do padding in hardware and compute signature */
	r = iso_ops->compute_signature(card, buf, tmplen, out, outlen);

err:
	sc_mem_secure_clear_free(buf, buflen);

	return r;
}

static int
dtrust_decipher(struct sc_card *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch (card->type) {
	/* No special handling necessary for RSA cards. */
	case SC_CARD_TYPE_DTRUST_V4_1_STD:
	case SC_CARD_TYPE_DTRUST_V4_4_STD:
	case SC_CARD_TYPE_DTRUST_V5_1_STD:
	case SC_CARD_TYPE_DTRUST_V5_4_STD:
		LOG_FUNC_RETURN(card->ctx, iso_ops->decipher(card, data, data_len, out, outlen));

	/* Elliptic Curve cards cannot use PSO:DECIPHER command and need to
	 * perform key agreement by a CardOS specific command. */
	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V5_1_M100:
	case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
		LOG_FUNC_RETURN(card->ctx, cardos_ec_compute_shared_value(card, data, data_len, out, outlen));

	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int
dtrust_logout(sc_card_t *card)
{
	struct dtrust_drv_data_t *drv_data;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	drv_data = card->drv_data;

	sc_sm_stop(card);
	drv_data->can = 0;

	/* If PACE is done between reader and card, SM is transparent to us as
	 * it ends at the reader. With CLA=0x0C we provoke a SM error to
	 * disable SM on the reader. */
	if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC) {
		struct sc_apdu apdu;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xA4, 0x00, 0x00);
		apdu.cla = 0x0C;

		r = sc_transmit_apdu(card, &apdu);
		if (r != SC_SUCCESS)
			sc_log(card->ctx, "Warning: Could not logout.");
	}

	r = sc_select_file(card, sc_get_mf_path(), NULL);

	LOG_FUNC_RETURN(card->ctx, r);
}

struct sc_card_driver *
sc_get_dtrust_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	dtrust_ops = *iso_ops;
	dtrust_ops.match_card = dtrust_match_card;
	dtrust_ops.init = dtrust_init;
	dtrust_ops.finish = dtrust_finish;
	dtrust_ops.pin_cmd = dtrust_pin_cmd;
	dtrust_ops.set_security_env = dtrust_set_security_env;
	dtrust_ops.compute_signature = dtrust_compute_signature;
	dtrust_ops.decipher = dtrust_decipher;
	dtrust_ops.logout = dtrust_logout;

	return &dtrust_drv;
}
