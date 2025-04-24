/*
 * Driver for Polish eID v2.0 cards issued from 2021.
 *
 * Copyright (C) 2025 Piotr Wegrzyn <piotro@piotro.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "libopensc/asn1.h"
#include "libopensc/card-edo.h"
#include "libopensc/card-edo2021.h"
#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "libopensc/sm.h"
#include "sm/sm-eac.h"
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

static struct sc_card_operations edo2021_ops;

static struct sc_card_driver edo2021_drv = {
		"Polish eID card issued from 2021 (e-dowód, eDO)",
		"edo2021",
		&edo2021_ops,
		NULL, 0, NULL};

static const struct sc_atr_table edo2021_atrs[] = {
		{"3b:89:80:01:02:4d:4b:4d:57:4b:53:4b:54:11", NULL, NULL, SC_CARD_TYPE_EDO2021, 0, NULL},
		{NULL,					NULL, NULL, 0,		      0, NULL}
};

static struct {
	int len;
	struct sc_object_id oid;
} edo2021_curves[] = {
		// secp384r1
		{384, {{1, 3, 132, 0, 34, -1}}}
};

static int
edo2021_match_card(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, edo2021_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Polish eID card (edo2021 driver).");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int
edo2021_set_security_env(struct sc_card *card, const struct sc_security_env *env, size_t data_len)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!env)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (env->algorithm != SC_ALGORITHM_EC || !(env->flags & SC_SEC_ENV_KEY_REF_PRESENT))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	u8 payload[] = {0x91, 0x02, 0x00, 0x00};

	if (data_len <= SHA_DIGEST_LENGTH) {
		payload[2] = 0x11;
	} else if (data_len <= SHA256_DIGEST_LENGTH) {
		payload[2] = 0x21;
	} else if (data_len <= SHA512_DIGEST_LENGTH) {
		payload[2] = 0x22;
	} else {
		sc_log(card->ctx, "unsupported data length for signature (%ld)", data_len);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	payload[3] |= env->key_ref[0];

	struct sc_apdu apdu;
	sc_format_apdu_ex(&apdu, 0x00, 0x22, 0x81, 0xB6, payload, sizeof payload, NULL, 0);

	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "SW check failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * This function is a stub for driver calls, it caches data from for later execution of edo2021_set_security_env
 * when signing.
 */
static int
edo2021_set_security_env_driver_stub(struct sc_card *card, const struct sc_security_env *env, int se_num)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	struct edo2021_privdata *privdata = (struct edo2021_privdata *)card->drv_data;

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (env->operation != SC_SEC_OPERATION_SIGN || se_num > 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	memcpy(&privdata->sec_env, env, sizeof(struct sc_security_env));

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
edo2021_compute_signature(struct sc_card *card, const u8 *data, size_t data_len, u8 *out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	struct edo2021_privdata *privdata = (struct edo2021_privdata *)card->drv_data;

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	/* Now we know the data length (from hashed input), perform the true set_security_env. */
	LOG_TEST_RET(card->ctx, edo2021_set_security_env(card, &privdata->sec_env, data_len), "set_security_env failed");

	/* Call default iso7816 handler, we need this card op only for security_env. */
	LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->compute_signature(card, data, data_len, out, outlen));

	LOG_FUNC_CALLED(card->ctx);
}

static int
edo2021_init(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->drv_data = calloc(1, sizeof(struct edo2021_privdata));
	if (!card->drv_data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);

	card->max_send_size = SC_MAX_APDU_RESP_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;

	for (size_t i = 0; i < sizeof edo2021_curves / sizeof *edo2021_curves; ++i) {
		LOG_TEST_RET(card->ctx, _sc_card_add_ec_alg(card, edo2021_curves[i].len, SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE, 0, &edo2021_curves[i].oid), "Add EC alg failed");
	}

	LOG_TEST_RET(card->ctx, sc_enum_apps(card), "Enumerate apps failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
edo2021_finish(sc_card_t *card)
{
	LOG_FUNC_CALLED(card->ctx);

	free(card->drv_data);
	card->drv_data = NULL;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

struct sc_card_driver *
sc_get_edo2021_driver(void)
{
	edo2021_ops = *sc_get_iso7816_driver()->ops;
	edo2021_ops.match_card = edo2021_match_card;
	edo2021_ops.init = edo2021_init;
	edo2021_ops.finish = edo2021_finish;
	edo2021_ops.set_security_env = edo2021_set_security_env_driver_stub;
	edo2021_ops.compute_signature = edo2021_compute_signature;
	edo2021_ops.logout = edo_logout;
	edo2021_ops.card_reader_lock_obtained = edo_card_reader_lock_obtained;

	return &edo2021_drv;
}

#else

#include "libopensc/opensc.h"

struct sc_card_driver *
sc_get_edo2021_driver(void)
{
	return NULL;
}

#endif
