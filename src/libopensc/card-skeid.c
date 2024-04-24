/*
 * card-skeid.c: Support for (CardOS based) cards issued as identity documents in Slovakia
 *
 * Copyright (C) 2022 Juraj Šarinay <juraj@sarinay.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "internal.h"

#define SKEID_KNOWN_URL_LEN 46

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations skeid_ops;
static struct sc_card_driver skeid_drv = {
	"Slovak eID card",
	"skeid",
	&skeid_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table skeid_atrs[] = {
	/* Slovak eID v3 - CardOS 5.4
	 *
	 * The ATR was intentionally omitted from minidriver_registration[] within win32/customactions.cpp
	 * as it is identical to that of CardOS v5.4 and therefore already included.
	 * Any new ATR may need an entry in minidriver_registration[]. */
	{"3b:d2:18:00:81:31:fe:58:c9:04:11", NULL, NULL, SC_CARD_TYPE_SKEID_V3, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static int skeid_known_url(sc_card_t * card)
{
	const struct sc_aid skeid_aid_eid = {{0xE8, 0x07, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x02}, 9};
	const char *known_url = "\x80\x01\x00\x5F\x50\x28http://www.minv.sk/cif/cif-sk-eid-v3.xml";
	u8 buf[SKEID_KNOWN_URL_LEN];

	sc_path_t url_path;

	int r = SC_ERROR_WRONG_CARD;

	sc_path_set(&url_path, SC_PATH_TYPE_DF_NAME, skeid_aid_eid.value, skeid_aid_eid.len, 0, 0);

	if (sc_select_file(card, &url_path, NULL) == SC_SUCCESS
		&& sc_get_data(card, 0x7F62, buf, SKEID_KNOWN_URL_LEN) == SKEID_KNOWN_URL_LEN
		&& !memcmp(buf, known_url, SKEID_KNOWN_URL_LEN))
		r = SC_SUCCESS;

	return r;
}

static int skeid_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, skeid_atrs, &card->type) < 0 || skeid_known_url(card) != SC_SUCCESS)
		return 0;

	sc_log(card->ctx,  "Slovak eID card v3 (CardOS 5.4)");

	return 1;
}

static int skeid_get_serialnr(sc_card_t *card)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x81);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;
	if (apdu.resplen == 8) {
		/* cache serial number */
		memcpy(card->serialnr.value, rbuf, 8);
		card->serialnr.len = 8;
	} else {
		sc_log(card->ctx, "unexpected response to GET DATA serial number");
		return SC_ERROR_INTERNAL;
	}
	return SC_SUCCESS;
}

static int skeid_init(sc_card_t *card)
{
	const unsigned long flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
	const size_t data_field_length = 437;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	card->name = "Slovak eID (CardOS)";
	card->type = SC_CARD_TYPE_SKEID_V3;
	card->cla = 0x00;

	r = skeid_get_serialnr(card);
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

	r = _sc_card_add_rsa_alg(card, 3072, flags, 0);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int skeid_set_security_env(sc_card_t *card,
		const sc_security_env_t *env,
		int se_num)
{
	int key_id;
	int r;

	assert(card != NULL && env != NULL);

	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT) || env->key_ref_len != 1) {
		sc_log(card->ctx, "No or invalid key reference");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* here we follow the behaviour of the proprietary driver accompanying the card
	 * where security operations are preceded by MSE RESTORE rather than MSE SET
	 */
	key_id = env->key_ref[0];
	r = sc_restore_security_env(card, key_id);

	return r;
}

static int skeid_logout(sc_card_t *card)
{
	int r;
	sc_path_t path;

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	return r;

}

struct sc_card_driver * sc_get_skeid_driver(void)
{
	if (iso_ops == NULL) iso_ops = sc_get_iso7816_driver()->ops;
	skeid_ops = *iso_ops;
	skeid_ops.match_card = skeid_match_card;
	skeid_ops.init = skeid_init;
	skeid_ops.set_security_env = skeid_set_security_env;
	skeid_ops.logout = skeid_logout;
	return &skeid_drv;
}
