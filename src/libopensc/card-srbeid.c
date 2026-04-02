/*
 * card-srbeid.c: Driver for Serbian cards using the CardEdge PKI applet.
 *
 * Serbian eID, health insurance, and Chamber of Commerce cards use the
 * same CardEdge PKCS#15 applet.  Cards are matched either by ATR
 * (Gemalto 2014+ eID) or by AID selection.
 *
 * Copyright (C) 2026 LibreSCRS contributors
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

#include "card-srbeid.h"
#include "internal.h"
#include "log.h"

/* MSE algorithm byte for RSA-2048 PKCS#1 v1.5 */
#define CE_MSE_ALG_RSA2048 0x02u

static struct sc_card_operations srbeid_ops;
static const struct sc_card_operations *iso_ops;

static struct sc_card_driver srbeid_drv = {
		"Serbian CardEdge driver",
		"srbeid",
		&srbeid_ops,
		NULL, 0, NULL};

/*
 * ATR table.
 *
 * Gemalto (2014+) Serbian eID:  3B:FF:94 ...
 * Mask FF:FF:FF matches the first 3 bytes; remaining bytes vary between
 * individual cards and are don't-cares.
 *
 * Other CardEdge cards have no distinct ATR and are identified via AID
 * selection in match_card().
 *
 * Apollo 2008 ATR 3B:B9:18 ... is intentionally absent — no CardEdge applet.
 */
static const struct sc_atr_table srbeid_atrs[] = {
		{"3B:FF:94", "FF:FF:FF", "Serbian eID (Gemalto 2014+)", SC_CARD_TYPE_SRBEID_BASE, 0, NULL},
		{NULL,       NULL,	     NULL,			   0,			      0, NULL}
};

static int
srbeid_match_card(sc_card_t *card)
{
	/* ATR hit: Gemalto 2014+ Serbian eID (3B:FF:94 ...) */
	if (_sc_match_atr(card, srbeid_atrs, &card->type) >= 0)
		return 1;

	/* AID-based match for cards without a distinct ATR. */
	if (iso7816_select_aid(card, AID_PKCS15, AID_PKCS15_LEN, NULL, NULL) == SC_SUCCESS) {
		sc_log(card->ctx, "srbeid: CardEdge applet found via AID");
		card->type = SC_CARD_TYPE_SRBEID_BASE;
		return 1;
	}

	return 0;
}

static int
srbeid_init(sc_card_t *card)
{
	LOG_FUNC_CALLED(card->ctx);

	card->caps |= SC_CARD_CAP_ISO7816_PIN_INFO;

	_sc_card_add_rsa_alg(card, 2048,
			SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE, 0);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * select_file — handle CardEdge's proprietary 10-byte FCI response.
 *
 * CardEdge FCI layout (10 bytes, big-endian):
 *   [FID_H FID_L Size_H Size_L ACL*6]
 *
 * iso7816_select_file() would try to parse this as ISO 7816-4 TLV (tag 0x6F)
 * and fail with SC_ERROR_UNKNOWN_DATA_RECEIVED.
 *
 * DF_NAME (AID) selection is delegated to the ISO layer.
 */
static int
srbeid_select_file(sc_card_t *card, const sc_path_t *in_path,
		sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 fci[16];
	sc_file_t *file;
	int r;

	if (in_path->type == SC_PATH_TYPE_DF_NAME)
		return iso_ops->select_file(card, in_path, file_out);

	/* AID-only path (path.len==0, path.aid.len>0): PKCS#15 layer wants
	 * to select the applet before a PIN or key operation. */
	if (in_path->len == 0 && in_path->aid.len > 0)
		return iso7816_select_aid(card, in_path->aid.value,
				in_path->aid.len, NULL, NULL);

	if (in_path->len != 2)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);
	apdu.data = in_path->value;
	apdu.datalen = 2;
	apdu.lc = 2;
	apdu.resp = fci;
	apdu.resplen = sizeof(fci);
	apdu.le = 10;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "SELECT FILE failed");

	if (apdu.resplen < 4)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (file_out) {
		file = sc_file_new();
		if (!file)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

		file->id = ((unsigned)in_path->value[0] << 8) | in_path->value[1];
		file->path = *in_path;
		file->size = ((size_t)fci[2] << 8) | (size_t)fci[3];
		file->type = SC_FILE_TYPE_WORKING_EF;
		*file_out = file;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * set_security_env — send MSE SET to the card.
 *
 * The PKCS#15 layer selects the PKI applet via the AID attached to
 * key_info.path before calling this function (see select_key_file()
 * in pkcs15-sec.c).
 *
 * OpenSC populates env->key_ref[0] from key_info.key_reference (low byte).
 * The high byte is always 0x60 (CE_KEYS_BASE_FID >> 8) for all CardEdge
 * key FIDs, so the full 2-byte FID is reconstructed here.
 *
 * MSE SET template P2: 0xB6 for signing, 0xB8 for deciphering.
 */
static int
srbeid_set_security_env(sc_card_t *card,
		const struct sc_security_env *env, int se_num)
{
	sc_apdu_t apdu;
	u8 mse_data[7];
	unsigned key_ref;
	u8 p2;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	(void)se_num;

	/* Extract key FID. */
	if ((env->flags & SC_SEC_ENV_FILE_REF_PRESENT) && env->file_ref.len >= 2) {
		key_ref = ((unsigned)env->file_ref.value[0] << 8) | (unsigned)env->file_ref.value[1];
	} else if ((env->flags & SC_SEC_ENV_KEY_REF_PRESENT) && env->key_ref_len >= 1) {
		key_ref = CE_KEYS_BASE_FID | (unsigned)env->key_ref[0];
	} else {
		sc_log(card->ctx, "srbeid: set_security_env: no key reference");
		return SC_ERROR_INCORRECT_PARAMETERS;
	}

	/* Determine MSE SET template from operation type. */
	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		p2 = 0xB6;
		break;
	case SC_SEC_OPERATION_DECIPHER:
		p2 = 0xB8;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* MSE SET: tag 0x80 = algorithm (RSA2048), tag 0x84 = key ref (2 bytes BE) */
	mse_data[0] = 0x80;
	mse_data[1] = 0x01;
	mse_data[2] = CE_MSE_ALG_RSA2048;
	mse_data[3] = 0x84;
	mse_data[4] = 0x02;
	mse_data[5] = (u8)((key_ref >> 8) & 0xFF);
	mse_data[6] = (u8)(key_ref & 0xFF);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, p2);
	apdu.data = mse_data;
	apdu.datalen = sizeof(mse_data);
	apdu.lc = sizeof(mse_data);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "MSE SET failed");

	sc_log(card->ctx, "srbeid: set_security_env: key_ref=0x%04x p2=0x%02x", key_ref, p2);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * compute_signature — PSO COMPUTE DIGITAL SIGNATURE (00 2A 9E 00).
 *
 * MSE SET has already been sent by set_security_env().
 * CardEdge uses P2=0x00 (not 0x9A as in ISO 7816-8), so we cannot
 * delegate to iso7816_compute_signature().
 */
static int
srbeid_compute_signature(sc_card_t *card,
		const u8 *data, size_t datalen, u8 *out, size_t outlen)
{
	sc_apdu_t apdu;
	u8 resp[256];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x00);
	apdu.data = data;
	apdu.datalen = datalen;
	apdu.lc = datalen;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = sizeof(resp);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "PSO COMPUTE DIGITAL SIGNATURE failed");

	if (apdu.resplen > outlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

/*
 * decipher — PSO DECIPHER (00 2A 80 86).
 *
 * MSE SET has already been sent by set_security_env().
 * CardEdge does not use a padding indicator byte, so we cannot
 * delegate to iso7816_decipher().
 */
static int
srbeid_decipher(sc_card_t *card,
		const u8 *crgram, size_t crgram_len, u8 *out, size_t outlen)
{
	sc_apdu_t apdu;
	u8 resp[256];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.data = crgram;
	apdu.datalen = crgram_len;
	apdu.lc = crgram_len;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = sizeof(resp);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "PSO DECIPHER failed");

	if (apdu.resplen > outlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

struct sc_card_driver *
sc_get_srbeid_driver(void)
{
	/* Save ISO ops for delegation, then override what we handle. */
	iso_ops = sc_get_iso7816_driver()->ops;
	srbeid_ops = *iso_ops;
	srbeid_ops.match_card = srbeid_match_card;
	srbeid_ops.init = srbeid_init;
	srbeid_ops.select_file = srbeid_select_file;
	srbeid_ops.set_security_env = srbeid_set_security_env;
	srbeid_ops.compute_signature = srbeid_compute_signature;
	srbeid_ops.decipher = srbeid_decipher;

	return &srbeid_drv;
}
