/*
 * Support for the eOI card
 *
 * Copyright (C) 2022 Luka Logar <luka.logar@iname.com>
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "opensc.h"

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include <openssl/aes.h>
#include <openssl/sha.h>
#include "internal.h"
#include "sm/sm-eac.h"
#include "common/compat_strlcpy.h"
#include "card-eoi.h"

static struct sc_card_operations eoi_ops;

static struct {
	int len;
	struct sc_object_id oid;
} eoi_curves[] = {
	/* secp384r1 */
	{384, {{1, 3, 132, 0, 34, -1}}}
};

static char *eoi_model = "ChipDocLite";

/* The description of the driver. */
static struct sc_card_driver eoi_drv =
{
	"eOI (Slovenian eID card)",
	"eOI",
	&eoi_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table eoi_atrs[] = {
	/* Contact interface */
	{ "3b:d5:18:ff:81:91:fe:1f:c3:80:73:c8:21:10:0a", NULL, NULL, SC_CARD_TYPE_EOI, 0, NULL },
	/* Contactless interface */
	{ "3b:85:80:01:80:73:c8:21:10:0e", NULL, NULL, SC_CARD_TYPE_EOI_CONTACTLESS, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

/*
 * CAN is stored encrypted in a file that (looks like) is pointed to by 'Card CAN' PIN object.
 * eoi_decrypt_can() decrypts CAN from it's encrypted form
 */

static void rol(u8 *to, const u8 *from)
{
	int i;
	u8 b = from[0] & 0x80;
	for (i = 15; i >= 0; i--) {
		u8 bo = b;
		b = from[i] & 0x80;
		to[i] = (from[i] << 1) | (bo ? 1 : 0);
		if ((i == 15) && bo)
			to[i] = (to[i] ^ 0x87) | 1;
	}
}

static int aes256_ecb_encrypt(const u8 *key, const u8 input[AES_BLOCK_SIZE], u8 output[AES_BLOCK_SIZE])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int r = 0, pos, len = pos = AES_BLOCK_SIZE;
	if (!ctx)
		goto err;
	if (!EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL))
		goto err;
	/* Disable padding, otherwise EVP_EncryptFinal() will fail */
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
		goto err;
	if (!EVP_EncryptUpdate(ctx, output, &pos, input, len))
		goto err;
	len -= pos;
	if (!EVP_EncryptFinal(ctx, output + pos, &len))
		goto err;
	r = 1;
err:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return r;
}

static int aes256_ecb_decrypt(const u8 *key, const u8 input[AES_BLOCK_SIZE], u8 output[AES_BLOCK_SIZE])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int r = 0, pos, len = pos = AES_BLOCK_SIZE;
	if (!ctx)
		goto err;
	if (!EVP_DecryptInit(ctx, EVP_aes_256_ecb(), key, NULL))
		goto err;
	/* Disable padding, otherwise it will fail to decrypt non-padded inputs */
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
		goto err;
	if (!EVP_DecryptUpdate(ctx, output, &pos, input, len))
		goto err;
	len -= pos;
	if (!EVP_DecryptFinal(ctx, output + pos, &len))
		goto err;
	r = 1;
err:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return r;
}

/*
 * CAN decrypt magic...
 */
static int get_can_key(const u8 *key, const u8 round, const u8 *input, u8 *output)
{
	size_t i;
	u8 tmp[3][AES_BLOCK_SIZE];
	memset(tmp[0], 0, AES_BLOCK_SIZE);
	if (!aes256_ecb_encrypt(key, tmp[0], tmp[0]))
		return 0;
	rol(tmp[1], tmp[0]);
	rol(tmp[0], tmp[1]);
	memset(tmp[1], 0, AES_BLOCK_SIZE);
	tmp[1][11] = 4;
	tmp[1][13] = 1;
	tmp[1][15] = round;
	if (!aes256_ecb_encrypt(key, tmp[1], tmp[2]))
		return 0;
	memset(tmp[1], 0, AES_BLOCK_SIZE);
	memcpy(tmp[1], &input[AES_BLOCK_SIZE], 8);
	tmp[1][8] = 0x80;
	for (i = 0; i < AES_BLOCK_SIZE; i++)
		tmp[0][i] = tmp[0][i] ^ tmp[1][i] ^ tmp[2][i];
	if (!aes256_ecb_encrypt(key, tmp[0], output))
		return 0;
	return 1;
}

#define AES256_KEY_LEN 32

static int eoi_decrypt_can(struct sc_pkcs15_u8 *enc_can, char *can) {
	/* Magic key that is used to decrypt CAN */
	const u8 magic_key[AES256_KEY_LEN] = {0xC8, 0x12, 0x0F, 0xD8, 0x21, 0x20, 0x1F, 0x77, 0xF1, 0x83, 0x9D, 0xD8, 0x86, 0xB0, 0x5C, 0xF2, 0x4F, 0x7E, 0x52, 0x66, 0xE5, 0x87, 0x89, 0x2B, 0xF4, 0xC5, 0xE5, 0x4C, 0x54, 0xA1, 0x55, 0x30};
	u8 can_key[AES256_KEY_LEN] = { 0 };

	if (!can || !enc_can || !enc_can->value || enc_can->len != 24)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (!get_can_key(magic_key, 0x01, enc_can->value, &can_key[0]))
		return SC_ERROR_INTERNAL;
	if (!get_can_key(magic_key, 0x02, enc_can->value, &can_key[AES_BLOCK_SIZE]))
		return SC_ERROR_INTERNAL;

	if (!aes256_ecb_decrypt(can_key, enc_can->value, (u8 *)can))
		return SC_ERROR_INTERNAL;
	can[AES_BLOCK_SIZE - 1] = 0;

	return SC_SUCCESS;
}

static int eoi_sm_open(struct sc_card *card)
{
	int r;
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	if (!privdata)
		return SC_ERROR_INTERNAL;

	if (!privdata->can[0]) {
		/* If no CAN is specified in conf, try to decrypt it from enc_can file */
		r = eoi_decrypt_can(&privdata->enc_can, privdata->can);
		sc_log_openssl(card->ctx);
		LOG_TEST_RET(card->ctx, r, "Cannot decrypt CAN");
	}
	/* CAN should be 6 chars long */
	if (strlen(privdata->can) != 6)
		return SC_ERROR_DECRYPT_FAILED;

	memset(&pace_input, 0, sizeof pace_input);
	memset(&pace_output, 0, sizeof pace_output);

	pace_input.pin_id = PACE_PIN_ID_CAN;
	pace_input.pin = (u8 *)privdata->can;
	pace_input.pin_length = strlen(privdata->can);

	/* EF.CardAccess can only be read from MF */
	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_RET(card->ctx, r, "sc_select_file failed");

	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);
	LOG_TEST_RET(card->ctx, r, "Error verifying CAN");

	return SC_SUCCESS;
}

static int eoi_get_data(sc_card_t *card, u8 data_id, u8 *buf, size_t len)
{
	int r;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, data_id);
	apdu.resp = buf;
	apdu.resplen = len;
	apdu.le = len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

#define ATR_MATCH 1

static int eoi_match_card(sc_card_t* card) {
	LOG_FUNC_CALLED(card->ctx);
	if (_sc_match_atr(card, eoi_atrs, &card->type) >= 0) {
		sc_log(card->ctx, "ATR recognized as Slovenian eID card");
		LOG_FUNC_RETURN(card->ctx, ATR_MATCH);
	}
	LOG_FUNC_RETURN(card->ctx, !ATR_MATCH);
}

static int eoi_init(sc_card_t* card) {
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	u8 version[6];
	size_t i, j;
	scconf_block **found_blocks, *block;
	int r;
	char *can;

	LOG_FUNC_CALLED(card->ctx);

	if (eoi_get_data(card, 0x16, version, sizeof(version)) != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);

	if (privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	privdata = sc_mem_secure_alloc(sizeof(struct eoi_privdata));
	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	/* sc_mem_secure_alloc()-ed memory may not be zeroized */
	memset(privdata, 0, sizeof(struct eoi_privdata));
	card->drv_data = privdata;

	sprintf(privdata->version, "%X%02X.%02X%02X", version[0], version[1], version[2], version[3]);
	sc_log(card->ctx, "App version: %s", privdata->version);

	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
	card->sm_ctx.ops.open = eoi_sm_open;

	card->max_send_size = SC_MAX_APDU_DATA_SIZE;
	card->max_recv_size = SC_MAX_APDU_RESP_SIZE;

	for (i = 0; i < sizeof eoi_curves / sizeof * eoi_curves; ++i) {
		r = _sc_card_add_ec_alg(card, eoi_curves[i].len, SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE, 0, &eoi_curves[i].oid);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Add EC alg failed");
	}

	can = getenv("EOI_CAN");
	if (can)
		strlcpy(privdata->can, can, sizeof(privdata->can));
	for (i = 0; card->ctx->conf_blocks[i]; i++) {
		found_blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
					"card_driver", "eoi");
		if (!found_blocks)
			continue;

		for (j = 0, block = found_blocks[j]; block; j++, block = found_blocks[j]) {
			if (!privdata->can[0]) {
				const char *can = scconf_get_str(block, "can", NULL);
				if (can)
					strlcpy(privdata->can, can, sizeof(privdata->can));
			}
		}
		free(found_blocks);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

err:
	if (privdata) {
		sc_mem_clear(privdata, sizeof(struct eoi_privdata));
		sc_mem_secure_free(privdata, sizeof(struct eoi_privdata));
	}
	card->drv_data = NULL;

	LOG_FUNC_RETURN(card->ctx, r);
}

static int eoi_finish(sc_card_t* card)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	if (privdata) {
		sc_mem_clear(privdata, sizeof(struct eoi_privdata));
		sc_mem_secure_free(privdata, sizeof(struct eoi_privdata));
	}

	card->drv_data = NULL;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int eoi_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	int i;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	for (i = 0; i < MAX_OBJECTS && privdata->pin_paths[i]; i++) {
		if (privdata->pin_paths[i] && sc_compare_path(privdata->pin_paths[i], in_path)) {
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}
	}

	LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->select_file(card, in_path, file_out));
}

static int eoi_logout(struct sc_card *card)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct sc_apdu apdu;
	u8 buf[256];
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	iso_sm_close(card);
	card->sm_ctx.sm_mode = SM_MODE_NONE;

	if (card->reader->flags & SC_READER_ENABLE_ESCAPE) {
		/*
		 * Get the UID of the ISO 14443 A card. (see PCSC Part 3)
		 * The "official" PKCS#11 does it and we do the same.
		 */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x00, 0x00);
		apdu.cla = 0xFF;
		apdu.resp = buf;
		apdu.resplen = 256;
		apdu.lc = 0;
		apdu.le = 256;

		r = sc_transmit_apdu(card, &apdu);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int eoi_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (data->cmd == SC_PIN_CMD_VERIFY && card->sm_ctx.sm_mode == SM_MODE_NONE) {
		/* Establish SM before any PIN VERIFY command */
		r = eoi_sm_open(card);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		int pin_reference = data->pin_reference;
		int pin2_len = data->pin2.len;
		/* Verify PUK, establish SM if necessary */
		data->cmd = SC_PIN_CMD_VERIFY;
		data->pin_reference = data->puk_reference;
		r = eoi_pin_cmd(card, data, tries_left);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* RESET RETRY COUNTER */
		data->cmd = SC_PIN_CMD_UNBLOCK;
		data->pin_reference = 0x80|pin_reference;
		data->pin1.len = 0;
		data->pin2.len = 0;
		r = sc_get_iso7816_driver()->ops->pin_cmd(card, data, tries_left);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* Continue as CHANGE PIN */
		data->cmd = SC_PIN_CMD_CHANGE;
		data->pin2.len = pin2_len;
	}

	/* CHANGE PIN command does not send the old PIN as it should already be verified */
	if (data->cmd == SC_PIN_CMD_CHANGE)
		data->pin1.len = 0;

	LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->pin_cmd(card, data, tries_left));
}

static int
eoi_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int r = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);
	switch (cmd) {
	case SC_CARDCTL_GET_MODEL:
		if (!ptr)
			r = SC_ERROR_INVALID_ARGUMENTS;
		else
			*(char **)ptr = eoi_model;
		break;
	default:
		r = sc_get_iso7816_driver()->ops->card_ctl(card, cmd, ptr);
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

#define ALREADY_PROCESSED 0x80000000

static int eoi_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct sc_apdu apdu;
	u8 sbuf[4];
	int i, r, locked = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (!card || !env)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* We don't know yet which hash is used. So just store the security_env data and return */
	if (!(env->algorithm_flags & ALREADY_PROCESSED)) {
		privdata->key_len = BYTES4BITS(env->algorithm_ref);
		memcpy(&privdata->sec_env, env, sizeof(struct sc_security_env));
		privdata->se_num = se_num;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	if (!(env->flags & SC_SEC_ENV_KEY_REF_PRESENT))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (env->key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (env->algorithm != SC_ALGORITHM_EC)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x81, 0xB6);
	sbuf[0] = 0x91;
	sbuf[1] = 0x02;
	if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
		sbuf[2] = 0x11;
	else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA256)
		sbuf[2] = 0x21;
	else if (env->algorithm_flags & (SC_ALGORITHM_ECDSA_RAW|SC_ALGORITHM_ECDSA_HASH_NONE))
		sbuf[2] = 0x22;
	else
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	for (i = 0; i < MAX_OBJECTS && privdata->prkey_mappings[i][1]; i++) {
		if (privdata->prkey_mappings[i][0] == env->key_ref[0])
			break;
	}
	if (i == MAX_OBJECTS)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	sbuf[3] = privdata->prkey_mappings[i][1];
	apdu.lc = 4;
	apdu.datalen = 4;
	apdu.data = sbuf;
	if (se_num > 0) {
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0) {
		r = SC_SUCCESS;
		goto err;
	}
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
err:
	if (locked)
		sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int eoi_compute_signature(struct sc_card *card, const u8 * data, size_t data_len, u8 *out, size_t outlen)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	/*
	 * Guess the correct mode. If the size is less than the full-key-len, it must be a hash then
	 */
	if (privdata->key_len != data_len) {
		switch (data_len) {
			case SHA_DIGEST_LENGTH:
				privdata->sec_env.algorithm_flags = SC_ALGORITHM_ECDSA_HASH_SHA1;
				break;
			case SHA256_DIGEST_LENGTH:
				privdata->sec_env.algorithm_flags = SC_ALGORITHM_ECDSA_HASH_SHA256;
				break;
		}
	}
	/* Now we know which hash is used */
	privdata->sec_env.algorithm_flags |= ALREADY_PROCESSED;

	/* Perform the true set_security_env */
	r = eoi_set_security_env(card, &privdata->sec_env, privdata->se_num);
	LOG_TEST_RET(card->ctx, r, "set_security_env failed");

	LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->compute_signature(card, data, data_len, out, outlen));
}

struct sc_card_driver *sc_get_eoi_driver(void)
{
	eoi_ops = *sc_get_iso7816_driver()->ops;

	eoi_ops.match_card = eoi_match_card;
	eoi_ops.init = eoi_init;
	eoi_ops.finish = eoi_finish;
	eoi_ops.select_file = eoi_select_file;
	eoi_ops.logout = eoi_logout;
	eoi_ops.pin_cmd = eoi_pin_cmd;
	eoi_ops.card_ctl = eoi_card_ctl;
	eoi_ops.set_security_env = eoi_set_security_env;
	eoi_ops.compute_signature = eoi_compute_signature;

	return &eoi_drv;
}

#else

struct sc_card_driver* sc_get_eoi_driver(void) {
	return NULL;
}

#endif
