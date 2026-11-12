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
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include "internal.h"
#include "sm/sm-eac.h"
#include "common/compat_strlcpy.h"
#include "card-eoi.h"
#include <eac/ca.h>
#include <eac/eac.h>
#include <eac/objects.h>
#include <eac/ta.h>

static struct sc_card_operations eoi_ops;

static struct {
	int len;
	struct sc_object_id oid;
} eoi_curves[] = {
	/* secp384r1 */
	{384, {{1, 3, 132, 0, 34, -1}}}
};

static char *eoi_model = "ChipDocLite";
static char *eoi_chipdoc_model = "ChipDoc v3.2";

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

/* Decrypt the 24-byte encrypted CAN blob (16 enc || 8 SN) into its 16-byte
 * plaintext block. Exposed for card-chipdocit: same chip, same key. */
int
chipdoc_decrypt_can_block(const u8 *enc_can, size_t enc_can_len, u8 out[AES_BLOCK_SIZE])
{
	/* Magic key that is used to decrypt CAN */
	const u8 magic_key[AES256_KEY_LEN] = {0xC8, 0x12, 0x0F, 0xD8, 0x21, 0x20, 0x1F, 0x77, 0xF1, 0x83, 0x9D, 0xD8, 0x86, 0xB0, 0x5C, 0xF2, 0x4F, 0x7E, 0x52, 0x66, 0xE5, 0x87, 0x89, 0x2B, 0xF4, 0xC5, 0xE5, 0x4C, 0x54, 0xA1, 0x55, 0x30};
	u8 can_key[AES256_KEY_LEN] = { 0 };

	if (!enc_can || !out || enc_can_len != 24)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!get_can_key(magic_key, 0x01, enc_can, &can_key[0]))
		return SC_ERROR_INTERNAL;
	if (!get_can_key(magic_key, 0x02, enc_can, &can_key[AES_BLOCK_SIZE]))
		return SC_ERROR_INTERNAL;
	if (!aes256_ecb_decrypt(can_key, enc_can, out))
		return SC_ERROR_INTERNAL;
	return SC_SUCCESS;
}

static int
eoi_decrypt_can(struct sc_pkcs15_u8 *enc_can, char *can)
{
	int r;

	if (!can || !enc_can || !enc_can->value)
		return SC_ERROR_INVALID_ARGUMENTS;
	r = chipdoc_decrypt_can_block(enc_can->value, enc_can->len, (u8 *)can);
	if (r != SC_SUCCESS)
		return r;
	can[AES_BLOCK_SIZE - 1] = 0;
	return SC_SUCCESS;
}

/*
 * ChipDoc cards use Chip Authentication (BSI TR-03110) instead of PACE:
 * EF(D004) holds the static CA key and the applet returns no nonce/token.
 */

/* Card Authentication public key: ECDH, AES-CBC, CMAC-128 */
#define EOI_CHIPDOC_CA_STD_DP 18 /* index of secp521r1 in OpenPACE */
/* The ChipDoc applet reports 63C7 after reset; the empty VERIFY probe is free. */
#define EOI_CHIPDOC_PIN_MAX_TRIES 7

static const u8 eoi_chipdoc_aid[] = {
	0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x03, 0x63, 0x64, 0x79, 0x6E, 0x69, 0x64
};

static int eoi_chipdoc_transmit(struct sc_card *card, u8 cla, u8 ins, u8 p1, u8 p2,
		const u8 *data, size_t data_len)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins, p1, p2);
	apdu.cla = cla;
	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

/* EF(D004): 5-byte header, length, then the uncompressed public point. */
static int eoi_chipdoc_read_ca_pubkey(struct sc_card *card, u8 **pubkey, size_t *pubkey_len)
{
	static const u8 ef_d004[] = {0xD0, 0x04};
	struct sc_apdu apdu;
	u8 buf[256];
	u8 *key;
	size_t point_len;
	int r;

	*pubkey = NULL;
	*pubkey_len = 0;

	/* Applet files are not reachable from MF. */
	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select MF");

	r = iso7816_select_aid(card, eoi_chipdoc_aid, sizeof eoi_chipdoc_aid, NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select the ChipDoc applet");

	r = eoi_chipdoc_transmit(card, 0x00, 0xA4, 0x02, 0x00, ef_d004, sizeof ef_d004);
	LOG_TEST_RET(card->ctx, r, "Cannot select EF(Chip Authentication public key)");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x00, 0x00);
	apdu.resp = buf;
	apdu.resplen = sizeof buf;
	apdu.le = 137;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Cannot read EF(Chip Authentication public key)");

	if (apdu.resplen < 6 || buf[0] != 0x00 || buf[1] != 0x01) {
		sc_log(card->ctx, "Unexpected content of EF(Chip Authentication public key)");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	point_len = buf[4];
	if (point_len < 3 || apdu.resplen < 5 + point_len) {
		sc_log(card->ctx, "Unexpected length of the Chip Authentication public key");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	key = malloc(1 + point_len);
	if (!key)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	key[0] = 0x04;
	memcpy(key + 1, buf + 5, point_len);

	*pubkey = key;
	*pubkey_len = 1 + point_len;
	return SC_SUCCESS;
}

/*
 * EF(D003) holds the serial in a 5A TLV; report its last 8 bytes.  The file
 * is under MF, so re-select the applet after.
 */
static int eoi_chipdoc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	static const u8 ef_d003[] = {0xD0, 0x03};
	struct sc_apdu apdu;
	u8 buf[16];
	size_t len, offs;
	int r;

	if (card->serialnr.len)
		goto end;

	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select MF");

	r = eoi_chipdoc_transmit(card, 0x00, 0xA4, 0x02, 0x00, ef_d003, sizeof ef_d003);
	LOG_TEST_RET(card->ctx, r, "Cannot select EF(serial number)");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x00, 0x00);
	apdu.resp = buf;
	apdu.resplen = sizeof buf;
	apdu.le = 0x0C;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Cannot read EF(serial number)");

	/* MF selection drops the applet context; re-select it for the caller. */
	r = iso7816_select_aid(card, eoi_chipdoc_aid, sizeof eoi_chipdoc_aid, NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select the ChipDoc applet");

	if (apdu.resplen < 2 || buf[0] != 0x5A || buf[1] > apdu.resplen - 2)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);


	len = buf[1];
	offs = len > 8 ? len - 8 : 0;
	memcpy(card->serialnr.value, buf + 2 + offs, len - offs);
	card->serialnr.len = len - offs;

end:
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	return SC_SUCCESS;
}


static int eoi_chipdoc_sm_open(struct sc_card *card)
{
	EAC_CTX *eac_ctx = NULL;
	BUF_MEM *comp_pubkey = NULL;
	u8 *picc_pubkey = NULL;
	size_t picc_pubkey_len = 0;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = eoi_chipdoc_read_ca_pubkey(card, &picc_pubkey, &picc_pubkey_len);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot read the Chip Authentication public key");

	EAC_init();
	eac_ctx = EAC_CTX_new();
	if (!eac_ctx)
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_OUT_OF_MEMORY, "Out of memory");
	eac_ctx->tr_version = EAC_TR_VERSION_2_02;

	if (!EAC_CTX_init_ca(eac_ctx, NID_id_CA_ECDH_AES_CBC_CMAC_128, EOI_CHIPDOC_CA_STD_DP))
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INTERNAL, "Cannot initialize Chip Authentication");

	/* TA_STEP3 only generates the ephemeral key. */
	comp_pubkey = TA_STEP3_generate_ephemeral_key(eac_ctx);
	if (!comp_pubkey)
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INTERNAL, "Cannot generate ephemeral key");

	r = perform_chip_authentication_ex_no_token(card, eac_ctx,
			picc_pubkey, picc_pubkey_len);
	if (r == SC_SUCCESS)
		eac_ctx = NULL;
	LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot perform Chip Authentication");

	/* The first SM command must be SELECT MF. */
	r = sc_select_file(card, sc_get_mf_path(), NULL);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot select MF");

	r = SC_SUCCESS;

err:
	BUF_MEM_clear_free(comp_pubkey);
	if (eac_ctx)
		EAC_CTX_clear_free(eac_ctx);
	if (picc_pubkey) {
		sc_mem_clear(picc_pubkey, picc_pubkey_len);
		free(picc_pubkey);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int eoi_sm_open(struct sc_card *card)
{
	int r;
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct establish_pace_channel_input pace_input;
	struct establish_pace_channel_output pace_output;

	if (!privdata)
		return SC_ERROR_INTERNAL;

	if (privdata->chipdoc_ca) {
		privdata->chipdoc_aid_selected = 0;
		privdata->chipdoc_mse_valid = 0;
	}

	/* Drop ChipDoc SM state invalidated by a reader reset before reopening. */
	if (privdata->chipdoc_ca && card->sm_ctx.sm_mode != SM_MODE_NONE) {
		iso_sm_close(card);
		card->sm_ctx.sm_mode = SM_MODE_NONE;
	}

	if (privdata->chipdoc_ca)
		return eoi_chipdoc_sm_open(card);

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

	/*
	 * ChipDoc cards do not use PACE.  Probe the contact interface only, so
	 * PACE-based eOI cards are unaffected.
	 */
	if (card->type == SC_CARD_TYPE_EOI) {
		u8 *pubkey = NULL;
		size_t pubkey_len = 0;

		if (eoi_chipdoc_read_ca_pubkey(card, &pubkey, &pubkey_len) == SC_SUCCESS) {
			sc_log(card->ctx, "Detected ChipDoc applet using Chip Authentication");
			privdata->chipdoc_ca = 1;
			/* The applet needs extended-length APDUs and supports
			 * GET CHALLENGE for C_GenerateRandom. */
			card->caps |= SC_CARD_CAP_APDU_EXT | SC_CARD_CAP_RAW_RSA_DECIPHER |
					SC_CARD_CAP_ISO7816_PIN_INFO | SC_CARD_CAP_RNG;
		}
		if (pubkey) {
			sc_mem_clear(pubkey, pubkey_len);
			free(pubkey);
		}
	}

	for (i = 0; i < sizeof eoi_curves / sizeof * eoi_curves; ++i) {
		r = _sc_card_add_ec_alg(card, eoi_curves[i].len, SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDSA_HASH_NONE, 0, &eoi_curves[i].oid);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Add EC alg failed");
	}

	if (privdata->chipdoc_ca) {
		/* PKCS#1 v1.5, PSS and raw RSA for 1024-4096 bit keys; the applet pads
		 * itself for signing.  PSO DECIPHER returns the raw RSA block, so leave
		 * PKCS#1 type 2 stripping to the software layer.  PSS uses salt = digest
		 * length and MGF1 with the same hash. */
		for (i = 1024; i <= 4096; i += 256) {
			r = _sc_card_add_rsa_alg(card, i,
					SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_PAD_PSS |
							SC_ALGORITHM_RSA_RAW |
							SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA224 |
							SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 |
							SC_ALGORITHM_RSA_HASH_SHA512 |
							SC_ALGORITHM_MGF1_SHA1 | SC_ALGORITHM_MGF1_SHA224 |
							SC_ALGORITHM_MGF1_SHA256 | SC_ALGORITHM_MGF1_SHA384 |
							SC_ALGORITHM_MGF1_SHA512,
					0);
			LOG_TEST_GOTO_ERR(card->ctx, r, "Add RSA alg failed");
		}
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

static int
eoi_is_chipdoc_root(const sc_path_t *path)
{
	return (path->type == SC_PATH_TYPE_PATH && path->len == 0
			&& path->aid.len == sizeof(eoi_chipdoc_aid)
			&& !memcmp(path->aid.value, eoi_chipdoc_aid, sizeof(eoi_chipdoc_aid)))
		|| (path->type == SC_PATH_TYPE_DF_NAME
			&& path->len == sizeof(eoi_chipdoc_aid)
			&& !memcmp(path->value, eoi_chipdoc_aid, sizeof(eoi_chipdoc_aid)));
}

static int eoi_select_file(sc_card_t *card, const sc_path_t *in_path, sc_file_t **file_out)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct sc_context *ctx = card->ctx;
	int i, r;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (privdata->chipdoc_ca) {
		if (privdata->chipdoc_aid_selected && eoi_is_chipdoc_root(in_path)) {
			sc_log(ctx, "ChipDoc applet is already selected");
			if (file_out)
				*file_out = NULL;
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
		privdata->chipdoc_aid_selected = 0;
		privdata->chipdoc_mse_valid = 0;
	}

	/* ChipDoc PINs have no selectable files: pretend success, but keep the
	 * applet selected for signing. */
	if (!privdata->chipdoc_ca) {
		for (i = 0; i < MAX_OBJECTS && privdata->pin_paths[i]; i++) {
			if (privdata->pin_paths[i] && sc_compare_path(privdata->pin_paths[i], in_path)) {
				LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
			}
		}
	}

	r = sc_get_iso7816_driver()->ops->select_file(card, in_path, file_out);
	if (r == SC_SUCCESS && privdata->chipdoc_ca && eoi_is_chipdoc_root(in_path))
		privdata->chipdoc_aid_selected = 1;
	LOG_FUNC_RETURN(ctx, r);
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

	privdata->chipdoc_aid_selected = 0;
	privdata->chipdoc_mse_valid = 0;
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

static int
eoi_card_reader_lock_obtained(struct sc_card *card, int was_reset)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;

	if (was_reset && privdata && privdata->chipdoc_ca) {
		privdata->chipdoc_aid_selected = 0;
		privdata->chipdoc_mse_valid = 0;
	}
	return SC_SUCCESS;
}

static int
eoi_chipdoc_pin_get_info(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (data->pin_type != SC_AC_CHV || data->pin_reference != 0x01)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* Let the ISO 7816 layer build and parse the empty VERIFY probe. */
	r = sc_get_iso7816_driver()->ops->pin_cmd(card, data);
	if (r == SC_SUCCESS && data->pin1.max_tries <= 0)
		data->pin1.max_tries = EOI_CHIPDOC_PIN_MAX_TRIES;

	LOG_FUNC_RETURN(card->ctx, r);
}

static int eoi_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (data->cmd == SC_PIN_CMD_GET_INFO && privdata && privdata->chipdoc_ca)
		LOG_FUNC_RETURN(card->ctx, eoi_chipdoc_pin_get_info(card, data));

	if (data->cmd == SC_PIN_CMD_VERIFY && privdata && privdata->chipdoc_ca
			&& data->puk_reference == 0
			&& card->sm_ctx.sm_mode != SM_MODE_NONE) {
		/* The SM channel can survive a PKCS#11 session change.  A
		 * successful SM SELECT MF proves that the SM keys and SSC are
		 * still valid; otherwise reopen with a fresh Chip
		 * Authentication below. */
		r = sc_select_file(card, sc_get_mf_path(), NULL);
		if (r == SC_SUCCESS) {
			r = sc_get_iso7816_driver()->ops->pin_cmd(card, data);
			if (r == SC_SUCCESS)
				LOG_FUNC_RETURN(card->ctx, r);
			/* Never retry a failed PIN; just drop SM for the next attempt. */
			if (card->sm_ctx.sm_mode != SM_MODE_NONE) {
				iso_sm_close(card);
				card->sm_ctx.sm_mode = SM_MODE_NONE;
			}
			LOG_FUNC_RETURN(card->ctx, r);
		}
		sc_log(card->ctx, "ChipDoc SM reuse failed, reopening: %s", sc_strerror(r));
	}

	if (data->cmd == SC_PIN_CMD_VERIFY
			&& ((privdata && privdata->chipdoc_ca) || card->sm_ctx.sm_mode == SM_MODE_NONE)) {
		/* Establish SM before PIN VERIFY.  For ChipDoc, always start a
		 * fresh channel: the generic PKCS#15 logout clears only the PIN
		 * state (SW_PIN_LOGOUT_ONLY), so a later login can otherwise
		 * reuse a stale SM context after the session is recreated. */
		r = eoi_sm_open(card);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		int pin_reference = data->pin_reference;
		size_t pin2_len = data->pin2.len;
		/* Verify PUK, establish SM if necessary */
		data->cmd = SC_PIN_CMD_VERIFY;
		data->pin_reference = data->puk_reference;
		r = eoi_pin_cmd(card, data);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* RESET RETRY COUNTER */
		data->cmd = SC_PIN_CMD_UNBLOCK;
		data->pin_reference = 0x80|pin_reference;
		data->pin1.len = 0;
		data->pin2.len = 0;
		r = sc_get_iso7816_driver()->ops->pin_cmd(card, data);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
		/* Continue as CHANGE PIN */
		data->cmd = SC_PIN_CMD_CHANGE;
		data->pin2.len = pin2_len;
	}

	/* CHANGE PIN command does not send the old PIN as it should already be verified */
	if (data->cmd == SC_PIN_CMD_CHANGE)
		data->pin1.len = 0;

	LOG_FUNC_RETURN(card->ctx, sc_get_iso7816_driver()->ops->pin_cmd(card, data));
}

static int
eoi_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct sc_card_driver *iso_driver = NULL;
	int r = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(card->ctx);
	switch (cmd) {
	case SC_CARDCTL_GET_MODEL:
		if (!ptr) {
			r = SC_ERROR_INVALID_ARGUMENTS;
		} else {
			*(char **)ptr = (privdata && privdata->chipdoc_ca)
					? eoi_chipdoc_model : eoi_model;
			r = SC_SUCCESS;
		}
		break;
	case SC_CARDCTL_GET_SERIALNR:
		/* ChipDoc: serial from EF(D003). */
		if (privdata && privdata->chipdoc_ca) {
			r = eoi_chipdoc_get_serialnr(card, (struct sc_serial_number *)ptr);
			break;
		}
		/* fall through */
	default:
		iso_driver = sc_get_iso7816_driver();
		if (iso_driver->ops->card_ctl != NULL) {
			r = sc_get_iso7816_driver()->ops->card_ctl(card, cmd, ptr);
		}
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
	if (env->algorithm != SC_ALGORITHM_EC
			&& !(env->algorithm == SC_ALGORITHM_RSA && privdata->chipdoc_ca))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x81, 0xB6);
	sbuf[0] = 0x91;
	sbuf[1] = 0x02;
	if (env->algorithm == SC_ALGORITHM_RSA) {
		/* The applet pads itself (DigestInfo for PKCS#1 v1.5; MGF1 with salt =
		 * digest length for PSS).  Hash refs, in order SHA-224/256/384/512:
		 * PKCS#1 0x27-0x2A, PSS 0x2B-0x2E. */
		unsigned long pss = env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS;

		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224)
			sbuf[2] = pss ? 0x2B : 0x27;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)
			sbuf[2] = pss ? 0x2C : 0x28;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384)
			sbuf[2] = pss ? 0x2D : 0x29;
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512)
			sbuf[2] = pss ? 0x2E : 0x2A;
		else
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
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
	if (privdata->chipdoc_ca && privdata->chipdoc_mse_valid
			&& !memcmp(sbuf, privdata->chipdoc_mse, sizeof(sbuf))) {
		sc_log(card->ctx, "ChipDoc key/algorithm already selected");
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
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
		if (r == SC_SUCCESS && privdata->chipdoc_ca) {
			memcpy(privdata->chipdoc_mse, sbuf, sizeof(sbuf));
			privdata->chipdoc_mse_valid = 1;
		}
	}
	if (se_num <= 0) {
		r = SC_SUCCESS;
		goto err;
	}
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_SUCCESS && privdata->chipdoc_ca) {
		memcpy(privdata->chipdoc_mse, sbuf, sizeof(sbuf));
		privdata->chipdoc_mse_valid = 1;
	}
	LOG_FUNC_RETURN(card->ctx, r);
err:
	if (locked)
		sc_unlock(card);
	if (r != SC_SUCCESS && privdata->chipdoc_ca)
		privdata->chipdoc_mse_valid = 0;
	LOG_FUNC_RETURN(card->ctx, r);
}

/* Run a complete raw-RSA block through MSE:SET DST and PSO.  Used for
 * signing and, with the returned block, decryption. */
static int
eoi_chipdoc_raw_rsa_block(struct sc_card *card, const u8 *em, size_t em_len,
		u8 *out, size_t outlen)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	sc_apdu_t apdu;
	u8 mse[] = { 0x83, 0x01, 0x00 };
	size_t klen, recv_size, i;
	unsigned int key_ref;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata || !privdata->sec_env.key_size_bits)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	klen = BYTES4BITS(privdata->sec_env.key_size_bits);
	if (klen != em_len)	/* only complete blocks are accepted */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	if (privdata->sec_env.key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	/* Raw mode maps key refs 0x10/0x11 to keys 0x90/0x91; refuse unknown
	 * references to avoid signing with the wrong key. */
	for (i = 0; i < MAX_OBJECTS && privdata->prkey_mappings[i][1]; i++) {
		if (privdata->prkey_mappings[i][0] == privdata->sec_env.key_ref[0])
			break;
	}
	if (i == MAX_OBJECTS)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	key_ref = privdata->prkey_mappings[i][1];
	if (key_ref != 0x90 && key_ref != 0x91)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	mse[2] = key_ref - 0x80;
	/* MSE: SET DST changes the selected key/algorithm, so a cached
	 * PKCS#1 security environment is no longer valid. */
	privdata->chipdoc_mse_valid = 0;


	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
	apdu.data = mse;
	apdu.datalen = sizeof(mse);
	apdu.lc = sizeof(mse);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");


	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x80, 0x86);
	apdu.data = em;
	apdu.datalen = em_len;
	apdu.lc = em_len;
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;

	recv_size = card->max_recv_size;
	card->max_recv_size = SC_MAX_EXT_APDU_RESP_SIZE;
	r = sc_transmit_apdu(card, &apdu);
	card->max_recv_size = recv_size;
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);

	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
eoi_decipher(struct sc_card *card, const u8 *crgram, size_t crgram_len,
		u8 *out, size_t outlen)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata || !crgram || !out || !crgram_len)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (!privdata->chipdoc_ca
			|| privdata->sec_env.operation != SC_SEC_OPERATION_DECIPHER
			|| privdata->sec_env.algorithm != SC_ALGORITHM_RSA)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	if (!(privdata->sec_env.flags & SC_SEC_ENV_KEY_REF_PRESENT)
			|| privdata->sec_env.key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (BYTES4BITS(privdata->sec_env.key_size_bits) > outlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);

	return eoi_chipdoc_raw_rsa_block(card, crgram, crgram_len, out, outlen);
}

/* Padded mode refuses some digests (SHA-384 PKCS#1; SHA-256/512 PSS);
 * retry with a locally built block via raw RSA. */
static int
eoi_chipdoc_raw_rsa(struct sc_card *card, unsigned long pad, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	static const struct {
		size_t len;
		unsigned long hash;
	} hashes[] = {
		{ SHA_DIGEST_LENGTH,
			SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_MGF1_SHA1 },
		{ SHA224_DIGEST_LENGTH,
			SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_MGF1_SHA224 },
		{ SHA256_DIGEST_LENGTH,
			SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_MGF1_SHA256 },
		{ SHA384_DIGEST_LENGTH,
			SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_MGF1_SHA384 },
		{ SHA512_DIGEST_LENGTH,
			SC_ALGORITHM_RSA_HASH_SHA512 | SC_ALGORITHM_MGF1_SHA512 },
	};
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	u8 em[512];
	size_t em_len, klen, i;
	unsigned long hash = 0;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata || !privdata->sec_env.key_size_bits)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	klen = BYTES4BITS(privdata->sec_env.key_size_bits);
	if (klen > sizeof(em))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	for (i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
		if (data_len == hashes[i].len) {
			hash = hashes[i].hash;
			break;
		}
	}
	if (!hash)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	em_len = klen;
	r = sc_pkcs1_encode(card->ctx, pad | hash, data, data_len, em, &em_len,
			privdata->sec_env.key_size_bits, NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot build the padding block");

	LOG_FUNC_RETURN(card->ctx, eoi_chipdoc_raw_rsa_block(card, em, em_len, out, outlen));
}

static int eoi_compute_signature(struct sc_card *card, const u8 * data, size_t data_len, u8 *out, size_t outlen)
{
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	/* CKM_RSA_X_509: the core supplies the complete block; sign it as-is. */
	if (privdata->chipdoc_ca && privdata->sec_env.algorithm == SC_ALGORITHM_RSA
			&& (privdata->sec_env.algorithm_flags & SC_ALGORITHM_RSA_RAW))
		LOG_FUNC_RETURN(card->ctx, eoi_chipdoc_raw_rsa_block(card, data, data_len, out, outlen));

	/* SHA-1 has no MSE hash reference in this driver.  Build the PKCS#1/PSS
	 * block locally and use the raw-RSA path, as done for the SHA-2 digests
	 * that the applet refuses in padded mode. */
	if (privdata->chipdoc_ca && privdata->sec_env.algorithm == SC_ALGORITHM_RSA
			&& (privdata->sec_env.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)) {
		unsigned long pad = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01;

		if (privdata->sec_env.algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS)
			pad = SC_ALGORITHM_RSA_PAD_PSS;
		LOG_FUNC_RETURN(card->ctx, eoi_chipdoc_raw_rsa(card, pad, data, data_len, out, outlen));
	}

	/*
	 * Shorter input is a digest.  EC has no usable raw digest ref: a 32-byte
	 * digest uses SHA-256 even on prime256v1 (raw ref 0x22 gets SW 6984).
	 */
	if (privdata->sec_env.algorithm == SC_ALGORITHM_EC) {
		switch (data_len) {
			case SHA_DIGEST_LENGTH:
				privdata->sec_env.algorithm_flags = SC_ALGORITHM_ECDSA_HASH_SHA1;
				break;
			case SHA256_DIGEST_LENGTH:
				privdata->sec_env.algorithm_flags = SC_ALGORITHM_ECDSA_HASH_SHA256;
				break;
		}
	} else if (privdata->key_len != data_len) {
		if (privdata->sec_env.algorithm == SC_ALGORITHM_RSA) {
			/* Keep PKCS#1 v1.5/PSS: the applet pads the raw hash itself. */
			unsigned long alg_flags = privdata->sec_env.algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS;

			switch (data_len) {
				case SHA224_DIGEST_LENGTH:
					alg_flags |= SC_ALGORITHM_RSA_HASH_SHA224;
					break;
				case SHA256_DIGEST_LENGTH:
					alg_flags |= SC_ALGORITHM_RSA_HASH_SHA256;
					break;
				case SHA384_DIGEST_LENGTH:
					alg_flags |= SC_ALGORITHM_RSA_HASH_SHA384;
					break;
				case SHA512_DIGEST_LENGTH:
					alg_flags |= SC_ALGORITHM_RSA_HASH_SHA512;
					break;
				default:
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
			}
			privdata->sec_env.algorithm_flags = alg_flags;
		}
	}
	/* Now we know which hash is used */
	privdata->sec_env.algorithm_flags |= ALREADY_PROCESSED;

	/* Perform the true set_security_env */
	r = eoi_set_security_env(card, &privdata->sec_env, privdata->se_num);
	LOG_TEST_RET(card->ctx, r, "set_security_env failed");

	if (privdata->chipdoc_ca && privdata->sec_env.algorithm == SC_ALGORITHM_RSA) {
		/* Send PSO here: the signature comes in one extended-length APDU (RSA-2048
		 * under SM exceeds a short APDU).  File reads stay short. */
		sc_apdu_t apdu;
		size_t recv_size = card->max_recv_size;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x9E, 0x9A);
		apdu.data = data;
		apdu.datalen = data_len;
		apdu.lc = data_len;
		apdu.resp = out;
		apdu.resplen = outlen;
		apdu.le = outlen;

		card->max_recv_size = SC_MAX_EXT_APDU_RESP_SIZE;
		r = sc_transmit_apdu(card, &apdu);
		card->max_recv_size = recv_size;
		if (r == SC_SUCCESS && apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
			LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
		if (r == SC_SUCCESS)
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);

		/* Padded mode refuses some digests (SHA-384 PKCS#1; SHA-256/512 PSS);
		 * retry raw with a locally built block.  In PSS mode only the applet's
		 * 0x6583 refusal is retried; it surfaces as SC_ERROR_ASN1_OBJECT_NOT_FOUND
		 * when the SM layer cannot parse the unprotected response. */
		{
			unsigned long pad = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01;
			int r_raw;

			if (privdata->sec_env.algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
				if (r != SC_ERROR_ASN1_OBJECT_NOT_FOUND &&
						(apdu.sw1 != 0x65 || apdu.sw2 != 0x83))
					LOG_FUNC_RETURN(card->ctx, r);
				pad = SC_ALGORITHM_RSA_PAD_PSS;
			}

			r_raw = eoi_chipdoc_raw_rsa(card, pad, data, data_len, out, outlen);
			if (r_raw >= 0)
				LOG_FUNC_RETURN(card->ctx, r_raw);
			sc_log(card->ctx, "%s: raw RSA fallback failed", sc_strerror(r_raw));
		}

		LOG_FUNC_RETURN(card->ctx, r);
	}

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
	eoi_ops.decipher = eoi_decipher;
	eoi_ops.card_reader_lock_obtained = eoi_card_reader_lock_obtained;

	return &eoi_drv;
}

#else

struct sc_card_driver* sc_get_eoi_driver(void) {
	return NULL;
}

#endif
