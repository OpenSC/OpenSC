/*
 * card-jacartapki.c: Support for JaCarta PKI applet
 *
 * Copyright (C) 2025  Andrey Khodunov <a.khodunov@aladdin.ru>
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
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "iso7816.h"
#include "opensc.h"
#include "pkcs15.h"
#include "sc-ossl-compat.h"
#include "sm/sm-iso-internal.h"
#include "sm/sm-iso.h"

#include "jacartapki.h"

#define JACARTAPKI_CARD_DEFAULT_FLAGS (SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_ISO9796 | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations jacartapki_ops;

static struct sc_card_driver jacartapki_drv = {
		"JaCarta PKI driver",
		"jacartapki",
		&jacartapki_ops,
		NULL, 0, NULL};

static struct sc_atr_table jacartapki_known_atrs[] = {
		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:06:11:59:00:01:28",
			"JaCarta PKI",								   SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:0B:03:52:00:05:38",
			"JaCarta PKI",								   SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:8C:80:01:80:73:C8:21:13:66:01:06:11:59:00:01:2C",
			"JaCarta PKI/BIO",							       SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:6C:00:FF:80:73:C8:21:13:66:01:06:11:59:00:01",
			"JaCarta PKI/BIO",							       SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:9F:11:81:11:3D:00:11:00:00:00:00:00:00:00:00:00:00:00:00:00:32",
			"JaCarta-2 PKI",								 SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:00:00:00:FF:FF:FF:FF:FF:0F:0F:FF:FF:00:0F:FF",
			"3B:FC:16:00:00:00:73:C8:21:13:66:01:06:11:59:00:01:2C",
			"JaCarta-2 PKI",								 SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{NULL,								NULL, NULL, 0,			      0, NULL}
};

static struct sc_aid jacartapki_aid = {
		{0xA0, 0x00, 0x00, 0x01, 0x64, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x00, 0x01},
		12
};

unsigned char jacartapki_ops_df[6] = {
		SC_AC_OP_CREATE, SC_AC_OP_CREATE_DF, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE};
unsigned char jacartapki_ops_ef[4] = {
		SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF};
unsigned char jacartapki_ops_do[3] = {
		SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN};
unsigned char jacartapki_ops_ko[7] = {
		SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO};
unsigned char jacartapki_ops_pin[7] = {
		SC_AC_OP_READ, SC_AC_OP_PIN_CHANGE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO};

static int jacartapki_get_serialnr(struct sc_card *, struct sc_serial_number *);
static int jacartapki_get_default_key(struct sc_card *, struct sc_cardctl_default_key *);
static int jacartapki_parse_sec_attrs(struct sc_card *, struct sc_file *);
static int jacartapki_process_fci(struct sc_card *, struct sc_file *, const unsigned char *, size_t);

/*
 * Presently JaCarta PKI Secure Messaging does not fully comply to ISO/IEC 7816-4 (OpenPGP Application on ISO Smart Card Operating Systems).
 * For commands we must wrap APDU data into 87 tag with 01 padding indicator indiscriminately of even/odd INS code.
 *
 * To overcome this we change APDU INS code several times for odd commands: get capabilities CBh, generate key pair 47h.
 *
 * in jacartapki_do_something methods: make INS even (+1) for sc_transmit_apdu argument
 * in jacartapki_iso_sm_authenticate method: modify APDU INS back (-1) in temporary buffer for MAC calculation
 * in jacartapki_iso_sm_get_apdu method: modify APDU INS back (-1) after all handling for PCSC layer to send
 * fortunately not stomp on other INS codes
 *
 */
#if defined(ENABLE_SM)
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
static void _DES_3cbc_encrypt(sm_des_cblock *input, sm_des_cblock *output, long length,
		DES_key_schedule *ks1, DES_key_schedule *ks2, sm_des_cblock *iv,
		int enc);
#endif
static int _sm_decrypt_des_cbc3(struct sc_context *ctx, const unsigned char *key,
		unsigned char *data, size_t data_len,
		unsigned char **out, size_t *out_len);
static int _sm_encrypt_des_cbc3(struct sc_context *ctx, const unsigned char *key,
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int not_force_pad);
static void _sm_incr_ssc(unsigned char *ssc, size_t ssc_len);

static int jacartapki_sm_open(struct sc_card *card);
static int jacartapki_cbc_cksum(struct sc_card *card, unsigned char *key, size_t key_size, unsigned char *in, size_t in_len, DES_cblock *icv);
static int jacartapki_sm_compute_mac(struct sc_card *card, const unsigned char *data, size_t data_len, DES_cblock *mac);
static int jacartapki_sm_check_mac(struct sc_card *card, const unsigned char *data, size_t data_len, const unsigned char *mac, size_t mac_len);
static int jacartapki_sm_close(struct sc_card *card);
static int jacartapki_iso_sm_open(struct sc_card *card);
static int jacartapki_iso_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *data, size_t datalen, u8 **enc);
static int jacartapki_iso_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *enc, size_t enclen, u8 **data);
static int jacartapki_iso_sm_get_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
static int jacartapki_iso_sm_free_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);
static int jacartapki_iso_sm_close(struct sc_card *card);
static int jacartapki_iso_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *data, size_t datalen, u8 **outdata);
static int jacartapki_iso_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *mac, size_t maclen, const u8 *macdata, size_t macdatalen);

#endif /* ENABLE_SM */

static int
jacartapki_get_tag_data(struct sc_context *ctx, const unsigned char *data, size_t data_len, struct sc_tlv_data *out)
{
	size_t taglen;
	const unsigned char *ptr = NULL;

	if (!ctx || !data || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = sc_asn1_find_tag(ctx, data, data_len, out->tag, &taglen);
	if (!ptr)
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;

	out->value = malloc(taglen);
	if (!out->value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(out->value, ptr, taglen);
	out->len = taglen;

	return SC_SUCCESS;
}

static int
jacartapki_get_capability(struct sc_card *card, unsigned tag,
		unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[0x100];
	unsigned char p1 = (unsigned char)((tag >> 8) & 0xFF);
	unsigned char p2 = (unsigned char)(tag & 0xFF);
	int rv;
	int ins;

	LOG_FUNC_CALLED(ctx);

	/* INS translation CB -> CC for 'even mode' capsulation, tag 0x87 */
	ins = (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT ? 0xCC : 0xCB);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, ins, p1, p2);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "get SE data  error");

	if (!out && !out_len)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (apdu.resplen > *out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, apdu.resp, apdu.resplen);
	*out_len = apdu.resplen;

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_get_caps(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv_data = (struct jacartapki_private_data *)card->drv_data;
	unsigned char buf[8];
	size_t buf_len;
	int rv;

	buf_len = sizeof(buf);
	rv = jacartapki_get_capability(card, 0x0180, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'CRYPTO' card capability");
	if (buf_len != sizeof(prv_data->caps.crypto))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'CRYPTO' capability data");
	memcpy(prv_data->caps.crypto, buf, buf_len);

	buf_len = sizeof(buf);
	rv = jacartapki_get_capability(card, 0x0188, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'KEY LENGTHS' card capability");
	if (buf_len != sizeof(prv_data->caps.supported_keys))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'KEY LENGTHS' capability data");
	memcpy(prv_data->caps.supported_keys, buf, buf_len);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_match_card(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i;

	i = _sc_match_atr(card, jacartapki_known_atrs, &card->type);
	if (i < 0) {
		return 0;
	}

	sc_debug(ctx, SC_LOG_DEBUG_MATCH, "'%s' card matched", jacartapki_known_atrs[i].name);
	return 1;
}

static int
jacartapki_load_options(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i, j;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	private_data->secure_verify = 0;

	for (i = 0; card->ctx->conf_blocks[i]; i++) {
		scconf_block **found_blocks, *block;

		found_blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
				"card_driver", "jacartapki");
		if (!found_blocks)
			continue;

		for (j = 0, block = found_blocks[j]; block; j++, block = found_blocks[j]) {
			private_data->secure_verify = scconf_get_bool(block, "secure_verify", 0);
		}
		free(found_blocks);
	}

	sc_log(ctx, "Secure-verify %i", private_data->secure_verify);

	return SC_SUCCESS;
}

static int
jacartapki_init(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = NULL;
	struct sc_path path;
	unsigned int flags;
	int rv = SC_ERROR_NO_CARD_SUPPORT;

	LOG_FUNC_CALLED(ctx);

	private_data = (struct jacartapki_private_data *)calloc(1, sizeof(struct jacartapki_private_data));
	if (private_data == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate private blob for card driver.");

	memset(private_data, 0, sizeof(struct jacartapki_private_data));

	private_data->auth_state[0].pin_reference = JACARTAPKI_USER_PIN_REFERENCE;
	private_data->auth_state[1].pin_reference = JACARTAPKI_SO_PIN_REFERENCE;

	card->cla = 0x00;
	card->drv_data = private_data;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, jacartapki_aid.value, jacartapki_aid.len, 0, 0);
	rv = sc_select_file(card, &path, NULL);
	if (0 > rv) {
		free(card->drv_data);
		card->drv_data = NULL;
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_CARD, "Failed to select Laser AID.");
	}

	rv = jacartapki_get_serialnr(card, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get card serial");

	rv = jacartapki_get_caps(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get card capabilities");

	flags = JACARTAPKI_CARD_DEFAULT_FLAGS;
	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 4096, flags, 0x10001);

	card->caps |= SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT;

	rv = jacartapki_load_options(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to read card driver configuration");

#if defined(ENABLE_SM)
	card->sm_ctx.ops.open = jacartapki_iso_sm_open;
	card->sm_ctx.ops.get_sm_apdu = jacartapki_iso_sm_get_apdu;
	card->sm_ctx.ops.free_sm_apdu = jacartapki_iso_sm_free_apdu;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

	OSSL_PROVIDER_load(NULL, "default");
	private_data->legacyOsslProvider = OSSL_PROVIDER_load(NULL, "legacy");
	if (!private_data->legacyOsslProvider)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "No Legacy OpenSSL provider.");

	private_data->desCbcCipher = EVP_CIPHER_fetch(NULL, "DES-CBC", NULL); /* "provider=legacy" */
	if (!private_data->desCbcCipher)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "No DES-CBC cipher");

	private_data->desEcbCipher = EVP_CIPHER_fetch(NULL, "DES-ECB", NULL);
	if (!private_data->desEcbCipher)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "No DES-ECB cipher");

#endif

#endif
	rv = SC_SUCCESS;
err:
#if defined(ENABLE_SM) && OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	if (rv < 0) {
		EVP_CIPHER_free(private_data->desEcbCipher);
		private_data->desEcbCipher = NULL;

		EVP_CIPHER_free(private_data->desCbcCipher);
		private_data->desCbcCipher = NULL;

		OSSL_PROVIDER_unload(private_data->legacyOsslProvider);
		private_data->legacyOsslProvider = NULL;
	}
#endif
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_read_binary(struct sc_card *card, unsigned int offs,
		u8 *buf, size_t count, unsigned long *flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;
	const size_t leMax = 0x100U;
	size_t binaryDataRead;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_read_binary(card:%p) offs %i; count %" SC_FORMAT_LEN_SIZE_T "u", card, offs, count);
	if (offs > 0x7fff) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", offs);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, (offs >> 8) & 0x7F, offs & 0xFF);
	apdu.le = MIN(count, leMax);
	apdu.resplen = count;
	apdu.resp = buf;
#ifdef ENABLE_SM
	if (card->sm_ctx.sm_mode != SM_MODE_NONE)
		apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;
#endif

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	binaryDataRead = apdu.resplen;
	if (apdu.sw1 == 0x61) {
		/* usually we get here when SM is on */
		unsigned char getRespBuf[0x100];
		while (binaryDataRead < count) {
			size_t getRespLen = leMax;
			memset(getRespBuf, 0, sizeof(getRespBuf));
			rv = card->ops->get_response(card, &getRespLen, getRespBuf);
			LOG_TEST_RET(ctx, rv, "GET RESPONSE error");
			if (getRespLen > 0) {
				if (getRespLen > count - binaryDataRead)
					getRespLen = count - binaryDataRead;
				memcpy(buf + binaryDataRead, getRespBuf, getRespLen);
				binaryDataRead += getRespLen;
			}
			if (rv == 0)
				break;
		}
	} else
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "jacartapki_read_binary() failed");
	sc_log(ctx, "jacartapki_read_binary() apdu.resplen %" SC_FORMAT_LEN_SIZE_T "u", apdu.resplen);

	LOG_FUNC_RETURN(ctx, (int)binaryDataRead);
}

static int
jacartapki_update_binary(struct sc_card *card,
		unsigned int idx, const u8 *buf, size_t count, unsigned long flags)
{
	int rv;
#ifdef ENABLE_SM
	if (card->sm_ctx.sm_mode != SM_MODE_NONE) {
		const size_t smOverhead = 20;
		const size_t chunkMax = sc_get_max_send_size(card) - smOverhead;
		assert(chunkMax > 0);
		int idxDone = 0;
		do {
			rv = iso_ops->update_binary(card, idx + idxDone, buf + idxDone, MIN(count - idxDone, chunkMax), flags);
			if (rv <= 0)
				break;
			idxDone += rv;

		} while ((size_t)idxDone < count);

		rv = (idxDone > 0 ? idxDone : rv);
	} else
#endif
		rv = iso_ops->update_binary(card, idx, buf, count, flags);
	return rv;
}

static int
jacartapki_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_erase_binary(card:%p) count %" SC_FORMAT_LEN_SIZE_T "u", card, count);
	if (!count)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "'ERASE BINARY' failed: invalid size to erase");

	tmp = malloc(count);
	if (!tmp)
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate temporary buffer");
	memset(tmp, 0xFF, count);

	rv = jacartapki_update_binary(card, offs, tmp, count, flags);
	free(tmp);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	size_t pathlen;
	int rv;
	int reopen_sm_session = 0;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "jacartapki_select_file(card:%p) path(type:%i):%s, out:%p", card, in_path->type, sc_print_path(in_path), file_out);

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;
	if (file_out)
		*file_out = NULL;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	apdu.cla = 0x80;

	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_ARGUMENTS, "Invalid path");
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		if (jacartapki_aid.len == in_path->len && !memcmp(jacartapki_aid.value, in_path->value, in_path->len)) {
			/* JaCarta PKI application has to be selected by the standand ISO7816 command */
			apdu.cla = 0x00;
		}
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (in_path->len < 2) {
			apdu.p1 = 0;
			break;
		} else if (memcmp(in_path->value, "\x3F\x00", 2)) {
			/* In a difference to ISO7816-4 specification (tab. 39)
			 * leading 3F00 has to be included into 'path-from-MF'. */
			memcpy(path, "\x3F\x00", 2);
			memcpy(path + 2, in_path->value, in_path->len);
			pathlen = in_path->len + 2;
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_ARGUMENTS, "Invalid path type");
	}

	/* reopening SM for select application */
	if (card->sm_ctx.sm_mode != SM_MODE_NONE && in_path->type == SC_PATH_TYPE_DF_NAME && jacartapki_aid.len == pathlen && !memcmp(jacartapki_aid.value, path, pathlen)) {
		jacartapki_iso_sm_close(card);
		reopen_sm_session = 1;
	}

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	/* Return FCI data */
	apdu.p2 = 0x0C; /* not ISO 7816-4 */
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	apdu.le = 256; /* card->max_recv_size > 0 ? card->max_recv_size : 256; */

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "Select file error");

	if (apdu.resplen < 2) {
		if (file_out)
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_UNKNOWN_DATA_RECEIVED, "Incorrect apdu resp.");
		else
			goto err;
	}

	switch (apdu.resp[0]) {
	case ISO7816_TAG_FCI:
	case ISO7816_TAG_FCP:
		file = sc_file_new();
		if (file == NULL)
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate sc_file");

		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_NOT_SUPPORTED, "FCI processing not supported");
		}

		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen) {
			struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;

			rv = jacartapki_process_fci(card, file, apdu.resp + 2, apdu.resp[1]);
			LOG_TEST_GOTO_ERR(ctx, rv, "Process FCI error");

			rv = jacartapki_parse_sec_attrs(card, file);
			LOG_TEST_GOTO_ERR(ctx, rv, "Security attributes parse error");

			if (file->type == SC_FILE_TYPE_INTERNAL_EF) {
				sc_file_free(prv->last_ko);
				sc_file_dup(&prv->last_ko, file);
			}
		}

		if (file_out)
			*file_out = file;
		else
			sc_file_free(file);
		break;
	case 0x00: /* proprietary coding */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_UNKNOWN_DATA_RECEIVED, "Proprietary encoding in 'SELECT' APDU response not supported");
		break;
	default:
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_UNKNOWN_DATA_RECEIVED, "Unknown 'SELECT' APDU response tag");
	}
err:
	if (reopen_sm_session)
		jacartapki_iso_sm_open(card);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_process_fci(struct sc_card *card, struct sc_file *file, const u8 *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen, len = buflen;
	const unsigned char *tag = NULL, *p = buf;

	LOG_FUNC_CALLED(ctx);
	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_FID, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(ctx, "  file identifier: 0x%02X%02X", tag[0], tag[1]);
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE, &taglen);
	if (tag != NULL && taglen > 0 && taglen < 3) {
		file->size = tag[0];
		if (taglen == 2)
			file->size = (file->size << 8) + tag[1];
		sc_log(ctx, "  bytes in file: %" SC_FORMAT_LEN_SIZE_T "d", file->size);
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE_FULL, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];

			sc_log(ctx, "  bytes in file: %d", bytes);
			file->size = bytes;
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x87, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			sc_log(ctx, "  shareable: %s", (byte & 0x40) ? "yes" : "no");
			file->ef_structure = byte & 0x07;
			switch ((byte >> 3) & 7) {
			case 0:
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				break;
			case 1:
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				break;
			case 7:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			default:
				type = "unknown";
				break;
			}
			sc_log(ctx, "  type: %s", type);
			sc_log(ctx, "  EF structure: %d", byte & 0x07);
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_DF_NAME, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char tbuf[128];

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		sc_hex_dump(file->name, file->namelen, tbuf, sizeof(tbuf));
		sc_log(ctx, "  File name: %s", tbuf);
		if (!file->type)
			file->type = SC_FILE_TYPE_DF;
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_PROP_INFO, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_prop_attr(file, tag, taglen);
	else
		file->prop_attr_len = 0;

	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen);
	} else {
		tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
		if (tag != NULL && taglen)
			sc_file_set_prop_attr(file, tag, taglen);
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen)
		sc_file_set_sec_attr(file, tag, taglen);

	tag = sc_asn1_find_tag(ctx, p, len, 0x8A, &taglen);
	if (tag != NULL && taglen == 1) {
		if (tag[0] == 0x01)
			file->status = SC_FILE_STATUS_CREATION;
		else if (tag[0] == 0x07 || tag[0] == 0x05)
			file->status = SC_FILE_STATUS_ACTIVATED;
		else if (tag[0] == 0x06 || tag[0] == 0x04)
			file->status = SC_FILE_STATUS_INVALIDATED;
	}

	file->magic = SC_FILE_MAGIC;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_parse_sec_attrs(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	unsigned type = file->type;
	unsigned char *attrs = file->sec_attr;
	size_t len = file->sec_attr_len;
	unsigned char *ops = NULL;
	size_t ii, ops_len = 0;

	LOG_FUNC_CALLED(ctx);
	if (type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(jacartapki_ops_ko) * 2) {
		if (file->prop_attr_len > 2) {
			if (*(file->prop_attr + 2) == JACARTAPKI_KO_ALGORITHM_PIN) {
				sc_log(ctx, "KO-PIN");
				ops = &jacartapki_ops_pin[0];
				ops_len = sizeof(jacartapki_ops_pin) / sizeof(jacartapki_ops_pin[0]);
			} else {
				sc_log(ctx, "KO algo:%X", *(file->prop_attr + 2));
				ops = &jacartapki_ops_ko[0];
				ops_len = sizeof(jacartapki_ops_ko) / sizeof(jacartapki_ops_ko[0]);
			}
		} else {
			sc_log(ctx, "KO");
			ops = &jacartapki_ops_ko[0];
			ops_len = sizeof(jacartapki_ops_ko) / sizeof(jacartapki_ops_ko[0]);
		}
	} else if (type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(jacartapki_ops_do) * 2) {
		sc_log(ctx, "DO");
		ops = &jacartapki_ops_do[0];
		ops_len = sizeof(jacartapki_ops_do) / sizeof(jacartapki_ops_do[0]);
	} else if (type == SC_FILE_TYPE_WORKING_EF) {
		sc_log(ctx, "EF");
		ops = &jacartapki_ops_ef[0];
		ops_len = sizeof(jacartapki_ops_ef) / sizeof(jacartapki_ops_ef[0]);
	} else if (type == SC_FILE_TYPE_DF) {
		sc_log(ctx, "DF");
		ops = &jacartapki_ops_df[0];
		ops_len = sizeof(jacartapki_ops_df) / sizeof(jacartapki_ops_df[0]);
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported file type");
	}
	sc_log(ctx, "sec.attrs(%" SC_FORMAT_LEN_SIZE_T "u) %s, ops_len %" SC_FORMAT_LEN_SIZE_T "u", len, sc_dump_hex(attrs, len), ops_len);

	for (ii = 0; ii < ops_len; ii++) {
		unsigned val = *(attrs + ii * 2) * 0x100 + *(attrs + ii * 2 + 1);

		sc_log(ctx, "access rule 0x%04X, op 0x%X(%i)", val, *(ops + ii), *(ops + ii));
		if (*(attrs + ii * 2)) {
			sc_log(ctx, "op:%X SC_AC_SCB, val:%X", *(ops + ii), val);
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_SCB, val);
		} else if (*(attrs + ii * 2 + 1) == 0xFF) {
			sc_log(ctx, "op:%X SC_AC_NEVER", *(ops + ii));
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		} else if (*(attrs + ii * 2 + 1)) {
			unsigned char ref = *(attrs + ii * 2 + 1);
			unsigned method = (ref == JACARTAPKI_TRANSPORT_PIN1_REFERENCE) ? SC_AC_AUT : SC_AC_CHV;
			/* TODO: normally, here we should check the type of referenced KO */

			if (ref == 0x30) {
				sc_log(ctx, "TODO: not supported LOGIC KO; here ref-30 changed for ref-20 : TODO");
				ref = 0x20;
			}

			sc_file_add_acl_entry(file, *(ops + ii), method, ref);
		} else {
			sc_log(ctx, "op:%X SC_AC_NONE", *(ops + ii));
			sc_file_add_acl_entry(file, *(ops + ii), SC_AC_NONE, SC_AC_KEY_REF_NONE);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_fcp_encode(struct sc_card *card, const struct sc_file *file, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buf[0x400];
	size_t offs = 0;
	unsigned char *ops = NULL;
	size_t ii, ops_len = 0, file_size = 0;

	LOG_FUNC_CALLED(ctx);

	if (file->type == SC_FILE_TYPE_DF) {
		ops = &jacartapki_ops_df[0];
		ops_len = sizeof(jacartapki_ops_df);
	} else if (file->type == SC_FILE_TYPE_WORKING_EF) {
		ops = &jacartapki_ops_ef[0];
		ops_len = sizeof(jacartapki_ops_ef);
		file_size = file->size;
	} else if (file->type == SC_FILE_TYPE_INTERNAL_EF && file->ef_structure == JACARTAPKI_FILE_DESCRIPTOR_KO) {
		ops = &jacartapki_ops_ko[0];
		ops_len = sizeof(jacartapki_ops_ko);
		file_size = file->size;
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported type of the file to be created.");
	}

	memset(buf, 0, sizeof(buf));
	offs = 0;

	buf[offs++] = ISO7816_TAG_FCP_LCS;
	buf[offs++] = 1;
	buf[offs++] = 0x04;

	buf[offs++] = ISO7816_TAG_FCP_FID;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF;

	buf[offs++] = ISO7816_TAG_FCP_SIZE;
	buf[offs++] = 2;
	buf[offs++] = (file_size >> 8) & 0xFF;
	buf[offs++] = file_size & 0xFF;

	if (file->namelen) {
		buf[offs++] = ISO7816_TAG_FCP_DF_NAME;
		buf[offs++] = file->namelen;
		memcpy(buf + offs, file->name, file->namelen);
		offs += file->namelen;
	}

	if (file->prop_attr && file->prop_attr_len) {
		buf[offs++] = ISO7816_TAG_FCP_PROP_INFO;
		buf[offs++] = file->prop_attr_len;
		memcpy(buf + offs, file->prop_attr, file->prop_attr_len);
		offs += file->prop_attr_len;
	}

	buf[offs++] = ISO7816_TAG_FCP_ACLS;
	buf[offs++] = ops_len * 2;

	for (ii = 0; ii < ops_len; ii++) {
		const struct sc_acl_entry *entry = sc_file_get_acl_entry(file, ops[ii]);

		if (entry)
			sc_log(ctx, "ops %i: method %X, reference %X", ops[ii], entry->method, entry->key_ref);
		else
			sc_log(ctx, "ops %i: no ACL entry", ops[ii]);

		if (!entry || entry->method == SC_AC_NEVER) {
			buf[offs++] = 0x00;
			buf[offs++] = 0xFF;
		} else if (entry->method == SC_AC_NONE) {
			buf[offs++] = 0x00;
			buf[offs++] = 0x00;
		} else if (entry->method == SC_AC_CHV) {
			buf[offs++] = 0x00;
			buf[offs++] = entry->key_ref & 0xFF;
		} else if (entry->method == SC_AC_SCB) {
			buf[offs++] = (entry->key_ref >> 8) & 0xFF;
			buf[offs++] = entry->key_ref & 0xFF;
		} else {
			LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported AC method");
		}
	}

	if (file->encoded_content && file->encoded_content_len) {
		memcpy(buf + offs, file->encoded_content, file->encoded_content_len);
		offs += file->encoded_content_len;
	}

	if (out) {
		if (out_len < offs)
			LOG_ERROR_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to encode FCP");
		memcpy(out, buf, offs);
	}

	LOG_FUNC_RETURN(ctx, (int)offs);
}

static int
jacartapki_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[0x400], fcp[0x400], p1 = (unsigned char)0;
	int fcp_len;
	size_t offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "create file (type:%i, ID:0x%X, path:%s)", file->type, file->id, sc_print_path(&file->path));

	/* Select parent */
	if (file->path.len > 2) {
		struct sc_path parent_path = file->path;

		parent_path.len -= 2;
		rv = jacartapki_select_file(card, &parent_path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select newly created file");
	}

	fcp_len = jacartapki_fcp_encode(card, file, fcp, sizeof(fcp));
	LOG_TEST_RET(ctx, fcp_len, "FCP encode error");

	if (file->type == SC_FILE_TYPE_WORKING_EF)
		p1 = 0x01;
	else if (file->type == SC_FILE_TYPE_DF)
		p1 = 0x38;
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		p1 = file->ef_structure;
	else
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported type of the file to create");

	offs = 0;
	sbuf[offs++] = ISO7816_TAG_FCP;
	if (fcp_len < 0x80) {
		sbuf[offs++] = fcp_len & 0xFF;
	} else if (fcp_len <= 0xFF) {
		sbuf[offs++] = 0x81;
		sbuf[offs++] = fcp_len & 0xFF;
	} else if (fcp_len <= 0xFFFF) {
		sbuf[offs++] = 0x82;
		sbuf[offs++] = (fcp_len >> 8) & 0xFF;
		sbuf[offs++] = fcp_len & 0xFF;
	}
	memcpy(sbuf + offs, fcp, fcp_len);
	offs += fcp_len;

	sc_log(ctx, "FCP data '%s'", sc_dump_hex(sbuf, offs));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.p1 = p1;
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "jacartapki_create_file() create file error");

	if (!file->path.len) {
		sc_append_file_id(&file->path, file->id);
		file->path.type = SC_PATH_TYPE_FILE_ID;
	}

	rv = jacartapki_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select newly created file");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;
	struct sc_apdu apdu;
	u8 pin_data[(sizeof(prv->auth_state) / sizeof(prv->auth_state[0])) * 4];
	int offs;
	int rv;

	LOG_FUNC_CALLED(ctx);

	offs = 0;
	for (int i = 0; i != sizeof(prv->auth_state) / sizeof(prv->auth_state[0]); i++) {
		if (prv->auth_state[i].logged_in) {
			pin_data[offs++] = 0; /* XX = 0 */
			pin_data[offs++] = 0; /* level */
			pin_data[offs++] = (prv->auth_state[i].pin_reference >> 8) & 0xFF;
			pin_data[offs++] = prv->auth_state[i].pin_reference & 0xFF;

			prv->auth_state[i].logged_in = 0;
		}
	}
	if (!offs)
		return SC_SUCCESS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x28, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.data = pin_data;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	if (rv == SC_SUCCESS)
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;

	LOG_FUNC_CALLED(ctx);

#ifdef ENABLE_SM
	if (card->sm_ctx.sm_mode != SM_MODE_NONE && card->sm_ctx.ops.close)
		card->sm_ctx.ops.close(card);

	if (private_data) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_CIPHER_free(private_data->desEcbCipher);
		private_data->desEcbCipher = NULL;

		EVP_CIPHER_free(private_data->desCbcCipher);
		private_data->desCbcCipher = NULL;

		OSSL_PROVIDER_unload(private_data->legacyOsslProvider);
		private_data->legacyOsslProvider = NULL;
#endif

#else
	if (private_data) {
#endif
		sc_file_free(private_data->last_ko);
		free(private_data);
		card->drv_data = NULL;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	int rv, p1 = 0;

	LOG_FUNC_CALLED(ctx);

	rv = jacartapki_select_file(card, path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	if (file->type == SC_FILE_TYPE_DF)
		p1 = 1;
	sc_file_free(file);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, p1, 0x00);

	sc_log(ctx, "delete %s file '%s'", (p1 ? "DF" : "EF"), sc_print_path(path));
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Failed to delete file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char p1s[] = {0x01, 0x38, 0x08};
	unsigned ii;
	size_t offs;

	LOG_FUNC_CALLED(ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x30, 0, 0);
	apdu.cla = 0x80;

	for (ii = 0, offs = 0; ii < sizeof(p1s); ii++) {
		size_t oo;
		int jj;
		int rv;

		apdu.p1 = p1s[ii];
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;
		apdu.le = MIN(apdu.resplen, 0x100);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "list files error");

		if (apdu.resplen < 4)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		if (rbuf[3] * 2 + offs > buflen)
			LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

		for (oo = 4, jj = 0; jj < rbuf[3]; jj++) {
			if (rbuf[oo] != 0xD2)
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
			memcpy(buf + offs, rbuf + oo + 2, 2);
			oo += 2 + rbuf[oo + 1];
			offs += 2;
		}
	}

	LOG_FUNC_RETURN(ctx, (int)offs);
}

static int
jacartapki_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	if (sw1 == 0x62 && sw2 == 0x82)
		return SC_SUCCESS;

	return iso_ops->check_sw(card, sw1, sw2);
}

static int
jacartapki_set_security_env(struct sc_card *card,
		const struct sc_security_env *senv, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	if (!senv)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "jacartapki_set_security_env() op:%X,flags:%lX,algo:(%lX,ref:%lX,flags:%lX)",
			senv->operation, senv->flags, senv->algorithm, senv->algorithm_ref, senv->algorithm_flags);
	*env = *senv;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_chv_secure_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char plain_text[16], sha1[SHA_DIGEST_LENGTH];
	unsigned char *encrypted = NULL;
	size_t encrypted_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%" SC_FORMAT_LEN_SIZE_T "u)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (!pin_cmd->pin1.data || !pin_cmd->pin1.len)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_ARGUMENTS, "null value not allowed for secure PIN verify");

	RAND_bytes(plain_text, 8);

	rv = iso_ops->get_challenge(card, plain_text + 8, 8);
	LOG_TEST_RET(ctx, rv, "Get card challenge failed");

	SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, sha1);

	sc_do_log(ctx, SC_LOG_DEBUG_PIN, FILENAME, __LINE__, __FUNCTION__, "key '%s'", sc_dump_hex(sha1, 16));

	rv = _sm_encrypt_des_cbc3(ctx, sha1, plain_text, 16, &encrypted, &encrypted_len, 1);
	LOG_TEST_GOTO_ERR(ctx, rv, "_encrypt_des_cbc3() failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.data = encrypted;
	apdu.datalen = encrypted_len;
	apdu.lc = encrypted_len;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	free(encrypted);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, int secure_verify,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%" SC_FORMAT_LEN_SIZE_T "u)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (pin_cmd->pin1.data && !pin_cmd->pin1.len) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_cmd->pin_reference);
	} else if (pin_cmd->pin1.data && pin_cmd->pin1.len) {
		if (secure_verify) {
			rv = jacartapki_chv_secure_verify(card, pin_cmd, tries_left);
			LOG_FUNC_RETURN(ctx, rv);
		} else {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, 0x00);
			apdu.data = pin_cmd->pin1.data;
			apdu.datalen = pin_cmd->pin1.len;
			apdu.lc = pin_cmd->pin1.len;
		}
	} else {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_is_verified(struct sc_card *card, const struct sc_pin_cmd_data *pin_cmd_data,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	int rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

	LOG_FUNC_CALLED(ctx);
	if (!pin_cmd_data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (pin_cmd_data->pin_type != SC_AC_CHV)
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non CHV PIN type is not supported for verification");

	pin_cmd = *pin_cmd_data;
	pin_cmd.pin1.data = (unsigned char *)"";
	pin_cmd.pin1.len = 0;
	rv = jacartapki_chv_verify(card, &pin_cmd, 0, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_from_ko_le(struct sc_context *ctx, unsigned reference, unsigned *out)
{
	if (!out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (reference == 0x30) {
		*out = 0x20;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

static int
jacartapki_select_global_pin(struct sc_card *card, unsigned reference, struct sc_file **out_file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Select global PIN file %X", reference);

	sc_format_path("3F0000FF", &path);
	path.value[path.len - 1] = reference;

	rv = jacartapki_select_file(card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Failed to select PIN file");

	if (file->prop_attr && (file->prop_attr_len >= 3) && (*(file->prop_attr + 2) == JACARTAPKI_KO_ALGORITHM_LOGIC)) {
		unsigned ref;

		rv = jacartapki_pin_from_ko_le(ctx, reference, &ref);
		LOG_TEST_RET(ctx, rv, "Unknown LogicalExpression KO");
		path.value[path.len - 1] = ref;

		sc_file_free(file);
		rv = jacartapki_select_file(card, &path, &file);
		LOG_TEST_RET(ctx, rv, "Failed to select PIN file");
	}

	if (out_file)
		*out_file = file;
	else
		sc_file_free(file);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_verify(struct sc_card *card, unsigned type, unsigned reference,
		const unsigned char *data, size_t data_len, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	int rv;
	unsigned int chv_ref = reference;
	int secure_verify;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify PIN(type:%X,ref:%i,data(len:%" SC_FORMAT_LEN_SIZE_T "u,%p)", type, reference, data_len, data);

	if (type == SC_AC_AUT && reference == JACARTAPKI_TRANSPORT_PIN1_REFERENCE)
		type = SC_AC_CHV;

	if (type == SC_AC_AUT) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	} else if (type == SC_AC_SCB) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	} else if (type == SC_AC_CHV) {
		if (!(reference & 0x80)) {
			rv = jacartapki_select_global_pin(card, reference, NULL);
			LOG_TEST_RET(ctx, rv, "Select PIN file error");
			chv_ref = 0;
		}
	} else {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = chv_ref;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;
	pin_cmd.pin1.data = data;
	pin_cmd.pin1.len = data_len;

	if (data && !data_len) {
		rv = jacartapki_pin_is_verified(card, &pin_cmd, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}
	/* plain VERIFY for Transport PIN #1,#2 */
	secure_verify = (reference != 0x01 && reference != 0x02 ? private_data->secure_verify : 0);

	rv = jacartapki_chv_verify(card, &pin_cmd, secure_verify, tries_left);
	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	/* TEMP P15 DF RELOAD PRIVATE */
	for (int i = 0; i != sizeof(private_data->auth_state) / sizeof(private_data->auth_state[0]); i++) {
		if (private_data->auth_state[i].pin_reference == reference) {
			private_data->auth_state[i].logged_in = 1;
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}

#if defined(ENABLE_SM)
static int
jacartapki_sm_chv_change(struct sc_card *card, struct sc_pin_cmd_data *data, unsigned chv_ref,
		int *tries_left, unsigned op_acl)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	unsigned char pin_data[SC_MAX_APDU_BUFFER_SIZE];
	size_t offs;
	int rv;
	int oneTimeSm = 0;

	assert(card);
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM change CHV(ref %i, length %" SC_FORMAT_LEN_SIZE_T "u, op-acl %X)", chv_ref, data->pin2.len, op_acl);

	if (!data->pin2.len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure needs new PIN defined");

	if ((unsigned)(data->pin2.len) > sizeof(pin_data))
		LOG_ERROR_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'SM change CHV' data");

	if (card->sm_ctx.sm_mode == SM_MODE_NONE) {
		rv = jacartapki_iso_sm_open(card);
		LOG_TEST_RET(ctx, rv, "Cannot open SM");
		oneTimeSm = 1;
	}

	card->sm_ctx.info.security_condition = op_acl;

	offs = 0;
	pin_data[offs++] = 0x62;
	pin_data[offs++] = data->pin2.len + 2;
	pin_data[offs++] = 0x81;
	pin_data[offs++] = data->pin2.len;
	memcpy(pin_data + offs, data->pin2.data, data->pin2.len);
	offs += data->pin2.len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, chv_ref);
	apdu.cla = 0x80;
	apdu.data = pin_data;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	if (!rv)
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (oneTimeSm)
		jacartapki_iso_sm_close(card);

	card->sm_ctx.info.security_condition = 0;

	LOG_TEST_RET(ctx, rv, "SM change CHV failed");
	LOG_FUNC_RETURN(ctx, rv);
}
#endif

static int
jacartapki_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	struct sc_file *pin_file = NULL;
	unsigned char pin_data[SC_MAX_APDU_BUFFER_SIZE];
	unsigned chv_ref = data->pin_reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(type:%i,ref:%i,lengths:%" SC_FORMAT_LEN_SIZE_T "u/%" SC_FORMAT_LEN_SIZE_T "u)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (data->pin1.len) {
		rv = jacartapki_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_TEST_RET(ctx, rv, "Cannot verify old PIN");
	}

	if (!data->pin2.len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing new PIN value");

	if ((unsigned)(data->pin2.len) > sizeof(pin_data))
		LOG_ERROR_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'Change PIN' data");

	if (data->pin_reference & 0x80) {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "TODO: local PINs");
	} else {
		const struct sc_acl_entry *entry;

		rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
		LOG_TEST_RET(ctx, rv, "Select PIN file error");

		chv_ref = 0;
		entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_CHANGE);
		if (entry) {
#if defined(ENABLE_SM)
			rv = jacartapki_sm_chv_change(card, data, chv_ref, tries_left, entry->key_ref);
			LOG_FUNC_RETURN(ctx, rv);
#else
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif
		}
	}

	memcpy(pin_data, data->pin1.data, data->pin1.len);
	memcpy(pin_data + data->pin1.len, data->pin2.data, data->pin2.len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, chv_ref);
	apdu.data = pin_data;
	apdu.datalen = data->pin1.len + data->pin2.len;
	apdu.lc = apdu.datalen;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PIN change failed");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	struct sc_file *pin_file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(type:%i,ref:%i,lengths:%" SC_FORMAT_LEN_SIZE_T "u/%" SC_FORMAT_LEN_SIZE_T "u)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (!(data->pin_reference & 0x80)) {
		const struct sc_acl_entry *entry;

		rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
		LOG_TEST_RET(ctx, rv, "Select PIN file error");

		if (data->pin1.len) {
			entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_RESET);
			if (entry) {
				sc_log(ctx, "Acl(PIN_RESET): %04X", entry->key_ref);
				if ((entry->key_ref & 0x00FF) == 0xFF) {
					LOG_ERROR_RET(ctx, SC_ERROR_NOT_ALLOWED, "Reset PIN not allowed");
				} else if (entry->key_ref & 0xC000) {
					LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Reset PIN protectd by SM: not supported (TODO)");
				} else if (entry->key_ref & 0x00FF) {
					rv = jacartapki_pin_verify(card, SC_AC_CHV, entry->key_ref & 0x00FF, data->pin1.data, data->pin1.len, tries_left);
					LOG_TEST_RET(ctx, rv, "Verify PUK failed");

					rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
					LOG_TEST_RET(ctx, rv, "Select PIN file error");
				}
			}
		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 0, 0);
	apdu.cla = 0x80;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PIN change failed");

	if (data->pin2.len) {
		size_t save_len = data->pin1.len;

		data->pin1.len = 0;
		rv = jacartapki_pin_change(card, data, tries_left);
		data->pin1.len = save_len;
		LOG_TEST_RET(ctx, rv, "Cannot set new PIN value");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_pin_getinfo(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	for (int i = 0; i != sizeof(private_data->auth_state) / sizeof(private_data->auth_state[0]); i++) {
		if (private_data->auth_state[i].pin_reference == (unsigned int)data->pin_reference) {
			data->pin1.logged_in = private_data->auth_state[i].logged_in;
			break;
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jacartapki_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%" SC_FORMAT_LEN_SIZE_T "u, PIN-2 %p:%" SC_FORMAT_LEN_SIZE_T "u",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		rv = jacartapki_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_CHANGE:
		rv = jacartapki_pin_change(card, data, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_UNBLOCK:
		rv = jacartapki_pin_reset(card, data, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_GET_INFO:
		rv = jacartapki_pin_getinfo(card, data);
		LOG_FUNC_RETURN(ctx, rv);
	default:
		sc_log(ctx, "PIN command 0x%X do not yet supported.", data->cmd);
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non-supported PIN command");
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

static int
jacartapki_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_serial_number sn;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->serialnr.len) {
		if (serial)
			*serial = card->serialnr;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sn.len = sizeof(sn.value);
	rv = jacartapki_get_capability(card, 0x0114, sn.value, &sn.len);
	LOG_TEST_RET(ctx, rv, "cannot get 'serial number' card capability");

	if (sizeof(prv_data->caps.serial) != sn.len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'SERIAL NUMBER' data");
	memcpy(&prv_data->caps.serial, sn.value, sn.len);

	card->serialnr = sn;
	if (serial)
		*serial = sn;
	sc_log(ctx, "jacartapki serial '%s'", sc_dump_hex(sn.value, sn.len));
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_get_default_key(struct sc_card *card, struct sc_cardctl_default_key *data)
{
	struct sc_context *ctx = card->ctx;
	scconf_block *atrblock = NULL;

	LOG_FUNC_CALLED(ctx);

	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (!atrblock)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);

	if (data->method == SC_AC_AUT && data->key_ref == 1) {
		const char *default_key = scconf_get_str(atrblock, "default_transport_pin1", JACARTAPKI_TRANSPORT_PIN1_VALUE);
		int rv;

		rv = sc_hex_to_bin(default_key, data->key_data, &data->len);
		LOG_TEST_RET(ctx, rv, "Cannot get transport PIN01 default value: HEX to BIN conversion error");

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);
}

static int
jacartapki_generate_key(struct sc_card *card, struct sc_cardctl_jacartapki_genkey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	const unsigned char *ptr = NULL;
	size_t offs, taglen;
	int rv;
	int ins;

	LOG_FUNC_CALLED(ctx);

	offs = 0;
	sbuf[offs++] = 0xAC;
	sbuf[offs++] = args->exponent_len + 6;
	sbuf[offs++] = 0x80;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = args->algorithm;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = args->exponent_len;
	memcpy(sbuf + offs, args->exponent, args->exponent_len);
	offs += args->exponent_len;

	/* INS translation 47 -> 48 for 'even mode' capsulation, tag 0x87 */
	ins = (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT ? 0x48 : 0x47);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, ins, 0x00, 0x00);
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = SC_MAX_APDU_RESP_SIZE;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	/* get modulus */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x81, &taglen);
	if (!ptr || (taglen != args->modulus_len))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid modulus data length");
	memcpy(args->modulus, ptr, taglen);

	/* get exponent */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x82, &taglen);
	if (!ptr || (taglen != args->exponent_len) || memcmp(ptr, args->exponent, taglen))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid exponent data");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_update_key(struct sc_card *card, const struct sc_cardctl_jacartapki_updatekey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, 0x00);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.cla = 0x80;
	apdu.datalen = args->len;
	apdu.data = args->data;
	apdu.lc = args->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return jacartapki_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return jacartapki_get_default_key(card, (struct sc_cardctl_default_key *)ptr);
	case SC_CARDCTL_ALADDIN_GENERATE_KEY:
		sc_log(ctx, "CMD SC_CARDCTL_ALADDIN_GENERATE_KEY");
		return jacartapki_generate_key(card, (struct sc_cardctl_jacartapki_genkey *)ptr);
	case SC_CARDCTL_ALADDIN_UPDATE_KEY:
		sc_log(ctx, "CMD SC_CARDCTL_ALADDIN_UPDATE_KEY");
		return jacartapki_update_key(card, (struct sc_cardctl_jacartapki_updatekey *)ptr);
	case SC_CARDCTL_PKCS11_INIT_TOKEN:
		sc_log(ctx, "CMD SC_CARDCTL_PKCS11_INIT_TOKEN");
		return SC_ERROR_NOT_SUPPORTED;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int
jacartapki_decipher(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	struct sc_tlv_data tlv;
	int rv;
	size_t offs;
	u8 *tagPtr;
	u8 *responseTagPtr;
	unsigned int tagClass;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "in-length:%" SC_FORMAT_LEN_SIZE_T "u, key-size:%" SC_FORMAT_LEN_SIZE_T "u, out-length:%" SC_FORMAT_LEN_SIZE_T "u", in_len, (prv->last_ko ? prv->last_ko->size : 0), out_len);
	if (env->operation != SC_SEC_OPERATION_DECIPHER)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "has to be SC_SEC_OPERATION_DECIPHER");
	else if (in_len > (sizeof(sbuf) - 4))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid data length");

	rv = sc_asn1_put_tag(0X82, in, in_len, sbuf, sizeof(sbuf), &tagPtr);
	assert(rv >= 0);
	offs = tagPtr - sbuf;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80,
			(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x0A : 0x0C);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = SC_MAX_APDU_RESP_SIZE;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	responseTagPtr = rbuf;
	rv = sc_asn1_read_tag((const u8 **)&responseTagPtr, apdu.resplen, &tagClass, &tlv.tag, &tlv.len);
	LOG_TEST_RET(ctx, rv, "Invalid response from PSO DST");
	tlv.value = responseTagPtr;

	if (tagClass != 0x80 || tlv.tag != 0x00) {
		sc_log(ctx, "invalid decrypted data tag. response(%" SC_FORMAT_LEN_SIZE_T "u) %s ...", apdu.resplen, sc_dump_hex(apdu.resp, 12));
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	if (tlv.len > out_len) {
		sc_log(ctx, "PSO Decipher failed: response data too long: %" SC_FORMAT_LEN_SIZE_T "u\n", tlv.len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	} else if (tlv.len == 0) {
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "PSO Decipher failed: response data missing.");
	}

	memcpy(out, tlv.value, tlv.len);
	LOG_FUNC_RETURN(ctx, (int)tlv.len);
}

static int
jacartapki_compute_signature_dst(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[MAX(SC_MAX_EXT_APDU_DATA_SIZE, SC_MAX_EXT_APDU_RESP_SIZE)];
	unsigned char dataTag;
	unsigned char pso;
	unsigned char algo;
	unsigned char tailReserved;
	int rv;
	size_t offs = 0;
	size_t keySize;
	unsigned long digestEncodeFlags;
	size_t digestLength;
	size_t sigValueLength;
	u8 *tagPtr;
	const u8 *sigValuePtr;

	LOG_FUNC_CALLED(ctx);

	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");

	keySize = prv->last_ko != NULL ? prv->last_ko->size : 0;
	sc_log(ctx, "SC_SEC_OPERATION: %04X, in-length:%" SC_FORMAT_LEN_SIZE_T "u, key-size:%" SC_FORMAT_LEN_SIZE_T "u", env->operation, in_len, keySize);

	if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224) ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_NONE)) {

		digestEncodeFlags = (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) | SC_ALGORITHM_RSA_PAD_NONE;

	} else if (env->algorithm_flags & SC_ALGORITHM_RSA_RAW) {

		digestEncodeFlags = SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_PAD_NONE;
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported digest type");
	}

	digestLength = sizeof(rbuf); /* rbuf reuse */
	rv = sc_pkcs1_encode(ctx, digestEncodeFlags, in, in_len, rbuf, &digestLength, keySize, NULL);
	LOG_TEST_RET(ctx, rv, "Failed to encode digest");

	if (env->algorithm_flags & SC_ALGORITHM_RSA_RAW) {
		dataTag = 0x82; /* tag 82H ciphertext */
		pso = 0x80;	/* PSO_Decrypt */
		algo = 0x0C;	/* ALG_RSA_NOPAD */
		tailReserved = 0;
	} else {
		dataTag = 0x80;
		pso = 0x9E;  /* PSO_Sign */
		algo = 0x8A; /* ALG_RSA_PKCS */
		tailReserved = 11;
	}

	if ((keySize && digestLength > (keySize - tailReserved)) || digestLength > SC_MAX_EXT_APDU_DATA_SIZE)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "too much of the input data");

	rv = sc_asn1_put_tag(dataTag, rbuf, digestLength, sbuf, sizeof(sbuf), &tagPtr);
	assert(rv >= 0);
	offs = tagPtr - sbuf;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, pso, algo);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = SC_MAX_APDU_RESP_SIZE;
	apdu.resp = rbuf;
	apdu.resplen = SC_MAX_EXT_APDU_RESP_SIZE;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	sigValuePtr = (u8 *)apdu.resp;
	if (env->algorithm_flags & SC_ALGORITHM_RSA_RAW) {
		unsigned int valueClass;
		unsigned int tagOut;
		rv = sc_asn1_read_tag(&sigValuePtr, apdu.resplen, &valueClass, &tagOut, &sigValueLength);
		LOG_TEST_RET(ctx, rv, "Incorrect ASN1 in PSO Decrypt response");

		if (0x00 != tagOut || 0x80 != valueClass || 5 > apdu.resplen)
			LOG_ERROR_RET(ctx, SC_ERROR_INTERNAL, "APDU response incorrect");
	} else {
		sigValueLength = apdu.resplen;
	}

	if (sigValueLength > out_len) {
		sc_log(ctx, "Compute signature failed: invalid response length %" SC_FORMAT_LEN_SIZE_T "u\n", sigValueLength);
		LOG_FUNC_RETURN(ctx, SC_ERROR_CARD_CMD_FAILED);
	}

	memcpy(out, sigValuePtr, sigValueLength);
	LOG_FUNC_RETURN(ctx, (int)sigValueLength);
}

static int
jacartapki_compute_signature_at(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv = (struct jacartapki_private_data *)card->drv_data;
	const struct sc_security_env *env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	if (env->operation != SC_SEC_OPERATION_AUTHENTICATE)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_AUTHENTICATE");

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

static int
jacartapki_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx;
	struct jacartapki_private_data *prv;
	struct sc_security_env *env;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	if (!in || !out)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid compute signature arguments");

	LOG_FUNC_CALLED(ctx);

	prv = (struct jacartapki_private_data *)card->drv_data;
	assert(prv);
	env = &prv->security_env;

	sc_log(ctx, "op:%x, inlen %" SC_FORMAT_LEN_SIZE_T "u, outlen %" SC_FORMAT_LEN_SIZE_T "u", env->operation, in_len, out_len);

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return jacartapki_compute_signature_dst(card, in, in_len, out, out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return jacartapki_compute_signature_at(card, in, in_len, out, out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

/* card reader lock obtained - re-select card applet if necessary. */
static int
jacartapki_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	if (was_reset > 0) {
		sc_path_set(&path, SC_PATH_TYPE_DF_NAME, jacartapki_aid.value, jacartapki_aid.len, 0, 0);
		rv = sc_select_file(card, &path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select Laser AID");
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

/* SM functions */
#ifdef ENABLE_SM

/*
 * _sm_*, _DES_* copy-pasted from sm/sm-common.c
 */

static int
_sm_decrypt_des_cbc3(struct sc_context *ctx, const unsigned char *key,
		unsigned char *data, size_t data_len,
		unsigned char **out, size_t *out_len)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
	sm_des_cblock kk, k2;
	DES_key_schedule ks, ks2;
	sm_des_cblock icv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	size_t st;
#else
	unsigned char icv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	EVP_CIPHER_CTX *cctx = NULL;
	EVP_CIPHER *alg = NULL;
	int tmplen;
#endif
	size_t decrypted_len;
	unsigned char *decrypted;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_SM);
	if (!out || !out_len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM decrypt_des_cbc3: invalid input arguments");

	decrypted_len = data_len + 7;
	decrypted_len -= decrypted_len % 8;

	decrypted = malloc(decrypted_len);
	if (!(decrypted))
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM decrypt_des_cbc3: allocation error");

#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);

	DES_set_key_unchecked(&kk, &ks);
	DES_set_key_unchecked(&k2, &ks2);

	for (st = 0; st < data_len; st += 8)
		_DES_3cbc_encrypt((sm_des_cblock *)(data + st),
				(sm_des_cblock *)(decrypted + st), 8, &ks, &ks2, &icv, DES_DECRYPT);
#else
	cctx = EVP_CIPHER_CTX_new();
	alg = sc_evp_cipher(ctx, "DES-EDE-CBC");
	if (!EVP_DecryptInit_ex2(cctx, alg, key, icv, NULL)) {
		sc_log_openssl(ctx);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		free(decrypted);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	/* Disable padding, otherwise it will fail to decrypt non-padded inputs */
	EVP_CIPHER_CTX_set_padding(cctx, 0);
	if (!EVP_DecryptUpdate(cctx, decrypted, &tmplen, data, (int)data_len)) {
		sc_log_openssl(ctx);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		free(decrypted);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	decrypted_len = tmplen;

	if (!EVP_DecryptFinal_ex(cctx, decrypted + decrypted_len, &tmplen)) {
		sc_log_openssl(ctx);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		free(decrypted);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	decrypted_len += tmplen;
	EVP_CIPHER_CTX_free(cctx);
	sc_evp_cipher_free(alg);
#endif
	*out = decrypted;
	*out_len = decrypted_len;
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_SUCCESS);
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
static void
_DES_3cbc_encrypt(sm_des_cblock *input, sm_des_cblock *output, long length,
		DES_key_schedule *ks1, DES_key_schedule *ks2, sm_des_cblock *iv,
		int enc)
{
	int off = ((int)length - 1) / 8;
	long l8 = ((length + 7) / 8) * 8;
	sm_des_cblock icv_out;

	memset(&icv_out, 0, sizeof(icv_out));
	if (enc == DES_ENCRYPT) {
		DES_cbc_encrypt((unsigned char *)input,
				(unsigned char *)output, length, ks1, iv, enc);
		DES_cbc_encrypt((unsigned char *)output,
				(unsigned char *)output, l8, ks2, iv, !enc);
		DES_cbc_encrypt((unsigned char *)output,
				(unsigned char *)output, l8, ks1, iv, enc);
		if ((unsigned)length >= sizeof(sm_des_cblock))
			memcpy(icv_out, output[off], sizeof(sm_des_cblock));
	} else {
		if ((unsigned)length >= sizeof(sm_des_cblock))
			memcpy(icv_out, input[off], sizeof(sm_des_cblock));
		DES_cbc_encrypt((unsigned char *)input,
				(unsigned char *)output, l8, ks1, iv, enc);
		DES_cbc_encrypt((unsigned char *)output,
				(unsigned char *)output, l8, ks2, iv, !enc);
		DES_cbc_encrypt((unsigned char *)output,
				(unsigned char *)output, length, ks1, iv, enc);
	}
	memcpy(*iv, icv_out, sizeof(sm_des_cblock));
}
#endif

/* This function expects the data to be a multiple of DES block size */
static int
_sm_encrypt_des_cbc3(struct sc_context *ctx, const unsigned char *key,
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int not_force_pad)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
	sm_des_cblock kk, k2;
	DES_key_schedule ks, ks2;
	sm_des_cblock icv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	size_t st;
#else
	unsigned char icv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	EVP_CIPHER_CTX *cctx = NULL;
	EVP_CIPHER *alg = NULL;
	int tmplen;
#endif
	unsigned char *data;
	size_t data_len;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_SM);
	sc_debug(ctx, SC_LOG_DEBUG_SM,
			"SM encrypt_des_cbc3: not_force_pad:%i,in_len:%" SC_FORMAT_LEN_SIZE_T "u",
			not_force_pad, in_len);
	if (!out || !out_len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM encrypt_des_cbc3: invalid input arguments");

	if (!in)
		in_len = 0;

	*out = NULL;
	*out_len = 0;

	data = malloc(in_len + 8);
	if (data == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM encrypt_des_cbc3: allocation error");

	if (in)
		memcpy(data, in, in_len);

	memcpy(data + in_len, "\x80\0\0\0\0\0\0\0", 8);
	data_len = in_len + (not_force_pad ? 7 : 8);
	data_len -= (data_len % 8);
	sc_debug(ctx, SC_LOG_DEBUG_SM,
			"SM encrypt_des_cbc3: data to encrypt (len:%" SC_FORMAT_LEN_SIZE_T "u,%s)",
			data_len, sc_dump_hex(data, data_len));

	*out_len = data_len;
	*out = calloc(data_len + 8, sizeof(unsigned char));
	if (*out == NULL) {
		free(data);
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM encrypt_des_cbc3: failure");
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L || defined(LIBRESSL_VERSION_NUMBER)
	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);

	DES_set_key_unchecked(&kk, &ks);
	DES_set_key_unchecked(&k2, &ks2);

	for (st = 0; st < data_len; st += 8)
		_DES_3cbc_encrypt((sm_des_cblock *)(data + st), (sm_des_cblock *)(*out + st), 8, &ks, &ks2, &icv, DES_ENCRYPT);
#else
	cctx = EVP_CIPHER_CTX_new();
	alg = sc_evp_cipher(ctx, "DES-EDE-CBC");
	if (!EVP_EncryptInit_ex2(cctx, alg, key, icv, NULL)) {
		sc_log_openssl(ctx);
		free(*out);
		free(data);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	/* Disable padding, otherwise it will fail to decrypt non-padded inputs */
	EVP_CIPHER_CTX_set_padding(cctx, 0);
	if (!EVP_EncryptUpdate(cctx, *out, &tmplen, data, (int)data_len)) {
		sc_log_openssl(ctx);
		free(*out);
		free(data);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	*out_len = tmplen;

	if (!EVP_EncryptFinal_ex(cctx, *out + *out_len, &tmplen)) {
		sc_log_openssl(ctx);
		free(*out);
		free(data);
		EVP_CIPHER_CTX_free(cctx);
		sc_evp_cipher_free(alg);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_ERROR_INTERNAL);
	}
	*out_len += tmplen;
	EVP_CIPHER_CTX_free(cctx);
	sc_evp_cipher_free(alg);
#endif

	free(data);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_SM, SC_SUCCESS);
}

static void
_sm_incr_ssc(unsigned char *ssc, size_t ssc_len)
{
	long ii;

	if (!ssc)
		return;

	for (ii = (long)ssc_len - 1; ii >= 0; ii--) {
		*(ssc + ii) += 1;
		if (*(ssc + ii) != 0)
			break;
	}
}

#if defined(LIBRESSL_VERSION_NUMBER)
static int
_compute_key_padded(struct sc_card *card, unsigned char *key /* shared secret */, int keySize, const BIGNUM *bY /* g^y mod N */, const BIGNUM *bx /* x */, const BIGNUM *bN /* N */)
{
	struct sc_context *ctx = card->ctx;
	BN_CTX *bnCtx = NULL;
	BIGNUM *bnR2 = NULL;
	int lZero;
	int rv = SC_SUCCESS;

	bnR2 = BN_new();
	if (!bnR2)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate BN");

	bnCtx = BN_CTX_new();
	if (!bnCtx)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate BN_CTX");

	if (0 == BN_mod_exp(bnR2, bY, bx, bN, bnCtx)) /* computes bY to the bx-th power modulo bN */
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "Failed to calculate shared secret");

	lZero = keySize - BN_num_bytes(bnR2);
	if (lZero > 0) {
		memset(key, 0, lZero);
		key += lZero;
	}

	BN_bn2bin(bnR2, key); /* key buffer size: DH_size(dh)*/
	rv = keySize;
err:
	BN_CTX_free(bnCtx);
	BN_free(bnR2);
	return rv;
}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

static EVP_PKEY *
icc_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* g */, const u8 *icc_p /* g^y mod N */, size_t icc_p_length)
{
	struct sc_context *ctx = card->ctx;
	OSSL_PARAM_BLD *param_builder = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *dh_key_ctx = NULL;
	EVP_PKEY *publicKey = NULL;

	param_builder = OSSL_PARAM_BLD_new();
	if (!param_builder)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_new failed");

	if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_P, prime))
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN prime failed");

	if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_G, generator))
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN generator failed");

	params = OSSL_PARAM_BLD_to_param(param_builder);
	if (!params)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_to_param failed");

	dh_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL); /*"provider=default"*/
	if (!dh_key_ctx)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new_from_name( DHX ) failed");

	if (EVP_PKEY_fromdata_init(dh_key_ctx) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata_init failed");

	publicKey = EVP_PKEY_new();
	if (!publicKey)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_new failed");

	if (EVP_PKEY_fromdata(dh_key_ctx, &publicKey, EVP_PKEY_KEY_PARAMETERS, params) <= 0 ||
			!EVP_PKEY_set1_encoded_public_key(publicKey, icc_p, icc_p_length)) {

		EVP_PKEY_free(publicKey);
		publicKey = NULL;
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata failed");
	}

err:
	OSSL_PARAM_BLD_free(param_builder);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(dh_key_ctx);
	return publicKey;
}

static EVP_PKEY *
ifd_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* G */, u8 **publicKey, size_t *publicKeyLength)
{
	struct sc_context *ctx = card->ctx;
	OSSL_PARAM_BLD *param_builder;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *dh_key_ctx = NULL;
	EVP_PKEY *dh_key_param = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *pkey = NULL;

	param_builder = OSSL_PARAM_BLD_new();
	if (!param_builder)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_new failed");

	if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_P, prime))
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN prime failed");

	if (!OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_G, generator))
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN generator failed");
	/*
	 * to use predefined private key BIGNUM:
	 * OSSL_PARAM_BLD_push_BN(param_builder,OSSL_PKEY_PARAM_PRIV_KEY, privKey)
	 * EVP_PKEY_fromdata(dh_key_ctx, &dh_key_param, EVP_PKEY_KEYPAIR, params)
	 * no key gen
	 */
	params = OSSL_PARAM_BLD_to_param(param_builder);
	if (!params)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_to_param failed");

	dh_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL); /*"provider=default"*/
	if (!dh_key_ctx)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new_from_name( DHX ) failed");

	if (EVP_PKEY_fromdata_init(dh_key_ctx) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata_init failed");

	if (EVP_PKEY_fromdata(dh_key_ctx, &dh_key_param, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata failed");

	key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_key_param, NULL);
	if (!key_ctx)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new_from_pkey failed");

	if (EVP_PKEY_keygen_init(key_ctx) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_keygen_init failed");

	if (EVP_PKEY_generate(key_ctx, &pkey) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_generate failed");

	*publicKeyLength = EVP_PKEY_get1_encoded_public_key(pkey, publicKey);

err:
	OSSL_PARAM_BLD_free(param_builder);
	OSSL_PARAM_free(params);
	EVP_PKEY_CTX_free(dh_key_ctx);
	EVP_PKEY_CTX_free(key_ctx);
	return pkey;
}

static int
derive_icc_ifd_key(struct sc_card *card, EVP_PKEY *icc_pkey, EVP_PKEY *ifd_pkey, u8 **sharedKey, size_t *keyLength)
{
	struct sc_context *ctx = card->ctx;
	EVP_PKEY_CTX *shared_key_ctx = NULL;
	u8 *shared_key;
	size_t shared_key_length;
	int rv;

	shared_key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ifd_pkey, NULL);
	if (!shared_key_ctx)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new failed");

	rv = EVP_PKEY_derive_init(shared_key_ctx);
	if (rv <= 0)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_derive_init failed");

	rv = EVP_PKEY_derive_set_peer_ex(shared_key_ctx, icc_pkey, 0);
	if (rv <= 0)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_derive_set_peer failed");

	rv = EVP_PKEY_derive(shared_key_ctx, NULL, &shared_key_length);
	if (rv <= 0)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_derive failed");

	shared_key = OPENSSL_malloc(shared_key_length);
	if (!shared_key)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "OPENSSL_malloc failed to allocate shared key buffer");

	rv = EVP_PKEY_derive(shared_key_ctx, shared_key, &shared_key_length);
	if (rv <= 0)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_derive failed");

	*sharedKey = shared_key;
	*keyLength = shared_key_length;
	rv = SC_SUCCESS;
err:
	EVP_PKEY_CTX_free(shared_key_ctx);
	return rv;
}

#endif

static int
jacartapki_sm_open(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sm_dh_session *dh_session = &card->sm_ctx.info.session.dh;
	struct sc_apdu apdu;
	BIGNUM *bn_N, *bn_g;
	unsigned char uu, rbuf[SC_MAX_APDU_BUFFER_SIZE * 2];
	int rv;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY *icc_pkey = NULL;
	EVP_PKEY *ifd_pkey = NULL;
	u8 *ifd_public_key = NULL;
	size_t ifd_public_key_length = 0;
	u8 *shared_key = NULL;
	size_t shared_key_length = 0;
#else
	const BIGNUM *bn_icc_p;
	BIGNUM *bn_ifd_y;
	int rd, dh_check;
	DH *dh = NULL;
	const BIGNUM *pub_key = NULL;
#endif
	LOG_FUNC_CALLED(ctx);
	memset(&card->sm_ctx.info, 0, sizeof(card->sm_ctx.info));

	private_data->sm_establish = 1;

	/* getting SM RSA public parameters */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x48, 0x00, 0x80);
	apdu.cla = 0x80;
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "'GET PUBLIC KEY' failed");

	dh_session->g.tag = JACARTAPKI_SM_RSA_TAG_G; /* TLV tag 80H g */
	rv = jacartapki_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->g);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'g'");
	bn_g = BN_bin2bn(dh_session->g.value, (int)dh_session->g.len, NULL);

	dh_session->N.tag = JACARTAPKI_SM_RSA_TAG_N; /* TLV tag 81H N */
	rv = jacartapki_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->N);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'N'");
	bn_N = BN_bin2bn(dh_session->N.value, (int)dh_session->N.len, NULL);

	dh_session->icc_p.tag = JACARTAPKI_SM_RSA_TAG_ICC_P; /* TLV tag 82H g^y mod N */
	rv = jacartapki_get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->icc_p);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'ICC-P'");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	/* ----------------------------- ICC key ----------------------------- */
	icc_pkey = icc_DH(card, bn_N, bn_g, dh_session->icc_p.value, dh_session->icc_p.len);
	if (!icc_pkey)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "Failed to form icc key.");

	/* ----------------------------- IFD key ----------------------------- */
	ifd_pkey = ifd_DH(card, bn_N, bn_g, &ifd_public_key, &ifd_public_key_length);
	if (!ifd_pkey)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "Failed to generate ifd key.");
	assert(ifd_public_key && ifd_public_key_length);

	/* ----------------------------- shared key ----------------------------- */
	rv = derive_icc_ifd_key(card, icc_pkey, ifd_pkey, &shared_key, &shared_key_length);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to derive ICC IFD shared key");
	assert(shared_key && shared_key_length);

	dh_session->ifd_p.value = ifd_public_key;
	dh_session->ifd_p.len = ifd_public_key_length;
	ifd_public_key = NULL;
	ifd_public_key_length = 0;

	dh_session->shared_secret.value = shared_key;
	dh_session->shared_secret.len = shared_key_length;
	shared_key = NULL;
	shared_key_length = 0;
#else
	bn_icc_p = BN_bin2bn(dh_session->icc_p.value, dh_session->icc_p.len, NULL);

	dh_session->ifd_y.value = malloc(SHA_DIGEST_LENGTH);
	if (!dh_session->ifd_y.value)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate private DH key");

	RAND_bytes((unsigned char *)&rd, sizeof(rd));
	SHA1((unsigned char *)(&rd), sizeof(rd), dh_session->ifd_y.value);
	dh_session->ifd_y.len = SHA_DIGEST_LENGTH;
	bn_ifd_y = BN_bin2bn(dh_session->ifd_y.value, dh_session->ifd_y.len, NULL);

	dh = DH_new();
	if (!dh)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate DH key");

	DH_set0_pqg(dh, bn_N, NULL, bn_g); /* dh->p, dh->g */
	DH_set0_key(dh, NULL, bn_ifd_y);   /* dh->priv_key */

	if (!DH_check(dh, &dh_check))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "OpenSSL 'DH-check' failed");
	if (!DH_generate_key(dh))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "OpenSSL 'DH-generate-key' failed");

	DH_get0_key(dh, &pub_key, NULL);

	dh_session->ifd_p.value = (unsigned char *)OPENSSL_malloc(BN_num_bytes(pub_key));
	if (!dh_session->ifd_p.value)
		LOG_ERROR_GOTO(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate IFD public key part");
	dh_session->ifd_p.len = BN_bn2bin(pub_key, dh_session->ifd_p.value);

	dh_session->shared_secret.value = (unsigned char *)OPENSSL_malloc(DH_size(dh));
	if (!dh_session->shared_secret.value)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate shared secret part");

#if !defined(LIBRESSL_VERSION_NUMBER)
	dh_session->shared_secret.len = DH_compute_key_padded(dh_session->shared_secret.value, bn_icc_p, dh);
#else
	rv = _compute_key_padded(card, dh_session->shared_secret.value, DH_size(dh), bn_icc_p, bn_ifd_y, bn_N);
	if (DH_size(dh) > rv)
		LOG_ERROR_GOTO(ctx, rv, "Failed to calculate shared secret");
#endif
#endif

	sc_log(ctx, "shared-secret(%" SC_FORMAT_LEN_SIZE_T "u) %s", dh_session->shared_secret.len,
			sc_dump_hex(dh_session->shared_secret.value, dh_session->shared_secret.len));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x86, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.lc = dh_session->ifd_p.len;
	apdu.datalen = dh_session->ifd_p.len;
	apdu.data = dh_session->ifd_p.value;
	apdu.le = sizeof(dh_session->card_challenge);
	apdu.resplen = sizeof(dh_session->card_challenge);
	apdu.resp = dh_session->card_challenge;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "'OPEN SM' failed");

	memcpy(dh_session->session_enc, dh_session->shared_secret.value, sizeof(dh_session->session_enc));
	memcpy(dh_session->session_mac, dh_session->shared_secret.value + 24, sizeof(dh_session->session_mac));
	for (uu = 0; uu < sizeof(dh_session->session_enc); uu++) {
		dh_session->session_enc[uu] ^= dh_session->card_challenge[uu];
		dh_session->session_mac[uu] ^= dh_session->card_challenge[16 + uu];
	}

	sc_log(ctx, "session key enc: %s", sc_dump_hex(dh_session->session_enc, 16));
	sc_log(ctx, "session key auth: %s", sc_dump_hex(dh_session->session_mac, 16));

	memset(dh_session->ssc, 0, sizeof(dh_session->ssc));

	card->sm_ctx.info.sm_type = SM_TYPE_DH_RSA;
	card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;

err:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_PKEY_free(icc_pkey);
	EVP_PKEY_free(ifd_pkey);
	OPENSSL_free(ifd_public_key);
	OPENSSL_free(shared_key);
#else
	DH_free(dh);
#endif
	private_data->sm_establish = 0;
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_cbc_cksum(struct sc_card *card, unsigned char *key, size_t key_size,
		unsigned char *in, size_t in_len, DES_cblock *icv)
{
	struct sc_context *ctx = card->ctx;
	DES_cblock out, last;
	size_t ii;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	EVP_CIPHER_CTX *evpK1Ctx = NULL;
	EVP_CIPHER_CTX *evpK2Ctx = NULL;
	OSSL_PARAM desParams[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
	void *updatedIV; /* DES_cblock */
	unsigned int padding;
	int len;
#else
	DES_key_schedule ks, ks2;
	size_t len;
#endif
	int rv = SC_SUCCESS;

	if (!key || !in || !icv || key_size != 2 * sizeof(DES_cblock))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (in_len % sizeof(DES_cblock))
		return SC_ERROR_INVALID_DATA;

	memset(icv, 0, sizeof(*icv));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

	evpK1Ctx = EVP_CIPHER_CTX_new();
	evpK2Ctx = EVP_CIPHER_CTX_new();
	if (!evpK1Ctx || !evpK2Ctx)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate EVP_CIPHER_CTX");

	desParams[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &padding);
	if (!EVP_CipherInit_ex2(evpK1Ctx, private_data->desCbcCipher, &key[0], *icv, 1, desParams))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-CBC cipher init failed");

	sc_log(ctx, "data for checksum (%" SC_FORMAT_LEN_SIZE_T "u) %s", in_len, sc_dump_hex(in, in_len));
	for (len = (int)in_len; len > (int)sizeof(DES_cblock); len -= (int)sizeof(DES_cblock), in += sizeof(DES_cblock)) {
		int tmpLen = 0;
		if (!EVP_EncryptUpdate(evpK1Ctx, out, &tmpLen, in, (int)sizeof(DES_cblock)))
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-CBC encrypt failed");
	}

	updatedIV = NULL;
	desParams[0] = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_UPDATED_IV, (void **)&updatedIV, 0); /* desParams reuse */
	if (!EVP_CIPHER_CTX_get_params(evpK1Ctx, desParams) || desParams[0].return_size != sizeof(*icv))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "Failed to get DES cipher params");

	for (ii = 0; ii < sizeof(DES_cblock); ii++)
		last[ii] = *(in + ii) ^ (*(DES_cblock *)updatedIV)[ii];

	EVP_CIPHER_CTX_reset(evpK1Ctx); /* evpCtx reuse */

	padding = 0;
	desParams[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &padding);
	/* for DESX, DES-EDE there is no ecb2_encrypt */
	if (!EVP_CipherInit_ex2(evpK1Ctx, private_data->desEcbCipher, &key[0], NULL, 1, desParams))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-ECB cipher init failed");
	if (!EVP_CipherInit_ex2(evpK2Ctx, private_data->desEcbCipher, &key[sizeof(DES_cblock)], NULL, 0, desParams))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-ECB cipher init failed");

	if (!EVP_EncryptUpdate(evpK1Ctx, out, &len, last, sizeof(DES_cblock)))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-ECB failed");
	if (!EVP_DecryptUpdate(evpK2Ctx, out, &len, out, sizeof(DES_cblock)))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-ECB failed");
	if (!EVP_EncryptUpdate(evpK1Ctx, *icv, &len, out, sizeof(DES_cblock)))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "DES-ECB failed");

#else
	DES_set_key((const_DES_cblock *)&key[0], &ks);
	DES_set_key((const_DES_cblock *)&key[sizeof(DES_cblock)], &ks2);

	sc_log(ctx, "data for checksum (%" SC_FORMAT_LEN_SIZE_T "u) %s", in_len, sc_dump_hex(in, in_len));
	for (len = (int)in_len; len > (int)sizeof(DES_cblock); len -= (int)sizeof(DES_cblock), in += sizeof(DES_cblock))
		DES_ncbc_encrypt(in, out, sizeof(DES_cblock), &ks, icv, DES_ENCRYPT);

	for (ii = 0; ii < sizeof(DES_cblock); ii++)
		last[ii] = *(in + ii) ^ (*icv)[ii];

	DES_ecb2_encrypt(&last, &out, &ks, &ks2, DES_ENCRYPT);
	memcpy(icv, &out, sizeof(*icv));
#endif
	sc_log(ctx, "cksum %s", sc_dump_hex((unsigned char *)icv, sizeof(*icv)));
	rv = SC_SUCCESS;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
err:
	EVP_CIPHER_CTX_free(evpK1Ctx);
	EVP_CIPHER_CTX_free(evpK2Ctx);
#endif
	return rv;
}

static int
jacartapki_sm_compute_mac(struct sc_card *card, const unsigned char *data, size_t data_len, DES_cblock *mac)
{
	struct sc_context *ctx = card->ctx;
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	unsigned char *dt = NULL, *ptr;
	size_t dt_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	/* Reserve place for SSC and data. */
	dt_len = sizeof(sess->ssc) + data_len;
	if (dt_len % sizeof(DES_cblock))
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_SM_INVALID_CHECKSUM, "Incorrect data size to checksum"); /* TODO: appropriate error code */

	ptr = dt = calloc(1, dt_len);
	if (!dt)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate checksum buffer");

	_sm_incr_ssc(sess->ssc, sizeof(sess->ssc));

	memcpy(ptr, sess->ssc, sizeof(sess->ssc));
	ptr += sizeof(sess->ssc);

	memcpy(ptr, data, data_len);

	rv = jacartapki_cbc_cksum(card, sess->session_mac, sizeof(sess->session_mac), dt, dt_len, mac);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get checksum CBC 3DES");
err:
	free(dt);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_sm_check_mac(struct sc_card *card, const unsigned char *data, size_t data_len,
		const unsigned char *mac, size_t mac_len)
{
	struct sc_context *ctx = card->ctx;
	int rv;
	DES_cblock macComputed;

	if (mac_len != sizeof(macComputed))
		LOG_ERROR_RET(ctx, SC_ERROR_SM_INVALID_CHECKSUM, "Invalid checksum length");

	rv = jacartapki_sm_compute_mac(card, data, data_len, &macComputed);
	LOG_TEST_RET(ctx, rv, "Failed to compute checksum");

	if (memcmp(mac, macComputed, mac_len))
		LOG_ERROR_RET(ctx, SC_ERROR_SM_INVALID_CHECKSUM, "Invalid checksum");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_sm_close(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	if (card->sm_ctx.sm_mode != SM_MODE_NONE) {
		struct sc_apdu apdu;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x86, 0xFF, 0xFF);
		apdu.cla = 0x80;
		apdu.flags = SC_APDU_FLAGS_NO_SM;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "'CLOSE SM' failed");

		card->sm_ctx.sm_mode = SM_MODE_NONE;
		memset(&card->sm_ctx.info, 0, sizeof(card->sm_ctx.info));
	}

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_iso_sm_open(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iso_sm_ctx *sctx = NULL;
	struct jacartapki_private_data *prv_data = (struct jacartapki_private_data *)card->drv_data;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = jacartapki_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM init failed");

	sctx = iso_sm_ctx_create();
	if (!sctx)
		LOG_ERROR_GOTO(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate SM context.");

	sctx->priv_data = prv_data;
	sctx->padding_indicator = SM_ISO_PADDING;
	sctx->block_length = sizeof(DES_cblock);
	sctx->authenticate = jacartapki_iso_sm_authenticate;
	sctx->encrypt = jacartapki_iso_sm_encrypt;
	sctx->decrypt = jacartapki_iso_sm_decrypt;
	sctx->verify_authentication = jacartapki_iso_sm_verify_authentication;

	rv = iso_sm_start(card, sctx);
	LOG_TEST_GOTO_ERR(ctx, rv, "Iso-sm start failed.");

	card->sm_ctx.ops.close = jacartapki_iso_sm_close;
	card->sm_ctx.ops.get_sm_apdu = jacartapki_iso_sm_get_apdu;
	card->sm_ctx.ops.free_sm_apdu = jacartapki_iso_sm_free_apdu;

	card->max_send_size = 0xEF; /* 0x10 SM overhead */

err:
	if (rv < 0)
		iso_sm_ctx_clear_free(sctx);

	return rv;
}

static int
jacartapki_iso_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc)
{
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	size_t valLen;
	int rv;

	rv = _sm_encrypt_des_cbc3(card->ctx, sess->session_enc, data, datalen, enc, &valLen, 1);
	LOG_TEST_RET(card->ctx, rv, "CBC 3DES encrypt failed");
	return (int)valLen;
}

static int
jacartapki_iso_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data)
{
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	size_t valLen;
	int rv;

	rv = _sm_decrypt_des_cbc3(card->ctx, sess->session_enc, (u8 *)enc, enclen, data, &valLen);
	LOG_TEST_RET(card->ctx, rv, "CBC 3DES decrypt failed");
	return (int)valLen;
}

static int
jacartapki_iso_sm_get_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu)
{
	const struct jacartapki_private_data *private_data = (const struct jacartapki_private_data *)card->drv_data;
	int rv;

	if (private_data->sm_establish != 0)
		return SC_ERROR_SM_NOT_APPLIED;

	rv = iso_get_sm_apdu(card, apdu, sm_apdu);
	if (rv == SC_SUCCESS) {
		struct sc_apdu *sm_apdu_correct = *sm_apdu;
		/*
		INS translation back
		CC -> CB
		48 -> 47
		*/
		if (sm_apdu_correct->ins == 0xCC || sm_apdu_correct->ins == 0x48) {
			sm_apdu_correct->ins = (sm_apdu_correct->ins == 0xCC ? 0xCB : 0x47); /* not a good practice */
		}
	}
	return rv;
}

static int
jacartapki_iso_sm_free_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu)
{
	int rv;
	struct sc_apdu *p;

	p = *sm_apdu;
	rv = iso_free_sm_apdu(card, apdu, &p);
	if (rv < 0)
		rv = sc_check_sw(card, (*sm_apdu)->sw1, (*sm_apdu)->sw2);

	return rv;
}

static int
jacartapki_iso_sm_close(struct sc_card *card)
{
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	jacartapki_sm_close(card);
	rv = iso_sm_close(card);
	card->max_send_size = 0xFF; /* no SM overhead */

	return rv;
}

static int
jacartapki_iso_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **outdata)
{
	int rv;
	DES_cblock *mac;
	size_t macLen = sizeof(DES_cblock);

	/*
	INS translation back
	CC -> CB
	48 -> 47

	data[0]: apdu->cla;
	data[1]: apdu->ins;
	...
	*/
	if (data[1] == 0xCC || data[1] == 0x48) {
		u8 *patchableApdu = (u8 *)data;
		patchableApdu[1] = (patchableApdu[1] == 0xCC ? 0xCB : 0x47); /* not a good practice too */
	}
	mac = calloc(1, macLen);
	if (!mac)
		LOG_ERROR_GOTO(card->ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate MAC buffer");

	rv = jacartapki_sm_compute_mac(card, data, datalen, mac);
	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to compute MAC checksum");

	*outdata = (u8 *)mac;
	rv = (int)macLen;
err:
	if (rv < 0)
		free(mac);
	return rv;
}

static int
jacartapki_iso_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *mac, size_t maclen,
		const u8 *macdata, size_t macdatalen)
{
	return jacartapki_sm_check_mac(card, macdata, macdatalen, mac, maclen);
}

#endif /* ENABLE_SM */

static struct sc_card_driver *
sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (!iso_ops)
		iso_ops = iso_drv->ops;

	jacartapki_ops = *iso_ops;

	jacartapki_ops.match_card = jacartapki_match_card;
	jacartapki_ops.init = jacartapki_init;
	jacartapki_ops.finish = jacartapki_finish;
	jacartapki_ops.read_binary = jacartapki_read_binary;
	/*	write_binary: ISO7816 implementation works	*/
	jacartapki_ops.update_binary = jacartapki_update_binary;
	jacartapki_ops.erase_binary = jacartapki_erase_binary;
	/*	resize_binary	*/
	/*	read_record: Untested	*/
	/*	write_record: Untested	*/
	/*	append_record: Untested	*/
	/*	update_record: Untested	*/
	jacartapki_ops.select_file = jacartapki_select_file;
	/*	get_response: Untested	*/
	/*	get_challenge: ISO7816 implementation works	*/
	jacartapki_ops.logout = jacartapki_logout;
	/*	restore_security_env	*/
	jacartapki_ops.set_security_env = jacartapki_set_security_env;
	jacartapki_ops.decipher = jacartapki_decipher;
	jacartapki_ops.compute_signature = jacartapki_compute_signature;
	jacartapki_ops.create_file = jacartapki_create_file;
	jacartapki_ops.delete_file = jacartapki_delete_file;
	jacartapki_ops.list_files = jacartapki_list_files;
	jacartapki_ops.check_sw = jacartapki_check_sw;
	jacartapki_ops.card_ctl = jacartapki_card_ctl;
	jacartapki_ops.process_fci = jacartapki_process_fci;
	/*	construct_fci: Not needed	*/
	jacartapki_ops.pin_cmd = jacartapki_pin_cmd;
	/*	get_data: Not implemented	*/
	/*	put_data: Not implemented	*/
	/*	delete_record: Not implemented	*/

	/* jacartapki_ops.read_public_key = jacartapki_read_public_key	*/

	jacartapki_ops.card_reader_lock_obtained = jacartapki_card_reader_lock_obtained;

	return &jacartapki_drv;
}

struct sc_card_driver *
sc_get_jacartapki_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
