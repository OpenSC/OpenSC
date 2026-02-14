/*
 * jacartapki.h: Support for JaCarta PKI applet
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
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <stdlib.h>
#include <string.h>

#include "libopensc/jacartapki.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/sc-ossl-compat.h"
#include "sm/sm-common.h"
#include "sm/sm-iso-internal.h"
#include "sm/sm-iso.h"
#include "sm/sm-jacartapki.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include <openssl/bn.h>
#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

#if defined(USE_OPENSSL3_LIBCTX)
#define JACARTAPKI_OSSL3CTX(a) a->ossl3ctx->libctx
#else
#define JACARTAPKI_OSSL3CTX(a) NULL
#endif

static int _get_tag_data(struct sc_context *ctx, const unsigned char *data, size_t data_len,
		struct sc_tlv_data *out);

#if defined(LIBRESSL_VERSION_NUMBER)
static int _compute_key_padded(struct sc_card *card, unsigned char *key /* shared secret */, int keySize,
		const BIGNUM *bY /* g^y mod N */, const BIGNUM *bx /* x */, const BIGNUM *bN /* N */);
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
static EVP_PKEY *icc_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* g */,
		const u8 *icc_p /* g^y mod N */, size_t icc_p_length);
static EVP_PKEY *ifd_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* G */,
		u8 **publicKey, size_t *publicKeyLength);
static int derive_icc_ifd_key(struct sc_card *card, EVP_PKEY *icc_pkey, EVP_PKEY *ifd_pkey,
		u8 **sharedKey, size_t *keyLength);
#endif

static int jacartapki_sm_open(struct sc_card *card);
static int jacartapki_sm_cbc_cksum(struct sc_card *card, unsigned char *key, size_t key_size,
		unsigned char *in, size_t in_len, DES_cblock *icv);
static int jacartapki_sm_compute_mac(struct sc_card *card, const unsigned char *data, size_t data_len,
		DES_cblock *mac);
static int jacartapki_sm_check_mac(struct sc_card *card, const unsigned char *data, size_t data_len,
		const unsigned char *mac, size_t mac_len);
static int jacartapki_sm_close(struct sc_card *card);

static int jacartapki_iso_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *data,
		size_t datalen, u8 **enc);
static int jacartapki_iso_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *enc,
		size_t enclen, u8 **data);
static int jacartapki_iso_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *data,
		size_t datalen, u8 **outdata);
static int jacartapki_iso_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx, const u8 *mac,
		size_t maclen, const u8 *macdata, size_t macdatalen);

static int
_get_tag_data(struct sc_context *ctx, const unsigned char *data, size_t data_len, struct sc_tlv_data *out)
{
	size_t taglen;
	const unsigned char *ptr = NULL;

	if (ctx == NULL || data == NULL || out == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = sc_asn1_find_tag(ctx, data, data_len, out->tag, &taglen);
	if (ptr == NULL)
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;

	out->value = malloc(taglen);
	if (out->value == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(out->value, ptr, taglen);
	out->len = taglen;

	return SC_SUCCESS;
}

#if defined(LIBRESSL_VERSION_NUMBER)
static int
_compute_key_padded(struct sc_card *card, unsigned char *key /* shared secret */, int keySize, const BIGNUM *bY /* g^y mod N */,
		const BIGNUM *bx /* x */, const BIGNUM *bN /* N */)
{
	struct sc_context *ctx = card->ctx;
	BN_CTX *bnCtx = NULL;
	BIGNUM *bnR2 = NULL;
	int lZero;
	int rv = SC_SUCCESS;

	bnR2 = BN_new();
	if (bnR2 == NULL)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate BN");

	bnCtx = BN_CTX_new();
	if (bnCtx == NULL)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate BN_CTX");

	if (BN_mod_exp(bnR2, bY, bx, bN, bnCtx) == 0) { /* computes bY to the bx-th power modulo bN */
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "Failed to calculate shared secret");
	}

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
#endif /* LIBRESSL_VERSION_NUMBER */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
static EVP_PKEY *
icc_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* g */,
		const u8 *icc_p /* g^y mod N */, size_t icc_p_length)
{
	struct sc_context *ctx = card->ctx;
	OSSL_PARAM_BLD *param_builder;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *dh_key_ctx = NULL;
	EVP_PKEY *publicKey = NULL;

	param_builder = OSSL_PARAM_BLD_new();
	if (param_builder == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_new failed");

	if (OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_P, prime) == 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN prime failed");

	if (OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_G, generator) == 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN generator failed");

	params = OSSL_PARAM_BLD_to_param(param_builder);
	if (params == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_to_param failed");

	dh_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL); /*"provider=default"*/
	if (dh_key_ctx == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new_from_name( DHX ) failed");

	if (EVP_PKEY_fromdata_init(dh_key_ctx) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata_init failed");

	publicKey = EVP_PKEY_new();
	if (publicKey == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_new failed");

	if (EVP_PKEY_fromdata(dh_key_ctx, &publicKey, EVP_PKEY_KEY_PARAMETERS, params) <= 0 ||
			EVP_PKEY_set1_encoded_public_key(publicKey, icc_p, icc_p_length) == 0) {

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
ifd_DH(struct sc_card *card, const BIGNUM *prime /* N */, const BIGNUM *generator /* G */, u8 **publicKey,
		size_t *publicKeyLength)
{
	struct sc_context *ctx = card->ctx;
	OSSL_PARAM_BLD *param_builder;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *dh_key_ctx = NULL;
	EVP_PKEY *dh_key_param = NULL;
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *pkey = NULL;

	param_builder = OSSL_PARAM_BLD_new();
	if (param_builder == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_new failed");

	if (OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_P, prime) == 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN prime failed");

	if (OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_FFC_G, generator) == 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_push_BN generator failed");
	/*
	 * to use predefined private key BIGNUM:
	 * OSSL_PARAM_BLD_push_BN(param_builder,OSSL_PKEY_PARAM_PRIV_KEY, privKey)
	 * EVP_PKEY_fromdata(dh_key_ctx, &dh_key_param, EVP_PKEY_KEYPAIR, params)
	 * no key gen
	 */
	params = OSSL_PARAM_BLD_to_param(param_builder);
	if (params == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "OSSL_PARAM_BLD_to_param failed");

	dh_key_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL); /*"provider=default"*/
	if (dh_key_ctx == NULL)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new_from_name( DHX ) failed");

	if (EVP_PKEY_fromdata_init(dh_key_ctx) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata_init failed");

	if (EVP_PKEY_fromdata(dh_key_ctx, &dh_key_param, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
		LOG_ERROR_GOTO(ctx, SC_ERROR_INTERNAL, "EVP_PKEY_fromdata failed");

	key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, dh_key_param, NULL);
	if (key_ctx == NULL)
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
	if (shared_key_ctx == NULL)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INTERNAL, "EVP_PKEY_CTX_new failed");

	rv = EVP_PKEY_derive_init(shared_key_ctx);
	if (rv <= 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "EVP_PKEY_derive_init failed");
	}

	rv = EVP_PKEY_derive_set_peer_ex(shared_key_ctx, icc_pkey, 0);
	if (rv <= 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "EVP_PKEY_derive_set_peer failed");
	}

	rv = EVP_PKEY_derive(shared_key_ctx, NULL, &shared_key_length);
	if (rv <= 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "EVP_PKEY_derive failed");
	}

	shared_key = OPENSSL_malloc(shared_key_length);
	if (shared_key == NULL) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "OPENSSL_malloc failed to allocate shared key buffer");
	}

	rv = EVP_PKEY_derive(shared_key_ctx, shared_key, &shared_key_length);
	if (rv <= 0) {
		OPENSSL_free(shared_key);
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "EVP_PKEY_derive failed");
	}

	*sharedKey = shared_key;
	*keyLength = shared_key_length;
	rv = SC_SUCCESS;
err:
	EVP_PKEY_CTX_free(shared_key_ctx);
	return rv;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER) */

int
jacartapki_sm_chv_change(struct sc_card *card, struct sc_pin_cmd_data *data, unsigned chv_ref,
		int *tries_left, unsigned op_acl)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	unsigned char pin_data[SC_MAX_APDU_BUFFER_SIZE];
	size_t offs;
	int rv;
	int oneTimeSm = 0;

	if (card == NULL)
		return SC_ERROR_INTERNAL;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM change CHV(ref %i, length %" SC_FORMAT_LEN_SIZE_T "u, op-acl %X)", chv_ref, data->pin2.len, op_acl);

	if (data->pin2.len == 0)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure needs new PIN defined");

	if (4 + data->pin2.len > sizeof(pin_data))
		LOG_ERROR_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "'SM change CHV' data is too large to fit into APDU buffer");

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
	if (rv == SC_SUCCESS)
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (oneTimeSm != 0)
		jacartapki_iso_sm_close(card);

	card->sm_ctx.info.security_condition = 0;

	LOG_TEST_RET(ctx, rv, "SM change CHV failed");
	LOG_FUNC_RETURN(ctx, rv);
}

int
jacartapki_sm_encrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int not_force_pad)
{
	return sm_encrypt_des_cbc3(ctx, key, in, in_len, out, out_len, not_force_pad);
}

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
	BIGNUM *bn_icc_p = NULL;
	BIGNUM *bn_ifd_y = NULL;
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
	rv = _get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->g);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'g'");
	bn_g = BN_bin2bn(dh_session->g.value, (int)dh_session->g.len, NULL);

	dh_session->N.tag = JACARTAPKI_SM_RSA_TAG_N; /* TLV tag 81H N */
	rv = _get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->N);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'N'");
	bn_N = BN_bin2bn(dh_session->N.value, (int)dh_session->N.len, NULL);

	dh_session->icc_p.tag = JACARTAPKI_SM_RSA_TAG_ICC_P; /* TLV tag 82H g^y mod N */
	rv = _get_tag_data(ctx, apdu.resp, apdu.resplen, &dh_session->icc_p);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid 'GET PUBLIC KEY' data: missing 'ICC-P'");

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	/* ----------------------------- ICC key ----------------------------- */
	icc_pkey = icc_DH(card, bn_N, bn_g, dh_session->icc_p.value, dh_session->icc_p.len);
	if (icc_pkey == NULL) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "Failed to form icc key.");
	}

	/* ----------------------------- IFD key ----------------------------- */
	ifd_pkey = ifd_DH(card, bn_N, bn_g, &ifd_public_key, &ifd_public_key_length);
	if (ifd_pkey == NULL || ifd_public_key == NULL || ifd_public_key_length == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "Failed to generate ifd key.");
	}

	/* ----------------------------- shared key ----------------------------- */
	rv = derive_icc_ifd_key(card, icc_pkey, ifd_pkey, &shared_key, &shared_key_length);
	if (rv < 0 || shared_key == NULL || shared_key_length == 0) {
		if (rv >= 0)
			rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "Failed to derive ICC IFD shared key");
	}

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
	if (bn_icc_p == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Cannot allocate ICC_P BN");
	}

	dh_session->ifd_y.value = malloc(SHA_DIGEST_LENGTH);
	if (dh_session->ifd_y.value == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Cannot allocate private DH key");
	}

	RAND_bytes((unsigned char *)&rd, sizeof(rd));
	SHA1((unsigned char *)(&rd), sizeof(rd), dh_session->ifd_y.value);
	dh_session->ifd_y.len = SHA_DIGEST_LENGTH;
	bn_ifd_y = BN_bin2bn(dh_session->ifd_y.value, dh_session->ifd_y.len, NULL);
	if (bn_ifd_y == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Cannot allocate IFD_Y BN");
	}

	dh = DH_new();
	if (dh == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Cannot allocate DH key");
	}

	DH_set0_pqg(dh, bn_N, NULL, bn_g); /* dh->p, dh->g */
	DH_set0_key(dh, NULL, bn_ifd_y);   /* dh->priv_key */

	if (DH_check(dh, &dh_check) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "OpenSSL 'DH-check' failed");
	}
	if (DH_generate_key(dh) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "OpenSSL 'DH-generate-key' failed");
	}

	DH_get0_key(dh, &pub_key, NULL);

	dh_session->ifd_p.value = (unsigned char *)OPENSSL_malloc(BN_num_bytes(pub_key));
	if (dh_session->ifd_p.value == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate IFD public key part");
	}
	dh_session->ifd_p.len = BN_bn2bin(pub_key, dh_session->ifd_p.value);

	dh_session->shared_secret.value = (unsigned char *)OPENSSL_malloc(DH_size(dh));
	if (dh_session->shared_secret.value == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate shared secret part");
	}

#if !defined(LIBRESSL_VERSION_NUMBER)
	dh_session->shared_secret.len = DH_compute_key_padded(dh_session->shared_secret.value, bn_icc_p, dh);
#else
	rv = _compute_key_padded(card, dh_session->shared_secret.value, DH_size(dh), bn_icc_p, bn_ifd_y, bn_N);
	if (DH_size(dh) > rv)
		LOG_ERROR_GOTO(ctx, rv, "Failed to calculate shared secret");
#endif
#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER) */

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
	BN_free(bn_icc_p);
	DH_free(dh);
#endif
	private_data->sm_establish = 0;
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_sm_cbc_cksum(struct sc_card *card, unsigned char *key, size_t key_size,
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

	if (key == NULL || in == NULL || icv == NULL || key_size != 2 * sizeof(DES_cblock))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (in_len % sizeof(DES_cblock))
		return SC_ERROR_INVALID_DATA;

	memset(icv, 0, sizeof(*icv));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

	evpK1Ctx = EVP_CIPHER_CTX_new();
	evpK2Ctx = EVP_CIPHER_CTX_new();
	if (evpK1Ctx == NULL || evpK2Ctx == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate EVP_CIPHER_CTX");
	}

	desParams[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &padding);
	if (EVP_CipherInit_ex2(evpK1Ctx, private_data->desCbcCipher, &key[0], *icv, 1, desParams) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-CBC cipher init failed");
	}

	sc_log(ctx, "data for checksum (%" SC_FORMAT_LEN_SIZE_T "u) %s", in_len, sc_dump_hex(in, in_len));
	for (len = (int)in_len; len > (int)sizeof(DES_cblock); len -= (int)sizeof(DES_cblock), in += sizeof(DES_cblock)) {
		int tmpLen = 0;
		if (EVP_EncryptUpdate(evpK1Ctx, out, &tmpLen, in, (int)sizeof(DES_cblock)) == 0) {
			rv = SC_ERROR_INTERNAL;
			LOG_ERROR_GOTO(ctx, rv, "DES-CBC encrypt failed");
		}
	}

	updatedIV = NULL;
	desParams[0] = OSSL_PARAM_construct_octet_ptr(OSSL_CIPHER_PARAM_UPDATED_IV, (void **)&updatedIV, 0); /* desParams reuse */
	if (EVP_CIPHER_CTX_get_params(evpK1Ctx, desParams) == 0 || desParams[0].return_size != sizeof(*icv)) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "Failed to get DES cipher params");
	}

	for (ii = 0; ii < sizeof(DES_cblock); ii++)
		last[ii] = *(in + ii) ^ (*(DES_cblock *)updatedIV)[ii];

	EVP_CIPHER_CTX_reset(evpK1Ctx); /* evpCtx reuse */

	padding = 0;
	desParams[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, &padding);
	/* for DESX, DES-EDE there is no ecb2_encrypt */
	if (EVP_CipherInit_ex2(evpK1Ctx, private_data->desEcbCipher, &key[0], NULL, 1, desParams) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-ECB cipher init failed");
	}
	if (EVP_CipherInit_ex2(evpK2Ctx, private_data->desEcbCipher, &key[sizeof(DES_cblock)], NULL, 0, desParams) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-ECB cipher init failed");
	}

	if (EVP_EncryptUpdate(evpK1Ctx, out, &len, last, sizeof(DES_cblock)) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-ECB failed");
	}
	if (EVP_DecryptUpdate(evpK2Ctx, out, &len, out, sizeof(DES_cblock)) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-ECB failed");
	}
	if (EVP_EncryptUpdate(evpK1Ctx, *icv, &len, out, sizeof(DES_cblock)) == 0) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "DES-ECB failed");
	}

#else
	DES_set_key((const_DES_cblock *)&key[0], &ks);
	DES_set_key((const_DES_cblock *)&key[sizeof(DES_cblock)], &ks2);

	sc_log(ctx, "data for checksum (%" SC_FORMAT_LEN_SIZE_T "u) %s", in_len, sc_dump_hex(in, in_len));
	for (len = (int)in_len; len > (int)sizeof(DES_cblock); len -= (int)sizeof(DES_cblock),
	    in += sizeof(DES_cblock))
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
	if ((dt_len % sizeof(DES_cblock)) != 0) {
		rv = SC_ERROR_SM_INVALID_CHECKSUM;
		LOG_ERROR_GOTO(ctx, rv, "Incorrect data size to checksum"); /* TODO: appropriate error code */
	}

	ptr = dt = calloc(1, dt_len);
	if (dt == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate checksum buffer");
	}

	sm_incr_ssc(sess->ssc, sizeof(sess->ssc));

	memcpy(ptr, sess->ssc, sizeof(sess->ssc));
	ptr += sizeof(sess->ssc);

	memcpy(ptr, data, data_len);

	rv = jacartapki_sm_cbc_cksum(card, sess->session_mac, sizeof(sess->session_mac), dt, dt_len, mac);
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

	if (memcmp(mac, macComputed, mac_len) != 0)
		LOG_ERROR_RET(ctx, SC_ERROR_SM_INVALID_CHECKSUM, "Invalid checksum");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_sm_close(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int rv = SC_SUCCESS;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
#endif
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_CIPHER_free(private_data->desEcbCipher);
	private_data->desEcbCipher = NULL;

	EVP_CIPHER_free(private_data->desCbcCipher);
	private_data->desCbcCipher = NULL;
#endif

	LOG_FUNC_RETURN(ctx, rv);
}

int
jacartapki_iso_sm_open(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iso_sm_ctx *sctx = NULL;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	int rv;

	LOG_FUNC_CALLED(ctx);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)

	private_data->desCbcCipher = EVP_CIPHER_fetch(JACARTAPKI_OSSL3CTX(ctx), "DES-CBC", NULL);
	if (private_data->desCbcCipher == NULL) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "No DES-CBC cipher");
	}

	private_data->desEcbCipher = EVP_CIPHER_fetch(JACARTAPKI_OSSL3CTX(ctx), "DES-ECB", NULL);
	if (private_data->desEcbCipher == NULL) {
		rv = SC_ERROR_INTERNAL;
		LOG_ERROR_GOTO(ctx, rv, "No DES-ECB cipher");
	}

#endif
	rv = jacartapki_sm_open(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "SM init failed");

	sctx = iso_sm_ctx_create();
	if (sctx == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate SM context.");
	}

	sctx->priv_data = private_data;
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
	if (rv < 0) {
#if defined(ENABLE_SM) && OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
		EVP_CIPHER_free(private_data->desEcbCipher);
		private_data->desEcbCipher = NULL;

		EVP_CIPHER_free(private_data->desCbcCipher);
		private_data->desCbcCipher = NULL;
#endif
		iso_sm_ctx_clear_free(sctx);
	}

	return rv;
}

static int
jacartapki_iso_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc)
{
	struct sm_dh_session *sess = &card->sm_ctx.info.session.dh;
	size_t valLen;
	int rv;

	rv = sm_encrypt_des_cbc3(card->ctx, sess->session_enc, data, datalen, enc, &valLen, 1);
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

	rv = sm_decrypt_des_cbc3(card->ctx, sess->session_enc, (u8 *)enc, enclen, data, &valLen);
	LOG_TEST_RET(card->ctx, rv, "CBC 3DES decrypt failed");
	return (int)valLen;
}

int
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
		switch (sm_apdu_correct->ins) { /* not a good practice */
		case 0xCC:
			sm_apdu_correct->ins = 0xCB;
			break;
		case 0x48:
			sm_apdu_correct->ins = 0x47;
			break;
		}
	}
	return rv;
}

int
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

int
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

#endif /* ENABLE_OPENSSL */
