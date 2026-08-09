/*
 * sm-idprime.c: proprietary EC-based Secure Messaging used by newer/FIPS
 * Gemalto IDPrime / SafeNet eToken applets.
 *
 * See sm-idprime.h and ETOKEN_FIPS_SM_NOTES.md (repository root) for the
 * full reverse-engineering writeup this is based on. In short, once session
 * keys exist, every APDU is wrapped exactly like textbook ISO 7816-4 SM
 * (DO'87'/'97'/'8E'/'99', ISO/IEC 9797-1 padding method 2) with:
 *   - confidentiality: AES-CBC, IV = AES-ECB-Encrypt(KSKEnc, SSC)
 *   - integrity: AES-CMAC(KSKMac, data), except the CBC-MAC chaining value
 *     is seeded with SSC instead of zero (SSC is incremented once per APDU
 *     direction, i.e. twice per command/response round trip)
 * This file implements exactly that on top of OpenSC's generic SM
 * encoder/decoder (sm-iso.c), which already produces byte-for-byte the same
 * DO layout and CLA handling.
 *
 * STATUS: scaffolding, not validated against real hardware yet.
 *
 * Copyright (C) 2026 David Hardening <contact@hardening-consulting.com>
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

#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_OPENSSL /* empty file without openssl */
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "libopensc/asn1.h"
#include "libopensc/errors.h"
#include "libopensc/internal.h"
#include "sm-idprime.h"
#include "sm-iso.h"

#define IDPRIME_SM_BLOCK_LEN 16

struct idprime_sm_ctx {
	u8 kenc[IDPRIME_SM_KEY_LEN_AES256];
	u8 kmac[IDPRIME_SM_KEY_LEN_AES256];
	size_t key_len; /* IDPRIME_SM_KEY_LEN_AES128 or _AES256 */
	u8 ssc[IDPRIME_SM_BLOCK_LEN];
};

static const EVP_CIPHER *
idprime_sm_ecb_cipher(size_t key_len)
{
	return key_len == IDPRIME_SM_KEY_LEN_AES256 ? EVP_aes_256_ecb() : EVP_aes_128_ecb();
}

static const EVP_CIPHER *
idprime_sm_cbc_cipher(size_t key_len)
{
	return key_len == IDPRIME_SM_KEY_LEN_AES256 ? EVP_aes_256_cbc() : EVP_aes_128_cbc();
}

/* Single-block (no padding) AES-ECB encryption, used both directly for ICV
 * derivation and as the primitive CMAC subkey generation/chaining is built
 * from. */
static int
idprime_sm_ecb_block(const u8 *key, size_t key_len,
		const u8 in[IDPRIME_SM_BLOCK_LEN], u8 out[IDPRIME_SM_BLOCK_LEN])
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int outl = 0, len2 = 0, ok = 0;

	if (!ctx)
		return 0;
	if (!EVP_EncryptInit_ex(ctx, idprime_sm_ecb_cipher(key_len), NULL, key, NULL))
		goto err;
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
		goto err;
	if (!EVP_EncryptUpdate(ctx, out, &outl, in, IDPRIME_SM_BLOCK_LEN))
		goto err;
	if (!EVP_EncryptFinal_ex(ctx, out + outl, &len2))
		goto err;
	ok = 1;
err:
	EVP_CIPHER_CTX_free(ctx);
	return ok;
}

/* Multiply-by-x in GF(2^128) with the standard AES-CMAC reduction
 * polynomial (Rb = 0x87), used for K1/K2 subkey generation (NIST SP800-38B
 * / RFC 4493). Treats the 16-byte string as a big-endian 128-bit integer. */
static void
idprime_sm_gf128_double(const u8 in[IDPRIME_SM_BLOCK_LEN], u8 out[IDPRIME_SM_BLOCK_LEN])
{
	int i;
	u8 msb = in[0] & 0x80;

	for (i = 0; i < IDPRIME_SM_BLOCK_LEN - 1; i++)
		out[i] = (u8)((in[i] << 1) | (in[i + 1] >> 7));
	out[IDPRIME_SM_BLOCK_LEN - 1] = (u8)(in[IDPRIME_SM_BLOCK_LEN - 1] << 1);
	if (msb)
		out[IDPRIME_SM_BLOCK_LEN - 1] ^= 0x87;
}

static int
idprime_sm_cmac_subkeys(const u8 *key, size_t key_len,
		u8 k1[IDPRIME_SM_BLOCK_LEN], u8 k2[IDPRIME_SM_BLOCK_LEN])
{
	u8 zero[IDPRIME_SM_BLOCK_LEN];
	u8 l[IDPRIME_SM_BLOCK_LEN];
	int ok;

	memset(zero, 0, sizeof zero);
	ok = idprime_sm_ecb_block(key, key_len, zero, l);
	if (ok) {
		idprime_sm_gf128_double(l, k1);
		idprime_sm_gf128_double(k1, k2);
	}
	sc_mem_clear(l, sizeof l);
	return ok;
}

/*
 * AES-CMAC over already block-aligned data (the caller -- sm-iso.c -- always
 * hands us data padded with ISO/IEC 9797-1 method 2 beforehand, so this
 * never needs the "short final block" / K2 case of textbook CMAC), except
 * the initial CBC-MAC chaining value is NOT zero (as in textbook CMAC) and
 * NOT the raw SSC either -- it's the SSC run through one extra AES-ECB
 * encryption under Kmac first:
 *   state0 = AES-Encrypt(Kmac, SSC)
 * then proceed with standard CMAC block chaining (K1/K2 whitening on the
 * last block) from state0. L (the CMAC subkey-generation value,
 * AES-Encrypt(Kmac, 0^128)) is NOT involved in state0 at all -- it's used
 * only for K1/K2, a fully separate computation.
 *
 * This construction (and specifically that state0 is SSC *encrypted*, not
 * SSC used directly, nor XORed with L first) was confirmed by directly
 * hooking the proprietary driver's etCryptoEcb() calls with gdb and
 * observing the literal block sequence during a real SM_AES_MAC() call --
 * see ETOKEN_FIPS_SM_NOTES.md section 9.6. Two earlier, plausible-looking
 * but wrong guesses (state0 = SSC with no extra encryption; state0 =
 * AES-Encrypt(Kmac, L XOR SSC)) were both ruled out by that same capture.
 */
static int
idprime_sm_cmac_ssc(const struct idprime_sm_ctx *sctx,
		const u8 *data, size_t datalen, u8 mac[IDPRIME_SM_BLOCK_LEN])
{
	u8 k1[IDPRIME_SM_BLOCK_LEN], k2[IDPRIME_SM_BLOCK_LEN];
	u8 state[IDPRIME_SM_BLOCK_LEN];
	u8 block[IDPRIME_SM_BLOCK_LEN];
	size_t nblocks, i, b;
	int ok = 0;

	if (datalen == 0 || datalen % IDPRIME_SM_BLOCK_LEN != 0)
		return 0;

	if (!idprime_sm_cmac_subkeys(sctx->kmac, sctx->key_len, k1, k2))
		return 0;
	(void)k2; /* only used for the short-final-block case, which never occurs here */

	if (!idprime_sm_ecb_block(sctx->kmac, sctx->key_len, sctx->ssc, state))
		goto done;

	nblocks = datalen / IDPRIME_SM_BLOCK_LEN;

	for (i = 0; i + 1 < nblocks; i++) {
		const u8 *in_block = data + i * IDPRIME_SM_BLOCK_LEN;
		for (b = 0; b < IDPRIME_SM_BLOCK_LEN; b++)
			block[b] = state[b] ^ in_block[b];
		if (!idprime_sm_ecb_block(sctx->kmac, sctx->key_len, block, state))
			goto done;
	}

	{
		const u8 *last = data + (nblocks - 1) * IDPRIME_SM_BLOCK_LEN;
		for (b = 0; b < IDPRIME_SM_BLOCK_LEN; b++)
			block[b] = state[b] ^ last[b] ^ k1[b];
	}
	ok = idprime_sm_ecb_block(sctx->kmac, sctx->key_len, block, mac);

done:
	sc_mem_clear(k1, sizeof k1);
	sc_mem_clear(k2, sizeof k2);
	sc_mem_clear(state, sizeof state);
	sc_mem_clear(block, sizeof block);
	return ok;
}

static int
idprime_sm_icv(const struct idprime_sm_ctx *sctx, u8 icv[IDPRIME_SM_BLOCK_LEN])
{
	return idprime_sm_ecb_block(sctx->kenc, sctx->key_len, sctx->ssc, icv);
}

static void
idprime_sm_incr_ssc(u8 ssc[IDPRIME_SM_BLOCK_LEN])
{
	int i;

	for (i = IDPRIME_SM_BLOCK_LEN - 1; i >= 0; i--) {
		if (++ssc[i] != 0)
			break;
	}
}

static int
idprime_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;
	EVP_CIPHER_CTX *cctx = NULL;
	u8 icv[IDPRIME_SM_BLOCK_LEN];
	u8 *out = NULL;
	int outl = 0, len2 = 0;
	int r = SC_ERROR_INTERNAL;

	if (!sctx || !data || datalen == 0 || datalen % IDPRIME_SM_BLOCK_LEN != 0)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!idprime_sm_icv(sctx, icv))
		return SC_ERROR_INTERNAL;

	out = malloc(datalen);
	if (!out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx)
		goto err;
	if (!EVP_EncryptInit_ex(cctx, idprime_sm_cbc_cipher(sctx->key_len), NULL, sctx->kenc, icv))
		goto err;
	if (!EVP_CIPHER_CTX_set_padding(cctx, 0))
		goto err;
	if (!EVP_EncryptUpdate(cctx, out, &outl, data, (int)datalen))
		goto err;
	if (!EVP_EncryptFinal_ex(cctx, out + outl, &len2))
		goto err;

	*enc = out;
	r = outl + len2;
	out = NULL;
err:
	free(out);
	if (cctx)
		EVP_CIPHER_CTX_free(cctx);
	sc_mem_clear(icv, sizeof icv);
	return r;
}

static int
idprime_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;
	EVP_CIPHER_CTX *cctx = NULL;
	u8 icv[IDPRIME_SM_BLOCK_LEN];
	u8 *out = NULL;
	int outl = 0, len2 = 0;
	int r = SC_ERROR_INTERNAL;

	if (!sctx || !enc || enclen == 0 || enclen % IDPRIME_SM_BLOCK_LEN != 0)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!idprime_sm_icv(sctx, icv))
		return SC_ERROR_INTERNAL;

	out = malloc(enclen);
	if (!out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	cctx = EVP_CIPHER_CTX_new();
	if (!cctx)
		goto err;
	if (!EVP_DecryptInit_ex(cctx, idprime_sm_cbc_cipher(sctx->key_len), NULL, sctx->kenc, icv))
		goto err;
	if (!EVP_CIPHER_CTX_set_padding(cctx, 0))
		goto err;
	if (!EVP_DecryptUpdate(cctx, out, &outl, enc, (int)enclen))
		goto err;
	if (!EVP_DecryptFinal_ex(cctx, out + outl, &len2))
		goto err;

	*data = out;
	r = outl + len2;
	out = NULL;
err:
	free(out);
	if (cctx)
		EVP_CIPHER_CTX_free(cctx);
	sc_mem_clear(icv, sizeof icv);
	return r;
}

static int
idprime_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **outdata)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;
	u8 *mac;

	if (!sctx || !data)
		return SC_ERROR_INVALID_ARGUMENTS;

	mac = malloc(IDPRIME_SM_BLOCK_LEN);
	if (!mac)
		return SC_ERROR_OUT_OF_MEMORY;

	if (!idprime_sm_cmac_ssc(sctx, data, datalen, mac)) {
		free(mac);
		return SC_ERROR_INTERNAL;
	}

	*outdata = mac;
	return IDPRIME_SM_BLOCK_LEN;
}

static int
idprime_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *mac, size_t maclen, const u8 *macdata, size_t macdatalen)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;
	u8 computed[IDPRIME_SM_BLOCK_LEN];
	int r;

	if (!sctx || !mac || maclen != IDPRIME_SM_BLOCK_LEN || !macdata)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (!idprime_sm_cmac_ssc(sctx, macdata, macdatalen, computed))
		return SC_ERROR_INTERNAL;

	r = (memcmp(mac, computed, IDPRIME_SM_BLOCK_LEN) == 0) ? SC_SUCCESS : SC_ERROR_SM_INVALID_CHECKSUM;
	sc_mem_clear(computed, sizeof computed);
	return r;
}

/* SSC is incremented once per APDU direction: once here before encrypting
 * the command (used as-is by the ICV/MAC derivation for the request), and
 * again in idprime_sm_post_transmit() before decrypting/verifying the
 * response -- i.e. twice per command/response round trip. */
static int
idprime_sm_pre_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx, sc_apdu_t *apdu)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;

	if (!sctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	idprime_sm_incr_ssc(sctx->ssc);
	return SC_SUCCESS;
}

static int
idprime_sm_post_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx, sc_apdu_t *sm_apdu)
{
	struct idprime_sm_ctx *sctx = ctx ? ctx->priv_data : NULL;

	if (!sctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	idprime_sm_incr_ssc(sctx->ssc);
	return SC_SUCCESS;
}

static void
idprime_sm_clear_free(const struct iso_sm_ctx *ctx)
{
	if (ctx && ctx->priv_data) {
		sc_mem_clear(ctx->priv_data, sizeof(struct idprime_sm_ctx));
		free(ctx->priv_data);
	}
}

/* Mirrors ComputeKSKEnc_MAC(): see sm-idprime.h for the exact construction. */
static int
idprime_sm_kdf(const u8 *z, size_t zlen, uint32_t counter, size_t key_len,
		u8 out[IDPRIME_SM_KEY_LEN_AES256])
{
	EVP_MD_CTX *ctx;
	u8 counter_be[4];
	u8 digest[SHA256_DIGEST_LENGTH];
	u8 domain_sep = 0x20;
	unsigned int digest_len = 0;
	int ok = 0;

	counter_be[0] = (u8)(counter >> 24);
	counter_be[1] = (u8)(counter >> 16);
	counter_be[2] = (u8)(counter >> 8);
	counter_be[3] = (u8)counter;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return 0;
	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
		goto err;

	if (key_len == IDPRIME_SM_KEY_LEN_AES128) {
		if (!EVP_DigestUpdate(ctx, z, zlen) || !EVP_DigestUpdate(ctx, counter_be, sizeof counter_be))
			goto err;
	} else {
		if (!EVP_DigestUpdate(ctx, counter_be, sizeof counter_be) ||
				!EVP_DigestUpdate(ctx, z, zlen) ||
				!EVP_DigestUpdate(ctx, &domain_sep, 1))
			goto err;
	}
	if (!EVP_DigestFinal_ex(ctx, digest, &digest_len) || digest_len != sizeof digest)
		goto err;

	memcpy(out, digest, key_len);
	ok = 1;
err:
	EVP_MD_CTX_free(ctx);
	sc_mem_clear(digest, sizeof digest);
	return ok;
}

int
idprime_sm_start(sc_card_t *card, const u8 *shared_secret, size_t shared_secret_len,
		size_t key_len, const u8 ssc_init[IDPRIME_SM_BLOCK_LEN])
{
	struct iso_sm_ctx *sctx = NULL;
	struct idprime_sm_ctx *priv = NULL;
	int r;

	if (!card || !shared_secret || shared_secret_len == 0 || !ssc_init ||
			(key_len != IDPRIME_SM_KEY_LEN_AES128 && key_len != IDPRIME_SM_KEY_LEN_AES256)) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	priv = calloc(1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	priv->key_len = key_len;
	memcpy(priv->ssc, ssc_init, sizeof priv->ssc);

	if (!idprime_sm_kdf(shared_secret, shared_secret_len, 1, key_len, priv->kenc) ||
			!idprime_sm_kdf(shared_secret, shared_secret_len, 2, key_len, priv->kmac)) {
		sc_mem_clear(priv, sizeof *priv);
		free(priv);
		return SC_ERROR_INTERNAL;
	}

	sctx = iso_sm_ctx_create();
	if (!sctx) {
		sc_mem_clear(priv, sizeof *priv);
		free(priv);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	sctx->priv_data = priv;
	sctx->padding_indicator = SM_ISO_PADDING;
	sctx->block_length = IDPRIME_SM_BLOCK_LEN;
	sctx->authenticate = idprime_sm_authenticate;
	sctx->verify_authentication = idprime_sm_verify_authentication;
	sctx->encrypt = idprime_sm_encrypt;
	sctx->decrypt = idprime_sm_decrypt;
	sctx->pre_transmit = idprime_sm_pre_transmit;
	sctx->post_transmit = idprime_sm_post_transmit;
	sctx->clear_free = idprime_sm_clear_free;

	r = iso_sm_start(card, sctx);
	if (r != SC_SUCCESS) {
		/* ownership of sctx (and thus priv, via clear_free) only transfers
		 * to the card on success */
		iso_sm_ctx_clear_free(sctx);
	}
	return r;
}

int
idprime_sm_reseed_ssc(sc_card_t *card, const u8 rnd_icc[8], const u8 rnd_ifd[8])
{
	struct iso_sm_ctx *sctx;
	struct idprime_sm_ctx *priv;

	if (!card || !rnd_icc || !rnd_ifd)
		return SC_ERROR_INVALID_ARGUMENTS;
	sctx = card->sm_ctx.info.cmd_data;
	if (!sctx || !sctx->priv_data)
		return SC_ERROR_INVALID_ARGUMENTS;
	priv = sctx->priv_data;

	memcpy(priv->ssc, rnd_icc, 8);
	memcpy(priv->ssc + 8, rnd_ifd, 8);
	return SC_SUCCESS;
}

int
idprime_sm_encode_general_authenticate(const u8 *point, size_t point_len,
		u8 *out, size_t out_max)
{
	int inner_len, r;
	u8 *p;

	if (!point || point_len == 0 || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	inner_len = sc_asn1_put_tag(0x85, point, point_len, NULL, 0, NULL);
	if (inner_len < 0)
		return inner_len;

	r = sc_asn1_put_tag(0x7C, NULL, (size_t)inner_len, NULL, 0, NULL);
	if (r < 0)
		return r;
	if ((size_t)r > out_max)
		return SC_ERROR_BUFFER_TOO_SMALL;

	p = out;
	r = sc_asn1_put_tag(0x7C, NULL, (size_t)inner_len, out, out_max, &p);
	if (r != SC_SUCCESS)
		return r;
	r = sc_asn1_put_tag(0x85, point, point_len, p, out_max - (size_t)(p - out), &p);
	if (r != SC_SUCCESS)
		return r;

	return (int)(p - out);
}

int
idprime_sm_decode_general_authenticate(sc_context_t *ctx, const u8 *resp, size_t resplen,
		const u8 **point, size_t *point_len)
{
	const u8 *body;
	size_t bodylen;

	if (!ctx || !resp || !point || !point_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	body = sc_asn1_find_tag(ctx, resp, resplen, 0x7C, &bodylen);
	if (body == NULL)
		return SC_ERROR_SM_NO_SESSION_KEYS;

	*point = sc_asn1_find_tag(ctx, body, bodylen, 0x85, point_len);
	if (*point == NULL || *point_len == 0)
		return SC_ERROR_SM_NO_SESSION_KEYS;

	return SC_SUCCESS;
}

#endif /* ENABLE_OPENSSL */
