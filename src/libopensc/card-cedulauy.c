/*
 * card-cedulauy.c: Support for the Uruguayan eID card (cédula de identidad)
 *
 * Copyright (C) 2026 Carlos Andrés Planchón Prestes <carlosandresplanchonprestes@gmail.com>
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
 * The card is a Gemalto/Thales "Classic V4" IAS/ECC platform card, but the
 * subset it exposes over the contact interface is plain ISO 7816, so the
 * driver is built on the generic iso7816 operations.  The IAS application
 * must be selected by AID before anything on the card is accessible.
 *
 * The card conventions come from the public documentation and reference code
 * published by AGESIC, Uruguay's national e-government agency ("Documentación
 * técnica de la cédula de identidad con chip" and
 * https://github.com/eIDuy/apdu-services).
 *
 * The PKCS#15 view of the card is provided by the synthetic emulator in
 * pkcs15-cedulauy.c.
 */

#include "libopensc/errors.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* MSE SET algorithm references (AGESIC "AlgoID" table): the hash is encoded
 * in the high nibble and the padding scheme in the low nibble. */
#define CEDULAUY_ALGO_HASH_NONE	  0x00 /* DigestInfo built in software */
#define CEDULAUY_ALGO_HASH_SHA256 0x40 /* card builds the DigestInfo */
#define CEDULAUY_ALGO_PAD_PKCS1	  0x02 /* PKCS#1 v1.5 */

#define CEDULAUY_ALGO_RSA_PKCS1	       (CEDULAUY_ALGO_HASH_NONE | CEDULAUY_ALGO_PAD_PKCS1)
#define CEDULAUY_ALGO_RSA_PKCS1_SHA256 (CEDULAUY_ALGO_HASH_SHA256 | CEDULAUY_ALGO_PAD_PKCS1)

// clang-format off
static const struct sc_atr_table cedulauy_atrs[] = {
	/* TA1 and the version/batch historical bytes differ between card
	 * batches and are masked out (mask contributed by Nicolás Gutiérrez,
	 * @nicolasgutierrezdev). */
	{ "3B:7F:94:00:00:80:31:80:65:B0:85:03:00:EF:12:0F:FF:82:90:00",
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
	  "Uruguayan eID (cedula de identidad)", SC_CARD_TYPE_CEDULAUY, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};
// clang-format on

/* IAS application AID (AGESIC, documented) */
static const unsigned char cedulauy_aid[] = {
		0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations cedulauy_ops;

static struct sc_card_driver cedulauy_drv = {
		"Uruguayan eID (cedula de identidad)",
		"cedulauy",
		&cedulauy_ops,
		NULL, 0, NULL};

#define SC_TRANSMIT_TEST_RET(card, apdu, text) \
	do { \
		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed"); \
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), text); \
	} while (0)

static int
cedulauy_select_app(struct sc_card *card)
{
	struct sc_apdu apdu;
	unsigned char resp[SC_MAX_APDU_RESP_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu_ex(&apdu, card->cla, 0xA4, 0x04, 0x00,
			cedulauy_aid, sizeof cedulauy_aid, resp, sizeof resp);
	SC_TRANSMIT_TEST_RET(card, apdu, "Cannot select the eID application");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
cedulauy_match_card(struct sc_card *card)
{
	int i = _sc_match_atr(card, cedulauy_atrs, &card->type);

	if (i < 0)
		return 0;
	card->name = cedulauy_atrs[i].name;
	return 1;
}

static int
cedulauy_init(struct sc_card *card)
{
	unsigned long flags;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	card->caps = SC_CARD_CAP_RNG;

	r = cedulauy_select_app(card);
	LOG_TEST_RET(card->ctx, r, "Cannot select the eID application");

	/* The card builds the DigestInfo on-card only for SHA-256 (algorithm
	 * reference 0x42).  Everything else is signed as raw PKCS#1 v1.5 over
	 * a DigestInfo built in software (algorithm reference 0x02). */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA256;
	r = _sc_card_add_rsa_alg(card, 2048, flags, 0);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
cedulauy_card_reader_lock_obtained(struct sc_card *card, int was_reset)
{
	if (was_reset)
		LOG_FUNC_RETURN(card->ctx, cedulauy_select_app(card));
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static const sc_file_t *
cedulauy_get_mf()
{
	static sc_file_t *mf = NULL;
	if (!mf) {
		mf = sc_file_new();
		if (mf) {
			mf->path = *sc_get_mf_path();
			mf->id = 0x3F00;
			mf->type = SC_FILE_TYPE_DF;
			mf->magic = SC_FILE_MAGIC;
		}
	}
	return mf;
}

static int
cedulauy_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file_out)
{
	struct sc_path path = *in_path;

	LOG_FUNC_CALLED(card->ctx);

	if (path.aid.len == sizeof cedulauy_aid && 0 == memcmp(path.aid.value, cedulauy_aid, sizeof cedulauy_aid)) {
		/* swallow cedula AID, it is always selected via init() */
		path.aid.len = 0;
	}
	if (path.type == SC_PATH_TYPE_PATH && path.len >= 2 && path.value[0] == 0x3F && path.value[1] == 0x00) {
		/* swallow MF, everything resides within the Application DF */
		memmove(path.value, path.value + 2, path.len - 2);
		path.len -= 2;
	}
	if (path.type == SC_PATH_TYPE_PATH && path.len == 0) {
		/* Selection of MF was requested */
		sc_file_dup(file_out, cedulauy_get_mf());
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(card->ctx, iso_ops->select_file(card, &path, file_out));
}

static int
cedulauy_set_security_env(struct sc_card *card, const struct sc_security_env *env,
		int se_num)
{
	struct sc_apdu apdu;
	/* MSE SET, Digital Signature Template: key reference and algorithm */
	unsigned char mse_data[] = {0x84, 0x01, 0xFF, 0x80, 0x01, CEDULAUY_ALGO_RSA_PKCS1};

	LOG_FUNC_CALLED(card->ctx);

	if (env == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	if ((env->flags & SC_SEC_ENV_ALG_PRESENT) && env->algorithm != SC_ALGORITHM_RSA)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	if (env->key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	mse_data[2] = env->key_ref[0];
	if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)
		mse_data[5] = CEDULAUY_ALGO_RSA_PKCS1_SHA256;

	sc_format_apdu_ex(&apdu, card->cla, 0x22, 0x41, 0xB6,
			mse_data, sizeof mse_data, NULL, 0);
	SC_TRANSMIT_TEST_RET(card, apdu, "MSE SET DST failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
cedulauy_compute_signature(struct sc_card *card, const u8 *data, size_t datalen,
		u8 *out, size_t outlen)
{
	struct sc_apdu apdu;
	unsigned char sbuf[64];
	unsigned char rbuf[256]; /* RSA 2048 */
	size_t offs = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (data == NULL || out == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* What is loaded here matches the algorithm set in set_security_env:
	 * for 0x42 'data' is the bare SHA-256 digest and the card builds the
	 * DigestInfo; for 0x02 'data' is a complete DigestInfo built in
	 * software, which the card pads (PKCS#1 v1.5) as-is. */
	if (datalen == 0 || datalen > sizeof(sbuf) - 2)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Unsupported hash/DigestInfo length");

	/* PSO HASH: load the digest */
	sbuf[offs++] = 0x90;
	sbuf[offs++] = (unsigned char)datalen;
	memcpy(sbuf + offs, data, datalen);
	offs += datalen;
	sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x90, 0xA0, sbuf, offs, NULL, 0);
	SC_TRANSMIT_TEST_RET(card, apdu, "PSO HASH failed");

	/* PSO COMPUTE DIGITAL SIGNATURE */
	sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x9E, 0x9A, NULL, 0, rbuf, sizeof rbuf);
	SC_TRANSMIT_TEST_RET(card, apdu, "PSO COMPUTE DIGITAL SIGNATURE failed");

	if (apdu.resplen > outlen)
		LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL,
				"Signature buffer too small");
	memcpy(out, apdu.resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

static int
cedulauy_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	/* As on other IAS/ECC cards, GET CHALLENGE only handles a length of 8 */
	unsigned char rbuf[8];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->get_challenge(card, rbuf, sizeof rbuf);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE failed");

	if (len < (size_t)r)
		r = (int)len;
	memcpy(rnd, rbuf, (size_t)r);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
cedulauy_logout(struct sc_card *card)
{
	/* Re-selecting the application resets its security status. */
	LOG_FUNC_RETURN(card->ctx, cedulauy_select_app(card));
}

struct sc_card_driver *
sc_get_cedulauy_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	cedulauy_ops = *iso_ops;
	cedulauy_ops.match_card = cedulauy_match_card;
	cedulauy_ops.init = cedulauy_init;
	cedulauy_ops.select_file = cedulauy_select_file;
	cedulauy_ops.set_security_env = cedulauy_set_security_env;
	cedulauy_ops.compute_signature = cedulauy_compute_signature;
	cedulauy_ops.decipher = NULL; /* the signing key is sign-only */
	cedulauy_ops.get_challenge = cedulauy_get_challenge;
	cedulauy_ops.logout = cedulauy_logout;
	cedulauy_ops.card_reader_lock_obtained = cedulauy_card_reader_lock_obtained;

	return &cedulauy_drv;
}
