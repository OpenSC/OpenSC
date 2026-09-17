/*
 * card-cedulauy.c: Support for the Uruguayan eID card (cédula de identidad)
 *
 * Copyright (C) 2026 Carlos Andrés Planchón Prestes <carlosandresplanchonprestes@gmail.com>
 * Copyright (C) 2026 Nicolás Gutiérrez <ngutierreztassano@gmail.com>
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
 * The card is a Gemalto/Thales IAS/ECC platform.  AGESIC issues it in
 * two applet versions: "IAS Classic v4" (2015 chip, contact only) and
 * "IAS Classic v5" (2022 chip, MultiApp V5.0, a dual-interface card with
 * a contactless/NFC side).  Both are supported here over the contact
 * interface, where the subset they expose is plain ISO 7816, so the
 * driver is built on the generic iso7816 operations.  The IAS application
 * must be selected by AID before anything on the card is accessible.
 *
 * The driver does not tell the two versions apart over the contact
 * interface: the ATR is matched with the applet-version and batch bytes
 * masked out, so one table entry covers every batch.  The way to
 * distinguish them is the applet label read with GET DATA (tag 7F30,
 * object C0): the ASCII string is either "IAS Classic v4" or
 * "IAS Classic v5".  This is documented by AGESIC and does not depend on
 * the ATR.  Only the v5 card answers on the contactless interface at all,
 * so anything reached over NFC is a v5 by construction.
 *
 * Everything above, and every card convention this driver relies on over the
 * contact interface (AID, file layout, algorithm references, PIN reference),
 * comes from the public documentation and reference code published by AGESIC,
 * Uruguay's national e-government agency: "Documentación técnica de la
 * cédula de identidad con chip" and https://github.com/eIDuy/apdu-services .
 *
 * The contactless interface is not covered by any of that: AGESIC publishes no
 * APDU-level documentation for it.  Everything in the paragraph below was
 * determined by observation against a v5 card.  It describes the batches that
 * were available for testing, not behaviour guaranteed by the issuer, and a
 * future batch may differ.
 *
 * Observed contactless behaviour.  The interface is a PACE-protected ICAO/eID
 * interface.  Its EF.CardAccess announces a single PACEInfo,
 * id-PACE-ECDH-GM-AES-CBC-CMAC-256 over NIST P-384, and no ChipAuthentication
 * or TerminalAuthentication info, so plain PACE is sufficient and no EAC
 * (TA/CA) is involved.  The MRZ is the only PACE password the card was seen to
 * accept: MSE:Set AT with the CAN reference (83 01 02) is rejected with 6A88,
 * the MRZ reference (83 01 01) is accepted.  The ATR is not stable across
 * activations, see cedulauy_atrs below.  Once PACE has installed secure
 * messaging the contact command flow above runs unchanged over the SM channel.
 * Nothing that identifies the cedula is readable before PACE, so the contactless
 * interface is only matched once PACE with the MRZ, stored with cedulauy-tool or
 * given in CEDULAUY_MRZ, and selecting the eID application have succeeded.
 */

#include "libopensc/errors.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)
#define CEDULAUY_HAS_PACE 1

#include <limits.h>
#include <stdio.h>

#include "common/compat_strlcat.h"
#include "libopensc/cardctl.h"
#include "libopensc/pace.h"
#include "sm/sm-eac.h"
#endif

/* MSE SET algorithm references: hash in the high nibble, padding in the low */
#define CEDULAUY_ALGO_HASH_NONE	  0x00
#define CEDULAUY_ALGO_HASH_SHA256 0x40
#define CEDULAUY_ALGO_PAD_PKCS1	  0x02

#define CEDULAUY_ALGO_RSA_PKCS1	       (CEDULAUY_ALGO_HASH_NONE | CEDULAUY_ALGO_PAD_PKCS1)
#define CEDULAUY_ALGO_RSA_PKCS1_SHA256 (CEDULAUY_ALGO_HASH_SHA256 | CEDULAUY_ALGO_PAD_PKCS1)

#define CEDULAUY_SM_MAC_LEN   8
#define CEDULAUY_SM_BLOCK_LEN 16
/* 87 81 <len> 01 <cryptogram>, 99 02 <SW>, 8E 08 <MAC>, SW */
#define CEDULAUY_SM_OVERHEAD ((1 + 2 + 1) + 4 + (2 + CEDULAUY_SM_MAC_LEN) + 2)
#define CEDULAUY_SM_WRAPPED(plainlen) \
	(CEDULAUY_SM_OVERHEAD + \
			(((plainlen) + 1) / CEDULAUY_SM_BLOCK_LEN + 1) * CEDULAUY_SM_BLOCK_LEN)

#define CEDULAUY_SM_MAX_SIZE 0xC0

static_assert(CEDULAUY_SM_WRAPPED(CEDULAUY_SM_MAX_SIZE) <= SC_MAX_APDU_RESP_SIZE,
		"the protected form of a CEDULAUY_SM_MAX_SIZE response has to fit into a short APDU response");

// clang-format off
static const struct sc_atr_table cedulauy_atrs[] = {
	{ "3B:7F:94:00:00:80:31:80:65:B0:85:03:00:EF:12:0F:FF:82:90:00",
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
	  "Uruguayan eID (cedula de identidad)", SC_CARD_TYPE_CEDULAUY, 0, NULL },
	/* contactless: historical bytes are randomised on every activation */
	{ "3B:8C:80:01:50:00:00:00:00:00:88:3C:1F:77:81:95:00",
	  "FF:FF:FF:FF:FF:00:00:00:00:FF:FF:FF:FF:FF:FF:FF:00",
	  "Uruguayan eID (cedula de identidad, NFC)", SC_CARD_TYPE_CEDULAUY_CONTACTLESS, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};
// clang-format on

static const unsigned char cedulauy_aid[] = {
		0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

#ifdef CEDULAUY_HAS_PACE

/* id-PACE-ECDH-GM-AES-CBC-CMAC-256 over NIST P-384 */
static const unsigned char cedulauy_ef_cardaccess[] = {
		0x31, 0x14, 0x30, 0x12,
		0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04,
		0x02, 0x01, 0x02,
		0x02, 0x01, 0x0F};

struct cedulauy_drv_data {
	unsigned char mrz[CEDULAUY_MRZ_LEN];
};

#define DRVDATA(card) ((struct cedulauy_drv_data *)((card)->drv_data))
#endif

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

#ifdef CEDULAUY_HAS_PACE

static int
cedulauy_select_mf(struct sc_card *card)
{
	static const unsigned char mf[] = {0x3F, 0x00};
	unsigned char resp[SC_MAX_APDU_RESP_SIZE];
	struct sc_apdu apdu;
	int r;

	sc_format_apdu_ex(&apdu, 0x00, 0xA4, 0x00, 0x0C, mf, sizeof mf, NULL, 0);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return SC_SUCCESS;

	/* any other SW is intentionally ignored: retry asking for the FCI,
	 * and let that SELECT's SW decide the result */
	sc_format_apdu_ex(&apdu, 0x00, 0xA4, 0x00, 0x00, mf, sizeof mf, resp, sizeof resp);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int
cedulauy_mrz_cache_path(struct sc_card *card, char *buf, size_t buflen)
{
	int r = sc_get_cache_dir(card->ctx, buf, buflen);
	LOG_TEST_RET(card->ctx, r, "Cannot determine the cache directory");

#ifdef _WIN32
	strlcat(buf, "\\", buflen);
#else
	strlcat(buf, "/", buflen);
#endif

	strlcat(buf, CEDULAUY_MRZ_CACHE_FILE, buflen);

	return SC_SUCCESS;
}

static int
cedulauy_get_cached_mrz(struct sc_card *card, unsigned char *mrz)
{
	char path[PATH_MAX];
	FILE *f;
	size_t got;

	if (cedulauy_mrz_cache_path(card, path, sizeof path) < 0)
		return 0;

	f = fopen(path, "rb");
	if (f == NULL)
		return 0;

	got = fread(mrz, 1, CEDULAUY_MRZ_LEN, f);
	fclose(f);

	return got == CEDULAUY_MRZ_LEN;
}

static int
cedulauy_get_mrz(struct sc_card *card, unsigned char *mrz)
{
	const char *env = getenv("CEDULAUY_MRZ");

	if (env != NULL) {
		if (strlen(env) == CEDULAUY_MRZ_LEN) {
			memcpy(mrz, env, CEDULAUY_MRZ_LEN);
			return 1;
		}
		sc_log(card->ctx, "Ignoring CEDULAUY_MRZ, it is not %d characters long",
				CEDULAUY_MRZ_LEN);
	}

	return cedulauy_get_cached_mrz(card, mrz);
}

static int
cedulauy_perform_pace(struct sc_card *card, const unsigned char *mrz)
{
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = cedulauy_select_mf(card);
	LOG_TEST_RET(card->ctx, r, "Cannot select the MF");

	/* the card rejects the CAN, only the MRZ is accepted */
	pace_input.pin_id = PACE_PIN_ID_MRZ;
	pace_input.pin = mrz;
	pace_input.pin_length = CEDULAUY_MRZ_LEN;

	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	free(pace_output.ef_cardaccess);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	LOG_TEST_RET(card->ctx, r, "PACE failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
cedulauy_match_contactless(struct sc_card *card)
{
	unsigned char buf[sizeof cedulauy_ef_cardaccess + 1];
	unsigned char mrz[CEDULAUY_MRZ_LEN];
	struct sc_apdu apdu;
	int r;

	if (cedulauy_select_mf(card) < 0)
		return 0;

	/* EF.CardAccess is the only file readable before PACE */
	sc_format_apdu_ex(&apdu, 0x00, 0xB0, 0x80 | SFID_EF_CARDACCESS, 0x00,
			NULL, 0, buf, sizeof buf);

	if (sc_transmit_apdu(card, &apdu) < 0 ||
			apdu.resplen != sizeof cedulauy_ef_cardaccess ||
			0 != memcmp(buf, cedulauy_ef_cardaccess, sizeof cedulauy_ef_cardaccess)) {
		sc_log(card->ctx, "Unexpected EF.CardAccess, not a cedula");
		return 0;
	}

	if (!cedulauy_get_mrz(card, mrz)) {
		sc_log(card->ctx, "Possibly a cedula, run cedulauy-tool to store its MRZ");
		return 0;
	}

	card->max_send_size = CEDULAUY_SM_MAX_SIZE;
	card->max_recv_size = CEDULAUY_SM_MAX_SIZE;

	r = cedulauy_perform_pace(card, mrz);
	if (r == SC_SUCCESS)
		r = cedulauy_select_app(card);
	if (r == SC_SUCCESS) {
		card->drv_data = calloc(1, sizeof(struct cedulauy_drv_data));
		if (card->drv_data == NULL)
			r = SC_ERROR_OUT_OF_MEMORY;
		else
			memcpy(DRVDATA(card)->mrz, mrz, CEDULAUY_MRZ_LEN);
	}
	sc_mem_clear(mrz, sizeof mrz);

	if (r != SC_SUCCESS) {
		sc_sm_stop(card);
		sc_log(card->ctx, "PACE with the stored MRZ failed, not a cedula or not this one");
		return 0;
	}

	return 1;
}

/* FIXME drop once #3778 (GET RESPONSE under SM) is merged */
static int
cedulauy_get_response(struct sc_card *card, size_t *count, u8 *buf)
{
	struct sc_apdu apdu = {0};
	size_t rlen;
	int r;

	if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT)
		return iso_ops->get_response(card, count, buf);

	if (*count > sc_get_max_recv_size(card))
		rlen = sc_get_max_recv_size(card);
	else
		rlen = *count;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xC0, 0x00, 0x00);
	apdu.le = rlen;
	apdu.resplen = rlen;
	apdu.resp = buf;

	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_SM;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	*count = apdu.resplen;

	if (apdu.resplen == 0)
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		r = 0;
	else if (apdu.sw1 == 0x61)
		r = apdu.sw2 == 0 ? 256 : apdu.sw2;
	else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
		r = 0;
	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	return r;
}

#endif /* CEDULAUY_HAS_PACE */

static int
cedulauy_match_card(struct sc_card *card)
{
	int type = 0;
	int i = _sc_match_atr(card, cedulauy_atrs, &type);

	if (i < 0)
		return 0;

	if (type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS) {
#ifdef CEDULAUY_HAS_PACE
		if (!cedulauy_match_contactless(card))
			return 0;
#else
		sc_log(card->ctx, "Built without PACE support, ignoring the contactless interface");
		return 0;
#endif
	}

	card->type = type;
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

	if (card->type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS) {
		/* match_card() has already established PACE and selected the application */
		if (card->drv_data == NULL)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_CARD, "No PACE channel to the card");
	} else {
		r = cedulauy_select_app(card);
		LOG_TEST_RET(card->ctx, r, "Cannot select the eID application");
	}

	/* only SHA-256 is hashed on-card, anything else gets a software DigestInfo */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA256;
	r = _sc_card_add_rsa_alg(card, 2048, flags, 0);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int
cedulauy_finish(struct sc_card *card)
{
#ifdef CEDULAUY_HAS_PACE
	sc_sm_stop(card);
	if (card->drv_data != NULL) {
		sc_mem_clear(card->drv_data, sizeof(struct cedulauy_drv_data));
		free(card->drv_data);
		card->drv_data = NULL;
	}
#endif
	return SC_SUCCESS;
}

static int
cedulauy_card_reader_lock_obtained(struct sc_card *card, int was_reset)
{
	if (!was_reset)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

#ifdef CEDULAUY_HAS_PACE
	if (card->type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS) {
		int r;

		sc_sm_stop(card);
		r = cedulauy_perform_pace(card, DRVDATA(card)->mrz);
		LOG_TEST_RET(card->ctx, r, "Cannot re-establish the PACE channel");
	}
#endif

	LOG_FUNC_RETURN(card->ctx, cedulauy_select_app(card));
}

static const sc_file_t *
cedulauy_get_mf(void)
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
		/* the AID is always selected in init() */
		path.aid.len = 0;
	}
	if (path.type == SC_PATH_TYPE_PATH && path.len >= 2 && path.value[0] == 0x3F && path.value[1] == 0x00) {
		memmove(path.value, path.value + 2, path.len - 2);
		path.len -= 2;
	}
	if (path.type == SC_PATH_TYPE_PATH && path.len == 0) {
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
	unsigned char rbuf[256];
	size_t offs = 0;
	int under_sm = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (data == NULL || out == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

#ifdef ENABLE_SM
	under_sm = card->sm_ctx.sm_mode == SM_MODE_TRANSMIT;
#endif

	if (datalen == 0 || datalen > sizeof(sbuf) - 2)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Unsupported hash/DigestInfo length");

	/* PSO HASH */
	sbuf[offs++] = 0x90;
	sbuf[offs++] = (unsigned char)datalen;
	memcpy(sbuf + offs, data, datalen);
	offs += datalen;
	if (under_sm) {
		/* under SM the card returns an encrypted body that must not be truncated */
		sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x90, 0xA0, sbuf, offs, rbuf, sizeof rbuf);
		apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;
	} else {
		sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x90, 0xA0, sbuf, offs, NULL, 0);
	}
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
	/* GET CHALLENGE only handles a length of 8 */
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
	/* re-selecting the application resets its security status */
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
	cedulauy_ops.finish = cedulauy_finish;
	cedulauy_ops.select_file = cedulauy_select_file;
	cedulauy_ops.set_security_env = cedulauy_set_security_env;
	cedulauy_ops.compute_signature = cedulauy_compute_signature;
	cedulauy_ops.decipher = NULL;
	cedulauy_ops.get_challenge = cedulauy_get_challenge;
	cedulauy_ops.logout = cedulauy_logout;
	cedulauy_ops.card_reader_lock_obtained = cedulauy_card_reader_lock_obtained;
#ifdef CEDULAUY_HAS_PACE
	cedulauy_ops.get_response = cedulauy_get_response;
#endif

	return &cedulauy_drv;
}
