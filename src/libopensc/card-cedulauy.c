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
 * future batch may differ; individual observations are marked "observed" at
 * the point where the code depends on them.
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
 *
 * Where a constant below comes from a standard rather than from AGESIC or from
 * observation, it is cited in place.  The standards involved are BSI TR-03110
 * part 3 (PACE, SecurityInfos, password references), ICAO Doc 9303 parts 5 and
 * 11 (TD1 MRZ, EF.CardAccess) and ISO/IEC 7816-4 (secure messaging, GET
 * RESPONSE).
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

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)
#define CEDULAUY_HAS_PACE 1

#include <errno.h>
#include <limits.h>
#include <stdio.h>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "common/compat_strlcat.h"
#include "libopensc/pace.h"
#include "sm/sm-eac.h"
#endif

/* MSE SET algorithm references (AGESIC "AlgoID" table): the hash is encoded
 * in the high nibble and the padding scheme in the low nibble. */
#define CEDULAUY_ALGO_HASH_NONE	  0x00 /* DigestInfo built in software */
#define CEDULAUY_ALGO_HASH_SHA256 0x40 /* card builds the DigestInfo */
#define CEDULAUY_ALGO_PAD_PKCS1	  0x02 /* PKCS#1 v1.5 */

#define CEDULAUY_ALGO_RSA_PKCS1	       (CEDULAUY_ALGO_HASH_NONE | CEDULAUY_ALGO_PAD_PKCS1)
#define CEDULAUY_ALGO_RSA_PKCS1_SHA256 (CEDULAUY_ALGO_HASH_SHA256 | CEDULAUY_ALGO_PAD_PKCS1)

/* The PACE password is the card's MRZ: the three lines of a TD1-size document,
 * 30 characters each, concatenated without separators (ICAO Doc 9303 part 5).
 * The card holds it in EF 700B under DF 7000, one of the public identity files
 * of the AGESIC layout (see cedulauy_data_files[] in pkcs15-cedulauy.c),
 * readable over the contact interface without a PIN.  The file content is a
 * BER-TLV with the 2-byte tag 7F01 and a single-byte length. */
#define CEDULAUY_MRZ_LEN  90
#define CEDULAUY_MRZ_PATH "3F007000700B"
#define CEDULAUY_MRZ_TAG1 0x7F
#define CEDULAUY_MRZ_TAG2 0x01

#define CEDULAUY_SM_MAC_LEN   8	 /* AES-CMAC, truncated as in ISO 7816-4 */
#define CEDULAUY_SM_BLOCK_LEN 16 /* AES */
/* ISO/IEC 7816-4 secure messaging turns a plain response into
 *   87 <len> 01 <cryptogram>   padding-content indicator + encrypted data
 *   99 02 <SW1> <SW2>          protected processing status
 *   8E 08 <MAC>                cryptographic checksum
 *   <SW1> <SW2>                status word of the protected response itself
 * The four groups are summed below in that order.  Length fields are counted
 * in their long form (81 xx), which is what the card uses for the cryptogram
 * at every size this driver asks for. */
#define CEDULAUY_SM_OVERHEAD ((1 + 2 + 1) + 4 + (2 + CEDULAUY_SM_MAC_LEN) + 2)
/* The cryptogram is the plaintext padded per ISO/IEC 9797-1 method 2 (one
 * mandatory 0x80 byte, then zeroes) up to the next AES block boundary, so it is
 * always at least one byte longer than the plaintext. */
#define CEDULAUY_SM_WRAPPED(plainlen) \
	(CEDULAUY_SM_OVERHEAD + \
			(((plainlen) + 1) / CEDULAUY_SM_BLOCK_LEN + 1) * CEDULAUY_SM_BLOCK_LEN)

/* Largest plain response the driver asks for over SM.  0xC0 is a whole number
 * of AES blocks and leaves margin below 0xDF, the largest plaintext whose
 * protected form still fits into a short APDU response (see the static_assert
 * below).  Keeping every other command under it means only the signature
 * response ever needs GET RESPONSE. */
#define CEDULAUY_SM_MAX_SIZE 0xC0

static_assert(CEDULAUY_SM_WRAPPED(CEDULAUY_SM_MAX_SIZE) <= SC_MAX_APDU_RESP_SIZE,
		"the protected form of a CEDULAUY_SM_MAX_SIZE response has to fit into a short APDU response");

// clang-format off
static const struct sc_atr_table cedulauy_atrs[] = {
	/* Contact interface.  TA1 and the version/batch historical bytes differ
	 * between card batches and are masked out (mask contributed by Nicolás
	 * Gutiérrez, @nicolasgutierrezdev). */
	{ "3B:7F:94:00:00:80:31:80:65:B0:85:03:00:EF:12:0F:FF:82:90:00",
	  "FF:FF:00:FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:FF:FF:FF",
	  "Uruguayan eID (cedula de identidad)", SC_CARD_TYPE_CEDULAUY, 0, NULL },
	/* Contactless (NFC) interface of the "IAS Classic v5" card.  Observed,
	 * not documented by AGESIC: the card randomises four of its historical
	 * bytes on every activation (anti-tracking) and the check byte follows
	 * from them, so an exact ATR is useless here.  Only the ISO 14443
	 * header and the ATR length are matched; cedulauy_match_card() then
	 * confirms the card by reading EF.CardAccess, which ICAO Doc 9303
	 * part 11 requires to be readable without prior authentication.
	 * card-npa.c matches by an EF.DIR probe for the same reason. */
	{ "3B:8C:80:01:00:00:00:00:00:00:00:00:00:00:00:00:00",
	  "FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:00:00:00:00",
	  "Uruguayan eID (cedula de identidad, NFC)", SC_CARD_TYPE_CEDULAUY_CONTACTLESS, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};
// clang-format on

/* IAS application AID (AGESIC, documented) */
static const unsigned char cedulauy_aid[] = {
		0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

#ifdef CEDULAUY_HAS_PACE

/* The PACEInfo this card was observed to announce in EF.CardAccess, DER
 * encoded and without the enclosing SEQUENCE so that it can be matched as a
 * substring of the file.  A SecurityInfo is an OID, a mandatory version and an
 * optional parameterId (BSI TR-03110 part 3, SecurityInfos). */
static const unsigned char cedulauy_pace_info[] = {
		/* OBJECT IDENTIFIER 0.4.0.127.0.7.2.2.4.2.4,
		 * id-PACE-ECDH-GM-AES-CBC-CMAC-256 (BSI TR-03110 part 3, PACE
		 * object identifiers) */
		0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04,
		/* INTEGER 2, PACEInfo version */
		0x02, 0x01, 0x02,
		/* INTEGER 15, parameterId: standardized domain parameters,
		 * NIST P-384 (BSI TR-03110 part 3, A.2.1.1) */
		0x02, 0x01, 0x0F};

struct cedulauy_drv_data {
	unsigned char pace;	      /* an SM channel is currently established */
	unsigned char mrz_from_cache; /* the MRZ in use came from the cache */
	unsigned char mrz[CEDULAUY_MRZ_LEN];
	size_t mrz_len;
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

	/* P2 = 0x0C asks for no response data at all */
	sc_format_apdu_ex(&apdu, 0x00, 0xA4, 0x00, 0x0C, mf, sizeof mf, NULL, 0);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return SC_SUCCESS;

	/* Which not every batch might accept. */
	sc_format_apdu_ex(&apdu, 0x00, 0xA4, 0x00, 0x00, mf, sizeof mf, resp, sizeof resp);
	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}


static int
cedulauy_read_ef_cardaccess(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_apdu apdu;
	int r;

	r = cedulauy_select_mf(card);
	if (r < 0)
		return r;

	sc_format_apdu_ex(&apdu, 0x00, 0xB0, 0x80 | SFID_EF_CARDACCESS, 0x00,
			NULL, 0, buf, buflen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0 && r != SC_ERROR_FILE_END_REACHED)
		return r;

	return (int)apdu.resplen;
}

static int
cedulauy_match_contactless(struct sc_card *card)
{
	unsigned char buf[CEDULAUY_SM_MAX_SIZE];
	int r;
	size_t i;

	r = cedulauy_read_ef_cardaccess(card, buf, sizeof buf);
	if (r < (int)sizeof cedulauy_pace_info) {
		sc_log(card->ctx, "Cannot read EF.CardAccess, not a cedula");
		return 0;
	}

	for (i = 0; i + sizeof cedulauy_pace_info <= (size_t)r; i++)
		if (0 == memcmp(buf + i, cedulauy_pace_info, sizeof cedulauy_pace_info))
			return 1;

	sc_log(card->ctx, "EF.CardAccess does not announce the expected PACE parameters");
	return 0;
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

	strlcat(buf, "cedulauy_mrz", buflen);

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

/*Open the MRZ cache for writing, owner-readable only.*/
static FILE *
cedulauy_open_mrz_cache(struct sc_card *card, const char *path)
{
#ifdef _WIN32
	/* No per-file restriction here: the cache lives under the user's
	 * profile directory, whose inherited ACL already limits access to the
	 * user (and administrators). */
	return fopen(path, "wb");
#else
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	FILE *f;

	if (fd < 0)
		return NULL;

	if (fchmod(fd, S_IRUSR | S_IWUSR) < 0)
		sc_log(card->ctx, "Cannot restrict the permissions of the MRZ cache");

	f = fdopen(fd, "wb");
	if (f == NULL)
		close(fd);

	return f;
#endif
}

static int
cedulauy_cache_mrz(struct sc_card *card, const unsigned char *mrz)
{
	char path[PATH_MAX];
	FILE *f;
	int r;

	if ((r = cedulauy_mrz_cache_path(card, path, sizeof path)) < 0)
		return r;

	f = cedulauy_open_mrz_cache(card, path);
	if (f == NULL && errno == ENOENT) {
		if ((r = sc_make_cache_dir(card->ctx)) < 0)
			return r;
		f = cedulauy_open_mrz_cache(card, path);
	}
	if (f == NULL)
		return SC_ERROR_INTERNAL;

	if (CEDULAUY_MRZ_LEN != fwrite(mrz, 1, CEDULAUY_MRZ_LEN, f)) {
		fclose(f);
		return SC_ERROR_INTERNAL;
	}
	fclose(f);

	return SC_SUCCESS;
}

static void
cedulauy_clear_cached_mrz(struct sc_card *card)
{
	char path[PATH_MAX];

	if (cedulauy_mrz_cache_path(card, path, sizeof path) < 0)
		return;
	if (remove(path) != 0)
		sc_log(card->ctx, "Cannot remove the MRZ cache");
}

static int
cedulauy_read_mrz(struct sc_card *card, unsigned char *mrz)
{
	struct sc_path path;
	unsigned char buf[3 + CEDULAUY_MRZ_LEN];
	int r;

	sc_format_path(CEDULAUY_MRZ_PATH, &path);

	r = sc_select_file(card, &path, NULL);
	if (r < 0)
		return r;

	r = sc_read_binary(card, 0, buf, sizeof buf, NULL);
	if (r < 0)
		return r;

	if (r < 3 + CEDULAUY_MRZ_LEN || buf[0] != CEDULAUY_MRZ_TAG1 ||
			buf[1] != CEDULAUY_MRZ_TAG2 || buf[2] != CEDULAUY_MRZ_LEN) {
		sc_mem_clear(buf, sizeof buf);
		return SC_ERROR_INVALID_DATA;
	}

	memcpy(mrz, buf + 3, CEDULAUY_MRZ_LEN);
	sc_mem_clear(buf, sizeof buf);

	return SC_SUCCESS;
}

static int
cedulauy_nfc_enrollment_enabled(struct sc_card *card)
{
	scconf_block **blocks;
	int enabled = 0;
	size_t i, j;

	for (i = 0; card->ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(card->ctx->conf,
				card->ctx->conf_blocks[i], "card_driver", "cedulauy");

		if (blocks == NULL)
			continue;
		for (j = 0; blocks[j] != NULL; j++)
			enabled = scconf_get_bool(blocks[j], "enable_nfc_enrollment", enabled);
		free(blocks);
	}

	return enabled;
}

static void
cedulauy_enroll_mrz(struct sc_card *card)
{
	unsigned char mrz[CEDULAUY_MRZ_LEN];

	if (!cedulauy_nfc_enrollment_enabled(card))
		return;

	if (cedulauy_get_cached_mrz(card, mrz))
		return;

	if (cedulauy_read_mrz(card, mrz) != SC_SUCCESS) {
		sc_log(card->ctx, "Cannot read the MRZ, not caching it");
		return;
	}

	if (cedulauy_cache_mrz(card, mrz) == SC_SUCCESS)
		sc_log(card->ctx, "Cached the MRZ for contactless use");

	sc_mem_clear(mrz, sizeof mrz);
}

static void
cedulauy_get_mrz(struct sc_card *card)
{
	struct cedulauy_drv_data *drv_data = DRVDATA(card);
	const char *env;

	drv_data->mrz_len = 0;
	drv_data->mrz_from_cache = 0;

	env = getenv("CEDULAUY_MRZ");
	if (env != NULL) {
		if (strlen(env) == CEDULAUY_MRZ_LEN) {
			memcpy(drv_data->mrz, env, CEDULAUY_MRZ_LEN);
			drv_data->mrz_len = CEDULAUY_MRZ_LEN;
			return;
		}
		sc_log(card->ctx, "Ignoring CEDULAUY_MRZ, it is not %d characters long",
				CEDULAUY_MRZ_LEN);
	}

	if (cedulauy_get_cached_mrz(card, drv_data->mrz)) {
		drv_data->mrz_len = CEDULAUY_MRZ_LEN;
		drv_data->mrz_from_cache = 1;
		return;
	}

	sc_log(card->ctx, "No MRZ in CEDULAUY_MRZ nor in the cache, will ask for it");
}

static int
cedulauy_perform_pace(struct sc_card *card)
{
	struct cedulauy_drv_data *drv_data = DRVDATA(card);
	struct establish_pace_channel_input pace_input = {0};
	struct establish_pace_channel_output pace_output = {0};
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (drv_data->pace) {
		sc_sm_stop(card);
		drv_data->pace = 0;
	}

	cedulauy_get_mrz(card);

	r = cedulauy_select_mf(card);
	LOG_TEST_RET(card->ctx, r, "Cannot select the MF");

	/* Password reference 1, the MRZ (BSI TR-03110 part 3, password
	 * references; the 83 01 01 of MSE:Set AT).  Observed: this card rejects
	 * reference 2, the CAN, with 6A88.  Without an MRZ at hand the password
	 * is left unset and sm-eac asks for it. */
	pace_input.pin_id = PACE_PIN_ID_MRZ;
	if (drv_data->mrz_len) {
		pace_input.pin = drv_data->mrz;
		pace_input.pin_length = drv_data->mrz_len;
	}

	/* TR-03110 v2.02 and later, as every other PACE driver in the tree
	 * requests; only v2.01 cards derive the authentication token
	 * differently. */
	r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);

	free(pace_output.ef_cardaccess);
	free(pace_output.recent_car);
	free(pace_output.previous_car);
	free(pace_output.id_icc);
	free(pace_output.id_pcd);

	if (r != SC_SUCCESS) {
		if (drv_data->mrz_from_cache) {
			cedulauy_clear_cached_mrz(card);
			drv_data->mrz_from_cache = 0;
		}
		sc_mem_clear(drv_data->mrz, sizeof drv_data->mrz);
		drv_data->mrz_len = 0;
		LOG_TEST_RET(card->ctx, r, "PACE failed");
	}

	drv_data->pace = 1;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * GET RESPONSE override.
 *
 * This is OpenSC issue #3777.  PR #3778 fixes it generically in iso-sm, and
 * this override can be dropped once that lands.  
 */
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
		r = 0; /* no more data to read */
	else if (apdu.sw1 == 0x61)
		r = apdu.sw2 == 0 ? 256 : apdu.sw2; /* more data to read */
	else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
		r = 0; /* Le not reached but file/record ended */
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

#ifdef CEDULAUY_HAS_PACE
	card->drv_data = calloc(1, sizeof(struct cedulauy_drv_data));
	if (card->drv_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	if (card->type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS) {
		card->max_send_size = CEDULAUY_SM_MAX_SIZE;
		card->max_recv_size = CEDULAUY_SM_MAX_SIZE;

		r = cedulauy_perform_pace(card);
		if (r < 0) {
			free(card->drv_data);
			card->drv_data = NULL;
			LOG_TEST_RET(card->ctx, r, "Cannot establish the PACE channel");
		}
	}
#endif

	r = cedulauy_select_app(card);
	if (r < 0) {
#ifdef CEDULAUY_HAS_PACE
		sc_sm_stop(card);
		free(card->drv_data);
		card->drv_data = NULL;
		if (card->type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS)
			r = SC_ERROR_INVALID_CARD;
#endif
		LOG_TEST_RET(card->ctx, r, "Cannot select the eID application");
	}

#ifdef CEDULAUY_HAS_PACE
	if (card->type == SC_CARD_TYPE_CEDULAUY)
		cedulauy_enroll_mrz(card);
#endif

	/* The card builds the DigestInfo on-card only for SHA-256 (algorithm
	 * reference 0x42).  Everything else is signed as raw PKCS#1 v1.5 over
	 * a DigestInfo built in software (algorithm reference 0x02). */
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
	/* A reset takes the secure-messaging channel with it. */
	if (card->type == SC_CARD_TYPE_CEDULAUY_CONTACTLESS) {
		int r = cedulauy_perform_pace(card);
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
	int under_sm = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (data == NULL || out == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

#ifdef ENABLE_SM
	under_sm = card->sm_ctx.sm_mode == SM_MODE_TRANSMIT;
#endif

	/* What is loaded here matches the algorithm set in set_security_env:
	 * for 0x42 'data' is the bare SHA-256 digest and the card builds the
	 * DigestInfo; for 0x02 'data' is a complete DigestInfo built in
	 * software, which the card pads (PKCS#1 v1.5) as-is. */
	if (datalen == 0 || datalen > sizeof(sbuf) - 2)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
				"Unsupported hash/DigestInfo length");

	/* PSO HASH: load the digest.  Over secure messaging the card answers
	 * with an encrypted body although it returns none on the contact
	 * interface; without a response buffer the SM layer would size the
	 * reply from resplen == 0 and truncate it.  The body itself is of no
	 * interest.  SC_APDU_FLAGS_NO_GET_RESP keeps a 61xx status from
	 * reaching cedulauy_get_response(), which cannot serve one. */
	sbuf[offs++] = 0x90;
	sbuf[offs++] = (unsigned char)datalen;
	memcpy(sbuf + offs, data, datalen);
	offs += datalen;
	if (under_sm) {
		sc_format_apdu_ex(&apdu, card->cla, 0x2A, 0x90, 0xA0, sbuf, offs, rbuf, sizeof rbuf);
		apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;
	} else {
		/* On the contact interface the command stays Case 3, and the
		 * card answers 61xx.  Leave GET RESPONSE handling alone: with
		 * Le == 0 sc_get_response() turns that status into 9000 without
		 * talking to the card, which is what the driver has always
		 * relied on.  Suppressing it would leave 61xx for sc_check_sw()
		 * to reject as an unknown status word. */
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
	/* Re-selecting the application resets its security status.  On the
	 * contactless interface the PACE channel is deliberately left up: it is
	 * transport, not authentication, and the card holds on to its own side
	 * of it until the RF field drops, so EF.CardAccess could not be read in
	 * the clear to negotiate a new one anyway. */
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
	cedulauy_ops.decipher = NULL; /* the signing key is sign-only */
	cedulauy_ops.get_challenge = cedulauy_get_challenge;
	cedulauy_ops.logout = cedulauy_logout;
	cedulauy_ops.card_reader_lock_obtained = cedulauy_card_reader_lock_obtained;
#ifdef CEDULAUY_HAS_PACE
	cedulauy_ops.get_response = cedulauy_get_response;
#endif

	return &cedulauy_drv;
}
