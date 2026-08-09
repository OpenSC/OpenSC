/*
 * sm-idprime.h: proprietary EC-based Secure Messaging used by newer/FIPS
 * Gemalto IDPrime / SafeNet eToken applets ("MA" in the vendor's own
 * naming).
 *
 * Reverse-engineered from libIDPrimeTokenEngine.so's idp_openSM_ECC_MAV(),
 * ComputeKSKEnc_MAC(), idp_apdu_SM_IN()/idp_apdu_SM_OUT() -- see
 * ETOKEN_FIPS_SM_NOTES.md in the repository root for the full writeup this
 * is based on.
 *
 * This only implements the *transport* on top of already-established
 * session keys, by wiring OpenSC's generic ISO 7816-4 SM encoder/decoder
 * (sm-iso.c) to an AES-CBC/AES-CMAC implementation matching the proprietary
 * driver's byte format. The EC key agreement and certificate-based mutual
 * authentication handshake that establishes those session keys is NOT
 * implemented here -- see card-idprime.c's idprime_get_ecc_full_sm() for
 * where this would need to be triggered from once that handshake exists.
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
#ifndef _SM_IDPRIME_H
#define _SM_IDPRIME_H

#include "libopensc/opensc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** AES session key length (bytes) the card expects, mirroring idp_maType 0x10 */
#define IDPRIME_SM_KEY_LEN_AES128 16
/** AES session key length (bytes) the card expects, mirroring idp_maType 0x20 */
#define IDPRIME_SM_KEY_LEN_AES256 32

/**
 * @brief Derives the two AES session keys from an ECDH shared secret and
 * starts Secure Messaging on \a card.
 *
 * Key derivation mirrors ComputeKSKEnc_MAC() in libIDPrimeTokenEngine.so:
 *   - key_len == IDPRIME_SM_KEY_LEN_AES128:
 *         K = SHA256(shared_secret || BE32(counter))[0:16]
 *   - key_len == IDPRIME_SM_KEY_LEN_AES256:
 *         K = SHA256(BE32(counter) || shared_secret || 0x20)[0:32]
 * with counter=1 for the encryption key (KSKEnc) and counter=2 for the MAC
 * key (KSKMac).
 *
 * @param card
 * @param shared_secret     raw ECDH shared secret (x-coordinate only)
 * @param shared_secret_len
 * @param key_len           IDPRIME_SM_KEY_LEN_AES128 or _AES256
 * @param ssc_init           initial 16-byte send sequence counter (the
 *                           proprietary driver seeds this as RND.ICC || RND.IFD
 *                           after the mutual-authentication handshake completes)
 *
 * @return SC_SUCCESS, or an error code if the card or arguments are invalid
 */
int idprime_sm_start(sc_card_t *card, const u8 *shared_secret, size_t shared_secret_len,
		size_t key_len, const u8 ssc_init[16]);

/**
 * @brief Reseeds the send sequence counter of an already-active idprime SM
 * session to \c rnd_icc \c || \c rnd_ifd.
 *
 * The proprietary driver uses a trivial small-integer SSC (starting at 1)
 * for the handshake messages themselves (MSE:SET AT, PSO:VERIFY CERTIFICATE,
 * GET CHALLENGE, EXTERNAL/INTERNAL AUTHENTICATE), then -- right as the
 * handshake completes and the connection moves into normal operation --
 * replaces it with the concatenation of RND.ICC (the card's GET CHALLENGE
 * response) and RND.IFD (the terminal's own nonce sent in INTERNAL
 * AUTHENTICATE). Both values are already known to card and host by then, so
 * this reseed needs no extra round trip. Confirmed via live gdb hook of
 * SM_AES_MAC's raw SSC argument against the real driver (see
 * ETOKEN_FIPS_SM_NOTES.md) -- skipping this desyncs the SSC from the very
 * first post-handshake command onward and every subsequent SM command fails.
 *
 * @param card
 * @param rnd_icc 8-byte RND.ICC from GET CHALLENGE
 * @param rnd_ifd 8-byte RND.IFD sent in INTERNAL AUTHENTICATE
 *
 * @return SC_SUCCESS, or an error code if no idprime SM session is active
 */
int idprime_sm_reseed_ssc(sc_card_t *card, const u8 rnd_icc[8], const u8 rnd_ifd[8]);

/**
 * @brief Builds the GENERAL AUTHENTICATE request body for the EC key
 * agreement step: \c 7C \c { \c 85 \c = \c point \c } (Dynamic Authentication
 * Data template carrying the caller's raw uncompressed EC point).
 *
 * @return number of bytes written to \a out, or a negative SC_ERROR_* code
 */
int idprime_sm_encode_general_authenticate(const u8 *point, size_t point_len,
		u8 *out, size_t out_max);

/**
 * @brief Extracts the card's ephemeral EC point from a GENERAL AUTHENTICATE
 * response of the same \c 7C \c { \c 85 \c = \c point \c } shape.
 *
 * @param[out] point      set to point inside \a resp (not a copy)
 * @param[out] point_len
 *
 * @return SC_SUCCESS or an error code
 */
int idprime_sm_decode_general_authenticate(sc_context_t *ctx, const u8 *resp, size_t resplen,
		const u8 **point, size_t *point_len);

#ifdef __cplusplus
}
#endif
#endif
