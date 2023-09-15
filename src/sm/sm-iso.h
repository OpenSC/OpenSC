/*
 * Copyright (C) 2012-2015 Frank Morgner
 *
 * This file is part of OpenSC.
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
/**
 * @file
 * @defgroup sm Interface to Secure Messaging (SM) defined in ISO 7816
 * @{
 */
#ifndef _ISO_SM_H
#define _ISO_SM_H

#include "libopensc/opensc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief maximum length of response when targeting a SM RAPDU
 *
 * Using SM with authenticated data+le and encrypted data this is the biggest
 * amount of the unencrypted response data we can receive. We assume AES block
 * length for padding and MAC. */
#define MAX_SM_APDU_RESP_SIZE 223

/** @brief maximum length of data when targeting a SM APDU
 *
 * Using SM with authenticated data+header and encrypted data this is the
 * biggest amount of the unencrypted data we can send. We assume AES block
 * length for padding and MAC. */
#define MAX_SM_APDU_DATA_SIZE 239

/** @brief Padding indicator: use ISO/IEC 9797-1 padding method 2 */
#define SM_ISO_PADDING 0x01
/** @brief Padding indicator: use no padding */
#define SM_NO_PADDING  0x02
/** @brief Padding indicator: use NIST sp800-73-4 */ 
#define SM_NIST_PADDING 0x04


/** @brief Secure messaging context
 *
 * This module provides *encoding and decoding* of secure messaging APDUs. The
 * actual cryptographic operations need to be specified via the call backs of
 * `struct iso_sm_ctx`.
 *
 *
 * Initialization of ISO 7816 Secure Messaging:
 *   1. Create the secure messaging context with iso_sm_ctx_create()
 *   2. Customize `struct iso_sm_ctx` with the needed cryptographic callbacks
 *      and data
 *   3. Run `iso_sm_start()`, which enables `SM_MODE_TRANSMIT`, so that all
 *      subsequent calls to sc_transmit_apdu() will be encrypted transparently.
 *      Memory ownership of `struct iso_sm_ctx` is transferred to the internal
 *      secure messaging context.
 *
 *
 * Deinitialization of ISO 7816 Secure Messaging:
 *   1. Run `sc_sm_stop()`
 *   2. `clear_free()` hook is called
 *   3. `struct iso_sm_ctx` is `free()`d
 *
 *
 * Sending and receiving ISO 7816 Secure Messaging data:
 *   1. Call `sc_transmit_apdu()` with an unencrypted APDU
 *   2. `pre_transmit()` hook is called
 *   3. Command APDU is encrypted (see workflow below)
 *   4. Encrypted APDU is sent to the card
 *   5. `post_transmit()` hook is called
 *   6. Encrypted response is decrypted (see workflow below)
 *   7. `finish()` hook is called
 *
 *
 * Workflow for encrypting a command APDU:
 *
 *                              ┌───────────────┬────┬──────┬────┐
 *                              │     Header    │    │      │    │
 *  ▶ Unencrypted command APDU  │ CLA,INS,P1,P2 │ Lc │ Data │ Le │
 *                              └───────────────┴────┴──────┴────┘
 *                             ╱               ╱     │       ╲
 * 1. Add padding to `block_size` according to `padding_indicator`
 *                           ╱               ╱       │         ╲
 *                          ╱               ╱        ▼          ◢
 *                         ╱               ╱         ┌───────────┐
 *                        ╱               ╱          │Padded Data│
 *                       ╱               ╱           └───────────┘
 *                      ╱               ╱            │            ╲
 * 2. Data encryption  ╱               ╱             │ `encrypt()` ╲
 *                    ╱               ╱              ▼              ◢
 *                   ╱ ┌────┬──────┬─────────────────┬───────────────┬────┬──────┬──┐
 *                  ╱  │0x87│Length│Padding Indicator│Encrypted Data │0x97│Length│Le│
 *                 ╱   └────┴──────┴─────────────────┴───────────────┴────┴──────┴──┘
 *                ╱    │         ╱                                                   ╲
 *               ╱     │        ╱                                                     ╲
 *              ╱      │       ╱                                                       ╲
 * 3. Add padding to header and formatted encrypted data according to `padding_indicator`
 *            ╱        │     ╱                                                           ╲
 *           ╱         │    ╱                                                             ╲
 *          ╱          │   ╱                                                               ╲
 *         ╱           │  ╱                                                                 ╲
 *        ◣            ▼ ◣                                                                   ◢
 *       ┌─────────────┬────┬──────┬─────────────────┬───────────────┬────┬──────┬──┬─────────┐
 *       │Padded Header│0x87│Length│Padding Indicator│Encrypted Data │0x97│Length│Le│ Padding │
 *       └─────────────┴────┴──────┴─────────────────┴───────────────┴────┴──────┴──┴─────────┘
 *        ╲                                                                                   │
 *          ────────────────────────────────────────────────────────────────                  │
 * 4. MAC calculation                                                        `authenticate()` │
 *                                                                                      ╲     │
 *                                                                                       ◢    ▼
 * ┌────────┬────┬────┬──────┬─────────────────┬───────────────┬────┬──────┬──┬────┬──────┬───┬──────┐
 * │ Header │ Lc │0x87│Length│Padding Indicator│Encrypted Data │0x97│Length│Le│0x8E│Length│MAC│ 0x00 │
 * └────────┴────┴────┴──────┴─────────────────┴───────────────┴────┴──────┴──┴────┴──────┴───┴──────┘
 *  ▶ Encrypted command APDU
 *
 *
 * Workflow for decrypting a response APDU
 *
 *  ▶ Encrypted response APDU
 *          ┌────┬──────┬─────────────────┬──────────────┬────┬────┬───────┬────┬──────┬───┬─────────┐
 *          │0x87│Length│Padding Indicator│Encrypted Data│0x99│0x02│SW1/SW2│0x8E│Length│MAC│ SW1/SW2 │
 *          └────┴──────┴─────────────────┴──────────────┴────┴────┴───────┴────┴──────┴───┴─────────┘
 *           ╲                            │              │                ╱           ╱     ╲
 *            ◢                           │              │               ◣           ◣       ◢
 *             ┌────────────────────────────────────────────────────────┐           ┌─────────┐
 *             │                     `mac_data`                         │           │  `mac`  │
 *             └────────────────────────────────────────────────────────┘           └─────────┘
 *                                        │              │               ╲         ╱
 *                                        │              │                ◢       ◣
 * 1. MAC verification                    │              │          `verify_authenticate()`
 *                                        ▼              ▼
 *                                        ┌──────────────┐
 *                                        │Encrypted Data│
 *                                        └──────────────┘
 * 2. Decrypt data                        │ `decrypt()` ╱
 *                                        ▼            ◣
 *                                        ┌───────────┐
 *                                        │Padded Data│
 *                                        └───────────┘
 *                                        │          ╱
 * 3. Remove padding from data according to `padding_indicator`
 *                                        │        ╱
 *                                        ▼       ◣
 *                                        ┌──────┬─────────┐
 *  ▶ Unencrypted response APDU           │ Data │ SW1/SW2 │
 *                                        └──────┴─────────┘
 **/
struct iso_sm_ctx {
	/** @brief data of the specific crypto implementation */
	void *priv_data;

	/** @brief Padding-content indicator byte (ISO 7816-4 Table 30) */
	u8 padding_indicator;
	/** @brief if 1 use tag 87 */
	u8 padding_tag;
	/** @brief if 1 do not pad data to to be mac'ed */
	u8  do_not_pad_macdata;
	/** @brief do_not_split_apdu into multiple apdus */
	u8  use_sm_chaining;
	/** @brief Pad to this block length */
	size_t block_length;

	/** @brief Call back function for authentication of data, i.e. MAC creation */
	int (*authenticate)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			const u8 *data, size_t datalen, u8 **outdata);
	/** @brief Call back function for verifying authentication data, i.e. MAC verification */
	int (*verify_authentication)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			const u8 *mac, size_t maclen,
			const u8 *macdata, size_t macdatalen);

	/** @brief Call back function for encryption of data */
	int (*encrypt)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			const u8 *data, size_t datalen, u8 **enc);
	/** @brief Call back function for decryption of data */
	int (*decrypt)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			const u8 *enc, size_t enclen, u8 **data);

	/** @brief Call back function for actions before encoding and encryption of \a apdu,
	 * e.g. for incrementing a send sequence counter */
	int (*pre_transmit)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			sc_apdu_t *apdu);
	/** @brief Call back function for actions before decryption and decoding of \a sm_apdu,
	 * e.g. for incrementing a send sequence counter */
	int (*post_transmit)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			sc_apdu_t *sm_apdu);
	/** @brief Call back function for actions after decrypting SM protected APDU */
	int (*finish)(sc_card_t *card, const struct iso_sm_ctx *ctx,
			sc_apdu_t *apdu);

	/** @brief Clears and frees private data */
	void (*clear_free)(const struct iso_sm_ctx *ctx);
};

/** 
 * @brief Clears and frees the SM context including private data
 *
 * Calls \a sctx->clear_free() if available
 * 
 * @param[in]     sctx (optional)
 */
void iso_sm_ctx_clear_free(struct iso_sm_ctx *sctx);

/**
 * @brief Creates a SM context
 *
 * @return SM context or NULL if an error occurred
 */
struct iso_sm_ctx *iso_sm_ctx_create(void);

/**
 * @brief Initializes a card for usage of the ISO SM driver
 *
 * If a SM module has been assigned previously to the card, it will be cleaned
 * up.
 *
 * @param[in] card
 * @param[in] sctx will NOT be freed automatically. \a sctx should be present
 * for the time of the SM session.
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int iso_sm_start(struct sc_card *card, struct iso_sm_ctx *sctx);

int iso_sm_close(struct sc_card *card);

#ifdef  __cplusplus
}
#endif
#endif
/* @} */
