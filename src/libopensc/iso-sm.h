/*
 * Copyright (C) 2012 Frank Morgner <morgner@informatik.hu-berlin.de>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef _ISO_SM_H
#define _ISO_SM_H

#include <libopensc/opensc.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Padding indicator: use ISO/IEC 9797-1 padding method 2 */
#define SM_ISO_PADDING 0x01
/** Padding indicator: use no padding */
#define SM_NO_PADDING  0x02

/** Secure messaging context */
struct iso_sm_ctx {
    /** 1 if secure messaging is activated, 0 otherwise */
    unsigned char active;

    /** data of the specific crypto implementation */
    void *priv_data;

    /** Padding-content indicator byte (ISO 7816-4 Table 30) */
    u8 padding_indicator;
    /** Pad to this block length */
    size_t block_length;

    /** Call back function for authentication of data */
    int (*authenticate)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            const u8 *data, size_t datalen, u8 **outdata);
    /** Call back function for verifying authentication data */
    int (*verify_authentication)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            const u8 *mac, size_t maclen,
            const u8 *macdata, size_t macdatalen);

    /** Call back function for encryption of data */
    int (*encrypt)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            const u8 *data, size_t datalen, u8 **enc);
    /** Call back function for decryption of data */
    int (*decrypt)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            const u8 *enc, size_t enclen, u8 **data);

    /** Call back function for actions before encoding and encryption of \a apdu */
    int (*pre_transmit)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            sc_apdu_t *apdu);
    /** Call back function for actions before decryption and decoding of \a sm_apdu */
    int (*post_transmit)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            sc_apdu_t *sm_apdu);
    /** Call back function for actions after decrypting SM protected APDU */
    int (*finish)(sc_card_t *card, const struct iso_sm_ctx *ctx,
            sc_apdu_t *apdu);

    /** Clears and frees private data */
    void (*clear_free)(const struct iso_sm_ctx *ctx);
};

/* @brief Protect an APDU with Secure Messaging
 *
 * If secure messaging (SM) is activated in \a sctx and \a apdu is not already
 * SM protected, \a apdu is processed with the following steps:
 * \li call to \a sctx->pre_transmit
 * \li encrypt \a apdu calling \a sctx->encrypt
 * \li authenticate \a apdu calling \a sctx->authenticate
 * \li copy the SM protected data to \a sm_apdu
 *
 * Data for authentication or encryption is always padded before the callback
 * functions are called
 *
 * @param[in]     card
 * @param[in]     apdu
 * @param[in,out] sm_apdu
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int iso_get_sm_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu *sm_apdu);

/* @brief Remove Secure Messaging from an APDU
 *
 * If secure messaging (SM) is activated in \a sctx and \a apdu is not already
 * SM protected, \a apdu is processed with the following steps:
 * \li verify SM protected \a apdu calling \a sctx->verify_authentication
 * \li decrypt SM protected \a apdu calling \a sctx->decrypt
 * \li copy decrypted/authenticated data and status bytes to \a apdu
 *
 * Callback functions must not remove padding.
 *
 * @param[in]     card
 * @param[in,out] apdu
 * @param[in]     sm_apdu
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int iso_free_sm_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu *sm_apdu);

/** 
 * @brief Clears and frees the SM context including private data
 *
 * Calls \a sctx->clear_free
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

#ifdef  __cplusplus
}
#endif
#endif
/* @} */
