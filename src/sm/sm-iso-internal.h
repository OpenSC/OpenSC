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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/**
 * @file
 * @defgroup sm Interface to Secure Messaging (SM) defined in ISO 7816
 * @{
 */
#ifndef _ISO_SM_INTERNAL_H
#define _ISO_SM_INTERNAL_H

#include "libopensc/opensc.h"

#ifdef __cplusplus
extern "C" {
#endif



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
int iso_get_sm_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);

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
 * @param[in,out] sm_apdu will be freed when done.
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int iso_free_sm_apdu(struct sc_card *card, struct sc_apdu *apdu, struct sc_apdu **sm_apdu);

/**
 * @brief Cleans up allocated resources of the ISO SM driver
 *
 * \c iso_sm_close() is designed as SM card operation. However, have in mind
 * that this card operation is not called automatically for \c
 * sc_disconnect_card() .
 *
 * @param[in] card
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int iso_sm_close(struct sc_card *card);

#ifdef  __cplusplus
}
#endif
#endif
/* @} */
