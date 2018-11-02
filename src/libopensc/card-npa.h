/*
 * Copyright (C) 2014-2015 Frank Morgner
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

#ifndef _CARD_NPA_H
#define _CARD_NPA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sm/sm-eac.h"

static const unsigned char esign_chat[] = {
	0x7F, 0x4C, 0x0E,
		0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x03,
		0x53, 0x01, 0x03,
};

static const unsigned char df_esign_aid[]  = { 0xa0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4e};

/** 
 * @brief Sends a reset retry counter APDU
 *
 * According to TR-03110 the reset retry counter APDU is used to set a new PIN
 * or to reset the retry counter of the PIN. The standard requires this
 * operation to be authorized either by an established PACE channel or by the
 * effective authorization of the terminal's certificate.
 * 
 * @param[in] card
 * @param[in] pin_id         Type of secret (usually PIN or CAN). You may use <tt>enum s_type</tt> from \c <openssl/pace.h>.
 * @param[in] ask_for_secret whether to ask the user for the secret (\c 1) or not (\c 0)
 * @param[in] new            (optional) new secret
 * @param[in] new_len        (optional) length of \a new
 * 
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int npa_reset_retry_counter(sc_card_t *card,
		enum s_type pin_id, int ask_for_secret,
		const char *new, size_t new_len);

/** 
 * @brief Send APDU to unblock the PIN
 *
 * @param[in] card
 */
#define npa_unblock_pin(card) \
	npa_reset_retry_counter(card, PACE_PIN, 0, NULL, 0)
/**
 * @brief Send APDU to set a new PIN
 *
 * @param[in] card
 * @param[in] newp           (optional) new PIN
 * @param[in] newplen        (optional) length of \a new
 */
#define npa_change_pin(card, newp, newplen) \
	npa_reset_retry_counter(card, PACE_PIN, 1, newp, newplen)

#ifdef  __cplusplus
}
#endif
#endif
