/*
 * Copyright (C) 2011-2015 Frank Morgner
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
 * @defgroup eac Interface to Extended Access Control
 * @{
 */
#ifndef _SC_EAC_H
#define _SC_EAC_H

#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include "sm/sm-iso.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_OPENPACE
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>

/** @brief ASN.1 type for authenticated auxiliary data for terminal authentication */
typedef STACK_OF(CVC_DISCRETIONARY_DATA_TEMPLATE) ASN1_AUXILIARY_DATA;
DECLARE_ASN1_FUNCTIONS(ASN1_AUXILIARY_DATA)

#else
/** @brief Type of the secret */
enum s_type {
	/** @brief MRZ is the Machine Readable Zone, printed on the card, encoding
	 * the personal information of the user */
	PACE_MRZ = 1,
	/** @brief CAN is the Card access number printed on the card */
	PACE_CAN,
	/** @brief PIN is the Personal Identification Number, a secret known only
	 * to the user and not printed on the card */
	PACE_PIN,
	/** @brief PUK is the Personal Unblocking key. This type of secret is used
	 * when the card is suspended due to too many incorrect PACE runs */
	PACE_PUK,
	/** @brief This type of secret is not defined in BSI TR-03110. We use it as
	 * a generic type, so we can use PACE independent from a ID card */
	PACE_RAW,
	/** @brief Undefined type, if nothing else matches */
	PACE_SEC_UNDEF
};

/**
 * @brief Identification of the specifications to use.
 *
 * @note TR-03110 v2.01 differs from all later versions of the Technical
 * Guideline in how the authentication token is calculated. Therefore old test
 * cards are incompatible with the newer specification.
 */
enum eac_tr_version {
	/** @brief Undefined type, if nothing else matches */
	EAC_TR_VERSION = 0,
	/** @brief Perform EAC according to TR-03110 v2.01 */
	EAC_TR_VERSION_2_01,
	/** @brief Perform EAC according to TR-03110 v2.02 and later */
	EAC_TR_VERSION_2_02,
};
#endif

/** @brief File identifier of EF.CardAccess */
#define  FID_EF_CARDACCESS   0x011C
/** @brief Short file identifier of EF.CardAccess */
#define SFID_EF_CARDACCESS   0x1C
/** @brief File identifier of EF.CardSecurity */
#define  FID_EF_CARDSECURITY 0x011D
/** @brief Short file identifier of EF.CardAccess */
#define SFID_EF_CARDSECURITY 0x1D

/** @brief Maximum length of PIN */
#define EAC_MAX_PIN_LEN       6
/** @brief Minimum length of PIN */
#define EAC_MIN_PIN_LEN       6
/** @brief Length of CAN */
#define EAC_CAN_LEN       6
/** @brief Minimum length of MRZ */
#define EAC_MAX_MRZ_LEN       128
/** @brief Number of retries for PIN */
#define EAC_MAX_PIN_TRIES     3
/** @brief Usage counter of PIN in suspended state */
#define EAC_UC_PIN_SUSPENDED  1


/**
 * @brief Names the type of the PACE secret
 *
 * @param pin_id type of the PACE secret
 *
 * @return Printable string containing the name
 */
const char *eac_secret_name(enum s_type pin_id);

/** 
 * @brief Establish secure messaging using PACE
 *
 * Modifies \a card to use the ISO SM driver and initializes the data
 * structures to use the established SM channel.
 *
 * Prints certificate description and card holder authorization template if
 * given in a human readable form to stdout. If no secret is given, the user is
 * asked for it. Only \a pace_input.pin_id is mandatory, the other members of
 * \a pace_input can be set to \c 0 or \c NULL respectively.
 *
 * The buffers in \a pace_output are allocated using \c realloc() and should be
 * set to NULL, if empty. If an EF.CardAccess is already present, this file is
 * reused and not fetched from the card.
 * 
 * @param[in,out] card
 * @param[in]     pace_input
 * @param[in,out] pace_output
 * @param[in]     tr_version  Version of TR-03110 to use with PACE
 * 
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int perform_pace(sc_card_t *card,
		struct establish_pace_channel_input pace_input,
		struct establish_pace_channel_output *pace_output,
		enum eac_tr_version tr_version);

/**
 * @brief Terminal Authentication version 2
 *
 * @param[in] card
 * @param[in] certs              chain of cv certificates, the last certificate
 *                               is the terminal's certificate, array should be
 *                               terminated with \c NULL
 * @param[in] certs_lens         length of each element in \c certs, should be
 *                               terminated with \c 0
 * @param[in] privkey            The terminal's private key
 * @param[in] privkey_len        length of \a privkey
 * @param[in] auxiliary_data     auxiliary data for age/validity/community ID
 *                               verification. Should be an ASN1 object tagged
 *                               with \c 0x67
 * @param[in] auxiliary_data_len length of \a auxiliary_data
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int perform_terminal_authentication(sc_card_t *card,
		const unsigned char **certs, const size_t *certs_lens,
		const unsigned char *privkey, size_t privkey_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len);

/**
 * @brief Establish secure messaging using Chip Authentication version 2
 *
 * Switches the SM context of \c card to the new established keys.
 *
 * @param[in] card
 * @param[in,out] ef_cardsecurity
 * @param[in,out] ef_cardsecurity_len
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int perform_chip_authentication(sc_card_t *card,
		unsigned char **ef_cardsecurity, size_t *ef_cardsecurity_len);
int perform_chip_authentication_ex(sc_card_t *card, void *eacsmctx,
		unsigned char *picc_pubkey, size_t picc_pubkey_len);

/** 
 * @brief Sends an MSE:Set AT to determine the number of remaining tries
 *
 * @param[in] card
 * @param[in] pin_id         Type of secret (usually PIN or CAN). You may use <tt>enum s_type</tt> from \c <openssl/pace.h>.
 * @param[in,out] tries_left Tries left or -1 if no specific number has been returned by the card (e.g. when there is no limit in retries).
 * 
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int eac_pace_get_tries_left(sc_card_t *card,
		enum s_type pin_id, int *tries_left);

/** @brief Disable checking validity period of CV certificates */
#define EAC_FLAG_DISABLE_CHECK_TA 2
/** @brief Disable checking passive authentication during CA */
#define EAC_FLAG_DISABLE_CHECK_CA 4

/** @brief Use \c eac_default_flags to disable checks for EAC/SM */
extern char eac_default_flags;

#ifdef  __cplusplus
}
#endif
#endif
/* @} */
