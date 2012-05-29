/*
 * OpenPGP specific operation for PKCS15 initialization
 *
 * Copyright (c) 2012  Nguyen Hong Quan <ng.hong.quan@gmail.com>.
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/cards.h"
#include "libopensc/asn1.h"
#include "pkcs15-init.h"
#include "profile.h"


/**
 * Erase card: erase all EFs/DFs created by OpenSC
 * @param  profile  The sc_profile_t object with the configurable profile
 *                  information
 * @param  p15card  The card from which the opensc application should be
 *                  erased.
 * @return SC_SUCCESS on success and an error code otherwise
 **/
static int openpgp_erase(struct sc_profile *profile, sc_pkcs15_card_t *p15card)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Create application DF
 * @param  profile  sc_profile_t object with the configurable profile
 *                  information
 * @param  p15card  sc_card_t object to be used
 * @param  df       sc_file_t with the application DF to create
 * @return SC_SUCCESS on success and an error value otherwise
 **/
static int openpgp_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Select PIN reference: do nothing special, the real PIN reference if
 * determined when the PIN is created. This is just helper function to
 * determine the next best file id of the PIN file.
 **/
static int openpgp_select_pin_reference(sc_profile_t *profile,
		sc_pkcs15_card_t *p15card, sc_pkcs15_auth_info_t *auth_info)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Create PIN and, if specified, PUK files
 * @param  profile  profile information for this card
 * @param  card     sc_card_t object to use
 * @param  pin_obj  sc_pkcs15_object_t for the PIN
 * @param  pin      PIN value
 * @param  len_len  PIN length
 * @param  puk      PUK value (optional)
 * @param  puk_len  PUK length (optional)
 * @return SC_SUCCESS on success and an error code otherwise
 **/
static int openpgp_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df, sc_pkcs15_object_t *pin_obj,
	const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Creates empty key file
 **/
static int openpgp_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Stores an external (RSA) on the card.
 * @param  profile  profile information for this card
 * @param  card     sc_card_t object to use
 * @param  obj      sc_pkcs15_object_t object with pkcs15 information
 * @param  key      the private key
 * @return SC_SUCCESS on success and an error code otherwise
 **/
static int openpgp_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/**
 * Generates a new (RSA) key pair using an existing key file.
 * @param  profile  IN profile information for this card
 * @param  card     IN sc_card_t object to use
 * @param  obj      IN sc_pkcs15_object_t object with pkcs15 information
 * @param  pukkey   OUT the newly created public key
 * @return SC_SUCCESS on success and an error code otherwise
 **/
static int openpgp_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int openpgp_emu_update_any_df(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
									 unsigned operation, sc_pkcs15_object_t *obj)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
	/* After storing object, pkcs15init will call this function to update DF.
	 * But OpenPGP has no other DF than OpenPGP-Application, so we do nothing. */
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

static int openpgp_emu_update_tokeninfo(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
										sc_pkcs15_tokeninfo_t *tokeninfo)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
	/* When unbinding pkcs15init, this function will be called.
	 * But for OpenPGP, token info does not need to change, we do nothing. */
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

static struct sc_pkcs15init_operations sc_pkcs15init_openpgp_operations = {
	openpgp_erase,
	NULL,				/* init_card */
	openpgp_create_dir,
	NULL,				/* create_domain */
	openpgp_select_pin_reference,
	openpgp_create_pin,
	NULL,				/* select key reference */
	openpgp_create_key,
	openpgp_store_key,
	openpgp_generate_key,
	NULL, NULL, 			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL,
	openpgp_emu_update_any_df,
	openpgp_emu_update_tokeninfo,
	NULL, NULL, 	/* pkcs15init emulation */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_openpgp_ops(void)
{
	return &sc_pkcs15init_openpgp_operations;
}