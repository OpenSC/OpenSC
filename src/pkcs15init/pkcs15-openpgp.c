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
	/* For OpenPGP card, the number of keys is fixed,
	 * so this function does not really do anything.
	 * It just present here to avoid pkcs15init's default routine,
	 * which tries to do impossible things. */
	LOG_FUNC_CALLED(p15card->card->ctx);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
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
	sc_card_t *card = p15card->card;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_pkcs15_prkey_rsa *rsa = &(key->u.rsa);
	sc_cardctl_openpgp_keystore_info_t key_info;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_log(card->ctx,  "only RSA is currently supported");
		return SC_ERROR_NOT_SUPPORTED;
	}

	memset(&key_info, 0, sizeof(sc_cardctl_openpgp_keystore_info_t));
	key_info.key_id = kinfo->id.value[0];
	key_info.algorithm = SC_OPENPGP_KEYALGO_RSA;
	key_info.rsa.e = rsa->exponent.data;
	key_info.rsa.e_len = rsa->exponent.len;
	key_info.rsa.p = rsa->p.data;
	key_info.rsa.p_len = rsa->p.len;
	key_info.rsa.q = rsa->q.data;
	key_info.rsa.q_len = rsa->q.len;
	key_info.rsa.n = rsa->modulus.data;
	key_info.rsa.n_len = rsa->modulus.len;
	r = sc_card_ctl(card, SC_CARDCTL_OPENPGP_STORE_KEY, &key_info);

	LOG_FUNC_RETURN(card->ctx, r);
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
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	sc_cardctl_openpgp_keygen_info_t key_info;
	sc_pkcs15_prkey_info_t *required = (sc_pkcs15_prkey_info_t *)obj->data;
	sc_pkcs15_id_t *kid = &(required->id);
	int r;

	LOG_FUNC_CALLED(ctx);
	memset(&key_info, 0, sizeof(key_info));
	sc_log(ctx, "Key ID to be generated: %s", sc_dump_hex(kid->value, kid->len));

	/* Accept KeyID = 45, which is default value set by pkcs15init */
	if (kid->len == 1 && kid->value[0] == 0x45) {
		/* Default key is authentication key. We choose this because the common use
		 * is to generate from PKCS#11 (Firefox/Thunderbird) */
		sc_log(ctx, "Authentication key is to be generated.");
		key_info.key_id = 3;
	}
	if (!key_info.key_id && (kid->len > 1 || kid->value[0] > 3)) {
		sc_log(ctx, "Key ID must be 1, 2 or 3!");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (!key_info.key_id)
		key_info.key_id = kid->value[0];

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_log(card->ctx,  "only RSA is currently supported");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Prepare buffer */
	key_info.algorithm = SC_OPENPGP_KEYALGO_RSA;
	key_info.rsa.modulus_len = required->modulus_length;
	key_info.rsa.modulus = calloc(required->modulus_length >> 3, 1);
	if (key_info.rsa.modulus == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_ENOUGH_MEMORY);

	/* The OpenPGP supports only 32-bit exponent. */
	key_info.rsa.exponent_len = 32;
	key_info.rsa.exponent = calloc(key_info.rsa.exponent_len>>3, 1); /* 1/8 */
	if (key_info.rsa.exponent == NULL) {
		free(key_info.rsa.modulus);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_ENOUGH_MEMORY);
	}

	r = sc_card_ctl(card, SC_CARDCTL_OPENPGP_GENERATE_KEY, &key_info);
	if (r < 0)
		goto out;

	pubkey->algorithm = SC_ALGORITHM_RSA;

	sc_log(ctx, "Set output modulus info");
	pubkey->u.rsa.modulus.len = key_info.rsa.modulus_len;
	pubkey->u.rsa.modulus.data = calloc(key_info.rsa.modulus_len, 1);
	if (pubkey->u.rsa.modulus.data == NULL)
		goto out;
	memcpy(pubkey->u.rsa.modulus.data, key_info.rsa.modulus, key_info.rsa.modulus_len);

	sc_log(ctx, "Set output exponent info");
	pubkey->u.rsa.exponent.len = key_info.rsa.exponent_len;
	pubkey->u.rsa.exponent.data = calloc(key_info.rsa.exponent_len>>3, 1); /* 1/8 */
	if (pubkey->u.rsa.exponent.data == NULL)
		goto out;
	memcpy(pubkey->u.rsa.exponent.data, key_info.rsa.exponent, key_info.rsa.exponent_len>>3); /* 1/8 */

out:
	if (key_info.rsa.modulus)
		free(key_info.rsa.modulus);
	if (key_info.rsa.exponent)
		free(key_info.rsa.exponent);
	LOG_FUNC_RETURN(ctx, r);
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

static int openpgp_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
                              struct sc_pkcs15_object *obj, struct sc_pkcs15_der *content,
                              struct sc_path *path)
{
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	sc_file_t *file;
	sc_pkcs15_cert_info_t *cinfo;
	sc_pkcs15_id_t *cid;
	sc_pkcs15_data_info_t *dinfo;
	u8 buf[254];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
	case SC_PKCS15_TYPE_PUBKEY:
		/* For these two type, store_data just don't need to do anything.
		 * All have been done already before this function is called */
		r = SC_SUCCESS;
		break;

	case SC_PKCS15_TYPE_CERT:
		cinfo = (sc_pkcs15_cert_info_t *) obj->data;
		cid = &(cinfo->id);

		if (cid->len != 1) {
			sc_log(card->ctx, "ID=%s is not valid.", sc_dump_hex(cid->value, cid->len));
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}

		/* OpenPGP card v.2 contains only 1 certificate */
		if (cid->value[0] != 3) {
			sc_log(card->ctx,
			       "This version does not support certificate ID = %d (only ID=3 is supported).",
			       cid->value[0]);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
		}
		/* Just update the certificate DO */
		sc_format_path("7F21", path);
		r = sc_select_file(card, path, &file);
		LOG_TEST_RET(card->ctx, r, "Cannot select cert file");
		r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
		sc_log(card->ctx,
		       "Data to write is %"SC_FORMAT_LEN_SIZE_T"u long",
		       content->len);
		if (r >= 0 && content->len)
			r = sc_put_data(p15card->card, 0x7F21, (const unsigned char *) content->value, content->len);
		break;

	case SC_PKCS15_TYPE_DATA_OBJECT:
		dinfo = (sc_pkcs15_data_info_t *) obj->data;
		/* dinfo->app_label contains filename */
		sc_log(ctx, "===== App label %s", dinfo->app_label);
		/* Currently, we only support DO 0101. The reason is that when initializing this
		 * pkcs15 emulation, PIN authentication is not applied and we can expose only this DO,
		 * which is "read always".
		 * If we support other DOs, they will not be exposed, and not helpful to user.
		 * I haven't found a way to refresh the list of exposed DOs after verifying PIN yet.
		 * http://sourceforge.net/mailarchive/message.php?msg_id=30646373
		 **/
		sc_log(ctx, "About to write to DO 0101");
		sc_format_path("0101", path);
		r = sc_select_file(card, path, &file);
		LOG_TEST_RET(card->ctx, r, "Cannot select private DO");
		r = sc_read_binary(card, 0, buf, sizeof(buf), 0);
		if (r < 0) {
			sc_log(ctx, "Cannot read DO 0101");
			break;
		}
		if (r > 0) {
			sc_log(ctx, "DO 0101 is full.");
			r = SC_ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
		if (r >= 0 && content->len) {
			r = sc_update_binary(p15card->card, 0,
			                     (const unsigned char *) content->value,
			                     content->len, 0);
		}
		break;

	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
	}

	LOG_FUNC_RETURN(card->ctx, r);
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
	NULL,   /* emu_write_info */
	openpgp_store_data, /* emu_store_data */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_openpgp_ops(void)
{
	return &sc_pkcs15init_openpgp_operations;
}
