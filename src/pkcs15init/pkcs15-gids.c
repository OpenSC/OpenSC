/*
 * pkcs15-gids.c: Support for GIDS smart cards.
 *
 * Copyright (C) 2015 Vincent Le Toux (My Smart Logon) <vincent.letoux@mysmartlogon.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "../libopensc/log.h"
#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/asn1.h"
#include "pkcs15-init.h"
#include "profile.h"

#include "../libopensc/card-gids.h"

/*
 * Select a key reference.
 */
static int
gids_select_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                               sc_pkcs15_prkey_info_t *key_info)
{
	sc_card_t *card = p15card->card;
	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_SELECT_KEY_REFERENCE, key_info));
}

/*
 * Create a new key file.
 */
static int
gids_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	sc_card_t *card = p15card->card;
	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_CREATE_KEY, obj));
}


/*
 * Generate a new key.
 */
static int
gids_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                       sc_pkcs15_object_t *obj,
                       sc_pkcs15_pubkey_t *pubkey)
{
	sc_card_t *card = p15card->card;
	struct sc_cardctl_gids_genkey call = {obj, pubkey};
	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_GENERATE_KEY, &call));
}

/*
 * Store a usable private key on the card.
 */
static int
gids_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *object,
                    sc_pkcs15_prkey_t *key)
{
	sc_card_t *card = p15card->card;
	
	struct sc_cardctl_gids_importkey call = {object, key};
	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_IMPORT_KEY, &call));
}

static int 
gids_delete_object(struct sc_profile *profile, struct sc_pkcs15_card * p15card,
			struct sc_pkcs15_object *object, const struct sc_path *path) {
	sc_card_t *card = p15card->card;
	switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_DELETE_KEY, object));
		break;
	case SC_PKCS15_TYPE_CERT:
		LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_DELETE_CERT, object));
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
}

static int gids_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
	/* After storing object, pkcs15init will call this function to update DF.
	 * But GIDS has no other DF than GIDS-Application, so we do nothing. */
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

static int gids_save_certificate(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object, struct sc_path *path) {
	int r;
	sc_card_t *card = p15card->card;
	struct sc_cardctl_gids_save_cert call = {object, NULL, path};
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) object->data;

	r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_PRKEY, &cert_info->id , &(call.privkeyobject));
	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		//TODO save the certificate in the special file
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "unable to find the private key associated to the certificate");

	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_GIDS_SAVE_CERT, &call));
}

static int gids_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
                              struct sc_pkcs15_object *object,	struct sc_pkcs15_der *content,
                              struct sc_path *path) {
	sc_card_t *card = p15card->card;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
	case SC_PKCS15_TYPE_PUBKEY:
		/* For these two type, store_data just don't need to do anything.
		 * All have been done already before this function is called */
		r = SC_SUCCESS;
		break;
	case SC_PKCS15_TYPE_CERT:
		r = gids_save_certificate(p15card, object, path);
		break;
	default:
		r = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int gids_emu_update_tokeninfo(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
										sc_pkcs15_tokeninfo_t *tokeninfo)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
	/* When unbinding pkcs15init, this function will be called.
	 * But for GIDS, token info does not need to change, we do nothing. */
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

static struct sc_pkcs15init_operations sc_pkcs15init_gids_operations =
{
	NULL,                           /* erase_card */
	NULL,                           /* init_card */
	NULL,                           /* create_dir */
	NULL,                           /* create_domain */
	NULL,                           /* pin_reference*/
	NULL,                           /* create_pin */
	gids_select_key_reference, /* key_reference */
	gids_create_key,           /* create_key */
	gids_store_key,            /* store_key */
	gids_generate_key,         /* generate_key */
	NULL, NULL,                     /* encode private/public key */
	NULL,                           /* finalize */
	gids_delete_object,                           /* delete_object */
	NULL, /* pkcs15init emulation emu_update_dir */
	gids_emu_update_any_df, /* pkcs15init emulation emu_update_any_df */
	gids_emu_update_tokeninfo, /* pkcs15init emulation emu_update_tokeninfo */
	NULL, /* pkcs15init emulation emu_write_info */
	gids_emu_store_data, /* pkcs15init emulation emu_store_data */
	NULL,                           /* sanity_check*/
};

struct
sc_pkcs15init_operations *sc_pkcs15init_get_gids_ops(void)
{
	return &sc_pkcs15init_gids_operations;
}
