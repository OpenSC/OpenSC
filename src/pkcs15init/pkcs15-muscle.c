/*
 * pkcs15-muscle.c: Support for MuscleCard Applet from musclecard.com
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <support@identityalliance.com>
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
#include <assert.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "libopensc/pkcs15.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define MUSCLE_KEY_ID_MIN	0x00
#define MUSCLE_KEY_ID_MAX	0x0F

static int muscle_erase_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	int r;
	struct sc_file *file;
	struct sc_path path;
	memset(&file, 0, sizeof(file));
	sc_format_path("3F00", &path);
	if ((r = sc_select_file(p15card->card, &path, &file)) < 0)
		return r;
	if ((r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_ERASE)) < 0)
		return r;
	if ((r = sc_delete_file(p15card->card, &path)) < 0)
		return r;
	return 0;
}


static int muscle_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	return 0;
}

static int
muscle_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	int	r;
	struct sc_file *file;
	struct sc_path path;
	memset(&file, 0, sizeof(file));
	sc_format_path("3F00", &path);
	if ((r = sc_select_file(p15card->card, &path, &file)) < 0)
		return r;
	if ((r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_CREATE)) < 0)
		return r;
	/* Create the application DF */
	if ((r = sc_pkcs15init_create_file(profile, p15card, df)) < 0)
		return r;

	if ((r = sc_select_file(p15card->card, &df->path, NULL)) < 0)
		return r;


	return 0;
}

static int
muscle_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df, sc_pkcs15_object_t *pin_obj,
	const unsigned char *pin, size_t pin_len,
	const unsigned char *puk, size_t puk_len)
{
	sc_file_t *file;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	int r;

	if ((r = sc_select_file(p15card->card, &df->path, &file)) < 0)
		return r;
	if ((r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_WRITE)) < 0)
		return r;

	auth_info->attrs.pin.flags &= ~SC_PKCS15_PIN_FLAG_LOCAL;
	return 0;
}

static int
muscle_select_pin_reference(sc_profile_t *profike, sc_pkcs15_card_t *p15card,
		sc_pkcs15_auth_info_t *auth_info)
{
	int	preferred;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		preferred = 0;
	} else {
		preferred = 1;
	}
	if (auth_info->attrs.pin.reference <= preferred) {
		auth_info->attrs.pin.reference = preferred;
		return 0;
	}

	if (auth_info->attrs.pin.reference > 2)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Caller, please select a different PIN reference */
	return SC_ERROR_INVALID_PIN_REFERENCE;
}

/*
 * Select a key reference
 */
static int
muscle_select_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_pkcs15_prkey_info_t *key_info)
{
	if (key_info->key_reference < MUSCLE_KEY_ID_MIN)
		key_info->key_reference = MUSCLE_KEY_ID_MIN;
	if (key_info->key_reference > MUSCLE_KEY_ID_MAX)
		return SC_ERROR_TOO_MANY_OBJECTS;
	return 0;
}

/*
 * Create a private key object.
 * This is a no-op.
 */
static int
muscle_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_pkcs15_object_t *obj)
{
	return 0;
}

/*
 * Store a private key object.
 */
static int
muscle_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_pkcs15_object_t *obj,
			sc_pkcs15_prkey_t *key)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_file_t* prkf;
	struct sc_pkcs15_prkey_rsa *rsa;
	sc_cardctl_muscle_key_info_t info;
	int		r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_log(ctx,  "Muscle supports RSA keys only.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	/* Verification stuff */
	/* Used for verification AND for obtaining private key acls */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &prkf);
	if (r < 0 || !prkf)
	   	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_NOT_SUPPORTED);
	r = sc_pkcs15init_authenticate(profile, p15card, prkf, SC_AC_OP_CRYPTO);
	if (r < 0) {
		sc_file_free(prkf);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(prkf);
	r = muscle_select_key_reference(profile, p15card, key_info);
	if (r < 0) {
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,r);
	}
	rsa = &key->u.rsa;

	info.keySize = rsa->modulus.len << 3;
	info.keyType = 0x03; /* CRT type */
	info.keyLocation = key_info->key_reference * 2; /* Mult by 2 to preserve even/odd keynumber structure */

	info.pLength = rsa->p.len;
	info.pValue = rsa->p.data;
	info.qLength = rsa->q.len;
	info.qValue = rsa->q.data;

	info.pqLength = rsa->iqmp.len;
	info.pqValue = rsa->iqmp.data;

	info.dp1Length = rsa->dmp1.len;
	info.dp1Value = rsa->dmp1.data;
	info.dq1Length = rsa->dmq1.len;
	info.dq1Value = rsa->dmq1.data;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_MUSCLE_IMPORT_KEY, &info);
	if (r < 0) {
		sc_log(ctx,  "Unable to import key");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE,r);
	}
	return r;
}

static int
muscle_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_pkcs15_object_t *obj,
			sc_pkcs15_pubkey_t *pubkey)
{
	sc_cardctl_muscle_gen_key_info_t args;
	sc_cardctl_muscle_key_info_t extArgs;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_card_t *card = p15card->card;
	sc_file_t* prkf;
	unsigned int	keybits;
	int		r;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_log(card->ctx,  "Muscle supports only RSA keys (for now).");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_NOT_SUPPORTED);
	}
	keybits = key_info->modulus_length & ~7UL;
	if (keybits > 2048) {
		sc_log(card->ctx,  "Unable to generate key, max size is %d",
				2048);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
	}
	/* Verification stuff */
	/* Used for verification AND for obtaining private key acls */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &prkf);
	if(r < 0 || !prkf)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_NOT_SUPPORTED);
	r = sc_pkcs15init_authenticate(profile, p15card, prkf, SC_AC_OP_CRYPTO);
	if (r < 0) {
		sc_file_free(prkf);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_NOT_SUPPORTED);
	}
	sc_file_free(prkf);

	/* END VERIFICATION STUFF */

	/* Public key acls... get_file_by_path as well? */

	memset(&args, 0, sizeof(args));
	args.keyType = 0x01; /* RSA forced */
	args.privateKeyLocation = key_info->key_reference * 2;
	args.publicKeyLocation = key_info->key_reference * 2 + 1;

	args.keySize = keybits;

	r = sc_card_ctl(card, SC_CARDCTL_MUSCLE_GENERATE_KEY, &args);
	if (r < 0) {
		sc_log(card->ctx,  "Unable to generate key");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,r);
	}

	memset(&extArgs, 0, sizeof(extArgs));
	memset(pubkey, 0, sizeof(*pubkey));

	extArgs.keyType = 0x01;
	extArgs.keyLocation = args.publicKeyLocation;
	r = sc_card_ctl(card, SC_CARDCTL_MUSCLE_EXTRACT_KEY, &extArgs);
	if (r < 0) {
		sc_log(card->ctx,  "Unable to extract the public key");
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,r);
	}

	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = extArgs.modLength;
	pubkey->u.rsa.modulus.data  = extArgs.modValue;
	pubkey->u.rsa.exponent.len  = extArgs.expLength;
	pubkey->u.rsa.exponent.data = extArgs.expValue;

	return r;
}


static struct sc_pkcs15init_operations sc_pkcs15init_muscle_operations = {
	muscle_erase_card,		/* erase card */
	muscle_init_card,		/* init_card  */
	muscle_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	muscle_select_pin_reference,	/* select pin reference */
	muscle_create_pin,		/* Create PIN */
	muscle_select_key_reference,	/* select_key_reference */
	muscle_create_key,		/* create_key */
	muscle_store_key,		/* store_key */
	muscle_generate_key,		/* generate_key */
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL,	/* pkcs15init emulation */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_muscle_ops(void)
{
	return &sc_pkcs15init_muscle_operations;
}
