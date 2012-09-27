/*
 * MioCOS specific operation for PKCS15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include <string.h>
#include <sys/types.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define MIOCOS_PIN_ID_MIN 1
#define MIOCOS_PIN_ID_MAX 15

/*
 * Allocate a file
 */
static int
miocos_new_file(struct sc_profile *profile, sc_card_t *card,
		unsigned int type, unsigned int num,
		sc_file_t **out)
{
	struct sc_file	*file;
	struct sc_path	*p;
	char		name[64];
	const char      *tag = NULL, *desc = NULL;

	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			tag = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			tag = "public-key";
			break;
		case SC_PKCS15_TYPE_PRKEY:
			desc = "extractable private key";
			tag = "extractable-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			desc = "certificate";
			tag = "certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			tag = "data";
			break;
		}
		if (tag)
			break;
		/* If this is a specific type such as
		 * SC_PKCS15_TYPE_CERT_FOOBAR, fall back to
		 * the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Profile doesn't define %s template (%s)",
				desc, name);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Now construct file from template */
	file->id += num;

	p = &file->path;
	*p = profile->df_info->file->path;
	p->value[p->len++] = file->id >> 8;
	p->value[p->len++] = file->id;

	*out = file;
	return 0;
}

static int
miocos_update_private_key(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa)
{
	int r;
	u8 buf[266];

	memcpy(buf, "\x30\x82\x01\x06\x80\x81\x80", 7);
	memcpy(buf + 7, rsa->modulus.data, 128);
	memcpy(buf + 7 + 128, "\x82\x81\x80", 3);
	memcpy(buf + 10 + 128, rsa->d.data, 128);
	r = sc_update_binary(card, 0, buf, sizeof(buf), 0);

	return r;
}

/*
 * Initialize the Application DF
 */
static int
miocos_create_dir(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_file *df)
{
	/* Create the application DF */
	if (sc_pkcs15init_create_file(profile, p15card, profile->df_info->file))
		return 1;

	return 0;
}

/*
 * Validate PIN reference
 */
static int
miocos_select_pin_reference(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_auth_info *auth_info)
{
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.reference < MIOCOS_PIN_ID_MIN)
		auth_info->attrs.pin.reference = MIOCOS_PIN_ID_MIN;

	return SC_SUCCESS;
}

/*
 * Create new PIN
 */
static int
miocos_create_pin(struct sc_profile *profile, sc_pkcs15_card_t *p15card, struct sc_file *df,
		struct sc_pkcs15_object *pin_obj,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	struct sc_pkcs15_auth_info tmpinfo;
	struct sc_cardctl_miocos_ac_info ac_info;
	int r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	/* Ignore SOPIN */
	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		return SC_SUCCESS;

	auth_info->path = profile->df_info->file->path;
	r = sc_select_file(p15card->card, &auth_info->path, NULL);
	if (r)
		return r;
	memset(&ac_info, 0, sizeof(ac_info));
	ac_info.ref = pin_attrs->reference;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &tmpinfo);
	ac_info.max_tries = tmpinfo.tries_left;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &tmpinfo);
	ac_info.max_unblock_tries = tmpinfo.tries_left;
	if (pin_len > 8)
		pin_len = 8;
	memcpy(ac_info.key_value, pin, pin_len);
	if (puk_len > 8)
		puk_len = 8;
	strncpy((char *) ac_info.unblock_value, (const char *) puk, puk_len);
	r = sc_card_ctl(p15card->card, SC_CARDCTL_MIOCOS_CREATE_AC, &ac_info);
        SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Miocos create AC failed");

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}


/*
 * Create private key file
 */
static int
miocos_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file;
	int r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
        	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "MioCOS supports only 1024-bit RSA keys.");

	if (key_info->modulus_length != 1024)
        	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "MioCOS supports only 1024-bit RSA keys.");

        sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "create private key ID:%s\n",  sc_pkcs15_print_id(&key_info->id));
	r = miocos_new_file(profile, p15card->card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
        SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot create key: failed to allocate new key object");

        memcpy(&file->path, &key_info->path, sizeof(file->path));
        file->id = file->path.value[file->path.len - 2] * 0x100
			+ file->path.value[file->path.len - 1];

        sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Path of private key file to create %s\n", sc_print_path(&file->path));

	r = sc_pkcs15init_create_file(profile, p15card, file);
	sc_file_free(file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, r);
}


/*
 * Store a private key
 */
static int
miocos_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *key)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_pkcs15_prkey_rsa *rsa;
	struct sc_file *file = NULL;
	int r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA
			|| key->algorithm != SC_ALGORITHM_RSA)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "MioCOS supports only 1024-bit RSA keys.");

	rsa = &key->u.rsa;
	if (rsa->modulus.len != 128)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "MioCOS supports only 1024-bit RSA keys.");

        sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "store key with ID:%s and path:%s\n", sc_pkcs15_print_id(&key_info->id),
			sc_print_path(&key_info->path));

	r = sc_select_file(p15card->card, &key_info->path, &file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot store key: select key file failed");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "No authorisation to store private key");

	r = miocos_update_private_key(profile, p15card->card, rsa);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, r);
}

static struct sc_pkcs15init_operations sc_pkcs15init_miocos_operations = {
	NULL,				/* erase_card */
	NULL,				/* init_card  */
	miocos_create_dir,
	NULL,				/* create_domain */
	miocos_select_pin_reference,
	miocos_create_pin,
	NULL,				/* select_key_reference */
	miocos_create_key,
	miocos_store_key,
	NULL,				/* generate_key */
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL,	/* pkcs15init emulation */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_miocos_ops(void)
{
	return &sc_pkcs15init_miocos_operations;
}
