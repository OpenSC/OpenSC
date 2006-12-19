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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "profile.h"

/*
 * Initialize the Application DF
 */
static int miocos_init_app(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_pin_info *pin_info,
		const u8 *pin, size_t pin_len, const u8 *puk, size_t puk_len)
{
	/* Create the application DF */
	if (sc_pkcs15init_create_file(profile, card, profile->df_info->file))
		return 1;

	return 0;
}

/*
 * Store a PIN
 */
static int
miocos_new_pin(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_pin_info *info, unsigned int idx,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	struct sc_pkcs15_pin_info tmpinfo;
	struct sc_cardctl_miocos_ac_info ac_info;
	int r;
	
	info->path = profile->df_info->file->path;
	r = sc_select_file(card, &info->path, NULL);
	if (r)
		return r;
	memset(&ac_info, 0, sizeof(ac_info));
	info->reference = idx + 1;
	ac_info.ref = idx + 1;
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
	r = sc_card_ctl(card, SC_CARDCTL_MIOCOS_CREATE_AC, &ac_info);
	if (r)
		return r;
	return 0;
}

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
			sc_error(card->ctx,
				"File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		sc_error(card->ctx, "Profile doesn't define %s template (%s)",
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
 * Store a private key
 */
static int
miocos_new_key(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_prkey *key, unsigned int idx,
		struct sc_pkcs15_prkey_info *info)
{
	sc_file_t *keyfile;
	struct sc_pkcs15_prkey_rsa *rsa;
	int r;
	
	if (key->algorithm != SC_ALGORITHM_RSA) {
		sc_error(card->ctx, "MioCOS supports only 1024-bit RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	rsa = &key->u.rsa;
	if (rsa->modulus.len != 128) {
		sc_error(card->ctx, "MioCOS supports only 1024-bit RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	r = miocos_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx,
			    &keyfile);
	if (r < 0)
		return r;

	info->modulus_length = 1024;
	info->path = keyfile->path;
	r = sc_pkcs15init_create_file(profile, card, keyfile);
	sc_file_free(keyfile);
	if (r < 0)
		return r;
	r = miocos_update_private_key(profile, card, rsa);

	return r;
}

static struct sc_pkcs15init_operations sc_pkcs15init_miocos_operations = {
	NULL,				/* erase_card */
	NULL,				/* init_card  */
	NULL,				/* create_dir */
	NULL,				/* create_domain */
	NULL,				/* select_pin_reference */
	NULL,				/* create_pin */
	NULL,				/* select_key_reference */
	NULL,				/* create_key */
	NULL,				/* store_key */
	NULL,				/* generate_key */
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	miocos_init_app,		/* old */
	miocos_new_pin,
	miocos_new_key,
	miocos_new_file,
	NULL,				/* old_generate_key */
	NULL 				/* delete_object */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_miocos_ops(void)
{
	return &sc_pkcs15init_miocos_operations;
}
