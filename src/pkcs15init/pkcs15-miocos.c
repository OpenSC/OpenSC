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
#include <sys/types.h>
#include <string.h>
#include <openssl/bn.h>
#include "opensc.h"
#include "cardctl.h"
#include "pkcs15-init.h"
#include "profile.h"

/*
 * Initialize the Application DF
 */
static int miocos_init_app(struct sc_profile *profile, struct sc_card *card,
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
miocos_new_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *info, unsigned int index,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	char template[18];
	sc_file_t *pinfile;
	struct sc_pkcs15_pin_info tmpinfo;
	struct sc_cardctl_miocos_ac_info ac_info;
	int r;
	
	sprintf(template, "pinfile-chv%d", index + 1);
	/* Profile must define a "pinfile" for each PIN */
	if (sc_profile_get_file(profile, template, &pinfile) < 0) {
		profile->cbs->error("Profile doesn't define \"%s\"", template);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	info->path = pinfile->path;
	if (info->path.len > 2)
		info->path.len -= 2;
	r = sc_pkcs15init_create_file(profile, card, pinfile);
	sc_file_free(pinfile);
	if (r)
		return r;
	memset(&ac_info, 0, sizeof(ac_info));
	info->reference = index + 1;
	ac_info.ref = index + 1;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &tmpinfo);
	ac_info.max_tries = tmpinfo.tries_left;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &tmpinfo);
	ac_info.max_unblock_tries = tmpinfo.tries_left;
	if (pin_len > 8)
		pin_len = 8;
	memcpy(ac_info.key_value, pin, pin_len);
	if (puk_len > 8)
		puk_len = 8;
	strncpy(ac_info.unblock_value, puk, puk_len);
	r = sc_card_ctl(card, SC_CARDCTL_MIOCOS_CREATE_AC, &ac_info);
	if (r)
		return r;
	return 0;
}

/*
 * Allocate a file
 */
static int
miocos_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num,
		struct sc_file **out)
{
	struct sc_file	*file;
	struct sc_path	*p;
	char		name[64], *tag, *desc;

	desc = tag = NULL;
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
			profile->cbs->error("File type not supported by card driver");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		profile->cbs->error("Profile doesn't define %s template (%s)\n",
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

static int bn2bin(const BIGNUM *num, u8 *buf)
{
	int r;

	r = BN_bn2bin(num, buf);
        if (r <= 0)
                return r;
        return 0;
}

static int
miocos_update_private_key(struct sc_profile *profile, struct sc_card *card,
		RSA *rsa)
{
	int r;
	u8 modulus[128];
	u8 priv_exp[128];
	u8 buf[266];
	
	if (bn2bin(rsa->d, priv_exp) != 0) {
		profile->cbs->error("Unable to convert private exponent.");
		return -1;
	}
	if (bn2bin(rsa->n, modulus) != 0) {
		profile->cbs->error("Unable to convert modulus.");
		return -1;
	}
	memcpy(buf, "\x30\x82\x01\x06\x80\x81\x80", 7);
	memcpy(buf + 7, modulus, 128);
	memcpy(buf + 7 + 128, "\x82\x81\x80", 3);
	memcpy(buf + 10 + 128, priv_exp, 128);
	r = sc_update_binary(card, 0, buf, sizeof(buf), 0);

	return r;
}

/*
 * Store a private key
 */
static int
miocos_new_key(struct sc_profile *profile, struct sc_card *card,
		EVP_PKEY *key, unsigned int index,
		struct sc_pkcs15_prkey_info *info)
{
	sc_file_t *keyfile;
	RSA *rsa;
	int r;
	
	if (key->type != EVP_PKEY_RSA) {
		profile->cbs->error("MioCOS supports only 1024-bit RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	rsa = EVP_PKEY_get1_RSA(key);
	if (RSA_size(rsa) != 128) {
		RSA_free(rsa);
		profile->cbs->error("MioCOS supports only 1024-bit RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	r = miocos_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, index,
			    &keyfile);
	if (r < 0) {
		RSA_free(rsa);
		return r;
	}
	info->modulus_length = 1024;
	info->path = keyfile->path;
	r = sc_pkcs15init_create_file(profile, card, keyfile);
	sc_file_free(keyfile);
	if (r < 0) {
		RSA_free(rsa);
		return r;
	}
	r = miocos_update_private_key(profile, card, rsa);
	RSA_free(rsa);

	return r;
}

struct sc_pkcs15init_operations sc_pkcs15init_miocos_operations = {
	NULL,
	miocos_init_app,
	miocos_new_pin,
	miocos_new_key,
	miocos_new_file,
};
