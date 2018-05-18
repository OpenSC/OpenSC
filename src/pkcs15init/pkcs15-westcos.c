/*
 * pkcs15-westcos.c: pkcs15 support for westcos card
 *
 * Copyright (C) 2009 francois.leblanc@cev-sa.com
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
#include <stdlib.h>
#include <stdio.h>

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

#include "libopensc/sc-ossl-compat.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "pkcs15-init.h"
#include "profile.h"

static int westcos_pkcs15init_init_card(sc_profile_t *profile,
						sc_pkcs15_card_t *p15card)
{
	int r;
	struct sc_path path;

	sc_format_path("3F00", &path);
	r = sc_select_file(p15card->card, &path, NULL);
	if(r) return (r);

	return r;
}

static int westcos_pkcs15init_create_dir(sc_profile_t *profile,
						sc_pkcs15_card_t *p15card,
						sc_file_t *df)
{
	int r;

	/* Create the application DF */
	sc_pkcs15init_create_file(profile, p15card, df);

	r = sc_select_file(p15card->card, &df->path, NULL);
	if(r) return r;

	return 0;
}

/*
 * Select the PIN reference
 */
static int westcos_pkcs15_select_pin_reference(sc_profile_t *profile,
					sc_pkcs15_card_t *p15card,
					sc_pkcs15_auth_info_t *auth_info)
{

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		auth_info->attrs.pin.reference = 1;
	} else {
		auth_info->attrs.pin.reference = 0;
	}

	return 0;
}

/*
 * Create a new PIN inside a DF
 */
static int westcos_pkcs15_create_pin(sc_profile_t *profile,
					sc_pkcs15_card_t *p15card,
					sc_file_t *df,
					sc_pkcs15_object_t *pin_obj,
					const u8 *pin, size_t pin_len,
					const u8 *puk, size_t puk_len)
{
	int r;
	sc_file_t *pinfile = NULL;

	if(pin_len>9 || puk_len>9)
		return SC_ERROR_INVALID_ARGUMENTS;

	r = sc_profile_get_file(profile, "PINFILE", &pinfile);
	if(r < 0) return r;

	r = sc_create_file(p15card->card, pinfile);
	if(r)
	{
		if(r != SC_ERROR_FILE_ALREADY_EXISTS)
			return (r);

		r = sc_select_file(p15card->card, &pinfile->path, NULL);
		if(r) return (r);
	}

	sc_file_free(pinfile);

	if(pin != NULL)
	{
		sc_changekey_t ck;
		struct sc_pin_cmd_pin pin_cmd;
		int ret;

		memset(&pin_cmd, 0, sizeof(pin_cmd));
		memset(&ck, 0, sizeof(ck));

		memcpy(ck.key_template, "\x1e\x00\x00\x10", 4);

		pin_cmd.encoding = SC_PIN_ENCODING_GLP;
		pin_cmd.len = pin_len;
		pin_cmd.data = pin;
		pin_cmd.max_length = 8;

		ret = sc_build_pin(ck.new_key.key_value,
			sizeof(ck.new_key.key_value), &pin_cmd, 1);
		if(ret < 0)
			return SC_ERROR_CARD_CMD_FAILED;

		ck.new_key.key_len = ret;
		r = sc_card_ctl(p15card->card, SC_CARDCTL_WESTCOS_CHANGE_KEY, &ck);
		if(r) return r;
	}

	if(puk != NULL)
	{
		sc_changekey_t ck;
		struct sc_pin_cmd_pin puk_cmd;
		int ret;

		memset(&puk_cmd, 0, sizeof(puk_cmd));
		memset(&ck, 0, sizeof(ck));

		memcpy(ck.key_template, "\x1e\x00\x00\x20", 4);

		puk_cmd.encoding = SC_PIN_ENCODING_GLP;
		puk_cmd.len = puk_len;
		puk_cmd.data = puk;
		puk_cmd.max_length = 8;

		ret = sc_build_pin(ck.new_key.key_value,
			sizeof(ck.new_key.key_value), &puk_cmd, 1);
		if(ret < 0)
			return SC_ERROR_CARD_CMD_FAILED;

		ck.new_key.key_len = ret;
		r = sc_card_ctl(p15card->card, SC_CARDCTL_WESTCOS_CHANGE_KEY, &ck);
		if(r) return r;
	}

	return 0;
}

/*
 * Create a new key file
 */
static int westcos_pkcs15init_create_key(sc_profile_t *profile,
						sc_pkcs15_card_t *p15card,
						sc_pkcs15_object_t *obj)
{

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		return SC_ERROR_NOT_SUPPORTED;
	}

	return 0;
}


/*
 * Store a private key
 */
static int westcos_pkcs15init_store_key(sc_profile_t *profile,
						sc_pkcs15_card_t *p15card,
						sc_pkcs15_object_t *obj,
						sc_pkcs15_prkey_t *key)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Generate key
 */
static int westcos_pkcs15init_generate_key(sc_profile_t *profile,
						sc_pkcs15_card_t *p15card,
						sc_pkcs15_object_t *obj,
						sc_pkcs15_pubkey_t *pubkey)
{
#ifndef ENABLE_OPENSSL
	return SC_ERROR_NOT_SUPPORTED;
#else
	int r = SC_ERROR_UNKNOWN;
	long lg;
	u8 *p;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	RSA *rsa = NULL;
	BIGNUM *bn = NULL;
	BIO *mem = NULL;

	sc_file_t *prkf = NULL;

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
		return SC_ERROR_NOT_SUPPORTED;
	}

#if OPENSSL_VERSION_NUMBER>=0x00908000L
	rsa = RSA_new();
	bn = BN_new();
	mem = BIO_new(BIO_s_mem());

	if(rsa == NULL || bn == NULL || mem == NULL)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if(!BN_set_word(bn, RSA_F4) ||
		!RSA_generate_key_ex(rsa, key_info->modulus_length, bn, NULL))
#else
	mem = BIO_new(BIO_s_mem());

	if(mem == NULL)
	{
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	rsa = RSA_generate_key(key_info->modulus_length, RSA_F4, NULL, NULL);
	if (!rsa)
#endif
	{
		r = SC_ERROR_UNKNOWN;
		goto out;
	}

	RSA_set_method(rsa, RSA_PKCS1_OpenSSL());

	if(pubkey != NULL)
	{
		if(!i2d_RSAPublicKey_bio(mem, rsa))
		{
			r = SC_ERROR_UNKNOWN;
			goto out;
		}

		lg = BIO_get_mem_data(mem, &p);

		pubkey->algorithm = SC_ALGORITHM_RSA;

		r = sc_pkcs15_decode_pubkey(p15card->card->ctx, pubkey, p, lg);
		if (r < 0)
			goto out;
	}

	(void) BIO_reset(mem);

	if(!i2d_RSAPrivateKey_bio(mem, rsa))
	{
		r = SC_ERROR_UNKNOWN;
		goto out;
	}

	lg = BIO_get_mem_data(mem, &p);

	/* Get the private key file */
	r = sc_profile_get_file_by_path(profile, &key_info->path, &prkf);
	if (r < 0)
	{
		char pbuf[SC_MAX_PATH_STRING_SIZE];

		r = sc_path_print(pbuf, sizeof(pbuf), &key_info->path);
		if (r != SC_SUCCESS)
			pbuf[0] = '\0';

		goto out;
	}

	prkf->size = lg;

	r = sc_pkcs15init_create_file(profile, p15card, prkf);
	if(r) goto out;

	r = sc_pkcs15init_update_file(profile, p15card, prkf, p, lg);
	if(r) goto out;

out:
	if(mem)
		BIO_free(mem);
	if(bn)
		BN_free(bn);
	if(rsa)
		RSA_free(rsa);
	sc_file_free(prkf);

	return r;
#endif
}

static int westcos_pkcs15init_finalize_card(sc_card_t *card)
{
	int r;

	/* be sure authenticate card */
	r = sc_card_ctl(card, SC_CARDCTL_WESTCOS_AUT_KEY, NULL);
	if(r) return (r);

	return sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_USER);
}

static struct sc_pkcs15init_operations sc_pkcs15init_westcos_operations = {
	NULL,					/* erase_card */
	westcos_pkcs15init_init_card,		/* init_card  */
	westcos_pkcs15init_create_dir,		/* create_dir */
	NULL,					/* create_domain */
	westcos_pkcs15_select_pin_reference,	/* select_pin_reference */
	westcos_pkcs15_create_pin,		/* create_pin */
	NULL,					/* select_key_reference */
	westcos_pkcs15init_create_key,		/* create_key */
	westcos_pkcs15init_store_key,		/* store_key */
	westcos_pkcs15init_generate_key,	/* generate_key */
	NULL, NULL,				/* encode private/public key */
	westcos_pkcs15init_finalize_card,	/* finalize_card */
	NULL,					/* delete_object */
	NULL, NULL, NULL, NULL, NULL,		/* pkcs15init emulation */
	NULL					/* sanity_check */
};

struct sc_pkcs15init_operations* sc_pkcs15init_get_westcos_ops(void)
{
	return &sc_pkcs15init_westcos_operations;
}
