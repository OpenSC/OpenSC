/*
 * Initialize Cards according to PKCS#15.
 *
 * This is a fill in the blanks sort of exercise. You need a
 * profile that describes characteristics of your card, and the
 * application specific layout on the card. This program will
 * set up the card according to this specification (including
 * PIN initialization etc) and create the corresponding PKCS15
 * structure.
 *
 * There are a very few tasks that are too card specific to have
 * a generic implementation; that is how PINs and keys are stored
 * on the card. These should be implemented in pkcs15-<cardname>.c
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
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
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <opensc/pkcs15.h>
#include "profile.h"
#include "pkcs15-init.h"

/* Default ID for new key/pin */
#define DEFAULT_ID		"45"
#define DEFAULT_PRKEY_FLAGS	0x1d
#define DEFAULT_PUBKEY_FLAGS	0x02
#define DEFAULT_CERT_FLAGS	0x02

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

static int	sc_pkcs15init_generate_key_soft(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15init_keyargs *);

static int	sc_pkcs15init_store_data(struct sc_pkcs15_card *,
			struct sc_profile *, unsigned int, void *,
			int (*)(void *, u8 **, size_t *),
			struct sc_path *);
static int	encode_pubkey(void *, u8 **, size_t *);
static int	encode_cert(void *, u8 **, size_t *);

static int	sc_pkcs15init_update_dir(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			struct sc_app_info *app);
static int	sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_odf(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_df(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			unsigned int df_type);
static int	sc_pkcs15init_x509_key_usage(X509 *, int);
static int	set_so_pin_from_card(struct sc_pkcs15_card *,
			struct sc_profile *);
static int	do_select_parent(struct sc_profile *, struct sc_card *,
			struct sc_file *, struct sc_file **);
static int	aodf_add_pin(struct sc_pkcs15_card *, struct sc_profile *,
			const struct sc_pkcs15_pin_info *, const char *);
static void	default_error_handler(const char *fmt, ...);
static void	default_debug_handler(const char *fmt, ...);

/* Card specific functions */
extern struct sc_pkcs15init_operations	sc_pkcs15init_gpk_operations;
extern struct sc_pkcs15init_operations	sc_pkcs15init_miocos_operations;
extern struct sc_pkcs15init_operations	sc_pkcs15init_cflex_operations;

static struct sc_pkcs15init_callbacks default_callbacks = {
	default_error_handler,
	default_debug_handler
};
static struct sc_pkcs15init_callbacks *callbacks = &default_callbacks;

#define p15init_error	callbacks->error
#define p15init_debug	callbacks->debug


/*
 * Set the application callbacks
 */
void
sc_pkcs15init_set_callbacks(struct sc_pkcs15init_callbacks *cb)
{
	callbacks = cb;
}

/*
 * Set up profile
 */
int
sc_pkcs15init_bind(struct sc_card *card, const char *name,
		struct sc_profile **result)
{
	struct sc_profile *profile;
	const char	*driver = card->driver->short_name;
	int		r;

	profile = sc_profile_new();

	profile->cbs = callbacks;
	if (!strcasecmp(driver, "GPK"))
		profile->ops = &sc_pkcs15init_gpk_operations;
	else if (!strcasecmp(driver, "MioCOS"))
		profile->ops = &sc_pkcs15init_miocos_operations;
	else if (!strcasecmp(driver, "flex"))
		profile->ops = &sc_pkcs15init_cflex_operations;
	else {
		p15init_error("Unsupported card driver %s", driver);
		sc_profile_free(profile);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if ((r = sc_profile_load(profile, name)) < 0
	 || (r = sc_profile_load(profile, driver)) < 0
	 || (r = sc_profile_finish(profile)) < 0)
		sc_profile_free(profile);
	*result = profile;

	if (r == 0)
		*result = profile;
	return r;
}

void
sc_pkcs15init_unbind(struct sc_profile *profile)
{
	sc_profile_free(profile);
}

/*
 * Erase the card
 * TBD: if the card does not support an erase command, use
 * Dir Next and the authentication information from the
 * profile to get everything back into the original state.
 */
int
sc_pkcs15init_erase_card(struct sc_card *card, struct sc_profile *profile)
{
	if (profile->ops->erase_card == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return profile->ops->erase_card(profile, card);
}

/*
 * Initialize the PKCS#15 application
 */
int
sc_pkcs15init_add_app(struct sc_card *card, struct sc_profile *profile,
		struct sc_pkcs15init_initargs *args)
{
	struct sc_pkcs15_card *p15card = profile->p15_card;
	struct sc_pkcs15_pin_info pin_info;
	struct sc_app_info *app;
	int	r;

	p15card->card = card;

	if (card->app_count >= SC_MAX_CARD_APPS) {
		p15init_error("Too many applications on this card.");
		return SC_ERROR_TOO_MANY_OBJECTS;
	}

	/* If the profile requires an SO PIN, check min/max length */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info);
	if (args->so_pin_len == 0) {
		/* Mark the SO PIN as "not set" */
		pin_info.reference = -1;
		sc_profile_set_pin_info(profile,
				SC_PKCS15INIT_SO_PIN, &pin_info);
	} else
	if (args->so_pin_len && args->so_pin_len < pin_info.min_length) {
		p15init_error("SO PIN too short (min length %u)",
				pin_info.min_length);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (args->so_pin_len > pin_info.stored_length)
		args->so_pin_len = pin_info.stored_length;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &pin_info);
	if (args->so_puk_len && args->so_puk_len < pin_info.min_length) {
		p15init_error("SO PUK too short (min length %u)",
				pin_info.min_length);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (args->so_puk_len > pin_info.stored_length)
		args->so_puk_len = pin_info.stored_length;

	/* Create the application DF and store the PINs */
	r = profile->ops->init_app(profile, card,
			args->so_pin, args->so_pin_len,
			args->so_puk, args->so_puk_len);
	if (r < 0)
		return 1;

	/* Store the PKCS15 information on the card
	 * We cannot use sc_pkcs15_create() because it makes
	 * all sorts of assumptions about DF and EF names, and
	 * doesn't work if secure messaging is required for the
	 * MF (which is the case with the GPK) */
	app = (struct sc_app_info *) calloc(1, sizeof(*app));
	app->path = p15card->file_app->path;
	if (p15card->file_app->namelen <= SC_MAX_AID_SIZE) {
		app->aid_len = p15card->file_app->namelen;
		memcpy(app->aid, p15card->file_app->name, app->aid_len);
	}
	if (args->serial)
		sc_pkcs15init_set_serial(profile, args->serial);
	if (args->label)
		app->label = strdup(args->label);
	else if (p15card->label)
		app->label = strdup(p15card->label);
	/* XXX: encode the DDO? */

	/* See if we've set an SO PIN */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info);
	if (pin_info.reference != -1 && args->so_pin_len) {
		sc_profile_set_secret(profile, SC_AC_SYMBOLIC,
				SC_PKCS15INIT_SO_PIN,
				args->so_pin, args->so_pin_len);
		pin_info.flags |= SC_PKCS15_PIN_FLAG_SO_PIN;
		r = aodf_add_pin(p15card, profile, &pin_info,
				"Security Officer PIN");
	} else {
		r = sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_AODF);
	}

	if (r >= 0)
		r = sc_pkcs15init_update_dir(p15card, profile, app);
	if (r >= 0)
		r = sc_pkcs15init_update_tokeninfo(p15card, profile);

	return r;
}

/*
 * Store a PIN/PUK pair
 */
int
sc_pkcs15init_store_pin(struct sc_pkcs15_card *p15card,
			struct sc_profile *profile,
			struct sc_pkcs15init_pinargs *args)
{
	struct sc_pkcs15_pin_info pin_info;
	struct sc_card	*card = p15card->card;
	int		r, index;

	/* No auth_id given: select one */
	if (args->auth_id.len == 0) {
		struct sc_pkcs15_object *dummy;
		unsigned int	n;

		args->auth_id.len = 1;
		card->ctx->log_errors = 0;
		for (n = 1, r = 0; n < 256; n++) {
			args->auth_id.value[0] = n;
			r = sc_pkcs15_find_pin_by_auth_id(p15card,
					&args->auth_id, &dummy);
			if (r == SC_ERROR_OBJECT_NOT_FOUND)
				break;
		}
		card->ctx->log_errors = 1;
		if (r != SC_ERROR_OBJECT_NOT_FOUND) {
			p15init_error("No auth_id specified for new PIN");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &pin_info);
	pin_info.auth_id = args->auth_id;

	/* Get the number of PINs we already have */
	index = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH,
				NULL, 0);

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Now store the PINs */
	r = profile->ops->new_pin(profile, card, &pin_info, index,
			args->pin, args->pin_len,
			args->puk, args->puk_len);

	/* Fix up any ACLs referring to the user pin */
	if (r >= 0)
		sc_profile_set_pin_info(profile, SC_PKCS15INIT_USER_PIN,
				&pin_info);

	if (r >= 0)
		r = aodf_add_pin(p15card, profile, &pin_info, args->label);

	return r;
}

static int
aodf_add_pin(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		const struct sc_pkcs15_pin_info *pin, const char *label)
{
	struct sc_pkcs15_pin_info *info;
	struct sc_pkcs15_object *object;
	int	r;

	info = (struct sc_pkcs15_pin_info *) calloc(1, sizeof(*info));
	*info = *pin;

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = SC_PKCS15_TYPE_AUTH_PIN;
	object->data = info;
	object->flags = 0x3; /* XXX */
	if (label)
		strncpy(object->label, label, sizeof(object->label));

	r = sc_pkcs15_add_object(p15card,
				&p15card->df[SC_PKCS15_AODF],
				0, object); 

	if (r >= 0)
		r = sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_AODF);

	return r;
}

/*
 * Generate a new private key
 */
int
sc_pkcs15init_generate_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	if (keyargs->onboard_keygen)
		return SC_ERROR_NOT_SUPPORTED;

	/* Fall back to software generated keys */
	return sc_pkcs15init_generate_key_soft(p15card, profile, keyargs);
}

static int
sc_pkcs15init_generate_key_soft(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	int	r;

	keyargs->pkey = EVP_PKEY_new();
	switch (keyargs->algorithm) {
	case SC_ALGORITHM_RSA: {
			RSA	*rsa;
			BIO	*err;

			err = BIO_new(BIO_s_mem());
			rsa = RSA_generate_key(keyargs->keybits,
					0x10001, NULL, err);
			BIO_free(err);
			if (rsa == 0) {
				p15init_error("RSA key generation error");
				return -1;
			}
			EVP_PKEY_assign_RSA(keyargs->pkey, rsa);
			break;
		}
	case SC_ALGORITHM_DSA: {
			DSA	*dsa;
			int	r = 0;

			dsa = DSA_generate_parameters(keyargs->keybits,
					NULL, 0, NULL,
					NULL, NULL, NULL);
			if (dsa)
				r = DSA_generate_key(dsa);
			if (r == 0 || dsa == 0) {
				p15init_error("DSA key generation error");
				return -1;
			}
			EVP_PKEY_assign_DSA(keyargs->pkey, dsa);
			break;
		}
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_pkcs15init_store_private_key(p15card, profile, keyargs);
	if (r < 0)
		return r;

	return 0;
}

/*
 * Store private key
 */
int
sc_pkcs15init_store_private_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	struct sc_pkcs15_pin_info *pin_info = NULL;
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_prkey_info *key_info;
	const char	*label;
	unsigned int	type, index, usage;
	int		r;

	switch (keyargs->algorithm) {
	case SC_ALGORITHM_RSA:
		type = SC_PKCS15_TYPE_PRKEY_RSA; break;
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
	case SC_ALGORITHM_DSA:
		type = SC_PKCS15_TYPE_PRKEY_DSA; break;
#endif
	default:
		p15init_error("Unsupported key algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (keyargs->auth_id.len != 0) {
		struct sc_pkcs15_object	*objp;

		r = sc_pkcs15_find_pin_by_auth_id(p15card,
				&keyargs->auth_id, &objp);
		if (r < 0)
			return r;
		pin_info = (struct sc_pkcs15_pin_info *) objp->data;
		sc_profile_set_pin_info(profile,
				SC_PKCS15INIT_USER_PIN, pin_info);
	}

	if (keyargs->id.len == 0)
		sc_pkcs15_format_id(DEFAULT_ID, &keyargs->id);
	if ((usage = keyargs->usage) == 0) {
		if (keyargs->cert)
			usage = sc_pkcs15init_x509_key_usage(keyargs->cert, 1);
		else
			usage = SC_PKCS15_PRKEY_USAGE_SIGN;
	}
	if ((label = keyargs->label) == NULL)
		label = "Private Key";

	key_info = calloc(1, sizeof(*key_info));
	key_info->id = keyargs->id;
	key_info->usage = usage;
	key_info->native = 1;
	key_info->key_reference = 0;
	/* modulus_length and path set by card driver */

	object = calloc(1, sizeof(*object));
	object->type = type;
	object->data = key_info;
	object->flags = DEFAULT_PRKEY_FLAGS;
	object->auth_id = keyargs->auth_id;
	strncpy(object->label, label, sizeof(object->label));

	/* Get the number of private keys already on this card */
	index = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0);

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	r = profile->ops->new_key(profile, p15card->card,
			keyargs->pkey, index, key_info);
	if (r == SC_ERROR_NOT_SUPPORTED) {
		/* XXX: handle extractable keys here.
		 * Store the private key, encrypted.
		 * So how does PKCS15 say this should be done? */
	}

	if (r < 0)
		return r;

	r = sc_pkcs15_add_object(p15card,
			&p15card->df[SC_PKCS15_PRKDF], 0, object);
	if (r < 0)
		return r;

	/* Now update the PrKDF */
	return sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_PRKDF);
}

/*
 * Store a public key
 */
int
sc_pkcs15init_store_public_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_pubkey_info *key_info;
	const char	*label;
	unsigned int	type, usage;
	int		r;

	switch (keyargs->algorithm) {
	case SC_ALGORITHM_RSA:
		type = SC_PKCS15_TYPE_PUBKEY_RSA; break;
#ifdef SC_PKCS15_TYPE_PUBKEY_DSA
	case SC_ALGORITHM_DSA:
		type = SC_PKCS15_TYPE_PUBKEY_DSA; break;
#endif
	default:
		p15init_error("Unsupported key algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (keyargs->id.len == 0)
		sc_pkcs15_format_id(DEFAULT_ID, &keyargs->id);
	if ((usage = keyargs->usage) == 0) {
		if (keyargs->cert)
			usage = sc_pkcs15init_x509_key_usage(keyargs->cert, 0);
		else
			usage = SC_PKCS15_PRKEY_USAGE_SIGN;
	}
	if ((label = keyargs->label) == NULL)
		label = "Public Key";

	key_info = calloc(1, sizeof(*key_info));
	key_info->id = keyargs->id;
	key_info->usage = usage;
	key_info->modulus_length = EVP_PKEY_size(keyargs->pkey);

	object = calloc(1, sizeof(*object));
	object->type = type;
	object->data = key_info;
	object->flags = DEFAULT_PUBKEY_FLAGS;
	strncpy(object->label, label, sizeof(object->label));

	/* Now create key file and store key */
	r = sc_pkcs15init_store_data(p15card, profile,
			type, keyargs->pkey,
			encode_pubkey, &key_info->path);

	/* Update the PuKDF */
	if (r >= 0)
		r = sc_pkcs15_add_object(p15card,
			&p15card->df[SC_PKCS15_PUKDF], 0, object);
	if (r >= 0)
		r = sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_PUKDF);

	return r;
}

/*
 * Store a certificate
 */
int
sc_pkcs15init_store_certificate(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_certargs *args)
{
	struct sc_pkcs15_cert_info *cert_info;
	struct sc_pkcs15_object *object;
	unsigned int	usage;
	const char	*label;
	int		r;

	usage = sc_pkcs15init_x509_key_usage(args->cert, 0);
	if ((label = args->label) == NULL)
		label = "Certificate";
	if (args->id.len == 0)
		sc_pkcs15_format_id(DEFAULT_ID, &args->id);

	if (args->id.len != 0) {
		sc_pkcs15_object_t *objp;
		struct sc_pkcs15_pin_info *pin_info;

		r = sc_pkcs15_find_prkey_by_id(p15card,
				&args->id, &objp);
		if (r == 0) {
			r = sc_pkcs15_find_pin_by_auth_id(p15card,
				&objp->auth_id, &objp);
		}
		if (r < 0) {
			/* XXX: Fallback to the first PIN object */
			r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN,
					&objp, 1);
			if (r != 1)
				r = SC_ERROR_OBJECT_NOT_FOUND;
		}
		if (r >= 0) {
			pin_info = (struct sc_pkcs15_pin_info *) objp->data;
			sc_profile_set_pin_info(profile,
					SC_PKCS15INIT_USER_PIN, pin_info);
		}
	}

	cert_info = calloc(1, sizeof(*cert_info));
	cert_info->id = args->id;

	object = calloc(1, sizeof(*object));
	object->type = SC_PKCS15_TYPE_CERT_X509;
	object->data = cert_info;
	object->flags = DEFAULT_CERT_FLAGS;
	strncpy(object->label, label, sizeof(object->label));

	r = sc_pkcs15init_store_data(p15card, profile,
			SC_PKCS15_TYPE_CERT_X509, args->cert,
			encode_cert, &cert_info->path);

	/* Now update the CDF */
	if (r >= 0)
		r = sc_pkcs15_add_object(p15card,
			&p15card->df[SC_PKCS15_CDF], 0, object);
	if (r >= 0)
		r = sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_CDF);

	return r;
}

static int
sc_pkcs15init_store_data(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int type, void *ptr,
		int (*encode)(void *, u8 **, size_t *),
		struct sc_path *path)
{
	struct sc_file	*file = NULL;
	unsigned char	*data = NULL;
	unsigned int	index;
	size_t		size;
	int		r;

	/* Encode the object */
	r = encode(ptr, &data, &size);
	if (r < 0)
		return r;

	/* Get the number of private keys already on this card */
	index = sc_pkcs15_get_objects(p15card,
			type & SC_PKCS15_TYPE_CLASS_MASK, NULL, 0);

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Allocate data file */
	r = profile->ops->new_file(profile, p15card->card, type, index, &file);
	if (r < 0) {
		p15init_error("Unable to allocate file");
		goto done;
	}

	r = sc_pkcs15init_update_file(profile, p15card->card,
			file, data, size);
	*path = file->path;

done:	if (file)
		sc_file_free(file);
	if (data)
		free(data);
	return r;
}

/*
 * Encoder functions
 */
static int
encode_pubkey(void *ptr, u8 **data, size_t *sizep)
{
	EVP_PKEY *pk = (EVP_PKEY *) ptr;
	RSA	*rsa;
	DSA	*dsa;
	u8	*p;

	switch (pk->type) {
	case EVP_PKEY_RSA:
		rsa = EVP_PKEY_get1_RSA(pk);
		*sizep = i2d_RSAPublicKey(rsa, NULL);
		*data = p = malloc(*sizep);
		i2d_RSAPublicKey(rsa, &p);
		RSA_free(rsa);
		break;
	case EVP_PKEY_DSA:
		dsa = EVP_PKEY_get1_DSA(pk);
		*sizep = i2d_DSAPublicKey(dsa, NULL);
		*data = p = malloc(*sizep);
		i2d_DSAPublicKey(dsa, &p);
		DSA_free(dsa);
		break;
	default:
		p15init_error("Unsupported key algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	return 0;
}

static int
encode_cert(void *ptr, u8 **data, size_t *sizep)
{
	X509	*cert = (X509 *) ptr;
	u8	*p;

	*sizep = i2d_X509(cert, NULL);
	*data = p = malloc(*sizep);
	i2d_X509(cert, &p);
	return 0;
}


/*
 * Map X509 keyUsage extension bits to PKCS#15 keyUsage bits
 */
static unsigned int	x509_to_pkcs15_private_key_usage[16] = {
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* digitalSignature */
	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,	/* NonRepudiation */
	SC_PKCS15_PRKEY_USAGE_UNWRAP,		/* keyEncipherment */
	SC_PKCS15_PRKEY_USAGE_DECRYPT,		/* dataEncipherment */
	SC_PKCS15_PRKEY_USAGE_DERIVE,		/* keyAgreement */
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* keyCertSign */
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* cRLSign */
};

static unsigned int	x509_to_pkcs15_public_key_usage[16] = {
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* digitalSignature */
	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,	/* NonRepudiation */
	SC_PKCS15_PRKEY_USAGE_WRAP,		/* keyEncipherment */
	SC_PKCS15_PRKEY_USAGE_ENCRYPT,		/* dataEncipherment */
	SC_PKCS15_PRKEY_USAGE_DERIVE,		/* keyAgreement */
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* keyCertSign */
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* cRLSign */
};

static int
sc_pkcs15init_x509_key_usage(X509 *cert, int private)
{
	unsigned int	x509_usage = cert->ex_kusage;
	unsigned int	p15_usage, n, *bits;

	bits = private? x509_to_pkcs15_private_key_usage
		      : x509_to_pkcs15_public_key_usage;
	for (n = p15_usage = 0; n < 16; n++) {
		if (x509_usage & (1 << n))
			p15_usage |= bits[n];
	}
	return p15_usage;
}

static int
sc_pkcs15init_update_dir(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_app_info *app)
{
	struct sc_card *card = p15card->card;
	int	r, retry = 1;

	do {
		struct sc_file	*dir_file;
		struct sc_path	path;

		card->ctx->log_errors = 0;
		r = sc_enum_apps(card);
		card->ctx->log_errors = 1;

		if (r != SC_ERROR_FILE_NOT_FOUND)
			break;

		sc_format_path("3F002F00", &path);
		if (sc_profile_get_file_by_path(profile, &path, &dir_file) < 0)
			return r;
		r = sc_pkcs15init_update_file(profile, card, dir_file, NULL, 0);
		sc_file_free(dir_file);
	} while (retry--);

	if (r >= 0) {
		card->app[card->app_count++] = app;
		r = sc_update_dir(card, NULL);
	}
	return r;
}

static int
sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_card	*card = p15card->card;
	u8		*buf = NULL;
	size_t		size;
	int		r;

	r = sc_pkcs15_encode_tokeninfo(card->ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile, card,
			       p15card->file_tokeninfo, buf, size);
	if (buf)
		free(buf);
	return r;
}

static int
sc_pkcs15init_update_odf(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_card	*card = p15card->card;
	u8		*buf = NULL;
	size_t		size;
	int		r;

	r = sc_pkcs15_encode_odf(card->ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile, card,
			       p15card->file_odf, buf, size);
	if (buf)
		free(buf);
	return r;
}

static int
sc_pkcs15init_update_df(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int df_type)
{
	struct sc_card	*card = p15card->card;
	struct sc_pkcs15_df *df;
	struct sc_file	*file = NULL;
	u8		*buf = NULL;
	size_t		bufsize;
	unsigned int	j;
	int		r = 0;

	df = &p15card->df[df_type];
	if (df->count == 0) {
		file = profile->df[df_type];
		if (file == NULL) {
			p15init_error("Profile doesn't define a DF file %u",
			 		df_type);
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_file_dup(df->file + df->count++, file);
		if ((r = sc_pkcs15init_update_odf(p15card, profile)) < 0)
			return r;
	}

	for (j = 0; r >= 0 && j < df->count; j++) {
		struct sc_file	*pfile = NULL;
		
		file = df->file[j];
		if (!sc_profile_get_file_by_path(profile, &file->path, &pfile))
			file = pfile;
		r = sc_pkcs15_encode_df(card->ctx, df, j, &buf, &bufsize);
		if (r >= 0) {
			r = sc_pkcs15init_update_file(profile, card,
					file, buf, bufsize);
			free(buf);
		}
		if (pfile)
			sc_file_free(pfile);
	}

	return r;
}

static int
do_verify_pin(struct sc_profile *pro, struct sc_card *card,
		unsigned int type, unsigned int reference)
{
	struct sc_pkcs15_pin_info pin_info;
	const char	*ident;
	unsigned int	pin_id = (unsigned int) -1;
	size_t		pinsize;
	u8		pinbuf[32];
	int		r;

	ident = "authentication data";
	if (type == SC_AC_CHV) {
		ident = "PIN";
		if (sc_profile_get_pin_id(pro, reference, &pin_id) >= 0)
			sc_profile_get_pin_info(pro, pin_id, &pin_info);
	} else if (type == SC_AC_PRO) {
		ident = "secure messaging key";
	} else if (type == SC_AC_AUT) {
		ident = "authentication key";
	} else if (type == SC_AC_SYMBOLIC) {
		switch (reference) {
		case SC_PKCS15INIT_USER_PIN:
			ident = "user PIN"; break;
		case SC_PKCS15INIT_SO_PIN:
			ident = "SO PIN"; break;
		}
		pin_id = reference;
		sc_profile_get_pin_info(pro, pin_id, &pin_info);
		type = SC_AC_CHV;
		reference = pin_info.reference;
		if (reference == -1)
			goto no_secret;
	}

	pinsize = sizeof(pinbuf);
	memset(pinbuf, 0, sizeof(pinbuf));

	r = sc_profile_get_secret(pro, type, reference, pinbuf, &pinsize);
	if (r < 0 && pin_id != -1)
		r = sc_profile_get_secret(pro, SC_AC_SYMBOLIC, pin_id,
				pinbuf, &pinsize);

	if (r < 0 && pin_id != -1 && callbacks && callbacks->get_pin) {
		r = callbacks->get_pin(pro, pin_id, &pin_info,
				pinbuf, &pinsize);
		if (r >= 0)
			sc_profile_set_secret(pro, SC_AC_SYMBOLIC, pin_id,
					pinbuf, pinsize);
	}
	if (r >= 0) {
		if (type == SC_AC_CHV) {
			int left = pro->pin_maxlen - pinsize;

			if (left > 0) {
				memset(pinbuf + pinsize, pro->pin_pad_char,
				       left);
				pinsize = pro->pin_maxlen;
			}
		}
		r = sc_verify(card, type, reference, pinbuf, pinsize, NULL);
		if (r) {
			p15init_error("Failed to verify %s (ref=0x%x)",
				ident, reference);
			return r;
		}
		return 0;
	}


no_secret:
	/* No secret found that we could present.
	 * XXX: Should we flag an error here, or let the
	 * operation proceed and then fail? */
	return 0;
}

/*
 * Present a single PIN to the card
 */
int
sc_pkcs15init_present_pin(struct sc_profile *profile, struct sc_card *card,
		unsigned int id)
{
	return do_verify_pin(profile, card, SC_AC_SYMBOLIC, id);
}

/*
 * Find out whether the card was initialized using an SO PIN,
 * and if so, set the profile information
 */
int
set_so_pin_from_card(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_pkcs15_pin_info pin;
	struct sc_pkcs15_object *obj;
	int		r;

	r = sc_pkcs15_find_so_pin(p15card, &obj);
	if (r == 0) {
		pin = *(struct sc_pkcs15_pin_info *) obj->data;
	} else if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin);
		pin.reference = -1;
	} else {
		return r;
	}

	sc_profile_set_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin);
	return 0;
}

/*
 * Present any authentication info as required by the file.
 *
 * XXX: There's a problem here if e.g. the SO PIN defined by
 * the profile is optional, and hasn't been set. In this case,
 * it would be better if we based our authentication on the
 * real ACLs of the file (i.e. the data returned by a previous
 * sc_select_file()). Current practice though is to prefer
 * checking against the ACL defined by the profile (introduced by
 * Juha for some reason) and I'm not sure we can change this
 * easily.
 */
int
sc_pkcs15init_authenticate(struct sc_profile *pro, struct sc_card *card,
		struct sc_file *file, int op)
{
	const struct sc_acl_entry *acl;
	int		r = 0;

#if 0
	/* Fix up the file's ACLs */
	if ((r = sc_pkcs15init_fixup_file(pro, file)) < 0)
		return r;
#endif

	acl = sc_file_get_acl_entry(file, op);
	for (; r == 0 && acl; acl = acl->next) {
		if (acl->method == SC_AC_NEVER)
			return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		if (acl->method == SC_AC_NONE)
			break;
		r = do_verify_pin(pro, card, acl->method, acl->key_ref);
	}
	return r;
}

int
do_select_parent(struct sc_profile *pro, struct sc_card *card,
		struct sc_file *file, struct sc_file **parent)
{
	struct sc_path	path;
	int		r;

	/* Get the parent's path */
	path = file->path;
	if (path.len >= 2)
		path.len -= 2;
	if (path.len == 0)
		sc_format_path("3F00", &path);

	*parent = NULL;
	r = sc_profile_get_file_by_path(pro, &path, parent);
	card->ctx->log_errors = 0;
	if (r == 0) {
		r = sc_select_file(card, &path, NULL);
	} else {
		/* Select the parent DF. */
		r = sc_select_file(card, &path, parent);
	}
	card->ctx->log_errors = 1;
	/* If DF doesn't exist, create it (unless it's the MF,
	 * but then something's badly broken anyway :-) */
	if (r == SC_ERROR_FILE_NOT_FOUND && path.len != 2) {
		if (*parent
		 && !(r = sc_pkcs15init_create_file(pro, card, *parent)))
			r = sc_select_file(card, &path, NULL);
	}
	return r;
}

int
sc_pkcs15init_create_file(struct sc_profile *pro, struct sc_card *card,
		struct sc_file *file)
{
	struct sc_file	*parent = NULL;
	int		r;

	/* Select parent DF and verify PINs/key as necessary */
	if ((r = do_select_parent(pro, card, file, &parent)) < 0
	 || (r = sc_pkcs15init_authenticate(pro, card,
			 	parent, SC_AC_OP_CREATE)) < 0) 
		goto out;

	/* Fix up the file's ACLs */
	if ((r = sc_pkcs15init_fixup_file(pro, file)) < 0)
		return r;

	r = sc_create_file(card, file);

out:	if (parent)
		sc_file_free(parent);
	return r;
}

int
sc_pkcs15init_update_file(struct sc_profile *profile, struct sc_card *card,
	       	struct sc_file *file, void *data, unsigned int datalen)
{
	int		r;

	card->ctx->log_errors = 0;
	if ((r = sc_select_file(card, &file->path, NULL)) < 0) {
		card->ctx->log_errors = 1;
		/* Create file if it doesn't exist */
		if (file->size < datalen)
			file->size = datalen;
		if (r != SC_ERROR_FILE_NOT_FOUND
		 || (r = sc_pkcs15init_create_file(profile, card, file)) < 0
		 || (r = sc_select_file(card, &file->path, NULL)) < 0)
			return r;
	}
	card->ctx->log_errors = 1;

	/* Present authentication info needed */
	r = sc_pkcs15init_authenticate(profile, card, file, SC_AC_OP_UPDATE);
	if (r >= 0 && datalen)
		r = sc_update_binary(card, 0, data, datalen, 0);

	return r;
}

/*
 * Fix up all file ACLs
 */
int
sc_pkcs15init_fixup_file(struct sc_profile *profile, struct sc_file *file)
{
	struct sc_pkcs15_pin_info so_pin, user_pin;
	struct sc_acl_entry so_acl, user_acl;
	unsigned int	op, needfix = 0;

	/* First, loop over all ACLs to find out whether there
	 * are still any symbolic references.
	 */
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		const struct sc_acl_entry *acl;

		acl = sc_file_get_acl_entry(file, op);
		for (; acl; acl = acl->next) {
			if (acl->method == SC_AC_SYMBOLIC)
				needfix++;
		}
	}

	if (!needfix)
		return 0;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &so_pin);
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &user_pin);

	/* If the profile doesn't specify a SO pin, change all
	 * ACLs that reference $sopin to NONE */
	so_acl.method = SC_AC_CHV;
	so_acl.key_ref = so_pin.reference;
	if (so_acl.key_ref == -1) {
		so_acl.method = SC_AC_NONE;
		so_acl.key_ref = 0;
	}

	/* If we haven't got a user pin, barf */
	user_acl.method = SC_AC_CHV;
	user_acl.key_ref = user_pin.reference;

	return sc_pkcs15init_fixup_acls(profile, file, &so_acl, &user_acl);
}

/*
 * Fix up a file's ACLs by replacing all occurrences of a symbolic
 * PIN name with the real reference.
 */
int
sc_pkcs15init_fixup_acls(struct sc_profile *profile, struct sc_file *file,
		struct sc_acl_entry *so_acl,
		struct sc_acl_entry *user_acl)
{
	struct sc_acl_entry acls[16];
	unsigned int	op, num;
	int		r = 0;

	for (op = 0; r == 0 && op < SC_MAX_AC_OPS; op++) {
		const struct sc_acl_entry *acl;
		const char	*what;
		int		added = 0;

		/* First, get original ACLs */
		acl = sc_file_get_acl_entry(file, op);
		for (num = 0; num < 16 && acl; num++, acl = acl->next)
			acls[num] = *acl;

		sc_file_clear_acl_entries(file, op);
		for (acl = acls; acl < acls + num; acl++) {
			if (acl->method != SC_AC_SYMBOLIC)
				goto next;
			if (acl->key_ref == SC_PKCS15INIT_SO_PIN) {
				acl = so_acl;
				what = "SO PIN";
			} else if (acl->key_ref == SC_PKCS15INIT_USER_PIN) {
				acl = user_acl;
				what = "user PIN";
			} else {
				p15init_error("ACL references unknown symbolic PIN %d",
						acl->key_ref);
				return SC_ERROR_INVALID_ARGUMENTS;
			}

			/* If we weren't given a replacement ACL,
			 * leave the original ACL untouched */
			if (acl == NULL || acl->key_ref == -1) {
				p15init_error("ACL references %s, which is not defined",
						what);
				return SC_ERROR_INVALID_ARGUMENTS;
			}

			if (acl->method == SC_AC_NONE)
				continue;

		next:	sc_file_add_acl_entry(file, op,
					acl->method, acl->key_ref);
			added++;
		}
		if (!added)
			sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
	}

	return r;
}

int
sc_pkcs15init_get_pin_info(struct sc_profile *profile,
		unsigned int id, struct sc_pkcs15_pin_info *pin)
{
	sc_profile_get_pin_info(profile, id, pin);
	return 0;
}

int
sc_pkcs15init_get_manufacturer(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_card->manufacturer_id;
	return 0;
}

int
sc_pkcs15init_get_serial(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_card->serial_number;
	return 0;
}

int
sc_pkcs15init_set_serial(struct sc_profile *profile, const char *serial)
{
	if (profile->p15_card->serial_number)
		free(profile->p15_card->serial_number);
	profile->p15_card->serial_number = strdup(serial);

	return 0;
}

int
sc_pkcs15init_get_label(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_card->label;
	return 0;
}

void
default_error_handler(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fputs("\n", stderr);
	va_end(ap);
}

void
default_debug_handler(const char *fmt, ...)
{
	/* Nothing */
}
