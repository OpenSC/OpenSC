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
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>
#ifdef HAVE_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#endif
#include <opensc/pkcs15.h>
#include "profile.h"
#include "pkcs15-init.h"
#include <opensc/cardctl.h>

/* Default ID for new key/pin */
#define DEFAULT_ID		0x45
#define DEFAULT_PRKEY_FLAGS	0x1d
#define DEFAULT_PUBKEY_FLAGS	0x02
#define DEFAULT_CERT_FLAGS	0x02
#define DEFAULT_DATA_FLAGS	0x03

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

static int	sc_pkcs15init_store_data(struct sc_pkcs15_card *,
			struct sc_profile *, unsigned int,
			sc_pkcs15_der_t *, struct sc_path *);
static size_t	sc_pkcs15init_keybits(sc_pkcs15_bignum_t *);

static int	sc_pkcs15init_update_dir(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			struct sc_app_info *app);
static int	sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_odf(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_add_object(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			unsigned int df_type,
			struct sc_pkcs15_object *);
static int	sc_pkcs15init_map_usage(unsigned long, int);
static int	set_so_pin_from_card(struct sc_pkcs15_card *,
			struct sc_profile *);
static int	set_user_pin_from_authid(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15_id *);
static int	do_select_parent(struct sc_profile *, struct sc_card *,
			struct sc_file *, struct sc_file **);
static int	aodf_add_pin(struct sc_pkcs15_card *, struct sc_profile *,
			const struct sc_pkcs15_pin_info *, const char *);
static int	check_key_compatibility(struct sc_pkcs15_card *,
			struct sc_pkcs15_prkey *, unsigned int,
			unsigned int, unsigned int);
static int	prkey_fixup(sc_pkcs15_prkey_t *);
static int	prkey_bits(sc_pkcs15_prkey_t *);
static int	prkey_pkcs15_algo(sc_pkcs15_prkey_t *);
static int	select_id(struct sc_pkcs15_card *, int, struct sc_pkcs15_id *);
static struct sc_pkcs15_df * find_df_by_type(struct sc_pkcs15_card *, int);
static void	default_error_handler(const char *fmt, ...);
static void	default_debug_handler(const char *fmt, ...);

/* Card specific functions */
extern struct sc_pkcs15init_operations	sc_pkcs15init_gpk_operations;
extern struct sc_pkcs15init_operations	sc_pkcs15init_miocos_operations;
extern struct sc_pkcs15init_operations	sc_pkcs15init_cflex_operations;
extern struct sc_pkcs15init_operations	sc_pkcs15init_etoken_operations;

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

/* Returns 1 if the a profile was found in the card's card_driver block
 *   in the config file, or 0 otherwise.
 * card_prof_name is a PATH_MAX -sized buffer that will hold the profile name */
static int get_profile_from_config(struct sc_card *card, char *card_prof_name)
{
	struct sc_context *ctx = card->ctx;
	const char *tmp;
	scconf_block **blocks, *blk;
	int i;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					"card_driver", card->driver->short_name);
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;

		tmp = scconf_get_str(blk, "profile", NULL);
		if (tmp != NULL) {
			strncpy(card_prof_name, tmp, PATH_MAX);
			return 1;
		}
	}

	return 0;
}

/*
 * Set up profile
 */
int
sc_pkcs15init_bind(struct sc_card *card, const char *name,
		const char *card_profile_name, struct sc_profile **result)
{
	struct sc_profile *profile;
	const char	*driver = card->driver->short_name;
	char		card_prof_name[PATH_MAX];
	int		r;

	/* Put the card into administrative mode */
	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0 && r != SC_ERROR_NOT_SUPPORTED)
		return r;

	profile = sc_profile_new();

	profile->cbs = callbacks;
	if (!strcasecmp(driver, "GPK"))
		profile->ops = &sc_pkcs15init_gpk_operations;
	else if (!strcasecmp(driver, "MioCOS"))
		profile->ops = &sc_pkcs15init_miocos_operations;
	else if (!strcasecmp(driver, "flex"))
		profile->ops = &sc_pkcs15init_cflex_operations;
	else if (!strcasecmp(driver, "eToken"))
		profile->ops = &sc_pkcs15init_etoken_operations;
	else {
		p15init_error("Unsupported card driver %s", driver);
		sc_profile_free(profile);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* 1. Use card_profile_name if present,
	 * 2. otherwise look in the config file, or
	 * 3. otherwise use the default profile name.
	 */
	if (card_profile_name != NULL)
		strcpy(card_prof_name, card_profile_name);         /* 1 */
	else if (!get_profile_from_config(card, card_prof_name)) /* 2 */
			strcpy(card_prof_name, driver);            /* 3 */

	if ((r = sc_profile_load(profile, name)) < 0
	 || (r = sc_profile_load(profile, card_prof_name)) < 0
	 || (r = sc_profile_finish(profile)) < 0) {
		fprintf(stderr,
			"Failed to load profile: %s\n",
			sc_strerror(r));
		sc_profile_free(profile);
		return r;
	}
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
 * Set the card's lifecycle
 */
int
sc_pkcs15init_set_lifecycle(sc_card_t *card, int lcycle)
{
	return sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &lcycle);
}

/*
 * Erase the card
 */
int
sc_pkcs15init_erase_card(struct sc_card *card, struct sc_profile *profile)
{
	if (profile->ops->erase_card == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return profile->ops->erase_card(profile, card);
}

int
sc_pkcs15init_erase_card_recursively(struct sc_card *card, 
		struct sc_profile *profile,
		int so_pin_ref)
{
	struct sc_pkcs15_card *p15orig = profile->p15_card;
	struct sc_pkcs15_pin_info sopin, temp;
	struct sc_file	*df = profile->df_info->file, *dir;
	int		r;

	/* Frob: need to tell the upper layers about the SO PIN id */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);
	if (so_pin_ref != -1) {
		temp = sopin;
		temp.reference = so_pin_ref;
		sc_profile_set_pin_info(profile, SC_PKCS15INIT_SO_PIN, &temp);
	} else {
		struct sc_pkcs15_card *p15card = NULL;

		card->ctx->log_errors = 0;
		if (sc_pkcs15_bind(card, &p15card) >= 0) {
			set_so_pin_from_card(p15card, profile);
			profile->p15_card = p15card;
		}
		card->ctx->log_errors = 1;
	}

	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete if before the DF because we create
	 * it *after* the DF. Some cards (e.g. the cryptoflex) want
	 * us to delete file in reverse order of creation.
	 * */
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		r = sc_pkcs15init_rmdir(card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)
			goto out;
	}

	card->ctx->log_errors = 0;
	r = sc_select_file(card, &df->path, &df);
	card->ctx->log_errors = 1;
	if (r >= 0) {
		r = sc_pkcs15init_rmdir(card, profile, df);
		sc_file_free(df);
	}
	if (r == SC_ERROR_FILE_NOT_FOUND)
		r = 0;

	/* Unfrob the SO pin reference, and return */
out:	sc_profile_set_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin);
	sc_profile_forget_secrets(profile, SC_AC_CHV, -1);
	sc_free_apps(card);
	if (profile->p15_card != p15orig) {
		sc_pkcs15_unbind(profile->p15_card);
		profile->p15_card = p15orig;
	}
	return r;
}

/*
 * Try to delete a file (and, in the DF case, its contents).
 * Note that this will not work if a pkcs#15 file's ERASE AC
 * references a pin other than the SO pin.
 */
int
sc_pkcs15init_rmdir(struct sc_card *card, struct sc_profile *profile,
		struct sc_file *df)
{
	u8		buffer[1024];
	struct sc_path	path;
	struct sc_file	*file, *parent;
	int		r = 0, nfids;

#if 0
	if (card->ctx->debug) {
		int	n;
		printf("%s(", __FUNCTION__);
		path = df->path;
		for (n = 0; n < path.len; n++)
			printf("%02x", path.value[n]);
		printf(")\n");
	}
#endif
	if (df == NULL)
		return SC_ERROR_INTERNAL;
	if (df->type == SC_FILE_TYPE_DF) {
		r = sc_pkcs15init_authenticate(profile, card, df,
				SC_AC_OP_LIST_FILES);
		if (r < 0)
			return r;
		card->ctx->log_errors = 0;
		r = sc_list_files(card, buffer, sizeof(buffer));
		card->ctx->log_errors = 1;
		if (r < 0)
			return r;

		path = df->path;
		path.len += 2;

		nfids = r / 2;
		while (r >= 0 && nfids--) {
			path.value[path.len-2] = buffer[2*nfids];
			path.value[path.len-1] = buffer[2*nfids+1];
			r = sc_select_file(card, &path, &file);
			if (r < 0) {
				if (r == SC_ERROR_FILE_NOT_FOUND)
					continue;
				break;
			}
			r = sc_pkcs15init_rmdir(card, profile, file);
			sc_file_free(file);
		}

		if (r < 0)
			return r;
	}

	/* Select the parent DF */
	path = df->path;
	path.len -= 2;
	r = sc_select_file(card, &path, &parent);
	if (r < 0)
		return r;

	r = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	if (r < 0)
		return r;
	r = sc_pkcs15init_authenticate(profile, card, df, SC_AC_OP_ERASE);
	if (r < 0)
		return r;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	card->ctx->log_errors = 0;
	r = sc_delete_file(card, &path);
	card->ctx->log_errors = 1;
	return r;
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
	if (args->so_pin_len > pin_info.max_length)
		args->so_pin_len = pin_info.max_length;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &pin_info);
	if (args->so_puk_len && args->so_puk_len < pin_info.min_length) {
		p15init_error("SO PUK too short (min length %u)",
				pin_info.min_length);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (args->so_puk_len > pin_info.max_length)
		args->so_puk_len = pin_info.max_length;

	/* Create the application DF and store the PINs */
	r = profile->ops->init_app(profile, card,
			args->so_pin, args->so_pin_len,
			args->so_puk, args->so_puk_len);
	if (r < 0)
		return r;

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

	if (args->label) {
		if (p15card->label)
			free(p15card->label);
		p15card->label = strdup(args->label);
	}
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
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_AODF, NULL);
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
	} else {
		struct sc_pkcs15_object *dummy;

		/* Make sure we don't get duplicate PIN IDs */
		card->ctx->log_errors = 0;
		r = sc_pkcs15_find_pin_by_auth_id(p15card,
				&args->auth_id, &dummy);
		if (r != SC_ERROR_OBJECT_NOT_FOUND) {
			p15init_error("There already is a PIN with this ID.");
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

	info = (struct sc_pkcs15_pin_info *) calloc(1, sizeof(*info));
	*info = *pin;

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = SC_PKCS15_TYPE_AUTH_PIN;
	object->data = info;
	object->flags = 0x3; /* XXX */
	if (label)
		strncpy(object->label, label, sizeof(object->label));

	return sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_AODF, object);
}

/*
 * Prepare private key download, and initialize a prkdf entry
 */
static int
sc_pkcs15init_init_prkdf(struct sc_pkcs15init_prkeyargs *keyargs,
		sc_pkcs15_prkey_t *key, int keybits,
		struct sc_pkcs15_object **res_obj
		)
{
	struct sc_pkcs15_prkey_info *key_info;
	struct sc_pkcs15_object *object;
	const char	*label;
	unsigned int	usage;
	int		r = 0;

	if (!keybits && (keybits = prkey_bits(key)) < 0)
		return keybits;

	if (keyargs->id.len == 0) {
		p15init_error("No key ID set for this key.");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 1);
	}

	if ((label = keyargs->label) == NULL)
		label = "Private Key";

	key_info = (struct sc_pkcs15_prkey_info *) calloc(1, sizeof(*key_info));
	key_info->id = keyargs->id;
	key_info->usage = usage;
	key_info->native = 1;
	key_info->key_reference = 0;
	key_info->modulus_length = keybits;
	/* path set by card driver */

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = prkey_pkcs15_algo(key);
	object->data = key_info;
	object->flags = DEFAULT_PRKEY_FLAGS;
	object->auth_id = keyargs->auth_id;
	strncpy(object->label, label, sizeof(object->label));

	*res_obj = object;
	return r;
}

/*
 * Generate a new private key
 */
int
sc_pkcs15init_generate_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_prkeyargs *keyargs,
		unsigned int keybits,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15init_pubkeyargs pubkey_args;
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_prkey_info *key_info;
	int		r, index;

	/* For now, we support just RSA key pair generation */
	if (!check_key_compatibility(p15card, &keyargs->key,
		 keyargs->x509_usage,
		 keybits, SC_ALGORITHM_ONBOARD_KEY_GEN))
		return SC_ERROR_NOT_SUPPORTED;

	if (profile->ops->generate_key == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	/* Set the USER PIN reference from args */
	r = set_user_pin_from_authid(p15card, profile, &keyargs->auth_id);
	if (r < 0)
		return r;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Select a Key ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	if ((r = select_id(p15card, SC_PKCS15_TYPE_PRKEY, &keyargs->id)) < 0)
		return r;

	/* Set up the PrKDF object */
	if ((r = sc_pkcs15init_init_prkdf(keyargs, &keyargs->key, keybits, &object)) < 0)
		return r;
	key_info = (struct sc_pkcs15_prkey_info *) object->data;

	/* Set up the PuKDF info. The public key will be filled in
	 * by the card driver's generate_key function called below */
	memset(&pubkey_args, 0, sizeof(pubkey_args));
	pubkey_args.id = keyargs->id;
	pubkey_args.label = keyargs->label;
	pubkey_args.usage = keyargs->usage;
	pubkey_args.x509_usage = keyargs->x509_usage;

	/* Generate the private key on card */
	index = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0);
	r = profile->ops->generate_key(profile, p15card->card, index, keybits,
			&pubkey_args.key, key_info);

	/* update PrKDF entry */
	if (r >= 0) {
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_PRKDF, object);
	}
	if (r >= 0) {
		r = sc_pkcs15init_store_public_key(p15card, profile,
				&pubkey_args, NULL);
	}

	if (r >= 0 && res_obj)
		*res_obj = object;
	sc_pkcs15_erase_pubkey(&pubkey_args.key);

	return r;
}


/*
 * Store private key
 */
int
sc_pkcs15init_store_private_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_prkeyargs *keyargs,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_prkey_info *key_info;
	sc_pkcs15_prkey_t key;
	int		keybits, index, r = 0;

	/* Create a copy of the key first */
	key = keyargs->key;

	if ((r = prkey_fixup(&key)) < 0)
		return r;
	if ((keybits = prkey_bits(&key)) < 0)
		return keybits;

	/* Now check whether the card is able to handle this key */
	if (!check_key_compatibility(p15card, &key,
			keyargs->x509_usage, keybits, 0)) {
		/* Make sure the caller explicitly tells us to store
		 * the key non-natively. */
		if (!(keyargs->flags & SC_PKCS15INIT_EXTRACTABLE)) {
			p15init_error("Card does not support this key.");
			return SC_ERROR_INCOMPATIBLE_KEY;
		}
		if (!keyargs->passphrase
		 && !(keyargs->flags & SC_PKCS15INIT_NO_PASSPHRASE)) {
			p15init_error("No key encryption passphrase given.");
			return SC_ERROR_PASSPHRASE_REQUIRED;
		}
	}

	/* Set the USER PIN reference from args */
	r = set_user_pin_from_authid(p15card, profile, &keyargs->auth_id);
	if (r < 0)
		return r;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Select a Key ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	if (keyargs->id.len != 0
	 && (keyargs->flags & SC_PKCS15INIT_SPLIT_KEY)) {
		/* Split key; this ID exists already */
	} else
	if ((r = select_id(p15card, SC_PKCS15_TYPE_PRKEY, &keyargs->id)) < 0)
		return r;

	/* Set up the PrKDF object */
	r = sc_pkcs15init_init_prkdf(keyargs, &key, 0, &object);
	if (r < 0)
		return r;
	key_info = (struct sc_pkcs15_prkey_info *) object->data;

	/* Get the number of private keys already on this card */
	index = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0);
	if (!(keyargs->flags & SC_PKCS15INIT_EXTRACTABLE)) {
		r = profile->ops->new_key(profile, p15card->card,
				&key, index, key_info);
		if (r < 0)
			return r;
	} else {
		sc_pkcs15_der_t	encoded, wrapped, *der = &encoded;
		struct sc_context *ctx = p15card->card->ctx;

		key_info->native = 0;
		object->flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
		object->flags &= ~SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;

		/* DER encode the private key */
		encoded.value = wrapped.value = NULL;
		r = sc_pkcs15_encode_prkey(ctx, &key, &encoded.value, &encoded.len);
		if (r < 0)
			return r;

		if (keyargs->passphrase) {
			r = sc_pkcs15_wrap_data(ctx, keyargs->passphrase,
					der->value, der->len,
					&wrapped.value, &wrapped.len);
			if (r < 0) {
				free(der->value);
				return r;
			}
			der = &wrapped;
		}

		r = sc_pkcs15init_store_data(p15card, profile,
			SC_PKCS15_TYPE_PRKEY, der, &key_info->path);

		/* If the key is encrypted, flag the PrKDF entry as
		 * indirect-protected */
		if (keyargs->passphrase)
			key_info->path.type = SC_PATH_TYPE_PATH_PROT;

		free(encoded.value);
		free(wrapped.value);

		if (r < 0)
			return r;
	}

	/* Now update the PrKDF */
	r = sc_pkcs15init_add_object(p15card, profile,
			SC_PKCS15_PRKDF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	return r;
}

int
sc_pkcs15init_store_split_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_prkeyargs *keyargs,
		struct sc_pkcs15_object **prk1_obj,
		struct sc_pkcs15_object **prk2_obj)
{
	unsigned int    usage = keyargs->x509_usage;
	int		r;

	/* keyEncipherment|dataEncipherment|keyAgreement */
	keyargs->x509_usage = usage & 0x1C;
	r = sc_pkcs15init_store_private_key(p15card, profile,
				keyargs, prk1_obj);

	if (r >= 0) {
		/* digitalSignature|nonRepudiation|certSign|cRLSign */
		keyargs->x509_usage = usage & 0x63;

		/* Prevent pkcs15init from choking on duplicate ID */
		keyargs->flags |= SC_PKCS15INIT_SPLIT_KEY;
		r = sc_pkcs15init_store_private_key(p15card, profile,
					keyargs, prk2_obj);
	}

	keyargs->x509_usage = usage;
	return r;
}

/*
 * Store a public key
 */
int
sc_pkcs15init_store_public_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_pubkeyargs *keyargs,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_pubkey_info *key_info;
	sc_pkcs15_pubkey_t key;
	sc_pkcs15_der_t	der_encoded;
	sc_path_t 	*path;
	const char	*label;
	unsigned int	keybits, type, usage;
	int		r;

	/* Create a copy of the key first */
	key = keyargs->key;

	switch (key.algorithm) {
	case SC_ALGORITHM_RSA:
		keybits = sc_pkcs15init_keybits(&key.u.rsa.modulus);
		type = SC_PKCS15_TYPE_PUBKEY_RSA; break;
#ifdef SC_PKCS15_TYPE_PUBKEY_DSA
	case SC_ALGORITHM_DSA:
		keybits = sc_pkcs15init_keybits(&key.u.dsa.q);
		type = SC_PKCS15_TYPE_PUBKEY_DSA; break;
#endif
	default:
		p15init_error("Unsupported key algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Select a Key ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	if ((r = select_id(p15card, SC_PKCS15_TYPE_PUBKEY, &keyargs->id)) < 0)
		return r;

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 0);
	}
	if ((label = keyargs->label) == NULL)
		label = "Public Key";

	key_info = (struct sc_pkcs15_pubkey_info *) calloc(1, sizeof(*key_info));
	key_info->id = keyargs->id;
	key_info->usage = usage;
	key_info->modulus_length = keybits;

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = type;
	object->data = key_info;
	object->flags = DEFAULT_PUBKEY_FLAGS;
	strncpy(object->label, label, sizeof(object->label));

	/* DER encode public key components */
	r = sc_pkcs15_encode_pubkey(p15card->card->ctx, &key,
			&der_encoded.value, &der_encoded.len);
	if (r < 0)
		return r;

	/* Now create key file and store key */
	r = sc_pkcs15init_store_data(p15card, profile,
			type, &der_encoded, &key_info->path);

	path = &((struct sc_pkcs15_pubkey_info *) object->data)->path;
	if (path->count == 0) {
		path->index = 0;
		path->count = -1;
	}

	/* Update the PuKDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
			SC_PKCS15_PUKDF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	return r;
}

/*
 * Store a certificate
 */
int
sc_pkcs15init_store_certificate(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_certargs *args,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15_cert_info *cert_info;
	struct sc_pkcs15_object *object;
	unsigned int	usage;
	const char	*label;
	int		r;

	usage = SC_PKCS15_PRKEY_USAGE_SIGN;
	if (args->x509_usage)
		usage = sc_pkcs15init_map_usage(args->x509_usage, 0);
	if ((label = args->label) == NULL)
		label = "Certificate";

	/* Select an ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	if ((r = select_id(p15card, SC_PKCS15_TYPE_CERT, &args->id)) < 0)
		return r;

	/* If there is a private key corresponding to the ID given
	 * by the user, make sure $PIN references the pin protecting
	 * this key
	 */
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

	cert_info = (struct sc_pkcs15_cert_info *) calloc(1, sizeof(*cert_info));
	cert_info->id = args->id;
	cert_info->authority = args->authority;

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = SC_PKCS15_TYPE_CERT_X509;
	object->data = cert_info;
	object->flags = DEFAULT_CERT_FLAGS;
	strncpy(object->label, label, sizeof(object->label));

	r = sc_pkcs15init_store_data(p15card, profile,
			SC_PKCS15_TYPE_CERT_X509, &args->der_encoded,
			&cert_info->path);

	/* Now update the CDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_CDF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	return r;
}

/*
 * Store a data object
 */
int
sc_pkcs15init_store_data_object(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_dataargs *args,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15_data_info *data_object_info;
	struct sc_pkcs15_object *object;
	const char	*label;
	int		r;

	if ((label = args->label) == NULL)
		label = "Data Object";

	/* Select an ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	if ((r = select_id(p15card, SC_PKCS15_TYPE_DATA_OBJECT, &args->id)) < 0)
		return r;

	/* Set the USER PIN reference from args */
	r = set_user_pin_from_authid(p15card, profile, &args->auth_id);
	if (r < 0)
		return r;

#ifdef notused
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
					SC_PKCS15INIT_SO_PIN, pin_info);
		}
	}
#endif

	data_object_info = (struct sc_pkcs15_data_info *) calloc(1, sizeof(*data_object_info));
	data_object_info->id = args->id;
	if (args->app_label != NULL)
		strncpy(data_object_info->app_label, args->app_label,
			sizeof(data_object_info->app_label) - 1);
	data_object_info->app_oid = args->app_oid;

	object = (struct sc_pkcs15_object *) calloc(1, sizeof(*object));
	object->type = SC_PKCS15_TYPE_DATA_OBJECT;
	object->data = data_object_info;
	object->flags = DEFAULT_DATA_FLAGS;
	object->auth_id = args->auth_id;
	strncpy(object->label, label, sizeof(object->label));
	r = sc_pkcs15init_store_data(p15card, profile,
			SC_PKCS15_TYPE_DATA_OBJECT, &args->der_encoded,
			&data_object_info->path);

	/* Now update the DDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_DODF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	return r;
}

static int
sc_pkcs15init_store_data(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int type, sc_pkcs15_der_t *data,
		struct sc_path *path)
{
	struct sc_file	*file = NULL;
	unsigned int	index;
	int		r;

	/* Get the number of objects of this type already on this card */
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
	if (file->path.count == 0) {
		file->path.index = 0;
		file->path.count = -1;
	}
	r = sc_pkcs15init_update_file(profile, p15card->card,
			file, data->value, data->len);
	*path = file->path;

done:	if (file)
		sc_file_free(file);
	return r;
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
sc_pkcs15init_map_usage(unsigned long x509_usage, int _private)
{
	unsigned int	p15_usage, n, *bits;

	bits = _private? x509_to_pkcs15_private_key_usage
		      : x509_to_pkcs15_public_key_usage;
	for (n = p15_usage = 0; n < 16; n++) {
		if (x509_usage & (1 << n))
			p15_usage |= bits[n];
	}
	return p15_usage;
}

/*
 * Compute modulus length
 */
size_t
sc_pkcs15init_keybits(sc_pkcs15_bignum_t *bn)
{
	unsigned int	mask, bits;

	if (!bn || !bn->len)
		return 0;
	bits = bn->len << 3;
	for (mask = 0x80; !(bn->data[0] & mask); mask >>= 1)
		bits--;
	return bits;
}

/*
 * Check whether the card has native crypto support for this key.
 */
static int
__check_key_compatibility(struct sc_pkcs15_card *p15card,
			  struct sc_pkcs15_prkey *key,
			  unsigned int x509_usage,
			  unsigned int key_length,
			  unsigned int flags)
{
	struct sc_algorithm_info *info;
	unsigned int count;
	int bad_usage = 0;

	count = p15card->card->algorithm_count;
	for (info = p15card->card->algorithms; count--; info++) {
		/* XXX: check for equality, or <= ? */
		if (info->algorithm != key->algorithm
		 || info->key_length != key_length
		 || (info->flags & flags) != flags)
			continue;
		if (key->algorithm == SC_ALGORITHM_RSA
		 && info->u._rsa.exponent != 0) {
			sc_pkcs15_bignum_t *e = &key->u.rsa.exponent;
			unsigned long	exponent = 0;
			unsigned int	n;

			if (e->len > 4)
				continue;
			for (n = 0; n < e->len; n++) {
				exponent <<= 8;
				exponent |= e->data[n];
			}
			if (info->u._rsa.exponent != exponent)
				continue;
		}

		/* Some cards will not support keys to do
		 * both sign/decrypt.
		 * For the convenience of the user, catch these
		 * here. */
		if (info->flags & SC_ALGORITHM_NEED_USAGE) {
			unsigned int	usage;

			usage = sc_pkcs15init_map_usage(x509_usage, 1);
			if ((usage & (SC_PKCS15_PRKEY_USAGE_UNWRAP
				     |SC_PKCS15_PRKEY_USAGE_DECRYPT))
			 && (usage & SC_PKCS15_PRKEY_USAGE_SIGN)) {
				bad_usage = 1;
				continue;
			}
		}
		return 1;
	}

	return bad_usage? -1 : 0;
}

static int
check_key_compatibility(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15_prkey *key,
			unsigned int x509_usage,
			unsigned int key_length,
			unsigned int flags)
{
	int	res;

	res = __check_key_compatibility(p15card, key,
				x509_usage, key_length, flags);
	if (res < 0) {
		p15init_error("This device requires that keys have a "
			"specific key usage.\n"
			"Keys can be used for either signature or decryption, "
			"but not both.\n"
			"Please specify a key usage.\n");
		res = 0;
	}
	return res;
}

int
sc_pkcs15init_requires_restrictive_usage(struct sc_pkcs15_card *p15card,
			struct sc_pkcs15init_prkeyargs *keyargs,
			unsigned int key_length)
{
	int	res;

	if (key_length == 0)
		key_length = prkey_bits(&keyargs->key);

	res = __check_key_compatibility(p15card, &keyargs->key,
			 keyargs->x509_usage,
			 key_length, 0);
	return res < 0;
}

/*
 * Check RSA key for consistency, and compute missing
 * CRT elements
 */
int
prkey_fixup_rsa(struct sc_pkcs15_prkey_rsa *key)
{
	if (!key->modulus.len || !key->exponent.len
	 || !key->d.len || !key->p.len || !key->q.len) {
		p15init_error("Missing private RSA coefficient");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

#ifdef HAVE_OPENSSL
#define GETBN(dst, src, mem) \
	do {	dst.len = BN_num_bytes(src); \
		assert(dst.len <= sizeof(mem)); \
		BN_bn2bin(src, dst.data = mem); \
	} while (0)

	/* Generate additional parameters.
	 * At least the GPK seems to need the full set of CRT
	 * parameters; storing just the private exponent produces
	 * invalid signatures.
	 * The cryptoflex does not seem to be able to do any sort
	 * of RSA without the full set of CRT coefficients either
	 */
	if (!key->dmp1.len || !key->dmq1.len || !key->iqmp.len) {
		static u8 dmp1[256], dmq1[256], iqmp[256];
		RSA    *rsa;
		BIGNUM *aux = BN_new();
		BN_CTX *ctx = BN_CTX_new();

		rsa = RSA_new();
		rsa->n = BN_bin2bn(key->modulus.data, key->modulus.len, 0);
		rsa->e = BN_bin2bn(key->exponent.data, key->exponent.len, 0);
		rsa->d = BN_bin2bn(key->d.data, key->d.len, 0);
		rsa->p = BN_bin2bn(key->p.data, key->p.len, 0);
		rsa->q = BN_bin2bn(key->q.data, key->q.len, 0);
		if (!rsa->dmp1)
			rsa->dmp1 = BN_new();
		if (!rsa->dmq1)
			rsa->dmq1 = BN_new();
		if (!rsa->iqmp)
			rsa->iqmp = BN_new();

		aux = BN_new();
		ctx = BN_CTX_new();

		BN_sub(aux, rsa->q, BN_value_one());
		BN_mod(rsa->dmq1, rsa->d, aux, ctx);

		BN_sub(aux, rsa->p, BN_value_one());
		BN_mod(rsa->dmp1, rsa->d, aux, ctx);

		BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);

		BN_clear_free(aux);
		BN_CTX_free(ctx);

		/* Not thread safe, but much better than a memory leak */
		GETBN(key->dmp1, rsa->dmp1, dmp1);
		GETBN(key->dmq1, rsa->dmq1, dmq1);
		GETBN(key->iqmp, rsa->iqmp, iqmp);
		RSA_free(rsa);
	}
#undef GETBN
#endif
	return 0;
}

static int
prkey_fixup(sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return prkey_fixup_rsa(&key->u.rsa);
	case SC_ALGORITHM_DSA:
		/* for now */
		return 0;
	}
	return 0;
}

static int
prkey_bits(sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return sc_pkcs15init_keybits(&key->u.rsa.modulus);
	case SC_ALGORITHM_DSA:
		return sc_pkcs15init_keybits(&key->u.dsa.q);
	}
	p15init_error("Unsupported key algorithm.\n");
	return SC_ERROR_NOT_SUPPORTED;
}

static int
prkey_pkcs15_algo(sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return SC_PKCS15_TYPE_PRKEY_RSA;
	case SC_ALGORITHM_DSA:
		return SC_PKCS15_TYPE_PRKEY_DSA;
	}
	p15init_error("Unsupported key algorithm.\n");
	return SC_ERROR_NOT_SUPPORTED;
}

static struct sc_pkcs15_df *
find_df_by_type(struct sc_pkcs15_card *p15card, int type)
{
	struct sc_pkcs15_df *df = p15card->df_list;
	
	while (df != NULL && df->type != type)
		df = df->next;
	return df;
}

int
select_id(struct sc_pkcs15_card *p15card, int type, struct sc_pkcs15_id *id)
{
	unsigned int nid = DEFAULT_ID;
	struct sc_pkcs15_object *dummy;
	int r, user_provided;
	int (*func)(struct sc_pkcs15_card *,
			const struct sc_pkcs15_id *,
			struct sc_pkcs15_object **);

	switch (type) {
	case SC_PKCS15_TYPE_PRKEY:
		func = sc_pkcs15_find_prkey_by_id;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		func = sc_pkcs15_find_pubkey_by_id;
		break;
	case SC_PKCS15_TYPE_CERT:
		func = sc_pkcs15_find_cert_by_id;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		func = sc_pkcs15_find_data_object_by_id;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	user_provided = (id->len != 0);
	while (nid < 255) {
		if (!user_provided) {
			id->value[0] = nid++;
			id->len = 1;
		}
		r = func(p15card, id, &dummy);
		if (r == SC_ERROR_OBJECT_NOT_FOUND)
			return 0;
		if (user_provided)
			return SC_ERROR_ID_NOT_UNIQUE;
	}
	
	return SC_ERROR_TOO_MANY_OBJECTS;
}

/*
 * Update EF(DIR)
 */
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
sc_pkcs15init_add_object(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int df_type,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_df *df;
	struct sc_card	*card = p15card->card;
	struct sc_file	*file = NULL, *pfile;
	u8		*buf = NULL;
	size_t		bufsize;
	int		update_odf = 0, r = 0;

	df = find_df_by_type(p15card, df_type);
	if (df == NULL) {
		file = profile->df[df_type];
		if (file == NULL) {
			p15init_error("Profile doesn't define a DF file %u",
			 		df_type);
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_pkcs15_add_df(p15card, df_type, &file->path, file);
		df = find_df_by_type(p15card, df_type);
		assert(df != NULL);
		update_odf = 1;
	}

	if (object) {
		object->df = df;
		r = sc_pkcs15_add_object(p15card, object); 
		if (r < 0)
			return r;
	}

	
	if (!sc_profile_get_file_by_path(profile, &df->path, &pfile))
		file = pfile;

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
	if (r >= 0) {
		r = sc_pkcs15init_update_file(profile, card,
				file, buf, bufsize);
		free(buf);
	}
	if (pfile)
		sc_file_free(pfile);

	/* Now update the ODF if we have to */
	if (r >= 0 && update_odf)
		r = sc_pkcs15init_update_odf(p15card, profile);

	return r;
}

int
sc_pkcs15init_change_attrib(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		int new_attrib_type,
		void *new_value,
		int new_len)
{
	struct sc_card	*card = p15card->card;
	u8		*buf = NULL;
	size_t		bufsize;
	int		df_type, r = 0;
	struct sc_pkcs15_df *df;

	if (object == NULL || object->df == NULL)
		return SC_ERROR_OBJECT_NOT_FOUND;
	df_type = object->df->type;

	df = find_df_by_type(p15card, df_type);
	if (df == NULL)
		return SC_ERROR_OBJECT_NOT_FOUND;

	switch(new_attrib_type)
	{
	case P15_ATTR_TYPE_LABEL:
		if (new_len >= SC_PKCS15_MAX_LABEL_SIZE)
			return SC_ERROR_INVALID_ARGUMENTS;
		memcpy(object->label, new_value, new_len);
		object->label[new_len] = '\0';
		break;
	case P15_ATTR_TYPE_ID:
		switch(df_type) {
		case SC_PKCS15_PRKDF:
			((sc_pkcs15_prkey_info_t *) object->data)->id =
				*((sc_pkcs15_id_t *) new_value);
			break;
		case SC_PKCS15_PUKDF:
		case SC_PKCS15_PUKDF_TRUSTED:
			((sc_pkcs15_pubkey_info_t *) object->data)->id =
				*((sc_pkcs15_id_t *) new_value);
			break;
		case SC_PKCS15_CDF:
		case SC_PKCS15_CDF_TRUSTED:
		case SC_PKCS15_CDF_USEFUL:
			((sc_pkcs15_cert_info_t *) object->data)->id =
				*((sc_pkcs15_id_t *) new_value);
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
	if (r >= 0) {
		r = sc_pkcs15init_update_file(profile, card,
				df->file, buf, bufsize);
		free(buf);
	}

	return r < 0 ? r : 0;
}

void
sc_pkcs15init_set_pin_data(struct sc_profile *profile, int pin_id,
				const void *value, size_t len)
{
	sc_profile_set_secret(profile, SC_AC_SYMBOLIC, pin_id, (const u8 *) value, len);
}

/*
 * PIN verification
 */
int
do_get_and_verify_secret(struct sc_profile *pro, struct sc_card *card,
		int type, int reference,
		u8 *pinbuf, size_t *pinsize,
		int verify)
{
	struct sc_pkcs15_pin_info pin_info;
	struct sc_cardctl_default_key data;
	const char	*ident, *label = NULL;
	unsigned int	pin_id = (unsigned int) -1;
	size_t		defsize = 0;
	u8		defbuf[32];
	int		r;

	ident = "authentication data";
	if (type == SC_AC_CHV) {
		sc_pkcs15_object_t *pin_obj;

		ident = "PIN";
		memset(&pin_info, 0, sizeof(pin_info));
		if (sc_profile_get_pin_id(pro, reference, &pin_id) >= 0) {
			sc_profile_get_pin_info(pro, pin_id, &pin_info);
		} else
		if (pro->p15_card
		 && sc_pkcs15_find_pin_by_reference(pro->p15_card, reference, &pin_obj) == 0) {
			memcpy(&pin_info, pin_obj->data, sizeof(pin_info));
		} else {
			/* This is all info we have */
			pin_info.reference = reference;
		}
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

		/* If reference is -1, this means the card issuer
		 * didn't set this PIN */
		if (reference == -1)
			return 0;
	}

	/* Try to get the cached secret, e.g. CHV1 */
	r = sc_profile_get_secret(pro, type, reference, pinbuf, pinsize);
	if (r >= 0)
		goto found;

	/* If this secret is linked to a symbolic PIN, e.g. SOPIN1,
	 * see if we've cached it under that name */
	if (pin_id != -1) {
		r = sc_profile_get_secret(pro, SC_AC_SYMBOLIC, pin_id,
				pinbuf, pinsize);
		if (r >= 0)
			goto found;
	}

	if (type != SC_AC_CHV) {
		/* Okay, nothing in our cache.
		 * Ask the card driver whether it knows a default key
		 * for this one.
		 */
		data.method = type;
		data.key_ref = reference;
		data.len = sizeof(defbuf);
		data.key_data = defbuf;
		if (sc_card_ctl(card, SC_CARDCTL_GET_DEFAULT_KEY, &data) >= 0)
			defsize = data.len;
	} else if (pro->p15_card) {
		/* Get the label, if we have one */
		struct sc_pkcs15_object *obj;
		int r;

		r = sc_pkcs15_find_pin_by_reference(pro->p15_card,
					reference, &obj);
		if (r >= 0 && obj->label[0])
			label = obj->label;
	}

	if (callbacks) {
		switch (type) {
		case SC_AC_CHV:
			if (callbacks->get_pin) {
				r = callbacks->get_pin(pro, pin_id,
						&pin_info, label,
						pinbuf, pinsize);
			}
			break;
		default:
			if (callbacks->get_key) {
				r = callbacks->get_key(pro, type, reference,
						defbuf, defsize,
						pinbuf, pinsize);
			}
			break;
		}
	}

	if (r < 0)
		return r;

found:	/* We got something. Cache it */
	sc_profile_set_secret(pro, type, reference, pinbuf, *pinsize);

	/* If it's a PIN, pad it out */
	if (type == SC_AC_CHV) {
		int left = pro->pin_maxlen - *pinsize;

		if (left > 0) {
			memset(pinbuf + *pinsize, pro->pin_pad_char, left);
			*pinsize = pro->pin_maxlen;
		}
		/* If it's associated with a symbolic PIN, store it under
		 * the symbolic name as well */
		if (pin_id != -1)
			sc_profile_set_secret(pro, SC_AC_SYMBOLIC, pin_id,
						pinbuf, *pinsize);
	}

	if (verify
	 && (r = sc_verify(card, type, reference, pinbuf, *pinsize, 0)) < 0) {
		p15init_error("Failed to verify %s (ref=0x%x)",
				ident, reference);
	}

	return r;
}

static int
do_verify_pin(struct sc_profile *pro, struct sc_card *card,
		unsigned int type, unsigned int reference)
{
	size_t		pinsize;
	u8		pinbuf[32];

	pinsize = sizeof(pinbuf);
	return do_get_and_verify_secret(pro, card, type, reference,
			pinbuf, &pinsize, 1);
}

void
sc_pkcs15init_set_secret(struct sc_profile *pro,
			int type, int reference,
			u8 *key, size_t len)
{
	sc_profile_set_secret(pro, type, reference, key, len);
}

int
sc_pkcs15init_get_secret(struct sc_profile *pro, struct sc_card *card,
		int type, int reference,
		u8 *pinbuf, size_t *pinsize)
{
	return do_get_and_verify_secret(pro, card, type, reference,
			pinbuf, pinsize, 0);
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
 * If the user specified an auth_id, select the corresponding
 * PIN entry and set the reference data
 */
static int
set_user_pin_from_authid(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15_id *auth_id)
{
	struct sc_pkcs15_object	*objp;
	int		r;

	if (auth_id->len == 0)
		return 0;

	r = sc_pkcs15_find_pin_by_auth_id(p15card, auth_id, &objp);
	if (r < 0)
		return r;

	sc_profile_set_pin_info(profile, SC_PKCS15INIT_USER_PIN,
			(struct sc_pkcs15_pin_info *) objp->data);
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

	/* Select the parent DF. */
	*parent = NULL;
	card->ctx->log_errors = 0;
	r = sc_select_file(card, &path, parent);
	card->ctx->log_errors = 1;
	/* If DF doesn't exist, create it (unless it's the MF,
	 * but then something's badly broken anyway :-) */
	if (r == SC_ERROR_FILE_NOT_FOUND && path.len != 2) {
		r = sc_profile_get_file_by_path(pro, &path, parent);
		if (r < 0) {
			char	buffer[SC_MAX_PATH_SIZE*2+1];
			size_t	n;

			buffer[0] = '\0';
			for (n = 0; n < path.len; n++)
				sprintf(buffer+2*n, "%02x", path.value[n]);
			p15init_error("profile doesn't define a DF %s");
			return r;
		}
		if (!(r = sc_pkcs15init_create_file(pro, card, *parent)))
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
	struct sc_file	*info = NULL;
	int		r;

	card->ctx->log_errors = 0;
	if ((r = sc_select_file(card, &file->path, &info)) < 0) {
		card->ctx->log_errors = 1;
		/* Create file if it doesn't exist */
		if (file->size < datalen)
			file->size = datalen;
		if (r != SC_ERROR_FILE_NOT_FOUND
		 || (r = sc_pkcs15init_create_file(profile, card, file)) < 0
		 || (r = sc_select_file(card, &file->path, &info)) < 0)
			return r;
	}
	card->ctx->log_errors = 1;

	if (info->size < datalen) {
		char	buf[16];

		sc_bin_to_hex(file->path.value, file->path.len, buf, sizeof(buf), 0);
		p15init_error("File %s too small - please increase size in profile", buf);
		sc_file_free(info);
		return SC_ERROR_TOO_MANY_OBJECTS;
	}

	/* Present authentication info needed */
	r = sc_pkcs15init_authenticate(profile, card, file, SC_AC_OP_UPDATE);
	if (r >= 0 && datalen)
		r = sc_update_binary(card, 0, (const u8 *) data, datalen, 0);

	sc_file_free(info);
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

#if 0
	/* If we haven't got a user pin, barf */
	user_acl.method = SC_AC_CHV;
	user_acl.key_ref = user_pin.reference;
#else
	/* Not setting a user pin is legitimate. */
	user_acl.method = SC_AC_CHV;
	user_acl.key_ref = user_pin.reference;
	if (user_acl.key_ref == -1) {
		user_acl.method = SC_AC_NONE;
		user_acl.key_ref = 0;
	}
#endif

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
