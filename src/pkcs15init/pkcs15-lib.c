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
#include <time.h>
#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif
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
#include <ltdl.h>
#include <opensc/pkcs15.h>
#include "profile.h"
#include "pkcs15-init.h"
#include <opensc/cardctl.h>
#include <opensc/log.h>

#define OPENSC_INFO_FILEPATH		"3F0050154946"
#define OPENSC_INFO_FILEID		0x4946
#define OPENSC_INFO_TAG_PROFILE		0x01
#define OPENSC_INFO_TAG_OPTION		0x02

/* Default ID for new key/pin */
#define DEFAULT_ID			0x45
#define DEFAULT_PIN_FLAGS		0x03
#define DEFAULT_PRKEY_ACCESS_FLAGS	0x1d
#define DEFAULT_PRKEY_FLAGS		0x03
#define DEFAULT_PUBKEY_FLAGS		0x02
#define DEFAULT_CERT_FLAGS		0x02
#define DEFAULT_DATA_FLAGS		0x02

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(sc_context_t *,
			struct sc_pkcs15_card *, u8 **, size_t *);

static int	sc_pkcs15init_store_data(struct sc_pkcs15_card *,
			struct sc_profile *, sc_pkcs15_object_t *,
			sc_pkcs15_id_t *,
			sc_pkcs15_der_t *, sc_path_t *);
static size_t	sc_pkcs15init_keybits(sc_pkcs15_bignum_t *);

static int	sc_pkcs15init_update_dir(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			sc_app_info_t *app);
static int	sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_odf(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int  sc_pkcs15init_update_any_df(sc_pkcs15_card_t *p15card,
			sc_profile_t *profile, 
			sc_pkcs15_df_t *df, int is_new);
static sc_pkcs15_object_t *sc_pkcs15init_new_object(int type, const char *label,
	       		sc_pkcs15_id_t *auth_id, void *data);
static int	sc_pkcs15init_add_object(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			unsigned int df_type,
			struct sc_pkcs15_object *);
static int	sc_pkcs15init_remove_object(sc_pkcs15_card_t *,
			sc_profile_t *, sc_pkcs15_object_t *);
static int	sc_pkcs15init_map_usage(unsigned long, int);
static int	set_so_pin_from_card(struct sc_pkcs15_card *,
			struct sc_profile *);
static int	set_user_pin_from_authid(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15_id *);
static int	do_select_parent(struct sc_profile *, sc_card_t *,
			sc_file_t *, sc_file_t **);
static int	sc_pkcs15init_create_pin(sc_pkcs15_card_t *, sc_profile_t *,
			sc_pkcs15_object_t *, struct sc_pkcs15init_pinargs *);
static int	check_key_compatibility(struct sc_pkcs15_card *,
			struct sc_pkcs15_prkey *, unsigned int,
			unsigned int, unsigned int);
static int	prkey_fixup(sc_pkcs15_card_t *, sc_pkcs15_prkey_t *);
static int	prkey_bits(sc_pkcs15_card_t *, sc_pkcs15_prkey_t *);
static int	prkey_pkcs15_algo(sc_pkcs15_card_t *, sc_pkcs15_prkey_t *);
static int	select_id(sc_pkcs15_card_t *, int, sc_pkcs15_id_t *,
			int (*)(const sc_pkcs15_object_t *, void *), void *,
			sc_pkcs15_object_t **);
static int	select_object_path(sc_pkcs15_card_t *, sc_profile_t *,
			sc_pkcs15_object_t *, sc_pkcs15_id_t *, sc_path_t *);
static int	sc_pkcs15init_get_pin_path(sc_pkcs15_card_t *,
			sc_pkcs15_id_t *, sc_path_t *);
static int	sc_pkcs15init_qualify_pin(sc_card_t *, const char *,
	       		unsigned int, sc_pkcs15_pin_info_t *);
static struct sc_pkcs15_df * find_df_by_type(struct sc_pkcs15_card *,
			unsigned int);
static int	sc_pkcs15init_read_info(sc_card_t *card, sc_profile_t *);
static int	sc_pkcs15init_parse_info(sc_card_t *, const u8 *, size_t, sc_profile_t *);
static int	sc_pkcs15init_write_info(sc_card_t *card, sc_profile_t *,
			sc_pkcs15_object_t *pin_obj);

static struct profile_operations {
	const char *name;
	void *func;
} profile_operations[] = {
	{ "gpk", (void *) sc_pkcs15init_get_gpk_ops },
	{ "miocos", (void *) sc_pkcs15init_get_miocos_ops },
	{ "flex", (void *) sc_pkcs15init_get_cryptoflex_ops },
	{ "cyberflex", (void *) sc_pkcs15init_get_cyberflex_ops },
	{ "etoken", (void *) sc_pkcs15init_get_etoken_ops },
	{ "jcop", (void *) sc_pkcs15init_get_jcop_ops },
	{ "starcos", (void *) sc_pkcs15init_get_starcos_ops },
	{ "oberthur", (void *) sc_pkcs15init_get_oberthur_ops },
	{ "setcos", (void *) sc_pkcs15init_get_setcos_ops },
	{ NULL, NULL },
};

static struct sc_pkcs15init_callbacks callbacks = {
	NULL,
	NULL,
};

/*
 * Set the application callbacks
 */
void
sc_pkcs15init_set_callbacks(struct sc_pkcs15init_callbacks *cb)
{
	callbacks.get_pin = cb? cb->get_pin : NULL;
	callbacks.get_key = cb? cb->get_key : NULL;
}

/*
 * Returns 1 if the a profile was found in the card's card_driver block
 * in the config file, or 0 otherwise.
 */
static int
get_profile_from_config(sc_card_t *card, char *buffer, size_t size)
{
	sc_context_t *ctx = card->ctx;
	const char *tmp;
	scconf_block **blocks, *blk;
	int i;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					"card_driver",
					card->driver->short_name);
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;

		tmp = scconf_get_str(blk, "profile", NULL);
		if (tmp != NULL) {
			strncpy(buffer, tmp, size);
			buffer[size-1] = '\0';
			return 1;
		}
	}

	return 0;
}


static const char *find_library(sc_context_t *ctx, const char *name)
{
	int          i;
	const char   *libname = NULL;
	scconf_block *blk, **blocks;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
			"framework", "pkcs15");
                blk = blocks[0];
                free(blocks);
                if (blk == NULL)
                        continue;
		blocks = scconf_find_blocks(ctx->conf, blk, "pkcs15init", name);
		blk = blocks[0];
                free(blocks);
                if (blk == NULL)
                        continue;
                libname = scconf_get_str(blk, "module", NULL);
                break;
        }
	if (!libname) {
		sc_debug(ctx, "unable to locate pkcs15init driver for '%s'\n", name);
	}
	return libname;
}

static void *load_dynamic_driver(sc_context_t *ctx, void **dll,
	const char *name)
{
	const char *version, *libname;
	lt_dlhandle handle;
	void *(*modinit)(const char *)  = NULL;
	const char *(*modversion)(void) = NULL;

	libname = find_library(ctx, name);
	if (!libname)
		return NULL;
	handle = lt_dlopen(libname);
	if (handle == NULL) {
		sc_error(ctx, "Module %s: cannot load '%s' library: %s\n", name, libname, lt_dlerror());
		return NULL;
	}

	/* verify correctness of module */
	modinit    = (void *(*)(const char *)) lt_dlsym(handle, "sc_module_init");
	modversion = (const char *(*)(void)) lt_dlsym(handle, "sc_driver_version");
	if (modinit == NULL || modversion == NULL) {
		sc_error(ctx, "dynamic library '%s' is not a OpenSC module\n",libname);
		lt_dlclose(handle);
		return NULL;
	}
	/* verify module version */
	version = modversion();
	if (version == NULL || strncmp(version, "0.9.", strlen("0.9.")) > 0) {
		sc_error(ctx,"dynamic library '%s': invalid module version\n",libname);
		lt_dlclose(handle);
		return NULL;
	}
	*dll = handle;
	sc_debug(ctx, "successfully loaded pkcs15init driver '%s'\n", name);

	return modinit(name);
}

/*
 * Set up profile
 */
int
sc_pkcs15init_bind(sc_card_t *card, const char *name,
		const char *profile_option,
		struct sc_profile **result)
{
	struct sc_profile *profile;
	struct sc_pkcs15init_operations * (* func)(void) = NULL;
	const char	*driver = card->driver->short_name;
	char		card_profile[PATH_MAX];
	int		r, i;

	/* Put the card into administrative mode */
	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0 && r != SC_ERROR_NOT_SUPPORTED)
		return r;

	profile = sc_profile_new();
	profile->card = card;
	profile->cbs = &callbacks;

	for (i = 0; profile_operations[i].name; i++) {
		if (!strcasecmp(driver, profile_operations[i].name)) {
			func = (struct sc_pkcs15init_operations *(*)(void)) profile_operations[i].func;
			break;
		}
	}
	if (!func) {
		/* no builtin support for this driver => look if there's a
		 * dynamic module for this card */
		func = (struct sc_pkcs15init_operations *(*)(void)) load_dynamic_driver(card->ctx, &profile->dll, driver);
	}
	if (func) {
		profile->ops = func();
	} else {
		sc_error(card->ctx, "Unsupported card driver %s", driver);
		sc_profile_free(profile);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Massage the main profile name to see if there are
	 * any options in there
	 */
	profile->name = strdup(name);
	if (strchr(profile->name, '+') != NULL) {
		char	*s;

		i = 0;
		(void) strtok(profile->name, "+");
		while ((s = strtok(NULL, "+")) != NULL) {
			if (i < SC_PKCS15INIT_MAX_OPTIONS-1)
				profile->options[i++] = strdup(s);
		}
	}

	if ((r = sc_pkcs15init_read_info(card, profile)) < 0) {
		sc_profile_free(profile);
		return r;
	}

	/* Check the config file for a profile name. 
	 * If none is defined, use the default profile name.
	 */
	if (!get_profile_from_config(card, card_profile, sizeof(card_profile)))
		strcpy(card_profile, driver);
	if (profile_option != NULL) {
		strncpy(card_profile, profile_option, sizeof(card_profile));
		card_profile[sizeof(card_profile) - 1] = '\0';
	}

	if ((r = sc_profile_load(profile, profile->name)) < 0
	 || (r = sc_profile_load(profile, card_profile)) < 0
	 || (r = sc_profile_finish(profile)) < 0) {
		sc_error(card->ctx, "Failed to load profile: %s\n", sc_strerror(r));
		sc_profile_free(profile);
		return r;
	}

	*result = profile;
	return r;
}

void
sc_pkcs15init_unbind(struct sc_profile *profile)
{
	int r;
	struct sc_context *ctx = profile->card->ctx;

	if (profile->dirty != 0 && profile->p15_data != NULL && profile->pkcs15.do_last_update) {
		r = sc_pkcs15init_update_tokeninfo(profile->p15_data, profile);
		if (r < 0)
			sc_error(ctx, "Failed to update TokenInfo: %s\n", sc_strerror(r));
	}
	if (profile->dll)
		lt_dlclose(profile->dll);
	sc_profile_free(profile);
}

void
sc_pkcs15init_set_p15card(sc_profile_t *profile,
		sc_pkcs15_card_t *p15card)
{
	profile->p15_data = p15card;
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
sc_pkcs15init_erase_card(sc_card_t *card, struct sc_profile *profile)
{
	if (profile->ops->erase_card == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return profile->ops->erase_card(profile, card);
}

int
sc_pkcs15init_erase_card_recursively(sc_card_t *card, 
		struct sc_profile *profile,
		int so_pin_ref)
{
	struct sc_pkcs15_card *p15orig = profile->p15_data;
	struct sc_file	*df = profile->df_info->file, *dir;
	int		r;

	/* Make sure we set the SO PIN reference in the key cache */
	if (sc_keycache_find_named_pin(NULL, SC_PKCS15INIT_SO_PIN) == -1) {
		struct sc_pkcs15_card *p15card = NULL;

		card->ctx->suppress_errors++;
		if (sc_pkcs15_bind(card, &p15card) >= 0) {
			set_so_pin_from_card(p15card, profile);
			profile->p15_data = p15card;
		}
		card->ctx->suppress_errors--;
	}

	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete it before the DF because we create
	 * it *after* the DF. Some cards (e.g. the cryptoflex) want
	 * us to delete files in reverse order of creation.
	 * */
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		r = sc_pkcs15init_rmdir(card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)
			goto out;
	}

	card->ctx->suppress_errors++;
	r = sc_select_file(card, &df->path, &df);
	card->ctx->suppress_errors--;
	if (r >= 0) {
		r = sc_pkcs15init_rmdir(card, profile, df);
		sc_file_free(df);
	}
	if (r == SC_ERROR_FILE_NOT_FOUND)
		r = 0;

out:	/* Forget any cached keys, the objects on card are all gone. */
	sc_keycache_forget_key(NULL, -1, -1);

	sc_free_apps(card);
	if (profile->p15_data != p15orig) {
		sc_pkcs15_unbind(profile->p15_data);
		profile->p15_data = p15orig;
	}
	return r;
}

int sc_pkcs15init_delete_by_path(struct sc_profile *profile,
		struct sc_card *card, const sc_path_t *file_path)
{
	sc_file_t *parent, *file;
	sc_path_t path;
	int r;

	if (file_path->len >= 2) {
		/* Select the parent DF */
		path = *file_path;
		path.len -= 2;
		r = sc_select_file(card, &path, &parent);
		if (r < 0)
			return r;

		r = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
		sc_file_free(parent);
		if (r < 0)
			return r;
	}

	/* Select the file itself */
	path = *file_path;
	r = sc_select_file(card, &path, &file);
	if (r < 0)
		return r;

	r = sc_pkcs15init_authenticate(profile, card, file, SC_AC_OP_ERASE);
	sc_file_free(file);
	if (r < 0) 
		return r;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = file_path->value[file_path->len - 2];
	path.value[1] = file_path->value[file_path->len - 1];
	path.len = 2;

	r = sc_delete_file(card, &path);
	return r;
}

/*
 * Try to delete a file (and, in the DF case, its contents).
 * Note that this will not work if a pkcs#15 file's ERASE AC
 * references a pin other than the SO pin.
 */
int
sc_pkcs15init_rmdir(sc_card_t *card, struct sc_profile *profile,
		sc_file_t *df)
{
	u8		buffer[1024];
	struct sc_path	path;
	struct sc_file	*file, *parent;
	int		r = 0, nfids;

	sc_debug(card->ctx, "sc_pkcs15init_rmdir(%s)\n",
			sc_print_path(&df->path));

	if (df == NULL)
		return SC_ERROR_INTERNAL;
	if (df->type == SC_FILE_TYPE_DF) {
		r = sc_pkcs15init_authenticate(profile, card, df,
				SC_AC_OP_LIST_FILES);
		if (r < 0)
			return r;
		card->ctx->suppress_errors++;
		r = sc_list_files(card, buffer, sizeof(buffer));
		card->ctx->suppress_errors--;
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

	r = sc_pkcs15init_authenticate(profile, card, df, SC_AC_OP_DELETE);
	if (r < 0) {
		sc_file_free(parent);
		return r;
	}
	r = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	if (r < 0)
		return r;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	card->ctx->suppress_errors++;
	r = sc_delete_file(card, &path);
	card->ctx->suppress_errors--;
	return r;
}

int
sc_pkcs15init_finalize_card(sc_card_t *card, struct sc_profile *profile)
{
	if (profile->ops->finalize_card == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return profile->ops->finalize_card(card);
}

/*
 * Initialize the PKCS#15 application
 */
int
sc_pkcs15init_add_app(sc_card_t *card, struct sc_profile *profile,
		struct sc_pkcs15init_initargs *args)
{
	sc_pkcs15_card_t	*p15spec = profile->p15_spec;
	sc_pkcs15_pin_info_t	pin_info, puk_info;
	sc_pkcs15_object_t	*pin_obj = NULL;
	sc_app_info_t	*app;
	sc_file_t		*df = profile->df_info->file;
	int			r;

	p15spec->card = card;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &puk_info);
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &puk_info);

	if (card->app_count >= SC_MAX_CARD_APPS) {
		sc_error(card->ctx, "Too many applications on this card.");
		return SC_ERROR_TOO_MANY_OBJECTS;
	}

	/* If the profile requires an SO PIN, check min/max length */
	if (args->so_pin_len) {
		const char	*pin_label;

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info);
		r = sc_pkcs15init_qualify_pin(card, "SO PIN", args->so_pin_len, &pin_info);
		if (r < 0)
			return r;

		/* Select the PIN reference */
		pin_info.path = df->path;
		if (profile->ops->select_pin_reference) {
			r = profile->ops->select_pin_reference(profile,
					card, &pin_info);
			if (r < 0)
				return r;

			if (pin_info.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				sc_keycache_set_pin_name(&pin_info.path,
					pin_info.reference,
					SC_PKCS15INIT_SO_PIN);
			else
				sc_keycache_set_pin_name(&pin_info.path,
					pin_info.reference,
					SC_PKCS15INIT_USER_PIN);
		}

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &puk_info);
		r = sc_pkcs15init_qualify_pin(card, "SO PUK", args->so_puk_len, &puk_info);
		if (r < 0)
			return r;

		if (!(pin_label = args->so_pin_label)) {
			if (pin_info.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				pin_label = "Security Officer PIN";
			else
				pin_label = "User PIN";
		}

		if (args->so_puk_len == 0)
			pin_info.flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED;

		pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN, 
						pin_label, NULL,
					       	&pin_info);
	}

	/* Perform card-specific initialization */
	if (profile->ops->init_card
	 && (r = profile->ops->init_card(profile, card)) < 0) {
		sc_profile_free(profile);
		return r;
	}

	/* Create the application DF and store the PINs */
	if (profile->ops->create_dir) {
		/* Create the directory */
		r = profile->ops->create_dir(profile, card, df);

		/* Set the SO PIN */
		if (r >= 0 && pin_obj) {
			r = profile->ops->create_pin(profile, card,
					df, pin_obj,
					args->so_pin, args->so_pin_len,
					args->so_puk, args->so_puk_len);
		}
	} else {
		/* Old style API */
		r = profile->ops->init_app(profile, card, &pin_info,
				args->so_pin, args->so_pin_len,
				args->so_puk, args->so_puk_len);
	}
	if (r < 0)
		return r;

	/* Put the new SO pin in the key cache (note: in case
	 * of the "onepin" profile store it as a normal pin) */
	if (args->so_pin_len && !(pin_info.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
		sc_keycache_put_key(&df->path,
			SC_AC_SYMBOLIC,
			SC_PKCS15INIT_USER_PIN,
			args->so_pin,
			args->so_pin_len);
	else
		sc_keycache_put_key(&df->path,
			SC_AC_SYMBOLIC,
			SC_PKCS15INIT_SO_PIN,
			args->so_pin,
			args->so_pin_len);

	/* Store the PKCS15 information on the card
	 * We cannot use sc_pkcs15_create() because it makes
	 * all sorts of assumptions about DF and EF names, and
	 * doesn't work if secure messaging is required for the
	 * MF (which is the case with the GPK) */
	app = (sc_app_info_t *) calloc(1, sizeof(*app));
	if (app == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	app->path = p15spec->file_app->path;
	if (p15spec->file_app->namelen <= SC_MAX_AID_SIZE) {
		app->aid_len = p15spec->file_app->namelen;
		memcpy(app->aid, p15spec->file_app->name, app->aid_len);
	}
	/* set serial number if explicitly specified */
	if (args->serial)
		sc_pkcs15init_set_serial(profile, args->serial);
	else {
		/* otherwise try to get the serial number from the card */
		sc_serial_number_t serialnr;
		r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr);
		if (r == SC_SUCCESS) {
			char hex_serial[SC_MAX_SERIALNR * 2 + 1];
			sc_bin_to_hex(serialnr.value, serialnr.len,
				hex_serial, sizeof(hex_serial), 0);
			sc_pkcs15init_set_serial(profile, hex_serial);
		}
	}

	if (args->label) {
		if (p15spec->label)
			free(p15spec->label);
		p15spec->label = strdup(args->label);
	}
	app->label = strdup(p15spec->label);

	/* XXX: encode the DDO? */

	/* See if we've set an SO PIN */
	if (pin_obj) {
		r = sc_pkcs15init_add_object(p15spec, profile,
			       	SC_PKCS15_AODF, pin_obj);
	} else {
		r = sc_pkcs15init_add_object(p15spec, profile,
				SC_PKCS15_AODF, NULL);
	}

	if (r >= 0)
		r = sc_pkcs15init_update_dir(p15spec, profile, app);
	if (r >= 0)
		r = sc_pkcs15init_update_tokeninfo(p15spec, profile);

	card->ctx->suppress_errors++;
	sc_pkcs15init_write_info(card, profile, pin_obj);
	card->ctx->suppress_errors--;
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
	sc_card_t		*card = p15card->card;
	sc_pkcs15_object_t	*pin_obj;
	sc_pkcs15_pin_info_t	*pin_info;
	int			r, idx;

	/* No auth_id given: select one */
	if (args->auth_id.len == 0) {
		struct sc_pkcs15_object *dummy;
		unsigned int	n;

		args->auth_id.len = 1;
		card->ctx->suppress_errors++;
		for (n = 1, r = 0; n < 256; n++) {
			args->auth_id.value[0] = n;
			r = sc_pkcs15_find_pin_by_auth_id(p15card,
					&args->auth_id, &dummy);
			if (r == SC_ERROR_OBJECT_NOT_FOUND)
				break;
		}
		card->ctx->suppress_errors--;
		if (r != SC_ERROR_OBJECT_NOT_FOUND) {
			sc_error(card->ctx, "No auth_id specified for new PIN");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	} else {
		struct sc_pkcs15_object *dummy;

		/* Make sure we don't get duplicate PIN IDs */
		card->ctx->suppress_errors++;
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &args->auth_id, &dummy);
		card->ctx->suppress_errors--;
		if (r != SC_ERROR_OBJECT_NOT_FOUND) {
			sc_error(card->ctx, "There already is a PIN with this ID.");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}

	pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN,
				args->label, NULL, NULL);
	if (pin_obj == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	pin_info = (sc_pkcs15_pin_info_t *) pin_obj->data;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, pin_info);
	pin_info->auth_id = args->auth_id;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Now store the PINs */
	if (profile->ops->create_pin) {
		r = sc_pkcs15init_create_pin(p15card, profile, pin_obj, args);
	} else {
		/* Get the number of PINs we already have */
		idx = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH,
					NULL, 0);

		r = profile->ops->new_pin(profile, card, pin_info, idx,
				args->pin, args->pin_len,
				args->puk, args->puk_len);
	}

	/* Fix up any ACLs referring to the user pin */
	if (r >= 0) {
		sc_keycache_set_pin_name(&pin_info->path,
				pin_info->reference,
				SC_PKCS15INIT_USER_PIN);
	}

	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
			       	SC_PKCS15_AODF, pin_obj);

	profile->dirty = 1;

	return r;
}

static int
sc_pkcs15init_create_pin(sc_pkcs15_card_t *p15card, sc_profile_t *profile,
		sc_pkcs15_object_t *pin_obj,
		struct sc_pkcs15init_pinargs *args)
{
	sc_pkcs15_pin_info_t *pin_info = (sc_pkcs15_pin_info_t *) pin_obj->data;
	sc_card_t	*card = p15card->card;
	sc_file_t	*df = profile->df_info->file;
	int		r, retry = 0;

	/* Some cards need to keep all their PINs in separate directories.
	 * Create a subdirectory now, and put the pin into
	 * this subdirectory
	 */
	if (profile->pin_domains) {
		if (!profile->ops->create_domain) {
			sc_error(card->ctx, "PIN domains not supported.");
			return SC_ERROR_NOT_SUPPORTED;
		}
		r = profile->ops->create_domain(profile, card,
				&pin_info->auth_id, &df);
		if (r < 0)
			return r;
	}

	pin_info->path = df->path;
	pin_info->reference = 0;

	/* Loop until we come up with an acceptable pin reference */
	while (1) {
		sc_pkcs15_object_t *dummy;

		if (profile->ops->select_pin_reference) {
			r = profile->ops->select_pin_reference(profile, card, pin_info);
			if (r < 0)
				return r;
			retry = 1;
		}

		r = sc_pkcs15_find_pin_by_reference(p15card,
				&pin_info->path,
				pin_info->reference, &dummy);
		if (r == SC_ERROR_OBJECT_NOT_FOUND)
			break;

		if (r != 0 || !retry) {
			/* Other error trying to retrieve pin obj */
			sc_error(card->ctx, "Failed to allocate PIN reference.");
			return SC_ERROR_TOO_MANY_OBJECTS;
		}

		pin_info->reference++;
	}

	sc_keycache_set_pin_name(&pin_info->path, pin_info->reference,
			SC_PKCS15INIT_USER_PIN);

	if (args->puk_len == 0)
		pin_info->flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED;

	r = profile->ops->create_pin(profile, card,
			df, pin_obj,
			args->pin, args->pin_len,
			args->puk, args->puk_len);

	if (df != profile->df_info->file)
		sc_file_free(df);
	return r;
}

/*
 * Default function for creating a pin subdirectory
 */
int
sc_pkcs15_create_pin_domain(sc_profile_t *profile, sc_card_t *card,
		const sc_pkcs15_id_t *id, sc_file_t **ret)
{
	sc_file_t *df = profile->df_info->file;
	int	r;

	/* Instantiate PIN directory just below the application DF */
	r = sc_profile_instantiate_template(profile,
				"pin-domain", &df->path,
				"pin-dir", id, ret);
	if (r >= 0)
		r = profile->ops->create_dir(profile, card, *ret);

	return r;
}

/*
 * Check if a given pkcs15 prkey object can be reused
 */
static int
can_reuse_prkey_obj(const sc_pkcs15_object_t *obj, void *data)
{
	sc_pkcs15_prkey_info_t	*key, *new_key;
	sc_pkcs15_object_t	*new_obj;

	new_obj = (sc_pkcs15_object_t *) data;
	if (obj->type != new_obj->type
	 || obj->flags != new_obj->flags)
		return 0;

	key = (sc_pkcs15_prkey_info_t *) obj->data;
	new_key = (sc_pkcs15_prkey_info_t *) new_obj->data;
	if (key->modulus_length != new_key->modulus_length)
		return 0;

	/* Don't mix up native vs extractable keys */
	if (key->native != new_key->native)
		return 0;

	/* Some cards don't enforce key usage, so we might as
	 * well allow the user to change it on those cards.
	 * Not yet implemented */
	if (key->usage != new_key->usage)
		return 0;

	/* Make sure the PIN is the same */
	if (!sc_pkcs15_compare_id(&obj->auth_id, &new_obj->auth_id))
		return 0;

	return 1;
}

/*
 * Prepare private key download, and initialize a prkdf entry
 */
static int
sc_pkcs15init_init_prkdf(sc_pkcs15_card_t *p15card,
		sc_profile_t *profile,
		struct sc_pkcs15init_prkeyargs *keyargs,
		sc_pkcs15_prkey_t *key, int keybits,
		struct sc_pkcs15_object **res_obj
		)
{
	struct sc_pkcs15_prkey_info *key_info;
	struct sc_pkcs15_object *object;
	sc_card_t	*card = p15card->card;
	const char	*label;
	unsigned int	usage;
	int		r = 0;

	*res_obj = NULL;
	if (!keybits)
		return SC_ERROR_INVALID_ARGUMENTS;

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 1);
	}

	if ((label = keyargs->label) == NULL)
		label = "Private Key";

	/* Create the prkey object now.
	 * If we find out below that we're better off reusing an
	 * existing object, we'll ditch this one */
	object = sc_pkcs15init_new_object(prkey_pkcs15_algo(p15card, key),
				label, &keyargs->auth_id,
				NULL);
	if (object == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	key_info = (sc_pkcs15_prkey_info_t *) object->data;
	key_info->usage = usage;
	key_info->native = 1;
	key_info->key_reference = 0;
	key_info->modulus_length = keybits;
	key_info->access_flags = DEFAULT_PRKEY_ACCESS_FLAGS;
	/* Path is selected below */

	if (keyargs->flags & SC_PKCS15INIT_EXTRACTABLE) {
		key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
		key_info->access_flags &= ~SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
		key_info->native = 0;
	}

	if (keyargs->id.len != 0 && (keyargs->flags & SC_PKCS15INIT_SPLIT_KEY)) {
		/* Split key; this ID exists already, don't check for
		 * the pkcs15 object */
	} else {
		/* Select a Key ID if the user didn't specify one, otherwise
		 * make sure it's compatible with our intended use */
		r = select_id(p15card, SC_PKCS15_TYPE_PRKEY, &keyargs->id,
				can_reuse_prkey_obj, object, res_obj);
		if (r < 0)
			return r;

		/* If we're reusing a deleted object, update it */
		if (*res_obj != NULL) {
			free(key_info); key_info = NULL;
			free(object); object = *res_obj;

			strncpy(object->label, label, sizeof(object->label));
			return 0;
		}
	}

	key_info->id = keyargs->id;

	r = select_object_path(p15card, profile, object,
			&key_info->id, &key_info->path);
	if (r < 0)
		return r;

	/* See if we need to select a key reference for this object */
	if (profile->ops->select_key_reference) {
		while (1) {
			sc_pkcs15_object_t *dummy;

			r = profile->ops->select_key_reference(profile,
					card, key_info);
			if (r < 0)
				return r;

			r = sc_pkcs15_find_prkey_by_reference(p15card,
					&key_info->path,
					key_info->key_reference,
					&dummy);
			if (r == SC_ERROR_OBJECT_NOT_FOUND)
				break;

			if (r != 0) {
				/* Other error trying to retrieve pin obj */
				sc_error(card->ctx,
					"Failed to select key reference.");
				return SC_ERROR_TOO_MANY_OBJECTS;
			}

			key_info->key_reference++;
		}
	}

	*res_obj = object;
	return 0;
}

/*
 * Generate a new private key
 */
int
sc_pkcs15init_generate_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keygen_args *keygen_args,
		unsigned int keybits,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_pkcs15init_pubkeyargs pubkey_args;
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_prkey_info *key_info;
	int		r;

	/* For now, we support just RSA key pair generation */
	if (!check_key_compatibility(p15card, &keygen_args->prkey_args.key,
		 keygen_args->prkey_args.x509_usage,
		 keybits, SC_ALGORITHM_ONBOARD_KEY_GEN))
		return SC_ERROR_NOT_SUPPORTED;

	if (profile->ops->generate_key == NULL && profile->ops->old_generate_key == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	/* Set the USER PIN reference from args */
	r = set_user_pin_from_authid(p15card, profile,
	    	&keygen_args->prkey_args.auth_id);
	if (r < 0)
		return r;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	/* Set up the PrKDF object */
	r = sc_pkcs15init_init_prkdf(p15card, profile, &keygen_args->prkey_args,
		&keygen_args->prkey_args.key, keybits, &object);
	if (r < 0)
		return r;
	key_info = (struct sc_pkcs15_prkey_info *) object->data;

	/* Set up the PuKDF info. The public key will be filled in
	 * by the card driver's generate_key function called below */
	memset(&pubkey_args, 0, sizeof(pubkey_args));
	pubkey_args.id = keygen_args->prkey_args.id;
#if 0
	pubkey_args.auth_id = keygen_args->prkey_args.auth_id;
#endif
	pubkey_args.label = keygen_args->pubkey_label;
	pubkey_args.usage = keygen_args->prkey_args.usage;
	pubkey_args.x509_usage = keygen_args->prkey_args.x509_usage;

	/* Generate the private key on card */
	if (profile->ops->create_key) {
		/* New API */
		r = profile->ops->create_key(profile, p15card->card, object);
		if (r < 0)
			return r;

		r = profile->ops->generate_key(profile, p15card->card,
				object, &pubkey_args.key);
		if (r < 0)
			return r;
	} else {
		int idx;

		idx = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0);
		r = profile->ops->old_generate_key(profile, p15card->card, idx, keybits,
				&pubkey_args.key, key_info);
	}

	/* update PrKDF entry */
	if (r >= 0) {
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_PRKDF, object);
	}

	if (r >= 0) {
		sc_pkcs15_object_t *pub_object;

		r = sc_pkcs15init_store_public_key(p15card, profile,
				&pubkey_args, &pub_object);
	}

	if (r >= 0 && res_obj)
		*res_obj = object;
		
	sc_pkcs15_erase_pubkey(&pubkey_args.key);

	profile->dirty = 1;

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
	sc_card_t	*card = p15card->card;
	sc_pkcs15_prkey_t key;
	int		keybits, idx, r = 0;

	/* Create a copy of the key first */
	key = keyargs->key;

	if ((r = prkey_fixup(p15card, &key)) < 0)
		return r;
	if ((keybits = prkey_bits(p15card, &key)) < 0)
		return keybits;

	/* Now check whether the card is able to handle this key */
	if (!check_key_compatibility(p15card, &key,
			keyargs->x509_usage, keybits, 0)) {
		/* Make sure the caller explicitly tells us to store
		 * the key non-natively. */
		if (!(keyargs->flags & SC_PKCS15INIT_EXTRACTABLE)) {
			sc_error(card->ctx, "Card does not support this key.");
			return SC_ERROR_INCOMPATIBLE_KEY;
		}
		if (!keyargs->passphrase
		 && !(keyargs->flags & SC_PKCS15INIT_NO_PASSPHRASE)) {
			sc_error(card->ctx,
				"No key encryption passphrase given.");
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

	/* Set up the PrKDF object */
	r = sc_pkcs15init_init_prkdf(p15card, profile, keyargs, &key, keybits, &object);
	if (r < 0)
		return r;
	key_info = (struct sc_pkcs15_prkey_info *) object->data;

	/* Get the number of private keys already on this card */
	idx = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0);
	if (!(keyargs->flags & SC_PKCS15INIT_EXTRACTABLE)) {
		if (profile->ops->create_key) {
			/* New API */
			r = profile->ops->create_key(profile, p15card->card, object);
			if (r < 0)
				return r;
			r = profile->ops->store_key(profile, p15card->card,
					object, &key);
			if (r < 0)
				return r;
		} else {
			r = profile->ops->new_key(profile, p15card->card,
					&key, idx, key_info);
			if (r < 0)
				return r;
		}
	} else {
		sc_pkcs15_der_t	encoded, wrapped, *der = &encoded;
		sc_context_t *ctx = p15card->card->ctx;

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
			object, &keyargs->id, der, &key_info->path);

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

	profile->dirty = 1;

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
 * Check if a given pkcs15 pubkey object can be reused
 */
static int
can_reuse_pubkey_obj(const sc_pkcs15_object_t *obj, void *data)
{
	sc_pkcs15_pubkey_info_t	*key, *new_key;
	sc_pkcs15_object_t	*new_obj;

	new_obj = (sc_pkcs15_object_t *) data;
	if (obj->type != new_obj->type)
		return 0;

	key = (sc_pkcs15_pubkey_info_t *) obj->data;
	new_key = (sc_pkcs15_pubkey_info_t *) new_obj->data;
	if (key->modulus_length != new_key->modulus_length)
		return 0;

	/* Some cards don't enforce key usage, so we might as
	 * well allow the user to change it on those cards.
	 * Not yet implemented */
	if (key->usage != new_key->usage)
		return 0;

	/* Make sure the PIN is the same */
	if (!sc_pkcs15_compare_id(&obj->auth_id, &new_obj->auth_id))
		return 0;

	return 1;
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
		sc_error(p15card->card->ctx, "Unsupported key algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 0);
	}
	if ((label = keyargs->label) == NULL)
		label = "Public Key";

	/* Set up the pkcs15 object. If we find below that we should
	 * reuse an existing object, we'll dith this one. */
	object = sc_pkcs15init_new_object(type, label, &keyargs->auth_id, NULL);
	if (object == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	key_info = (sc_pkcs15_pubkey_info_t *) object->data;
	key_info->usage = usage;
	key_info->modulus_length = keybits;

	/* Select a Key ID if the user didn't specify one, otherwise
	 * make sure it's unique */
	*res_obj = NULL;
	r = select_id(p15card, SC_PKCS15_TYPE_PUBKEY, &keyargs->id,
			can_reuse_pubkey_obj, object, res_obj);
	if (r < 0)
		return r;

	/* If we reuse an existing object, update it */
	if (*res_obj) {
		sc_pkcs15_free_pubkey_info(key_info);
		key_info = NULL;
		sc_pkcs15_free_object(object);
		object = *res_obj;

		strncpy(object->label, label, sizeof(object->label));
	} else {
		key_info->id = keyargs->id;
		*res_obj = object;
	}

	/* DER encode public key components */
	r = sc_pkcs15_encode_pubkey(p15card->card->ctx, &key,
			&der_encoded.value, &der_encoded.len);
	if (r < 0)
		return r;

	/* Now create key file and store key */
	r = sc_pkcs15init_store_data(p15card, profile,
			object, &keyargs->id,
			&der_encoded, &key_info->path);

	path = &key_info->path;
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

	if (der_encoded.value)
		free(der_encoded.value);

	profile->dirty = 1;

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
	if ((r = select_id(p15card, SC_PKCS15_TYPE_CERT, &args->id, NULL, NULL, NULL)) < 0)
		return r;

	/* If there is a private key corresponding to the ID given
	 * by the user, make sure $PIN references the pin protecting
	 * this key
	 */
	if (args->id.len != 0
	 && profile->protect_certificates
	 && sc_pkcs15_find_prkey_by_id(p15card, &args->id, &object) == 0) {
		r = set_user_pin_from_authid(p15card, profile, &object->auth_id);
		if (r < 0) {
			sc_error(p15card->card->ctx,
				      "Failed to assign user pin reference "
				      "(copied from private key auth_id)\n");
			return r;
		}
	}

	object = sc_pkcs15init_new_object(SC_PKCS15_TYPE_CERT_X509, label, NULL, NULL);
	if (object == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	cert_info = (sc_pkcs15_cert_info_t *) object->data;
	cert_info->id = args->id;
	cert_info->authority = args->authority;

	if (profile->pkcs15.direct_certificates) {
		sc_der_copy(&cert_info->value, &args->der_encoded);
	} else {
		r = sc_pkcs15init_store_data(p15card, profile,
				object, &args->id,
				&args->der_encoded, &cert_info->path);
	}

	/* Remove the corresponding public key object, if it exists. */
	if (r >= 0 && !profile->keep_public_key) {
		sc_pkcs15_object_t *puk = NULL;

		r = sc_pkcs15_find_pubkey_by_id(p15card, &cert_info->id, &puk);
		if (r == 0)
			r = sc_pkcs15init_remove_object(p15card, profile, puk);
		else if (r == SC_ERROR_OBJECT_NOT_FOUND)
			r = 0;
	}

	/* Now update the CDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_CDF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

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
	struct sc_pkcs15_object *objs[32];
	const char	*label;
	int		r, i;
	unsigned int    tid = 0x01;

	if ((label = args->label) == NULL)
		label = "Data Object";

	if (!args->id.len) {
		/* Select an ID if the user didn't specify one, otherwise
		 * make sure it's unique (even though data objects doesn't
		 * have a pkcs15 id we need one here to create a unique 
		 * file id from the data file template */
		r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
		if (r < 0)
			return r;
		for (i = 0; i < r; i++) {
			u8 cid;
			struct sc_pkcs15_data_info *cinfo;
			cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
			if (!cinfo->path.len)
				continue;
			cid = cinfo->path.value[cinfo->path.len - 1];
			if (cid >= tid)
				tid = cid + 1;
		}
		if (tid > 0xff)
			/* too many data objects ... */
			return SC_ERROR_TOO_MANY_OBJECTS;
		args->id.len = 1;
		args->id.value[0] = tid;
	} else {
		/* in case the user specifies an id it should be at most
		 * one byte long */
		if (args->id.len > 1)
			return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Set the USER PIN reference from args */
	r = set_user_pin_from_authid(p15card, profile, &args->auth_id);
	if (r < 0)
		return r;

	object = sc_pkcs15init_new_object(SC_PKCS15_TYPE_DATA_OBJECT, label, &args->auth_id, NULL);
	if (object == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	data_object_info = (sc_pkcs15_data_info_t *) object->data;
	if (label != NULL) {
		strncpy(data_object_info->app_label, label,
			sizeof(data_object_info->app_label) - 1);
	}
	data_object_info->app_oid = args->app_oid;

	r = sc_pkcs15init_store_data(p15card, profile,
			object, &args->id, &args->der_encoded,
			&data_object_info->path);

	/* Now update the DDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile,
				SC_PKCS15_DODF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

	return r;
}

static int
sc_pkcs15init_store_data(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		sc_pkcs15_object_t *object, sc_pkcs15_id_t *id,
		sc_pkcs15_der_t *data,
		sc_path_t *path)
{
	struct sc_file	*file = NULL;
	int		r;
	unsigned int idx = -1;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	if (profile->ops->new_file == NULL) {
		/* New API */
		r = select_object_path(p15card, profile,
				object, id,
				path);
		if (r < 0)
			return r;

		r = sc_profile_get_file_by_path(profile, path, &file);
		if (r < 0)
			return r;
	} else {

		/* Get the number of objects of this type already on this card */
		idx = sc_pkcs15_get_objects(p15card,
				object->type & SC_PKCS15_TYPE_CLASS_MASK,
				NULL, 0);

		/* Allocate data file */
		r = profile->ops->new_file(profile, p15card->card,
				object->type, idx, &file);
		if (r < 0) {
			sc_error(p15card->card->ctx, "Unable to allocate file");
			goto done;
		}
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
typedef struct {
	unsigned long x509_usage;
	unsigned int p15_usage;
} sc_usage_map;

static sc_usage_map x509_to_pkcs15_private_key_usage[16] = {
	{ SC_PKCS15INIT_X509_DIGITAL_SIGNATURE,
	  SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
	{ SC_PKCS15INIT_X509_NON_REPUDIATION, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
	{ SC_PKCS15INIT_X509_KEY_ENCIPHERMENT, SC_PKCS15_PRKEY_USAGE_UNWRAP },
	{ SC_PKCS15INIT_X509_DATA_ENCIPHERMENT, SC_PKCS15_PRKEY_USAGE_DECRYPT },
	{ SC_PKCS15INIT_X509_KEY_AGREEMENT, SC_PKCS15_PRKEY_USAGE_DERIVE },
	{ SC_PKCS15INIT_X509_KEY_CERT_SIGN,
	  SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
	{ SC_PKCS15INIT_X509_CRL_SIGN,
	  SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER }
};

static sc_usage_map x509_to_pkcs15_public_key_usage[16] = {
	{ SC_PKCS15INIT_X509_DIGITAL_SIGNATURE,
	  SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
	{ SC_PKCS15INIT_X509_NON_REPUDIATION, SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
	{ SC_PKCS15INIT_X509_KEY_ENCIPHERMENT, SC_PKCS15_PRKEY_USAGE_WRAP },
	{ SC_PKCS15INIT_X509_DATA_ENCIPHERMENT, SC_PKCS15_PRKEY_USAGE_ENCRYPT },
	{ SC_PKCS15INIT_X509_KEY_AGREEMENT, SC_PKCS15_PRKEY_USAGE_DERIVE },
	{ SC_PKCS15INIT_X509_KEY_CERT_SIGN,
	  SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
	{ SC_PKCS15INIT_X509_CRL_SIGN,
	  SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER }
};

static int
sc_pkcs15init_map_usage(unsigned long x509_usage, int _private)
{
	unsigned int	p15_usage = 0, n;
	sc_usage_map   *map;

	map = _private ? x509_to_pkcs15_private_key_usage
		      : x509_to_pkcs15_public_key_usage;
	for (n = 0; n < 16; n++) {
		if (x509_usage & map[n].x509_usage)
			p15_usage |= map[n].p15_usage;
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
	sc_algorithm_info_t *info;
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
		 && info->u._rsa.exponent != 0
		 && key->u.rsa.exponent.len != 0) {
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
		sc_error(p15card->card->ctx,
			"This device requires that keys have a "
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
		key_length = prkey_bits(p15card, &keyargs->key);

	res = __check_key_compatibility(p15card, &keyargs->key,
			 keyargs->x509_usage,
			 key_length, 0);
	return res < 0;
}

/*
 * Check RSA key for consistency, and compute missing
 * CRT elements
 */
static int
prkey_fixup_rsa(sc_pkcs15_card_t *p15card, struct sc_pkcs15_prkey_rsa *key)
{
	if (!key->modulus.len || !key->exponent.len
	 || !key->d.len || !key->p.len || !key->q.len) {
		sc_error(p15card->card->ctx,
			"Missing private RSA coefficient");
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
prkey_fixup(sc_pkcs15_card_t *p15card, sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return prkey_fixup_rsa(p15card, &key->u.rsa);
	case SC_ALGORITHM_DSA:
		/* for now */
		return 0;
	}
	return 0;
}

static int
prkey_bits(sc_pkcs15_card_t *p15card, sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return sc_pkcs15init_keybits(&key->u.rsa.modulus);
	case SC_ALGORITHM_DSA:
		return sc_pkcs15init_keybits(&key->u.dsa.q);
	}
	sc_error(p15card->card->ctx, "Unsupported key algorithm.\n");
	return SC_ERROR_NOT_SUPPORTED;
}

static int
prkey_pkcs15_algo(sc_pkcs15_card_t *p15card, sc_pkcs15_prkey_t *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return SC_PKCS15_TYPE_PRKEY_RSA;
	case SC_ALGORITHM_DSA:
		return SC_PKCS15_TYPE_PRKEY_DSA;
	}
	sc_error(p15card->card->ctx, "Unsupported key algorithm.\n");
	return SC_ERROR_NOT_SUPPORTED;
}

static struct sc_pkcs15_df *
find_df_by_type(struct sc_pkcs15_card *p15card, unsigned int type)
{
	struct sc_pkcs15_df *df = p15card->df_list;
	
	while (df != NULL && df->type != type)
		df = df->next;
	return df;
}

int
select_id(sc_pkcs15_card_t *p15card, int type, sc_pkcs15_id_t *id,
		int (*can_reuse)(const sc_pkcs15_object_t *, void *),
		void *data, sc_pkcs15_object_t **reuse_obj)
{
	unsigned int nid = DEFAULT_ID;
	sc_pkcs15_id_t unused_id;
	struct sc_pkcs15_object *obj;
	int r;

	if (reuse_obj)
		*reuse_obj = NULL;

	/* If the user provided an ID, make sure we can use it */
	if (id->len != 0) {
		r = sc_pkcs15_find_object_by_id(p15card, type, id, &obj);
		if (r == SC_ERROR_OBJECT_NOT_FOUND)
			return 0;
		if (strcmp(obj->label, "deleted"))
			return SC_ERROR_ID_NOT_UNIQUE;
		if (can_reuse != NULL && !can_reuse(obj, data))
			return SC_ERROR_INCOMPATIBLE_OBJECT;
		if (reuse_obj)
			*reuse_obj = obj;
		return 0;
	}

	memset(&unused_id, 0, sizeof(unused_id));
	while (nid < 255) {
		id->value[0] = nid++;
		id->len = 1;

		r = sc_pkcs15_find_object_by_id(p15card, type, id, &obj);
		if (r == SC_ERROR_OBJECT_NOT_FOUND) {
			/* We don't have an object of that type yet.
			 * If we're allocating a PRKEY object, make
			 * sure there's no conflicting pubkey or cert
			 * object either. */
			if (type == SC_PKCS15_TYPE_PRKEY) {
				sc_pkcs15_search_key_t search_key;

				memset(&search_key, 0, sizeof(search_key));
				search_key.class_mask = 
					SC_PKCS15_SEARCH_CLASS_PUBKEY |
					SC_PKCS15_SEARCH_CLASS_CERT;
				search_key.id = id;

				r = sc_pkcs15_search_objects(p15card,
						&search_key,
						NULL, 0);
				/* If there is a pubkey or cert with
				 * this ID, skip it. */
				if (r > 0)
					continue;
			}
			if (!unused_id.len)
				unused_id = *id;
			continue;
		}

		/* Check if we can reuse a deleted object */
		if (!strcmp(obj->label, "deleted")
		 && (can_reuse == NULL || can_reuse(obj, data))) {
			if (reuse_obj)
				*reuse_obj = obj;
			return 0;
		}
	}

	if (unused_id.len) {
		*id = unused_id;
		return 0;
	}
	
	return SC_ERROR_TOO_MANY_OBJECTS;
}

/*
 * Select a path for a new object
 *  1.	If the object is to be protected by a PIN, use the path
 *  	given in the PIN auth object
 *  2.	Otherwise, use the path of the application DF
 *  3.	If the profile defines a key-dir template, the new object
 *  	should go into a subdirectory of the selected DF:
 *  	Instantiate the template, using the ID of the new object
 *  	to uniquify the path. Inside the instantiated template,
 *  	look for a file corresponding to the type of object we
 *  	wish to create ("private-key", "public-key" etc).
 */
int
select_object_path(sc_pkcs15_card_t *p15card, sc_profile_t *profile,
		sc_pkcs15_object_t *obj, sc_pkcs15_id_t *obj_id,
		sc_path_t *path)
{
	sc_file_t	*file;
	const char	*name;
	int		r;

	/* For cards with a pin-domain profile, we need
	 * to put the key below the DF of the specified PIN */
	memset(path, 0, sizeof(*path));
	if (obj->auth_id.len) {
		r = sc_pkcs15init_get_pin_path(p15card, &obj->auth_id, path);
		if (r < 0)
			return r;
	} else {
		*path = profile->df_info->file->path;
	}

	/* If the profile specifies a key directory template,
	 * instantiate it now and create the DF
	 */
	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		name = "private-key";
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		name = "public-key";
		break;
	case SC_PKCS15_TYPE_CERT:
		name = "certificate";
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		name = "data";
		break;
	default:
		return 0;
	}

	sc_debug(p15card->card->ctx,
		"key-domain.%s @%s (auth_id.len=%d)\n",
		name, sc_print_path(path), obj->auth_id.len);
	r = sc_profile_instantiate_template(profile,
					"key-domain", path, 
					name, obj_id, &file);
	if (r < 0) {
		if (r == SC_ERROR_TEMPLATE_NOT_FOUND)
			return 0;
		return r;
	}

	*path = file->path;
	sc_file_free(file);
	return 0;
}

/*
 * Update EF(DIR)
 */
static int
sc_pkcs15init_update_dir(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		sc_app_info_t *app)
{
	sc_card_t *card = p15card->card;
	int	r, retry = 1;

	do {
		struct sc_file	*dir_file;
		struct sc_path	path;

		card->ctx->suppress_errors++;
		r = sc_enum_apps(card);
		card->ctx->suppress_errors--;

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

static char *get_generalized_time(sc_context_t *ctx)
{
#ifdef HAVE_GETTIMEOFDAY
	struct timeval tv;
#endif
	struct tm *tm_time;
	time_t t;
	char*  ret;
	size_t r;

#ifdef HAVE_GETTIMEOFDAY
	gettimeofday(&tv, NULL);
	t = tv.tv_sec;
#else
	t = time(NULL);
#endif
	tm_time = gmtime(&t);
	if (tm_time == NULL) {
		sc_error(ctx, "error: gmtime failed\n");
		return NULL;
	}

	ret = calloc(1, 16);
	if (ret == NULL) {
		sc_error(ctx, "error: calloc failed\n");
		return NULL;
	}
	/* print time in generalized time format */
	r = strftime(ret, 16, "%Y%m%d%H%M%SZ", tm_time);
	if (r == 0) {
		sc_error(ctx, "error: strftime failed\n");
		free(ret);
		return NULL;
	}

	return ret;
}

static int sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_card	*card = p15card->card;
	u8		*buf = NULL;
	size_t		size;
	int		r;

	/* set lastUpdate field */
	p15card->last_update = get_generalized_time(card->ctx);
	if (p15card->last_update == NULL)
		return SC_ERROR_INTERNAL;

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

	sc_debug(card->ctx, "called\n");
	r = sc_pkcs15_encode_odf(card->ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile, card,
			       p15card->file_odf, buf, size);
	if (buf)
		free(buf);
	return r;
}

/*
 * Update any PKCS15 DF file (except ODF and DIR)
 */
static int
sc_pkcs15init_update_any_df(sc_pkcs15_card_t *p15card, 
		sc_profile_t *profile,
		sc_pkcs15_df_t *df,
		int is_new)
{
	struct sc_card	*card = p15card->card;
	sc_file_t	*file = df->file, *pfile = NULL;
	u8		*buf = NULL;
	size_t		bufsize;
	int		update_odf = is_new, r = 0;

	if (!sc_profile_get_file_by_path(profile, &df->path, &pfile))
		file = pfile;

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
	if (r >= 0) {
		r = sc_pkcs15init_update_file(profile, card,
				file, buf, bufsize);

#if 0
		/* If the DF is empty, delete it and remove
		 * the corresponding entry from the ODF
		 *
		 * XXX Before enabling this we should make this a
		 * profile option, because not all cards allow
		 * arbitrary removal of files.
		 */
		if (bufsize == 0) {
			sc_pkcs15_remove_df(p15card, df);
			sc_file_free(card, df->path);
			update_odf = 1;
		} else
#endif

		/* For better performance and robustness, we want
		 * to note which portion of the file actually
		 * contains valid data.
		 *
		 * This is particularly useful if we store certificates
		 * directly in the CDF - we may want to make the CDF
		 * fairly big, without having to read the entire file
		 * every time we parse the CDF.
		 */
		if (profile->pkcs15.encode_df_length) {
			df->path.count = bufsize;
			df->path.index = 0;
			update_odf = 1;
		}
		free(buf);
	}
	if (pfile)
		sc_file_free(pfile);

	/* Now update the ODF if we have to */
	if (r >= 0 && update_odf)
		r = sc_pkcs15init_update_odf(p15card, profile);

	return r;
}

/*
 * Add an object to one of the pkcs15 directory files.
 */
static int
sc_pkcs15init_add_object(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int df_type,
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_df *df;
	struct sc_card	*card = p15card->card;
	struct sc_file	*file = NULL;
	int		is_new = 0, r = 0;

	sc_debug(card->ctx, "called, DF %u obj %p\n", df_type, object);

	df = find_df_by_type(p15card, df_type);
	if (df != NULL) {
		file = df->file;
	} else {
		file = profile->df[df_type];
		if (file == NULL) {
			sc_error(card->ctx,
					"Profile doesn't define a DF file %u",
			 		df_type);
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_pkcs15_add_df(p15card, df_type, &file->path, file);
		df = find_df_by_type(p15card, df_type);
		assert(df != NULL);
		is_new = 1;

		/* Mark the df as enumerated, so libopensc doesn't try
		 * to load the file at a most inconvenient moment */
		df->enumerated = 1;
	}

	if (object == NULL) {
		/* Add nothing; just instantiate this directory file */
	} else if (object->df == NULL) {
		object->df = df;
		r = sc_pkcs15_add_object(p15card, object); 
		if (r < 0)
			return r;
	} else {
		/* Reused an existing object */
		assert(object->df == df);
	}

	return sc_pkcs15init_update_any_df(p15card, profile, df, is_new);
#if 0
	if (!sc_profile_get_file_by_path(profile, &df->path, &pfile))
		file = pfile;

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
	if (r >= 0) {
		r = sc_pkcs15init_update_file(profile, card,
				file, buf, bufsize);
		/* For better performance and robustness, we want
		 * to note which portion of the file actually
		 * contains valid data.
		 *
		 * This is particularly useful if we store certificates
		 * directly in the CDF - we may want to make the CDF
		 * fairly big, without having to read the entire file
		 * every time we parse the CDF.
		 */
		if (profile->pkcs15.encode_df_length) {
			df->path.count = bufsize;
			df->path.index = 0;
			update_odf = 1;
		}
		free(buf);
	}
	if (pfile)
		sc_file_free(pfile);

	/* Now update the ODF if we have to */
	if (r >= 0 && update_odf)
		r = sc_pkcs15init_update_odf(p15card, profile);

	return r;
#endif
}

static int
sc_pkcs15init_remove_object(sc_pkcs15_card_t *p15card,
		sc_profile_t *profile, sc_pkcs15_object_t *obj)
{
	sc_card_t	*card = p15card->card;
	struct sc_pkcs15_df *df;
	sc_path_t	path;
	int		r = 0;

	switch(obj->type & SC_PKCS15_TYPE_CLASS_MASK)
	{
	case SC_PKCS15_TYPE_PUBKEY:
		path = ((sc_pkcs15_pubkey_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		path = ((sc_pkcs15_prkey_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_CERT:
		path = ((sc_pkcs15_cert_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		path = ((sc_pkcs15_data_info_t *)obj->data)->path;
		break;
	default:
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	/* Get the DF we're part of. If there's no DF, fine, we haven't
	 * been added yet. */
	if ((df = obj->df) == NULL)
		return 0;

	/* Unlink the object and update the DF */
	sc_pkcs15_remove_object(p15card, obj);
	if ((r = sc_pkcs15init_update_any_df(p15card, profile, df, 0)) < 0)
		return r;

	/* XXX Dangerous - the object indicated by path may be the
	 * application DF. This isn't true for the Oberthur, but
	 * it may be for others. */
	r = sc_delete_file(card, &path);

	return r;
}

sc_pkcs15_object_t *
sc_pkcs15init_new_object(int type, const char *label, sc_pkcs15_id_t *auth_id, void *data)
{
	sc_pkcs15_object_t	*object;
	unsigned int		data_size = 0;

	object = (sc_pkcs15_object_t *) calloc(1, sizeof(*object));
	if (object == NULL)
		return NULL;
	object->type = type;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		object->flags = DEFAULT_PIN_FLAGS;
		data_size = sizeof(sc_pkcs15_pin_info_t);
		break;
	case SC_PKCS15_TYPE_PRKEY:
		object->flags = DEFAULT_PRKEY_FLAGS;
		data_size = sizeof(sc_pkcs15_prkey_info_t);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		object->flags = DEFAULT_PUBKEY_FLAGS;
		data_size = sizeof(sc_pkcs15_pubkey_info_t);
		break;
	case SC_PKCS15_TYPE_CERT:
		object->flags = DEFAULT_CERT_FLAGS;
		data_size = sizeof(sc_pkcs15_cert_info_t);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		object->flags = DEFAULT_DATA_FLAGS;
		data_size = sizeof(sc_pkcs15_data_info_t);
		break;
	}

	if (data_size) {
		object->data = calloc(1, data_size);
		if (data)
			memcpy(object->data, data, data_size);
	}

	if (label)
		strncpy(object->label, label, sizeof(object->label));
	if (auth_id)
		object->auth_id = *auth_id;

	return object;
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

int sc_pkcs15init_delete_object(sc_pkcs15_card_t *p15card,
	sc_profile_t *profile, sc_pkcs15_object_t *obj)
{
	sc_path_t path;
	struct sc_pkcs15_df *df;
	int r;

	if (profile->ops->delete_object == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	switch(obj->type & SC_PKCS15_TYPE_CLASS_MASK)
	{
	case SC_PKCS15_TYPE_PUBKEY:
		path = ((sc_pkcs15_pubkey_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		path = ((sc_pkcs15_prkey_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_CERT:
		path = ((sc_pkcs15_cert_info_t *)obj->data)->path;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		path = ((sc_pkcs15_data_info_t *)obj->data)->path;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	r = profile->ops->delete_object(profile, p15card->card,
		obj->type, obj->data, &path);
	if (r < 0) {
		sc_error(p15card->card->ctx, "ops->delete_object() failed: %d", r);
		return r;
	}

	/* Get the DF we're part of. If there's no DF, fine, we haven't
	 * been added yet. */
	if ((df = obj->df) == NULL)
		return 0;

	/* Unlink the object and update the DF */
	sc_pkcs15_remove_object(p15card, obj);
	r = sc_pkcs15init_update_any_df(p15card, profile, df, 0);

	/* mark card as dirty */
	profile->dirty = 1;

	return r;
}

int
sc_pkcs15init_update_certificate(sc_pkcs15_card_t *p15card,
	sc_profile_t *profile,
	sc_pkcs15_object_t *obj,
	const unsigned char *rawcert, int certlen)
{
	sc_file_t *file = NULL, *parent = NULL;
	sc_path_t *path = &((sc_pkcs15_cert_info_t *)obj->data)->path;
	int r;

	/* Set the SO PIN reference from card */
	if ((r = set_so_pin_from_card(p15card, profile)) < 0)
		return r;

	r = sc_select_file(p15card->card, path, &file);
	if (r < 0)
		return r;

	/* If the new cert doesn't fit in the EF, delete it and make the same, but bigger EF */
	if (file->size < certlen) {
		if ((r = sc_pkcs15init_delete_by_path(profile, p15card->card, path)) < 0)
			goto done;

		file->size = certlen;

		if ((r = do_select_parent(profile, p15card->card, file, &parent)) < 0
			|| (r = sc_pkcs15init_authenticate(profile, p15card->card,
				parent, SC_AC_OP_CREATE)) < 0)
					goto done;
 		if ((r = sc_create_file(p15card->card, file)) < 0)
			goto done;
	}

	/* Write the new cert */
	if ((r = sc_pkcs15init_authenticate(profile, p15card->card, file, SC_AC_OP_UPDATE)) < 0)
		goto done;
	if ((r = sc_select_file(p15card->card, path, NULL)) < 0)
		goto done;
	if ((r = sc_update_binary(p15card->card, 0, rawcert, certlen, 0)) < 0)
		goto done;

	/* Fill the remaining space in the EF (if any) with zeros */
	if (certlen < file->size) {
		unsigned char *tmp = (unsigned char *) calloc(file->size - certlen, 1);
		if (tmp == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		r = sc_update_binary(p15card->card, certlen, tmp, file->size - certlen, 0);
		free(tmp);
	}

	if (r >= 0) {
		/* Update the CDF entry */
		path = &((sc_pkcs15_cert_info_t *)obj->data)->path;
		if (file->size != certlen) {
			path->index = 0;
			path->count = certlen;
		}
		else
			path->count = -1;
		r = sc_pkcs15init_update_any_df(p15card, profile, obj->df, 0);
	}

	/* mark card as dirty */
	profile->dirty = 1;

done:
	if (file)
		sc_file_free(file);
	if (parent)
		sc_file_free(parent);

	return r;
}

/*
 * PIN verification
 */
static int
do_get_and_verify_secret(sc_profile_t *pro, sc_card_t *card,
		sc_file_t *file, int type, int reference,
		u8 *pinbuf, size_t *pinsize,
		int verify)
{
	struct sc_cardctl_default_key data;
	sc_pkcs15_card_t *p15card = pro->p15_data;
	sc_pkcs15_object_t *pin_obj = NULL;
	sc_pkcs15_pin_info_t pin_info;
	sc_path_t	*path;
	const char	*ident, *label = NULL;
	int		pin_id = -1;
	size_t		defsize = 0;
	u8		defbuf[0x100];
	int		r;

	path = file? &file->path : NULL;

	ident = "authentication data";
	if (type == SC_AC_CHV) {
		ident = "PIN";
		memset(&pin_info, 0, sizeof(pin_info));
		pin_info.reference = reference;

		/* Maybe this is the $SOPIN or $PIN? */
		pin_id = sc_keycache_get_pin_name(path, reference);
		if (pin_id >= 0)
			sc_profile_get_pin_info(pro, pin_id, &pin_info);

		/* Try to get information on the PIN, such as the
		 * label, max length etc */
		if (p15card && path != NULL && !(path->len & 1)) {
			sc_path_t tmp_path = *path;

			do {
				r = sc_pkcs15_find_pin_by_reference(p15card,
					&tmp_path, reference, &pin_obj);
				tmp_path.len -= 2;
			} while (r < 0 && tmp_path.len > 1);
			if (pin_obj)
				memcpy(&pin_info, pin_obj->data, sizeof(pin_info));
		}
	} else if (type == SC_AC_PRO) {
		ident = "secure messaging key";
	} else if (type == SC_AC_AUT) {
		ident = "authentication key";
	} else if (type == SC_AC_SYMBOLIC) {
		/* This is a symbolic PIN name */
		pin_id = reference;
		switch (pin_id) {
		case SC_PKCS15INIT_USER_PIN:
			ident = "user PIN"; break;
		case SC_PKCS15INIT_SO_PIN:
			ident = "SO PIN"; break;
		}

		/* See if the card initializer set this PIN.
		 * If the reference is -1, he didn't, and any
		 * access conditions involving this pin should be
		 * ignored.
		 */
		reference = sc_keycache_find_named_pin(path, pin_id);
		if (reference == -1) {
			if (card->ctx->debug >= 2) {
				sc_debug(card->ctx,
					"no %s set for this card\n",
					ident);
			}
			return 0;
		}

		sc_profile_get_pin_info(pro, pin_id, &pin_info);
		type = SC_AC_CHV;
	}

	/* Try to get the cached secret, e.g. CHV1 */
	r = sc_keycache_get_key(path, type, reference, pinbuf, *pinsize);
	if (r >= 0) {
		*pinsize = r;
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
	} else if (pin_obj && pin_obj->label[0]) {
		label = pin_obj->label;
	}

	switch (type) {
	case SC_AC_CHV:
		if (callbacks.get_pin) {
			r = callbacks.get_pin(pro, pin_id,
					&pin_info, label,
					pinbuf, pinsize);
		}
		break;
	default:
		if (callbacks.get_key) {
			r = callbacks.get_key(pro, type, reference,
					defbuf, defsize,
					pinbuf, pinsize);
		}
		break;
	}

	if (r < 0)
		return r;

	/* We got something. Cache it */
	sc_keycache_put_key(path, type, reference, pinbuf, *pinsize);

	/* If it's a PIN, pad it out */
found:	if (type == SC_AC_CHV) {
		int left = pro->pin_maxlen - *pinsize;

		if (left > 0) {
			memset(pinbuf + *pinsize, pro->pin_pad_char, left);
			*pinsize = pro->pin_maxlen;
		}
	}

	if (verify) {
		/* We may have selected the AODF instead of the file
		 * itself: */
		if (file)
			r = sc_select_file(card, &file->path, NULL);
	 	if (r >= 0
		 && (r = sc_verify(card, type, reference, pinbuf, *pinsize, 0)) < 0) {
			sc_error(card->ctx, "Failed to verify %s (ref=0x%x)",
					ident, reference);
		}
	}

	return r;
}

static int
do_verify_pin(struct sc_profile *pro, sc_card_t *card, sc_file_t *file,
		unsigned int type, unsigned int reference)
{
	size_t		pinsize;
	u8		pinbuf[0x100];

	pinsize = sizeof(pinbuf);
	return do_get_and_verify_secret(pro, card, file, type, reference,
			pinbuf, &pinsize, 1);
}

void
sc_pkcs15init_set_secret(struct sc_profile *pro,
			int type, int reference,
			u8 *key, size_t len)
{
	sc_keycache_put_key(NULL, type, reference, key, len);
}

int
sc_pkcs15init_verify_key(struct sc_profile *pro, sc_card_t *card,
		sc_file_t *file,  unsigned int type, unsigned int reference)
{
	size_t		keysize;
	u8		keybuf[64];

	keysize = sizeof(keybuf);
	return do_get_and_verify_secret(pro, card, file, type, reference,
			keybuf, &keysize, 1);
}

/*
 * Find out whether the card was initialized using an SO PIN,
 * and if so, set the profile information
 */
int
set_so_pin_from_card(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_pkcs15_pin_info *pin;
	struct sc_pkcs15_object *obj;
	int		r;

	r = sc_pkcs15_find_so_pin(p15card, &obj);
	if (r == 0) {
		pin = (struct sc_pkcs15_pin_info *) obj->data;
		return sc_keycache_set_pin_name(&pin->path,
				pin->reference,
				SC_PKCS15INIT_SO_PIN);
	}
	
	/* If the card doesn't have an SO PIN, we simply zap the
	 * naming info from the cache */
	if (r == SC_ERROR_OBJECT_NOT_FOUND)
		return sc_keycache_set_pin_name(NULL, -1, SC_PKCS15INIT_SO_PIN);

	return r;
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
	struct sc_pkcs15_pin_info *pin;
	struct sc_pkcs15_object	*objp;
	int		r;

	if (auth_id->len == 0)
		return 0;

	r = sc_pkcs15_find_pin_by_auth_id(p15card, auth_id, &objp);
	if (r < 0)
		return r;

	pin = (struct sc_pkcs15_pin_info *) objp->data;

	/* If the PIN resides in a separate directory, make sure the
	 * profile defines the DF. Otherwise, generate a file object
	 * on the fly (XXX hack attack)
	 *
	 * Possible fix: store all file info from the profile on the card
	 */
	if (pin->path.len != 0) {
		sc_file_t	*df = NULL;

		r = sc_profile_get_file_by_path(profile, &pin->path, &df);
		if (r == SC_ERROR_FILE_NOT_FOUND
		 && (r = sc_select_file(p15card->card, &pin->path, &df)) == 0) {
			sc_profile_add_file(profile, "pin-dir (auto)", df);
		}

		if (df)
			sc_file_free(df);
	}

	return sc_keycache_set_pin_name(&pin->path,
			pin->reference, SC_PKCS15INIT_USER_PIN);
}

/*
 * Present any authentication info as required by the file.
 *
 * Depending on the SC_CARD_CAP_USE_FCI_AC caps file in sc_card_t,
 * we read the ACs of the file on the card, or rely on the ACL
 * info for that file in the profile file.
 *
 * In the latter case, there's a problem here if e.g. the SO PIN
 * defined by the profile is optional, and hasn't been set. 
 * On the orther hands, some cards do not return access conditions
 * in their response to SELECT FILE), so the latter case has been
 * used in most cards while the first case was added much later.
 */
int
sc_pkcs15init_authenticate(struct sc_profile *pro, sc_card_t *card,
		sc_file_t *file, int op)
{
	const sc_acl_entry_t *acl;
	sc_file_t *file_tmp = NULL;
	int		r = 0;

	sc_debug(card->ctx, "path=%s, op=%u\n",
				sc_print_path(&file->path), op);

	if (card->caps & SC_CARD_CAP_USE_FCI_AC) {
		if ((r = sc_select_file(card, &file->path, &file_tmp)) < 0)
			return r;
		acl = sc_file_get_acl_entry(file_tmp, op);
	}
	else
		acl = sc_file_get_acl_entry(file, op);

	for (; r == 0 && acl; acl = acl->next) {
		if (acl->method == SC_AC_NEVER)
			return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		if (acl->method == SC_AC_NONE)
			break;
		if (acl->method == SC_AC_UNKNOWN) {
			sc_debug(card->ctx, "unknown acl method\n");
			break;
		}
		r = do_verify_pin(pro, card, file_tmp ? file_tmp : file,
			acl->method, acl->key_ref);
	}

	if (file_tmp)
		sc_file_free(file_tmp);

	return r;
}

int
do_select_parent(struct sc_profile *pro, sc_card_t *card,
		sc_file_t *file, sc_file_t **parent)
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
	card->ctx->suppress_errors++;
	r = sc_select_file(card, &path, parent);
	card->ctx->suppress_errors--;
	/* If DF doesn't exist, create it (unless it's the MF,
	 * but then something's badly broken anyway :-) */
	if (r == SC_ERROR_FILE_NOT_FOUND && path.len != 2) {
		r = sc_profile_get_file_by_path(pro, &path, parent);
		if (r < 0) {
			sc_error(card->ctx, "profile doesn't define a DF %s",
					sc_print_path(&path));
			return r;
		}
		if (!(r = sc_pkcs15init_create_file(pro, card, *parent)))
			r = sc_select_file(card, &path, NULL);
	} else if (r == SC_SUCCESS && !strcmp(card->name, "STARCOS SPK 2.3")) {
		/* in case of starcos spk 2.3 SELECT FILE does not
		 * give us the ACLs => ask the profile */
		sc_file_free(*parent);
		r = sc_profile_get_file_by_path(pro, &path, parent);
		if (r < 0) {
			sc_error(card->ctx, "profile doesn't define a DF %s",
					sc_print_path(&path));
			return r;
		}
	}
	return r;
}

int
sc_pkcs15init_create_file(struct sc_profile *pro, sc_card_t *card,
		sc_file_t *file)
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
sc_pkcs15init_update_file(struct sc_profile *profile, sc_card_t *card,
	       	sc_file_t *file, void *data, unsigned int datalen)
{
	struct sc_file	*info = NULL;
	void		*copy = NULL;
	int		r, need_to_zap = 0;

	sc_debug(card->ctx, "called, path=%s, %u bytes\n",
			sc_print_path(&file->path), datalen);

	card->ctx->suppress_errors++;
	if ((r = sc_select_file(card, &file->path, &info)) < 0) {
		card->ctx->suppress_errors--;
		/* Create file if it doesn't exist */
		if (file->size < datalen)
			file->size = datalen;
		if (r != SC_ERROR_FILE_NOT_FOUND
		 || (r = sc_pkcs15init_create_file(profile, card, file)) < 0
		 || (r = sc_select_file(card, &file->path, &info)) < 0)
			return r;
	} else {
		card->ctx->suppress_errors--;
		need_to_zap = 1;
	}

	if (info->size < datalen) {
		sc_error(card->ctx,
			      "File %s too small (require %u, have %u) - "
			      "please increase size in profile",
			      sc_print_path(&file->path),
			      datalen, info->size);
		sc_file_free(info);
		return SC_ERROR_TOO_MANY_OBJECTS;
	} else if (info->size > datalen && need_to_zap) {
		/* zero out the rest of the file - we may have shrunk
		 * the file contents */
		copy = calloc(1, info->size);
		if (copy == NULL) {
			sc_file_free(info);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(copy, data, datalen);
		datalen = info->size;
		data = copy;
	}

	/* Present authentication info needed */
	r = sc_pkcs15init_authenticate(profile, card, file, SC_AC_OP_UPDATE);

	if (r >= 0 && datalen)
		r = sc_update_binary(card, 0, (const u8 *) data, datalen, 0);

	if (copy)
		free(copy);
	sc_file_free(info);
	return r;
}

/*
 * Fix up all file ACLs
 */
int
sc_pkcs15init_fixup_file(struct sc_profile *profile, sc_file_t *file)
{
	sc_context_t	*ctx = profile->card->ctx;
	sc_acl_entry_t	so_acl, user_acl;
	unsigned int	op, needfix = 0;
	int		ref;

	/* First, loop over all ACLs to find out whether there
	 * are still any symbolic references.
	 */
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		const sc_acl_entry_t *acl;

		acl = sc_file_get_acl_entry(file, op);
		for (; acl; acl = acl->next) {
			if (acl->method == SC_AC_SYMBOLIC)
				needfix++;
		}
	}

	if (!needfix)
		return 0;

	/* If the profile doesn't specify a SO pin, change all
	 * ACLs that reference $sopin to NONE */
	ref = sc_keycache_find_named_pin(&file->path, SC_PKCS15INIT_SO_PIN);
	if (ref < 0) {
		so_acl.method = SC_AC_NONE;
		so_acl.key_ref = 0;
	} else {
		if (ctx->debug >= 2) {
			sc_debug(ctx,
				"sc_pkcs15init_fixup_file: SO pin is CVH%d\n",
				ref);
		}
		so_acl.method = SC_AC_CHV;
		so_acl.key_ref = ref;
	}

	ref = sc_keycache_find_named_pin(&file->path, SC_PKCS15INIT_USER_PIN);
	if (ref < 0) {
		user_acl.method = SC_AC_NONE;
		user_acl.key_ref = 0;
	} else {
		if (ctx->debug >= 2) {
			sc_debug(ctx,
				"sc_pkcs15init_fixup_file: user pin is CVH%d\n",
				ref);
		}
		user_acl.method = SC_AC_CHV;
		user_acl.key_ref = ref;
	}

	return sc_pkcs15init_fixup_acls(profile, file, &so_acl, &user_acl);
}

/*
 * Fix up a file's ACLs by replacing all occurrences of a symbolic
 * PIN name with the real reference.
 */
int
sc_pkcs15init_fixup_acls(struct sc_profile *profile, sc_file_t *file,
		sc_acl_entry_t *so_acl,
		sc_acl_entry_t *user_acl)
{
	sc_card_t	*card = profile->card;
	sc_acl_entry_t acls[16];
	unsigned int	op, num;
	int		r = 0;

	for (op = 0; r == 0 && op < SC_MAX_AC_OPS; op++) {
		const sc_acl_entry_t *acl;
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
				sc_error(card->ctx,
					"ACL references unknown symbolic PIN %d",
					acl->key_ref);
				return SC_ERROR_INVALID_ARGUMENTS;
			}

			/* If we weren't given a replacement ACL,
			 * leave the original ACL untouched */
			if (acl == NULL || acl->key_ref == (unsigned int)-1) {
				sc_error(card->ctx,
					"ACL references %s, which is not defined",
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
sc_pkcs15init_get_pin_path(sc_pkcs15_card_t *p15card,
		sc_pkcs15_id_t *auth_id, sc_path_t *path)
{
	sc_pkcs15_object_t *obj;
	int	r;

	r = sc_pkcs15_find_pin_by_auth_id(p15card, auth_id, &obj);
	if (r < 0)
		return r;
	*path = ((sc_pkcs15_pin_info_t *) obj->data)->path;
	return 0;
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
	*res = profile->p15_spec->manufacturer_id;
	return 0;
}

int
sc_pkcs15init_get_serial(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_spec->serial_number;
	return 0;
}

int
sc_pkcs15init_set_pin_data(sc_profile_t *profile, int id,
		const u8 *key, size_t len)
{
	return sc_keycache_put_key(NULL, SC_AC_SYMBOLIC, id, key, len);
}

int
sc_pkcs15init_set_serial(struct sc_profile *profile, const char *serial)
{
	if (profile->p15_spec->serial_number)
		free(profile->p15_spec->serial_number);
	profile->p15_spec->serial_number = strdup(serial);

	return 0;
}

int
sc_pkcs15init_get_label(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_spec->label;
	return 0;
}

int
sc_pkcs15init_qualify_pin(sc_card_t *card, const char *pin_name,
	       	unsigned int pin_len, sc_pkcs15_pin_info_t *pin_info)
{
	if (pin_len == 0)
		return 0;
	if (pin_len < pin_info->min_length) {
		sc_error(card->ctx, "%s too short (min length %u)",
				pin_name, pin_info->min_length);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (pin_len > pin_info->max_length) {
		sc_error(card->ctx, "%s too long (max length %u)",
				pin_name, pin_info->max_length);
		return SC_ERROR_WRONG_LENGTH;
	}

	return 0;
}

/*
 * Get the list of options from the card, if it specifies them
 */
static int
sc_pkcs15init_read_info(sc_card_t *card, sc_profile_t *profile)
{
	sc_path_t	path;
	sc_file_t	*file = NULL;
	u8		*mem = NULL;
	size_t		len = 0;
	int		r;

	card->ctx->suppress_errors++;
	sc_format_path(OPENSC_INFO_FILEPATH, &path);
	if ((r = sc_select_file(card, &path, &file)) >= 0) {
		len = file->size;
		sc_file_free(file);
		r = SC_ERROR_OUT_OF_MEMORY;
		if ((mem = (u8 *) malloc(len)) != NULL) {
			r = sc_read_binary(card, 0, mem, len, 0);
		}
	} else {
		r = 0;
	}
	card->ctx->suppress_errors--;

	if (r >= 0)
		r = sc_pkcs15init_parse_info(card, mem, len, profile);
	if (mem)
		free(mem);
	return r;
}

static int
set_info_string(char **strp, const u8 *p, size_t len)
{
	char	*s;

	if (!(s = (char *) malloc(len+1)))
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(s, p, len);
	s[len] = '\0';
	if (*strp)
		free(*strp);
	*strp = s;
	return 0;
}

/*
 * Parse OpenSC Info file. We rudely clobber any information
 * given on the command line.
 */
static int
sc_pkcs15init_parse_info(sc_card_t *card,
	       			const u8 *p, size_t len,
				sc_profile_t *profile)
{
	u8		tag;
       	const u8	*end;
	unsigned int	nopts = 0;
	size_t		n;

	end = p + len;
	while (p < end && (tag = *p++) != 0 && tag != 0xFF) {
		int	r = 0;

		if (p >= end || p + (n = *p++) > end)
			goto error;

		switch (tag) {
		case OPENSC_INFO_TAG_PROFILE:
			r = set_info_string(&profile->name, p, n);
			if (r < 0)
				return r;
			break;
		case OPENSC_INFO_TAG_OPTION:
			if (nopts >= SC_PKCS15INIT_MAX_OPTIONS - 1) {
				sc_error(card->ctx,
					"Too many options in OpenSC Info file\n");
				return SC_ERROR_PKCS15INIT;
			}
			r = set_info_string(&profile->options[nopts], p, n);
			if (r < 0)
				return r;
			profile->options[++nopts] = NULL;
			break;
		default:
			/* Unknown options ignored */ ;
		}
		p += n;
	}
	return 0;

error:
	sc_error(card->ctx, "OpenSC info file corrupted\n");
	return SC_ERROR_PKCS15INIT;
}

static int
do_encode_string(u8 **memp, u8 *end, u8 tag, const char *s)
{
	u8	*p = *memp;
	int	n;

	n = s? strlen(s) : 0;
	if (n > 255)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (p + 2 + n > end)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*p++ = tag;
	*p++ = n;
	memcpy(p, s, n);
	*memp = p + n;
	return 0;
}

int
sc_pkcs15init_write_info(sc_card_t *card, sc_profile_t *profile, sc_pkcs15_object_t *pin_obj)
{
	sc_file_t	*file = NULL;
	sc_file_t	*df = profile->df_info->file;
	u8		buffer[512], *p, *end;
	unsigned int	method;
	unsigned long	key_ref;
	int		n, r;

	file = sc_file_new();
	file->path.type = SC_PATH_TYPE_PATH;
	memcpy(file->path.value, df->path.value, df->path.len);
	file->path.len = df->path.len;
	sc_append_file_id(&file->path, OPENSC_INFO_FILEID);
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->id = OPENSC_INFO_FILEID;

	if (pin_obj != NULL) {
		method = SC_AC_CHV;
		key_ref = ((sc_pkcs15_pin_info_t *) pin_obj->data)->reference;
	}
	else {
		method = SC_AC_NONE; /* Unprotected */
		key_ref = 0;
	}
	for (n = 0; n < SC_MAX_AC_OPS; n++) {
		if (n == SC_AC_OP_READ)
			sc_file_add_acl_entry(file, n, SC_AC_NONE, 0);
		else
			sc_file_add_acl_entry(file, n, method, key_ref);
	}

	p = buffer;
	end = buffer + sizeof(buffer);

	r = do_encode_string(&p, end, OPENSC_INFO_TAG_PROFILE, profile->name);
	for (n = 0; r >= 0 && profile->options[n]; n++)
		r = do_encode_string(&p, end, OPENSC_INFO_TAG_OPTION, profile->options[n]);

	if (r >= 0) {
		file->size = p - buffer;
		if (file->size < 128)
			file->size = 128;
		r = sc_pkcs15init_update_file(profile, card, file, buffer, p - buffer);
	}

	sc_file_free(file);
	return r;
}
