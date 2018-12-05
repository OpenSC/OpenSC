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
 * Copyright (C) 2002, Olaf Kirch <okir@suse.de>
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
#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#endif

#include "libopensc/sc-ossl-compat.h"
#include "common/compat_strlcpy.h"
#include "common/libscdl.h"
#include "libopensc/pkcs15.h"
#include "libopensc/cardctl.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/aux-data.h"
#include "profile.h"
#include "pkcs15-init.h"
#include "pkcs11/pkcs11.h"

#define OPENSC_INFO_FILEPATH		"3F0050154946"
#define OPENSC_INFO_FILEID		0x4946
#define OPENSC_INFO_TAG_PROFILE		0x01
#define OPENSC_INFO_TAG_OPTION		0x02

/* Default ID for new key/pin */
#define DEFAULT_ID			0x45
#define DEFAULT_PIN_FLAGS		(SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE)
#define DEFAULT_PRKEY_FLAGS		(SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE)
#define DEFAULT_PUBKEY_FLAGS		(SC_PKCS15_CO_FLAG_MODIFIABLE)
#define DEFAULT_SKEY_FLAGS		(SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE)
#define DEFAULT_CERT_FLAGS		(SC_PKCS15_CO_FLAG_MODIFIABLE)
#define DEFAULT_DATA_FLAGS		(SC_PKCS15_CO_FLAG_MODIFIABLE)

#define TEMPLATE_INSTANTIATE_MIN_INDEX	0x0
#define TEMPLATE_INSTANTIATE_MAX_INDEX	0xFE

/* Maximal number of access conditions that can be defined for one card operation. */
#define SC_MAX_OP_ACS                   16

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

static int	sc_pkcs15init_store_data(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15_object *,
			struct sc_pkcs15_der *, struct sc_path *);
static size_t	sc_pkcs15init_keybits(struct sc_pkcs15_bignum *);

static int	sc_pkcs15init_update_dir(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			struct sc_app_info *app);
static int	sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_lastupdate(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_odf(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_map_usage(unsigned long, int);
static int	do_select_parent(struct sc_profile *, struct sc_pkcs15_card *,
			struct sc_file *, struct sc_file **);
static int	sc_pkcs15init_create_pin(struct sc_pkcs15_card *, struct sc_profile *,
			struct sc_pkcs15_object *, struct sc_pkcs15init_pinargs *);
static int	check_keygen_params_consistency(struct sc_card *card,
			unsigned int alg, struct sc_pkcs15init_prkeyargs *prkey,
			unsigned int *keybits);
static int	check_key_compatibility(struct sc_pkcs15_card *, unsigned int,
			struct sc_pkcs15_prkey *, unsigned int,
			unsigned int, unsigned int);
static int	prkey_fixup(struct sc_pkcs15_card *, struct sc_pkcs15_prkey *);
static int	prkey_bits(struct sc_pkcs15_card *, struct sc_pkcs15_prkey *);
static int	key_pkcs15_algo(struct sc_pkcs15_card *, unsigned int);
static int	select_id(struct sc_pkcs15_card *, int, struct sc_pkcs15_id *);
static int	select_object_path(struct sc_pkcs15_card *, struct sc_profile *,
			struct sc_pkcs15_object *, struct sc_path *);
static int	sc_pkcs15init_get_pin_path(struct sc_pkcs15_card *,
			struct sc_pkcs15_id *, struct sc_path *);
static int	sc_pkcs15init_qualify_pin(struct sc_card *, const char *,
			unsigned int, struct sc_pkcs15_auth_info *);
static struct	sc_pkcs15_df * find_df_by_type(struct sc_pkcs15_card *,
			unsigned int);
static int	sc_pkcs15init_read_info(struct sc_card *card, struct sc_profile *);
static int	sc_pkcs15init_parse_info(struct sc_card *, const unsigned char *, size_t,
			struct sc_profile *);
static int	sc_pkcs15init_write_info(struct sc_pkcs15_card *, struct sc_profile *,
			struct sc_pkcs15_object *);

static struct profile_operations {
	const char *name;
	void *func;
} profile_operations[] = {
	{ "rutoken", (void *) sc_pkcs15init_get_rutoken_ops },
	{ "gpk", (void *) sc_pkcs15init_get_gpk_ops },
	{ "miocos", (void *) sc_pkcs15init_get_miocos_ops },
	{ "flex", (void *) sc_pkcs15init_get_cryptoflex_ops },
	{ "cyberflex", (void *) sc_pkcs15init_get_cyberflex_ops },
	{ "cardos", (void *) sc_pkcs15init_get_cardos_ops },
	{ "etoken", (void *) sc_pkcs15init_get_cardos_ops }, /* legacy */
	{ "jcop", (void *) sc_pkcs15init_get_jcop_ops },
	{ "starcos", (void *) sc_pkcs15init_get_starcos_ops },
	{ "oberthur", (void *) sc_pkcs15init_get_oberthur_ops },
	{ "openpgp", (void *) sc_pkcs15init_get_openpgp_ops },
	{ "setcos", (void *) sc_pkcs15init_get_setcos_ops },
	{ "incrypto34", (void *) sc_pkcs15init_get_incrypto34_ops },
	{ "muscle", (void*) sc_pkcs15init_get_muscle_ops },
	{ "asepcos", (void*) sc_pkcs15init_get_asepcos_ops },
	{ "entersafe",(void*) sc_pkcs15init_get_entersafe_ops },
	{ "epass2003",(void*) sc_pkcs15init_get_epass2003_ops },
	{ "rutoken_ecp", (void *) sc_pkcs15init_get_rtecp_ops },
	{ "westcos", (void *) sc_pkcs15init_get_westcos_ops },
	{ "myeid", (void *) sc_pkcs15init_get_myeid_ops },
	{ "sc-hsm", (void *) sc_pkcs15init_get_sc_hsm_ops },
	{ "isoApplet", (void *) sc_pkcs15init_get_isoApplet_ops },
	{ "gids", (void *) sc_pkcs15init_get_gids_ops },
#ifdef ENABLE_OPENSSL
	{ "authentic", (void *) sc_pkcs15init_get_authentic_ops },
	{ "iasecc", (void *) sc_pkcs15init_get_iasecc_ops },
#endif
	{ NULL, NULL },
};


static struct sc_pkcs15init_callbacks callbacks = {
	NULL,
	NULL,
};


static void sc_pkcs15init_empty_callback(void *ptr)
{
}

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
get_profile_from_config(struct sc_card *card, char *buffer, size_t size)
{
	struct sc_context *ctx = card->ctx;
	const char *tmp;
	scconf_block **blocks, *blk;
	int i;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					"card_driver",
					card->driver->short_name);
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;

		tmp = scconf_get_str(blk, "profile", NULL);
		if (tmp != NULL) {
			strlcpy(buffer, tmp, size);
			return 1;
		}
	}

	return 0;
}


static const char *
find_library(struct sc_context *ctx, const char *name)
{
	int          i;
	const char   *libname = NULL;
	scconf_block *blk, **blocks;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], "framework", "pkcs15");
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;
		blocks = scconf_find_blocks(ctx->conf, blk, "pkcs15init", name);
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;
		libname = scconf_get_str(blk, "module", NULL);
		break;
	}
	if (!libname) {
		sc_log(ctx, "unable to locate pkcs15init driver for '%s'", name);
	}
	return libname;
}


static void *
load_dynamic_driver(struct sc_context *ctx, void **dll,
	const char *name)
{
	const char *version, *libname;
	void *handle;
	void *(*modinit)(const char *)  = NULL;
	const char *(*modversion)(void) = NULL;

	libname = find_library(ctx, name);
	if (!libname)
		return NULL;
	handle = sc_dlopen(libname);
	if (handle == NULL) {
		sc_log(ctx, "Module %s: cannot load '%s' library: %s", name, libname, sc_dlerror());
		return NULL;
	}

	/* verify correctness of module */
	modinit    = (void *(*)(const char *)) sc_dlsym(handle, "sc_module_init");
	modversion = (const char *(*)(void)) sc_dlsym(handle, "sc_driver_version");
	if (modinit == NULL || modversion == NULL) {
		sc_log(ctx, "dynamic library '%s' is not a OpenSC module",libname);
		sc_dlclose(handle);
		return NULL;
	}
	/* verify module version */
	version = modversion();
	if (version == NULL || strncmp(version, "0.9.", strlen("0.9.")) > 0) {
		sc_log(ctx,"dynamic library '%s': invalid module version",libname);
		sc_dlclose(handle);
		return NULL;
	}
	*dll = handle;
	sc_log(ctx, "successfully loaded pkcs15init driver '%s'", name);

	return modinit(name);
}


/*
 * Set up profile
 */
int
sc_pkcs15init_bind(struct sc_card *card, const char *name, const char *profile_option,
		struct sc_app_info *app_info, struct sc_profile **result)
{
	struct sc_context *ctx = card->ctx;
	struct sc_profile *profile;
	struct sc_pkcs15init_operations * (* func)(void) = NULL;
	const char	*driver = card->driver->short_name;
	char		card_profile[PATH_MAX];
	int		r, i;

	LOG_FUNC_CALLED(ctx);
	/* Put the card into administrative mode */
	r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0 && r != SC_ERROR_NOT_SUPPORTED)
		LOG_TEST_RET(ctx, r, "Set lifecycle error");

	profile = sc_profile_new();
	profile->card = card;

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
	}
	else {
		sc_log(ctx, "Unsupported card driver %s", driver);
		sc_profile_free(profile);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported card driver");
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

	r = sc_pkcs15init_read_info(card, profile);
	if (r < 0) {
		sc_profile_free(profile);
		LOG_TEST_RET(ctx, r, "Read info error");
	}

	/* Check the config file for a profile name.
	 * If none is defined, use the default profile name.
	 */
	if (!get_profile_from_config(card, card_profile, sizeof(card_profile)))
		strlcpy(card_profile, driver, sizeof card_profile);
	if (profile_option != NULL)
		strlcpy(card_profile, profile_option, sizeof(card_profile));

	do   {
		r = sc_profile_load(profile, profile->name);
		if (r < 0)   {
			sc_log(ctx, "Failed to load profile '%s': %s", profile->name, sc_strerror(r));
			break;
		}

		r = sc_profile_load(profile, card_profile);
		if (r < 0)   {
			sc_log(ctx, "Failed to load profile '%s': %s", card_profile, sc_strerror(r));
			break;
		}

		r = sc_profile_finish(profile, app_info);
		if (r < 0)
			sc_log(ctx, "Failed to finalize profile: %s", sc_strerror(r));
	}  while (0);

	if (r < 0)   {
		sc_profile_free(profile);
		LOG_TEST_RET(ctx, r, "Load profile error");
	}

	if (app_info && app_info->aid.len)   {
		struct sc_path path;

		if (card->ef_atr && card->ef_atr->aid.len)   {
			sc_log(ctx, "sc_pkcs15init_bind() select MF using EF.ATR data");
			memset(&path, 0, sizeof(struct sc_path));
			path.type = SC_PATH_TYPE_DF_NAME;
			path.aid = card->ef_atr->aid;
			r = sc_select_file(card, &path, NULL);
			if (r)
				return r;
		}

		if (app_info->path.len)   {
			path = app_info->path;
		}
		else   {
			memset(&path, 0, sizeof(struct sc_path));
			path.type = SC_PATH_TYPE_DF_NAME;
			path.aid = app_info->aid;
		}
		sc_log(ctx, "sc_pkcs15init_bind() select application path(type:%X) '%s'", path.type, sc_print_path(&path));
		r = sc_select_file(card, &path, NULL);
	}

	*result = profile;
	LOG_FUNC_RETURN(ctx, r);
}


void
sc_pkcs15init_unbind(struct sc_profile *profile)
{
	int r;
	struct sc_context *ctx = profile->card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Pksc15init Unbind: %i:%p:%i", profile->dirty, profile->p15_data, profile->pkcs15.do_last_update);
	if (profile->dirty != 0 && profile->p15_data != NULL && profile->pkcs15.do_last_update) {
		r = sc_pkcs15init_update_lastupdate(profile->p15_data, profile);
		if (r < 0)
			sc_log(ctx, "Failed to update TokenInfo: %s", sc_strerror(r));
	}
	if (profile->dll)
		sc_dlclose(profile->dll);
	sc_profile_free(profile);
}


void
sc_pkcs15init_set_p15card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *p15objects[10];
	int i, r, nn_objs;

	LOG_FUNC_CALLED(ctx);

	/* Prepare pin-domain instantiation:
	 * for every present local User PIN, add to the profile EF list the named PIN path. */
	nn_objs = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, p15objects, 10);
	for (i = 0; i < nn_objs; i++) {
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) p15objects[i]->data;
		struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
		struct sc_file *file = NULL;

		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			continue;
		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
			continue;
		if (!auth_info->path.len)
			continue;

		r = sc_profile_get_file_by_path(profile, &auth_info->path, &file);
                if (r == SC_ERROR_FILE_NOT_FOUND)   {
			if (!sc_select_file(p15card->card, &auth_info->path, &file))   {
				char pin_name[16];

				sprintf(pin_name, "pin-dir-%02X%02X", file->path.value[file->path.len - 2],
						file->path.value[file->path.len - 1]);
				sc_log(ctx, "add '%s' to profile file list", pin_name);
				sc_profile_add_file(profile, pin_name, file);
			}
		}

		sc_file_free(file);
	}

	profile->p15_data = p15card;
	sc_log(ctx, "sc_pkcs15init_set_p15card() returns");
}


/*
 * Set the card's lifecycle
 */
int
sc_pkcs15init_set_lifecycle(struct sc_card *card, int lcycle)
{
	return sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &lcycle);
}


/*
 * Erase the card
 */
int
sc_pkcs15init_erase_card(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_aid *aid)
{
	struct sc_context *ctx = NULL;
	int rv;

	if (!p15card)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);
	/* Needs the 'SOPIN' AUTH pkcs15 object.
	 * So that, SOPIN can be found by it's reference. */
	if (sc_pkcs15_bind(p15card->card, aid, &p15card) >= 0)
		profile->p15_data = p15card;

	if (profile->ops->erase_card == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv = profile->ops->erase_card(profile, p15card);

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_pkcs15init_erase_card_recursively(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_file	*df = profile->df_info->file, *dir;
	int		r;

	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete it before the DF because we create
	 * it *after* the DF. Some cards (e.g. the cryptoflex) want
	 * us to delete files in reverse order of creation.
	 * */
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		r = sc_pkcs15init_rmdir(p15card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)   {
			sc_free_apps(p15card->card);
			return r;
		}
	}

	r = sc_select_file(p15card->card, &df->path, &df);
	if (r >= 0) {
		r = sc_pkcs15init_rmdir(p15card, profile, df);
		sc_file_free(df);
	}
	if (r == SC_ERROR_FILE_NOT_FOUND)
		r = 0;

	sc_free_apps(p15card->card);
	return r;
}


int
sc_pkcs15init_delete_by_path(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		const struct sc_path *file_path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *parent = NULL, *file = NULL;
	struct sc_path path;
	int rv;
	/*int file_type = SC_FILE_TYPE_DF;*/

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "trying to delete '%s'", sc_print_path(file_path));

	/* For some cards, to delete file should be satisfied the 'DELETE' ACL of the file itself,
	 * for the others the 'DELETE' ACL of parent.
	 * Let's start from the file's 'DELETE' ACL.
	 *
	 * TODO: 'DELETE_SELF' exists. Proper solution would be to use this acl by every
	 * card (driver and profile) that uses self delete ACL.
	 */
	/* Select the file itself */
        path = *file_path;
        rv = sc_select_file(p15card->card, &path, &file);
        LOG_TEST_RET(ctx, rv, "cannot select file to delete");

	if (sc_file_get_acl_entry(file, SC_AC_OP_DELETE_SELF))   {
		sc_log(ctx, "Found 'DELETE-SELF' acl");
		rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE_SELF);
		sc_file_free(file);
	}
	else if (sc_file_get_acl_entry(file, SC_AC_OP_DELETE))   {
		sc_log(ctx, "Found 'DELETE' acl");
	        rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE);
		sc_file_free(file);
	}
	else    {
		sc_log(ctx, "Try to get the parent's 'DELETE' access");
		/*file_type = file->type;*/
		if (file_path->len >= 2) {
			/* Select the parent DF */
			path.len -= 2;
			rv = sc_select_file(p15card->card, &path, &parent);
			LOG_TEST_RET(ctx, rv, "Cannot select parent");

			rv = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_DELETE);
			sc_file_free(parent);
			LOG_TEST_RET(ctx, rv, "parent 'DELETE' authentication failed");
		}
	}
	LOG_TEST_RET(ctx, rv, "'DELETE' authentication failed");

	/* Reselect file to delete: current path could be changed by 'verify PIN' procedure */
	path = *file_path;
	rv = sc_select_file(p15card->card, &path, &file);
	LOG_TEST_RET(ctx, rv, "cannot select file to delete");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = file_path->value[file_path->len - 2];
	path.value[1] = file_path->value[file_path->len - 1];
	path.len = 2;

	/* Reselect file to delete if the parent DF was selected and it's not DF. */
/*
	if (file_type != SC_FILE_TYPE_DF)   {
		rv = sc_select_file(p15card->card, &path, &file);
		LOG_TEST_RET(ctx, rv, "cannot select file to delete");
	}
*/

	sc_log(ctx, "Now really delete file");
	rv = sc_delete_file(p15card->card, &path);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Try to delete a file (and, in the DF case, its contents).
 * Note that this will not work if a pkcs#15 file's ERASE AC
 * references a pin other than the SO pin.
 */
int
sc_pkcs15init_rmdir(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char buffer[1024];
	struct sc_path	path;
	struct sc_file	*file, *parent;
	int		r = 0, nfids;

	if (df == NULL)
		return SC_ERROR_INTERNAL;
	sc_log(ctx, "sc_pkcs15init_rmdir(%s)", sc_print_path(&df->path));

	if (df->type == SC_FILE_TYPE_DF) {
		r = sc_pkcs15init_authenticate(profile, p15card, df, SC_AC_OP_LIST_FILES);
		if (r < 0)
			return r;
		r = sc_list_files(p15card->card, buffer, sizeof(buffer));
		if (r < 0)
			return r;

		path = df->path;
		path.len += 2;

		nfids = r / 2;
		while (r >= 0 && nfids--) {
			path.value[path.len-2] = buffer[2*nfids];
			path.value[path.len-1] = buffer[2*nfids+1];
			r = sc_select_file(p15card->card, &path, &file);
			if (r < 0) {
				if (r == SC_ERROR_FILE_NOT_FOUND)
					continue;
				break;
			}
			r = sc_pkcs15init_rmdir(p15card, profile, file);
			sc_file_free(file);
		}

		if (r < 0)
			return r;
	}

	/* Select the parent DF */
	path = df->path;
	path.len -= 2;
	r = sc_select_file(p15card->card, &path, &parent);
	if (r < 0)
		return r;

	r = sc_pkcs15init_authenticate(profile, p15card, df, SC_AC_OP_DELETE);
	if (r < 0) {
		sc_file_free(parent);
		return r;
	}
	r = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	if (r < 0)
		return r;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	/* ensure that the card is in the correct lifecycle */
	r = sc_pkcs15init_set_lifecycle(p15card->card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r < 0 && r != SC_ERROR_NOT_SUPPORTED)
		return r;

	r = sc_delete_file(p15card->card, &path);
	return r;
}


int
sc_pkcs15init_finalize_card(struct sc_card *card, struct sc_profile *profile)
{
	if (profile->ops->finalize_card == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return profile->ops->finalize_card(card);
}


int
sc_pkcs15init_finalize_profile(struct sc_card *card, struct sc_profile *profile,
		struct sc_aid *aid)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_app_info *app = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->app_count < 0 && SC_SUCCESS != sc_enum_apps(card))
		sc_log(ctx, "Could not enumerate apps");

	if (aid)   {
		sc_log(ctx, "finalize profile for AID %s", sc_dump_hex(aid->value, aid->len));
		app = sc_find_app(card, aid);
	}
	else if (card->app_count == 1) {
		app = card->app[0];
	}
	else if (card->app_count > 1) {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Need AID defined in this context");
	}

	sc_log(ctx, "Finalize profile with application '%s'", app ? app->label : "default");
	rv = sc_profile_finish(profile, app);

	sc_log(ctx, "sc_pkcs15init_finalize_profile() returns %i", rv);
	LOG_FUNC_RETURN(ctx, rv);
}

/*
 * Initialize the PKCS#15 application
 */
int
sc_pkcs15init_add_app(struct sc_card *card, struct sc_profile *profile,
		struct sc_pkcs15init_initargs *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_card	*p15card = profile->p15_spec;
	struct sc_pkcs15_auth_info pin_ainfo, puk_ainfo;
	struct sc_pkcs15_pin_attributes *pin_attrs = &pin_ainfo.attrs.pin;
	struct sc_pkcs15_object	*pin_obj = NULL;
	struct sc_app_info	*app;
	struct sc_file		*df = profile->df_info->file;
	int			r = SC_SUCCESS;
	int			has_so_pin = args->so_pin_len != 0;

	LOG_FUNC_CALLED(ctx);
	p15card->card = card;

	/* FIXME:
	 * Some cards need pincache
	 *  for ex. to create temporary CHV key with the value of default AUTH key.
	 */
	p15card->opts.use_pin_cache = 1;

	if (card->app_count >= SC_MAX_CARD_APPS)
		LOG_TEST_RET(ctx, SC_ERROR_TOO_MANY_OBJECTS, "Too many applications on this card.");

	/* In case of pinpad readers check if SO PIN is defined in a profile */
	if (!has_so_pin && (card->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_ainfo);
		/* If found, assume we want SO PIN */
		has_so_pin = pin_ainfo.attrs.pin.reference != -1;
	}

	/* If the profile requires an SO PIN, check min/max length */
	if (has_so_pin) {
		const char	*pin_label;

		if (args->so_pin_len) {
			sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_ainfo);
			r = sc_pkcs15init_qualify_pin(card, "SO PIN", args->so_pin_len, &pin_ainfo);
			LOG_TEST_RET(ctx, r, "Failed to qualify SO PIN");
		}

		/* Path encoded only for local SO PIN */
		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_LOCAL)
			pin_ainfo.path = df->path;

		/* Select the PIN reference */
		if (profile->ops->select_pin_reference) {
			r = profile->ops->select_pin_reference(profile, p15card, &pin_ainfo);
			LOG_TEST_RET(ctx, r, "Failed to select card specific PIN reference");
		}

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &puk_ainfo);
		r = sc_pkcs15init_qualify_pin(card, "SO PUK", args->so_puk_len, &puk_ainfo);
		LOG_TEST_RET(ctx, r, "Failed to qualify SO PUK");

		if (!(pin_label = args->so_pin_label)) {
			if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				pin_label = "Security Officer PIN";
			else
				pin_label = "User PIN";
		}

		if (args->so_puk_len == 0)
			pin_attrs->flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED;

		pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN, pin_label, NULL, &pin_ainfo);
		if (pin_obj)   {
			/* When composing ACLs to create 'DIR' DF,
			 *	the references of the not-yet-existing PINs can be requested.
			 * For this, create a 'virtual' AUTH object 'SO PIN', accessible by the card specific part,
			 * but not yet written into the on-card PKCS#15.
			 */
			sc_log(ctx, "Add virtual SO_PIN('%.*s',flags:%X,reference:%i,path:'%s')", (int) sizeof pin_obj->label, pin_obj->label,
					pin_attrs->flags, pin_attrs->reference, sc_print_path(&pin_ainfo.path));

			r = sc_pkcs15_add_object(p15card, pin_obj);
			LOG_TEST_RET(ctx, r, "Failed to add 'SOPIN' AUTH object");
		}
	}

	/* Perform card-specific initialization */

	if (profile->ops->init_card)   {
		r = profile->ops->init_card(profile, p15card);
		if (r < 0 && pin_obj)   {
			sc_pkcs15_remove_object(p15card, pin_obj);
			sc_pkcs15_free_object(pin_obj);
		}
		LOG_TEST_RET(ctx, r, "Card specific init failed");
	}

	/* Create the application directory */
	if (profile->ops->create_dir)
		r = profile->ops->create_dir(profile, p15card, df);
	LOG_TEST_RET(ctx, r, "Create 'DIR' error");

	/* Store SO PIN */
	if (pin_obj && profile->ops->create_pin)
		r = profile->ops->create_pin(profile, p15card, df, pin_obj,
				args->so_pin, args->so_pin_len,
				args->so_puk, args->so_puk_len);

	if (pin_obj)
		/* Remove 'virtual' AUTH object . */
		sc_pkcs15_remove_object(p15card, pin_obj);

	if (r < 0)
		sc_pkcs15_free_object(pin_obj);
	LOG_TEST_RET(ctx, r, "Card specific create application DF failed");

	/* Store the PKCS15 information on the card
	 * We cannot use sc_pkcs15_create() because it makes
	 * all sorts of assumptions about DF and EF names, and
	 * doesn't work if secure messaging is required for the
	 * MF (which is the case with the GPK) */
	app = (struct sc_app_info *)calloc(1, sizeof(*app));
	if (app == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate application info");

	app->path = p15card->file_app->path;
	if (p15card->file_app->namelen <= SC_MAX_AID_SIZE) {
		app->aid.len = p15card->file_app->namelen;
		memcpy(app->aid.value, p15card->file_app->name, app->aid.len);
	}

	/* set serial number if explicitly specified */
	if (args->serial)   {
		sc_pkcs15init_set_serial(profile, args->serial);
	}
	else {
		/* otherwise try to get the serial number from the card */
		struct sc_serial_number serialnr;

		r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr);
		if (r == SC_SUCCESS) {
			char hex_serial[SC_MAX_SERIALNR * 2 + 1];

			sc_bin_to_hex(serialnr.value, serialnr.len, hex_serial, sizeof(hex_serial), 0);
			sc_pkcs15init_set_serial(profile, hex_serial);
		}
	}

	if (args->label) {
		if (p15card->tokeninfo->label)
			free(p15card->tokeninfo->label);
		p15card->tokeninfo->label = strdup(args->label);
	}
	app->label = strdup(p15card->tokeninfo->label);

	/* See if we've set an SO PIN */
	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_AODF, pin_obj);
	if (r >= 0) {
		r = sc_pkcs15init_update_dir(p15card, profile, app);
		if (r >= 0) {
			r = sc_pkcs15init_update_tokeninfo(p15card, profile);
		} else {
			/* FIXME: what to do if sc_pkcs15init_update_dir failed? */
			free(app->label);
			free(app); /* unused */
		}
	}
	else {
		free(app->label);
		free(app); /* unused */
	}

	sc_pkcs15init_write_info(p15card, profile, pin_obj);
	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Store a PIN/PUK pair
 */
static int
sc_pkcs15init_store_puk(struct sc_pkcs15_card *p15card,
			struct sc_profile *profile,
			struct sc_pkcs15init_pinargs *args)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object	*pin_obj;
	struct sc_pkcs15_auth_info *auth_info;
	int			r;
	char puk_label[0x30];

	LOG_FUNC_CALLED(ctx);
	if (!args->puk_id.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "PUK auth ID not supplied");

	/* Make sure we don't get duplicate PIN IDs */
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &args->puk_id, NULL);
	if (r != SC_ERROR_OBJECT_NOT_FOUND)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "There already is a PIN with this ID.");

	if (!args->puk_label)   {
		if (args->label)
			snprintf(puk_label, sizeof(puk_label), "%s (PUK)", args->label);
		else
			snprintf(puk_label, sizeof(puk_label), "User PUK");

		args->puk_label = puk_label;
	}

	args->pin = args->puk;
	args->pin_len = args->puk_len;
	args->puk = NULL;
	args->puk_len = 0;

	pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN, args->puk_label, NULL, NULL);
	if (pin_obj == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate PIN object");

	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, auth_info);
	auth_info->auth_id = args->puk_id;

	/* Now store the PINs */
	if (profile->ops->create_pin)
		r = sc_pkcs15init_create_pin(p15card, profile, pin_obj, args);
	else {
		sc_pkcs15_free_object(pin_obj);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "In Old API store PUK object is not supported");
	}

	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_AODF, pin_obj);
	else
		sc_pkcs15_free_object(pin_obj);

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_store_pin(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
			struct sc_pkcs15init_pinargs *args)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object	*pin_obj;
	struct sc_pkcs15_auth_info *auth_info;
	int			r;

	LOG_FUNC_CALLED(ctx);
	/* No auth_id given: select one */
	if (args->auth_id.len == 0) {
		unsigned int	n;

		args->auth_id.len = 1;
		for (n = 1, r = 0; n < 256; n++) {
			args->auth_id.value[0] = n;
			r = sc_pkcs15_find_pin_by_auth_id(p15card, &args->auth_id, NULL);
			if (r == SC_ERROR_OBJECT_NOT_FOUND)
				break;
		}

		if (r != SC_ERROR_OBJECT_NOT_FOUND)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "No auth_id specified for new PIN");
	}
	else   {
		/* Make sure we don't get duplicate PIN IDs */
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &args->auth_id, NULL);
		if (r != SC_ERROR_OBJECT_NOT_FOUND)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "There already is a PIN with this ID.");
	}

	pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN, args->label, NULL, NULL);
	if (pin_obj == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate PIN object");

	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, auth_info);
	auth_info->auth_id = args->auth_id;

	/* Now store the PINs */
	sc_log(ctx, "Store PIN(%.*s,authID:%s)", (int) sizeof pin_obj->label, pin_obj->label, sc_pkcs15_print_id(&auth_info->auth_id));
	r = sc_pkcs15init_create_pin(p15card, profile, pin_obj, args);
	if (r < 0)
		sc_pkcs15_free_object(pin_obj);
	LOG_TEST_RET(ctx, r, "Card specific create PIN failed.");

	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_AODF, pin_obj);
	if (r < 0)
		sc_pkcs15_free_object(pin_obj);
	LOG_TEST_RET(ctx, r, "Failed to add PIN object");

	if (args->puk_id.len)
		r = sc_pkcs15init_store_puk(p15card, profile, args);

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


static int
sc_pkcs15init_create_pin(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15_object *pin_obj,
		struct sc_pkcs15init_pinargs *args)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	struct sc_file	*df = profile->df_info->file;
	int		r, retry = 0;

	LOG_FUNC_CALLED(ctx);
	/* Some cards need to keep all their PINs in separate directories.
	 * Create a subdirectory now, and put the pin into
	 * this subdirectory
	 */
	if (profile->pin_domains) {
		if (!profile->ops->create_domain)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "PIN domains not supported.");

		r = profile->ops->create_domain(profile, p15card, &auth_info->auth_id, &df);
		LOG_TEST_RET(ctx, r, "Card specific create domain failed");
	}

	/* Path encoded only for local PINs */
	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_LOCAL)
		auth_info->path = df->path;

	/* pin_info->reference = 0; */

	/* Loop until we come up with an acceptable pin reference */
	while (1) {
		if (profile->ops->select_pin_reference) {
			r = profile->ops->select_pin_reference(profile, p15card, auth_info);
			LOG_TEST_RET(ctx, r, "Card specific select PIN reference failed");

			retry = 1;
		}

		r = sc_pkcs15_find_pin_by_reference(p15card, &auth_info->path, pin_attrs->reference, NULL);
		if (r == SC_ERROR_OBJECT_NOT_FOUND)
			break;

		if (r != 0 || !retry)
			/* Other error trying to retrieve pin obj */
			LOG_TEST_RET(ctx, SC_ERROR_TOO_MANY_OBJECTS, "Failed to allocate PIN reference.");

		pin_attrs->reference++;
	}

	if (args->puk_len == 0)
		pin_attrs->flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED;

	sc_log(ctx, "create PIN with reference:%X, flags:%X, path:%s",
			pin_attrs->reference, pin_attrs->flags, sc_print_path(&auth_info->path));
	r = profile->ops->create_pin(profile, p15card,
			df, pin_obj,
			args->pin, args->pin_len,
			args->puk, args->puk_len);

	if (df != profile->df_info->file)
		sc_file_free(df);

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Default function for creating a pin subdirectory
 */
int
sc_pkcs15_create_pin_domain(struct sc_profile *profile,
		struct sc_pkcs15_card *p15card, const struct sc_pkcs15_id *id,
		struct sc_file **ret)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *df = profile->df_info->file;
	int	r;

	sc_log(ctx, "create PIN domain (path:%s,ID:%s)", sc_print_path(&df->path), sc_pkcs15_print_id(id));
	/* Instantiate PIN directory just below the application DF */
	r = sc_profile_instantiate_template(profile, "pin-domain", &df->path, "pin-dir", id, ret);
	if (r >= 0)   {
		sc_log(ctx, "create PIN DF(path:%s)", sc_print_path(&(*ret)->path));
		r = profile->ops->create_dir(profile, p15card, *ret);
	}

	return r;
}

static int
sc_pkcs15init_encode_prvkey_content(struct sc_pkcs15_card *p15card, struct sc_pkcs15_prkey *prvkey,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	if (prvkey->algorithm == SC_ALGORITHM_RSA)   {
		struct sc_pkcs15_pubkey pubkey;
		int rv;

		pubkey.algorithm = prvkey->algorithm;
		pubkey.u.rsa.modulus = prvkey->u.rsa.modulus;
		pubkey.u.rsa.exponent = prvkey->u.rsa.exponent;

		rv = sc_pkcs15_encode_pubkey(ctx, &pubkey, &object->content.value, &object->content.len);
		LOG_TEST_RET(ctx, rv, "Failed to encode public key");
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Prepare private key download, and initialize a prkdf entry
 */
static int
sc_pkcs15init_init_prkdf(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_prkeyargs *keyargs, struct sc_pkcs15_prkey *key, int keybits,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info;
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	struct sc_pkcs15_object *object = NULL;
	const char	*label;
	unsigned int	usage;
	int		r = 0, key_type;

	LOG_FUNC_CALLED(ctx);
	if (!res_obj || !keybits) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		LOG_TEST_GOTO_ERR(ctx, r, "Initialize PrKDF entry failed");
	}

	*res_obj = NULL;

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 1);
	}

	if ((label = keyargs->label) == NULL)
		label = DEFAULT_PRIVATE_KEY_LABEL;

	/* Create the prkey object now.
	 * If we find out below that we're better off reusing an
	 * existing object, we'll ditch this one */
	key_type = key_pkcs15_algo(p15card, key->algorithm);
	r = key_type;
	LOG_TEST_GOTO_ERR(ctx, r, "Unsupported key type");

	object = sc_pkcs15init_new_object(key_type, label, &keyargs->auth_id, NULL);
	if (object == NULL)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate new PrKey object");

	key_info = (struct sc_pkcs15_prkey_info *) object->data;
	key_info->usage = usage;
	key_info->native = 1;
	key_info->key_reference = 0;
	key_info->modulus_length = keybits;
	key_info->access_flags = keyargs->access_flags;
	object->user_consent = keyargs->user_consent;
	/* Path is selected below */

	if (keyargs->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE) {
		key_info->access_flags &= ~SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
	}

	/* Select a Key ID if the user didn't specify one,
	 * otherwise make sure it's compatible with our intended use */
	r = select_id(p15card, SC_PKCS15_TYPE_PRKEY, &keyargs->id);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot select ID for PrKey object");

	key_info->id = keyargs->id;

	if (key->algorithm == SC_ALGORITHM_GOSTR3410) {
		key_info->params.len = sizeof(*keyinfo_gostparams);
		/* FIXME: malloc() call in pkcs15init, but free() call
		 * in libopensc (sc_pkcs15_free_prkey_info) */
		key_info->params.data = malloc(key_info->params.len);
		if (!key_info->params.data) {
			r = SC_ERROR_OUT_OF_MEMORY;
			LOG_TEST_GOTO_ERR(ctx, r, "Cannot allocate memory for GOST parameters");
		}
		keyinfo_gostparams = key_info->params.data;
		keyinfo_gostparams->gostr3410 = keyargs->params.gost.gostr3410;
		keyinfo_gostparams->gostr3411 = keyargs->params.gost.gostr3411;
		keyinfo_gostparams->gost28147 = keyargs->params.gost.gost28147;
	}
	else if (key->algorithm == SC_ALGORITHM_EC)  {
		struct sc_ec_parameters *ecparams = &keyargs->key.u.ec.params;
		key_info->params.data = &keyargs->key.u.ec.params;
		key_info->params.free_params = sc_pkcs15init_empty_callback;
		key_info->field_length = ecparams->field_length;
		key_info->modulus_length = 0;
	}

	r = select_object_path(p15card, profile, object, &key_info->path);
	LOG_TEST_GOTO_ERR(ctx, r, "Failed to select private key object path");

	/* See if we need to select a key reference for this object */
	if (profile->ops->select_key_reference) {
		while (1) {
			sc_log(ctx, "Look for usable key reference starting from %i", key_info->key_reference);
			r = profile->ops->select_key_reference(profile, p15card, key_info);
			LOG_TEST_GOTO_ERR(ctx, r, "Failed to select card specific key reference");

			r = sc_pkcs15_find_prkey_by_reference(p15card, &key_info->path, key_info->key_reference, NULL);
			if (r == SC_ERROR_OBJECT_NOT_FOUND)   {
				sc_log(ctx, "Will use key reference %i", key_info->key_reference);
				break;
			}

			if (r != 0) {
				/* Other error trying to retrieve pin obj */
				r = SC_ERROR_TOO_MANY_OBJECTS;
				LOG_TEST_GOTO_ERR(ctx, r, "Failed to select key reference");
			}

			key_info->key_reference++;
		}
	}

	*res_obj = object;
	object = NULL;
	r = SC_SUCCESS;

err:
	if (object)
		sc_pkcs15init_free_object(object);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Prepare secret key download, and initialize a skdf entry
 */
static int
sc_pkcs15init_init_skdf(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_skeyargs *keyargs, struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_skey_info *key_info;
	struct sc_pkcs15_object *object = NULL;
	const char	*label;
	unsigned int	usage;
	unsigned int	keybits = keyargs->value_len;
	int		r = 0, key_type;

	LOG_FUNC_CALLED(ctx);
	if (!res_obj || !keybits) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		LOG_TEST_GOTO_ERR(ctx, r, "Initialize SKDF entry failed");
	}

	*res_obj = NULL;

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_ENCRYPT|SC_PKCS15_PRKEY_USAGE_DECRYPT;
	}

	if ((label = keyargs->label) == NULL)
		label = DEFAULT_SECRET_KEY_LABEL;

	/* Create the skey object now.
	 * If we find out below that we're better off reusing an
	 * existing object, we'll ditch this one */
	key_type = key_pkcs15_algo(p15card, keyargs->algorithm);
	r = key_type;
	LOG_TEST_GOTO_ERR(ctx, r, "Unsupported key type");

	object = sc_pkcs15init_new_object(key_type, label, &keyargs->auth_id, NULL);
	if (object == NULL)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate new SKey object");

	key_info = (struct sc_pkcs15_skey_info *) object->data;
	key_info->usage = usage;
	key_info->native = 1;
	key_info->key_reference = 0;
	switch (keyargs->algorithm) {
	case SC_ALGORITHM_DES:
		key_info->key_type = CKK_DES;
		break;
	case SC_ALGORITHM_3DES:
		key_info->key_type = CKK_DES3;
		break;
	case SC_ALGORITHM_AES:
		key_info->key_type = CKK_AES;
		break;
	default:
		key_info->key_type = CKK_GENERIC_SECRET;
		break;
	}
	key_info->value_len = keybits;
	key_info->access_flags = keyargs->access_flags;
	/* Path is selected below */

	if (keyargs->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE) {
		key_info->access_flags &= ~SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
	}

	if (keyargs->session_object > 0)
	    object->session_object = 1;

	object->user_consent = keyargs->user_consent;

	/* Select a Key ID if the user didn't specify one,
	 * otherwise make sure it's compatible with our intended use */
	r = select_id(p15card, SC_PKCS15_TYPE_SKEY, &keyargs->id);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot select ID for SKey object");

	key_info->id = keyargs->id;

	r = select_object_path(p15card, profile, object, &key_info->path);
	LOG_TEST_GOTO_ERR(ctx, r, "Failed to select secret key object path");

	/* See if we need to select a key reference for this object */
	if (profile->ops->select_key_reference)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_NOT_SUPPORTED, "SKey keyreference selection not supported");

	*res_obj = object;
	object = NULL;
	r = SC_SUCCESS;

err:
	if (object)
		sc_pkcs15init_free_object(object);
	LOG_FUNC_RETURN(ctx, r);
}

static int
_pkcd15init_set_aux_md_data(struct sc_pkcs15_card *p15card, struct sc_auxiliary_data **aux_data,
		unsigned char *guid, size_t guid_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char flags = SC_MD_CONTAINER_MAP_VALID_CONTAINER;
	char gd[SC_MD_MAX_CONTAINER_NAME_LEN + 1];
	int rv;

	LOG_FUNC_CALLED(ctx);

	if(!guid || !guid_len)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (!aux_data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (guid_len > SC_MD_MAX_CONTAINER_NAME_LEN)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	memset(gd, 0, sizeof(gd));
	memcpy(gd, guid, guid_len);

	if (*aux_data == NULL)   {
		rv = sc_aux_data_allocate(ctx, aux_data, NULL);
		LOG_TEST_RET(ctx, rv, "Failed to allocate aux data");
	}

	rv = sc_aux_data_set_md_guid(ctx, *aux_data, gd);
	LOG_TEST_RET(ctx, rv, "Failed to set private key CMAP record GUID");

	if (sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0) == 0)
		flags |= SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER;

	rv = sc_aux_data_set_md_flags(ctx, *aux_data, flags);
	LOG_TEST_RET(ctx, rv, "Failed to set private key CMAP record flags");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Copy gost3410 parameters (e.g. from prkey to pubkey)
 */
static int
sc_copy_gost_params(struct sc_pkcs15_gost_parameters *dst, struct sc_pkcs15_gost_parameters *src)
{
	if (!dst || !src)
		return SC_ERROR_INVALID_ARGUMENTS;

	memcpy((dst->key).value, (src->key).value, sizeof((src->key).value));
	memcpy((dst->hash).value, (src->hash).value, sizeof((src->hash).value));
	memcpy((dst->cipher).value, (src->cipher).value, sizeof((src->cipher).value));

	return SC_SUCCESS;
}

/*
 * Generate a new private key
 */
int
sc_pkcs15init_generate_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_keygen_args *keygen_args, unsigned int keybits,
		struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15init_pubkeyargs pubkey_args;
	struct sc_pkcs15_object *object = NULL;
	struct sc_pkcs15_prkey_info *key_info = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int r, caller_supplied_id = 0;

	LOG_FUNC_CALLED(ctx);
	/* check supported key size */
	r = check_keygen_params_consistency(p15card->card,
		keygen_args->prkey_args.key.algorithm, &keygen_args->prkey_args,
		&keybits);
	LOG_TEST_RET(ctx, r, "Invalid key size");

	if (check_key_compatibility(p15card, keygen_args->prkey_args.key.algorithm,
			&keygen_args->prkey_args.key, keygen_args->prkey_args.x509_usage,
			keybits, SC_ALGORITHM_ONBOARD_KEY_GEN) != SC_SUCCESS)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Cannot generate key with the given parameters");

	if (profile->ops->generate_key == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Key generation not supported");

	if (keygen_args->prkey_args.id.len)   {
		caller_supplied_id = 1;

		/* Make sure that private key's ID is the unique inside the PKCS#15 application */
		r = sc_pkcs15_find_prkey_by_id(p15card, &keygen_args->prkey_args.id, NULL);
		if (!r)
			LOG_TEST_RET(ctx, SC_ERROR_NON_UNIQUE_ID, "Non unique ID of the private key object");
		else if (r != SC_ERROR_OBJECT_NOT_FOUND)
			LOG_TEST_RET(ctx, r, "Find private key error");
	}

	/* Set up the PrKDF object */
	r = sc_pkcs15init_init_prkdf(p15card, profile, &keygen_args->prkey_args,
		&keygen_args->prkey_args.key, keybits, &object);
	LOG_TEST_RET(ctx, r, "Set up private key object error");

	key_info = (struct sc_pkcs15_prkey_info *) object->data;

	r = _pkcd15init_set_aux_md_data(p15card, &key_info->aux_data,
			keygen_args->prkey_args.guid, keygen_args->prkey_args.guid_len);
	LOG_TEST_RET(ctx, r, "Failed to set aux MD data");

	/* Set up the PuKDF info. The public key will be filled in
	 * by the card driver's generate_key function called below.
	 * Auth.ID of the public key object is left empty. */
	memset(&pubkey_args, 0, sizeof(pubkey_args));
	pubkey_args.id = keygen_args->prkey_args.id;
	pubkey_args.label = keygen_args->pubkey_label ? keygen_args->pubkey_label : object->label;
	pubkey_args.usage = keygen_args->prkey_args.usage;
	pubkey_args.x509_usage = keygen_args->prkey_args.x509_usage;

	if (keygen_args->prkey_args.key.algorithm == SC_ALGORITHM_GOSTR3410)   {
		pubkey_args.params.gost = keygen_args->prkey_args.params.gost;
		r = sc_copy_gost_params(&(pubkey_args.key.u.gostr3410.params), &(keygen_args->prkey_args.key.u.gostr3410.params));
		LOG_TEST_RET(ctx, r, "Cannot allocate GOST parameters");
	}
	else if (keygen_args->prkey_args.key.algorithm == SC_ALGORITHM_EC)   {
		pubkey_args.key.u.ec.params = keygen_args->prkey_args.key.u.ec.params;
		r = sc_copy_ec_params(&pubkey_args.key.u.ec.params, &keygen_args->prkey_args.key.u.ec.params);
		LOG_TEST_RET(ctx, r, "Cannot allocate EC parameters");
	}

	/* Generate the private key on card */
	r = profile->ops->create_key(profile, p15card, object);
	LOG_TEST_RET(ctx, r, "Cannot generate key: create key failed");

	r = profile->ops->generate_key(profile, p15card, object, &pubkey_args.key);
	LOG_TEST_RET(ctx, r, "Failed to generate key");

	/* update PrKDF entry */
	if (!caller_supplied_id)   {
		struct sc_pkcs15_id iid;

		/* Caller not supplied ID, so,
		 * if intrinsic ID can be calculated -- overwrite the native one */
		memset(&iid, 0, sizeof(iid));
		r = sc_pkcs15init_select_intrinsic_id(p15card, profile, SC_PKCS15_TYPE_PUBKEY, &iid, &pubkey_args.key);
		LOG_TEST_RET(ctx, r, "Select intrinsic ID error");

		if (iid.len)
			key_info->id = iid;
	}

	pubkey = &pubkey_args.key;
	if (!pubkey->alg_id)   {
		pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
		if (!pubkey->alg_id)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		sc_init_oid(&pubkey->alg_id->oid);
		pubkey->alg_id->algorithm = pubkey->algorithm;
	}

	pubkey_args.id = key_info->id;
	r = sc_pkcs15_encode_pubkey(ctx, pubkey, &object->content.value, &object->content.len);
	LOG_TEST_RET(ctx, r, "Failed to encode public key");

	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_PRKDF, object);
	LOG_TEST_RET(ctx, r, "Failed to add generated private key object");

	if (!r && profile->ops->emu_store_data)   {
		r = profile->ops->emu_store_data(p15card, profile, object, NULL, NULL);
		if (r == SC_ERROR_NOT_IMPLEMENTED)
			r = SC_SUCCESS;
		LOG_TEST_RET(ctx, r, "Card specific 'store data' failed");
	}

	r = sc_pkcs15init_store_public_key(p15card, profile, &pubkey_args, NULL);
	LOG_TEST_RET(ctx, r, "Failed to store public key");

	if (res_obj)
		*res_obj = object;

	sc_pkcs15_erase_pubkey(&pubkey_args.key);

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Generate a new secret key
 */
int
sc_pkcs15init_generate_secret_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_skeyargs *skey_args, struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *object = NULL;
	unsigned int keybits = skey_args->value_len;
	int r;

	LOG_FUNC_CALLED(ctx);
	/* check supported key size */
	r = check_keygen_params_consistency(p15card->card, skey_args->algorithm, NULL, &keybits);
	LOG_TEST_RET(ctx, r, "Invalid key size");

	if (check_key_compatibility(p15card, skey_args->algorithm, NULL, 0,
			keybits, SC_ALGORITHM_ONBOARD_KEY_GEN) != SC_SUCCESS)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Cannot generate key with the given parameters");

	if (profile->ops->generate_key == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Key generation not supported");

	if (skey_args->id.len)   {
		/* Make sure that secret key's ID is the unique inside the PKCS#15 application */
		r = sc_pkcs15_find_skey_by_id(p15card, &skey_args->id, NULL);
		if (!r)
			LOG_TEST_RET(ctx, SC_ERROR_NON_UNIQUE_ID, "Non unique ID of the private key object");
		else if (r != SC_ERROR_OBJECT_NOT_FOUND)
			LOG_TEST_RET(ctx, r, "Find private key error");
	}

	/* Set up the SKDF object */
	r = sc_pkcs15init_init_skdf(p15card, profile, skey_args, &object);
	LOG_TEST_RET(ctx, r, "Set up secret key object error");

	/* Generate the secret key on card */
	r = profile->ops->create_key(profile, p15card, object);
	LOG_TEST_RET(ctx, r, "Cannot generate key: create key failed");

	r = profile->ops->generate_key(profile, p15card, object, NULL);
	LOG_TEST_RET(ctx, r, "Failed to generate key");

	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_SKDF, object);
	LOG_TEST_RET(ctx, r, "Failed to add generated secret key object");

	if (!r && profile->ops->emu_store_data)   {
		r = profile->ops->emu_store_data(p15card, profile, object, NULL, NULL);
		if (r == SC_ERROR_NOT_IMPLEMENTED)
			r = SC_SUCCESS;
		LOG_TEST_RET(ctx, r, "Card specific 'store data' failed");
	}

	if (res_obj)
		*res_obj = object;

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Store private key
 */
int
sc_pkcs15init_store_private_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_prkeyargs *keyargs, struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *object = NULL;
	struct sc_pkcs15_prkey key;
	struct sc_pkcs15_prkey_info *key_info = NULL;
	int keybits, r = 0;

	LOG_FUNC_CALLED(ctx);
	/* Create a copy of the key first */
	key = keyargs->key;

	r = prkey_fixup(p15card, &key);
	LOG_TEST_RET(ctx, r, "Private key data sanity check failed");

	keybits = prkey_bits(p15card, &key);
	LOG_TEST_RET(ctx, keybits, "Invalid private key size");

	/* Now check whether the card is able to handle this key */
	if (check_key_compatibility(p15card, key.algorithm, &key, keyargs->x509_usage, keybits, 0) != SC_SUCCESS) {
		/* Make sure the caller explicitly tells us to store
		 * the key as extractable. */
		if (!(keyargs->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE))
			LOG_TEST_RET(ctx, SC_ERROR_INCOMPATIBLE_KEY, "Card does not support this key for crypto. Cannot store it as non extractable.");
	}

	/* Select a intrinsic Key ID if user didn't specify one */
	r = sc_pkcs15init_select_intrinsic_id(p15card, profile, SC_PKCS15_TYPE_PRKEY,
			&keyargs->id, &keyargs->key);
	LOG_TEST_RET(ctx, r, "Get intrinsic ID error");

	/* Make sure that private key's ID is the unique inside the PKCS#15 application */
	r = sc_pkcs15_find_prkey_by_id(p15card, &keyargs->id, NULL);
	if (!r)
		LOG_TEST_RET(ctx, SC_ERROR_NON_UNIQUE_ID, "Non unique ID of the private key object");
	else if (r != SC_ERROR_OBJECT_NOT_FOUND)
		LOG_TEST_RET(ctx, r, "Find private key error");

	/* Set up the PrKDF object */
	r = sc_pkcs15init_init_prkdf(p15card, profile, keyargs, &key, keybits, &object);
	LOG_TEST_RET(ctx, r, "Failed to initialize private key object");

	r = sc_pkcs15init_encode_prvkey_content(p15card, &key, object);
	LOG_TEST_RET(ctx, r, "Failed to encode public key");

	key_info = (struct sc_pkcs15_prkey_info *) object->data;
	r = _pkcd15init_set_aux_md_data(p15card, &key_info->aux_data, keyargs->guid, keyargs->guid_len);
	LOG_TEST_RET(ctx, r, "Failed to set aux MD data");

	if (profile->ops->create_key)
		r = profile->ops->create_key(profile, p15card, object);
	LOG_TEST_RET(ctx, r, "Card specific 'create key' failed");

	if (profile->ops->store_key)
		r = profile->ops->store_key(profile, p15card, object, &key);
	LOG_TEST_RET(ctx, r, "Card specific 'store key' failed");

	sc_pkcs15_free_object_content(object);
	r = sc_pkcs15init_encode_prvkey_content(p15card, &key, object);
	LOG_TEST_RET(ctx, r, "Failed to encode public key");

	/* Now update the PrKDF */
	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_PRKDF, object);
	LOG_TEST_RET(ctx, r, "Failed to add new private key PKCS#15 object");

	if (!r && profile->ops->emu_store_data)   {
		r = profile->ops->emu_store_data(p15card, profile, object, NULL, NULL);
		if (r == SC_ERROR_NOT_IMPLEMENTED)
			r = SC_SUCCESS;
		LOG_TEST_RET(ctx, r, "Card specific 'store data' failed");
	}

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Store a public key
 */
int
sc_pkcs15init_store_public_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_pubkeyargs *keyargs, struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *object = NULL;
	struct sc_pkcs15_pubkey_info *key_info;
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	struct sc_pkcs15_pubkey key;
	struct sc_path	*path;
	const char	*label;
	unsigned int	keybits, type = 0, usage;
	int		r;

	LOG_FUNC_CALLED(ctx);
	if (!keyargs)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Store public key aborted");

	/* Create a copy of the key first */
	key = keyargs->key;

	switch (key.algorithm) {
	case SC_ALGORITHM_RSA:
		keybits = sc_pkcs15init_keybits(&key.u.rsa.modulus);
		type = SC_PKCS15_TYPE_PUBKEY_RSA;
		break;
#ifdef SC_PKCS15_TYPE_PUBKEY_DSA
	case SC_ALGORITHM_DSA:
		keybits = sc_pkcs15init_keybits(&key.u.dsa.q);
		type = SC_PKCS15_TYPE_PUBKEY_DSA;
		break;
#endif
	case SC_ALGORITHM_GOSTR3410:
		keybits = SC_PKCS15_GOSTR3410_KEYSIZE;
		type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
		break;
	case SC_ALGORITHM_EC:
		type = SC_PKCS15_TYPE_PUBKEY_EC;

		key.u.ec.params = keyargs->key.u.ec.params;
		r = sc_pkcs15_fix_ec_parameters(ctx, &key.u.ec.params);
		LOG_TEST_RET(ctx, r, "Failed to fix EC public key parameters");

		keybits = key.u.ec.params.field_length;
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported key algorithm.");
	}

	if ((usage = keyargs->usage) == 0) {
		usage = SC_PKCS15_PRKEY_USAGE_VERIFY;
		if (keyargs->x509_usage)
			usage = sc_pkcs15init_map_usage(keyargs->x509_usage, 0);
	}
	label = keyargs->label;
	if (!label)
		label = "Public Key";

	/* Set up the pkcs15 object. */
	object = sc_pkcs15init_new_object(type, label, &keyargs->auth_id, NULL);
	if (object == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate new public key object");

	key_info = (struct sc_pkcs15_pubkey_info *) object->data;
	key_info->usage = usage;
	key_info->modulus_length = keybits;

	if (key.algorithm == SC_ALGORITHM_GOSTR3410) {
		key_info->params.len = sizeof(*keyinfo_gostparams);
		/* FIXME: malloc() call in pkcs15init, but free() call
		 * in libopensc (sc_pkcs15_free_prkey_info) */
		key_info->params.data = malloc(key_info->params.len);
		if (!key_info->params.data) {
			r = SC_ERROR_OUT_OF_MEMORY;
			LOG_TEST_GOTO_ERR(ctx, r, "Cannot allocate GOST params");
		}
		keyinfo_gostparams = key_info->params.data;
		keyinfo_gostparams->gostr3410 = keyargs->params.gost.gostr3410;
		keyinfo_gostparams->gostr3411 = keyargs->params.gost.gostr3411;
		keyinfo_gostparams->gost28147 = keyargs->params.gost.gost28147;
	}
	else if (key.algorithm == SC_ALGORITHM_EC)   {
		key_info->field_length = keybits;
		if (key.u.ec.params.der.value) {
			key_info->params.data = malloc(key.u.ec.params.der.len);
			if (!key_info->params.data) {
				r = SC_ERROR_OUT_OF_MEMORY;
				LOG_TEST_GOTO_ERR(ctx, r, "Cannot allocate EC params");
			}
			key_info->params.len = key.u.ec.params.der.len;
			memcpy(key_info->params.data, key.u.ec.params.der.value, key.u.ec.params.der.len);
		}
	}

	/* Select a intrinsic Key ID if the user didn't specify one */
	r = sc_pkcs15init_select_intrinsic_id(p15card, profile, SC_PKCS15_TYPE_PUBKEY, &keyargs->id, &key);
	LOG_TEST_GOTO_ERR(ctx, r, "Get intrinsic ID error");

	/* Select a Key ID if the user didn't specify one and there is no intrinsic ID,
	 * otherwise make sure it's unique */
	r = select_id(p15card, SC_PKCS15_TYPE_PUBKEY, &keyargs->id);
	LOG_TEST_GOTO_ERR(ctx, r, "Failed to select public key object ID");

	/* Make sure that private key's ID is the unique inside the PKCS#15 application */
	r = sc_pkcs15_find_pubkey_by_id(p15card, &keyargs->id, NULL);
	if (!r) {
		r = SC_ERROR_NON_UNIQUE_ID;
		LOG_TEST_GOTO_ERR(ctx, r, "Non unique ID of the public key object");
	} else if (r != SC_ERROR_OBJECT_NOT_FOUND)  {
		LOG_TEST_GOTO_ERR(ctx, r, "Find public key error");
	}

	key_info->id = keyargs->id;

	/* DER encode public key components */
	r = sc_pkcs15_encode_pubkey(p15card->card->ctx, &key, &object->content.value, &object->content.len);
	LOG_TEST_GOTO_ERR(ctx, r, "Encode public key error");

	r = sc_pkcs15_encode_pubkey(p15card->card->ctx, &key, &key_info->direct.raw.value, &key_info->direct.raw.len);
	LOG_TEST_GOTO_ERR(ctx, r, "RAW encode public key error");

	/* EC key are encoded as SPKI to preserve domain parameter */
	r = sc_pkcs15_encode_pubkey_as_spki(p15card->card->ctx, &key, &key_info->direct.spki.value, &key_info->direct.spki.len);
	LOG_TEST_GOTO_ERR(ctx, r, "SPKI encode public key error");

	/* Now create key file and store key */
	if (type == SC_PKCS15_TYPE_PUBKEY_EC)
		r = sc_pkcs15init_store_data(p15card, profile, object, &key_info->direct.spki, &key_info->path);
	else
		r = sc_pkcs15init_store_data(p15card, profile, object, &object->content, &key_info->path);

	path = &key_info->path;
	if (path->count == 0) {
		path->index = 0;
		path->count = -1;
	}

	/* Update the PuKDF */
	if (r >= 0)
		r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_PUKDF, object);

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

err:
	if (object && r < 0)
		sc_pkcs15init_free_object(object);

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Store secret key
 */
int
sc_pkcs15init_store_secret_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15init_skeyargs *keyargs, struct sc_pkcs15_object **res_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *object = NULL;
	int r = 0;

	LOG_FUNC_CALLED(ctx);

	/* Now check whether the card is able to handle this key */
	if (check_key_compatibility(p15card, keyargs->algorithm, NULL, 0, keyargs->value_len, 0) != SC_SUCCESS) {
		/* Make sure the caller explicitly tells us to store
		 * the key as extractable. */
		if (!(keyargs->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE))
			LOG_TEST_RET(ctx, SC_ERROR_INCOMPATIBLE_KEY, "Card does not support this key for crypto. Cannot store it as non extractable.");
	}

#ifdef ENABLE_OPENSSL
	if (!keyargs->id.len) {
		/* Calculating intrinsic Key ID for secret key does not make
		 * sense - just generate random one */
		if (RAND_bytes(keyargs->id.value, 20) == 1)
			keyargs->id.len = 20;
	}
#endif

	/* Make sure that secret key's ID is the unique inside the PKCS#15 application */
	r = sc_pkcs15_find_skey_by_id(p15card, &keyargs->id, NULL);
	if (!r)
		LOG_TEST_RET(ctx, SC_ERROR_NON_UNIQUE_ID, "Non unique ID of the secret key object");
	else if (r != SC_ERROR_OBJECT_NOT_FOUND)
		LOG_TEST_RET(ctx, r, "Find secret key error");

	/* Set up the SKDF object */
	r = sc_pkcs15init_init_skdf(p15card, profile, keyargs, &object);
	LOG_TEST_RET(ctx, r, "Failed to initialize secret key object");

	if (profile->ops->create_key)
		r = profile->ops->create_key(profile, p15card, object);
	LOG_TEST_RET(ctx, r, "Card specific 'create key' failed");

	/* If no key data, only an empty EF is created. 
	 * It can be used to receive an unwrapped key later. */
	if (keyargs->key.data_len > 0) {
		if (profile->ops->store_key) {
			struct sc_pkcs15_prkey key;
			memset(&key, 0, sizeof(key));
			key.algorithm = keyargs->algorithm;
			key.u.secret = keyargs->key;
			r = profile->ops->store_key(profile, p15card, object, &key);
		}
	}
	LOG_TEST_RET(ctx, r, "Card specific 'store key' failed");

	sc_pkcs15_free_object_content(object);

	/* Now update the SKDF, unless it is a session object.
	   If we have an on card session object, we have created the actual key object on card.
	   The card handles removing it when the session is finished or during the next reset.
	   We will maintain the object in the P15 structure in memory for duration of the session,
	   but we don't want it to be written into SKDF. */
	if (!object->session_object) {
		r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_SKDF, object);
		LOG_TEST_RET(ctx, r, "Failed to add new secret key PKCS#15 object");
	}

	if (!r && profile->ops->emu_store_data && !object->session_object)   {
		r = profile->ops->emu_store_data(p15card, profile, object, NULL, NULL);
		if (r == SC_ERROR_NOT_IMPLEMENTED)
			r = SC_SUCCESS;
		LOG_TEST_RET(ctx, r, "Card specific 'store data' failed");
	}

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
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
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *cert_info = NULL;
	struct sc_pkcs15_object *object = NULL;
	struct sc_pkcs15_object *key_object = NULL;
	struct sc_path existing_path;
	const char *label = NULL;
	int		r;

	LOG_FUNC_CALLED(ctx);

	memset(&existing_path, 0, sizeof(struct sc_path));

	label = args->label;
	if (!label)
		label = "Certificate";

	r = sc_pkcs15init_select_intrinsic_id(p15card, profile, SC_PKCS15_TYPE_CERT_X509,
			&args->id, &args->der_encoded);
	LOG_TEST_RET(ctx, r, "Get certificate 'intrinsic ID' error");
	sc_log(ctx, "Cert(ID:%s) rv %i", sc_pkcs15_print_id(&args->id), r);

	/* Select an ID if the user didn't specify one, otherwise make sure it's unique */
	r = select_id(p15card, SC_PKCS15_TYPE_CERT, &args->id);
	if (r == SC_ERROR_NON_UNIQUE_ID && args->update)   {
		struct sc_pkcs15_object *existing_obj = NULL;

		r = sc_pkcs15_find_object_by_id(p15card, SC_PKCS15_TYPE_CERT, &args->id, &existing_obj);
		if (!r)   {
			sc_log(ctx, "Found cert(ID:%s)", sc_pkcs15_print_id(&args->id));
			existing_path = ((struct sc_pkcs15_cert_info *)existing_obj->data)->path;

			sc_pkcs15_remove_object(p15card, existing_obj);
			sc_pkcs15_free_object(existing_obj);
		}

		r = select_id(p15card, SC_PKCS15_TYPE_CERT, &args->id);
	}
	sc_log(ctx, "Select ID Cert(ID:%s) rv %i", sc_pkcs15_print_id(&args->id), r);
	LOG_TEST_RET(ctx, r, "Select certificate ID error");

	object = sc_pkcs15init_new_object(SC_PKCS15_TYPE_CERT_X509, label, NULL, NULL);
	if (object == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate certificate object");
	cert_info = (struct sc_pkcs15_cert_info *) object->data;
	cert_info->id = args->id;
	cert_info->authority = args->authority;
	sc_der_copy(&object->content, &args->der_encoded);
	sc_der_copy(&cert_info->value, &args->der_encoded);

	if (existing_path.len)   {
		sc_log(ctx, "Using existing path %s", sc_print_path(&existing_path));
		cert_info->path = existing_path;
	}

	sc_log(ctx, "Store cert(%.*s,ID:%s,der(%p,%"SC_FORMAT_LEN_SIZE_T"u))",
	       (int) sizeof object->label, object->label,
	       sc_pkcs15_print_id(&cert_info->id), args->der_encoded.value,
	       args->der_encoded.len);

	if (!profile->pkcs15.direct_certificates)
		r = sc_pkcs15init_store_data(p15card, profile, object, &args->der_encoded, &cert_info->path);

	/* Now update the CDF */
	if (r >= 0)   {
		r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_CDF, object);
		/* TODO: update private key PKCS#15 object with the certificate's attributes */
	}

	if (r >= 0)   {
		r = sc_pkcs15_prkey_attrs_from_cert(p15card, object, &key_object);
		if (r)   {
			r = 0;
		}
		else if (key_object) {
			if (profile->ops->emu_update_any_df) {
				r = profile->ops->emu_update_any_df(profile, p15card, SC_AC_OP_UPDATE, key_object);
				if (r == SC_ERROR_NOT_SUPPORTED)
					r = SC_SUCCESS;
			}
			else {
				r = sc_pkcs15init_update_any_df(p15card, profile, key_object->df, 0);
				sc_log(ctx, "update_any_df returned %i", r);
			}
		}
	}

	if (r < 0)   {
		sc_pkcs15_remove_object(p15card, object);
		sc_pkcs15_free_object(object);
	}
	else if (res_obj)   {
		*res_obj = object;
	}

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
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
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *data_object_info;
	struct sc_pkcs15_object *object;
	struct sc_pkcs15_object *objs[32];
	const char	*label;
	int		r, i;
	unsigned int    tid = 0x01;

	LOG_FUNC_CALLED(ctx);
	if (!profile)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing profile");
	label = args->label;

	if (!args->id.len) {
		/* Select an ID if the user didn't specify one, otherwise
		 * make sure it's unique (even though data objects doesn't
		 * have a pkcs15 id we need one here to create a unique
		 * file id from the data file template */
		r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
		LOG_TEST_RET(ctx, r, "Get 'DATA' objects error");

		for (i = 0; i < r; i++) {
			unsigned char cid;
			struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
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
	}
	else   {
		/* in case the user specifies an id it should be at most
		 * one byte long */
		if (args->id.len > 1)
			return SC_ERROR_INVALID_ARGUMENTS;
	}

	object = sc_pkcs15init_new_object(SC_PKCS15_TYPE_DATA_OBJECT, label, &args->auth_id, NULL);
	if (object == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	data_object_info = (struct sc_pkcs15_data_info *) object->data;
	if (args->app_label != NULL)
		strlcpy(data_object_info->app_label, args->app_label, sizeof(data_object_info->app_label));
	else if (label != NULL)
		strlcpy(data_object_info->app_label, label, sizeof(data_object_info->app_label));

	data_object_info->app_oid = args->app_oid;
	sc_der_copy(&data_object_info->data, &args->der_encoded);

	r = sc_pkcs15init_store_data(p15card, profile, object, &args->der_encoded, &data_object_info->path);
	LOG_TEST_RET(ctx, r, "Store 'DATA' object error");

	/* Now update the DDF */
	r = sc_pkcs15init_add_object(p15card, profile, SC_PKCS15_DODF, object);
	LOG_TEST_RET(ctx, r, "'DODF' update error");

	if (r >= 0 && res_obj)
		*res_obj = object;

	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_get_pin_reference(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, unsigned auth_method, int reference)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_pkcs15_object *auth_objs[0x10];
	int r, ii, nn_objs;

	LOG_FUNC_CALLED(ctx);

	/* 1. Look for the corresponding pkcs15 PIN object. */

	/* Get all existing pkcs15 AUTH objects */
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, auth_objs, 0x10);
	LOG_TEST_RET(ctx, r, "Get PKCS#15 AUTH objects error");
	nn_objs = r;

	sc_log(ctx, "found %i auth objects; looking for AUTH object(auth_method:%i,reference:%i)",
			nn_objs, auth_method, reference);
	for (ii=0; ii<nn_objs; ii++)   {
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *)auth_objs[ii]->data;
		struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;

		sc_log(ctx, "check PIN(%.*s,auth_method:%i,type:%i,reference:%i,flags:%X)",
				(int) sizeof auth_objs[ii]->label, auth_objs[ii]->label, auth_info->auth_method, pin_attrs->type,
				pin_attrs->reference, pin_attrs->flags);
		/* Find out if there is AUTH pkcs15 object with given 'type' and 'reference' */
		if (auth_info->auth_method == auth_method && pin_attrs->reference == reference)
			LOG_FUNC_RETURN(ctx, pin_attrs->reference);

		if (auth_method != SC_AC_SYMBOLIC)
			continue;

		/* Translate 'SYMBOLIC' PIN reference into the pkcs#15 pinAttributes.flags
		 * 	and check for the existing pkcs15 PIN object with these flags. */
		switch (reference)   {
		case SC_PKCS15INIT_USER_PIN:
			if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				continue;
			if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
				continue;
			break;
		case SC_PKCS15INIT_SO_PIN:
			if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
				continue;
			if (!(pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN))
				continue;
			break;
		case SC_PKCS15INIT_USER_PUK:
			if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				continue;
			if (!(pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))
				continue;
			break;
		case SC_PKCS15INIT_SO_PUK:
			if (!(pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))
				continue;
			if (!(pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN))
				continue;
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid Symbolic PIN reference");
		}

		LOG_FUNC_RETURN(ctx, pin_attrs->reference);

	}

	/* 2. No existing pkcs15 PIN object
	 *	-- check if profile defines some PIN with 'reference' as PIN reference. */
	r = sc_profile_get_pin_id_by_reference(profile, auth_method, reference, &auth_info);
	if (r < 0)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "PIN template not found");

	LOG_FUNC_RETURN(ctx, auth_info.attrs.pin.reference);
}


static int
sc_pkcs15init_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object, struct sc_pkcs15_der *data,
		struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file	*file = NULL;
	int		r;

	LOG_FUNC_CALLED(ctx);

	if (profile->ops->emu_store_data)   {
		r = profile->ops->emu_store_data(p15card, profile, object, data, path);
		if (r == SC_SUCCESS || r != SC_ERROR_NOT_IMPLEMENTED)
			LOG_FUNC_RETURN(ctx, r);
	}

	r = select_object_path(p15card, profile, object, path);
	LOG_TEST_RET(ctx, r, "Failed to select object path");

	r = sc_profile_get_file_by_path(profile, path, &file);
	LOG_TEST_RET(ctx, r, "Failed to get file by path");

	if (file->path.count == 0) {
		file->path.index = 0;
		file->path.count = -1;
	}

	r = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	if (r && r != SC_ERROR_FILE_NOT_FOUND) {
		sc_file_free(file);
		LOG_TEST_RET(ctx, r, "Cannot delete file");
	}

	r = sc_pkcs15init_update_file(profile, p15card, file, data->value, data->len);

	*path = file->path;

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
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
static size_t
sc_pkcs15init_keybits(struct sc_pkcs15_bignum *bn)
{
	unsigned int	mask, bits;

	if (!bn || !bn->len)
		return 0;
	bits = bn->len << 3;
	for (mask = 0x80; mask && !(bn->data[0] & mask); mask >>= 1)
		bits--;
	return bits;
}


/*
 * Check consistency of the key parameters.
 */
static int
check_keygen_params_consistency(struct sc_card *card,
		unsigned int alg, struct sc_pkcs15init_prkeyargs *prkey,
		unsigned int *keybits)
{
	struct sc_context *ctx = card->ctx;
	int i, rv;

	if (alg == SC_ALGORITHM_EC && prkey)   {
		struct sc_ec_parameters *ecparams = &prkey->key.u.ec.params;

		rv = sc_pkcs15_fix_ec_parameters(ctx, ecparams);
		LOG_TEST_RET(ctx, rv, "Cannot fix EC parameters");

		sc_log(ctx, "EC parameters: %s", sc_dump_hex(ecparams->der.value, ecparams->der.len));
		if (!*keybits)
			*keybits = ecparams->field_length;
	}

	for (i = 0; i < card->algorithm_count; i++) {
		struct sc_algorithm_info *info = &card->algorithms[i];

		if (info->algorithm != alg)
			continue;

		if (info->key_length != *keybits)
			continue;

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


/*
 * Check whether the card has native crypto support for this key.
 */
static int
check_key_compatibility(struct sc_pkcs15_card *p15card, unsigned int alg,
		struct sc_pkcs15_prkey *prkey, unsigned int x509_usage,
		unsigned int key_length, unsigned int flags)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_algorithm_info *info;
	unsigned int count;

	LOG_FUNC_CALLED(ctx);
	count = p15card->card->algorithm_count;
	for (info = p15card->card->algorithms; count--; info++) {
		/* don't check flags if none was specified */
		if (info->algorithm != alg || info->key_length != key_length)
			continue;
		if (flags != 0 && ((info->flags & flags) != flags))
			continue;

		if (alg == SC_ALGORITHM_RSA && prkey)   {
			if (info->u._rsa.exponent != 0 && prkey->u.rsa.exponent.len != 0) {
				struct sc_pkcs15_bignum *e = &prkey->u.rsa.exponent;
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
		}
		else if (alg == SC_ALGORITHM_EC)   {
			if (!sc_valid_oid(&prkey->u.ec.params.id))
				if (sc_pkcs15_fix_ec_parameters(ctx, &prkey->u.ec.params))
					LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_VALID);
			if (sc_valid_oid(&info->u._ec.params.id))
				if (!sc_compare_oid(&info->u._ec.params.id, &prkey->u.ec.params.id))
					continue;
		}

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_VALID);
}


/*
 * Check RSA key for consistency, and compute missing
 * CRT elements
 */
static int
prkey_fixup_rsa(struct sc_pkcs15_card *p15card, struct sc_pkcs15_prkey_rsa *key)
{
	struct sc_context *ctx = p15card->card->ctx;

	if (!key->modulus.len || !key->exponent.len || !key->d.len || !key->p.len || !key->q.len) {
		sc_log(ctx, "Missing private RSA coefficient");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

#ifdef ENABLE_OPENSSL

	/* Generate additional parameters.
	 * At least the GPK seems to need the full set of CRT
	 * parameters; storing just the private exponent produces
	 * invalid signatures.
	 * The cryptoflex does not seem to be able to do any sort
	 * of RSA without the full set of CRT coefficients either
	 */
	 /* We don't really need an RSA structure, only the BIGNUMs */

	if (!key->dmp1.len || !key->dmq1.len || !key->iqmp.len) {
		BIGNUM *aux;
		BN_CTX *bn_ctx;
		BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_p, *rsa_q, *rsa_dmp1, *rsa_dmq1, *rsa_iqmp;

		rsa_n = BN_bin2bn(key->modulus.data, key->modulus.len, NULL);
		rsa_e = BN_bin2bn(key->exponent.data, key->exponent.len, NULL);
		rsa_d = BN_bin2bn(key->d.data, key->d.len, NULL);
		rsa_p = BN_bin2bn(key->p.data, key->p.len, NULL);
		rsa_q = BN_bin2bn(key->q.data, key->q.len, NULL);
		rsa_dmp1 = BN_new();
		rsa_dmq1 = BN_new();
		rsa_iqmp = BN_new();

		aux = BN_new();
		bn_ctx = BN_CTX_new();

		BN_sub(aux, rsa_q, BN_value_one());
		BN_mod(rsa_dmq1, rsa_d, aux, bn_ctx);

		BN_sub(aux, rsa_p, BN_value_one());
		BN_mod(rsa_dmp1, rsa_d, aux, bn_ctx);

		BN_mod_inverse(rsa_iqmp, rsa_q, rsa_p, bn_ctx);

		BN_clear_free(aux);
		BN_CTX_free(bn_ctx);

		/* Do not replace, only fill in missing */
		if (key->dmp1.data == NULL) {
			key->dmp1.len = BN_num_bytes(rsa_dmp1);
			key->dmp1.data = malloc(key->dmp1.len);
			if (key->dmp1.data) {
				BN_bn2bin(rsa_dmp1, key->dmp1.data);
			} else {
				key->dmp1.len = 0;
			}
		}

		if (key->dmq1.data == NULL) {
			key->dmq1.len = BN_num_bytes(rsa_dmq1);
			key->dmq1.data = malloc(key->dmq1.len);
			if (key->dmq1.data) {
				BN_bn2bin(rsa_dmq1, key->dmq1.data);
			} else {
				key->dmq1.len = 0;
			}
		}
		if (key->iqmp.data == NULL) {
			key->iqmp.len = BN_num_bytes(rsa_iqmp);
			key->iqmp.data = malloc(key->iqmp.len);
			if (key->iqmp.data) {
				BN_bn2bin(rsa_iqmp, key->iqmp.data);
			} else {
				key->iqmp.len = 0;
			}
		}

		BN_clear_free(rsa_n);
		BN_clear_free(rsa_e);
		BN_clear_free(rsa_d);
		BN_clear_free(rsa_p);
		BN_clear_free(rsa_q);
		BN_clear_free(rsa_dmp1);
		BN_clear_free(rsa_dmq1);
		BN_clear_free(rsa_iqmp);

	}
#endif
	return 0;
}


static int
prkey_fixup(struct sc_pkcs15_card *p15card, struct sc_pkcs15_prkey *key)
{
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return prkey_fixup_rsa(p15card, &key->u.rsa);
	case SC_ALGORITHM_DSA:
	case SC_ALGORITHM_GOSTR3410:
		/* for now */
		return 0;
	}
	return 0;
}


static int
prkey_bits(struct sc_pkcs15_card *p15card, struct sc_pkcs15_prkey *key)
{
	struct sc_context *ctx = p15card->card->ctx;

	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return sc_pkcs15init_keybits(&key->u.rsa.modulus);
	case SC_ALGORITHM_DSA:
		return sc_pkcs15init_keybits(&key->u.dsa.q);
	case SC_ALGORITHM_GOSTR3410:
		if (sc_pkcs15init_keybits(&key->u.gostr3410.d) > SC_PKCS15_GOSTR3410_KEYSIZE) {
			sc_log(ctx,
			       "Unsupported key (keybits %"SC_FORMAT_LEN_SIZE_T"u)",
			       sc_pkcs15init_keybits(&key->u.gostr3410.d));
			return SC_ERROR_OBJECT_NOT_VALID;
		}
		return SC_PKCS15_GOSTR3410_KEYSIZE;
	case SC_ALGORITHM_EC:
		sc_log(ctx, "Private EC key length %"SC_FORMAT_LEN_SIZE_T"u",
		       key->u.ec.params.field_length);
		if (key->u.ec.params.field_length == 0)   {
			sc_log(ctx, "Invalid EC key length");
			return SC_ERROR_OBJECT_NOT_VALID;
		}
		return key->u.ec.params.field_length;
	}
	sc_log(ctx, "Unsupported key algorithm.");
	return SC_ERROR_NOT_SUPPORTED;
}


static int
key_pkcs15_algo(struct sc_pkcs15_card *p15card, unsigned int algorithm)
{
	struct sc_context *ctx = p15card->card->ctx;

	switch (algorithm) {
	case SC_ALGORITHM_RSA:
		return SC_PKCS15_TYPE_PRKEY_RSA;
	case SC_ALGORITHM_DSA:
		return SC_PKCS15_TYPE_PRKEY_DSA;
	case SC_ALGORITHM_GOSTR3410:
		return SC_PKCS15_TYPE_PRKEY_GOSTR3410;
	case SC_ALGORITHM_EC:
		return SC_PKCS15_TYPE_PRKEY_EC;
	case SC_ALGORITHM_DES:
		return SC_PKCS15_TYPE_SKEY_DES;
	case SC_ALGORITHM_3DES:
		return SC_PKCS15_TYPE_SKEY_3DES;
	case SC_ALGORITHM_AES:
	case SC_ALGORITHM_UNDEFINED:
		return SC_PKCS15_TYPE_SKEY_GENERIC;
	}
	sc_log(ctx, "Unsupported key algorithm.");
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
sc_pkcs15init_select_intrinsic_id(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		int type, struct sc_pkcs15_id *id_out, void *data)
{
#ifndef ENABLE_OPENSSL
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
#else
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	unsigned id_style;
	struct sc_pkcs15_id id;
	unsigned char *id_data = NULL;
	size_t id_data_len = 0;
	int rv, allocated = 0;

	LOG_FUNC_CALLED(ctx);

	if (!id_out || !profile)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	id_style = profile->id_style;

	/* ID already exists */
	if (id_out->len)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	/* Native ID style is not intrinsic one */
	if (id_style == SC_PKCS15INIT_ID_STYLE_NATIVE)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	memset(&id, 0, sizeof(id));
	/* Get PKCS15 public key */
	switch(type)   {
	case SC_PKCS15_TYPE_CERT_X509:
		rv = sc_pkcs15_pubkey_from_cert(ctx, (struct sc_pkcs15_der *)data, &pubkey);
		LOG_TEST_RET(ctx, rv, "X509 parse error");
		allocated = 1;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		rv = sc_pkcs15_pubkey_from_prvkey(ctx, (struct sc_pkcs15_prkey *)data, &pubkey);
		LOG_TEST_RET(ctx, rv, "Cannot get public key");
		allocated = 1;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		pubkey = (struct sc_pkcs15_pubkey *)data;
		allocated = 0;
		break;
	default:
		sc_log(ctx, "Intrinsic ID is not implemented for the object type 0x%X", type);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	/* Skip silently if key is not initialized. */
	if (pubkey->algorithm == SC_ALGORITHM_RSA && !pubkey->u.rsa.modulus.len)
		goto done;
	else if (pubkey->algorithm == SC_ALGORITHM_DSA && !pubkey->u.dsa.pub.data)
		goto done;
	else if (pubkey->algorithm == SC_ALGORITHM_GOSTR3410 &&
			!pubkey->u.gostr3410.xy.data)
		goto done;
	else if (pubkey->algorithm == SC_ALGORITHM_EC && !pubkey->u.ec.ecpointQ.value)
		goto done;

	/* In Mozilla 'GOST R 34.10' is not yet supported.
	 * So, switch to the ID recommended by RFC2459 */
	if (pubkey->algorithm == SC_ALGORITHM_GOSTR3410 && id_style == SC_PKCS15INIT_ID_STYLE_MOZILLA)
		id_style = SC_PKCS15INIT_ID_STYLE_RFC2459;

	switch (id_style)  {
	case SC_PKCS15INIT_ID_STYLE_MOZILLA:
		if (pubkey->algorithm == SC_ALGORITHM_RSA)
			SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, id.value);
		else if (pubkey->algorithm == SC_ALGORITHM_DSA)
			SHA1(pubkey->u.dsa.pub.data, pubkey->u.dsa.pub.len, id.value);
		else if (pubkey->algorithm == SC_ALGORITHM_EC)
			/* ID should be SHA1 of the X coordinate according to PKCS#15 v1.1 */
			/* skip the 04 tag and get the X component */
			SHA1(pubkey->u.ec.ecpointQ.value+1, (pubkey->u.ec.ecpointQ.len - 1) / 2, id.value);
		else
			goto done;

		id.len = SHA_DIGEST_LENGTH;
		break;
	case SC_PKCS15INIT_ID_STYLE_RFC2459:
		rv = sc_pkcs15_encode_pubkey(ctx, pubkey, &id_data, &id_data_len);
		LOG_TEST_GOTO_ERR(ctx, rv, "Encoding public key error");

		if (!id_data || !id_data_len) {
			rv = SC_ERROR_INTERNAL;
			LOG_TEST_GOTO_ERR(ctx, rv, "Encoding public key error");
		}

		SHA1(id_data, id_data_len, id.value);
		id.len = SHA_DIGEST_LENGTH;

		break;
	default:
		sc_log(ctx, "Unsupported ID style: %i", id_style);
		rv = SC_ERROR_NOT_SUPPORTED;
		LOG_TEST_GOTO_ERR(ctx, rv, "Non supported ID style");
	}

done:
	memcpy(id_out, &id, sizeof(*id_out));
	rv = id_out->len;
err:
	if (id_data)
		free(id_data);
	if (allocated)
		sc_pkcs15_free_pubkey(pubkey);

	LOG_FUNC_RETURN(ctx, rv);
#endif
}


static int
select_id(struct sc_pkcs15_card *p15card, int type, struct sc_pkcs15_id *id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_id unused_id;
	struct sc_pkcs15_object *obj;
	unsigned int nid = DEFAULT_ID;
	int r;

	LOG_FUNC_CALLED(ctx);
	/* If the user provided an ID, make sure we can use it */
	if (id->len != 0) {
		r = sc_pkcs15_find_object_by_id(p15card, type, id, &obj);

		if (r == SC_ERROR_OBJECT_NOT_FOUND)
			r = 0;
		else if (!r)
			r = SC_ERROR_NON_UNIQUE_ID;

		LOG_FUNC_RETURN(ctx, r);
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
				struct sc_pkcs15_search_key search_key;

				memset(&search_key, 0, sizeof(search_key));
				search_key.class_mask = SC_PKCS15_SEARCH_CLASS_PUBKEY | SC_PKCS15_SEARCH_CLASS_CERT;
				search_key.id = id;

				r = sc_pkcs15_search_objects(p15card, &search_key, NULL, 0);
				/* If there is a pubkey or cert with
				 * this ID, skip it. */
				if (r > 0)
					continue;
			}
			if (!unused_id.len)
				unused_id = *id;
			continue;
		}
	}

	if (unused_id.len) {
		*id = unused_id;
		LOG_FUNC_RETURN(ctx, 0);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_TOO_MANY_OBJECTS);
}


/*
 * Select a path for a new object
 *  1.	If the object is to be protected by a PIN, use the path
 *	given in the PIN auth object
 *  2.	Otherwise, use the path of the application DF
 *  3.	If the profile defines a key-dir template, the new object
 *	should go into a subdirectory of the selected DF:
 *	Instantiate the template, using the ID of the new object
 *	to uniquify the path. Inside the instantiated template,
 *	look for a file corresponding to the type of object we
 *	wish to create ("private-key", "public-key" etc).
 */
static const char *
get_template_name_from_object (struct sc_pkcs15_object *obj)
{
	switch (obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		return "private-key";
	case SC_PKCS15_TYPE_PUBKEY:
		return "public-key";
	case SC_PKCS15_TYPE_SKEY:
		return "secret-key";
	case SC_PKCS15_TYPE_CERT:
		return "certificate";
	case SC_PKCS15_TYPE_DATA_OBJECT:
		if (obj->flags & SC_PKCS15_CO_FLAG_PRIVATE)
			return "privdata";
		else
			return "data";
	}

	return NULL;
}


static int
get_object_path_from_object (struct sc_pkcs15_object *obj,
		struct sc_path *ret_path)
{
	if (!ret_path)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(ret_path, 0, sizeof(struct sc_path));

	switch(obj->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PRKEY:
		*ret_path = ((struct sc_pkcs15_prkey_info *)obj->data)->path;
		return SC_SUCCESS;
	case SC_PKCS15_TYPE_PUBKEY:
		*ret_path = ((struct sc_pkcs15_pubkey_info *)obj->data)->path;
		return SC_SUCCESS;
	case SC_PKCS15_TYPE_SKEY:
		*ret_path = ((struct sc_pkcs15_skey_info *)obj->data)->path;
		return SC_SUCCESS;
	case SC_PKCS15_TYPE_CERT:
		*ret_path = ((struct sc_pkcs15_cert_info *)obj->data)->path;
		return SC_SUCCESS;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		*ret_path = ((struct sc_pkcs15_data_info *)obj->data)->path;
		return SC_SUCCESS;
	case SC_PKCS15_TYPE_AUTH:
		*ret_path = ((struct sc_pkcs15_auth_info *)obj->data)->path;
		return SC_SUCCESS;
	}
	return SC_ERROR_NOT_SUPPORTED;
}


static int
select_object_path(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *obj, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file	*file;
	struct sc_pkcs15_object	*objs[32];
	struct sc_pkcs15_id indx_id;
	struct sc_path obj_path;
	int ii, r, nn_objs, indx;
	const char *name;

	LOG_FUNC_CALLED(ctx);
	r = sc_pkcs15_get_objects(p15card, obj->type & SC_PKCS15_TYPE_CLASS_MASK, objs, sizeof(objs)/sizeof(objs[0]));
	LOG_TEST_RET(ctx, r, "Get PKCS#15 objects error");
	nn_objs = r;

	/* For cards with a pin-domain profile, we need
	 * to put the key below the DF of the specified PIN
	 */
	memset(path, 0, sizeof(*path));
	if (obj->auth_id.len && profile->pin_domains != 0) {
		r = sc_pkcs15init_get_pin_path(p15card, &obj->auth_id, path);
		LOG_TEST_RET(ctx, r, "Cannot get PIN path");
	}
	else {
		*path = profile->df_info->file->path;
	}

	/* If the profile specifies a key directory template,
	 * instantiate it now and create the DF
	 */
	name = get_template_name_from_object (obj);
	if (!name)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sc_log(ctx, "key-domain.%s @%s (auth_id.len=%"SC_FORMAT_LEN_SIZE_T"u)",
	       name, sc_print_path(path), obj->auth_id.len);

	indx_id.len = 1;
	for (indx = TEMPLATE_INSTANTIATE_MIN_INDEX; indx <= TEMPLATE_INSTANTIATE_MAX_INDEX; indx++)   {
		indx_id.value[0] = indx;
		r = sc_profile_instantiate_template(profile, "key-domain", path, name, &indx_id, &file);
		if (r == SC_ERROR_TEMPLATE_NOT_FOUND)   {
			/* No template in 'key-domain' -- try to instantiate the template-'object name'
			 * outside of the 'key-domain' scope. */
			char t_name[0x40];

			snprintf(t_name, sizeof(t_name), "template-%s", name);
			sc_log(ctx, "get instance %i of '%s'", indx, t_name);
			r = sc_profile_get_file_instance(profile, t_name, indx, &file);
			if (r == SC_ERROR_FILE_NOT_FOUND)
				LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
		LOG_TEST_RET(ctx, r, "Template instantiation error");

		if (file->type == SC_FILE_TYPE_BSO)
			break;

		sc_log(ctx, "instantiated template path %s", sc_print_path(&file->path));
		for (ii=0; ii<nn_objs; ii++)   {
			r = get_object_path_from_object(objs[ii], &obj_path);
			LOG_TEST_RET(ctx, r, "Failed to get object path from pkcs15 object");

			if (obj_path.len != file->path.len)
				break;

			if (!memcmp(obj_path.value, file->path.value, obj_path.len))
				break;
		}

		if (ii==nn_objs)
			break;

		if (obj_path.len != file->path.len)
			break;

		sc_file_free(file);

		indx_id.value[0] += 1;
	}

	if (indx > TEMPLATE_INSTANTIATE_MAX_INDEX)
		LOG_TEST_RET(ctx, SC_ERROR_TOO_MANY_OBJECTS, "Template instantiation error");

	*path = file->path;
	sc_file_free(file);

	sc_log(ctx, "returns object path '%s'", sc_print_path(path));
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Update EF(DIR)
 */
static int
sc_pkcs15init_update_dir(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_app_info *app)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card	*card = p15card->card;
	int r, retry = 1;

	LOG_FUNC_CALLED(ctx);
	if (profile->ops->emu_update_dir)   {
		r = profile->ops->emu_update_dir(profile, p15card, app);
		LOG_FUNC_RETURN(ctx, r);
	}

	do {
		struct sc_file	*dir_file;
		struct sc_path	path;

		r = sc_enum_apps(card);
		if (r != SC_ERROR_FILE_NOT_FOUND)
			break;
		/* DIR file is not yet created. */

		sc_format_path("3F002F00", &path);
		r = sc_profile_get_file_by_path(profile, &path, &dir_file);
		LOG_TEST_RET(ctx, r, "DIR file not defined in profile");

		/* Create DIR file */
		r = sc_pkcs15init_update_file(profile, p15card, dir_file, NULL, 0);
		sc_file_free(dir_file);
	} while (retry--);

	if (r >= 0) {
		card->app[card->app_count++] = app;
		r = sc_update_dir(card, NULL);
	}
	LOG_FUNC_RETURN(ctx, r);
}


static int
sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char	*buf = NULL;
	size_t		size;
	int		rv;

	LOG_FUNC_CALLED(ctx);

	/* set lastUpdate field */
	if (p15card->tokeninfo->last_update.gtime != NULL)   {
		free(p15card->tokeninfo->last_update.gtime);
		p15card->tokeninfo->last_update.gtime = NULL;
	}
	rv = sc_pkcs15_get_generalized_time(ctx, &p15card->tokeninfo->last_update.gtime);
	LOG_TEST_RET(ctx, rv, "Cannot allocate generalized time string");

	if (profile->ops->emu_update_tokeninfo)
		return profile->ops->emu_update_tokeninfo(profile, p15card, p15card->tokeninfo);

	if (!p15card->file_tokeninfo)   {
		sc_log(ctx, "No TokenInfo to update");
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	rv = sc_pkcs15_encode_tokeninfo(ctx, p15card->tokeninfo, &buf, &size);
	if (rv >= 0)
		rv = sc_pkcs15init_update_file(profile, p15card, p15card->file_tokeninfo, buf, size);
	if (buf)
		free(buf);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_pkcs15init_update_lastupdate(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_context *ctx = p15card->card->ctx;
	int		r;

	LOG_FUNC_CALLED(ctx);
	if (p15card->tokeninfo->last_update.path.len)    {
		static const struct sc_asn1_entry c_asn1_last_update[2] = {
		        { "generalizedTime",    SC_ASN1_GENERALIZEDTIME, SC_ASN1_TAG_GENERALIZEDTIME,   SC_ASN1_OPTIONAL, NULL, NULL },
			{ NULL, 0, 0, 0, NULL, NULL }
		};
		struct sc_asn1_entry asn1_last_update[2];
		size_t lupdate_len;
		struct sc_file *file = NULL;
		struct sc_pkcs15_last_update *last_update = &p15card->tokeninfo->last_update;
		unsigned char *buf = NULL;
		size_t buflen;

		/* update 'lastUpdate' file */
		if (last_update->gtime != NULL)
			free(last_update->gtime);
		r = sc_pkcs15_get_generalized_time(ctx, &last_update->gtime);
		LOG_TEST_RET(ctx, r, "Cannot allocate generalized time string");

		sc_copy_asn1_entry(c_asn1_last_update, asn1_last_update);
		lupdate_len = strlen(last_update->gtime);
		sc_format_asn1_entry(asn1_last_update + 0, last_update->gtime, &lupdate_len, 1);

		r = sc_asn1_encode(ctx, asn1_last_update, &buf, &buflen);
		LOG_TEST_RET(ctx, r, "select object path failed");

		r = sc_select_file(p15card->card, &last_update->path, &file);
		LOG_TEST_RET(ctx, r, "select object path failed");

		r = sc_pkcs15init_update_file(profile, p15card, file, buf, buflen);
		sc_file_free(file);
		if (buf)
			free(buf);
		LOG_TEST_RET(ctx, r, "Cannot update 'LastUpdate' file");
		LOG_FUNC_RETURN(ctx, r);
	}

	r = sc_pkcs15init_update_tokeninfo(p15card, profile);
	LOG_FUNC_RETURN(ctx, r);
}


static int
sc_pkcs15init_update_odf(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_context	*ctx = p15card->card->ctx;
	unsigned char	*buf = NULL;
	size_t		size;
	int		r;

	LOG_FUNC_CALLED(ctx);
	r = sc_pkcs15_encode_odf(ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile, p15card, p15card->file_odf, buf, size);
	if (buf)
		free(buf);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Update any PKCS15 DF file (except ODF and DIR)
 */
int
sc_pkcs15init_update_any_df(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15_df *df,
		int is_new)
{
	struct sc_context	*ctx = p15card->card->ctx;
	struct sc_card	*card = p15card->card;
	struct sc_file	*file = NULL;
	unsigned char	*buf = NULL;
	size_t		bufsize;
	int		update_odf = is_new, r = 0;

	LOG_FUNC_CALLED(ctx);
	if (!df)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "DF missing");

	r = sc_profile_get_file_by_path(profile, &df->path, &file);
	if (r < 0 || file == NULL)
		sc_select_file(card, &df->path, &file);

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
	if (r >= 0) {
		r = sc_pkcs15init_update_file(profile, p15card, file, buf, bufsize);

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
	sc_file_free(file);

	LOG_TEST_RET(ctx, r, "Failed to encode or update xDF");

	/* Now update the ODF if we have to */
	if (update_odf)
		r = sc_pkcs15init_update_odf(p15card, profile);
	LOG_TEST_RET(ctx, r, "Failed to encode or update ODF");

	LOG_FUNC_RETURN(ctx, r > 0 ? SC_SUCCESS : r);
}

/*
 * Add an object to one of the pkcs15 directory files.
 */
int
sc_pkcs15init_add_object(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		unsigned int df_type, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_df *df;
	int is_new = 0, r = 0, object_added = 0;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "add object %p to DF of type %u", object, df_type);

	df = find_df_by_type(p15card, df_type);
	if (df == NULL) {
		struct sc_file	*file;
		file = profile->df[df_type];
		if (file == NULL) {
			sc_log(ctx, "Profile doesn't define a DF file %u", df_type);
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "DF not found in profile");
		}
		sc_pkcs15_add_df(p15card, df_type, &file->path);
		df = find_df_by_type(p15card, df_type);
		assert(df != NULL);
		is_new = 1;

		/* Mark the df as enumerated, so libopensc doesn't try
		 * to load the file at a most inconvenient moment */
		df->enumerated = 1;
	}

	if (object == NULL) {
		sc_log(ctx, "Add nothing; just instantiate this directory file");
	}
	else if (object->df == NULL) {
		sc_log(ctx, "Append object");
		object->df = df;
		r = sc_pkcs15_add_object(p15card, object);
		LOG_TEST_RET(ctx, r, "Failed to add pkcs15 object");
		object_added = 1;
	}
	else {
		sc_log(ctx, "Reuse existing object");
		assert(object->df == df);
	}

	if (profile->ops->emu_update_any_df)
		r = profile->ops->emu_update_any_df(profile, p15card, SC_AC_OP_CREATE, object);
	else
		r = sc_pkcs15init_update_any_df(p15card, profile, df, is_new);

	if (r < 0 && object_added)
		sc_pkcs15_remove_object(p15card, object);

	LOG_FUNC_RETURN(ctx, r > 0 ? SC_SUCCESS : r);
}


struct sc_pkcs15_object *
sc_pkcs15init_new_object(int type, const char *label, struct sc_pkcs15_id *auth_id, void *data)
{
	struct sc_pkcs15_object	*object;
	unsigned int data_size = 0;

	object = calloc(1, sizeof(*object));
	if (object == NULL)
		return NULL;
	object->type = type;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		object->flags = DEFAULT_PIN_FLAGS;
		data_size = sizeof(struct sc_pkcs15_auth_info);
		break;
	case SC_PKCS15_TYPE_PRKEY:
		object->flags = DEFAULT_PRKEY_FLAGS;
		data_size = sizeof(struct sc_pkcs15_prkey_info);
		break;
	case SC_PKCS15_TYPE_SKEY:
		object->flags = DEFAULT_SKEY_FLAGS;
		data_size = sizeof(struct sc_pkcs15_skey_info);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		object->flags = DEFAULT_PUBKEY_FLAGS;
		data_size = sizeof(struct sc_pkcs15_pubkey_info);
		break;
	case SC_PKCS15_TYPE_CERT:
		object->flags = DEFAULT_CERT_FLAGS;
		data_size = sizeof(struct sc_pkcs15_cert_info);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		object->flags = DEFAULT_DATA_FLAGS;
		if (auth_id->len != 0)
			object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
		data_size = sizeof(struct sc_pkcs15_data_info);
		break;
	}

	if (data_size) {
		object->data = calloc(1, data_size);
		if (data)
			memcpy(object->data, data, data_size);
	}

	if (label)
		strlcpy(object->label, label, sizeof(object->label));
	if (auth_id)
		object->auth_id = *auth_id;

	return object;
}


void
sc_pkcs15init_free_object(struct sc_pkcs15_object *object)
{
	if (object) {
		free(object->data);
		free(object);
	}
}


int
sc_pkcs15init_change_attrib(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		int new_attrib_type, void *new_value, int new_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card	*card = p15card->card;
	unsigned char	*buf = NULL;
	size_t		bufsize;
	int		df_type, r = 0;
	struct sc_pkcs15_df *df;
	struct sc_pkcs15_id new_id = *((struct sc_pkcs15_id *) new_value);

	LOG_FUNC_CALLED(ctx);
	if (object == NULL || object->df == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot change attribute");
	df_type = object->df->type;

	df = find_df_by_type(p15card, df_type);
	if (df == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "Cannot change attribute");

	sc_log(ctx, "type of attribute to change %i; DF type %i", new_attrib_type, df_type);
	switch(new_attrib_type)   {
	case P15_ATTR_TYPE_LABEL:
		if (new_len >= SC_PKCS15_MAX_LABEL_SIZE)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "New label too long");
		memcpy(object->label, new_value, new_len);
		object->label[new_len] = '\0';
		break;
	case P15_ATTR_TYPE_ID:
		switch(df_type) {
		case SC_PKCS15_PRKDF:
			((struct sc_pkcs15_prkey_info *) object->data)->id = new_id;
			break;
		case SC_PKCS15_PUKDF:
		case SC_PKCS15_PUKDF_TRUSTED:
			((struct sc_pkcs15_pubkey_info *) object->data)->id = new_id;
			break;
		case SC_PKCS15_SKDF:
			((struct sc_pkcs15_skey_info *) object->data)->id = new_id;
			break;
		case SC_PKCS15_CDF:
		case SC_PKCS15_CDF_TRUSTED:
		case SC_PKCS15_CDF_USEFUL:
			((struct sc_pkcs15_cert_info *) object->data)->id = new_id;
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Cannot change ID attribute");
		}
		break;
	case P15_ATTR_TYPE_VALUE:
		switch(df_type) {
		case SC_PKCS15_DODF: {
			u8 *nv;
			struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *) object->data;
			struct sc_path old_data_path = info->path;
			struct sc_path new_data_path;
			struct sc_pkcs15_der new_data;
			new_data.len = new_len;
			new_data.value = (u8 *) new_value;
			
			/* save new data as a new data file on token */
			r = sc_pkcs15init_store_data(p15card, profile, object, &new_data, &new_data_path);
			profile->dirty = 1;
			LOG_TEST_RET(ctx, r, "Failed to store new data");

			nv = (u8 *) malloc (new_len * sizeof(u8));
			if (!nv) {
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			}
			memcpy(nv, new_value, new_len * sizeof(u8));
			free(info->data.value);
			/*  set object members to represent new CKA_VALUE value,
				new path will be written to DODF later in this function*/
			info->data.len = new_len;
			info->data.value = nv;
			info->path = new_data_path;
			
			/* delete old data file from token */
			r = sc_pkcs15init_delete_by_path(profile, p15card, &old_data_path);
			LOG_TEST_RET(ctx, r, "Failed to delete old data");
			break;
		}
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Cannot change value attribute");
		}
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Only 'LABEL' or 'ID' or 'VALUE'(for data objects) attributes can be changed");
	}

	if (profile->ops->emu_update_any_df)   {
		r = profile->ops->emu_update_any_df(profile, p15card, SC_AC_OP_CREATE, object);
		LOG_TEST_RET(ctx, r, "Card specific DF update failed");
	}
	else   {
		r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &bufsize);
		if (r >= 0) {
			struct sc_file *file = NULL;

			r = sc_profile_get_file_by_path(profile, &df->path, &file);
			if (r < 0)
				free(buf);
			LOG_TEST_RET(ctx, r, "Cannot instantiate file by path");

			r = sc_pkcs15init_update_file(profile, p15card, file, buf, bufsize);
			free(buf);
			sc_file_free(file);
		}
	}

	if (r > 0)
		r = 0;
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_delete_object(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *obj)
{
	struct sc_context	*ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	struct sc_path path;
	struct sc_pkcs15_df *df;
	int r = 0, stored_in_ef = 0;

	LOG_FUNC_CALLED(ctx);
	r = get_object_path_from_object(obj, &path);
	LOG_TEST_RET(ctx, r, "Failed to get object path");

	sc_log(ctx, "delete object(type:%X) with path(type:%X,%s)", obj->type, path.type, sc_print_path(&path));

	if (profile->ops->delete_object != NULL) {
		/* If there's a card-specific way to delete objects, use it. */
		r = profile->ops->delete_object(profile, p15card, obj, &path);
		if (r != SC_ERROR_NOT_SUPPORTED)
			LOG_TEST_RET(ctx, r, "Card specific delete object failed");
	}

	if (profile->ops->delete_object == NULL || r == SC_ERROR_NOT_SUPPORTED)  {
		if (path.len || path.aid.len)   {
			r = sc_select_file(p15card->card, &path, &file);
			if (r != SC_ERROR_FILE_NOT_FOUND)
				LOG_TEST_RET(ctx, r, "select object path failed");

			stored_in_ef = (file->type != SC_FILE_TYPE_DF);
			sc_file_free(file);
		}

		/* If the object is stored in a normal EF, try to delete the EF. */
		if (r == SC_SUCCESS && stored_in_ef) {
			r = sc_pkcs15init_delete_by_path(profile, p15card, &path);
			LOG_TEST_RET(ctx, r, "Failed to delete object by path");
		}
	}

	if (profile->ops->emu_update_any_df)   {
		r = profile->ops->emu_update_any_df(profile, p15card, SC_AC_OP_ERASE, obj);
		LOG_TEST_RET(ctx, r, "'ERASE' update DF failed");
	}

	/* Get the DF we're part of. If there's no DF, fine, we haven't been added yet. */
	df = obj->df;
	if (df)   {
		/* Unlink the object and update the DF */
		sc_pkcs15_remove_object(p15card, obj);
		sc_pkcs15_free_object(obj);
	}

	if (!profile->ops->emu_update_any_df)
		r = sc_pkcs15init_update_any_df(p15card, profile, df, 0);

	/* mark card as dirty */
	profile->dirty = 1;

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_update_certificate(struct sc_pkcs15_card *p15card,
	struct sc_profile *profile, struct sc_pkcs15_object *obj,
	const unsigned char *rawcert, size_t certlen)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	struct sc_path *path = &((struct sc_pkcs15_cert_info *)obj->data)->path;
	int r;

	LOG_FUNC_CALLED(ctx);
	r = sc_select_file(p15card->card, path, &file);
	LOG_TEST_RET(ctx, r, "Failed to select cert file");

	/* If the new cert doesn't fit in the EF, delete it and make the same, but bigger EF */
	if (file->size != certlen) {
		struct sc_file *parent = NULL;

		r = sc_pkcs15init_delete_by_path(profile, p15card, path);
		if (r < 0)
			goto done;

		file->size = certlen;

		r = do_select_parent(profile, p15card, file, &parent);
		if (r < 0)
			goto done;

		r = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_CREATE);
		sc_file_free(parent);
		if (r < 0)   {
			sc_log(ctx, "'CREATE' authentication failed");
			goto done;
		}

		/* ensure we are in the correct lifecycle */
		r = sc_pkcs15init_set_lifecycle(p15card->card, SC_CARDCTRL_LIFECYCLE_ADMIN);
		if (r < 0 && r != SC_ERROR_NOT_SUPPORTED)
			goto done;

		r = sc_create_file(p15card->card, file);
		if (r < 0)   {
			sc_log(ctx, "Cannot create cert file");
			goto done;
		}
	}

	if (!sc_file_get_acl_entry(file, SC_AC_OP_UPDATE))   {
		struct sc_path tmp_path;

		/* FCI of selected cert file do not contains ACLs.
		 * For the 'UPDATE' authentication use instead sc_file
		 *	instantiated from card profile with default ACLs. */
		sc_file_free(file);

		r = select_object_path(p15card, profile, obj, &tmp_path);
		if (r < 0)   {
			sc_log(ctx, "Select object path error");
			goto done;
		}

		r = sc_profile_get_file_by_path(profile, path, &file);
		if (r < 0)   {
			sc_log(ctx, "Cannot instantiate cert file");
			goto done;
		}
	}

	/* Write the new cert */
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	if (r < 0)   {
		sc_log(ctx, "'UPDATE' authentication failed");
		goto done;
	}

	r = sc_select_file(p15card->card, path, NULL);
	if (r < 0)
		goto done;

	r = sc_update_binary(p15card->card, 0, rawcert, certlen, 0);
	if (r < 0)
		goto done;

	/* Fill the remaining space in the EF (if any) with zeros */
	if (certlen < file->size) {
		unsigned char *tmp = calloc(file->size - certlen, 1);
		if (tmp == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto done;
		}
		r = sc_update_binary(p15card->card, certlen, tmp, file->size - certlen, 0);
		free(tmp);
		if (r < 0)
			sc_log(ctx, "Update cert file error");
	}

	if (r >= 0) {
		/* Update the CDF entry */
		path = &((struct sc_pkcs15_cert_info *)obj->data)->path;
		if (file->size != certlen) {
			path->index = 0;
			path->count = certlen;
		}
		else   {
			path->count = -1;
		}

		if (profile->ops->emu_update_any_df) {
			r = profile->ops->emu_update_any_df(profile, p15card, SC_AC_OP_UPDATE, obj);
			if (r == SC_ERROR_NOT_SUPPORTED)
				r = SC_SUCCESS;
		}
		else {
			r = sc_pkcs15init_update_any_df(p15card, profile, obj->df, 0);
		}

		if (r < 0)
			sc_log(ctx, "Failed to update CDF");
	}

	/* mark card as dirty */
	profile->dirty = 1;

done:
	sc_file_free(file);

	LOG_FUNC_RETURN(ctx, r);
}


static const char *
get_pin_ident_name(int type, int reference)
{
	switch (type)   {
	case SC_AC_CHV:
		return "PIN";
	case SC_AC_PRO:
		return "secure messaging key";
	case SC_AC_AUT:
		return "authentication key";
	case SC_AC_SEN:
		return "security environment";
	case SC_AC_IDA:
		return "PKCS#15 reference";
	case SC_AC_SCB:
		return "SCB byte in IAS/ECC";
	case SC_AC_SYMBOLIC:
		switch (reference) {
	        case SC_PKCS15INIT_USER_PIN:
			return "user PIN";
		case SC_PKCS15INIT_SO_PIN:
			return "SO PIN";
	        case SC_PKCS15INIT_USER_PUK:
			return "user PUK";
		case SC_PKCS15INIT_SO_PUK:
			return "SO PUK";
		}
	}
	return "authentication data";
}


static int
sc_pkcs15init_get_transport_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		int type, int reference, unsigned char *pinbuf, size_t *pinsize)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_cardctl_default_key data;
	size_t		defsize = 0;
	unsigned char	defbuf[0x100];
	int rv;

	LOG_FUNC_CALLED(ctx);

	data.method = type;
	data.key_ref = reference;
	data.len = sizeof(defbuf);
	data.key_data = defbuf;
	rv = sc_card_ctl(p15card->card, SC_CARDCTL_GET_DEFAULT_KEY, &data);
	if (rv >= 0)
		defsize = data.len;

	if (callbacks.get_key)   {
		rv = callbacks.get_key(profile, type, reference, defbuf, defsize, pinbuf, pinsize);
		LOG_TEST_RET(ctx, rv, "Cannot get key");
	}
	else if (rv >= 0)  {
		if (*pinsize < defsize)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Get transport key error");

		memcpy(pinbuf, data.key_data, data.len);
		*pinsize = data.len;
	}

	memset(&auth_info, 0, sizeof(auth_info));
	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.auth_method = type;
	auth_info.attrs.pin.reference = reference;
	auth_info.attrs.pin.stored_length = *pinsize;
	auth_info.attrs.pin.max_length = *pinsize;
	auth_info.attrs.pin.min_length = *pinsize;

	pin_obj = sc_pkcs15init_new_object(SC_PKCS15_TYPE_AUTH_PIN, "Default transport key", NULL, &auth_info);
	if (!pin_obj)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate AUTH object");

	rv = sc_pkcs15_add_object(p15card, pin_obj);
	LOG_TEST_RET(ctx, rv, "Cannot add PKCS#15 AUTH object");

	sc_pkcs15_pincache_add(p15card, pin_obj, pinbuf, *pinsize);

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * PIN verification
 */
int
sc_pkcs15init_verify_secret(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *file, unsigned int type, int reference)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_path	*path;
	int		r, use_pinpad = 0, pin_id = -1;
	const char	*ident, *label = NULL;
	unsigned char	pinbuf[0x100];
	size_t		pinsize = 0;


	LOG_FUNC_CALLED(ctx);
	path = file? &file->path : NULL;

	ident = get_pin_ident_name(type, reference);
	sc_log(ctx, "get and verify PIN('%s',type:0x%X,reference:0x%X)", ident, type, reference);

	if (type == SC_AC_SEN)   {
		r = sc_card_ctl(p15card->card, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, (void *)(&reference));
		sc_log(ctx, "Card CTL(GET_CHV_REFERENCE_IN_SE) returned %i", r);
		if (r > 0)   {
			sc_log(ctx, "CHV(ref:%i) found in SE(ref:%i)", r, reference);
			type = SC_AC_CHV;
			reference = r;
		}
		else if (r != SC_ERROR_NOT_SUPPORTED)
			LOG_TEST_RET(ctx, r, "Card CTL error: cannot get CHV reference");
	}

	memset(&auth_info, 0, sizeof(auth_info));
	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.auth_method = type;
	auth_info.attrs.pin.reference = reference;

	pin_id = sc_pkcs15init_get_pin_reference(p15card, profile, type, reference);
	sc_log(ctx, "found PIN reference %i", pin_id);
	if (type == SC_AC_SYMBOLIC) {
		if (pin_id == -1)
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		reference = pin_id;
		type = SC_AC_CHV;
		sc_log(ctx, "Symbolic PIN resolved to PIN(type:CHV,reference:%i)", reference);
	}

	if (path && path->len)   {
		struct sc_path tmp_path = *path;
		int iter;
		r = SC_ERROR_OBJECT_NOT_FOUND;
		for (iter = tmp_path.len/2; iter >= 0 && r == SC_ERROR_OBJECT_NOT_FOUND; iter--, tmp_path.len -= 2) {
			r = sc_pkcs15_find_pin_by_type_and_reference(p15card,
					tmp_path.len ? &tmp_path : NULL,
					type, reference, &pin_obj);
		}
	}
	else {
		r = sc_pkcs15_find_pin_by_type_and_reference(p15card, NULL, type, reference, &pin_obj);
	}

	if (!r && pin_obj)   {
		memcpy(&auth_info, pin_obj->data, sizeof(auth_info));
		sc_log(ctx, "found PIN object '%.*s'", (int) sizeof pin_obj->label, pin_obj->label);
	}

	if (pin_obj)   {
		sc_log(ctx,
		       "PIN object '%.*s'; pin_obj->content.len:%"SC_FORMAT_LEN_SIZE_T"u",
		       (int) sizeof pin_obj->label, pin_obj->label,
		       pin_obj->content.len);
		if (pin_obj->content.value && pin_obj->content.len)   {
			if (pin_obj->content.len > sizeof(pinbuf))
				LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "PIN buffer is too small");
			memcpy(pinbuf, pin_obj->content.value, pin_obj->content.len);
			pinsize = pin_obj->content.len;
			sc_log(ctx, "'ve got '%s' value from cache", ident);
			goto found;
		}
	}

	if (pin_obj && pin_obj->label[0])
		label = pin_obj->label;

	switch (type) {
	case SC_AC_CHV:
		if (callbacks.get_pin)   {
			pinsize = sizeof(pinbuf);
			r = callbacks.get_pin(profile, pin_id, &auth_info, label, pinbuf, &pinsize);
			sc_log(ctx,
			       "'get_pin' callback returned %i; pinsize:%"SC_FORMAT_LEN_SIZE_T"u",
			       r, pinsize);
		}
		break;
	case SC_AC_SCB:
	case SC_AC_PRO:
		pinsize = 0;
		r = 0;
		break;
	default:
		pinsize = sizeof(pinbuf);
		r = sc_pkcs15init_get_transport_key(profile, p15card, type, reference, pinbuf, &pinsize);
		break;
	}

	if (r == SC_ERROR_OBJECT_NOT_FOUND)   {
		if (p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD)
			r = 0, use_pinpad = 1;
		else
			r = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}

	LOG_TEST_RET(ctx, r, "Failed to get secret");
	if (type == SC_AC_PRO)   {
		sc_log(ctx, "No 'verify' for secure messaging");
		LOG_FUNC_RETURN(ctx, r);
	}

found:
	if (pin_obj)   {
		r = sc_pkcs15_verify_pin(p15card, pin_obj, use_pinpad ? NULL : pinbuf, use_pinpad ? 0 : pinsize);
		LOG_TEST_RET(ctx, r, "Cannot validate pkcs15 PIN");
	}

	if (file)   {
		r = sc_select_file(p15card->card, &file->path, NULL);
		LOG_TEST_RET(ctx, r, "Failed to select PIN path");
	}

	if (!pin_obj) {
		struct sc_pin_cmd_data pin_cmd;

		memset(&pin_cmd, 0, sizeof(pin_cmd));
		pin_cmd.cmd = SC_PIN_CMD_VERIFY;
		pin_cmd.pin_type = type;
		pin_cmd.pin_reference = reference;
		pin_cmd.pin1.data = use_pinpad ? NULL : pinbuf;
		pin_cmd.pin1.len = use_pinpad ? 0: pinsize;

		r = sc_pin_cmd(p15card->card, &pin_cmd, NULL);
		LOG_TEST_RET(ctx, r, "'VERIFY' pin cmd failed");
	}

	LOG_FUNC_RETURN(ctx, r);
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
 * On the other hands, some cards do not return access conditions
 * in their response to SELECT FILE), so the latter case has been
 * used in most cards while the first case was added much later.
 */
int
sc_pkcs15init_authenticate(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *file, int op)
{
	struct sc_context *ctx = p15card->card->ctx;
	const struct sc_acl_entry *acl = NULL;
	struct sc_file *file_tmp = NULL;
	int  r = 0;

	LOG_FUNC_CALLED(ctx);
	assert(file != NULL);
	sc_log(ctx, "path '%s', op=%u", sc_print_path(&file->path), op);

	if (p15card->card->caps & SC_CARD_CAP_USE_FCI_AC) {
		r = sc_select_file(p15card->card, &file->path, &file_tmp);
		LOG_TEST_RET(ctx, r, "Authentication failed: cannot select file.");

		acl = sc_file_get_acl_entry(file_tmp, op);
	}
	else   {
		acl = sc_file_get_acl_entry(file, op);
	}
	sc_log(ctx, "acl %p",acl);

	for (; r == 0 && acl; acl = acl->next) {
		if (acl->method == SC_AC_NEVER)   {
			LOG_TEST_RET(ctx, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Authentication failed: never allowed");
		}
		else if (acl->method == SC_AC_NONE)   {
			sc_log(ctx, "always allowed");
			break;
		}
		else if (acl->method == SC_AC_UNKNOWN)  {
			sc_log(ctx, "unknown acl method");
			break;
		}
		sc_log(ctx, "verify acl(method:%i,reference:%i)", acl->method, acl->key_ref);
		r = sc_pkcs15init_verify_secret(profile, p15card, file_tmp ? file_tmp : file, acl->method, acl->key_ref);
	}

	sc_file_free(file_tmp);

	LOG_FUNC_RETURN(ctx, r);
}


static int
do_select_parent(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *file, struct sc_file **parent)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path	path;
	int		r;

	LOG_FUNC_CALLED(ctx);
	/* Get the parent's path */
	path = file->path;
	if (path.len >= 2)
		path.len -= 2;
	if (!path.len && !path.aid.len)
		sc_format_path("3F00", &path);

	/* Select the parent DF. */
	*parent = NULL;
	r = sc_select_file(p15card->card, &path, parent);
	/* If DF doesn't exist, create it (unless it's the MF,
	 * but then something's badly broken anyway :-) */
	if (r == SC_ERROR_FILE_NOT_FOUND && path.len != 2) {
		r = sc_profile_get_file_by_path(profile, &path, parent);
		if (r < 0) {
			sc_log(ctx, "no profile template for DF %s", sc_print_path(&path));
			LOG_FUNC_RETURN(ctx, r);
		}

		r = sc_pkcs15init_create_file(profile, p15card, *parent);
		LOG_TEST_RET(ctx, r, "Cannot create parent DF");

		r = sc_select_file(p15card->card, &path, NULL);
		LOG_TEST_RET(ctx, r, "Cannot select parent DF");
	}
	else if (r == SC_SUCCESS && !strcmp(p15card->card->name, "STARCOS")) {
		/* in case of starcos spk 2.3 SELECT FILE does not
		 * give us the ACLs => ask the profile */
		sc_file_free(*parent);

		r = sc_profile_get_file_by_path(profile, &path, parent);
		if (r < 0) {
			sc_log(ctx, "in StarCOS profile there is no template for DF %s", sc_print_path(&path));
			LOG_FUNC_RETURN(ctx, r);
		}
	}
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_create_file(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *file)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file	*parent = NULL;
	int		r;

	LOG_FUNC_CALLED(ctx);
	if (!file) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_log(ctx, "create file '%s'", sc_print_path(&file->path));
	/* Select parent DF and verify PINs/key as necessary */
	r = do_select_parent(profile, p15card, file, &parent);
	LOG_TEST_RET(ctx, r, "Cannot create file: select parent error");

	r = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_CREATE);
	LOG_TEST_RET(ctx, r, "Cannot create file: 'CREATE' authentication failed");

	/* Fix up the file's ACLs */
	r = sc_pkcs15init_fixup_file(profile, p15card, file);
	LOG_TEST_RET(ctx, r, "Cannot create file: file fixup failed");

	/* ensure we are in the correct lifecycle */
	r = sc_pkcs15init_set_lifecycle(p15card->card, SC_CARDCTRL_LIFECYCLE_ADMIN);
	if (r != SC_ERROR_NOT_SUPPORTED)
		LOG_TEST_RET(ctx, r, "Cannot create file: failed to set lifecycle 'ADMIN'");

	r = sc_create_file(p15card->card, file);
	LOG_TEST_RET(ctx, r, "Create file failed");

	sc_file_free(parent);
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15init_update_file(struct sc_profile *profile,
		struct sc_pkcs15_card *p15card, struct sc_file *file,
		void *data, unsigned int datalen)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file	*selected_file = NULL;
	void		*copy = NULL;
	int		r, need_to_zap = 0;

	LOG_FUNC_CALLED(ctx);
	if (!file)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "path:%s; datalen:%i", sc_print_path(&file->path), datalen);

	r = sc_select_file(p15card->card, &file->path, &selected_file);
	if (!r)   {
		need_to_zap = 1;
	}
	else if (r == SC_ERROR_FILE_NOT_FOUND)   {
		/* Create file if it doesn't exist */
		if (file->size < datalen)
			file->size = datalen;

		r = sc_pkcs15init_create_file(profile, p15card, file);
		LOG_TEST_RET(ctx, r, "Failed to create file");

		r = sc_select_file(p15card->card, &file->path, &selected_file);
		LOG_TEST_RET(ctx, r, "Failed to select newly created file");
	}
	else   {
		LOG_TEST_RET(ctx, r, "Failed to select file");
	}

	if (selected_file->size < datalen) {
		sc_log(ctx,
		       "File %s too small (require %u, have %"SC_FORMAT_LEN_SIZE_T"u)",
		       sc_print_path(&file->path), datalen,
		       selected_file->size);
		sc_file_free(selected_file);
		LOG_TEST_RET(ctx, SC_ERROR_FILE_TOO_SMALL, "Update file failed");
	}
	else if (selected_file->size > datalen && need_to_zap) {
		/* zero out the rest of the file - we may have shrunk
		 * the file contents */
		copy = calloc(1, selected_file->size);
		if (copy == NULL) {
			sc_file_free(selected_file);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		memcpy(copy, data, datalen);
		datalen = selected_file->size;
		data = copy;
	}

	/* Present authentication info needed */
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	if (r >= 0 && datalen)
		r = sc_update_binary(p15card->card, 0, (const unsigned char *) data, datalen, 0);

	if (copy)
		free(copy);
	sc_file_free(selected_file);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Fix up a file's ACLs by replacing all occurrences of a symbolic
 * PIN name with the real reference.
 */
static int
sc_pkcs15init_fixup_acls(struct sc_pkcs15_card *p15card, struct sc_file *file,
		struct sc_acl_entry *so_acl, struct sc_acl_entry *user_acl)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned int	op;
	int		r = 0;

	LOG_FUNC_CALLED(ctx);
	for (op = 0; r == 0 && op < SC_MAX_AC_OPS; op++) {
		struct sc_acl_entry acls[SC_MAX_OP_ACS];
		const struct sc_acl_entry *acl;
		const char	*what;
		int		added = 0, num, ii;

		/* First, get original ACLs */
		acl = sc_file_get_acl_entry(file, op);
		for (num = 0; num < SC_MAX_OP_ACS && acl; num++, acl = acl->next)
			acls[num] = *acl;

		sc_file_clear_acl_entries(file, op);
		for (ii = 0; ii < num; ii++) {
			acl = acls + ii;
			if (acl->method != SC_AC_SYMBOLIC)
				goto next;

			if (acl->key_ref == SC_PKCS15INIT_SO_PIN) {
				acl = so_acl;
				what = "SO PIN";
			}
			else if (acl->key_ref == SC_PKCS15INIT_USER_PIN) {
				acl = user_acl;
				what = "user PIN";
			}
			else {
				sc_log(ctx, "ACL references unknown symbolic PIN %d", acl->key_ref);
				return SC_ERROR_INVALID_ARGUMENTS;
			}

			/* If we weren't given a replacement ACL,
			 * leave the original ACL untouched */
			if (acl->key_ref == (unsigned int)-1) {
				sc_log(ctx, "ACL references %s, which is not defined", what);
				return SC_ERROR_INVALID_ARGUMENTS;
			}

			if (acl->method == SC_AC_NONE)
				continue;
		next:
			sc_file_add_acl_entry(file, op, acl->method, acl->key_ref);
			added++;
		}
		if (!added)
			sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
	}

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Fix up all file ACLs
 */
int
sc_pkcs15init_fixup_file(struct sc_profile *profile,
		struct sc_pkcs15_card *p15card, struct sc_file *file)
{
	struct sc_context	*ctx = profile->card->ctx;
	struct sc_acl_entry	so_acl, user_acl;
	unsigned int	op, needfix = 0;
	int		rv, pin_ref;

	LOG_FUNC_CALLED(ctx);
	/* First, loop over all ACLs to find out whether there
	 * are still any symbolic references.
	 */
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		const struct sc_acl_entry *acl;

		acl = sc_file_get_acl_entry(file, op);
		for (; acl; acl = acl->next)
			if (acl->method == SC_AC_SYMBOLIC)
				needfix++;
	}

	if (!needfix)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile, SC_AC_SYMBOLIC, SC_PKCS15INIT_SO_PIN);
	if (pin_ref < 0) {
		so_acl.method = SC_AC_NONE;
		so_acl.key_ref = 0;
	}
	else {
		so_acl.method = SC_AC_CHV;
		so_acl.key_ref = pin_ref;
	}

	pin_ref = sc_pkcs15init_get_pin_reference(p15card, profile, SC_AC_SYMBOLIC, SC_PKCS15INIT_USER_PIN);
	if (pin_ref < 0) {
		user_acl.method = SC_AC_NONE;
		user_acl.key_ref = 0;
	}
	else {
		user_acl.method = SC_AC_CHV;
		user_acl.key_ref = pin_ref;
	}
	sc_log(ctx, "so_acl(method:%X,ref:%X), user_acl(method:%X,ref:%X)",
			so_acl.method, so_acl.key_ref, user_acl.method, user_acl.key_ref);

	rv = sc_pkcs15init_fixup_acls(p15card, file, &so_acl, &user_acl);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_pkcs15init_get_pin_path(struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_id *auth_id, struct sc_path *path)
{
	struct sc_pkcs15_object *obj;
	int	r;

	r = sc_pkcs15_find_pin_by_auth_id(p15card, auth_id, &obj);
	if (r < 0)
		return r;
	*path = ((struct sc_pkcs15_auth_info *) obj->data)->path;
	return SC_SUCCESS;
}


int
sc_pkcs15init_get_pin_info(struct sc_profile *profile, int id, struct sc_pkcs15_auth_info *pin)
{
	sc_profile_get_pin_info(profile, id, pin);
	return SC_SUCCESS;
}


int
sc_pkcs15init_get_manufacturer(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_spec->tokeninfo->manufacturer_id;
	return SC_SUCCESS;
}

int
sc_pkcs15init_get_serial(struct sc_profile *profile, const char **res)
{
	*res = profile->p15_spec->tokeninfo->serial_number;
	return SC_SUCCESS;
}


int
sc_pkcs15init_set_serial(struct sc_profile *profile, const char *serial)
{
	if (profile->p15_spec->tokeninfo->serial_number)
		free(profile->p15_spec->tokeninfo->serial_number);
	profile->p15_spec->tokeninfo->serial_number = strdup(serial);

	return SC_SUCCESS;
}


/*
 * Card specific sanity check procedure.
 */
int
sc_pkcs15init_sanity_check(struct sc_pkcs15_card *p15card, struct sc_profile *profile)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);
	if (profile->ops->sanity_check)
		rv = profile->ops->sanity_check(profile, p15card);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_pkcs15init_qualify_pin(struct sc_card *card, const char *pin_name,
		unsigned int pin_len, struct sc_pkcs15_auth_info *auth_info)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_pin_attributes *pin_attrs;

	LOG_FUNC_CALLED(ctx);
	if (pin_len == 0 || auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	pin_attrs = &auth_info->attrs.pin;

	if (pin_len < pin_attrs->min_length) {
		sc_log(ctx,
		       "%s too short (min length %"SC_FORMAT_LEN_SIZE_T"u)",
		       pin_name, pin_attrs->min_length);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
	}
	if (pin_len > pin_attrs->max_length) {
		sc_log(ctx,
		       "%s too long (max length %"SC_FORMAT_LEN_SIZE_T"u)",
		       pin_name, pin_attrs->max_length);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Get the list of options from the card, if it specifies them
 */
static int
sc_pkcs15init_read_info(struct sc_card *card, struct sc_profile *profile)
{
	struct sc_path	path;
	struct sc_file	*file = NULL;
	unsigned char	*mem = NULL;
	size_t		len = 0;
	int		r;

	sc_format_path(OPENSC_INFO_FILEPATH, &path);
	r = sc_select_file(card, &path, &file);
	if (r >= 0) {
		len = file->size;
		sc_file_free(file);
		mem = malloc(len);
		if (mem != NULL)
			r = sc_read_binary(card, 0, mem, len, 0);
		else
			r = SC_ERROR_OUT_OF_MEMORY;
	}
	else   {
		r = 0;
	}

	if (r >= 0)
		r = sc_pkcs15init_parse_info(card, mem, r, profile);

	if (mem)
		free(mem);
	return r;
}


static int
set_info_string(char **strp, const u8 *p, size_t len)
{
	char	*s;

	if (!(s = malloc(len+1)))
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(s, p, len);
	s[len] = '\0';
	if (*strp)
		free(*strp);
	*strp = s;
	return SC_SUCCESS;
}

/*
 * Parse OpenSC Info file. We rudely clobber any information
 * given on the command line.
 *
 * passed is a pointer (p) to (len) bytes. Those bytes contain
 * one or several tag-length-value constructs, where tag and
 * length are both single bytes. a final 0x00 or 0xff byte
 * (with or without len byte) is ok.
 */
static int
sc_pkcs15init_parse_info(struct sc_card *card,
		const unsigned char *p, size_t len, struct sc_profile *profile)
{
	unsigned char	tag;
	const unsigned char *end;
	unsigned int	nopts = 0;
	size_t		n;

	if ((p == NULL) || (len == 0))
		return 0;

	end = p + (len - 1);
	while (p < end) {	/* more bytes to look at */
		int	r = 0;

		tag = *p; p++;
		if ((tag == 0) || (tag == 0xff) || (p >= end))
			break;

		n = *p;
		p++;

		if (p >= end || p + n > end) /* invalid length byte n */
			goto error;

		switch (tag) {
		case OPENSC_INFO_TAG_PROFILE:
			r = set_info_string(&profile->name, p, n);
			if (r < 0)
				return r;
			break;
		case OPENSC_INFO_TAG_OPTION:
			if (nopts >= SC_PKCS15INIT_MAX_OPTIONS - 1) {
				sc_log(card->ctx, "Too many options in OpenSC Info file");
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
	sc_log(card->ctx, "OpenSC info file corrupted");
	return SC_ERROR_PKCS15INIT;
}


static int
do_encode_string(unsigned char **memp, unsigned char *end,
		unsigned char tag, const char *s)
{
	unsigned char	*p = *memp;
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


static int
sc_pkcs15init_write_info(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15_object *pin_obj)
{
	struct sc_file	*file = NULL, *df = profile->df_info->file;
	unsigned char	buffer[128], *p, *end;
	unsigned int	method;
	unsigned long	key_ref;
	int		n, r;

	if (profile->ops->emu_write_info)
		return profile->ops->emu_write_info(profile, p15card, pin_obj);

	memset(buffer, 0, sizeof(buffer));

	file = sc_file_new();
	file->path.type = SC_PATH_TYPE_PATH;
	memcpy(file->path.value, df->path.value, df->path.len);
	file->path.len = df->path.len;
	sc_append_file_id(&file->path, OPENSC_INFO_FILEID);
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->id = OPENSC_INFO_FILEID;
	file->size = sizeof(buffer);

	if (pin_obj != NULL) {
		method = SC_AC_CHV;
		key_ref = ((struct sc_pkcs15_auth_info *) pin_obj->data)->attrs.pin.reference;
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

	if (r >= 0)
		r = sc_pkcs15init_update_file(profile, p15card, file, buffer, file->size);

	sc_file_free(file);
	return r;
}
