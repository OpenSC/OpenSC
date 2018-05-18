/*
 * pkcs15-syn.c: PKCS #15 emulation of non-pkcs15 cards
 *
 * Copyright (C) 2003 Olaf Kirch <okir@suse.de>
 *		 2004 Nils Larsch <nlarsch@betrusted.com>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "common/libscdl.h"
#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"
#include "pkcs15-syn.h"

struct sc_pkcs15_emulator_handler builtin_emulators[] = {
	{ "westcos",	sc_pkcs15emu_westcos_init_ex	},
	{ "openpgp",	sc_pkcs15emu_openpgp_init_ex	},
	{ "infocamere",	sc_pkcs15emu_infocamere_init_ex	},
	{ "starcert",	sc_pkcs15emu_starcert_init_ex	},
	{ "tcos",	sc_pkcs15emu_tcos_init_ex	},
	{ "esteid",	sc_pkcs15emu_esteid_init_ex	},
	{ "itacns",	sc_pkcs15emu_itacns_init_ex	},
	{ "postecert",	sc_pkcs15emu_postecert_init_ex  },
	{ "PIV-II",     sc_pkcs15emu_piv_init_ex	},
	{ "cac",        sc_pkcs15emu_cac_init_ex	},
	{ "gemsafeGPK",	sc_pkcs15emu_gemsafeGPK_init_ex	},
	{ "gemsafeV1",	sc_pkcs15emu_gemsafeV1_init_ex	},
	{ "actalis",	sc_pkcs15emu_actalis_init_ex	},
	{ "atrust-acos",sc_pkcs15emu_atrust_acos_init_ex},
	{ "tccardos",	sc_pkcs15emu_tccardos_init_ex	},
	{ "entersafe",  sc_pkcs15emu_entersafe_init_ex  },
	{ "pteid",	sc_pkcs15emu_pteid_init_ex	},
	{ "oberthur",   sc_pkcs15emu_oberthur_init_ex	},
	{ "sc-hsm",	sc_pkcs15emu_sc_hsm_init_ex	},
	{ "dnie",       sc_pkcs15emu_dnie_init_ex   },
	{ "gids",       sc_pkcs15emu_gids_init_ex   },
	{ "iasecc",	sc_pkcs15emu_iasecc_init_ex   },
	{ "jpki",	sc_pkcs15emu_jpki_init_ex },
	{ "coolkey",    sc_pkcs15emu_coolkey_init_ex	},
	{ "din66291",    sc_pkcs15emu_din_66291_init_ex	},
	{ NULL, NULL }
};

static int parse_emu_block(sc_pkcs15_card_t *, struct sc_aid *, scconf_block *);
static sc_pkcs15_df_t * sc_pkcs15emu_get_df(sc_pkcs15_card_t *p15card,
	unsigned int type);

static const char *builtin_name = "builtin";
static const char *func_name    = "sc_pkcs15_init_func";
static const char *exfunc_name  = "sc_pkcs15_init_func_ex";


int sc_pkcs15_is_emulation_only(sc_card_t *card)
{
	switch (card->type) {
		case SC_CARD_TYPE_MCRD_ESTEID_V10:
		case SC_CARD_TYPE_MCRD_ESTEID_V11:
		case SC_CARD_TYPE_MCRD_ESTEID_V30:
		case SC_CARD_TYPE_GEMSAFEV1_PTEID:
		case SC_CARD_TYPE_OPENPGP_V1:
		case SC_CARD_TYPE_OPENPGP_V2:
		case SC_CARD_TYPE_OPENPGP_GNUK:
		case SC_CARD_TYPE_OPENPGP_V3:
		case SC_CARD_TYPE_SC_HSM:
		case SC_CARD_TYPE_SC_HSM_SOC:
		case SC_CARD_TYPE_DNIE_BASE:
		case SC_CARD_TYPE_DNIE_BLANK:
		case SC_CARD_TYPE_DNIE_ADMIN:
		case SC_CARD_TYPE_DNIE_USER:
		case SC_CARD_TYPE_DNIE_TERMINATED:
		case SC_CARD_TYPE_IASECC_GEMALTO:
		case SC_CARD_TYPE_PIV_II_GENERIC:
		case SC_CARD_TYPE_PIV_II_HIST:
		case SC_CARD_TYPE_PIV_II_NEO:
		case SC_CARD_TYPE_PIV_II_YUBIKEY4:

			return 1;
		default:
			return 0;
	}
}

int
sc_pkcs15_bind_synthetic(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_context_t		*ctx = p15card->card->ctx;
	scconf_block		*conf_block, **blocks, *blk;
	sc_pkcs15emu_opt_t	opts;
	int			i, r = SC_ERROR_WRONG_CARD;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	memset(&opts, 0, sizeof(opts));
	conf_block = NULL;

	conf_block = sc_get_conf_block(ctx, "framework", "pkcs15", 1);

	if (!conf_block) {
		/* no conf file found => try builtin drivers  */
		sc_log(ctx, "no conf file (or section), trying all builtin emulators");
		for (i = 0; builtin_emulators[i].name; i++) {
			sc_log(ctx, "trying %s", builtin_emulators[i].name);
			r = builtin_emulators[i].handler(p15card, aid, &opts);
			if (r == SC_SUCCESS)
				/* we got a hit */
				goto out;
		}
	} else {
		/* we have a conf file => let's use it */
		int builtin_enabled;
		const scconf_list *list, *item;

		builtin_enabled = scconf_get_bool(conf_block, "enable_builtin_emulation", 1);
		list = scconf_find_list(conf_block, "builtin_emulators"); /* FIXME: rename to enabled_emulators */

		if (builtin_enabled && list) {
			/* get the list of enabled emulation drivers */
			for (item = list; item; item = item->next) {
				/* go through the list of builtin drivers */
				const char *name = item->data;

				sc_log(ctx, "trying %s", name);
				for (i = 0; builtin_emulators[i].name; i++)
					if (!strcmp(builtin_emulators[i].name, name)) {
						r = builtin_emulators[i].handler(p15card, aid, &opts);
						if (r == SC_SUCCESS)
							/* we got a hit */
							goto out;
					}
			}
		}
		else if (builtin_enabled) {
			sc_log(ctx, "no emulator list in config file, trying all builtin emulators");
			for (i = 0; builtin_emulators[i].name; i++) {
				sc_log(ctx, "trying %s", builtin_emulators[i].name);
				r = builtin_emulators[i].handler(p15card, aid, &opts);
				if (r == SC_SUCCESS)
					/* we got a hit */
					goto out;
			}
		}

		/* search for 'emulate foo { ... }' entries in the conf file */
		sc_log(ctx, "searching for 'emulate foo { ... }' blocks");
		blocks = scconf_find_blocks(ctx->conf, conf_block, "emulate", NULL);
		sc_log(ctx, "Blocks: %p", blocks);
		for (i = 0; blocks && (blk = blocks[i]) != NULL; i++) {
			const char *name = blk->name->data;
			sc_log(ctx, "trying %s", name);
			r = parse_emu_block(p15card, aid, blk);
			if (r == SC_SUCCESS) {
				free(blocks);
				goto out;
			}
		}
		if (blocks)
			free(blocks);
	}

out:
	if (r == SC_SUCCESS) {
		p15card->magic  = SC_PKCS15_CARD_MAGIC;
		p15card->flags |= SC_PKCS15_CARD_FLAG_EMULATED;
	} else {
		if (r != SC_ERROR_WRONG_CARD)
			sc_log(ctx, "Failed to load card emulator: %s", sc_strerror(r));
	}

	LOG_FUNC_RETURN(ctx, r);
}


static int parse_emu_block(sc_pkcs15_card_t *p15card, struct sc_aid *aid, scconf_block *conf)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	sc_pkcs15emu_opt_t opts;
	void *handle = NULL;
	int		(*init_func)(sc_pkcs15_card_t *);
	int		(*init_func_ex)(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *);
	int		r;
	const char	*driver, *module_name;

	driver = conf->name->data;

	init_func    = NULL;
	init_func_ex = NULL;

	memset(&opts, 0, sizeof(opts));
	opts.blk     = conf;

	module_name = scconf_get_str(conf, "module", builtin_name);
	if (!strcmp(module_name, "builtin")) {
		int	i;

		/* This function is built into libopensc itself.
		 * Look it up in the table of emulators */
		module_name = driver;
		for (i = 0; builtin_emulators[i].name; i++) {
			if (!strcmp(builtin_emulators[i].name, module_name)) {
				init_func_ex = builtin_emulators[i].handler;
				break;
			}
		}
	} else {
		const char *(*get_version)(void);
		const char *name = NULL;
		void	*address;
		unsigned int major = 0, minor = 0, fix = 0;

		sc_log(ctx, "Loading %s", module_name);

		/* try to open dynamic library */
		handle = sc_dlopen(module_name);
		if (!handle) {
			sc_log(ctx, "unable to open dynamic library '%s': %s",
					module_name, sc_dlerror());
			return SC_ERROR_INTERNAL;
		}

		/* try to get version of the driver/api */
		get_version =  (const char *(*)(void)) sc_dlsym(handle, "sc_driver_version");
		if (get_version) {
			if (3 != sscanf(get_version(), "%u.%u.%u", &major, &minor, &fix)) {
				sc_log(ctx, "unable to get modules version number");
				sc_dlclose(handle);
				return SC_ERROR_INTERNAL;
			}
		}

		if (!get_version || (major == 0 && minor <= 9 && fix < 3)) {
			/* no sc_driver_version function => assume old style
			 * init function (note: this should later give an error
			 */
			/* get the init function name */
			name = scconf_get_str(conf, "function", func_name);

			address = sc_dlsym(handle, name);
			if (address)
				init_func = (int (*)(sc_pkcs15_card_t *)) address;
		} else {
			name = scconf_get_str(conf, "function", exfunc_name);

			address = sc_dlsym(handle, name);
			if (address)
				init_func_ex = (int (*)(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *)) address;
		}
	}
	/* try to initialize the pkcs15 structures */
	if (init_func_ex)
		r = init_func_ex(p15card, aid, &opts);
	else if (init_func)
		r = init_func(p15card);
	else
		r = SC_ERROR_WRONG_CARD;

	if (r >= 0) {
		sc_log(card->ctx, "%s succeeded, card bound", module_name);
		p15card->dll_handle = handle;
	} else {
		sc_log(card->ctx, "%s failed: %s", module_name, sc_strerror(r));
		/* clear pkcs15 card */
		sc_pkcs15_card_clear(p15card);
		if (handle)
			sc_dlclose(handle);
	}

	return r;
}

static sc_pkcs15_df_t * sc_pkcs15emu_get_df(sc_pkcs15_card_t *p15card,
	unsigned int type)
{
	sc_pkcs15_df_t	*df;
	sc_file_t	*file;
	int		created = 0;

	while (1) {
		for (df = p15card->df_list; df; df = df->next) {
			if (df->type == type) {
				if (created)
					df->enumerated = 1;
				return df;
			}
		}

		assert(created == 0);

		file = sc_file_new();
		if (!file)
			return NULL;
		sc_format_path("11001101", &file->path);
		sc_pkcs15_add_df(p15card, type, &file->path);
		sc_file_free(file);
		created++;
	}
}

int sc_pkcs15emu_add_pin_obj(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_auth_info_t *in_pin)
{
	sc_pkcs15_auth_info_t pin = *in_pin;

	pin.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	if(!pin.auth_method) /* or SC_AC_NONE */
		pin.auth_method = SC_AC_CHV;

	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_AUTH_PIN, obj, &pin);
}

int sc_pkcs15emu_add_rsa_prkey(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_prkey_info_t *in_key)
{
	sc_pkcs15_prkey_info_t key = *in_key;

	if (key.access_flags == 0)
		key.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
				| SC_PKCS15_PRKEY_ACCESS_LOCAL;

	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_PRKEY_RSA, obj, &key);
}

int sc_pkcs15emu_add_rsa_pubkey(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_pubkey_info_t *in_key)
{
	sc_pkcs15_pubkey_info_t key = *in_key;

	if (key.access_flags == 0)
		key.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;

	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_PUBKEY_RSA, obj, &key);
}

int sc_pkcs15emu_add_ec_prkey(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_prkey_info_t *in_key)
{
	sc_pkcs15_prkey_info_t key = *in_key;

	if (key.access_flags == 0)
		key.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
				| SC_PKCS15_PRKEY_ACCESS_LOCAL;

	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_PRKEY_EC, obj, &key);
}
int sc_pkcs15emu_add_ec_pubkey(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_pubkey_info_t *in_key)
{
	sc_pkcs15_pubkey_info_t key = *in_key;

	if (key.access_flags == 0)
		key.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;

	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_PUBKEY_EC, obj, &key);
}

int sc_pkcs15emu_add_x509_cert(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_cert_info_t *cert)
{
	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_CERT_X509, obj, cert);
}

int sc_pkcs15emu_add_data_object(sc_pkcs15_card_t *p15card,
	const sc_pkcs15_object_t *obj, const sc_pkcs15_data_info_t *data)
{
	return sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, obj, data);
}

int sc_pkcs15emu_object_add(sc_pkcs15_card_t *p15card, unsigned int type,
	const sc_pkcs15_object_t *in_obj, const void *data)
{
	sc_pkcs15_object_t *obj;
	unsigned int	df_type;
	size_t		data_len;

	obj = calloc(1, sizeof(*obj));
	if (!obj)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(obj, in_obj, sizeof(*obj));
	obj->type  = type;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		df_type  = SC_PKCS15_AODF;
		data_len = sizeof(struct sc_pkcs15_auth_info);
		break;
	case SC_PKCS15_TYPE_PRKEY:
		df_type  = SC_PKCS15_PRKDF;
		data_len = sizeof(struct sc_pkcs15_prkey_info);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		df_type = SC_PKCS15_PUKDF;
		data_len = sizeof(struct sc_pkcs15_pubkey_info);
		break;
	case SC_PKCS15_TYPE_CERT:
		df_type = SC_PKCS15_CDF;
		data_len = sizeof(struct sc_pkcs15_cert_info);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		df_type = SC_PKCS15_DODF;
		data_len = sizeof(struct sc_pkcs15_data_info);
		break;
	default:
		sc_log(p15card->card->ctx, "Unknown PKCS15 object type %d", type);
		free(obj);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	obj->data = calloc(1, data_len);
	if (obj->data == NULL) {
		free(obj);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(obj->data, data, data_len);

	obj->df = sc_pkcs15emu_get_df(p15card, df_type);
	sc_pkcs15_add_object(p15card, obj);

	return SC_SUCCESS;
}

