/*
 * pkcs15-syn.c: PKCS #15 emulation of non-pkcs15 cards
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
 *               2004  Nils Larsch <nlarsch@betrusted.com>
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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

extern int sc_pkcs15emu_openpgp_init_ex(sc_pkcs15_card_t *,
					sc_pkcs15emu_opt_t *);
extern int sc_pkcs15emu_infocamere_init_ex(sc_pkcs15_card_t *,
					sc_pkcs15emu_opt_t *);
extern int sc_pkcs15emu_starcert_init_ex(sc_pkcs15_card_t *,
					sc_pkcs15emu_opt_t *);
extern int sc_pkcs15emu_netkey_init_ex(sc_pkcs15_card_t *,
					sc_pkcs15emu_opt_t *);
extern int sc_pkcs15emu_esteid_init_ex(sc_pkcs15_card_t *,
					sc_pkcs15emu_opt_t *);

static struct {
	const char *		name;
	int			(*handler)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);
} builtin_emulators[] = {
      {	"openpgp",		sc_pkcs15emu_openpgp_init_ex	},
      { "infocamere",           sc_pkcs15emu_infocamere_init_ex	},
      { "starcert",             sc_pkcs15emu_starcert_init_ex	},
      { "netkey",		sc_pkcs15emu_netkey_init_ex	},
      { "esteid",		sc_pkcs15emu_esteid_init_ex	},
      { NULL }
};

static int parse_emu_block(sc_pkcs15_card_t *, scconf_block *);

static const char *builtin_name = "builtin";
static const char *func_name    = "sc_pkcs15_init_func";
static const char *exfunc_name  = "sc_pkcs15_init_func_ex";


int
sc_pkcs15_bind_synthetic(sc_pkcs15_card_t *p15card)
{
	sc_context_t		*ctx = p15card->card->ctx;
	scconf_block		*conf_block, **blocks, *blk;
	sc_pkcs15emu_opt_t	opts;
	int			i, r = SC_ERROR_WRONG_CARD;

	SC_FUNC_CALLED(ctx, 1);

	memset(&opts, 0, sizeof(opts));

	conf_block = NULL;
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
						"framework", "pkcs15");
		if (blocks[0] != NULL)
			conf_block = blocks[0];
		free(blocks);
	}

	if (!conf_block) {
		/* no conf file found => try the internal drivers  */
		sc_debug(ctx, "no conf file, trying builtin emulators\n");
		for (i = 0; builtin_emulators[i].name; i++) {
			sc_debug(ctx, "trying %s\n", builtin_emulators[i].name);
			r = builtin_emulators[i].handler(p15card, &opts);
			if (r == SC_SUCCESS)
				/* we got a hit */
				goto out;
		}
	} else {
		/* we have a conf file => let's use it */
		const scconf_list *list, *item;
		/* find out if the internal drivers should be used */
		i = scconf_get_bool(conf_block, "enable_builtin_emulation", 1);
		if (i) {
			/* get the list of the internal drivers */
			sc_debug(ctx, "use builtin drivers\n");
			list = scconf_find_list(conf_block, "builtin_emulators");
			for (item = list; item; item = item->next) {
				/* get through the list of builtin drivers */
				const char *name = item->data;

				sc_debug(ctx, "trying %s\n", name);
				for (i = 0; builtin_emulators[i].name; i++)
					if (!strcmp(builtin_emulators[i].name, name)) {
						r = builtin_emulators[i].handler(p15card, &opts);
						if (r == SC_SUCCESS)
							goto out;
					}
			}
		}
		/* search for 'emulate foo { ... }' entries in the conf file */
		sc_debug(ctx, "searching for 'emulate foo { ... }' blocks\n");
		blocks = scconf_find_blocks(ctx->conf, conf_block, "emulate", NULL);

		for (i = 0; (blk = blocks[i]) != NULL; i++) {
			const char *name = blk->name->data;
			sc_debug(ctx, "trying %s\n", name);
			r = parse_emu_block(p15card, blk);
			if (r == SC_SUCCESS) {
				free(blocks);
				goto out;
			}
		}
		if (blocks)
			free(blocks);
	}
		
	/* Total failure */
	return SC_ERROR_WRONG_CARD;

out:	if (r == SC_SUCCESS) {
		p15card->magic  = 0x10203040;
	} else if (r != SC_ERROR_WRONG_CARD) {
		sc_error(ctx, "Failed to load card emulator: %s\n",
				sc_strerror(r));
	}

	return r;
}

static int emu_detect_card(const sc_card_t *card, const scconf_block *blk)
{
	int   r = 1, match = 0;
	const scconf_list *list, *item;
	/* currently only ATR matching is supported (more to follow) */

	/* check the ATR */
	list = scconf_find_list(blk, "atr");
	if (list) {
		for (item = list; item; item = item->next) {
			u8     atr[SC_MAX_ATR_SIZE];
			size_t len = sizeof(atr);

			if (!item->data)
				/* skip empty data */
				continue;
			if (sc_hex_to_bin(item->data, atr, &len) != SC_SUCCESS)
				/* ignore errors, try next atr */
				continue;
			if (len == card->atr_len && !memcmp(card->atr, atr, len)){
				match = 1;
				break;
			}
		}
		if (match)
			r = 1;
		else
			r = 0;
	}

	return r;
}

static int parse_emu_block(sc_pkcs15_card_t *p15card, scconf_block *conf)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	sc_pkcs15emu_opt_t opts;
	void		*dll = NULL;
	int		(*init_func)(sc_pkcs15_card_t *);
	int		(*init_func_ex)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);
	int		r;
	const char	*module_name;

	r = emu_detect_card(card, conf);
	if (!r)
		return SC_ERROR_WRONG_CARD;

	init_func    = NULL;
	init_func_ex = NULL;
	opts.blk     = conf;
	opts.flags   = SC_PKCS15EMU_FLAGS_NO_CHECK;

	module_name = scconf_get_str(conf, "module", builtin_name);

	if (!strcmp(module_name, "builtin")) {
		int	i;

		/* This function is built into libopensc itself.
		 * Look it up in the table of emulators */
		if (!conf->name)
			return SC_ERROR_INTERNAL;

		module_name = conf->name->data;
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

		sc_debug(ctx, "Loading %s\n", module_name);
		
		/* try to open dynamic library */
		r = sc_module_open(ctx, &dll, module_name);
		if (r != SC_SUCCESS)
			return r;
		/* try to get version of the driver/api */
		r = sc_module_get_address(ctx, dll, &address, "sc_driver_version");
		if (r < 0)
			get_version = NULL;
		else
			get_version = (const char *(*)())address;
		if (!get_version || strcmp(get_version(), "0.9.3") < 0) {
			/* no sc_driver_version function => assume old style
			 * init function (note: this should later give an error
			 */
			/* get the init function name */
			name = scconf_get_str(conf, "function", func_name);

			r = sc_module_get_address(ctx, dll, &address, name);
			if (r == SC_SUCCESS)
				init_func = (int (*)(sc_pkcs15_card_t *)) address;
		} else {
			name = scconf_get_str(conf, "function", exfunc_name);

			r = sc_module_get_address(ctx, dll, &address, name);
			if (r == SC_SUCCESS)
				init_func_ex = (int (*)(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *)) address;
		}
	}
	/* try to initialize the pkcs15 structures */
	if (init_func_ex)
		r = init_func_ex(p15card, &opts);
	else if (init_func)
		r = init_func(p15card);
	else
		r = SC_ERROR_WRONG_CARD;

	if (r >= 0) {
		sc_debug(card->ctx, "%s succeeded, card bound\n",
				module_name);
		p15card->dll_handle = dll;
	} else if (ctx->debug >= 4) {
		sc_debug(card->ctx, "%s failed: %s\n",
				module_name, sc_strerror(r));
		/* clear pkcs15 card */
		sc_pkcs15_card_clear(p15card);
		if (dll)
			sc_module_close(ctx, dll);
	}

	return r;
}

sc_pkcs15_df_t *
sc_pkcs15emu_get_df(sc_pkcs15_card_t *p15card, int type)
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
		sc_format_path("11001101", &file->path);
		sc_pkcs15_add_df(p15card, type, &file->path, file);
		created++;
	}
}

int
sc_pkcs15emu_add_object(sc_pkcs15_card_t *p15card, int type,
		const char *label, void *data,
		const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_object_t *obj;
	int		df_type;

	obj = (sc_pkcs15_object_t *) calloc(1, sizeof(*obj));

	obj->type  = type;
	obj->data  = data;
                
	if (label)
		strncpy(obj->label, label, sizeof(obj->label)-1);

	obj->flags = obj_flags;
	if (auth_id)
		obj->auth_id = *auth_id;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		df_type = SC_PKCS15_AODF;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		df_type = SC_PKCS15_PRKDF;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		df_type = SC_PKCS15_PUKDF;
		break;
	case SC_PKCS15_TYPE_CERT:
		df_type = SC_PKCS15_CDF;
		break;
	default:
		sc_error(p15card->card->ctx,
			"Unknown PKCS15 object type %d\n", type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	obj->df = sc_pkcs15emu_get_df(p15card, df_type);
	sc_pkcs15_add_object(p15card, obj);

	return 0;
}

int
sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id, const char *label,
                const sc_path_t *path, int ref, int type,
                unsigned int min_length,
                unsigned int max_length,
                int flags, int tries_left, const char pad_char, int obj_flags)
{
	sc_pkcs15_pin_info_t *info;
                
	info = (sc_pkcs15_pin_info_t *) calloc(1, sizeof(*info));
	info->auth_id           = *id;
	info->min_length        = min_length;
	info->max_length        = max_length;
	info->stored_length     = max_length;
	info->type              = type;
	info->reference         = ref;
	info->flags             = flags;
	info->tries_left        = tries_left;
	info->magic             = SC_PKCS15_PIN_MAGIC;
	info->pad_char          = pad_char;
        
	if (path)
		info->path = *path;     
	if (type == SC_PKCS15_PIN_TYPE_BCD)
		info->stored_length /= 2;
                
	return sc_pkcs15emu_add_object(p15card,
	                               SC_PKCS15_TYPE_AUTH_PIN,
	                               label, info, NULL, obj_flags);
}

int
sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
		int type, int authority,
		const sc_path_t *path,
		const sc_pkcs15_id_t *id,
                const char *label, int obj_flags)
{
	/* const char *label = "Certificate"; */
	sc_pkcs15_cert_info_t *info;
	info = (sc_pkcs15_cert_info_t *) calloc(1, sizeof(*info));
	info->id		= *id;
	info->authority		= authority;
	if (path)
		info->path = *path;
                
	info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, NULL,
					obj_flags);
}

int
sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id,
                const char *label,
                int type, unsigned int modulus_length, int usage,
                const sc_path_t *path, int ref,
                const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_prkey_info_t *info;   
        
	info = (sc_pkcs15_prkey_info_t *) calloc(1, sizeof(*info));
	info->id                = *id;
	info->modulus_length    = modulus_length;
	info->usage             = usage;
	info->native            = 1;
	info->access_flags      = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
                                | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
                                | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
                                | SC_PKCS15_PRKEY_ACCESS_LOCAL;
	info->key_reference     = ref;
 
	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card,
	                               type, label, info, auth_id, obj_flags);
}

int
sc_pkcs15emu_add_pubkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label, int type,
		unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		const sc_pkcs15_id_t *auth_id, int obj_flags)
{
	sc_pkcs15_pubkey_info_t *info;

	info = (sc_pkcs15_pubkey_info_t *) calloc(1, sizeof(*info));
	info->id		= *id;
	info->modulus_length	= modulus_length;
	info->usage		= usage;
	info->access_flags	= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
	info->key_reference	= ref;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, auth_id,
					obj_flags);
}
