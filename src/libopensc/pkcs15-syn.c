/*
 * pkcs15-syn.c: PKCS #15 emulation of non-pkcs15 cards
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
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

static int	sc_pkcs15_bind_emulation(sc_pkcs15_card_t *, const char *,
				scconf_block *, int);

extern int	sc_pkcs15emu_openpgp_init(sc_pkcs15_card_t *);

static struct {
	const char *		name;
	int			(*handler)(sc_pkcs15_card_t *);
} builtin_emulators[] = {
      {	"openpgp",		sc_pkcs15emu_openpgp_init	},

      { NULL }
};


int
sc_pkcs15_bind_synthetic(sc_pkcs15_card_t *p15card, int check_atr)
{
	sc_context_t		*ctx = p15card->card->ctx;
	const scconf_list	*clist, *tmp;
	scconf_block		*conf_block, **blocks, *blk;
	int			i, r;

	SC_FUNC_CALLED(ctx, 1);

	assert(p15card);

	conf_block = NULL;
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
						"framework", "pkcs15");
		if (blocks[0] != NULL)
			conf_block = blocks[0];
		free(blocks);
	}
	if (!conf_block)
		return SC_ERROR_WRONG_CARD;

	/* Old-style: get the pkcs15_syn libs from the conf file */
	clist = scconf_find_list(conf_block, "pkcs15_syn");
	for (tmp = clist; tmp != NULL; tmp = tmp->next) {
		const char *module = tmp->data;

		if (module == NULL)
			continue;
		r = sc_pkcs15_bind_emulation(p15card, module, NULL, check_atr);
		if (r != SC_ERROR_WRONG_CARD)
			goto out;
	}

	/* New-style: get lib name, function name, ATR list */
	blocks = scconf_find_blocks(ctx->conf, conf_block, "emulate", NULL);
	for (i = 0; (blk = blocks[i]) != NULL; i++) {
		const char *module;

		module = scconf_get_str(blk, "module", NULL);
		if (!module)
			continue;

		r = sc_pkcs15_bind_emulation(p15card, module, blk, check_atr);
		if (r != SC_ERROR_WRONG_CARD) {
			free(blocks);
			goto out;
		}
	}
	free(blocks);

	/* Total failure */
	return SC_ERROR_WRONG_CARD;

out:	if (r == SC_SUCCESS) {
		/* p15card->flags |= SC_PKCS15_CARD_FLAG_READONLY; */
		p15card->magic  = 0x10203040;
	} else if (r != SC_ERROR_WRONG_CARD) {
		sc_error(ctx, "Failed to load card emulator: %s\n",
				sc_strerror(r));
	}

	return r;
}

int
sc_pkcs15_bind_emulation(sc_pkcs15_card_t *p15card,
				const char *module_name,
				scconf_block *conf,
				int check_atr)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	const scconf_list *list, *item;
	void		*dll = NULL;
	int		(*init_func)(sc_pkcs15_card_t *);
	int		r;

	if (conf && (list = scconf_find_list(conf, "atr"))) {
		int	match = 0;

		if (!check_atr)
			return SC_ERROR_WRONG_CARD;
		for (item = list; item; item = item->next) {
			u8	atr[SC_MAX_ATR_SIZE];
			size_t	len = sizeof(atr);

			if (!item->data)
				continue;
			if (sc_hex_to_bin(item->data, atr, &len))
				continue;
			if (len > card->atr_len
			 || memcmp(card->atr, atr, len))
				continue;
			match = 1;
			break;
		}
		if (!match)
			return SC_ERROR_WRONG_CARD;
	} else if (!check_atr) {
		/* ATR checking required, but no ATR list to match against */
		return SC_ERROR_WRONG_CARD;
	}

	init_func = NULL;
	if (!strcmp(module_name, "builtin")) {
		int	i;

		/* This function is built into libopensc itself.
		 * Look it up in the table of emulators */
		if (conf == NULL || !conf->name)
			return SC_ERROR_INTERNAL;

		module_name = conf->name->data;
		for (i = 0; builtin_emulators[i].name; i++) {
			if (!strcmp(builtin_emulators[i].name, module_name)) {
				init_func = builtin_emulators[i].handler;
				break;
			}
		}
		if (!init_func)
			return SC_ERROR_WRONG_CARD;
	} else {
		const char *function_name = NULL;
		void	*address;

		if (ctx->debug >= 4)
			sc_debug(ctx, "Loading %s\n", module_name);

		/* try to open dynamic library */
		r = sc_module_open(ctx, &dll, module_name);
		if (r != SC_SUCCESS)
			return r;

		/* get a handle to the pkcs15 init function 
		 * XXX the init_func should not modify the contents of
		 * sc_pkcs15_card_t unless the card is really the one
		 * the driver is intended for -- Nils
		 */
		if (conf)
			function_name = scconf_get_str(conf, "function", NULL);
		if (function_name == NULL)
			function_name = "sc_pkcs15_init_func";

		r = sc_module_get_address(ctx, dll, &address, function_name);
		if (r != SC_SUCCESS)
			return r;

		/* try to initialize synthetic pkcs15 structures */
		init_func = (int (*)(sc_pkcs15_card_t *)) address;
	}

	r = init_func(p15card);
	if (r >= 0) {
		sc_debug(card->ctx, "%s succeeded, card bound\n",
				module_name);
		p15card->dll_handle = dll;
	} else if (ctx->debug >= 4) {
		sc_debug(card->ctx, "%s failed: %s\n",
				module_name, sc_strerror(r));
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
		const sc_pkcs15_id_t *auth_id)
{
	sc_pkcs15_object_t *obj;
	int		df_type;

	obj = (sc_pkcs15_object_t *) calloc(1, sizeof(*obj));

	obj->type  = type;
	obj->data  = data;
                
	if (label)
		strncpy(obj->label, label, sizeof(obj->label)-1);

	if (!(p15card->flags & SC_PKCS15_CARD_FLAG_READONLY))
		obj->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
	if (auth_id)
		obj->auth_id = *auth_id;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		obj->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
		df_type = SC_PKCS15_AODF;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		obj->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
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
                int flags, int tries_left, const char pad_char)
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
	                               label, info, NULL);
}

int
sc_pkcs15emu_add_cert(sc_pkcs15_card_t *p15card,
		int type, int authority,
		const sc_path_t *path,
		const sc_pkcs15_id_t *id,
                const char *label)
{
	/* const char *label = "Certificate"; */
	sc_pkcs15_cert_info_t *info;
	info = (sc_pkcs15_cert_info_t *) calloc(1, sizeof(*info));
	info->id		= *id;
	info->authority		= authority;
	if (path)
		info->path = *path;
                
	info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, NULL);
}

int
sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
                const sc_pkcs15_id_t *id,
                const char *label,
                int type, unsigned int modulus_length, int usage,
                const sc_path_t *path, int ref,
                const sc_pkcs15_id_t *auth_id)
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
	                               type, label, info, auth_id);
}

int
sc_pkcs15emu_add_pubkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label, int type,
		unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		const sc_pkcs15_id_t *auth_id)
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

	return sc_pkcs15emu_add_object(p15card, type, label, info, auth_id);
}
