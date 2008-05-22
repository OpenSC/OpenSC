/*
 * PKCS15 emulation layer for Rutoken
 *
 * Copyright (C) 2007  Pavel Mironchik <rutoken@rutoken.ru>
 * Copyright (C) 2007  Eugene Hermann <rutoken@rutoken.ru> 
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <opensc/opensc.h>
#include <opensc/log.h>
#include <opensc/pkcs15.h>
#include "cardctl.h"

int sc_pkcs15emu_rutoken_init_ex(sc_pkcs15_card_t *p15card, 
		sc_pkcs15emu_opt_t *opts);

#define PrKDF_path      "3F00FF000001"
#define PuKDF_path      "3F00FF000002"
#define CDF_path        "3F00FF000003"
#define DODF_path       "3F00FF000004"
#define AODF_path       "3F00FF000000"

static const struct
{
	char const*  path;
	unsigned int type;
} arr_profile_df[] =
		{
			{ PrKDF_path, SC_PKCS15_PRKDF },
			{ PuKDF_path, SC_PKCS15_PUKDF },
			{ CDF_path,   SC_PKCS15_CDF   },
			{ DODF_path,  SC_PKCS15_DODF  },
			{ AODF_path,  SC_PKCS15_AODF  }
		};

static const struct {
	int           reference;
	const char   *label;
	unsigned int  flags;
} pinlist[]=
{
	{ SC_RUTOKEN_DEF_ID_GCHV_USER, "User PIN", 
		SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
	},
	{ SC_RUTOKEN_DEF_ID_GCHV_ADMIN, "SO PIN", 
		SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
		| SC_PKCS15_PIN_FLAG_SO_PIN
	}
};

static int add_predefined_pin(sc_pkcs15_card_t *p15card, sc_path_t *adf_path)
{
	size_t i;
	sc_pkcs15_pin_info_t *pin_info;
	sc_pkcs15_object_t *pin_obj;

	for (i = 0; i < sizeof(pinlist)/sizeof(pinlist[0]); ++i)
	{
		pin_info = calloc(1, sizeof(*pin_info));
		pin_obj = calloc(1, sizeof(*pin_obj));
		if (!pin_info || !pin_obj)
		{
			free(pin_info);
			free(pin_obj);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		pin_info->auth_id.len      = 1;
		pin_info->auth_id.value[0] = (u8)pinlist[i].reference;
		pin_info->reference        = pinlist[i].reference;
		pin_info->flags            = pinlist[i].flags;
		pin_info->type             = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info->min_length       = 1;
		pin_info->stored_length    = 16;
		pin_info->max_length       = 16;
		pin_info->pad_char         = -1;
		pin_info->tries_left       = 1;
		pin_info->path             = *adf_path;

		strncpy(pin_obj->label, pinlist[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj->flags = SC_PKCS15_CO_FLAG_PRIVATE;
		sc_pkcs15emu_add_pin_obj(p15card, pin_obj, pin_info);
		free(pin_obj);
		free(pin_info);
	}
	return SC_SUCCESS;
}

static void set_string(char **strp, const char *value)
{
	if (*strp) free(*strp);
	*strp = value ? strdup(value) : NULL;
}

static int set_card_info(sc_pkcs15_card_t *p15card)
{
	sc_card_t         *card = p15card->card;
	sc_context_t      *ctx = p15card->card->ctx;
	sc_serial_number_t serialnr;
	char               serial[30] = {0};
	u8                 info[8];

	/*  get the card serial number   */
	if (sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr) < 0) 
	{
		sc_debug(ctx, "Unable to get ICCSN\n");
		return SC_ERROR_WRONG_CARD;
	}
	sc_bin_to_hex(serialnr.value, serialnr.len , serial, sizeof(serial), 0);
	set_string(&p15card->serial_number, serial);
	/*  get ruToken information  */
	if (sc_card_ctl(card, SC_CARDCTL_RUTOKEN_GET_INFO, info) < 0) 
	{
		sc_debug(ctx, "Unable to get token information\n");
		return SC_ERROR_WRONG_CARD;
	}
	set_string(&p15card->label, card->name);
	p15card->version = (info[1] >> 4)*10 + (info[1] & 0x0f);
	sc_bin_to_hex(info + 3, 3 , serial, sizeof(serial), 0);
	set_string(&p15card->manufacturer_id, serial);
	return SC_SUCCESS;
}

static int sc_pkcs15_rutoken_init_func(sc_pkcs15_card_t *p15card)
{
	sc_context_t *ctx;
	sc_file_t *df;
	sc_card_t *card;
	sc_path_t path;
	size_t i;
	int r;
	unsigned int added_pin = 0;

	if (!p15card || !p15card->card || !p15card->card->ctx
			|| !p15card->card->ops
			|| !p15card->card->ops->select_file
	)
		return SC_ERROR_INVALID_ARGUMENTS;
	card = p15card->card;
	ctx = card->ctx;
	r = set_card_info(p15card);
	if (r != SC_SUCCESS)
	{
		sc_error(ctx, "Unable to set card info: %s\n", sc_strerror(r));
		r = SC_SUCCESS;
	}

	for (i = 0; i < sizeof(arr_profile_df)/sizeof(arr_profile_df[0]); ++i)
	{
		df = NULL;
		sc_format_path(arr_profile_df[i].path, &path);
		if (card->ops->select_file(card, &path, &df) == SC_ERROR_FILE_NOT_FOUND)
		{
			sc_error(ctx, "File system mismatch\n");
			r = SC_ERROR_OBJECT_NOT_FOUND;
		}
		if (r == SC_SUCCESS)
			r = sc_pkcs15_add_df(p15card, arr_profile_df[i].type, &path, df);
		if (df)
			sc_file_free(df);

		if (r != SC_SUCCESS) break;

		if (arr_profile_df[i].type == SC_PKCS15_AODF
				&&  add_predefined_pin(p15card, &path) == SC_SUCCESS
		)
			added_pin = 1;
	}
	if (!added_pin)
	{
		sc_debug(ctx, "Use formating token!\n");
		sc_format_path("", &path);
		r = add_predefined_pin(p15card, &path);
	}
	return r;
}

int sc_pkcs15emu_rutoken_init_ex(sc_pkcs15_card_t *p15card, 
		sc_pkcs15emu_opt_t *opts)
{
	struct sc_card *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, 1);
	/* check if we have the correct card OS */
	if (strcmp(card->name, "Rutoken card"))
		return SC_ERROR_WRONG_CARD;
	sc_debug(card->ctx, "%s found", card->name);
	return sc_pkcs15_rutoken_init_func(p15card);
}

