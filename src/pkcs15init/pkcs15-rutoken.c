/*
 * Rutoken S specific operation for PKCS15 initialization
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

#include "config.h"

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/pkcs15.h"
#include "pkcs15-init.h"
#include "profile.h"

static const sc_SecAttrV2_t wn_sec_attr = {
	0x43, 1, 1, 0, 0, 0, 0, -1,
	2, 0, 0, 0,
	2
};
static const sc_SecAttrV2_t p2_sec_attr = {
	0x43, 1, 1, 0, 0, 0, 0, -1,
	1, 0, 0, 0,
	2
};
static const sc_SecAttrV2_t p1_sec_attr = {
	0x43, -1, 1, 0, 0, 0, 0, -1,
	0, 0, 0, 0,
	1
};

static const struct
{
	u8                     id, options, flags, try, pass[8];
	sc_SecAttrV2_t const*  p_sattr;
} do_pins[] =
		{
			{ SC_RUTOKEN_DEF_ID_GCHV_USER, SC_RUTOKEN_OPTIONS_GACCESS_USER,
			  SC_RUTOKEN_FLAGS_COMPACT_DO, 0xFF,
			  { '1', '2', '3', '4', '5', '6', '7', '8' }, &p2_sec_attr
			},
			{ SC_RUTOKEN_DEF_ID_GCHV_ADMIN, SC_RUTOKEN_OPTIONS_GACCESS_ADMIN,
			  SC_RUTOKEN_FLAGS_COMPACT_DO, 0xFF,
			  { '8', '7', '6', '5', '4', '3', '2', '1' }, &p1_sec_attr
			}
		};

/*
 * Create a DF
 */
static int
rutoken_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_file_t *df)
{
	if (!profile || !p15card || !p15card->card || !p15card->card->ctx || !df)
		return SC_ERROR_INVALID_ARGUMENTS;
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	return sc_pkcs15init_create_file(profile, p15card, df);
}

/*
 * Select a PIN reference
 */
static int
rutoken_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_pkcs15_auth_info_t *auth_info)
{
	int pin_ref;
	unsigned int so_pin_flag;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx || !auth_info)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	pin_ref = auth_info->attrs.pin.reference;
	so_pin_flag = auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN;

	sc_log(p15card->card->ctx,  "PIN reference %i%s\n",
			pin_ref, so_pin_flag ? " SO PIN flag" : "");

	if ((pin_ref == SC_RUTOKEN_DEF_ID_GCHV_ADMIN && so_pin_flag)
			|| (pin_ref == SC_RUTOKEN_DEF_ID_GCHV_USER && !so_pin_flag)
	)
		return SC_SUCCESS;
	else
		return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Create a PIN object within the given DF
 */
static int
rutoken_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
			sc_file_t *df, sc_pkcs15_object_t *pin_obj,
			const unsigned char *pin, size_t pin_len,
			const unsigned char *puk, size_t puk_len)
{
	sc_context_t *ctx;
	sc_pkcs15_auth_info_t *auth_info;
	size_t i;

	(void)puk; /* no warning */
	if (!profile || !p15card || !p15card->card || !p15card->card->ctx
			|| !df || !pin_obj || !pin_obj->data || !pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (puk_len != 0)
	{
		sc_log(ctx, 
				"Do not enter User unblocking PIN (PUK): %s\n",
				sc_strerror(SC_ERROR_NOT_SUPPORTED));
		return SC_ERROR_NOT_SUPPORTED;
	}

	auth_info = (sc_pkcs15_auth_info_t *)pin_obj->data;
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
                return SC_ERROR_OBJECT_NOT_VALID;

	for (i = 0; i < sizeof(do_pins)/sizeof(do_pins[0]); ++i)
		if (auth_info->attrs.pin.reference == do_pins[i].id)
		{
			if (pin_len == sizeof(do_pins[i].pass)
					&&  memcmp(do_pins[i].pass, pin, pin_len) == 0
			)
				return SC_SUCCESS;
			else
			{
				sc_log(ctx,  "Incorrect PIN\n");
				break;
			}
		}
	sc_log(ctx, 
			"PIN reference %i not found in standard (Rutoken) PINs\n",
			auth_info->attrs.pin.reference);
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Initialization routine
 */

static int create_pins(sc_card_t *card)
{
	sc_DO_V2_t param_do;
	size_t i;
	int r = SC_SUCCESS;

	for (i = 0; i < sizeof(do_pins)/sizeof(do_pins[0]); ++i)
	{
		memset(&param_do, 0, sizeof(param_do));
		param_do.HDR.OTID.byObjectType  = SC_RUTOKEN_TYPE_CHV;
		param_do.HDR.OTID.byObjectID    = do_pins[i].id;
		param_do.HDR.OP.byObjectOptions = do_pins[i].options;
		param_do.HDR.OP.byObjectFlags   = do_pins[i].flags;
		param_do.HDR.OP.byObjectTry     = do_pins[i].try;
		param_do.HDR.wDOBodyLen = sizeof(do_pins[i].pass);
		/* assert(do_pins[i].p_sattr != NULL); */
		/* assert(sizeof(*param_do.HDR.SA_V2)) */
		/* assert(sizeof(param_do.HDR.SA_V2) == sizeof(*do_pins[i].p_sattr)); */
		memcpy(param_do.HDR.SA_V2, *do_pins[i].p_sattr,
				sizeof(*do_pins[i].p_sattr));
		/* assert(do_pins[i].pass); */
		/* assert(sizeof(*param_do.abyDOBody)) */
		/* assert(sizeof(param_do.abyDOBody) >= sizeof(do_pins[i].pass)); */
		memcpy(param_do.abyDOBody, do_pins[i].pass, sizeof(do_pins[i].pass));

		r = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_CREATE_DO, &param_do);
		if (r != SC_SUCCESS) break;
	}
	return r;
}

static int create_typical_fs(sc_card_t *card)
{
	sc_file_t *df;
	int r;

	df = sc_file_new();
	if (!df)
		return SC_ERROR_OUT_OF_MEMORY;
	df->type = SC_FILE_TYPE_DF;
	do
	{
		r = sc_file_set_sec_attr(df, wn_sec_attr, sizeof(wn_sec_attr));
		if (r != SC_SUCCESS) break;

		/* Create MF  3F00 */
		df->id = 0x3F00;
		sc_format_path("3F00", &df->path);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		/* Create     3F00/0000 */
		df->id = 0x0000;
		sc_append_file_id(&df->path, df->id);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		/* Create     3F00/0000/0000 */
		df->id = 0x0000;
		sc_append_file_id(&df->path, df->id);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		/* Create USER PIN and SO PIN*/
		r = create_pins(card);
		if (r != SC_SUCCESS) break;

		/* VERIFY USER PIN */
		r = sc_verify(card, SC_AC_CHV, do_pins[0].id,
				do_pins[0].pass, sizeof(do_pins[0].pass), NULL);
		if (r != SC_SUCCESS) break;

		/* Create     3F00/0000/0000/0001 */
		df->id = 0x0001;
		sc_append_file_id(&df->path, df->id);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		sc_format_path("3F0000000000", &df->path);
		r = sc_select_file(card, &df->path, NULL);
		if (r != SC_SUCCESS) break;

		/* Create     3F00/0000/0000/0002 */
		df->id = 0x0002;
		sc_append_file_id(&df->path, df->id);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		sc_format_path("3F000000", &df->path);
		r = sc_select_file(card, &df->path, NULL);
		if (r != SC_SUCCESS) break;

		/* Create     3F00/0000/0001 */
		df->id = 0x0001;
		sc_append_file_id(&df->path, df->id);
		r = sc_create_file(card, df);
		if (r != SC_SUCCESS) break;

		/* RESET ACCESS RIGHTS */
		r = sc_logout(card);
	} while(0);
	sc_file_free(df);
	return r;
}

/*
 * Erase everything that's on the card
 */
static int
rutoken_erase(struct sc_profile *profile, sc_pkcs15_card_t *p15card)
{
	sc_card_t *card;
	int ret, ret_end;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	card = p15card->card;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* ret = sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL); */
	ret = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_FORMAT_INIT, NULL);
	if (ret == SC_SUCCESS)
	{
		ret = create_typical_fs(card);
		if (ret != SC_SUCCESS)
			sc_log(card->ctx, 
					"Failed to create typical fs: %s\n",
					sc_strerror(ret));
		ret_end = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_FORMAT_END, NULL);
		if (ret_end != SC_SUCCESS)
			ret = ret_end;
	}
	if (ret != SC_SUCCESS)
		sc_log(card->ctx, 
				"Failed to erase: %s\n", sc_strerror(ret));
	else
		sc_free_apps(card);
	return ret;
}

static struct sc_pkcs15init_operations sc_pkcs15init_rutoken_operations = {
	rutoken_erase,                  /* erase_card */
	NULL,                           /* init_card */
	rutoken_create_dir,             /* create_dir */
	NULL,                           /* create_domain */
	rutoken_select_pin_reference,   /* select_pin_reference */
	rutoken_create_pin,             /* create_pin */
	NULL,                           /* select_key_reference */
	NULL,                           /* create_key */
	NULL,                           /* store_key */
	NULL,                           /* generate_key */
	NULL,                           /* encode_private_key */
	NULL,                           /* encode_public_key */
	NULL,                           /* finalize_card */
	NULL,                           /* delete_object */
	NULL, NULL, NULL, NULL, NULL,   /* pkcs15init emulation */
	NULL                            /* sanity_check */
};

struct sc_pkcs15init_operations* sc_pkcs15init_get_rutoken_ops(void)
{
	return &sc_pkcs15init_rutoken_operations;
}

