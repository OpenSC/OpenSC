/*
 * Rutoken specific operation for PKCS15 initialization
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
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include <opensc/pkcs15.h>
#include "pkcs15-init.h"
#include "profile.h"

static const sc_SecAttrV2_t pr_sec_attr = {0x43, 1, 1, 0, 0, 0, 0, 1, 2, 2, 0, 0, 0, 0, 2};
static const sc_SecAttrV2_t wn_sec_attr = {0x43, 1, 1, 0, 0, 0, 0,-1, 2, 2, 0, 0, 0, 0, 0};
static const sc_SecAttrV2_t p2_sec_attr = {0x43, 1, 1, 0, 0, 0, 0,-1, 1, 2, 0, 0, 0, 0, 0};
static const sc_SecAttrV2_t p1_sec_attr = {0x43, 1, 1, 0, 0, 0, 0,-1, 1, 1, 0, 0, 0, 0, 0};

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


static int rutoken_get_bin_from_prkey(const struct sc_pkcs15_prkey_rsa *rsa,
			u8 *bufkey, size_t *bufkey_size)
{
	const uint32_t bitlen = rsa->modulus.len * 8;
	size_t i, len;

	if (    rsa->modulus.len  != bitlen/8
	     || rsa->p.len        != bitlen/16
	     || rsa->q.len        != bitlen/16
	     || rsa->dmp1.len     != bitlen/16
	     || rsa->dmq1.len     != bitlen/16
	     || rsa->iqmp.len     != bitlen/16
	     || rsa->d.len        != bitlen/8
	     || rsa->exponent.len > sizeof(uint32_t)
	)
		return -1;

	if (*bufkey_size < 14 + sizeof(uint32_t) * 2 + bitlen/8 * 2 + bitlen/16 * 5)
		return -1;

	bufkey[0] = 2;
	bufkey[1] = 1;

	/* BLOB header */
	bufkey[2] = 0x07; /* Type */
	bufkey[3] = 0x02; /* Version */
	/* reserve */
	bufkey[4] = 0;
	bufkey[5] = 0;
	/* aiKeyAlg */
	bufkey[6] = 0;
	bufkey[7] = 0xA4;
	bufkey[8] = 0;
	bufkey[9] = 0;

	/* RSAPUBKEY */
	/* magic "RSA2" */
	bufkey[10] = 0x52;
	bufkey[11] = 0x53;
	bufkey[12] = 0x41;
	bufkey[13] = 0x32;
	len = 14;
	/* bitlen */
	for (i = 0; i < sizeof(uint32_t); ++i)
		bufkey[len++] = (bitlen >> i*8) & 0xff;
	/* pubexp */
	for (i = 0; i < sizeof(uint32_t); ++i)
		if (i < rsa->exponent.len)
			bufkey[len++] = rsa->exponent.data[rsa->exponent.len - 1 - i];
		else
			bufkey[len++] = 0;

#define MEMCPY_BUF_REVERSE_RSA(NAME) \
	do { \
		for (i = 0; i < rsa->NAME.len; ++i) \
			bufkey[len++] = rsa->NAME.data[rsa->NAME.len - 1 - i]; \
	} while (0)

	/* PRIVATEKEYBLOB tail */
	MEMCPY_BUF_REVERSE_RSA(modulus); /* modulus */
	MEMCPY_BUF_REVERSE_RSA(p); /* prime1 */
	MEMCPY_BUF_REVERSE_RSA(q); /* prime2 */
	MEMCPY_BUF_REVERSE_RSA(dmp1); /* exponent1 */
	MEMCPY_BUF_REVERSE_RSA(dmq1); /* exponent2 */
	MEMCPY_BUF_REVERSE_RSA(iqmp); /* coefficient */
	MEMCPY_BUF_REVERSE_RSA(d); /* privateExponent */

	*bufkey_size = len;
	return 0;
}

/*
 * Create a DF
 */
static int
rutoken_create_dir(sc_profile_t *profile, sc_card_t *card, sc_file_t *df)
{
	if (!profile || !card || !card->ctx || !df)
		return SC_ERROR_INVALID_ARGUMENTS;
	SC_FUNC_CALLED(card->ctx, 1);
	return sc_pkcs15init_create_file(profile, card, df);
}

/*
 * Select a PIN reference
 */
static int
rutoken_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_pin_info_t *pin_info)
{
	if (!profile || !card || !pin_info)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	sc_debug(card->ctx, "PIN reference %i, PIN flags 0x%x\n",
			pin_info->reference, pin_info->flags);
	/* XXX:
	 * Create:
	 * First iteration find reference for create new PIN object with
	 * pin_info->reference == 0
	 * Next iteration ++pin_info->reference signify PIN object
	 * (pin_info->reference == SC_RUTOKEN_DEF_ID_GCHV_ADMIN  or
	 *  pin_info->reference == SC_RUTOKEN_DEF_ID_GCHV_USER)
	 * is already created.
	 * Find:
	 * Valid PIN reference: { SC_RUTOKEN_DEF_ID_GCHV_ADMIN,
	 * SC_RUTOKEN_DEF_ID_GCHV_USER }
	 */
	if (pin_info->reference != 0
			&& pin_info->reference != SC_RUTOKEN_DEF_ID_GCHV_ADMIN
			&& pin_info->reference != SC_RUTOKEN_DEF_ID_GCHV_USER
	)
		/* PKCS#15 SOPIN and UserPIN already created */
		return SC_ERROR_NOT_SUPPORTED;

	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		pin_info->reference = SC_RUTOKEN_DEF_ID_GCHV_ADMIN;
	else
		pin_info->reference = SC_RUTOKEN_DEF_ID_GCHV_USER;
	sc_debug(card->ctx, "PIN reference %i\n", pin_info->reference);
	return SC_SUCCESS;
}

/*
 * Create a PIN object within the given DF
 */
static int
rutoken_create_pin(sc_profile_t *profile, sc_card_t *card,
			sc_file_t *df, sc_pkcs15_object_t *pin_obj,
			const unsigned char *pin, size_t pin_len,
			const unsigned char *puk, size_t puk_len)
{
	sc_pkcs15_pin_info_t *pin_info;
	size_t i;

	if (!profile || !card || !df || !pin_obj || !pin_obj->data || !pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	if (puk_len != 0)
	{
		sc_error(card->ctx, "Do not enter User unblocking PIN (PUK): %s\n",
				sc_strerror(SC_ERROR_NOT_SUPPORTED));
		return SC_ERROR_NOT_SUPPORTED;
	}
	pin_info = (sc_pkcs15_pin_info_t *)pin_obj->data;
	for (i = 0; i < sizeof(do_pins)/sizeof(do_pins[0]); ++i)
		if (pin_info->reference == do_pins[i].id)
		{
			if (pin_len == sizeof(do_pins[i].pass)
					&&  memcmp(do_pins[i].pass, pin, pin_len) == 0
			)
				return SC_SUCCESS;
			else
			{
				sc_error(card->ctx, "Incorrect PIN\n");
				break;
			}
		}
	sc_debug(card->ctx, "PIN reference %i not found in standard (Rutoken) PINs\n",
			pin_info->reference);
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Select a key reference
 */
static int
rutoken_select_key_reference(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_prkey_info_t *key_info)
{
	int id_low;

	if (!profile || !card || !card->ctx || !key_info || key_info->path.len < 1)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	id_low = key_info->key_reference + key_info->path.value[key_info->path.len - 1];
	sc_debug(card->ctx, "id_low = %i, key_reference = %i\n",
			id_low, key_info->key_reference);
	if (id_low > 0xFF)
		return SC_ERROR_TOO_MANY_OBJECTS;

	key_info->path.value[key_info->path.len - 1] = id_low & 0xFF;
	return SC_SUCCESS;
}

/*
 * Create a private key object.
 * This is a no-op.
 */
static int
rutoken_create_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj)
{
	if (!profile || !card || !card->ctx || !obj)
		return SC_ERROR_INVALID_ARGUMENTS;
	SC_FUNC_CALLED(card->ctx, 1);
	return SC_SUCCESS;
}

/* 
 * Store a private key object.
 */
static int
rutoken_store_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj,
			sc_pkcs15_prkey_t *key)
{
	sc_pkcs15_prkey_info_t *key_info;
	u8 *prkeybuf = NULL;
	size_t prsize = 2048;
	sc_file_t *file;
	int ret;

	if (!profile || !card || !card->ctx || !obj || !obj->data || !key)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		return SC_ERROR_NOT_SUPPORTED;

	key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	if (key_info->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;

	prkeybuf = calloc(prsize, 1);
	if (!prkeybuf)
		return SC_ERROR_OUT_OF_MEMORY;

	/*
	 * encode private key 
	 * create key file 
	 * write a key
	 */
	ret = rutoken_get_bin_from_prkey(&key->u.rsa, prkeybuf, &prsize);
	sc_debug(card->ctx, "sc_rutoken_get_bin_from_prkey returned %i\n", ret);
	if (ret == 0)
	{
		file = sc_file_new();
		if (!file)
			ret = SC_ERROR_OUT_OF_MEMORY;
		else
		{
			/* create (or update) key file */
			file->path = key_info->path;
			file->type = SC_FILE_TYPE_WORKING_EF;
			file->id = key_info->path.value[key_info->path.len - 2] << 8
				| key_info->path.value[key_info->path.len - 1];
			file->size = prsize;
			sc_file_set_sec_attr(file, (u8*)&pr_sec_attr, SEC_ATTR_SIZE);

			ret = sc_pkcs15init_update_file(profile, card,
					file, prkeybuf, prsize);
			sc_file_free(file);
		}
		memset(prkeybuf, 0, prsize);
	}
	free(prkeybuf);
	return ret;
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
		r = sc_file_set_sec_attr(df, wn_sec_attr, SEC_ATTR_SIZE);
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
rutoken_erase(struct sc_profile *profile, sc_card_t *card)
{
	int ret, ret_end;

	if (!profile || !card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	/* ret = sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL); */
	ret = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_FORMAT_INIT, NULL);
	if (ret == SC_SUCCESS)
	{
		ret = create_typical_fs(card);
		if (ret != SC_SUCCESS)
			sc_error(card->ctx, "Failed to create typical fs: %s\n",
					sc_strerror(ret));
		ret_end = sc_card_ctl(card, SC_CARDCTL_RUTOKEN_FORMAT_END, NULL);
		if (ret_end != SC_SUCCESS)
			ret = ret_end;
	}
	if (ret != SC_SUCCESS)
		sc_error(card->ctx, "Failed to erase: %s\n", sc_strerror(ret));
	return ret;
}

static struct sc_pkcs15init_operations sc_pkcs15init_rutoken_operations = {
	rutoken_erase,                  /* erase_card */
	NULL,                           /* init_card */
	rutoken_create_dir,             /* create_dir */
	NULL,                           /* create_domain */
	rutoken_select_pin_reference,   /* select_pin_reference */
	rutoken_create_pin,             /* create_pin */
	rutoken_select_key_reference,   /* select_key_reference */
	rutoken_create_key,             /* create_key */
	rutoken_store_key,              /* store_key */
	NULL,                           /* generate_key */
	NULL,                           /* encode_private_key */
	NULL,                           /* encode_public_key */
	NULL,                           /* finalize_card */
	/* Old-style API */
	NULL,                           /* init_app */
	NULL,                           /* new_pin */
	NULL,                           /* new_key */
	NULL,                           /* new_file */
	NULL,                           /* old_generate_key */
	NULL                            /* delete_object */
};

struct sc_pkcs15init_operations* sc_pkcs15init_get_rutoken_ops(void)
{
	return &sc_pkcs15init_rutoken_operations;
}

