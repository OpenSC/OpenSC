/*
 * pkcs15-rtecp.c: Rutoken ECP specific operation for PKCS15 initialization
 *
 * Copyright (C) 2009  Aleksey Samsonov <samsonov@guardant.ru>
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

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/pkcs15.h"
#include "pkcs15-init.h"
#include "profile.h"

#define RTECP_SO_PIN_REF        1
#define RTECP_USER_PIN_REF      2

/*
 * Erase everything that's on the card
 */
static int rtecp_erase(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	int r;

	if (!profile || !p15card || !p15card->card)
		return SC_ERROR_INVALID_ARGUMENTS;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_RTECP_INIT, NULL);
	if (r == SC_SUCCESS)
		sc_free_apps(p15card->card);
	return r;
}

static int create_sysdf(sc_profile_t *profile, sc_card_t *card, const char *name)
{
	sc_file_t *file;
	sc_path_t path;
	int r;

	assert(profile && card && card->ctx && name);
	r = sc_profile_get_file(profile, name, &file);
	if (r == SC_SUCCESS)
	{
		assert(file);
		path = file->path;
		assert(path.len > 2);
		if (path.len > 2)
			path.len -= 2;
		r = sc_select_file(card, &path, NULL);
		if (r == SC_SUCCESS)
			r = sc_file_add_acl_entry(file, SC_AC_OP_CREATE,
					SC_AC_CHV, RTECP_USER_PIN_REF);
		if (r == SC_SUCCESS)
			r = sc_file_add_acl_entry(file, SC_AC_OP_DELETE,
					SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		if (r == SC_SUCCESS)
			r = sc_create_file(card, file);
		sc_file_free(file);
	}
	sc_log(card->ctx, 
		"Create %s failed: %s\n", name, sc_strerror(r));
	return r;
}

/*
 * Card-specific initialization of PKCS15 meta-information
 */
static int rtecp_init(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	sc_card_t *card;
	sc_file_t *file;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	card = p15card->card;

	r = sc_profile_get_file(profile, "MF", &file);
	LOG_TEST_RET(card->ctx, r, "Get MF info failed");
	assert(file);
	r = sc_create_file(card, file);
	sc_file_free(file);
	LOG_TEST_RET(card->ctx, r, "Create MF failed");

	r = sc_profile_get_file(profile, "DIR", &file);
	LOG_TEST_RET(card->ctx, r, "Get DIR file info failed");
	assert(file);
	r = sc_create_file(card, file);
	sc_file_free(file);
	LOG_TEST_RET(card->ctx, r, "Create DIR file failed");

	create_sysdf(profile, card, "Sys-DF");
	create_sysdf(profile, card, "SysKey-DF");
	create_sysdf(profile, card, "PuKey-DF");
	create_sysdf(profile, card, "PrKey-DF");
	create_sysdf(profile, card, "SKey-DF");
	create_sysdf(profile, card, "Cer-DF");
	create_sysdf(profile, card, "LCHV-DF");

	create_sysdf(profile, card, "Resrv1-DF");
	create_sysdf(profile, card, "Resrv2-DF");
	create_sysdf(profile, card, "Resrv3-DF");
	create_sysdf(profile, card, "Resrv4-DF");

	return sc_select_file(card, sc_get_mf_path(), NULL);
}

/*
 * Create a DF
 */
static int rtecp_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	if (!profile || !p15card || !p15card->card || !df)
		return SC_ERROR_INVALID_ARGUMENTS;
	return sc_create_file(p15card->card, df);
}

/*
 * Select a PIN reference
 */
static int rtecp_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_auth_info_t *auth_info)
{
	int pin_ref;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx || !auth_info)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
	                return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		pin_ref = RTECP_SO_PIN_REF;
	else
		pin_ref = RTECP_USER_PIN_REF;
	if (auth_info->attrs.pin.reference != pin_ref)
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_NOT_SUPPORTED);

	return SC_SUCCESS;
}

/*
 * Create a PIN object within the given DF
 */
static int rtecp_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_file_t *df, sc_pkcs15_object_t *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	sc_context_t *ctx;
	sc_pkcs15_auth_info_t *auth_info;
	sc_file_t *file = NULL;
	/*                        GCHV min-length Flags Attempts  Reserve */
	unsigned char prop[]  = { 0x01,       '?', 0x01,     '?', 0, 0 };
	/*                  AccessMode Unblock Change             Delete */
	unsigned char sec[15] = { 0x43,    '?',   '?', 0, 0, 0, 0,  0xFF };
	char pin_sname[0x10];
	int r, reset_by_sopin = 0;

	(void)puk; /* no warning */
	if (!profile || !p15card || !p15card->card || !p15card->card->ctx || !df
			|| !pin_obj || !pin_obj->data || !pin || !pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (puk_len != 0)
	{
		sc_log(ctx,  "Do not enter User unblocking PIN (PUK): %s\n",
				sc_strerror(SC_ERROR_NOT_SUPPORTED));
		return SC_ERROR_NOT_SUPPORTED;
	}

	auth_info = (sc_pkcs15_auth_info_t *)pin_obj->data;
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.reference != RTECP_SO_PIN_REF
			&& auth_info->attrs.pin.reference != RTECP_USER_PIN_REF)
	{
		sc_log(ctx,  "PIN reference %i not found in standard"
				" (Rutoken ECP) PINs\n", auth_info->attrs.pin.reference);
		return SC_ERROR_NOT_SUPPORTED;
	}

	snprintf(pin_sname, sizeof(pin_sname), "CHV%i", auth_info->attrs.pin.reference);
	if (auth_info->attrs.pin.reference == RTECP_USER_PIN_REF)   {
		r = sc_profile_get_file(profile, pin_sname, &file);
		if (!r)   {
			const struct sc_acl_entry *acl = NULL;

			r = sc_pkcs15init_fixup_file(profile, p15card, file);
			if (r < 0)
				sc_file_free(file);
			LOG_TEST_RET(p15card->card->ctx, r, "Cannot fixup the ACLs of PIN file");

			acl = sc_file_get_acl_entry(file, SC_AC_OP_PIN_RESET);
			if (acl && acl->method == SC_AC_CHV && acl->key_ref == RTECP_SO_PIN_REF)   {
				sc_log(ctx,  "Allow reset of User PIN with SoPIN\n");
				reset_by_sopin = 1;
			}
			sc_file_free(file);
		}
	}

	file = sc_file_new();
	if (!file)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->id = auth_info->attrs.pin.reference;
	file->size = pin_len;
	assert(sizeof(sec)/sizeof(sec[0]) > 2);
	sec[1] = (auth_info->attrs.pin.reference == RTECP_SO_PIN_REF) ? 0xFF : RTECP_SO_PIN_REF;
	sec[2] = (unsigned char)auth_info->attrs.pin.reference | (reset_by_sopin ? RTECP_SO_PIN_REF : 0);
	r = sc_file_set_sec_attr(file, sec, sizeof(sec));
	if (r == SC_SUCCESS)
	{
		assert(sizeof(prop)/sizeof(prop[0]) > 3);
		prop[1] = (unsigned char)auth_info->attrs.pin.min_length;
		prop[3] = 0x11 * (unsigned char)(auth_info->tries_left & 0x0F);
		r = sc_file_set_prop_attr(file, prop, sizeof(prop));
	}
	if (r == SC_SUCCESS)
		r = sc_file_set_type_attr(file, (const u8*)"\x10\x00", 2);
	if (r == SC_SUCCESS)
		r = sc_create_file(p15card->card, file);
	sc_file_free(file);

	if (r == SC_SUCCESS)
		r = sc_change_reference_data(p15card->card, SC_AC_CHV,
				auth_info->attrs.pin.reference, NULL, 0, pin, pin_len, NULL);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Select a reference for a private key object
 */
static int rtecp_select_key_reference(sc_profile_t *profile,
		sc_pkcs15_card_t *p15card, sc_pkcs15_prkey_info_t *key_info)
{
	sc_file_t *df;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx || !key_info)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (key_info->key_reference <= 0)
		key_info->key_reference = 1;
	else if (key_info->key_reference > 0xFF)
		return SC_ERROR_TOO_MANY_OBJECTS;

	r = sc_profile_get_file(profile, "PrKey-DF", &df);
	LOG_TEST_RET(p15card->card->ctx, r, "Get PrKey-DF info failed");
	assert(df);
	key_info->path = df->path;
	sc_file_free(df);
	r = sc_append_file_id(&key_info->path, key_info->key_reference);
	return r;
}

/*
 * Create an empty key object
 */
static int rtecp_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj)
{
	sc_context_t *ctx;
	/*                              RSA_PRkey/ Adds Miller-
	 *                              RSA_PUBkey Rabin tests    Attempts Reserve */
	const unsigned char prkey_prop[]  = { 0x23,          0, 0,    0xAA, 0, 0 };
	const unsigned char pbkey_prop[]  = { 0x33,          0, 0,    0xAA, 0, 0 };
	/*                  GOSTR3410_PRkey/
	 *                  GOSTR3410_PUBkey  paramset    Attempts Reserve */
	unsigned char prgkey_prop[] = { 0x03,      '?', 0,    0xAA, 0, 0 };
	unsigned char pbgkey_prop[] = { 0x13,      '?', 0,    0xAA, 0, 0 };
	/*                        AccessMode  - Update  Use  -  -  - Delete */
	unsigned char prkey_sec[15] = { 0x46, 0,   '?', '?', 0, 0, 0,   '?' };
	unsigned char pbkey_sec[15] = { 0x46, 0,   '?',   0, 0, 0, 0,   '?' };
	unsigned char auth_id, paramset;
	sc_pkcs15_prkey_info_t *key_info;
	sc_file_t *file;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx
			|| !obj || !obj->data)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA
			&& obj->type != SC_PKCS15_TYPE_PRKEY_GOSTR3410)
		return SC_ERROR_NOT_SUPPORTED;
	if (obj->auth_id.len != 1)
		return SC_ERROR_INVALID_ARGUMENTS;
	auth_id = obj->auth_id.value[0];

	key_info = (sc_pkcs15_prkey_info_t *)obj->data;
	assert(key_info);
	if ((obj->type == SC_PKCS15_TYPE_PRKEY_RSA
				&& key_info->modulus_length % 128 != 0)
			|| (obj->type == SC_PKCS15_TYPE_PRKEY_GOSTR3410
				&& key_info->modulus_length
				!= SC_PKCS15_GOSTR3410_KEYSIZE))
	{
		sc_log(ctx, 
			 "Unsupported key size %"SC_FORMAT_LEN_SIZE_T"u\n",
			 key_info->modulus_length);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (obj->type == SC_PKCS15_TYPE_PRKEY_GOSTR3410)
	{
		if (key_info->params.len < sizeof(int))
			return SC_ERROR_INVALID_ARGUMENTS;
		if (((int*)key_info->params.data)[0] < 1
				|| ((int*)key_info->params.data)[0] > 3)
			return SC_ERROR_INVALID_ARGUMENTS;
		paramset = ((unsigned int*)key_info->params.data)[0] & 0x03;
		assert(sizeof(prgkey_prop)/sizeof(prgkey_prop[0]) > 1);
		assert(sizeof(pbgkey_prop)/sizeof(pbgkey_prop[0]) > 1);
		prgkey_prop[1] = 0x10 + (paramset << 4);
		pbgkey_prop[1] = prgkey_prop[1];
	}

	r = sc_profile_get_file(profile, "PKCS15-AppDF", &file);
	LOG_TEST_RET(ctx, r, "Get PKCS15-AppDF info failed");
	r = sc_file_add_acl_entry(file, SC_AC_OP_CREATE, SC_AC_CHV, auth_id);
	if (r == SC_SUCCESS)
		r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_CREATE);
	sc_file_free(file);
	LOG_TEST_RET(ctx, r, "Authenticate failed");

	file = sc_file_new();
	if (!file)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	file->id = key_info->key_reference;
	r = sc_file_set_type_attr(file, (const u8*)"\x10\x00", 2);

	/* private key file */
	if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)
		file->size = key_info->modulus_length / 8 / 2 * 5 + 8;
	else
		file->size = key_info->modulus_length / 8;
	if (r == SC_SUCCESS)
	{
		assert(sizeof(prkey_sec)/sizeof(prkey_sec[0]) > 7);
		prkey_sec[2] = auth_id;
		prkey_sec[3] = auth_id;
		prkey_sec[7] = auth_id;
		r = sc_file_set_sec_attr(file, prkey_sec, sizeof(prkey_sec));
	}
	if (r == SC_SUCCESS)
	{
		if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)
			r = sc_file_set_prop_attr(file, prkey_prop, sizeof(prkey_prop));
		else
			r = sc_file_set_prop_attr(file, prgkey_prop,sizeof(prgkey_prop));
	}
	if (r == SC_SUCCESS)  {
		sc_log(ctx, "create private key file id:%04i", file->id);
		r = sc_create_file(p15card->card, file);
	}
	/* public key file */
	if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)
		file->size = key_info->modulus_length / 8 / 2 * 3;
	else
		file->size = key_info->modulus_length / 8 * 2;
	if (r == SC_SUCCESS)
	{
		assert(sizeof(pbkey_sec)/sizeof(pbkey_sec[0]) > 7);
		pbkey_sec[2] = auth_id;
		pbkey_sec[7] = auth_id;
		r = sc_file_set_sec_attr(file, pbkey_sec, sizeof(pbkey_sec));
	}
	if (r == SC_SUCCESS)
	{
		if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)
			r = sc_file_set_prop_attr(file, pbkey_prop, sizeof(pbkey_prop));
		else
			r = sc_file_set_prop_attr(file, pbgkey_prop,sizeof(pbgkey_prop));
	}
	if (r == SC_SUCCESS)   {
		sc_log(ctx, "create public key file id:%04i", file->id);
		r = sc_create_file(p15card->card, file);
	}
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Store a key on the card
 */
static int rtecp_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	sc_card_t *card;
	sc_pkcs15_prkey_info_t *key_info;
	sc_file_t *pukey_df;
	sc_path_t path;
	unsigned char *buf;
	size_t buf_len, key_len, len, i;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx
			|| !obj || !obj->data || !key)
		return SC_ERROR_INVALID_ARGUMENTS;

	card = p15card->card;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if ((obj->type != SC_PKCS15_TYPE_PRKEY_RSA || key->algorithm != SC_ALGORITHM_RSA)
			&& (obj->type != SC_PKCS15_TYPE_PRKEY_GOSTR3410
				|| key->algorithm != SC_ALGORITHM_GOSTR3410))
		return SC_ERROR_NOT_SUPPORTED;

	key_info = (sc_pkcs15_prkey_info_t *)obj->data;
	assert(key_info);

	if (key->algorithm == SC_ALGORITHM_RSA)
	{
		assert(key_info->modulus_length % 128 == 0);
		len = key_info->modulus_length / 8 / 2;
		key_len = len * 5 + 8;
		buf_len = key_len;
	}
	else
	{
		assert(key_info->modulus_length == SC_PKCS15_GOSTR3410_KEYSIZE);
		len = key_info->modulus_length / 8;
		key_len = len;
		buf_len = len;
	}
	if (key->algorithm == SC_ALGORITHM_RSA && (!key->u.rsa.p.data
			|| !key->u.rsa.q.data || !key->u.rsa.iqmp.data
			|| !key->u.rsa.dmp1.data || !key->u.rsa.dmq1.data
			|| !key->u.rsa.modulus.data || !key->u.rsa.exponent.data
			|| key->u.rsa.p.len != len || key->u.rsa.q.len != len
			|| key->u.rsa.iqmp.len != len || key->u.rsa.dmp1.len != len
			|| key->u.rsa.dmq1.len != len || key->u.rsa.modulus.len != 2*len
			|| key->u.rsa.exponent.len > len || key->u.rsa.exponent.len == 0))
		return SC_ERROR_INVALID_ARGUMENTS;
	if (key->algorithm == SC_ALGORITHM_GOSTR3410 && (!key->u.gostr3410.d.data
			|| key->u.gostr3410.d.len != len))
		return SC_ERROR_INVALID_ARGUMENTS;
	buf = calloc(1, buf_len);
	if (!buf)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	assert(key_len <= buf_len);
	if (key->algorithm == SC_ALGORITHM_RSA)
	{
		/* p */
		for (i = 0; i < len; ++i)
			buf[i] = key->u.rsa.p.data[len - 1 - i];
		/* q */
		for (i = 0; i < len; ++i)
			buf[len + 4 + i] = key->u.rsa.q.data[len - 1 - i];
		/* iqmp */
		for (i = 0; i < len; ++i)
			buf[len + 4 + len + 4 + i] = key->u.rsa.iqmp.data[len - 1 - i];
		/* dmp1 */
		for (i = 0; i < len; ++i)
			buf[len + 4 + len + 4 + len + i] =
				key->u.rsa.dmp1.data[len - 1 - i];
		/* dmq1 */
		for (i = 0; i < len; ++i)
			buf[len * 4 + 8 + i] = key->u.rsa.dmq1.data[len - 1 - i];
	}
	else
	{
		/* d */
		for (i = 0; i < len; ++i)
			buf[i] = key->u.gostr3410.d.data[len - 1 - i];
	}
	path = key_info->path;
	r = sc_select_file(card, &path, NULL);
	if (r == SC_SUCCESS)
		r = sc_change_reference_data(card, 0, 0, NULL, 0, buf, key_len, NULL);
	assert(buf);
	sc_mem_clear(buf, key_len);
	/* store public key */
	if (key->algorithm == SC_ALGORITHM_RSA)
		key_len = len * 3;
	else
		goto end;
	assert(key_len <= buf_len);
	if (key->algorithm == SC_ALGORITHM_RSA)
	{
		/* modulus */
		for (i = 0; i < 2*len; ++i)
			buf[i] = key->u.rsa.modulus.data[2*len - 1 - i];
		/* exponent */
		for (i = 0; i < key->u.rsa.exponent.len && i < len; ++i)
			buf[2 * len + i] = key->u.rsa.exponent.data[
				key->u.rsa.exponent.len - 1 - i];
	}
	if (r == SC_SUCCESS)
	{
		r = sc_profile_get_file(profile, "PuKey-DF", &pukey_df);
		if (r == SC_SUCCESS)
		{
			assert(pukey_df);
			path = pukey_df->path;
			r = sc_append_file_id(&path, key_info->key_reference);
			sc_file_free(pukey_df);
		}
		else if (card->ctx->debug >= 2)
			sc_log(card->ctx,  "%s\n", "Get PuKey-DF info failed");
	}
	if (r == SC_SUCCESS)
	{
		r = sc_select_file(card, &path, NULL);
		if (r == SC_SUCCESS)
			r = sc_change_reference_data(card, 0, 0, NULL, 0,
					buf, key_len, NULL);
		if (r && card->ctx->debug >= 2)
			sc_log(card->ctx,  "%s\n", "Store public key failed");
	}
end:
	assert(buf);
	free(buf);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Generate key
 */
static int rtecp_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	sc_context_t *ctx;
	sc_pkcs15_prkey_info_t *key_info;
	sc_rtecp_genkey_data_t data;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx
			|| !obj || !obj->data || !pubkey)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	switch (obj->type)
	{
	case SC_PKCS15_TYPE_PRKEY_RSA:
		data.type = SC_ALGORITHM_RSA;
		break;
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		data.type = SC_ALGORITHM_GOSTR3410;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	key_info = (sc_pkcs15_prkey_info_t *)obj->data;
	assert(key_info);
	data.key_id = key_info->key_reference;
	assert(data.key_id != 0);
	switch (data.type)
	{
	case SC_ALGORITHM_RSA:
		assert(key_info->modulus_length % 128 == 0);
		data.u.rsa.modulus_len = key_info->modulus_length / 8;
		data.u.rsa.modulus = calloc(1, data.u.rsa.modulus_len);
		data.u.rsa.exponent_len = key_info->modulus_length / 8 / 2;
		data.u.rsa.exponent = calloc(1, data.u.rsa.exponent_len);
		if (!data.u.rsa.modulus || !data.u.rsa.exponent)
		{
			free(data.u.rsa.modulus);
			free(data.u.rsa.exponent);
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		break;
	case SC_ALGORITHM_GOSTR3410:
		assert(key_info->modulus_length == SC_PKCS15_GOSTR3410_KEYSIZE);
		data.u.gostr3410.xy_len = key_info->modulus_length / 8 * 2;
		data.u.gostr3410.xy = calloc(1, data.u.gostr3410.xy_len);
		if (!data.u.gostr3410.xy)
		{
			free(data.u.gostr3410.xy);
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		break;
	default:
		assert(0);
	}
	r = sc_card_ctl(p15card->card, SC_CARDCTL_RTECP_GENERATE_KEY, &data);
	if (r == SC_SUCCESS)
	{
		assert(pubkey);
		pubkey->algorithm = data.type;
		switch (data.type)
		{
		case SC_ALGORITHM_RSA:
			pubkey->u.rsa.modulus.data = data.u.rsa.modulus;
			pubkey->u.rsa.modulus.len = data.u.rsa.modulus_len;
			pubkey->u.rsa.exponent.data = data.u.rsa.exponent;
			pubkey->u.rsa.exponent.len = data.u.rsa.exponent_len;
			break;
		case SC_ALGORITHM_GOSTR3410:
			pubkey->u.gostr3410.xy.data = data.u.gostr3410.xy;
			pubkey->u.gostr3410.xy.len = data.u.gostr3410.xy_len;
			break;
		}
	}
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Finalize card
 * Ends the initialization phase of the smart card/token
 */
static int rtecp_finalize(sc_card_t *card)
{
	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;
	return sc_card_ctl(card, SC_CARDCTL_RTECP_INIT_END, NULL);
}


/*
 * Delete object
 * 
 * Applied to private key: used to delete public part internal file
 */
static int rtecp_delete_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *obj, const struct sc_path *path)
{
	sc_context_t *ctx;
	sc_file_t *df;
	sc_path_t pubkey_path;
	int key_ref;
	int r;

	if (!profile || !p15card || !p15card->card || !p15card->card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "delete object: type %X, path %s", obj->type, sc_print_path(path));

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PRKEY)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	key_ref = ((struct sc_pkcs15_prkey_info *)obj->data)->key_reference;
	sc_log(ctx, "key reference %04i", key_ref);

	r = sc_profile_get_file(profile, "PuKey-DF", &df);
	LOG_TEST_RET(ctx, r, "Get PuKey-DF info failed");
	pubkey_path = df->path;
	sc_file_free(df);

	r = sc_append_file_id(&pubkey_path, key_ref);
	LOG_TEST_RET(ctx, r, "Append ID to file failed");

	sc_log(ctx, "delete pubkey file %s", sc_print_path(&pubkey_path));
	r = sc_pkcs15init_delete_by_path(profile, p15card, &pubkey_path);
	if (r && r != SC_ERROR_FILE_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, r);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static struct sc_pkcs15init_operations sc_pkcs15init_rtecp_operations = {
	rtecp_erase,                    /* erase_card */
	rtecp_init,                     /* init_card */
	rtecp_create_dir,               /* create_dir */
	NULL,                           /* create_domain */
	rtecp_select_pin_reference,     /* select_pin_reference */
	rtecp_create_pin,               /* create_pin */
	rtecp_select_key_reference,     /* select_key_reference */
	rtecp_create_key,               /* create_key */
	rtecp_store_key,                /* store_key */
	rtecp_generate_key,             /* generate_key */
	NULL,                           /* encode_private_key */
	NULL,                           /* encode_public_key */
	rtecp_finalize,                 /* finalize_card */
	rtecp_delete_object,            /* delete_object */
	NULL, NULL, NULL, NULL, NULL,   /* pkcs15init emulation */
	NULL                            /* sanity_check */
};

struct sc_pkcs15init_operations * sc_pkcs15init_get_rtecp_ops(void)
{
	return &sc_pkcs15init_rtecp_operations;
}

