/*
 * pkcs15-pubkey.c: PKCS #15 public key functions
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# include <openssl/param_build.h>
#endif
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif
#endif

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"


#define C_ASN1_PKINFO_ATTR_SIZE 3
static const struct sc_asn1_entry c_asn1_pkinfo[C_ASN1_PKINFO_ATTR_SIZE] = {
		{ "algorithm", SC_ASN1_ALGORITHM_ID,  SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "subjectPublicKey", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL},
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_KEY_ATTR_SIZE 6
static const struct sc_asn1_entry c_asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE] = {
		{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
		{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
		{ "native",	 SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_PUBKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_com_pubkey_attr[C_ASN1_COM_PUBKEY_ATTR_SIZE] = {
		{ "subjectName", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS,
				SC_ASN1_EMPTY_ALLOWED | SC_ASN1_ALLOC | SC_ASN1_OPTIONAL, NULL, NULL },
				{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSAKEY_VALUE_CHOICE_SIZE 3
static const struct sc_asn1_entry c_asn1_rsakey_value_choice[C_ASN1_RSAKEY_VALUE_CHOICE_SIZE] = {
		{ "path",       SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSAKEY_ATTR_SIZE 4
static const struct sc_asn1_entry c_asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE] = {
		{ "value",	 SC_ASN1_CHOICE, 0, 0, NULL, NULL },
		{ "modulusLength", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
		{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_ECKEY_VALUE_CHOICE_SIZE 3
static const struct sc_asn1_entry c_asn1_eckey_value_choice[C_ASN1_ECKEY_VALUE_CHOICE_SIZE] = {
		{ "path",       SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
		{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_ECKEY_ATTR_SIZE 3
static const struct sc_asn1_entry c_asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE] = {
		{ "value",	 SC_ASN1_CHOICE, 0, 0, NULL, NULL },
		{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSA_TYPE_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_rsa_type_attr[C_ASN1_RSA_TYPE_ATTR_SIZE] = {
		{ "publicRSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_EC_TYPE_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_ec_type_attr[C_ASN1_EC_TYPE_ATTR_SIZE] = {
		{ "publicECKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_GOST3410KEY_ATTR_SIZE 5
static const struct sc_asn1_entry c_asn1_gostr3410key_attr[C_ASN1_GOST3410KEY_ATTR_SIZE] = {
		{ "value", SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "params_r3410", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
		{ "params_r3411", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "params_28147", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_GOST3410_TYPE_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_gostr3410_type_attr[C_ASN1_GOST3410_TYPE_ATTR_SIZE] = {
		{ "publicGOSTR3410KeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PUBKEY_CHOICE_SIZE 4
static const struct sc_asn1_entry c_asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE] = {
		{ "publicRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "publicGOSTR3410Key", SC_ASN1_PKCS15_OBJECT, 4 | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
		{ "publicECKey", SC_ASN1_PKCS15_OBJECT, 0 | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
		/*TODO: -DEE not clear EC is needed here  as look like it is for pukdf */
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PUBKEY_SIZE 2
static const struct sc_asn1_entry c_asn1_pubkey[C_ASN1_PUBKEY_SIZE] = {
		{ "publicKey",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_pubkey_from_spki_sequence(sc_context_t *ctx, const u8 *buf, size_t buflen, sc_pkcs15_pubkey_t ** outpubkey);

int
sc_pkcs15_decode_pubkey_direct_value(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *) obj->data;

	LOG_FUNC_CALLED(ctx);
	if (obj->content.value == NULL || obj->content.len == 0)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	if (*obj->content.value == (SC_ASN1_TAG_CONSTRUCTED | SC_ASN1_TAG_SEQUENCE))   {
		/* RAW direct value */
		sc_log(ctx, "Decoding 'RAW' direct value");
		info->direct.raw.value = malloc(obj->content.len);
		if (!info->direct.raw.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		memcpy(info->direct.raw.value, obj->content.value, obj->content.len);
		info->direct.raw.len = obj->content.len;

		/* TODO: encode 'spki' direct value */
	}

	if (*obj->content.value == (SC_ASN1_TAG_CONTEXT | SC_ASN1_TAG_CONSTRUCTED | 0x01))   {
		struct sc_pkcs15_pubkey *pubkey = NULL;
		int rv;

		/* SPKI direct value */
		sc_log(ctx, "Decoding 'SPKI' direct value");
		info->direct.spki.value = malloc(obj->content.len);
		if (!info->direct.spki.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		memcpy(info->direct.spki.value, obj->content.value, obj->content.len);
		info->direct.spki.len = obj->content.len;

		rv = sc_pkcs15_pubkey_from_spki_sequence(ctx, info->direct.spki.value, info->direct.spki.len, &pubkey);
		LOG_TEST_RET(ctx, rv, "Failed to decode 'SPKI' direct value");

		rv = sc_pkcs15_encode_pubkey(ctx, pubkey, &info->direct.raw.value, &info->direct.raw.len);
		sc_pkcs15_free_pubkey(pubkey);
		LOG_TEST_RET(ctx, rv, "Failed to encode 'RAW' direct value");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int sc_pkcs15_decode_pukdf_entry(struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *obj,
		const u8 ** buf, size_t *buflen)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info;
	int r, gostr3410_params[3];
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	size_t usage_len, af_len;
	struct sc_pkcs15_der *der = &obj->content;
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_pubkey_attr[C_ASN1_COM_PUBKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_value_choice[C_ASN1_RSAKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsa_type_attr[C_ASN1_RSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_eckey_value_choice[C_ASN1_ECKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_ec_type_attr[C_ASN1_EC_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOST3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410_type_attr[C_ASN1_GOST3410_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_pubkey[C_ASN1_PUBKEY_SIZE];
	struct sc_asn1_pkcs15_object rsakey_obj = { obj, asn1_com_key_attr,
			asn1_com_pubkey_attr, asn1_rsa_type_attr };
	struct sc_asn1_pkcs15_object eckey_obj = { obj, asn1_com_key_attr,
			asn1_com_pubkey_attr, asn1_ec_type_attr };
	struct sc_asn1_pkcs15_object gostr3410key_obj =  { obj, asn1_com_key_attr,
			asn1_com_pubkey_attr, asn1_gostr3410_type_attr };

	info = calloc(1, sizeof *info);
	if (info == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	usage_len = sizeof(info->usage);
	af_len = sizeof(info->access_flags);

	sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
	sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
	sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_value_choice, asn1_rsakey_value_choice);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_ec_type_attr, asn1_ec_type_attr);
	sc_copy_asn1_entry(c_asn1_eckey_value_choice, asn1_eckey_value_choice);
	sc_copy_asn1_entry(c_asn1_eckey_attr, asn1_eckey_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410_type_attr, asn1_gostr3410_type_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_com_pubkey_attr + 0, &info->subject.value, &info->subject.len, 0);

	sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 1, &gostr3410key_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 2, &eckey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_value_choice + 0, &info->path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_value_choice + 1, &der->value, &der->len, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, asn1_rsakey_value_choice, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info->modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_ec_type_attr + 0, asn1_eckey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_eckey_value_choice + 0, &info->path, NULL, 0);
	sc_format_asn1_entry(asn1_eckey_value_choice + 1, &der->value, &der->len, 0);

	sc_format_asn1_entry(asn1_eckey_attr + 0, asn1_eckey_value_choice, NULL, 0);

	sc_format_asn1_entry(asn1_gostr3410_type_attr + 0, asn1_gostr3410key_attr, NULL, 0);

	sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &info->path, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 1, &gostr3410_params[0], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 2, &gostr3410_params[1], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 3, &gostr3410_params[2], NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info->id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info->usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info->native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info->access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info->key_reference, NULL, 0);

	sc_format_asn1_entry(asn1_pubkey + 0, asn1_pubkey_choice, NULL, 0);

	/* Fill in defaults */
	info->key_reference = -1;
	info->native = 1;
	memset(gostr3410_params, 0, sizeof(gostr3410_params));

	r = sc_asn1_decode(ctx, asn1_pubkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		goto err;
	LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 decoding failed");
	if (asn1_pubkey_choice[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_RSA;
	} else if (asn1_pubkey_choice[1].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
		assert(info->modulus_length == 0);
		info->modulus_length = SC_PKCS15_GOSTR3410_KEYSIZE;
		assert(info->params.len == 0);
		info->params.len = sizeof(struct sc_pkcs15_keyinfo_gostparams);
		info->params.data = malloc(info->params.len);
		if (info->params.data == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		assert(sizeof(*keyinfo_gostparams) == info->params.len);
		keyinfo_gostparams = info->params.data;
		keyinfo_gostparams->gostr3410 = (unsigned int)gostr3410_params[0];
		keyinfo_gostparams->gostr3411 = (unsigned int)gostr3410_params[1];
		keyinfo_gostparams->gost28147 = (unsigned int)gostr3410_params[2];
	}
	else if (asn1_pubkey_choice[2].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_EC;
	}
	else {
		goto err;
	}

	if (!p15card->app || !p15card->app->ddo.aid.len) {
		if (!p15card->file_app) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info->path);
		if (r < 0) {
			goto err;
		}
	}
	else   {
		info->path.aid = p15card->app->ddo.aid;
	}
	sc_log(ctx, "PubKey path '%s'", sc_print_path(&info->path));

	/* OpenSC 0.11.4 and older encoded "keyReference" as a negative
	   value. Fixed in 0.11.5 we need to add a hack, so old cards
	   continue to work. */
	if (info->key_reference < -1)
		info->key_reference += 256;

	obj->data = info;
	info = NULL;

	r = sc_pkcs15_decode_pubkey_direct_value(p15card, obj);
	if (r < 0) {
		info = obj->data;
		obj->data = NULL;
	}
	LOG_TEST_GOTO_ERR(ctx, r, "Decode public key direct value failed");

err:
	if (r < 0) {
		sc_pkcs15_free_pubkey_info(info);
		if (der->len) {
			free(der->value);
			/* der points to obj->content */
			obj->content.value = NULL;
			obj->content.len = 0;
		}
	}

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_encode_pukdf_entry(struct sc_context *ctx, const struct sc_pkcs15_object *obj,
		unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_pubkey_attr[C_ASN1_COM_PUBKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_value_choice[C_ASN1_RSAKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsa_type_attr[C_ASN1_RSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_eckey_value_choice[C_ASN1_ECKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_ec_type_attr[C_ASN1_EC_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOST3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410_type_attr[C_ASN1_GOST3410_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_pubkey[C_ASN1_PUBKEY_SIZE];

	struct sc_pkcs15_pubkey_info *pubkey = (struct sc_pkcs15_pubkey_info *) obj->data;
	struct sc_asn1_pkcs15_object rsakey_obj = {
		(struct sc_pkcs15_object *) obj, asn1_com_key_attr, asn1_com_pubkey_attr, asn1_rsa_type_attr
	};
	struct sc_asn1_pkcs15_object eckey_obj = { (struct sc_pkcs15_object *) obj,
			asn1_com_key_attr,
			asn1_com_pubkey_attr, asn1_ec_type_attr };
	struct sc_asn1_pkcs15_object gostr3410key_obj =  { (struct sc_pkcs15_object *) obj,
			asn1_com_key_attr,
			asn1_com_pubkey_attr, asn1_gostr3410_type_attr };
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	int r;
	size_t af_len, usage_len;
	unsigned char *spki_value = NULL;

	sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
	sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
	sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_value_choice, asn1_rsakey_value_choice);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_ec_type_attr, asn1_ec_type_attr);
	sc_copy_asn1_entry(c_asn1_eckey_value_choice, asn1_eckey_value_choice);
	sc_copy_asn1_entry(c_asn1_eckey_attr, asn1_eckey_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410_type_attr, asn1_gostr3410_type_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 1);
		if (pubkey->path.len)   {
			sc_format_asn1_entry(asn1_rsakey_value_choice + 0, &pubkey->path, NULL, 1);
		}
		else  if (pubkey->direct.raw.value && pubkey->direct.raw.len)   {
			/* In RSAPublicKeyChoice 'raw' value keep it's SEQUENCE tag */
			sc_log(ctx,  "Encode direct 'RAW' value");
			sc_format_asn1_entry(asn1_rsakey_value_choice + 1, pubkey->direct.raw.value, (void *)&pubkey->direct.raw.len, 1);
		}
		else  if (pubkey->direct.spki.value && pubkey->direct.spki.len)   {
			/* In RSAPublicKeyChoice 'spki' value changes initial SEQUENCE tag for
			 * CONTEXT [1] constructed SEQUENCE */
			sc_log(ctx,  "Encode direct 'SPKI' value");
			spki_value = malloc(pubkey->direct.spki.len);
			if (!spki_value)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			memcpy(spki_value, pubkey->direct.spki.value, pubkey->direct.spki.len);
			*spki_value = (SC_ASN1_TAG_CONTEXT | SC_ASN1_TAG_CONSTRUCTED | 0x01);

			sc_format_asn1_entry(asn1_rsakey_value_choice + 1, spki_value, (void *)&pubkey->direct.spki.len, 1);
		}
		else if (obj->content.value && obj->content.len) {
			sc_log(ctx,  "Encode 'RAW' object content");
			sc_format_asn1_entry(asn1_rsakey_value_choice + 1, obj->content.value, (void *)&obj->content.len, 1);
		}
		else   {
			sc_log(ctx,  "Use empty path");
			sc_format_asn1_entry(asn1_rsakey_value_choice + 0, &pubkey->path, NULL, 1);
		}

		sc_format_asn1_entry(asn1_rsakey_attr + 0, asn1_rsakey_value_choice, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 1, &pubkey->modulus_length, NULL, 1);
		break;
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		sc_format_asn1_entry(asn1_pubkey_choice + 1, &gostr3410key_obj, NULL, 1);

		sc_format_asn1_entry(asn1_gostr3410_type_attr + 0, asn1_gostr3410key_attr, NULL, 1);

		sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &pubkey->path, NULL, 1);
		if (pubkey->params.len == sizeof(*keyinfo_gostparams))   {
			keyinfo_gostparams = pubkey->params.data;
			sc_format_asn1_entry(asn1_gostr3410key_attr + 1,
					&keyinfo_gostparams->gostr3410, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 2,
					&keyinfo_gostparams->gostr3411, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 3,
					&keyinfo_gostparams->gost28147, NULL, 1);
		}
		break;
	case SC_PKCS15_TYPE_PUBKEY_EC:
		sc_format_asn1_entry(asn1_pubkey_choice + 2, &eckey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_ec_type_attr + 0, asn1_eckey_attr, NULL, 1);

		if (pubkey->path.len)   {
			sc_format_asn1_entry(asn1_eckey_value_choice + 0, &pubkey->path, NULL, 1);
		}
		else  if (pubkey->direct.spki.value)   {
			sc_format_asn1_entry(asn1_eckey_value_choice + 1, pubkey->direct.spki.value, (void *)&pubkey->direct.spki.len, 1);
		}
		else  if (pubkey->direct.raw.value)   {
			sc_format_asn1_entry(asn1_eckey_value_choice + 1, pubkey->direct.raw.value, (void *)&pubkey->direct.raw.len, 1);
			LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "Needs KeyInfo with reference to algorithm in TokenInfo");
		}
		else  if (obj->content.value)   {
			sc_format_asn1_entry(asn1_eckey_value_choice + 1, obj->content.value, (void *)&obj->content.len, 1);
			LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "Needs KeyInfo with reference to algorithm in TokenInfo");
		}

		sc_format_asn1_entry(asn1_eckey_attr + 0, asn1_eckey_value_choice, NULL, 1);

		break;
	default:
		sc_log(ctx,  "Unsupported public key type: %X", obj->type);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		break;
	}

	sc_format_asn1_entry(asn1_com_key_attr + 0, &pubkey->id, NULL, 1);
	usage_len = sizeof(pubkey->usage);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &pubkey->usage, &usage_len, 1);
	if (pubkey->native == 0)
		sc_format_asn1_entry(asn1_com_key_attr + 2, &pubkey->native, NULL, 1);
	if (pubkey->access_flags) {
		af_len = sizeof(pubkey->access_flags);
		sc_format_asn1_entry(asn1_com_key_attr + 3, &pubkey->access_flags, &af_len, 1);
	}
	if (pubkey->key_reference >= 0)
		sc_format_asn1_entry(asn1_com_key_attr + 4, &pubkey->key_reference, NULL, 1);
	sc_format_asn1_entry(asn1_pubkey + 0, asn1_pubkey_choice, NULL, 1);

	if (pubkey->subject.value && pubkey->subject.len)
		sc_format_asn1_entry(asn1_com_pubkey_attr + 0, pubkey->subject.value, &pubkey->subject.len, 1);
	else
		memset(asn1_com_pubkey_attr, 0, sizeof(asn1_com_pubkey_attr));

	r = sc_asn1_encode(ctx, asn1_pubkey, buf, buflen);

	sc_log(ctx, "Key path %s", sc_print_path(&pubkey->path));

	free(spki_value);
	return r;
}

// clang-format off
#define C_ASN1_PUBLIC_KEY_SIZE 2
static struct sc_asn1_entry c_asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE] = {
		{ "publicKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSA_PUB_COEFFICIENTS_SIZE 3
static struct sc_asn1_entry c_asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE] = {
		{ "modulus",  SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ "exponent", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE 2
static struct sc_asn1_entry c_asn1_gostr3410_pub_coefficients[C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE] = {
		{ "xy", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

/* PKCS15 raw uses OCTET STRING, SPKI uses BIT STRING */
/* accept either */
#define C_ASN1_EC_POINTQ_SIZE 3
static struct sc_asn1_entry c_asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE] = {
		{ "ecpointQ-OS", SC_ASN1_OCTET_STRING,  SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ "ecpointQ-BS", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING,   SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

/*  See RFC8410 */
#define C_ASN1_EDDSA_PUBKEY_SIZE 3
static struct sc_asn1_entry c_asn1_eddsa_pubkey[C_ASN1_EDDSA_PUBKEY_SIZE] = {
		{ "ecpointQ-OS", SC_ASN1_OCTET_STRING,  SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ "ecpointQ-BS", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING,	  SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};
// clang-format on

int
sc_pkcs15_decode_pubkey_rsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_rsa *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_pub_coefficients, NULL, 0);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, &key->modulus.data, &key->modulus.len, 0);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, &key->exponent.data, &key->exponent.len, 0);

	r = sc_asn1_decode(ctx, asn1_public_key, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of public key failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_encode_pubkey_rsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_rsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_pub_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, key->modulus.data, &key->modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, key->exponent.data, &key->exponent.len, 1);

	r = sc_asn1_encode(ctx, asn1_public_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_decode_pubkey_gostr3410(sc_context_t *ctx, struct sc_pkcs15_pubkey_gostr3410 *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_gostr3410_pub_coeff[C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE];
	int r;
	struct sc_object_id param_key = {{ 1, 2, 643, 2, 2, 35, 1, -1}};
	struct sc_object_id param_hash = {{ 1, 2, 643, 2, 2, 30, 1, -1}};

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_gostr3410_pub_coefficients, asn1_gostr3410_pub_coeff);
	sc_format_asn1_entry(asn1_gostr3410_pub_coeff + 0, &key->xy.data, &key->xy.len, 0);

	r = sc_asn1_decode(ctx, asn1_gostr3410_pub_coeff, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of public key failed");

	key->params.key = param_key;
	key->params.hash = param_hash;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_pkcs15_encode_pubkey_gostr3410(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_gostr3410 *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_gostr3410_pub_coeff[C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE];
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_gostr3410_pub_coefficients, asn1_gostr3410_pub_coeff);
	sc_format_asn1_entry(asn1_gostr3410_pub_coeff + 0, key->xy.data, &key->xy.len, 1);

	r = sc_asn1_encode(ctx, asn1_gostr3410_pub_coeff, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * We are storing the ec_pointQ as u8 string not as DER
 * Will accept either BIT STRING or OCTET STRING
 */
int
sc_pkcs15_decode_pubkey_ec(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_ec *key,
		const u8 *buf, size_t buflen)
{
	int r;
	u8 * ecpoint_data = NULL;
	size_t ecpoint_len = 0;
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
	sc_format_asn1_entry(asn1_ec_pointQ + 0, &ecpoint_data, &ecpoint_len, 0);
	sc_format_asn1_entry(asn1_ec_pointQ + 1, &ecpoint_data, &ecpoint_len, 0);
	r = sc_asn1_decode_choice(ctx, asn1_ec_pointQ, buf, buflen, NULL, NULL);
	if (r < 0 || ecpoint_len == 0 || ecpoint_data == NULL) {
		free(ecpoint_data);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ecpoint_len:%" SC_FORMAT_LEN_SIZE_T "u", ecpoint_len);
	/* if from bit string */
	if (asn1_ec_pointQ[1].flags & SC_ASN1_PRESENT)
		ecpoint_len = BYTES4BITS(ecpoint_len);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ecpoint_len:%" SC_FORMAT_LEN_SIZE_T "u", ecpoint_len);

	if (*ecpoint_data != 0x04) {
		free(ecpoint_data);
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Supported only uncompressed EC pointQ value");
	}

	key->ecpointQ.len = ecpoint_len;
	key->ecpointQ.value = ecpoint_data;

	key->params.field_length = (ecpoint_len - 1)/2 * 8;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_encode_pubkey_ec(sc_context_t *ctx, struct sc_pkcs15_pubkey_ec *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];
	size_t key_len;
	/*
	 * PKCS15 uses RAW vs SPKI for pub key, and in raw uses OCTET STRING
	 * PKCS11 does not define CKA_VALUE for a pub key
	 * But some PKCS11 modules define a CKA_VALUE for a public key
	 * and PKCS11 says ECPOINT is encoded as "DER-encoding of ANSI X9.62 ECPoint value Q"
	 * But ANSI X9.62 (early draft at least) says encode as OCTET STRING
	 * IETF encodes it in SubjectPublicKeyInfo (SPKI) in BIT STRING
	 * For now return as OCTET STRING.
	 */

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);

	key_len = key->ecpointQ.len;
	sc_format_asn1_entry(asn1_ec_pointQ + 0, key->ecpointQ.value, &key_len, 1);

	LOG_FUNC_RETURN(ctx,
			sc_asn1_encode(ctx, asn1_ec_pointQ, buf, buflen));
}

/*
 * all "ec" keys use same pubkey format, keep this external entrypoint
 * keys are just byte strings.
 * will accept in either BIT STRING or OCTET STRING
 */
int
sc_pkcs15_decode_pubkey_eddsa(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_ec *key,
		const u8 *buf, size_t buflen)
{
	int r;
	u8 *ecpoint_data = NULL;
	size_t ecpoint_len = 0;
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
	sc_format_asn1_entry(asn1_ec_pointQ + 0, &ecpoint_data, &ecpoint_len, 1);
	sc_format_asn1_entry(asn1_ec_pointQ + 1, &ecpoint_data, &ecpoint_len, 1);
	r = sc_asn1_decode_choice(ctx, asn1_ec_pointQ, buf, buflen, NULL, NULL);
	if (r < 0 || ecpoint_len == 0 || ecpoint_data == NULL) {
		free(ecpoint_data);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
	}

	if (asn1_ec_pointQ[1].flags & SC_ASN1_PRESENT)
		ecpoint_len = BYTES4BITS(ecpoint_len);

	key->ecpointQ.len = ecpoint_len;
	key->ecpointQ.value = ecpoint_data;
	key->params.field_length = ecpoint_len * 8;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_pkcs15_encode_pubkey_eddsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_ec *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_eddsa_pubkey[C_ASN1_EDDSA_PUBKEY_SIZE];
	size_t key_len;

	LOG_FUNC_CALLED(ctx);
	key_len = key->ecpointQ.len; /* in bytes */
	sc_copy_asn1_entry(c_asn1_eddsa_pubkey, asn1_eddsa_pubkey);
	sc_format_asn1_entry(asn1_eddsa_pubkey + 0, key->ecpointQ.value, &key_len, 1);

	LOG_FUNC_RETURN(ctx,
			sc_asn1_encode(ctx, asn1_eddsa_pubkey, buf, buflen));
}

int
sc_pkcs15_encode_pubkey(sc_context_t *ctx, struct sc_pkcs15_pubkey *key,
		u8 **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_encode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_GOSTR3410)
		return sc_pkcs15_encode_pubkey_gostr3410(ctx, &key->u.gostr3410, buf, len);
	if (key->algorithm == SC_ALGORITHM_EC)
		return sc_pkcs15_encode_pubkey_ec(ctx, &key->u.ec, buf, len);
	if (key->algorithm == SC_ALGORITHM_EDDSA || key->algorithm == SC_ALGORITHM_XEDDSA)
		return sc_pkcs15_encode_pubkey_eddsa(ctx, &key->u.ec, buf, len);

	sc_log(ctx, "Encoding of public key type %lu not supported", key->algorithm);
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static const struct sc_asn1_entry       c_asn1_spki_key_items[] = {
		{ "algorithm",  SC_ASN1_ALGORITHM_ID, SC_ASN1_CONS| SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL},
		{ "key",	SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry       c_asn1_spki_key[] = {
		{ "publicKey",  SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL},
		{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * Encode a pubkey as a SPKI, useful for pkcs15-tool, and for PKCS#15 files.
 */
int
sc_pkcs15_encode_pubkey_as_spki(sc_context_t *ctx, struct sc_pkcs15_pubkey *pubkey,
		u8 **buf, size_t *len)
{
	int r = 0;
	struct sc_asn1_entry  asn1_spki_key[2], asn1_spki_key_items[3];
	struct sc_pkcs15_u8 pkey;
	size_t key_len;

	LOG_FUNC_CALLED(ctx);
	pkey.value =  NULL;
	pkey.len = 0;

	sc_log(ctx, "Encoding public key with algorithm %lu", pubkey->algorithm);
	if (!pubkey->alg_id)   {
		pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
		if (!pubkey->alg_id)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		sc_init_oid(&pubkey->alg_id->oid);
		pubkey->alg_id->algorithm = pubkey->algorithm;
	}

	switch (pubkey->algorithm) {
	case SC_ALGORITHM_EC:
	case SC_ALGORITHM_EDDSA:
	case SC_ALGORITHM_XEDDSA:
		/*
		 * most keys, but not EC have only one encoding.
		 * For a SPKI, the ecpoint is placed directly in the
		 * BIT STRING
		 */
		key_len = pubkey->u.ec.ecpointQ.len * 8;
		pkey.value = pubkey->u.ec.ecpointQ.value;
		pkey.len = 0; /* flag as do not delete */

		if (pubkey->u.ec.params.named_curve || pubkey->u.ec.params.der.value)   {
			struct sc_ec_parameters *ec_params = NULL;

			r = sc_pkcs15_fix_ec_parameters(ctx, &pubkey->u.ec.params);
			LOG_TEST_RET(ctx, r, "failed to fix EC parameters");

			/* EDDSA and XEDDSA only have algo and no param in SPKI */
			if (pubkey->algorithm == SC_ALGORITHM_EC) {
				ec_params = calloc(1, sizeof(struct sc_ec_parameters));
				if (!ec_params)
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				ec_params->type = 1;
				ec_params->der.value = calloc(1, pubkey->u.ec.params.der.len);
				if (!ec_params->der.value) {
					free(ec_params);
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				}
				memcpy(ec_params->der.value, pubkey->u.ec.params.der.value, pubkey->u.ec.params.der.len);
				ec_params->der.len = pubkey->u.ec.params.der.len;
			}
			/* This could have been already allocated: avoid memory leak */
			sc_asn1_clear_algorithm_id(pubkey->alg_id);
			pubkey->alg_id->params = ec_params; /* NULL for EDDSA and XEDDSA */
		}
		break;
	case SC_ALGORITHM_GOSTR3410:
		/* TODO is this needed?  does it cause mem leak? */
		pubkey->alg_id->params = &pubkey->u.gostr3410.params;
		r = sc_pkcs15_encode_pubkey(ctx, pubkey, &pkey.value, &pkey.len);
		key_len = pkey.len * 8;
		break;
	default:
		r = sc_pkcs15_encode_pubkey(ctx, pubkey, &pkey.value, &pkey.len);
		key_len = pkey.len * 8;
		break;
	}

	if (r == 0) {
		sc_copy_asn1_entry(c_asn1_spki_key, asn1_spki_key);
		sc_copy_asn1_entry(c_asn1_spki_key_items, asn1_spki_key_items);
		sc_format_asn1_entry(asn1_spki_key + 0, asn1_spki_key_items, NULL, 1);
		sc_format_asn1_entry(asn1_spki_key_items + 0, pubkey->alg_id, NULL, 1);
		sc_format_asn1_entry(asn1_spki_key_items + 1, pkey.value, &key_len, 1);

		r =  sc_asn1_encode(ctx, asn1_spki_key, buf, len);
	}

	/*  pkey.len == 0 is flag to not delete */
	if (pkey.len && pkey.value)
		free(pkey.value);

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_decode_pubkey(sc_context_t *ctx, struct sc_pkcs15_pubkey *key,
		const u8 *buf, size_t len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_decode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_GOSTR3410)
		return sc_pkcs15_decode_pubkey_gostr3410(ctx, &key->u.gostr3410, buf, len);
	if (key->algorithm == SC_ALGORITHM_EC)
		return sc_pkcs15_decode_pubkey_ec(ctx, &key->u.ec, buf, len);
	if (key->algorithm == SC_ALGORITHM_EDDSA || key->algorithm == SC_ALGORITHM_XEDDSA)
		return sc_pkcs15_decode_pubkey_eddsa(ctx, &key->u.ec, buf, len);

	sc_log(ctx, "Decoding of public key type %lu not supported", key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}


/*
 * Read public key.
 */
int
sc_pkcs15_read_pubkey(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		struct sc_pkcs15_pubkey **out)
{
	struct sc_context *ctx;
	const struct sc_pkcs15_pubkey_info *info = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	unsigned char *data = NULL;
	size_t	len;
	int	algorithm, r;
	int	private_obj;

	if (p15card == NULL || p15card->card == NULL || p15card->card->ops == NULL
			|| obj == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	ctx = p15card->card->ctx;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Public key type 0x%X", obj->type);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		algorithm = SC_ALGORITHM_RSA;
		break;
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		algorithm = SC_ALGORITHM_GOSTR3410;
		break;
	case SC_PKCS15_TYPE_PUBKEY_EC:
		algorithm = SC_ALGORITHM_EC;
		break;
	case SC_PKCS15_TYPE_PUBKEY_EDDSA:
		algorithm = SC_ALGORITHM_EDDSA;
		break;
	case SC_PKCS15_TYPE_PUBKEY_XEDDSA:
		algorithm = SC_ALGORITHM_XEDDSA;
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported public key type.");
	}
	info = (const struct sc_pkcs15_pubkey_info *) obj->data;

	pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (pubkey == NULL) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	pubkey->algorithm = algorithm;

	/* starting from SPKI direct value
	   in a compact form it presents complete public key data */
	if (info->direct.spki.value && info->direct.spki.len)   {
		sc_log(ctx, "Using direct SPKI value,  tag 0x%X", *(info->direct.spki.value));
		r = sc_pkcs15_pubkey_from_spki_sequence(ctx, info->direct.spki.value, info->direct.spki.len, &pubkey);
		LOG_TEST_GOTO_ERR(ctx, r, "Failed to decode 'SPKI' direct value");
	}
	else if (info->direct.raw.value && info->direct.raw.len)   {
		sc_log(ctx, "Using direct RAW value");
		r = sc_pkcs15_decode_pubkey(ctx, pubkey, info->direct.raw.value, info->direct.raw.len);
		LOG_TEST_GOTO_ERR(ctx, r, "Failed to decode 'RAW' direct value");
		sc_log(ctx, "TODO: for EC keys 'raw' data needs to be completed with referenced algorithm from TokenInfo");
	}
	else if (obj->content.value && obj->content.len)   {
		sc_log(ctx, "Using object content");
		r = sc_pkcs15_decode_pubkey(ctx, pubkey, obj->content.value, obj->content.len);
		LOG_TEST_GOTO_ERR(ctx, r, "Failed to decode object content value");
		sc_log(ctx, "TODO: for EC keys 'raw' data needs to be completed with referenced algorithm from TokenInfo");
	}
	else if (p15card->card->ops->read_public_key)   {
		sc_log(ctx, "Call card specific 'read-public-key' handle");
		r = p15card->card->ops->read_public_key(p15card->card, algorithm,
				(struct sc_path *)&info->path, info->key_reference, (unsigned)info->modulus_length,
				&data, &len);
		LOG_TEST_GOTO_ERR(ctx, r, "Card specific 'read-public' procedure failed.");

		r = sc_pkcs15_decode_pubkey(ctx, pubkey, data, len);
		LOG_TEST_GOTO_ERR(ctx, r, "Decode public key error");
	}
	else if (info->path.len)   {
		sc_log(ctx, "Read from EF and decode");
		private_obj = obj->flags & SC_PKCS15_CO_FLAG_PRIVATE;
		r = sc_pkcs15_read_file(p15card, &info->path, &data, &len, private_obj);
		LOG_TEST_GOTO_ERR(ctx, r, "Failed to read public key file.");

		if ((algorithm == SC_ALGORITHM_EC || algorithm == SC_ALGORITHM_EDDSA || algorithm == SC_ALGORITHM_XEDDSA)
				&& *data == (SC_ASN1_TAG_SEQUENCE | SC_ASN1_TAG_CONSTRUCTED))
			r = sc_pkcs15_pubkey_from_spki_sequence(ctx, data, len, &pubkey);
		else
			r = sc_pkcs15_decode_pubkey(ctx, pubkey, data, len);
		LOG_TEST_GOTO_ERR(ctx, r, "Decode public key error");
	}
	else {
		r = SC_ERROR_NOT_IMPLEMENTED;
		LOG_TEST_GOTO_ERR(ctx, r, "No way to get public key");
	}

err:
	if (r) {
		sc_pkcs15_free_pubkey(pubkey);
	} else
		*out = pubkey;
	free(data);

	LOG_FUNC_RETURN(ctx, r);
}


static int
sc_pkcs15_dup_bignum (struct sc_pkcs15_bignum *dst, struct sc_pkcs15_bignum *src)
{
	if (!dst || !src) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (src->data && src->len)   {
		dst->data = calloc(1, src->len);
		if (!dst->data)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(dst->data, src->data, src->len);
		dst->len = src->len;
	}

	return 0;
}


int
sc_pkcs15_pubkey_from_prvkey(struct sc_context *ctx, struct sc_pkcs15_prkey *prvkey,
		struct sc_pkcs15_pubkey **out)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int rv = SC_SUCCESS;

	if (!prvkey || !out) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	*out = NULL;
	pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (!pubkey)
		return SC_ERROR_OUT_OF_MEMORY;

	pubkey->algorithm = prvkey->algorithm;
	switch (prvkey->algorithm) {
	case SC_ALGORITHM_RSA:
		rv = sc_pkcs15_dup_bignum(&pubkey->u.rsa.modulus, &prvkey->u.rsa.modulus);
		if (!rv)
			rv = sc_pkcs15_dup_bignum(&pubkey->u.rsa.exponent, &prvkey->u.rsa.exponent);
		break;
	case SC_ALGORITHM_GOSTR3410:
		break;
	case SC_ALGORITHM_EC:
	case SC_ALGORITHM_EDDSA:
	case SC_ALGORITHM_XEDDSA:
		/* Copy pubkey */
		if (prvkey->u.ec.ecpointQ.value == NULL || prvkey->u.ec.ecpointQ.len <= 0) {
			sc_pkcs15_free_pubkey(pubkey);
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
		}
		pubkey->u.ec.ecpointQ.value = malloc(prvkey->u.ec.ecpointQ.len);
		if (!pubkey->u.ec.ecpointQ.value) {
			sc_pkcs15_free_pubkey(pubkey);
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		memcpy(pubkey->u.ec.ecpointQ.value, prvkey->u.ec.ecpointQ.value, prvkey->u.ec.ecpointQ.len);
		pubkey->u.ec.ecpointQ.len = prvkey->u.ec.ecpointQ.len;
		break;
	default:
		sc_log(ctx, "Unsupported private key algorithm");
		rv = SC_ERROR_NOT_SUPPORTED;
	}

	if (rv)
		sc_pkcs15_free_pubkey(pubkey);
	else
		*out = pubkey;

	return rv;
}


int
sc_pkcs15_dup_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key, struct sc_pkcs15_pubkey **out)
{
	struct sc_pkcs15_pubkey *pubkey = NULL;
	int rv = SC_SUCCESS;
	u8* alg;
	size_t alglen;

	LOG_FUNC_CALLED(ctx);

	if (!key || !out) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	*out = NULL;
	pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (!pubkey)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	pubkey->algorithm = key->algorithm;

	if (key->alg_id) {
		rv = sc_asn1_encode_algorithm_id(ctx, &alg, &alglen,key->alg_id, 0);
		if (rv == SC_SUCCESS) {
			pubkey->alg_id = (struct sc_algorithm_id *)calloc(1, sizeof(struct sc_algorithm_id));
			if (pubkey->alg_id == NULL) {
				free(pubkey);
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			}
			rv = sc_asn1_decode_algorithm_id(ctx, alg, alglen, pubkey->alg_id, 0);
			free(alg);
		}
	}

	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		rv = sc_pkcs15_dup_bignum(&pubkey->u.rsa.modulus, &key->u.rsa.modulus);
		if (!rv)
			rv = sc_pkcs15_dup_bignum(&pubkey->u.rsa.exponent, &key->u.rsa.exponent);
		break;
	case SC_ALGORITHM_GOSTR3410:
		break;
	case SC_ALGORITHM_EC:
	case SC_ALGORITHM_EDDSA:
	case SC_ALGORITHM_XEDDSA:
		pubkey->u.ec.ecpointQ.value = malloc(key->u.ec.ecpointQ.len);
		if (!pubkey->u.ec.ecpointQ.value) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		memcpy(pubkey->u.ec.ecpointQ.value, key->u.ec.ecpointQ.value, key->u.ec.ecpointQ.len);
		pubkey->u.ec.ecpointQ.len = key->u.ec.ecpointQ.len;

		if (key->u.ec.params.named_curve) {
			rv = sc_pkcs15_fix_ec_parameters(ctx, &key->u.ec.params);
			if (rv)
				break;
		}

		pubkey->u.ec.params.der.value = malloc(key->u.ec.params.der.len);
		if (!pubkey->u.ec.params.der.value) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		memcpy(pubkey->u.ec.params.der.value, key->u.ec.params.der.value, key->u.ec.params.der.len);
		pubkey->u.ec.params.der.len = key->u.ec.params.der.len;

		/* RFC4810 no named_curve */
		if ((key->algorithm != SC_ALGORITHM_EDDSA) && (key->algorithm != SC_ALGORITHM_XEDDSA)) {
			if (key->u.ec.params.named_curve) {
				pubkey->u.ec.params.named_curve = strdup(key->u.ec.params.named_curve);
				if (!pubkey->u.ec.params.named_curve)
					rv = SC_ERROR_OUT_OF_MEMORY;
			} else {
				sc_log(ctx, "named_curve parameter missing");
				rv = SC_ERROR_NOT_SUPPORTED;
			}
		}

		break;
	default:
		sc_log(ctx, "Unsupported private key algorithm");
		rv = SC_ERROR_NOT_SUPPORTED;
	}

	if (rv)
		sc_pkcs15_free_pubkey(pubkey);
	else
		*out = pubkey;

	LOG_FUNC_RETURN(ctx, rv);
}



void
sc_pkcs15_erase_pubkey(struct sc_pkcs15_pubkey *key)
{
	if (key == NULL) {
		return;
	}
	if (key->alg_id) {
		sc_asn1_clear_algorithm_id(key->alg_id);
		free(key->alg_id);
	}
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		free(key->u.rsa.modulus.data);
		free(key->u.rsa.exponent.data);
		break;
	case SC_ALGORITHM_GOSTR3410:
		free(key->u.gostr3410.xy.data);
		break;
	case SC_ALGORITHM_EC:
	case SC_ALGORITHM_EDDSA:
	case SC_ALGORITHM_XEDDSA:
		free(key->u.ec.params.der.value);
		free(key->u.ec.params.named_curve);
		free(key->u.ec.ecpointQ.value);
		break;
	}
	sc_mem_clear(key, sizeof(*key));
}


void
sc_pkcs15_free_pubkey(struct sc_pkcs15_pubkey *key)
{
	if (!key)
		return;
	sc_pkcs15_erase_pubkey(key);
	free(key);
}


void
sc_pkcs15_free_pubkey_info(sc_pkcs15_pubkey_info_t *info)
{
	if (info) {
		free(info->subject.value);
		free(info->direct.spki.value);
		free(info->direct.raw.value);
		sc_pkcs15_free_key_params(&info->params);
		free(info);
	}
}


static int
sc_pkcs15_read_der_file(sc_context_t *ctx, char * filename,
		u8 ** buf, size_t * buflen)
{
	int r;
	int f = -1;
	size_t len, offs;
	u8 tagbuf[16]; /* enough to read in the tag and length */
	u8 * rbuf = NULL;
	size_t rbuflen = 0;
	const u8 * body = NULL;
	size_t bodylen;
	unsigned int cla_out, tag_out;
	ssize_t sz;

	LOG_FUNC_CALLED(ctx);
	if (!buf || !buflen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	*buf = NULL;
	*buflen = 0;

	f = open(filename, O_RDONLY);
	if (f < 0) {
		r = SC_ERROR_FILE_NOT_FOUND;
		goto out;
	}

	sz = read(f, tagbuf, sizeof(tagbuf)); /* get tag and length */
	if (sz < 2) {
		sc_log(ctx, "Problem with '%s'", filename);
		r =  SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto out;
	}
	len = sz;

	body = tagbuf;
	r = sc_asn1_read_tag(&body, len, &cla_out, &tag_out, &bodylen);
	if (r != SC_SUCCESS && r != SC_ERROR_ASN1_END_OF_CONTENTS)
		goto out;

	if (body == NULL)   {
		r = SC_SUCCESS;
		goto out;
	}

	offs = body - tagbuf;
	if (offs > len || offs < 2 || offs > offs + bodylen)   {
		r = SC_ERROR_INVALID_ASN1_OBJECT;
		goto out;
	}

	rbuflen = offs + bodylen;
	rbuf = malloc(rbuflen);
	if (rbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(rbuf, tagbuf, len); /* copy first or only part */
	if (rbuflen > len) {
		/* read rest of file */
		sz = read(f, rbuf + len, rbuflen - len);
		if (sz < (ssize_t)(rbuflen - len)) {
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			free (rbuf);
			rbuf = NULL;
			goto out;
		}
	}
	*buflen = rbuflen;
	*buf = rbuf;
	rbuf = NULL;
	r = (int)rbuflen;
out:
	if (f >= 0)
		close(f);

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * can be used as an SC_ASN1_CALLBACK while parsing a certificate,
 * or can be called from the sc_pkcs15_pubkey_from_spki_file
 */
int
sc_pkcs15_pubkey_from_spki_fields(struct sc_context *ctx, struct sc_pkcs15_pubkey **outpubkey,
		unsigned char *buf, size_t buflen, int depth)
{

	struct sc_pkcs15_pubkey *pubkey = NULL;
	struct sc_pkcs15_der pk = { NULL, 0 };
	struct sc_algorithm_id pk_alg;
	struct sc_asn1_entry asn1_pkinfo[C_ASN1_PKINFO_ATTR_SIZE];
	unsigned char *tmp_buf = NULL;
	int r;

	sc_log(ctx,
	       "sc_pkcs15_pubkey_from_spki_fields() called: %p:%"SC_FORMAT_LEN_SIZE_T"u\n%s",
	       buf, buflen, sc_dump_hex(buf, buflen));

	tmp_buf = malloc(buflen);
	if (!tmp_buf) {
		r = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, r, "");
	}
	memcpy(tmp_buf, buf, buflen);

	if ((*tmp_buf & SC_ASN1_TAG_CONTEXT))
		*tmp_buf = SC_ASN1_TAG_CONSTRUCTED | SC_ASN1_TAG_SEQUENCE;

	memset(&pk_alg, 0, sizeof(pk_alg));
	pubkey = calloc(1, sizeof(sc_pkcs15_pubkey_t));
	if (pubkey == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, r, "");
	}

	sc_copy_asn1_entry(c_asn1_pkinfo, asn1_pkinfo);

	sc_format_asn1_entry(asn1_pkinfo + 0, &pk_alg, NULL, 0);
	sc_format_asn1_entry(asn1_pkinfo + 1, &pk.value, &pk.len, 0);

	r = sc_asn1_decode(ctx, asn1_pkinfo, tmp_buf, buflen, NULL, NULL);
	if (r != SC_SUCCESS) {
		sc_asn1_clear_algorithm_id(&pk_alg);
		LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 parsing of subjectPubkeyInfo failed");
	}

	pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
	if (pubkey->alg_id == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, r, "");
	}

	memcpy(pubkey->alg_id, &pk_alg, sizeof(struct sc_algorithm_id));
	pubkey->algorithm = pk_alg.algorithm;
	pk_alg.params = NULL;
	sc_log(ctx, "DEE pk_alg.algorithm=%lu", pk_alg.algorithm);

	if (pk.len == 0)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_INTERNAL, "Incorrect length of key");
	pk.len = BYTES4BITS(pk.len); /* convert number of bits to bytes */

	if (pk_alg.algorithm == SC_ALGORITHM_EC)   {
		/* EC public key is not encapsulated into BIT STRING -- it's a BIT STRING */
		/*
		 * sc_pkcs15_fix_ec_parameters below will set field_length from curve.
		 * if no alg_id->params, assume field_length is multiple of 8
		 */
		pubkey->u.ec.params.field_length = (pk.len - 1) / 2 * 8;

		if (pubkey->alg_id->params) {
			struct sc_ec_parameters *ecp = (struct sc_ec_parameters *)pubkey->alg_id->params;

			pubkey->u.ec.params.der.value = malloc(ecp->der.len);
			if (pubkey->u.ec.params.der.value == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				LOG_TEST_GOTO_ERR(ctx, r, "");
			}

			memcpy(pubkey->u.ec.params.der.value, ecp->der.value, ecp->der.len);
			pubkey->u.ec.params.der.len = ecp->der.len;
			r = sc_pkcs15_fix_ec_parameters(ctx, &pubkey->u.ec.params);
			LOG_TEST_GOTO_ERR(ctx, r, "failed to fix EC parameters");
		}

		pubkey->u.ec.ecpointQ.value = malloc(pk.len);
		if (pubkey->u.ec.ecpointQ.value == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			LOG_TEST_GOTO_ERR(ctx, r, "failed to malloc() memory");
		}
		memcpy(pubkey->u.ec.ecpointQ.value, pk.value, pk.len);
		pubkey->u.ec.ecpointQ.len = pk.len;
	} else if (pk_alg.algorithm == SC_ALGORITHM_EDDSA ||
		   pk_alg.algorithm == SC_ALGORITHM_XEDDSA) {
		/*
		 * SPKI will have OID, EDDSA can have ED25519 or ED448 with different sizes
		 * EDDSA/XEDDSA public key is not encapsulated into BIT STRING -- it's a BIT STRING
		 * no params, but oid is the params.
		 */
		r = sc_encode_oid(ctx, &pk_alg.oid, &pubkey->u.ec.params.der.value, &pubkey->u.ec.params.der.len);
		LOG_TEST_GOTO_ERR(ctx, r, "failed to encode (X)EDDSA oid");
		r = sc_pkcs15_fix_ec_parameters(ctx, &pubkey->u.ec.params);
		LOG_TEST_GOTO_ERR(ctx, r, "failed to fix EC parameters");

		pubkey->u.ec.ecpointQ.value = malloc(pk.len);
		memcpy(pubkey->u.ec.ecpointQ.value, pk.value, pk.len);
		pubkey->u.ec.ecpointQ.len = pk.len;
	} else {
		/* Public key is expected to be encapsulated into BIT STRING */
		r = sc_pkcs15_decode_pubkey(ctx, pubkey, pk.value, pk.len);
		LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 parsing of subjectPubkeyInfo failed");
	}

	*outpubkey = pubkey;
	pubkey = NULL;

err:
	sc_pkcs15_free_pubkey(pubkey);
	free(pk.value);
	free(tmp_buf);

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_pubkey_from_spki_sequence(struct sc_context *ctx, const unsigned char *buf, size_t buflen,
		struct sc_pkcs15_pubkey ** outpubkey)
{
	struct sc_pkcs15_pubkey * pubkey = NULL;
	struct sc_asn1_entry asn1_spki[] = {
			{ "subjectPublicKeyInfo", SC_ASN1_CALLBACK, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, sc_pkcs15_pubkey_from_spki_fields, &pubkey},
			{ NULL, 0, 0, 0, NULL, NULL } };
	int r;

	LOG_FUNC_CALLED(ctx);

	r = sc_asn1_decode(ctx, asn1_spki, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 cannot parse subjectPublicKeyInfo");

	if(outpubkey) {
		free(*outpubkey);
		*outpubkey = pubkey;
	} else
		free(pubkey);

	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_pubkey_from_spki_file(struct sc_context *ctx, char * filename,
		struct sc_pkcs15_pubkey ** outpubkey)
{
	int r;
	u8 * buf = NULL;
	size_t buflen = 0;

	LOG_FUNC_CALLED(ctx);

	r = sc_pkcs15_read_der_file(ctx, filename, &buf, &buflen);
	LOG_TEST_RET(ctx, r, "Cannot read SPKI DER file");

	r = sc_pkcs15_pubkey_from_spki_sequence(ctx, buf, buflen, outpubkey);
	free(buf);

	LOG_FUNC_RETURN(ctx, r);
}

// clang-format off
static struct ec_curve_info {
	const char *name;
	const char *oid_str;
	const struct sc_pkcs15_der oid_der;
	size_t size;
	const unsigned int key_type;

} ec_curve_infos[] = {
		{"secp192r1",		"1.2.840.10045.3.1.1", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01", 10}, 192, SC_ALGORITHM_EC},
		{"prime192v1",		"1.2.840.10045.3.1.1", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01", 10}, 192, SC_ALGORITHM_EC},
		{"nistp192",		"1.2.840.10045.3.1.1", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01", 10}, 192, SC_ALGORITHM_EC},
		{"ansiX9p192r1",	"1.2.840.10045.3.1.1", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01", 10}, 192, SC_ALGORITHM_EC},

		{"secp224r1",		"1.3.132.0.33", {(u8 *)"\x06\x05\x2b\x81\x04\x00\x21", 7}, 224, SC_ALGORITHM_EC},
		{"nistp224",		"1.3.132.0.33", {(u8 *)"\x06\x05\x2b\x81\x04\x00\x21", 7}, 224, SC_ALGORITHM_EC},

		{"prime256v1",		"1.2.840.10045.3.1.7", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10}, 256, SC_ALGORITHM_EC},
		{"secp256r1",		"1.2.840.10045.3.1.7", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10}, 256, SC_ALGORITHM_EC},
		{"nistp256",		"1.2.840.10045.3.1.7", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10}, 256, SC_ALGORITHM_EC},
		{"ansiX9p256r1",	"1.2.840.10045.3.1.7", {(u8 *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", 10}, 256, SC_ALGORITHM_EC},

		{"secp384r1",		"1.3.132.0.34", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x22", 7}, 384, SC_ALGORITHM_EC},
		{"prime384v1",		"1.3.132.0.34", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x22", 7}, 384, SC_ALGORITHM_EC},
		{"nistp384",		"1.3.132.0.34", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x22", 7}, 384, SC_ALGORITHM_EC},
		{"ansiX9p384r1",	"1.3.132.0.34", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x22", 7}, 384, SC_ALGORITHM_EC},

		{"secp521r1",		"1.3.132.0.35", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x23", 7}, 521, SC_ALGORITHM_EC},
		{"nistp521",		"1.3.132.0.35", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x23", 7}, 521, SC_ALGORITHM_EC},

		{"brainpoolP192r1",	"1.3.36.3.3.2.8.1.1.3", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x03", 11}, 192, SC_ALGORITHM_EC},
		{"brainpoolP224r1",	"1.3.36.3.3.2.8.1.1.5", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x05", 11}, 224, SC_ALGORITHM_EC},
		{"brainpoolP256r1",	"1.3.36.3.3.2.8.1.1.7", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07", 11}, 256, SC_ALGORITHM_EC},
		{"brainpoolP320r1",	"1.3.36.3.3.2.8.1.1.9", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x09", 11}, 320, SC_ALGORITHM_EC},
		{"brainpoolP384r1",	"1.3.36.3.3.2.8.1.1.11", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B", 11}, 384, SC_ALGORITHM_EC},
		{"brainpoolP512r1",	"1.3.36.3.3.2.8.1.1.13", {(u8 *)"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D", 11}, 512, SC_ALGORITHM_EC},

		{"secp192k1",		"1.3.132.0.31", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x1F", 7}, 192, SC_ALGORITHM_EC},
		{"secp256k1",		"1.3.132.0.10", {(u8 *)"\x06\x05\x2B\x81\x04\x00\x0A", 7}, 256, SC_ALGORITHM_EC},

		/* OpenPGP extensions by Yubikey and GNUK are not defined in RFCs but we know the oid written to card */

		{"edwards25519",	"1.3.6.1.4.1.11591.15.1", {(u8 *)"\x06\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01", 11}, 255, SC_ALGORITHM_EDDSA},
		{"curve25519",		"1.3.6.1.4.1.3029.1.5.1", {(u8 *)"\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01", 12}, 255, SC_ALGORITHM_XEDDSA},

		/* RFC 8410 defined curves */
		{"X25519",              "1.3.101.110", {(u8 *)"\x06\x03\x2b\x65\x6e", 5}, 255, SC_ALGORITHM_XEDDSA},
		{"X448",		"1.3.101.111", {(u8 *)"\x06\x03\x2b\x65\x6f", 5}, 448, SC_ALGORITHM_XEDDSA},
		{"Ed25519",             "1.3.101.112", {(u8 *)"\x06\x03\x2b\x65\x70", 5}, 255, SC_ALGORITHM_EDDSA},
		{"Ed448",		"1.3.101.113", {(u8 *)"\x06\x03\x2b\x65\x71", 5}, 448, SC_ALGORITHM_EDDSA},
		/* GnuPG openpgp curves as used in gnupg-card are equivalent to RFC8410 OIDs */
		{"cv25519",		"1.3.101.110", {(u8 *)"\x06\x03\x2b\x65\x6e", 5}, 255, SC_ALGORITHM_XEDDSA},
		{"ed25519",		"1.3.101.112", {(u8 *)"\x06\x03\x2b\x65\x70", 5}, 255, SC_ALGORITHM_EDDSA},

		{NULL, NULL, {NULL, 0}, 0, 0}, /* Do not touch this */
};
// clang-format on

int
sc_pkcs15_fix_ec_parameters(struct sc_context *ctx, struct sc_ec_parameters *ecparams)
{
	int rv, ii;
	int mapped_string = 0; /* der is printable string that can be replaced with der of OID */

	LOG_FUNC_CALLED(ctx);

	/* In PKCS#11 EC parameters arrives in DER encoded form */
	if (ecparams->der.value && ecparams->der.len && ecparams->der.len > 2) {

		switch (ecparams->der.value[0]) {
		case 0x06: /* der.value is an OID */
			for (ii = 0; ec_curve_infos[ii].name; ii++) {
				size_t len = ec_curve_infos[ii].oid_der.len;

				if (ecparams->der.len == len &&
						memcmp(ecparams->der.value, ec_curve_infos[ii].oid_der.value, len) == 0)
					break; /* found ec_curve_infos[ii] */
			}
			break;

		case 0x13:
			/* printable string as per PKCS11 V 3.0 for experimental curves */
			{
				int r_tag;
				const u8 *body = ecparams->der.value;
				size_t len = ecparams->der.len;
				unsigned int cla_out, tag_out;
				size_t bodylen;

				r_tag = sc_asn1_read_tag(&body, len, &cla_out, &tag_out, &bodylen);
				if (r_tag != SC_SUCCESS || tag_out != 0x13) {
					sc_log(ctx, "Invalid printable string");
					LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
				}
				for (ii = 0; ec_curve_infos[ii].name; ii++) {
					size_t len = strlen(ec_curve_infos[ii].name);
					if (bodylen != len || memcmp(ec_curve_infos[ii].name, body, len) != 0)
						continue;
					/* found replacement of printable string to OID */
					mapped_string = 1;
					break;
				}
			}
			break;

		default:
			sc_log(ctx, "Unsupported ec params");
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
		}

		if (ec_curve_infos[ii].name == NULL) /* end of ec_curve_info */
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported named curve");

		/* ii points to entry with matching oid_der or a mapped entry with replacement oid_der */
		sc_log(ctx, "Found known curve '%s'", ec_curve_infos[ii].name);
		if (mapped_string) { /* free previous name if any replace below with new name */
			free(ecparams->named_curve);
			ecparams->named_curve = NULL;
		}

		if (!ecparams->named_curve) { /* if present,keep the name as some curves have multiple names */
			ecparams->named_curve = strdup(ec_curve_infos[ii].name);
			if (!ecparams->named_curve)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

			sc_log(ctx, "Curve name: '%s'", ecparams->named_curve);
		}

		/* fill in object_id based on oid_der */
		sc_format_oid(&ecparams->id, ec_curve_infos[ii].oid_str);

		ecparams->field_length = ec_curve_infos[ii].size;
		ecparams->key_type = ec_curve_infos[ii].key_type;
		sc_log(ctx, "Curve length %" SC_FORMAT_LEN_SIZE_T "u key_type %d",
				ecparams->field_length, ecparams->key_type);
		if (mapped_string) {
			/* replace the printable string version with the oid */
			if (ecparams->der.value)
				free(ecparams->der.value);
			ecparams->der.len = ec_curve_infos[ii].oid_der.len;
			ecparams->der.value = malloc(ecparams->der.len);
			if (ecparams->der.value == NULL) {
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			}
			memcpy(ecparams->der.value, ec_curve_infos[ii].oid_der.value, ecparams->der.len);
		}
	} else if (ecparams->named_curve) { /* it can be name of curve or OID in ASCII form */
		/* caller did not provide an OID, look for a name or oid_string */
		for (ii = 0; ec_curve_infos[ii].name; ii++) {
			if (!strcmp(ec_curve_infos[ii].name, ecparams->named_curve))
				break;
			if (!strcmp(ec_curve_infos[ii].oid_str, ecparams->named_curve))
				break;
		}
		if (!ec_curve_infos[ii].name) {
			sc_log(ctx, "Named curve '%s' not supported", ecparams->named_curve);
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
		}

		rv = sc_format_oid(&ecparams->id, ec_curve_infos[ii].oid_str);
		LOG_TEST_RET(ctx, rv, "Invalid OID format");

		ecparams->field_length = ec_curve_infos[ii].size;
		ecparams->key_type = ec_curve_infos[ii].key_type;
		sc_log(ctx, "Curve length %" SC_FORMAT_LEN_SIZE_T "u key_type %d",
				ecparams->field_length, ecparams->key_type);

		if (ecparams->der.value == NULL || ecparams->der.len == 0) {
			free(ecparams->der.value); /* just in case */
			ecparams->der.value = NULL;
			ecparams->der.len = 0;
			/* if caller did not provide valid der OID, fill in */
			rv = sc_encode_oid (ctx, &ecparams->id, &ecparams->der.value, &ecparams->der.len);
			LOG_TEST_RET(ctx, rv, "Cannot encode object ID");
		}
	} else
		LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "EC parameters has to be presented as a named curve or explicit data");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_convert_pubkey(struct sc_pkcs15_pubkey *pkcs15_key, void *evp_key)
{
#ifdef ENABLE_OPENSSL
	EVP_PKEY *pk = (EVP_PKEY *)evp_key;
	int pk_type;
	pk_type = EVP_PKEY_base_id(pk);

	switch (pk_type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_pubkey_rsa *dst = &pkcs15_key->u.rsa;
		/* Get parameters */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		const BIGNUM *src_n, *src_e;
		RSA *src = NULL;
		if (!(src = EVP_PKEY_get1_RSA(pk)))
			return SC_ERROR_INCOMPATIBLE_KEY;
		RSA_get0_key(src, &src_n, &src_e, NULL);
		if (!src_n || !src_e) {
			RSA_free(src);
			return SC_ERROR_INTERNAL;
		}
#else
		BIGNUM *src_n = NULL, *src_e = NULL;
		if (EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_N, &src_n) != 1 ||
			EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_RSA_E, &src_e) != 1) {
			BN_free(src_n);
			return SC_ERROR_INTERNAL;
		}
#endif
		/* Convert */
		pkcs15_key->algorithm = SC_ALGORITHM_RSA;
		if (!sc_pkcs15_convert_bignum(&dst->modulus, src_n) ||
			!sc_pkcs15_convert_bignum(&dst->exponent, src_e)) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			RSA_free(src);
#else
			BN_free(src_n); BN_free(src_e);
#endif
			return SC_ERROR_INVALID_DATA;
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		RSA_free(src);
#else
		BN_free(src_n); BN_free(src_e);
#endif
		break;
	}
#if !defined(OPENSSL_NO_EC)
	case NID_id_GostR3410_2001: {
		struct sc_pkcs15_pubkey_gostr3410 *dst = &pkcs15_key->u.gostr3410;
		BIGNUM *X, *Y;
		int r = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		const EC_KEY *eckey = NULL;
		const EC_POINT *point = NULL;
		const EC_GROUP *group = NULL;
		if (!(eckey = EVP_PKEY_get0(pk)))
			return SC_ERROR_INCOMPATIBLE_KEY;
		if (!(point = EC_KEY_get0_public_key(eckey)) ||
			!(group = EC_KEY_get0_group(eckey)))
			return SC_ERROR_INTERNAL;
#else
		EC_POINT *point = NULL;
		EC_GROUP *group = NULL;
		int nid = 0;
		unsigned char *pub = NULL;
		size_t pub_len = 0;
		char *group_name = NULL;
		size_t group_name_len = 0;

		if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) != 1) {
			return SC_ERROR_INTERNAL;
		}
		if (EVP_PKEY_get_group_name(pk, NULL, 0, &group_name_len) != 1) {
			return SC_ERROR_INTERNAL;
		}
		if (!(pub = malloc(pub_len)) || !(group_name = malloc(group_name_len))) {
			free(pub);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len, NULL) != 1 ||
			EVP_PKEY_get_group_name(pk, group_name, group_name_len, NULL) != 1) {
			free(pub);
			free(group_name);
			return SC_ERROR_INTERNAL;
		}
		if ((nid = OBJ_sn2nid(group_name) == 0) ||
			!(group = EC_GROUP_new_by_curve_name(nid)) ||
			!(point = EC_POINT_new(group)) ||
			EC_POINT_oct2point(group, point, pub, pub_len, NULL) != 1) {
			free(pub);
			free(group_name);
			EC_POINT_free(point);
			EC_GROUP_free(group);
			return SC_ERROR_INTERNAL;
		}
		free(pub);
		free(group_name);
#endif
		X = BN_new();
		Y = BN_new();
		if (X && Y && group)
				r = EC_POINT_get_affine_coordinates(group, point, X, Y, NULL);
		if (r == 1) {
			dst->xy.len = BN_num_bytes(X) + BN_num_bytes(Y);
			dst->xy.data = malloc(dst->xy.len);
			if (dst->xy.data) {
				BN_bn2bin(Y, dst->xy.data);
				BN_bn2bin(X, dst->xy.data + BN_num_bytes(Y));
				r = sc_mem_reverse(dst->xy.data, dst->xy.len);
				if (!r)
					r = 1;
				pkcs15_key->algorithm = SC_ALGORITHM_GOSTR3410;
			}
			else
				r = -1;
		}
		BN_free(X);
		BN_free(Y);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EC_GROUP_free(group);
		EC_POINT_free(point);
#endif
		if (r != 1)
			return SC_ERROR_INTERNAL;
		break;
	}
	case EVP_PKEY_EC: {
		struct sc_pkcs15_pubkey_ec *dst = &pkcs15_key->u.ec;
		pkcs15_key->algorithm = SC_ALGORITHM_EC;
		unsigned char buf[255]; size_t buflen = 255;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		const EC_KEY *src = NULL;
		const EC_GROUP *grp = NULL;
		const EC_POINT *point = NULL;
		int nid = 0;

		if (!(src = EVP_PKEY_get0_EC_KEY(pk)))
			return SC_ERROR_INCOMPATIBLE_KEY;
		if (!(point = EC_KEY_get0_public_key(src)) ||
			!(grp = EC_KEY_get0_group(src))) {
			return SC_ERROR_INCOMPATIBLE_KEY;
		 }

		/* Decode EC_POINT from a octet string */
		buflen = EC_POINT_point2oct(grp, point,
				POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);

		/* get curve name */
		nid = EC_GROUP_get_curve_name(grp);
		if(nid != 0) {
			const char *group_name = OBJ_nid2sn(nid);
			if (group_name)
				dst->params.named_curve = strdup(group_name);
		}
#else
		char group_name[256];
		if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, buflen, NULL) != 1)
			return SC_ERROR_INTERNAL;
		if (EVP_PKEY_get_group_name(pk, group_name, sizeof(group_name), NULL) != 1)
			return SC_ERROR_INTERNAL;
		dst->params.named_curve = strdup(group_name);

		/* Decode EC_POINT from a octet string */
		if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, buflen, &buflen) != 1) {
			return SC_ERROR_INCOMPATIBLE_KEY;
		}
#endif

		/* copy the public key */
		if (buflen > 0) {
			dst->ecpointQ.value = malloc(buflen);
			if (!dst->ecpointQ.value)
				return SC_ERROR_OUT_OF_MEMORY;
			memcpy(dst->ecpointQ.value, buf, buflen);
			dst->ecpointQ.len = buflen;
			/* calculate the field length */
			dst->params.field_length = (buflen - 1) / 2 * 8;
		}
		else
			return SC_ERROR_INCOMPATIBLE_KEY;

		break;
	}
#endif /* !defined(OPENSSL_NO_EC) */
#ifdef EVP_PKEY_ED25519
	case EVP_PKEY_ED25519: {
		/* TODO */
		break;
	}
#endif /* EVP_PKEY_ED25519 */
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	return SC_SUCCESS;
#else
	return SC_ERROR_NOT_IMPLEMENTED;
#endif
}
