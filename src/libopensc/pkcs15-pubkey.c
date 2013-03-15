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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"

#ifdef ENABLE_OPENSSL
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	#ifndef OPENSSL_NO_EC
	#include <openssl/ec.h>
	#endif
#endif
#endif

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
	{ "path",       SC_ASN1_PATH,      SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "direct",     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSAKEY_ATTR_SIZE 4
static const struct sc_asn1_entry c_asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE] = {
	{ "value",         SC_ASN1_CHOICE, 0, 0, NULL, NULL },
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

#define C_ASN1_ECKEY_ATTR_SIZE 4
static const struct sc_asn1_entry c_asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE] = {
	{ "value",         SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ "fieldSize",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
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

#define C_ASN1_DSAKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE] = {
	{ "value", SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_DSA_TYPE_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_dsa_type_attr[C_ASN1_DSA_TYPE_ATTR_SIZE] = {
	{ "publicDSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
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

#define C_ASN1_PUBKEY_CHOICE_SIZE 5
static const struct sc_asn1_entry c_asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE] = {
	{ "publicRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "publicDSAKey", SC_ASN1_PKCS15_OBJECT, 2 | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
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

int sc_pkcs15_decode_pukdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
	sc_context_t *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info info;
	int r, gostr3410_params[3];
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_pkcs15_der *der = &obj->content;
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_pubkey_attr[C_ASN1_COM_PUBKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_value_choice[C_ASN1_RSAKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsa_type_attr[C_ASN1_RSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_eckey_value_choice[C_ASN1_ECKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_ec_type_attr[C_ASN1_EC_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsa_type_attr[C_ASN1_DSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOST3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410_type_attr[C_ASN1_GOST3410_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_pubkey[C_ASN1_PUBKEY_SIZE];
	struct sc_asn1_pkcs15_object rsakey_obj = { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_rsa_type_attr };
	struct sc_asn1_pkcs15_object eckey_obj = { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_ec_type_attr };
	struct sc_asn1_pkcs15_object dsakey_obj = { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_dsa_type_attr };
	struct sc_asn1_pkcs15_object gostr3410key_obj =  { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_gostr3410_type_attr };

	sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
	sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
	sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_value_choice, asn1_rsakey_value_choice);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_ec_type_attr, asn1_ec_type_attr);
	sc_copy_asn1_entry(c_asn1_eckey_value_choice, asn1_eckey_value_choice);
	sc_copy_asn1_entry(c_asn1_eckey_attr, asn1_eckey_attr);
	sc_copy_asn1_entry(c_asn1_dsa_type_attr, asn1_dsa_type_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410_type_attr, asn1_gostr3410_type_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_com_pubkey_attr + 0, &info.subject.value, &info.subject.len, 0);

	sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 1, &dsakey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 2, &gostr3410key_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 3, &eckey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_value_choice + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_value_choice + 1, &der->value, &der->len, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, asn1_rsakey_value_choice, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_ec_type_attr + 0, asn1_eckey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_eckey_value_choice + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_eckey_value_choice + 1, &der->value, &der->len, 0);

	sc_format_asn1_entry(asn1_eckey_attr + 0, asn1_eckey_value_choice, NULL, 0);
	sc_format_asn1_entry(asn1_eckey_attr + 1, &info.field_length, NULL, 0);

	sc_format_asn1_entry(asn1_dsa_type_attr + 0, asn1_dsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_dsakey_attr + 0, &info.path, NULL, 0);

	sc_format_asn1_entry(asn1_gostr3410_type_attr + 0, asn1_gostr3410key_attr, NULL, 0);

	sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 1, &gostr3410_params[0], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 2, &gostr3410_params[1], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 3, &gostr3410_params[2], NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

	sc_format_asn1_entry(asn1_pubkey + 0, asn1_pubkey_choice, NULL, 0);

	/* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.key_reference = -1;
	info.native = 1;
	memset(gostr3410_params, 0, sizeof(gostr3410_params));

	r = sc_asn1_decode(ctx, asn1_pubkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "ASN.1 decoding failed");
	if (asn1_pubkey_choice[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_RSA;
	} else if (asn1_pubkey_choice[2].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
		assert(info.modulus_length == 0);
		info.modulus_length = SC_PKCS15_GOSTR3410_KEYSIZE;
		assert(info.params.len == 0);
		info.params.len = sizeof(struct sc_pkcs15_keyinfo_gostparams);
		info.params.data = malloc(info.params.len);
		if (info.params.data == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		assert(sizeof(*keyinfo_gostparams) == info.params.len);
		keyinfo_gostparams = info.params.data;
		keyinfo_gostparams->gostr3410 = (unsigned int)gostr3410_params[0];
		keyinfo_gostparams->gostr3411 = (unsigned int)gostr3410_params[1];
		keyinfo_gostparams->gost28147 = (unsigned int)gostr3410_params[2];
	} 
	else if (asn1_pubkey_choice[3].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_EC;
	}
	else {
		obj->type = SC_PKCS15_TYPE_PUBKEY_DSA;
	}
	if (!p15card->app || !p15card->app->ddo.aid.len)   {
		r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info.path);
		if (r < 0) {
			sc_pkcs15_free_key_params(&info.params);
			return r;
		}
	}
	else   {
		info.path.aid = p15card->app->ddo.aid;
	}
	sc_log(ctx, "PubKey path '%s'", sc_print_path(&info.path));

        /* OpenSC 0.11.4 and older encoded "keyReference" as a negative
           value. Fixed in 0.11.5 we need to add a hack, so old cards
           continue to work. */
	if (info.key_reference < -1)
		info.key_reference += 256;

	obj->data = malloc(sizeof(info));
	if (obj->data == NULL) {
		sc_pkcs15_free_key_params(&info.params);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_pukdf_entry(sc_context_t *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_pubkey_attr[C_ASN1_COM_PUBKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_value_choice[C_ASN1_RSAKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsa_type_attr[C_ASN1_RSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_eckey_value_choice[C_ASN1_ECKEY_VALUE_CHOICE_SIZE];
	struct sc_asn1_entry asn1_eckey_attr[C_ASN1_ECKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_ec_type_attr[C_ASN1_EC_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsa_type_attr[C_ASN1_DSA_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOST3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410_type_attr[C_ASN1_GOST3410_TYPE_ATTR_SIZE];
	struct sc_asn1_entry asn1_pubkey_choice[C_ASN1_PUBKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_pubkey[C_ASN1_PUBKEY_SIZE];

	struct sc_pkcs15_pubkey_info *pubkey =
		(struct sc_pkcs15_pubkey_info *) obj->data;
	struct sc_asn1_pkcs15_object rsakey_obj = { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_rsa_type_attr };
	struct sc_asn1_pkcs15_object eckey_obj = { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_ec_type_attr };
	struct sc_asn1_pkcs15_object dsakey_obj = { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_dsa_type_attr };
	struct sc_asn1_pkcs15_object gostr3410key_obj =  { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_gostr3410_type_attr };
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	int r;
	size_t af_len, usage_len;

	sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
	sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
	sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_value_choice, asn1_rsakey_value_choice);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_ec_type_attr, asn1_ec_type_attr);
	sc_copy_asn1_entry(c_asn1_eckey_value_choice, asn1_eckey_value_choice);
	sc_copy_asn1_entry(c_asn1_eckey_attr, asn1_eckey_attr);
	sc_copy_asn1_entry(c_asn1_dsa_type_attr, asn1_dsa_type_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410_type_attr, asn1_gostr3410_type_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 1);
		if (pubkey->path.len || !obj->content.value)
			sc_format_asn1_entry(asn1_rsakey_value_choice + 0, &pubkey->path, NULL, 1);
		else
			sc_format_asn1_entry(asn1_rsakey_value_choice + 1, obj->content.value, (void *)&obj->content.len, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 0, asn1_rsakey_value_choice, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 1, &pubkey->modulus_length, NULL, 1);
		break;

	case SC_PKCS15_TYPE_PUBKEY_DSA:
		sc_format_asn1_entry(asn1_pubkey_choice + 1, &dsakey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_dsa_type_attr + 0, asn1_dsakey_attr, NULL, 1);

		sc_format_asn1_entry(asn1_dsakey_attr + 0, &pubkey->path, NULL, 1);
		break;

	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		sc_format_asn1_entry(asn1_pubkey_choice + 2, &gostr3410key_obj, NULL, 1);

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
		/* MyEID is a PKCS15 card with ECC */
		sc_format_asn1_entry(asn1_pubkey_choice + 3, &eckey_obj, NULL, 1);
		
		sc_format_asn1_entry(asn1_ec_type_attr + 0, asn1_eckey_attr, NULL, 1);
		if (pubkey->path.len || !obj->content.value)
			sc_format_asn1_entry(asn1_eckey_value_choice + 0, &pubkey->path, NULL, 1);
		else
			sc_format_asn1_entry(asn1_eckey_value_choice + 1, obj->content.value, (void *)&obj->content.len, 1);
		sc_format_asn1_entry(asn1_eckey_attr + 0, asn1_eckey_value_choice, NULL, 1);
		sc_format_asn1_entry(asn1_eckey_attr + 1, &pubkey->field_length, NULL, 1);
		
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
	return r;
}

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

#define C_ASN1_DSA_PUB_COEFFICIENTS_SIZE 5
static struct sc_asn1_entry c_asn1_dsa_pub_coefficients[C_ASN1_DSA_PUB_COEFFICIENTS_SIZE] = {
	{ "publicKey",SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramP",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramQ",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramG",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL },
};

#define C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE 2
static struct sc_asn1_entry c_asn1_gostr3410_pub_coefficients[C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE] = {
	{ "xy", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_EC_POINTQ_SIZE 2
static struct sc_asn1_entry c_asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE] = {
	{ "ecpointQ", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


int
sc_pkcs15_decode_pubkey_rsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_rsa *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_pub_coefficients, NULL, 0);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, &key->modulus.data, &key->modulus.len, 0);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, &key->exponent.data, &key->exponent.len, 0);

	r = sc_asn1_decode(ctx, asn1_public_key, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of public key failed");

	return SC_SUCCESS;
}


int
sc_pkcs15_encode_pubkey_rsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_rsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_pub_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, key->modulus.data, &key->modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, key->exponent.data, &key->exponent.len, 1);

	r = sc_asn1_encode(ctx, asn1_public_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	return 0;
}


int
sc_pkcs15_decode_pubkey_dsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_dsa *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_dsa_pub_coefficients[C_ASN1_DSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_copy_asn1_entry(c_asn1_dsa_pub_coefficients, asn1_dsa_pub_coefficients);

	sc_format_asn1_entry(asn1_public_key + 0, asn1_dsa_pub_coefficients, NULL, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 0, &key->pub.data, &key->pub.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 1, &key->g.data, &key->g.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 2, &key->p.data, &key->p.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 3, &key->q.data, &key->q.len, 0);

	r = sc_asn1_decode(ctx, asn1_public_key, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 decoding failed");

	return 0;
}


int
sc_pkcs15_encode_pubkey_dsa(sc_context_t *ctx, struct sc_pkcs15_pubkey_dsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_public_key[C_ASN1_PUBLIC_KEY_SIZE];
	struct sc_asn1_entry asn1_dsa_pub_coefficients[C_ASN1_DSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_copy_asn1_entry(c_asn1_dsa_pub_coefficients, asn1_dsa_pub_coefficients);

	sc_format_asn1_entry(asn1_public_key + 0, asn1_dsa_pub_coefficients, NULL, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 0, key->pub.data, &key->pub.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 1, key->g.data, &key->g.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 2, key->p.data, &key->p.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coefficients + 3, key->q.data, &key->q.len, 1);

	r = sc_asn1_encode(ctx, asn1_public_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	return 0;
}


int
sc_pkcs15_decode_pubkey_gostr3410(sc_context_t *ctx, struct sc_pkcs15_pubkey_gostr3410 *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_gostr3410_pub_coeff[C_ASN1_GOSTR3410_PUB_COEFFICIENTS_SIZE];
	int r;
	struct sc_object_id param_key = {{ 1, 2, 643, 2, 2, 35, 1, -1}};
	struct sc_object_id param_hash = {{ 1, 2, 643, 2, 2, 30, 1, -1}};

	sc_copy_asn1_entry(c_asn1_gostr3410_pub_coefficients, asn1_gostr3410_pub_coeff);
	sc_format_asn1_entry(asn1_gostr3410_pub_coeff + 0, &key->xy.data, &key->xy.len, 0);

	r = sc_asn1_decode(ctx, asn1_gostr3410_pub_coeff, buf, buflen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of public key failed");

	key->params.key = param_key;
	key->params.hash = param_hash;

	return 0;
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
 * We are storing the ec_pointQ as a octet string.
 * Thus we will just copy the string.
 * But to get the field length we decode it.
 */
int
sc_pkcs15_decode_pubkey_ec(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_ec *key,
		const u8 *buf, size_t buflen)
{
	int r;
	u8 * ecpoint_data;
	size_t ecpoint_len;
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];

	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
	sc_format_asn1_entry(asn1_ec_pointQ + 0, &ecpoint_data, &ecpoint_len, 1);
	r = sc_asn1_decode(ctx, asn1_ec_pointQ, buf, buflen, NULL, NULL);
	if (r < 0)
		LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	sc_log(ctx, "DEE-EC key=%p, buf=%p, buflen=%d", key, buf, buflen);
	key->ecpointQ.value = malloc(buflen);
	if (key->ecpointQ.value == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	key->ecpointQ.len = buflen;
	memcpy(key->ecpointQ.value, buf, buflen);

	/* An uncompressed ecpoint is of the form 04||x||y
	 * The 04 indicates uncompressed
	 * x and y are same size, and field_length = sizeof(x) in bits. */
	/* TODO: -DEE  support more then uncompressed */
	key->params.field_length = (ecpoint_len - 1)/2 * 8;
	if (ecpoint_data)
		free (ecpoint_data);

	return r;
}


int
sc_pkcs15_encode_pubkey_ec(sc_context_t *ctx, struct sc_pkcs15_pubkey_ec *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_ec_pointQ[C_ASN1_EC_POINTQ_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
	sc_format_asn1_entry(asn1_ec_pointQ + 0, key->ecpointQ.value, &key->ecpointQ.len, 1);

	r = sc_asn1_encode(ctx, asn1_ec_pointQ, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding failed");

	sc_log(ctx, "EC key->ecpointQ=%p:%d *buf=%p:%d", key->ecpointQ.value, key->ecpointQ.len, *buf, *buflen);
	return 0;
}


int
sc_pkcs15_encode_pubkey(sc_context_t *ctx, struct sc_pkcs15_pubkey *key,
		u8 **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_encode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_encode_pubkey_dsa(ctx, &key->u.dsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_GOSTR3410)
		return sc_pkcs15_encode_pubkey_gostr3410(ctx, &key->u.gostr3410, buf, len);
	if (key->algorithm == SC_ALGORITHM_EC)
		return sc_pkcs15_encode_pubkey_ec(ctx, &key->u.ec, buf, len);
	sc_log(ctx, "Encoding of public key type %u not supported", key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_pkcs15_decode_pubkey(sc_context_t *ctx, struct sc_pkcs15_pubkey *key,
		const u8 *buf, size_t len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_decode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_decode_pubkey_dsa(ctx, &key->u.dsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_GOSTR3410)
		return sc_pkcs15_decode_pubkey_gostr3410(ctx, &key->u.gostr3410, buf, len);
	if (key->algorithm == SC_ALGORITHM_EC)
		return sc_pkcs15_decode_pubkey_ec(ctx, &key->u.ec, buf, len);
	sc_log(ctx, "Decoding of public key type %u not supported", key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Read public key.
 */
int
sc_pkcs15_read_pubkey(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_object *obj,
		struct sc_pkcs15_pubkey **out)
{
	struct sc_context *ctx = p15card->card->ctx;
	const struct sc_pkcs15_pubkey_info *info = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	unsigned char *data = NULL;
	size_t	len;
	int	algorithm, r;

	assert(p15card != NULL && obj != NULL && out != NULL);
	LOG_FUNC_CALLED(ctx);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		algorithm = SC_ALGORITHM_RSA;
		break;
	case SC_PKCS15_TYPE_PUBKEY_DSA:
		algorithm = SC_ALGORITHM_DSA;
		break;
	case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		algorithm = SC_ALGORITHM_GOSTR3410;
		break;
	case SC_PKCS15_TYPE_PUBKEY_EC:
		algorithm = SC_ALGORITHM_EC;
		break;
	default:
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported public key type.");
	}
	info = (const struct sc_pkcs15_pubkey_info *) obj->data;

	sc_log(ctx, "Content (%p, %i)", obj->content.value, obj->content.len);
	if (obj->content.value && obj->content.len)   {
		/* public key data is present as 'direct' value of pkcs#15 object */
		data = calloc(1, obj->content.len);
		if (!data)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		memcpy(data, obj->content.value, obj->content.len);
		len = obj->content.len;
	}
	else if (p15card->card->ops->read_public_key)   {
		r = p15card->card->ops->read_public_key(p15card->card, algorithm,
				&info->path, info->key_reference, info->modulus_length,
				&data, &len);
		LOG_TEST_RET(ctx, r, "Card specific 'read-public' procedure failed.");
	}
	else if (info->path.len)   {
		r = sc_pkcs15_read_file(p15card, &info->path, &data, &len);
		LOG_TEST_RET(ctx, r, "Failed to read public key file.");
	}
	else    {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "No way to get public key");
	}

	if (!data || !len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_VALID);

	pubkey = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (pubkey == NULL) {
		free(data);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	pubkey->algorithm = algorithm;
	pubkey->data.value = data;
	pubkey->data.len = len;
	if (sc_pkcs15_decode_pubkey(ctx, pubkey, data, len)) {
		free(data);
		free(pubkey);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
	}

	*out = pubkey;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_pkcs15_dup_bignum (struct sc_pkcs15_bignum *dst, struct sc_pkcs15_bignum *src)
{
	assert(dst && src);

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
	struct sc_pkcs15_pubkey *pubkey;
	int rv = SC_SUCCESS;

	assert(prvkey && out);

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
	case SC_ALGORITHM_DSA:
		rv = sc_pkcs15_dup_bignum(&pubkey->u.dsa.pub, &prvkey->u.dsa.pub);
		if (!rv)
			rv = sc_pkcs15_dup_bignum(&pubkey->u.dsa.p, &prvkey->u.dsa.p);
		if (!rv)
			rv = sc_pkcs15_dup_bignum(&pubkey->u.dsa.q, &prvkey->u.dsa.q);
		if (!rv)
			rv = sc_pkcs15_dup_bignum(&pubkey->u.dsa.g, &prvkey->u.dsa.g);
		break;
	case SC_ALGORITHM_GOSTR3410:
		break;
	case SC_ALGORITHM_EC:
		pubkey->u.ec.ecpointQ.value = malloc(prvkey->u.ec.ecpointQ.len);
		memcpy(pubkey->u.ec.ecpointQ.value, prvkey->u.ec.ecpointQ.value, prvkey->u.ec.ecpointQ.len);
		pubkey->u.ec.ecpointQ.len = prvkey->u.ec.ecpointQ.len;
		break;
	default:
		sc_log(ctx, "Unsupported private key algorithm");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (rv)
		sc_pkcs15_free_pubkey(pubkey);
	else
		*out = pubkey;

	return rv;
}


void
sc_pkcs15_erase_pubkey(struct sc_pkcs15_pubkey *key)
{
	assert(key != NULL);
	if (key->alg_id) {
		sc_asn1_clear_algorithm_id(key->alg_id);
		free(key->alg_id);
	}
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		if (key->u.rsa.modulus.data)
			free(key->u.rsa.modulus.data);
		if (key->u.rsa.exponent.data)
			free(key->u.rsa.exponent.data);
		break;
	case SC_ALGORITHM_DSA:
		if (key->u.dsa.pub.data)
			free(key->u.dsa.pub.data);
		if (key->u.dsa.g.data)
			free(key->u.dsa.g.data);
		if (key->u.dsa.p.data)
			free(key->u.dsa.p.data);
		if (key->u.dsa.q.data)
			free(key->u.dsa.q.data);
		break;
	case SC_ALGORITHM_GOSTR3410:
		if (key->u.gostr3410.xy.data)
			free(key->u.gostr3410.xy.data);
		break;
	case SC_ALGORITHM_EC:
		if (key->u.ec.params.der.value)
			free(key->u.ec.params.der.value);
		if (key->u.ec.params.named_curve)
			free(key->u.ec.params.named_curve);
		if (key->u.ec.ecpointQ.value)
			free(key->u.ec.ecpointQ.value);
		break;
	}
	if (key->data.value)
		free(key->data.value);
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
sc_pkcs15_free_pubkey_info(sc_pkcs15_pubkey_info_t *key)
{
	if (key->subject.value)
		free(key->subject.value);
	sc_pkcs15_free_key_params(&key->params);
	free(key);
}


static int
sc_pkcs15_read_der_file(sc_context_t *ctx, char * filename,
		u8 ** buf, size_t * buflen)
{
	int r;
	int f = -1;
	size_t len;
	u8 tagbuf[16]; /* enough to read in the tag and length */
	u8 * rbuf = NULL;
	size_t rbuflen;
	const u8 * body;
	size_t bodylen;
	unsigned int cla_out, tag_out;
	*buf = NULL;

	LOG_FUNC_CALLED(ctx);
	f = open(filename, O_RDONLY);
	if (f < 0) {
		r = SC_ERROR_FILE_NOT_FOUND;
		goto out;
	}

	r = read(f, tagbuf, sizeof(tagbuf)); /* get tag and length */
	if (r < 2) {
		sc_log(ctx, "Problem with '%s'", filename);
		r =  SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto out;
	}
	len = r;
	body = tagbuf;
	if (sc_asn1_read_tag(&body, 0xfffff, &cla_out, &tag_out, &bodylen) != SC_SUCCESS) {
		sc_log(ctx, "DER problem");
		r = SC_ERROR_INVALID_ASN1_OBJECT;
		goto out;
	}

	rbuflen = body - tagbuf + bodylen;
	rbuf = malloc(rbuflen);
	if (rbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(rbuf, tagbuf, len); /* copy first or only part */
	if (rbuflen > len) {
		/* read rest of file */
		r = read(f, rbuf + len, rbuflen - len);
		if (r < (int)(rbuflen - len)) {
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			free (rbuf);
			rbuf = NULL;
			goto out;
		}
	}
	*buflen = rbuflen;
	*buf = rbuf;
	rbuf = NULL;
	r = rbuflen;
out:
	if (rbuf)
		free(rbuf);
	if (f > 0)
		close(f);

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * can be used as an SC_ASN1_CALLBACK while parsing a certificate,
 * or can be called from the sc_pkcs15_pubkey_from_spki_filename
 */
int
sc_pkcs15_pubkey_from_spki(sc_context_t *ctx, sc_pkcs15_pubkey_t ** outpubkey,
		u8 *buf, size_t buflen, int depth)
{

	int r;
	sc_pkcs15_pubkey_t * pubkey = NULL;
	sc_pkcs15_der_t pk = { NULL, 0 };
	struct sc_algorithm_id pk_alg;
	struct sc_asn1_entry asn1_pkinfo[C_ASN1_PKINFO_ATTR_SIZE];
	struct sc_asn1_entry asn1_ec_pointQ[2];

	sc_log(ctx, "sc_pkcs15_pubkey_from_spki %p:%d", buf, buflen);

	memset(&pk_alg, 0, sizeof(pk_alg));
	pubkey = calloc(1, sizeof(sc_pkcs15_pubkey_t));
	if (pubkey == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	sc_copy_asn1_entry(c_asn1_pkinfo, asn1_pkinfo);
	sc_format_asn1_entry(asn1_pkinfo + 0, &pk_alg, NULL, 0);
	sc_format_asn1_entry(asn1_pkinfo + 1, &pk.value, &pk.len, 0);

	r = sc_asn1_decode(ctx, asn1_pkinfo, buf, buflen, NULL, NULL);
	if (r < 0)
		goto err;

	pubkey->alg_id = calloc(1, sizeof(struct sc_algorithm_id));
	if (pubkey->alg_id == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(pubkey->alg_id, &pk_alg, sizeof(struct sc_algorithm_id));
	pubkey->algorithm = pk_alg.algorithm;

	sc_log(ctx, "DEE pk_alg.algorithm=%d", pk_alg.algorithm);

	/* pk.len is in bits at this point */
	switch (pk_alg.algorithm) {
	case SC_ALGORITHM_EC:
		/*
		 * For most keys, the above ASN.1 parsing of a key works, but for EC keys,
		 * the ec_pointQ in a certificate is stored in a bitstring, but
		 * in PKCS#11 it is an octet string and we just decoded its
		 * contents from the bitstring in the certificate. So we need to encode it
		 * back to an octet string so we can store it as an octet string.
		 */
		pk.len >>= 3;  /* Assume it is multiple of 8 */
/*		pubkey->u.ec.field_length = (pk.len - 1)/2 * 8;  */

		sc_copy_asn1_entry(c_asn1_ec_pointQ, asn1_ec_pointQ);
		sc_format_asn1_entry(&asn1_ec_pointQ[0], pk.value, &pk.len, 1);
		r = sc_asn1_encode(ctx, asn1_ec_pointQ, &pubkey->data.value, &pubkey->data.len);

		sc_log(ctx, "DEE r=%d data=%p:%d", r, pubkey->data.value, pubkey->data.len);
		break;
	default:
		pk.len >>= 3;	/* convert number of bits to bytes */
		pubkey->data = pk; /* save in publey */
		pk.value = NULL;
		break;
	}

	/* Now decode what every is in pk as it depends on the key algorthim */

	r = sc_pkcs15_decode_pubkey(ctx, pubkey, pubkey->data.value, pubkey->data.len);
	if (r < 0)
		goto err;

	*outpubkey = pubkey;
	pubkey = NULL;
	return 0;

err:
	if (pubkey)
		free(pubkey);
	if (pk.value)
		free(pk.value);

	LOG_TEST_RET(ctx, r, "ASN.1 parsing of  subjectPubkeyInfo failed");
	LOG_FUNC_RETURN(ctx, r);
}


int
sc_pkcs15_pubkey_from_spki_filename(sc_context_t *ctx, char * filename,
		sc_pkcs15_pubkey_t ** outpubkey)
{
	int r;
	u8 * buf = NULL;
	size_t buflen = 0;
	sc_pkcs15_pubkey_t * pubkey = NULL;
	struct sc_asn1_entry asn1_spki[] = {
		{ "PublicKeyInfo",SC_ASN1_CALLBACK, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, sc_pkcs15_pubkey_from_spki, &pubkey},
		{ NULL, 0, 0, 0, NULL, NULL } };

	*outpubkey = NULL;
	r = sc_pkcs15_read_der_file(ctx, filename, &buf, &buflen);
	if (r < 0)
		return r;

	r = sc_asn1_decode(ctx, asn1_spki, buf, buflen, NULL, NULL);

	if (buf)
		free(buf);
	*outpubkey = pubkey;
	return r;
}


static struct ec_curve_info {
	const char *name;
	const char *oid_str;
	const char *oid_encoded;
	size_t size;
} ec_curve_infos[] = {
	{"secp192r1",		"1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"prime192r1",		"1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"ansiX9p192r1",	"1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"prime256v1",		"1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"secp256r1",		"1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"ansiX9p256r1",	"1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"secp384r1",		"1.3.132.0.34", "06052B81040022", 384},
	{"prime384v1",		"1.3.132.0.34", "06052B81040022", 384},
	{"ansiX9p384r1",	"1.3.132.0.34", "06052B81040022", 384},
	{"brainpoolP192r1",	"1.3.36.3.3.2.8.1.1.3", "06092B2403030208010103", 192},
	{"brainpoolP224r1",	"1.3.36.3.3.2.8.1.1.5", "06092B2403030208010105", 224},
	{"brainpoolP256r1",	"1.3.36.3.3.2.8.1.1.7", "06092B2403030208010107", 256},
	{"brainpoolP320r1",	"1.3.36.3.3.2.8.1.1.9", "06092B2403030208010109", 320},
	{NULL, NULL, NULL, 0},
};


int
sc_pkcs15_fix_ec_parameters(struct sc_context *ctx, struct sc_pkcs15_ec_parameters *ecparams)
{
	int rv, ii;

	LOG_FUNC_CALLED(ctx);

	/* In PKCS#11 EC parameters arrives in DER encoded form */
	if (ecparams->der.value && ecparams->der.len)   {
		for (ii=0; ec_curve_infos[ii].name; ii++)   {
			struct sc_object_id id;
			unsigned char *buf = NULL;
			size_t len = 0;

			sc_format_oid(&id, ec_curve_infos[ii].oid_str);
			sc_encode_oid (ctx, &id, &buf, &len);

			if (ecparams->der.len == len && !memcmp(ecparams->der.value, buf, len))   {
				free(buf);
				break;
			}

			free(buf);
		}

		/* TODO: support of explicit EC parameters form */
		if (!ec_curve_infos[ii].name)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported named curve");

		sc_log(ctx, "Found known curve '%s'", ec_curve_infos[ii].name);
		if (!ecparams->named_curve)   {
			ecparams->named_curve = strdup(ec_curve_infos[ii].name);
			if (!ecparams->named_curve)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

			sc_log(ctx, "Curve name: '%s'", ecparams->named_curve);
		}

		if (!sc_valid_oid(&ecparams->id))
			sc_format_oid(&ecparams->id, ec_curve_infos[ii].oid_str);

		ecparams->field_length = ec_curve_infos[ii].size;
		sc_log(ctx, "Curve length %i", ecparams->field_length);
	}
	else if (ecparams->named_curve)   {	/* it can be name of curve or OID in ASCII form */
		for (ii=0; ec_curve_infos[ii].name; ii++)   {
			if (!strcmp(ec_curve_infos[ii].name, ecparams->named_curve))
				break;
			if (!strcmp(ec_curve_infos[ii].oid_str, ecparams->named_curve))
				break;
		}
		if (!ec_curve_infos[ii].name)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported named curve");

		rv = sc_format_oid(&ecparams->id, ec_curve_infos[ii].oid_str);
		LOG_TEST_RET(ctx, rv, "Invalid OID format");

		ecparams->field_length = ec_curve_infos[ii].size;

		if (!ecparams->der.value || !ecparams->der.len)   {
			rv = sc_encode_oid (ctx, &ecparams->id, &ecparams->der.value, &ecparams->der.len);
			LOG_TEST_RET(ctx, rv, "Cannot encode object ID");
		}
	}
	else if (sc_valid_oid(&ecparams->id))  {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_IMPLEMENTED, "EC parameters has to be presented as a named curve or explicit data");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_pkcs15_convert_pubkey(struct sc_pkcs15_pubkey *pkcs15_key, void *evp_key)
{
#ifdef ENABLE_OPENSSL
	EVP_PKEY *pk = (EVP_PKEY *)evp_key;

	switch (pk->type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_pubkey_rsa *dst = &pkcs15_key->u.rsa;
		RSA *src = EVP_PKEY_get1_RSA(pk);

		pkcs15_key->algorithm = SC_ALGORITHM_RSA;
		if (!sc_pkcs15_convert_bignum(&dst->modulus, src->n) || !sc_pkcs15_convert_bignum(&dst->exponent, src->e))
			return SC_ERROR_INVALID_DATA;
		RSA_free(src);
		break;
		}
	case EVP_PKEY_DSA: {
		struct sc_pkcs15_pubkey_dsa *dst = &pkcs15_key->u.dsa;
		DSA *src = EVP_PKEY_get1_DSA(pk);

		pkcs15_key->algorithm = SC_ALGORITHM_DSA;
		sc_pkcs15_convert_bignum(&dst->pub, src->pub_key);
		sc_pkcs15_convert_bignum(&dst->p, src->p);
		sc_pkcs15_convert_bignum(&dst->q, src->q);
		sc_pkcs15_convert_bignum(&dst->g, src->g);
		DSA_free(src);
		break;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
	case NID_id_GostR3410_2001: {
		struct sc_pkcs15_pubkey_gostr3410 *dst = &pkcs15_key->u.gostr3410;
		EC_KEY *eckey = EVP_PKEY_get0(pk);
		const EC_POINT *point;
		BIGNUM *X, *Y;
		int r = 0;

		assert(eckey);
		point = EC_KEY_get0_public_key(eckey);
		if (!point)
			return SC_ERROR_INTERNAL;
		X = BN_new();
		Y = BN_new();
		if (X && Y && EC_KEY_get0_group(eckey))
			r = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(eckey),
					point, X, Y, NULL);
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
		if (r != 1)
			return SC_ERROR_INTERNAL;
		break;
		}
	case EVP_PKEY_EC: {
		struct sc_pkcs15_pubkey_ec *dst = &pkcs15_key->u.ec;
		EC_KEY *src = NULL;
		const EC_GROUP *grp = NULL;
		unsigned char buf[255];
		size_t buflen = 255;
		int nid;

		src = EVP_PKEY_get0(pk);
		assert(src);
		assert(EC_KEY_get0_public_key(src));

		pkcs15_key->algorithm = SC_ALGORITHM_EC;
		grp = EC_KEY_get0_group(src);
		if(grp == 0)
			return SC_ERROR_INCOMPATIBLE_KEY;

		/* Decode EC_POINT from a octet string */
		buflen = EC_POINT_point2oct(grp, (const EC_POINT *) EC_KEY_get0_public_key(src),
				POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);

		/* get curve name */
		nid = EC_GROUP_get_curve_name(grp);
		if(nid != 0) {
			const char *name = OBJ_nid2sn(nid);
			if(sizeof(name) > 0)
				dst->params.named_curve = strdup(name);
		}

		/* copy the public key */
		if (buflen > 0) {
			dst->ecpointQ.value = malloc(buflen);
			memcpy(dst->ecpointQ.value, buf, buflen);
			dst->ecpointQ.len = buflen;
			/* calculate the field length */
			dst->params.field_length = (buflen - 1) / 2 * 8;
		}
		else
			return SC_ERROR_INCOMPATIBLE_KEY;

		break;
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC) */
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	return SC_SUCCESS;
#else
	return SC_ERROR_NOT_IMPLEMENTED;
#endif
}

