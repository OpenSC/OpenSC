/*
 * pkcs15-prkey.c: PKCS #15 private key functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"
#include "common/compat_strlcpy.h"

#ifdef ENABLE_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	#ifndef OPENSSL_NO_EC
	#include <openssl/ec.h>
	#endif
#endif
#endif

/*
 * in src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as 8
 */
#define C_ASN1_SUPPORTED_ALGORITHMS_SIZE (SC_MAX_SUPPORTED_ALGORITHMS + 1)
static const struct sc_asn1_entry c_asn1_supported_algorithms[C_ASN1_SUPPORTED_ALGORITHMS_SIZE] = {
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algorithmReference", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_KEY_ATTR_SIZE 7
static const struct sc_asn1_entry c_asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
/* Absent in PKCS#15-v1.1 but present in ISO 7816-15(2004-01-15)*/
	{ "algReference", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_PRKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_com_prkey_attr[C_ASN1_COM_PRKEY_ATTR_SIZE] = {
	{ "subjectName", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS,
		SC_ASN1_EMPTY_ALLOWED | SC_ASN1_ALLOC | SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_RSAKEY_ATTR_SIZE 4
static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
	{ "value",         SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "modulusLength", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PRK_RSA_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_prk_rsa_attr[C_ASN1_PRK_RSA_ATTR_SIZE] = {
	{ "privateRSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_GOSTR3410KEY_ATTR_SIZE 5
static const struct sc_asn1_entry c_asn1_gostr3410key_attr[C_ASN1_GOSTR3410KEY_ATTR_SIZE] = {
	{ "value",         SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "params_r3410",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "params_r3411",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "params_28147",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PRK_GOSTR3410_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_prk_gostr3410_attr[C_ASN1_PRK_GOSTR3410_ATTR_SIZE] = {
	{ "privateGOSTR3410KeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_DSAKEY_I_P_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_dsakey_i_p_attr[C_ASN1_DSAKEY_I_P_ATTR_SIZE] = {
	{ "path",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_DSAKEY_VALUE_ATTR_SIZE 3
static const struct sc_asn1_entry c_asn1_dsakey_value_attr[C_ASN1_DSAKEY_VALUE_ATTR_SIZE] = {
	{ "path",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "pathProtected",SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_DSAKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE] = {
	{ "value",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PRK_DSA_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_prk_dsa_attr[C_ASN1_PRK_DSA_ATTR_SIZE] = {
	{ "privateDSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * The element fieldSize is a proprietary extension to ISO 7816-15, providing to the middleware
 * the size of the underlying ECC field. This value is required for determine a proper size for
 * buffer allocations. The field follows the definition for modulusLength in RSA keys
 */
#define C_ASN1_ECCKEY_ATTR 4
static const struct sc_asn1_entry c_asn1_ecckey_attr[C_ASN1_ECCKEY_ATTR] = {
	{ "value",	   SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "fieldSize",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PRK_ECC_ATTR 2
static const struct sc_asn1_entry c_asn1_prk_ecc_attr[C_ASN1_PRK_ECC_ATTR] = {
	{ "privateECCKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PRKEY_SIZE 5
static const struct sc_asn1_entry c_asn1_prkey[C_ASN1_PRKEY_SIZE] = {
	{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "privateECCKey", SC_ASN1_PKCS15_OBJECT,  0 | SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "privateDSAKey", SC_ASN1_PKCS15_OBJECT,  2 | SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "privateGOSTR3410Key", SC_ASN1_PKCS15_OBJECT, 4 | SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
	sc_context_t *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info info;
	int r, i, gostr3410_params[3];
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_prkey_attr[C_ASN1_COM_PRKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_rsa_attr[C_ASN1_PRK_RSA_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_dsa_attr[C_ASN1_PRK_DSA_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_i_p_attr[C_ASN1_DSAKEY_I_P_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_value_attr[C_ASN1_DSAKEY_VALUE_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOSTR3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_gostr3410_attr[C_ASN1_PRK_GOSTR3410_ATTR_SIZE];
	struct sc_asn1_entry asn1_ecckey_attr[C_ASN1_ECCKEY_ATTR];
	struct sc_asn1_entry asn1_prk_ecc_attr[C_ASN1_PRK_ECC_ATTR];
	struct sc_asn1_entry asn1_prkey[C_ASN1_PRKEY_SIZE];
	struct sc_asn1_entry asn1_supported_algorithms[C_ASN1_SUPPORTED_ALGORITHMS_SIZE];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = {obj, asn1_com_key_attr, asn1_com_prkey_attr, asn1_prk_rsa_attr};
	struct sc_asn1_pkcs15_object dsa_prkey_obj = {obj, asn1_com_key_attr, asn1_com_prkey_attr, asn1_prk_dsa_attr};
	struct sc_asn1_pkcs15_object gostr3410_prkey_obj = {obj, asn1_com_key_attr, asn1_com_prkey_attr, asn1_prk_gostr3410_attr};
	struct sc_asn1_pkcs15_object ecc_prkey_obj = { obj, asn1_com_key_attr, asn1_com_prkey_attr, asn1_prk_ecc_attr };

	sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr, asn1_dsakey_i_p_attr);
	sc_copy_asn1_entry(c_asn1_prk_gostr3410_attr, asn1_prk_gostr3410_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_prk_ecc_attr, asn1_prk_ecc_attr);
	sc_copy_asn1_entry(c_asn1_ecckey_attr, asn1_ecckey_attr);

	sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 1, &ecc_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 2, &dsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 3, &gostr3410_prkey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_gostr3410_attr + 0, asn1_gostr3410key_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_ecc_attr + 0, asn1_ecckey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_dsakey_attr + 0, asn1_dsakey_value_attr, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_value_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_value_attr + 1, asn1_dsakey_i_p_attr, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_i_p_attr + 0, &info.path, NULL, 0);

	sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 1, &gostr3410_params[0], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 2, &gostr3410_params[1], NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410key_attr + 3, &gostr3410_params[2], NULL, 0);

	sc_format_asn1_entry(asn1_ecckey_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_ecckey_attr + 1, &info.field_length, NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

	for (i=0; i<SC_MAX_SUPPORTED_ALGORITHMS && (asn1_supported_algorithms + i)->name; i++)
		sc_format_asn1_entry(asn1_supported_algorithms + i, &info.algo_refs[i], NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 5, asn1_supported_algorithms, NULL, 0);

	sc_format_asn1_entry(asn1_com_prkey_attr + 0, &info.subject.value, &info.subject.len, 0);

	/* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.key_reference = -1;
	info.native = 1;
	memset(gostr3410_params, 0, sizeof(gostr3410_params));

	r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "PrKey DF ASN.1 decoding failed");
	if (asn1_prkey[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
	}
	else if (asn1_prkey[1].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_EC;
	}
	else if (asn1_prkey[2].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_DSA;
		/* If the value was indirect-protected, mark the path */
		if (asn1_dsakey_i_p_attr[0].flags & SC_ASN1_PRESENT)
			info.path.type = SC_PATH_TYPE_PATH_PROT;
	}
	else if (asn1_prkey[3].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
		assert(info.modulus_length == 0);
		info.modulus_length = SC_PKCS15_GOSTR3410_KEYSIZE;
		assert(info.params.len == 0);
		info.params.len = sizeof(struct sc_pkcs15_keyinfo_gostparams);
		info.params.data = malloc(info.params.len);
		if (info.params.data == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		assert(sizeof(*keyinfo_gostparams) == info.params.len);
		keyinfo_gostparams = info.params.data;
		keyinfo_gostparams->gostr3410 = gostr3410_params[0];
		keyinfo_gostparams->gostr3411 = gostr3410_params[1];
		keyinfo_gostparams->gost28147 = gostr3410_params[2];
	}
	else {
		sc_log(ctx, "Neither RSA or DSA or GOSTR3410 or ECC key in PrKDF entry.");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
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
	sc_log(ctx, "PrivKey path '%s'", sc_print_path(&info.path));

	/* OpenSC 0.11.4 and older encoded "keyReference" as a negative value.
	 * Fixed in 0.11.5 we need to add a hack, so old cards continue to work. */
	if (info.key_reference < -1)
		info.key_reference += 256;

	/* Check the auth_id - if not present, try and find it in access rules */
	if ((obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) && (obj->auth_id.len == 0)) {
		sc_log(ctx, "Private key %s has no auth ID - checking AccessControlRules",
				sc_pkcs15_print_id(&info.id));

		/* Search in the access_rules for an appropriate auth ID */
		for (i = 0; i < SC_PKCS15_MAX_ACCESS_RULES; i++) {
			/* If access_mode is one of the private key usage modes */
			if (obj->access_rules[i].access_mode &
					(SC_PKCS15_ACCESS_RULE_MODE_EXECUTE |
					 SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS |
					 SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT |
					 SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH)) {
				if (obj->access_rules[i].auth_id.len != 0) {
					/* Found an auth ID to use for private key access */
					obj->auth_id = obj->access_rules[i].auth_id;
					sc_log(ctx, "Auth ID found - %s",
						 sc_pkcs15_print_id(&obj->auth_id));
					break;
				}
			}
		}

		/* No auth ID found */
		if (i == SC_PKCS15_MAX_ACCESS_RULES)
			sc_log(ctx, "Warning: No auth ID found");
	}

	obj->data = malloc(sizeof(info));
	if (obj->data == NULL) {
		sc_pkcs15_free_key_params(&info.params);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(obj->data, &info, sizeof(info));

	sc_log(ctx, "Key Subject %s", sc_dump_hex(info.subject.value, info.subject.len));
	sc_log(ctx, "Key path %s", sc_print_path(&info.path));
	return 0;
}

int sc_pkcs15_encode_prkdf_entry(sc_context_t *ctx, const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_prkey_attr[C_ASN1_COM_PRKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_rsakey_attr[C_ASN1_RSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_rsa_attr[C_ASN1_PRK_RSA_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_attr[C_ASN1_DSAKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_dsa_attr[C_ASN1_PRK_DSA_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_value_attr[C_ASN1_DSAKEY_VALUE_ATTR_SIZE];
	struct sc_asn1_entry asn1_dsakey_i_p_attr[C_ASN1_DSAKEY_I_P_ATTR_SIZE];
	struct sc_asn1_entry asn1_gostr3410key_attr[C_ASN1_GOSTR3410KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_prk_gostr3410_attr[C_ASN1_PRK_GOSTR3410_ATTR_SIZE];
	struct sc_asn1_entry asn1_ecckey_attr[C_ASN1_ECCKEY_ATTR];
	struct sc_asn1_entry asn1_prk_ecc_attr[C_ASN1_PRK_ECC_ATTR];
	struct sc_asn1_entry asn1_prkey[C_ASN1_PRKEY_SIZE];
	struct sc_asn1_entry asn1_supported_algorithms[C_ASN1_SUPPORTED_ALGORITHMS_SIZE];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = {
		(struct sc_pkcs15_object *) obj, asn1_com_key_attr,
		asn1_com_prkey_attr, asn1_prk_rsa_attr
	};
	struct sc_asn1_pkcs15_object dsa_prkey_obj = {
		(struct sc_pkcs15_object *) obj, asn1_com_key_attr,
		asn1_com_prkey_attr, asn1_prk_dsa_attr
	};
	struct sc_asn1_pkcs15_object gostr3410_prkey_obj = {
		(struct sc_pkcs15_object *) obj,
		asn1_com_key_attr, asn1_com_prkey_attr,
		asn1_prk_gostr3410_attr
	};
	struct sc_asn1_pkcs15_object ecc_prkey_obj = {
		(struct sc_pkcs15_object *) obj,
		asn1_com_key_attr, asn1_com_prkey_attr,
		asn1_prk_ecc_attr
	};
	struct sc_pkcs15_prkey_info *prkey = (struct sc_pkcs15_prkey_info *) obj->data;
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	int r, i;
	size_t af_len, usage_len;

	sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr, asn1_dsakey_i_p_attr);
	sc_copy_asn1_entry(c_asn1_prk_gostr3410_attr, asn1_prk_gostr3410_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);
	sc_copy_asn1_entry(c_asn1_prk_ecc_attr, asn1_prk_ecc_attr);
	sc_copy_asn1_entry(c_asn1_ecckey_attr, asn1_ecckey_attr);

	sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 0, &prkey->path, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 1, &prkey->modulus_length, NULL, 1);
		break;
	case SC_PKCS15_TYPE_PRKEY_EC:
		sc_format_asn1_entry(asn1_prkey + 1, &ecc_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_ecc_attr + 0, asn1_ecckey_attr, NULL, 1);
		sc_format_asn1_entry(asn1_ecckey_attr + 0, &prkey->path, NULL, 1);
		sc_format_asn1_entry(asn1_ecckey_attr + 1, &prkey->field_length, NULL, 1);
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		sc_format_asn1_entry(asn1_prkey + 2, &dsa_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_value_attr, NULL, 1);
		if (prkey->path.type != SC_PATH_TYPE_PATH_PROT) {
			/* indirect: just add the path */
			sc_format_asn1_entry(asn1_dsakey_value_attr + 0, &prkey->path, NULL, 1);
		}
		else {
			/* indirect-protected */
			sc_format_asn1_entry(asn1_dsakey_value_attr + 1, asn1_dsakey_i_p_attr, NULL, 1);
			sc_format_asn1_entry(asn1_dsakey_i_p_attr + 0, &prkey->path, NULL, 1);
		}
		break;
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		sc_format_asn1_entry(asn1_prkey + 3, &gostr3410_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_gostr3410_attr + 0, asn1_gostr3410key_attr, NULL, 1);
		sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &prkey->path, NULL, 1);
		if (prkey->params.len == sizeof(*keyinfo_gostparams))   {
			keyinfo_gostparams = prkey->params.data;
			sc_format_asn1_entry(asn1_gostr3410key_attr + 1, &keyinfo_gostparams->gostr3410, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 2, &keyinfo_gostparams->gostr3411, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 3, &keyinfo_gostparams->gost28147, NULL, 1);
		}
		break;
	default:
		sc_log(ctx, "Invalid private key type: %X", obj->type);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		break;
	}
	sc_format_asn1_entry(asn1_com_key_attr + 0, &prkey->id, NULL, 1);
	usage_len = sizeof(prkey->usage);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &prkey->usage, &usage_len, 1);
	if (prkey->native == 0)
		sc_format_asn1_entry(asn1_com_key_attr + 2, &prkey->native, NULL, 1);
	if (prkey->access_flags) {
		af_len = sizeof(prkey->access_flags);
		sc_format_asn1_entry(asn1_com_key_attr + 3, &prkey->access_flags, &af_len, 1);
	}
	if (prkey->key_reference >= 0)
		sc_format_asn1_entry(asn1_com_key_attr + 4, &prkey->key_reference, NULL, 1);

	for (i=0; i<SC_MAX_SUPPORTED_ALGORITHMS && prkey->algo_refs[i]; i++)   {
		sc_log(ctx, "Encode algorithm(%i) %i", i, prkey->algo_refs[i]);
		sc_format_asn1_entry(asn1_supported_algorithms + i, &prkey->algo_refs[i], NULL, 1);
	}
	sc_format_asn1_entry(asn1_com_key_attr + 5, asn1_supported_algorithms, NULL, prkey->algo_refs[0] != 0);

	if (prkey->subject.value && prkey->subject.len)
		sc_format_asn1_entry(asn1_com_prkey_attr + 0, prkey->subject.value, &prkey->subject.len, 1);
	else
		memset(asn1_com_prkey_attr, 0, sizeof(asn1_com_prkey_attr));

	r = sc_asn1_encode(ctx, asn1_prkey, buf, buflen);

	sc_log(ctx, "Key path %s", sc_print_path(&prkey->path));
	return r;
}

int
sc_pkcs15_prkey_attrs_from_cert(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *cert_object,
		struct sc_pkcs15_object **out_key_object)
{
	struct sc_context *ctx = p15card->card->ctx;
#ifdef ENABLE_OPENSSL
	struct sc_pkcs15_object *key_object = NULL;
	struct sc_pkcs15_prkey_info *key_info = NULL;
	X509 *x = NULL;
	BIO *mem = NULL;
	unsigned char *buff = NULL, *ptr = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (out_key_object)
		*out_key_object = NULL;

	rv = sc_pkcs15_find_prkey_by_id(p15card, &((struct sc_pkcs15_cert_info *)cert_object->data)->id, &key_object);
	if (rv == SC_ERROR_OBJECT_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, rv, "Find private key error");

	key_info = (struct sc_pkcs15_prkey_info *) key_object->data;

	ERR_load_ERR_strings();
	ERR_load_crypto_strings();

	sc_log(ctx, "CertValue(%i) %p", cert_object->content.len, cert_object->content.value);
	mem = BIO_new_mem_buf(cert_object->content.value, cert_object->content.len);
	if (!mem)
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "MEM buffer allocation error");

	x = d2i_X509_bio(mem, NULL);
	if (!x)
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "x509 parse error");

	buff = OPENSSL_malloc(i2d_X509(x,NULL) + EVP_MAX_MD_SIZE);
	if (!buff)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "OpenSSL allocation error");

	ptr = buff;
	rv = i2d_X509_NAME(X509_get_subject_name(x), &ptr);
	if (rv <= 0)
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "Get subject name error");

	key_info->subject.value = malloc(rv);
	if (!key_info->subject.value)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Subject allocation error");

	memcpy(key_info->subject.value, buff, rv);
	key_info->subject.len = rv;

	strlcpy(key_object->label, cert_object->label, sizeof(key_object->label));

	rv = 0;

	if (x)
		X509_free(x);
	if (mem)
		BIO_free(mem);
	if (buff)
		OPENSSL_free(buff);

	ERR_clear_error();
	ERR_free_strings();

	if (out_key_object)
		*out_key_object = key_object;

	sc_log(ctx, "Subject %s", sc_dump_hex(key_info->subject.value, key_info->subject.len));
	LOG_FUNC_RETURN(ctx, rv);
#else
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
#endif
}


void
sc_pkcs15_free_prkey(struct sc_pkcs15_prkey *key)
{
	if (!key)
		return;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		free(key->u.rsa.modulus.data);
		free(key->u.rsa.exponent.data);
		free(key->u.rsa.d.data);
		free(key->u.rsa.p.data);
		free(key->u.rsa.q.data);
		free(key->u.rsa.iqmp.data);
		free(key->u.rsa.dmp1.data);
		free(key->u.rsa.dmq1.data);
		break;
	case SC_ALGORITHM_DSA:
		free(key->u.dsa.pub.data);
		free(key->u.dsa.p.data);
		free(key->u.dsa.q.data);
		free(key->u.dsa.g.data);
		free(key->u.dsa.priv.data);
		break;
	case SC_ALGORITHM_GOSTR3410:
		assert(key->u.gostr3410.d.data);
		free(key->u.gostr3410.d.data);
		break;
	case SC_ALGORITHM_EC:
		if (key->u.ec.params.der.value)
			free(key->u.ec.params.der.value);
		if (key->u.ec.params.named_curve)
			free(key->u.ec.params.named_curve);
		if (key->u.ec.privateD.data)
			free(key->u.ec.privateD.data);
		if (key->u.ec.ecpointQ.value)
			free(key->u.ec.ecpointQ.value);
		break;
	}
}


void sc_pkcs15_free_prkey_info(sc_pkcs15_prkey_info_t *key)
{
	if (key->subject.value)
		free(key->subject.value);
	if (key->cmap_record.guid)
		free(key->cmap_record.guid);

	sc_pkcs15_free_key_params(&key->params);

	free(key);
}

int
sc_pkcs15_convert_bignum(sc_pkcs15_bignum_t *dst, const void *src)
{
#ifdef ENABLE_OPENSSL
	const BIGNUM *bn = (const BIGNUM *)src;

	if (bn == 0)
		return 0;
	dst->len = BN_num_bytes(bn);
	dst->data = malloc(dst->len);
	BN_bn2bin(bn, dst->data);
	return 1;
#else
	return 0;
#endif
}

int
sc_pkcs15_convert_prkey(struct sc_pkcs15_prkey *pkcs15_key, void *evp_key)
{
#ifdef ENABLE_OPENSSL
	EVP_PKEY *pk = (EVP_PKEY *)evp_key;

	switch (pk->type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_prkey_rsa *dst = &pkcs15_key->u.rsa;
		RSA *src = EVP_PKEY_get1_RSA(pk);

		pkcs15_key->algorithm = SC_ALGORITHM_RSA;
		if (!sc_pkcs15_convert_bignum(&dst->modulus, src->n)
		 || !sc_pkcs15_convert_bignum(&dst->exponent, src->e)
		 || !sc_pkcs15_convert_bignum(&dst->d, src->d)
		 || !sc_pkcs15_convert_bignum(&dst->p, src->p)
		 || !sc_pkcs15_convert_bignum(&dst->q, src->q))
			return SC_ERROR_NOT_SUPPORTED;
		if (src->iqmp && src->dmp1 && src->dmq1) {
			sc_pkcs15_convert_bignum(&dst->iqmp, src->iqmp);
			sc_pkcs15_convert_bignum(&dst->dmp1, src->dmp1);
			sc_pkcs15_convert_bignum(&dst->dmq1, src->dmq1);
		}
		RSA_free(src);
		break;
		}
	case EVP_PKEY_DSA: {
		struct sc_pkcs15_prkey_dsa *dst = &pkcs15_key->u.dsa;
		DSA *src = EVP_PKEY_get1_DSA(pk);

		pkcs15_key->algorithm = SC_ALGORITHM_DSA;
		sc_pkcs15_convert_bignum(&dst->pub, src->pub_key);
		sc_pkcs15_convert_bignum(&dst->p, src->p);
		sc_pkcs15_convert_bignum(&dst->q, src->q);
		sc_pkcs15_convert_bignum(&dst->g, src->g);
		sc_pkcs15_convert_bignum(&dst->priv, src->priv_key);
		DSA_free(src);
		break;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
	case NID_id_GostR3410_2001: {
		struct sc_pkcs15_prkey_gostr3410 *dst = &pkcs15_key->u.gostr3410;
		EC_KEY *src = EVP_PKEY_get0(pk);

		assert(src);
		pkcs15_key->algorithm = SC_ALGORITHM_GOSTR3410;
		assert(EC_KEY_get0_private_key(src));
		sc_pkcs15_convert_bignum(&dst->d, EC_KEY_get0_private_key(src));
		break;
		}
	case EVP_PKEY_EC: {
		struct sc_pkcs15_prkey_ec *dst = &pkcs15_key->u.ec;
		EC_KEY *src = NULL;
		const EC_GROUP *grp = NULL;
		unsigned char buf[255];
		size_t buflen = 255;
		int nid;

		src = EVP_PKEY_get0(pk);
		assert(src);
		assert(EC_KEY_get0_private_key(src));
		assert(EC_KEY_get0_public_key(src));

		pkcs15_key->algorithm = SC_ALGORITHM_EC;

		if (!sc_pkcs15_convert_bignum(&dst->privateD, EC_KEY_get0_private_key(src)))
			return SC_ERROR_INCOMPATIBLE_KEY;

		grp = EC_KEY_get0_group(src);
		if(grp == 0)
			return SC_ERROR_INCOMPATIBLE_KEY;

		/* get curve name */
		nid = EC_GROUP_get_curve_name(grp);
		if(nid != 0)
			dst->params.named_curve = strdup(OBJ_nid2sn(nid));

		/* Decode EC_POINT from a octet string */
		buflen = EC_POINT_point2oct(grp, (const EC_POINT *) EC_KEY_get0_public_key(src),
				POINT_CONVERSION_UNCOMPRESSED, buf, buflen, NULL);
		if (!buflen)
			return SC_ERROR_INCOMPATIBLE_KEY;

		/* copy the public key */
		dst->ecpointQ.value = malloc(buflen);
		memcpy(dst->ecpointQ.value, buf, buflen);
		dst->ecpointQ.len = buflen;

		/*
		 * In OpenSC the field_length is in bits. Not all curves are a mutiple of 8.
		 * EC_POINT_point2oct handles this and returns octstrings that can handle
		 * these curves. Get real field_length from OpenSSL. 
		 */
		dst->params.field_length = EC_GROUP_get_degree(grp);

		/* Octetstring may need leading zeros if BN is to short */
		if (dst->privateD.len < (dst->params.field_length + 7) / 8)   {
			size_t d = (dst->params.field_length + 7) / 8 - dst->privateD.len;

			dst->privateD.data = realloc(dst->privateD.data, dst->privateD.len + d);
			if (!dst->privateD.data)
				return SC_ERROR_OUT_OF_MEMORY;

			memmove(dst->privateD.data + d, dst->privateD.data, dst->privateD.len);
			memset(dst->privateD.data, 0, d);

			dst->privateD.len += d;
		}

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
