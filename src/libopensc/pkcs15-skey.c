/*
 * pkcs15-skey.c: PKCS #15 secret key functions
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2011  Viktor Tarasov <viktor.tarasov@opentrust.com>
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
#include "pkcs11/pkcs11.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

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
	{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL},
	{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL},
	{ "native",      SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL},
	{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "algReference", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_SKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_com_skey_attr[C_ASN1_COM_SKEY_ATTR_SIZE] = {
	{ "keyLen",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_SKEY_GENERIC_VALUE_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_generic_skey_value_attr[C_ASN1_COM_SKEY_GENERIC_VALUE_ATTR_SIZE] = {
	{ "path",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_SKEY_GENERIC_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_generic_skey_attr[C_ASN1_COM_SKEY_GENERIC_ATTR_SIZE] = {
	{ "secretKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_SKEY_CHOICE_SIZE 5
static const struct sc_asn1_entry c_asn1_skey_choice[C_ASN1_SKEY_CHOICE_SIZE] = {
	{ "genericSecretKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "desKey",	SC_ASN1_PKCS15_OBJECT, SC_ASN1_CTX | 2 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "des2Key",	SC_ASN1_PKCS15_OBJECT, SC_ASN1_CTX | 3 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "des3Key",	SC_ASN1_PKCS15_OBJECT, SC_ASN1_CTX | 4 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_SKEY_SIZE 2
static const struct sc_asn1_entry c_asn1_skey[C_ASN1_SKEY_SIZE] = {
	{ "secretKey",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


int
sc_pkcs15_decode_skdf_entry(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj,
		const u8 ** buf, size_t *buflen)
{
        struct sc_context *ctx = p15card->card->ctx;
        struct sc_pkcs15_skey_info info;
	int r, i, ii;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_skey_attr[C_ASN1_COM_SKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_generic_skey_attr[C_ASN1_COM_SKEY_GENERIC_ATTR_SIZE];
	struct sc_asn1_entry asn1_generic_skey_value_attr[C_ASN1_COM_SKEY_GENERIC_VALUE_ATTR_SIZE];
	struct sc_asn1_entry asn1_skey_choice[C_ASN1_SKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_skey[C_ASN1_SKEY_SIZE];
	struct sc_asn1_entry asn1_supported_algorithms[C_ASN1_SUPPORTED_ALGORITHMS_SIZE];
	struct sc_asn1_pkcs15_object skey_des_obj = {
		obj, asn1_com_key_attr, asn1_com_skey_attr, asn1_generic_skey_attr
	};
	static const struct sc_object_id id_aes = { { 2, 16, 840, 1, 101, 3, 4, 1, -1 } };
	struct sc_object_id temp_oid;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_ASN1);

	sc_copy_asn1_entry(c_asn1_skey, asn1_skey);
	sc_copy_asn1_entry(c_asn1_skey_choice, asn1_skey_choice);
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);
	sc_copy_asn1_entry(c_asn1_com_skey_attr, asn1_com_skey_attr);
	sc_copy_asn1_entry(c_asn1_generic_skey_attr, asn1_generic_skey_attr);
	sc_copy_asn1_entry(c_asn1_generic_skey_value_attr, asn1_generic_skey_value_attr);

	sc_format_asn1_entry(asn1_skey + 0, asn1_skey_choice, NULL, 0);
	sc_format_asn1_entry(asn1_skey_choice + 0, &skey_des_obj, NULL, 0);
	sc_format_asn1_entry(asn1_skey_choice + 1, &skey_des_obj, NULL, 0);
	sc_format_asn1_entry(asn1_skey_choice + 2, &skey_des_obj, NULL, 0);
	sc_format_asn1_entry(asn1_skey_choice + 3, &skey_des_obj, NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);
	for (i=0; i<SC_MAX_SUPPORTED_ALGORITHMS && (asn1_supported_algorithms + i)->name; i++)
		sc_format_asn1_entry(asn1_supported_algorithms + i, &info.algo_refs[i], NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 5, asn1_supported_algorithms, NULL, 0);

	sc_format_asn1_entry(asn1_com_skey_attr + 0, &info.value_len, NULL, 0);

	sc_format_asn1_entry(asn1_generic_skey_attr + 0, asn1_generic_skey_value_attr, NULL, 0);
	sc_format_asn1_entry(asn1_generic_skey_value_attr + 0, &info.path, NULL, 0);

        /* Fill in defaults */
	memset(&info, 0, sizeof(info));
	info.native = 1;

	r = sc_asn1_decode(ctx, asn1_skey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "ASN.1 decoding failed");
	if (asn1_skey_choice[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_SKEY_GENERIC;

		/* Check key type. framework-pkcs15 recognizes one type per key, and AES is the only algorithm supported for
		* SKEY_GENERIC type keys, so just check if this key is AES compatible. */

		for (i = 0; i < SC_MAX_SUPPORTED_ALGORITHMS && info.algo_refs[i] != 0 && info.key_type == 0; i++) {
			for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo != 0; ii++) {
				if (info.algo_refs[i] == p15card->tokeninfo->supported_algos[ii].reference) {
					temp_oid = p15card->tokeninfo->supported_algos[ii].algo_id;
					temp_oid.value[8] = -1; /* strip off AES subtype octet*/

					if (sc_compare_oid(&id_aes, &temp_oid)) {
						info.key_type = CKK_AES;
						break;
					}
				}
			}
		}
	}
	else if (asn1_skey_choice[1].flags & SC_ASN1_PRESENT)
		obj->type = SC_PKCS15_TYPE_SKEY_DES;
	else if (asn1_skey_choice[2].flags & SC_ASN1_PRESENT)
		obj->type = SC_PKCS15_TYPE_SKEY_2DES;
	else if (asn1_skey_choice[3].flags & SC_ASN1_PRESENT)
		obj->type = SC_PKCS15_TYPE_SKEY_3DES;
	else
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported secret key type");

	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int sc_pkcs15_encode_skdf_entry(struct sc_context *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_pkcs15_skey_info *skey = (struct sc_pkcs15_skey_info *) obj->data;
	int r, i;
	size_t usage_len = sizeof(skey->usage);
	size_t af_len = sizeof(skey->access_flags);
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_skey_attr[C_ASN1_COM_SKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_generic_skey_attr[C_ASN1_COM_SKEY_GENERIC_ATTR_SIZE];
	struct sc_asn1_entry asn1_generic_skey_value_attr[C_ASN1_COM_SKEY_GENERIC_VALUE_ATTR_SIZE];
	struct sc_asn1_entry asn1_skey_choice[C_ASN1_SKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_skey[C_ASN1_SKEY_SIZE];
	struct sc_asn1_entry asn1_supported_algorithms[C_ASN1_SUPPORTED_ALGORITHMS_SIZE];
	struct sc_asn1_pkcs15_object skey_obj = {
		(struct sc_pkcs15_object *) obj, asn1_com_key_attr,
		asn1_com_skey_attr, asn1_generic_skey_attr
	};

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_ASN1);

	sc_copy_asn1_entry(c_asn1_skey, asn1_skey);
	sc_copy_asn1_entry(c_asn1_skey_choice, asn1_skey_choice);
	sc_copy_asn1_entry(c_asn1_supported_algorithms, asn1_supported_algorithms);

	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);
	sc_copy_asn1_entry(c_asn1_com_skey_attr, asn1_com_skey_attr);
	sc_copy_asn1_entry(c_asn1_generic_skey_attr, asn1_generic_skey_attr);
	sc_copy_asn1_entry(c_asn1_generic_skey_value_attr, asn1_generic_skey_value_attr);

	sc_format_asn1_entry(asn1_skey + 0, asn1_skey_choice, NULL, 1);
	switch (obj->type) {
	case SC_PKCS15_TYPE_SKEY_GENERIC:
		sc_format_asn1_entry(asn1_skey_choice + 0, &skey_obj, NULL, 1);
		break;
	case SC_PKCS15_TYPE_SKEY_DES:
		sc_format_asn1_entry(asn1_skey_choice + 1, &skey_obj, NULL, 1);
		break;
	case SC_PKCS15_TYPE_SKEY_2DES:
		sc_format_asn1_entry(asn1_skey_choice + 2, &skey_obj, NULL, 1);
		break;
	case SC_PKCS15_TYPE_SKEY_3DES:
		sc_format_asn1_entry(asn1_skey_choice + 3, &skey_obj, NULL, 1);
		break;
	default:
		sc_log(ctx, "Invalid secret key type: %X", obj->type);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
		break;
	}

	sc_format_asn1_entry(asn1_com_key_attr + 0, &skey->id, NULL, 1);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &skey->usage, &usage_len, 1);
	if (skey->native == 0)
		sc_format_asn1_entry(asn1_com_key_attr + 2, &skey->native, NULL, 1);
	if (skey->access_flags)
		sc_format_asn1_entry(asn1_com_key_attr + 3, &skey->access_flags, &af_len, 1);
	if (skey->key_reference >= 0)
		sc_format_asn1_entry(asn1_com_key_attr + 4, &skey->key_reference, NULL, 1);
	for (i=0; i<SC_MAX_SUPPORTED_ALGORITHMS && i<C_ASN1_SUPPORTED_ALGORITHMS_SIZE && skey->algo_refs[i]; i++)
		sc_format_asn1_entry(asn1_supported_algorithms + i, &skey->algo_refs[i], NULL, 1);
	sc_format_asn1_entry(asn1_com_key_attr + 5, asn1_supported_algorithms, NULL, skey->algo_refs[0] != 0);

	sc_format_asn1_entry(asn1_com_skey_attr + 0, &skey->value_len, NULL, 1);

	sc_format_asn1_entry(asn1_generic_skey_attr + 0, asn1_generic_skey_value_attr, NULL, 1);

	sc_format_asn1_entry(asn1_generic_skey_value_attr + 0, &skey->path, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_skey, buf, buflen);

	sc_log(ctx, "Key path %s", sc_print_path(&skey->path));
	LOG_FUNC_RETURN(ctx, r);
}
