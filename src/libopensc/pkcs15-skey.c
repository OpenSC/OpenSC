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
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define C_ASN1_COM_KEY_ATTR_SIZE 6
static const struct sc_asn1_entry c_asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL},
	{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL},
	{ "native",      SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL},
	{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_SKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_com_skey_attr[C_ASN1_COM_SKEY_ATTR_SIZE] = {
	{ "keyLen",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_COM_GENERIC_SKEY_ATTR_SIZE 2
static const struct sc_asn1_entry c_asn1_generic_skey_attr[C_ASN1_COM_GENERIC_SKEY_ATTR_SIZE] = {
	{ "value",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL},
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
	int r;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[C_ASN1_COM_KEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_com_skey_attr[C_ASN1_COM_SKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_generic_skey_attr[C_ASN1_COM_GENERIC_SKEY_ATTR_SIZE];
	struct sc_asn1_entry asn1_skey_choice[C_ASN1_SKEY_CHOICE_SIZE];
	struct sc_asn1_entry asn1_skey[C_ASN1_SKEY_SIZE];
	struct sc_asn1_pkcs15_object skey_des_obj = {
		obj, asn1_com_key_attr, asn1_com_skey_attr, asn1_generic_skey_attr
	};

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_ASN1);

	sc_copy_asn1_entry(c_asn1_skey, asn1_skey);
	sc_copy_asn1_entry(c_asn1_skey_choice, asn1_skey_choice);

	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);
	sc_copy_asn1_entry(c_asn1_com_skey_attr, asn1_com_skey_attr);
	sc_copy_asn1_entry(c_asn1_generic_skey_attr, asn1_generic_skey_attr);

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

	sc_format_asn1_entry(asn1_com_skey_attr + 0, &info.value_len, NULL, 0);

	sc_format_asn1_entry(asn1_generic_skey_attr + 0, &info.path, NULL, 0);

        /* Fill in defaults */
	memset(&info, 0, sizeof(info));

	r = sc_asn1_decode(ctx, asn1_skey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "ASN.1 decoding failed");
	if (asn1_skey_choice[1].flags & SC_ASN1_PRESENT)
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
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}
