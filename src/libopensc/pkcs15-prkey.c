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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, NULL },
	{ "usage",	 SC_ASN1_BIT_STRING, ASN1_BIT_STRING, 0, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, ASN1_BOOLEAN, SC_ASN1_OPTIONAL, NULL },
	{ "accessFlags", SC_ASN1_BIT_STRING, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, NULL },
	{ "keyReference",SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_com_prkey_attr[] = {
        /* FIXME */
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ "modulusLength", SC_ASN1_INTEGER, ASN1_INTEGER, 0, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prk_rsa_attr[] = {
	{ "privateRSAKeyAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prk_dsa_attr[] = {
	{ "privateDSAKeyAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prkey[] = {
	{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ "privateDSAKey", SC_ASN1_PKCS15_OBJECT,  2 | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};		

int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
        struct sc_context *ctx = p15card->card->ctx;
        struct sc_pkcs15_prkey_info info;
	int r;
	int usage_len = sizeof(info.usage);
	int af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2];
	struct sc_asn1_entry asn1_prkey[3];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = { obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_rsa_attr };
	struct sc_asn1_pkcs15_object dsa_prkey_obj = { obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_dsa_attr };

        sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

        sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
        sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);

        sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 1, &dsa_prkey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_dsakey_attr + 0, &info.path, NULL, 0);

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

        /* Fill in defaults */
        memset(&info, 0, sizeof(info));
	info.key_reference = -1;
	info.native = 1;

	r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, r, "ASN.1 decoding failed");
	if (asn1_prkey[0].flags & SC_ASN1_PRESENT)
		obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
	else if (asn1_prkey[1].flags & SC_ASN1_PRESENT)
		obj->type = SC_PKCS15_TYPE_PRKEY_DSA;
	else
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_INTERNAL);
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_prkdf_entry(struct sc_context *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2];
	struct sc_asn1_entry asn1_prkey[3];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_rsa_attr };
	struct sc_asn1_pkcs15_object dsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_dsa_attr };
	struct sc_pkcs15_prkey_info *prkey =
                (struct sc_pkcs15_prkey_info *) obj->data;
	int r;
	int af_len, usage_len;

        sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

        sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
        sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);

        sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 0, &prkey->path, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 1, &prkey->modulus_length, NULL, 1);
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		sc_format_asn1_entry(asn1_prkey + 1, &dsa_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_attr, NULL, 1);
		sc_format_asn1_entry(asn1_dsakey_attr + 0, &prkey->modulus_length, NULL, 1);
                break;
	default:
		error(ctx, "Invalid private key type: %X\n", obj->type);
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_INTERNAL);
		break;
	}
	sc_format_asn1_entry(asn1_com_key_attr + 0, &prkey->id, NULL, 1);
	usage_len = _sc_count_bit_string_size(&prkey->usage, sizeof(prkey->usage));
	sc_format_asn1_entry(asn1_com_key_attr + 1, &prkey->usage, &usage_len, 1);
	if (prkey->native == 0)
		sc_format_asn1_entry(asn1_com_key_attr + 2, &prkey->native, NULL, 1);
	if (prkey->access_flags) {
		af_len = _sc_count_bit_string_size(&prkey->access_flags, sizeof(prkey->access_flags));
		sc_format_asn1_entry(asn1_com_key_attr + 3, &prkey->access_flags, &af_len, 1);
	}
	if (prkey->key_reference >= 0)
		sc_format_asn1_entry(asn1_com_key_attr + 4, &prkey->key_reference, NULL, 1);
	r = sc_asn1_encode(ctx, asn1_prkey, buf, buflen);

	return r;
}
