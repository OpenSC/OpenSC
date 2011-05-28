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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
/* IAS/ECC and ECC(CEN/TS 15480-2:2007) defines 'algReference' member of 'CommonKeyAttributes'.
 * It's absent in PKCS#15 v1.1 .
 * Will see if any card will really need it.
 *	{ "algReference", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_CTX | 1, SC_ASN1_OPTIONAL, NULL, NULL },
 */
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_com_prkey_attr[] = {
	{ "subjectName", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 
		SC_ASN1_EMPTY_ALLOWED | SC_ASN1_ALLOC | SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "modulusLength", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prk_rsa_attr[] = {
	{ "privateRSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_gostr3410key_attr[] = {
	{ "value",         SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "params_r3410",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "params_r3411",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "params_28147",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prk_gostr3410_attr[] = {
	{ "privateGOSTR3410KeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_i_p_attr[] = {
	{ "path",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_value_attr[] = {
	{ "path",	SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "pathProtected",SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL},
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_attr[] = {
	{ "value",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prk_dsa_attr[] = {
	{ "privateDSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_prkey[] = {
	{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "privateDSAKey", SC_ASN1_PKCS15_OBJECT,  2 | SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "privateGOSTR3410Key", SC_ASN1_PKCS15_OBJECT, 3 | SC_ASN1_CTX | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
        sc_context_t *ctx = p15card->card->ctx;
        struct sc_pkcs15_prkey_info info;
	int r, gostr3410_params[3];
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[2];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2],
			asn1_dsakey_i_p_attr[2],
			asn1_dsakey_value_attr[3];
	struct sc_asn1_entry asn1_gostr3410key_attr[5], asn1_prk_gostr3410_attr[2];
	struct sc_asn1_entry asn1_prkey[4];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = { obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_rsa_attr };
	struct sc_asn1_pkcs15_object dsa_prkey_obj = { obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_dsa_attr };
	struct sc_asn1_pkcs15_object gostr3410_prkey_obj =  { obj, asn1_com_key_attr,
						       asn1_com_prkey_attr,
						       asn1_prk_gostr3410_attr };

	sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

	sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr, asn1_dsakey_i_p_attr);
	sc_copy_asn1_entry(c_asn1_prk_gostr3410_attr, asn1_prk_gostr3410_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);

	sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
	sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 1, &dsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 2, &gostr3410_prkey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_gostr3410_attr + 0, asn1_gostr3410key_attr, NULL, 0);

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

	sc_format_asn1_entry(asn1_com_key_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 1, &info.usage, &usage_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 2, &info.native, NULL, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 3, &info.access_flags, &af_len, 0);
	sc_format_asn1_entry(asn1_com_key_attr + 4, &info.key_reference, NULL, 0);

	sc_format_asn1_entry(asn1_com_prkey_attr + 0, &info.subject.value, &info.subject.len, 0);

        /* Fill in defaults */
        memset(&info, 0, sizeof(info));
	info.key_reference = -1;
	info.native = 1;
	memset(gostr3410_params, 0, sizeof(gostr3410_params));

	r = sc_asn1_decode_choice(ctx, asn1_prkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "ASN.1 decoding failed");
	if (asn1_prkey[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_RSA;
	} else if (asn1_prkey[1].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_DSA;
		/* If the value was indirect-protected, mark the path */
		if (asn1_dsakey_i_p_attr[0].flags & SC_ASN1_PRESENT)
			info.path.type = SC_PATH_TYPE_PATH_PROT;
	} else if (asn1_prkey[2].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
		assert(info.modulus_length == 0);
		info.modulus_length = SC_PKCS15_GOSTR3410_KEYSIZE;
		assert(info.params.len == 0);
		info.params.len = sizeof(struct sc_pkcs15_keyinfo_gostparams);
		info.params.data = malloc(info.params.len);
		if (info.params.data == NULL)
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		assert(sizeof(*keyinfo_gostparams) == info.params.len);
		keyinfo_gostparams = info.params.data;
		keyinfo_gostparams->gostr3410 = gostr3410_params[0];
		keyinfo_gostparams->gostr3411 = gostr3410_params[1];
		keyinfo_gostparams->gost28147 = gostr3410_params[2];
	} else {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Neither RSA or DSA or GOSTR3410 key in PrKDF entry.");
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ASN1_OBJECT);
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
	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "PrivKey path '%s'", sc_print_path(&info.path));

        /* OpenSC 0.11.4 and older encoded "keyReference" as a negative
           value. Fixed in 0.11.5 we need to add a hack, so old cards
           continue to work. */
      	if (info.key_reference < -1)
		info.key_reference += 256;

	obj->data = malloc(sizeof(info));
	if (obj->data == NULL) {
		sc_pkcs15_free_key_params(&info.params);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_prkdf_entry(sc_context_t *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[2];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2],
			asn1_dsakey_value_attr[3],
			asn1_dsakey_i_p_attr[2];
	struct sc_asn1_entry asn1_gostr3410key_attr[5], asn1_prk_gostr3410_attr[2];
	struct sc_asn1_entry asn1_prkey[4];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_rsa_attr };
	struct sc_asn1_pkcs15_object dsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_dsa_attr };
	struct sc_asn1_pkcs15_object gostr3410_prkey_obj =  { (struct sc_pkcs15_object *) obj,
						       asn1_com_key_attr, asn1_com_prkey_attr,
						       asn1_prk_gostr3410_attr };
	struct sc_pkcs15_prkey_info *prkey =
                (struct sc_pkcs15_prkey_info *) obj->data;
	struct sc_pkcs15_keyinfo_gostparams *keyinfo_gostparams;
	int r;
	size_t af_len, usage_len;

	sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

	sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
	sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
	sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr, asn1_dsakey_i_p_attr);
	sc_copy_asn1_entry(c_asn1_prk_gostr3410_attr, asn1_prk_gostr3410_attr);
	sc_copy_asn1_entry(c_asn1_gostr3410key_attr, asn1_gostr3410key_attr);

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
		sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_value_attr, NULL, 1);
		if (prkey->path.type != SC_PATH_TYPE_PATH_PROT) {
			/* indirect: just add the path */
			sc_format_asn1_entry(asn1_dsakey_value_attr + 0,
					&prkey->path, NULL, 1);
		} else {
			/* indirect-protected */
			sc_format_asn1_entry(asn1_dsakey_value_attr + 1,
					asn1_dsakey_i_p_attr, NULL, 1);
			sc_format_asn1_entry(asn1_dsakey_i_p_attr + 0,
					&prkey->path, NULL, 1);
		}
                break;
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		sc_format_asn1_entry(asn1_prkey + 2, &gostr3410_prkey_obj, NULL, 1);
		sc_format_asn1_entry(asn1_prk_gostr3410_attr + 0, asn1_gostr3410key_attr, NULL, 1);
		sc_format_asn1_entry(asn1_gostr3410key_attr + 0, &prkey->path, NULL, 1);
		if (prkey->params.len == sizeof(*keyinfo_gostparams))
		{
			keyinfo_gostparams = prkey->params.data;
			sc_format_asn1_entry(asn1_gostr3410key_attr + 1,
					&keyinfo_gostparams->gostr3410, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 2,
					&keyinfo_gostparams->gostr3411, NULL, 1);
			sc_format_asn1_entry(asn1_gostr3410key_attr + 3,
					&keyinfo_gostparams->gost28147, NULL, 1);
		}
		break;
	default:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Invalid private key type: %X", obj->type);
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
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

	sc_format_asn1_entry(asn1_com_prkey_attr + 0, prkey->subject.value, &prkey->subject.len, prkey->subject.len != 0);

	r = sc_asn1_encode(ctx, asn1_prkey, buf, buflen);

	return r;
}

static void
sc_pkcs15_erase_prkey(struct sc_pkcs15_prkey *key)
{
	assert(key != NULL);
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
		/* TODO: -DEE may not need much */
		break;
	}
	sc_mem_clear(key, sizeof(key));
}

void
sc_pkcs15_free_prkey(struct sc_pkcs15_prkey *key)
{
	sc_pkcs15_erase_prkey(key);
	free(key);
}

void sc_pkcs15_free_prkey_info(sc_pkcs15_prkey_info_t *key)
{
	if (key->subject.value)
		free(key->subject.value);

	sc_pkcs15_free_key_params(&key->params);

	free(key);
}
