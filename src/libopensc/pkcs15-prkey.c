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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, NULL },
	{ "usage",	 SC_ASN1_BIT_FIELD, ASN1_BIT_STRING, 0, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, ASN1_BOOLEAN, SC_ASN1_OPTIONAL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, NULL },
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

static const struct sc_asn1_entry c_asn1_dsakey_i_p_attr[] = {
	{ "path",	SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_value_attr[] = {
	{ "path",	SC_ASN1_PATH, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ "pathProtected",SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_attr[] = {
	{ "value",	SC_ASN1_CHOICE, 0, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prk_dsa_attr[] = {
	{ "privateDSAKeyAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

static const struct sc_asn1_entry c_asn1_prkey[] = {
	{ "privateRSAKey", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ "privateDSAKey", SC_ASN1_PKCS15_OBJECT,  2 | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};		

int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
        struct sc_context *ctx = p15card->card->ctx;
        struct sc_pkcs15_prkey_info info;
	int r;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_prkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_prk_rsa_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2],
			asn1_dsakey_i_p_attr[2],
			asn1_dsakey_value_attr[3];
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
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr,
					asn1_dsakey_i_p_attr);

        sc_copy_asn1_entry(c_asn1_com_prkey_attr, asn1_com_prkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_prkey + 0, &rsa_prkey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_prkey + 1, &dsa_prkey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_prk_rsa_attr + 0, asn1_rsakey_attr, NULL, 0);
	sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_dsakey_attr + 0, asn1_dsakey_value_attr, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_value_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_value_attr + 1, asn1_dsakey_i_p_attr, NULL, 0);
	sc_format_asn1_entry(asn1_dsakey_i_p_attr + 0, &info.path, NULL, 0);


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
	else if (asn1_prkey[1].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PRKEY_DSA;
		/* If the value was indirect-protected, mark the path */
		if (asn1_dsakey_i_p_attr[0].flags & SC_ASN1_PRESENT)
			info.path.type = SC_PATH_TYPE_PATH_PROT;
	} else
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
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_prk_dsa_attr[2],
			asn1_dsakey_value_attr[3],
			asn1_dsakey_i_p_attr[2];
	struct sc_asn1_entry asn1_prkey[3];
	struct sc_asn1_pkcs15_object rsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_rsa_attr };
	struct sc_asn1_pkcs15_object dsa_prkey_obj = { (struct sc_pkcs15_object *) obj, asn1_com_key_attr,
						       asn1_com_prkey_attr, asn1_prk_dsa_attr };
	struct sc_pkcs15_prkey_info *prkey =
                (struct sc_pkcs15_prkey_info *) obj->data;
	int r;
	size_t af_len, usage_len;

        sc_copy_asn1_entry(c_asn1_prkey, asn1_prkey);

        sc_copy_asn1_entry(c_asn1_prk_rsa_attr, asn1_prk_rsa_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_prk_dsa_attr, asn1_prk_dsa_attr);
        sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_value_attr, asn1_dsakey_value_attr);
	sc_copy_asn1_entry(c_asn1_dsakey_i_p_attr, asn1_dsakey_i_p_attr);

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
		sc_format_asn1_entry(asn1_prk_dsa_attr + 0, asn1_dsakey_value_attr, 0, 1);
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
	default:
		sc_error(ctx, "Invalid private key type: %X\n", obj->type);
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_INTERNAL);
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
	r = sc_asn1_encode(ctx, asn1_prkey, buf, buflen);

	return r;
}

/*
 * Store private keys on the card, encrypted
 */
static const struct sc_asn1_entry	c_asn1_dsa_prkey_obj[] = {
	{ "privateKey", SC_ASN1_OCTET_STRING, ASN1_INTEGER, SC_ASN1_ALLOC },
	{ NULL }
};

int
sc_pkcs15_encode_prkey_dsa(struct sc_context *ctx,
		struct sc_pkcs15_prkey_dsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry	asn1_dsa_prkey_obj[2];

	sc_copy_asn1_entry(c_asn1_dsa_prkey_obj, asn1_dsa_prkey_obj);
	sc_format_asn1_entry(asn1_dsa_prkey_obj + 0,
			key->priv.data, &key->priv.len, 1);

	return sc_asn1_encode(ctx, asn1_dsa_prkey_obj, buf, buflen);
}

int
sc_pkcs15_decode_prkey_dsa(struct sc_context *ctx,
		struct sc_pkcs15_prkey_dsa *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry	asn1_dsa_prkey_obj[2];

	sc_copy_asn1_entry(c_asn1_dsa_prkey_obj, asn1_dsa_prkey_obj);
	sc_format_asn1_entry(asn1_dsa_prkey_obj + 0,
			&key->priv.data, &key->priv.len, 0);

	return sc_asn1_decode(ctx, asn1_dsa_prkey_obj, buf, buflen, NULL, NULL);
}

int
sc_pkcs15_encode_prkey(struct sc_context *ctx,
		struct sc_pkcs15_prkey *key,
		u8 **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_encode_prkey_dsa(ctx, &key->u.dsa, buf, len);
	sc_error(ctx, "Cannot encode private key type %u.\n",
			key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_pkcs15_decode_prkey(struct sc_context *ctx,
		struct sc_pkcs15_prkey *key,
		const u8 *buf, size_t len)
{
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_decode_prkey_dsa(ctx, &key->u.dsa, buf, len);
	sc_error(ctx, "Cannot decode private key type %u.\n",
			key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_pkcs15_read_prkey(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_object *obj,
		const char *passphrase,
		struct sc_pkcs15_prkey **out)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *info;
	struct sc_pkcs15_prkey key;
	struct sc_path path;
	u8 *data = NULL;
	size_t len;
	int r;

	memset(&key, 0, sizeof(key));
	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		key.algorithm = SC_ALGORITHM_RSA;
		break;
	case SC_PKCS15_TYPE_PRKEY_DSA:
		key.algorithm = SC_ALGORITHM_DSA;
		break;
	default:
		sc_error(ctx, "Unsupported object type.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	info = (struct sc_pkcs15_prkey_info *) obj->data;
	if (info->native) {
		sc_error(ctx, "Private key is native, will not read.");
		return SC_ERROR_NOT_ALLOWED;
	}

	path = info->path;
	if (path.type == SC_PATH_TYPE_PATH_PROT)
		path.type = SC_PATH_TYPE_PATH;

	r = sc_pkcs15_read_file(p15card, &path, &data, &len, NULL);
	if (r < 0) {
		sc_error(ctx, "Unable to read private key file.\n");
		return r;
	}

	/* Is this a protected file? */
	if (info->path.type == SC_PATH_TYPE_PATH_PROT) {
		u8 *clear;
		size_t clear_len;

		if (passphrase == NULL) {
			r = SC_ERROR_PASSPHRASE_REQUIRED;
			goto fail;
		}
		r = sc_pkcs15_unwrap_data(ctx,
				passphrase,
				data, len,
				&clear, &clear_len);
		if (r < 0)  {
			sc_error(ctx, "Failed to unwrap privat key.");
			goto fail;
		}
		free(data);
		data = clear;
		len = clear_len;
	}

	r = sc_pkcs15_decode_prkey(ctx, &key, data, len);
	if (r < 0) {
		sc_error(ctx, "Unable to decode private key");
		goto fail;
	}

	*out = (struct sc_pkcs15_prkey *) malloc(sizeof(key));
	if (*out == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto fail;
	}

	**out = key;
	free(data);
	return 0;

fail:	if (data)
		free(data);
	return r;
}

void
sc_pkcs15_erase_prkey(struct sc_pkcs15_prkey *key)
{
	assert(key != NULL);
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		free(key->u.rsa.modulus.data);
		free(key->u.rsa.exponent.data);
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
	}
	memset(key, 0, sizeof(key));
}

void
sc_pkcs15_free_prkey(struct sc_pkcs15_prkey *key)
{
	sc_pkcs15_erase_prkey(key);
	free(key);
}
