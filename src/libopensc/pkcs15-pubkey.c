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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const struct sc_asn1_entry c_asn1_com_key_attr[] = {
	{ "iD",		 SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "usage",	 SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "native",	 SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessFlags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "keyReference",SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_com_pubkey_attr[] = {
        /* FIXME */
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_rsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "modulusLength", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "keyInfo",	   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_rsa_type_attr[] = {
	{ "publicRSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dsakey_attr[] = {
	{ "value",	   SC_ASN1_PATH, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_dsa_type_attr[] = {
	{ "publicDSAKeyAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_pubkey_choice[] = {
	{ "publicRSAKey", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "publicDSAKey", SC_ASN1_PKCS15_OBJECT, 2 | SC_ASN1_CTX | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_pubkey[] = {
	{ "publicKey",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int sc_pkcs15_decode_pukdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 ** buf, size_t *buflen)
{
        sc_context_t *ctx = p15card->card->ctx;
        struct sc_pkcs15_pubkey_info info;
	int r;
	size_t usage_len = sizeof(info.usage);
	size_t af_len = sizeof(info.access_flags);
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_pubkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_rsa_type_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_dsa_type_attr[2];
	struct sc_asn1_entry asn1_pubkey_choice[3];
	struct sc_asn1_entry asn1_pubkey[2];
	struct sc_asn1_pkcs15_object rsakey_obj = { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_rsa_type_attr };
	struct sc_asn1_pkcs15_object dsakey_obj = { obj, asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_dsa_type_attr };

        sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
        sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
        sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_dsa_type_attr, asn1_dsa_type_attr);
        sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
        sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 0);
	sc_format_asn1_entry(asn1_pubkey_choice + 1, &dsakey_obj, NULL, 0);

	sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_rsakey_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_rsakey_attr + 1, &info.modulus_length, NULL, 0);

	sc_format_asn1_entry(asn1_dsa_type_attr + 0, asn1_dsakey_attr, NULL, 0);

	sc_format_asn1_entry(asn1_dsakey_attr + 0, &info.path, NULL, 0);

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

	r = sc_asn1_decode(ctx, asn1_pubkey, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, r, "ASN.1 decoding failed");
	if (asn1_pubkey_choice[0].flags & SC_ASN1_PRESENT) {
		obj->type = SC_PKCS15_TYPE_PUBKEY_RSA;
	} else {
		obj->type = SC_PKCS15_TYPE_PUBKEY_DSA;
	}
	r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info.path);
	if (r < 0)
		return r;
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}
int sc_pkcs15_encode_pukdf_entry(sc_context_t *ctx,
				 const struct sc_pkcs15_object *obj,
				 u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_com_key_attr[6], asn1_com_pubkey_attr[1];
	struct sc_asn1_entry asn1_rsakey_attr[4], asn1_rsa_type_attr[2];
	struct sc_asn1_entry asn1_dsakey_attr[2], asn1_dsa_type_attr[2];
	struct sc_asn1_entry asn1_pubkey_choice[3];
	struct sc_asn1_entry asn1_pubkey[2];
	struct sc_pkcs15_pubkey_info *pubkey =
                (struct sc_pkcs15_pubkey_info *) obj->data;
	struct sc_asn1_pkcs15_object rsakey_obj = { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_rsa_type_attr };
	struct sc_asn1_pkcs15_object dsakey_obj = { (struct sc_pkcs15_object *) obj,
						    asn1_com_key_attr,
						    asn1_com_pubkey_attr, asn1_dsa_type_attr };
	int r;
	size_t af_len, usage_len;

        sc_copy_asn1_entry(c_asn1_pubkey, asn1_pubkey);
        sc_copy_asn1_entry(c_asn1_pubkey_choice, asn1_pubkey_choice);
        sc_copy_asn1_entry(c_asn1_rsa_type_attr, asn1_rsa_type_attr);
        sc_copy_asn1_entry(c_asn1_rsakey_attr, asn1_rsakey_attr);
        sc_copy_asn1_entry(c_asn1_dsa_type_attr, asn1_dsa_type_attr);
        sc_copy_asn1_entry(c_asn1_dsakey_attr, asn1_dsakey_attr);
        sc_copy_asn1_entry(c_asn1_com_pubkey_attr, asn1_com_pubkey_attr);
        sc_copy_asn1_entry(c_asn1_com_key_attr, asn1_com_key_attr);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		sc_format_asn1_entry(asn1_pubkey_choice + 0, &rsakey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_rsa_type_attr + 0, asn1_rsakey_attr, NULL, 1);

		sc_format_asn1_entry(asn1_rsakey_attr + 0, &pubkey->path, NULL, 1);
		sc_format_asn1_entry(asn1_rsakey_attr + 1, &pubkey->modulus_length, NULL, 1);
		break;

	case SC_PKCS15_TYPE_PUBKEY_DSA:
		sc_format_asn1_entry(asn1_pubkey_choice + 1, &dsakey_obj, NULL, 1);

		sc_format_asn1_entry(asn1_dsa_type_attr + 0, asn1_dsakey_attr, NULL, 1);

		sc_format_asn1_entry(asn1_dsakey_attr + 0, &pubkey->path, NULL, 1);
		break;
	default:
		sc_error(ctx, "Unsupported public key type: %X\n", obj->type);
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_INTERNAL);
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

	r = sc_asn1_encode(ctx, asn1_pubkey, buf, buflen);

	return r;
}

/* this should be required, not optional. But it is missing in some siemens cards and thus causes warnings */
/* so we silence these warnings by making it optional - the card works ok without. :/ */
static struct sc_asn1_entry c_asn1_public_key[2] = {
	{ "publicKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static struct sc_asn1_entry c_asn1_rsa_pub_coefficients[3] = {
	{ "modulus",  SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "exponent", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static struct sc_asn1_entry c_asn1_dsa_pub_coefficients[5] = {
	{ "publicKey",SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramP",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramQ",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ "paramG",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL },
};

int
sc_pkcs15_decode_pubkey_rsa(sc_context_t *ctx,
			struct sc_pkcs15_pubkey_rsa *key,
			const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_public_key[2];
	struct sc_asn1_entry asn1_rsa_coeff[3];
	int r;
	
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_coeff, NULL, 0);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_coeff);
	sc_format_asn1_entry(asn1_rsa_coeff + 0,
				&key->modulus.data, &key->modulus.len, 0);
	sc_format_asn1_entry(asn1_rsa_coeff + 1,
				&key->exponent.data, &key->exponent.len, 0);

	r = sc_asn1_decode(ctx, asn1_public_key, buf, buflen, NULL, NULL);
	SC_TEST_RET(ctx, r, "ASN.1 parsing of public key failed");

	return 0;
}

int
sc_pkcs15_encode_pubkey_rsa(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_rsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_public_key[2];
	struct sc_asn1_entry asn1_rsa_pub_coeff[3];
	int r;
	
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_format_asn1_entry(asn1_public_key + 0, asn1_rsa_pub_coeff, NULL, 1);

	sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients, asn1_rsa_pub_coeff);
	sc_format_asn1_entry(asn1_rsa_pub_coeff + 0,
				key->modulus.data, &key->modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_pub_coeff + 1,
				key->exponent.data, &key->exponent.len, 1);

	r = sc_asn1_encode(ctx, asn1_public_key, buf, buflen);
	SC_TEST_RET(ctx, r, "ASN.1 encoding failed");

	return 0;
}

int
sc_pkcs15_decode_pubkey_dsa(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_dsa *key,
		const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_public_key[2];
	struct sc_asn1_entry asn1_dsa_pub_coeff[5];
	int r;
	
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_copy_asn1_entry(c_asn1_dsa_pub_coefficients, asn1_dsa_pub_coeff);

	sc_format_asn1_entry(asn1_public_key + 0, asn1_dsa_pub_coeff, NULL, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 0,
				&key->pub.data, &key->pub.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 1,
				&key->g.data, &key->g.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 2,
				&key->p.data, &key->p.len, 0);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 3,
				&key->q.data, &key->q.len, 0);

	r = sc_asn1_decode(ctx, asn1_public_key, buf, buflen,
				NULL, NULL);
	SC_TEST_RET(ctx, r, "ASN.1 decoding failed");

	return 0;
}

int
sc_pkcs15_encode_pubkey_dsa(sc_context_t *ctx,
		struct sc_pkcs15_pubkey_dsa *key,
		u8 **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_public_key[2];
	struct sc_asn1_entry asn1_dsa_pub_coeff[5];
	int r;
	
	sc_copy_asn1_entry(c_asn1_public_key, asn1_public_key);
	sc_copy_asn1_entry(c_asn1_dsa_pub_coefficients, asn1_dsa_pub_coeff);

	sc_format_asn1_entry(asn1_public_key + 0, asn1_dsa_pub_coeff, NULL, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 0,
				key->pub.data, &key->pub.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 1,
				key->g.data, &key->g.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 2,
				key->p.data, &key->p.len, 1);
	sc_format_asn1_entry(asn1_dsa_pub_coeff + 3,
				key->q.data, &key->q.len, 1);

	r = sc_asn1_encode(ctx, asn1_public_key, buf, buflen);
	SC_TEST_RET(ctx, r, "ASN.1 encoding failed");

	return 0;
}

int
sc_pkcs15_encode_pubkey(sc_context_t *ctx,
		struct sc_pkcs15_pubkey *key,
		u8 **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_encode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_encode_pubkey_dsa(ctx, &key->u.dsa, buf, len);
	sc_error(ctx, "Encoding of public key type %u not supported\n",
			key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_pkcs15_decode_pubkey(sc_context_t *ctx,
		struct sc_pkcs15_pubkey *key,
		const u8 *buf, size_t len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return sc_pkcs15_decode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	if (key->algorithm == SC_ALGORITHM_DSA)
		return sc_pkcs15_decode_pubkey_dsa(ctx, &key->u.dsa, buf, len);
	sc_error(ctx, "Decoding of public key type %u not supported\n",
			key->algorithm);
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Read public key.
 */
int
sc_pkcs15_read_pubkey(struct sc_pkcs15_card *p15card,
			const struct sc_pkcs15_object *obj,
			struct sc_pkcs15_pubkey **out)
{
	const struct sc_pkcs15_pubkey_info *info;
	struct sc_pkcs15_pubkey *pubkey;
	u8	*data;
	size_t	len;
	int	algorithm, r;

	assert(p15card != NULL && obj != NULL && out != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);

	switch (obj->type) {
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		algorithm = SC_ALGORITHM_RSA;
		break;
	case SC_PKCS15_TYPE_PUBKEY_DSA:
		algorithm = SC_ALGORITHM_DSA;
		break;
	default:
		sc_error(p15card->card->ctx, "Unsupported public key type.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	info = (const struct sc_pkcs15_pubkey_info *) obj->data;

	r = sc_pkcs15_read_file(p15card, &info->path, &data, &len, NULL);
	if (r < 0) {
		sc_error(p15card->card->ctx, "Failed to read public key file.");
		return r;
	}

	pubkey = (struct sc_pkcs15_pubkey *) calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if (pubkey == NULL) {
		free(data);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	pubkey->algorithm = algorithm;
	pubkey->data.value = data;
	pubkey->data.len = len;
	if (sc_pkcs15_decode_pubkey(p15card->card->ctx, pubkey, data, len)) {
		free(data);
		free(pubkey);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	*out = pubkey;
	return 0;
}

void sc_pkcs15_erase_pubkey(struct sc_pkcs15_pubkey *key)
{
	assert(key != NULL);
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		free(key->u.rsa.modulus.data);
		free(key->u.rsa.exponent.data);
		break;
	case SC_ALGORITHM_DSA:
		free(key->u.dsa.pub.data);
		free(key->u.dsa.g.data);
		free(key->u.dsa.p.data);
		free(key->u.dsa.q.data);
		break;
	}
	free(key->data.value);
	sc_mem_clear(key, sizeof(*key));
}

void sc_pkcs15_free_pubkey(struct sc_pkcs15_pubkey *key)
{
	sc_pkcs15_erase_pubkey(key);
	free(key);
}

void sc_pkcs15_free_pubkey_info(sc_pkcs15_pubkey_info_t *key)
{
	if (key->subject)
		free(key->subject);
	free(key);
}
