/*
 * pkcs15.c: PKCS #15 wrap/unwrap functions
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
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
#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * The asn.1 stuff from openssl and the one from opensc don't
 * coexist very well. Openssl has typedef ... ASN1_OBJECT; while
 * in opensc has a #define ASN1_OBJECT 6.
 *
 * Everything seems to work fine however if the openssl one is included
 * first.
 */
#include "asn1.h"


#ifndef ENABLE_OPENSSL
int
sc_pkcs15_wrap_data(sc_context_t *ctx,
		const char *passphrase,
		const u8 *in, size_t in_len,
		u8 **out, size_t *out_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_pkcs15_unwrap_data(sc_context_t *ctx,
		const char *passphrase,
		const u8 *in, size_t in_len,
		u8 **out, size_t *out_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

#else /* ENABLE_OPENSSL */

static int
sc_pkcs15_derive_key(sc_context_t *ctx,
		const struct sc_algorithm_id *der_alg, 
		const struct sc_algorithm_id *enc_alg,
		const char *passphrase,
		EVP_CIPHER_CTX *crypt_ctx, int enc_dec)
{
	struct sc_pbkdf2_params *info;
	unsigned int	key_len;
	const EVP_CIPHER	*cipher;
	u8		*iv = NULL, key[64];
	int		r;

	if (!ctx || ! der_alg || !enc_alg) 
		return SC_ERROR_NOT_SUPPORTED;

	/* XXX: We might also encounter PBES2 here */
	if (der_alg->algorithm != SC_ALGORITHM_PBKDF2) {
		sc_error(ctx, "Unsupported key derivation algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	switch (enc_alg->algorithm) {
	case SC_ALGORITHM_3DES:
		cipher = EVP_des_ede3_cbc();
		iv = (u8 *) enc_alg->params;
		break;
	case SC_ALGORITHM_DES:
		cipher = EVP_des_cbc();
		iv = (u8 *) enc_alg->params;
		break;
	default:
		sc_error(ctx, "Unsupported key encryption algorithm.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (!iv) {
		sc_error(ctx, "Unsupported key encryption parameters.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	key_len = EVP_CIPHER_key_length(cipher);

	info = (struct sc_pbkdf2_params *) der_alg->params;
	if (!info) {
		sc_error(ctx, "Key parameters missing.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (info->key_length && info->key_length != key_len) {
		sc_error(ctx, "Incompatible key length.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (key_len > sizeof(key)) {
		sc_error(ctx, "Huge key length (%u).\n", key_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = PKCS5_PBKDF2_HMAC_SHA1(passphrase, -1,
			info->salt, info->salt_len,
			info->iterations, key_len, key);
	if (r == 0) {
		sc_error(ctx, "Key derivation failed.\n");
		return SC_ERROR_INTERNAL; /* for lack of something better */
	}

	/* Now we have the key. Set up the cipher context */
	memset(crypt_ctx, 0, sizeof(*crypt_ctx));
	EVP_CipherInit(crypt_ctx, cipher, key, iv, enc_dec);
	return 0;
}

static int
do_cipher(EVP_CIPHER_CTX *cipher_ctx, const u8 *in, size_t in_len,
		u8 **out, size_t *out_len)
{
	const u8 *end;
	u8	*p;
	size_t	bl, done, left, total;

	*out = p = (u8 *) malloc(in_len + EVP_CIPHER_CTX_key_length(cipher_ctx));
	*out_len = total = 0;

	bl = EVP_CIPHER_CTX_block_size(cipher_ctx);
	end = in + in_len;
	while (in < end) {
		if ((left = end - in) > bl)
			left = bl;
		if (!EVP_CipherUpdate(cipher_ctx,
					p + total, (int *) &done,
					(u8 *) in, (int)left))
			goto fail;
		total += done;
		in += left;
	}
	if (1 || total < in_len) {
		if (!EVP_CipherFinal(cipher_ctx, p + total, (int *) &done))
			goto fail;
		total += done;
	}
	*out_len = total;
	return 0;

fail:	free(p);
	return SC_ERROR_INTERNAL;
}

int
sc_pkcs15_wrap_data(sc_context_t *ctx,
		const char *passphrase,
		const u8 *in, size_t in_len,
		u8 **out, size_t *out_len)
{
	struct sc_pkcs15_enveloped_data envdata;
	EVP_CIPHER_CTX cipher_ctx;
	struct sc_pbkdf2_params der_info;
	u8	des_iv[8];
	int	r;

	memset(&envdata, 0, sizeof(envdata));
	memset(&der_info, 0, sizeof(der_info));

	RAND_bytes(des_iv, sizeof(des_iv));
	der_info.salt_len = sizeof(der_info.salt);
	RAND_bytes(der_info.salt, sizeof(der_info.salt));
	der_info.iterations = 32;
	der_info.hash_alg.algorithm = SC_ALGORITHM_SHA1;
	envdata.id.len = 1;
	envdata.ke_alg.algorithm = SC_ALGORITHM_PBKDF2;
	envdata.ke_alg.params = &der_info;
	envdata.ce_alg.algorithm = SC_ALGORITHM_3DES;
	envdata.ce_alg.params = des_iv;
	envdata.key = (u8 *) "";
	r = sc_pkcs15_derive_key(ctx, &envdata.ke_alg, &envdata.ce_alg,
			passphrase, &cipher_ctx, 1);
	if (r < 0)
		return r;

	/* Now encrypt the data using the derived key */
	r = do_cipher(&cipher_ctx, in, in_len,
			&envdata.content, &envdata.content_len);
	if (r < 0)
		return r;

	/* Finally, DER encode the whole mess */
	r = sc_pkcs15_encode_enveloped_data(ctx, &envdata, out, out_len);

	free(envdata.content);
	return r;
}


int
sc_pkcs15_unwrap_data(sc_context_t *ctx,
		const char *passphrase,
		const u8 *in, size_t in_len,
		u8 **out, size_t *out_len)
{
	struct sc_pkcs15_enveloped_data envdata;
	EVP_CIPHER_CTX cipher_ctx;
	int	r;

	memset(&envdata, 0, sizeof(envdata));
	r = sc_pkcs15_decode_enveloped_data(ctx, &envdata, in, in_len);
	if (r < 0) {
		sc_error(ctx, "Failed to decode EnvelopedData.\n");
		return r;
	}

	/* Derive the key using the info in EnvelopedData */
	r = sc_pkcs15_derive_key(ctx, &envdata.ke_alg, &envdata.ce_alg,
			passphrase, &cipher_ctx, 0);
	if (r < 0)
		return r;

	/* Now decrypt the data using the derived key */
	r = do_cipher(&cipher_ctx, envdata.content, envdata.content_len,
			out, out_len);
	if (r < 0)
		return r;

	if (envdata.ce_alg.params)
		free(envdata.ce_alg.params);
	if (envdata.ke_alg.params)
		free(envdata.ke_alg.params);
	free(envdata.content);
	return r;
}
#endif /* ENABLE_OPENSSL */

/*
 * Encode/decode EnvelopedData
 * Note we cheat with the recipientInfo field, which is a SET OF:
 * we treat it as if there's always just one element in the set.
 */
static const struct sc_asn1_entry	c_asn1_enveloped_data_attr[] = {
	{ "version",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "originator",	SC_ASN1_STRUCT,	SC_ASN1_CONS| SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "recipients",	SC_ASN1_STRUCT, SC_ASN1_CONS| SC_ASN1_TAG_SET, 0, NULL, NULL },
	{ "contentInfo",SC_ASN1_STRUCT, SC_ASN1_CONS| SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	/* some more optional foo we ignore for now */
	{ NULL, 0, 0, 0, NULL, NULL}
};

static const struct sc_asn1_entry	c_asn1_content_attr[] = {
	{ "contentType",SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL },
	{ "contentEncrAlg", SC_ASN1_ALGORITHM_ID, SC_ASN1_CONS| SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "encrContent",SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry	c_asn1_encr_content[] = {
	{ "data",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry	c_asn1_recipients_attr[] = {
	{ "kekri",	SC_ASN1_STRUCT, SC_ASN1_CTX | 2 | SC_ASN1_CONS , 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry	c_asn1_kekri_attr[] = {
	{ "version",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "id",		SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "keyEncrAlg",	SC_ASN1_ALGORITHM_ID, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "keyEncrKey",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry	c_asn1_kek_attr[] = {
	{ "id",		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "date",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_GENERALIZEDTIME, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "other",	SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int
sc_pkcs15_decode_enveloped_data(sc_context_t *ctx,
				struct sc_pkcs15_enveloped_data *result,
				const u8 *buf, size_t buflen)
{
	struct sc_asn1_entry	asn1_enveloped_data_attr[5],
				asn1_content_attr[4],
				asn1_encr_content[2],
				asn1_recipients_attr[2],
				asn1_kekri_attr[5],
				asn1_kek_attr[4];
	struct sc_pkcs15_enveloped_data data;
	int r;

	sc_copy_asn1_entry(c_asn1_enveloped_data_attr, asn1_enveloped_data_attr);
	sc_copy_asn1_entry(c_asn1_content_attr, asn1_content_attr);
	sc_copy_asn1_entry(c_asn1_encr_content, asn1_encr_content);
	sc_copy_asn1_entry(c_asn1_recipients_attr, asn1_recipients_attr);
	sc_copy_asn1_entry(c_asn1_kekri_attr, asn1_kekri_attr);
	sc_copy_asn1_entry(c_asn1_kek_attr, asn1_kek_attr);

	sc_format_asn1_entry(asn1_enveloped_data_attr + 2,
				asn1_recipients_attr, NULL, 0);
	sc_format_asn1_entry(asn1_enveloped_data_attr + 3,
				asn1_content_attr, NULL, 0);

	sc_format_asn1_entry(asn1_content_attr + 1, &data.ce_alg, NULL, 0);
	sc_format_asn1_entry(asn1_content_attr + 2,
			asn1_encr_content, NULL, 0);
	sc_format_asn1_entry(asn1_encr_content + 0,
			&data.content, &data.content_len, 0);

	sc_format_asn1_entry(asn1_recipients_attr + 0,
			asn1_kekri_attr, NULL, 0);

	sc_format_asn1_entry(asn1_kekri_attr + 1,
			asn1_kek_attr, NULL, 0);
	sc_format_asn1_entry(asn1_kekri_attr + 2,
			&data.ke_alg, NULL, 0);
	sc_format_asn1_entry(asn1_kekri_attr + 3,
			&data.key, &data.key_len, 0);

	sc_format_asn1_entry(asn1_kek_attr + 0,
			&data.id, &data.id.len, 0);

	memset(&data, 0, sizeof(data));

	r = sc_asn1_decode(ctx, asn1_enveloped_data_attr, buf, buflen, NULL, NULL);
	if (r >= 0)
		*result = data;
	return r;
}

int
sc_pkcs15_encode_enveloped_data(sc_context_t *ctx,
				struct sc_pkcs15_enveloped_data *data,
				u8 **buf, size_t *buflen)
{
	static struct sc_object_id oid_id_data = {{ 1, 2, 840, 113549, 1, 7, 1, -1 }};
	struct sc_asn1_entry	asn1_enveloped_data_attr[5],
				asn1_content_attr[4],
				asn1_encr_content[2],
				asn1_recipients_attr[2],
				asn1_kekri_attr[5],
				asn1_kek_attr[4];
	int version2 = 2, version4 = 4, r;

	sc_copy_asn1_entry(c_asn1_enveloped_data_attr, asn1_enveloped_data_attr);
	sc_copy_asn1_entry(c_asn1_content_attr, asn1_content_attr);
	sc_copy_asn1_entry(c_asn1_encr_content, asn1_encr_content);
	sc_copy_asn1_entry(c_asn1_recipients_attr, asn1_recipients_attr);
	sc_copy_asn1_entry(c_asn1_kekri_attr, asn1_kekri_attr);
	sc_copy_asn1_entry(c_asn1_kek_attr, asn1_kek_attr);

	sc_format_asn1_entry(asn1_enveloped_data_attr + 0,
				&version2, NULL, 1);
	sc_format_asn1_entry(asn1_enveloped_data_attr + 2,
				asn1_recipients_attr, NULL, 1);
	sc_format_asn1_entry(asn1_enveloped_data_attr + 3,
				asn1_content_attr, NULL, 1);

	sc_format_asn1_entry(asn1_content_attr + 0, &oid_id_data, NULL, 1);
	sc_format_asn1_entry(asn1_content_attr + 1, &data->ce_alg, NULL, 1);
	sc_format_asn1_entry(asn1_content_attr + 2,
			asn1_encr_content, NULL, 1);
	sc_format_asn1_entry(asn1_encr_content + 0,
			data->content, &data->content_len, 1);

	sc_format_asn1_entry(asn1_recipients_attr + 0,
			asn1_kekri_attr, NULL, 1);

	sc_format_asn1_entry(asn1_kekri_attr + 0,
			&version4, NULL, 1);
	sc_format_asn1_entry(asn1_kekri_attr + 1,
			asn1_kek_attr, NULL, 1);
	sc_format_asn1_entry(asn1_kekri_attr + 2,
			&data->ke_alg, NULL, 1);
	sc_format_asn1_entry(asn1_kekri_attr + 3,
			data->key, &data->key_len, 1);

	sc_format_asn1_entry(asn1_kek_attr + 0,
			&data->id, &data->id.len, 1);

	memset(&data, 0, sizeof(data));

	r = sc_asn1_encode(ctx, asn1_enveloped_data_attr, buf, buflen);
	return r;
}
