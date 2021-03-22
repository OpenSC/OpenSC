/*
 * pkc15-algo.c: ASN.1 handling for algorithm IDs and parameters
 *
 * Copyright (C) 2001, 2002  Olaf Kirch <okir@suse.de>
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"

/*
 * AlgorithmIdentifier handling
 */
static struct sc_asn1_entry	c_asn1_des_iv[] = {
	{ "iv",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
asn1_decode_des_params(sc_context_t *ctx, void **paramp,
				const u8 *buf, size_t buflen, int depth)
{
	struct sc_asn1_entry asn1_des_iv[2];
	u8	iv[8];
	int	ivlen = 8, r;

	sc_copy_asn1_entry(c_asn1_des_iv, asn1_des_iv);
	sc_format_asn1_entry(asn1_des_iv + 0, iv, &ivlen, 0);
	r = _sc_asn1_decode(ctx, asn1_des_iv, buf, buflen, NULL, NULL, 0, depth + 1);
	if (r < 0)
		return r;
	if (ivlen != 8)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	*paramp = malloc(8);
	if (!*paramp)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(*paramp, iv, 8);
	return 0;
}

static int
asn1_encode_des_params(sc_context_t *ctx, void *params,
				u8 **buf, size_t *buflen, int depth)
{
	struct sc_asn1_entry asn1_des_iv[2];
	int	ivlen = 8;

	sc_copy_asn1_entry(c_asn1_des_iv, asn1_des_iv);
	sc_format_asn1_entry(asn1_des_iv + 0, params, &ivlen, 1);
	return _sc_asn1_encode(ctx, asn1_des_iv, buf, buflen, depth + 1);
}

static const struct sc_asn1_entry	c_asn1_gostr3410_params0[] = {
	{ "GOSTR3410Params", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry	c_asn1_gostr3410_params[] = {
	{ "key_params", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL },
	{ "hash_params", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL },
	{ "cipher_params", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
asn1_decode_gostr3410_params(sc_context_t *ctx, void **paramp,
		const u8 *buf, size_t buflen, int depth)
{
	struct sc_asn1_entry asn1_gostr3410_params0[2], asn1_gostr3410_params[4];
	struct sc_object_id keyp, hashp, cipherp;
	int r;

	sc_copy_asn1_entry(c_asn1_gostr3410_params0, asn1_gostr3410_params0);
	sc_copy_asn1_entry(c_asn1_gostr3410_params, asn1_gostr3410_params);

	sc_format_asn1_entry(asn1_gostr3410_params0 + 0, asn1_gostr3410_params, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410_params + 0, &keyp, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410_params + 1, &hashp, NULL, 0);
	sc_format_asn1_entry(asn1_gostr3410_params + 2, &cipherp, NULL, 0);

	r = _sc_asn1_decode(ctx, asn1_gostr3410_params0, buf, buflen, NULL, NULL, 0, depth + 1);
	/* TODO: store in paramp */
	(void)paramp; /* no warning */
	return r;
}

static int
asn1_encode_gostr3410_params(sc_context_t *ctx, void *params,
		u8 **buf, size_t *buflen, int depth)
{
	struct sc_asn1_entry asn1_gostr3410_params0[2], asn1_gostr3410_params[4];
	struct sc_pkcs15_gost_parameters *gost_params = (struct sc_pkcs15_gost_parameters *)params;
	int r;

	sc_copy_asn1_entry(c_asn1_gostr3410_params0, asn1_gostr3410_params0);
	sc_copy_asn1_entry(c_asn1_gostr3410_params, asn1_gostr3410_params);

	sc_format_asn1_entry(asn1_gostr3410_params0 + 0, asn1_gostr3410_params, NULL, 1);
	sc_format_asn1_entry(asn1_gostr3410_params + 0, &gost_params->key, NULL, 1);
	sc_format_asn1_entry(asn1_gostr3410_params + 1, &gost_params->hash, NULL, 1);
	/* sc_format_asn1_entry(asn1_gostr3410_params + 2, &cipherp, NULL, 1); */

	r = _sc_asn1_encode(ctx, asn1_gostr3410_params0, buf, buflen, depth + 1);

	sc_log(ctx, "encoded-params: %s", sc_dump_hex(*buf, *buflen));
	return r;
}

static const struct sc_asn1_entry	c_asn1_pbkdf2_params[] = {
	{ "salt",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "count",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "keyLength",	SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "prf",	SC_ASN1_ALGORITHM_ID, SC_ASN1_TAG_SEQUENCE, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
asn1_decode_pbkdf2_params(sc_context_t *ctx, void **paramp,
				const u8 *buf, size_t buflen, int depth)
{
	struct sc_pbkdf2_params info;
	struct sc_asn1_entry asn1_pbkdf2_params[5];
	int r;

	sc_copy_asn1_entry(c_asn1_pbkdf2_params, asn1_pbkdf2_params);
	sc_format_asn1_entry(asn1_pbkdf2_params + 0,
			info.salt, &info.salt_len, 0);
	sc_format_asn1_entry(asn1_pbkdf2_params + 1,
			&info.iterations, NULL, 0);
	sc_format_asn1_entry(asn1_pbkdf2_params + 2,
			&info.key_length, NULL, 0);
	sc_format_asn1_entry(asn1_pbkdf2_params + 3,
			&info.hash_alg, NULL, 0);

	memset(&info, 0, sizeof(info));
	info.salt_len = sizeof(info.salt);
	info.hash_alg.algorithm = SC_ALGORITHM_SHA1;

	r = _sc_asn1_decode(ctx, asn1_pbkdf2_params, buf, buflen, NULL, NULL, 0, depth + 1);
	if (r < 0)
		return r;

	*paramp = malloc(sizeof(info));
	if (!*paramp)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(*paramp, &info, sizeof(info));
	return 0;
}

static int
asn1_encode_pbkdf2_params(sc_context_t *ctx, void *params,
				u8 **buf, size_t *buflen, int depth)
{
	struct sc_pbkdf2_params *info;
	struct sc_asn1_entry asn1_pbkdf2_params[5];

	info = (struct sc_pbkdf2_params *) params;

	sc_copy_asn1_entry(c_asn1_pbkdf2_params, asn1_pbkdf2_params);
	sc_format_asn1_entry(asn1_pbkdf2_params + 0,
			info->salt, &info->salt_len, 1);
	sc_format_asn1_entry(asn1_pbkdf2_params + 1,
			&info->iterations, NULL, 1);
	if (info->key_length > 0)
		sc_format_asn1_entry(asn1_pbkdf2_params + 2,
				&info->key_length, NULL, 1);
	if (info->hash_alg.algorithm != SC_ALGORITHM_SHA1)
		sc_format_asn1_entry(asn1_pbkdf2_params + 3,
				&info->hash_alg, NULL, 0);

	return _sc_asn1_encode(ctx, asn1_pbkdf2_params, buf, buflen, depth + 1);
}

static const struct sc_asn1_entry	c_asn1_pbes2_params[] = {
	{ "keyDerivationAlg", SC_ASN1_ALGORITHM_ID, SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "keyEcnryptionAlg", SC_ASN1_ALGORITHM_ID, SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
asn1_decode_pbes2_params(sc_context_t *ctx, void **paramp,
				const u8 *buf, size_t buflen, int depth)
{
	struct sc_asn1_entry asn1_pbes2_params[3];
	struct sc_pbes2_params info;
	int r;

	sc_copy_asn1_entry(c_asn1_pbes2_params, asn1_pbes2_params);
	sc_format_asn1_entry(asn1_pbes2_params + 0,
				&info.derivation_alg, NULL, 0);
	sc_format_asn1_entry(asn1_pbes2_params + 1,
				&info.key_encr_alg, NULL, 0);
	memset(&info, 0, sizeof(info));

	r = _sc_asn1_decode(ctx, asn1_pbes2_params, buf, buflen, NULL, NULL, 0, depth + 1);
	if (r < 0)
		return r;
	*paramp = malloc(sizeof(info));
	if (!*paramp)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(*paramp, &info, sizeof(info));
	return 0;
}

static int
asn1_encode_pbes2_params(sc_context_t *ctx, void *params,
				u8 **buf, size_t *buflen, int depth)
{
	struct sc_asn1_entry asn1_pbes2_params[3];
	struct sc_pbes2_params *info;

	info = (struct sc_pbes2_params *) params;
	sc_copy_asn1_entry(c_asn1_pbes2_params, asn1_pbes2_params);
	sc_format_asn1_entry(asn1_pbes2_params + 0,
				&info->derivation_alg, NULL, 0);
	sc_format_asn1_entry(asn1_pbes2_params + 1,
				&info->key_encr_alg, NULL, 0);
	return _sc_asn1_encode(ctx, asn1_pbes2_params, buf, buflen, depth + 1);
}

static void
asn1_free_pbes2_params(void *ptr)
{
	struct sc_pbes2_params *params = (struct sc_pbes2_params *) ptr;

	sc_asn1_clear_algorithm_id(&params->derivation_alg);
	sc_asn1_clear_algorithm_id(&params->key_encr_alg);
	free(params);
}

static const struct sc_asn1_entry c_asn1_ec_params[] = {
	{ "ecParameters", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "namedCurve", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL},
	{ "implicityCA",  SC_ASN1_NULL, SC_ASN1_TAG_NULL, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int
asn1_decode_ec_params(sc_context_t *ctx, void **paramp,
	const u8 *buf, size_t buflen, int depth)
{
	int r;
	struct sc_object_id curve;
	struct sc_asn1_entry asn1_ec_params[4];
	struct sc_ec_parameters *ecp;

	memset(&curve, 0, sizeof(curve));

	/* We only want to copy the parms if they are a namedCurve
	 * or ecParameters  nullParam aka implicityCA is not to be
	 * used with PKCS#11 2.20 */
	sc_copy_asn1_entry(c_asn1_ec_params, asn1_ec_params);
	sc_format_asn1_entry(asn1_ec_params + 1, &curve, 0, 0);

	/* Some signature algorithms will not have any data */
	if (buflen == 0 || buf == NULL)
		return 0;

	r = sc_asn1_decode_choice(ctx, asn1_ec_params, buf, buflen, NULL, NULL);
	/* r = index in asn1_ec_params */
	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "asn1_decode_ec_params r=%d", r);
	if (r < 0)
		return r;

	ecp = calloc(sizeof(struct sc_ec_parameters), 1);
	if (ecp == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	if (r <= 1) {
		ecp->der.value = malloc(buflen);
		if (ecp->der.value == NULL) {
			free(ecp);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		ecp->der.len = buflen;
		memcpy(ecp->der.value, buf, buflen);
	}
	else    {
		r = 0;
	}

	ecp->type = r; /* but 0 = ecparams if any, 1=named curve */
	*paramp = ecp;
	return SC_SUCCESS;
};

static int
asn1_encode_ec_params(sc_context_t *ctx, void *params,
u8 **buf, size_t *buflen, int depth)
{
	 struct sc_ec_parameters *ecp = (struct sc_ec_parameters *) params;

	/* Only handle named curves. They may be absent too */
	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "asn1_encode_ec_params() called");
	*buf = NULL;
	*buflen = 0;
	if (ecp && ecp->type == 1 && ecp->der.value) { /* named curve */
		*buf = malloc(ecp->der.len);
		if (*buf == NULL)
			return SC_ERROR_OUT_OF_MEMORY;

		memcpy(*buf, ecp->der.value, ecp->der.len);
		*buflen = ecp->der.len;
	}
	else   {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "Not named curve");
	}

	return 0;
}

static void
asn1_free_ec_params(void *params)
{
	struct sc_ec_parameters *ecp = (struct sc_ec_parameters *) params;

	if (ecp) {
		if (ecp->der.value)
			free(ecp->der.value);
		if (ecp->named_curve)
			free(ecp->named_curve);
		free(ecp);
	}
}


static struct sc_asn1_pkcs15_algorithm_info algorithm_table[] = {
#ifdef SC_ALGORITHM_SHA1
	/* hmacWithSHA1 */
	{ SC_ALGORITHM_SHA1, {{ 1, 2, 840, 113549, 2, 7, -1}}, NULL, NULL, NULL },
	{ SC_ALGORITHM_SHA1, {{ 1, 3, 6, 1, 5, 5, 8, 1, 2, -1}}, NULL, NULL, NULL },
	/* SHA1 */
	{ SC_ALGORITHM_SHA1, {{ 1, 3, 14, 3, 2, 26, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_MD5
	{ SC_ALGORITHM_MD5, {{ 1, 2, 840, 113549, 2, 5, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_DSA
	{ SC_ALGORITHM_DSA, {{ 1, 2, 840, 10040, 4, 3, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RSA /* really rsaEncryption */
	{ SC_ALGORITHM_RSA, {{ 1, 2, 840, 113549, 1, 1, 1, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_DH
	{ SC_ALGORITHM_DH, {{ 1, 2, 840, 10046, 2, 1, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RC2_WRAP /* from CMS */
	{ SC_ALGORITHM_RC2_WRAP,  {{ 1, 2, 840, 113549, 1, 9, 16, 3, 7, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_RC2 /* CBC mode */
	{ SC_ALGORITHM_RC2, {{ 1, 2, 840, 113549, 3, 2, -1}},
			asn1_decode_rc2_params,
			asn1_encode_rc2_params },
#endif
#ifdef SC_ALGORITHM_DES /* CBC mode */
	{ SC_ALGORITHM_DES, {{ 1, 3, 14, 3, 2, 7, -1}},
			asn1_decode_des_params,
			asn1_encode_des_params,
			free },
#endif
#ifdef SC_ALGORITHM_3DES_WRAP /* from CMS */
	{ SC_ALGORITHM_3DES_WRAP, {{ 1, 2, 840, 113549, 1, 9, 16, 3, 6, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_3DES /* EDE CBC mode */
	{ SC_ALGORITHM_3DES, {{ 1, 2, 840, 113549, 3, 7, -1}},
			asn1_decode_des_params,
			asn1_encode_des_params,
			free },
#endif
#ifdef SC_ALGORITHM_GOST /* EDE CBC mode */
	{ SC_ALGORITHM_GOST, {{ 1, 2, 4434, 66565, 3, 7, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_GOSTR3410
	{ SC_ALGORITHM_GOSTR3410, {{ 1, 2, 643, 2, 2, 19, -1}},
			asn1_decode_gostr3410_params,
			asn1_encode_gostr3410_params,
			NULL },
#endif
/* We do not support PBES1 because the encryption is weak */
#ifdef SC_ALGORITHM_PBKDF2
	{ SC_ALGORITHM_PBKDF2, {{ 1, 2, 840, 113549, 1, 5, 12, -1}},
			asn1_decode_pbkdf2_params,
			asn1_encode_pbkdf2_params,
			free },
#endif
#ifdef SC_ALGORITHM_PBES2
	{ SC_ALGORITHM_PBES2, {{ 1, 2, 840, 113549, 1, 5, 13, -1}},
			asn1_decode_pbes2_params,
			asn1_encode_pbes2_params,
			asn1_free_pbes2_params },
#endif
#ifdef SC_ALGORITHM_EC
	{ SC_ALGORITHM_EC, {{ 1, 2, 840, 10045, 2, 1, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
/* TODO: -DEE Not clear if we need the next five or not */
#ifdef SC_ALGORITHM_ECDSA_SHA1
	/* Note RFC 3279 says no ecParameters */
	{ SC_ALGORITHM_ECDSA_SHA1, {{ 1, 2, 840, 10045, 4, 1, -1}}, NULL, NULL, NULL},
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA224
/* These next 4 are defined in RFC 5758 */
	{ SC_ALGORITHM_ECDSA_SHA224, {{ 1, 2, 840, 10045, 4, 3, 1, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA256
	{ SC_ALGORITHM_ECDSA_SHA256, {{ 1, 2, 840, 10045, 4, 3, 2, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA384
	{ SC_ALGORITHM_ECDSA_SHA384, {{ 1, 2, 840, 10045, 4, 3, 3, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_ECDSA_SHA512
	{ SC_ALGORITHM_ECDSA_SHA512, {{ 1, 2, 840, 10045, 4, 3, 4, -1}},
			asn1_decode_ec_params,
			asn1_encode_ec_params,
			asn1_free_ec_params },
#endif
#ifdef SC_ALGORITHM_EDDSA
	/* aka Ed25519 */
	{ SC_ALGORITHM_EDDSA, {{1, 3, 6, 1, 4, 1, 11591, 15, 1, -1}}, NULL, NULL, NULL },
#endif
#ifdef SC_ALGORITHM_XEDDSA
	/* aka curve25519 */
	{ SC_ALGORITHM_XEDDSA, {{1, 3, 6, 1, 4, 1, 3029, 1, 5, 1, -1}}, NULL, NULL, NULL },
#endif
	{ -1, {{ -1 }}, NULL, NULL, NULL }
};


static struct sc_asn1_pkcs15_algorithm_info *
sc_asn1_get_algorithm_info(const struct sc_algorithm_id *id)
{
	struct sc_asn1_pkcs15_algorithm_info *aip = NULL;

	for (aip = algorithm_table; aip->id >= 0; aip++)   {
		if ((int) id->algorithm < 0 && sc_compare_oid(&id->oid, &aip->oid))
			return aip;

		if (aip->id == (int)id->algorithm)
			return aip;
	}

	return NULL;
}

static const struct sc_asn1_entry c_asn1_alg_id[3] = {
	{ "algorithm",  SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, NULL, NULL },
	{ "nullParam",  SC_ASN1_NULL, SC_ASN1_TAG_NULL, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int
sc_asn1_decode_algorithm_id(struct sc_context *ctx, const unsigned char *in,
			    size_t len, struct sc_algorithm_id *id,
			    int depth)
{
	struct sc_asn1_pkcs15_algorithm_info *alg_info = NULL;
	struct sc_asn1_entry asn1_alg_id[3];
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_copy_asn1_entry(c_asn1_alg_id, asn1_alg_id);
	sc_format_asn1_entry(asn1_alg_id + 0, &id->oid, NULL, 0);

	memset(id, 0, sizeof(*id));
	r = _sc_asn1_decode(ctx, asn1_alg_id, in, len, &in, &len, 0, depth + 1);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of algo ID failed");

        sc_log(ctx, "decoded OID '%s'", sc_dump_oid(&(id->oid)));

	/* See if we understand the algorithm, and if we do, check
	 * whether we know how to decode any additional parameters */
	id->algorithm = (unsigned int ) -1;
	alg_info = sc_asn1_get_algorithm_info(id);
	if (alg_info != NULL) {
		id->algorithm = alg_info->id;
		if (alg_info->decode) {
			if (asn1_alg_id[1].flags & SC_ASN1_PRESENT) {
				sc_log(ctx, "SC_ASN1_PRESENT was set, so invalid");
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
			}
			r = alg_info->decode(ctx, &id->params, in, len, depth);
		}
	}

	LOG_FUNC_RETURN(ctx, r);
}

int
sc_asn1_encode_algorithm_id(struct sc_context *ctx, u8 **buf, size_t *len,
			    const struct sc_algorithm_id *id,
			    int depth)
{
	struct sc_asn1_pkcs15_algorithm_info *alg_info;
	struct sc_algorithm_id temp_id;
	struct sc_asn1_entry asn1_alg_id[3];
	u8 *obj = NULL;
	size_t obj_len = 0;
	int r;
	u8 *tmp;

	LOG_FUNC_CALLED(ctx);
        sc_log(ctx, "type of algorithm to encode: %i", id->algorithm);
	alg_info = sc_asn1_get_algorithm_info(id);
	if (alg_info == NULL) {
		sc_log(ctx, "Cannot encode unknown algorithm %u", id->algorithm);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Set the oid if not yet given */
	if (!sc_valid_oid(&id->oid)) {
		temp_id = *id;
		temp_id.oid = alg_info->oid;
		id = &temp_id;
	}

        sc_log(ctx, "encode algo %s", sc_dump_oid(&(id->oid)));
	sc_copy_asn1_entry(c_asn1_alg_id, asn1_alg_id);
	sc_format_asn1_entry(asn1_alg_id + 0, (void *) &id->oid, NULL, 1);

	/* no parameters, write NULL tag */
	if (!id->params || !alg_info->encode)
		asn1_alg_id[1].flags |= SC_ASN1_PRESENT;

	r = _sc_asn1_encode(ctx, asn1_alg_id, buf, len, depth + 1);
	LOG_TEST_RET(ctx, r, "ASN.1 encode of algorithm failed");

	/* Encode any parameters */
	if (id->params && alg_info->encode) {
		r = alg_info->encode(ctx, id->params, &obj, &obj_len, depth+1);
		if (r < 0) {
			if (obj)
				free(obj);
			LOG_FUNC_RETURN(ctx, r);
		}
	}

	if (obj_len) {
		tmp = (u8 *) realloc(*buf, *len + obj_len);
		if (!tmp) {
			free(*buf);
			*buf = NULL;
			free(obj);
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		*buf = tmp;
		memcpy(*buf + *len, obj, obj_len);
		*len += obj_len;
		free(obj);
	}

	sc_log(ctx, "return encoded algorithm ID: %s", sc_dump_hex(*buf, *len));
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

void
sc_asn1_clear_algorithm_id(struct sc_algorithm_id *id)
{
	struct sc_asn1_pkcs15_algorithm_info *aip;

	if (id->params && (aip = sc_asn1_get_algorithm_info(id)) && aip->free) {
		aip->free(id->params);
		id->params = NULL;
	}
}
