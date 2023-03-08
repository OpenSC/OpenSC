/*
 * OpenSSL helper functions, e.g. for implementing MD5 support
 * et al
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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

#ifdef ENABLE_OPENSSL		/* empty file without openssl */
#include <string.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/opensslconf.h> /* for OPENSSL_NO_* */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif
#include "libopensc/sc-ossl-compat.h"
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif /* OPENSSL_NO_EC */
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif /* OPENSSL_NO_ENGINE */
#include <openssl/asn1.h>
#include <openssl/crypto.h>

#include "sc-pkcs11.h"

static CK_RV	sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *);
static CK_RV	sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
static CK_RV	sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG_PTR);
static void	sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *);

static sc_pkcs11_mechanism_type_t openssl_sha1_mech = {
	CKM_SHA_1,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL,NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha224_mech = {
	CKM_SHA224,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha256_mech = {
	CKM_SHA256,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha384_mech = {
	CKM_SHA384,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha512_mech = {
	CKM_SHA512,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_gostr3411_mech = {
	CKM_GOSTR3411,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL,NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_md5_mech = {
	CKM_MD5,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_ripemd160_mech = {
	CKM_RIPEMD160,
	{ 0, 0, CKF_DIGEST },
	{ -1 },
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL, NULL, NULL,	/* decrypt_* */
	NULL, NULL, NULL, NULL, /* encrypt */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
	NULL,			/* copy_mech_data */
};

static void * dup_mem(void *in, size_t in_len)
{
	void *out = malloc(in_len);
	if (out)
		memcpy(out, in, in_len);
	return out;
}

static CK_RV ossl_md_copy(const void *src, void **dst)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	int ret = EVP_MD_up_ref((EVP_MD *)src);
	if (ret != 1) {
		return CKR_GENERAL_ERROR;
	}
#endif
	*dst = (EVP_MD *)src;
	return CKR_OK;
}

static void ossl_md_free(const void *md)
{
	sc_evp_md_free((EVP_MD *)md);
}

void
sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *p11card)
{
	sc_pkcs11_mechanism_type_t *mt = NULL;
/*
 * Engine support is being deprecated in 3.0. OpenSC loads GOST as engine.
 * When GOST developers convert to provider, we can load the provider
 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#if !defined(OPENSSL_NO_ENGINE)
	ENGINE *e;
/* crypto locking removed in 1.1 */
#if OPENSSL_VERSION_NUMBER  < 0x10100000L
	void (*locking_cb)(int, int, const char *, int);

	locking_cb = CRYPTO_get_locking_callback();
	if (locking_cb)
		CRYPTO_set_locking_callback(NULL);
#endif

	e = ENGINE_by_id("gost");
	if (!e)
	{
#if !defined(OPENSSL_NO_STATIC_ENGINE) && !defined(OPENSSL_NO_GOST) && !defined(LIBRESSL_VERSION_NUMBER)

/* ENGINE_load_gost removed in 1.1 */
#if OPENSSL_VERSION_NUMBER  < 0x10100000L
		ENGINE_load_gost();
#endif
		e = ENGINE_by_id("gost");
#else
		/* try to load dynamic gost engine */
		e = ENGINE_by_id("dynamic");
		if (!e) {
			ENGINE_load_dynamic();
			e = ENGINE_by_id("dynamic");
		}
		if (e && (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "gost", 0) ||
					!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))) {
			ENGINE_free(e);
			e = NULL;
		}
#endif /* !OPENSSL_NO_STATIC_ENGINE && !OPENSSL_NO_GOST */
	}
	if (e) {
		ENGINE_set_default(e, ENGINE_METHOD_ALL);
		ENGINE_free(e);
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (locking_cb)
		CRYPTO_set_locking_callback(locking_cb);
#endif
#endif /* !defined(OPENSSL_NO_ENGINE) */
#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	openssl_sha1_mech.mech_data = sc_evp_md(context, "sha1");
	openssl_sha1_mech.free_mech_data = ossl_md_free;
	openssl_sha1_mech.copy_mech_data = ossl_md_copy;
	mt = dup_mem(&openssl_sha1_mech, sizeof openssl_sha1_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

	openssl_sha224_mech.mech_data = sc_evp_md(context, "sha224");
	openssl_sha224_mech.free_mech_data = ossl_md_free;
	openssl_sha224_mech.copy_mech_data = ossl_md_copy;
	mt = dup_mem(&openssl_sha224_mech, sizeof openssl_sha224_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

	openssl_sha256_mech.mech_data = sc_evp_md(context, "sha256");
	openssl_sha256_mech.free_mech_data = ossl_md_free;
	openssl_sha256_mech.copy_mech_data = ossl_md_copy;
	mt = dup_mem(&openssl_sha256_mech, sizeof openssl_sha256_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

	openssl_sha384_mech.mech_data = sc_evp_md(context, "sha384");
	openssl_sha384_mech.free_mech_data = ossl_md_free;
	openssl_sha384_mech.copy_mech_data = ossl_md_copy;
	mt = dup_mem(&openssl_sha384_mech, sizeof openssl_sha384_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

	openssl_sha512_mech.mech_data = sc_evp_md(context, "sha512");
	openssl_sha512_mech.free_mech_data = ossl_md_free;
	openssl_sha512_mech.copy_mech_data = ossl_md_copy;
	mt = dup_mem(&openssl_sha512_mech, sizeof openssl_sha512_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

	if (!FIPS_mode()) {
		openssl_md5_mech.mech_data = sc_evp_md(context, "md5");
		openssl_md5_mech.free_mech_data = ossl_md_free;
		openssl_md5_mech.copy_mech_data = ossl_md_copy;
		mt = dup_mem(&openssl_md5_mech, sizeof openssl_md5_mech);
		sc_pkcs11_register_mechanism(p11card, mt, NULL);
		sc_pkcs11_free_mechanism(&mt);

		openssl_ripemd160_mech.mech_data = sc_evp_md(context, "ripemd160");
		openssl_ripemd160_mech.free_mech_data = ossl_md_free;
		openssl_ripemd160_mech.copy_mech_data = ossl_md_copy;
		mt = dup_mem(&openssl_ripemd160_mech, sizeof openssl_ripemd160_mech);
		sc_pkcs11_register_mechanism(p11card, mt, NULL);
		sc_pkcs11_free_mechanism(&mt);

	}
	openssl_gostr3411_mech.mech_data = EVP_get_digestbynid(NID_id_GostR3411_94);
	mt = dup_mem(&openssl_gostr3411_mech, sizeof openssl_gostr3411_mech);
	sc_pkcs11_register_mechanism(p11card, mt, NULL);
	sc_pkcs11_free_mechanism(&mt);

}


/*
 * Handle OpenSSL digest functions
 */
#define DIGEST_CTX(op) \
	(op ? (EVP_MD_CTX *) (op)->priv_data : NULL)

static CK_RV sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *op)
{
	sc_pkcs11_mechanism_type_t *mt;
	EVP_MD_CTX	*md_ctx;
	EVP_MD		*md;

	if (!op || !(mt = op->type) || !(md = (EVP_MD *) mt->mech_data))
		return CKR_ARGUMENTS_BAD;

	if (!(md_ctx = EVP_MD_CTX_create()))
		return CKR_HOST_MEMORY;
	if (!EVP_DigestInit(md_ctx, md)) {
		EVP_MD_CTX_destroy(md_ctx);
		return CKR_GENERAL_ERROR;
	}
	op->priv_data = md_ctx;
	return CKR_OK;
}

static CK_RV sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *op,
				CK_BYTE_PTR pData, CK_ULONG pDataLen)
{
	EVP_MD_CTX *md_ctx = DIGEST_CTX(op);
	if (!md_ctx)
		return CKR_ARGUMENTS_BAD;
	if (!EVP_DigestUpdate(md_ctx, pData, pDataLen))
		return CKR_GENERAL_ERROR;
	return CKR_OK;
}

static CK_RV sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *op,
				CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	EVP_MD_CTX *md_ctx = DIGEST_CTX(op);

	if (!md_ctx)
		return CKR_ARGUMENTS_BAD;
	if (*pulDigestLen < (unsigned) EVP_MD_CTX_size(md_ctx)) {
		sc_log(context, "Provided buffer too small: %lu < %d",
		       *pulDigestLen, EVP_MD_CTX_size(md_ctx));
		*pulDigestLen = EVP_MD_CTX_size(md_ctx);
		return CKR_BUFFER_TOO_SMALL;
	}
	if (!EVP_DigestFinal(md_ctx, pDigest, (unsigned *) pulDigestLen))
		return CKR_GENERAL_ERROR;

	return CKR_OK;
}

static void sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *op)
{
	if (op) {
		EVP_MD_CTX	*md_ctx = DIGEST_CTX(op);
		if (md_ctx)
			EVP_MD_CTX_destroy(md_ctx);
		op->priv_data = NULL;
	}
}

#if !defined(OPENSSL_NO_EC)

static void reverse(unsigned char *buf, size_t len)
{
	unsigned char tmp;
	size_t i;

	for (i = 0; i < len / 2; ++i) {
		tmp = buf[i];
		buf[i] = buf[len - 1 - i];
		buf[len - 1 - i] = tmp;
	}
}

static CK_RV gostr3410_verify_data(const unsigned char *pubkey, unsigned int pubkey_len,
		const unsigned char *params, unsigned int params_len,
		unsigned char *data, unsigned int data_len,
		unsigned char *signat, unsigned int signat_len)
{
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	EC_POINT *P;
	BIGNUM *X, *Y;
	ASN1_OCTET_STRING *octet = NULL;
	char paramset[2] = "A";
	int r = -1, ret_vrf = 0;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	const EC_GROUP *group = NULL;
#else
	EC_GROUP *group = NULL;
	char group_name[256];
	OSSL_PARAM *old_params = NULL, *new_params = NULL, *p = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	unsigned char *buf = NULL;
	size_t buf_len = 0;
	EVP_PKEY *new_pkey = NULL;
#endif

	pkey = EVP_PKEY_new();
	if (!pkey)
		return CKR_HOST_MEMORY;

	r = EVP_PKEY_set_type(pkey, NID_id_GostR3410_2001);
	if (r == 1) {
		pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!pkey_ctx) {
			EVP_PKEY_free(pkey);
			return CKR_HOST_MEMORY;
		}
		/* FIXME: fully check params[] */
		if (params_len > 0 && params[params_len - 1] >= 1 &&
				params[params_len - 1] <= 3) {
			paramset[0] += params[params_len - 1] - 1;
			r = EVP_PKEY_CTX_ctrl_str(pkey_ctx, "paramset", paramset);
		}
		else
			r = -1;
		if (r == 1)
			r = EVP_PKEY_paramgen_init(pkey_ctx);
		if (r == 1)
			r = EVP_PKEY_paramgen(pkey_ctx, &pkey);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (r == 1 && EVP_PKEY_get0(pkey) != NULL)
			group = EC_KEY_get0_group(EVP_PKEY_get0(pkey));
#else
		if (r == 1) {
			EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group_name, sizeof(group_name), NULL);
			group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(group_name));
		}
#endif
		r = -1;
		if (group)
			octet = d2i_ASN1_OCTET_STRING(NULL, &pubkey, (long)pubkey_len);
		if (group && octet) {
			reverse(octet->data, octet->length);
			Y = BN_bin2bn(octet->data, octet->length / 2, NULL);
			X = BN_bin2bn((const unsigned char*)octet->data +
					octet->length / 2, octet->length / 2, NULL);
			ASN1_OCTET_STRING_free(octet);
			P = EC_POINT_new(group);
			if (P && X && Y)
						r = EC_POINT_set_affine_coordinates(group,
						P, X, Y, NULL);
			BN_free(X);
			BN_free(Y);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
			if (r == 1 && EVP_PKEY_get0(pkey) && P)
				r = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), P);
#else
			EC_GROUP_free(group);

			buf_len = EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
			if (!(buf = malloc(buf_len)))
				r = -1;
			if (r == 1 && P)
				r = EC_POINT_point2oct(group, P, POINT_CONVERSION_COMPRESSED, buf, buf_len, NULL);

			if (EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &old_params) != 1 ||
				!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_octet_string(bld, "pub", buf, buf_len) != 1 ||
				!(new_params = OSSL_PARAM_BLD_to_param(bld)) ||
				!(p = OSSL_PARAM_merge(old_params, new_params))) {
				r = -1;
			}
			free(buf);
			OSSL_PARAM_BLD_free(bld);

			if (r == 1) {
				if (EVP_PKEY_fromdata_init(pkey_ctx) != 1 ||
					EVP_PKEY_fromdata(pkey_ctx, &new_pkey, EVP_PKEY_KEYPAIR, p) != 1) {
					r = -1;
				}
			}
			OSSL_PARAM_free(old_params);
			OSSL_PARAM_free(new_params);
			OSSL_PARAM_free(p);

			if (r == 1) {
				EVP_PKEY_free(pkey);
				pkey = new_pkey;
			}
#endif
			EC_POINT_free(P);
		}
		if (r == 1) {
			r = EVP_PKEY_verify_init(pkey_ctx);
			reverse(data, data_len);
			if (r == 1)
				ret_vrf = EVP_PKEY_verify(pkey_ctx, signat, signat_len,
						data, data_len);
		}
	}
	EVP_PKEY_CTX_free(pkey_ctx);
	EVP_PKEY_free(pkey);
	if (r != 1)
		return CKR_GENERAL_ERROR;
	return ret_vrf == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;
}
#endif /* !defined(OPENSSL_NO_EC) */

/* If no hash function was used, finish with RSA_public_decrypt().
 * If a hash function was used, we can make a big shortcut by
 *   finishing with EVP_VerifyFinal().
 */
CK_RV sc_pkcs11_verify_data(const unsigned char *pubkey, unsigned int pubkey_len,
			const unsigned char *pubkey_params, unsigned int pubkey_params_len,
			CK_MECHANISM_PTR mech, sc_pkcs11_operation_t *md,
			unsigned char *data, unsigned int data_len,
			unsigned char *signat, unsigned int signat_len)
{
	int res;
	CK_RV rv = CKR_GENERAL_ERROR;
	EVP_PKEY *pkey = NULL;
	const unsigned char *pubkey_tmp = NULL;
	int sLen;

	if (mech->mechanism == CKM_GOSTR3410)
	{
#if !defined(OPENSSL_NO_EC)
		return gostr3410_verify_data(pubkey, pubkey_len,
				pubkey_params, pubkey_params_len,
				data, data_len, signat, signat_len);
#else
		(void)pubkey_params, (void)pubkey_params_len; /* no warning */
		return CKR_FUNCTION_NOT_SUPPORTED;
#endif
	}

	/*
	 * PKCS#11 does not define CKA_VALUE for public keys, and different cards
	 * return either the raw or spki versions as defined in PKCS#15
	 * And we need to support more then just RSA.
	 * We can use d2i_PUBKEY which works for SPKI and any key type.
	 */
	pubkey_tmp = pubkey; /* pass in so pubkey pointer is not modified */

	pkey = d2i_PUBKEY(NULL, &pubkey_tmp, pubkey_len);
	if (pkey == NULL)
		return CKR_GENERAL_ERROR;

	if (md != NULL && (mech->mechanism == CKM_SHA1_RSA_PKCS
		|| mech->mechanism == CKM_MD5_RSA_PKCS
		|| mech->mechanism == CKM_RIPEMD160_RSA_PKCS
		|| mech->mechanism == CKM_SHA224_RSA_PKCS
		|| mech->mechanism == CKM_SHA256_RSA_PKCS
		|| mech->mechanism == CKM_SHA384_RSA_PKCS
		|| mech->mechanism == CKM_SHA512_RSA_PKCS
		|| mech->mechanism == CKM_ECDSA_SHA1
		|| mech->mechanism == CKM_ECDSA_SHA224
		|| mech->mechanism == CKM_ECDSA_SHA256
		|| mech->mechanism == CKM_ECDSA_SHA384
		|| mech->mechanism == CKM_ECDSA_SHA512
		)) {
		EVP_MD_CTX *md_ctx = DIGEST_CTX(md);

		/* This does not really use the data argument, but the data
		 * are already collected in the md_ctx
		 */
		sc_log(context, "Trying to verify using EVP");
		if (md_ctx) {

			if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
				unsigned char *signat_tmp = NULL;
				size_t signat_len_tmp;
				int r;
				r = sc_asn1_sig_value_rs_to_sequence(NULL, signat,
						signat_len, &signat_tmp, &signat_len_tmp);
				if (r == 0) {
					res = EVP_VerifyFinal(md_ctx, signat_tmp, signat_len_tmp, pkey);
				} else {
					sc_log(context, "sc_asn1_sig_value_rs_to_sequence failed r:%d",r);
					res = -1;
				}
				free(signat_tmp);
			} else
				res = EVP_VerifyFinal(md_ctx, signat, signat_len, pkey);
		} else {
			res = -1;
		}
		EVP_PKEY_free(pkey);
		if (res == 1)
			return CKR_OK;
		else if (res == 0) {
			sc_log(context, "EVP_VerifyFinal(): Signature invalid");
			return CKR_SIGNATURE_INVALID;
		} else {
			sc_log(context, "EVP_VerifyFinal() returned %d\n", res);
			return CKR_GENERAL_ERROR;
		}
	} else	/* If plain CKM_ECDSA (without any hashing) is used or card supports
		 * on-card CKM_ECDSA_SHAx only we land here. Since for CKM_ECDSA_SHAx no
		 * hashing happened in C_VerifyUpdate() we do it here instead.
		 */
		if (md == NULL && (mech->mechanism == CKM_ECDSA
		    || mech->mechanism == CKM_ECDSA_SHA1
		    || mech->mechanism == CKM_ECDSA_SHA224
		    || mech->mechanism == CKM_ECDSA_SHA256
		    || mech->mechanism == CKM_ECDSA_SHA384
		    || mech->mechanism == CKM_ECDSA_SHA512)) {
		size_t signat_len_tmp;
		unsigned char *signat_tmp = NULL;
		unsigned int mdbuf_len;
		unsigned char *mdbuf = NULL;
		EVP_PKEY_CTX *ctx;
		int r;

		sc_log(context, "Trying to verify using EVP");

		/* If needed, hash input first
		 */
		if (mech->mechanism == CKM_ECDSA_SHA1
		    || mech->mechanism == CKM_ECDSA_SHA224
		    || mech->mechanism == CKM_ECDSA_SHA256
		    || mech->mechanism == CKM_ECDSA_SHA384
		    || mech->mechanism == CKM_ECDSA_SHA512) {
			EVP_MD_CTX *mdctx;
			EVP_MD *md = NULL;
			switch (mech->mechanism) {
				case CKM_ECDSA_SHA1:
					md = sc_evp_md(context, "sha1");
					break;
				case CKM_ECDSA_SHA224:
					md = sc_evp_md(context, "sha224");
					break;
				case CKM_ECDSA_SHA256:
					md = sc_evp_md(context, "sha256");
					break;
				case CKM_ECDSA_SHA384:
					md = sc_evp_md(context, "sha384");
					break;
				case CKM_ECDSA_SHA512:
					md = sc_evp_md(context, "sha512");
					break;
				default:
					EVP_PKEY_free(pkey);
					return CKR_GENERAL_ERROR;
			}
			mdbuf_len = EVP_MD_size(md);
			mdbuf = calloc(1, mdbuf_len);
			if (mdbuf == NULL) {
				EVP_PKEY_free(pkey);
				sc_evp_md_free(md);
				return CKR_DEVICE_MEMORY;
			}
			if ((mdctx = EVP_MD_CTX_new()) == NULL) {
				free(mdbuf);
				EVP_PKEY_free(pkey);
				sc_evp_md_free(md);
				return CKR_GENERAL_ERROR;
			}
			if (!EVP_DigestInit(mdctx, md)
				|| !EVP_DigestUpdate(mdctx, data, data_len)
				|| !EVP_DigestFinal(mdctx, mdbuf, &mdbuf_len)) {
				EVP_PKEY_free(pkey);
				EVP_MD_CTX_free(mdctx);
				sc_evp_md_free(md);
				free(mdbuf);
				return CKR_GENERAL_ERROR;
			}
			EVP_MD_CTX_free(mdctx);
			sc_evp_md_free(md);
			data = mdbuf;
			data_len = mdbuf_len;
		}

		res = 0;
		r = sc_asn1_sig_value_rs_to_sequence(NULL, signat, signat_len,
						     &signat_tmp, &signat_len_tmp);
		ctx = sc_evp_pkey_ctx_new(context, pkey);
		if (r == 0 && EVP_PKEY_base_id(pkey) == EVP_PKEY_EC && ctx && EVP_PKEY_verify_init(ctx) == 1)
			res = EVP_PKEY_verify(ctx, signat_tmp, signat_len_tmp, data, data_len);

		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(signat_tmp);
		free(mdbuf);

		if (res == 1)
			return CKR_OK;
		else if (res == 0)
			return CKR_SIGNATURE_INVALID;
		else
			return CKR_GENERAL_ERROR;

	} else {
		unsigned char *rsa_out = NULL, pad;
		size_t rsa_outlen = 0;
		EVP_PKEY_CTX *ctx = sc_evp_pkey_ctx_new(context, pkey);
		if (!ctx) {
			EVP_PKEY_free(pkey);
			return CKR_DEVICE_MEMORY;
		}

		sc_log(context, "Trying to verify using low-level API");
		switch (mech->mechanism) {
		case CKM_RSA_PKCS:
		case CKM_MD5_RSA_PKCS:
		case CKM_RIPEMD160_RSA_PKCS:
		 	pad = RSA_PKCS1_PADDING;
		 	break;
		case CKM_RSA_X_509:
			pad = RSA_NO_PADDING;
			break;
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
			pad = RSA_NO_PADDING;
			break;
		default:
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			return CKR_ARGUMENTS_BAD;
		}

		if ( EVP_PKEY_verify_recover_init(ctx) != 1 ||
			EVP_PKEY_CTX_set_rsa_padding(ctx, pad) != 1) {
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(pkey);
			return CKR_GENERAL_ERROR;
		}

		rsa_outlen = EVP_PKEY_size(pkey);
		rsa_out = calloc(1, rsa_outlen);
		if (rsa_out == NULL) {
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			return CKR_DEVICE_MEMORY;
		}
		if (EVP_PKEY_verify_recover(ctx, rsa_out, &rsa_outlen, signat, signat_len) != 1) {
			free(rsa_out);
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			sc_log(context, "RSA_public_decrypt() returned %d\n", (int) rsa_outlen);
			return CKR_GENERAL_ERROR;
		}
		EVP_PKEY_CTX_free(ctx);
		/* For PSS mechanisms we can not simply compare the "decrypted"
		 * data -- we need to verify the PSS padding is valid
		 */
		if (mech->mechanism == CKM_RSA_PKCS_PSS ||
		    mech->mechanism == CKM_SHA1_RSA_PKCS_PSS ||
		    mech->mechanism == CKM_SHA224_RSA_PKCS_PSS ||
		    mech->mechanism == CKM_SHA256_RSA_PKCS_PSS ||
		    mech->mechanism == CKM_SHA384_RSA_PKCS_PSS ||
		    mech->mechanism == CKM_SHA512_RSA_PKCS_PSS) {
			CK_RSA_PKCS_PSS_PARAMS* param = NULL;
			EVP_MD *mgf_md = NULL, *pss_md = NULL;
			unsigned char digest[EVP_MAX_MD_SIZE];

			if (mech->pParameter == NULL) {
				free(rsa_out);
				EVP_PKEY_free(pkey);
				sc_log(context, "PSS mechanism requires parameter");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			param = (CK_RSA_PKCS_PSS_PARAMS*)mech->pParameter;
			switch (param->mgf) {
			case CKG_MGF1_SHA1:
				mgf_md = sc_evp_md(context, "sha1");
				break;
			case CKG_MGF1_SHA224:
				mgf_md = sc_evp_md(context, "sha224");
				break;
			case CKG_MGF1_SHA256:
				mgf_md = sc_evp_md(context, "sha256");
				break;
			case CKG_MGF1_SHA384:
				mgf_md = sc_evp_md(context, "sha384");
				break;
			case CKG_MGF1_SHA512:
				mgf_md = sc_evp_md(context, "sha512");
				break;
			default:
				free(rsa_out);
				EVP_PKEY_free(pkey);
				return CKR_MECHANISM_PARAM_INVALID;
			}

			switch (param->hashAlg) {
			case CKM_SHA_1:
				pss_md = sc_evp_md(context, "sha1");
				break;
			case CKM_SHA224:
				pss_md = sc_evp_md(context, "sha224");
				break;
			case CKM_SHA256:
				pss_md = sc_evp_md(context, "sha256");
				break;
			case CKM_SHA384:
				pss_md = sc_evp_md(context, "sha384");
				break;
			case CKM_SHA512:
				pss_md = sc_evp_md(context, "sha512");
				break;
			default:
				sc_evp_md_free(mgf_md);
				free(rsa_out);
				EVP_PKEY_free(pkey);
				return CKR_MECHANISM_PARAM_INVALID;
			}

			/* for the mechanisms with hash algorithm, the data
			 * is already added to the hash buffer, so we need
			 * to finish the hash operation here
			 */
			if (mech->mechanism != CKM_RSA_PKCS_PSS) {
				EVP_MD_CTX *md_ctx = DIGEST_CTX(md);
				unsigned char *tmp = digest;
				unsigned int tmp_len;

				if (!md_ctx || !EVP_DigestFinal(md_ctx, tmp, &tmp_len)) {
					sc_evp_md_free(mgf_md);
					sc_evp_md_free(pss_md);
					free(rsa_out);
					EVP_PKEY_free(pkey);
					return CKR_GENERAL_ERROR;
				}
				data = tmp;
				data_len = tmp_len;
			}
			rv = CKR_SIGNATURE_INVALID;

			/* special mode - autodetect sLen from signature */
			/* https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pss.c */
			/* there is no way to pass negative value here, we using maximal value for this */
			if (((CK_ULONG) 1 ) << (sizeof(CK_ULONG) * CHAR_BIT -1) == param->sLen)
				sLen = RSA_PSS_SALTLEN_AUTO;
			else
				sLen = param->sLen;

			if ((ctx = sc_evp_pkey_ctx_new(context, pkey)) == NULL ||
				EVP_PKEY_verify_init(ctx) != 1 ||
				EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) != 1 ||
				EVP_PKEY_CTX_set_signature_md(ctx, pss_md) != 1 ||
				EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, sLen) != 1 ||
				EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf_md) != 1) {
				sc_log(context, "Failed to initialize EVP_PKEY_CTX");
				sc_evp_md_free(mgf_md);
				sc_evp_md_free(pss_md);
				free(rsa_out);
				EVP_PKEY_free(pkey);
				EVP_PKEY_CTX_free(ctx);
				return rv;
			}

			if (data_len == (unsigned int) EVP_MD_size(pss_md) &&
					EVP_PKEY_verify(ctx, signat, signat_len, data, data_len) == 1)
				rv = CKR_OK;
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
			sc_evp_md_free(mgf_md);
			sc_evp_md_free(pss_md);
			free(rsa_out);
			sc_log(context, "Returning %lu", rv);
			return rv;
		} else {
			EVP_PKEY_free(pkey);
		}

		if ((unsigned int) rsa_outlen == data_len && memcmp(rsa_out, data, data_len) == 0)
			rv = CKR_OK;
		else
			rv = CKR_SIGNATURE_INVALID;
		free(rsa_out);
	}

	return rv;
}
#endif
