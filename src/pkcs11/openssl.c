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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/conf.h>
#include <openssl/opensslconf.h> /* for OPENSSL_NO_* */
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
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha224_mech = {
	CKM_SHA224,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha256_mech = {
	CKM_SHA256,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha384_mech = {
	CKM_SHA384,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_sha512_mech = {
	CKM_SHA512,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_gostr3411_mech = {
	CKM_GOSTR3411,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_md5_mech = {
	CKM_MD5,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static sc_pkcs11_mechanism_type_t openssl_ripemd160_mech = {
	CKM_RIPEMD160,
	{ 0, 0, CKF_DIGEST },
	0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final,
	NULL, NULL, NULL, NULL,	/* sign_* */
	NULL, NULL, NULL,	/* verif_* */
	NULL, NULL,		/* decrypt_* */
	NULL,			/* derive */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* mech_data */
	NULL,			/* free_mech_data */
};

static void * dup_mem(void *in, size_t in_len)
{
	void *out = malloc(in_len);
	if (out)
		memcpy(out, in, in_len);
	return out;
}

void
sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *p11card)
{
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

	openssl_sha1_mech.mech_data = EVP_sha1();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_sha1_mech, sizeof openssl_sha1_mech));
	openssl_sha224_mech.mech_data = EVP_sha224();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_sha224_mech, sizeof openssl_sha224_mech));
	openssl_sha256_mech.mech_data = EVP_sha256();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_sha256_mech, sizeof openssl_sha256_mech));
	openssl_sha384_mech.mech_data = EVP_sha384();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_sha384_mech, sizeof openssl_sha384_mech));
	openssl_sha512_mech.mech_data = EVP_sha512();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_sha512_mech, sizeof openssl_sha512_mech));
	openssl_md5_mech.mech_data = EVP_md5();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_md5_mech, sizeof openssl_md5_mech));
	openssl_ripemd160_mech.mech_data = EVP_ripemd160();
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_ripemd160_mech, sizeof openssl_ripemd160_mech));
	openssl_gostr3411_mech.mech_data = EVP_get_digestbynid(NID_id_GostR3411_94);
	sc_pkcs11_register_mechanism(p11card, dup_mem(&openssl_gostr3411_mech, sizeof openssl_gostr3411_mech));
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
	const EC_GROUP *group = NULL;
	char paramset[2] = "A";
	int r = -1, ret_vrf = 0;

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
		if (r == 1 && EVP_PKEY_get0(pkey) != NULL)
			group = EC_KEY_get0_group(EVP_PKEY_get0(pkey));
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
						r = EC_POINT_set_affine_coordinates_GFp(group,
						P, X, Y, NULL);
			BN_free(X);
			BN_free(Y);
			if (r == 1 && EVP_PKEY_get0(pkey) && P)
				r = EC_KEY_set_public_key(EVP_PKEY_get0(pkey), P);
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

			if (EVP_PKEY_get0_EC_KEY(pkey)) {
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
	} else if (md == NULL && mech->mechanism == CKM_ECDSA) {
		size_t signat_len_tmp;
		unsigned char *signat_tmp = NULL;
		EVP_PKEY_CTX *ctx;
		const EC_KEY *eckey;
		int r;

		sc_log(context, "Trying to verify using EVP");

		res = 0;
		r = sc_asn1_sig_value_rs_to_sequence(NULL, signat, signat_len,
						     &signat_tmp, &signat_len_tmp);
		eckey = EVP_PKEY_get0_EC_KEY(pkey);
		ctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (r == 0 && eckey && ctx && 1 == EVP_PKEY_verify_init(ctx))
			res = EVP_PKEY_verify(ctx, signat_tmp, signat_len_tmp, data, data_len);

		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(signat_tmp);

		if (res == 1)
			return CKR_OK;
		else if (res == 0)
			return CKR_SIGNATURE_INVALID;
		else
			return CKR_GENERAL_ERROR;

	} else {
		RSA *rsa;
		unsigned char *rsa_out = NULL, pad;
		int rsa_outlen = 0;

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
			return CKR_ARGUMENTS_BAD;
		}

		rsa = EVP_PKEY_get1_RSA(pkey);
		EVP_PKEY_free(pkey);
		if (rsa == NULL)
			return CKR_DEVICE_MEMORY;

		rsa_out = calloc(1, RSA_size(rsa));
		if (rsa_out == NULL) {
			RSA_free(rsa);
			return CKR_DEVICE_MEMORY;
		}

		rsa_outlen = RSA_public_decrypt(signat_len, signat, rsa_out, rsa, pad);
		if (rsa_outlen <= 0) {
			RSA_free(rsa);
			free(rsa_out);
			sc_log(context, "RSA_public_decrypt() returned %d\n", rsa_outlen);
			return CKR_GENERAL_ERROR;
		}

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
			const EVP_MD *mgf_md, *pss_md;
			unsigned char digest[EVP_MAX_MD_SIZE];

			if (mech->pParameter == NULL) {
				RSA_free(rsa);
				free(rsa_out);
				sc_log(context, "PSS mechanism requires parameter");
				return CKR_MECHANISM_PARAM_INVALID;
			}

			param = (CK_RSA_PKCS_PSS_PARAMS*)mech->pParameter;
			switch (param->mgf) {
			case CKG_MGF1_SHA1:
				mgf_md = EVP_sha1();
				break;
			case CKG_MGF1_SHA224:
				mgf_md = EVP_sha224();
				break;
			case CKG_MGF1_SHA256:
				mgf_md = EVP_sha256();
				break;
			case CKG_MGF1_SHA384:
				mgf_md = EVP_sha384();
				break;
			case CKG_MGF1_SHA512:
				mgf_md = EVP_sha512();
				break;
			default:
				RSA_free(rsa);
				free(rsa_out);
				return CKR_MECHANISM_PARAM_INVALID;
			}

			switch (param->hashAlg) {
			case CKM_SHA_1:
				pss_md = EVP_sha1();
				break;
			case CKM_SHA224:
				pss_md = EVP_sha224();
				break;
			case CKM_SHA256:
				pss_md = EVP_sha256();
				break;
			case CKM_SHA384:
				pss_md = EVP_sha384();
				break;
			case CKM_SHA512:
				pss_md = EVP_sha512();
				break;
			default:
				RSA_free(rsa);
				free(rsa_out);
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
					RSA_free(rsa);
					free(rsa_out);
					return CKR_GENERAL_ERROR;
				}
				data = tmp;
				data_len = tmp_len;
			}
			rv = CKR_SIGNATURE_INVALID;
			if (data_len == (unsigned int) EVP_MD_size(pss_md)
					&& RSA_verify_PKCS1_PSS_mgf1(rsa, data, pss_md, mgf_md,
						rsa_out, EVP_MD_size(pss_md)/*sLen*/) == 1)
				rv = CKR_OK;
			RSA_free(rsa);
			free(rsa_out);
			sc_log(context, "Returning %lu", rv);
			return rv;
		}
		RSA_free(rsa);

		if ((unsigned int) rsa_outlen == data_len && memcmp(rsa_out, data, data_len) == 0)
			rv = CKR_OK;
		else
			rv = CKR_SIGNATURE_INVALID;

		free(rsa_out);
	}

	return rv;
}
#endif
