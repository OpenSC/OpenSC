/*
 * OpenSSL helper functions, e.g. for implementing MD5 support
 * et al
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#include "sc-pkcs11.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>

static CK_RV	sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *);
static CK_RV	sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG);
static CK_RV	sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *,
					CK_BYTE_PTR, CK_ULONG_PTR);
static void	sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *);

static sc_pkcs11_mechanism_type_t openssl_sha1_mech = {
	CKM_SHA_1,
	{ 0, 0, CKF_DIGEST }, 0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final
};

static sc_pkcs11_mechanism_type_t openssl_md5_mech = {
	CKM_MD5,
	{ 0, 0, CKF_DIGEST }, 0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final
};

static sc_pkcs11_mechanism_type_t openssl_ripemd160_mech = {
	CKM_RIPEMD160,
	{ 0, 0, CKF_DIGEST }, 0,
	sizeof(struct sc_pkcs11_operation),
	sc_pkcs11_openssl_md_release,
	sc_pkcs11_openssl_md_init,
	sc_pkcs11_openssl_md_update,
	sc_pkcs11_openssl_md_final
};

void
sc_pkcs11_register_openssl_mechanisms(struct sc_pkcs11_card *card)
{
	openssl_sha1_mech.mech_data = EVP_sha1();
	sc_pkcs11_register_mechanism(card, &openssl_sha1_mech);
	openssl_md5_mech.mech_data = EVP_md5();
	sc_pkcs11_register_mechanism(card, &openssl_md5_mech);
	openssl_ripemd160_mech.mech_data = EVP_ripemd160();
	sc_pkcs11_register_mechanism(card, &openssl_ripemd160_mech);
}

/*
 * Handle OpenSSL digest functions
 */
#define DIGEST_CTX(op) \
	((EVP_MD_CTX *) (op)->priv_data)

CK_RV
sc_pkcs11_openssl_md_init(sc_pkcs11_operation_t *op)
{
	sc_pkcs11_mechanism_type_t *mt;
	EVP_MD_CTX	*md_ctx;
	EVP_MD		*md;

	if (!op || !(mt = op->type) || !(md = (EVP_MD *) mt->mech_data))
		return CKR_ARGUMENTS_BAD;

	if (!(md_ctx = calloc(1, sizeof(*md_ctx))))
		return CKR_HOST_MEMORY;
	EVP_DigestInit(md_ctx, md);
	op->priv_data = md_ctx;
	return CKR_OK;
}

CK_RV
sc_pkcs11_openssl_md_update(sc_pkcs11_operation_t *op,
				CK_BYTE_PTR pData, CK_ULONG pDataLen)
{
	EVP_DigestUpdate(DIGEST_CTX(op), pData, pDataLen);
	return CKR_OK;
}

CK_RV
sc_pkcs11_openssl_md_final(sc_pkcs11_operation_t *op,
				CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	EVP_MD_CTX	*md_ctx = DIGEST_CTX(op);
	unsigned int	len = *pulDigestLen;

	if (len < EVP_MD_CTX_size(md_ctx)) {
		*pulDigestLen = EVP_MD_CTX_size(md_ctx);
		return CKR_BUFFER_TOO_SMALL;
	}
	EVP_DigestFinal(md_ctx, pDigest, &len);
	*pulDigestLen = len;

	return CKR_OK;
}

void
sc_pkcs11_openssl_md_release(sc_pkcs11_operation_t *op)
{
	EVP_MD_CTX	*md_ctx = DIGEST_CTX(op);

	if (md_ctx)
		free(md_ctx);
	op->priv_data = NULL;
}

#endif
