/*
 * OpenSSL helper functions, e.g. for implementing MD5 support
 * et al
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
 */

#include "sc-pkcs11.h"
#include "opensc/scrandom.h"

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

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

static int rng_seeded = 0; 


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

	if (!(md_ctx = (EVP_MD_CTX *) calloc(1, sizeof(*md_ctx))))
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

CK_RV
sc_pkcs11_openssl_add_seed_rand(struct sc_pkcs11_session *session,
				CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (!(session->slot->card->card->caps & SC_CARD_CAP_RNG))
		return CKR_RANDOM_NO_RNG;

	if (pSeed == NULL || ulSeedLen == 0)
		return CKR_OK;

	RAND_seed(pSeed, ulSeedLen);

	return CKR_OK;
}

CK_RV
sc_pkcs11_openssl_add_gen_rand(struct sc_pkcs11_session *session,
				CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	unsigned char seed[20];
	int r;

	if (!(session->slot->card->card->caps & SC_CARD_CAP_RNG))
		return CKR_RANDOM_NO_RNG;

	if (RandomData == NULL || ulRandomLen == 0)
		return CKR_OK;

	if (scrandom_get_data(seed, 20) == -1) {
		error(context, "scrandom_get_data() failed\n");
		return CKR_FUNCTION_FAILED;
	}
	RAND_seed(seed, 20);

	if (rng_seeded == 0) {
		r = sc_get_challenge(session->slot->card->card, seed, 20);
		if (r != 0) {
			error(context, "sc_get_challenge() returned %d\n", r);
			return sc_to_cryptoki_error(r, session->slot->card->reader);
		}
		rng_seeded = 1;
	}
	RAND_seed(seed, 20);

	r = RAND_bytes(RandomData, ulRandomLen);

	return r == 1 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static int
do_convert_bignum(sc_pkcs15_bignum_t *dst, BIGNUM *src)
{
	if (src == 0)
		return 0;
	dst->len = BN_num_bytes(src);
	dst->data = (u8 *) malloc(dst->len);
	BN_bn2bin(src, dst->data);
	return 1;
}

CK_RV
sc_pkcs11_gen_keypair_soft(CK_KEY_TYPE keytype, CK_ULONG keybits,
	struct sc_pkcs15_prkey *privkey, struct sc_pkcs15_pubkey *pubkey)
{
	switch (keytype) {
	case CKK_RSA: {
		RSA	*rsa;
		BIO	*err;
		struct sc_pkcs15_prkey_rsa  *sc_priv = &privkey->u.rsa;
		struct sc_pkcs15_pubkey_rsa *sc_pub  = &pubkey->u.rsa;

		err = BIO_new(BIO_s_mem());
		rsa = RSA_generate_key(keybits, 0x10001, NULL, err);
		BIO_free(err);
		if (rsa == NULL) {
			debug(context, "RSA_generate_key() failed\n");
			return CKR_FUNCTION_FAILED;
		}

		privkey->algorithm = pubkey->algorithm = SC_ALGORITHM_RSA;

		if (!do_convert_bignum(&sc_priv->modulus, rsa->n)
		 || !do_convert_bignum(&sc_priv->exponent, rsa->e)
		 || !do_convert_bignum(&sc_priv->d, rsa->d)
		 || !do_convert_bignum(&sc_priv->p, rsa->p)
		 || !do_convert_bignum(&sc_priv->q, rsa->q)) {
		 	debug(context, "do_convert_bignum() failed\n");
		 	RSA_free(rsa);
			return CKR_FUNCTION_FAILED;
		}
		if (rsa->iqmp && rsa->dmp1 && rsa->dmq1) {
			do_convert_bignum(&sc_priv->iqmp, rsa->iqmp);
			do_convert_bignum(&sc_priv->dmp1, rsa->dmp1);
			do_convert_bignum(&sc_priv->dmq1, rsa->dmq1);
		}

		if (!do_convert_bignum(&sc_pub->modulus, rsa->n)
		 || !do_convert_bignum(&sc_pub->exponent, rsa->e)) {
		 	debug(context, "do_convert_bignum() failed\n");
		 	RSA_free(rsa);
			return CKR_FUNCTION_FAILED;
		}

		RSA_free(rsa);

		break;
		}
	default:
		return CKR_MECHANISM_PARAM_INVALID;
	}

	return CKR_OK;
}
#endif
