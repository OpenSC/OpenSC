/*
 * sc-ossl-compat.h: OpenSC ecompatability for older OpenSSL versions
 *
 * Copyright (C) 2016	Douglas E. Engert <deengert@gmail.com>
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

#ifndef _SC_OSSL_COMPAT_H
#define _SC_OSSL_COMPAT_H

#ifdef ENABLE_OPENSSL

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
/*
 * Provide backward compatability to older versions of OpenSSL
 * while using most of OpenSSL 1.1  API
 */

/*
 * EVP_CIPHER_CTX functions:
 * EVP_CIPHER_CTX_new	    not in 0.9.7
 * EVP_CIPHER_CTX_free	    not in 0.9.7
 * EVP_CIPHER_CTX_init	    in 0.9.7 to 1.0.2. defined in 1.1 as EVP_CIPHER_CTX_reset
 * EVP_CIPHER_CTX_cleanup   in 0.9.7 to 1.0.2, defined in 1.1 as EVP_CIPHER_CTX_reset
 * EVP_CIPHER_CTX_reset	    only in 1.1
 *
 * EVP_CIPHER_CTX_new	    does a EVP_CIPHER_CTX_init
 * EVP_CIPHER_CTX_free	    does a EVP_CIPHER_CTX_cleanup
 * EVP_CIPHER_CTX_cleanup   does equivelent of a EVP_CIPHER_CTX_init
 * Use EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free, and  EVP_CIPHER_CTX_cleanup between operations
 */

#if OPENSSL_VERSION_NUMBER  <= 0x009070dfL

/* in 0.9.7  EVP_CIPHER_CTX was always allocated inline or in other structures */

#define EVP_CIPHER_CTX_new() ({ \
	EVP_CIPHER_CTX * tmp = NULL; \
	tmp = OPENSSL_malloc(sizeof(struct evp_cipher_ctx_st)); \
	if (tmp) { \
	EVP_CIPHER_CTX_init(tmp); \
	} \
	tmp; \
	})

#define EVP_CIPHER_CTX_free(x) ({ \
	if (x) { \
		EVP_CIPHER_CTX_cleanup(x); \
		OPENSSL_free(x); \
	} \
	})
#endif /* OPENSSL_VERSION_NUMBER =< 0x00907000L */

/*
 * 1.1 renames RSA_PKCS1_SSLeay to RSA_PKCS1_OpenSSL
 * use RSA_PKCS1_OpenSSL
 * Previous versions are missing a number of functions to access
 * some hidden structures. Define them here:
 */

/*  EVP_PKEY_base_id introduced in 1.0.1 */
#if OPENSSL_VERSION_NUMBER < 0x10001000L
#define EVP_PKEY_base_id(x)		(x->type)
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define RSA_PKCS1_OpenSSL		RSA_PKCS1_SSLeay
#define OPENSSL_malloc_init		CRYPTO_malloc_init

#define EVP_PKEY_get0_RSA(x)		(x->pkey.rsa)
#define EVP_PKEY_get0_DSA(x)		(x->pkey.dsa)
#define X509_get_extension_flags(x)	(x->ex_flags)
#define X509_get_key_usage(x)		(x->ex_kusage)
#define X509_get_extended_key_usage(x)	(x->ex_xkusage)
#define EVP_PKEY_up_ref(user_key)	CRYPTO_add(&user_key->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define X509_up_ref(cert)		CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509)
#endif

/*
 * OpenSSL-1.1.0-pre5 has hidden the RSA and DSA structures
 * One can no longer use statements like rsa->n = ...
 * Macros and defines don't work on all systems, so use inline versions
 * If that is not good enough, vsersions could be added to libopensc
 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* based on OpenSSL-1.1.0 e_os2.h */
/* sc_ossl_inline: portable inline definition usable in public headers */
# if !defined(inline) && !defined(__cplusplus)
#  if defined(__STDC_VERSION__) && __STDC_VERSION__>=199901L
   /* just use inline */
#   define sc_ossl_inline inline
#  elif defined(__GNUC__) && __GNUC__>=2
#   define sc_ossl_inline __inline__
#  elif defined(_MSC_VER)
#   define sc_ossl_inline __inline
#  else
#   define sc_ossl_inline
#  endif
# else
#  define sc_ossl_inline inline
# endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define RSA_bits(R) (BN_num_bits(R->n))

#include <openssl/bn.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif

#if 1
#ifndef OPENSSL_NO_RSA
static sc_ossl_inline int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* d is the private component and may be NULL */
    if (n == NULL || e == NULL)
        return 0;

    BN_free(r->n);
    BN_free(r->e);
    BN_free(r->d);
    r->n = n;
    r->e = e;
    r->d = d;

    return 1;
}

static sc_ossl_inline int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    if (p == NULL || q == NULL)
        return 0;

    BN_free(r->p);
    BN_free(r->q);
    r->p = p;
    r->q = q;

    return 1;
}

static sc_ossl_inline int RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    if (dmp1 == NULL || dmq1 == NULL || iqmp == NULL)
        return 0;

    BN_free(r->dmp1);
    BN_free(r->dmq1);
    BN_free(r->iqmp);
    r->dmp1 = dmp1;
    r->dmq1 = dmq1;
    r->iqmp = iqmp;

    return 1;
}

static sc_ossl_inline void RSA_get0_key(const RSA *r, BIGNUM **n, BIGNUM **e, BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

static sc_ossl_inline void RSA_get0_factors(const RSA *r, BIGNUM **p, BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

static sc_ossl_inline void RSA_get0_crt_params(const RSA *r,
                         BIGNUM **dmp1, BIGNUM **dmq1, BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

#endif /* OPENSSL_NO_RSA */

#ifndef OPENSSL_NO_DSA
static sc_ossl_inline void DSA_get0_pqg(const DSA *d, BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

static sc_ossl_inline void DSA_get0_key(const DSA *d, BIGNUM **pub_key, BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

/* NOTE: DSA_set0_*  functions not defined because they are not currently used in OpenSC */
#endif /* OPENSSL_NO_DSA */

#else /* if we used macros */

#define RSA_set0_key(R, N, E, D) \
	({ \
		int ret = 0; \
		if (!(N) || !(E)) { \
			ret = 0; \
		} else { \
			BN_free(R->n); \
			BN_free(R->e); \
			BN_free(R->d); \
			R->n = (N); \
			R->e = (E); \
			R->d = (D); \
			ret = 1; \
		} \
		ret; \
	})

#define RSA_set0_factors(R, P, Q) \
	 ({ \
		int ret= 0; \
		if (!P || !Q) { \
			ret = 0; \
		} else { \
			BN_free(R->p); \
			BN_free(R->q); \
			R->p = P; \
			R->q = Q; \
			ret = 1; \
		} \
		ret; \
	})

#define RSA_set0_crt_params(R, DMP1, DMQ1, IQMP) \
	({ \
		int ret = 0; \
		if (!DMP1 || !DMQ1 || !IQMP) { \
			 ret = 0; \
		} else { \
			BN_free(R->dmp1); \
			BN_free(R->dmq1); \
			BN_free(R->iqmp); \
			R->dmp1 = DMP1; \
			R->dmq1 = DMQ1; \
			R->iqmp = IQMP; \
			ret = 1; \
		} \
		ret; \
	})

#define RSA_get0_key(R, N, E, D) { \
	BIGNUM **n = N; \
	BIGNUM **e = E; \
	BIGNUM **d = D; \
	if (n) *(n) = R->n; \
	if (e) *(e) = R->e; \
	if (d) *(d) = R->d; \
	}

#define RSA_get0_factors(R, P, Q) {\
	BIGNUM **p = P; \
	BIGNUM **q = Q; \
	if (p) *(p) = R->p; \
	if (q) *(q) = R->q; \
	}

#define RSA_get0_crt_params(R, DMP1, DMQ1, IQMP) { \
	BIGNUM **dmp1 = DMP1; \
	BIGNUM **dmq1 = DMQ1; \
	BIGNUM **iqmp = IQMP; \
	if (dmp1) *(dmp1) = R->dmp1; \
	if (dmq1) *(dmq1) = R->dmq1; \
	if (iqmp) *(iqmp) = R->iqmp; \
	}

#define DSA_get0_key(D, PUB, PRIV) { \
	BIGNUM **pub = PUB; \
	BIGNUM **priv = PRIV; \
	if (pub) *(pub) = D->pub_key; \
	if (priv) *(priv) = D->priv_key; \
	}

#define DSA_get0_pqg(D, P, Q, G) { \
	BIGNUM **p = P; \
	BIGNUM **q = Q; \
	BIGNUM **g = G; \
	if (p) *(p) = D->p; \
	if (q) *(q) = D->q; \
	if (g) *(g) = D->g; \
	}

/* NOTE: DSA_set0_*  functions not defined because they are not used in OpenSC */
#endif /* 0 */
#endif

#ifdef __cplusplus
}
#endif

#endif /* ENABLE_OPENSSL */
#endif
