/*
 * sc-ossl-compat.h: OpenSC compatibility for older OpenSSL versions
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
 * Provide backward compatibility to older versions of OpenSSL
 * while using most of OpenSSL 1.1  API
 *
 * LibreSSL is a fork of OpenSSL from 2014
 * In its version of openssl/opensslv.h it defines:
 * OPENSSL_VERSION_NUMBER  0x20000000L (Will not change)
 * LIBRESSL_VERSION_NUMBER  0x2050000fL (changes with its versions.
 * The LibreSSL appears to follow the OpenSSL-1.0.1 API
 *
 */

/*
 * 1.1.0 depracated ERR_load_crypto_strings(), SSL_load_error_strings(), ERR_free_strings()
 * and ENGINE_load_dynamic.EVP_CIPHER_CTX_cleanup and EVP_CIPHER_CTX_init are replaced
 * by EVP_CIPHER_CTX_reset.
 * But for compatability with LibreSSL and older OpenSSL. OpenSC uses the older functions
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L  && !defined(LIBRESSL_VERSION_NUMBER)
#define ERR_load_crypto_strings(x) {}
#define SSL_load_error_strings(x)  {}
#define ERR_free_strings(x)        {}
#define ENGINE_load_dynamic(x)     {}
#define EVP_CIPHER_CTX_cleanup(x) EVP_CIPHER_CTX_reset(x)
#define EVP_CIPHER_CTX_init(x) EVP_CIPHER_CTX_reset(x)
#endif

 
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define RSA_PKCS1_OpenSSL		RSA_PKCS1_SSLeay

#define X509_get_extension_flags(x)	(x->ex_flags)
#define X509_get_key_usage(x)		(x->ex_kusage)
#define X509_get_extended_key_usage(x)	(x->ex_xkusage)
#if !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2050300fL
#define X509_up_ref(cert)		CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509)
#endif
#if !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x20700000L
#define OPENSSL_malloc_init		CRYPTO_malloc_init
#define EVP_PKEY_get0_RSA(x)		(x->pkey.rsa)
#define EVP_PKEY_get0_EC_KEY(x)		(x->pkey.ec)
#define EVP_PKEY_get0_DSA(x)		(x->pkey.dsa)
#define EVP_PKEY_up_ref(user_key)	CRYPTO_add(&user_key->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define ASN1_STRING_get0_data(x)	ASN1_STRING_data(x)
#endif
#endif

/* workaround unused value warning for a macro that does nothing */
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20700000L
#define OPENSSL_malloc_init()
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define EC_POINT_get_affine_coordinates_GFp     EC_POINT_get_affine_coordinates
#define EC_POINT_set_affine_coordinates_GFp     EC_POINT_set_affine_coordinates
#endif

/*
 * OpenSSL-1.1.0-pre5 has hidden the RSA and DSA structures
 * One can no longer use statements like rsa->n = ...
 * Macros and defines don't work on all systems, so use inline versions
 * If that is not good enough, versions could be added to libopensc
 */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
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

#if OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2050300fL)

#define RSA_bits(R) (BN_num_bits(R->n))

#include <openssl/bn.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_EC
#include <openssl/ecdsa.h>
#endif

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

static sc_ossl_inline void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

static sc_ossl_inline void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

static sc_ossl_inline void RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp)
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
static sc_ossl_inline void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

static sc_ossl_inline void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

/* NOTE: DSA_set0_*  functions not defined because they are not currently used in OpenSC */
#endif /* OPENSSL_NO_DSA */


#ifndef OPENSSL_NO_EC
static sc_ossl_inline int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
        return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif /* OPENSSL_NO_EC */

static sc_ossl_inline int CRYPTO_secure_malloc_init(size_t size, int minsize)
{
    return 0;
}

static sc_ossl_inline int CRYPTO_secure_malloc_initialized()
{
    return 0;
}

static sc_ossl_inline void CRYPTO_secure_malloc_done()
{
}

#else

#include <openssl/crypto.h>

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_OPENSSL */
#endif /* _SC_OSSL_COMPAT_H */
