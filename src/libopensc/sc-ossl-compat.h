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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
 * Provide compatibility OpenSSL 1.1.1, 3.0.1 and LibreSSL 3.4.2
 *
 * LibreSSL is a fork of OpenSSL from 2014
 * In its version of openssl/opensslv.h it defines:
 * OPENSSL_VERSION_NUMBER  0x20000000L (Will not change)
 * LIBRESSL_VERSION_NUMBER  0x3040200fL (changes with its versions)
 */

#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30500000L
#define X509_get_extension_flags(x)	(x->ex_flags)
#define X509_get_key_usage(x)		(x->ex_kusage)
#define X509_get_extended_key_usage(x)	(x->ex_xkusage)
#define EVP_MD_CTX_md_data(x)          (x->md_data)
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define OPENSSL_malloc_init()			while(0) continue
#if LIBRESSL_VERSION_NUMBER < 0x30500000L
#define FIPS_mode()                             (0)
#endif
/* OpenSSL 1.1.1 has EVP_sha3_* */
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x30800000L
#define EVP_sha3_224()                          (NULL)
#define EVP_sha3_256()                          (NULL)
#define EVP_sha3_384()                          (NULL)
#define EVP_sha3_512()                          (NULL)
#endif
#if LIBRESSL_VERSION_NUMBER < 0x3070000fL
#define EVP_PKEY_new_raw_public_key(t, e, p, l) (NULL)
#define EVP_PKEY_get_raw_public_key(p, pu, l)   (0)
#endif
#endif

/* OpenSSL 1.1.1 has FIPS_mode function */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define FIPS_mode()                             EVP_default_properties_is_fips_enabled(NULL)
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define USE_OPENSSL3_LIBCTX

#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

typedef struct ossl3ctx {
	OSSL_LIB_CTX *libctx;
	OSSL_PROVIDER *defprov;
	OSSL_PROVIDER *legacyprov;
} ossl3ctx_t;

static inline EVP_MD *_sc_evp_md(ossl3ctx_t *ctx, const char *algorithm)
{
	return EVP_MD_fetch(ctx->libctx, algorithm, NULL);
}
#define sc_evp_md(ctx, alg) _sc_evp_md((ctx)->ossl3ctx, alg)

static inline void sc_evp_md_free(EVP_MD *md)
{
	EVP_MD_free(md);
}

static inline EVP_PKEY_CTX *_sc_evp_pkey_ctx_new(ossl3ctx_t *ctx,
						 EVP_PKEY *pkey)
{
	return EVP_PKEY_CTX_new_from_pkey(ctx->libctx, pkey, NULL);
}
#define sc_evp_pkey_ctx_new(ctx, pkey) \
	_sc_evp_pkey_ctx_new((ctx)->ossl3ctx, pkey)

static inline EVP_CIPHER *_sc_evp_cipher(ossl3ctx_t *ctx, const char *algorithm)
{
	return EVP_CIPHER_fetch(ctx->libctx, algorithm, NULL);
}
#define sc_evp_cipher(ctx, alg) _sc_evp_cipher((ctx)->ossl3ctx, alg)

static inline void sc_evp_cipher_free(EVP_CIPHER *cipher)
{
	EVP_CIPHER_free(cipher);
}

#else /* OPENSSL < 3 */

#include <openssl/evp.h>

static inline EVP_MD *sc_evp_md(void *unused, const char *algorithm)
{
	return (EVP_MD *)EVP_get_digestbyname(algorithm);
}

static inline void sc_evp_md_free(EVP_MD *md)
{
	return;
}

static inline EVP_PKEY_CTX *sc_evp_pkey_ctx_new(void *unused, EVP_PKEY *pkey)
{
	return EVP_PKEY_CTX_new(pkey, NULL);
}

static inline EVP_CIPHER *sc_evp_cipher(void *unused, const char *algorithm)
{
	return (EVP_CIPHER *)EVP_get_cipherbyname(algorithm);
}

static inline void sc_evp_cipher_free(EVP_CIPHER *cipher)
{
	return;
}

#endif


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_OPENSSL */
#endif /* _SC_OSSL_COMPAT_H */
