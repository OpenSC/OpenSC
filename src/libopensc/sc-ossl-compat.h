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

#ifdef __cplusplus
}
#endif

#endif /* ENABLE_OPENSSL */
#endif
