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
#define EVP_sha3_224()                          (NULL)
#define EVP_sha3_256()                          (NULL)
#define EVP_sha3_384()                          (NULL)
#define EVP_sha3_512()                          (NULL)
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

typedef struct ossl3ctx {
	OSSL_LIB_CTX *libctx;
	OSSL_PROVIDER *defprov;
} ossl3ctx_t;

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_OPENSSL */
#endif /* _SC_OSSL_COMPAT_H */
