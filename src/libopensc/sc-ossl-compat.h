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
 * Drop support of old versions of OpenSSL and LibreSSL
 * while using most of OpenSSL 1.1.1  API
 * and working on supporting OpenSSL 3.0
 *
 * LibreSSL is a fork of OpenSSL from 2014
 * In its version of openssl/opensslv.h it defines:
 * OPENSSL_VERSION_NUMBER  0x20000000L (Will not change)
 * LIBRESSL_VERSION_NUMBER  0x2050000fL (changes with its versions.
 */

#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER == 0x20000000L
#error LibreSSL no longer supported by OpenSC
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define EC_POINT_get_affine_coordinates_GFp     EC_POINT_get_affine_coordinates
#define EC_POINT_set_affine_coordinates_GFp     EC_POINT_set_affine_coordinates

# ifndef FIPS_mode
#define FIPS_mode()                             EVP_default_properties_is_fips_enabled(NULL)
# endif

/* As defined in openssl/include/openssl/evp.h */
# ifndef EVP_PK_RSA
#  define EVP_PK_RSA      0x0001
#  define EVP_PK_DSA      0x0002
#  define EVP_PK_DH       0x0004
#  define EVP_PK_EC       0x0008
#  define EVP_PKT_SIGN    0x0010
#  define EVP_PKT_ENC     0x0020
#  define EVP_PKT_EXCH    0x0040
#  define EVP_PKS_RSA     0x0100
#  define EVP_PKS_DSA     0x0200
#  define EVP_PKS_EC      0x0400
# endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define EVP_PKEY_eq                             EVP_PKEY_cmp
#define EVP_PKEY_CTX_set1_rsa_keygen_pubexp     EVP_PKEY_CTX_set_rsa_keygen_pubexp
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_OPENSSL */
#endif /* _SC_OSSL_COMPAT_H */
