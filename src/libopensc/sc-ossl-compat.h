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
 * while using OpenSSL 1.1  API
 */

#if OPENSSL_VERSION_NUMBER =< 0x00907000L

/* in 0.9.7  EVP_CIPHER_CTX was always allocated inline or in other structures */

#define EVP_CIPHER_CTX_new() ({ \
    EVP_CIPHER_CTX * tmp = NULL; \
    tmp = OPENSSL_malloc(sizeof(struct evp_cipher_ctx_st); \
    if (tmp) { \
	EVP_CIPHER_CTX_init(tmp); \
    } \
    tmp; \
    })

#define EVP_CIPHER_CTX_free(x) OPENSSL_free(x)

#endif /* OPENSSL_VERSION_NUMBER =< 0x00907000L */

#ifdef __cplusplus
}
#endif

#endif /* ENABLE_OPENSSL */
#endif
