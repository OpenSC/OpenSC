/* p11_rsa.c */
/* Written by Olaf Kirch <okir@lst.de>
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/*
 * This file implements the handling of RSA keys stored on a
 * PKCS11 token
 */

#include "pkcs11-internal.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static int pkcs11_get_rsa_public(PKCS11_KEY *, EVP_PKEY *);
static int pkcs11_get_rsa_private(PKCS11_KEY *, EVP_PKEY *);
RSA_METHOD *pkcs11_get_rsa_method(void);

#define key_getattr(k, t, p, s) \
	pkcs11_getattr(KEY2TOKEN(key), PRIVKEY(key)->object, t, p, s)
#define key_getattr_bn(k, t, bn) \
	pkcs11_getattr_bn(KEY2TOKEN(key), PRIVKEY(key)->object, t, bn)

/*
 * Get RSA key material
 */
int pkcs11_get_rsa_private(PKCS11_KEY * key, EVP_PKEY * pk)
{
	CK_BBOOL sensitive, extractable;
	RSA *rsa;

	if (!(rsa = EVP_PKEY_get1_RSA(pk))) {
		ERR_clear_error();	/* the above flags an error */
		rsa = RSA_new();
		EVP_PKEY_set1_RSA(pk, rsa);
	}

	if (key_getattr(key, CKA_SENSITIVE, &sensitive, sizeof(sensitive))
	    || key_getattr(key, CKA_EXTRACTABLE, &extractable, sizeof(extractable)))
		return -1;

	if (!rsa->n && key_getattr_bn(key, CKA_MODULUS, &rsa->n))
		return -1;
	if (!rsa->e && key_getattr_bn(key, CKA_PUBLIC_EXPONENT, &rsa->e))
		return -1;

	/* If the key is not extractable, create a key object
	 * that will use the card's functions to sign & decrypt */
	if (sensitive || !extractable) {
		RSA_set_method(rsa, pkcs11_get_rsa_method());
		rsa->flags |= RSA_FLAG_SIGN_VER;
		RSA_set_app_data(rsa, key);
		return 0;
	}

	/* TBD - extract RSA private key. */
	PKCS11err(PKCS11_F_PKCS11_GET_KEY, PKCS11_NOT_SUPPORTED);
	return -1;
}

int pkcs11_get_rsa_public(PKCS11_KEY * key, EVP_PKEY * pk)
{
	/* TBD */
	return 0;
}

static int
pkcs11_rsa_decrypt(int flen, const unsigned char *from, unsigned char *to,
		   RSA * rsa, int padding)
{
	PKCS11_KEY *key = (PKCS11_KEY *) RSA_get_app_data(rsa);

	if (padding != RSA_PKCS1_PADDING)
		return -1;
	if (key == NULL)
		return -1;

	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_DECRYPT, PKCS11_NOT_SUPPORTED);
	return -1;
}

static int
pkcs11_rsa_encrypt(int flen, const unsigned char *from, unsigned char *to,
		   RSA * rsa, int padding)
{
	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_ENCRYPT, PKCS11_NOT_SUPPORTED);
	return -1;
}

static int
pkcs11_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const RSA * rsa)
{
	PKCS11_KEY *key = (PKCS11_KEY *) RSA_get_app_data(rsa);
	PKCS11_KEY_private *priv;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG sigsize;
	int rv;

	if (key == NULL)
		return -1;
	ctx = KEY2CTX(key);
	priv = PRIVKEY(key);
	slot = TOKEN2SLOT(priv->parent);
	session = PRIVSLOT(slot)->session;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	rv = CRYPTOKI_call(ctx, C_SignInit(session, &mechanism, priv->object));
	if (rv)
		goto fail;

	/* API is somewhat fishy here. *siglen is 0 on entry (cleared
	 * by OpenSSL). The library assumes that the memory passed
	 * by the caller is always big enough */
	sigsize = BN_num_bytes(rsa->n);
	rv = CRYPTOKI_call(ctx,
			   C_Sign(session, (CK_BYTE *) m, m_len, sigret, &sigsize));
	if (rv)
		goto fail;

	*siglen = sigsize;
	return 1;

      fail:PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, pkcs11_map_err(rv));
	return 0;
}

/* Lousy hack alert. If RSA_verify detects that the key has the
 * RSA_FLAG_SIGN_VER flags set, it will assume that verification
 * is implemented externally as well.
 * We work around this by temporarily cleaning the flag, and
 * calling RSA_verify once more.
 */
static int
pkcs11_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
		  unsigned char *signature, unsigned int siglen, const RSA * rsa)
{
	RSA *r = (RSA *) rsa;	/* Ugly hack to get rid of compiler warning */
	int res;

	if (r->flags & RSA_FLAG_SIGN_VER) {
		r->flags &= ~RSA_FLAG_SIGN_VER;
		res = RSA_verify(type, m, m_len, signature, siglen, r);
		r->flags |= RSA_FLAG_SIGN_VER;
	} else {
		PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
		res = 0;
	}
	return res;
}

/*
 * Overload the default OpenSSL methods for RSA
 */
RSA_METHOD *pkcs11_get_rsa_method(void)
{
	static RSA_METHOD ops;

	if (!ops.rsa_priv_enc) {
		ops = *RSA_get_default_method();
		ops.rsa_priv_enc = pkcs11_rsa_encrypt;
		ops.rsa_priv_dec = pkcs11_rsa_decrypt;
		ops.rsa_sign = pkcs11_rsa_sign;
		ops.rsa_verify = pkcs11_rsa_verify;
	}
	return &ops;
}

PKCS11_KEY_ops pkcs11_rsa_ops = {
	EVP_PKEY_RSA,
	pkcs11_get_rsa_public,
	pkcs11_get_rsa_private
};
