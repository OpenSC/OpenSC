/* p11_key.c */
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

#include "pkcs11-internal.h"
#include <string.h>

static int pkcs11_find_keys(PKCS11_TOKEN *, unsigned int);
static int pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
			   CK_SESSION_HANDLE session, CK_OBJECT_CLASS type);
static int pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
			   CK_SESSION_HANDLE session, CK_OBJECT_HANDLE o,
			   CK_OBJECT_CLASS type, PKCS11_KEY **);
static int pkcs11_store_private_key(PKCS11_TOKEN *, EVP_PKEY *, char *,
				    unsigned char *, unsigned int, PKCS11_KEY **);
static int pkcs11_store_public_key(PKCS11_TOKEN *, EVP_PKEY *, char *,
				   unsigned char *, unsigned int, PKCS11_KEY **);

static CK_OBJECT_CLASS key_search_class;
static CK_ATTRIBUTE key_search_attrs[] = {
	{CKA_CLASS, &key_search_class, sizeof(key_search_class)},
};
#define numof(arr)	(sizeof(arr)/sizeof((arr)[0]))

/*
 * Enumerate all keys on the card
 * For now, we enumerate just the private keys.
 */
int
PKCS11_enumerate_keys(PKCS11_TOKEN * token, PKCS11_KEY ** keyp, unsigned int *countp)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	if (priv->nkeys < 0) {
		priv->nkeys = 0;
		if (pkcs11_find_keys(token, CKO_PRIVATE_KEY)) {
			pkcs11_destroy_keys(token);
			return -1;
		}
		priv->nprkeys = priv->nkeys;
		if (pkcs11_find_keys(token, CKO_PUBLIC_KEY)) {
			pkcs11_destroy_keys(token);
			return -1;
		}
	}
	*keyp = priv->keys;
	*countp = priv->nprkeys;
	return 0;
}

/*
 * Store a private key on the token
 */
int PKCS11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label)
{
	if (pkcs11_store_private_key(token, pk, label, NULL, 0, NULL))
		return -1;
	return 0;
}

/*
 * Generate and store a private key on the token
 * FIXME: We should check first whether the token supports
 * on-board key generation, and if it does, use its own algorithm
 */
int
PKCS11_generate_key(PKCS11_TOKEN * token,
		    int algorithm, unsigned int bits, char *label)
{
	PKCS11_KEY *key_obj;
	EVP_PKEY *pk;
	RSA *rsa;
	BIO *err;
	int rc;

	if (algorithm != EVP_PKEY_RSA) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	err = BIO_new_fp(stderr, BIO_NOCLOSE);
	rsa = RSA_generate_key(bits, 0x10001, NULL, err);
	BIO_free(err);
	if (rsa == NULL) {
		PKCS11err(PKCS11_F_PKCS11_GENERATE_KEY, PKCS11_KEYGEN_FAILED);
		return -1;
	}

	pk = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pk, rsa);
	rc = pkcs11_store_private_key(token, pk, label, NULL, 0, &key_obj);

	if (rc == 0) {
		PKCS11_KEY_private *kpriv;

		kpriv = PRIVKEY(key_obj);
		rc = pkcs11_store_public_key(token, pk, label,
					     kpriv->id, kpriv->id_len, NULL);
	}
	EVP_PKEY_free(pk);
	return rc;
}

/*
 * Get the key type
 */
int PKCS11_get_key_type(PKCS11_KEY * key)
{
	PKCS11_KEY_private *priv = PRIVKEY(key);

	return priv->ops->type;
}

/*
 * Create a key object that will allow an OpenSSL application
 * to use the token via an EVP_PKEY
 */
EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY * key)
{
	PKCS11_KEY_private *priv = PRIVKEY(key);
	EVP_PKEY *pk;

	pk = EVP_PKEY_new();
	if (priv->ops->get_private(key, pk)
	    || priv->ops->get_public(key, pk)) {
		EVP_PKEY_free(pk);
		return NULL;
	}
	key->evp_key = pk;
	return pk;
}

/*
 * Find all keys of a given type (public or private)
 */
int pkcs11_find_keys(PKCS11_TOKEN * token, unsigned int type)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	int rv, res = -1;

	/* Make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 0))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Tell the PKCS11 lib to enumerate all matching objects */
	key_search_class = type;
	rv = CRYPTOKI_call(ctx, C_FindObjectsInit(session, key_search_attrs,
						  numof(key_search_attrs)));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	do {
		res = pkcs11_next_key(ctx, token, session, type);
	} while (res == 0);

	CRYPTOKI_call(ctx, C_FindObjectsFinal(session));
	return (res < 0) ? -1 : 0;
}

int
pkcs11_next_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session, CK_OBJECT_CLASS type)
{
	CK_OBJECT_HANDLE obj;
	CK_ULONG count;
	int rv;

	/* Get the next matching object */
	rv = CRYPTOKI_call(ctx, C_FindObjects(session, &obj, 1, &count));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_KEYS, rv);

	if (count == 0)
		return 1;

	if (pkcs11_init_key(ctx, token, session, obj, type, NULL))
		return -1;

	return 0;
}

int
pkcs11_init_key(PKCS11_CTX * ctx, PKCS11_TOKEN * token,
		CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj,
		CK_OBJECT_CLASS type, PKCS11_KEY ** ret)
{
	PKCS11_TOKEN_private *tpriv;
	PKCS11_KEY_private *kpriv;
	PKCS11_KEY *key;
	char label[256];
	unsigned char id[256];
	CK_KEY_TYPE key_type;
	PKCS11_KEY_ops *ops;
	size_t size;

	size = sizeof(key_type);
	if (pkcs11_getattr_var(token, obj, CKA_KEY_TYPE, &key_type, &size))
		return -1;

	switch (key_type) {
	case CKK_RSA:
		ops = &pkcs11_rsa_ops;
		break;
	default:
		/* Ignore any keys we don't understand */
		return 0;
	}

	tpriv = PRIVTOKEN(token);
	tpriv->keys = (PKCS11_KEY *) OPENSSL_realloc(tpriv->keys,
						     (tpriv->nkeys +
						      1) * sizeof(PKCS11_KEY));

	key = tpriv->keys + tpriv->nkeys++;
	memset(key, 0, sizeof(*key));
	key->_private = kpriv = PKCS11_NEW(PKCS11_KEY_private);
	kpriv->object = obj;
	kpriv->parent = token;

	if (!pkcs11_getattr_s(token, obj, CKA_LABEL, label, sizeof(label)))
		key->label = BUF_strdup(label);
	key->id_len = sizeof(id);
	if (!pkcs11_getattr_var(token, obj, CKA_ID, id, (size_t *) & key->id_len)) {
		key->id = (unsigned char *) malloc(key->id_len);
		memcpy(key->id, id, key->id_len);
	}
	key->isPrivate = (type == CKO_PRIVATE_KEY);

	/* Initialize internal information */
	kpriv->id_len = sizeof(kpriv->id);
	if (pkcs11_getattr_var(token, obj, CKA_ID, kpriv->id, &kpriv->id_len))
		kpriv->id_len = 0;
	kpriv->ops = ops;

	if (ret)
		*ret = key;
	return 0;
}

/*
 * Destroy all keys
 */
void pkcs11_destroy_keys(PKCS11_TOKEN * token)
{
	PKCS11_TOKEN_private *priv = PRIVTOKEN(token);

	while (priv->nkeys > 0) {
		PKCS11_KEY *key = &priv->keys[--(priv->nkeys)];

		if (key->evp_key)
			EVP_PKEY_free(key->evp_key);
		OPENSSL_free(key->label);
		if (key->id)
			free(key->id);
	}
	if (priv->keys)
		OPENSSL_free(priv->keys);
	priv->nprkeys = -1;
	priv->nkeys = -1;
	priv->keys = NULL;
}

/*
 * Store private key
 */
int
pkcs11_store_private_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label,
			 unsigned char *id, unsigned int id_len,
			 PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the key attrs */
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);

		pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_PRIVATE_KEY);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa->n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa->e);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIVATE_EXPONENT, rsa->d);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIME_1, rsa->p);
		pkcs11_addattr_bn(attrs + n++, CKA_PRIME_2, rsa->q);
		if (label)
			pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
		if (id && id_len)
			pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);
	} else {
		PKCS11err(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PRIVATE_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, session, object,
			       CKO_PRIVATE_KEY, ret_key);
}

/*
 * Store public key
 */
int
pkcs11_store_public_key(PKCS11_TOKEN * token, EVP_PKEY * pk, char *label,
			unsigned char *id, unsigned int id_len,
			PKCS11_KEY ** ret_key)
{
	PKCS11_SLOT *slot = TOKEN2SLOT(token);
	PKCS11_CTX *ctx = TOKEN2CTX(token);
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attrs[32];
	unsigned int n = 0;
	int rv;

	/* First, make sure we have a session */
	if (!PRIVSLOT(slot)->haveSession && PKCS11_open_session(slot, 1))
		return -1;
	session = PRIVSLOT(slot)->session;

	/* Now build the key attrs */
	if (pk->type == EVP_PKEY_RSA) {
		RSA *rsa = EVP_PKEY_get1_RSA(pk);

		pkcs11_addattr_int(attrs + n++, CKA_CLASS, CKO_PUBLIC_KEY);
		pkcs11_addattr_int(attrs + n++, CKA_KEY_TYPE, CKK_RSA);
		pkcs11_addattr_bn(attrs + n++, CKA_MODULUS, rsa->n);
		pkcs11_addattr_bn(attrs + n++, CKA_PUBLIC_EXPONENT, rsa->e);
		if (label)
			pkcs11_addattr_s(attrs + n++, CKA_LABEL, label);
		if (id && id_len)
			pkcs11_addattr(attrs + n++, CKA_ID, id, id_len);
	} else {
		PKCS11err(PKCS11_F_PKCS11_STORE_PUBLIC_KEY, PKCS11_NOT_SUPPORTED);
		return -1;
	}

	/* Now call the pkcs11 module to create the object */
	rv = CRYPTOKI_call(ctx, C_CreateObject(session, attrs, n, &object));

	/* Zap all memory allocated when building the template */
	pkcs11_zap_attrs(attrs, n);

	CRYPTOKI_checkerr(PKCS11_F_PKCS11_STORE_PUBLIC_KEY, rv);

	/* Gobble the key object */
	return pkcs11_init_key(ctx, token, session, object, CKO_PUBLIC_KEY, ret_key);
}
