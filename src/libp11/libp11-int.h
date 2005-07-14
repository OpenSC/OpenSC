/* libp11-int.h */
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

#ifndef _LIBP11_INT_H
#define _LIBP11_INT_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifndef _WIN32
#include <rsaref/unix.h>
#include <rsaref/pkcs11.h>
#else
#include <rsaref/win32.h>
#pragma pack(push, cryptoki, 1)
#include <rsaref/pkcs11.h>
#pragma pack(pop, cryptoki)
#endif

#include <rsaref/pkcs11.h>

extern void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern CK_RV C_UnloadModule(void *module);

#include <libp11.h>

/* get private implementations of PKCS11 structures */

/*
 * PKCS11_CTX: context for a PKCS11 implementation
 */
typedef struct pkcs11_ctx_private {
	char *name;
	void *libinfo;
	CK_FUNCTION_LIST_PTR method;

	CK_SESSION_HANDLE session;
	int nslots;
	PKCS11_SLOT *slots;
} PKCS11_CTX_private;
#define PRIVCTX(ctx)		((PKCS11_CTX_private *) (ctx->_private))

typedef struct pkcs11_slot_private {
	PKCS11_CTX *parent;
	unsigned char haveSession, loggedIn;
	CK_SLOT_ID id;
	CK_SESSION_HANDLE session;
} PKCS11_SLOT_private;
#define PRIVSLOT(slot)		((PKCS11_SLOT_private *) (slot->_private))
#define SLOT2CTX(slot)		(PRIVSLOT(slot)->parent)

typedef struct pkcs11_token_private {
	PKCS11_SLOT *parent;
	int nkeys, nprkeys;
	PKCS11_KEY *keys;
	int ncerts;
	PKCS11_CERT *certs;
} PKCS11_TOKEN_private;
#define PRIVTOKEN(token)	((PKCS11_TOKEN_private *) (token->_private))
#define TOKEN2SLOT(token)	(PRIVTOKEN(token)->parent)
#define TOKEN2CTX(token)	SLOT2CTX(TOKEN2SLOT(token))

typedef struct pkcs11_key_ops {
	int type;               /* EVP_PKEY_xxx */
	int (*get_public) (PKCS11_KEY *, EVP_PKEY *);
	int (*get_private) (PKCS11_KEY *, EVP_PKEY *);
} PKCS11_KEY_ops;

typedef struct pkcs11_key_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
	PKCS11_KEY_ops *ops;
} PKCS11_KEY_private;
#define PRIVKEY(key)		((PKCS11_KEY_private *) key->_private)
#define KEY2SLOT(key)		TOKEN2SLOT(KEY2TOKEN(key))
#define KEY2TOKEN(key)		(PRIVKEY(key)->parent)
#define KEY2CTX(key)		TOKEN2CTX(KEY2TOKEN(key))

typedef struct pkcs11_cert_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[255];
	size_t id_len;
} PKCS11_CERT_private;
#define PRIVCERT(cert)		((PKCS11_CERT_private *) cert->_private)
#define CERT2SLOT(cert)		TOKEN2SLOT(CERT2TOKEN(cert))
#define CERT2TOKEN(cert)	(PRIVCERT(cert)->parent)
#define CERT2CTX(cert)		TOKEN2CTX(CERT2TOKEN(cert))

/*
 * Mapping Cryptoki error codes to those used internally
 * by this code.
 * Right now, we just map them directly, and make sure
 * that the few genuine messages we use don't clash with
 * PKCS#11
 */
#define pkcs11_map_err(rv)	(rv)

/*
 * Internal functions
 */
#define CRYPTOKI_checkerr(f, rv) \
	do { if (rv) { \
		PKCS11err(f, pkcs11_map_err(rv)); \
		return -1; \
	} } while (0)
#define CRYPTOKI_call(ctx, func_and_args) \
	PRIVCTX(ctx)->method->func_and_args

/* Memory allocation */
#define PKCS11_NEW(type) \
	((type *) pkcs11_malloc(sizeof(type)))
#define PKCS11_DUP(s) \
	pkcs11_strdup((char *) s, sizeof(s))

extern int PKCS11_open_session(PKCS11_SLOT *, int);
extern void pkcs11_destroy_all_slots(PKCS11_CTX *);
extern void pkcs11_destroy_slot(PKCS11_CTX *, PKCS11_SLOT *);
extern void pkcs11_destroy_keys(PKCS11_TOKEN *);
extern void pkcs11_destroy_certs(PKCS11_TOKEN *);
extern void *pkcs11_malloc(size_t);
extern char *pkcs11_strdup(char *, size_t);

extern int pkcs11_getattr(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			  unsigned int, void *, size_t);
extern int pkcs11_getattr_s(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			    unsigned int, void *, size_t);
extern int pkcs11_getattr_var(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			      unsigned int, void *, size_t *);
extern int pkcs11_getattr_bn(PKCS11_TOKEN *, CK_OBJECT_HANDLE,
			     unsigned int, BIGNUM **);

#define key_getattr(key, t, p, s) \
	pkcs11_getattr(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (p), (s))

#define key_getattr_bn(key, t, bn) \
	pkcs11_getattr_bn(KEY2TOKEN((key)), PRIVKEY((key))->object, (t), (bn))

typedef int (*pkcs11_i2d_fn) (void *, unsigned char **);
extern void pkcs11_addattr(CK_ATTRIBUTE_PTR, int, const void *, size_t);
extern void pkcs11_addattr_int(CK_ATTRIBUTE_PTR, int, unsigned long);
extern void pkcs11_addattr_s(CK_ATTRIBUTE_PTR, int, const char *);
extern void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR, int, const BIGNUM *);
extern void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR, int, pkcs11_i2d_fn, void *);
extern void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR, unsigned int);

extern void *memdup(const void *, size_t);

extern PKCS11_KEY_ops pkcs11_rsa_ops;

extern int pkcs11_find_key(PKCS11_CTX * ctx, PKCS11_KEY **key,
	char* passphrase, char* s_slot_key_id, int verbose);

#endif
