/* pkcs11.h */
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

#ifndef _PKCS11_INTERNAL_H
#define _PKCS11_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <opensc/pkcs11.h>

#ifdef __cplusplus
extern "C" {
#endif

/* get some structures for local code to handle pkcs11 data readily */
/* Use the first free lib ID available */
#define ERR_LIB_PKCS11	42

#define PKCS11err(f,r) \
ERR_PUT_error(ERR_LIB_PKCS11,(f),(r),__FILE__,__LINE__)

/*
 * The purpose of this library is to provide a simple PKCS11
 * interface to OpenSSL application that wish to use a previously
 * initialized card (as opposed to initializing it, etc).
 *
 * I am therefore making some simplifying assumptions:
 *
 *  -	no support for any operations that alter the card,
 *  	i.e. readonly-login
 */

/* PKCS11 key object (public or private) */
typedef struct PKCS11_key_st {
	char *label;
	unsigned char *id;
	int id_len;
	unsigned char isPrivate;	/* private key present? */
	unsigned char needLogin;	/* login to read private key? */
	EVP_PKEY *evp_key;		/* initially NULL, need to call PKCS11_load_key */
	void *_private;
} PKCS11_KEY;

/* PKCS11 certificate object */
typedef struct PKCS11_cert_st {
	char *label;
	unsigned char *id;
	int id_len;
	X509 *x509;
	void *_private;
} PKCS11_CERT;

/* PKCS11 token, e.g. smart card or USB key */
typedef struct PKCS11_token_st {
	char *label;
	char *manufacturer;
	char *model;
	unsigned char initialized;
	unsigned char loginRequired;
	unsigned char userPinSet;
	unsigned char readOnly;
	void *_private;
} PKCS11_TOKEN;

/* PKCS11 slot, e.g. card reader */
typedef struct PKCS11_slot_st {
	char *manufacturer;
	char *description;
	unsigned char removable;
	PKCS11_TOKEN *token;	/* NULL if no token present */
	void *_private;
} PKCS11_SLOT;

typedef struct PKCS11_ctx_st {
	char *manufacturer;
	char *description;
	void *_private;
} PKCS11_CTX;

extern PKCS11_CTX *PKCS11_CTX_new(void);
extern int PKCS11_CTX_load(PKCS11_CTX *, const char *ident);
extern void PKCS11_CTX_unload(PKCS11_CTX *);
extern void PKCS11_CTX_free(PKCS11_CTX *);

/* Get a list of all slots */
extern int PKCS11_enumerate_slots(PKCS11_CTX *, PKCS11_SLOT **, unsigned int *);

/* Find the first slot with a token */
extern PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX *);

/* Authenticate to the card */
extern int PKCS11_login(PKCS11_SLOT *, int so, char *pin);
extern int PKCS11_logout(PKCS11_SLOT *);

/* Get a list of all keys associated with this token */
extern int PKCS11_enumerate_keys(PKCS11_TOKEN *, PKCS11_KEY **, unsigned int *);

/* Get the key type (as EVP_PKEY_XXX) */
extern int PKCS11_get_key_type(PKCS11_KEY *);

/* Get the enveloped private key */
extern EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *);

/* Get a list of all certificates associated with this token */
extern int PKCS11_enumerate_certs(PKCS11_TOKEN *, PKCS11_CERT **, unsigned int *);

/* Initialize a token */
extern int PKCS11_init_token(PKCS11_TOKEN *, char *pin, char *label);

/* Initialize the user PIN on a token */
extern int PKCS11_init_pin(PKCS11_TOKEN *, char *pin);

/* Store various objects on the token */
extern int PKCS11_generate_key(PKCS11_TOKEN *, int, unsigned int, char *);
extern int PKCS11_store_private_key(PKCS11_TOKEN *, EVP_PKEY *, char *);

/* Load PKCS11 error strings */
extern void ERR_load_PKCS11_strings(void);

/*
 * Function and reason codes
 */
#define PKCS11_F_PKCS11_CTX_LOAD		1
#define PKCS11_F_PKCS11_ENUM_SLOTS		2
#define PKCS11_F_PKCS11_CHECK_TOKEN		3
#define PKCS11_F_PKCS11_OPEN_SESSION		4
#define PKCS11_F_PKCS11_LOGIN			5
#define PKCS11_F_PKCS11_ENUM_KEYS		6
#define PKCS11_F_PKCS11_GET_KEY			7
#define PKCS11_F_PKCS11_RSA_DECRYPT		8
#define PKCS11_F_PKCS11_RSA_ENCRYPT		9
#define PKCS11_F_PKCS11_RSA_SIGN		10
#define PKCS11_F_PKCS11_RSA_VERIFY		11
#define PKCS11_F_PKCS11_ENUM_CERTS		12
#define PKCS11_F_PKCS11_INIT_TOKEN		13
#define PKCS11_F_PKCS11_INIT_PIN		14
#define PKCS11_F_PKCS11_LOGOUT			15
#define PKCS11_F_PKCS11_STORE_PRIVATE_KEY	16
#define PKCS11_F_PKCS11_GENERATE_KEY		17
#define PKCS11_F_PKCS11_STORE_PUBLIC_KEY	18
#define PKCS11_F_PKCS11_STORE_CERTIFICATE	19
#define PKCS11_F_PKCS11_GETATTR			40

#define PKCS11_ERR_BASE				1024
#define PKCS11_LOAD_MODULE_ERROR		(PKCS11_ERR_BASE+1)
#define PKCS11_MODULE_LOADED_ERROR		(PKCS11_ERR_BASE+2)
#define PKCS11_SYMBOL_NOT_FOUND_ERROR		(PKCS11_ERR_BASE+3)
#define PKCS11_NOT_SUPPORTED			(PKCS11_ERR_BASE+4)
#define PKCS11_NO_SESSION			(PKCS11_ERR_BASE+5)
#define PKCS11_KEYGEN_FAILED			(PKCS11_ERR_BASE+6)

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
	int type;		/* EVP_PKEY_xxx */
	int (*get_public) (PKCS11_KEY *, EVP_PKEY *);
	int (*get_private) (PKCS11_KEY *, EVP_PKEY *);
} PKCS11_KEY_ops;

typedef struct pkcs11_key_private {
	PKCS11_TOKEN *parent;
	CK_OBJECT_HANDLE object;
	unsigned char id[32];
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
	unsigned char id[32];
	size_t id_len;
} PKCS11_CERT_private;
#define PRIVCERT(cert)		((PKCS11_CERT_private *) cert->_private)

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

typedef int (*pkcs11_i2d_fn) (void *, unsigned char **);
extern void pkcs11_addattr(CK_ATTRIBUTE_PTR, int, const void *, size_t);
extern void pkcs11_addattr_int(CK_ATTRIBUTE_PTR, int, unsigned long);
extern void pkcs11_addattr_s(CK_ATTRIBUTE_PTR, int, const char *);
extern void pkcs11_addattr_bn(CK_ATTRIBUTE_PTR, int, const BIGNUM *);
extern void pkcs11_addattr_obj(CK_ATTRIBUTE_PTR, int, pkcs11_i2d_fn, void *);
extern void pkcs11_zap_attrs(CK_ATTRIBUTE_PTR, unsigned int);

extern void *memdup(const void *, size_t);

extern PKCS11_KEY_ops pkcs11_rsa_ops;

#ifdef  __cplusplus
}
#endif
#endif
