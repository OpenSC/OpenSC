/* libp11.h */
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

#ifndef _LIB11_H
#define _LIB11_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

/* get some structures for local code to handle pkcs11 data readily */
#define ERR_LIB_PKCS11	ERR_LIB_USER

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
	unsigned char secureLogin;
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
extern int PKCS11_login(PKCS11_SLOT *, int so, const char *pin);
extern int PKCS11_logout(PKCS11_SLOT *);

/* Get a list of all keys associated with this token */
extern int PKCS11_enumerate_keys(PKCS11_TOKEN *, PKCS11_KEY **, unsigned int *);

/* Get the key type (as EVP_PKEY_XXX) */
extern int PKCS11_get_key_type(PKCS11_KEY *);

/* Get size of key modulus in number of bytes */
extern int PKCS11_get_key_size(PKCS11_KEY *);
/* Get actual modules and public exponent as BIGNUM */
extern int PKCS11_get_key_modulus(PKCS11_KEY *, BIGNUM **);
extern int PKCS11_get_key_exponent(PKCS11_KEY *, BIGNUM **);

/* Get the enveloped private key */
extern EVP_PKEY *PKCS11_get_private_key(PKCS11_KEY *);
extern EVP_PKEY *PKCS11_get_public_key(PKCS11_KEY *);

/* Find the corresponding certificate (if any) */
extern PKCS11_CERT *PKCS11_find_certificate(PKCS11_KEY *);

/* Find the corresponding key (if any) */
extern PKCS11_KEY *PKCS11_find_key(PKCS11_CERT *);

/* Get a list of all certificates associated with this token */
extern int PKCS11_enumerate_certs(PKCS11_TOKEN *, PKCS11_CERT **, unsigned int *);

/* Initialize a token */
extern int PKCS11_init_token(PKCS11_TOKEN *, const char *pin,
	const char *label);

/* Initialize the user PIN on a token */
extern int PKCS11_init_pin(PKCS11_TOKEN *, const char *pin);

/* Change the user PIN on a token */
extern int PKCS11_change_pin(PKCS11_SLOT *, const char *old_pin,
	const char *new_pin);

/* Store various objects on the token */
extern int PKCS11_generate_key(PKCS11_TOKEN *, int, unsigned int, char *);
extern int PKCS11_store_private_key(PKCS11_TOKEN *, EVP_PKEY *, char *);

/* rsa private key operations */
extern int PKCS11_sign(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const PKCS11_KEY * key);
extern int PKCS11_private_encrypt(int flen, const unsigned char *from,
	unsigned char *to, const PKCS11_KEY * rsa, int padding);
extern int PKCS11_private_decrypt(int flen, const unsigned char *from,
	unsigned char *to, PKCS11_KEY * key, int padding);
extern int PKCS11_verify(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_KEY * key);

/* access random number generator */
extern int PKCS11_seed_random(PKCS11_SLOT *, const unsigned char *s, unsigned int s_len);
extern int PKCS11_generate_random(PKCS11_SLOT *, unsigned char *r, unsigned int r_len);

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
#define PKCS11_F_PKCS11_SEED_RANDOM		20
#define PKCS11_F_PKCS11_GENERATE_RANDOM		21
#define PKCS11_F_PKCS11_CHANGE_PIN		22
#define PKCS11_F_PKCS11_GETATTR			40

#define PKCS11_ERR_BASE				1024
#define PKCS11_LOAD_MODULE_ERROR		(PKCS11_ERR_BASE+1)
#define PKCS11_MODULE_LOADED_ERROR		(PKCS11_ERR_BASE+2)
#define PKCS11_SYMBOL_NOT_FOUND_ERROR		(PKCS11_ERR_BASE+3)
#define PKCS11_NOT_SUPPORTED			(PKCS11_ERR_BASE+4)
#define PKCS11_NO_SESSION			(PKCS11_ERR_BASE+5)
#define PKCS11_KEYGEN_FAILED			(PKCS11_ERR_BASE+6)

#ifdef __cplusplus
}
#endif
#endif
