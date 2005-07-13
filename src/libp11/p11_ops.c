/* p11_ops.c */
/* Written by Olaf Kirch <okir@lst.de>
 * Edited by Kevin Stefanik <kstef@mtppi.org>
 */
/* ====================================================================
 * Copyright (c) 1999-2004 The OpenSSL Project.  All rights reserved.
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


/* this file does certain cryptographic operations via the pkcs11 library */

#include <string.h>
#include "libp11-int.h"


int
pkcs11_sign(int type, const unsigned char *m, unsigned int m_len,
		unsigned char *sigret, unsigned int *siglen, const PKCS11_KEY * key)
{

	PKCS11_KEY_private *priv;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	int rv, ssl = ((type == NID_md5_sha1) ? 1 : 0);
	unsigned char *encoded = NULL;
	int sigsize;
	CK_ULONG ck_sigsize;

	if (key == NULL)
		return 0;
	ctx = KEY2CTX(key);
	priv = PRIVKEY(key);
	slot = TOKEN2SLOT(priv->parent);
	session = PRIVSLOT(slot)->session;
	
	sigsize=PKCS11_get_key_size(key);
	ck_sigsize=sigsize;

	if (ssl) {
		if((m_len != 36) /* SHA1 + MD5 */ ||
		   ((m_len + RSA_PKCS1_PADDING) > sigsize)) {
			return(0); /* the size is wrong */
		}
	} else {
		ASN1_TYPE parameter = { V_ASN1_NULL, { NULL } };
 		ASN1_STRING digest = { m_len, V_ASN1_OCTET_STRING, (unsigned char *)m };
		X509_ALGOR algor = { NULL, &parameter };
		X509_SIG digest_info = { &algor, &digest };
		int size;
		/* Fetch the OID of the algorithm used */
		if((algor.algorithm = OBJ_nid2obj(type)) && 
		   (algor.algorithm->length) &&
		   /* Get the size of the encoded DigestInfo */
		   (size = i2d_X509_SIG(&digest_info, NULL)) &&
		   /* Check that size is compatible with PKCS#11 padding */
		   (size + RSA_PKCS1_PADDING <= sigsize) &&
		   (encoded = (unsigned char *) malloc(sigsize))) {
			unsigned char *tmp = encoded;
			/* Actually do the encoding */
			i2d_X509_SIG(&digest_info,&tmp);
			m = encoded;
			m_len = size;
		} else {
			return(0);
		}
	}

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	/* API is somewhat fishy here. *siglen is 0 on entry (cleared
	 * by OpenSSL). The library assumes that the memory passed
	 * by the caller is always big enough */
	if((rv = CRYPTOKI_call(ctx, C_SignInit
			       (session, &mechanism, priv->object))) == 0) {
		rv = CRYPTOKI_call(ctx, C_Sign
				   (session, (CK_BYTE *) m, m_len,
				    sigret, &ck_sigsize));
	}
	*siglen = ck_sigsize;
	free(encoded);

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_SIGN, pkcs11_map_err(rv));
	}
	return (rv) ? 0 : 1;
}


int
pkcs11_private_encrypt(int flen, const unsigned char *from, unsigned char *to,
		   const PKCS11_KEY * rsa, int padding)
{
	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_ENCRYPT, PKCS11_NOT_SUPPORTED);
	return -1;
}

int
pkcs11_private_decrypt(int flen, const unsigned char *from, unsigned char *to,
		   PKCS11_KEY * key, int padding)
{
	CK_RV rv;
	PKCS11_KEY_private *priv;
	PKCS11_SLOT *slot;
	PKCS11_CTX *ctx;
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ULONG size;
								
	if (padding != RSA_PKCS1_PADDING) {
			printf("pkcs11 engine: only RSA_PKCS1_PADDING allowed so far\n");
			return -1;
	}
	if (key == NULL)
			return -1;

	/* PKCS11 calls go here */
										
	ctx = KEY2CTX(key);
	priv = PRIVKEY(key);
	slot = TOKEN2SLOT(priv->parent);
	session = PRIVSLOT(slot)->session;
	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	if( (rv = CRYPTOKI_call(ctx, C_DecryptInit(session, &mechanism, priv->object))) == 0) {
		rv = CRYPTOKI_call(ctx, C_Decrypt
			   (session, (CK_BYTE *) from, (CK_ULONG)flen,
	   		    (CK_BYTE_PTR)to, &size));
	}

	if (rv) {
		PKCS11err(PKCS11_F_PKCS11_RSA_DECRYPT, pkcs11_map_err(rv));
	}

	return (rv) ? 0 : size;
}

int
pkcs11_verify(int type, const unsigned char *m, unsigned int m_len,
		  unsigned char *signature, unsigned int siglen, PKCS11_KEY * key)
{

	/* PKCS11 calls go here */
	PKCS11err(PKCS11_F_PKCS11_RSA_VERIFY, PKCS11_NOT_SUPPORTED);
	return -1;
}

