/* p11_load.c */
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

static void *handle = NULL;

/*
 * Create a new context
 */
PKCS11_CTX *PKCS11_CTX_new(void)
{
	PKCS11_CTX_private *priv;
	PKCS11_CTX *ctx;

	/* Load error strings */
	ERR_load_PKCS11_strings();

	priv = PKCS11_NEW(PKCS11_CTX_private);
	ctx = PKCS11_NEW(PKCS11_CTX);
	ctx->_private = priv;

	/* Mark list of slots as "need to fetch from card" */
	priv->nslots = -1;

	return ctx;
}

/*
 * Load the shared library, and initialize it.
 */
int PKCS11_CTX_load(PKCS11_CTX * ctx, const char *name)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);
	CK_INFO ck_info;
	int rv;

	if (priv->libinfo != NULL) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_MODULE_LOADED_ERROR);
		return -1;
	}
	handle = C_LoadModule(name, &priv->method);
	if (!handle) {
		PKCS11err(PKCS11_F_PKCS11_CTX_LOAD, PKCS11_LOAD_MODULE_ERROR);
		return -1;
	}

	/* Tell the PKCS11 to initialize itself */
	rv = priv->method->C_Initialize(NULL);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CTX_LOAD, rv);

	/* Get info on the library */
	rv = priv->method->C_GetInfo(&ck_info);
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CTX_LOAD, rv);

	ctx->manufacturer = PKCS11_DUP(ck_info.manufacturerID);
	ctx->description = PKCS11_DUP(ck_info.libraryDescription);

	return 0;
}

/*
 * Unload the shared library
 */
void PKCS11_CTX_unload(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv;
	priv = PRIVCTX(ctx);

	/* Free any slot info we have allocated */
	pkcs11_destroy_all_slots(ctx);

	/* Tell the PKCS11 library to shut down */
	priv->method->C_Finalize(NULL);

	/* Unload the module */
	C_UnloadModule(handle);
}

/*
 * Free a context
 */
void PKCS11_CTX_free(PKCS11_CTX * ctx)
{
	PKCS11_CTX_unload(ctx);	/* Make sure */
	OPENSSL_free(ctx->manufacturer);
	OPENSSL_free(ctx->description);
	OPENSSL_free(ctx->_private);
	OPENSSL_free(ctx);
}
