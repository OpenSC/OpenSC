/* p11_slot.c */
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
#include <openssl/buffer.h>

static int pkcs11_init_slot(PKCS11_CTX *, PKCS11_SLOT *, CK_SLOT_ID);
static int pkcs11_check_token(PKCS11_CTX *, PKCS11_SLOT *);
static void pkcs11_destroy_token(PKCS11_TOKEN *);

/*
 * Enumerate slots
 */
int
PKCS11_enumerate_slots(PKCS11_CTX * ctx, PKCS11_SLOT ** slotp, unsigned int *countp)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);

	if (priv->nslots < 0) {
		CK_SLOT_ID slotid[64];
		CK_ULONG nslots = sizeof(slotid), n;
		PKCS11_SLOT *slots;
		int rv;

		rv = priv->method->C_GetSlotList(FALSE, slotid, &nslots);
		CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_SLOTS, rv);

		slots = (PKCS11_SLOT *) pkcs11_malloc(nslots * sizeof(PKCS11_SLOT));
		for (n = 0; n < nslots; n++) {
			if (pkcs11_init_slot(ctx, &slots[n], slotid[n])) {
				while (n--)
					pkcs11_destroy_slot(ctx, slots + n);
				OPENSSL_free(slots);
				return -1;
			}
		}
		priv->nslots = nslots;
		priv->slots = slots;
	}

	*slotp = priv->slots;
	*countp = priv->nslots;
	return 0;
}

/*
 * Find a slot with a token that looks "valuable"
 */
PKCS11_SLOT *PKCS11_find_token(PKCS11_CTX * ctx)
{
	PKCS11_SLOT *slot_list, *slot, *best;
	PKCS11_TOKEN *tok;
	unsigned int n, nslots;

	if (PKCS11_enumerate_slots(ctx, &slot_list, &nslots))
		return NULL;

	best = NULL;
	for (n = 0, slot = slot_list; n < nslots; n++, slot++) {
		if ((tok = slot->token) != NULL) {
			if (best == NULL
			    || (tok->initialized > best->token->initialized
				&& tok->userPinSet > best->token->userPinSet
				&& tok->loginRequired > best->token->loginRequired))
				best = slot;
		}
	}
	return best;
}

/*
 * Open a session with this slot
 */
int PKCS11_open_session(PKCS11_SLOT * slot, int rw)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = SLOT2CTX(slot);
	int rv;

	if (priv->haveSession) {
		CRYPTOKI_call(ctx, C_CloseSession(priv->session));
		priv->haveSession = 0;
	}
	rv = CRYPTOKI_call(ctx,
			   C_OpenSession(priv->id,
					 CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION :
							       0), NULL, NULL,
					 &priv->session));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_OPEN_SESSION, rv);
	priv->haveSession = 1;

	return 0;
}

/*
 * Authenticate with the card
 */
int PKCS11_login(PKCS11_SLOT * slot, int so, char *pin)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	/* Calling PKCS11_login invalidates all cached
	 * keys we have */
	if (slot->token)
		pkcs11_destroy_keys(slot->token);
	if (priv->loggedIn) {
		/* already logged in, log out first */
		if (PKCS11_logout(slot))
			return -1;
	}
	if (!priv->haveSession) {
		/* SO gets a r/w session by default,
		 * user gets a r/o session by default. */
		if (PKCS11_open_session(slot, so))
			return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Login(priv->session,
					so ? CKU_SO : CKU_USER,
					(CK_UTF8CHAR *) pin, strlen(pin)));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_LOGIN, rv);
	priv->loggedIn = 1;
	return 0;
}

/*
 * Log out
 */
int PKCS11_logout(PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_CTX *ctx = priv->parent;
	int rv;

	/* Calling PKCS11_logout invalidates all cached
	 * keys we have */
	if (slot->token)
		pkcs11_destroy_keys(slot->token);
	if (!priv->haveSession) {
		PKCS11err(PKCS11_F_PKCS11_LOGOUT, PKCS11_NO_SESSION);
		return -1;
	}

	rv = CRYPTOKI_call(ctx, C_Logout(priv->session));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_LOGOUT, rv);
	priv->loggedIn = 0;
	return 0;
}

/*
 * Initialize the token
 */
int PKCS11_init_token(PKCS11_TOKEN * token, char *pin, char *label)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(TOKEN2SLOT(token));
	PKCS11_CTX_private *cpriv;
	PKCS11_CTX *ctx = priv->parent;
	int n, rv;

	if (!label)
		label = "PKCS#11 Token";
	rv = CRYPTOKI_call(ctx, C_InitToken(priv->id,
					    (CK_UTF8CHAR *) pin, strlen(pin),
					    (CK_UTF8CHAR *) label));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_INIT_TOKEN, rv);

	cpriv = PRIVCTX(ctx);
	for (n = 0; n < cpriv->nslots; n++) {
		if (pkcs11_check_token(ctx, cpriv->slots + n) < 0)
			return -1;
	}

	return 0;
}

/*
 * Set the User PIN
 */
int PKCS11_init_pin(PKCS11_TOKEN * token, char *pin)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(TOKEN2SLOT(token));
	PKCS11_CTX *ctx = priv->parent;
	int len, rv;

	if (!priv->haveSession) {
		PKCS11err(PKCS11_F_PKCS11_INIT_PIN, PKCS11_NO_SESSION);
		return -1;
	}

	len = pin ? strlen(pin) : 0;
	rv = CRYPTOKI_call(ctx, C_InitPIN(priv->session, (CK_UTF8CHAR *) pin, len));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_INIT_PIN, rv);

	return pkcs11_check_token(ctx, TOKEN2SLOT(token));
}

/*
 * Helper functions
 */
int pkcs11_init_slot(PKCS11_CTX * ctx, PKCS11_SLOT * slot, CK_SLOT_ID id)
{
	PKCS11_SLOT_private *priv;
	CK_SLOT_INFO info;
	int rv;

	rv = CRYPTOKI_call(ctx, C_GetSlotInfo(id, &info));
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_ENUM_SLOTS, rv);

	priv = PKCS11_NEW(PKCS11_SLOT_private);
	priv->parent = ctx;
	priv->id = id;

	slot->description = PKCS11_DUP(info.slotDescription);
	slot->manufacturer = PKCS11_DUP(info.manufacturerID);
	slot->removable = (info.flags & CKF_REMOVABLE_DEVICE) ? 1 : 0;
	slot->_private = priv;

	if ((info.flags & CKF_TOKEN_PRESENT) && pkcs11_check_token(ctx, slot))
		return -1;

	return 0;
}

void pkcs11_destroy_all_slots(PKCS11_CTX * ctx)
{
	PKCS11_CTX_private *priv = PRIVCTX(ctx);

	while (priv->nslots > 0)
		pkcs11_destroy_slot(ctx, &priv->slots[--(priv->nslots)]);
	OPENSSL_free(priv->slots);
	priv->slots = NULL;
	priv->nslots = -1;
}

void pkcs11_destroy_slot(PKCS11_CTX * ctx, PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);

	CRYPTOKI_call(ctx, C_CloseAllSessions(priv->id));
	OPENSSL_free(slot->_private);
	OPENSSL_free(slot->description);
	OPENSSL_free(slot->manufacturer);
	if (slot->token) {
		pkcs11_destroy_token(slot->token);
		OPENSSL_free(slot->token);
	}
	memset(slot, 0, sizeof(*slot));
}

int pkcs11_check_token(PKCS11_CTX * ctx, PKCS11_SLOT * slot)
{
	PKCS11_SLOT_private *priv = PRIVSLOT(slot);
	PKCS11_TOKEN_private *tpriv;
	CK_TOKEN_INFO info;
	PKCS11_TOKEN *token;
	int rv;

	if (slot->token)
		pkcs11_destroy_token(slot->token);
	else
		slot->token = PKCS11_NEW(PKCS11_TOKEN);
	token = slot->token;

	rv = CRYPTOKI_call(ctx, C_GetTokenInfo(priv->id, &info));
	if (rv == CKR_TOKEN_NOT_PRESENT) {
		OPENSSL_free(token);
		slot->token = NULL;
		return 0;
	}
	CRYPTOKI_checkerr(PKCS11_F_PKCS11_CHECK_TOKEN, rv);

	/* We have a token */
	tpriv = PKCS11_NEW(PKCS11_TOKEN_private);
	tpriv->parent = slot;
	tpriv->nkeys = -1;
	tpriv->ncerts = -1;

	token->label = PKCS11_DUP(info.label);
	token->manufacturer = PKCS11_DUP(info.manufacturerID);
	token->model = PKCS11_DUP(info.model);
	token->initialized = (info.flags & CKF_TOKEN_INITIALIZED) ? 1 : 0;
	token->loginRequired = (info.flags & CKF_LOGIN_REQUIRED) ? 1 : 0;
	token->userPinSet = (info.flags & CKF_USER_PIN_INITIALIZED) ? 1 : 0;
	token->readOnly = (info.flags & CKF_WRITE_PROTECTED) ? 1 : 0;
	token->_private = tpriv;

	return 0;
}

void pkcs11_destroy_token(PKCS11_TOKEN * token)
{
	/* XXX destroy keys associated with this token */
	OPENSSL_free(token->label);
	OPENSSL_free(token->manufacturer);
	OPENSSL_free(token->model);
	OPENSSL_free(token->_private);
	memset(token, 0, sizeof(*token));
}
