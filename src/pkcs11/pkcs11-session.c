/*
 * pkcs11-session.c: PKCS#11 functions for session management
 *
 * Copyright (C) 2001  Timo Teräs <timo.teras@iki.fi>
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

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sc-pkcs11.h"

CK_RV get_session(CK_SESSION_HANDLE hSession, struct sc_pkcs11_session **session)
{
	*session = list_seek(&sessions, &hSession);
	if (!*session)
		return CKR_SESSION_HANDLE_INVALID;
	return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID,	/* the slot's ID */
		    CK_FLAGS flags,	/* defined in CK_SESSION_INFO */
		    CK_VOID_PTR pApplication,	/* pointer passed to callback */
		    CK_NOTIFY Notify,	/* notification callback function */
		    CK_SESSION_HANDLE_PTR phSession)
{				/* receives new session handle */
	CK_RV rv;
	struct sc_pkcs11_slot *slot;
	struct sc_pkcs11_session *session;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	if (flags & ~(CKF_SERIAL_SESSION | CKF_RW_SESSION))
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_OpenSession(0x%lx)", slotID);

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	/* Check that no conflicting sessions exist */
	if (!(flags & CKF_RW_SESSION) && (slot->login_user == CKU_SO)) {
		rv = CKR_SESSION_READ_WRITE_SO_EXISTS;
		goto out;
	}

	session = (struct sc_pkcs11_session *)calloc(1, sizeof(struct sc_pkcs11_session));
	if (session == NULL) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	/* make session handle from pointer and check its uniqueness */
	session->handle = (CK_SESSION_HANDLE)(uintptr_t)session;
	if (list_seek(&sessions, &session->handle) != NULL) {
		sc_log(context, "C_OpenSession handle 0x%lx already exists", session->handle);

		free(session);

		rv = CKR_HOST_MEMORY;
		goto out;
	}

	session->slot = slot;
	session->notify_callback = Notify;
	session->notify_data = pApplication;
	session->flags = flags;
	slot->nsessions++;
	list_append(&sessions, session);
	*phSession = session->handle;
	sc_log(context, "C_OpenSession handle: 0x%lx", session->handle);

out:
	sc_log(context, "C_OpenSession() = %s", lookup_enum(RV_T, rv));
	sc_pkcs11_unlock();
	return rv;
}

/* Internal version of C_CloseSession that gets called with
 * the global lock held */
static CK_RV sc_pkcs11_close_session(CK_SESSION_HANDLE hSession)
{
	struct sc_pkcs11_slot *slot;
	struct sc_pkcs11_session *session;

	sc_log(context, "real C_CloseSession(0x%lx)", hSession);

	session = list_seek(&sessions, &hSession);
	if (!session)
		return CKR_SESSION_HANDLE_INVALID;

	/* If we're the last session using this slot, make sure
	 * we log out */
	slot = session->slot;
	slot->nsessions--;
	if (slot->nsessions == 0 && slot->login_user >= 0) {
		slot->login_user = -1;
		if (sc_pkcs11_conf.atomic)
			pop_all_login_states(slot);
		else {
			if (slot->p11card == NULL)
				return CKR_TOKEN_NOT_RECOGNIZED;
			slot->p11card->framework->logout(slot);
		}
	}

	if (list_delete(&sessions, session) != 0)
		sc_log(context, "Could not delete session from list!");
	free(session);
	return CKR_OK;
}

/* Internal version of C_CloseAllSessions that gets called with
 * the global lock held */
CK_RV sc_pkcs11_close_all_sessions(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK, error;
	struct sc_pkcs11_session *session;
	unsigned int i;
	sc_log(context, "real C_CloseAllSessions(0x%lx) %d", slotID, list_size(&sessions));
	for (i = 0; i < list_size(&sessions); i++) {
		session = list_get_at(&sessions, i);
		if (session->slot->id == slotID)
			if ((error = sc_pkcs11_close_session(session->handle)) != CKR_OK)
				rv = error;
	}
	return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{				/* the session's handle */
	CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_CloseSession(0x%lx)", hSession);

	rv = sc_pkcs11_close_session(hSession);

	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{				/* the token's slot */
	CK_RV rv;
	struct sc_pkcs11_slot *slot;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_CloseAllSessions(0x%lx)", slotID);

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_close_all_sessions(slotID);

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,	/* the session's handle */
		       CK_SESSION_INFO_PTR pInfo)
{				/* receives session information */
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;
	int logged_out;

	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_GetSessionInfo(hSession:0x%lx)", hSession);

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	sc_log(context, "C_GetSessionInfo(slot:0x%lx)", session->slot->id);
	pInfo->slotID = session->slot->id;
	pInfo->flags = session->flags;
	pInfo->ulDeviceError = 0;

	slot = session->slot;
	logged_out = (slot_get_logged_in_state(slot) == SC_PIN_STATE_LOGGED_OUT);
	if (logged_out && slot->login_user > -1) {
		sc_pkcs11_close_all_sessions(session->slot->id);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (slot->login_user == CKU_SO && !logged_out) {
		pInfo->state = CKS_RW_SO_FUNCTIONS;
	} else if ((slot->login_user == CKU_USER && !logged_out) || (!(slot->token_info.flags & CKF_LOGIN_REQUIRED))) {
		pInfo->state = (session->flags & CKF_RW_SESSION)
		    ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
	} else {
		pInfo->state = (session->flags & CKF_RW_SESSION)
		    ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	}

out:
	sc_log(context, "C_GetSessionInfo(0x%lx) = %s", hSession, lookup_enum(RV_T, rv));
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,	/* the session's handle */
			  CK_BYTE_PTR pOperationState,	/* location receiving state */
			  CK_ULONG_PTR pulOperationStateLen)
{				/* location receiving state length */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,	/* the session's handle */
			  CK_BYTE_PTR pOperationState,	/* the location holding the state */
			  CK_ULONG ulOperationStateLen,	/* location holding state length */
			  CK_OBJECT_HANDLE hEncryptionKey,	/* handle of en/decryption key */
			  CK_OBJECT_HANDLE hAuthenticationKey)
{				/* handle of sign/verify key */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,	/* the session's handle */
	      CK_USER_TYPE userType,	/* the user type */
	      CK_CHAR_PTR pPin,	/* the user's PIN */
	      CK_ULONG ulPinLen)
{				/* the length of the PIN */
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	if (pPin == NULL_PTR && ulPinLen > 0)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (userType != CKU_USER && userType != CKU_SO && userType != CKU_CONTEXT_SPECIFIC) {
		rv = CKR_USER_TYPE_INVALID;
		goto out;
	}
	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	sc_log(context, "C_Login(0x%lx, %lu)", hSession, userType);

	slot = session->slot;

	if (!(slot->token_info.flags & CKF_USER_PIN_INITIALIZED) && userType == CKU_USER) {
		rv = CKR_USER_PIN_NOT_INITIALIZED;
		goto out;
	}

	/* TODO: check if context specific is valid */
	if (userType == CKU_CONTEXT_SPECIFIC) {
		if (slot->login_user == -1) {
			rv = CKR_OPERATION_NOT_INITIALIZED;
		}
		else   {
			rv = restore_login_state(slot);
			if (rv == CKR_OK && slot->p11card && slot->p11card->framework)
				rv = slot->p11card->framework->login(slot, userType, pPin, ulPinLen);
			rv = reset_login_state(slot, rv);
		}
	}
	else {
		sc_log(context, "C_Login() slot->login_user %i", slot->login_user);
		if (slot->login_user >= 0) {
			if ((CK_USER_TYPE) slot->login_user == userType)
				rv = CKR_USER_ALREADY_LOGGED_IN;
			else
				rv = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
			goto out;
		}

		rv = restore_login_state(slot);
		if (rv == CKR_OK) {
			sc_log(context, "C_Login() userType %li", userType);
			if (slot->p11card == NULL)
				return CKR_TOKEN_NOT_RECOGNIZED;
			rv = slot->p11card->framework->login(slot, userType, pPin, ulPinLen);
			sc_log(context, "fLogin() rv %li", rv);
		}
		if (rv == CKR_OK)
			rv = push_login_state(slot, userType, pPin, ulPinLen);
		if (rv == CKR_OK) {
			slot->login_user = (int) userType;
		}
		rv = reset_login_state(slot, rv);
	}

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{				/* the session's handle */
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	sc_log(context, "C_Logout(hSession:0x%lx)", hSession);

	slot = session->slot;

	if (slot->login_user >= 0) {
		slot->login_user = -1;
		if (sc_pkcs11_conf.atomic)
			pop_all_login_states(slot);
		else {
			if (!slot->p11card)
				return CKR_TOKEN_NOT_RECOGNIZED;
			rv = slot->p11card->framework->logout(slot);
		}
	} else
		rv = CKR_USER_NOT_LOGGED_IN;

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	sc_log(context, "C_InitPIN() called, pin '%s'", pPin ? (char *) pPin : "<null>");
	if (pPin == NULL_PTR && ulPinLen > 0)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	if (!(session->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}

	slot = session->slot;
	if (slot->login_user != CKU_SO) {
		rv = CKR_USER_NOT_LOGGED_IN;
	} else if (slot->p11card == NULL || slot->p11card->framework->init_pin == NULL) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	} else {
		rv = restore_login_state(slot);
		if (rv == CKR_OK) {
			rv = slot->p11card->framework->init_pin(slot, pPin, ulPinLen);
			sc_log(context, "C_InitPIN() init-pin result %li", rv);
		}
		rv = reset_login_state(slot, rv);
	}

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	if ((pOldPin == NULL_PTR && ulOldLen > 0) || (pNewPin == NULL_PTR && ulNewLen > 0))
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	slot = session->slot;
	sc_log(context, "Changing PIN (session 0x%lx; login user %d)", hSession, slot->login_user);

	if (!(session->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}

	rv = restore_login_state(slot);
	if (rv == CKR_OK) {
		if (slot->p11card == NULL)
			return CKR_TOKEN_NOT_RECOGNIZED;
		rv = slot->p11card->framework->change_pin(slot, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	rv = reset_login_state(slot, rv);

out:
	sc_pkcs11_unlock();
	return rv;
}
