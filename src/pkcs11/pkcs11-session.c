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


#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "sc-pkcs11.h"
#include <sc-log.h>

CK_RV C_OpenSession(CK_SLOT_ID            slotID,        /* the slot's ID */
		    CK_FLAGS              flags,         /* defined in CK_SESSION_INFO */
		    CK_VOID_PTR           pApplication,  /* pointer passed to callback */
		    CK_NOTIFY             Notify,        /* notification callback function */
		    CK_SESSION_HANDLE_PTR phSession)     /* receives new session handle */
{
	struct sc_pkcs11_slot *slot;
        struct sc_pkcs11_session *session;
	int rv;

	debug(context, "Opening new session for slot %d\n", slotID);

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

        rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		return rv;

	/* Check that no conflictions sessions exist */
	if (!(flags & CKF_RW_SESSION) && (slot->login_user == CKU_SO))
		return CKR_SESSION_READ_WRITE_SO_EXISTS;

        session = (struct sc_pkcs11_session*) malloc(sizeof(struct sc_pkcs11_session));
	memset(session, 0, sizeof(struct sc_pkcs11_session));
	session->slot = slot;
	session->notify_callback = Notify;
        session->notify_data = pApplication;
        session->flags = flags;

	rv = pool_insert(&session_pool, session, phSession);
	if (rv != CKR_OK)
                free(session);
	else
		slot->nsessions++;

        return rv;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	struct sc_pkcs11_slot *slot;
	int rv;
        struct sc_pkcs11_session *session;

	rv = pool_find_and_delete(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
                return rv;

	/* If we're the last session using this slot, make sure
	 * we log out */
	slot = session->slot;
	slot->nsessions--;
	if (slot->nsessions == 0 && slot->login_user >= 0) {
		slot->login_user = -1;
		slot->card->framework->logout(slot->card, slot->fw_data);
	}

	free(session);
        return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) /* the token's slot */
{
	struct sc_pkcs11_pool_item *item, *next;
        struct sc_pkcs11_session *session;

	for (item = session_pool.head; item != NULL; item = next) {
		session = (struct sc_pkcs11_session*) item->item;
                next = item->next;

		if (session->slot->id == slotID) {
                        C_CloseSession(item->handle);
		}
	}

        return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,  /* the session's handle */
		       CK_SESSION_INFO_PTR pInfo)   /* receives session information */
{
        int rv;
	struct sc_pkcs11_session *session;

        rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		return rv;

	pInfo->slotID = session->slot->id;
        pInfo->flags = session->flags;
        pInfo->ulDeviceError = 0;

	switch (session->slot->login_user) {
	case CKU_USER:
		pInfo->state = (session->flags & CKF_RW_SESSION)
			? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
                break;
	case CKU_SO:
		pInfo->state = CKS_RW_SO_FUNCTIONS;
                break;
	default:
		pInfo->state = (session->flags & CKF_RW_SESSION)
			? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	}

        return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,             /* the session's handle */
			  CK_BYTE_PTR       pOperationState,      /* location receiving state */
			  CK_ULONG_PTR      pulOperationStateLen) /* location receiving state length */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,            /* the session's handle */
			  CK_BYTE_PTR      pOperationState,      /* the location holding the state */
			  CK_ULONG         ulOperationStateLen,  /* location holding state length */
			  CK_OBJECT_HANDLE hEncryptionKey,       /* handle of en/decryption key */
			  CK_OBJECT_HANDLE hAuthenticationKey)   /* handle of sign/verify key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,  /* the session's handle */
	      CK_USER_TYPE      userType,  /* the user type */
	      CK_CHAR_PTR       pPin,      /* the user's PIN */
	      CK_ULONG          ulPinLen)  /* the length of the PIN */
{
        int rv;
	struct sc_pkcs11_session *session;
        struct sc_pkcs11_slot *slot;

	if (userType != CKU_USER)
                return CKR_USER_TYPE_INVALID;

        rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		return rv;

	debug(context, "Login for session %d\n", hSession);

        slot = session->slot;

	if (slot->login_user >= 0)
                return CKR_USER_ALREADY_LOGGED_IN;

	rv = slot->card->framework->login(slot->card,
                                          slot->fw_data,
					  pPin, ulPinLen);
	if (rv == CKR_OK)
                slot->login_user = userType;

        return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        int rv;
	struct sc_pkcs11_session *session;
        struct sc_pkcs11_slot *slot;

        rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		return rv;

	debug(context, "Logout for session %d\n", hSession);

	slot = session->slot;

	slot->login_user = -1;
        return slot->card->framework->logout(slot->card, slot->fw_data);
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
#if 0
	struct pkcs11_session *ses;
        struct sc_pkcs15_card *card;
	int rc;

	LOG("C_SetPIN(%d, '%s', %d, '%s', %d)\n", hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

#if 0
	if (!(ses->flags & CKF_RW_SESSION))
		return CKR_SESSION_READ_ONLY;
#endif
	ses = session[hSession];
	card = slot[ses->slot].p15card;

	LOG("Master PIN code update starts.\n");
        rc = sc_pkcs15_change_pin(card, &card->pin_info[0], pOldPin, ulOldLen, pNewPin, ulNewLen);
	switch (rc) {
	case 0:
		LOG("Master PIN code CHANGED succesfully.\n");
                break;
	case SC_ERROR_PIN_CODE_INCORRECT:
                LOG("Master PIN code INVALID!\n");
		return CKR_PIN_INCORRECT;
	default:
                LOG("Device error!? rc=%d\n", rc);
                return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
#endif
        return CKR_FUNCTION_NOT_SUPPORTED;
}

