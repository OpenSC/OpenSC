#include <stdio.h>
#include <malloc.h>
#include "sc-pkcs11.h"


CK_RV C_OpenSession(CK_SLOT_ID            slotID,        /* the slot's ID */
		    CK_FLAGS              flags,         /* defined in CK_SESSION_INFO */
		    CK_VOID_PTR           pApplication,  /* pointer passed to callback */
		    CK_NOTIFY             Notify,        /* notification callback function */
		    CK_SESSION_HANDLE_PTR phSession)     /* receives new session handle */
{
	int i, rc;
        struct pkcs11_session *ses;

	LOG("C_OpenSession(%d, 0x%x, 0x%x, 0x%x, 0x%x)\n",
	    slotID, flags, pApplication, Notify, phSession);

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	for (i=1; i<PKCS11_MAX_SESSIONS; i++)
		if (session[i] == NULL)
			break;

	if (i >= PKCS11_MAX_SESSIONS)
		return CKR_SESSION_COUNT;

	if (!(slot[slotID].flags & SLOT_CONNECTED)) {
		rc = slot_connect(slotID);
		if (rc)
                        return rc;
	}

	ses = session[i] = (struct pkcs11_session*) malloc(sizeof(struct pkcs11_session));
	memset(ses, 0, sizeof(struct pkcs11_session));
	ses->slot = slotID;
        if (flags & CKF_RW_SESSION)
		ses->state = CKS_RW_PUBLIC_SESSION;
	else    ses->state = CKS_RO_PUBLIC_SESSION;
        ses->flags = flags;
	ses->notify_callback = Notify;
        ses->notify_parameter = pApplication;

        *phSession = i;
        return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	LOG("C_CloseSession(%d)\n", hSession);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	free(session[hSession]);
        session[hSession] = NULL;
        return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) /* the token's slot */
{
	int i;

	LOG("C_CloseAllSessions(%d)\n", slotID);
	for (i = 0; i < PKCS11_MAX_SESSIONS; i++) {
		if (session[i] && session[i]->slot == slotID)
                        C_CloseSession(i);
	}

        return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,  /* the session's handle */
		       CK_SESSION_INFO_PTR pInfo)   /* receives session information */
{
        struct pkcs11_session *ses;

	LOG("C_GetSessionInfo(%d, 0x%x)\n", hSession, pInfo);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

        ses = session[hSession];
	pInfo->slotID = ses->slot;
	pInfo->state = ses->state;
        pInfo->flags = ses->flags;
        pInfo->ulDeviceError = 0;

        return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,             /* the session's handle */
			  CK_BYTE_PTR       pOperationState,      /* location receiving state */
			  CK_ULONG_PTR      pulOperationStateLen) /* location receiving state length */
{
	LOG("C_GetOperationState(%d, %0x%x, %d)\n", hSession,
	    pOperationState, pulOperationStateLen);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,            /* the session's handle */
			  CK_BYTE_PTR      pOperationState,      /* the location holding the state */
			  CK_ULONG         ulOperationStateLen,  /* location holding state length */
			  CK_OBJECT_HANDLE hEncryptionKey,       /* handle of en/decryption key */
			  CK_OBJECT_HANDLE hAuthenticationKey)   /* handle of sign/verify key */
{
	LOG("C_SetOperationState(%d, 0x%x, %d, 0x%x, 0x%x)\n",
	    hSession, pOperationState, ulOperationStateLen,
	    hEncryptionKey, hAuthenticationKey);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession,  /* the session's handle */
	      CK_USER_TYPE      userType,  /* the user type */
	      CK_CHAR_PTR       pPin,      /* the user's PIN */
	      CK_ULONG          ulPinLen)  /* the length of the PIN */
{
	struct pkcs11_session *ses;
        struct sc_pkcs15_card *card;
        int rc;

	LOG("C_Login(%d, %d, 0x%x, %d)\n", hSession, userType, pPin, ulPinLen);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	if (userType != CKU_USER) {
		LOG("Login tried for Security Officer\n");
                return CKR_USER_TYPE_INVALID;
	}

	if (ulPinLen < 4 || ulPinLen > 8)
                return CKR_PIN_LEN_RANGE;

	ses = session[hSession];
	card = slot[ses->slot].p15card;

	if (ses->state != CKS_RO_PUBLIC_SESSION &&
	    ses->state != CKS_RW_PUBLIC_SESSION)
                return CKR_USER_ALREADY_LOGGED_IN;

	LOG("Master PIN code verification starts.\n");
        rc = sc_pkcs15_verify_pin(card, &card->pins[0], pPin, ulPinLen);
	switch (rc) {
	case 0:
                LOG("Master PIN code verified succesfully.\n");
		if (ses->state == CKS_RO_PUBLIC_SESSION)
			ses->state = CKS_RO_USER_FUNCTIONS;
		else    ses->state = CKS_RW_USER_FUNCTIONS;
                break;
	case SC_ERROR_PIN_CODE_INCORRECT:
                LOG("Master PIN code INVALID!\n");
		return CKR_PIN_INCORRECT;
	default:
                LOG("Device error!? rc=%d\n", rc);
                return CKR_DEVICE_ERROR;
	}

        return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	struct pkcs11_session *ses;

	LOG("C_Logout(%d)\n", hSession);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	ses = session[hSession];
	switch (ses->state) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RW_PUBLIC_SESSION:
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RO_USER_FUNCTIONS:
		ses->state = CKS_RO_PUBLIC_SESSION;
                break;
	case CKS_RW_USER_FUNCTIONS:
	case CKS_RW_SO_FUNCTIONS:
		ses->state = CKS_RW_PUBLIC_SESSION;
                break;
	}

        return CKR_OK;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
        LOG("C_InitPIN(%d, '%s', %d)\n", hSession, pPin, ulPinLen);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
	struct pkcs11_session *ses;
        struct sc_pkcs15_card *card;
	int rc;

	LOG("C_SetPIN(%d, '%s', %d, '%s', %d)\n", hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	//if (!(ses->flags & CKF_RW_SESSION))
	//	return CKR_SESSION_READ_ONLY;

	ses = session[hSession];
	card = slot[ses->slot].p15card;

	LOG("Master PIN code update starts.\n");
        rc = sc_pkcs15_change_pin(card, &card->pins[0], pOldPin, ulOldLen, pNewPin, ulNewLen);
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
}

