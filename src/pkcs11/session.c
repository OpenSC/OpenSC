#include "sc-pkcs11.h"


CK_RV C_OpenSession(CK_SLOT_ID            slotID,        /* the slot's ID */
		    CK_FLAGS              flags,         /* defined in CK_SESSION_INFO */
		    CK_VOID_PTR           pApplication,  /* pointer passed to callback */
		    CK_NOTIFY             Notify,        /* notification callback function */
		    CK_SESSION_HANDLE_PTR phSession)     /* receives new session handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) /* the token's slot */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,  /* the session's handle */
		       CK_SESSION_INFO_PTR pInfo)   /* receives session information */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
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
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}


