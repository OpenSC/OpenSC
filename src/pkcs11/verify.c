#include "sc-pkcs11.h"

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		   CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
		   CK_OBJECT_HANDLE  hKey)        /* handle of the verification key */
{
        LOG("C_VerifyInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,       /* the session's handle */
	       CK_BYTE_PTR       pData,          /* plaintext data (digest) to compare */
	       CK_ULONG          ulDataLen,      /* length of data (digest) in bytes */
	       CK_BYTE_PTR       pSignature,     /* the signature to be verified */
	       CK_ULONG          ulSignatureLen) /* count of bytes of signature */
{
        LOG("C_Verify\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		     CK_BYTE_PTR       pPart,     /* plaintext data (digest) to compare */
		     CK_ULONG          ulPartLen) /* length of data (digest) in bytes */
{
        LOG("C_VerifyUpdate\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,       /* the session's handle */
		    CK_BYTE_PTR       pSignature,     /* the signature to be verified */
		    CK_ULONG          ulSignatureLen) /* count of bytes of signature */
{
        LOG("C_VerifyFinal\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
			  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
			  CK_OBJECT_HANDLE  hKey)        /* handle of the verification key */
{
        LOG("C_VerifyRecoverInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,        /* the session's handle */
		      CK_BYTE_PTR       pSignature,      /* the signature to be verified */
		      CK_ULONG          ulSignatureLen,  /* count of bytes of signature */
		      CK_BYTE_PTR       pData,           /* receives decrypted data (digest) */
		      CK_ULONG_PTR      pulDataLen)      /* receives byte count of data */
{
        LOG("C_VerifyRecover\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}


