#include "sc-pkcs11.h"

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
		   CK_MECHANISM_PTR  pMechanism) /* the digesting mechanism */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,     /* the session's handle */
	       CK_BYTE_PTR       pData,        /* data to be digested */
	       CK_ULONG          ulDataLen,    /* bytes of data to be digested */
	       CK_BYTE_PTR       pDigest,      /* receives the message digest */
	       CK_ULONG_PTR      pulDigestLen) /* receives byte length of digest */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		     CK_BYTE_PTR       pPart,     /* data to be digested */
		     CK_ULONG          ulPartLen) /* bytes of data to be digested */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,  /* the session's handle */
		  CK_OBJECT_HANDLE  hKey)      /* handle of secret key to digest */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,     /* the session's handle */
		    CK_BYTE_PTR       pDigest,      /* receives the message digest */
		    CK_ULONG_PTR      pulDigestLen) /* receives byte count of digest */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		 CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
		 CK_OBJECT_HANDLE  hKey)        /* handle of the signature key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,        /* the session's handle */
	     CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
	     CK_ULONG          ulDataLen,       /* count of bytes to be signed */
	     CK_BYTE_PTR       pSignature,      /* receives the signature */
	     CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pPart,     /* the data (digest) to be signed */
		   CK_ULONG          ulPartLen) /* count of bytes to be signed */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,        /* the session's handle */
		  CK_BYTE_PTR       pSignature,      /* receives the signature */
		  CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
			CK_OBJECT_HANDLE  hKey)       /* handle of the signature key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,        /* the session's handle */
		    CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
		    CK_ULONG          ulDataLen,       /* count of bytes to be signed */
		    CK_BYTE_PTR       pSignature,      /* receives the signature */
		    CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}



