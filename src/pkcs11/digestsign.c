#include "sc-pkcs11.h"

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
		   CK_MECHANISM_PTR  pMechanism) /* the digesting mechanism */
{
        LOG("C_DigestInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,     /* the session's handle */
	       CK_BYTE_PTR       pData,        /* data to be digested */
	       CK_ULONG          ulDataLen,    /* bytes of data to be digested */
	       CK_BYTE_PTR       pDigest,      /* receives the message digest */
	       CK_ULONG_PTR      pulDigestLen) /* receives byte length of digest */
{
        LOG("C_Digest\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		     CK_BYTE_PTR       pPart,     /* data to be digested */
		     CK_ULONG          ulPartLen) /* bytes of data to be digested */
{
        LOG("C_DigestUpdate\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,  /* the session's handle */
		  CK_OBJECT_HANDLE  hKey)      /* handle of secret key to digest */
{
        LOG("C_DigestKey\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,     /* the session's handle */
		    CK_BYTE_PTR       pDigest,      /* receives the message digest */
		    CK_ULONG_PTR      pulDigestLen) /* receives byte count of digest */
{
        LOG("C_DigestFinal\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		 CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
		 CK_OBJECT_HANDLE  hKey)        /* handle of the signature key */
{
        LOG("C_SignInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,        /* the session's handle */
	     CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
	     CK_ULONG          ulDataLen,       /* count of bytes to be signed */
	     CK_BYTE_PTR       pSignature,      /* receives the signature */
	     CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        LOG("C_Sign\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pPart,     /* the data (digest) to be signed */
		   CK_ULONG          ulPartLen) /* count of bytes to be signed */
{
        LOG("C_SignUpdate\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,        /* the session's handle */
		  CK_BYTE_PTR       pSignature,      /* receives the signature */
		  CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        LOG("C_SignFinal\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
			CK_OBJECT_HANDLE  hKey)       /* handle of the signature key */
{
        LOG("C_SignRecoverInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,        /* the session's handle */
		    CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
		    CK_ULONG          ulDataLen,       /* count of bytes to be signed */
		    CK_BYTE_PTR       pSignature,      /* receives the signature */
		    CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
        LOG("C_SignRecover\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}



