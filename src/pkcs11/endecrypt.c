#include "sc-pkcs11.h"

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of encryption key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,            /* the session's handle */
		CK_BYTE_PTR       pData,               /* the plaintext data */
		CK_ULONG          ulDataLen,           /* bytes of plaintext data */
		CK_BYTE_PTR       pEncryptedData,      /* receives encrypted data */
		CK_ULONG_PTR      pulEncryptedDataLen) /* receives encrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,           /* the session's handle */
		      CK_BYTE_PTR       pPart,              /* the plaintext data */
		      CK_ULONG          ulPartLen,          /* bytes of plaintext data */
		      CK_BYTE_PTR       pEncryptedPart,     /* receives encrypted data */
		      CK_ULONG_PTR      pulEncryptedPartLen)/* receives encrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,                /* the session's handle */
		     CK_BYTE_PTR       pLastEncryptedPart,      /* receives encrypted last part */
		     CK_ULONG_PTR      pulLastEncryptedPartLen) /* receives byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of the decryption key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,           /* the session's handle */
		CK_BYTE_PTR       pEncryptedData,     /* input encrypted data */
		CK_ULONG          ulEncryptedDataLen, /* count of bytes of input */
		CK_BYTE_PTR       pData,              /* receives decrypted output */
		CK_ULONG_PTR      pulDataLen)         /* receives decrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
		      CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
		      CK_ULONG          ulEncryptedPartLen,  /* count of bytes of input */
		      CK_BYTE_PTR       pPart,               /* receives decrypted output */
		      CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,       /* the session's handle */
		     CK_BYTE_PTR       pLastPart,      /* receives decrypted output */
		     CK_ULONG_PTR      pulLastPartLen)  /* receives decrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}


