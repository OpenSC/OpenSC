/* Copyright (C) 2001  Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#include "sc-pkcs11.h"

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of encryption key */
{
        LOG("C_EncryptInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,            /* the session's handle */
		CK_BYTE_PTR       pData,               /* the plaintext data */
		CK_ULONG          ulDataLen,           /* bytes of plaintext data */
		CK_BYTE_PTR       pEncryptedData,      /* receives encrypted data */
		CK_ULONG_PTR      pulEncryptedDataLen) /* receives encrypted byte count */
{
        LOG("C_Encrypt\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,           /* the session's handle */
		      CK_BYTE_PTR       pPart,              /* the plaintext data */
		      CK_ULONG          ulPartLen,          /* bytes of plaintext data */
		      CK_BYTE_PTR       pEncryptedPart,     /* receives encrypted data */
		      CK_ULONG_PTR      pulEncryptedPartLen)/* receives encrypted byte count */
{
        LOG("C_EncryptUpdate\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,                /* the session's handle */
		     CK_BYTE_PTR       pLastEncryptedPart,      /* receives encrypted last part */
		     CK_ULONG_PTR      pulLastEncryptedPartLen) /* receives byte count */
{
        LOG("C_EncryptFinal\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of the decryption key */
{
        LOG("C_DecryptInit\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,           /* the session's handle */
		CK_BYTE_PTR       pEncryptedData,     /* input encrypted data */
		CK_ULONG          ulEncryptedDataLen, /* count of bytes of input */
		CK_BYTE_PTR       pData,              /* receives decrypted output */
		CK_ULONG_PTR      pulDataLen)         /* receives decrypted byte count */
{
        LOG("C_Decrypt\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
		      CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
		      CK_ULONG          ulEncryptedPartLen,  /* count of bytes of input */
		      CK_BYTE_PTR       pPart,               /* receives decrypted output */
		      CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
        LOG("C_DecryptUpdate\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,       /* the session's handle */
		     CK_BYTE_PTR       pLastPart,      /* receives decrypted output */
		     CK_ULONG_PTR      pulLastPartLen)  /* receives decrypted byte count */
{
        LOG("C_DecryptFinal\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
}


