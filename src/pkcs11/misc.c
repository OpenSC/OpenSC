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

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pPart,               /* the plaintext data */
			    CK_ULONG          ulPartLen,           /* bytes of plaintext data */
			    CK_BYTE_PTR       pEncryptedPart,      /* receives encrypted data */
			    CK_ULONG_PTR      pulEncryptedPartLen) /* receives encrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
			    CK_ULONG          ulEncryptedPartLen,  /* count of bytes of input */
			    CK_BYTE_PTR       pPart,               /* receives decrypted output */
			    CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			  CK_BYTE_PTR       pPart,               /* the plaintext data */
			  CK_ULONG          ulPartLen,           /* bytes of plaintext data */
			  CK_BYTE_PTR       pEncryptedPart,      /* receives encrypted data */
			  CK_ULONG_PTR      pulEncryptedPartLen) /* receives encrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
			    CK_ULONG          ulEncryptedPartLen,  /* count of byes of input */
			    CK_BYTE_PTR       pPart,               /* receives decrypted output */
			    CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE    hSession,    /* the session's handle */
		    CK_MECHANISM_PTR     pMechanism,  /* the key generation mechanism */
		    CK_ATTRIBUTE_PTR     pTemplate,   /* template for the new key */
		    CK_ULONG             ulCount,     /* number of attributes in template */
		    CK_OBJECT_HANDLE_PTR phKey)       /* receives handle of new key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE    hSession,                    /* the session's handle */
			CK_MECHANISM_PTR     pMechanism,                  /* the key gen. mech. */
			CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* pub. attr. template */
			CK_ULONG             ulPublicKeyAttributeCount,   /* # of pub. attrs. */
			CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* priv. attr. template */
			CK_ULONG             ulPrivateKeyAttributeCount,  /* # of priv. attrs. */
			CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
			CK_OBJECT_HANDLE_PTR phPrivateKey)                /* gets priv. key handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
		CK_OBJECT_HANDLE  hWrappingKey,    /* handle of the wrapping key */
		CK_OBJECT_HANDLE  hKey,            /* handle of the key to be wrapped */
		CK_BYTE_PTR       pWrappedKey,     /* receives the wrapped key */
		CK_ULONG_PTR      pulWrappedKeyLen)/* receives byte size of wrapped key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		  CK_MECHANISM_PTR     pMechanism,        /* the unwrapping mechanism */
		  CK_OBJECT_HANDLE     hUnwrappingKey,    /* handle of the unwrapping key */
		  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
		  CK_ULONG             ulWrappedKeyLen,   /* bytes length of wrapped key */
		  CK_ATTRIBUTE_PTR     pTemplate,         /* template for the new key */
		  CK_ULONG             ulAttributeCount,  /* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)             /* gets handle of recovered key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		  CK_MECHANISM_PTR     pMechanism,        /* the key derivation mechanism */
		  CK_OBJECT_HANDLE     hBaseKey,          /* handle of the base key */
		  CK_ATTRIBUTE_PTR     pTemplate,         /* template for the new key */
		  CK_ULONG             ulAttributeCount,  /* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)             /* gets handle of derived key */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pSeed,     /* the seed material */
		   CK_ULONG          ulSeedLen) /* count of bytes of seed material */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,    /* the session's handle */
		       CK_BYTE_PTR       RandomData,  /* receives the random data */
		       CK_ULONG          ulRandomLen) /* number of bytes to be generated */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) /* the session's handle */
{
        return CKR_FUNCTION_NOT_SUPPORTED;
}


