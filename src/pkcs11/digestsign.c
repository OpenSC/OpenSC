/*
 * digestsign.c: PKCS#11 functions for signing and calculating digest
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
#include <ctype.h>

#include "sc-pkcs11.h"

static void hex_dump(const unsigned char *buf, int count)
{
	int i;
	for (i = 0; i < count; i++) {
                unsigned char c = buf[i];
		int printch = 0;
		if (!isalnum(c) && !ispunct(c) && !isspace(c))
			printch = 0;
                if (printch)
			LOG("%02X%c ", c, c);
		else
                        LOG("%02X  ", c);
	}
	LOG("\n");
}

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
	struct pkcs11_slot *slt;
	struct pkcs11_session *ses;
	struct pkcs11_object *object;

	LOG("C_SignInit(%d, {%d, 0x%x, %d}, %d)\n",
	    hSession,
            pMechanism->mechanism, pMechanism->pParameter, pMechanism->ulParameterLen,
	    hKey);

	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;
        ses = session[hSession];
	slt = &slot[ses->slot];
	if (hKey < 1 || hKey > slt->num_objects)
                return CKR_OBJECT_HANDLE_INVALID;
	object = slt->object[hKey];

	if (object->object_type != CKO_PRIVATE_KEY)
                return CKR_OBJECT_HANDLE_INVALID;

	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		// Signing according to PKCS#1 standard
                LOG("CKM_RSA_PKCS mechanism requested\n");
		ses->sign.algorithm_ref = 0x02;
		break;
	default:
		LOG("Requested mechanism #d not supported\n", pMechanism->mechanism);
                break;
	}

	LOG("Token id is %d\n", object->token_id);
        ses->sign.private_key_id = object->token_id;

	return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,        /* the session's handle */
	     CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
	     CK_ULONG          ulDataLen,       /* count of bytes to be signed */
	     CK_BYTE_PTR       pSignature,      /* receives the signature */
	     CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
	char signature[1024];
        struct sc_pkcs15_card *p15card;
	struct pkcs11_session *ses;
        int c;

	LOG("C_Sign(%d, 0x%x, %d, 0x%x, 0x%x)\n",
	    hSession, pData, ulDataLen, pSignature, pulSignatureLen);
        hex_dump(pData, ulDataLen);

	if (hSession < 1 || hSession > PKCS11_MAX_SESSIONS || session[hSession] == NULL)
		return CKR_SESSION_HANDLE_INVALID;
        ses = session[hSession];
	p15card = slot[ses->slot].p15card;

	c = sc_pkcs15_compute_signature(p15card, &p15card->prkey_info[ses->sign.private_key_id],
					SC_PKCS15_HASH_NONE, pData, ulDataLen,
					signature, sizeof(signature));
	if (c < 0) {
		LOG("Compute signature failed: (%d) %s\n", c, sc_strerror(c));
                return CKR_DEVICE_ERROR;
	}

	if (*pulSignatureLen < c) {
                LOG("Buffer too small, %d < %d\n", *pulSignatureLen, c);
		return CKR_BUFFER_TOO_SMALL;
	}

        LOG("Got signature, %d bytes (buffer was %d)\n", c, *pulSignatureLen);
        hex_dump(signature, c);
	memcpy(pSignature, signature, c);
        *pulSignatureLen = c;

	return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pPart,     /* the data (digest) to be signed */
		   CK_ULONG          ulPartLen) /* count of bytes to be signed */
{
	LOG("C_SignUpdate(%d, 0x%x, %d)\n",
	    hSession, pPart, ulPartLen);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,        /* the session's handle */
		  CK_BYTE_PTR       pSignature,      /* receives the signature */
		  CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
	LOG("C_SignFinal(%d, 0x%x, %d)\n",
	    hSession, pSignature, pulSignatureLen);
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



