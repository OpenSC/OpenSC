/*
 * cardmod.c: card module support for opensc
 *
 * Copyright (C) 2009,2010 francois.leblanc@cev-sa.com 
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

/*
 * This module require "cardmod.h" from CNG SDK or plattform SDK to
 * be build. 
 */

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include "cardmod.h"

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

/* if use of internal-winscard.h */
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER		0x80100004L
#define SCARD_E_UNSUPPORTED_FEATURE		0x80100022L
#define SCARD_E_NO_MEMORY				0x80100006L
#define SCARD_W_WRONG_CHV				0x8010006BL
#define SCARD_E_FILE_NOT_FOUND			0x80100024L
#define SCARD_E_UNKNOWN_CARD			0x8010000DL
#define SCARD_F_UNKNOWN_ERROR			0x80100014L
#endif

typedef struct _VENDOR_SPECIFIC
{
	BYTE bPinsFreshness;
	char *pin;
	
	sc_pkcs15_object_t *cert_objs[32];
	int cert_count;
	sc_pkcs15_object_t *prkey_objs[32];
	int prkey_count;
	sc_pkcs15_object_t *pin_objs[8];
	int pin_count;
	
	sc_context_t *ctx;
	sc_reader_t *reader;
	sc_card_t *card;
	sc_pkcs15_card_t *p15card;

	sc_pkcs15_object_t *pkey;

	struct {
		BYTE file_appdir[9];
		CARD_CACHE_FILE_FORMAT file_cardcf;
		BYTE file_cardid[16];
	}cardFiles;
	
}VENDOR_SPECIFIC;

static void logprintf(PCARD_DATA pCardData, int level, const char* format, ...)
{
	va_list arg;
	VENDOR_SPECIFIC *vs;
	
	va_start(arg, format);
	if(pCardData != NULL)
	{
		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(vs != NULL && vs->ctx != NULL)
		{
#ifdef _MSC_VER
			sc_debug(vs->ctx, level, format, arg);
#else
			/* FIXME: trouble in vsprintf with %S arg under
			mingw32
			*/
			if(vs->ctx->debug>=level) {
				vfprintf(vs->ctx->debug_file, format, arg);
			}
#endif
		}
	}
	va_end(arg);
} 

static void print_werror(PCARD_DATA pCardData, char *str)
{
	void *buf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	  FORMAT_MESSAGE_FROM_SYSTEM |
	  FORMAT_MESSAGE_IGNORE_INSERTS,
	  NULL,GetLastError(),0,
	  (LPTSTR) &buf,0,NULL);

	logprintf(pCardData, 0, "%s%s\n", str, buf);
	LocalFree(buf);
}

/*
 * Compute modulus length
 */
static size_t compute_keybits(sc_pkcs15_bignum_t *bn)
{
	unsigned int mask, bits;

	if (!bn || !bn->len)
		return 0;
	bits = bn->len << 3;
	for (mask = 0x80; !(bn->data[0] & mask); mask >>= 1)
		bits--;
	return bits;
}

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	int i;
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 1, "CardDeleteContext\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;
	
	if(vs->pin != NULL)
	{	
		free(vs->pin);
		vs->pin = NULL;
	}

	if(vs->p15card)
	{
		logprintf(pCardData, 6, "sc_pkcs15_unbind\n");
		sc_pkcs15_unbind(vs->p15card);
	}

	if(vs->card)
	{
		logprintf(pCardData, 6, "sc_disconnect_card\n");
		sc_disconnect_card(vs->card);
		vs->card = NULL;
	}
	
	if(vs->ctx)
	{
		logprintf(pCardData, 6, "release context\n");
		sc_release_context(vs->ctx);
		vs->ctx = NULL;
	}

	logprintf(pCardData, 1, "***********************************" \
					"***********************************\n");

	pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	pCardData->pvVendorSpecific = NULL;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData, 
	__in PCARD_CAPABILITIES  pCardCapabilities)
{
	logprintf(pCardData, 1, "pCardCapabilities=%X\n", pCardCapabilities);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pCardCapabilities) return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION
		&& pCardCapabilities->dwVersion != 0)
			return ERROR_REVISION_MISMATCH;
	
	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	logprintf(pCardData, 1, "CardDeleteContainer\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData)
{
	logprintf(pCardData, 1, "CardCreateContainer\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBKEYSTRUCT_BASE;

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in PCONTAINER_INFO pContainerInfo)
{
	int r;
	int lg;
	char name[100];
	void  *pkeyblob, *pubkeyblob;
	sc_pkcs15_cert_t *cert = NULL;
	VENDOR_SPECIFIC *vs = NULL;
	
	PUBKEYSTRUCT_BASE *oh = NULL;
	DWORD sz = 0;

	DWORD ret;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	
	logprintf(pCardData, 1, "CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, " \
		"dwVersion=%u, cbSigPublicKey=%u, cbKeyExPublicKey=%u\n", \
		bContainerIndex, dwFlags, pContainerInfo->dwVersion, \
		pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if(!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo) SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (pContainerInfo->dwVersion < 0 
		|| pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION) 
			return ERROR_REVISION_MISMATCH;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	
	if(bContainerIndex>=vs->cert_count)
		return SCARD_E_INVALID_PARAMETER;
	
	r = sc_pkcs15_read_certificate(vs->p15card, \
		(struct sc_pkcs15_cert_info *)(vs->cert_objs[bContainerIndex]->data), \
		&cert);
	logprintf(pCardData, 1, "read_certificate %d return %d, cert = %p\n", \
		bContainerIndex, r, cert);
	if(r)
	{
		return SCARD_E_FILE_NOT_FOUND;
	}
	pubkey = cert->key;

	if(pubkey->algorithm == SC_ALGORITHM_RSA)
	{
		int modulus = compute_keybits(&(pubkey->u.rsa.modulus));
		sz = sizeof(*oh)+modulus/8;
		oh = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
		if(oh)
		{
			PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING \
				| PKCS_7_ASN_ENCODING, cert->data, cert->data_len);
			PCERT_PUBLIC_KEY_INFO pinf = \
				&(cer->pCertInfo->SubjectPublicKeyInfo);
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, \
				RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData, \
				pinf->PublicKey.cbData , 0, oh, &sz);

		
			oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
			pContainerInfo->cbKeyExPublicKey = 0;
			pContainerInfo->pbKeyExPublicKey = NULL;
			pContainerInfo->cbSigPublicKey = sz;
			pContainerInfo->pbSigPublicKey = (PBYTE)oh;
			pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

			logprintf(pCardData, 3, "return info on SIGN_CONTAINER_INDEX\n");
			ret = SCARD_S_SUCCESS;
		}
		else
		{
			ret = SCARD_E_NO_MEMORY;
		}
	}

	if(cert)
	{
		sc_pkcs15_free_certificate(cert);
	}

	return ret;
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in PBYTE pbPin,
	__in DWORD cbPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	int r;
	sc_pkcs15_object_t *pin_obj;
	char type[256];
	VENDOR_SPECIFIC *vs;

	if(!pCardData) return SCARD_E_INVALID_PARAMETER;
	
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 1, "CardAuthenticatePin %S %d %d\n", NULLWSTR(pwszUserId), \
		cbPin, vs->bPinsFreshness);

	if (NULL == pwszUserId) return SCARD_E_INVALID_PARAMETER;
	if (wcscmp(wszCARD_USER_USER,pwszUserId) != 0 && \
		wcscmp(wszCARD_USER_ADMIN,pwszUserId) != 0) \
			return SCARD_E_INVALID_PARAMETER;
	if (NULL == pbPin) return SCARD_E_INVALID_PARAMETER;

	if (cbPin < 4 || cbPin > 12) return SCARD_W_WRONG_CHV;

	if (wcscmp(wszCARD_USER_ADMIN,pwszUserId) == 0) 
	{
		return SCARD_W_WRONG_CHV;
	}
	
	wcstombs(type, pwszUserId, 100);
	type[10] = 0;
	
	logprintf(pCardData, 1, "CardAuthenticatePin %.20s, %d, %d\n", NULLSTR(type), \
		cbPin, (pcAttemptsRemaining==NULL?-2:*pcAttemptsRemaining));
	
	pin_obj = vs->pin_objs[0];
	r = sc_pkcs15_verify_pin(vs->p15card, pin_obj, (const u8 *) pbPin, cbPin);
	if (r) 
	{
		logprintf(pCardData, 3, "PIN code verification failed: %s\n", sc_strerror(r));
		
		if(pcAttemptsRemaining) 
		{
			(*pcAttemptsRemaining) = -1;
		}
		return SCARD_W_WRONG_CHV;
	}
	
	logprintf(pCardData, 3, "Pin code correct.\n");
	
	SET_PIN(vs->cardFiles.file_cardcf.bPinsFreshness, ROLE_USER);
	
	return SCARD_S_SUCCESS; 
}

DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out                                 PDWORD pcbChallengeData)
{
	logprintf(pCardData, 1, "CardGetChallenge\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE  pbResponseData,
	__in DWORD  cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "CardAuthenticateChallenge\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardUnblockPin(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData) PBYTE  pbAuthenticationData,
	__in DWORD  cbAuthenticationData,
	__in_bcount(cbNewPinData) PBYTE  pbNewPinData,
	__in DWORD  cbNewPinData,
	__in DWORD  cRetryCount,
	__in DWORD  dwFlags)
{
	logprintf(pCardData, 1, "CardUnblockPin\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbCurrentAuthenticator) PBYTE pbCurrentAuthenticator,
	__in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator) PBYTE pbNewAuthenticator,
	__in DWORD cbNewAuthenticator,
	__in DWORD cRetryCount,
	__in DWORD dwFlags,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "CardChangeAuthenticator\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "CardDeauthenticate\n");

	if(!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	CLEAR_PIN(vs->cardFiles.file_cardcf.bPinsFreshness, ROLE_USER);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "CardCreateDirectory\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName)

{
	logprintf(pCardData, 1, "CardDeleteDirectory\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "CardCreateFile\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "CardReadFile\n");

	if(!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 2, "pszDirectoryName = %s, pszFileName = %s, " \
		"dwFlags = %X, pcbData=%d, *ppbData=%X\n", \
		NULLSTR(pszDirectoryName), NULLSTR(pszFileName), \
		dwFlags, *pcbData, *ppbData);

	if (!pszFileName) return SCARD_E_INVALID_PARAMETER;
	if (!strlen(pszFileName)) return SCARD_E_INVALID_PARAMETER;
	if (!ppbData) return SCARD_E_INVALID_PARAMETER;
	if (!pcbData) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	if(pszDirectoryName == NULL)
	{
		if(strcmp(pszFileName, "cardid") == 0) 
		{
			*pcbData = strlen(vs->p15card->tokeninfo->serial_number) + 10;
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			if(!*ppbData)
			{
				return SCARD_E_NO_MEMORY;
			}
			
			strcpy(*ppbData, vs->p15card->tokeninfo->serial_number);
			
			logprintf(pCardData, 7, "return cardid\n");

			return SCARD_S_SUCCESS;
		}

		if(strcmp(pszFileName, "cardcf") == 0) 
		{
			char texte[2048];
			
			*pcbData = sizeof(vs->cardFiles.file_cardcf);
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			if(!*ppbData)
			{
				return SCARD_E_NO_MEMORY;
			}
			
			memcpy(*ppbData, &(vs->cardFiles.file_cardcf), *pcbData);

			sc_bin_to_hex((unsigned char*)&(vs->cardFiles.file_cardcf), \
				sizeof(vs->cardFiles.file_cardcf), texte, sizeof(texte)-5, ':');

			logprintf(pCardData, 7, "return cardcf = %s\n", texte);

			return SCARD_S_SUCCESS;
		}

	}
	
	if(pszDirectoryName != NULL && strcmp(pszDirectoryName, "mscp") == 0)
	{
		int r,i,n, type;
		sc_pkcs15_cert_t *cert = NULL;

		if(strcmp(pszFileName, "cmapfile") == 0) 
		{
			PCONTAINER_MAP_RECORD p;
			sc_pkcs15_pubkey_t *pubkey = NULL;
			
			*pcbData = 32*sizeof(CONTAINER_MAP_RECORD);
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			if(!*ppbData)
			{
				return SCARD_E_NO_MEMORY;
			}
			
			memset(*ppbData, 0, *pcbData);
			
			for(i = 0, p = (PCONTAINER_MAP_RECORD)*ppbData; \
				i < vs->cert_count; i++,p++)
			{
				sc_pkcs15_cert_t *cert = NULL;
				
				r = sc_pkcs15_read_certificate(vs->p15card, \
					(struct sc_pkcs15_cert_info *)(vs->cert_objs[i]->data), \
					&cert);
				logprintf(pCardData, 2, "sc_pkcs15_read_certificate return %d\n", r);
				if(r)
				{
					return SCARD_E_FILE_NOT_FOUND;
				}
				pubkey = cert->key;
				if(pubkey->algorithm == SC_ALGORITHM_RSA)
				{
#ifdef _MSC_VER
					swprintf(p->wszGuid, sizeof(p->wszGuid), L"%0*.*d", MAX_CONTAINER_NAME_LEN, \
						MAX_CONTAINER_NAME_LEN, i);
#else
					swprintf(p->wszGuid, L"%0*.*d", MAX_CONTAINER_NAME_LEN, \
						MAX_CONTAINER_NAME_LEN, i);
#endif
					
					p->bFlags += CONTAINER_MAP_VALID_CONTAINER;
					if(i == 0)
					{
						p->bFlags += CONTAINER_MAP_DEFAULT_CONTAINER;
					}
					p->wSigKeySizeBits = \
						compute_keybits(&(pubkey->u.rsa.modulus));
					p->wKeyExchangeKeySizeBits = \
						compute_keybits(&(pubkey->u.rsa.modulus));
				}
				sc_pkcs15_free_certificate(cert);
			}

			logprintf(pCardData, 7, "return cmapfile\n");

			return SCARD_S_SUCCESS;
		}
		
		if(sscanf(pszFileName, "ksc%d", &n) <= 0)
		{
			if(sscanf(pszFileName, "kxc%d", &n) <= 0)
			{
				n = -1;
			}
		}
		
		logprintf(pCardData, 7, "n = %d\n", n);
		
		if(n>=0 && n<vs->cert_count)
		{
			sc_pkcs15_cert_t *cert = NULL;
			
			r = sc_pkcs15_read_certificate(vs->p15card, \
				(struct sc_pkcs15_cert_info *)(vs->cert_objs[n]->data), \
				&cert);
			logprintf(pCardData, 2, "Reading certificat return %d\n", r);
			if(r)
			{
				return SCARD_E_FILE_NOT_FOUND;
			}
			
			*pcbData = cert->data_len;
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			
			if(*ppbData == NULL)
			{
				logprintf(pCardData, 0, "memory error\n");
				return SCARD_E_NO_MEMORY;
			}
			
			CopyMemory(*ppbData, cert->data, *pcbData);

			if(1)
			{
				char texte[2048];
				sc_bin_to_hex(*ppbData, *pcbData, texte, sizeof(texte)-5, ':');
				logprintf(pCardData, 6, "*ppbData = %s\n", texte);
			}

			sc_pkcs15_free_certificate(cert);
			
			return SCARD_S_SUCCESS;
		}
	}
	
	logprintf(pCardData, 5, "File not found\n");
	return SCARD_E_FILE_NOT_FOUND;
}

DWORD WINAPI CardWriteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData)
{
	logprintf(pCardData, 1, "CardWriteFile %s %d\n", NULLSTR(pszFileName), cbData);

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
		
	if(pszDirectoryName == NULL)
	{
		if(strcmp(pszFileName, "cardcf") == 0) 
		{
			logprintf(pCardData, 2, "write cardcf ok.\n");
			return SCARD_S_SUCCESS;
		}
	}
	
	return SCARD_E_FILE_NOT_FOUND;
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardDeleteFile\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags)
{
	const char root_files[] = "cardapps\0cardcf\0cardid\0\0";
	const char mscp_files[] = "kxc00\0kxc01\0cmapfile\0\0";
	
	logprintf(pCardData, 1, "CardEnumFiles\n");
	
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pmszFileNames) return SCARD_E_INVALID_PARAMETER;
	if (!pdwcbFileName) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	if (!pszDirectoryName || !strlen(pszDirectoryName)) 
	{
		DWORD sz = sizeof(root_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return SCARD_E_NO_MEMORY;
		CopyMemory(t,root_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return SCARD_S_SUCCESS;
	}
	if (strcmpi(pszDirectoryName,"mscp") == 0) 
	{
		DWORD sz = sizeof(mscp_files) - 1;
		LPSTR t = (LPSTR)(*pCardData->pfnCspAlloc)(sz);
		if (!t) return SCARD_E_NO_MEMORY;
		CopyMemory(t,mscp_files,sz);
		*pmszFileNames = t;
		*pdwcbFileName = sz;
		return SCARD_S_SUCCESS;
	}
	
	return SCARD_E_FILE_NOT_FOUND;
}

DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in PCARD_FILE_INFO pCardFileInfo)
{
	logprintf(pCardData, 1, "CardGetFileInfo\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData,
	__in DWORD dwFlags,
	__in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	
	logprintf(pCardData, 1, "CardQueryFreeSpace %X, dwFlags=%X, version=%X\n", \
		pCardFreeSpaceInfo, dwFlags, pCardFreeSpaceInfo->dwVersion);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = -1;
	pCardFreeSpaceInfo->dwMaxKeyContainers = vs->cert_count;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = vs->cert_count;

	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__out PCARD_KEY_SIZES pKeySizes)
{
	logprintf(pCardData, 1, "CardQueryKeySizes dwKeySpec=%X, dwFlags=%X, version=%X\n", \
		dwKeySpec, dwFlags, pKeySizes->dwVersion);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pKeySizes) return SCARD_E_INVALID_PARAMETER;
	
	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwMinimumBitlen = 512;
	pKeySizes->dwDefaultBitlen = 1024;
	pKeySizes->dwMaximumBitlen = 16384;
	pKeySizes->dwIncrementalBitlen = 64;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo)

{
	logprintf(pCardData, 1, "CardRSADecrypt\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardSignData(__in PCARD_DATA pCardData,
	__in PCARD_SIGNING_INFO pInfo)
{
	int r;
	int i, opt_crypt_flags = 0;
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg = pInfo->aiHashAlg;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_prkey_info_t *prkey_info;
	
	logprintf(pCardData, 1, "CardSignData\n");

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSignData dwVersion=%u, bContainerIndex=%u," \
		"dwKeySpec=%u, dwSigningFlags=0x%08X, aiHashAlg=0x%08X, cbData=%u\n", \
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, \
		pInfo->dwSigningFlags, pInfo->aiHashAlg, pInfo->cbData);
		
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	vs->pkey = NULL;
	
	logprintf(pCardData, 2, "pInfo->dwVersion = %d\n", pInfo->dwVersion);

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags) 
	{
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType) 
		{
			logprintf(pCardData, 0, "unsupported paddingtype\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		opt_crypt_flags += SC_ALGORITHM_RSA_PAD_PKCS1;
		if (!pinf->pszAlgId) 
		{
			/* hashAlg = CALG_SSL3_SHAMD5; */
			logprintf(pCardData, 0, "unsupported hashAlg\n");
		}
		else 
		{
			
			if (wcscmp(pinf->pszAlgId, L"MD5") == 0)  opt_crypt_flags += SC_ALGORITHM_RSA_HASH_MD5;
			if (wcscmp(pinf->pszAlgId, L"SHA1") == 0)  opt_crypt_flags += SC_ALGORITHM_RSA_HASH_SHA1;
		}
	}
	else
	{
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");
		
		opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1;
		
		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH) 
		{
			logprintf(pCardData, 0, "bogus aiHashAlg\n");
			return SCARD_E_INVALID_PARAMETER;
		}
		if (hashAlg !=0 && hashAlg != CALG_SSL3_SHAMD5 &&
			hashAlg != CALG_SHA1 && hashAlg != CALG_MD5) 
		{
			logprintf(pCardData, 0, "unsupported aiHashAlg\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}

		if (hashAlg == CALG_MD5) 
			opt_crypt_flags += SC_ALGORITHM_RSA_HASH_MD5;
		if (hashAlg == CALG_SHA1) 
			opt_crypt_flags += SC_ALGORITHM_RSA_HASH_SHA1;
		
		
	}
	
	logprintf(pCardData, 2, "pInfo->pbSignedData = %p, opt_crypt_flags = 0x%08X\n", \
		pInfo->pbSignedData, opt_crypt_flags);
	
	if(!(pInfo->bContainerIndex < vs->cert_count))
	{
		return SCARD_E_INVALID_PARAMETER;
	}
		
	cert_info = (struct sc_pkcs15_cert_info *) \
		(vs->cert_objs[pInfo->bContainerIndex]->data);
	
	for(i = 0; i < vs->prkey_count; i++)
	{
		sc_pkcs15_object_t *obj = (sc_pkcs15_object_t *)vs->prkey_objs[i];
		if(sc_pkcs15_compare_id(&((struct sc_pkcs15_prkey_info *) obj->data)->id, &(cert_info->id)))
		{
			vs->pkey = vs->prkey_objs[i];
			break;
		}
	}
	
	if(vs->pkey == NULL)
	{
		return SCARD_E_INVALID_PARAMETER;
	}
	
	prkey_info = (sc_pkcs15_prkey_info_t*)(vs->pkey->data);
	
	pInfo->cbSignedData = prkey_info->modulus_length / 8;
	logprintf(pCardData, 3, "pInfo->cbSignedData = %d\n", pInfo->cbSignedData);
	
	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))
	{
		int r,i;
		char texte[1024];
		BYTE *pbuf = NULL, *pbuf2 = NULL;
		DWORD lg, lg2;
		
		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %d\n", lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf) 
		{
			return SCARD_E_NO_MEMORY;
		}
		
		lg2 = pInfo->cbData;
		pbuf2 = pCardData->pfnCspAlloc(lg2);
		if (!pbuf2) 
		{
			pCardData->pfnCspFree(pbuf);
			return SCARD_E_NO_MEMORY;
		}

		sc_bin_to_hex(pInfo->pbData, pInfo->cbData, texte, \
			sizeof(texte)-24, ':');
		logprintf(pCardData, 3, "pInfo->pbData = %s\n", texte);
		
		/*inversion donnees*/
		for(i = 0; i < lg2; i++) pbuf2[i] = pInfo->pbData[lg2-i-1];

		sc_bin_to_hex(pbuf2, lg2, texte, sizeof(texte)-24, ':');
		logprintf(pCardData, 3, "pbuf2 = %s\n", texte);
		

		pInfo->pbSignedData = pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData) 
		{
			pCardData->pfnCspFree(pbuf);
			pCardData->pfnCspFree(pbuf2);
			return SCARD_E_NO_MEMORY;
		}
		
		r = sc_pkcs15_compute_signature(vs->p15card, vs->pkey, \
			opt_crypt_flags, pInfo->pbData, pInfo->cbData, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)
		{
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature erreur %s\n", \
				sc_strerror(r));
		}

		pCardData->pfnCspFree(pbuf2);

		pInfo->cbSignedData = r;
		
		/*inversion donnees*/
		for(i = 0; i < r; i++) pInfo->pbSignedData[i] = pbuf[r-i-1];

		sc_bin_to_hex(pbuf, r, texte, sizeof(texte)-24, ':');
		logprintf(pCardData, 3, "pbuf = %s\n", texte);

		pCardData->pfnCspFree(pbuf);
		
		logprintf(pCardData, 3, "sc_pkcs15_compute_signature erreur %s\n", \
			sc_strerror(r));

		sc_bin_to_hex(pInfo->pbSignedData, pInfo->cbSignedData, texte, \
			sizeof(texte)-24, ':');
		logprintf(pCardData, 3, "pInfo->pbSignedData = %s\n", texte);
		
	}
	
	logprintf(pCardData, 3, "CardSignData, dwVersion=%u, name=%S, hScard=0x%08X," \
		"hSCardCtx=0x%08X\n", pCardData->dwVersion, \
		NULLWSTR(pCardData->pwszCardName),pCardData->hScard, \
		pCardData->hSCardCtx);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__in PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	logprintf(pCardData, 1, "CardConstructDHAgreement\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__in PCARD_DERIVE_KEY pAgreementInfo)
{
	logprintf(pCardData, 1, "CardDeriveKey\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDestroyDHAgreement(
	__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardDestroyDHAgreement\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CspGetDHAgreement(__in  PCARD_DATA pCardData,
	__in  PVOID hSecretAgreement,
	__out BYTE* pbSecretAgreementIndex,
	__in  DWORD dwFlags)
{
	logprintf(pCardData, 1, "CspGetDHAgreement\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardGetChallengeEx\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData,
	__in   PIN_ID PinId,
	__in   DWORD dwFlags,
	__in   PBYTE pbPinData,
	__in   DWORD cbPinData,
	__deref_out_bcount_opt(*pcbSessionPin) PBYTE *ppbSessionPin,
	__out_opt PDWORD pcbSessionPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	int r;
	VENDOR_SPECIFIC *vs;
	sc_pkcs15_object_t *pin_obj;

	logprintf(pCardData, 1, "CardAuthenticateEx\n");
	
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	
	logprintf(pCardData, 2, "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
		PinId,dwFlags,cbPinData,pcAttemptsRemaining ? "YES" : "NO");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN ||
		dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			return SCARD_E_UNSUPPORTED_FEATURE;
	if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT) 
		return SCARD_E_INVALID_PARAMETER;

	if (NULL == pbPinData) return SCARD_E_INVALID_PARAMETER;
	
	if (PinId != ROLE_USER) return SCARD_E_INVALID_PARAMETER;
	
	pin_obj = vs->pin_objs[0];
	r = sc_pkcs15_verify_pin(vs->p15card, pin_obj, (const u8 *) pbPinData, cbPinData);
	if (r) 
	{
		logprintf(pCardData, 2, "PIN code verification failed: %s\n", sc_strerror(r));
		
		if(pcAttemptsRemaining) 
		{
			(*pcAttemptsRemaining) = -1;
		}
		return SCARD_W_WRONG_CHV;
	}
	
	logprintf(pCardData, 2, "Pin code correct.\n");
	
	SET_PIN(vs->cardFiles.file_cardcf.bPinsFreshness, ROLE_USER);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData,
	__in   DWORD dwFlags,
	__in   PIN_ID dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in   DWORD cbAuthenticatingPinData,
	__in   PIN_ID dwTargetPinId,
	__in_bcount(cbTargetData) PBYTE pbTargetData,
	__in   DWORD cbTargetData,
	__in   DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "CardChangeAuthenticatorEx\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "CardDeauthenticateEx\n");
	
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	CLEAR_PIN(vs->bPinsFreshness, ROLE_USER);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "CardGetContainerProperty\n");
	
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 2, "CardGetContainerProperty bContainerIndex=%u, wszProperty=%S," \
		"cbData=%u, dwFlags=0x%08X\n",bContainerIndex,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) return SCARD_E_INVALID_PARAMETER;
	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!pdwDataLen) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CCP_CONTAINER_INFO,wszProperty)  == 0)
	{
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && 
				p->dwVersion != 0 ) return ERROR_REVISION_MISMATCH;
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		return CardGetContainerInfo(pCardData,bContainerIndex,0,p);
	}
	
	if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty) == 0) 
	{
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		*p = ROLE_USER;
		logprintf(pCardData, 2,"Return Pin id %u\n",*p);
		return SCARD_S_SUCCESS;
	}
	
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI CardSetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen) PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardSetContainerProperty\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "CardGetProperty\n");
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 2, "CardGetProperty wszProperty=%S, cbData=%u, dwFlags=%u\n", \
		NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;
	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!pdwDataLen) return SCARD_E_INVALID_PARAMETER;
	
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (wcscmp(CP_CARD_FREE_SPACE,wszProperty) == 0)
	{
		PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo = (PCARD_FREE_SPACE_INFO )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*pCardFreeSpaceInfo);
		if (cbData < sizeof(*pCardFreeSpaceInfo)) return SCARD_E_NO_MEMORY;
		if (pCardFreeSpaceInfo->dwVersion > CARD_FREE_SPACE_INFO_CURRENT_VERSION ) 
			return ERROR_REVISION_MISMATCH;

		pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
		pCardFreeSpaceInfo->dwBytesAvailable = -1;
		pCardFreeSpaceInfo->dwMaxKeyContainers = vs->cert_count;
		pCardFreeSpaceInfo->dwKeyContainersAvailable = vs->cert_count;

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_CAPABILITIES,wszProperty) == 0)
	{
		PCARD_CAPABILITIES pCardCapabilities = (PCARD_CAPABILITIES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*pCardCapabilities);
		if (cbData < sizeof(*pCardCapabilities)) return SCARD_E_NO_MEMORY;
		if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION &&
			pCardCapabilities->dwVersion != 0) return ERROR_REVISION_MISMATCH;
		
		pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
		pCardCapabilities->fCertificateCompression = TRUE;
		pCardCapabilities->fKeyGen = FALSE;

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)
	{
		PCARD_KEY_SIZES pKeySizes = (PCARD_KEY_SIZES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*pKeySizes);
		if (cbData < sizeof(*pKeySizes)) return SCARD_E_NO_MEMORY;
		if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION &&
			pKeySizes->dwVersion != 0) return ERROR_REVISION_MISMATCH;
		
		pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
		pKeySizes->dwMinimumBitlen = 512;
		pKeySizes->dwDefaultBitlen = 1024;
		pKeySizes->dwMaximumBitlen = 16384;
		pKeySizes->dwIncrementalBitlen = 64;
		
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_READ_ONLY,wszProperty) == 0)
	{
		BOOL *p = (BOOL*)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		*p = TRUE; /* XXX HACK */
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_CACHE_MODE,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		*p = CP_CACHE_MODE_NO_CACHE;
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		*p = 0;
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_GUID,wszProperty) == 0) 
	{
		if (pdwDataLen) *pdwDataLen = sizeof(vs->cardFiles.file_cardid);
		if (cbData < sizeof(vs->cardFiles.file_cardid)) return SCARD_E_NO_MEMORY;

		CopyMemory(pbData,vs->cardFiles.file_cardid,sizeof(vs->cardFiles.file_cardid));
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_SERIAL_NO,wszProperty) == 0)
	{
		if (pdwDataLen) *pdwDataLen = sizeof(vs->p15card->tokeninfo->serial_number);
		if (cbData < sizeof(vs->p15card->tokeninfo->serial_number)) return SCARD_E_NO_MEMORY;

		CopyMemory(pbData,vs->p15card->tokeninfo->serial_number,sizeof(vs->p15card->tokeninfo->serial_number));
		
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_PIN_INFO,wszProperty) == 0)
	{
		PPIN_INFO p = (PPIN_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		if (p->dwVersion != PIN_INFO_CURRENT_VERSION) return ERROR_REVISION_MISMATCH;
		p->PinType = AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags) 
		{
			case ROLE_USER:
				logprintf(pCardData, 2,"returning info on PIN ROLE_USER ( Auth ) [%u]\n",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = 0;
				p->dwUnblockPermission = 0; 
				break;
			default:
				logprintf(pCardData, 0,"Invalid Pin number %u requested\n",dwFlags);
				return SCARD_E_INVALID_PARAMETER;
			}
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)
	{
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		SET_PIN(*p, ROLE_USER);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_AUTHENTICATED_STATE,wszProperty) == 0)
	{
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		return SCARD_E_INVALID_PARAMETER;
	}
	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (dwFlags != ROLE_USER) return SCARD_E_INVALID_PARAMETER;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return SCARD_E_NO_MEMORY;
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_PIN_STRENGTH_CHANGE,wszProperty) == 0)
	{
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	if (wcscmp(CP_CARD_PIN_STRENGTH_UNBLOCK,wszProperty)  == 0)
	{
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI CardSetProperty(__in   PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen)  PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardSetProperty\n");
	
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	
	logprintf(pCardData, 2, "CardSetProperty wszProperty=%S, cbDataLen=%u, dwFlags=%u",\
		NULLWSTR(wszProperty),cbDataLen,dwFlags);

	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0 ||
		wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0) return SCARD_E_INVALID_PARAMETER;

	if (dwFlags) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_PIN_CONTEXT_STRING, wszProperty) == 0)
		return SCARD_S_SUCCESS;

	if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0 || 
		wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0 ||
		wcscmp(CP_CARD_GUID, wszProperty) == 0 ||
		wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0) {
			return SCARD_E_INVALID_PARAMETER;
	}

	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!cbDataLen) return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_PARENT_WINDOW, wszProperty) == 0) {
		if (cbDataLen != sizeof(DWORD)) 
			return SCARD_E_INVALID_PARAMETER;
		else
		{
			HWND cp = *((HWND *) pbData);
			if (cp!=0 && !IsWindow(cp))  return SCARD_E_INVALID_PARAMETER;
		}
		return SCARD_S_SUCCESS;
	}

	return SCARD_E_INVALID_PARAMETER;
}

#define MINIMUM_VERSION_SUPPORTED (4)
#define CURRENT_VERSION_SUPPORTED (6)

DWORD WINAPI CardAcquireContext(IN PCARD_DATA pCardData, __in DWORD dwFlags)
{
	DWORD result;
	DWORD dwActiveProtocol;
	VENDOR_SPECIFIC *vs;
	DWORD suppliedVersion = 0;
	BYTE empty_appdir[] = {1,'m','s','c','p',0,0,0,0};
	BYTE empty_cardcf[6]={0,0,0,0,0,0};
	BYTE empty_cardid[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	u8 challenge[8];
	
	if (!pCardData) 
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags) 
		return SCARD_E_INVALID_PARAMETER;
	
	suppliedVersion = pCardData->dwVersion;

	/* VENDOR SPECIFIC */
	vs = pCardData->pvVendorSpecific = \
		pCardData->pfnCspAlloc(sizeof(VENDOR_SPECIFIC));
	memset(vs, 0, sizeof(VENDOR_SPECIFIC));

	logprintf(pCardData, 1, "=================================" \
					"=================================\n");

	logprintf(pCardData, 1, "CardAcquireContext, dwVersion=%u, name=%S," \
			"hScard=0x%08X, hSCardCtx=0x%08X\n", pCardData->dwVersion, \
			NULLWSTR(pCardData->pwszCardName),pCardData->hScard, \
			pCardData->hSCardCtx);
	
	/* The lowest supported version is 4. */
	if (pCardData->dwVersion < MINIMUM_VERSION_SUPPORTED)
	{
		return (DWORD) ERROR_REVISION_MISMATCH;
	}
 
	if( pCardData->hScard == 0)
	{
		logprintf(pCardData, 0, "Invalide handle.\n");
		return SCARD_E_INVALID_HANDLE;
	}
	
	logprintf(pCardData, 2, "request version pCardData->dwVersion = %d\n", pCardData->dwVersion);

	pCardData->dwVersion = min(pCardData->dwVersion, CURRENT_VERSION_SUPPORTED);

	logprintf(pCardData, 2, "pCardData->dwVersion = %d\n", pCardData->dwVersion);

	if(1)
	{
		int r;
		HKEY key;
		sc_context_param_t ctx_param;
		
		vs->ctx = NULL;
		
		logprintf(pCardData, 3, "create ctx\n");
		
		memset(&ctx_param, 0, sizeof(ctx_param));
		ctx_param.ver = 1;
		ctx_param.app_name = "cardmod";

		if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\OpenSC Project\\Opensc", 0, NULL, \
			REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &key, NULL) == ERROR_SUCCESS)
		{
			if(RegSetValueEx(key, "pcsc_ctx", NULL, REG_DWORD, &(pCardData->hSCardCtx), \
				sizeof(pCardData->hSCardCtx)) != ERROR_SUCCESS)
			{
				print_werror(pCardData, "RegSetValueEx pcsc_ctx");
				return SCARD_F_UNKNOWN_ERROR;
			}
			if(RegSetValueEx(key, "pcsc_card", NULL, REG_DWORD, &(pCardData->hScard), \
				sizeof(pCardData->hScard)) != ERROR_SUCCESS)
			{
				print_werror(pCardData, "RegSetValueEx pcsc_card");
				return SCARD_F_UNKNOWN_ERROR;
			}
			RegCloseKey(key);
		}
		else
		{
			print_werror(pCardData, "RegCreateKeyEx");
			return SCARD_F_UNKNOWN_ERROR;
		}
		
		r = sc_context_create(&(vs->ctx), &ctx_param);
		logprintf(pCardData, 3, "sc_context_create passed r = %d\n", r);
		if (r) 
		{
			logprintf(pCardData, 0, "Failed to establish context: %s\n", \
				sc_strerror(r));
			return SCARD_F_UNKNOWN_ERROR;
		}
		else
		{
			int i;
			
			logprintf(pCardData, 5, "sc_ctx_get_reader_count(ctx): %d\n", \
				sc_ctx_get_reader_count(vs->ctx));

			vs->reader = sc_ctx_get_reader(vs->ctx, 0);
			if(vs->reader)
			{
				logprintf(pCardData, 3, "%s\n", NULLSTR(vs->reader->name));
					
				r = sc_connect_card(vs->reader, &(vs->card));
				logprintf(pCardData, 2, "sc_connect_card result = %d, %s\n", \
						r, sc_strerror(r));
				if(!r)
				{
					r = sc_pkcs15_bind(vs->card, NULL, &(vs->p15card));
					logprintf(pCardData, 2, "PKCS#15 initialization result: %d, %s\n", \
						r, sc_strerror(r));
				}
			}

			if(vs->card == NULL || vs->p15card == NULL)
			{
				logprintf(pCardData, 0, "Card unknow.\n");
				return SCARD_E_UNKNOWN_CARD;
			}
		}
		
		r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, \
			vs->cert_objs, 32);
		if (r < 0) 
		{
			logprintf(pCardData, 0, "Certificate enumeration failed: %s\n", \
				sc_strerror(r));
			return SCARD_F_UNKNOWN_ERROR;
		}
		
		vs->cert_count = r;
		logprintf(pCardData, 2, "Found %d certificat(s) in the card.\n", \
			vs->cert_count);
		
		r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_PRKEY_RSA, \
			vs->prkey_objs, 32);
		if (r < 0) 
		{
			logprintf(pCardData, 0, "Private key enumeration failed: %s\n", \
				sc_strerror(r));
			return SCARD_F_UNKNOWN_ERROR;
		}
		
		vs->prkey_count = r;
		logprintf(pCardData, 2, "Found %d private key(s) in the card.\n", \
			vs->prkey_count);

		r = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_AUTH_PIN, \
			vs->pin_objs, 8);
		if (r < 0) 
		{
			logprintf(pCardData, 2, "Pin object enumeration failed: %s\n", \
				sc_strerror(r));
			return SCARD_F_UNKNOWN_ERROR;
		}
		
		vs->pin_count = r;
		logprintf(pCardData, 2, "Found %d pin(s) in the card.\n", \
			vs->pin_count);

	}
	
	if(1)
	{
		int i;
		sc_pkcs15_prkey_info_t *prkey_info;
		sc_pkcs15_cert_t *cert;
		char texte[4096];
		for(i = 0; i < vs->prkey_count; i++)
		{
			prkey_info = (sc_pkcs15_prkey_info_t*)(vs->prkey_objs[i]->data);
			sc_bin_to_hex(prkey_info->subject.value, prkey_info->subject.len, \
				texte, sizeof(texte)-5, ':');
			logprintf(pCardData, 5, "prkey_info->subject %d (subject_len=%d) = %s," \
				"modulus_length=%d\n", i, prkey_info->subject.len, \
				texte, prkey_info->modulus_length);
		}
		
		for(i = 0; i < vs->cert_count; i++)
		{
			sc_pkcs15_read_certificate(vs->p15card, \
				(struct sc_pkcs15_cert_info *)(vs->cert_objs[i]->data), &cert);
			sc_bin_to_hex(cert->subject, cert->subject_len, texte, \
				sizeof(texte)-5, ':');
			logprintf(pCardData, 5, "cert->subject %d = %s\n", i, texte);
			sc_pkcs15_free_certificate(cert);
		}
		
		for(i = 0; i < vs->pin_count; i++)
		{
			const char *pin_flags[] = 
			{
				"case-sensitive", "local", "change-disabled",
				"unblock-disabled", "initialized", "needs-padding",
				"unblockingPin", "soPin", "disable_allowed",
				"integrity-protected", "confidentiality-protected",
				"exchangeRefData"
			};
			const char *pin_types[] = {"bcd", "ascii-numeric", "UTF-8",
				"halfnibble bcd", "iso 9664-1"}; 
			const struct sc_pkcs15_object *obj = vs->pin_objs[i];
			const struct sc_pkcs15_pin_info *pin = (const struct sc_pkcs15_pin_info *) (obj->data);
			const size_t pf_count = sizeof(pin_flags)/sizeof(pin_flags[0]);
			size_t j;

			logprintf(pCardData, 2, "PIN [%s]\n", obj->label);
			logprintf(pCardData, 2, "\tCom. Flags: 0x%X\n", obj->flags);
			logprintf(pCardData, 2, "\tID        : %s\n", sc_pkcs15_print_id(&pin->auth_id));
			logprintf(pCardData, 2, "\tFlags     : [0x%02X]", pin->flags);
			for (j = 0; j < pf_count; j++)
				if (pin->flags & (1 << j)) {
					logprintf(pCardData, 2, ", %s", pin_flags[j]);
				}
			logprintf(pCardData, 2, "\n");
			logprintf(pCardData, 2, "\tLength    : min_len:%lu, max_len:%lu, stored_len:%lu\n",
				(unsigned long)pin->min_length, (unsigned long)pin->max_length,
				(unsigned long)pin->stored_length);
			logprintf(pCardData, 2, "\tPad char  : 0x%02X\n", pin->pad_char);
			logprintf(pCardData, 2, "\tReference : %d\n", pin->reference);
			if (pin->type < sizeof(pin_types)/sizeof(pin_types[0]))
				logprintf(pCardData, 2, "\tType      : %s\n", pin_types[pin->type]);
			else
				logprintf(pCardData, 2, "\tType      : [encoding %d]\n", pin->type);
			logprintf(pCardData, 2, "\tPath      : %s\n", sc_print_path(&pin->path));
			if (pin->tries_left >= 0)
				logprintf(pCardData, 2, "\tTries left: %d\n", pin->tries_left);
		}
	}
	
	logprintf(pCardData, 1, "Opensc init done.\n");
	
	pCardData->pfnCardDeleteContext = CardDeleteContext;
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
	pCardData->pfnCardDeleteContainer = CardDeleteContainer;
	pCardData->pfnCardCreateContainer = CardCreateContainer;
	pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
	pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
	pCardData->pfnCardGetChallenge = CardGetChallenge;
	pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge;
	pCardData->pfnCardUnblockPin = CardUnblockPin;
	pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;
	pCardData->pfnCardDeauthenticate = CardDeauthenticate; /* NULL */
	pCardData->pfnCardCreateDirectory = CardCreateDirectory;
	pCardData->pfnCardDeleteDirectory = CardDeleteDirectory;
	pCardData->pvUnused3 = NULL;
	pCardData->pvUnused4 = NULL;
	pCardData->pfnCardCreateFile = CardCreateFile;
	pCardData->pfnCardReadFile = CardReadFile;
	pCardData->pfnCardWriteFile = CardWriteFile;
	pCardData->pfnCardDeleteFile = CardDeleteFile;
	pCardData->pfnCardEnumFiles = CardEnumFiles;
	pCardData->pfnCardGetFileInfo = CardGetFileInfo;
	pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;
	pCardData->pfnCardSignData = CardSignData;
	pCardData->pfnCardRSADecrypt = CardRSADecrypt;
	pCardData->pfnCardConstructDHAgreement = CardConstructDHAgreement;

	memcpy(vs->cardFiles.file_appdir, empty_appdir, sizeof(empty_appdir));
	memset(&(vs->cardFiles.file_cardcf), 0, sizeof(vs->cardFiles.file_cardcf));
	
	if(sc_get_challenge(vs->p15card->card, challenge, sizeof(challenge)))
	{
		vs->cardFiles.file_cardcf.wContainersFreshness = rand()%30000;
		vs->cardFiles.file_cardcf.wFilesFreshness = rand()%30000;
	}
	else
	{
		vs->cardFiles.file_cardcf.wContainersFreshness = challenge[0]*256+challenge[1];
		vs->cardFiles.file_cardcf.wFilesFreshness = challenge[3]*256+challenge[4];
	}
	memcpy(vs->cardFiles.file_cardid, empty_cardid, sizeof(empty_cardid));
		
	if (suppliedVersion > 4) {
		pCardData->pfnCardDeriveKey = CardDeriveKey; 
		pCardData->pfnCardDestroyDHAgreement = CardDestroyDHAgreement; 
		pCardData->pfnCspGetDHAgreement = CspGetDHAgreement; 
		
		if (suppliedVersion > 5 ) {
			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
		}
	}

	return SCARD_S_SUCCESS;
}

BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call) 
	{
		case DLL_PROCESS_ATTACH:
			{
				DWORD winlogon = 0;
				HKEY key;
				CHAR name[MAX_PATH * 2 ] = "\0", *p;
				GetModuleFileName(GetModuleHandle(NULL),name,MAX_PATH);
				p = name  + strlen(name) - 1;
				while (isalnum(*p) || ('.' == *p) || ('_' == *p)) p--;
				p++;
				
				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\OpenSC Project\\Opensc",\
					NULL, KEY_READ, &key)==ERROR_SUCCESS)
				{
					CHAR val[1024]; 
					DWORD type;
					LONG size = sizeof(val);

					if(RegQueryValueEx(key,"winlogon", NULL, &type, 
						val, &size) == ERROR_SUCCESS)
					{
						if(type == REG_DWORD)
						{
							winlogon = *(DWORD*)val;
						}
					}

					RegCloseKey(key);
				}
								
				if (*p == '\0') return FALSE;
				if(!winlogon)
				{
					if (!strcmpi(p,"explorer.exe")) return FALSE;
					if (!strcmpi(p,"winlogon.exe"))return FALSE;
					if (!strcmpi(p,"svchost.exe"))return FALSE;
				}
				
			}
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
       case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
