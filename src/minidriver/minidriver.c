/*
 * minidriver.c: OpenSC minidriver
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
 * This module requires "cardmod.h" from CNG SDK or platform SDK to build.
 */

#include "config.h"
#ifdef ENABLE_MINIDRIVER

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include "cardmod.h"

#include "libopensc/cardctl.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"

#if defined(__MINGW32__)
/* Part of the build svn project in the include directory */
#include "cardmod-mingw-compat.h"
#endif

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
	SCARDCONTEXT hSCardCtx;
	SCARDHANDLE hScard;

}VENDOR_SPECIFIC;

static int associate_card(PCARD_DATA pCardData);
static int disassociate_card(PCARD_DATA pCardData);

static void logprintf(PCARD_DATA pCardData, int level, const char* format, ...)
{
	va_list arg;
	VENDOR_SPECIFIC *vs;
/* #define CARDMOD_LOW_LEVEL_DEBUG 1 */
#ifdef CARDMOD_LOW_LEVEL_DEBUG
/* Use a simplied log to get all messages including messages
 * before opensc is loaded. The file must be modifiable by all
 * users as we maybe called under lsa or user. Note data from
 * multiple process and threads may get intermingled.
 * flush to get last message before ann crash
 * close so as the file is not left open during any wait.
 */
	{
		FILE* lldebugfp = NULL;

		lldebugfp = fopen("C:\\tmp\\cardmod.log.txt","ab");
		if (lldebugfp != NULL) {
			va_start(arg, format);
			vfprintf(lldebugfp, format, arg);
			va_end(arg);
			fflush(lldebugfp);
			fclose(lldebugfp);
			lldebugfp = NULL;
		}
	return;
	}
#endif

	va_start(arg, format);
	if(pCardData != NULL)
	{
		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(vs != NULL && vs->ctx != NULL)
		{
#ifdef _MSC_VER
			sc_do_log_noframe(vs->ctx, level, format, arg);
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

static void loghex(PCARD_DATA pCardData, int level, PBYTE data, int len)
{
	char line[74];
	char *c;
	int i, a;
	unsigned char * p;

	logprintf(pCardData, level, "--- %p:%d\n", data, len);

	if (data == NULL || len <= 0) return;

	p = data;
	c = line;
	i = 0;
	a = 0;
	memset(line, 0, sizeof(line));

	while(i < len) {
		sprintf(c,"%02X", *p);
		p++;
		c += 2;
		i++;
		if (i%32 == 0) {
			logprintf(pCardData, level, " %04X  %s\n", a, line);
			a +=32;
			memset(line, 0, sizeof(line));
			c = line;
		} else {
			if (i%4 == 0) *(c++) = ' ';
			if (i%16 == 0) *(c++) = ' ';
		}
	}
	if (i%32 != 0)
		logprintf(pCardData, level, " %04X  %s\n", a, line);
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
 * check if the card has been removed, or the
 * caller has changed the handles.
 * if so, then free up all previous card info
 * and reestablish
 */
static int check_reader_status(PCARD_DATA pCardData) {

	int r;
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 4, "check_reader_status\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 7, "pCardData->hSCardCtx:0x%08X hScard:0x%08X\n",
			pCardData->hSCardCtx, pCardData->hScard);

	if (pCardData->hSCardCtx != vs->hSCardCtx
				|| pCardData->hScard != vs->hScard) {
			logprintf (pCardData, 1, "HANDLES CHANGED from 0x%08X 0x%08X\n", vs->hSCardCtx, vs->hScard);

			 r = disassociate_card(pCardData);
			 logprintf(pCardData, 1, "disassociate_card r = 0x%08X\n");
			 r = associate_card(pCardData); /* need to check return codes */
			 logprintf(pCardData, 1, "associate_card r = 0x%08X\n");
	} else

	/* This should always work, as BaseCSP should be checking for removal too */
	if (vs->reader) {
		r = sc_detect_card_presence(vs->reader);
		logprintf(pCardData, 2, "check_reader_status r=%d flags 0x%08X\n",
			r, vs->reader->flags);
	}
	return SCARD_S_SUCCESS;
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


static int get_pin_by_role(PCARD_DATA pCardData, PIN_ID role, struct sc_pkcs15_object **ret_obj)
{
	VENDOR_SPECIFIC *vs;
	int i;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "get PIN with role %i\n", role);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (vs->pin_count == 0)   {
		logprintf(pCardData, 2, "cannot get PIN object: no PIN defined\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (!ret_obj)
		return SCARD_E_INVALID_PARAMETER;

	*ret_obj = NULL;

	for(i = 0; i < vs->pin_count; i++)
	{
		struct sc_pkcs15_object *obj = vs->pin_objs[i];
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) (obj->data);
		unsigned int pin_flags = auth_info->attrs.pin.flags;
		unsigned int admin_pin_flags = SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN;

		logprintf(pCardData, 2, "PIN[%s] flags 0x%X\n", obj->label, pin_flags);
		if (role == ROLE_USER)   {
			if (!(pin_flags & admin_pin_flags))   {
				*ret_obj = obj;
				break;
			}
		}
		else if (role == ROLE_ADMIN)   {
			if (pin_flags & admin_pin_flags)   {
				*ret_obj = obj;
				break;
			}
		}
		else   {
			logprintf(pCardData, 2, "cannot get PIN object: unsupported role\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
	}

	if (i == vs->pin_count)   {
		logprintf(pCardData, 2, "cannot get PIN object: not found\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	return SCARD_S_SUCCESS;
}

static void dump_objects (PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	sc_pkcs15_prkey_info_t *prkey_info;
	sc_pkcs15_cert_t *cert;
	int i;

	if (!pCardData)
		return;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return;

	for(i = 0; i < vs->prkey_count; i++)
	{
		prkey_info = (sc_pkcs15_prkey_info_t*)(vs->prkey_objs[i]->data);
		logprintf(pCardData, 5, "prkey_info->subject %d (subject_len=%d)" \
			"modulus_length=%d subject ", i, prkey_info->subject.len, \
				prkey_info->modulus_length);
		loghex(pCardData, 5, prkey_info->subject.value, prkey_info->subject.len);
	}

	for(i = 0; i < vs->cert_count; i++)
	{
		sc_pkcs15_read_certificate(vs->p15card, \
			(struct sc_pkcs15_cert_info *)(vs->cert_objs[i]->data), &cert);
		logprintf(pCardData, 5, "cert->subject %d ", i);
		loghex(pCardData, 5, cert->subject, cert->subject_len);
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
		const struct sc_pkcs15_auth_info *auth_info = (const struct sc_pkcs15_auth_info *) (obj->data);
		const struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
		const size_t pf_count = sizeof(pin_flags)/sizeof(pin_flags[0]);
		size_t j;

		logprintf(pCardData, 2, "PIN [%s]\n", obj->label);
		logprintf(pCardData, 2, "\tCom. Flags: 0x%X\n", obj->flags);
		logprintf(pCardData, 2, "\tID        : %s\n", sc_pkcs15_print_id(&auth_info->auth_id));
		logprintf(pCardData, 2, "\tFlags     : [0x%02X]", pin_attrs->flags);
		for (j = 0; j < pf_count; j++)
			if (pin_attrs->flags & (1 << j)) {
				logprintf(pCardData, 2, ", %s", pin_flags[j]);
			}
		logprintf(pCardData, 2, "\n");
		logprintf(pCardData, 2, "\tLength    : min_len:%lu, max_len:%lu, stored_len:%lu\n",
			(unsigned long)pin_attrs->min_length, (unsigned long)pin_attrs->max_length,
			(unsigned long)pin_attrs->stored_length);
		logprintf(pCardData, 2, "\tPad char  : 0x%02X\n", pin_attrs->pad_char);
		logprintf(pCardData, 2, "\tReference : %d\n", pin_attrs->reference);
		if (pin_attrs->type < sizeof(pin_types)/sizeof(pin_types[0]))
			logprintf(pCardData, 2, "\tType      : %s\n", pin_types[pin_attrs->type]);
		else
			logprintf(pCardData, 2, "\tType      : [encoding %d]\n", pin_attrs->type);
		logprintf(pCardData, 2, "\tPath      : %s\n", sc_print_path(&auth_info->path));
		if (auth_info->tries_left >= 0)
			logprintf(pCardData, 2, "\tTries left: %d\n", auth_info->tries_left);
	}
}


DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContext\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	disassociate_card(pCardData);

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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "pCardCapabilities=%X\n", pCardCapabilities);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pCardCapabilities) return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION
		&& pCardCapabilities->dwVersion != 0)
			return ERROR_REVISION_MISMATCH;

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = TRUE;
	pCardCapabilities->fKeyGen = FALSE;

	check_reader_status(pCardData);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContainer - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateContainer - unsupported\n");
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
	sc_pkcs15_cert_t *cert = NULL;
	VENDOR_SPECIFIC *vs = NULL;

	PUBKEYSTRUCT_BASE *oh = NULL;
	PUBKEYSTRUCT_BASE *oh2 = NULL;

	DWORD sz = 0;
	DWORD sz2 = 0;

	DWORD ret;
	sc_pkcs15_pubkey_t *pubkey = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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

	check_reader_status(pCardData);

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

		PCCERT_CONTEXT cer = CertCreateCertificateContext(X509_ASN_ENCODING \
			| PKCS_7_ASN_ENCODING, cert->data, cert->data_len);
		PCERT_PUBLIC_KEY_INFO pinf = \
			&(cer->pCertInfo->SubjectPublicKeyInfo);

		sz = 0; /* get size */
		CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, \
		RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData, \
		pinf->PublicKey.cbData , 0, oh, &sz);
		sz2 = sz;

		oh = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
		oh2 = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz2);
		if(oh && oh2)
		{
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, \
				RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData, \
				pinf->PublicKey.cbData , 0, oh, &sz);

			oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
			pContainerInfo->cbSigPublicKey = sz;
			pContainerInfo->pbSigPublicKey = (PBYTE)oh;

			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, \
				RSA_CSP_PUBLICKEYBLOB, pinf->PublicKey.pbData, \
				pinf->PublicKey.cbData , 0, oh2, &sz2);

			oh2->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
			pContainerInfo->cbKeyExPublicKey = sz2;
			pContainerInfo->pbKeyExPublicKey = (PBYTE)oh2;

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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticatePin %S %d %d\n", NULLWSTR(pwszUserId), \
		cbPin, vs->cardFiles.file_cardcf.bPinsFreshness);

	check_reader_status(pCardData);

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

	r = get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (r != SCARD_S_SUCCESS)
	{
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return r;
	}

	r = sc_pkcs15_verify_pin(vs->p15card, pin_obj, (const u8 *) pbPin, cbPin);
	if (r)
	{
		logprintf(pCardData, 1, "PIN code verification failed: %s\n", sc_strerror(r));

		if(pcAttemptsRemaining)
		{
			(*pcAttemptsRemaining) = -1;
		}
		return SCARD_W_WRONG_CHV;
	}

	logprintf(pCardData, 3, "Pin code correct.\n");

	SET_PIN(vs->cardFiles.file_cardcf.bPinsFreshness, ROLE_USER);
	logprintf(pCardData, 3, "PinsFreshness = %d\n",
		vs->cardFiles.file_cardcf.bPinsFreshness);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out                                 PDWORD pcbChallengeData)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallenge - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE  pbResponseData,
	__in DWORD  cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateChallenge - unsupported\n");
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardUnblockPin - unsupported\n");
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticator - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticate%S %d\n", NULLWSTR(pwszUserId),
			dwFlags);

	if(!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	/* TODO This does not look correct, as it does not look at the pwszUserId */
	/* TODO We need to tell the card the pin is no longer valid */
	CLEAR_PIN(vs->cardFiles.file_cardcf.bPinsFreshness, ROLE_USER);
	logprintf(pCardData, 5, "PinsFreshness = %d\n",
		vs->cardFiles.file_cardcf.bPinsFreshness);

	/*TODO Should we reset the card ? */

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateDirectory - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName)

{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteDirectory - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateFile - unsupported\n");
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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

	check_reader_status(pCardData);

	if(pszDirectoryName == NULL)
	{
		if(strcmp(pszFileName, "cardid") == 0)
		{
			*pcbData = sizeof(vs->cardFiles.file_cardid);
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			if(!*ppbData)
				return SCARD_E_NO_MEMORY;

			memcpy(*ppbData, &(vs->cardFiles.file_cardid), *pcbData);

			logprintf(pCardData, 7, "return cardid ");
			loghex(pCardData, 7, *ppbData, *pcbData);

			return SCARD_S_SUCCESS;
		}

		if(strcmp(pszFileName, "cardcf") == 0)
		{
			*pcbData = sizeof(vs->cardFiles.file_cardcf);
			*ppbData = pCardData->pfnCspAlloc(*pcbData);
			if(!*ppbData)
			{
				return SCARD_E_NO_MEMORY;
			}

			memcpy(*ppbData, &(vs->cardFiles.file_cardcf), *pcbData);

			logprintf(pCardData, 7, "return cardcf ");
			loghex(pCardData, 7, *ppbData, *pcbData);

			return SCARD_S_SUCCESS;
		}

	}

	if(pszDirectoryName != NULL && strcmp(pszDirectoryName, "mscp") == 0)
	{
		int r,i,n;
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
				struct sc_pkcs15_cert_info *cert_info = (sc_pkcs15_cert_info_t *)vs->cert_objs[i]->data;
				sc_pkcs15_cert_t *cert = NULL;

				r = sc_pkcs15_read_certificate(vs->p15card, cert_info, &cert);
				logprintf(pCardData, 2, "sc_pkcs15_read_certificate return %d\n", r);
				if(r)
				{
					return SCARD_E_FILE_NOT_FOUND;
				}
				pubkey = cert->key;
				if(pubkey->algorithm == SC_ALGORITHM_RSA)
				{
					struct sc_card *card = vs->p15card->card;
					char guid[MAX_CONTAINER_NAME_LEN + 1];

					r = sc_pkcs15_get_guid(vs->p15card, vs->cert_objs[i], guid, sizeof(guid));
					if (r)
						return r;

					logprintf(pCardData, 7, "Guid=%s\n", guid);

					mbstowcs(p->wszGuid, guid, MAX_CONTAINER_NAME_LEN + 1);

					p->bFlags += CONTAINER_MAP_VALID_CONTAINER;
					if(i == 0)
					{
						p->bFlags += CONTAINER_MAP_DEFAULT_CONTAINER;
					}
					/* TODO Looks like these should be based on sc_pkcs15_prkey_info usage */
					/* On PIV on W7, auth cert is AT_KEYEXCHANGE, Signing cert is AT_SIGNATURE */

					p->wSigKeySizeBits = \
						compute_keybits(&(pubkey->u.rsa.modulus));
					p->wKeyExchangeKeySizeBits = \
						compute_keybits(&(pubkey->u.rsa.modulus));
				}
				sc_pkcs15_free_certificate(cert);

				logprintf(pCardData, 7, "cmapfile entry %d ",i);
				loghex(pCardData, 7, (PBYTE) p, sizeof(CONTAINER_MAP_RECORD));
			}

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
				logprintf(pCardData, 6, "cert returned ");
				loghex(pCardData, 6, *ppbData, *pcbData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardWriteFile %s %d\n", NULLSTR(pszFileName), cbData);

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	if(pszDirectoryName == NULL)
	{
		if(strcmp(pszFileName, "cardcf") == 0)
		{
			logprintf(pCardData, 2, "write cardcf ok.\n");
			loghex(pCardData, 2, pbData, cbData); /*TODO did it change */
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteFile - unsupported\n");
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetFileInfo - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData,
	__in DWORD dwFlags,
	__in PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardQueryFreeSpace %X, dwFlags=%X, version=%X\n", \
		pCardFreeSpaceInfo, dwFlags, pCardFreeSpaceInfo->dwVersion);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = -1;
	pCardFreeSpaceInfo->dwMaxKeyContainers = vs->cert_count;

	pCardFreeSpaceInfo->dwKeyContainersAvailable = vs->cert_count; /*TODO should this be 0 */

	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__out PCARD_KEY_SIZES pKeySizes)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	int r, i, opt_crypt_flags = 0;
	unsigned ui;
	VENDOR_SPECIFIC *vs;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE *pbuf = NULL, *pbuf2 = NULL;
	DWORD lg= 0, lg2 = 0;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardRSADecrypt\n");
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	vs->pkey = NULL;

	logprintf(pCardData, 2, "CardRSADecrypt dwVersion=%u, bContainerIndex=%u," \
		"dwKeySpec=%u pbData=%p, cbData=%u\n", \
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, \
		pInfo->pbData,  pInfo->cbData);

	if (pInfo->dwVersion == CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) {
		logprintf(pCardData, 2, "  pPaddingInfo=%p dwPaddingType=0x%08X\n", \
			pInfo->pPaddingInfo, pInfo->dwPaddingType);
	}

	if (!(pInfo->bContainerIndex < vs->cert_count))
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
		logprintf(pCardData, 2, "CardRSADecrypt prkey not found\n");
        return SCARD_E_INVALID_PARAMETER;
    }

    prkey_info = (sc_pkcs15_prkey_info_t*)(vs->pkey->data);


	/* input and output buffers are always the same size */
	pbuf = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf) {
		return SCARD_E_NO_MEMORY;
	}
	lg2 = pInfo->cbData;
	pbuf2 = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf2) {
		return SCARD_E_NO_MEMORY;
	}

	/*inversion donnees*/
	for(ui = 0; ui < pInfo->cbData; ui++) pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];

	r = sc_pkcs15_decipher(vs->p15card, vs->pkey,
		opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
	logprintf(pCardData, 2, "sc_pkcs15_decipher return %d\n", r);
	if ( r != pInfo->cbData || r < 0) {
		logprintf(pCardData, 2, "sc_pkcs15_decipher erreur %s\n", \
			sc_strerror(r));
	}

	/*inversion donnees */
        for(ui = 0; ui < pInfo->cbData; ui++) pInfo->pbData[ui] = pbuf2[pInfo->cbData-ui-1];

	pCardData->pfnCspFree(pbuf);
	pCardData->pfnCspFree(pbuf2);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardSignData(__in PCARD_DATA pCardData,
	__in PCARD_SIGNING_INFO pInfo)
{
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg;
	sc_pkcs15_cert_info_t *cert_info;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE dataToSign[0x200];
	int r, opt_crypt_flags = 0, opt_hash_flags = 0;
	size_t dataToSignLen = sizeof(dataToSign);

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSignData\n");

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	if (!pInfo) return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSignData dwVersion=%u, bContainerIndex=%u," \
		"dwKeySpec=%u, dwSigningFlags=0x%08X, aiHashAlg=0x%08X\n", \
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, \
		pInfo->dwSigningFlags, pInfo->aiHashAlg);

	logprintf(pCardData, 7, "pInfo->pbData(%i) ", pInfo->cbData);
	loghex(pCardData, 7, pInfo->pbData, pInfo->cbData);

	hashAlg = pInfo->aiHashAlg;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	vs->pkey = NULL;

	logprintf(pCardData, 2, "pInfo->dwVersion = %d\n", pInfo->dwVersion);

	if (dataToSignLen < pInfo->cbData) return SCARD_E_INSUFFICIENT_BUFFER;
	memcpy(dataToSign, pInfo->pbData, pInfo->cbData);
	dataToSignLen = pInfo->cbData;

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)
	{
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)
		{
			logprintf(pCardData, 0, "unsupported paddingtype\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		if (!pinf->pszAlgId)
		{
			/* hashAlg = CALG_SSL3_SHAMD5; */
			logprintf(pCardData, 3, "Using CALG_SSL3_SHAMD5  hashAlg\n");
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		}
		else
		{

			if (wcscmp(pinf->pszAlgId, L"MD5") == 0)  opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
			else if (wcscmp(pinf->pszAlgId, L"SHA1") == 0)  opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHAMD5") == 0) opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			else
				logprintf(pCardData, 0,"unknown AlgId %S\n",NULLWSTR(pinf->pszAlgId));
		}
	}
	else
	{
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");

		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)
		{
			logprintf(pCardData, 0, "bogus aiHashAlg\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		if (hashAlg == CALG_MD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
		else if (hashAlg == CALG_SHA1)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
		else if (hashAlg == CALG_SSL3_SHAMD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else if (hashAlg !=0)
			return SCARD_E_UNSUPPORTED_FEATURE;
	}

	/* From sc-minidriver_specs_v7.docx pp.76:
	 * 'The Base CSP/KSP performs the hashing operation on the data before passing it
	 * 	to CardSignData for signature.'
         * So, the SC_ALGORITHM_RSA_HASH_* flags should not be passed to pkcs15 library
	 * 	when calculating the signature .
	 *
	 * From sc-minidriver_specs_v7.docx pp.76:
	 * 'If the aiHashAlg member is nonzero, it specifies the hash algorithm’s object identifier (OID)
	 *  that is encoded in the PKCS padding.'
	 * So, the digest info has be included into the data to be signed.
	 * */
	if (opt_hash_flags)   {
		logprintf(pCardData, 2, "include digest info of the algorithm 0x%08X\n", opt_hash_flags);
		dataToSignLen = sizeof(dataToSign);
		r = sc_pkcs1_encode(vs->p15card->card->ctx, opt_hash_flags,
			pInfo->pbData, pInfo->cbData, dataToSign, &dataToSignLen, 0);
		if (r)   {
			logprintf(pCardData, 2, "PKCS#1 encode error %s\n", sc_strerror(r));
			return SCARD_E_INVALID_VALUE;
		}
	}
	opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;

	if(!(pInfo->bContainerIndex < vs->cert_count))
	{
		return SCARD_E_INVALID_PARAMETER;
	}

	cert_info = (struct sc_pkcs15_cert_info *) \
		(vs->cert_objs[pInfo->bContainerIndex]->data);

	r = sc_pkcs15_find_prkey_by_id(vs->p15card, &cert_info->id, &vs->pkey);
	if (r)
		return SCARD_E_INVALID_PARAMETER;

	prkey_info = (sc_pkcs15_prkey_info_t*)(vs->pkey->data);

	pInfo->cbSignedData = prkey_info->modulus_length / 8;
	logprintf(pCardData, 3, "pInfo->cbSignedData = %d\n", pInfo->cbSignedData);

	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))
	{
		int r,i;
		BYTE *pbuf = NULL;
		DWORD lg;

		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %d\n", lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf)
		{
			return SCARD_E_NO_MEMORY;
		}

		logprintf(pCardData, 7, "Data to sign: ");
		loghex(pCardData, 7, dataToSign, dataToSignLen);

		pInfo->pbSignedData = pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData)
		{
			pCardData->pfnCspFree(pbuf);
			return SCARD_E_NO_MEMORY;
		}

		r = sc_pkcs15_compute_signature(vs->p15card, vs->pkey, \
			opt_crypt_flags, dataToSign, dataToSignLen, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)
		{
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature erreur %s\n", \
				sc_strerror(r));
		}

		pInfo->cbSignedData = r;

		/*inversion donnees*/
		for(i = 0; i < r; i++) pInfo->pbSignedData[i] = pbuf[r-i-1];

		logprintf(pCardData, 7, "pbuf ");
		loghex(pCardData, 7, pbuf, r);

		pCardData->pfnCspFree(pbuf);

		logprintf(pCardData, 7, "pInfo->pbSignedData ");
		loghex(pCardData, 7, pInfo->pbSignedData, pInfo->cbSignedData);

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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardConstructDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__in PCARD_DERIVE_KEY pAgreementInfo)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeriveKey - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDestroyDHAgreement(
	__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "CardDestroyDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CspGetDHAgreement(__in  PCARD_DATA pCardData,
	__in  PVOID hSecretAgreement,
	__out BYTE* pbSecretAgreementIndex,
	__in  DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CspGetDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallengeEx - unsupported\n");
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
	sc_pkcs15_object_t *pin_obj = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateEx\n");

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
		PinId,dwFlags,cbPinData,pcAttemptsRemaining ? "YES" : "NO");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN ||
		dwFlags == CARD_AUTHENTICATE_SESSION_PIN)
			return SCARD_E_UNSUPPORTED_FEATURE;
	if (dwFlags && dwFlags != CARD_PIN_SILENT_CONTEXT)
		return SCARD_E_INVALID_PARAMETER;

	if (NULL == pbPinData) return SCARD_E_INVALID_PARAMETER;

	if (PinId != ROLE_USER) return SCARD_E_INVALID_PARAMETER;

	r = get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (r != SCARD_S_SUCCESS)
	{
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return r;
	}

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
	logprintf(pCardData, 7, "PinsFreshness = %d\n",
		vs->cardFiles.file_cardcf.bPinsFreshness);

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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticatorEx - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticateEx PinId=%d dwFlags=0x%08X\n",PinId, dwFlags);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	/*TODO Should we reset the card? */
	vs->cardFiles.file_cardcf.bPinsFreshness &= ~PinId;
	logprintf(pCardData, 7, "PinsFreshness = %d\n",
		vs->cardFiles.file_cardcf.bPinsFreshness);

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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerProperty\n");

	check_reader_status(pCardData);

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
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		return CardGetContainerInfo(pCardData,bContainerIndex,0,p);
	}

	if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty) == 0)
	{
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetContainerProperty - unsupported\n");
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetProperty\n");
	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 2, "CardGetProperty wszProperty=%S, cbData=%u, dwFlags=%u\n", \
		NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty) return SCARD_E_INVALID_PARAMETER;
	if (!pbData) return SCARD_E_INVALID_PARAMETER;
	if (!pdwDataLen) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

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

		logprintf(pCardData, 7, "pCardFreeSpaceInfo ");
		loghex(pCardData, 7, pbData, *pdwDataLen);

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_CAPABILITIES,wszProperty) == 0)
	{
		PCARD_CAPABILITIES pCardCapabilities = (PCARD_CAPABILITIES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*pCardCapabilities);
		if (cbData < sizeof(*pCardCapabilities)) return ERROR_INSUFFICIENT_BUFFER;
		if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION &&
			pCardCapabilities->dwVersion != 0) return ERROR_REVISION_MISMATCH;

		pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
		pCardCapabilities->fCertificateCompression = TRUE;
		pCardCapabilities->fKeyGen = FALSE;

		logprintf(pCardData, 7, "pCardCapabilities ");
		loghex(pCardData, 7, pbData, *pdwDataLen);

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)
	{
		PCARD_KEY_SIZES pKeySizes = (PCARD_KEY_SIZES )pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*pKeySizes);
		if (cbData < sizeof(*pKeySizes)) return ERROR_INSUFFICIENT_BUFFER;
		if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION &&
			pKeySizes->dwVersion != 0) return ERROR_REVISION_MISMATCH;

		pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
		pKeySizes->dwMinimumBitlen = 512;
		pKeySizes->dwDefaultBitlen = 1024;
		pKeySizes->dwMaximumBitlen = 16384;
		pKeySizes->dwIncrementalBitlen = 64;

		logprintf(pCardData, 7, "pKeySizes ");
		loghex(pCardData, 7, pbData, *pdwDataLen);

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_READ_ONLY,wszProperty) == 0)
	{
		BOOL *p = (BOOL*)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		*p = TRUE; /* XXX HACK */

		logprintf(pCardData, 7, "pcardReadOnly");
		loghex(pCardData, 7, pbData, *pdwDataLen);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_CACHE_MODE,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		*p = CP_CACHE_MODE_NO_CACHE;

		logprintf(pCardData, 7, "pCardCacheMode ");
		loghex(pCardData, 7, pbData, *pdwDataLen);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		*p = 0;

		logprintf(pCardData, 7, "pSupportsX509Enrolment ");
		loghex(pCardData, 7, pbData, *pdwDataLen);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_GUID,wszProperty) == 0)
	{
		if (pdwDataLen) *pdwDataLen = sizeof(vs->cardFiles.file_cardid);
		if (cbData < sizeof(vs->cardFiles.file_cardid)) return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData,vs->cardFiles.file_cardid,sizeof(vs->cardFiles.file_cardid));

		logprintf(pCardData, 7, "CardGUID ");
		loghex(pCardData, 7, pbData, *pdwDataLen);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_SERIAL_NO,wszProperty) == 0)
	{
		if (pdwDataLen) *pdwDataLen = sizeof(vs->p15card->tokeninfo->serial_number);
		if (cbData < sizeof(vs->p15card->tokeninfo->serial_number)) return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData,vs->p15card->tokeninfo->serial_number,sizeof(vs->p15card->tokeninfo->serial_number));

		logprintf(pCardData, 7, "SerialNumber ");
		loghex(pCardData, 7, pbData, *pdwDataLen);
		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_PIN_INFO,wszProperty) == 0)
	{
		PPIN_INFO p = (PPIN_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
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

		loghex(pCardData, 7, pbData, *pdwDataLen);


		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)
	{
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		SET_PIN(*p, ROLE_USER);
		logprintf(pCardData, 7, "CARD_LIST_PINS ");
		loghex(pCardData, 7, pbData, *pdwDataLen);

		return SCARD_S_SUCCESS;
	}
	if (wcscmp(CP_CARD_AUTHENTICATED_STATE,wszProperty) == 0)
	{
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		logprintf(pCardData, 7, "CARD_AUTHENTICATED_STATE invalid\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)
	{
		DWORD *p = (DWORD *)pbData;
		if (dwFlags != ROLE_USER) return SCARD_E_INVALID_PARAMETER;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p)) return ERROR_INSUFFICIENT_BUFFER;
		*p = CARD_PIN_STRENGTH_PLAINTEXT;

		logprintf(pCardData, 7, "CARD_PIN_STRENGTH_VERIFY");
		loghex(pCardData, 7, pbData, *pdwDataLen);

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

	logprintf(pCardData, 3, "INVALID PARAMETER\n");
	return SCARD_E_INVALID_PARAMETER;
}

DWORD WINAPI CardSetProperty(__in   PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen)  PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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

	logprintf(pCardData, 3, "INVALID PARAMETER\n");
	return SCARD_E_INVALID_PARAMETER;
}

#define MINIMUM_VERSION_SUPPORTED (4)
#define CURRENT_VERSION_SUPPORTED (6)

DWORD WINAPI CardAcquireContext(IN PCARD_DATA pCardData, __in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD suppliedVersion = 0;
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAcquireContext, dwVersion=%u, name=%S," \
			"hScard=0x%08X, hSCardCtx=0x%08X\n", pCardData->dwVersion, \
			NULLWSTR(pCardData->pwszCardName),pCardData->hScard, \
			pCardData->hSCardCtx);

	vs->hScard = pCardData->hScard;
	vs->hSCardCtx = pCardData->hSCardCtx;

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
		sc_context_param_t ctx_param;

		vs->ctx = NULL;

		logprintf(pCardData, 3, "create ctx\n");

		memset(&ctx_param, 0, sizeof(ctx_param));
		ctx_param.ver = 1;
		ctx_param.app_name = "cardmod";

		r = sc_context_create(&(vs->ctx), &ctx_param);
		logprintf(pCardData, 3, "sc_context_create passed r = %d\n", r);
		if (r)
		{
			logprintf(pCardData, 0, "Failed to establish context: %s\n", \
				sc_strerror(r));
			return SCARD_F_UNKNOWN_ERROR;
		}
	}

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

	associate_card(pCardData);

	logprintf(pCardData, 1, "OpenSC init done.\n");

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

static int associate_card(PCARD_DATA pCardData)
{
    VENDOR_SPECIFIC *vs;
	int  r;
	BYTE empty_appdir[] = {1,'m','s','c','p',0,0,0,0};
	BYTE empty_cardcf[6]={0,0,0,0,0,0};
	BYTE empty_cardid[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

	logprintf(pCardData, 1, "associate_card\n");
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	/*
	 * set the addresses of the reader and card handles
	 * Our cardmod pcsc code will use these  when we call sc_ctx_use_reader
	 * We use the address of the handles as provided in the pCardData
	 */
	vs->hSCardCtx = pCardData->hSCardCtx;
	vs->hScard = pCardData->hScard;

	memcpy(vs->cardFiles.file_appdir, empty_appdir, sizeof(empty_appdir));
	memset(&(vs->cardFiles.file_cardcf), 0, sizeof(vs->cardFiles.file_cardcf));
	memcpy(vs->cardFiles.file_cardid, empty_cardid, sizeof(empty_cardid));

	/* set the provided reader and card handles into ctx */
	logprintf(pCardData, 5, "cardmod_use_handles %d\n", \
	sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard));

	/* should be only one reader */
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

	/*
	 * We want a 16 byte unique serial number
	 * PKCS15 gives us a char string, that
	 * appears to have been formated with %02x or %02X
	 * so as to make it printable.
	 * So for now we will try and convert back to bin,
	 * and use the last 32 bytes of the vs-p15card->tokeninfo->serial_number
	 * TODO needs to be looked at closer
	 */

	if (vs->p15card->tokeninfo && vs->p15card->tokeninfo->serial_number) {
		size_t len1, len2;
		char * cserial;

		len1 = strlen(vs->p15card->tokeninfo->serial_number);
		cserial = vs->p15card->tokeninfo->serial_number;
		len2 = sizeof(vs->cardFiles.file_cardid) * 2;
		if ( len1 > len2) {
			cserial += len1 - len2;
			len1 = len2;
		}
		len1 /= 2;
		r = sc_hex_to_bin(cserial, vs->cardFiles.file_cardid, &len1);
		logprintf(pCardData, 7, "serial number r=%d len1=%d len2=%d ",r, len1, len2);
		loghex(pCardData, 7, vs->cardFiles.file_cardid, sizeof(vs->cardFiles.file_cardid));
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

#if 1
	dump_objects(pCardData);
#endif

	return SCARD_S_SUCCESS;

}

static int disassociate_card(PCARD_DATA pCardData)
{

    VENDOR_SPECIFIC *vs;
	int i;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	logprintf(pCardData, 1, "disassociate_card\n");

	if(vs->pin != NULL)
	{
		free(vs->pin);
		vs->pin = NULL;
	}

	for (i = 0; i < vs->cert_count; i++) {
		vs->cert_objs[i] = NULL;
	}
	vs->cert_count = 0;

	for (i = 0; i < vs->prkey_count; i++) {
		vs->prkey_objs[i] = NULL;
	}
	vs->prkey_count = 0;

	for (i = 0; i < vs->pin_count; i++) {
		vs->pin_objs[i] = NULL;
	}
	vs->pin_count = 0;


	if(vs->p15card)
	{
		logprintf(pCardData, 6, "sc_pkcs15_unbind\n");
		sc_pkcs15_unbind(vs->p15card);
		vs->p15card = NULL;
	}

	if(vs->card)
	{
		logprintf(pCardData, 6, "sc_disconnect_card\n");
		sc_disconnect_card(vs->card);
		vs->card = NULL;
	}

	vs->reader = NULL;

	vs->hSCardCtx = -1;
	vs->hScard = -1;

	return SCARD_S_SUCCESS;
}


BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
#ifdef CARDMOD_LOW_LEVEL_DEBUG
	logprintf(NULL,8,"\n********** DllMain hModule=0x%08X reason=%d Reserved=%p P:%d T:%d\n",
		hModule, ul_reason_for_call, lpReserved, GetCurrentProcessId(), GetCurrentThreadId());
#endif
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
#ifdef CARDMOD_LOW_LEVEL_DEBUG
			{
				CHAR name[MAX_PATH + 1] = "\0";
				GetModuleFileName(GetModuleHandle(NULL),name,MAX_PATH);
				logprintf(NULL,1,"** DllMain Attach ModuleFileName=%s\n",name);
			}
#endif
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
#endif

