/*
 * minidriver.c: OpenSC minidriver
 *
 * Copyright (C) 2009,2010 francois.leblanc@cev-sa.com
 * Copyright (C) 2015 vincent.letoux@mysmartlogon.com
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
#include <string.h>
#include <time.h>

#include <windows.h>
#include <Commctrl.h>
#include <timeapi.h>
#include "cardmod.h"

#include "common/compat_strlcpy.h"
#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "libopensc/aux-data.h"
#include "libopensc/sc-ossl-compat.h"
#include "ui/notify.h"
#include "ui/strings.h"
#include "ui/wchar_from_char_str.h"
#include "pkcs15init/pkcs15-init.h"

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/pem.h>
#endif
#endif

#ifdef ENABLE_OPENPACE
#include <eac/eac.h>
#endif

#if defined(__MINGW32__)
#include "cardmod-mingw-compat.h"
#endif

#include "cardmod.h"

/* store the instance given at DllMain when attached to access internal resources */
HINSTANCE g_inst;

#define MD_MINIMUM_VERSION_SUPPORTED 4
#define MD_CURRENT_VERSION_SUPPORTED 7

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

#define MD_MAX_KEY_CONTAINERS 12
#define MD_CARDID_SIZE 16

#define MD_ROLE_USER_SIGN (ROLE_ADMIN + 1)
/*
 * must be higher than MD_ROLE_USER_SIGN and
 * less than or equal MAX_PINS
 */
#define MD_MAX_PINS MAX_PINS

#define MD_CARDCF_LENGTH	(sizeof(CARD_CACHE_FILE_FORMAT))

#define MD_KEY_USAGE_KEYEXCHANGE		\
	SC_PKCS15INIT_X509_KEY_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DATA_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE
#define MD_KEY_USAGE_KEYEXCHANGE_ECC		\
	SC_PKCS15INIT_X509_KEY_AGREEMENT| \
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE
#define MD_KEY_USAGE_SIGNATURE			\
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE	| \
	SC_PKCS15INIT_X509_KEY_CERT_SIGN	| \
	SC_PKCS15INIT_X509_CRL_SIGN
#define MD_KEY_ACCESS				\
	SC_PKCS15_PRKEY_ACCESS_SENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE	| \
	SC_PKCS15_PRKEY_ACCESS_LOCAL

/* copied from pkcs15-cardos.c */
#define USAGE_ANY_SIGN		(SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_ANY_DECIPHER	(SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP)
#define USAGE_ANY_AGREEMENT (SC_PKCS15_PRKEY_USAGE_DERIVE)

/* if use of internal-winscard.h */
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER	0x80100004L
#define SCARD_E_UNSUPPORTED_FEATURE	0x80100022L
#define SCARD_E_NO_MEMORY		0x80100006L
#define SCARD_W_WRONG_CHV		0x8010006BL
#define SCARD_E_FILE_NOT_FOUND		0x80100024L
#define SCARD_E_UNKNOWN_CARD		0x8010000DL
#define SCARD_F_UNKNOWN_ERROR		0x80100014L
#endif

 /* defined twice: in versioninfo-minidriver.rc.in and in minidriver.c */
#define IDI_SMARTCARD   102

#define SUBKEY_ENABLE_CANCEL "Software\\OpenSC Project\\OpenSC\\md_pinpad_dlg_enable_cancel"

/* magic to determine previous pinpad authentication */
#define MAGIC_SESSION_PIN "opensc-minidriver"

#define TLS1_0_PROTOCOL_VERSION 0x0301
#define TLS1_1_PROTOCOL_VERSION 0x0302
#define TLS1_2_PROTOCOL_VERSION 0x0303
#define TLS_DERIVE_KEY_SIZE 48

struct md_directory {
	unsigned char name[9];

	CARD_DIRECTORY_ACCESS_CONDITION acl;

	struct md_file *files;
	struct md_directory *subdirs;

	struct md_directory *next;
};

struct md_file {
	unsigned char name[9];

	CARD_FILE_ACCESS_CONDITION acl;

	unsigned char *blob;
	size_t size;

	struct md_file *next;
};

struct md_pkcs15_container {
	int index;
	struct sc_pkcs15_id id;
	char guid[MAX_CONTAINER_NAME_LEN + 1];
	unsigned char flags;
	size_t size_key_exchange, size_sign;

	struct sc_pkcs15_object *cert_obj, *prkey_obj, *pubkey_obj;
	// BOOL guid_overwrite;
};

struct md_dh_agreement {
	DWORD dwSize;
	PBYTE pbAgreement;
};

struct md_guid_conversion {
	CHAR szOpenSCGuid[MAX_CONTAINER_NAME_LEN+1];
	CHAR szWindowsGuid[MAX_CONTAINER_NAME_LEN+1];
};

#define MD_MAX_CONVERSIONS 50
struct md_guid_conversion md_static_conversions[MD_MAX_CONVERSIONS] = {0};

typedef struct _VENDOR_SPECIFIC
{
	BOOL initialized;

	struct sc_pkcs15_object *pin_objs[MD_MAX_PINS];

	struct sc_context *ctx;
	struct sc_reader *reader;
	struct sc_card *card;
	struct sc_pkcs15_card *p15card;

	struct md_pkcs15_container p15_containers[MD_MAX_KEY_CONTAINERS];

	struct md_directory root;

	SCARDCONTEXT hSCardCtx;
	SCARDHANDLE hScard;

	/* These will be used in CardAuthenticateEx to display a dialog box when doing
	 * external PIN verification.
	 */
	HWND hwndParent;
	LPWSTR wszPinContext;
	/* these will be used to store intermediate dh agreements results */
	struct md_dh_agreement* dh_agreements;
	BYTE allocatedAgreements;

	CRITICAL_SECTION hScard_lock;
} VENDOR_SPECIFIC;

static DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror,
						  DWORD dwDefaulCode);
static DWORD associate_card(PCARD_DATA pCardData);
static void disassociate_card(PCARD_DATA pCardData);
static DWORD md_pkcs15_delete_object(PCARD_DATA pCardData, struct sc_pkcs15_object *obj);
static DWORD md_fs_init(PCARD_DATA pCardData);
static void md_fs_finalize(PCARD_DATA pCardData);

#if defined(__GNUC__)
static void logprintf(PCARD_DATA pCardData, int level, const char* format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 3, 4)));
#endif

static void logprintf(PCARD_DATA pCardData, int level, _Printf_format_string_ const char* format, ...)
{
	va_list arg;
	VENDOR_SPECIFIC *vs;
/* Use a simplified log to get all messages including messages
 * before opensc is loaded. The file must be modifiable by all
 * users as we maybe called under lsa or user. Note data from
 * multiple process and threads may get intermingled.
 * flush to get last message before any crash
 * close so as the file is not left open during any wait.
 */
	DWORD md_debug = 0;
	size_t sz = sizeof(md_debug);
	int rv;

	rv = sc_ctx_win32_get_config_value("CARDMOD_LOW_LEVEL_DEBUG",
			"MiniDriverDebug", "Software\\OpenSC Project\\OpenSC",
			(char *)(&md_debug), &sz);
	if (rv == SC_SUCCESS && md_debug != 0)   {
		FILE *lldebugfp = fopen("C:\\tmp\\md.log","a+");
		if (lldebugfp)   {
			va_start(arg, format);
			vfprintf(lldebugfp, format, arg);
			va_end(arg);
			fflush(lldebugfp);
			fclose(lldebugfp);
		}
	}

	va_start(arg, format);
	if(pCardData != NULL)   {
		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(vs != NULL && vs->ctx != NULL)
			sc_do_log_noframe(vs->ctx, level, format, arg);
	}
	va_end(arg);
}

static void loghex(PCARD_DATA pCardData, int level, PBYTE data, size_t len)
{
	char line[74];
	char *c;
	unsigned int i, a;
	unsigned char * p;

	logprintf(pCardData, level, "--- %p:%"SC_FORMAT_LEN_SIZE_T"u\n",
		  data, len);

	if (data == NULL || len <= 0) return;

	p = data;
	c = line;
	i = 0;
	a = 0;
	memset(line, 0, sizeof(line));

	while(i < len) {
		snprintf(c, sizeof(line) - (size_t)(c - line), "%02X", *p);
		line[sizeof(line) - 1] = 0;
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

static DWORD reinit_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	DWORD r;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "trying to reinit card\n");

	if (vs->initialized) {
		disassociate_card(pCardData);
		md_fs_finalize(pCardData);
	}

	r = associate_card(pCardData);
	if (r != SCARD_S_SUCCESS)
		return r;

	r = md_fs_init(pCardData);
	if (r != SCARD_S_SUCCESS) {
		logprintf(pCardData, 1,
			  "reinit_card md_fs_init failed, r = 0x%lX\n",
			  (unsigned long)r);
		disassociate_card(pCardData);
		return r;
	}

	return SCARD_S_SUCCESS;
}

static BOOL lock(PCARD_DATA pCardData)
{
	if (pCardData) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if (vs) {
			EnterCriticalSection(&vs->hScard_lock);
			return TRUE;
		}
	}

	return FALSE;
}

static void unlock(PCARD_DATA pCardData)
{
	if (pCardData) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if (vs) {
			LeaveCriticalSection(&vs->hScard_lock);
		}
	}
}

static DWORD reinit_card_for(PCARD_DATA pCardData, const char *name)
{
	DWORD r;

	r = reinit_card(pCardData);
	if (r != SCARD_S_SUCCESS)
		logprintf(pCardData, 1,
			  "%s was called, but unable to initialize card, r = %u\n",
			  name, (unsigned int)r);

	return r;
}

static DWORD check_card_status(PCARD_DATA pCardData, const char *name)
{
	VENDOR_SPECIFIC *vs;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (vs->initialized)
		return SCARD_S_SUCCESS;

	return reinit_card_for(pCardData, name);
}

/*
 * check if the card is OK, has been removed, or the
 * caller has changed the handles.
 * if so, then try to reinit card
 */
static DWORD
check_card_reader_status(PCARD_DATA pCardData, const char *name)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwRet;
	int r;

	logprintf(pCardData, 4, "check_reader_status\n");
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	dwRet = check_card_status(pCardData, name);
	if (dwRet != SCARD_S_SUCCESS)
		return dwRet;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 7, "pCardData->hSCardCtx:0x%08X hScard:0x%08X\n",
		  (unsigned int)pCardData->hSCardCtx,
		  (unsigned int)pCardData->hScard);

	if (pCardData->hSCardCtx != vs->hSCardCtx || pCardData->hScard != vs->hScard) {
		logprintf(pCardData, 1, "HANDLES CHANGED from 0x%08X 0x%08X\n",
			  (unsigned int)vs->hSCardCtx,
			  (unsigned int)vs->hScard);
		return reinit_card_for(pCardData, name);
	}

	/* This should always work, as BaseCSP should be checking for removal too */
	r = sc_detect_card_presence(vs->reader);
	logprintf(pCardData, 2,
		  "check_reader_status r=%d flags 0x%08X\n", r,
		  (unsigned int)vs->reader->flags);
	if (r < 0)
		return md_translate_OpenSC_to_Windows_error(r,
							    SCARD_F_INTERNAL_ERROR);

	if (!(r & SC_READER_CARD_PRESENT)) {
		/*
		 * if there is really no card present it may not make sense to
		 * try initializing the card but since it won't hurt let's try
		 * it anyway for completeness
		 */
		logprintf(pCardData, 1, "no card present? trying to reinit\n");
		return reinit_card_for(pCardData, name);
	}

	return SCARD_S_SUCCESS;
}

static DWORD
md_get_pin_by_role(PCARD_DATA pCardData, PIN_ID role, struct sc_pkcs15_object **ret_obj)
{
	VENDOR_SPECIFIC *vs;
	int rv;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!ret_obj)
		return SCARD_E_INVALID_PARAMETER;

	/* please keep me in sync with _get_auth_object_by_name() in pkcs11/framework-pkcs15.c */
	if (role == ROLE_USER) {
		/* Get 'global' User PIN; if no, get the 'local' one */
		rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
						 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
							 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
	}
	else if (role == MD_ROLE_USER_SIGN) {
		int idx = 0;

		/* Get the 'global' user PIN */
		rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
						 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
		if (!rv) {
			/* Global (user) PIN exists, get the local one -- sign PIN */
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
							 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
		}
		else {
			/* No global PIN, try to get first local one -- user PIN */
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
							 SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, ret_obj);
			if (!rv) {
				/* User PIN is local, try to get the second local -- sign PIN */
				idx++;
				rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
								 SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, ret_obj);
			}
		}
	}
	else if (role == ROLE_ADMIN) {
		/* Get SO PIN; if no, get the 'global' PUK; if no get the 'local' one  */
		rv = sc_pkcs15_find_so_pin(vs->p15card, ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL,
							 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL,
							 SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, ret_obj);
	}
	else   {
		logprintf(pCardData, 2,
			  "cannot get PIN object: unsupported role %u\n",
			  (unsigned int)role);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (rv)
		return SCARD_E_UNSUPPORTED_FEATURE;

	if (*ret_obj)
		logprintf(pCardData, 7, "Returning PIN '%.*s' for role %u\n",
			  (int) sizeof (*ret_obj)->label, (*ret_obj)->label,
			  (unsigned int)role);

	return SCARD_S_SUCCESS;
}

static const char *
md_get_config_str(PCARD_DATA pCardData, enum ui_str id)
{
	VENDOR_SPECIFIC *vs;
	const char *ret = NULL;

	if (!pCardData)
		return ret;

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader) {
		const char *preferred_language = NULL;
		struct sc_atr atr;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		if (vs->p15card && vs->p15card->tokeninfo
				&& vs->p15card->tokeninfo->preferred_language) {
			preferred_language = vs->p15card->tokeninfo->preferred_language;
		}
		ret = ui_get_str(vs->ctx, &atr, vs->p15card, id);
	}

	return ret;
}


static HICON
md_get_config_icon(PCARD_DATA pCardData, char *flag_name, HICON ret_default)
{
	VENDOR_SPECIFIC *vs;
	HICON ret = ret_default;

	if (!pCardData)
		return ret;

	logprintf(pCardData, 2, "Get '%s' option\n", flag_name);

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader)   {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock) {
			const char *filename = scconf_get_str(atrblock, flag_name, NULL);
			if (filename) {
				ret = (HICON) LoadImage(g_inst, filename, IMAGE_ICON, 0, 0,
						LR_LOADFROMFILE|LR_DEFAULTSIZE|LR_SHARED);
			}
			if (!ret)
				ret = ret_default;
		}
	}


	return ret;
}


static HICON
md_get_pinpad_dlg_icon(PCARD_DATA pCardData)
{
	return md_get_config_icon(pCardData, "md_pinpad_dlg_icon", NULL);
}


static int
md_get_config_int(PCARD_DATA pCardData, char *flag_name, int ret_default)
{
	VENDOR_SPECIFIC *vs;
	int ret = ret_default;

	if (!pCardData)
		return ret;

	logprintf(pCardData, 2, "Get '%s' option\n", flag_name);

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader)   {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock)
			ret = scconf_get_int(atrblock, flag_name, ret_default);
	}

	return ret;
}


static int
md_get_pinpad_dlg_timeout(PCARD_DATA pCardData)
{
	return md_get_config_int(pCardData, "md_pinpad_dlg_timeout", 30);
}


static BOOL
md_get_config_bool(PCARD_DATA pCardData, char *flag_name, BOOL ret_default)
{
	VENDOR_SPECIFIC *vs;
	BOOL ret = ret_default;

	if (!pCardData)
		return ret;

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (!vs)
		return ret;

	if (vs->ctx && vs->reader)   {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock)
			ret = scconf_get_bool(atrblock, flag_name, ret_default) ? TRUE : FALSE;
	}

	return ret;
}


/* 'cancellation' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_pinpad_dlg_enable_cancel(PCARD_DATA pCardData)
{
	TCHAR path[MAX_PATH]={0};

	logprintf(pCardData, 2, "Is cancelling the PIN pad dialog enabled?\n");

	if (GetModuleFileName(NULL, path, ARRAYSIZE(path))) {
		DWORD enable_cancel;
		size_t sz = sizeof enable_cancel;

		if (SC_SUCCESS == sc_ctx_win32_get_config_value(NULL, path,
					SUBKEY_ENABLE_CANCEL,
					(char *)(&enable_cancel), &sz)) {
			switch (enable_cancel) {
				case 0:
					return FALSE;
				case 1:
					return TRUE;
			}
		}
	}

	return md_get_config_bool(pCardData, "md_pinpad_dlg_enable_cancel", FALSE);
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_read_only(PCARD_DATA pCardData)
{
	BOOL ret = TRUE;

	logprintf(pCardData, 2, "Is read-only?\n");

	if (pCardData && pCardData->pvVendorSpecific) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
		if (vs->p15card && vs->p15card->tokeninfo) {
			if (vs->p15card->tokeninfo->flags & SC_PKCS15_TOKEN_READONLY) {
				ret = TRUE;
			} else {
				ret = FALSE;
			}
		}
	}

	return md_get_config_bool(pCardData, "read_only", ret);
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_supports_X509_enrollment(PCARD_DATA pCardData)
{
	BOOL defaultvalue = !md_is_read_only(pCardData);
	logprintf(pCardData, 2, "Is supports X509 enrollment?\n");
	return md_get_config_bool(pCardData, "md_supports_X509_enrollment", defaultvalue);
}


/* Get know if the GUID has to used as ID of crypto objects */
static BOOL
md_is_guid_as_id(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as ID of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_id", FALSE);
}


/* Get know if the GUID has to used as label of crypto objects */
static BOOL
md_is_guid_as_label(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as label of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_label", FALSE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_GEN mechanism */
static BOOL
md_is_supports_container_key_gen(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key generation' create_container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_gen", TRUE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_IMPORT mechanism */
static BOOL
md_is_supports_container_key_import(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key import' create container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_import", TRUE);
}

/* generate unique key label (GUID)*/
static VOID md_generate_guid( __in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szGuid) {
	RPC_CSTR szRPCGuid = NULL;
	GUID Label = {0};
	UuidCreate(&Label);
	if (UuidToStringA(&Label, &szRPCGuid) == RPC_S_OK && szRPCGuid) {
		strlcpy(szGuid, (PSTR)szRPCGuid, MAX_CONTAINER_NAME_LEN + 1);
		RpcStringFreeA(&szRPCGuid);
	} else
		szGuid[0] = 0;
}

static DWORD
md_contguid_get_guid_from_card(PCARD_DATA pCardData, struct sc_pkcs15_object *prkey, __in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szGuid)
{
	int rv;
	VENDOR_SPECIFIC *vs;
	size_t guid_len = MAX_CONTAINER_NAME_LEN+1;

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	rv = sc_pkcs15_get_object_guid(vs->p15card, prkey, 1, (unsigned char*) szGuid, &guid_len);
	if (rv)   {
		logprintf(pCardData, 2, "md_contguid_get_guid_from_card(): error %d\n", rv);
		return SCARD_F_INTERNAL_ERROR;
	}

	return SCARD_S_SUCCESS;
}

/* add a new entry in the guid conversion table */
static DWORD
md_contguid_add_conversion(PCARD_DATA pCardData, struct sc_pkcs15_object *prkey,
		__in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szWindowsGuid)
{
	DWORD ret;
	int i;
	CHAR szOpenSCGuid[MAX_CONTAINER_NAME_LEN+1] = "";

	ret = md_contguid_get_guid_from_card(pCardData, prkey, szOpenSCGuid);
	if (ret != SCARD_S_SUCCESS)
		return ret;

	if (strcmp(szOpenSCGuid, szWindowsGuid) == 0)
		return ret;

	for (i = 0; i < MD_MAX_CONVERSIONS; i++) {
		if (md_static_conversions[i].szWindowsGuid[0] == 0) {
			strlcpy(md_static_conversions[i].szWindowsGuid,
				szWindowsGuid, MAX_CONTAINER_NAME_LEN + 1);
			strlcpy(md_static_conversions[i].szOpenSCGuid,
				szOpenSCGuid, MAX_CONTAINER_NAME_LEN + 1);
			logprintf(pCardData, 0, "md_contguid_add_conversion(): Registering conversion '%s' '%s'\n", szWindowsGuid, szOpenSCGuid);
			return SCARD_S_SUCCESS;;
		}
	}
	logprintf(pCardData, 0, "md_contguid_add_conversion(): Unable to add a new conversion with guid %s.\n", szWindowsGuid);
	return SCARD_F_INTERNAL_ERROR;;
}

/* remove an entry in the guid conversion table*/
static VOID
md_contguid_delete_conversion(PCARD_DATA pCardData, __in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szWindowsGuid)
{
	int i;
	for (i = 0; i < MD_MAX_CONVERSIONS; i++) {
		if (strcmp(md_static_conversions[i].szWindowsGuid,szWindowsGuid) == 0) {
			memset(md_static_conversions + i, 0, sizeof(struct md_guid_conversion));
		}
	}
}

/* build key args from the minidriver guid */
static VOID
md_contguid_build_key_args_from_cont_guid(PCARD_DATA pCardData, __in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szGuid,
		struct sc_pkcs15init_prkeyargs *prkey_args)
{
	/* strlen(szGuid) <= MAX_CONTAINER_NAME */
	logprintf(pCardData, 3, "Using the guid '%s'\n", szGuid);
	if (szGuid[0] != 0)   {
		prkey_args->guid = (unsigned char*) szGuid;
		prkey_args->guid_len = strlen(szGuid);
	}

	if (md_is_guid_as_id(pCardData))  {
		memcpy(prkey_args->id.value, szGuid, strlen(szGuid));
		prkey_args->id.len = strlen(szGuid);
	}
	if (md_is_guid_as_label(pCardData))  {
		prkey_args->label =  szGuid;
	}
}

/* build minidriver guid from the key */
static DWORD
md_contguid_build_cont_guid_from_key(PCARD_DATA pCardData, struct sc_pkcs15_object *key_obj, __in_ecount(MAX_CONTAINER_NAME_LEN+1) PSTR szGuid)
{
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
	DWORD dwret = SCARD_S_SUCCESS;

	szGuid[0] = '\0';
	/* prioritize the use of the key id over the key label as a container name */
	if (md_is_guid_as_id(pCardData) && prkey_info->id.len > 0 && prkey_info->id.len <= MAX_CONTAINER_NAME_LEN)  {
		memcpy(szGuid, prkey_info->id.value, prkey_info->id.len);
		szGuid[prkey_info->id.len] = 0;
	} else if (md_is_guid_as_label(pCardData) && key_obj->label[0] != 0)  {
		strlcpy(szGuid, key_obj->label, MAX_CONTAINER_NAME_LEN + 1);
	} else {
		dwret = md_contguid_get_guid_from_card(pCardData, key_obj, szGuid);
	}

	return dwret;
}


static DWORD
md_cont_flags_from_key(PCARD_DATA pCardData, struct sc_pkcs15_object *key_obj, unsigned char *cont_flags)
{
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	VENDOR_SPECIFIC *vs;
	int rv;

	vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;

	*cont_flags = CONTAINER_MAP_VALID_CONTAINER;
	if (prkey_info->aux_data)   {
		rv = sc_aux_data_get_md_flags(vs->ctx, prkey_info->aux_data, cont_flags);
		if (rv != SC_ERROR_NOT_SUPPORTED && rv != SC_SUCCESS)
			return SCARD_F_INTERNAL_ERROR;
	}

	return SCARD_S_SUCCESS;
}


/* Search directory by name and optionally by name of it's parent */
static DWORD
md_fs_find_directory(PCARD_DATA pCardData, struct md_directory *parent, char *name, struct md_directory **out)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;

	if (out)
		*out = NULL;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (!parent)
		parent = &vs->root;

	if (!name)   {
		dir = parent;
	}
	else   {
		dir = parent->subdirs;
		while(dir)   {
			if (strlen(name) > sizeof dir->name
					|| !strncmp((char *)dir->name, name, sizeof dir->name))
				break;
			dir = dir->next;
		}
	}

	if (!dir)
		return SCARD_E_DIR_NOT_FOUND;

	if (out)
		*out = dir;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' directory\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_directory(PCARD_DATA pCardData, struct md_directory **head, char *name,
		CARD_FILE_ACCESS_CONDITION acl,
		struct md_directory **out)
{
	struct md_directory *new_dir = NULL;

	if (!pCardData || !head || !name)
		return SCARD_E_INVALID_PARAMETER;

	new_dir = pCardData->pfnCspAlloc(sizeof(struct md_directory));
	if (!new_dir)
		return SCARD_E_NO_MEMORY;
	memset(new_dir, 0, sizeof(struct md_directory));

	strlcpy((char *)new_dir->name, name, sizeof(new_dir->name));
	new_dir->acl = acl;

	if (*head == NULL)   {
		*head = new_dir;
	}
	else    {
		struct md_directory *last = *head;
		while (last->next)
			last = last->next;
		last->next = new_dir;
	}

	if (out)
		*out = new_dir;

	logprintf(pCardData, 3, "MD virtual file system: directory '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_find_file(PCARD_DATA pCardData, char *parent, char *name, struct md_file **out)
{
	struct md_file *file = NULL;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (out)
		*out = NULL;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			  parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}

	for (file = dir->files; file!=NULL;)   {
		if (sizeof file->name < strlen(name)
				|| !strncmp((char *)file->name, name, sizeof file->name))
			break;
		file = file->next;
	}
	if (!file)
		return SCARD_E_FILE_NOT_FOUND;

	if (out)
		*out = file;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' file\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_file(PCARD_DATA pCardData, struct md_file **head, char *name, CARD_FILE_ACCESS_CONDITION acl,
		unsigned char *blob, size_t size, struct md_file **out)
{
	struct md_file *new_file = NULL;

	if (!pCardData || !head || !name)
		return SCARD_E_INVALID_PARAMETER;

	new_file = pCardData->pfnCspAlloc(sizeof(struct md_file));
	if (!new_file)
		return SCARD_E_NO_MEMORY;
	memset(new_file, 0, sizeof(struct md_file));

	strlcpy((char *)new_file->name, name, sizeof(new_file->name));
	new_file->size = size;
	new_file->acl = acl;

	if (size)   {
		new_file->blob = pCardData->pfnCspAlloc(size);
		if (!new_file->blob)   {
			pCardData->pfnCspFree(new_file);
			return SCARD_E_NO_MEMORY;
		}

		if (blob)
			CopyMemory(new_file->blob, blob, size);
		else
			memset(new_file->blob, 0, size);
	}

	if (*head == NULL)   {
		*head = new_file;
	}
	else    {
		struct md_file *last = *head;
		while (last->next)
			last = last->next;
		last->next = new_file;
	}

	if (out)
		*out = new_file;

	logprintf(pCardData, 3, "MD virtual file system: file '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static void
md_fs_free_file(PCARD_DATA pCardData, struct md_file *file)
{
	if (!file)
		return;
	if (file->blob)
		pCardData->pfnCspFree(file->blob);
	file->blob = NULL;
	file->size = 0;
	pCardData->pfnCspFree(file);
}


static DWORD
md_fs_delete_file(PCARD_DATA pCardData, char *parent, char *name)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL, *file_to_rm = NULL;
	struct md_directory *dir = NULL;
	int deleted = 0;
	DWORD dwret;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			  parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (!dir->files)   {
		logprintf(pCardData, 2, "no files in '%s' directory\n", parent ? parent : "<null>");
		return SCARD_E_FILE_NOT_FOUND;
	}

	if (sizeof dir->files->name < strlen(name)
			|| !strncmp((char *)dir->files->name, name, sizeof dir->files->name))   {
		file_to_rm = dir->files;
		dir->files = dir->files->next;
		md_fs_free_file(pCardData, file_to_rm);
		dwret = SCARD_S_SUCCESS;
	}
	else   {
		for (file = dir->files; file!=NULL; file = file->next)   {
			if (!file->next)
				break;
			if (sizeof file->next->name < strlen(name)
					|| !strncmp((char *)file->next->name, name, sizeof file->next->name))   {
				file_to_rm = file->next;
				file->next = file->next->next;
				md_fs_free_file(pCardData, file_to_rm);
				deleted = 1;
				break;
			}
		}
		dwret = deleted ? SCARD_S_SUCCESS : SCARD_E_FILE_NOT_FOUND;
	}

	if (!strcmp(parent, "mscp"))   {
		int idx = -1;

		if(sscanf(name, "ksc%d", &idx) > 0)   {
		}
		else if(sscanf(name, "kxc%d", &idx) > 0)   {
		}

		if (idx >= 0 && idx < MD_MAX_KEY_CONTAINERS)   {
			dwret = md_pkcs15_delete_object(pCardData, vs->p15_containers[idx].cert_obj);
			vs->p15_containers[idx].cert_obj = NULL;
			if(dwret != SCARD_S_SUCCESS)
				logprintf(pCardData, 2,
					  "Cannot delete certificate PKCS#15 object #%i: dwret 0x%lX\n",
					  idx, (unsigned long)dwret);
		}
	}

	return dwret;
}

static void
md_fs_finalize(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL, *file_to_rm;
	struct md_directory *dir = NULL, *dir_to_rm;

	if (!pCardData)
		return;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return;

	file = vs->root.files;
	while (file != NULL) {
		file_to_rm = file;
		file = file->next;
		md_fs_free_file(pCardData, file_to_rm);
	}
	vs->root.files = NULL;

	dir = vs->root.subdirs;
	while(dir)   {
		file = dir->files;
		while (file != NULL) {
			file_to_rm = file;
			file = file->next;
			md_fs_free_file(pCardData, file_to_rm);
		}
		dir_to_rm = dir;
		dir = dir->next;
		pCardData->pfnCspFree(dir_to_rm);
	}
	vs->root.subdirs = NULL;
}

/*
 * Update 'soft' containers.
 * Called each time when 'WriteFile' is called for 'cmapfile'.
 */
static DWORD
md_pkcs15_update_containers(PCARD_DATA pCardData, unsigned char *blob, size_t size)
{
	VENDOR_SPECIFIC *vs;
	CONTAINER_MAP_RECORD *pp;
	int nn_records, idx;

	if (!pCardData || !blob || size < sizeof(CONTAINER_MAP_RECORD))
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	nn_records = (int) size/sizeof(CONTAINER_MAP_RECORD);
	if (nn_records > MD_MAX_KEY_CONTAINERS)
		nn_records = MD_MAX_KEY_CONTAINERS;

	for (idx=0, pp = (CONTAINER_MAP_RECORD *)blob; idx<nn_records; idx++, pp++)   {
		struct md_pkcs15_container *cont = &(vs->p15_containers[idx]);
		size_t count;
		CHAR szGuid[MAX_CONTAINER_NAME_LEN+1] = "";

		count = wcstombs(szGuid, pp->wszGuid, sizeof(cont->guid));
		if (!count)   {
			if (cont->guid[0] != 0) {
				md_contguid_delete_conversion(pCardData, cont->guid);
			}
			memset(cont, 0, sizeof(CONTAINER_MAP_RECORD));
		}
		else   {
			strlcpy(cont->guid, szGuid, MAX_CONTAINER_NAME_LEN + 1);
			cont->index = idx;
			cont->flags = pp->bFlags;
			cont->size_sign = pp->wSigKeySizeBits;
			cont->size_key_exchange = pp->wKeyExchangeKeySizeBits;
			logprintf(pCardData, 3, "update P15 containers: touch container (idx:%i,id:%s,guid:%.*s,flags:%X)\n",
				idx, sc_pkcs15_print_id(&cont->id),
				(int)sizeof cont->guid, cont->guid, cont->flags);
		}
	}

	return SCARD_S_SUCCESS;
}


static DWORD
md_pkcs15_delete_object(PCARD_DATA pCardData, struct sc_pkcs15_object *obj)
{
	VENDOR_SPECIFIC *vs;
	struct sc_profile *profile = NULL;
	struct sc_card *card = NULL;
	struct sc_app_info *app_info = NULL;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	int rv;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	card = vs->p15card->card;

	if (!obj)
		return SCARD_S_SUCCESS;
	logprintf(pCardData, 3, "MdDeleteObject('%.*s',type:0x%X) called\n", (int) sizeof obj->label, obj->label, obj->type);

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdDeleteObject(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdDeleteObject(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdDeleteObject(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);

	rv = sc_pkcs15init_delete_object(vs->p15card, profile, obj);
	if (rv)   {
		logprintf(pCardData, 2, "MdDeleteObject(): pkcs15init delete object failed %d\n", rv);
		goto done;
	}

	dwret = SCARD_S_SUCCESS;
	logprintf(pCardData, 3, "MdDeleteObject() returns OK\n");
done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}


/* Set 'soft' file contents,
 * and update data associated to  'cardcf' and 'cmapfile'.
 */
static DWORD
md_fs_set_content(PCARD_DATA pCardData, struct md_file *file, unsigned char *blob, size_t size)
{
	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	if (file->blob)
		pCardData->pfnCspFree(file->blob);

	file->blob = pCardData->pfnCspAlloc(size);
	if (!file->blob)
		return SCARD_E_NO_MEMORY;
	CopyMemory(file->blob, blob, size);
	file->size = size;

	if (!strcmp((char *)file->name, "cmapfile"))
		return md_pkcs15_update_containers(pCardData, blob, size);

	return SCARD_S_SUCCESS;
}

/*
 * Set 'cardid' from the 'serialNumber' attribute of the 'tokenInfo'
 */
static DWORD
md_set_cardid(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (vs->p15card->tokeninfo && vs->p15card->tokeninfo->serial_number) {
		unsigned char sn_bin[SC_MAX_SERIALNR];
		unsigned char cardid_bin[MD_CARDID_SIZE];
		size_t offs, wr, sn_len = sizeof(sn_bin);
		int rv;

		rv = sc_hex_to_bin(vs->p15card->tokeninfo->serial_number, sn_bin, &sn_len);
		if (rv) {
			sn_len = strlen(vs->p15card->tokeninfo->serial_number);
			if (sn_len > SC_MAX_SERIALNR) {
				sn_len = SC_MAX_SERIALNR;
			}
			memcpy(sn_bin, vs->p15card->tokeninfo->serial_number, sn_len);
		}

		if (sn_len > 0) {
			for (offs=0; offs < MD_CARDID_SIZE; )   {
				wr = MD_CARDID_SIZE - offs;
				if (wr > sn_len)
					wr = sn_len;
				memcpy(cardid_bin + offs, sn_bin, wr);
				offs += wr;
			}
		} else {
			memset(cardid_bin, 0, MD_CARDID_SIZE);
		}

		dwret = md_fs_set_content(pCardData, file, cardid_bin, MD_CARDID_SIZE);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}

	logprintf(pCardData, 3, "cardid(%"SC_FORMAT_LEN_SIZE_T"u)\n",
		  file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/* fill the msroots file from root certificates */
static DWORD
md_fs_read_msroots_file(PCARD_DATA pCardData, struct md_file *file)
{
	CERT_BLOB dbStore = {0};
	HCERTSTORE hCertStore;
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	DWORD dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *) pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, (HCRYPTPROV_LEGACY)NULL, 0, NULL);
	if (!hCertStore)
		goto Ret;

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
		dwret = md_translate_OpenSC_to_Windows_error(rv, dwret);
		goto Ret;
	}
	cert_num = rv;
	for(ii = 0; ii < cert_num; ii++)   {
		struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) prkey_objs[ii]->data;
		struct sc_pkcs15_cert *cert = NULL;
		PCCERT_CONTEXT wincert = NULL;
		if (cert_info->authority) {
			rv = sc_pkcs15_read_certificate(vs->p15card, cert_info, &cert);
			if(rv)   {
				logprintf(pCardData, 2, "Cannot read certificate idx:%i: sc-error %d\n", ii, rv);
				continue;
			}
			wincert = CertCreateCertificateContext(X509_ASN_ENCODING, cert->data.value, (DWORD) cert->data.len);
			if (wincert) {
				CertAddCertificateContextToStore(hCertStore, wincert, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
				CertFreeCertificateContext(wincert);
			}
			else {
				logprintf(pCardData, 2,
					  "unable to load the certificate from Windows 0x%08X\n",
					  (unsigned int)GetLastError());
			}
			sc_pkcs15_free_certificate(cert);
		}
	}
	if (FALSE == CertSaveStore(	hCertStore,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			CERT_STORE_SAVE_AS_PKCS7,
			CERT_STORE_SAVE_TO_MEMORY,
				&dbStore,
		0)) {
		goto Ret;
	}

	dbStore.pbData = (PBYTE) pCardData->pfnCspAlloc(dbStore.cbData);

	if (NULL == dbStore.pbData) {
		dwret = SCARD_E_NO_MEMORY;
		goto Ret;
	}

	if (FALSE == CertSaveStore(	hCertStore,
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				CERT_STORE_SAVE_AS_PKCS7,
				CERT_STORE_SAVE_TO_MEMORY,
				&dbStore,
				0))
	{
		goto Ret;
	}
	file->size = dbStore.cbData;
	file->blob = dbStore.pbData;
	dbStore.pbData = NULL;
	dwret = SCARD_S_SUCCESS;

Ret:
	if (dbStore.pbData)
		pCardData->pfnCspFree(dbStore.pbData);
	if (hCertStore)
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return dwret;
}

/*
 * Return content of the 'soft' file.
 */
static DWORD
md_fs_read_content(PCARD_DATA pCardData, char *parent, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs || !vs->p15card)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			  parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_DIR_NOT_FOUND;
	}

	if (!strcmp((char *)dir->name, "mscp"))   {
		int idx, rv;

		if(sscanf((char *)file->name, "ksc%d", &idx) > 0)   {
		}
		else if(sscanf((char *)file->name, "kxc%d", &idx) > 0)   {
		}
		else   {
			idx = -1;
		}

		if (idx >=0 && idx < MD_MAX_KEY_CONTAINERS && vs->p15_containers[idx].cert_obj)   {
			struct sc_pkcs15_cert *cert = NULL;
			struct sc_pkcs15_object *cert_obj = vs->p15_containers[idx].cert_obj;
			struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *)cert_obj->data;

			rv = sc_pkcs15_read_certificate(vs->p15card, cert_info, &cert);
			if(rv)   {
				logprintf(pCardData, 2, "Cannot read certificate idx:%i: sc-error %d\n", idx, rv);
				logprintf(pCardData, 2, "set cardcf from 'DATA' pkcs#15 object\n");
				return md_translate_OpenSC_to_Windows_error(rv,
									    SCARD_F_INTERNAL_ERROR);
			}

			file->blob = pCardData->pfnCspAlloc(cert->data.len);
			if (file->blob) {
				CopyMemory(file->blob, cert->data.value, cert->data.len);
				file->size = cert->data.len;
				dwret = SCARD_S_SUCCESS;
			} else
				dwret = SCARD_E_NO_MEMORY;

			sc_pkcs15_free_certificate(cert);

			return dwret;
		} else if (!strcmp((char *)file->name, "msroots"))
			return md_fs_read_msroots_file(pCardData, file);
	}

	return SCARD_E_FILE_NOT_FOUND;
}

/*
 * Set content of 'cardcf',
 * for that look for the possible source in the following order:
 * - data from the dedicated PKCS#15 'DATA' object;
 * - 'lastUpdate' attribute of tokenInfo;
 * - random data.
 */
static DWORD
md_set_cardcf(PCARD_DATA pCardData, struct md_file *file)
{
	CARD_CACHE_FILE_FORMAT empty = {0};
	DWORD dwret;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_set_content(pCardData, file, (unsigned char *)(&empty), MD_CARDCF_LENGTH);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "'cardcf' content(%"SC_FORMAT_LEN_SIZE_T"u)\n",
		  file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

static DWORD
md_set_cardapps(PCARD_DATA pCardData, struct md_file *file)
{
	DWORD dwret;
	unsigned char mscp[8] = {'m','s','c','p',0,0,0,0};

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_set_content(pCardData, file, mscp, sizeof(mscp));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "mscp(%"SC_FORMAT_LEN_SIZE_T"u)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/* check if the card has root certificates. If yes, notify the base csp by creating the msroots file */
static DWORD
md_fs_add_msroots(PCARD_DATA pCardData, struct md_file **head)
{
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	DWORD dwret;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	if (!pCardData || !head)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *) pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_S_SUCCESS;
	}
	cert_num = rv;
	for(ii = 0; ii < cert_num; ii++)   {
		struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) prkey_objs[ii]->data;
		if (cert_info->authority) {
			dwret = md_fs_add_file(pCardData, head, "msroots", EveryoneReadUserWriteAc, NULL, 0, NULL);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;
			return SCARD_S_SUCCESS;
		}
	}
	return SCARD_S_SUCCESS;
}

/*
 * Set the content of the 'soft' 'cmapfile':
 * 1. Initialize internal p15_contaniers with the existing private keys PKCS#15 objects;
 * 2. Try to read the content of the PKCS#15 'DATA' object 'CSP':'cmapfile',
 *		If some record from the 'DATA' object references an existing key:
 *    2a. Update the non-pkcs#15 attributes of the corresponding internal p15_container;
 *    2b. Change the index of internal p15_container according to the index from 'DATA' file.
 *	  Records from 'DATA' file are ignored is they do not have
 *		the corresponding PKCS#15 private key object.
 * 3. Initialize the content of the 'soft' 'cmapfile' from the internal p15-containers.
 */
static DWORD
md_set_cmapfile(PCARD_DATA pCardData, struct md_file *file)
{
	typedef enum { SCF_NONE,
		       SCF_NONDEFAULT_SIGN_PIN,
		       SCF_NONDEFAULT_OTHER_PIN,
		       SCF_NONDEFAULT_USER_PIN,
		       SCF_DEFAULT_SIGN_PIN,
		       SCF_DEFAULT_OTHER_PIN,
		       SCF_DEFAULT_USER_PIN
	} pin_mode_t;
	VENDOR_SPECIFIC *vs;
	PCONTAINER_MAP_RECORD p;
	unsigned char *cmap_buf = NULL;
	size_t cmap_len;
	DWORD dwret;
	int ii, rv, conts_num, found_default = 0;
	/* struct sc_pkcs15_data *data_object; */
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	pin_mode_t pin_mode = SCF_NONE;
	int pin_cont_idx = -1;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "set 'cmapfile'\n");
	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_get_pin_by_role(pCardData, ROLE_USER, &vs->pin_objs[ROLE_USER]);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return dwret;
	}

	dwret = md_get_pin_by_role(pCardData, MD_ROLE_USER_SIGN, &vs->pin_objs[MD_ROLE_USER_SIGN]);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "Cannot get Sign PIN object -- ignored");
		vs->pin_objs[MD_ROLE_USER_SIGN] = NULL;
	}

	dwret = md_get_pin_by_role(pCardData, ROLE_ADMIN, &vs->pin_objs[ROLE_ADMIN]);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "Cannot get Admin PIN object -- ignored");
		vs->pin_objs[ROLE_ADMIN] = NULL;
	}

	cmap_len = MD_MAX_KEY_CONTAINERS*sizeof(CONTAINER_MAP_RECORD);
	cmap_buf = pCardData->pfnCspAlloc(cmap_len);
	if(!cmap_buf)
		return SCARD_E_NO_MEMORY;
	memset(cmap_buf, 0, cmap_len);

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_PRKEY, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "Private key enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_F_UNKNOWN_ERROR;
	}

	conts_num = rv;
	logprintf(pCardData, 2, "Found %d private key(s) in the card.\n", conts_num);

	/* Initialize the P15 container array with the existing keys */
	for(ii = 0; ii < conts_num; ii++)   {
		struct sc_pkcs15_object *key_obj = prkey_objs[ii];
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
		struct md_pkcs15_container *cont = &vs->p15_containers[ii];

		if(key_obj->type != SC_PKCS15_TYPE_PRKEY_RSA && key_obj->type != SC_PKCS15_TYPE_PRKEY_EC)   {
			logprintf(pCardData, 7, "Non 'RSA' 'EC' key (type:%X) are ignored\n", key_obj->type);
			continue;
		}

		dwret = md_contguid_build_cont_guid_from_key(pCardData, key_obj, cont->guid);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;

		/* replace the OpenSC guid by a Windows Guid if needed
		Typically used in the certificate enrollment process.
		Windows create a new container with a Windows guid, close the context, then create a new context and look for the previous container.
		If we return our guid, it fails because the Windows guid can't be found.
		The overwrite is present to avoid this conversion been replaced by md_pkcs15_update_container_from_do*/
		// cont->guid_overwrite = md_contguid_find_conversion(pCardData, cont->guid);

		// cont->flags = CONTAINER_MAP_VALID_CONTAINER;
		dwret = md_cont_flags_from_key(pCardData, key_obj, &cont->flags);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;

		logprintf(pCardData, 7, "Container[%i] is '%.*s' guid=%.*s\n", ii,
			  (int) sizeof key_obj->label, key_obj->label,
			  (int) sizeof cont->guid, cont->guid);

		if (cont->flags & CONTAINER_MAP_VALID_CONTAINER &&
		    key_obj->auth_id.len > 0) {
			struct sc_pkcs15_object *keypin_obj;
			struct sc_pkcs15_auth_info *userpin_info =
				(struct sc_pkcs15_auth_info *)vs->pin_objs[ROLE_USER]->data;
			struct sc_pkcs15_auth_info *signpin_info =
				vs->pin_objs[MD_ROLE_USER_SIGN] ?
				(struct sc_pkcs15_auth_info *)vs->pin_objs[MD_ROLE_USER_SIGN]->data :
				NULL;
			struct sc_pkcs15_auth_info *adminpin_info =
				vs->pin_objs[ROLE_ADMIN] ?
				(struct sc_pkcs15_auth_info *)vs->pin_objs[ROLE_ADMIN]->data :
				NULL;

			if (sc_pkcs15_find_pin_by_auth_id(vs->p15card, &key_obj->auth_id, &keypin_obj))
				logprintf(pCardData, 2,
					  "Container[%i] has an unknown auth id, might not work properly\n",
					  ii);
			else {
				size_t pinidx;
				size_t pinidxempty = MD_MAX_PINS;
				for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
					struct sc_pkcs15_auth_info *pin_info;

					if (!vs->pin_objs[pinidx]) {
						if (pinidxempty >= MD_MAX_PINS)
							pinidxempty = pinidx;

						continue;
					}

					pin_info =
						(struct sc_pkcs15_auth_info *)vs->pin_objs[pinidx]->data;

					if (sc_pkcs15_compare_id(&key_obj->auth_id,
								 &pin_info->auth_id))
						break;
				}

				if (pinidx >= MD_MAX_PINS) {
					if (pinidxempty >= MD_MAX_PINS)
						logprintf(pCardData, 2,
							  "no free slot for container[%i] auth id, might not work properly\n",
							  ii);
					else
						vs->pin_objs[pinidxempty] = keypin_obj;
				}

				if (sc_pkcs15_compare_id(&key_obj->auth_id, &userpin_info->auth_id)) {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_USER_PIN : SCF_NONDEFAULT_USER_PIN;

					logprintf(pCardData, 7,
						  "Container[%i]%s is secured by User PIN\n",
						  ii,
						  cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						  " (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				} else if (signpin_info != NULL &&
					   sc_pkcs15_compare_id(&key_obj->auth_id, &signpin_info->auth_id)) {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_SIGN_PIN : SCF_NONDEFAULT_SIGN_PIN;

					logprintf(pCardData, 7,
						  "Container[%i]%s is secured by Sign PIN\n",
						  ii,
						  cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						  " (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				} else if (adminpin_info != NULL &&
					   sc_pkcs15_compare_id(&key_obj->auth_id, &adminpin_info->auth_id)) {
					logprintf(pCardData, 2,
						  "Container[%i] is secured by Admin PIN, might not work properly\n",
						  ii);
				} else {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_OTHER_PIN : SCF_NONDEFAULT_OTHER_PIN;

					logprintf(pCardData, 7,
						  "Container[%i]%s is secured by other PIN\n",
						  ii,
						  cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						  " (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				}
			}
		}

		if (cont->flags & CONTAINER_MAP_VALID_CONTAINER &&
		    cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER)
			found_default = 1;

		/* AT_KEYEXCHANGE is more general key usage,
		 *	it allows 'decryption' as well as 'signature' key usage.
		 * AT_SIGNATURE allows only 'signature' usage.
		 */
		cont->size_key_exchange = cont->size_sign = 0;
		if (key_obj->type == SC_PKCS15_TYPE_PRKEY_RSA) {
			if (prkey_info->usage & USAGE_ANY_DECIPHER)
				cont->size_key_exchange = prkey_info->modulus_length;
			else if (prkey_info->usage & USAGE_ANY_SIGN)
				cont->size_sign = prkey_info->modulus_length;
			else
				cont->size_key_exchange = prkey_info->modulus_length;
		} else if (key_obj->type == SC_PKCS15_TYPE_PRKEY_EC) {
			if (prkey_info->usage & USAGE_ANY_AGREEMENT)
				cont->size_key_exchange = prkey_info->field_length;
			else if (prkey_info->usage & USAGE_ANY_SIGN)
				cont->size_sign = prkey_info->field_length;
			else
				cont->size_key_exchange = prkey_info->field_length;
		}

		logprintf(pCardData, 7,
			  "Container[%i]'s key-exchange:%"SC_FORMAT_LEN_SIZE_T"u, sign:%"SC_FORMAT_LEN_SIZE_T"u\n",
			  ii, cont->size_key_exchange, cont->size_sign);

		cont->id = prkey_info->id;
		cont->prkey_obj = prkey_objs[ii];

		/* Try to find the friend objects: certificate and public key */
		if (!sc_pkcs15_find_cert_by_id(vs->p15card, &cont->id, &cont->cert_obj))
			logprintf(pCardData, 2, "found certificate friend '%.*s'\n", (int) sizeof cont->cert_obj->label, cont->cert_obj->label);

		if (!sc_pkcs15_find_pubkey_by_id(vs->p15card, &cont->id, &cont->pubkey_obj))
			logprintf(pCardData, 2, "found public key friend '%.*s'\n", (int) sizeof cont->pubkey_obj->label, cont->pubkey_obj->label);
	}

	if (conts_num)   {
		/* Read 'CMAPFILE' (Gemalto style) and update the attributes of P15 containers */
#if 0
		struct sc_pkcs15_object *dobjs[MD_MAX_KEY_CONTAINERS + 1], *default_cont = NULL;
		int num_dobjs = MD_MAX_KEY_CONTAINERS + 1;

		rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_DATA_OBJECT, dobjs, num_dobjs);
		if (rv < 0)   {
			logprintf(pCardData, 0, "'DATA' object enumeration failed: %s\n", sc_strerror(rv));
			return SCARD_F_UNKNOWN_ERROR;
		}

		num_dobjs = rv;
		logprintf(pCardData, 2, "Found %d 'DATA' objects.\n", num_dobjs);

		for (ii=0;ii<num_dobjs;ii++)   {
			struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)dobjs[ii]->data;

			if (strcmp(dinfo->app_label, "CSP"))
				continue;

			logprintf(pCardData, 2, "Found 'DATA' object '%.*s'\n", (int) sizeof dobjs[ii]->label, dobjs[ii]->label);
			if (!strncmp(dobjs[ii]->label, "Default Key Container", sizeof dobjs[ii]->label))   {
				default_cont = dobjs[ii];
				continue;
			}

			dwret = md_pkcs15_update_container_from_do(pCardData, dobjs[ii]);
			if (dwret != SCARD_S_SUCCESS)   {
				logprintf(pCardData, 2, "Cannot update container from DO: %li", dwret);
				return dwret;
			}
		}

		if (default_cont)   {
			dwret = md_pkcs15_default_container_from_do(pCardData, default_cont);
			if (dwret != SCARD_S_SUCCESS)   {
				logprintf(pCardData, 2, "Cannot set default container from DO: %li", dwret);
				return dwret;
			}
		}
#endif

		/* if no default container was found promote the best one (PIN-wise) to default */
		if (!found_default && (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
				       pin_mode == SCF_NONDEFAULT_OTHER_PIN ||
				       pin_mode == SCF_NONDEFAULT_USER_PIN)) {
			struct md_pkcs15_container *cont =
				&vs->p15_containers[pin_cont_idx];
			cont->flags |= CONTAINER_MAP_DEFAULT_CONTAINER;

			found_default = 1;

			logprintf(pCardData, 7,
				  "Container[%i] promoted to default\n",
				  pin_cont_idx);

			if (pin_mode == SCF_NONDEFAULT_SIGN_PIN)
				pin_mode = SCF_DEFAULT_SIGN_PIN;
			else if (pin_mode == SCF_NONDEFAULT_OTHER_PIN)
				pin_mode = SCF_DEFAULT_OTHER_PIN;
			else
				pin_mode = SCF_DEFAULT_USER_PIN;
		}

		/* if all containers use non-user PINs we need to make the best container PIN the user (primary) one */
		if (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
		    pin_mode == SCF_DEFAULT_SIGN_PIN ||
		    pin_mode == SCF_NONDEFAULT_OTHER_PIN ||
		    pin_mode == SCF_DEFAULT_OTHER_PIN) {
			struct sc_pkcs15_object *user_pin_old =
				vs->pin_objs[ROLE_USER];
			struct sc_pkcs15_object *user_pin_new =
				NULL;

			if (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
			    pin_mode == SCF_DEFAULT_SIGN_PIN) {
				user_pin_new = vs->pin_objs[MD_ROLE_USER_SIGN];
				vs->pin_objs[MD_ROLE_USER_SIGN] = NULL;

				logprintf(pCardData, 7,
					  "Sign PIN%s promoted to user one\n",
					  pin_mode == SCF_DEFAULT_SIGN_PIN ?
					  " (from default container)" : "");
			} else {
				struct sc_pkcs15_object *key_obj =
					vs->p15_containers[pin_cont_idx].prkey_obj;
				struct sc_pkcs15_object *keypin_obj;

				if (sc_pkcs15_find_pin_by_auth_id(vs->p15card, &key_obj->auth_id, &keypin_obj))
					logprintf(pCardData, 2,
					  "Cannot find container[%i] auth id again, might not work properly\n",
						  pin_cont_idx);
				else {
					size_t pinidx;

					logprintf(pCardData, 7,
						  "Container[%i]%s PIN will be made the user one\n",
						  pin_cont_idx,
						  pin_mode == SCF_DEFAULT_OTHER_PIN ?
						  " (default)" : "");

					for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
						struct sc_pkcs15_auth_info *pin_info;

						if (!vs->pin_objs[pinidx])
							continue;

						pin_info =
							(struct sc_pkcs15_auth_info *)vs->pin_objs[pinidx]->data;

						if (sc_pkcs15_compare_id(&key_obj->auth_id,
									 &pin_info->auth_id)) {
							vs->pin_objs[pinidx] = NULL;
							break;
						}
					}

					user_pin_new = keypin_obj;
				}
			}

			if (user_pin_new) {
				size_t pinidx;

				vs->pin_objs[ROLE_USER] = user_pin_new;

				for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
					if (vs->pin_objs[pinidx])
						continue;

					vs->pin_objs[pinidx] = user_pin_old;
					break;
				}

				if (pinidx >= MD_MAX_PINS) {
					logprintf(pCardData, 2,
						  "no free slot for previous User PIN, replacing last one\n");

					vs->pin_objs[MD_MAX_PINS - 1] = user_pin_old;
				}
			}
		}

		/* Initialize 'CMAPFILE' content from the P15 containers */
		p = (PCONTAINER_MAP_RECORD)cmap_buf;
		for (ii=0; ii<MD_MAX_KEY_CONTAINERS; ii++)   {
			if (!(vs->p15_containers[ii].flags & CONTAINER_MAP_VALID_CONTAINER))
				continue;

			if (!found_default)   {
				vs->p15_containers[ii].flags |= CONTAINER_MAP_DEFAULT_CONTAINER;
				found_default = 1;
			}

			mbstowcs((p+ii)->wszGuid, vs->p15_containers[ii].guid, MAX_CONTAINER_NAME_LEN + 1);
			(p+ii)->bFlags = vs->p15_containers[ii].flags;
			(p+ii)->wSigKeySizeBits = (WORD) vs->p15_containers[ii].size_sign;
			(p+ii)->wKeyExchangeKeySizeBits = (WORD) vs->p15_containers[ii].size_key_exchange;

			if (vs->p15_containers[ii].cert_obj)   {
				char k_name[6];

				if (vs->p15_containers[ii].size_key_exchange)   {
					snprintf(k_name, sizeof(k_name), "kxc%02i", ii);
					k_name[sizeof(k_name) - 1] = 0;
					dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
					if (dwret != SCARD_S_SUCCESS)
						return dwret;
				}

				if (vs->p15_containers[ii].size_sign)   {
					snprintf(k_name, sizeof(k_name), "ksc%02i", ii);
					k_name[sizeof(k_name) - 1] = 0;
					dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
					if (dwret != SCARD_S_SUCCESS)
						return dwret;
				}
			}

			logprintf(pCardData, 7, "cmapfile entry(%d) '%s' ",ii, vs->p15_containers[ii].guid);
			loghex(pCardData, 7, (PBYTE) (p+ii), sizeof(CONTAINER_MAP_RECORD));
		}
	}

	dwret = md_fs_add_msroots(pCardData, &(file->next));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_set_content(pCardData, file, cmap_buf, cmap_len);
	pCardData->pfnCspFree(cmap_buf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "cmap(%"SC_FORMAT_LEN_SIZE_T"u)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/*
 * Initialize internal 'soft' file system
 */
static DWORD
md_fs_init(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	struct md_file *cardid, *cardcf, *cardapps, *cmapfile;
	struct md_directory *mscp;

	if (!pCardData || !pCardData->pvVendorSpecific)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardid", EveryoneReadAdminWriteAc, NULL, 0, &cardid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardid(pCardData, cardid);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardcf", EveryoneReadUserWriteAc, NULL, 0, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cardcf(pCardData, cardcf);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardapps", EveryoneReadAdminWriteAc, NULL, 0, &cardapps);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cardapps(pCardData, cardapps);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_directory(pCardData, &(vs->root.subdirs), "mscp", UserCreateDeleteDirAc, &mscp);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(mscp->files), "cmapfile", EveryoneReadUserWriteAc, NULL, 0, &cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cmapfile(pCardData, cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

#ifdef OPENSSL_VERSION_NUMBER
	logprintf(pCardData, 3,
		  "MD virtual file system initialized; OPENSSL_VERSION_NUMBER 0x%lX\n",
		  OPENSSL_VERSION_NUMBER);
#else
	logprintf(pCardData, 3,
		  "MD virtual file system initialized; Without OPENSSL\n");
#endif
	return SCARD_S_SUCCESS;

ret_cleanup:
	md_fs_finalize(pCardData);
	return dwret;
}

/* Create SC context */
static DWORD
md_create_context(PCARD_DATA pCardData, VENDOR_SPECIFIC *vs)
{
	sc_context_param_t ctx_param;
	int r;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 3, "create sc ccontext\n");
	vs->ctx = NULL;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 1;
	ctx_param.app_name = "cardmod";

	r = sc_context_create(&(vs->ctx), &ctx_param);
	if (r)   {
		logprintf(pCardData, 0, "Failed to establish context: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	logprintf(pCardData, 3, "sc context created\n");
	return SCARD_S_SUCCESS;
}

static DWORD
md_card_capabilities(PCARD_DATA pCardData, PCARD_CAPABILITIES  pCardCapabilities)
{
	if (!pCardCapabilities)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = TRUE;
	/* a read only card cannot generate new keys */
	pCardCapabilities->fKeyGen = ! md_is_read_only(pCardData);

	return SCARD_S_SUCCESS;
}

static DWORD
md_free_space(PCARD_DATA pCardData, PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	int count, idx;

	if (!pCardData || !pCardFreeSpaceInfo)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardFreeSpaceInfo->dwVersion > CARD_FREE_SPACE_INFO_CURRENT_VERSION )
		return ERROR_REVISION_MISMATCH;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	/* Count free containers */
	for (idx=0, count=0; idx<MD_MAX_KEY_CONTAINERS; idx++)
		if (!vs->p15_containers[idx].prkey_obj)
			count++;

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = CARD_DATA_VALUE_UNKNOWN;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = count;
	pCardFreeSpaceInfo->dwMaxKeyContainers = MD_MAX_KEY_CONTAINERS;

	return SCARD_S_SUCCESS;
}

/* Check the new key to be created for the compatibility with card:
 * - for the key to be generated the card needs to support the mechanism and size;
 * - for the key to be imported checked also the validity of supplied key blob.
 */
static DWORD
md_check_key_compatibility(PCARD_DATA pCardData, DWORD flags, DWORD key_type,
		DWORD key_size, BYTE *pbKeyData)
{
	VENDOR_SPECIFIC *vs;
	struct sc_algorithm_info *algo_info;
	unsigned int count, key_algo;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	switch(key_type) {
		case AT_SIGNATURE:
		case AT_KEYEXCHANGE:
			key_algo = SC_ALGORITHM_RSA;
			break;
		case AT_ECDHE_P256 :
		case AT_ECDHE_P384 :
		case AT_ECDHE_P521 :
		case AT_ECDSA_P256 :
		case AT_ECDSA_P384 :
		case AT_ECDSA_P521 :
			key_algo = SC_ALGORITHM_EC;
			break;
		default:
			logprintf(pCardData, 3, "Unsupported key type: 0x%lX\n",
				  (unsigned long)key_type);
			return SCARD_E_UNSUPPORTED_FEATURE;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (flags & CARD_CREATE_CONTAINER_KEY_IMPORT)   {
		if (key_algo == SC_ALGORITHM_RSA) {
			PUBLICKEYSTRUC *pub_struc = (PUBLICKEYSTRUC *)pbKeyData;
			RSAPUBKEY *pub_rsa = (RSAPUBKEY *)(pbKeyData + sizeof(PUBLICKEYSTRUC));

			if (!pub_struc)   {
				logprintf(pCardData, 3, "No data for the key import operation\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if (pub_struc->bType != PRIVATEKEYBLOB)   {
				logprintf(pCardData, 3, "Invalid blob data for the key import operation\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if ((key_type == AT_KEYEXCHANGE) && (pub_struc->aiKeyAlg != CALG_RSA_KEYX))   {
				logprintf(pCardData, 3, "Expected KEYEXCHANGE type of blob\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if ((key_type == AT_SIGNATURE) && (pub_struc->aiKeyAlg != CALG_RSA_SIGN))   {
				logprintf(pCardData, 3, "Expected KEYSIGN type of blob\n");
				return SCARD_E_INVALID_PARAMETER;
			}

			if (pub_rsa->magic == BCRYPT_RSAPUBLIC_MAGIC || pub_rsa->magic == BCRYPT_RSAPRIVATE_MAGIC)   {
				key_size = pub_rsa->bitlen;
			}
			else {
				logprintf(pCardData, 3, "'Magic' control failed\n");
				return SCARD_E_INVALID_PARAMETER;
			}

			logprintf(pCardData, 3, "Set key size to %lu\n",
				  (unsigned long)key_size);
		} else if (key_algo == SC_ALGORITHM_EC) {
			BCRYPT_ECCKEY_BLOB *pub_ecc = (BCRYPT_ECCKEY_BLOB *)pbKeyData;
			switch(key_type) {
				case AT_ECDSA_P256:
					if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDSA_P256 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 256;
					break;
				case AT_ECDSA_P384:
					if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P384_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDSA_P384 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 384;
					break;
				case AT_ECDSA_P521:
					if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P521_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDSA_P521 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 521;
					break;
				case AT_ECDHE_P256:
					if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P256_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDHE_P256 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 256;
					break;
				case AT_ECDHE_P384:
					if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P384_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDHE_P384 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 384;
					break;
				case AT_ECDHE_P521:
					if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P521_MAGIC) {
						logprintf(pCardData, 3, "Expected AT_ECDHE_P521 magic\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					key_size = 521;
					break;
			}
		}
		logprintf(pCardData, 3, "Set key size to %lu\n",
			  (unsigned long)key_size);
	}

	count = vs->p15card->card->algorithm_count;
	for (algo_info = vs->p15card->card->algorithms; count--; algo_info++) {
		if (algo_info->algorithm != key_algo || algo_info->key_length != key_size)
			continue;
		logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
		return SCARD_S_SUCCESS;
	}

	logprintf(pCardData, 3,
		  "No card support for key(type:0x%lX,size:0x%lX)\n",
		  (unsigned long)key_type, (unsigned long)key_size);
	return SCARD_E_UNSUPPORTED_FEATURE;
}


static DWORD
md_pkcs15_generate_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, DWORD key_size, PIN_ID PinId)
{
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	struct sc_app_info *app_info = NULL;
	struct sc_pkcs15init_keygen_args keygen_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	struct md_pkcs15_container *cont = NULL;
	int rv;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	CHAR szGuid[MAX_CONTAINER_NAME_LEN +1] = "Default key label";

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (PinId >= MD_MAX_PINS || !vs->pin_objs[PinId])
		return SCARD_E_INVALID_PARAMETER;

	card = vs->p15card->card;

	memset(&pub_args, 0, sizeof(pub_args));
	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.prkey_args.label = szGuid;
	keygen_args.pubkey_label = szGuid;

	if (key_type == AT_SIGNATURE)   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if (key_type == AT_KEYEXCHANGE)   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
	}
	else if ((key_type == AT_ECDSA_P256) || (key_type == AT_ECDSA_P384) || (key_type == AT_ECDSA_P521))   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_EC;
		pub_args.key.algorithm = SC_ALGORITHM_EC;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if ((key_type == AT_ECDHE_P256) || (key_type == AT_ECDHE_P384) || (key_type == AT_ECDHE_P521))   {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_EC;
		pub_args.key.algorithm = SC_ALGORITHM_EC;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE_ECC;
	}
	else    {
		logprintf(pCardData, 3,
			  "MdGenerateKey(): unsupported key type: 0x%lX\n",
			  (unsigned long)key_type);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	if (pub_args.key.algorithm == SC_ALGORITHM_EC) {
		keygen_args.prkey_args.key.u.ec.params.field_length = key_size;
		if ((key_type == AT_ECDSA_P256)|| (key_type == AT_ECDHE_P256)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp256r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 10;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
		} else if ((key_type == AT_ECDSA_P384)|| (key_type == AT_ECDHE_P384)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp384r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 7;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x05\x2B\x81\x04\x00\x22";
		} else if ((key_type == AT_ECDSA_P521)|| (key_type == AT_ECDHE_P521)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp521r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 7;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x05\x2B\x81\x04\x00\x23";
		}
	}

	keygen_args.prkey_args.access_flags = MD_KEY_ACCESS;

	pin_obj = vs->pin_objs[PinId];
	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	keygen_args.prkey_args.auth_id = pub_args.auth_id = auth_info->auth_id;

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);
	cont = &(vs->p15_containers[idx]);

	/* use the Windows Guid as input to determine some characteristics of the key such as the label or the id */
	md_contguid_build_key_args_from_cont_guid(pCardData, cont->guid, &(keygen_args.prkey_args));

	if (keygen_args.prkey_args.label == NULL) {
		md_generate_guid(szGuid);
		keygen_args.prkey_args.label = szGuid;
	}
	keygen_args.pubkey_label = keygen_args.prkey_args.label;

	rv = sc_pkcs15init_generate_key(vs->p15card, profile, &keygen_args, key_size, &cont->prkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdGenerateKey(): key generation failed: sc-error %i\n", rv);
		goto done;
	}

	dwret = md_contguid_add_conversion(pCardData, cont->prkey_obj, cont->guid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags = CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3,
		  "MdGenerateKey(): generated key(idx:%lu,id:%s,guid:%.*s)\n",
		  (unsigned long)idx, sc_pkcs15_print_id(&cont->id),
		  (int) sizeof cont->guid, cont->guid);

done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}

static DWORD
md_pkcs15_store_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, BYTE *blob, DWORD blob_size, PIN_ID PinId)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_app_info *app_info = NULL;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15init_prkeyargs prkey_args;
	struct sc_pkcs15init_pubkeyargs pubkey_args;
	BYTE *ptr = blob;
	EVP_PKEY *pkey=NULL;
	int rv;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	CHAR szGuid[MAX_CONTAINER_NAME_LEN +1] = "Default key label";

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (PinId >= MD_MAX_PINS || !vs->pin_objs[PinId])
		return SCARD_E_INVALID_PARAMETER;

	card = vs->p15card->card;

	pkey = b2i_PrivateKey((const unsigned char **)&ptr, blob_size);
	if (!pkey)   {
		logprintf(pCardData, 1, "MdStoreKey() MSBLOB key parse error");
		return SCARD_E_INVALID_PARAMETER;
	}

	memset(&prkey_args, 0, sizeof(prkey_args));
	rv = sc_pkcs15_convert_prkey(&prkey_args.key, pkey);
	if (rv)   {
		logprintf(pCardData, 1, "MdStoreKey() cannot convert private key");
		return SCARD_E_INVALID_PARAMETER;
	}

	memset(&pubkey_args, 0, sizeof(pubkey_args));
	rv = sc_pkcs15_convert_pubkey(&pubkey_args.key, pkey);
	if (rv)   {
		logprintf(pCardData, 1, "MdStoreKey() cannot convert public key");
		return SCARD_E_INVALID_PARAMETER;
	}

	if (key_type == AT_SIGNATURE)   {
		prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
		pubkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if (key_type == AT_KEYEXCHANGE)   {
		prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
		pubkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
	}
	else    {
		logprintf(pCardData, 3,
			  "MdStoreKey(): unsupported key type: 0x%lX\n",
			  (unsigned long)key_type);
		return SCARD_E_INVALID_PARAMETER;
	}

	prkey_args.access_flags = MD_KEY_ACCESS;

	pin_obj = vs->pin_objs[PinId];
	prkey_args.auth_id = ((struct sc_pkcs15_auth_info *) pin_obj->data)->auth_id;

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdStoreKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreKey(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreKey(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);
	cont = &(vs->p15_containers[idx]);

	prkey_args.label = szGuid;
	/* use the Windows Guid as input to determine some characteristics of the key such as the label or the id */
	md_contguid_build_key_args_from_cont_guid(pCardData, cont->guid, &prkey_args);

	memcpy(pubkey_args.id.value, prkey_args.id.value, prkey_args.id.len);
	pubkey_args.id.len = prkey_args.id.len;
	pubkey_args.label = prkey_args.label;

	if (prkey_args.label == szGuid) {
		md_generate_guid(szGuid);
	}
	pubkey_args.label = prkey_args.label;

	rv = sc_pkcs15init_store_private_key(vs->p15card, profile, &prkey_args, &cont->prkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreKey(): private key store failed: sc-error %i\n", rv);
		goto done;
	}

	rv = sc_pkcs15init_store_public_key(vs->p15card, profile, &pubkey_args, &cont->pubkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreKey(): public key store failed: sc-error %i\n", rv);
		goto done;
	}

	dwret = md_contguid_add_conversion(pCardData, cont->prkey_obj, cont->guid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags |= CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3,
		  "MdStoreKey(): stored key(idx:%lu,id:%s,guid:%.*s)\n",
		  (unsigned long)idx, sc_pkcs15_print_id(&cont->id),
		  (int) sizeof cont->guid, cont->guid);

done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
#else
	logprintf(pCardData, 1, "MD store key not supported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
#endif
}


static DWORD
md_pkcs15_store_certificate(PCARD_DATA pCardData, char *file_name, unsigned char *blob, size_t len)
{
	VENDOR_SPECIFIC *vs;
	struct md_pkcs15_container *cont = NULL;
	struct sc_card *card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_app_info *app_info = NULL;
	struct sc_pkcs15_object *cert_obj;
	struct sc_pkcs15init_certargs args;
	int rv, idx;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "MdStoreCert(): store certificate '%s'\n", file_name);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	card = vs->p15card->card;

	memset(&args, 0, sizeof(args));
	args.der_encoded.value = blob;
	args.der_encoded.len = len;
	args.update = 1;

	/* use container's ID as ID of certificate to store */
	idx = -1;
	if(sscanf(file_name, "ksc%d", &idx) > 0) {
	} else if(sscanf(file_name, "kxc%d", &idx) > 0) {
	}

	if (idx >= 0 && idx < MD_MAX_KEY_CONTAINERS)   {
		cont = &(vs->p15_containers[idx]);
		args.id = cont->id;
		logprintf(pCardData, 3, "MdStoreCert(): store certificate(idx:%i,id:%s)\n", idx, sc_pkcs15_print_id(&cont->id));
	}

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdStoreCert(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, vs->p15card);

	rv = sc_pkcs15init_store_certificate(vs->p15card, profile, &args, &cert_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot store certificate: sc-error %i\n", rv);
		goto done;
	}

	dwret = SCARD_S_SUCCESS;
done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}

static DWORD
md_query_key_sizes(PCARD_DATA pCardData, DWORD dwKeySpec, CARD_KEY_SIZES *pKeySizes)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct sc_algorithm_info* algo_info;
	int count = 0, i, keysize = 0, flag;
	if (!pKeySizes)
		return SCARD_E_INVALID_PARAMETER;

	if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION && pKeySizes->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	logprintf(pCardData, 1, "md_query_key_sizes: store dwKeySpec '%lu'\n",
		  (unsigned long)dwKeySpec);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	count = vs->p15card->card->algorithm_count;

	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwMinimumBitlen = 0;
	pKeySizes->dwDefaultBitlen = 0;
	pKeySizes->dwMaximumBitlen = 0;
	pKeySizes->dwIncrementalBitlen = 0;

	/* dwKeySpec=0 is a special value when the key size is queried without specifying the algorithm.
	Used on old minidriver version. In this case, it is RSA */
	if ((dwKeySpec == 0) || (dwKeySpec == AT_KEYEXCHANGE) || (dwKeySpec == AT_SIGNATURE)) {
		for (i = 0; i < count; i++) {
			algo_info = vs->p15card->card->algorithms + i;
			if (algo_info->algorithm == SC_ALGORITHM_RSA) {
				if (pKeySizes->dwMinimumBitlen == 0 || pKeySizes->dwMinimumBitlen > algo_info->key_length) {
					pKeySizes->dwMinimumBitlen = algo_info->key_length;
				}
				if (pKeySizes->dwMaximumBitlen == 0 || pKeySizes->dwMaximumBitlen < algo_info->key_length) {
					pKeySizes->dwMaximumBitlen = algo_info->key_length;
				}
				if (algo_info->key_length == 2048) {
					pKeySizes->dwDefaultBitlen = algo_info->key_length;
				}
				if (algo_info->key_length == 1536) {
					pKeySizes->dwIncrementalBitlen = 512;
				}
			}
		}
		if (pKeySizes->dwMinimumBitlen == 0) {
			logprintf(pCardData, 0, "No RSA key found\n");
			return SCARD_E_INVALID_PARAMETER;
		}
		if (pKeySizes->dwDefaultBitlen == 0) {
			logprintf(pCardData, 3, "No 2048 key found\n");
			pKeySizes->dwDefaultBitlen  = pKeySizes->dwMaximumBitlen;
		}
		if (pKeySizes->dwIncrementalBitlen == 0) {
			pKeySizes->dwIncrementalBitlen = 1024;
		}
	} else {
		keysize = 0;
		for (i = 0; i < count; i++) {
			algo_info = vs->p15card->card->algorithms + i;
			if (algo_info->algorithm == SC_ALGORITHM_EC) {
				flag = SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_EXT_EC_NAMEDCURVE;
				/* ECDHE */
				if ((dwKeySpec == AT_ECDHE_P256) && (algo_info->key_length == 256) && (algo_info->flags & flag)) {
					keysize = 256;
					break;
				}
				if ((dwKeySpec == AT_ECDHE_P384) && (algo_info->key_length == 384) && (algo_info->flags & flag)) {
					keysize = 384;
					break;
				}
				if ((dwKeySpec == AT_ECDHE_P521) && (algo_info->key_length == 521) && (algo_info->flags & flag)) {
					keysize = 521;
					break;
				}
				/* ECDSA */
				flag = SC_ALGORITHM_ECDSA_HASH_NONE|
						SC_ALGORITHM_ECDSA_HASH_SHA1|
						SC_ALGORITHM_ECDSA_HASH_SHA224|
						SC_ALGORITHM_ECDSA_HASH_SHA256|
						SC_ALGORITHM_EXT_EC_NAMEDCURVE;
				if ((dwKeySpec == AT_ECDSA_P256) && (algo_info->key_length == 256) && (algo_info->flags & flag)) {
					keysize = 256;
					break;
				}
				if ((dwKeySpec == AT_ECDSA_P384) && (algo_info->key_length == 384) && (algo_info->flags & flag)) {
					keysize = 384;
					break;
				}
				if ((dwKeySpec == AT_ECDSA_P521) && (algo_info->key_length == 521) && (algo_info->flags & flag)) {
					keysize = 521;
					break;
				}
			}
			if (keysize) {
				pKeySizes->dwMinimumBitlen = keysize;
				pKeySizes->dwDefaultBitlen = keysize;
				pKeySizes->dwMaximumBitlen = keysize;
				pKeySizes->dwIncrementalBitlen = 1;
			} else {
				logprintf(pCardData, 0,
					  "No ECC key found (keyspec=%lu)\n",
					  (unsigned long)dwKeySpec);
				return SCARD_E_INVALID_PARAMETER;
			}
		}
	}

	logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
	logprintf(pCardData, 3, " dwMinimumBitlen: %lu\n",
		  (unsigned long)pKeySizes->dwMinimumBitlen);
	logprintf(pCardData, 3, " dwDefaultBitlen: %lu\n",
		  (unsigned long)pKeySizes->dwDefaultBitlen);
	logprintf(pCardData, 3, " dwMaximumBitlen: %lu\n",
		  (unsigned long)pKeySizes->dwMaximumBitlen);
	logprintf(pCardData, 3, " dwIncrementalBitlen: %lu\n",
		  (unsigned long)pKeySizes->dwIncrementalBitlen);
	return SCARD_S_SUCCESS;
}

static DWORD WINAPI
md_dialog_perform_pin_operation_thread(PVOID lpParameter)
{
	/* unstack the parameters */
	LONG_PTR* parameter = (LONG_PTR*) lpParameter;
	int operation = (int) parameter[0];
	struct sc_pkcs15_card *p15card = (struct sc_pkcs15_card *) parameter[1];
	struct sc_pkcs15_object *pin_obj = (struct sc_pkcs15_object *) parameter[2];
	const u8 *pin1 = (const u8 *) parameter[3];
	size_t pin1len = parameter[4];
	const u8 *pin2 = (const u8 *) parameter[5];
	size_t *pin2len = (size_t *) parameter[6];
	int rv = 0;
	switch (operation)
	{
	case SC_PIN_CMD_VERIFY:
		rv = sc_pkcs15_verify_pin(p15card, pin_obj, pin1, pin1len);
		break;
	case SC_PIN_CMD_GET_SESSION_PIN:
		rv = sc_pkcs15_verify_pin_with_session_pin(p15card, pin_obj, pin1, pin1len, pin2, pin2len);
		break;
	case SC_PIN_CMD_CHANGE:
		rv = sc_pkcs15_change_pin(p15card, pin_obj, pin1, pin1len,pin2, pin2len ? *pin2len : 0);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = sc_pkcs15_unblock_pin(p15card, pin_obj, pin1, pin1len,pin2, pin2len ? *pin2len : 0);
		break;
	default:
		rv = (DWORD) ERROR_INVALID_PARAMETER;
		break;
	}
	if (parameter[10] != 0) {
		EndDialog((HWND) parameter[10], rv);
	}
	return (DWORD) rv;
}

static const char *md_get_ui_str(PCARD_DATA pCardData, enum ui_str id)
{
	const char *str = md_get_config_str(pCardData, id);

	if (str && *str == '\0') {
		/* if the user used an empty string, remove the field by setting it to NULL */
		str = NULL;
	}

	return str;
}

static HRESULT CALLBACK md_dialog_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam, LONG_PTR dwRefData)
{
	LONG_PTR param;

	UNREFERENCED_PARAMETER(lParam);
	switch (message) {
		case TDN_CREATED:
			{
				PCARD_DATA pCardData = (PCARD_DATA)((LONG_PTR*)dwRefData)[7];
				DWORD now = timeGetTime();

				/* remove the icon from the window title */
				SendMessage(hWnd, WM_SETICON, (LPARAM) ICON_BIG, (LONG_PTR) NULL);
				SendMessage(hWnd, WM_SETICON, (LPARAM) ICON_SMALL, (LONG_PTR) NULL);

				/* store parameter like pCardData for further use if needed */
				((LONG_PTR*)dwRefData)[11] = (LONG_PTR) now;
				SetWindowLongPtr(hWnd, GWLP_USERDATA, dwRefData);
				((LONG_PTR*)dwRefData)[10] = (LONG_PTR) hWnd;

				if (!md_is_pinpad_dlg_enable_cancel(pCardData)) {
					int timeout = md_get_pinpad_dlg_timeout(pCardData);
					if (timeout > 0) {
						SendMessage(hWnd, TDM_SET_PROGRESS_BAR_RANGE, 0, MAKELPARAM(0, timeout*1000));
					}

					/* disable "Close" */
					SendMessage(hWnd, TDM_ENABLE_BUTTON, IDCLOSE, 0);

					/* launch the function in another thread context store the thread handle */
					((LONG_PTR*)dwRefData)[9] = (LONG_PTR) CreateThread(NULL, 0, md_dialog_perform_pin_operation_thread, (LPVOID) dwRefData, 0, NULL);
				} else {
					int timeout = md_get_pinpad_dlg_timeout(pCardData);
					if (timeout > 0) {
						SendMessage(hWnd, TDM_SET_PROGRESS_BAR_RANGE, 0, 0);
						SendMessage(hWnd, TDM_SET_PROGRESS_BAR_STATE, PBST_PAUSED, 0);
					}
				}
			}
			return S_OK;

		case TDN_TIMER:
			SendMessage(hWnd, TDM_SET_PROGRESS_BAR_POS, wParam, 0L);
			return S_OK;

		case TDN_BUTTON_CLICKED:
			switch(LOWORD(wParam)) {
				case IDCANCEL:
					DestroyWindow(hWnd);
					break;

				case IDOK:
					param = GetWindowLongPtr(hWnd, GWLP_USERDATA);
					if (param) {
						PCARD_DATA pCardData = (PCARD_DATA)((LONG_PTR*)param)[7];
						VENDOR_SPECIFIC* vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;

						int timeout = md_get_pinpad_dlg_timeout(pCardData);
						if (timeout > 0) {
							DWORD start = (DWORD)((LONG_PTR*)dwRefData)[11];
							DWORD delta = timeGetTime() - start;
							SendMessage(hWnd, TDM_SET_PROGRESS_BAR_RANGE, 0, MAKELPARAM(delta, delta + timeout*1000));
							SendMessage(hWnd, TDM_SET_PROGRESS_BAR_STATE, PBST_NORMAL, 0);
						}

						/* disable "OK" and "Cancel" */
						SendMessage(hWnd, TDM_ENABLE_BUTTON, IDOK, 0);
						SendMessage(hWnd, TDM_ENABLE_BUTTON, IDCANCEL, 0);

						/* disable "x" */
						HMENU menu = GetSystemMenu(hWnd, FALSE);
						if (menu) {
							EnableMenuItem(menu, SC_CLOSE, MF_BYCOMMAND | MF_GRAYED);
						}

						/* launch the function in another thread context store the thread handle */
						((LONG_PTR*)dwRefData)[9] = (LONG_PTR) CreateThread(NULL, 0, md_dialog_perform_pin_operation_thread, (LPVOID) dwRefData, 0, NULL);
					}
					break;

				default:
					return S_FALSE;
			}
			break;

		case TDN_DESTROYED:
			/* clean resources used */
			param = GetWindowLongPtr(hWnd, GWLP_USERDATA);
			if (param) {
				HANDLE hThread = (HANDLE)((LONG_PTR*)param)[9];
				CloseHandle(hThread);
			}
			break;
	}

	/* don't close the Task Dialog */
	return S_FALSE;
}



static int 
md_dialog_perform_pin_operation(PCARD_DATA pCardData, int operation, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *pin_obj,
		const u8 *pin1, size_t pin1len,
		const u8 *pin2, size_t *pin2len, BOOL displayUI, DWORD role)
{
	LONG_PTR parameter[12];
	INT_PTR result = 0;
	HWND hWndDlg = 0;
	TASKDIALOGCONFIG tc = {0};
	int rv = 0;
	BOOL checked, user_checked;
	VENDOR_SPECIFIC* pv = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	/* stack the parameters */
	parameter[0] = (LONG_PTR)operation;
	parameter[1] = (LONG_PTR)p15card;
	parameter[2] = (LONG_PTR)pin_obj;
	parameter[3] = (LONG_PTR)pin1;
	parameter[4] = (LONG_PTR)pin1len;
	parameter[5] = (LONG_PTR)pin2;
	parameter[6] = (LONG_PTR)pin2len;
	parameter[7] = (LONG_PTR)pCardData;
	parameter[8] = (LONG_PTR)role;
	parameter[9] = 0; /* place holder for thread handle */
	parameter[10] = 0; /* place holder for window handle */
	parameter[11] = 0; /* place holder for end of timer */

	/* launch the function to perform in the same thread context */
	if (!displayUI) {
		rv = md_dialog_perform_pin_operation_thread(parameter);
		SecureZeroMemory(parameter, sizeof(parameter));
		return rv;
	}

	/* launch the UI in the same thread context than the parent and the function to perform in another thread context 
	this is the only way to display a modal dialog attached to a parent (hwndParent != 0) */
	tc.hwndParent = pv->hwndParent;
	tc.hInstance = g_inst;

	tc.pszWindowTitle = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_TITLE));
	tc.pszMainInstruction = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_MAIN));
	tc.pszExpandedControlText = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_CONTROL_EXPANDED));
	tc.pszCollapsedControlText = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_CONTROL_COLLAPSED));
	tc.pszExpandedInformation = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_EXPANDED));
	tc.pszVerificationText = wchar_from_char_str(md_get_ui_str(pCardData,
			MD_PINPAD_DLG_VERIFICATION));
	switch (role) {
		case ROLE_ADMIN:
			tc.pszContent = wchar_from_char_str(md_get_ui_str(pCardData,
					MD_PINPAD_DLG_CONTENT_ADMIN));
			break;
		case MD_ROLE_USER_SIGN:
			tc.pszContent = wchar_from_char_str(md_get_ui_str(pCardData,
					MD_PINPAD_DLG_CONTENT_USER_SIGN));
			break;
		case ROLE_USER:
		default:
			tc.pszContent = wchar_from_char_str(md_get_ui_str(pCardData,
					MD_PINPAD_DLG_CONTENT_USER));
			break;
	}

	if (pv->wszPinContext) {
		/* overwrite the main instruction with the application's information if
		 * possible */
		tc.pszMainInstruction = pv->wszPinContext;
	}

	tc.dwFlags = TDF_POSITION_RELATIVE_TO_WINDOW;
	if (tc.pszExpandedInformation != NULL) {
		tc.dwFlags |= TDF_EXPAND_FOOTER_AREA;
	}
	if (md_get_pinpad_dlg_timeout(pCardData) > 0) {
		tc.dwFlags |= TDF_SHOW_PROGRESS_BAR | TDF_CALLBACK_TIMER;
	}
	
	checked = !md_is_pinpad_dlg_enable_cancel(pCardData);
	if (checked) {
		tc.dwFlags |= TDF_VERIFICATION_FLAG_CHECKED;
		/* can't use TDCBF_CANCEL_BUTTON since this would implicitly set TDF_ALLOW_DIALOG_CANCELLATION */
		tc.dwCommonButtons = TDCBF_CLOSE_BUTTON;
	} else {
		tc.dwFlags |= TDF_ALLOW_DIALOG_CANCELLATION;
		tc.dwCommonButtons = TDCBF_CANCEL_BUTTON | TDCBF_OK_BUTTON;
	}

	tc.hMainIcon = md_get_pinpad_dlg_icon(pCardData);
	if (tc.hMainIcon) {
		tc.dwFlags |= TDF_USE_HICON_MAIN;
	} else {
		tc.pszMainIcon = MAKEINTRESOURCEW(IDI_SMARTCARD);
	}
	tc.pfCallback = md_dialog_proc;
	tc.lpCallbackData = (LONG_PTR)parameter;
	tc.cbSize = sizeof(tc);

	result = TaskDialogIndirect(&tc, NULL, NULL, &user_checked);

	if (user_checked != checked) {
		TCHAR path[MAX_PATH]={0};
		if (GetModuleFileName(NULL, path, ARRAYSIZE(path))) {
			HKEY hKey;
			LSTATUS lstatus = RegOpenKeyExA(HKEY_CURRENT_USER,
					SUBKEY_ENABLE_CANCEL, 0, KEY_WRITE, &hKey);
			if (ERROR_SUCCESS != lstatus) {
				lstatus = RegCreateKeyExA(HKEY_CURRENT_USER,
						SUBKEY_ENABLE_CANCEL, 0, NULL, REG_OPTION_NON_VOLATILE,
						KEY_WRITE, NULL, &hKey, NULL);
			}
			if (ERROR_SUCCESS == lstatus) {
				DWORD enable_cancel = 0;
				if (user_checked == FALSE) {
					enable_cancel = 1;
				}
				lstatus = RegSetValueEx(hKey, path, 0, REG_DWORD,
						(const BYTE*)&enable_cancel, sizeof(enable_cancel));
				RegCloseKey(hKey);
			}
		}
	}

	LocalFree((WCHAR *) tc.pszWindowTitle);
	LocalFree((WCHAR *) tc.pszMainInstruction);
	LocalFree((WCHAR *) tc.pszExpandedControlText);
	LocalFree((WCHAR *) tc.pszCollapsedControlText);
	LocalFree((WCHAR *) tc.pszExpandedInformation);
	LocalFree((WCHAR *) tc.pszContent);

	SecureZeroMemory(parameter, sizeof(parameter));

	return (int) result;
}

static DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror,
						  DWORD dwDefaulCode)
{
	switch(OpenSCerror)
	{
		/* Errors related to reader operation */
		case SC_ERROR_READER:
			return SCARD_E_PROTO_MISMATCH;
		case SC_ERROR_NO_READERS_FOUND:
			return SCARD_E_NO_READERS_AVAILABLE;
		case SC_ERROR_CARD_NOT_PRESENT:
			return SCARD_E_NO_SMARTCARD;
		case SC_ERROR_TRANSMIT_FAILED:
			return SCARD_E_NOT_TRANSACTED;
		case SC_ERROR_CARD_REMOVED:
			return SCARD_W_REMOVED_CARD;
		case SC_ERROR_CARD_RESET:
			return SCARD_W_RESET_CARD;
		case SC_ERROR_KEYPAD_CANCELLED:
			return SCARD_W_CANCELLED_BY_USER;
		case SC_ERROR_KEYPAD_MSG_TOO_LONG:
			return SCARD_W_CARD_NOT_AUTHENTICATED;
		case SC_ERROR_KEYPAD_PIN_MISMATCH:
			return SCARD_E_INVALID_CHV;
		case SC_ERROR_KEYPAD_TIMEOUT:
			return ERROR_TIMEOUT;
		case SC_ERROR_EVENT_TIMEOUT:
			return SCARD_E_TIMEOUT;
		case SC_ERROR_CARD_UNRESPONSIVE:
			return SCARD_W_UNRESPONSIVE_CARD;
		case SC_ERROR_READER_LOCKED:
			return SCARD_E_SHARING_VIOLATION;

		/* Resulting from a card command or related to the card*/
		case SC_ERROR_INCORRECT_PARAMETERS:
			return SCARD_E_INVALID_PARAMETER;
		case SC_ERROR_MEMORY_FAILURE:
		case SC_ERROR_NOT_ENOUGH_MEMORY:
			return SCARD_E_NO_MEMORY;
		case SC_ERROR_NOT_ALLOWED:
			return SCARD_W_SECURITY_VIOLATION;
		case SC_ERROR_AUTH_METHOD_BLOCKED:
			return SCARD_W_CHV_BLOCKED;
		case SC_ERROR_PIN_CODE_INCORRECT:
			return SCARD_W_WRONG_CHV;

		/* Returned by OpenSC library when called with invalid arguments */
		case SC_ERROR_INVALID_ARGUMENTS:
			return ERROR_INVALID_PARAMETER;
		case SC_ERROR_BUFFER_TOO_SMALL:
			return NTE_BUFFER_TOO_SMALL;

		/* Resulting from OpenSC internal operation */
		case SC_ERROR_INTERNAL:
			return ERROR_INTERNAL_ERROR;
		case SC_ERROR_NOT_SUPPORTED:
			return SCARD_E_UNSUPPORTED_FEATURE;
		case SC_ERROR_NOT_IMPLEMENTED:
			return ERROR_CALL_NOT_IMPLEMENTED;

		default:
			return dwDefaulCode;
	}
}

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	VENDOR_SPECIFIC *vs = NULL;
	CRITICAL_SECTION hScard_lock;

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1,
		  "\nP:%lu T:%lu pCardData:%p hScard=0x%08X hSCardCtx=0x%08X CardDeleteContext\n",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData,
		  (unsigned int)pCardData->hScard,
		  (unsigned int)pCardData->hSCardCtx);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	hScard_lock = vs->hScard_lock;
	EnterCriticalSection(&hScard_lock);

	disassociate_card(pCardData);
	md_fs_finalize(pCardData);

	if(vs->ctx)   {
		logprintf(pCardData, 6, "release context\n");
		sc_release_context(vs->ctx);
		vs->ctx = NULL;
	}

	logprintf(pCardData, 1, "**********************************************************************\n");

	pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	pCardData->pvVendorSpecific = NULL;

	LeaveCriticalSection(&hScard_lock);
	DeleteCriticalSection(&hScard_lock);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData,
	__inout PCARD_CAPABILITIES  pCardCapabilities)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "pCardCapabilities=%p\n", pCardCapabilities);

	if (!pCardData || !pCardCapabilities || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_status(pCardData, "CardQueryCapabilities");
	if (dwret != SCARD_S_SUCCESS) {
		goto err;
	}

	dwret = md_card_capabilities(pCardData, pCardCapabilities);
	if (dwret != SCARD_S_SUCCESS) {
		goto err;
	}

err:
	unlock(pCardData);

	return dwret;
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwret;
	struct md_pkcs15_container* cont;
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContainer(idx:%u)\n",
		  (unsigned int)bContainerIndex);

	if (!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardDeleteContainer");
	if (dwret != SCARD_S_SUCCESS) {
		goto err;
	}

	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	if (!md_is_supports_container_key_gen(pCardData))   {
		logprintf(pCardData, 1, "Denied 'deletion' mechanism to delete container.\n");
		dwret = SCARD_E_UNSUPPORTED_FEATURE;
		goto err;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	cont = &(vs->p15_containers[bContainerIndex]);

	dwret = md_pkcs15_delete_object(pCardData, cont->prkey_obj);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 1, "private key deletion failed\n");
		goto err;
	}

	dwret = md_pkcs15_delete_object(pCardData, cont->pubkey_obj);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "public key deletion failed\n");
		goto err;
	}

	ZeroMemory(cont, sizeof(struct md_pkcs15_container));

	logprintf(pCardData, 1, "key deleted\n");

err:
	unlock(pCardData);

	return dwret;
}

/** The CardCreateContainerEx function creates a new key container that the
container index identifies and the bContainerIndex parameter specifies. The function
associates the key container with the PIN that the PinId parameter specified.
This function is useful if the card-edge does not allow for changing the key attributes
after the key container is created. This function replaces the need to call
CardSetContainerProperty to set the CCP_PIN_IDENTIFIER property CardCreateContainer
is called.
The caller of this function can provide the key material that the card imports.
This is useful in those situations in which the card either does not support internal
key generation or the caller requests that the key be archived in the card.*/
DWORD WINAPI CardCreateContainerEx(__in PCARD_DATA  pCardData,
				   __in BYTE  bContainerIndex,
				   __in DWORD  dwFlags,
				   __in DWORD  dwKeySpec,
				   __in DWORD  dwKeySize,
				   __in PBYTE  pbKeyData,
				   __in PIN_ID  PinId)
{
	DWORD dwret;

	if (!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	if (PinId == ROLE_ADMIN) {
		dwret = SCARD_W_SECURITY_VIOLATION;
		goto err;
	}

	dwret = check_card_reader_status(pCardData, "CardCreateContainerEx");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardCreateContainerEx(idx:%u,flags:%lX,type:%lX,size:%lu,data:%p,pin:%u)\n",
		  (unsigned int)bContainerIndex, (unsigned long)dwFlags,
		  (unsigned long)dwKeySpec, (unsigned long)dwKeySize, pbKeyData,
		  (unsigned int)PinId);

	if (pbKeyData)   {
		logprintf(pCardData, 7, "Key data\n");
		loghex(pCardData, 7, pbKeyData, dwKeySize);
	}

	dwret = md_check_key_compatibility(pCardData, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "check key compatibility failed\n");
		goto err;
	}

	if (!md_is_supports_container_key_gen(pCardData))   {
		logprintf(pCardData, 1, "Denied 'generate key' mechanism to create container.\n");
		dwFlags &= ~CARD_CREATE_CONTAINER_KEY_GEN;
	}

	if (!md_is_supports_container_key_import(pCardData))   {
		logprintf(pCardData, 1, "Denied 'import key' mechanism to create container.\n");
		dwFlags &= ~CARD_CREATE_CONTAINER_KEY_IMPORT;
	}

	if (!dwFlags)   {
		logprintf(pCardData, 1, "Unsupported create container mechanism.\n");
		dwret = SCARD_E_UNSUPPORTED_FEATURE;
		goto err;
	}

	if (dwFlags & CARD_CREATE_CONTAINER_KEY_GEN)   {
		dwret = md_pkcs15_generate_key(pCardData, bContainerIndex, dwKeySpec, dwKeySize, PinId);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key generation failed\n");
			goto err;
		}
		logprintf(pCardData, 1, "key generated\n");
	}
	else if ((dwFlags & CARD_CREATE_CONTAINER_KEY_IMPORT) && (pbKeyData != NULL)) {
		dwret = md_pkcs15_store_key(pCardData, bContainerIndex, dwKeySpec, pbKeyData, dwKeySize, PinId);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key store failed\n");
			goto err;
		}
		logprintf(pCardData, 1, "key imported\n");
	}
	else   {
		logprintf(pCardData, 1, "Invalid dwFlags value: 0x%lX\n",
			  (unsigned long)dwFlags);
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

err:
	unlock(pCardData);

	return dwret;
}

DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData,
				 __in BYTE bContainerIndex,
				 __in DWORD dwFlags,
				 __in DWORD dwKeySpec,
				 __in DWORD dwKeySize,
				 __in PBYTE pbKeyData)
{
	return CardCreateContainerEx(pCardData, bContainerIndex, dwFlags,
				     dwKeySpec, dwKeySize, pbKeyData,
				     ROLE_USER);
}

typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBRSAKEYSTRUCT_BASE;

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
	__inout PCONTAINER_INFO pContainerInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD sz = 0;
	DWORD ret;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15_der pubkey_der;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	int rv;
	pubkey_der.value = NULL;
	pubkey_der.len = 0;

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	ret = check_card_reader_status(pCardData, "CardGetContainerInfo");
	if (ret != SCARD_S_SUCCESS)
		goto err;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, dwVersion=%lu, cbSigPublicKey=%lu, cbKeyExPublicKey=%lu\n",
		  (unsigned int)bContainerIndex, (unsigned int)dwFlags,
		  (unsigned long)pContainerInfo->dwVersion,
		  (unsigned long)pContainerInfo->cbSigPublicKey,
		  (unsigned long)pContainerInfo->cbKeyExPublicKey);

	if (dwFlags) {
		ret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS) {
		ret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}
	if (pContainerInfo->dwVersion > CONTAINER_INFO_CURRENT_VERSION) {
		ret = ERROR_REVISION_MISMATCH;
		goto err;
	}

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		ret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	cont = &vs->p15_containers[bContainerIndex];

	if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %u is empty\n",
			  (unsigned int)bContainerIndex);
		ret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	ret = SCARD_F_UNKNOWN_ERROR;
	prkey_info = (struct sc_pkcs15_prkey_info *)cont->prkey_obj->data;

	if ((cont->prkey_obj->content.value != NULL) && (cont->prkey_obj->content.len > 0))   {
		sc_der_copy(&pubkey_der, &cont->prkey_obj->content);
		ret = SCARD_S_SUCCESS;
	}

	if (!pubkey_der.value && cont->pubkey_obj)   {
		struct sc_pkcs15_pubkey *pubkey = NULL;

		logprintf(pCardData, 1, "now read public key '%.*s'\n", (int) sizeof cont->pubkey_obj->label, cont->pubkey_obj->label);
		rv = sc_pkcs15_read_pubkey(vs->p15card, cont->pubkey_obj, &pubkey);
		if (!rv)   {
			rv = sc_pkcs15_encode_pubkey(vs->ctx, pubkey, &pubkey_der.value, &pubkey_der.len);
			if (rv)   {
				logprintf(pCardData, 1, "encode public key error %d\n", rv);
				ret = SCARD_F_INTERNAL_ERROR;
			}
			else   {
				logprintf(pCardData, 1, "public key encoded\n");
				ret = SCARD_S_SUCCESS;
			}

			sc_pkcs15_free_pubkey(pubkey);
		}
		else {
			logprintf(pCardData, 1, "public key read error %d\n", rv);
			ret = SCARD_E_FILE_NOT_FOUND;
		}
	}

	if (!pubkey_der.value && cont->cert_obj)   {
		struct sc_pkcs15_cert *cert = NULL;

		logprintf(pCardData, 1, "now read certificate '%.*s'\n", (int) sizeof cont->cert_obj->label, cont->cert_obj->label);
		rv = sc_pkcs15_read_certificate(vs->p15card, (struct sc_pkcs15_cert_info *)(cont->cert_obj->data), &cert);
		if(!rv)   {
			rv = sc_pkcs15_encode_pubkey(vs->ctx, cert->key, &pubkey_der.value, &pubkey_der.len);
			if (rv)   {
				logprintf(pCardData, 1, "encode certificate public key error %d\n", rv);
				ret = SCARD_F_INTERNAL_ERROR;
			}
			else   {
				logprintf(pCardData, 1, "certificate public key encoded\n");
				ret = SCARD_S_SUCCESS;
			}

			sc_pkcs15_free_certificate(cert);
		}
		else   {
			logprintf(pCardData, 1,
				  "certificate '%u' read error %d\n",
				  (unsigned int)bContainerIndex, rv);
			ret = SCARD_E_FILE_NOT_FOUND;
		}
	}

	if (!pubkey_der.value && (cont->size_sign || cont->size_key_exchange)) {
		logprintf(pCardData, 2, "cannot find public key\n");
		ret = SCARD_F_INTERNAL_ERROR;
		goto err;
	}

	if (ret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 7,
			  "GetContainerInfo(idx:%u) failed; error %lX",
			  (unsigned int)bContainerIndex, (unsigned long)ret);
		goto err;
	}

	logprintf(pCardData, 7, "SubjectPublicKeyInfo:\n");
	loghex(pCardData, 7, pubkey_der.value, pubkey_der.len);

	if (prkey_info->modulus_length > 0) {
		logprintf(pCardData, 7, "Encoding RSA public key");
		if (pubkey_der.len && pubkey_der.value)   {
			sz = 0; /* get size */
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
					pubkey_der.value, (DWORD) pubkey_der.len, 0, NULL, &sz);

			if (cont->size_sign)   {
				PUBRSAKEYSTRUCT_BASE *publicKey = (PUBRSAKEYSTRUCT_BASE *)pCardData->pfnCspAlloc(sz);
				if (!publicKey) {
					ret = SCARD_E_NO_MEMORY;
					goto err;
				}

				CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
						pubkey_der.value, (DWORD) pubkey_der.len, 0, publicKey, &sz);

				publicKey->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
				pContainerInfo->cbSigPublicKey = sz;
				pContainerInfo->pbSigPublicKey = (PBYTE)publicKey;

				logprintf(pCardData, 3,
					  "return info on SIGN_CONTAINER_INDEX %u\n",
					  (unsigned int)bContainerIndex);
			}

			if (cont->size_key_exchange)   {
				PUBRSAKEYSTRUCT_BASE *publicKey = (PUBRSAKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
				if (!publicKey) {
					ret = SCARD_E_NO_MEMORY;
					goto err;
				}

				CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
						pubkey_der.value, (DWORD) pubkey_der.len, 0, publicKey, &sz);

				publicKey->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
				pContainerInfo->cbKeyExPublicKey = sz;
				pContainerInfo->pbKeyExPublicKey = (PBYTE)publicKey;

				logprintf(pCardData, 3,
					  "return info on KEYX_CONTAINER_INDEX %u\n",
					  (unsigned int)bContainerIndex);
			}
		}
	} else if (prkey_info->field_length > 0) {
		logprintf(pCardData, 7, "Encoding ECC public key");

		if (pubkey_der.len > 2 && pubkey_der.value && pubkey_der.value[0] == 4 && pubkey_der.value[1] == pubkey_der.len -2) {
			BCRYPT_ECCKEY_BLOB *publicKey = NULL;
			DWORD dwMagic = 0;
			if (cont->size_sign)   {
				sz = (DWORD) (sizeof(BCRYPT_ECCKEY_BLOB) +  pubkey_der.len -3);

				switch(cont->size_sign)
				{
				case 256:
					dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
					break;
				case 384:
					dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
					break;
				case 521:
					dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
					break;
				default:
					logprintf(pCardData, 3,
						  "Unable to match the ECC public size to one of Microsoft algorithm %"SC_FORMAT_LEN_SIZE_T"u\n",
						  cont->size_sign);
					ret = SCARD_F_INTERNAL_ERROR;
					goto err;
				}

				publicKey = (BCRYPT_ECCKEY_BLOB *)pCardData->pfnCspAlloc(sz);
				if (!publicKey) {
					ret = SCARD_E_NO_MEMORY;
					goto err;
				}

				publicKey->cbKey =  (DWORD)(pubkey_der.len -3) /2;
				publicKey->dwMagic = dwMagic;

				pContainerInfo->cbSigPublicKey = sz;
				pContainerInfo->pbSigPublicKey = (PBYTE)publicKey;
				memcpy(((PBYTE)publicKey) + sizeof(BCRYPT_ECCKEY_BLOB),  pubkey_der.value + 3,  pubkey_der.len -3);

				logprintf(pCardData, 3,
					  "return info on ECC SIGN_CONTAINER_INDEX %u\n",
					  (unsigned int)bContainerIndex);
			}
			if (cont->size_key_exchange)   {
				sz = (DWORD) (sizeof(BCRYPT_ECCKEY_BLOB) +  pubkey_der.len -3);

				switch(cont->size_key_exchange)
				{
				case 256:
					dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
					break;
				case 384:
					dwMagic = BCRYPT_ECDH_PUBLIC_P384_MAGIC;
					break;
				case 521:
					dwMagic = BCRYPT_ECDH_PUBLIC_P521_MAGIC;
					break;
				default:
					logprintf(pCardData, 3,
						  "Unable to match the ECC public size to one of Microsoft algorithm %"SC_FORMAT_LEN_SIZE_T"u\n",
						  cont->size_key_exchange);
					ret = SCARD_F_INTERNAL_ERROR;
					goto err;
				}

				publicKey = (BCRYPT_ECCKEY_BLOB *)pCardData->pfnCspAlloc(sz);
				if (!publicKey) {
					ret = SCARD_E_NO_MEMORY;
					goto err;
				}

				publicKey->cbKey =  (DWORD)(pubkey_der.len -3) /2;
				publicKey->dwMagic = dwMagic;

				pContainerInfo->cbKeyExPublicKey = sz;
				pContainerInfo->pbKeyExPublicKey = (PBYTE)publicKey;
				memcpy(((PBYTE)publicKey) + sizeof(BCRYPT_ECCKEY_BLOB),  pubkey_der.value + 3,  pubkey_der.len -3);

				logprintf(pCardData, 3,
					  "return info on ECC KEYX_CONTAINER_INDEX %u\n",
					  (unsigned int)bContainerIndex);
			}
		}
	}
	logprintf(pCardData, 7, "returns container(idx:%u) info",
		  (unsigned int)bContainerIndex);

err:
	free(pubkey_der.value);
	unlock(pCardData);

	return ret;
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbPin) PBYTE pbPin,
	__in DWORD cbPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	PIN_ID PinId = 0;
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticatePin '%S':%lu\n",
		  NULLWSTR(pwszUserId), (unsigned long)cbPin);

	if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0)	{
		PinId = ROLE_USER;
	}
	else if (wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0) {
		PinId = ROLE_ADMIN;
	}
	else {
		return SCARD_E_INVALID_PARAMETER;
	}
	if (pbPin == NULL)
		return SCARD_E_INVALID_PARAMETER;

	return CardAuthenticateEx(pCardData, PinId, CARD_PIN_SILENT_CONTEXT, pbPin, cbPin, NULL, NULL, pcAttemptsRemaining);
}


DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out                                 PDWORD pcbChallengeData)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	int rv;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallenge\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbChallengeData || !pcbChallengeData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardGetChallenge");
	if (dwret != SCARD_S_SUCCESS) {
		goto err;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	*pcbChallengeData = 8;

	*ppbChallengeData = (PBYTE) pCardData->pfnCspAlloc(8);
	if (!*ppbChallengeData) {
		dwret = SCARD_E_NO_MEMORY;
		goto err;
	}

	rv = sc_get_challenge(vs->p15card->card, *ppbChallengeData, 8);
	if (rv < 0) {
		logprintf(pCardData, 1, "Get challenge failed: %s\n", sc_strerror(rv));
		pCardData->pfnCspFree(*ppbChallengeData);
		*ppbChallengeData = NULL;
		dwret = SCARD_E_UNEXPECTED;
		goto err;
	}
	dwret = SCARD_S_SUCCESS;

	logprintf(pCardData, 7, "returns %lu bytes:\n",
		  (unsigned long)*pcbChallengeData);
	loghex(pCardData, 7, *ppbChallengeData, *pcbChallengeData);

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE  pbResponseData,
	__in DWORD  cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining)
{
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
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
	DWORD r = SCARD_S_SUCCESS;

	if(!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardUnblockPin\n");

	if (pwszUserId == NULL) {
		logprintf(pCardData, 1, "no user ID\n");
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}
	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN,pwszUserId) != 0) {
		logprintf(pCardData, 1, "unknown user ID %S\n", pwszUserId);
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}
	if (wcscmp(wszCARD_USER_ADMIN, pwszUserId) == 0) {
		logprintf(pCardData, 1, "unlocking admin not supported\n");
		r = SCARD_E_UNSUPPORTED_FEATURE;
		goto err;
	}
	if (dwFlags & CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE) {
		logprintf(pCardData, 1,
				"challenge / response not supported, we'll treat response as a PUK\n");
		logprintf(pCardData, 1,
				"note that you'll need to type PUK in hex (replace every PUK digit X with '3X') in Win CAD unblock dialog response field\n");
		dwFlags &= ~CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE;
	}
	if (dwFlags) {
		logprintf(pCardData, 1, "flags of %x not supported\n",
				(unsigned int)dwFlags);
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	logprintf(pCardData, 1,
			"UserID('%S'), AuthData(%p, %lu), NewPIN(%p, %lu), Retry(%lu), dwFlags(0x%lX)\n",
			pwszUserId, pbAuthenticationData,
			(unsigned long)cbAuthenticationData, pbNewPinData,
			(unsigned long)cbNewPinData, (unsigned long)cRetryCount,
			(unsigned long)dwFlags);

	r = CardChangeAuthenticatorEx(pCardData,
			PIN_CHANGE_FLAG_UNBLOCK |
			CARD_PIN_SILENT_CONTEXT,
			ROLE_ADMIN, pbAuthenticationData,
			cbAuthenticationData, ROLE_USER,
			pbNewPinData, cbNewPinData,
			cRetryCount, NULL);

err:
	unlock(pCardData);

	return r;
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
	DWORD r = SCARD_S_SUCCESS;
	PIN_ID pinid;

	if(!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
			(unsigned long)GetCurrentProcessId(),
			(unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticator\n");

	if (pwszUserId == NULL) {
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	if (dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)   {
		logprintf(pCardData, 1, "Other then 'authentication' the PIN are not supported\n");
		r = SCARD_E_UNSUPPORTED_FEATURE;
		goto err;
	}
	else if (dwFlags != CARD_AUTHENTICATE_PIN_PIN){
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN, pwszUserId) != 0) {
		r = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	logprintf(pCardData, 1,
			"UserID('%S'), CurrentPIN(%p, %lu), NewPIN(%p, %lu), Retry(%lu), dwFlags(0x%lX)\n",
			pwszUserId, pbCurrentAuthenticator,
			(unsigned long)cbCurrentAuthenticator, pbNewAuthenticator,
			(unsigned long)cbNewAuthenticator, (unsigned long)cRetryCount,
			(unsigned long)dwFlags);

	if (wcscmp(wszCARD_USER_USER, pwszUserId) == 0)
		pinid = ROLE_USER;
	else
		pinid = ROLE_ADMIN;

	r = CardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_CHANGEPIN |
			CARD_PIN_SILENT_CONTEXT, pinid,
			pbCurrentAuthenticator,
			cbCurrentAuthenticator, pinid,
			pbNewAuthenticator, cbNewAuthenticator,
			cRetryCount, pcAttemptsRemaining);

err:
	unlock(pCardData);
	return r;
}

/* Note: the PIN freshness will be managed by the Base CSP */
DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	DWORD dwret;
	VENDOR_SPECIFIC* vs = NULL;
	int rv;

	logprintf(pCardData, 1, "\nP:%ld T:%ld pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticate(%S) %lu\n",
		  NULLWSTR(pwszUserId), (unsigned long)dwFlags);

	if(!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardDeauthenticate");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	sc_pkcs15_pincache_clear(vs->p15card);

	rv = sc_logout(vs->p15card->card);

	if (rv != SC_SUCCESS) {
		/* force a reset of a card - SCARD_S_SUCCESS do not lead to the reset
		 * of the card and leave it still authenticated */
		dwret = SCARD_E_UNSUPPORTED_FEATURE;
		goto err;
	}

	dwret = SCARD_S_SUCCESS;

err:
	unlock(pCardData);

	return dwret;
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateDirectory - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName)
{
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteDirectory(%s) - unsupported\n", NULLSTR(pszDirectoryName));
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	struct md_directory *dir = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardCreateFile(%s::%s, size %lu, acl:0x%X) called\n",
		  NULLSTR(pszDirectoryName), NULLSTR(pszFileName),
		  (unsigned long)cbInitialCreationSize, AccessCondition);

	if (!lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_status(pCardData, "CardCreateFile");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	dwret = md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardCreateFile() cannot find parent directory '%s'", NULLSTR(pszDirectoryName));
		goto err;
	}

	dwret = md_fs_add_file(pCardData, &dir->files, pszFileName, AccessCondition, NULL, cbInitialCreationSize, NULL);
	if (dwret != SCARD_S_SUCCESS)
		goto err;

err:
	unlock(pCardData);

	return dwret;
}


DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount_opt(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData)
{
	struct md_file *file = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardReadFile\n");

	if(!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2,
		  "pszDirectoryName = %s, pszFileName = %s, dwFlags = %lX, pcbData=%p, ppbData=%p\n",
		  NULLSTR(pszDirectoryName), NULLSTR(pszFileName),
		  (unsigned long)dwFlags, pcbData, ppbData);

	if (!pszFileName || !strlen(pszFileName) || dwFlags) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	dwret = check_card_reader_status(pCardData, "CardReadFile");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardReadFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		dwret = SCARD_E_FILE_NOT_FOUND;
		goto err;
	}

	if (!file->blob) {
		dwret = md_fs_read_content(pCardData, pszDirectoryName, file);
		if (dwret != SCARD_S_SUCCESS)
			goto err;
	}

	if (ppbData) {
		*ppbData = pCardData->pfnCspAlloc(file->size);
		if(!*ppbData) {
			dwret = SCARD_E_NO_MEMORY;
			goto err;
		}

		memcpy(*ppbData, file->blob, file->size);
	}

	if (pcbData)
		*pcbData = (DWORD)file->size;

	logprintf(pCardData, 7, "returns '%s' content:\n",  NULLSTR(pszFileName));
	loghex(pCardData, 7, file->blob, file->size);

err:
	unlock(pCardData);

	return dwret;
}


DWORD WINAPI CardWriteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData)
{
	struct md_file *file = NULL;
	DWORD dwret;

	if(!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardWriteFile() dirName:'%s', fileName:'%s' \n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	dwret = check_card_reader_status(pCardData, "CardWriteFile");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	if (pbData && cbData)   {
		logprintf(pCardData, 1, "CardWriteFile try to write (%lu):\n",
			  (unsigned long)cbData);
		loghex(pCardData, 2, pbData, cbData);
	}

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		dwret = SCARD_E_FILE_NOT_FOUND;
		goto err;
	}

	logprintf(pCardData, 7, "set content of '%s' to:\n",  NULLSTR(pszFileName));
	loghex(pCardData, 7, pbData, cbData);

	dwret = md_fs_set_content(pCardData, file, pbData, cbData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "cannot set file content: %lu\n",
			  (unsigned long)dwret);
		goto err;
	}

	if (pszDirectoryName && !strcmp(pszDirectoryName, "mscp"))   {
		if ((strstr(pszFileName, "kxc") == pszFileName) || (strstr(pszFileName, "ksc") == pszFileName))	{
			dwret = md_pkcs15_store_certificate(pCardData, pszFileName, pbData, cbData);
			if (dwret != SCARD_S_SUCCESS)
				goto err;
			logprintf(pCardData, 2, "md_pkcs15_store_certificate() OK\n");
		}
	}

	logprintf(pCardData, 2, "write '%s' ok.\n",  NULLSTR(pszFileName));

err:
	unlock(pCardData);
	return dwret;
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteFile(%s, %s) called\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	if(!pCardData  || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardDeleteFile");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	dwret = md_fs_delete_file(pCardData, pszDirectoryName, pszFileName);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2,
			  "CardDeleteFile(): delete file error: %lX\n",
			  (unsigned long)dwret);
		goto err;
	}

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__deref_out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwret;
	char mstr[0x100];
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
	size_t offs;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardEnumFiles() directory '%s'\n", NULLSTR(pszDirectoryName));

	if (!pCardData || !pmszFileNames || !pdwcbFileName || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)   {
		logprintf(pCardData, 1,
			  "CardEnumFiles() dwFlags not 'zero' -- %lX\n",
			  (unsigned long)dwFlags);
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	dwret = check_card_status(pCardData, "CardEnumFiles");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	memset(mstr, 0, sizeof(mstr));

	if (!pszDirectoryName || !strlen(pszDirectoryName))
		dir = &vs->root;
	else
		md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (!dir)   {
		logprintf(pCardData, 2, "enum files() failed: directory '%s' not found\n", NULLSTR(pszDirectoryName));
		dwret = SCARD_E_FILE_NOT_FOUND;
		goto err;
	}

	file = dir->files;
	for (offs = 0; file != NULL && offs < sizeof(mstr) - 10;)   {
		logprintf(pCardData, 2, "enum files(): file name '%s'\n", file->name);
		strlcpy(mstr + offs, (char *)file->name, sizeof(mstr) - offs);
		offs += strlen((char *)file->name) + 1;
		file = file->next;
	}
	mstr[offs] = 0;
	offs += 1;

	*pmszFileNames = (LPSTR)(*pCardData->pfnCspAlloc)(offs);
	if (*pmszFileNames == NULL) {
		dwret = SCARD_E_NO_MEMORY;
		goto err;
	}

	CopyMemory(*pmszFileNames, mstr, offs);
	*pdwcbFileName = (DWORD) offs;

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__inout PCARD_FILE_INFO pCardFileInfo)
{
	DWORD dwret;
	struct md_file *file = NULL;

	if(!pCardData  || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetFileInfo(dirName:'%s',fileName:'%s', out %p)\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), pCardFileInfo);

	dwret = check_card_status(pCardData, "CardGetFileInfo");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		dwret = SCARD_E_FILE_NOT_FOUND;
		goto err;
	}

	pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	pCardFileInfo->cbFileSize = (DWORD) file->size;
	pCardFileInfo->AccessCondition = file->acl;

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
	__inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardQueryFreeSpace %p, dwFlags=%lX, version=%lX\n",
		  pCardFreeSpaceInfo, (unsigned long)dwFlags,
		  (unsigned long)pCardFreeSpaceInfo->dwVersion);

	if (!pCardData || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_status(pCardData, "CardQueryFreeSpace");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardQueryFreeSpace() md free space error");
		goto err;
	}

	logprintf(pCardData, 7, "FreeSpace:\n");
	loghex(pCardData, 7, (BYTE *)pCardFreeSpaceInfo, sizeof(*pCardFreeSpaceInfo));

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__inout PCARD_KEY_SIZES pKeySizes)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardQueryKeySizes dwKeySpec=%lX, dwFlags=%lX, version=%lX\n",
		  (unsigned long)dwKeySpec, (unsigned long)dwFlags,
		  pKeySizes ? (unsigned long)pKeySizes->dwVersion : 0);

	if (!pCardData || dwFlags != 0 || dwKeySpec == 0 || !lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_status(pCardData, "CardQueryKeySizes");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	dwret = md_query_key_sizes(pCardData, dwKeySpec, pKeySizes);
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	logprintf(pCardData, 7, "pKeySizes:\n");
	loghex(pCardData, 7, (BYTE *)pKeySizes, sizeof(*pKeySizes));

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo)

{
	DWORD dwret;
	int r, opt_crypt_flags = 0;
	unsigned ui;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_prkey_info *prkey_info;
	BYTE *pbuf = NULL, *pbuf2 = NULL;
	struct sc_pkcs15_object *pkey = NULL;
	struct sc_algorithm_info *alg_info = NULL;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardRSADecrypt\n");
	if (!pCardData || !pInfo || pInfo->pbData == NULL)
		return SCARD_E_INVALID_PARAMETER;
	if (pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if ( pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		return SCARD_E_INVALID_PARAMETER;

	if (!lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardRSADecrypt");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	/* check if the container exists */
	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS) {
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	logprintf(pCardData, 2,
		  "CardRSADecrypt dwVersion=%lu, bContainerIndex=%u, dwKeySpec=%lu pbData=%p, cbData=%lu\n",
		  (unsigned long)pInfo->dwVersion,
		  (unsigned int)pInfo->bContainerIndex,
		  (unsigned long)pInfo->dwKeySpec, pInfo->pbData,
		  (unsigned long)pInfo->cbData);

	if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		logprintf(pCardData, 2,
			  "  pPaddingInfo=%p dwPaddingType=0x%08X\n",
			  pInfo->pPaddingInfo,
			  (unsigned int)pInfo->dwPaddingType);

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;
	if (!pkey)   {
		logprintf(pCardData, 2, "CardRSADecrypt prkey not found\n");
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	/* input and output buffers are always the same size */
	pbuf = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf) {
		dwret = SCARD_E_NO_MEMORY;
		goto err;
	}

	pbuf2 = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf2) {
		pCardData->pfnCspFree(pbuf);
		dwret = SCARD_E_NO_MEMORY;
		goto err;
	}

	/*inversion donnees*/
	for(ui = 0; ui < pInfo->cbData; ui++)
		pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];
	logprintf(pCardData, 2, "Data to be decrypted (inverted):\n");
	loghex(pCardData, 7, pbuf, pInfo->cbData);

	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);
	alg_info = sc_card_find_rsa_alg(vs->p15card->card, (unsigned int) prkey_info->modulus_length);
	if (!alg_info)   {
		logprintf(pCardData, 2,
			  "Cannot get appropriate RSA card algorithm for key size %"SC_FORMAT_LEN_SIZE_T"u\n",
			  prkey_info->modulus_length);
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		dwret = SCARD_F_INTERNAL_ERROR;
		goto err;
	}

	/* filter bogus input: the data to decrypt is shorter than the RSA key ? */
	if ( pInfo->cbData < prkey_info->modulus_length / 8)
	{
		/* according to the minidriver specs, this is the error code to return
		(instead of invalid parameter when the call is forwarded to the card implementation) */
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		dwret = SCARD_E_INSUFFICIENT_BUFFER;
		goto err;
	}

	if (alg_info->flags & SC_ALGORITHM_RSA_RAW)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher: using RSA-RAW mechanism\n");
		r = sc_pkcs15_decipher(vs->p15card, pkey, opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);

		if (r > 0) {
			/* Need to handle padding */
			if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) {
				logprintf(pCardData, 2,
					  "sc_pkcs15_decipher: DECRYPT-INFO dwVersion=%lu\n",
					  (unsigned long)pInfo->dwVersion);
				if (pInfo->dwPaddingType == CARD_PADDING_PKCS1)   {
					size_t temp = pInfo->cbData;
					logprintf(pCardData, 2, "sc_pkcs15_decipher: stripping PKCS1 padding\n");
					r = sc_pkcs1_strip_02_padding(vs->ctx, pbuf2, pInfo->cbData, pbuf2, &temp);
					pInfo->cbData = (DWORD) temp;
					if (r < 0)   {
						logprintf(pCardData, 2, "Cannot strip PKCS1 padding: %i\n", r);
						pCardData->pfnCspFree(pbuf);
						pCardData->pfnCspFree(pbuf2);
						dwret = SCARD_F_INTERNAL_ERROR;
						goto err;
					}
				}
				else if (pInfo->dwPaddingType == CARD_PADDING_OAEP)   {
					/* TODO: Handle OAEP padding if present - can call PFN_CSP_UNPAD_DATA */
					logprintf(pCardData, 2, "OAEP padding not implemented\n");
					pCardData->pfnCspFree(pbuf);
					pCardData->pfnCspFree(pbuf2);
					dwret = SCARD_F_INTERNAL_ERROR;
					goto err;
				}
			}
		}
	}
	else if (alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher: using RSA_PAD_PKCS1 mechanism\n");
		r = sc_pkcs15_decipher(vs->p15card, pkey, opt_crypt_flags | SC_ALGORITHM_RSA_PAD_PKCS1,
				pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);
		if (r > 0) {
			/* No padding info, or padding info none */
			if ((pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) ||
					((pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) && (pInfo->dwPaddingType == CARD_PADDING_NONE))) {
				if ((unsigned)r <= pInfo->cbData - 9)	{
					/* add pkcs1 02 padding */
					logprintf(pCardData, 2, "Add '%s' to the output data", "PKCS#1 BT02 padding");
					memset(pbuf, 0x30, pInfo->cbData);
					*(pbuf + 0) = 0;
					*(pbuf + 1) = 2;
					memcpy(pbuf + pInfo->cbData - r, pbuf2, r);
					*(pbuf + pInfo->cbData - r - 1) = 0;
					memcpy(pbuf2, pbuf, pInfo->cbData);
				}
			}
			else if (pInfo->dwPaddingType == CARD_PADDING_PKCS1) {
				/* PKCS1 padding is already handled by the card... */
				pInfo->cbData = r;
			}
			/* TODO: Handle OAEP padding if present - can call PFN_CSP_UNPAD_DATA */
		}
	}
	else    {
		logprintf(pCardData, 2, "CardRSADecrypt: no usable RSA algorithm\n");
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		dwret = md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE);
		goto err;
	}

	logprintf(pCardData, 2, "decrypted data(%lu):\n",
		  (unsigned long)pInfo->cbData);
	loghex(pCardData, 7, pbuf2, pInfo->cbData);

	/*inversion donnees */
	for(ui = 0; ui < pInfo->cbData; ui++)
		pInfo->pbData[ui] = pbuf2[pInfo->cbData-ui-1];

	pCardData->pfnCspFree(pbuf);
	pCardData->pfnCspFree(pbuf2);

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __inout PCARD_SIGNING_INFO pInfo)
{
	DWORD dwret;
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE dataToSign[0x200];
	int opt_crypt_flags;
	size_t dataToSignLen = sizeof(dataToSign);
	sc_pkcs15_object_t *pkey;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSignData\n");

	if (!pCardData || !pInfo)
		return SCARD_E_INVALID_PARAMETER;
	if ( ( pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION   ) &&
			( pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION ) )
		return ERROR_REVISION_MISMATCH;
	if ( pInfo->pbData == NULL )
		return SCARD_E_INVALID_PARAMETER;
	switch(pInfo->dwKeySpec)
	{
	case AT_SIGNATURE:
	case AT_KEYEXCHANGE:
	case AT_ECDSA_P256:
	case AT_ECDSA_P384:
	case AT_ECDSA_P521:
	case AT_ECDHE_P256:
	case AT_ECDHE_P384:
	case AT_ECDHE_P521:
		break;
	default:
		return SCARD_E_INVALID_PARAMETER;
	}
	if (pInfo->dwSigningFlags & ~(CARD_PADDING_INFO_PRESENT | CARD_PADDING_NONE | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_PKCS1 | CARD_PADDING_PSS | CARD_PADDING_OAEP))
		return SCARD_E_INVALID_PARAMETER;

	if (!lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardSignData");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	logprintf(pCardData, 2,
		  "CardSignData dwVersion=%lu, bContainerIndex=%u, dwKeySpec=%lu, dwSigningFlags=0x%08X, aiHashAlg=0x%08X\n",
		  (unsigned long)pInfo->dwVersion,
		  (unsigned int)pInfo->bContainerIndex,
		  (unsigned long)pInfo->dwKeySpec,
		  (unsigned int)pInfo->dwSigningFlags,
		  (unsigned int)pInfo->aiHashAlg);

	logprintf(pCardData, 7, "pInfo->pbData(%lu) ",
		  (unsigned long)pInfo->cbData);
	loghex(pCardData, 7, pInfo->pbData, pInfo->cbData);

	hashAlg = pInfo->aiHashAlg;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS) {
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;
	if (!pkey) {
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}
	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);

	logprintf(pCardData, 2, "pInfo->dwVersion = %lu\n",
		  (unsigned long)pInfo->dwVersion);

	if (dataToSignLen < pInfo->cbData) {
		dwret = SCARD_E_INSUFFICIENT_BUFFER;
		goto err;
	}
	memcpy(dataToSign, pInfo->pbData, pInfo->cbData);
	dataToSignLen = pInfo->cbData;

	if (0 == (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags))   {
		/* When CARD_PADDING_INFO_PRESENT is not set in dwSigningFlags, this is
		 * the basic version of the signing structure. (If this is not the
		 * basic verison of the signing structure, the minidriver should return
		 * ERROR_REVISION_MISMATCH.) The minidriver should only do PKCS1
		 * padding and use the value in aiHashAlg. */
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");

		opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1;
		if (hashAlg == CALG_MD5)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_MD5;
		else if (hashAlg == CALG_SHA1)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
		else if (hashAlg == CALG_SSL3_SHAMD5)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else if (hashAlg == CALG_SHA_256)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA256;
		else if (hashAlg == CALG_SHA_384)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA384;
		else if (hashAlg == CALG_SHA_512)
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA512;
		else if (hashAlg == (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_RIPEMD160))
			opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;
		else if (hashAlg !=0) {
			logprintf(pCardData, 0, "bogus aiHashAlg %i\n", hashAlg);
			dwret = SCARD_E_UNSUPPORTED_FEATURE;
			goto err;
		}
	} else {
		switch (pInfo->dwPaddingType) {
			case CARD_PADDING_NONE:
				opt_crypt_flags = SC_ALGORITHM_RSA_PAD_NONE;
				break;

			case CARD_PADDING_PKCS1:
				opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1;
				BCRYPT_PKCS1_PADDING_INFO *pkcs1_pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;

				if (!pkcs1_pinf->pszAlgId || wcscmp(pkcs1_pinf->pszAlgId, L"SHAMD5") == 0) {
					/* hashAlg = CALG_SSL3_SHAMD5; */
					logprintf(pCardData, 3, "Using CALG_SSL3_SHAMD5  hashAlg\n");
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
				} else if (wcscmp(pkcs1_pinf->pszAlgId, BCRYPT_MD5_ALGORITHM) == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_MD5;
				else if (wcscmp(pkcs1_pinf->pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
				else if (wcscmp(pkcs1_pinf->pszAlgId, L"SHA224") == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA224;
				else if (wcscmp(pkcs1_pinf->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA256;
				else if (wcscmp(pkcs1_pinf->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA384;
				else if (wcscmp(pkcs1_pinf->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA512;
				else if (wcscmp(pkcs1_pinf->pszAlgId, L"RIPEMD160") == 0)
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;
				else {
					logprintf(pCardData, 0,"unknown AlgId %S\n",NULLWSTR(pkcs1_pinf->pszAlgId));
					dwret = SCARD_E_UNSUPPORTED_FEATURE;
					goto err;
				}
				break;

			case CARD_PADDING_PSS:
				opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PSS;
				BCRYPT_PSS_PADDING_INFO *pss_pinf = (BCRYPT_PSS_PADDING_INFO *)pInfo->pPaddingInfo;
				ULONG expected_salt_len;

				if (!pss_pinf->pszAlgId || wcscmp(pss_pinf->pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0) {
					/* hashAlg = CALG_SHA1; */
					logprintf(pCardData, 3, "Using CALG_SHA1  hashAlg\n");
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
					expected_salt_len = 160;
				} else if (wcscmp(pss_pinf->pszAlgId, L"SHA224") == 0) {
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA224;
					expected_salt_len = 224;
				} else if (wcscmp(pss_pinf->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA256;
					expected_salt_len = 256;
				} else if (wcscmp(pss_pinf->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA384;
					expected_salt_len = 384;
				} else if (wcscmp(pss_pinf->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
					opt_crypt_flags |= SC_ALGORITHM_RSA_HASH_SHA512;
					expected_salt_len = 512;
				} else {
					logprintf(pCardData, 0,"unknown AlgId %S\n",NULLWSTR(pss_pinf->pszAlgId));
					dwret = SCARD_E_UNSUPPORTED_FEATURE;
					goto err;
				}
				/* We're strict, and only do PSS signatures with a salt length that
				 * matches the digest length (any shorter is rubbish, any longer
				 * is useless). */
				if (pss_pinf->cbSalt != expected_salt_len / 8) {
					dwret = SCARD_E_INVALID_PARAMETER;
					goto err;
				}
				break;

			default:
				logprintf(pCardData, 0, "unsupported paddingtype\n");
				dwret = SCARD_E_INVALID_PARAMETER;
				goto err;
		}
	}
	

	/* Compute output size */
	if ( prkey_info->modulus_length > 0) {
		/* RSA */
		pInfo->cbSignedData = (DWORD) prkey_info->modulus_length / 8;
	} else if ( prkey_info->field_length > 0) {
		switch(prkey_info->field_length) {
			case 256:
				/* ECDSA_P256 */
				pInfo->cbSignedData = 256 / 8 * 2;
				break;
			case 384:
				/* ECDSA_P384 */
				pInfo->cbSignedData = 384 / 8 * 2;
				break;
			case 512:
				/* ECDSA_P512 : special case !!!*/
				pInfo->cbSignedData = 132;
				break;
			default:
				logprintf(pCardData, 0,
					  "unknown ECC key size %"SC_FORMAT_LEN_SIZE_T"u\n",
					  prkey_info->field_length);
				dwret = SCARD_E_INVALID_VALUE;
				goto err;
		}
	} else {
		logprintf(pCardData, 0, "invalid private key\n");
		dwret = SCARD_E_INVALID_VALUE;
		goto err;
	}

	logprintf(pCardData, 3, "pInfo->cbSignedData = %lu\n",
		  (unsigned long)pInfo->cbSignedData);

	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))   {
		int r,i;
		BYTE *pbuf = NULL;
		DWORD lg;

		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %lu\n", (unsigned long)lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf) {
			dwret = SCARD_E_NO_MEMORY;
			goto err;
		}

		logprintf(pCardData, 7, "Data to sign: ");
		loghex(pCardData, 7, dataToSign, dataToSignLen);

		pInfo->pbSignedData = (PBYTE) pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData)   {
			pCardData->pfnCspFree(pbuf);
			dwret = SCARD_E_NO_MEMORY;
			goto err;
		}

		r = sc_pkcs15_compute_signature(vs->p15card, pkey, opt_crypt_flags, dataToSign, dataToSignLen, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)   {
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature error %s\n", sc_strerror(r));
			pCardData->pfnCspFree(pbuf);
			dwret = md_translate_OpenSC_to_Windows_error(r, SCARD_F_INTERNAL_ERROR);
			goto err;
		}

		pInfo->cbSignedData = r;

		
		/*revert data only for RSA (Microsoft uses the big endian version while everyone is using little endian*/
		if ( prkey_info->modulus_length > 0) {
			for(i = 0; i < r; i++)
				pInfo->pbSignedData[i] = pbuf[r-i-1];
		} else {
			for(i = 0; i < r; i++)
				pInfo->pbSignedData[i] = pbuf[i];
		}

		pCardData->pfnCspFree(pbuf);

		logprintf(pCardData, 7, "Signature (inverted): ");
		loghex(pCardData, 7, pInfo->pbSignedData, pInfo->cbSignedData);
	}

	logprintf(pCardData, 3,
		  "CardSignData, dwVersion=%lu, name=%S, hScard=0x%08X, hSCardCtx=0x%08X\n",
		  (unsigned long)pCardData->dwVersion,
		  NULLWSTR(pCardData->pwszCardName),
		  (unsigned int)pCardData->hScard,
		  (unsigned int)pCardData->hSCardCtx);

err:
	unlock(pCardData);
	return dwret;
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__inout PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	DWORD dwret;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_object *pkey = NULL;
	int r, opt_derive_flags = 0;
	u8* out = 0;
	unsigned long outlen = 0;
	PBYTE pbPublicKey = NULL;
	DWORD dwPublicKeySize = 0;
	struct md_dh_agreement* dh_agreement = NULL;
	struct md_dh_agreement* temp = NULL;
	BYTE i;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardConstructDHAgreement\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pAgreementInfo)
		return SCARD_E_INVALID_PARAMETER;
	if ( pAgreementInfo->pbPublicKey == NULL )
		return SCARD_E_INVALID_PARAMETER;
	if (pAgreementInfo->dwVersion > CARD_DH_AGREEMENT_INFO_VERSION)
		return ERROR_REVISION_MISMATCH;
	if ( pAgreementInfo->dwVersion < CARD_DH_AGREEMENT_INFO_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	if (!lock(pCardData))
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardConstructDHAgreement");
	if (dwret != SCARD_S_SUCCESS)
		goto err;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		dwret = SCARD_E_INVALID_PARAMETER;
		goto err;
	}

	/* check if the container exists */
	if (pAgreementInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS) {
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	logprintf(pCardData, 2, "CardConstructDHAgreement dwVersion=%lu, dwKeySpec=%u pbData=%p, cbData=%lu\n",
		  (unsigned long)pAgreementInfo->dwVersion,
		  (unsigned int)pAgreementInfo->bContainerIndex,
		  pAgreementInfo->pbPublicKey,
		  (unsigned long)pAgreementInfo->dwPublicKey);

	pkey = vs->p15_containers[pAgreementInfo->bContainerIndex].prkey_obj;
	if (!pkey)   {
		logprintf(pCardData, 2, "CardConstructDHAgreement prkey not found\n");
		dwret = SCARD_E_NO_KEY_CONTAINER;
		goto err;
	}

	/* convert the Windows public key into an OpenSC public key */
	dwPublicKeySize = pAgreementInfo->dwPublicKey - sizeof(BCRYPT_ECCKEY_BLOB) + 1;
	pbPublicKey = (PBYTE) pCardData->pfnCspAlloc(dwPublicKeySize);
	if (!pbPublicKey) {
		dwret = ERROR_OUTOFMEMORY;
		goto err;
	}

	pbPublicKey[0] = 4;
	memcpy(pbPublicKey+1, pAgreementInfo->pbPublicKey +  sizeof(BCRYPT_ECCKEY_BLOB), dwPublicKeySize-1);

	/* derive the key using the OpenSC functions */
	r = sc_pkcs15_derive(vs->p15card, pkey, opt_derive_flags, pbPublicKey, dwPublicKeySize, out, &outlen );
	logprintf(pCardData, 2, "sc_pkcs15_derive returned %d\n", r);

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_derive error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(pbPublicKey);
		dwret = md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE);
		goto err;
	}

	out = pCardData->pfnCspAlloc(outlen);

	if (!out) {
		dwret = ERROR_OUTOFMEMORY;
		goto err;
	}

	r = sc_pkcs15_derive(vs->p15card, pkey, opt_derive_flags, pbPublicKey, dwPublicKeySize, out, &outlen );
	logprintf(pCardData, 2, "sc_pkcs15_derive returned %d\n", r);

	pCardData->pfnCspFree(pbPublicKey);

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_derive error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(out);
		dwret = md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE);
		goto err;
	}

	/* save the dh agreement for later use */

	/* try to find an empty index */
	for (i = 0; i < vs->allocatedAgreements; i++) {
		dh_agreement = vs->dh_agreements + i;
		if (dh_agreement->pbAgreement == NULL) {
			pAgreementInfo->bSecretAgreementIndex = i;
			dh_agreement->pbAgreement = out;
			dh_agreement->dwSize = outlen;
			dwret = SCARD_S_SUCCESS;
			goto err;
		}
	}
	/* no empty space => need to allocate memory */
	temp = (struct md_dh_agreement*) pCardData->pfnCspAlloc((vs->allocatedAgreements+1) * sizeof(struct md_dh_agreement));
	if (!temp) {
		pCardData->pfnCspFree(out);
		dwret = SCARD_E_NO_MEMORY;
		goto err;
	}
	if ((vs->allocatedAgreements) > 0) {
		memcpy(temp, vs->dh_agreements, sizeof(struct md_dh_agreement) * (vs->allocatedAgreements));
		pCardData->pfnCspFree(vs->dh_agreements);
	}
	vs->dh_agreements = temp;
	dh_agreement = vs->dh_agreements + (vs->allocatedAgreements);
	pAgreementInfo->bSecretAgreementIndex = (vs->allocatedAgreements);
	dh_agreement->pbAgreement = out;
	dh_agreement->dwSize = outlen;
	vs->allocatedAgreements++;

err:
	unlock(pCardData);
	return dwret;
}


DWORD WINAPI CardDeriveHashOrHMAC(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo,
	__in struct md_dh_agreement* agreement,
	__in PWSTR szAlgorithm,
	__in PBYTE pbHmacKey, __in DWORD dwHmacKeySize 
	)
{
	DWORD dwReturn = 0;
	/* CNG variables */
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD dwSize, dwHashSize;
	PBYTE pbBuffer = NULL;
	DWORD dwBufferSize = 0;
	ULONG i;
	NCryptBufferDesc* parameters = NULL;

	dwReturn = BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgorithm, NULL, (pbHmacKey?BCRYPT_ALG_HANDLE_HMAC_FLAG:0));
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to find a provider for the algorithm %S 0x%08X\n",
			  szAlgorithm, (unsigned int)dwReturn);
		goto cleanup;
	}
	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the hash length\n");
		goto cleanup;
	}
	pAgreementInfo->cbDerivedKey = dwHashSize;
	if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY) {
		dwReturn = SCARD_S_SUCCESS;
		goto cleanup;
	}
	pAgreementInfo->pbDerivedKey = (PBYTE)pCardData->pfnCspAlloc(dwHashSize);
	if (pAgreementInfo->pbDerivedKey == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}

	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBufferSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to get the buffer length 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}

	pbBuffer = (PBYTE)LocalAlloc(0, dwBufferSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0) {
		dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, pbHmacKey, dwHmacKeySize, 0);
	}
	else {
		dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, NULL, 0, 0);
	}
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to create the alg object 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}

	parameters = (NCryptBufferDesc*) pAgreementInfo->pParameterList;
	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			if (buffer->BufferType == KDF_SECRET_PREPEND) {
				dwReturn = BCryptHashData(hHash, (PUCHAR)buffer->pvBuffer, buffer->cbBuffer, 0);
				if (dwReturn) {
					logprintf(pCardData, 0,
						  "CardDeriveKey: unable to hash data 0x%08X\n",
						  (unsigned int)dwReturn);
					goto cleanup;
				}
			}
		}
	}

	dwReturn = BCryptHashData(hHash, (PUCHAR)agreement->pbAgreement, agreement->dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to hash data 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}

	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			if (buffer->BufferType == KDF_SECRET_APPEND) {
				dwReturn = BCryptHashData(hHash, (PUCHAR)buffer->pvBuffer, buffer->cbBuffer, 0);
				if (dwReturn) {
					logprintf(pCardData, 0,
						  "CardDeriveKey: unable to hash data 0x%08X\n",
						  (unsigned int)dwReturn);
					goto cleanup;
				}
			}
		}
	}

	dwReturn = BCryptFinishHash(hHash, pAgreementInfo->pbDerivedKey, pAgreementInfo->cbDerivedKey, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to finish hash 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}

cleanup:

	if (hHash)
		BCryptDestroyHash(hHash);
	if (pbBuffer)
		LocalFree(pbBuffer);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return dwReturn;
}

/* Generic function to perform hash. Could have been OpenSSL but used BCrypt* functions.
BCrypt is loaded as a delay load library. The dll can be loaded into Windows XP until this code is called.
Hopefully, ECC is not available in Windows XP and BCrypt functions are not called */
DWORD HashDataWithBCrypt(__in PCARD_DATA pCardData, BCRYPT_ALG_HANDLE hAlgorithm, 
		PBYTE pbOuput, DWORD dwOutputSize, PBYTE pbSecret, DWORD dwSecretSize, 
		PBYTE pbData1, DWORD dwDataSize1,
		PBYTE pbData2, DWORD dwDataSize2, 
		PBYTE pbData3, DWORD dwDataSize3 )
{
	DWORD dwReturn, dwSize, dwBufferSize;
	BCRYPT_HASH_HANDLE hHash = NULL;
	PBYTE pbBuffer = NULL;

	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBufferSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to get the buffer length 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}
	pbBuffer = (PBYTE)LocalAlloc(0, dwBufferSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, pbSecret, dwSecretSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to create the alg object 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}
	if (pbData1) {
		dwReturn = BCryptHashData(hHash, pbData1, dwDataSize1, 0);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: unable to hash data 0x%08X\n",
				  (unsigned int)dwReturn);
			goto cleanup;
		}
	}
	if (pbData2) {
		dwReturn = BCryptHashData(hHash, pbData2, dwDataSize2, 0);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: unable to hash data 0x%08X\n",
				  (unsigned int)dwReturn);
			goto cleanup;
		}
	}
	if (pbData3) {
		dwReturn = BCryptHashData(hHash, pbData3, dwDataSize3, 0);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: unable to hash data 0x%08X\n",
				  (unsigned int)dwReturn);
			goto cleanup;
		}
	}
	dwReturn = BCryptFinishHash(hHash, pbOuput, dwOutputSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to finish hash 0x%08X\n",
			  (unsigned int)dwReturn);
		goto cleanup;
	}
cleanup:
	if (hHash)
		BCryptDestroyHash(hHash);
	if (pbBuffer)
		LocalFree(pbBuffer);
	return dwReturn;
}

/* Generic function for TLS PRF. Compute the P_HASH function */
DWORD WINAPI DoTlsPrf(__in PCARD_DATA pCardData,
					__in PBYTE pbOutput,
					__in PBYTE pbSecret,
					__in DWORD dwSecretSize,
					__in PWSTR szAlgorithm,
					__in PBYTE pbLabel, __in DWORD dwLabelSize,
					__in PBYTE pbSeed
	)
{
	DWORD dwReturn = 0, i;
	/* CNG variables */
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	DWORD dwSize, dwHashSize, dwNumberOfRounds, dwLastRoundSize;
	PBYTE pbBuffer = NULL;
	/* TLS intermediate results */
	PBYTE pbAx = NULL;

	dwReturn = BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgorithm, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (dwReturn) {
		logprintf(pCardData, 0,
			  "CardDeriveKey: unable to find a provider for the algorithm %S 0x%08X\n",
			  szAlgorithm, (unsigned int)dwReturn);
		goto cleanup;
	}
	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the hash length\n");
		goto cleanup;
	}

	/* size is always 48 */
	dwLastRoundSize = TLS_DERIVE_KEY_SIZE % dwHashSize;
	if (dwLastRoundSize == 0) dwLastRoundSize = dwHashSize;
	dwNumberOfRounds = (DWORD) (TLS_DERIVE_KEY_SIZE / dwHashSize) + (dwLastRoundSize == dwHashSize?0:1);

	/* store TLS A1, A2 intermediate operations */
	pbAx = (PBYTE) LocalAlloc(0, dwNumberOfRounds * dwHashSize);
	if (pbAx == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}

	pbBuffer = (PBYTE) LocalAlloc(0, dwHashSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	
	for (i = 0; i<dwNumberOfRounds; i++) {
		/* A1, A2, ... */
		if (i == 0) {
			/* A(1) = HMAC_hash(secret, label + seed)*/
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbAx, dwHashSize, pbSecret, dwSecretSize, 
					pbLabel, dwLabelSize,
					pbSeed, 64, 
					NULL, 0);
		} else {
			/* A(i) = HMAC_hash(secret, A(i-1))*/
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbAx + i * dwHashSize, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + (i-1) * dwHashSize, dwHashSize,
					NULL, 0, 
					NULL, 0);
		}
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: unable to hash %S 0x%08X\n",
				  szAlgorithm, (unsigned int)dwReturn);
			goto cleanup;
		}
		if (dwNumberOfRounds -1 == i) {
			/* last round */
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbBuffer, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + i * dwHashSize, dwHashSize,
					pbLabel, dwLabelSize,
					pbSeed, 64);
			memcpy(pbOutput + i * dwHashSize, pbBuffer, dwLastRoundSize);
		} else {
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbOutput + i * dwHashSize, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + i * dwHashSize, dwHashSize,
					pbLabel, dwLabelSize,
					pbSeed, 64);
		}
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: unable to hash %S 0x%08X\n",
				  szAlgorithm, (unsigned int)dwReturn);
			goto cleanup;
		}
	}

cleanup:
	if (pbBuffer)
		LocalFree(pbBuffer);
	if (pbAx)
		LocalFree(pbAx);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return dwReturn;
}

/* Implement TLS 1.0, 1.1 and 1.2 PRF */
DWORD WINAPI CardDeriveTlsPrf(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo,
	__in struct md_dh_agreement* agreement,
	__in DWORD dwProtocol,
	__in PWSTR szAlgorithm,
	__in PBYTE pbLabel, __in DWORD dwLabelSize,
	__in PBYTE pbSeed
	)
{
	DWORD dwReturn = 0;
	PBYTE pbBuffer = NULL;
	DWORD i;
	if(dwProtocol == 0) {
		dwProtocol = TLS1_0_PROTOCOL_VERSION;
	} else if (dwProtocol == TLS1_0_PROTOCOL_VERSION || dwProtocol == TLS1_1_PROTOCOL_VERSION) {
		/* TLS 1.0 & 1.1 */
	} else if (dwProtocol == TLS1_2_PROTOCOL_VERSION) {
		/* TLS 1.2 */
		if (szAlgorithm && wcscmp(szAlgorithm, BCRYPT_SHA256_ALGORITHM) != 0 && wcscmp(szAlgorithm, BCRYPT_SHA384_ALGORITHM) != 0) {
			logprintf(pCardData, 0, "CardDeriveKey: The algorithm for TLS_PRF is invalid %S\n", szAlgorithm);
			return SCARD_E_INVALID_PARAMETER;
		}
	} else {
		logprintf(pCardData, 0,
			  "CardDeriveTlsPrf: TLS protocol unknown 0x%08X\n",
			  (unsigned int)dwReturn);
		return SCARD_E_INVALID_PARAMETER;
	}
	/* size is always 48 according to msdn */
	pAgreementInfo->cbDerivedKey = TLS_DERIVE_KEY_SIZE;
	if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY) {
		return SCARD_S_SUCCESS;
	}

	pAgreementInfo->pbDerivedKey = (PBYTE)pCardData->pfnCspAlloc(TLS_DERIVE_KEY_SIZE);
	if (pAgreementInfo->pbDerivedKey == NULL) {
		return SCARD_E_NO_MEMORY;
	}

	if (dwProtocol == TLS1_0_PROTOCOL_VERSION || dwProtocol == TLS1_1_PROTOCOL_VERSION) {
		/* TLS 1.0 & 1.1 */
		DWORD dwNewSecretLength = (((agreement->dwSize) + (2) - 1) / (2));
		dwReturn = DoTlsPrf(pCardData,
						pAgreementInfo->pbDerivedKey,
						agreement->pbAgreement,
						dwNewSecretLength,
						BCRYPT_MD5_ALGORITHM,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n",
				  szAlgorithm, (unsigned int)dwReturn);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
		pbBuffer = (PBYTE) LocalAlloc(0, TLS_DERIVE_KEY_SIZE);
		if (!pbBuffer) {
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return SCARD_E_NO_MEMORY;
		}
		dwReturn = DoTlsPrf(pCardData,
						pbBuffer,
						agreement->pbAgreement + dwNewSecretLength,
						dwNewSecretLength,
						BCRYPT_SHA1_ALGORITHM,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n",
				  szAlgorithm, (unsigned int)dwReturn);
			LocalFree(pbBuffer);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
		for (i = 0; i< TLS_DERIVE_KEY_SIZE; i++) {
			pAgreementInfo->pbDerivedKey[i] = pAgreementInfo->pbDerivedKey[i] ^ pbBuffer[i];
		}
		LocalFree(pbBuffer);

	} else if (dwProtocol == TLS1_2_PROTOCOL_VERSION) {
		dwReturn = DoTlsPrf(pCardData,
						pAgreementInfo->pbDerivedKey,
						agreement->pbAgreement,
						agreement->dwSize,
						szAlgorithm,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n",
				  szAlgorithm, (unsigned int)dwReturn);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
	}
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo)
{
	VENDOR_SPECIFIC *vs;
	struct md_dh_agreement* agreement = NULL;
	NCryptBufferDesc* parameters = NULL;
	ULONG i;
	DWORD dwReturn = 0;
	/* store parameter references */
	PWSTR szAlgorithm = NULL;
	PBYTE pbHmacKey = NULL;
	DWORD dwHmacKeySize = 0;
	PBYTE pbLabel = NULL;
	DWORD dwLabelSize = 0;
	PBYTE pbSeed = NULL;
	DWORD dwProtocol = 0;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeriveKey\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pAgreementInfo)
		return SCARD_E_INVALID_PARAMETER;
	if (!pAgreementInfo->dwVersion)
		return ERROR_REVISION_MISMATCH;
	if (pAgreementInfo->dwVersion > CARD_DERIVE_KEY_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if (pAgreementInfo->pwszKDF == NULL)
		return SCARD_E_INVALID_PARAMETER;
	if (pAgreementInfo->dwFlags & ~(KDF_USE_SECRET_AS_HMAC_KEY_FLAG | CARD_RETURN_KEY_HANDLE | CARD_BUFFER_SIZE_ONLY))
		return SCARD_E_INVALID_PARAMETER;

	/* according to the documentation, CARD_DERIVE_KEY_CURRENT_VERSION should be equal to 2.
	In practice it is not 2 but 1

	if ( pAgreementInfo->dwVersion < CARD_DERIVE_KEY_CURRENT_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;*/

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	/* check if the agreement index is ok */
	if (pAgreementInfo->bSecretAgreementIndex >= vs->allocatedAgreements) {
		return SCARD_E_INVALID_PARAMETER;
	}

	agreement = vs->dh_agreements + pAgreementInfo->bSecretAgreementIndex;
	if (agreement->pbAgreement == NULL) {
		return SCARD_E_INVALID_PARAMETER;
	}

	if (pAgreementInfo->dwFlags & CARD_RETURN_KEY_HANDLE ) {
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	/* find the algorithm, checks parameters */

	parameters = (NCryptBufferDesc*)pAgreementInfo->pParameterList;
	
	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			switch(buffer->BufferType) {
				case KDF_HASH_ALGORITHM:
					if (szAlgorithm != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one algorithm\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA1_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA1_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA256_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA256_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA384_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA384_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA512_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA512_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_MD5_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_MD5_ALGORITHM;
					} else {
						logprintf(pCardData, 0,
							  "CardDeriveKey: unsupported algorithm %S\n",
							  (PWSTR)buffer->pvBuffer);
						return SCARD_E_INVALID_PARAMETER;
					}
					break;
				case KDF_HMAC_KEY:
					if (pbHmacKey != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one hhmac key\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					pbHmacKey = (PBYTE) buffer->pvBuffer;
					dwHmacKeySize = buffer->cbBuffer;
					break;
				case KDF_SECRET_APPEND:
				case KDF_SECRET_PREPEND:
					/* do not throw an error for invalid arg*/
					break;
				case KDF_TLS_PRF_LABEL:
					if (pbLabel != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one Label\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					pbLabel = (PBYTE)buffer->pvBuffer;
					dwLabelSize = buffer->cbBuffer;
					break;
				case KDF_TLS_PRF_SEED:
					if (pbSeed != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one Seed\n");
						return SCARD_E_INVALID_PARAMETER;
					}
					if (buffer->cbBuffer != 64)
					{
						logprintf(pCardData, 0,
							  "CardDeriveKey: invalid seed size %lu\n",
							  buffer->cbBuffer);
						return SCARD_E_INVALID_PARAMETER;
					}
					pbSeed = (PBYTE)buffer->pvBuffer;
					break;
				case KDF_TLS_PRF_PROTOCOL:
					dwProtocol = *((PDWORD)buffer->pvBuffer);
					break;
				/*case KDF_ALGORITHMID:
				case KDF_PARTYUINFO:
				case KDF_PARTYVINFO:
				case KDF_SUPPPUBINFO:
				case KDF_SUPPPRIVINFO:
					break;*/
				default:
					logprintf(pCardData, 0,
						  "CardDeriveKey: unknown buffer type %lu\n",
						  (parameters->pBuffers + i)->BufferType);
					return SCARD_E_INVALID_PARAMETER;
			}
		}
	}
	/* default parameters */
	if (szAlgorithm == NULL && wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) != 0) {
		szAlgorithm = BCRYPT_SHA1_ALGORITHM;
	}

	/* check the values with the KDF chosen */
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HASH) == 0) {
	}
	else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0) {
		if (pbHmacKey == NULL) {
			logprintf(pCardData, 0, "CardDeriveKey: no hhmac key for hmac KDF\n");
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) == 0) {
		if (!pbSeed) {
			logprintf(pCardData, 0, "CardDeriveKey: No seed was provided\n");
			return SCARD_E_INVALID_PARAMETER;
		}
		if (!pbLabel) {
			logprintf(pCardData, 0, "CardDeriveKey: No label was provided\n");
			return SCARD_E_INVALID_PARAMETER;
		}
	} else {
		logprintf(pCardData, 0, "CardDeriveKey: unsupported KDF %S\n", pAgreementInfo->pwszKDF);
		return SCARD_E_INVALID_PARAMETER;
	}

	/* do the job for the KDF Hash & Hmac */
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HASH) == 0 ||
		wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0 ) {

		dwReturn = CardDeriveHashOrHMAC(pCardData, pAgreementInfo, agreement, szAlgorithm, pbHmacKey, dwHmacKeySize);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: got an error while deriving the Key (hash or HMAC) 0x%08X\n",
				  (unsigned int)dwReturn);
			return dwReturn;
		}

	} else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) == 0) {
		dwReturn = CardDeriveTlsPrf(pCardData, pAgreementInfo, agreement, dwProtocol, szAlgorithm, pbLabel, dwLabelSize, pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0,
				  "CardDeriveKey: got an error while deriving the Key (TlsPrf) 0x%08X\n",
				  (unsigned int)dwReturn);
			return dwReturn;
		}
	}
	/*else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_SP80056A_CONCAT ) == 0) {
	}*/


	return SCARD_S_SUCCESS;

}

DWORD WINAPI CardDestroyDHAgreement(
	__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	struct md_dh_agreement* agreement = NULL;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDestroyDHAgreement\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (bSecretAgreementIndex >= vs->allocatedAgreements) {
		return SCARD_E_INVALID_PARAMETER;
	}

	agreement = vs->dh_agreements + bSecretAgreementIndex;
	if (agreement->pbAgreement == NULL) {
		return SCARD_E_INVALID_PARAMETER;
	}
	SecureZeroMemory(agreement->pbAgreement, agreement->dwSize);
	pCardData->pfnCspFree(agreement->pbAgreement);
	agreement->pbAgreement = 0;
	agreement->dwSize = 0;
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags)
{
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallengeEx - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData,
	__in   PIN_ID PinId,
	__in   DWORD dwFlags,
	__in_bcount(cbPinData) PBYTE pbPinData,
	__in   DWORD cbPinData,
	__deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
	__out_opt PDWORD pcbSessionPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	DWORD dwret;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	unsigned int  auth_method;
	int r;
	BOOL DisplayPinpadUI = FALSE;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateEx\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardAuthenticateEx");
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 2,
		  "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%lu, Attempts %s\n",
		  (unsigned int)PinId, (unsigned int)dwFlags,
		  (unsigned long)cbPinData, pcAttemptsRemaining ? "YES" : "NO");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (PinId >= MD_MAX_PINS)
		return SCARD_E_INVALID_PARAMETER;

	pin_obj = vs->pin_objs[PinId];
	if (!pin_obj)
		return SCARD_E_INVALID_PARAMETER;

#if 0
	/* TODO do we need to return SCARD_E_UNSUPPORTED_FEATURE if the card
	 * doesn't support it or if the minidriver doesn't support it in general?
	 * */
	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN || dwFlags == CARD_AUTHENTICATE_SESSION_PIN) {
		if (! (vs->reader->capabilities & SC_READER_CAP_PIN_PAD
					|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH))
			return SCARD_E_UNSUPPORTED_FEATURE;
	}
#endif

	if (dwFlags & ~(CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN | CARD_PIN_SILENT_CONTEXT))
		return SCARD_E_INVALID_PARAMETER;

	if (dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN &&
		(ppbSessionPin == NULL || pcbSessionPin == NULL))
		return SCARD_E_INVALID_PARAMETER;

	/* using a pin pad */
	if (NULL == pbPinData) {
		if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD
					|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH))
			return SCARD_E_INVALID_PARAMETER;
		if (!(dwFlags & CARD_PIN_SILENT_CONTEXT)
				&& !(vs->ctx->flags & SC_CTX_FLAG_DISABLE_POPUPS)) {
			DisplayPinpadUI = TRUE;
		}
	}

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	/* save the pin type */
	auth_method = auth_info->auth_method;

	/* Do we need to display a prompt to enter PIN on pin pad? */
	logprintf(pCardData, 7, "PIN pad=%s, pbPinData=%p, hwndParent=%p\n",
		vs->reader->capabilities & SC_READER_CAP_PIN_PAD
		|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH
		? "yes" : "no", pbPinData, vs->hwndParent);

	if (dwFlags & CARD_AUTHENTICATE_SESSION_PIN) {
		/* check if the pin is the session pin generated by a previous authentication with a pinpad */
		if (pbPinData != NULL && cbPinData == sizeof(MAGIC_SESSION_PIN) && memcmp(MAGIC_SESSION_PIN, pbPinData, sizeof(MAGIC_SESSION_PIN)) == 0) {
			logprintf(pCardData, 2, "use magic session pin");
			pbPinData = NULL;
			cbPinData = 0;
		} else {
			/* seems we have a real session pin, set the pin type accordingly */
			logprintf(pCardData, 2,
				  "use real session pin with %lu bytes",
				  (unsigned long)cbPinData);
			auth_info->auth_method = SC_AC_SESSION;
		}
	}

	/* set the session pin according to the minidriver specification */
	if (dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN) {
		size_t session_pin_len = SC_MAX_PIN_SIZE;

		logprintf(pCardData, 2, "generating session pin");
		*ppbSessionPin = pCardData->pfnCspAlloc(SC_MAX_PIN_SIZE);
		r = md_dialog_perform_pin_operation(pCardData,
						    SC_PIN_CMD_GET_SESSION_PIN,
						    vs->p15card, pin_obj,
						    (const u8 *) pbPinData,
						    cbPinData,
						    *ppbSessionPin,
						    *ppbSessionPin != NULL ?
						    &session_pin_len : NULL,
						    DisplayPinpadUI, PinId);
		if (r) {
			if (*ppbSessionPin != NULL) {
				pCardData->pfnCspFree(*ppbSessionPin);
				*ppbSessionPin = NULL;
			}
			*pcbSessionPin = 0;
			logprintf(pCardData, 2, "generating session pin failed");
		} else {
			if (*ppbSessionPin != NULL && session_pin_len > 0) {
				logprintf(pCardData, 2,
					  "generated session pin with %"SC_FORMAT_LEN_SIZE_T"u bytes",
					  session_pin_len);

				*pcbSessionPin = session_pin_len;
			} else {
				logprintf(pCardData, 2, "session pin not supported");
				if (*ppbSessionPin != NULL) {
					pCardData->pfnCspFree(*ppbSessionPin);
					*ppbSessionPin = NULL;
				}
				*pcbSessionPin = 0;
			}
		}
	} else {
		if (pcbSessionPin) *pcbSessionPin = 0;
		if (ppbSessionPin) *ppbSessionPin = NULL;
		logprintf(pCardData, 2, "standard pin verification");
		r = md_dialog_perform_pin_operation(pCardData, SC_PIN_CMD_VERIFY, vs->p15card, pin_obj, (const u8 *) pbPinData, cbPinData, NULL, NULL, DisplayPinpadUI, PinId);
	}

	/* restore the pin type */
	auth_info->auth_method = auth_method;

	if (r)   {
		logprintf(pCardData, 1, "PIN code verification failed: %s; tries left %i\n", sc_strerror(r), auth_info->tries_left);

		if (r == SC_ERROR_AUTH_METHOD_BLOCKED) {
			if(pcAttemptsRemaining)
				(*pcAttemptsRemaining) = 0;
			return SCARD_W_CHV_BLOCKED;
		}

		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = auth_info->tries_left;
		return md_translate_OpenSC_to_Windows_error(r, SCARD_W_WRONG_CHV);
	}

	logprintf(pCardData, 2, "Pin code correct.\n");

	/* set the session pin according to the minidriver specification */
	if (dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN
			&& *pcbSessionPin == 0
			&& (vs->reader->capabilities & SC_READER_CAP_PIN_PAD
				|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH)) {
		/* If we could not generate a real session PIN, set it to a special
		 * value for pinpad authentication to force a new pinpad authentication */
		*ppbSessionPin = pCardData->pfnCspAlloc(sizeof(MAGIC_SESSION_PIN));
		if (*ppbSessionPin != NULL) {
			memcpy(*ppbSessionPin, MAGIC_SESSION_PIN, sizeof(MAGIC_SESSION_PIN));
			*pcbSessionPin = sizeof(MAGIC_SESSION_PIN);
		}
	}

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
	DWORD dwret;
	VENDOR_SPECIFIC *vs = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	int rv;
	struct sc_pkcs15_auth_info *auth_info;
	BOOL DisplayPinpadUI = FALSE;
	size_t target_len = cbTargetData;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticatorEx\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardChangeAuthenticatorEx");
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (!(dwFlags & PIN_CHANGE_FLAG_UNBLOCK) && !(dwFlags & PIN_CHANGE_FLAG_CHANGEPIN)){
		logprintf(pCardData, 1, "Unknown flag\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	if ((dwFlags & PIN_CHANGE_FLAG_UNBLOCK) && (dwFlags & PIN_CHANGE_FLAG_CHANGEPIN))
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags & PIN_CHANGE_FLAG_UNBLOCK && dwAuthenticatingPinId == dwTargetPinId)
		return SCARD_E_INVALID_PARAMETER;
	if (dwAuthenticatingPinId >= MD_MAX_PINS || dwTargetPinId >= MD_MAX_PINS)
		return SCARD_E_INVALID_PARAMETER;
	if (!vs->pin_objs[dwAuthenticatingPinId] || !vs->pin_objs[dwTargetPinId])
		return SCARD_E_INVALID_PARAMETER;

	/* according to the spec: cRetryCount MUST be zero */
	if (cRetryCount)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2,
		  "CardChangeAuthenticatorEx: AuthenticatingPinId=%u, dwFlags=0x%08X, cbAuthenticatingPinData=%lu, TargetPinId=%u, cbTargetData=%lu, Attempts %s\n",
		  (unsigned int)dwAuthenticatingPinId, (unsigned int)dwFlags,
		  (unsigned long)cbAuthenticatingPinData,
		  (unsigned int)dwTargetPinId, (unsigned long)cbTargetData,
		  pcAttemptsRemaining ? "YES" : "NO");

	if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD
				|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH)) {
		if (pbAuthenticatingPinData == NULL  || cbAuthenticatingPinData == 0)    {
			logprintf(pCardData, 1, "Invalid current PIN data\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		if (pbTargetData == NULL  || cbTargetData == 0)   {
			logprintf(pCardData, 1, "Invalid new PIN data\n");
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	/* using a pin pad */
	if (NULL == pbAuthenticatingPinData) {
		if (!(dwFlags & CARD_PIN_SILENT_CONTEXT)
				&& !(vs->ctx->flags & SC_CTX_FLAG_DISABLE_POPUPS)) {
			DisplayPinpadUI = TRUE;
		}
	}

	pin_obj = vs->pin_objs[dwTargetPinId];

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

	/* FIXME: this does not enforce dwAuthenticatingPinId */
	rv = md_dialog_perform_pin_operation(pCardData,
					     (dwFlags & PIN_CHANGE_FLAG_UNBLOCK ?
					      SC_PIN_CMD_UNBLOCK :
					      SC_PIN_CMD_CHANGE),
					     vs->p15card, pin_obj,
					     (const u8 *) pbAuthenticatingPinData,
					     cbAuthenticatingPinData,
					     pbTargetData, &target_len,
					     DisplayPinpadUI, dwTargetPinId);

	if (rv)   {
		logprintf(pCardData, 2, "Failed to %s %s PIN: '%s' (%i)\n",
																(dwFlags & PIN_CHANGE_FLAG_CHANGEPIN?"change":"unblock"),
																(dwTargetPinId==ROLE_ADMIN?"admin":"user"), sc_strerror(rv), rv);
		auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
		if (rv == SC_ERROR_AUTH_METHOD_BLOCKED) {
			if(pcAttemptsRemaining)
				(*pcAttemptsRemaining) = 0;
			return SCARD_W_CHV_BLOCKED;
		}

		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = auth_info->tries_left;
		return md_translate_OpenSC_to_Windows_error(rv, SCARD_W_WRONG_CHV);
	}

	logprintf(pCardData, 7, "returns success\n");
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags)
{

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardDeauthenticateEx PinId=%u dwFlags=0x%08X\n",
		  (unsigned int)PinId, (unsigned int)dwFlags);

	return CardDeauthenticate(pCardData, wszCARD_USER_USER, 0);
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	DWORD dwret;
	VENDOR_SPECIFIC *vs = NULL;
	struct md_pkcs15_container *cont = NULL;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerProperty\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_status(pCardData, "CardGetContainerProperty");
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 2,
		  "CardGetContainerProperty bContainerIndex=%u, wszProperty=%S, cbData=%lu, dwFlags=0x%08X\n",
		  (unsigned int)bContainerIndex, NULLWSTR(wszProperty),
		  (unsigned long)cbData, (unsigned int)dwFlags);
	if (!wszProperty)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData || !pdwDataLen)
		return SCARD_E_INVALID_PARAMETER;
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return SCARD_E_NO_KEY_CONTAINER;

	/* the test for the existence of containers is redundant with the one made in CardGetContainerInfo but CCP_PIN_IDENTIFIER does not do it */
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	cont = &vs->p15_containers[bContainerIndex];

	if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %u is empty\n",
			  (unsigned int)bContainerIndex);
		return SCARD_E_NO_KEY_CONTAINER;
	}

	if (wcscmp(CCP_CONTAINER_INFO,wszProperty)  == 0)   {
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && p->dwVersion != 0 )
				return ERROR_REVISION_MISMATCH;
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		return CardGetContainerInfo(pCardData,bContainerIndex,0,p);
	}

	if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty) == 0)   {
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;

		if (cont->prkey_obj->auth_id.len == 0)
			*p = ROLE_EVERYONE;
		else {
			size_t pinidx;
			for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
				struct sc_pkcs15_auth_info *pin_info;

				if (!vs->pin_objs[pinidx])
					continue;

				pin_info =
					(struct sc_pkcs15_auth_info *)vs->pin_objs[pinidx]->data;

				if (sc_pkcs15_compare_id(&cont->prkey_obj->auth_id,
							 &pin_info->auth_id))
					break;
			}

			if (pinidx >= MD_MAX_PINS) {
				logprintf(pCardData, 2,
					  "Could not find container %i PIN, returning no PIN needed, might not work properly\n",
					  bContainerIndex);
				*p = ROLE_EVERYONE;
			} else
				*p = (PIN_ID)pinidx;
		}

		logprintf(pCardData, 2, "Return Pin id %u\n",
			  (unsigned int)*p);
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
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
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
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 2,
		  "CardGetProperty('%S',cbData=%lu,dwFlags=%lu) called\n",
		  NULLWSTR(wszProperty), (unsigned long)cbData,
		  (unsigned long)dwFlags);

	if (!pCardData || !wszProperty)
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData || !pdwDataLen)
		return SCARD_E_INVALID_PARAMETER;

	dwret = check_card_reader_status(pCardData, "CardGetProperty");
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (wcscmp(CP_CARD_FREE_SPACE,wszProperty) == 0)   {
		PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo = (PCARD_FREE_SPACE_INFO )pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*pCardFreeSpaceInfo);
		if (cbData < sizeof(*pCardFreeSpaceInfo))
			return SCARD_E_NO_MEMORY;

		dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "Get free space error");
			return dwret;
		}
	}
	else if (wcscmp(CP_CARD_CAPABILITIES, wszProperty) == 0)   {
		PCARD_CAPABILITIES pCardCapabilities = (PCARD_CAPABILITIES )pbData;

		if (pdwDataLen)
			*pdwDataLen = sizeof(*pCardCapabilities);
		if (cbData < sizeof(*pCardCapabilities))
			return ERROR_INSUFFICIENT_BUFFER;
		dwret = md_card_capabilities(pCardData, pCardCapabilities);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}
	else if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)   {
		PCARD_KEY_SIZES pKeySizes = (PCARD_KEY_SIZES )pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*pKeySizes);
		if (cbData < sizeof(*pKeySizes))
			return ERROR_INSUFFICIENT_BUFFER;

		dwret = md_query_key_sizes(pCardData, 0, pKeySizes);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}
	else if (wcscmp(CP_CARD_READ_ONLY, wszProperty) == 0)   {
		BOOL *p = (BOOL *)pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;

		*p = md_is_read_only(pCardData);
	}
	else if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = CP_CACHE_MODE_NO_CACHE;
	}
	else if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0)   {
		BOOL *p = (BOOL *)pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = md_is_supports_X509_enrollment(pCardData);
	}
	else if (wcscmp(CP_CARD_GUID, wszProperty) == 0)   {
		struct md_file *cardid = NULL;

		md_fs_find_file(pCardData, NULL, "cardid", &cardid);
		if (!cardid)   {
			logprintf(pCardData, 2, "file 'cardid' not found\n");
			return SCARD_E_FILE_NOT_FOUND;
		}

		if (pdwDataLen)
			*pdwDataLen = (DWORD) cardid->size;
		if (cbData < cardid->size)
			return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData, cardid->blob, cardid->size);
	}
	else if (wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0)   {
		unsigned char buf[64];
		size_t buf_len = sizeof(buf);

		if (sc_hex_to_bin(vs->p15card->tokeninfo->serial_number, buf, &buf_len))   {
			buf_len = strlen(vs->p15card->tokeninfo->serial_number);
			if (buf_len > SC_MAX_SERIALNR) {
				buf_len = SC_MAX_SERIALNR;
			}
			memcpy(buf, vs->p15card->tokeninfo->serial_number, buf_len);
		}

		if (pdwDataLen)
			*pdwDataLen = (DWORD) buf_len;
		if (cbData < buf_len)
			return ERROR_INSUFFICIENT_BUFFER;

		CopyMemory(pbData, buf, buf_len);
	}
	else if (wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)   {
		PPIN_INFO p = (PPIN_INFO) pbData;

		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);

		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;

		if (p->dwVersion != PIN_INFO_CURRENT_VERSION)
			return ERROR_REVISION_MISMATCH;

		if (dwFlags >= MD_MAX_PINS)
			return SCARD_E_INVALID_PARAMETER;

		if (!vs->pin_objs[dwFlags])
			return SCARD_E_INVALID_PARAMETER;

		p->PinType = vs->reader->capabilities & SC_READER_CAP_PIN_PAD
			|| vs->p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH
			? ExternalPinType : AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags)   {
			case ROLE_ADMIN:
				logprintf(pCardData, 2,
					  "returning info on PIN ROLE_ADMIN ( Unblock ) [%lu]\n",
					  (unsigned long)dwFlags);
				p->PinPurpose = UnblockOnlyPin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
				p->dwUnblockPermission = 0;
				break;
			default:
				logprintf(pCardData, 2,
					  "returning info on normal PIN [%lu]\n",
					  (unsigned long)dwFlags);

				if (dwFlags == ROLE_USER)
					p->PinPurpose = PrimaryCardPin;
				else if (dwFlags == MD_ROLE_USER_SIGN)
					p->PinPurpose = DigitalSignaturePin;
				else
					p->PinPurpose = AuthenticationPin;

				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(dwFlags);
				p->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
				break;
		}
	}
	else if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
		size_t pinidx;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;

		memset(p, 0, sizeof(*p));
		for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
			if (!vs->pin_objs[pinidx])
				continue;

			SET_PIN(*p, (PIN_ID)pinidx);
		}
	}
	else if (wcscmp(CP_CARD_AUTHENTICATED_STATE,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;

		logprintf(pCardData, 7, "CARD_AUTHENTICATED_STATE invalid\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;

		if (dwFlags >= MD_MAX_PINS)
			return SCARD_E_INVALID_PARAMETER;

		if (!vs->pin_objs[dwFlags])
			return SCARD_E_INVALID_PARAMETER;

		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		if (vs->p15card->card->caps & SC_CARD_CAP_SESSION_PIN) {
			*p |= CARD_PIN_STRENGTH_SESSION_PIN;
		}
	}
	else if (wcscmp(CP_KEY_IMPORT_SUPPORT, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = 0;
	}
	else if (wcscmp(CP_ENUM_ALGORITHMS, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (wcscmp(CP_PADDING_SCHEMES, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (wcscmp(CP_CHAINING_MODES, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		return SCARD_E_INVALID_PARAMETER;
	}
	else   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		return SCARD_E_INVALID_PARAMETER;

	}

	logprintf(pCardData, 7, "returns '%S' ", wszProperty);
	loghex(pCardData, 7, pbData, *pdwDataLen);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardSetProperty(__in   PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen)  PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetProperty\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2,
		  "CardSetProperty wszProperty=%S, pbData=%p, cbDataLen=%lu, dwFlags=%lu",
		  NULLWSTR(wszProperty), pbData, (unsigned long)cbDataLen,
		  (unsigned long)dwFlags);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (!wszProperty)
		return SCARD_E_INVALID_PARAMETER;

	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	if (!cbDataLen)
		return SCARD_E_INVALID_PARAMETER;

	/* the following properties cannot be set according to the minidriver specifications */
	if (wcscmp(wszProperty,CP_CARD_FREE_SPACE) == 0 ||
			wcscmp(wszProperty,CP_CARD_CAPABILITIES) == 0 ||
			wcscmp(wszProperty,CP_CARD_KEYSIZES) == 0 ||
			wcscmp(wszProperty,CP_CARD_LIST_PINS) == 0 ||
			wcscmp(wszProperty,CP_CARD_AUTHENTICATED_STATE) == 0 ||
			wcscmp(wszProperty,CP_KEY_IMPORT_SUPPORT) == 0 ||
			wcscmp(wszProperty,CP_ENUM_ALGORITHMS) == 0 ||
			wcscmp(wszProperty,CP_PADDING_SCHEMES) == 0 ||
			wcscmp(wszProperty,CP_CHAINING_MODES) == 0 ||
			wcscmp(wszProperty,CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0 ||
			wcscmp(wszProperty,CP_CARD_CACHE_MODE) == 0 ||
			wcscmp(wszProperty,CP_CARD_SERIAL_NO) == 0
			)   {
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	/* the following properties can be set, but are not implemented by the minidriver */
	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0 ||
			wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0 ||
			wcscmp(CP_CARD_GUID, wszProperty) == 0 ) {
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	/* This property and CP_PIN_CONTEXT_STRING are set just prior to a call to
	 * CardAuthenticateEx if the PIN required is declared of type ExternalPinType.
	 */
	if (wcscmp(CP_PARENT_WINDOW, wszProperty) == 0) {
		if (cbDataLen != sizeof(HWND) || !pbData)   {
			return SCARD_E_INVALID_PARAMETER;
		}
		else   {
			HWND cp = *((HWND *) pbData);
			if (cp!=0 && !IsWindow(cp))
				return SCARD_E_INVALID_PARAMETER;
			vs->hwndParent = cp;
		}
		logprintf(pCardData, 3, "Saved parent window (%p)\n", vs->hwndParent);
		return SCARD_S_SUCCESS;
	}
	
	if (wcscmp(CP_PIN_CONTEXT_STRING, wszProperty) == 0) {
		vs->wszPinContext = (PWSTR) pbData;
		logprintf(pCardData, 3, "Saved PIN context string: %S\n", (PWSTR) pbData);
		return SCARD_S_SUCCESS;
	}
	logprintf(pCardData, 3, "INVALID PARAMETER\n");
	return SCARD_E_INVALID_PARAMETER;
}


// 4.8 Secure key injection


/** The CardImportSessionKey function imports a temporary session key to the card.
The session key is encrypted with a key exchange key, and the function returns a
handle of the imported session key to the caller.*/

DWORD WINAPI CardImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in VOID  *pPaddingInfo,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out CARD_KEY_HANDLE  *phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(bContainerIndex);
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pPaddingInfo);
	UNREFERENCED_PARAMETER(pwszBlobType);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(phKey);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardImportSessionKey - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The MDImportSessionKey function imports a temporary session key to the card minidriver
and returns a key handle to the caller.*/

DWORD WINAPI MDImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out PCARD_KEY_HANDLE  phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pwszBlobType);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(phKey);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "MDImportSessionKey - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The MDEncryptData function uses a key handle to encrypt data with a symmetric key.
The data is encrypted in a format that the smart card supports.*/

DWORD WINAPI MDEncryptData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags,
    __deref_out_ecount(*pcEncryptedData)
        PCARD_ENCRYPTED_DATA  *ppEncryptedData,
    __out PDWORD  pcEncryptedData
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszSecureFunction);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);
	UNREFERENCED_PARAMETER(ppEncryptedData);
	UNREFERENCED_PARAMETER(pcEncryptedData);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "MDEncryptData - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


/** The CardGetSharedKeyHandle function returns a session key handle to the caller.
Note:  The manner in which this session key has been established is outside the
scope of this specification. For example, the session key could be established
by either a permanent shared key or a key derivation algorithm that has occurred
before the call to CardGetSharedKeyHandle.*/

DWORD WINAPI CardGetSharedKeyHandle(
    __in PCARD_DATA  pCardData,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __deref_opt_out_bcount(*pcbOutput)
        PBYTE  *ppbOutput,
    __out_opt PDWORD  pcbOutput,
    __out PCARD_KEY_HANDLE  phKey
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(ppbOutput);
	UNREFERENCED_PARAMETER(pcbOutput);
	UNREFERENCED_PARAMETER(phKey);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetSharedKeyHandle - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** The CardDestroyKey function releases a temporary key on the card. The card
should delete all of the key material that is associated with that key handle.*/

DWORD WINAPI CardDestroyKey(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDestroyKey - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function can be used to get properties for a cryptographic algorithm.*/
DWORD WINAPI CardGetAlgorithmProperty (
    __in PCARD_DATA  pCardData,
    __in LPCWSTR   pwszAlgId,
    __in LPCWSTR   pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)
        PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbData);
	UNREFERENCED_PARAMETER(cbData);
	UNREFERENCED_PARAMETER(pdwDataLen);
	UNREFERENCED_PARAMETER(dwFlags);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetAlgorithmProperty - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function is used to get the properties of a key.*/
DWORD WINAPI CardGetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
    )
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbData);
	UNREFERENCED_PARAMETER(cbData);
	UNREFERENCED_PARAMETER(pdwDataLen);
	UNREFERENCED_PARAMETER(dwFlags);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetKeyProperty - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** This function is used to set the properties of a key.*/
DWORD WINAPI CardSetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(dwFlags);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetKeyProperty - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

/** CardProcessEncryptedData processes a set of encrypted data BLOBs by
sending them to the card where the data BLOBs are decrypted.*/

DWORD WINAPI CardProcessEncryptedData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_ecount(cEncryptedData)
        PCARD_ENCRYPTED_DATA  pEncryptedData,
    __in DWORD  cEncryptedData,
    __out_bcount_part_opt(cbOutput, *pdwOutputLen)
        PBYTE  pbOutput,
    __in DWORD  cbOutput,
    __out_opt PDWORD  pdwOutputLen,
    __in DWORD  dwFlags
)
{
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszSecureFunction);
	UNREFERENCED_PARAMETER(pEncryptedData);
	UNREFERENCED_PARAMETER(cEncryptedData);
	UNREFERENCED_PARAMETER(pbOutput);
	UNREFERENCED_PARAMETER(cbOutput);
	UNREFERENCED_PARAMETER(pdwOutputLen);
	UNREFERENCED_PARAMETER(dwFlags);
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardProcessEncryptedData - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData, __in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret, suppliedVersion = 0;
	CRITICAL_SECTION hScard_lock;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags & ~CARD_SECURE_KEY_INJECTION_NO_CARD_MODE)
		return SCARD_E_INVALID_PARAMETER;
	if (!(dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE)) {
		if( pCardData->hSCardCtx == 0)   {
			logprintf(pCardData, 0, "Invalid handle.\n");
			return SCARD_E_INVALID_HANDLE;
		}
		if( pCardData->hScard == 0)   {
			logprintf(pCardData, 0, "Invalid handle.\n");
			return SCARD_E_INVALID_HANDLE;
		}
	}
	else
	{
		/* secure key injection not supported */
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (pCardData->pbAtr == NULL)
		return SCARD_E_INVALID_PARAMETER;
	if ( pCardData->pwszCardName == NULL )
		return SCARD_E_INVALID_PARAMETER;
	/* <2 length or >=0x22 are not ISO compliant */
	if (pCardData->cbAtr >= 0x22 || pCardData->cbAtr <= 0x2)
		return SCARD_E_INVALID_PARAMETER;
	/* ATR beginning by 0x00 or 0xFF are not ISO compliant */
	if (pCardData->pbAtr[0] == 0xFF || pCardData->pbAtr[0] == 0x00)
		return SCARD_E_UNKNOWN_CARD;
	/* Memory management functions */
	if ( ( pCardData->pfnCspAlloc   == NULL ) ||
		( pCardData->pfnCspReAlloc == NULL ) ||
		( pCardData->pfnCspFree    == NULL ) )
		return SCARD_E_INVALID_PARAMETER;

	/* The lowest supported version is 4 - maximum is 7. */
	if (pCardData->dwVersion < MD_MINIMUM_VERSION_SUPPORTED)
		return (DWORD) ERROR_REVISION_MISMATCH;

	suppliedVersion = pCardData->dwVersion;

	/* VENDOR SPECIFIC */
	vs = pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(VENDOR_SPECIFIC));
	if (!vs)
		return SCARD_E_NO_MEMORY;
	memset(vs, 0, sizeof(VENDOR_SPECIFIC));

	InitializeCriticalSection(&vs->hScard_lock);
	lock(pCardData);

	logprintf(pCardData, 1, "==================================================================\n");
	logprintf(pCardData, 1, "\nP:%lu T:%lu pCardData:%p ",
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1,
		  "CardAcquireContext, dwVersion=%lu, name=%S,hScard=0x%08X, hSCardCtx=0x%08X\n",
		  (unsigned long)pCardData->dwVersion,
		  NULLWSTR(pCardData->pwszCardName),
		  (unsigned int)pCardData->hScard,
		  (unsigned int)pCardData->hSCardCtx);

	vs->hScard = pCardData->hScard;
	vs->hSCardCtx = pCardData->hSCardCtx;

	logprintf(pCardData, 2, "request version pCardData->dwVersion = %lu\n",
		  (unsigned long)pCardData->dwVersion);
	pCardData->dwVersion = min(pCardData->dwVersion, MD_CURRENT_VERSION_SUPPORTED);
	logprintf(pCardData, 2, "pCardData->dwVersion = %lu\n",
		  (unsigned long)pCardData->dwVersion);

	dwret = md_create_context(pCardData, vs);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_free;

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
	pCardData->pfnCardDeauthenticate = CardDeauthenticate;
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

	dwret = associate_card(pCardData);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_release;

	dwret = md_fs_init(pCardData);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_disassoc;

	logprintf(pCardData, 1, "OpenSC init done.\n");
	logprintf(pCardData, 1, "Supplied version %lu - version used %lu.\n",
		  (unsigned long)suppliedVersion,
		  (unsigned long)pCardData->dwVersion);

	if (pCardData->dwVersion >= CARD_DATA_VERSION_FIVE) {
		pCardData->pfnCardDeriveKey = CardDeriveKey;
		pCardData->pfnCardDestroyDHAgreement = CardDestroyDHAgreement;

		if (pCardData->dwVersion >= CARD_DATA_VERSION_SIX) {

			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
			if (pCardData->dwVersion >= CARD_DATA_VERSION_SEVEN) {

				pCardData->pfnMDImportSessionKey         = MDImportSessionKey;
				pCardData->pfnMDEncryptData              = MDEncryptData;
				pCardData->pfnCardImportSessionKey       = CardImportSessionKey;
				pCardData->pfnCardGetSharedKeyHandle     = CardGetSharedKeyHandle;
				pCardData->pfnCardGetAlgorithmProperty   = CardGetAlgorithmProperty;
				pCardData->pfnCardGetKeyProperty         = CardGetKeyProperty;
				pCardData->pfnCardSetKeyProperty         = CardSetKeyProperty;
				pCardData->pfnCardProcessEncryptedData   = CardProcessEncryptedData;
				pCardData->pfnCardDestroyKey             = CardDestroyKey;
				pCardData->pfnCardCreateContainerEx      = CardCreateContainerEx;
			}
		}
	}

	unlock(pCardData);

	return SCARD_S_SUCCESS;

ret_disassoc:
	disassociate_card(pCardData);

ret_release:
	sc_release_context(vs->ctx);

ret_free:
	hScard_lock = vs->hScard_lock;
	pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	pCardData->pvVendorSpecific = NULL;
	LeaveCriticalSection(&hScard_lock);
	DeleteCriticalSection(&hScard_lock);
	return dwret;
}

static DWORD associate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	int  r;
	struct sc_app_info *app_generic;
	struct sc_aid *aid;

	logprintf(pCardData, 1, "associate_card\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	/*
	 * set the addresses of the reader and card handles
	 * Our pcsc code will use these  when we call sc_ctx_use_reader
	 * We use the address of the handles as provided in the pCardData
	 */
	vs->hSCardCtx = pCardData->hSCardCtx;
	vs->hScard = pCardData->hScard;

	/* set the provided reader and card handles into ctx */
	r = sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard);
	if (r != SC_SUCCESS) {
		logprintf(pCardData, 0, "sc_ctx_use_reader() failed with %d\n", r);
		return SCARD_E_COMM_DATA_LOST;
	}

	/* should be only one reader */
	logprintf(pCardData, 5, "sc_ctx_get_reader_count(ctx): %d\n", sc_ctx_get_reader_count(vs->ctx));

	vs->reader = sc_ctx_get_reader(vs->ctx, 0);
	if (!vs->reader)
		return SCARD_E_COMM_DATA_LOST;

	r = sc_connect_card(vs->reader, &(vs->card));
	if (r != SC_SUCCESS) {
		logprintf(pCardData, 0, "Cannot connect card in reader '%s'\n", NULLSTR(vs->reader->name));
		return SCARD_E_UNKNOWN_CARD;
	}
	logprintf(pCardData, 3, "Connected card in '%s'\n", NULLSTR(vs->reader->name));

	app_generic = sc_pkcs15_get_application_by_type(vs->card, "generic");
	if (app_generic)
		logprintf(pCardData, 3, "Use generic application '%s'\n", app_generic->label);
	aid = app_generic ? &app_generic->aid : NULL;

	r = sc_pkcs15_bind(vs->card, aid, &(vs->p15card));
	logprintf(pCardData, 2, "PKCS#15 initialization result: %d, %s\n", r, sc_strerror(r));
	if (r != SC_SUCCESS) {
		logprintf(pCardData, 0, "PKCS#15 init failed.\n");
		sc_disconnect_card(vs->card);
		return SCARD_E_UNKNOWN_CARD;
	}

	vs->initialized = TRUE;

	return SCARD_S_SUCCESS;
}

static void disassociate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;

	if (!pCardData) {
		logprintf(pCardData, 1,
			  "disassociate_card called without card data\n");
		return;
	}

	logprintf(pCardData, 1, "disassociate_card\n");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		logprintf(pCardData, 1,
			  "disassociate_card called without vendor specific data\n");
		return;
	}

	memset(vs->pin_objs, 0, sizeof(vs->pin_objs));
	memset(vs->p15_containers, 0, sizeof(vs->p15_containers));

	if(vs->p15card)   {
		logprintf(pCardData, 6, "sc_pkcs15_unbind\n");
		sc_pkcs15_unbind(vs->p15card);
		vs->p15card = NULL;
	}

	if(vs->card)   {
		logprintf(pCardData, 6, "sc_disconnect_card\n");
		sc_disconnect_card(vs->card);
		vs->card = NULL;
	}

	vs->reader = NULL;

	vs->hSCardCtx = -1;
	vs->hScard = -1;
	vs->initialized = FALSE;
}


BOOL APIENTRY DllMain( HINSTANCE hinstDLL,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	CHAR name[MAX_PATH + 1] = "\0";
	char *reason = "";

	GetModuleFileNameA(GetModuleHandle(NULL),name,MAX_PATH);

	switch (ul_reason_for_call)   {
	case DLL_PROCESS_ATTACH:
		reason = "Attach Process";
		break;
	case DLL_THREAD_ATTACH:
		reason = "Attach Thread";
		break;
	case DLL_THREAD_DETACH:
		reason = "Detach Thread";
		break;
	case DLL_PROCESS_DETACH:
		reason = "Detach Process";
		break;
	}

	logprintf(NULL, 8,
		  "\n********** DllMain Module(handle:0x%p) '%s'; reason='%s'; Reserved=%p; P:%lu; T:%lu\n",
		  hinstDLL, name, reason, lpReserved,
		  (unsigned long)GetCurrentProcessId(),
		  (unsigned long)GetCurrentThreadId());
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_inst = hinstDLL;
		sc_notify_instance = hinstDLL;
		sc_notify_init();
		break;
	case DLL_PROCESS_DETACH:
		sc_notify_close();
		if (lpReserved == NULL) {
#if defined(ENABLE_OPENSSL) && defined(OPENSSL_SECURE_MALLOC_SIZE)
			CRYPTO_secure_malloc_done();
#endif
#ifdef ENABLE_OPENPACE
			EAC_cleanup();
#endif
		}
		break;
	}
	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
#endif
