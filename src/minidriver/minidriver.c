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
#include <time.h>

#include <windows.h>
#include "cardmod.h"

#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "pkcs15init/pkcs15-init.h"

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/pem.h>
#endif
#endif

#if defined(__MINGW32__)
/* Part of the build svn project in the include directory */
#include "cardmod-mingw-compat.h"
#endif

/* store the instance given at DllMain when attached to access internal resources */
HINSTANCE g_inst;

#define MD_MINIMUM_VERSION_SUPPORTED 4
#define MD_CURRENT_VERSION_SUPPORTED 7

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

#define MD_MAX_KEY_CONTAINERS 12
#define MD_CARDID_SIZE 16

#define MD_UTC_TIME_LENGTH_MAX	16
#define MD_CARDCF_LENGTH	(sizeof(CARD_CACHE_FILE_FORMAT))

#define MD_DATA_APPLICAITON_NAME "CSP"
#define MD_DATA_DEFAULT_CONT_LABEL "Default Key Container"

#define MD_KEY_USAGE_KEYEXCHANGE		\
	SC_PKCS15INIT_X509_KEY_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DATA_ENCIPHERMENT	| \
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
#define IDD_PINPAD      101
#define IDI_LOGO        102
#define IDC_PINPAD_TEXT 1001
#define IDC_PINPAD_ICON 1000

/* magic to determine previous pinpad authentication */
#define MAGIC_SESSION_PIN "opensc-minidriver"

struct md_directory {
	unsigned char parent[9];
	unsigned char name[9];

	CARD_DIRECTORY_ACCESS_CONDITION acl;

	struct md_file *files;
	struct md_directory *subdirs;

	struct md_directory *next;
};

struct md_file {
	unsigned char parent[9];
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
	unsigned flags;
	size_t size_key_exchange, size_sign;

	struct sc_pkcs15_object *cert_obj, *prkey_obj, *pubkey_obj;
};

typedef struct _VENDOR_SPECIFIC
{
	struct sc_pkcs15_object *obj_user_pin, *obj_sopin;

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
}VENDOR_SPECIFIC;

/*
 * Windows (ex. Vista) may access the card from more the one thread.
 * The following data type and static data is an attemt to resolve
 * some of the encountered multi-thread issues of OpenSC
 * on the minidriver side.
 *
 * TODO: resolve multi-thread issues on the OpenSC side
 */
#define MD_STATIC_FLAG_READ_ONLY			1
#define MD_STATIC_FLAG_SUPPORTS_X509_ENROLLMENT		2
#define MD_STATIC_FLAG_CONTEXT_DELETED			4
#define MD_STATIC_FLAG_GUID_AS_ID			8
#define MD_STATIC_FLAG_GUID_AS_LABEL			16
#define MD_STATIC_FLAG_CREATE_CONTAINER_KEY_IMPORT	32
#define MD_STATIC_FLAG_CREATE_CONTAINER_KEY_GEN		64
#define MD_STATIC_FLAG_IGNORE_PIN_LENGTH		128

#define MD_STATIC_PROCESS_ATTACHED		0xA11AC4EDL
struct md_opensc_static_data {
	unsigned flags, flags_checked;
	unsigned long attach_check;
};
static struct md_opensc_static_data md_static_data;


#define C_ASN1_MD_CONTAINER_ATTRS_SIZE 7
static const struct sc_asn1_entry c_asn1_md_container_attrs[C_ASN1_MD_CONTAINER_ATTRS_SIZE] = {
	{ "index", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "id", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "guid", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_EMPTY_ALLOWED, NULL, NULL },
	{ "flags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
	{ "sizeKeyExchange", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "sizeSign", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_MD_CONTAINER_SIZE 2
static const struct sc_asn1_entry c_asn1_md_container[C_ASN1_MD_CONTAINER_SIZE] = {
	{ "mdContainer", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int associate_card(PCARD_DATA pCardData);
static int disassociate_card(PCARD_DATA pCardData);
static DWORD md_get_cardcf(PCARD_DATA pCardData, CARD_CACHE_FILE_FORMAT **out);
static DWORD md_pkcs15_delete_object(PCARD_DATA pCardData, struct sc_pkcs15_object *obj);
static DWORD md_fs_init(PCARD_DATA pCardData);

static void logprintf(PCARD_DATA pCardData, int level, _Printf_format_string_ const char* format, ...)
{
	va_list arg;
	VENDOR_SPECIFIC *vs;
#define CARDMOD_LOW_LEVEL_DEBUG 1
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

		lldebugfp = fopen("C:\\tmp\\md.log","a+");
		if (lldebugfp)   {
			va_start(arg, format);
			vfprintf(lldebugfp, format, arg);
			va_end(arg);
			fflush(lldebugfp);
			fclose(lldebugfp);
			lldebugfp = NULL;
		}
	}
#endif

	va_start(arg, format);
	if(pCardData != NULL)   {
		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(vs != NULL && vs->ctx != NULL)   {
#ifdef _MSC_VER
			sc_do_log_noframe(vs->ctx, level, format, arg);
#else
			/* FIXME: trouble in vsprintf with %S arg under mingw32 */
			if(vs->ctx->debug>=level) {
				vfprintf(vs->ctx->debug_file, format, arg);
			}
#endif
		}
	}
	va_end(arg);
}

static void loghex(PCARD_DATA pCardData, int level, PBYTE data, size_t len)
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

static void print_werror(PCARD_DATA pCardData, PSTR str)
{
	void *buf;
	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), 0, (LPSTR) &buf, 0, NULL);

	logprintf(pCardData, 0, "%s%s\n", str, (PSTR) buf);
	LocalFree(buf);
}

/*
 * check if the card has been removed, or the
 * caller has changed the handles.
 * if so, then free up all previous card info
 * and reestablish
 */
static int
check_reader_status(PCARD_DATA pCardData)
{
	int r = SCARD_S_SUCCESS;
	VENDOR_SPECIFIC *vs = NULL;

	logprintf(pCardData, 4, "check_reader_status\n");
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 7, "pCardData->hSCardCtx:0x%08X hScard:0x%08X\n",
			pCardData->hSCardCtx, pCardData->hScard);

	if (pCardData->hSCardCtx != vs->hSCardCtx || pCardData->hScard != vs->hScard) {
		logprintf (pCardData, 1, "HANDLES CHANGED from 0x%08X 0x%08X\n", vs->hSCardCtx, vs->hScard);

		/* Basically a mini AcquireContext */
		r = disassociate_card(pCardData);
		logprintf(pCardData, 1, "disassociate_card r = 0x%08X\n", r);
		r = associate_card(pCardData); /* need to check return codes */
		if (r != SCARD_S_SUCCESS) 
			return r;
		logprintf(pCardData, 1, "associate_card r = 0x%08X\n", r);
		/* Rebuild 'soft' fs - in case changed */
		r = md_fs_init(pCardData);
		logprintf(pCardData, 1, "md_fs_init r = 0x%08X\n", r);
	}
	else if (vs->reader) {
		/* This should always work, as BaseCSP should be checking for removal too */
		r = sc_detect_card_presence(vs->reader);
		logprintf(pCardData, 2, "check_reader_status r=%d flags 0x%08X\n", r, vs->reader->flags);
	}

	return r;
}

static DWORD
md_get_pin_by_role(PCARD_DATA pCardData, PIN_ID role, struct sc_pkcs15_object **ret_obj)
{
	VENDOR_SPECIFIC *vs;
	int rv = SC_SUCCESS;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!ret_obj)
		return SCARD_E_INVALID_PARAMETER;

	*ret_obj = NULL;

	if (role == ROLE_USER)   {
		if (!vs->obj_user_pin)   {
			/* Get 'global' User PIN; if no, get the 'local' one */
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &vs->obj_user_pin);
			if (rv)
				rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
						SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &vs->obj_user_pin);
		}

		*ret_obj = vs->obj_user_pin;
	}
	else if (role == ROLE_ADMIN)  {
		/* Get SO PIN; if no, get the 'global' PUK; if no get the 'local' one  */
		if (!vs->obj_sopin)   {
			rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_SOPIN,
					SC_PKCS15_PIN_TYPE_FLAGS_SOPIN, NULL, &vs->obj_sopin);
			if (rv)
				rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL,
						SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &vs->obj_sopin);
			if (rv)
				rv = sc_pkcs15_find_pin_by_flags(vs->p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL,
						SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &vs->obj_sopin);
		}

		*ret_obj = vs->obj_sopin;
	}
	else   {
		logprintf(pCardData, 2, "cannot get PIN object: unsupported role\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	return (rv == SC_SUCCESS) ? SCARD_S_SUCCESS : SCARD_E_UNSUPPORTED_FEATURE;
}


static BOOL
md_get_config_bool(PCARD_DATA pCardData, char *flag_name, unsigned flag, BOOL ret_default)
{
	VENDOR_SPECIFIC *vs;
	BOOL ret = ret_default;

	if (!pCardData)
		return ret;

	logprintf(pCardData, 2, "Get '%s' option\n", flag_name);
	if (md_static_data.flags_checked & flag)   {
		ret = (md_static_data.flags & flag) ? TRUE : FALSE;
		logprintf(pCardData, 2, "Returns checked flag: %s\n", ret ? "TRUE" : "FALSE");
		return ret;
	}

	vs = pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader)   {
		/* TODO: use atr from pCardData */
		scconf_block *atrblock = _sc_match_atr_block(vs->ctx, NULL, &vs->reader->atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, vs->reader->atr.value, vs->reader->atr.len);

		if (atrblock)
			ret = scconf_get_bool(atrblock, flag_name, ret_default) ? TRUE : FALSE;
	}

	md_static_data.flags_checked |= flag;
	if (ret == TRUE)
		md_static_data.flags |= flag;
	else
		md_static_data.flags &= ~flag;

	logprintf(pCardData, 2, "Returns '%s' flag '%s', static flags/checked %X/%X\n",
			flag_name, ret ? "TRUE" : "FALSE",
			md_static_data.flags, md_static_data.flags_checked);
	return ret;
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_read_only(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is read-only?\n");
	return md_get_config_bool(pCardData, "md_read_only", MD_STATIC_FLAG_READ_ONLY, TRUE);
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_supports_X509_enrollment(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports X509 enrollment?\n");
	return md_get_config_bool(pCardData, "md_supports_X509_enrollment", MD_STATIC_FLAG_SUPPORTS_X509_ENROLLMENT, FALSE);
}


/* Get know if the GUID has to used as ID of crypto objects */
static BOOL
md_is_guid_as_id(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as ID of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_id", MD_STATIC_FLAG_GUID_AS_ID, FALSE);
}


/* Get know if the GUID has to used as label of crypto objects */
static BOOL
md_is_guid_as_label(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as label of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_label", MD_STATIC_FLAG_GUID_AS_LABEL, FALSE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_GEN mechanism */
static BOOL
md_is_supports_container_key_gen(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key generation' create_container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_gen", MD_STATIC_FLAG_CREATE_CONTAINER_KEY_GEN, TRUE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_IMPORT mechanism */
static BOOL
md_is_supports_container_key_import(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key import' create container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_import", MD_STATIC_FLAG_CREATE_CONTAINER_KEY_IMPORT, TRUE);
}


/* Check if specified PIN has been verified */
static BOOL
md_is_pin_set(PCARD_DATA pCardData, DWORD role)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;

	if (!pCardData)
		return FALSE;
	vs = pCardData->pvVendorSpecific;

	if (md_get_cardcf(pCardData, &cardcf) != SCARD_S_SUCCESS)
		return FALSE;

	return IS_PIN_SET(cardcf->bPinsFreshness, role);
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
	if (!parent)
		parent = &vs->root;

	if (!name)   {
		dir = parent;
	}
	else   {
		dir = parent->subdirs;
		while(dir)   {
			if (!strcmp(dir->name, name))
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

	strncpy(new_dir->name, name, sizeof(new_dir->name) - 1);
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
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (out)
		*out = NULL;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
		return dwret;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}

	for (file = dir->files; file!=NULL;)   {
		if (!strcmp(file->name, name))
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

	strncpy(new_file->name, name, sizeof(new_file->name) - 1);
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

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
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

	if (!strcmp(dir->files->name, name))   {
		file_to_rm = dir->files;
		dir->files = dir->files->next;
		md_fs_free_file(pCardData, file_to_rm);
		dwret = SCARD_S_SUCCESS;
	}
	else   {
		for (file = dir->files; file!=NULL; file = file->next)   {
			if (!file->next)
				break;
			if (!strcmp(file->next->name, name))   {
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
				logprintf(pCardData, 2, "Cannot delete certificate PKCS#15 object #%i: dwret 0x%X\n", idx, dwret);
		}
	}

	return dwret;
}

static DWORD
md_fs_finalize(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL, *file_to_rm;
	struct md_directory *dir = NULL, *dir_to_rm;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	file = vs->root.files;
	while (file != NULL) {
		file_to_rm = file;
		file = file->next;
		md_fs_free_file(pCardData, file_to_rm);
	}

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
	return 0;
}

static DWORD
md_pkcs15_encode_cardcf(PCARD_DATA pCardData, unsigned char *in, size_t in_size,
		unsigned char *out, size_t *out_size)
{
	VENDOR_SPECIFIC *vs;
	char *last_update = NULL;

	if (!pCardData || !in || in_size < MD_CARDCF_LENGTH
			|| !out || !out_size || *out_size < MD_CARDCF_LENGTH)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	memcpy(out, in, MD_CARDCF_LENGTH);

	/* write down 'cardcf' with cleared PinsFreshness */
	((CARD_CACHE_FILE_FORMAT *)out)->bPinsFreshness = PIN_SET_NONE;

	last_update = sc_pkcs15_get_lastupdate(vs->p15card);
	if (!last_update || (*out_size < MD_CARDCF_LENGTH + MD_UTC_TIME_LENGTH_MAX))   {
		*out_size = MD_CARDCF_LENGTH;
	}
	else   {
		size_t lu_size = strlen(last_update);

		if (lu_size > MD_UTC_TIME_LENGTH_MAX)
			lu_size = MD_UTC_TIME_LENGTH_MAX;

		memcpy(out + MD_CARDCF_LENGTH, last_update, lu_size);
		if (lu_size < MD_UTC_TIME_LENGTH_MAX)
			memset(out + MD_CARDCF_LENGTH + lu_size, 0, MD_UTC_TIME_LENGTH_MAX - lu_size);

		*out_size = MD_CARDCF_LENGTH + MD_UTC_TIME_LENGTH_MAX;
	}
	return SCARD_S_SUCCESS;
}


static DWORD
md_pkcs15_encode_cmapfile(PCARD_DATA pCardData, unsigned char **out, size_t *out_len)
{
	VENDOR_SPECIFIC *vs;
	unsigned char *encoded, *ret, *p;
	size_t guid_len, encoded_len, flags_len, ret_len;
	int idx;

	if (!pCardData || !out || !out_len)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	logprintf(pCardData, 2, "encode P15 'cmapfile'\n");

	ret = NULL, ret_len = 0;
	for (idx=0; idx<MD_MAX_KEY_CONTAINERS; idx++)   {
		struct sc_asn1_entry asn1_md_container_attrs[C_ASN1_MD_CONTAINER_ATTRS_SIZE];
		struct sc_asn1_entry asn1_md_container[C_ASN1_MD_CONTAINER_SIZE];
		struct md_pkcs15_container cont = vs->p15_containers[idx];
		int rv;

		if (!cont.id.len && !strlen(cont.guid))
			continue;

		sc_copy_asn1_entry(c_asn1_md_container_attrs, asn1_md_container_attrs);
		sc_copy_asn1_entry(c_asn1_md_container, asn1_md_container);

		guid_len = strlen(cont.guid);
		flags_len = sizeof(size_t);
		sc_format_asn1_entry(asn1_md_container_attrs + 0, &cont.index, NULL, 1);
		sc_format_asn1_entry(asn1_md_container_attrs + 1, &cont.id, NULL, 1);
		sc_format_asn1_entry(asn1_md_container_attrs + 2, cont.guid, &guid_len, 1);
		sc_format_asn1_entry(asn1_md_container_attrs + 3, &cont.flags, &flags_len, 1);
		sc_format_asn1_entry(asn1_md_container_attrs + 4, &cont.size_key_exchange, NULL, 1);
		sc_format_asn1_entry(asn1_md_container_attrs + 5, &cont.size_sign, NULL, 1);

		sc_format_asn1_entry(asn1_md_container + 0, asn1_md_container_attrs, NULL, 1);

		rv = sc_asn1_encode(vs->ctx, asn1_md_container, &encoded, &encoded_len);
		if (rv < 0) {
			logprintf(pCardData, 3, "MdEncodeCMapFile(): ASN1 encode error(%i): %s\n", rv, sc_strerror(rv));
			return SCARD_F_INTERNAL_ERROR;
		}

		p = realloc(ret, ret_len + encoded_len);
		if (!p)   {
			logprintf(pCardData, 3, "MdEncodeCMapFile(): realloc failed\n");
			free(ret);
			return SCARD_E_NO_MEMORY;
		}
		ret = p;
		memcpy(ret + ret_len, encoded, encoded_len);
		free(encoded);
		ret_len += encoded_len;
	}

	logprintf(pCardData, 3, "encoded P15 'cmapfile':\n");
	loghex(pCardData, 3, ret, ret_len);

	*out = ret;
	*out_len = ret_len;

	return SCARD_S_SUCCESS;
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
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	int nn_records, idx;

	if (!pCardData || !blob || size < sizeof(CONTAINER_MAP_RECORD))
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	nn_records = (int) size/sizeof(CONTAINER_MAP_RECORD);
	if (nn_records > MD_MAX_KEY_CONTAINERS)
		nn_records = MD_MAX_KEY_CONTAINERS;

	for (idx=0, pp = (CONTAINER_MAP_RECORD *)blob; idx<nn_records; idx++, pp++)   {
		struct md_pkcs15_container *cont = &(vs->p15_containers[idx]);
		size_t count;

		count = wcstombs(cont->guid, pp->wszGuid, sizeof(cont->guid));
		if (!count)   {
			memset(cont, 0, sizeof(CONTAINER_MAP_RECORD));
		}
		else   {
			cont->index = idx;
			cont->flags = pp->bFlags;
			cont->size_sign = pp->wSigKeySizeBits;
			cont->size_key_exchange = pp->wKeyExchangeKeySizeBits;
			logprintf(pCardData, 3, "update P15 containers: touch container (idx:%i,id:%s,guid:%s,flags:%X)\n",
				idx, sc_pkcs15_print_id(&cont->id),cont->guid,cont->flags);
		}
	}

	return SCARD_S_SUCCESS;
}

static DWORD
md_pkcs15_update_container_from_do(PCARD_DATA pCardData, struct sc_pkcs15_object *dobj)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	struct sc_pkcs15_data *ddata = NULL;
	struct sc_pkcs15_id id;
	int rv, offs, idx;
	unsigned flags;

	if (!pCardData || !dobj)
		return SCARD_E_INVALID_PARAMETER;
	vs = pCardData->pvVendorSpecific;

	rv = sc_pkcs15_read_data_object(vs->p15card, (struct sc_pkcs15_data_info *)dobj->data, &ddata);
	if (rv)   {
		logprintf(pCardData, 2, "sc_pkcs15_read_data_object('%s') returned %i\n", dobj->label, rv);
		return SCARD_F_INTERNAL_ERROR;
	}

	offs = 0;
	if (*(ddata->data + offs++) != 0x01)   {
		sc_pkcs15_free_data_object(ddata);
		return SCARD_E_INVALID_VALUE;
	}
	id.len = *(ddata->data + offs++);
	memcpy(id.value, ddata->data + offs, id.len);
	offs += (int) id.len;

	if (*(ddata->data + offs++) != 0x02)   {
		sc_pkcs15_free_data_object(ddata);
		return SCARD_E_INVALID_VALUE;
	}
	if (*(ddata->data + offs++) != 0x01)   {
		sc_pkcs15_free_data_object(ddata);
		return SCARD_E_INVALID_VALUE;
	}

	flags = *(ddata->data + offs);

	for (idx=0; idx<MD_MAX_KEY_CONTAINERS && vs->p15_containers[idx].prkey_obj; idx++)   {
		if (sc_pkcs15_compare_id(&id, &vs->p15_containers[idx].id))   {
			snprintf(vs->p15_containers[idx].guid, sizeof(vs->p15_containers[idx].guid),
					"%s", dobj->label);
			vs->p15_containers[idx].flags = flags;
			logprintf(pCardData, 2, "Set container's guid to '%s' and flags to 0x%X\n",
					vs->p15_containers[idx].guid, flags);
			break;
		}
	}

	sc_pkcs15_free_data_object(ddata);
	return SCARD_S_SUCCESS;
}


static DWORD
md_pkcs15_default_container_from_do(PCARD_DATA pCardData, struct sc_pkcs15_object *dobj)
{
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_data *ddata = NULL;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	int rv, idx;
	char guid[MAX_CONTAINER_NAME_LEN + 1];

	if (!pCardData || !dobj)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;

	rv = sc_pkcs15_read_data_object(vs->p15card, (struct sc_pkcs15_data_info *)dobj->data, &ddata);
	if (rv)   {
		logprintf(pCardData, 2, "sc_pkcs15_read_data_object('%s') returned %i\n", dobj->label, rv);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (ddata->data_len > MAX_CONTAINER_NAME_LEN || ddata->data_len < 32)   {
		logprintf(pCardData, 2, "Invalid container name length %i\n", ddata->data_len);
		return SCARD_E_INVALID_VALUE;
	}

	memset(guid, 0, sizeof(guid));
	memcpy(&guid[0] , ddata->data, ddata->data_len);

	logprintf(pCardData, 2, "Search container '%s' to set it as default\n", guid);
	for (idx=0; idx<MD_MAX_KEY_CONTAINERS && vs->p15_containers[idx].prkey_obj; idx++)   {
		if (strstr(vs->p15_containers[idx].guid, guid))   {
			vs->p15_containers[idx].flags |= CONTAINER_MAP_DEFAULT_CONTAINER;
			logprintf(pCardData, 2, "Default container is '%s'\n", vs->p15_containers[idx].guid);
			break;
		}
	}

	sc_pkcs15_free_data_object(ddata);
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
	card = vs->p15card->card;

	if (!obj)
		return SCARD_S_SUCCESS;
	logprintf(pCardData, 3, "MdDeleteObject('%s',type:0x%X) called\n", obj->label, obj->type);

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdDeleteObject(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, app_info, &profile);
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

	if (!strcmp(file->name, "cmapfile"))
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

		for (offs=0; offs < MD_CARDID_SIZE; )   {
			wr = MD_CARDID_SIZE - offs;
			if (wr > sn_len)
				wr = sn_len;
			memcpy(cardid_bin + offs, sn_bin, wr);
			offs += wr;
		}

		dwret = md_fs_set_content(pCardData, file, cardid_bin, MD_CARDID_SIZE);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}

	logprintf(pCardData, 3, "cardid(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/* fill the msroot file from root certificates */
static void
md_fs_read_msroot_file(PCARD_DATA pCardData, char *parent, struct md_file *file)
{
	CERT_BLOB dbStore = {0};
	HCERTSTORE hCertStore = NULL;
	DWORD dwret = 0;
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];

	hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, (HCRYPTPROV_LEGACY) NULL, 0, NULL);
	if (!hCertStore) {
		dwret = GetLastError();
		goto Ret;
	}

	vs = (VENDOR_SPECIFIC *) pCardData->pvVendorSpecific;

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
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
				logprintf(pCardData, 2, "unable to load the certificate from windows 0x%08X\n", GetLastError());
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
		dwret = GetLastError();
		goto Ret;
	}

	dbStore.pbData = (PBYTE) pCardData->pfnCspAlloc(dbStore.cbData);

	if (NULL == dbStore.pbData) {
		dwret = ERROR_NOT_ENOUGH_MEMORY;
		goto Ret;
	}

	if (FALSE == CertSaveStore(	hCertStore,
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				CERT_STORE_SAVE_AS_PKCS7,
				CERT_STORE_SAVE_TO_MEMORY,
				&dbStore,
				0))
	{
		dwret = GetLastError();
		goto Ret;
	}
	file->size = dbStore.cbData;
	file->blob = dbStore.pbData;
	dbStore.pbData = NULL;
Ret:
	if (dbStore.pbData)
		pCardData->pfnCspFree(dbStore.pbData);
	if (hCertStore)
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
}

/*
 * Return content of the 'soft' file.
 */
static void
md_fs_read_content(PCARD_DATA pCardData, char *parent, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (!pCardData || !file)
		return;

	vs = pCardData->pvVendorSpecific;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "find directory '%s' error: %X\n", parent ? parent : "<null>", dwret);
		return;
	}
	else if (!dir)   {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return;
	}
	if (vs->p15card == NULL) {
		return SCARD_F_INTERNAL_ERROR;
	}

	if (!strcmp(dir->name, "mscp"))   {
		int idx, rv;

		if(sscanf(file->name, "ksc%d", &idx) > 0)   {
		}
		else if(sscanf(file->name, "kxc%d", &idx) > 0)   {
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
				return;
			}

			file->size = cert->data.len;
			file->blob = pCardData->pfnCspAlloc(cert->data.len);
			CopyMemory(file->blob, cert->data.value, cert->data.len);
			sc_pkcs15_free_certificate(cert);
		}
		if (!strcmp(file->name, "msroot")) {
			md_fs_read_msroot_file(pCardData, parent, file);
		}
	}
	else   {
		return;
	}
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
	VENDOR_SPECIFIC *vs;
	char *last_update = NULL;
	CARD_CACHE_FILE_FORMAT empty;
	size_t empty_len = sizeof(empty);
	DWORD dwret;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	memset(&empty, 0, sizeof(empty));
	empty.bVersion = CARD_CACHE_FILE_CURRENT_VERSION;

	last_update = sc_pkcs15_get_lastupdate(vs->p15card);
	if (vs->p15card->md_data)    {
		logprintf(pCardData, 2, "Set 'cardcf' using internal MD data\n");
		empty.wContainersFreshness = vs->p15card->md_data->cardcf.cont_freshness;
		empty.wFilesFreshness = vs->p15card->md_data->cardcf.files_freshness;
	}
	else if (last_update)   {
		unsigned crc32 = sc_crc32(last_update, strlen(last_update));

		logprintf(pCardData, 2, "Set 'cardcf' using lastUpdate '%s'; CRC32 %X\n", last_update, crc32);
		empty.wContainersFreshness = crc32;
		empty.wFilesFreshness = crc32;
	}
	else   {
		logprintf(pCardData, 2, "Set 'cardcf' using random value\n");
		srand((unsigned)time(NULL));
		empty.wContainersFreshness = rand()%30000;
		empty.wFilesFreshness = rand()%30000;
	}

	dwret = md_fs_set_content(pCardData, file, (unsigned char *)(&empty), MD_CARDCF_LENGTH);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "'cardcf' content(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/*
 * Return content of the 'soft' 'cardcf' file
 */
static DWORD
md_get_cardcf(PCARD_DATA pCardData, CARD_CACHE_FILE_FORMAT **out)
{
	struct md_file *file = NULL;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	md_fs_find_file(pCardData, NULL, "cardcf", &file);
	if (!file)   {
		logprintf(pCardData, 2, "file 'cardcf' not found\n");
		return SCARD_E_FILE_NOT_FOUND;
	}
	if (!file->blob || file->size < MD_CARDCF_LENGTH)
		return SCARD_E_INVALID_VALUE;
	if (out)
		*out = (CARD_CACHE_FILE_FORMAT *)file->blob;

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

	logprintf(pCardData, 3, "mscp(%i)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/* check if the card has root certificates. If yes, notify the base csp by creating the msroot file */
static DWORD
md_fs_add_msroot(PCARD_DATA pCardData, struct md_file **head)
{
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	DWORD dwret;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	if (!pCardData || !head)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *) pCardData->pvVendorSpecific;

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_S_SUCCESS;
	}
	cert_num = rv;
	for(ii = 0; ii < cert_num; ii++)   {
		struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) prkey_objs[ii]->data;
		if (cert_info->authority) {
			dwret = md_fs_add_file(pCardData, head, "msroot", EveryoneReadUserWriteAc, NULL, 0, NULL);
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
 *        If some record from the 'DATA' object references an existing key:
 *    2a. Update the non-pkcs#15 attributes of the corresponding internal p15_container;
 *    2b. Change the index of internal p15_container according to the index from 'DATA' file.
 *        Records from 'DATA' file are ignored is they do not have
 *            the corresponding PKCS#15 private key object.
 * 3. Initalize the content of the 'soft' 'cmapfile' from the inernal p15-containers.
 */
static DWORD
md_set_cmapfile(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	PCONTAINER_MAP_RECORD p;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	unsigned char *cmap_buf = NULL;
	size_t cmap_len;
	DWORD dwret;
	int ii, rv, conts_num, found_default = 0;
	/* struct sc_pkcs15_data *data_object; */
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 0, "set 'cmapfile'\n");
	vs = pCardData->pvVendorSpecific;
	cmap_len = MD_MAX_KEY_CONTAINERS*sizeof(CONTAINER_MAP_RECORD);
	cmap_buf = pCardData->pfnCspAlloc(cmap_len);
	if(!cmap_buf)
		return SCARD_E_NO_MEMORY;
	memset(cmap_buf, 0, cmap_len);

	rv = sc_pkcs15_get_objects(vs->p15card, SC_PKCS15_TYPE_PRKEY_RSA, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0)   {
		logprintf(pCardData, 0, "Private key enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_F_UNKNOWN_ERROR;
	}

	conts_num = rv;
	logprintf(pCardData, 2, "Found %d private key(s) in the card.\n", conts_num);

	/* Initialize the P15 container array with the existing keys */
	for(ii = 0; ii < conts_num; ii++)   {
		struct sc_pkcs15_object *key_obj = prkey_objs[ii], *cert_obj = NULL;
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
		struct md_pkcs15_container *cont = &vs->p15_containers[ii];

		if(key_obj->type != SC_PKCS15_TYPE_PRKEY_RSA)   {
			logprintf(pCardData, 7, "Non 'RSA' key (type:%X) are ignored\n", key_obj->type);
			continue;
		}

		if (prkey_info->cmap_record.guid)   {
			strncpy(cont->guid, prkey_info->cmap_record.guid, sizeof(cont->guid));

			cont->size_key_exchange = prkey_info->cmap_record.keysize_keyexchange;
			cont->size_sign = prkey_info->cmap_record.keysize_sign;

			cont->flags = prkey_info->cmap_record.flags;
			if (cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER)
				found_default = 1;
		}
		else   {
			size_t guid_len;

			memset(cont->guid, 0, sizeof(cont->guid));
			guid_len = sizeof(cont->guid);

			rv = sc_pkcs15_get_object_guid(vs->p15card, key_obj, 0, cont->guid, &guid_len);
			if (rv)   {
				logprintf(pCardData, 2, "sc_pkcs15_get_object_guid() error %d\n", rv);
				return SCARD_F_INTERNAL_ERROR;
			}

			cont->flags = CONTAINER_MAP_VALID_CONTAINER;

			/* AT_KEYEXCHANGE is more general key usage,
			 *	it allows 'decryption' as well as 'signature' key usage.
			 * AT_SIGNATURE allows only 'signature' usage.
			 */
			cont->size_key_exchange = cont->size_sign = 0;
			if (prkey_info->usage & USAGE_ANY_DECIPHER)
				cont->size_key_exchange = prkey_info->modulus_length;
			else if (prkey_info->usage & USAGE_ANY_SIGN)
				cont->size_sign = prkey_info->modulus_length;
			else
				cont->size_key_exchange = prkey_info->modulus_length;
		}

		logprintf(pCardData, 7, "Container[%i]'s guid=%s\n", ii, cont->guid);
		logprintf(pCardData, 7, "Container[%i]'s key-exchange:%i, sign:%i\n", ii, cont->size_key_exchange, cont->size_sign);

		cont->id = prkey_info->id;
		cont->prkey_obj = prkey_objs[ii];

		/* Try to find the friend objects: certficate and public key */
		if (!sc_pkcs15_find_cert_by_id(vs->p15card, &cont->id, &cont->cert_obj))
			logprintf(pCardData, 2, "found certificate friend '%s'\n", cont->cert_obj->label);

		if (!sc_pkcs15_find_pubkey_by_id(vs->p15card, &cont->id, &cont->pubkey_obj))
			logprintf(pCardData, 2, "found public key friend '%s'\n", cont->pubkey_obj->label);
	}

	if (conts_num)   {
		/* Read 'CMAPFILE' (Gemalto style) and update the attributes of P15 containers */
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

			if (strcmp(dinfo->app_label, MD_DATA_APPLICAITON_NAME))
				continue;

			logprintf(pCardData, 2, "Found 'DATA' object '%s'\n", dobjs[ii]->label);
			if (!strcmp(dobjs[ii]->label, MD_DATA_DEFAULT_CONT_LABEL))   {
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

		/* Initialize 'CMAPFILE' content from the P15 containers */
		p = (PCONTAINER_MAP_RECORD)cmap_buf;
		for (ii=0; ii<MD_MAX_KEY_CONTAINERS; ii++)   {
			struct sc_pkcs15_object *cert_obj = NULL;

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
					snprintf((char *)k_name, sizeof(k_name), "kxc%02i", ii);
					dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
					if (dwret != SCARD_S_SUCCESS)
						return dwret;
				}

				if (vs->p15_containers[ii].size_sign)   {
					snprintf((char *)k_name, sizeof(k_name), "ksc%02i", ii);
					dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, NULL, 0, NULL);
					if (dwret != SCARD_S_SUCCESS)
						return dwret;
				}
			}

			logprintf(pCardData, 7, "cmapfile entry(%d) '%s' ",ii, vs->p15_containers[ii].guid);
			loghex(pCardData, 7, (PBYTE) (p+ii), sizeof(CONTAINER_MAP_RECORD));
		}
	}
	
	dwret = md_fs_add_msroot(pCardData, &(file->next));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_set_content(pCardData, file, cmap_buf, cmap_len);
	pCardData->pfnCspFree(cmap_buf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "cmap(%i)\n", file->size);
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
		return dwret;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardcf", EveryoneReadUserWriteAc, NULL, 0, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardcf(pCardData, cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardapps", EveryoneReadAdminWriteAc, NULL, 0, &cardapps);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardapps(pCardData, cardapps);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_directory(pCardData, &(vs->root.subdirs), "mscp", UserCreateDeleteDirAc, &mscp);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_add_file(pCardData, &(mscp->files), "cmapfile", EveryoneReadUserWriteAc, NULL, 0, &cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cmapfile(pCardData, cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

#ifdef OPENSSL_VERSION_NUMBER
	logprintf(pCardData, 3, "MD virtual file system initialized; OPENSSL_VERSION_NUMBER 0x%Xl\n", OPENSSL_VERSION_NUMBER);
#else
	logprintf(pCardData, 3, "MD virtual file system initialized; Without OPENSSL\n");
#endif
	return SCARD_S_SUCCESS;
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

	if (key_type == AT_SIGNATURE || key_type == AT_KEYEXCHANGE)   {
		key_algo = SC_ALGORITHM_RSA;
	}
	else   {
		logprintf(pCardData, 3, "Unsupported key type: 0x%X\n", key_type);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (flags & CARD_CREATE_CONTAINER_KEY_IMPORT)   {
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

		if (pub_rsa->magic == 0x31415352 || pub_rsa->magic == 0x32415352)   {
			key_size = pub_rsa->bitlen;
		}
		else {
			logprintf(pCardData, 3, "'Magic' control failed\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		logprintf(pCardData, 3, "Set key size to %i\n", key_size);
	}

	count = vs->p15card->card->algorithm_count;
	for (algo_info = vs->p15card->card->algorithms; count--; algo_info++) {
		if (algo_info->algorithm != key_algo || algo_info->key_length != key_size)
			continue;
		logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
		return SCARD_S_SUCCESS;
	}

	logprintf(pCardData, 3, "No card support for key(type:0x%X,size:0x%X)\n", key_type, key_size);
	return SCARD_E_UNSUPPORTED_FEATURE;
}


static DWORD
md_pkcs15_generate_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, DWORD key_size)
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
	DWORD dw, dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	card = vs->p15card->card;

	memset(&pub_args, 0, sizeof(pub_args));
	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.prkey_args.label = "TODO: key label";
	keygen_args.pubkey_label = "TODO: key label";

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
	else    {
		logprintf(pCardData, 3, "MdGenerateKey(): unsupported key type: 0x%X\n", key_type);
		return SCARD_E_INVALID_PARAMETER;
	}

	keygen_args.prkey_args.access_flags = MD_KEY_ACCESS;

	dw = md_get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (dw != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "MdGenerateKey(): cannot get User PIN object");
		return dw;
	}

	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	keygen_args.prkey_args.auth_id = pub_args.auth_id = auth_info->auth_id;

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, app_info, &profile);
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
	if (strlen(cont->guid))   {
		logprintf(pCardData, 3, "MdGenerateKey(): generate key(idx:%i,guid:%s)\n", idx, cont->guid);
		keygen_args.prkey_args.guid = cont->guid;
		keygen_args.prkey_args.guid_len = strlen(cont->guid);
	}

	if (md_is_guid_as_id(pCardData))  {
		if (strlen(cont->guid) > sizeof(keygen_args.prkey_args.id.value))   {
			logprintf(pCardData, 3, "MdGenerateKey(): cannot set ID -- invalid GUID length\n");
			goto done;
		}

		memcpy(keygen_args.prkey_args.id.value, cont->guid, strlen(cont->guid));
		keygen_args.prkey_args.id.len = strlen(cont->guid);
		logprintf(pCardData, 3, "MdGenerateKey(): use ID:%s\n", sc_pkcs15_print_id(&keygen_args.prkey_args.id));
	}

	if (md_is_guid_as_label(pCardData))  {
		keygen_args.prkey_args.label =  cont->guid;
		logprintf(pCardData, 3, "MdGenerateKey(): use label '%s'\n", keygen_args.prkey_args.label);
	}

	rv = sc_pkcs15init_generate_key(vs->p15card, profile, &keygen_args, key_size, &cont->prkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdGenerateKey(): key generation failed: sc-error %i\n", rv);
		goto done;
	}

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags = CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3, "MdGenerateKey(): generated key(idx:%i,id:%s,guid:%s)\n",
			idx, sc_pkcs15_print_id(&cont->id),cont->guid);

	dwret = SCARD_S_SUCCESS;
done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}


static DWORD
md_pkcs15_store_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, BYTE *blob, DWORD blob_size)
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
	char *label = NULL;
	BYTE *ptr = blob;
	EVP_PKEY *pkey=NULL;
	int rv;
	DWORD dw, dwret = SCARD_F_INTERNAL_ERROR;
	BOOL is_guid_as_id = FALSE;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	card = vs->p15card->card;

	pkey = b2i_PrivateKey(&ptr, blob_size);
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
		logprintf(pCardData, 3, "MdStoreKey(): unsupported key type: 0x%X\n", key_type);
		return SCARD_E_INVALID_PARAMETER;
	}

	prkey_args.access_flags = MD_KEY_ACCESS;

	dw = md_get_pin_by_role(pCardData, ROLE_USER, &pin_obj);
	if (dw != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "MdStoreKey(): cannot get User PIN object");
		return dw;
	}

	prkey_args.auth_id = ((struct sc_pkcs15_auth_info *) pin_obj->data)->auth_id;

	rv = sc_lock(card);
	if (rv)   {
		logprintf(pCardData, 3, "MdStoreKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = vs->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, app_info, &profile);
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
	if (strlen(cont->guid))   {
		logprintf(pCardData, 3, "MdStoreKey(): store key(idx:%i,id:%s,guid:%s)\n", idx, sc_pkcs15_print_id(&cont->id), cont->guid);
		prkey_args.guid = cont->guid;
		prkey_args.guid_len = strlen(cont->guid);
	}

	if (md_is_guid_as_id(pCardData))  {
		if (strlen(cont->guid) > sizeof(prkey_args.id.value))   {
			logprintf(pCardData, 3, "MdStoreKey(): cannot set ID -- invalid GUID length\n");
			goto done;
		}

		memcpy(prkey_args.id.value, cont->guid, strlen(cont->guid));
		prkey_args.id.len = strlen(cont->guid);

		memcpy(pubkey_args.id.value, cont->guid, strlen(cont->guid));
		pubkey_args.id.len = strlen(cont->guid);

		logprintf(pCardData, 3, "MdStoreKey(): use ID:%s\n", sc_pkcs15_print_id(&prkey_args.id));
	}

	if (md_is_guid_as_label(pCardData))  {
		prkey_args.label =  cont->guid;
		pubkey_args.label =  cont->guid;
		logprintf(pCardData, 3, "MdStoreKey(): use label '%s'\n", prkey_args.label);
	}

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

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags |= CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3, "MdStoreKey(): stored key(idx:%i,id:%s,guid:%s)\n", idx, sc_pkcs15_print_id(&cont->id),cont->guid);
	dwret = SCARD_S_SUCCESS;

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
	card = vs->p15card->card;

	memset(&args, 0, sizeof(args));
	args.der_encoded.value = blob;
	args.der_encoded.len = len;
	args.update = 1;

	/* use container's ID as ID of certificate to store */
	idx = -1;
	if(sscanf(file_name, "ksc%d", &idx) > 0)
		;
	else if(sscanf(file_name, "kxc%d", &idx) > 0)
		;

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
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, app_info, &profile);
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
md_query_key_sizes(CARD_KEY_SIZES *pKeySizes)
{
	if (!pKeySizes)
		return SCARD_E_INVALID_PARAMETER;

	if (pKeySizes->dwVersion != CARD_KEY_SIZES_CURRENT_VERSION && pKeySizes->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwMinimumBitlen = 1024;
	pKeySizes->dwDefaultBitlen = 2048;
	pKeySizes->dwMaximumBitlen = 2048;
	pKeySizes->dwIncrementalBitlen = 1024;

	return SCARD_S_SUCCESS;
}

static VOID CenterWindow(HWND hwndWindow, HWND hwndParent)
{
	RECT rectWindow, rectParent;
	int nWidth,nHeight, nScreenWidth, nScreenHeight;
	int nX, nY;
	GetWindowRect(hwndWindow, &rectWindow);

	nWidth = rectWindow.right - rectWindow.left;
	nHeight = rectWindow.bottom - rectWindow.top;

	nScreenWidth = GetSystemMetrics(SM_CXSCREEN);
	nScreenHeight = GetSystemMetrics(SM_CYSCREEN);

     // make the window relative to its parent
     if (hwndParent != NULL) {
		 GetWindowRect(hwndParent, &rectParent);
         nX = ((rectParent.right - rectParent.left) - nWidth) / 2 + rectParent.left;
         nY = ((rectParent.bottom - rectParent.top) - nHeight) / 2 + rectParent.top;
	 }
	 else {
		 nX = (nScreenWidth - nWidth) /2;
		 nY = (nScreenHeight - nHeight) /2;
	 }
	// make sure that the dialog box never moves outside of the screen
	if (nX < 0) nX = 0;
	if (nY < 0) nY = 0;
	if (nX + nWidth > nScreenWidth) nX = nScreenWidth - nWidth;
	if (nY + nHeight > nScreenHeight) nY = nScreenHeight - nHeight;
 
    MoveWindow(hwndWindow, nX, nY, nWidth, nHeight, TRUE);
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
	size_t pin2len = parameter[6];
	int rv = 0;
	switch (operation)
	{
	case SC_PIN_CMD_VERIFY:
		rv = sc_pkcs15_verify_pin(p15card, pin_obj, pin1, pin1len);
		break;
	case SC_PIN_CMD_CHANGE:
		rv = sc_pkcs15_change_pin(p15card, pin_obj, pin1, pin1len,pin2, pin2len);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = sc_pkcs15_unblock_pin(p15card, pin_obj, pin1, pin1len,pin2, pin2len);
		break;
	default:
		rv = (DWORD) ERROR_INVALID_PARAMETER;
		break;
	}
	if (parameter[9] != 0) {
		EndDialog((HWND) parameter[9], rv);
	}
	return (DWORD) rv;
}

static INT_PTR CALLBACK md_dialog_proc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(wParam);
	switch (message)
	{
	case WM_INITDIALOG:
		{
			HICON hIcon = NULL;
			PCARD_DATA pCardData = (PCARD_DATA) (((LONG_PTR*)lParam)[7]);
			VENDOR_SPECIFIC* vs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
			/* store parameter like pCardData for further use if needed */
			SetWindowLongPtr(hWnd, GWLP_USERDATA, lParam);
			/* change the text shown on the screen */
			if (vs->wszPinContext )   {
				SetWindowTextW(GetDlgItem(hWnd, IDC_PINPAD_TEXT), vs->wszPinContext );
			}
			CenterWindow(hWnd, vs->hwndParent);
			/* load the information icon */
			hIcon = (HICON) LoadImage(0, IDI_INFORMATION, IMAGE_ICON, 0, 0, LR_SHARED);
			SendMessage(GetDlgItem(hWnd, IDC_PINPAD_ICON),STM_SETIMAGE,IMAGE_ICON, (LPARAM) hIcon);
			/* change the icon */
			hIcon = LoadIcon(g_inst, MAKEINTRESOURCE(IDI_LOGO));
			if (hIcon)
			{
				SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hIcon);
				SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hIcon);
			}
			/* launch the function in another thread context store the thread handle */
			((LONG_PTR*)lParam)[9] = (LONG_PTR) hWnd;
			((LONG_PTR*)lParam)[8] = (LONG_PTR) CreateThread(NULL, 0, md_dialog_perform_pin_operation_thread, (PVOID) lParam, 0, NULL);
		}
		return TRUE;
	case WM_DESTROY:
		{
			/* clean resources used */
			LPARAM param = GetWindowLongPtr(hWnd, GWLP_USERDATA);
			if (param) {
				HANDLE hThread = (HANDLE)((LONG_PTR*)param)[8];
				CloseHandle(hThread);
			}
		}
		break;
	}
	return FALSE;
}



static int 
md_dialog_perform_pin_operation(PCARD_DATA pCardData, int operation, struct sc_pkcs15_card *p15card,
			 struct sc_pkcs15_object *pin_obj,
			 const u8 *pin1, size_t pin1len,
			 const u8 *pin2, size_t pin2len, BOOL displayUI)
{
	LONG_PTR parameter[10];
	INT_PTR result = 0;
	HWND hWndDlg = 0;
	int rv = 0;
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
	parameter[8] = 0; /* place holder for thread handle */
	parameter[9] = 0; /* place holder for window handle */
	/* launch the function to perform in the same thread context */
	if (!displayUI) {
		rv = md_dialog_perform_pin_operation_thread(parameter);
		SecureZeroMemory(parameter, sizeof(parameter));
		return rv;
	}
	/* launch the UI in the same thread context than the parent and the function to perform in another thread context 
	this is the only way to display a modal dialog attached to a parent (hwndParent != 0) */
	result = DialogBoxParam(g_inst, MAKEINTRESOURCE(IDD_PINPAD), pv->hwndParent, md_dialog_proc, (LPARAM) parameter);
	SecureZeroMemory(parameter, sizeof(parameter));
	return (int) result;
}

DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror, DWORD dwDefaulCode)
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

	if (md_static_data.attach_check != MD_STATIC_PROCESS_ATTACHED)
		return SCARD_S_SUCCESS;

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p hScard=0x%08X hSCardCtx=0x%08X CardDeleteContext\n",
			GetCurrentProcessId(), GetCurrentThreadId(), pCardData, pCardData->hScard, pCardData->hSCardCtx);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	disassociate_card(pCardData);

	if(vs->ctx)   {
		logprintf(pCardData, 6, "release context\n");
		sc_release_context(vs->ctx);
		md_static_data.flags |= MD_STATIC_FLAG_CONTEXT_DELETED;
		vs->ctx = NULL;
	}

	logprintf(pCardData, 1, "**********************************************************************\n");

	md_fs_finalize(pCardData);
	pCardData->pfnCspFree(pCardData->pvVendorSpecific);
	pCardData->pvVendorSpecific = NULL;

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData,
	__inout PCARD_CAPABILITIES  pCardCapabilities)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "pCardCapabilities=%p\n", pCardCapabilities);

	if (!pCardData || !pCardCapabilities)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_card_capabilities(pCardData, pCardCapabilities);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	check_reader_status(pCardData);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteContainer(idx:%i)\n", bContainerIndex);

	logprintf(pCardData, 1, "CardDeleteContainer() not supported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}


DWORD WINAPI CardCreateContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwret;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateContainer(idx:%i,flags:%X,type:%X,size:%i,data:%p)\n",
			bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);

	if (pbKeyData)   {
		logprintf(pCardData, 7, "Key data\n");
		loghex(pCardData, 7, pbKeyData, dwKeySize);
	}

	dwret = md_check_key_compatibility(pCardData, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "check key compatibility failed\n");
		return dwret;
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
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (dwFlags & CARD_CREATE_CONTAINER_KEY_GEN)   {
		dwret = md_pkcs15_generate_key(pCardData, bContainerIndex, dwKeySpec, dwKeySize);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key generation failed\n");
			return dwret;
		}
		logprintf(pCardData, 1, "key generated\n");
	}
	else if ((dwFlags & CARD_CREATE_CONTAINER_KEY_IMPORT) && (pbKeyData != NULL)) {
		dwret = md_pkcs15_store_key(pCardData, bContainerIndex, dwKeySpec, pbKeyData, dwKeySize);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key store failed\n");
			return dwret;
		}
		logprintf(pCardData, 1, "key imported\n");
	}
	else   {
		logprintf(pCardData, 1, "Invalid dwFlags value: 0x%X\n", dwFlags);
		return SCARD_E_INVALID_PARAMETER;
	}

	return SCARD_S_SUCCESS;
}


typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBKEYSTRUCT_BASE;

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
	__inout PCONTAINER_INFO pContainerInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD sz = 0;
	DWORD ret = SCARD_F_UNKNOWN_ERROR;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15_der pubkey_der;
	int rv;

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pContainerInfo)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, " \
		"dwVersion=%u, cbSigPublicKey=%u, cbKeyExPublicKey=%u\n", \
		bContainerIndex, dwFlags, pContainerInfo->dwVersion, \
		pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return SCARD_E_NO_KEY_CONTAINER;
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	cont = &vs->p15_containers[bContainerIndex];

	if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %i is empty\n", bContainerIndex);
		return SCARD_E_NO_KEY_CONTAINER;
	}

	if (vs->p15card == NULL) {
		return SCARD_F_INTERNAL_ERROR;
	}

	check_reader_status(pCardData);
	pubkey_der.value = NULL;
	pubkey_der.len = 0;

	if ((cont->prkey_obj->content.value != NULL) && (cont->prkey_obj->content.len > 0))   {
		sc_der_copy(&pubkey_der, &cont->prkey_obj->content);
		ret = SCARD_S_SUCCESS;
	}

	if (!pubkey_der.value && cont->pubkey_obj)   {
		struct sc_pkcs15_pubkey *pubkey = NULL;

		logprintf(pCardData, 1, "now read public key '%s'\n", cont->pubkey_obj->label);
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

		logprintf(pCardData, 1, "now read certificate '%s'\n", cont->cert_obj->label);
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
			logprintf(pCardData, 1, "certificate '%d' read error %d\n", bContainerIndex, rv);
			ret = SCARD_E_FILE_NOT_FOUND;
		}
	}

	if (!pubkey_der.value && (cont->size_sign || cont->size_key_exchange)) {
		logprintf(pCardData, 2, "cannot find public key\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	if (ret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 7, "GetContainerInfo(idx:%i) failed; error %X", bContainerIndex, ret);
		return ret;
	}

	logprintf(pCardData, 7, "SubjectPublicKeyInfo:\n");
	loghex(pCardData, 7, pubkey_der.value, pubkey_der.len);

	if (pubkey_der.len && pubkey_der.value)   {
		sz = 0; /* get size */
		CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
				pubkey_der.value, (DWORD) pubkey_der.len, 0, NULL, &sz);

		if (cont->size_sign)   {
			PUBKEYSTRUCT_BASE *oh = (PUBKEYSTRUCT_BASE *)pCardData->pfnCspAlloc(sz);
			if (!oh)
				return SCARD_E_NO_MEMORY;

			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
					pubkey_der.value, (DWORD) pubkey_der.len, 0, oh, &sz);

			oh->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
			pContainerInfo->cbSigPublicKey = sz;
			pContainerInfo->pbSigPublicKey = (PBYTE)oh;

			logprintf(pCardData, 3, "return info on SIGN_CONTAINER_INDEX %i\n", bContainerIndex);
		}

		if (cont->size_key_exchange)   {
			PUBKEYSTRUCT_BASE *oh = (PUBKEYSTRUCT_BASE*)pCardData->pfnCspAlloc(sz);
			if (!oh)
				return SCARD_E_NO_MEMORY;

			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
					pubkey_der.value, (DWORD) pubkey_der.len, 0, oh, &sz);

			oh->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
			pContainerInfo->cbKeyExPublicKey = sz;
			pContainerInfo->pbKeyExPublicKey = (PBYTE)oh;

			logprintf(pCardData, 3, "return info on KEYX_CONTAINER_INDEX %i\n", bContainerIndex);
		}
	}

	logprintf(pCardData, 7, "returns container(idx:%i) info", bContainerIndex);
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbPin) PBYTE pbPin,
	__in DWORD cbPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	PIN_ID PinId = 0;
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticatePin '%S':%d\n", NULLWSTR(pwszUserId), cbPin);

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
	int rv;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetChallenge\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbChallengeData || !pcbChallengeData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "Asked challenge length %i, buffer %p\n", *pcbChallengeData, *ppbChallengeData);
	if (pcbChallengeData == NULL)   {
		*ppbChallengeData = NULL;

		logprintf(pCardData, 7, "returns zero bytes\n");
		return SCARD_S_SUCCESS;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	*pcbChallengeData = 8;

	*ppbChallengeData = (PBYTE) pCardData->pfnCspAlloc(8);
	if (!*ppbChallengeData)
		return SCARD_E_NO_MEMORY;

	rv = sc_get_challenge(vs->p15card->card, *ppbChallengeData, 8);
	if (rv)   {
		logprintf(pCardData, 1, "Get challenge failed: %s\n", sc_strerror(rv));
		pCardData->pfnCspFree(*ppbChallengeData);
		*ppbChallengeData = NULL;
		return SCARD_E_UNEXPECTED;
	}

	logprintf(pCardData, 7, "returns %i bytes:\n", *pcbChallengeData);
	loghex(pCardData, 7, *ppbChallengeData, *pcbChallengeData);
	return SCARD_S_SUCCESS;
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
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardUnblockPin\n");

	if (pwszUserId == NULL)
		return SCARD_E_INVALID_PARAMETER;
	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN,pwszUserId) != 0)
		return SCARD_E_INVALID_PARAMETER;
	if (wcscmp(wszCARD_USER_ADMIN, pwszUserId) == 0)
		return SCARD_E_UNSUPPORTED_FEATURE;
	if (dwFlags & CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)
		return SCARD_E_UNSUPPORTED_FEATURE;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "UserID('%S'), AuthData(%p, %u), NewPIN(%p, %u), Retry(%u), dwFlags(0x%X)\n",
			pwszUserId, pbAuthenticationData, cbAuthenticationData, pbNewPinData, cbNewPinData,
			cRetryCount, dwFlags);

	return CardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_UNBLOCK | CARD_PIN_SILENT_CONTEXT, ROLE_ADMIN, pbAuthenticationData, cbAuthenticationData, ROLE_USER, pbNewPinData, cbNewPinData, cRetryCount, NULL);
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
	PIN_ID pinid;
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticator\n");

	if (pwszUserId == NULL)
		return SCARD_E_INVALID_PARAMETER;

	if (dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)   {
		logprintf(pCardData, 1, "Other then 'authentication' the PIN are not supported\n");
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	else if (dwFlags != CARD_AUTHENTICATE_PIN_PIN){
		return SCARD_E_INVALID_PARAMETER;
	}

	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN, pwszUserId) != 0)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "UserID('%S'), CurrentPIN(%p, %u), NewPIN(%p, %u), Retry(%u), dwFlags(0x%X)\n",
			pwszUserId, pbCurrentAuthenticator, cbCurrentAuthenticator, pbNewAuthenticator, cbNewAuthenticator,
			cRetryCount, dwFlags);

	if (wcscmp(wszCARD_USER_USER, pwszUserId) == 0)
		pinid = ROLE_USER;
	else
		pinid = ROLE_ADMIN;

	return CardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_CHANGEPIN | CARD_PIN_SILENT_CONTEXT, pinid, pbCurrentAuthenticator, cbCurrentAuthenticator, pinid, pbNewAuthenticator, cbNewAuthenticator, cRetryCount, pcAttemptsRemaining);
}

/* this function is not called on purpose.
If a deauthentication is not possible, it should be set to NULL in CardAcquireContext.
Because this function do nothing - it is not called.
Note: the PIN freshnesh will be managed by the Base CSP*/
DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	struct md_file *cmapfile = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticate(%S) %d\n", NULLWSTR(pwszUserId), dwFlags);

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	logprintf(pCardData, 1, "CardDeauthenticate bPinsFreshness:%d\n", cardcf->bPinsFreshness);

	if (!wcscmp(pwszUserId, wszCARD_USER_USER))
		CLEAR_PIN(cardcf->bPinsFreshness, ROLE_USER);
	else if (!wcscmp(pwszUserId, wszCARD_USER_ADMIN))
		CLEAR_PIN(cardcf->bPinsFreshness, ROLE_ADMIN);
	else
		return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 5, "PinsFreshness = %d\n",  cardcf->bPinsFreshness);

	/* TODO Reset PKCS#15 PIN object 'validated' flag */

	/* force a reset of a card - SCARD_S_SUCCESS do not lead to the reset of the card and leave it still authenticated */
	return SCARD_E_UNSUPPORTED_FEATURE;
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardCreateFile(%s::%s, size %i, acl:0x%X) called\n",
			NULLSTR(pszDirectoryName), NULLSTR(pszFileName), cbInitialCreationSize, AccessCondition);

	dwret = md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardCreateFile() cannot find parent directory '%s'", NULLSTR(pszDirectoryName));
		return dwret;
	}

	dwret = md_fs_add_file(pCardData, &dir->files, pszFileName, AccessCondition, NULL, cbInitialCreationSize, NULL);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount_opt(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardReadFile\n");

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!ppbData || !pcbData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 2, "pszDirectoryName = %s, pszFileName = %s, dwFlags = %X, pcbData=%u, *ppbData=%X\n",
		NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags, *pcbData, *ppbData);

	if (!pszFileName || !strlen(pszFileName))
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;

	check_reader_status(pCardData);

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardReadFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	if (!file->blob)
		md_fs_read_content(pCardData, pszDirectoryName, file);

	*ppbData = pCardData->pfnCspAlloc(file->size);
	if(!*ppbData)
		return SCARD_E_NO_MEMORY;
	*pcbData = (DWORD) file->size;
	memcpy(*ppbData, file->blob, file->size);

	logprintf(pCardData, 7, "returns '%s' content:\n",  NULLSTR(pszFileName));
	loghex(pCardData, 7, *ppbData, *pcbData);
	return SCARD_S_SUCCESS;
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

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardWriteFile() dirName:'%s', fileName:'%s' \n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	check_reader_status(pCardData);

	if (pbData && cbData)   {
		logprintf(pCardData, 1, "CardWriteFile try to write (%i):\n", cbData);
		loghex(pCardData, 2, pbData, cbData);
	}

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	logprintf(pCardData, 7, "set content of '%s' to:\n",  NULLSTR(pszFileName));
	loghex(pCardData, 7, pbData, cbData);

	dwret = md_fs_set_content(pCardData, file, pbData, cbData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "cannot set file content: %li\n", dwret);
		return dwret;
	}

	if (pszDirectoryName && !strcmp(pszDirectoryName, "mscp"))   {
		if ((strstr(pszFileName, "kxc") == pszFileName) || (strstr(pszFileName, "ksc") == pszFileName))	{
			dwret = md_pkcs15_store_certificate(pCardData, pszFileName, pbData, cbData);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;
			logprintf(pCardData, 2, "md_pkcs15_store_certificate() OK\n");
		}
	}

	logprintf(pCardData, 2, "write '%s' ok.\n",  NULLSTR(pszFileName));
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags)
{
	struct md_file *file = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeleteFile(%s, %s) called\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName));

	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	check_reader_status(pCardData);

	dwret = md_fs_delete_file(pCardData, pszDirectoryName, pszFileName);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "CardDeleteFile(): delete file error: %X\n", dwret);
		return dwret;
	}

	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__deref_out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	char mstr[0x100];
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
	size_t offs;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardEnumFiles() directory '%s'\n", NULLSTR(pszDirectoryName));

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pmszFileNames || !pdwcbFileName)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)   {
		logprintf(pCardData, 1, "CardEnumFiles() dwFlags not 'zero' -- %X\n", dwFlags);
		return SCARD_E_INVALID_PARAMETER;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	memset(mstr, 0, sizeof(mstr));

	if (!pszDirectoryName || !strlen(pszDirectoryName))
		dir = &vs->root;
	else
		md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (!dir)   {
		logprintf(pCardData, 2, "enum files() failed: directory '%s' not found\n", NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	file = dir->files;
	for (offs = 0; file != NULL && offs < sizeof(mstr) - 10;)   {
		logprintf(pCardData, 2, "enum files(): file name '%s'\n", file->name);
		strcpy(mstr+offs, file->name);
		offs += strlen(file->name) + 1;
		file = file->next;
	}
	offs += 1;

	*pmszFileNames = (LPSTR)(*pCardData->pfnCspAlloc)(offs);
	if (*pmszFileNames == NULL)
		return SCARD_E_NO_MEMORY;

	CopyMemory(*pmszFileNames, mstr, offs);
	*pdwcbFileName = (DWORD) offs;
	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__inout PCARD_FILE_INFO pCardFileInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetFileInfo(dirName:'%s',fileName:'%s', out %p)\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), pCardFileInfo);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		return SCARD_E_FILE_NOT_FOUND;
	}

	pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	pCardFileInfo->cbFileSize = (DWORD) file->size;
	pCardFileInfo->AccessCondition = file->acl;

	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
	__inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardQueryFreeSpace %p, dwFlags=%X, version=%X\n",
		pCardFreeSpaceInfo, dwFlags, pCardFreeSpaceInfo->dwVersion);

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardQueryFreeSpace() md free space error");
		return dwret;
	}

	logprintf(pCardData, 7, "FreeSpace:\n");
	loghex(pCardData, 7, (BYTE *)pCardFreeSpaceInfo, sizeof(*pCardFreeSpaceInfo));
	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__inout PCARD_KEY_SIZES pKeySizes)
{
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardQueryKeySizes dwKeySpec=%X, dwFlags=%X, version=%X\n",  dwKeySpec, dwFlags, (pKeySizes?pKeySizes->dwVersion:0));

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if ( dwFlags != 0 )
		return SCARD_E_INVALID_PARAMETER;
	switch(dwKeySpec)
	{
		case AT_ECDHE_P256 :
		case AT_ECDHE_P384 :
		case AT_ECDHE_P521 :
		case AT_ECDSA_P256 :
		case AT_ECDSA_P384 :
		case AT_ECDSA_P521 :
			return SCARD_E_UNSUPPORTED_FEATURE;
		case AT_KEYEXCHANGE:
		case AT_SIGNATURE  :
			break;
		default:
			return SCARD_E_INVALID_PARAMETER;
	}

	dwret = md_query_key_sizes(pKeySizes);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 7, "pKeySizes:\n");
	loghex(pCardData, 7, (BYTE *)pKeySizes, sizeof(*pKeySizes));
	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo)

{
	int r, opt_crypt_flags = 0;
	unsigned ui;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_prkey_info *prkey_info;
	BYTE *pbuf = NULL, *pbuf2 = NULL;
	DWORD lg= 0, lg2 = 0;
	struct sc_pkcs15_object *pkey = NULL;
	struct sc_algorithm_info *alg_info = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardRSADecrypt\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!pInfo)
		return SCARD_E_INVALID_PARAMETER;
	if ( pInfo->pbData == NULL )
		return SCARD_E_INVALID_PARAMETER;
	if (pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if ( pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	/* check if the container exists */
	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return SCARD_E_NO_KEY_CONTAINER;

	check_reader_status(pCardData);

	logprintf(pCardData, 2, "CardRSADecrypt dwVersion=%u, bContainerIndex=%u,dwKeySpec=%u pbData=%p, cbData=%u\n",
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, pInfo->pbData,  pInfo->cbData);

	if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		logprintf(pCardData, 2, "  pPaddingInfo=%p dwPaddingType=0x%08X\n", pInfo->pPaddingInfo, pInfo->dwPaddingType);

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;
	if (!pkey)   {
		logprintf(pCardData, 2, "CardRSADecrypt prkey not found\n");
		return SCARD_E_NO_KEY_CONTAINER;
	}

	/* input and output buffers are always the same size */
	pbuf = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf)
		return SCARD_E_NO_MEMORY;

	lg2 = pInfo->cbData;
	pbuf2 = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf2) {
		pCardData->pfnCspFree(pbuf);
		return SCARD_E_NO_MEMORY;
	}

	/*inversion donnees*/
	for(ui = 0; ui < pInfo->cbData; ui++)
		pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];
	logprintf(pCardData, 2, "Data to be decrypted (inverted):\n");
	loghex(pCardData, 7, pbuf, pInfo->cbData);

	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);
	alg_info = sc_card_find_rsa_alg(vs->p15card->card, (unsigned int) prkey_info->modulus_length);
	if (!alg_info)   {
		logprintf(pCardData, 2, "Cannot get appropriate RSA card algorithm for key size %i\n", prkey_info->modulus_length);
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		return SCARD_F_INTERNAL_ERROR;
	}

	/* filter boggus input: the data to decrypt is shorter than the RSA key ? */
	if ( pInfo->cbData < prkey_info->modulus_length / 8)
	{
		/* according to the minidriver specs, this is the error code to return
		(instead of invalid parameter when the call is forwarded to the card implementation) */
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	if (alg_info->flags & SC_ALGORITHM_RSA_RAW)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher: using RSA-RAW mechanism\n");
		r = sc_pkcs15_decipher(vs->p15card, pkey, opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);

		if (r > 0) {
			/* Need to handle padding */
			if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) {
				logprintf(pCardData, 2, "sc_pkcs15_decipher: DECRYPT-INFO dwVersion=%u\n", pInfo->dwVersion);
				if (pInfo->dwPaddingType == CARD_PADDING_PKCS1)   {
					size_t temp = pInfo->cbData;
					logprintf(pCardData, 2, "sc_pkcs15_decipher: stripping PKCS1 padding\n");
					r = sc_pkcs1_strip_02_padding(vs->ctx, pbuf2, pInfo->cbData, pbuf2, &temp);
					pInfo->cbData = (DWORD) temp;
					if (r < 0)   {
						logprintf(pCardData, 2, "Cannot strip PKCS1 padding: %i\n", r);
						pCardData->pfnCspFree(pbuf);
						pCardData->pfnCspFree(pbuf2);
						return SCARD_F_INTERNAL_ERROR;
					}
				}
				else if (pInfo->dwPaddingType == CARD_PADDING_OAEP)   {
					/* TODO: Handle OAEP padding if present - can call PFN_CSP_UNPAD_DATA */
					logprintf(pCardData, 2, "OAEP padding not implemented\n");
					pCardData->pfnCspFree(pbuf);
					pCardData->pfnCspFree(pbuf2);
					return SCARD_F_INTERNAL_ERROR;
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
			    ((pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) &&
			    (pInfo->dwPaddingType == CARD_PADDING_NONE))) {
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
		return SCARD_E_INVALID_PARAMETER;
	}

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		return md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE);
	}

	logprintf(pCardData, 2, "decrypted data(%i):\n", pInfo->cbData);
	loghex(pCardData, 7, pbuf2, pInfo->cbData);

	/*inversion donnees */
	for(ui = 0; ui < pInfo->cbData; ui++)
		pInfo->pbData[ui] = pbuf2[pInfo->cbData-ui-1];

	pCardData->pfnCspFree(pbuf);
	pCardData->pfnCspFree(pbuf2);
	return SCARD_S_SUCCESS;
}


DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __inout PCARD_SIGNING_INFO pInfo)
{
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE dataToSign[0x200];
	int r, opt_crypt_flags = 0, opt_hash_flags = 0;
	size_t dataToSignLen = sizeof(dataToSign);
	sc_pkcs15_object_t *pkey;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSignData\n");

	if (!pCardData || !pInfo)
		return SCARD_E_INVALID_PARAMETER;
	if ( ( pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION   ) &&
			( pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION ) )
		return ERROR_REVISION_MISMATCH;
	if ( pInfo->pbData == NULL )
		return SCARD_E_INVALID_PARAMETER;
	if (pInfo->dwKeySpec != AT_SIGNATURE && pInfo->dwKeySpec != AT_KEYEXCHANGE)
		return SCARD_E_INVALID_PARAMETER;
	if (pInfo->dwSigningFlags & ~(CARD_PADDING_INFO_PRESENT | CARD_PADDING_NONE | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_PKCS1 | CARD_PADDING_PSS | CARD_PADDING_OAEP))
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSignData dwVersion=%u, bContainerIndex=%u, dwKeySpec=%u, dwSigningFlags=0x%08X, aiHashAlg=0x%08X\n",
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, pInfo->dwSigningFlags, pInfo->aiHashAlg);

	logprintf(pCardData, 7, "pInfo->pbData(%i) ", pInfo->cbData);
	loghex(pCardData, 7, pInfo->pbData, pInfo->cbData);

	hashAlg = pInfo->aiHashAlg;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return SCARD_E_NO_KEY_CONTAINER;

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;
	if (!pkey)
		return SCARD_E_NO_KEY_CONTAINER;
	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);

	check_reader_status(pCardData);

	logprintf(pCardData, 2, "pInfo->dwVersion = %d\n", pInfo->dwVersion);

	if (dataToSignLen < pInfo->cbData)
		return SCARD_E_INSUFFICIENT_BUFFER;
	memcpy(dataToSign, pInfo->pbData, pInfo->cbData);
	dataToSignLen = pInfo->cbData;

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)   {
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (CARD_PADDING_PSS == pInfo->dwPaddingType)   {
			logprintf(pCardData, 0, "unsupported paddingtype CARD_PADDING_PSS\n");
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
		else if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)   {
			logprintf(pCardData, 0, "unsupported paddingtype\n");
			return SCARD_E_INVALID_PARAMETER;
		}
			
		if (!pinf->pszAlgId)   {
			/* hashAlg = CALG_SSL3_SHAMD5; */
			logprintf(pCardData, 3, "Using CALG_SSL3_SHAMD5  hashAlg\n");
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		}
		else   {
			if (wcscmp(pinf->pszAlgId, L"MD5") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
			else if (wcscmp(pinf->pszAlgId, L"SHA1") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHAMD5") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHA224") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA224;
			else if (wcscmp(pinf->pszAlgId, L"SHA256") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA256;
			else if (wcscmp(pinf->pszAlgId, L"SHA384") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA384;
			else if (wcscmp(pinf->pszAlgId, L"SHA512") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA512;
			else if (wcscmp(pinf->pszAlgId, L"RIPEMD160") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_RIPEMD160;
			else
						{
				logprintf(pCardData, 0,"unknown AlgId %S\n",NULLWSTR(pinf->pszAlgId));
								return SCARD_E_UNSUPPORTED_FEATURE;
						}
		}
	}
	else   {
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");

		if (GET_ALG_CLASS(hashAlg) != ALG_CLASS_HASH)   {
			logprintf(pCardData, 0, "bogus aiHashAlg\n");
			return SCARD_E_INVALID_PARAMETER;
		}

		if (hashAlg == CALG_MD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
		else if (hashAlg == CALG_SHA1)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
		else if (hashAlg == CALG_SSL3_SHAMD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else if (hashAlg == CALG_SHA_256)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA256;
		else if (hashAlg == CALG_SHA_384)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA384;
		else if (hashAlg == CALG_SHA_512)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA512;
		else if (hashAlg == (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_RIPEMD160))
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_RIPEMD160;
		else if (hashAlg !=0)
			return SCARD_E_UNSUPPORTED_FEATURE;
	}
	
	if (pInfo->dwSigningFlags & CARD_PADDING_NONE)
	{
		/* do not add the digest info when called from CryptSignHash(CRYPT_NOHASHOID)

		Note: SC_ALGORITHM_RSA_HASH_MD5_SHA1 aka CALG_SSL3_SHAMD5 do not have a digest info to be added
		      CryptSignHash(CALG_SSL3_SHAMD5,CRYPT_NOHASHOID) is the same than CryptSignHash(CALG_SSL3_SHAMD5)
		*/
		opt_hash_flags = 0;
	}

	/* From sc-minidriver_specs_v7.docx pp.76:
	 * 'The Base CSP/KSP performs the hashing operation on the data before passing it
	 *	to CardSignData for signature.'
	 * So, the SC_ALGORITHM_RSA_HASH_* flags should not be passed to pkcs15 library
	 *	when calculating the signature .
	 *
	 * From sc-minidriver_specs_v7.docx pp.76:
	 * 'If the aiHashAlg member is nonzero, it specifies the hash algorithm’s object identifier (OID)
	 *  that is encoded in the PKCS padding.'
	 * So, the digest info has be included into the data to be signed.
	 * */
	if (opt_hash_flags)   {
		logprintf(pCardData, 2, "include digest info of the algorithm 0x%08X\n", opt_hash_flags);
		dataToSignLen = sizeof(dataToSign);
		r = sc_pkcs1_encode(vs->ctx, opt_hash_flags, pInfo->pbData, pInfo->cbData, dataToSign, &dataToSignLen, 0);
		if (r)   {
			logprintf(pCardData, 2, "PKCS#1 encode error %s\n", sc_strerror(r));
			return SCARD_E_INVALID_VALUE;
		}
	}
	opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;

	pInfo->cbSignedData = (DWORD) prkey_info->modulus_length / 8;
	logprintf(pCardData, 3, "pInfo->cbSignedData = %d\n", pInfo->cbSignedData);

	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))   {
		int r,i;
		BYTE *pbuf = NULL;
		DWORD lg;

		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %d\n", lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf)
			return SCARD_E_NO_MEMORY;

		logprintf(pCardData, 7, "Data to sign: ");
		loghex(pCardData, 7, dataToSign, dataToSignLen);

		pInfo->pbSignedData = pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData)   {
			pCardData->pfnCspFree(pbuf);
			return SCARD_E_NO_MEMORY;
		}

		r = sc_pkcs15_compute_signature(vs->p15card, pkey, opt_crypt_flags, dataToSign, dataToSignLen, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)   {
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature erreur %s\n", sc_strerror(r));
			pCardData->pfnCspFree(pbuf);
			return md_translate_OpenSC_to_Windows_error(r, SCARD_F_INTERNAL_ERROR);
		}

		pInfo->cbSignedData = r;

		/*inversion donnees*/
		for(i = 0; i < r; i++)
			pInfo->pbSignedData[i] = pbuf[r-i-1];
		pCardData->pfnCspFree(pbuf);

		logprintf(pCardData, 7, "Signature (inverted): ");
		loghex(pCardData, 7, pInfo->pbSignedData, pInfo->cbSignedData);
	}

	logprintf(pCardData, 3, "CardSignData, dwVersion=%u, name=%S, hScard=0x%08X, hSCardCtx=0x%08X\n",
			pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),pCardData->hScard, pCardData->hSCardCtx);

	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__inout PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardConstructDHAgreement - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo)
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
	__in_bcount(cbPinData) PBYTE pbPinData,
	__in   DWORD cbPinData,
	__deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
	__out_opt PDWORD pcbSessionPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	DWORD dwret;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	int r;
	BOOL DisplayPinpadUI = FALSE;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAuthenticateEx\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
		PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	r = check_reader_status(pCardData);

	if ((vs->p15card) == NULL)
		return SCARD_F_INTERNAL_ERROR;

	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN || dwFlags == CARD_AUTHENTICATE_SESSION_PIN) {
		if (! (vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
			return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (dwFlags & ~(CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN | CARD_PIN_SILENT_CONTEXT))
		return SCARD_E_INVALID_PARAMETER;

	/* using a pin pad */
	if (NULL == pbPinData) {
		if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
			return SCARD_E_INVALID_PARAMETER;
		if (!(dwFlags & CARD_PIN_SILENT_CONTEXT)) {
			DisplayPinpadUI = TRUE;
		}
	}

	if (PinId != ROLE_USER)
		return SCARD_E_INVALID_PARAMETER;

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

	r = md_get_pin_by_role(pCardData, PinId, &pin_obj);
	if (r != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return r;
	}

	if (!pin_obj)
		return SCARD_F_INTERNAL_ERROR;
	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	/* Do we need to display a prompt to enter PIN on pin pad? */
	logprintf(pCardData, 7, "PIN pad=%s, pbPinData=%p, hwndParent=%p\n",
		vs->reader->capabilities & SC_READER_CAP_PIN_PAD ? "yes" : "no", pbPinData, vs->hwndParent);

	/* check if the pin is the session pin generated by a previous authentication with a pinpad */
	if (pbPinData != NULL && cbPinData == sizeof(MAGIC_SESSION_PIN) && memcmp(MAGIC_SESSION_PIN, pbPinData, sizeof(MAGIC_SESSION_PIN)) == 0) {
		pbPinData = NULL;
		cbPinData = 0;
	}

	r = md_dialog_perform_pin_operation(pCardData, SC_PIN_CMD_VERIFY, vs->p15card, pin_obj, (const u8 *) pbPinData, cbPinData, NULL, 0, DisplayPinpadUI);

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
	if (dwFlags == CARD_AUTHENTICATE_GENERATE_SESSION_PIN && (vs->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
		/* we set it to a special value for pinpad authentication to force a new pinpad authentication */
		if (pcbSessionPin) *pcbSessionPin = sizeof(MAGIC_SESSION_PIN);
		if (ppbSessionPin) {
			*ppbSessionPin = pCardData->pfnCspAlloc(sizeof(MAGIC_SESSION_PIN));
			if (ppbSessionPin) memcpy(*ppbSessionPin, MAGIC_SESSION_PIN, sizeof(MAGIC_SESSION_PIN));
		}
	} else {
		if (pcbSessionPin) *pcbSessionPin = 0;
		if (ppbSessionPin) *ppbSessionPin = NULL;
	}

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	SET_PIN(cardcf->bPinsFreshness, PinId);
	logprintf(pCardData, 7, "PinsFreshness = %d\n", cardcf->bPinsFreshness);
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
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dw_rv;
	struct sc_pkcs15_object *pin_obj = NULL;
	int rv;
	struct sc_pkcs15_auth_info *auth_info;
	BOOL DisplayPinpadUI = FALSE;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardChangeAuthenticatorEx\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (!(dwFlags & PIN_CHANGE_FLAG_UNBLOCK) && !(dwFlags & PIN_CHANGE_FLAG_CHANGEPIN)){
		logprintf(pCardData, 1, "Unknown flag\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	if ((dwFlags & PIN_CHANGE_FLAG_UNBLOCK) && (dwFlags & PIN_CHANGE_FLAG_CHANGEPIN))
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags & PIN_CHANGE_FLAG_UNBLOCK && dwAuthenticatingPinId == dwTargetPinId)
		return SCARD_E_INVALID_PARAMETER;
	if (dwAuthenticatingPinId != ROLE_USER && dwAuthenticatingPinId != ROLE_ADMIN)
		return SCARD_E_INVALID_PARAMETER;
	if (dwTargetPinId != ROLE_USER && dwTargetPinId != ROLE_ADMIN) {
		logprintf(pCardData, 1, "Only ROLE_USER or ROLE_ADMIN is supported\n");
		return SCARD_E_INVALID_PARAMETER;
	}
	/* according to the spec: cRetryCount MUST be zero */
	if (cRetryCount)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardChangeAuthenticatorEx: AuthenticatingPinId=%u, dwFlags=0x%08X, cbAuthenticatingPinData=%u, TargetPinId=%u, cbTargetData=%u, Attempts %s\n",
		dwAuthenticatingPinId, dwFlags, cbAuthenticatingPinData, dwTargetPinId, cbTargetData, pcAttemptsRemaining ? "YES" : "NO");


	check_reader_status(pCardData);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
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
		if (!(dwFlags & CARD_PIN_SILENT_CONTEXT)) {
			DisplayPinpadUI = TRUE;
		}
	}

	dw_rv = md_get_pin_by_role(pCardData, dwTargetPinId, &pin_obj);
	if (dw_rv != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object %s", (dwTargetPinId==ROLE_ADMIN?"admin":"user"));
		return dw_rv;
	}
	if (!pin_obj)
		return SCARD_F_INTERNAL_ERROR;

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

	rv = md_dialog_perform_pin_operation(pCardData, (dwFlags & PIN_CHANGE_FLAG_UNBLOCK ? SC_PIN_CMD_UNBLOCK:SC_PIN_CMD_CHANGE), 
		vs->p15card, pin_obj, (const u8 *) pbAuthenticatingPinData, cbAuthenticatingPinData, pbTargetData, cbTargetData, DisplayPinpadUI);
	
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
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT *cardcf = NULL;
	struct md_file *cmapfile = NULL;
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardDeauthenticateEx PinId=%d dwFlags=0x%08X\n",PinId, dwFlags);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	check_reader_status(pCardData);

	dwret = md_get_cardcf(pCardData, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	CLEAR_PIN(cardcf->bPinsFreshness, PinId);
	logprintf(pCardData, 1, "CardDeauthenticateEx bPinsFreshness:%d\n", cardcf->bPinsFreshness);

	/* TODO Reset PKCS#15 PIN object 'validated' flag */

	/* force a reset of a card - SCARD_S_SUCCESS does not lead to the reset of the card and leave it still authenticated */
	return SCARD_E_UNSUPPORTED_FEATURE;
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_pkcs15_container *cont = NULL;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardGetContainerProperty\n");

	check_reader_status(pCardData);

	if (!pCardData) return SCARD_E_INVALID_PARAMETER;
	logprintf(pCardData, 2, "CardGetContainerProperty bContainerIndex=%u, wszProperty=%S," \
		"cbData=%u, dwFlags=0x%08X\n",bContainerIndex,NULLWSTR(wszProperty),cbData,dwFlags);
	if (!wszProperty)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData || !pdwDataLen)
		return SCARD_E_INVALID_PARAMETER;
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		return SCARD_E_NO_KEY_CONTAINER;

	/* the test for the existence of containers is redondant with the one made in CardGetContainerInfo but CCP_PIN_IDENTIFIER does not do it */
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	cont = &vs->p15_containers[bContainerIndex];

	if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %i is empty\n", bContainerIndex);
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
	DWORD dwret;

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 2, "CardGetProperty('%S',cbData=%u,dwFlags=%u) called\n", NULLWSTR(wszProperty),cbData,dwFlags);

	if (!pCardData || !wszProperty)
		return SCARD_E_INVALID_PARAMETER;
	if (!pbData || !pdwDataLen)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

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

		dwret = md_query_key_sizes(pKeySizes);
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
		size_t sn_len = strlen(vs->p15card->tokeninfo->serial_number)/2;

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

		p->PinType = vs->reader->capabilities & SC_READER_CAP_PIN_PAD ? ExternalPinType : AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags)   {
			case ROLE_USER:
				logprintf(pCardData, 2,"returning info on PIN ROLE_USER ( Auth ) [%u]\n",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(ROLE_USER);
				p->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
				break;
			case ROLE_ADMIN:
				logprintf(pCardData, 2,"returning info on PIN ROLE_ADMIN ( Unblock ) [%u]\n",dwFlags);
				p->PinPurpose = UnblockOnlyPin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
				p->dwUnblockPermission = 0;
				break;
			default:
				logprintf(pCardData, 0,"Invalid Pin number %u requested\n",dwFlags);
				return SCARD_E_INVALID_PARAMETER;
		}
	}
	else if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		SET_PIN(*p, ROLE_USER);
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

		if (dwFlags != ROLE_USER)
			return SCARD_E_INVALID_PARAMETER;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
	}
	else if (wcscmp(CP_KEY_IMPORT_SUPPORT, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			return ERROR_INSUFFICIENT_BUFFER;
		*p = 0;
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

	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardSetProperty\n");

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "CardSetProperty wszProperty=%S, pbData=%p, cbDataLen=%u, dwFlags=%u",\
		NULLWSTR(wszProperty),pbData,cbDataLen,dwFlags);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
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
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardProcessEncryptedData - unsupported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
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

DWORD WINAPI CardCreateContainerEx(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwFlags,
    __in DWORD  dwKeySpec,
    __in DWORD  dwKeySize,
    __in PBYTE  pbKeyData,
    __in PIN_ID  PinId
)
{
	if (PinId == ROLE_ADMIN)
		return SCARD_W_SECURITY_VIOLATION;
	if (PinId != ROLE_USER)
		return SCARD_E_INVALID_PARAMETER;
	/* basically CardCreateContainerEx is CardCreateContainer + the PinId */
	return CardCreateContainer(pCardData, bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
}

DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData, __in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret, suppliedVersion = 0;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	if (dwFlags)
		return SCARD_E_INVALID_PARAMETER;
	if (!(dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE)) {
		if( pCardData->hSCardCtx == 0)   {
			logprintf(pCardData, 0, "Invalide handle.\n");
			return SCARD_E_INVALID_HANDLE;
		}
		if( pCardData->hScard == 0)   {
			logprintf(pCardData, 0, "Invalide handle.\n");
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
	/* <2 lenght or >=0x22 are not ISO compliant */
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
	memset(vs, 0, sizeof(VENDOR_SPECIFIC));

	logprintf(pCardData, 1, "==================================================================\n");
	logprintf(pCardData, 1, "\nP:%d T:%d pCardData:%p ",GetCurrentProcessId(), GetCurrentThreadId(), pCardData);
	logprintf(pCardData, 1, "CardAcquireContext, dwVersion=%u, name=%S,hScard=0x%08X, hSCardCtx=0x%08X\n",
			pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),pCardData->hScard, pCardData->hSCardCtx);

	vs->hScard = pCardData->hScard;
	vs->hSCardCtx = pCardData->hSCardCtx;

	logprintf(pCardData, 2, "request version pCardData->dwVersion = %d\n", pCardData->dwVersion);
	pCardData->dwVersion = min(pCardData->dwVersion, MD_CURRENT_VERSION_SUPPORTED);
	logprintf(pCardData, 2, "pCardData->dwVersion = %d\n", pCardData->dwVersion);

	dwret = md_create_context(pCardData, vs);
	if (dwret != SCARD_S_SUCCESS) {
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);
		pCardData->pvVendorSpecific = NULL;
		return dwret;
	}
	md_static_data.flags &= ~MD_STATIC_FLAG_CONTEXT_DELETED;

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
	/* the minidriver does not perform a deauthentication - set it to NULL according to the specification */
	pCardData->pfnCardDeauthenticate = NULL;
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
	if (dwret != SCARD_S_SUCCESS) {
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);
		pCardData->pvVendorSpecific = NULL;
		return dwret;
	}

	dwret = md_fs_init(pCardData);
	if (dwret != SCARD_S_SUCCESS) {
		pCardData->pfnCspFree(pCardData->pvVendorSpecific);
		pCardData->pvVendorSpecific = NULL;
		return dwret;
	}

	logprintf(pCardData, 1, "OpenSC init done.\n");
	logprintf(pCardData, 1, "Supplied version %u - version used %u.\n", suppliedVersion, pCardData->dwVersion);

	if (pCardData->dwVersion >= CARD_DATA_VERSION_FIVE) {
		pCardData->pfnCardDeriveKey = CardDeriveKey;
		pCardData->pfnCardDestroyDHAgreement = CardDestroyDHAgreement;
		pCardData->pfnCspGetDHAgreement = CspGetDHAgreement;

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

	return SCARD_S_SUCCESS;
}

static int associate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	DWORD dw;
	int  r;

	logprintf(pCardData, 1, "associate_card\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	/*
	 * set the addresses of the reader and card handles
	 * Our cardmod pcsc code will use these  when we call sc_ctx_use_reader
	 * We use the address of the handles as provided in the pCardData
	 */
	vs->hSCardCtx = pCardData->hSCardCtx;
	vs->hScard = pCardData->hScard;

	/**
	 * Check if a linked context has been deleted - if so, repair shared data.
	 * Multithreaded issue - TODO: proper multithreaded handling
	 */
	if (md_static_data.flags & MD_STATIC_FLAG_CONTEXT_DELETED)
	{
		r = sc_context_repair(&(vs->ctx));
		logprintf(pCardData, 2, "sc_context_repair called - result = %d, %s\n", r, sc_strerror(r));
		md_static_data.flags &= ~MD_STATIC_FLAG_CONTEXT_DELETED;
	}

	/* set the provided reader and card handles into ctx */
	logprintf(pCardData, 5, "cardmod_use_handles %d\n", sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard));

	/* should be only one reader */
	logprintf(pCardData, 5, "sc_ctx_get_reader_count(ctx): %d\n", sc_ctx_get_reader_count(vs->ctx));

	vs->reader = sc_ctx_get_reader(vs->ctx, 0);
	if(vs->reader)   {
		struct sc_app_info *app_generic = NULL;
		struct sc_aid *aid = NULL;

		r = sc_connect_card(vs->reader, &(vs->card));
		if(r)   {
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
	}

	if(vs->card == NULL || vs->p15card == NULL)   {
		logprintf(pCardData, 0, "Card unknown.\n");
		return SCARD_E_UNKNOWN_CARD;
	}

	dw = md_get_pin_by_role(pCardData, ROLE_USER, &vs->obj_user_pin);
	if (dw != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return dw;
	}

	dw = md_get_pin_by_role(pCardData, ROLE_USER, &vs->obj_sopin);
	if (dw != SCARD_S_SUCCESS)
		logprintf(pCardData, 2, "Cannot get ADMIN PIN object -- ignored");

	return SCARD_S_SUCCESS;

}

static int disassociate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;

	logprintf(pCardData, 1, "disassociate_card\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	vs->obj_user_pin = NULL;
	vs->obj_sopin = NULL;

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

	return SCARD_S_SUCCESS;
}


BOOL APIENTRY DllMain( HINSTANCE hinstDLL,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
#ifdef CARDMOD_LOW_LEVEL_DEBUG
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

	logprintf(NULL,8,"\n********** DllMain Module(handle:0x%p) '%s'; reason='%s'; Reserved=%p; P:%d; T:%d\n",
			hinstDLL, name, reason, lpReserved, GetCurrentProcessId(), GetCurrentThreadId());
#endif
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_inst = hinstDLL;
		md_static_data.attach_check = MD_STATIC_PROCESS_ATTACHED;
		break;
	case DLL_PROCESS_DETACH:
		md_static_data.attach_check = 0;
		break;
	}
	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
#endif

