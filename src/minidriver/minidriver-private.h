/*
 * minidriver-private.h: private OpenSC minidriver declarations
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Private data shared by the generic Windows minidriver and card-specific
 * adapters. This header is internal to src/minidriver.
 */
#ifndef OPENSC_MINIDRIVER_PRIVATE_H
#define OPENSC_MINIDRIVER_PRIVATE_H

#define MD_MAX_KEY_CONTAINERS 32
#define MD_CARDID_SIZE	      16
#define MD_ROLE_USER_SIGN     (ROLE_ADMIN + 1)
#define MD_MAX_PINS	      MAX_PINS

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
};

struct md_dh_agreement {
	DWORD dwSize;
	PBYTE pbAgreement;
};

struct md_guid_conversion {
	CHAR szOpenSCGuid[MAX_CONTAINER_NAME_LEN + 1];
	CHAR szWindowsGuid[MAX_CONTAINER_NAME_LEN + 1];
};

struct md_jpki_state;

typedef struct _VENDOR_SPECIFIC {
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
	HWND hwndParent;
	LPWSTR wszPinContext;
	struct md_dh_agreement *dh_agreements;
	BYTE allocatedAgreements;
	int need_pin_always;
	struct md_jpki_state *jpki;
	CRITICAL_SECTION hScard_lock;
} VENDOR_SPECIFIC;

#if defined(__GNUC__)
void logprintf(PCARD_DATA pCardData, int level, const char *format, ...)
		__attribute__((format(SC_PRINTF_FORMAT, 3, 4)));
#else
void logprintf(PCARD_DATA pCardData, int level, const char *format, ...);
#endif

DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror,
		DWORD dwDefaultCode);
DWORD md_fs_find_file(PCARD_DATA pCardData, char *parent, char *name,
		struct md_file **out);

#endif
