/*
 * card-gids.h: Support for GIDS smart cards.
 *
 * Copyright (C) 2015 Vincent Le Toux (My Smart Logon) <vincent.letoux@mysmartlogon.com>
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

#ifndef CARD_GIDS_H_
#define CARD_GIDS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pkcs15.h"

struct sc_cardctl_gids_genkey {
	sc_pkcs15_object_t *object;
	struct sc_pkcs15_pubkey* pubkey;
};

struct sc_cardctl_gids_importkey {
	sc_pkcs15_object_t *object;
	sc_pkcs15_prkey_t *key;
};

struct sc_cardctl_gids_save_cert {
	sc_pkcs15_object_t *certobject;
	sc_pkcs15_object_t *privkeyobject;
	struct sc_path *path;
};

typedef struct sc_cardctl_gids_get_container {
	size_t containernum;
	int pubusage;
	int prvusage;
	char label[40];
	int module_length;
	sc_path_t certificatepath;
} sc_cardctl_gids_get_container_t;

typedef struct sc_cardctl_gids_init_param {
	u8 init_code[24];
	size_t user_pin_len;
	u8* user_pin;
	u8 cardid[16];
} sc_cardctl_gids_init_param_t;

// information about common files
#define UserCreateDeleteDirAc_FI 0xA000
#define EveryoneReadUserWriteAc_FI 0xA010
#define EveryoneReadAdminWriteAc_FI 0xA012
#define MF_FI UserCreateDeleteDirAc_FI
#define MF_DO 0xDF1F
#define CERT_FI EveryoneReadUserWriteAc_FI
#define KEYMAP_FI UserCreateDeleteDirAc_FI
#define KEYMAP_DO 0xDF20
#define CARDAPPS_FI EveryoneReadUserWriteAc_FI
#define CARDAPPS_DO 0xDF21
#define CARDCF_FI EveryoneReadUserWriteAc_FI
#define CARDCF_DO 0xDF22
#define CMAP_FI EveryoneReadUserWriteAc_FI
#define CMAP_DO 0xDF23
#define CARDID_FI EveryoneReadAdminWriteAc_FI
#define CARDID_DO 0xDF20
#define GIDS_MAX_DO 0xDFFF

#define MAX_GIDS_FILE_SIZE 65000

typedef struct gids_mf_record {
	char directory[9];
	char filename[9];
	int dataObjectIdentifier;
	int fileIdentifier;
} gids_mf_record_t;

struct gids_keymap_record {
	int state;
	unsigned char algid;
	unsigned char keytype;
	unsigned short keyref;
	unsigned short unknownWithFFFF;
};

#define GIDS_MAX_CONTAINER 126

// stolen from cardmod.h
#define MAX_CONTAINER_NAME_LEN				39
#define CONTAINER_MAP_VALID_CONTAINER		1
#define CONTAINER_MAP_DEFAULT_CONTAINER		2
typedef struct _CONTAINER_MAP_RECORD
{
	unsigned short wszGuid [MAX_CONTAINER_NAME_LEN + 1];
	unsigned char bFlags;
	unsigned char bReserved;
	unsigned short wSigKeySizeBits;
	unsigned short wKeyExchangeKeySizeBits;
} CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;

#ifdef __cplusplus
}
#endif

#endif /* CARD_GIDS_H_ */
