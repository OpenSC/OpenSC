/*
 * iasecc.h Support for IAS/ECC smart cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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

#ifndef _OPENSC_IASECC_H
#define _OPENSC_IASECC_H

#include "libopensc/errors.h"
#include "libopensc/types.h"
#include "libopensc/iasecc-sdo.h"

#define ISO7812_PAN_SN_TAG	0x5A

#ifndef SHA256_DIGEST_LENGTH
	#define SHA_DIGEST_LENGTH	20
	#define SHA256_DIGEST_LENGTH	32
#endif

#ifndef CKM_RSA_PKCS
	#define CKM_RSA_PKCS		0x00000001
	#define CKM_SHA1_RSA_PKCS	0x00000006
	#define CKM_SHA256_RSA_PKCS	0x00000040
	#define CKM_SHA_1		0x00000220
	#define CKM_SHA256		0x00000250
#endif

#define IASECC_TITLE "IASECC"

#define IASECC_FCP_TAG			0x62
#define IASECC_FCP_TAG_SIZE		0x80
#define IASECC_FCP_TAG_TYPE		0x82
#define IASECC_FCP_TAG_FID		0x83
#define IASECC_FCP_TAG_NAME		0x84
#define IASECC_FCP_TAG_SFID		0x88
#define IASECC_FCP_TAG_ACLS		0xA1
#define IASECC_FCP_TAG_ACLS_CONTACT	0x8C
#define IASECC_FCP_TAG_ACLS_CONTACTLESS	0x9C

#define IASECC_FCP_TYPE_EF	0x01
#define IASECC_FCP_TYPE_DF	0x38

#define IASECC_OBJECT_REF_LOCAL		0x80
#define IASECC_OBJECT_REF_GLOBAL	0x00

#define IASECC_OBJECT_REF_MIN	0x01
#define IASECC_OBJECT_REF_MAX	0x1F

#define IASECC_SE_REF_MIN	0x01
#define IASECC_SE_REF_MAX	0x0F

/* IAS/ECC interindustry data tags */
#define IASECC_ATR_TAG_IO_BUFFER_SIZES		0xE0

#define IASECC_SFI_EF_DIR	0x1E
#define IASECC_SFI_EF_ATR	0x1D
#define IASECC_SFI_EF_SN	0x1C
#define IASECC_SFI_EF_DH	0x1B

#define IASECC_READ_BINARY_LENGTH_MAX	0xE7

#define IASECC_PSO_HASH_TAG_PARTIAL	0x90
#define IASECC_PSO_HASH_TAG_REMAINING	0x80

#define IASECC_CARD_ANSWER_TAG_DATA	0x87
#define IASECC_CARD_ANSWER_TAG_SW	0x99
#define IASECC_CARD_ANSWER_TAG_MAC	0x8E

#define IASECC_SM_DO_TAG_TLE	0x97 
#define IASECC_SM_DO_TAG_TSW	0x99 
#define IASECC_SM_DO_TAG_TCC	0x8E 
#define IASECC_SM_DO_TAG_TCG_ODD_INS	0x85 
#define IASECC_SM_DO_TAG_TCG_EVEN_INS	0x87 
#define IASECC_SM_DO_TAG_TCG	0x87 
#define IASECC_SM_DO_TAG_TBR	0x85 

struct sc_security_env;

typedef struct iasecc_qsign_data {
	int hash_algo;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	size_t hash_size;

	unsigned char pre_hash[SHA256_DIGEST_LENGTH];
	size_t pre_hash_size;

	unsigned char counter[8];
	unsigned long counter_long;

	unsigned char last_block[64];
	size_t last_block_size;
} iasecc_qsign_data_t;


struct iasecc_version {
	unsigned char ic_manufacturer;
	unsigned char ic_type;
	unsigned char os_version;
	unsigned char iasecc_version;
};

struct iasecc_io_buffer_sizes {
	size_t send;
	size_t send_sc;
	size_t recv;
	size_t recv_sc;
};

struct iasecc_private_data {
	struct iasecc_version version;
	struct iasecc_io_buffer_sizes max_sizes;

	struct sc_security_env security_env;
	size_t key_size;
	unsigned op_method, op_ref;

	struct iasecc_se_info *se_info;
};
#endif
