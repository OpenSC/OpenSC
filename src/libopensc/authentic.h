/*
 * authentic.h: Specific definitions for the Oberthur's card
 * 		'COSMO v7' with applet 'AuthentIC v3' 
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

#ifndef _OPENSC_AUTHENTIC_V3_H
#define _OPENSC_AUTHENTIC_V3_H

#include "libopensc/errors.h"
#include "libopensc/types.h"
#include "libopensc/iso7816.h"

#ifndef CKM_RSA_PKCS
	#define CKM_RSA_PKCS		0x00000001
	#define CKM_SHA1_RSA_PKCS	0x00000006
	#define CKM_SHA256_RSA_PKCS	0x00000040
	#define CKM_SHA_1		0x00000220
	#define CKM_SHA256		0x00000250
#endif

#define AUTHENTIC_V3_CREDENTIAL_ID_MASK	7

#define AUTHENTIC_V3_CRYPTO_OBJECT_REF_MIN	0x81
#define AUTHENTIC_V3_CRYPTO_OBJECT_REF_MAX	0xFF

#define _MAKE_AUTHENTIC_MAGIC(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | ((d)))

#define AUTHENTIC_SDO_MAGIC                _MAKE_AUTHENTIC_MAGIC('A', 'W', 'S', 'D')
#define AUTHENTIC_SDO_MAGIC_UPDATE         _MAKE_AUTHENTIC_MAGIC('A', 'W', 'U', 'D')
#define AUTHENTIC_SDO_MAGIC_UPDATE_RSA     _MAKE_AUTHENTIC_MAGIC('A', 'W', 'U', 'R')

#define AUTHENTIC_OBJECT_REF_FLAG_LOCAL	0x80

#define AUTHENTIC_MECH_CREDENTIAL_PIN		0x00
#define AUTHENTIC_MECH_CREDENTIAL_BIO		0x01
#define AUTHENTIC_MECH_CREDENTIAL_DES		0x02
#define AUTHENTIC_MECH_CREDENTIAL_2DES		0x03
#define AUTHENTIC_MECH_CREDENTIAL_3DES		0x04
#define AUTHENTIC_MECH_CREDENTIAL_AES128	0x05
#define AUTHENTIC_MECH_CREDENTIAL_AES192	0x06
#define AUTHENTIC_MECH_CREDENTIAL_AES256	0x07

#define AUTHENTIC_MECH_CRYPTO_DES	0x02
#define AUTHENTIC_MECH_CRYPTO_2DES	0x03
#define AUTHENTIC_MECH_CRYPTO_3DES	0x04	
#define AUTHENTIC_MECH_CRYPTO_AES128	0x05
#define AUTHENTIC_MECH_CRYPTO_AES192	0x06
#define AUTHENTIC_MECH_CRYPTO_AES256	0x07
#define AUTHENTIC_MECH_CRYPTO_RSA1024	0x08
#define AUTHENTIC_MECH_CRYPTO_RSA1280	0x09
#define AUTHENTIC_MECH_CRYPTO_RSA1536	0x0A
#define AUTHENTIC_MECH_CRYPTO_RSA1792	0x0B
#define AUTHENTIC_MECH_CRYPTO_RSA2048	0x0C

#define AUTHENTIC_TAG_DOCP			0xA1
#define AUTHENTIC_TAG_DOCP_MECH			0x80
#define AUTHENTIC_TAG_DOCP_ID			0x83
#define AUTHENTIC_TAG_DOCP_ACLS			0x86
#define AUTHENTIC_TAG_DOCP_SCP			0x87
#define AUTHENTIC_TAG_DOCP_USAGE_COUNTER	0x90

#define AUTHENTIC_TAG_RSA		0xA5

#define AUTHENTIC_TAG_RSA_PRIVATE	0x7F48
#define AUTHENTIC_TAG_RSA_PRIVATE_P	0x92
#define AUTHENTIC_TAG_RSA_PRIVATE_Q	0x93
#define AUTHENTIC_TAG_RSA_PRIVATE_PQ	0x94
#define AUTHENTIC_TAG_RSA_PRIVATE_DP1	0x95
#define AUTHENTIC_TAG_RSA_PRIVATE_DQ1	0x96

#define AUTHENTIC_TAG_RSA_PUBLIC		0x7F49
#define AUTHENTIC_TAG_RSA_PUBLIC_MODULUS	0x81
#define AUTHENTIC_TAG_RSA_PUBLIC_EXPONENT	0x82

#define AUTHENTIC_TAG_RSA_GENERATE_DATA	0xAC

#define AUTHENTIC_TAG_CREDENTIAL			0x5F00
#define AUTHENTIC_TAG_CREDENTIAL_TRYLIMIT		0x91
#define AUTHENTIC_TAG_CREDENTIAL_PINPOLICY		0xA1
#define AUTHENTIC_TAG_CREDENTIAL_PINPOLICY_MAXLENGTH	0x83
#define AUTHENTIC_TAG_CREDENTIAL_PINPOLICY_MINLENGTH	0x84
#define AUTHENTIC_TAG_CREDENTIAL_PINPOLICY_COMPLEXITY	0x85

#define AUTHENTIC_ALGORITHM_RSA_PKCS1	0x11
#define AUTHENTIC_ALGORITHM_RSA_X509	0x12
#define AUTHENTIC_ALGORITHM_RSA_OAEP	0x13
#define AUTHENTIC_ALGORITHM_RSA_ISO9796	0x14

#define AUTHENTIC_TAG_CRT_AT	0xA4
#define AUTHENTIC_TAG_CRT_HT	0xAA
#define AUTHENTIC_TAG_CRT_CCT	0xB4
#define AUTHENTIC_TAG_CRT_DST	0xB6
#define AUTHENTIC_TAG_CRT_CT	0xB8

#define AUTHENTIC_ACL_NUM_PIN_VERIFY	0
#define AUTHENTIC_ACL_NUM_PIN_RESET	1
#define AUTHENTIC_ACL_NUM_PIN_CHANGE	2
#define AUTHENTIC_ACL_NUM_PIN_MODIFY	3
#define AUTHENTIC_ACL_NUM_PIN_DELETE	4

/* SM related macros */
#define AUTHENTIC_AC_SM_MASK	0x60

#define AUTHENTIC_GP_SM_LEVEL_MASK	0x6000
#define AUTHENTIC_GP_SM_LEVEL_PLAIN	0x2000 
#define AUTHENTIC_GP_SM_LEVEL_MAC	0x4000 
#define AUTHENTIC_GP_SM_LEVEL_ENC_MAC	0x6000 

/* 
 * DOCP (Data Object Control Parameters)
 * Common holder for the all DOCP types.
 */
struct sc_authentic_sdo_docp {
	unsigned char mech;			/* Crypto Mechanism ID */
	unsigned char id;			/* Data Object ID */
	unsigned char security_parameter;	/* Security Control Parameter */
	unsigned char velocity_limit, try_limit;

	unsigned char acl_data[16];		/* Encoded AuthentIC ACL data */
	size_t acl_data_len;

	unsigned char usage_counter[2];
};

struct sc_authentic_sdo  {
	struct sc_authentic_sdo_docp docp;
	union {
		struct sc_pkcs15_prkey *prvkey;
	} data;

	struct sc_file *file;

	unsigned magic;
};

#endif
