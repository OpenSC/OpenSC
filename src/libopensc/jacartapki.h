/*
 * jacartapki.h: Support for JaCarta PKI applet
 *
 * Copyright (C) 2025  Andrey Khodunov <a.khodunov@aladdin.ru>
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
 */
#ifndef _JACARTAPKI_H
#define _JACARTAPKI_H

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <openssl/evp.h>

#include "libopensc/errors.h"
#include "libopensc/types.h"

#define SC_PKCS15_TYPE_VENDOR_DEFINED 0x4000

#define JACARTAPKI_MODEL "JaCarta PKI"

#define JACARTAPKI_KO_ALLOW_TICKET	  0x80
#define JACARTAPKI_KO_ALLOW_SECURE_VERIFY 0x40

#define JACARTAPKI_KO_NON_CRYPTO    0x00
#define JACARTAPKI_KO_CLASS_SKEY    0x01
#define JACARTAPKI_KO_CLASS_ECC	    0x03
#define JACARTAPKI_KO_CLASS_RSA	    0x04
#define JACARTAPKI_KO_CLASS_RSA_CRT 0x05

#define JACARTAPKI_KO_USAGE_AUTH_EXT	  0x01
#define JACARTAPKI_KO_USAGE_AUTH_INT	  0x02
#define JACARTAPKI_KO_USAGE_SIGN	  0x04
#define JACARTAPKI_KO_USAGE_VERIFY	  0x04
#define JACARTAPKI_KO_USAGE_ENCRYPT	  0x08
#define JACARTAPKI_KO_USAGE_DECRYPT	  0x08
#define JACARTAPKI_KO_USAGE_KEY_AGREEMENT 0x80

#define JACARTAPKI_KO_ALGORITHM_PIN	  0x00
#define JACARTAPKI_KO_ALGORITHM_BIOMETRIC 0x01
#define JACARTAPKI_KO_ALGORITHM_LOGIC	  0x0F
#define JACARTAPKI_KO_ALGORITHM_TDES	  0x10
#define JACARTAPKI_KO_ALGORITHM_AES	  0x11
#define JACARTAPKI_KO_ALGORITHM_RSA	  0x20
#define JACARTAPKI_KO_ALGORITHM_ECC	  0x30

#define JACARTAPKI_KO_PADDING_NO  0x00
#define JACARTAPKI_KO_PADDING_YES 0x01

#define JACARTAPKI_FILE_DESCRIPTOR_EF 0x01
#define JACARTAPKI_FILE_DESCRIPTOR_DF 0x38
#define JACARTAPKI_FILE_DESCRIPTOR_DO 0x39
#define JACARTAPKI_FILE_DESCRIPTOR_KO 0x08

#define JACARTAPKI_KO_DATA_TAG_PIN 0x81
#define JACARTAPKI_KO_DATA_TAG_RSA 0x71

#define JACARTAPKI_PIV_ALGO_RSA_1024  0x06
#define JACARTAPKI_PIV_ALGO_RSA_2048  0x07
#define JACARTAPKI_PIV_ALGO_RSA_4096  0x08
#define JACARTAPKI_PIV_ALGO_ECC_FP224 0x0E
#define JACARTAPKI_PIV_ALGO_ECC_FP256 0x11

#define JACARTAPKI_SM_RSA_TAG_G	    0x80
#define JACARTAPKI_SM_RSA_TAG_N	    0x81
#define JACARTAPKI_SM_RSA_TAG_ICC_P 0x82

#define JACARTAPKI_SM_ACCESS_INPUT  0x4000
#define JACARTAPKI_SM_ACCESS_OUTPUT 0x8000

#define JACARTAPKI_FS_REF_MASK	     0x3F
#define JACARTAPKI_FS_BASEFID_PUBKEY 0x0080
/* TODO: Private key can have different 'BASEFID's */
#define JACARTAPKI_FS_BASEFID_PRVKEY_EXCH 0x0040 /* jacartapki.profile -> template-private-key file-id */
#define JACARTAPKI_FS_BASEFID_PRVKEY_SIGN 0x0060

#define JACARTAPKI_FS_BASEFID_DATA 0x0600 /* jacartapki.profile -> jacartapki-public-data-attributes, jacartapki-private-data-attributes file-id */

#define JACARTAPKI_FS_BASEFID_CERT	0x0440 /* jacartapki.profile -> jacartapki-certificate-attributes file-id */
#define JACARTAPKI_FS_BASEFID_CERT_CMAP 0x8400

#define JACARTAPKI_ATTRIBUTE_VALID   0
#define JACARTAPKI_ATTRIBUTE_INVALID 1

#define JACARTAPKI_FS_KEY_REF_MIN 0x01
#define JACARTAPKI_FS_KEY_REF_MAX 0x1E

#define JACARTAPKI_FS_ATTR_REF_MIN 0x00
#define JACARTAPKI_FS_ATTR_REF_MAX 0x1D

#define CKA_ALADDIN   0x80000010l
#define CKA_CERT_HASH 0x80000013l

#define CKFP_CANNOT_REVEAL	 0x01l
#define CKFP_ONLY_SO_CAN_SET	 0x02l
#define CKFP_READ_ONLY		 0x04l
#define CKFP_MODIFIABLE		 0x10l
#define CKFP_MODIFIABLE_TO_TRUE	 0x30l
#define CKFP_MODIFIABLE_TO_FALSE 0x50l

#define JACARTAPKI_PKCS15_TYPE_PRESENT_IN_CMAP 0x2000

#define JACARTAPKI_CARDCF_PATH "3F00300030034001"

#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#define JACARTAPKI_ATTRS_DIGEST_OFFSET 0x0C

#define JACARTAPKI_TOKEN_INFO_LENGTH 160

#define JACARTAPKI_TRANSPORT_PIN1_VALUE	    "31:32:33:34"
#define JACARTAPKI_TRANSPORT_PIN1_REFERENCE 0x01
#define JACARTAPKI_TRANSPORT_PIN1_AUTH_ID   0x01
#define JACARTAPKI_TRANSPORT_PIN1_PATH	    "3F000001"

#define JACARTAPKI_USER_PIN_REFERENCE 0x20
#define JACARTAPKI_USER_PIN_AUTH_ID   0x20
#define JACARTAPKI_SO_PIN_REFERENCE   0x10
#define JACARTAPKI_SO_PIN_AUTH_ID     0x10

#define JACARTAPKI_USER_PIN_TYPE_PIN	 0x01
#define JACARTAPKI_USER_PIN_TYPE_BIO	 0x03
#define JACARTAPKI_USER_PIN_TYPE_PIN_BIO 0x04

#define JACARTAPKI_VERSION_HW_MAJOR 0x01
#define JACARTAPKI_VERSION_HW_MINOR 0x00
#define JACARTAPKI_VERSION_FW_MAJOR 0x01
#define JACARTAPKI_VERSION_FW_MINOR 0x00

/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN	39
 * #define CONTAINER_MAP_VALID_CONTAINER	1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER	2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *	WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *	BYTE bFlags;
 *	BYTE bReserved;
 *	WORD wSigKeySizeBits;
 *	WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
#define CMAP_FID		    0x867F
#define CMAP_GUID_INFO_SIZE	    80
#define CMAP_FLAG_CONTAINER_VALID   0x01
#define CMAP_FLAG_CONTAINER_DEFAULT 0x02
#define CMAP_DO_APPLICATION_NAME    "CSP"

#ifdef _MSC_VER
#define PACKED
#pragma pack(push, 1)
#elif defined(__GNUC__)
#define PACKED __attribute__((__packed__))
#endif

typedef struct jacartapki_cmap_record {
	/* original MD fields */
	unsigned char guid[CMAP_GUID_INFO_SIZE]; /* 40 x sizeof unicode chars */
	unsigned char flags;
	unsigned char reserved;
	unsigned short keysize_sign;
	unsigned short keysize_keyexchange;

	/* PKCS#11 helper fields */
	/* actual ASCII CKA_ID length (in unicode chars) */
	unsigned short guid_len;

	/* DF - DS/PKI + MSB in lower byte == 1 (0x80) if we use our
	 * Conversion to Unicode with MSB on in any byte */
	unsigned short rfu;
} PACKED jacartapki_cmap_record_t;

typedef struct jacartapki_cardcf {
	unsigned char _unused[4];
	unsigned short cont_freshness;
	unsigned short files_freshness;
} PACKED jacartapki_cardcf_t;

typedef struct jacartapki_version {
	unsigned char major;
	unsigned char minor;
} PACKED jacartapki_version_t;

typedef struct jacartapki_token_info {
	unsigned char label[32];		/* 0   */
	unsigned char manufacturer_id[32];	/* 32  */
	unsigned char model[16];		/* 64  */
	unsigned char serial_number[16];	/* 80  */
	uint32_t flags;				/* 96  */
	uint32_t max_session_count;		/* 100 */
	uint32_t session_count;			/* 104 */
	uint32_t max_rw_session_count;		/* 108 */
	uint32_t rw_session_count;		/* 112 */
	uint32_t max_pin_len;			/* 116 */
	uint32_t min_pin_len;			/* 120 */
	uint32_t total_public_memory;		/* 124 */
	uint32_t free_public_memory;		/* 128 */
	uint32_t total_private_memory;		/* 132 */
	uint32_t free_private_memory;		/* 136 */
	jacartapki_version_t hardware_version;	/* 140 */
	jacartapki_version_t firmware_version;	/* 142 */
	unsigned char utc_time[16];		/* 144 */
} PACKED jacartapki_token_info_t;		/* 160 */

#ifdef _MSC_VER
#undef PACKED
#pragma pack(pop)
#elif defined(__GNUC__)
#undef PACKED
#endif

struct sc_md_data {
	jacartapki_cardcf_t cardcf;
};

struct sc_cardctl_jacartapki_genkey {
	unsigned char algorithm;

	unsigned char *exponent;
	size_t exponent_len;

	unsigned char *modulus;
	size_t modulus_len;
};

struct sc_cardctl_jacartapki_updatekey {
	unsigned char *data;
	size_t len;
};

struct jacartapki_card_capabilities {
	unsigned char supported_keys[5];
	unsigned char crypto[3];
	struct {
		unsigned char data[2];
		unsigned char serial[4];
		unsigned char batch[2];
	} serial;
	struct {
		unsigned char total_size[4];
		unsigned char free_space[4];
		unsigned char size[4];
	} eeprom;
};

struct jacartapki_card_auth_state {
	unsigned pin_reference;
	unsigned char logged_in;
};

struct jacartapki_private_data {
	struct sc_security_env security_env;
	struct sc_file *last_ko;

	int secure_verify;
	int sm_establish;

	struct jacartapki_card_capabilities caps;

	/* TEMP P15 DF RELOAD PRIVATE */
	struct jacartapki_card_auth_state auth_state[2];

#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER)
	EVP_CIPHER *desCbcCipher;
	EVP_CIPHER *desEcbCipher;
#endif
};

struct jacartapki_cka {
	unsigned long cka;
	unsigned char internal_cka;

	unsigned char *val;
	size_t len;
};

int jacartapki_get_free_index(struct sc_pkcs15_card *p15card, unsigned type, unsigned base_file_id);

int jacartapki_encode_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key,
		unsigned char **buf, size_t *len);

int jacartapki_attrs_cert_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_cert_info *info, unsigned char *data, size_t data_len);
int jacartapki_attrs_prvkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey_info *info, unsigned char *data, size_t data_len);
int jacartapki_attrs_pubkey_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey_info *info, unsigned char *data, size_t data_len);
int jacartapki_attrs_data_object_decode(struct sc_context *ctx, struct sc_pkcs15_object *object,
		struct sc_pkcs15_data_info *info, unsigned char *data, size_t data_len, unsigned char *hash_exists);

int jacartapki_md_cmap_record_decode(struct sc_context *ctx, const struct sc_pkcs15_data *data, size_t *offs,
		jacartapki_cmap_record_t **out);
int jacartapki_md_cmap_record_guid(struct sc_context *ctx, jacartapki_cmap_record_t *rec,
		unsigned char **out, size_t *out_len);

int jacartapki_attrs_prvkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int jacartapki_attrs_pubkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int jacartapki_attrs_cert_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);
int jacartapki_attrs_data_object_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len);

int jacartapki_encode_update_key(struct sc_context *ctx, struct sc_pkcs15_prkey *prkey,
		struct sc_cardctl_jacartapki_updatekey *update_data);

int jacartapki_cmap_set_key_guid(struct sc_context *ctx, struct sc_pkcs15_prkey_info *info, int *is_converted);
int jacartapki_cmap_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *ignore,
		unsigned char **out, size_t *out_len);

int sc_pkcs15emu_jacartapki_create_pin(struct sc_pkcs15_card *p15card, char *label,
		char *pin_path, unsigned char auth_id, unsigned flags);

#endif /* ENABLE_OPENSSL */

#endif /* _JACARTAPKI_H */
