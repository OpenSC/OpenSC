/*
 * card-piv.c: Support for PIV-II from NIST SP800-73
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005-2023  Douglas E. Engert <deengert@gmail.com>
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
 * Copyright (C) 2007, EMC, Russell Larner <rlarner@rsa.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#ifdef ENABLE_OPENSSL
	/* openssl needed for card administration and SM */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#if !defined(OPENSSL_NO_EC)
#include <openssl/ec.h>
#endif
#endif

/* 800-73-4 SM and VCI need: ECC, SM and real OpenSSL >= 1.1 */
#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM) && !defined(OPENSSL_NO_EC) && !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
#else
#undef ENABLE_PIV_SM
#endif

#ifdef ENABLE_PIV_SM
#include <openssl/cmac.h>
#include "compression.h"
#endif

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "simpletlv.h"

enum {
	PIV_OBJ_CCC = 0,
	PIV_OBJ_CHUI,
	/*  PIV_OBJ_UCHUI is not in new with 800-73-2 */
	PIV_OBJ_X509_PIV_AUTH,
	PIV_OBJ_CHF,
	PIV_OBJ_PI,
	PIV_OBJ_CHFI,
	PIV_OBJ_X509_DS,
	PIV_OBJ_X509_KM,
	PIV_OBJ_X509_CARD_AUTH,
	PIV_OBJ_SEC_OBJ,
	PIV_OBJ_DISCOVERY,
	PIV_OBJ_HISTORY,
	PIV_OBJ_RETIRED_X509_1,
	PIV_OBJ_RETIRED_X509_2,
	PIV_OBJ_RETIRED_X509_3,
	PIV_OBJ_RETIRED_X509_4,
	PIV_OBJ_RETIRED_X509_5,
	PIV_OBJ_RETIRED_X509_6,
	PIV_OBJ_RETIRED_X509_7,
	PIV_OBJ_RETIRED_X509_8,
	PIV_OBJ_RETIRED_X509_9,
	PIV_OBJ_RETIRED_X509_10,
	PIV_OBJ_RETIRED_X509_11,
	PIV_OBJ_RETIRED_X509_12,
	PIV_OBJ_RETIRED_X509_13,
	PIV_OBJ_RETIRED_X509_14,
	PIV_OBJ_RETIRED_X509_15,
	PIV_OBJ_RETIRED_X509_16,
	PIV_OBJ_RETIRED_X509_17,
	PIV_OBJ_RETIRED_X509_18,
	PIV_OBJ_RETIRED_X509_19,
	PIV_OBJ_RETIRED_X509_20,
	PIV_OBJ_IRIS_IMAGE,
	PIV_OBJ_BITGT,
	PIV_OBJ_SM_CERT_SIGNER,
	PIV_OBJ_PCRDCS,
	PIV_OBJ_9B03,
	PIV_OBJ_9A06,
	PIV_OBJ_9C06,
	PIV_OBJ_9D06,
	PIV_OBJ_9E06,
	PIV_OBJ_8206,
	PIV_OBJ_8306,
	PIV_OBJ_8406,
	PIV_OBJ_8506,
	PIV_OBJ_8606,
	PIV_OBJ_8706,
	PIV_OBJ_8806,
	PIV_OBJ_8906,
	PIV_OBJ_8A06,
	PIV_OBJ_8B06,
	PIV_OBJ_8C06,
	PIV_OBJ_8D06,
	PIV_OBJ_8E06,
	PIV_OBJ_8F06,
	PIV_OBJ_9006,
	PIV_OBJ_9106,
	PIV_OBJ_9206,
	PIV_OBJ_9306,
	PIV_OBJ_9406,
	PIV_OBJ_9506,
	PIV_OBJ_LAST_ENUM
};

/*
 * Flags in the piv_obj_cache:
 * PIV_OBJ_CACHE_VALID means the data in the cache can be used.
 * It might have zero length indicating that the object was not found.
 * PIV_OBJ_CACHE_NOT_PRESENT means do not even try to read the object.
 * Either because the object did not parse or
 * these objects will only be present if the history object says
 * they are on the card, or the discovery or history object in not present.
 * If the file listed in the history object offCardCertURL was found,
 * its certs will be read into the cache and PIV_OBJ_CACHE_VALID set
 * and PIV_OBJ_CACHE_NOT_PRESENT unset.
 *
 */

#define PIV_OBJ_CACHE_VALID		1
#define PIV_OBJ_CACHE_COMPRESSED	2
#define PIV_OBJ_CACHE_NOT_PRESENT	8

typedef struct piv_obj_cache {
	u8* obj_data;
	size_t obj_len;
	u8* internal_obj_data; /* like a cert in the object */
	size_t internal_obj_len;
	int flags;
} piv_obj_cache_t;

enum {
	PIV_STATE_NORMAL = 0,
	PIV_STATE_MATCH,
	PIV_STATE_INIT
};

/* ccc_flags */
#define PIV_CCC_FOUND		0x00000001
#define PIV_CCC_F0_PIV		0x00000002
#define PIV_CCC_F0_CAC		0x00000004
#define PIV_CCC_F0_JAVA		0x00000008
#define PIV_CCC_F3_CAC_PKI	0x00000010

#define PIV_CCC_TAG_F0		0xF0
#define PIV_CCC_TAG_F3		0xF3

/* 800-73-4 Cipher Suite Table 14 */
#define PIV_CS_CS2		0x27
#define PIV_CS_CS7		0x2E

#ifdef ENABLE_PIV_SM
#ifdef USE_OPENSSL3_LIBCTX
#define PIV_LIBCTX card->ctx->ossl3ctx->libctx
#else
#define PIV_LIBCTX NULL
#endif

	/* Table 14 and other constants */
	typedef struct cipher_suite {
		u8 id; /* taken from AID "AC" tag */
		int field_length;
		int nid;     /* for OpenSSL curves */
		struct sc_object_id oid; /* for opensc */
		int p1;	     /* for APDU */
		size_t Qlen; /* size of pubkey 04||x||y for all keys */
		size_t AuthCryptogramlen; /* both H and ICC must match */
		size_t Zlen; /* size of shared secret from ECDH */
		size_t otherinfolen; /* used in 4.1.6  Key Derivation */

		int o0len; /* first in otherinfo */
		u8 o0_char;
		size_t CBhlen;
		size_t T16Qehlen;
		size_t IDsicclen;
		size_t Nicclen;
		size_t CBicclen; /* last in otherinfo */

		int naeskeys; /* number of aes key generated */
		int aeskeylen; /* size of aes key bytes*/
		int kdf_hash_size; /* size of hash in bytes */
		EVP_MD *(*kdf_md)(void);
		const EVP_CIPHER *(*cipher_cbc)(void);
		const EVP_CIPHER *(*cipher_ecb)(void);
		char *cipher_cbc_name;
		char *cipher_ecb_name;
		char *curve_group;
	} cipher_suite_t;

// clang-fromat off
#define PIV_CSS_SIZE 2
static cipher_suite_t css[PIV_CSS_SIZE] = {
		{PIV_CS_CS2, 256, NID_X9_62_prime256v1, {{1, 2, 840, 10045, 3, 1, 7, -1}},
		PIV_CS_CS2, 65, 16, 32, 61,
		4, 0x09, 1, 16, 8, 16, 1,
		4, 128/8, SHA256_DIGEST_LENGTH,
		(EVP_MD *(*)(void)) EVP_sha256,
		(const EVP_CIPHER *(*)(void)) EVP_aes_128_cbc,
		(const EVP_CIPHER *(*)(void)) EVP_aes_128_ecb,
		"aes-128-cbc", "aes-128-ecb",
		"prime256v1"},

		{PIV_CS_CS7, 384, NID_secp384r1, {{1, 3, 132, 0, 34, -1}},
		PIV_CS_CS7, 97, 16, 48, 69,
		4, 0x0D, 1, 16, 8, 24, 1,
		4, 256/8, SHA384_DIGEST_LENGTH,
		(EVP_MD *(*)(void)) EVP_sha384,
		(const EVP_CIPHER *(*)(void)) EVP_aes_256_cbc,
		(const EVP_CIPHER *(*)(void)) EVP_aes_256_ecb,
		"aes-256-cbc", "aes-256-ecb",
		"secp384r1"}
	};
// clang-format on

/* 800-73-4  4.1.5 Card Verifiable Certificates */
typedef struct piv_cvc {
	sc_pkcs15_der_t der;					// Previous read der
	int cpi;						// Certificate profile indicator (0x80)
	char issuerID[8];					// Issuer Identification Number
	size_t issuerIDlen;					//  8 bytes of sha-1 or 16 byte for GUID
	u8  subjectID[16];					//  Subject Identifier (8) or GUID (16)  == CHUI
	size_t subjectIDlen;					//  8 bytes of sha-1 or 16 byte for GUID
	struct sc_object_id pubKeyOID;				// Public key algorithm object identifier
	u8 *publicPoint;					// Public point for ECC
	size_t publicPointlen;
	int roleID;						// Role Identifier 0x00 or 0x12
	u8 *body;						// signed part of CVC in DER
	size_t bodylen;
	struct sc_object_id  signatureAlgOID;			// Signature Algroithm Identifier
	u8 *signature;						// Certificate signature DER
	size_t signaturelen;
} piv_cvc_t;

#define PIV_SM_MAX_FIELD_LENGTH  384
#define PIV_SM_MAX_MD_LENGTH	SHA384_DIGEST_LENGTH

#define PIV_SM_FLAGS_SM_CERT_SIGNER_VERIFIED	0x000000001lu
#define PIV_SM_FLAGS_SM_CVC_VERIFIED		0X000000002lu
#define PIV_SM_FLAGS_SM_IN_CVC_VERIFIED		0x000000004lu
#define PIV_SM_FLAGS_SM_CERT_SIGNER_PRESENT	0x000000010lu
#define PIV_SM_FLAGS_SM_CVC_PRESENT		0X000000020lu
#define PIV_SM_FLAGS_SM_IN_CVC_PRESENT		0x000000040lu
#define PIV_SM_FLAGS_SM_IS_ACTIVE		0x000000080lu	/* SM has been started */
	/* if card supports SP800-73-4 SM: */
#define PIV_SM_FLAGS_NEVER			0x000000100lu	/* Don't use SM even if card support it */
								/* Default is use if card supports it */
								/* will use VCI if card supports it for contactless */
#define PIV_SM_FLAGS_ALWAYS			0x000000200lu	/* Use SM or quit, VCI requires SM */
#define PIV_SM_FLAGS_DEFER_OPEN			0x000001000lu	/* call sm_open from reader_lock_obtained */
#define PIV_SM_VCI_ACTIVE			0x000002000lu   /* VCI is active */
#define PIV_SM_GET_DATA_IN_CLEAR		0x000004000lu	/* OK to do this GET DATA in the clear */

typedef struct piv_sm_session {
	/* set by piv_sm_open */
	int aes_size; /* 128 or 256 */

	u8 SKcfrm[32];
	u8 SKmac[32];
	u8 SKenc[32];  /* keys are either AES 128 or AES 256 */
	u8 SKrmac[32];
	u8 enc_counter[16];
	u8 enc_counter_last[16];

	u8 resp_enc_counter[16];
	u8 C_MCV[16];
	u8 C_MCV_last[16];
	u8 R_MCV[16];
	u8 R_MCV_last[16];
} piv_sm_session_t;

#define C_ASN1_PIV_CVC_PUBKEY_SIZE 3
	/* ECC key only */
static const struct sc_asn1_entry c_asn1_piv_cvc_pubkey[C_ASN1_PIV_CVC_PUBKEY_SIZE] = {
	{ "publicKeyOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "publicPoint", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_DSOBJ_SIZE 2
static const struct sc_asn1_entry c_asn1_piv_cvc_dsobj[C_ASN1_PIV_CVC_DSOBJ_SIZE] = {
	{ "DigitalSignature", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_DSSIG_SIZE 3
static const struct sc_asn1_entry c_asn1_piv_cvc_dssig[C_ASN1_PIV_CVC_DSSIG_SIZE] = {
	{ "signatureAlgorithmID", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "signatureValue", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_ALG_ID_SIZE 3
static const struct sc_asn1_entry c_asn1_piv_cvc_alg_id[C_ASN1_PIV_CVC_ALG_ID_SIZE] = {
	{ "signatureAlgorithmOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "nullParam",  SC_ASN1_NULL, SC_ASN1_UNI | SC_ASN1_TAG_NULL, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_BODY_SIZE 7
static const struct sc_asn1_entry c_asn1_piv_cvc_body[C_ASN1_PIV_CVC_BODY_SIZE] = {
	{ "certificateProfileIdentifier", SC_ASN1_INTEGER, SC_ASN1_APP | 0x1F29, 0, NULL, NULL },
	{ "Issuer ID Number", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "Subject Identifier", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F20, 0, NULL, NULL },
	{ "publicKey", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F49, 0, NULL, NULL },
	{ "roleIdentifier", SC_ASN1_CALLBACK, SC_ASN1_APP | 0x1F4C, 0, NULL, NULL },
	/* signature is over the above 5 entries  treat roleIdentifier special to get end */
	{ "DSignatureObject", SC_ASN1_STRUCT, SC_ASN1_APP | 0x1F37, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


#define C_ASN1_PIV_CVC_SIZE 2
static const struct sc_asn1_entry c_asn1_piv_cvc[C_ASN1_PIV_CVC_SIZE] = {
	{ "CVC certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_SM_RESPONSE_SIZE 4
static const struct sc_asn1_entry c_asn1_sm_response[C_ASN1_PIV_SM_RESPONSE_SIZE] = {
	{ "encryptedData",      SC_ASN1_CALLBACK,   SC_ASN1_CTX | 7,        SC_ASN1_OPTIONAL,       NULL, NULL },
	{ "statusWord",         SC_ASN1_CALLBACK,   SC_ASN1_CTX | 0x19,     0,                      NULL, NULL },
	{ "mac",                SC_ASN1_CALLBACK,   SC_ASN1_CTX | 0x0E,     0,                      NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * SW internal apdu response table.
 *
 * Override APDU response error codes from iso7816.c to allow
 * handling of SM specific error
 */
static const struct sc_card_error piv_sm_errors[] = {
	{0x6882, SC_ERROR_SM, "SM not supported"},
	{0x6982, SC_ERROR_SM_NO_SESSION_KEYS, "SM Security status not satisfied"}, /* no session established */
	{0x6987, SC_ERROR_SM, "Expected SM Data Object missing"},
	{0x6988, SC_ERROR_SM_INVALID_SESSION_KEY, "SM Data Object incorrect"}, /* other process interference */
	{0, 0, NULL}
};
#endif /* ENABLE_PIV_SM */

/* 800-73-4 3.3.2 Discovery Object - PIN Usage Policy */
#define PIV_PP_PIN		0x00004000u
#define PIV_PP_GLOBAL		0x00002000u
#define PIV_PP_OCC		0x00001000u
#define PIV_PP_VCI_IMPL		0x00000800u
#define PIV_PP_VCI_WITHOUT_PC	0x00000400u
#define PIV_PP_PIV_PRIMARY	0x00000010u
#define PIV_PP_GLOBAL_PRIMARY	0x00000020u

/* init_flags */
#define PIV_INIT_AID_PARSED			0x00000001u
#define PIV_INIT_AID_AC				0x00000002u
#define PIV_INIT_DISCOVERY_PARSED		0x00000004u
#define PIV_INIT_DISCOVERY_PP			0x00000008u
#define PIV_INIT_IN_READER_LOCK_OBTAINED	0x00000010u
#define PIV_INIT_CONTACTLESS			0x00000020u

#define PIV_PAIRING_CODE_LEN	 8

typedef struct piv_private_data {
	struct sc_lv_data aid_der; /* previous aid response to compare */
	int enumtag;
	int max_object_size; /* use setable option. In case objects get bigger */
	int selected_obj; /* The index into the piv_objects last selected */
	int return_only_cert; /* return the cert from the object */
	int rwb_state; /* first time -1, 0, in middle, 1 at eof */
	int operation; /* saved from set_security_env */
	unsigned long algorithm; /* saved from set_security_env */
	int key_ref; /* saved from set_security_env and */
	int alg_id;  /* used in decrypt, signature, derive */
	int key_size; /*  RSA: modulus_bits EC: field_length in bits */
	u8* w_buf;   /* write_binary buffer */
	size_t w_buf_len; /* length of w_buff */
	piv_obj_cache_t obj_cache[PIV_OBJ_LAST_ENUM];
	int keysWithOnCardCerts;
	int keysWithOffCardCerts;
	char * offCardCertURL;
	int pin_preference; /* set from Discovery object */
	int logged_in;
	int pstate;
	int pin_cmd_verify;
	int context_specific;
	unsigned int pin_cmd_verify_sw1;
	unsigned int pin_cmd_verify_sw2;
	int tries_left; /* SC_PIN_CMD_GET_INFO tries_left from last */
	unsigned int card_issues; /* card_issues flags for this card */
	int object_test_verify; /* Can test this object to set verification state of card */
	int yubico_version; /* 3 byte version number of NEO or Yubikey4  as integer */
	unsigned int ccc_flags;	    /* From  CCC indicate if CAC card */
	unsigned int pin_policy; /* from discovery */
	unsigned int init_flags;
	u8  csID; /* 800-73-4 Cipher Suite ID 0x27 or 0x2E */
#ifdef ENABLE_PIV_SM
	cipher_suite_t *cs; /* active cipher_suite */
	piv_cvc_t sm_cvc;  /* 800-73-4:  SM CVC Table 15 */
	piv_cvc_t sm_in_cvc; /* Intermediate CVC Table 16 */
	unsigned long  sm_flags;
	unsigned char pairing_code[PIV_PAIRING_CODE_LEN]; /* 8 ASCII digits */
	piv_sm_session_t sm_session;
#endif /* ENABLE_PIV_SM */
} piv_private_data_t;

#define PIV_DATA(card) ((piv_private_data_t*)card->drv_data)

struct piv_aid {
	int enumtag;
	size_t len_short;	/* min length without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};

/*
 * The Generic AID entry should be the "A0 00 00 03 08 00 00 10 00 "
 * NIST published 800-73 on 10/6/2005
 * 800-73-1 March 2006 included Errata
 * 800-73-2 Part 1 implies  version is  "02 00"
 * i.e. "A0 00 00 03 08 00 00 01 00 02 00".
 * but we don't need the version number. But could get it from the PIX.
 * Discovery object was added.
 *
 * 800-73-3 Part 1 now refers to "01 00" i.e. going back to 800-73-1.
 * The main differences between 73-2, and 73-3 are the addition of the
 * key History object, certs and keys and Iris objects.
 * These can be discovered using GET DATA

 * 800-73-4 Has many changes, including optional Secure Messaging,
 * optional Virtual Contact Interface and pairing code.
 */

/* ATRs of cards known to have PIV applet. But must still be tested for a PIV applet */
static const struct sc_atr_table piv_atrs[] = {
	/* CAC cards with PIV from: CAC-utilziation-and-variation-matrix-v2.03-20May2016.doc */
	/*
	 * https://www.cac.mil/Common-Access-Card/Developer-Resources/
	 * https://www.cac.mil/Portals/53/Documents/DoD%20Token%20utilziation%20and%20variation%20matrix%20v2_06_17October2019.docx?ver=2019-10-18-102519-120
	 */
	/* Oberthur Card Systems (PIV Endpoint) with PIV endpoint applet and PIV auth cert OBSOLETE */
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:77:E3:03:00:82:90:00:C1", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },

	/* Gemalto (PIV Endpoint) with PIV endpoint applet and PIV auth cert OBSOLETE */
	{ "3B 7D 96 00 00 80 31 80 65 B0 83 11 13 AC 83 00 90 00", NULL, NULL, SC_CARD_TYPE_PIV_II_GEMALTO, 0, NULL },

	/* Gemalto (PIV Endpoint) 2 entries  2016, 2019 */
	{ "3B:7D:96:00:00:80:31:80:65:B0:83:11:17:D6:83:00:90:00", NULL, NULL, SC_CARD_TYPE_PIV_II_GEMALTO, 0, NULL },

	/* Oberthur Card System (PIV Endpoint)  2 entries 2016, 2019 */
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:B0:F3:10:00:07:90:00:80", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },
	/* Oberthur Card System  with LCS 0F - Some VA cards have Terminated state */
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:B0:F3:10:00:0F:90:00:88", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },

	/* Giesecke & Devrient (PIV Endpoint)  2 entries 2016, 2019 */
	{ "3B:7A:18:00:00:73:66:74:65:20:63:64:31:34:34", NULL, NULL, SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC, 0, NULL },
	/* Giesecke & Devrient (CAC PIV Endpoint) 2019 */
	{ "3B:F9:18:00:00:00:53:43:45:37:20:03:00:20:46", NULL, NULL, SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC, 0, NULL },

	/* IDEMIA (new name for Oberthur) (DoD Alternate Token IDEMIA Cosmo V8.0 2019*/
	{ "3B:D8:18:00:80:B1:FE:45:1F:07:80:31:C1:64:08:06:92:0F:D5", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },
	{ "3b:86:80:01:80:31:c1:52:41:1a:7e", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL }, /* contactless */

	/* Following PIVKEY entries are from Windows registry provided by gw@taglio.com 2022-09-05 */
	/* PIVKEY PIVKey Feitian (02) */
	{ "3b:9f:95:81:31:fe:9f:00:66:46:53:05:10:00:11:71:df:00:00:00:00:00:02", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey Feitian (7C)  aka C910 contactless */
	{ "3b:8c:80:01:90:67:46:4a:00:64:16:06:f2:72:7e:00:7c", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/*PIVKey Feitian (E0)  aka C910 */
	{ "3b:fc:18:00:00:81:31:80:45:90:67:46:4a:00:64:16:06:f2:72:7e:00:e0", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey Feitian (FE)  aka PIVKEY T600 token and T800  on Feitian eJAVA */
	{ "3b:fc:18:00:00:81:31:80:45:90:67:46:4a:00:64:2d:70:c1:72:fe:e0:fe", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP241 (AD) */
	{ "3b:f9:13:00:00:81:31:fe:45:53:50:49:56:4b:45:59:37:30:ad", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP242R2 (16) */
	{ "3b:88:80:01:50:49:56:4b:45:59:37:30:16", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP242R2 (5E) */
	{ "3b:88:80:01:4a:43:4f:50:76:32:34:31:5e", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP242R2 (B7) */
	{ "3b:f8:13:00:00:81:31:fe:45:4a:43:4f:50:76:32:34:31:b7", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP3 (67) */
	{ "3b:88:80:01:46:49:44:45:53:4d:4f:31:67", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP3 (8E) */
	{ "3b:f8:13:00:00:81:31:fe:45:46:49:44:45:53:4d:4f:31:8e", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey JCOP31 (57) */
	{ "3b:f9:18:00:ff:81:31:fe:45:4a:43:4f:50:33:31:56:32:32:57", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey NXP JCOP (03) */
	{ "3b:8a:80:01:01:50:49:56:4b:45:59:37:30:16:03", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey NXP JCOP (FF)  aka CP70 */
	{ "3b:f8:13:00:00:81:31:fe:45:50:49:56:4b:45:59:37:30:ff", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey SLE78 (3B) */
	{ "3b:8d:80:01:53:4c:4a:35:32:47:44:4c:31:32:38:43:52:3b", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey SLE78 (6D) */
	{ "3b:88:80:01:00:00:00:11:77:81:83:00:6d", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey SLE78 (28) aka C980 */
	{ "3b:f9:96:00:00:81:31:fe:45:53:50:49:56:4b:45:59:37:30:28", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey SLE78 (44) aka C980 contactless */
	{ "3b:89:80:01:53:50:49:56:4b:45:59:37:30:44", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey SLE78 (57B) */
	{ "3b:fd:96:00:00:81:31:fe:45:53:4c:4a:35:32:47:44:4c:31:32:38:43:52:57", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey uTrust (01) ISO 14443 Type B without historical bytes */
	{ "3b:80:80:01:01", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey uTrust (73) */
	{ "3b:96:11:81:21:75:75:54:72:75:73:74:73", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },
	/* PIVKey uTrust FIDO2 (73) */
	{ "3b:96:11:81:21:75:75:54:72:75:73:74:73", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },

	/* Swissbit iShield Key Pro with PIV endpoint applet */
	{ "3b:97:11:81:21:75:69:53:68:69:65:6c:64:05", NULL, NULL, SC_CARD_TYPE_PIV_II_SWISSBIT, 0, NULL },

	/* ID-One PIV 2.4.1 on Cosmo V8.1 NIST sp800-73-4 with Secure Messaging and VCI  2020 */
	{ "3b:d6:96:00:81:b1:fe:45:1f:87:80:31:c1:52:41:1a:2a", NULL, NULL, SC_CARD_TYPE_PIV_II_800_73_4, 0, NULL },
	{ "3b:d6:97:00:81:b1:fe:45:1f:87:80:31:c1:52:41:12:23",
	  "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:00:00", NULL, SC_CARD_TYPE_PIV_II_800_73_4, 0, NULL },
	{ "3b:86:80:01:80:31:c1:52:41:12:76", NULL, NULL, SC_CARD_TYPE_PIV_II_800_73_4, 0, NULL }, /* contactless */

	{ NULL, NULL, NULL, 0, 0, NULL }
};

static struct piv_supported_ec_curves {
	struct sc_object_id oid;
	size_t size;
} ec_curves[] = {
	{{{1, 2, 840, 10045, 3, 1, 7, -1}},     256}, /* secp256r1, nistp256, prime256v1, ansiX9p256r1 */
	{{{1, 3, 132, 0, 34, -1}},              384}, /* secp384r1, nistp384, prime384v1, ansiX9p384r1 */
	{{{-1}}, 0} /* This entry must not be touched. */
};

/* all have same AID */
static struct piv_aid piv_aids[] = {
	{SC_CARD_TYPE_PIV_II_GENERIC, /* Not really card type but what PIV AID is supported */
		 9, 9, (u8 *) "\xA0\x00\x00\x03\x08\x00\x00\x10\x00" },
	{0,  9, 0, NULL }
};

/* card_issues - bugs in PIV implementations requires special handling */
#define CI_VERIFY_630X			    0x00000001U /* VERIFY tries left returns 630X rather then 63CX */
#define CI_VERIFY_LC0_FAIL		    0x00000002U /* VERIFY Lc=0 never returns 90 00 if PIN not needed */
							/* will also test after first PIN verify if protected object can be used instead */
#define CI_NO_RANDOM			    0x00000004U /* can not use Challenge to get random data or no 9B key */
#define CI_CANT_USE_GETDATA_FOR_STATE	    0x00000008U /* No object to test verification inplace of VERIFY Lc=0 */
#define CI_LEAKS_FILE_NOT_FOUND		    0x00000010U /* GET DATA of empty object returns 6A 82 even if PIN not verified */
#define CI_DISCOVERY_USELESS		    0x00000020U /* Discovery can not be used to query active AID invalid or no data returned */
#define CI_PIV_AID_LOSE_STATE		    0x00000040U /* PIV AID can lose the login state run with out it*/

#define CI_OTHER_AID_LOSE_STATE		    0x00000100U /* Other drivers match routines may reset our security state and lose AID!!! */
#define CI_NFC_EXPOSE_TOO_MUCH		    0x00000200U /* PIN, crypto and objects exposed over NFS in violation of 800-73-3 */

#define CI_NO_RSA2048			    0x00010000U /* does not have RSA 2048 */
#define CI_NO_EC384			    0x00020000U /* does not have EC 384 */
#define CI_NO_EC			    0x00040000U /* No EC at all */

/*
 * Flags in the piv_object:
 * PIV_OBJECT_NOT_PRESENT: the presents of the object is
 * indicated by the History object.
 */

#define PIV_OBJECT_TYPE_CERT		0x01
#define PIV_OBJECT_TYPE_PUBKEY		0x02
#define PIV_OBJECT_NOT_PRESENT		0x04
#define PIV_OBJECT_TYPE_CVC		0x08 /* is in cert object */
#define PIV_OBJECT_NEEDS_PIN		0x10 /* On both contact and contactless */
#define PIV_OBJECT_NEEDS_VCI		0x20 /* NIST sp800-73-4 Requires VCI on contactless and card enforces this. */
					     /* But also See CI_NFC_EXPOSE_TOO_MUCH for non approved PIV-like cards */

struct piv_object {
	int enumtag;
	const char * name;
	unsigned int resp_tag;
	const char * oidstring;
	size_t tag_len;
	u8  tag_value[3];
	u8  containerid[2];	/* will use as relative paths for simulation */
	int flags;              /* object has some internal object like a cert */
};

/* Must be in order, and one per enumerated PIV_OBJ */
// clang-format off
static const struct piv_object piv_objects[] = {
	{ PIV_OBJ_CCC, "Card Capability Container",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00", PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_CHUI, "Card Holder Unique Identifier",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.48.0", 3, "\x5F\xC1\x02", "\x30\x00", 0},
	{ PIV_OBJ_X509_PIV_AUTH, "X.509 Certificate for PIV Authentication",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.1.1", 3, "\x5F\xC1\x05", "\x01\x01", PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI} ,
	{ PIV_OBJ_CHF, "Card Holder Fingerprints",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x10", PIV_OBJECT_NEEDS_PIN | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_PI, "Printed Information",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x09", "\x30\x01", PIV_OBJECT_NEEDS_PIN | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_CHFI, "Cardholder Facial Images",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30", PIV_OBJECT_NEEDS_PIN | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_X509_DS, "X.509 Certificate for Digital Signature",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.1.0", 3, "\x5F\xC1\x0A", "\x01\x00", PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_X509_KM, "X.509 Certificate for Key Management",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.1.2", 3, "\x5F\xC1\x0B", "\x01\x02", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_X509_CARD_AUTH, "X.509 Certificate for Card Authentication",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.5.0", 3, "\x5F\xC1\x01", "\x05\x00", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_SEC_OBJ, "Security Object",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00", PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_DISCOVERY, "Discovery Object",
			SC_ASN1_APP | SC_ASN1_CONS | 0x1E,
			"2.16.840.1.101.3.7.2.96.80", 1, "\x7E", "\x60\x50", 0},
	{ PIV_OBJ_HISTORY, "Key History Object",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.96.96", 3, "\x5F\xC1\x0C", "\x60\x60", PIV_OBJECT_NEEDS_VCI},

/* 800-73-3, 21 new objects, 20 history certificates */
	{ PIV_OBJ_RETIRED_X509_1, "Retired X.509 Certificate for Key Management 1",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.1", 3, "\x5F\xC1\x0D", "\x10\x01",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_2, "Retired X.509 Certificate for Key Management 2",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.2", 3, "\x5F\xC1\x0E", "\x10\x02",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_3, "Retired X.509 Certificate for Key Management 3",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.3", 3, "\x5F\xC1\x0F", "\x10\x03",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_4, "Retired X.509 Certificate for Key Management 4",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.4", 3, "\x5F\xC1\x10", "\x10\x04",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_5, "Retired X.509 Certificate for Key Management 5",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.5", 3, "\x5F\xC1\x11", "\x10\x05",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_6, "Retired X.509 Certificate for Key Management 6",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.6", 3, "\x5F\xC1\x12", "\x10\x06",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_7, "Retired X.509 Certificate for Key Management 7",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.7", 3, "\x5F\xC1\x13", "\x10\x07",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_8, "Retired X.509 Certificate for Key Management 8",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.8", 3, "\x5F\xC1\x14", "\x10\x08",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_9, "Retired X.509 Certificate for Key Management 9",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.9", 3, "\x5F\xC1\x15", "\x10\x09",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_10, "Retired X.509 Certificate for Key Management 10",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.10", 3, "\x5F\xC1\x16", "\x10\x0A",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_11, "Retired X.509 Certificate for Key Management 11",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.11", 3, "\x5F\xC1\x17", "\x10\x0B",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_12, "Retired X.509 Certificate for Key Management 12",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.12", 3, "\x5F\xC1\x18", "\x10\x0C",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_13, "Retired X.509 Certificate for Key Management 13",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.13", 3, "\x5F\xC1\x19", "\x10\x0D",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_14, "Retired X.509 Certificate for Key Management 14",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.14", 3, "\x5F\xC1\x1A", "\x10\x0E",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_15, "Retired X.509 Certificate for Key Management 15",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.15", 3, "\x5F\xC1\x1B", "\x10\x0F",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_16, "Retired X.509 Certificate for Key Management 16",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.16", 3, "\x5F\xC1\x1C", "\x10\x10",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_17, "Retired X.509 Certificate for Key Management 17",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.17", 3, "\x5F\xC1\x1D", "\x10\x11",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_18, "Retired X.509 Certificate for Key Management 18",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.18", 3, "\x5F\xC1\x1E", "\x10\x12",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_19, "Retired X.509 Certificate for Key Management 19",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.19", 3, "\x5F\xC1\x1F", "\x10\x13",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},
	{ PIV_OBJ_RETIRED_X509_20, "Retired X.509 Certificate for Key Management 20",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.20", 3, "\x5F\xC1\x20", "\x10\x14",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT | PIV_OBJECT_NEEDS_VCI},

	{ PIV_OBJ_IRIS_IMAGE, "Cardholder Iris Images",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.21", 3, "\x5F\xC1\x21", "\x10\x15", PIV_OBJECT_NEEDS_PIN | PIV_OBJECT_NEEDS_VCI},

/* 800-73-4, 3 new objects */
	{ PIV_OBJ_BITGT, "Biometric Information Templates Group Template",
			 SC_ASN1_APP | SC_ASN1_CONS | 0x1F61,
			"2.16.840.1.101.3.7.2.16.22", 2, "\x7F\x61", "\x10\x16", 0},
	{ PIV_OBJ_SM_CERT_SIGNER, "Secure Messaging Certificate Signer",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.23", 3, "\x5F\xC1\x22", "\x10\x17",
			PIV_OBJECT_TYPE_CERT | PIV_OBJECT_TYPE_CVC},
	{PIV_OBJ_PCRDCS, "Pairing Code Reference Data Container",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.16.24", 3, "\x5F\xC1\x23", "\x10\x18", PIV_OBJECT_NEEDS_PIN | PIV_OBJECT_NEEDS_VCI},

/* following not standard , to be used by piv-tool only for testing */
	{ PIV_OBJ_9B03, "3DES-ECB ADM",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.3", 2, "\x9B\x03", "\x9B\x03", 0},
	/* Only used when signing a cert req, usually from engine
	 * after piv-tool generated the key and saved the pub key
	 * to a file. Note RSA key can be 1024, 2048 or 3072
	 * but still use the "9x06" name.
	 */
	{ PIV_OBJ_9A06, "RSA 9A Pub key from last genkey",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.20", 2, "\x9A\x06", "\x9A\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9C06, "Pub 9C key from last genkey",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.21", 2, "\x9C\x06", "\x9C\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9D06, "Pub 9D key from last genkey",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.22", 2, "\x9D\x06", "\x9D\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9E06, "Pub 9E key from last genkey",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.23", 2, "\x9E\x06", "\x9E\x06", PIV_OBJECT_TYPE_PUBKEY},

	{ PIV_OBJ_8206, "Pub 82 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.101", 2, "\x82\x06", "\x82\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8306, "Pub 83 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.102", 2, "\x83\x06", "\x83\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8406, "Pub 84 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.103", 2, "\x84\x06", "\x84\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8506, "Pub 85 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.104", 2, "\x85\x06", "\x85\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8606, "Pub 86 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.105", 2, "\x86\x06", "\x86\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8706, "Pub 87 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.106", 2, "\x87\x06", "\x87\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8806, "Pub 88 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.107", 2, "\x88\x06", "\x88\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8906, "Pub 89 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.108", 2, "\x89\x06", "\x89\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8A06, "Pub 8A key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.109", 2, "\x8A\x06", "\x8A\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8B06, "Pub 8B key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.110", 2, "\x8B\x06", "\x8B\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8C06, "Pub 8C key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.111", 2, "\x8C\x06", "\x8C\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8D06, "Pub 8D key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.112", 2, "\x8D\x06", "\x8D\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8E06, "Pub 8E key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.113", 2, "\x8E\x06", "\x8E\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8F06, "Pub 8F key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.114", 2, "\x8F\x06", "\x8F\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9006, "Pub 90 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.115", 2, "\x90\x06", "\x90\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9106, "Pub 91 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.116", 2, "\x91\x06", "\x91\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9206, "Pub 92 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.117", 2, "\x92\x06", "\x92\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9306, "Pub 93 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.118", 2, "\x93\x06", "\x93\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9406, "Pub 94 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.119", 2, "\x94\x06", "\x94\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9506, "Pub 95 key ",
			SC_ASN1_APP | 0x13,
			"2.16.840.1.101.3.7.2.9999.120", 2, "\x95\x06", "\x95\x06", PIV_OBJECT_TYPE_PUBKEY},
			/*
			 * "Secure Messaging Certificate Signer" is just a certificate.
			 * No pub or private key on the card.
			 */
	{ PIV_OBJ_LAST_ENUM, "", 0, "", 0, "", "", 0}
};
// clang-format on

static struct sc_card_operations piv_ops;

static struct sc_card_driver piv_drv = {
	"Personal Identity Verification Card",
	"PIV-II",
	&piv_ops,
	NULL, 0, NULL
};

static int piv_get_cached_data(sc_card_t * card, int enumtag, u8 **buf, size_t *buf_len);
static int piv_cache_internal_data(sc_card_t *card, int enumtag);
static int piv_logout(sc_card_t *card);
static int piv_match_card_continued(sc_card_t *card);
static int piv_obj_cache_free_entry(sc_card_t *card, int enumtag, int flags);

#ifdef ENABLE_PIV_SM
static void piv_inc(u8 *counter, size_t size);
static int piv_encode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu);
static int piv_get_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu);
static int piv_free_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu);
static int piv_get_asn1_obj(sc_context_t *ctx, void *arg,  const u8 *obj, size_t len, int depth);
static int piv_sm_open(struct sc_card *card);
static int piv_decode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu);
static int piv_sm_close(sc_card_t *card);
static void piv_clear_cvc_content(piv_cvc_t *cvc);
static void piv_clear_sm_session(piv_sm_session_t *session);
static int piv_decode_cvc(sc_card_t * card, u8 **buf, size_t *buflen, piv_cvc_t *cvc);
static int piv_parse_pairing_code(sc_card_t *card, const char *option);
static int Q2OS(int fsize, u8 *Q, size_t Qlen, u8 * OS, size_t *OSlen);
static int piv_send_vci_pairing_code(struct sc_card *card, u8 *paring_code);
static int piv_sm_verify_sig(struct sc_card *card, const EVP_MD *type,
		EVP_PKEY *pkey, u8 *data, size_t data_size,
		unsigned char *sig, size_t siglen);
static int piv_sm_verify_certs(struct sc_card *card);


static void piv_inc(u8 *counter, size_t size)
{
	unsigned int c = 1;
	unsigned int b;
	int i;
	for (i = size - 1; c != 0 && i >= 0; i--){
			b = c + counter[i];
			counter[i] = b & 0xff;
			c = b>>8;
	}
}

/*
 *  Construct SM protected APDU
 */

static int piv_encode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu)
{
	int r = 0;
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;
	u8 pad[16] ={0x80};
	u8 zeros[16] = {0x00};
	u8 IV[16];
	u8 header[16];
	int padlen = 16; /* may be less */
	u8 *sbuf = NULL;
	size_t sbuflen = 0;
	int MCVlen = 16;
	int enc_datalen = 0;
	int T87len;
	int T97len = 2 + 1;
	int T8Elen = 2 + 8;

	int outli = 0;
	int outl = 0;
	int outll = 0;
	int outdl = 0;
	u8 discard[16];
	int macdatalen;
	size_t C_MCVlen = 16; /* debugging*/

	u8 *p;
	EVP_CIPHER_CTX *ed_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC_CTX *cmac_ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n;
#endif

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
	cmac_params_n = 0;
	cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);
	cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
	if (mac == NULL
			|| (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	ed_ctx = EVP_CIPHER_CTX_new();
	if (ed_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_ecb)(), NULL, priv->sm_session.SKenc, zeros) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx, 0) != 1
			|| EVP_EncryptUpdate(ed_ctx, IV, &outli, priv->sm_session.enc_counter, 16) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"SM encode failed in OpenSSL");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	sm_apdu->cla = 0x0c;
	sm_apdu->ins = plain->ins;
	sm_apdu->p1 = plain->p1;
	sm_apdu->p2 = plain->p2;

	/*
	 * All APDUs will be converted to case as SM data is always sent and received
	 * if plain->cse == SC_APDU_CASE_1 it never has the the 0x20 bit set
	 * which "let OpenSC decides whether to use short or extended APDUs"
	 * PIV SM data added for plain->cse == SC_APDU_CASE_1 will not need extended APDUs.
	 *
	 * NIST 800-73-4 does not say if cards can or must support extended APDUs
	 * they must support command chaining and multiple get response APDUs and
	 * all examples use short APDUs. The following keep the option open to use extended
	 * APDUs in future specifications or "PIV like" cards are know to
	 * support extended APDUs.
	 *
	 * Turn off the CASE bits, and set CASE 4 in sm_apdu.
	 */

	sm_apdu->cse = (plain->cse & ~SC_APDU_SHORT_MASK) | SC_APDU_CASE_4_SHORT;

	p = header; /* to be included in CMAC */
	*p++ = 0x0c;
	*p++ = plain->ins;
	*p++ = plain->p1;
	*p++ = plain->p2;
	memcpy(p, pad, 12);

	/* 800-73-4 say padding is 1 to 16 bytes, with 0x80 0x00... */

	/* may not need enc_data for cse 1 or 2 */
	if (plain->datalen == 0) {
		enc_datalen = 0;
		T87len = 0;
		padlen = 0;
	} else {
		enc_datalen = ((plain->datalen + 15) / 16) * 16; /* may add extra 16 bytes */
		padlen = enc_datalen - plain->datalen;
		r = T87len = sc_asn1_put_tag(0x87, NULL, 1 + enc_datalen, NULL, 0, NULL);
		if (r < 0)
			goto err;
	}

	if (plain->resplen == 0 || plain->le == 0)
		T97len = 0;

	sbuflen = T87len + T97len + T8Elen;

	sbuf = calloc(1, sbuflen);
	if (sbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	p = sbuf;
	if (T87len != 0) {
		 r = sc_asn1_put_tag(0x87, NULL, 1 + enc_datalen, sbuf, sbuflen, &p);
		 if (r != SC_SUCCESS)
			goto err;

		*p++ = 0x01; /* padding context indicator */

		/* first round encryptes Enc counter with zero IV, and does not save the output */
		if (EVP_CIPHER_CTX_reset(ed_ctx) != 1
				|| EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_cbc)(), NULL, priv->sm_session.SKenc, IV) != 1
				|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
				|| EVP_EncryptUpdate(ed_ctx, p ,&outl, plain->data, plain->datalen) != 1
				|| EVP_EncryptUpdate(ed_ctx, p + outl, &outll, pad, padlen) != 1
				|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
				|| outdl != 0) {  /* should not happen */
			sc_log_openssl(card->ctx);
			sc_log(card->ctx,"SM _encode failed in OpenSSL");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		p += enc_datalen;
	}

	if (T97len) {
		*p++ = 0x97;
		*p++ = 0x01;
		*p++ = plain->le;
	}
	macdatalen = p - sbuf;

	memcpy(priv->sm_session.C_MCV_last, priv->sm_session.C_MCV, MCVlen); /* save is case fails */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (CMAC_Init(cmac_ctx, priv->sm_session.SKmac, priv->sm_session.aes_size, (*cs->cipher_cbc)(), NULL) != 1
			|| CMAC_Update(cmac_ctx, priv->sm_session.C_MCV, MCVlen) != 1
			|| CMAC_Update(cmac_ctx, header, sizeof(header)) != 1
			|| CMAC_Update(cmac_ctx, sbuf,  macdatalen) != 1
			|| CMAC_Final(cmac_ctx, priv->sm_session.C_MCV, &C_MCVlen) != 1) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	if(!EVP_MAC_init(cmac_ctx, (const unsigned char *)priv->sm_session.SKmac,
				priv->sm_session.aes_size, cmac_params)
			|| !EVP_MAC_update(cmac_ctx, priv->sm_session.C_MCV, MCVlen)
			|| !EVP_MAC_update(cmac_ctx, header, sizeof(header))
			|| !EVP_MAC_update(cmac_ctx, sbuf,  macdatalen)
			|| !EVP_MAC_final(cmac_ctx, priv->sm_session.C_MCV, &C_MCVlen, MCVlen)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	*p++ = 0x8E;
	*p++ = 0x08;
	memcpy(p, priv->sm_session.C_MCV, 8);
	p += 8;
	if (p != sbuf + sbuflen) { /* debugging */
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sm_apdu->data = sbuf;
	sm_apdu->datalen = sbuflen;
	sbuf = NULL;

	sm_apdu->lc = sm_apdu->datalen;
	if (sm_apdu->datalen > 255)
		sm_apdu->flags |= SC_APDU_FLAGS_CHAINING;

	sm_apdu->resplen = plain->resplen + 40; /* expect at least tagged status and rmac8 */
	sm_apdu->resp = malloc(sm_apdu->resplen);
	if (sm_apdu->resp == NULL) {
		r =  SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	sm_apdu->le = 256; /* always ask for 256 */

	memcpy(priv->sm_session.enc_counter_last, priv->sm_session.enc_counter, sizeof(priv->sm_session.enc_counter));
	piv_inc(priv->sm_session.enc_counter, sizeof(priv->sm_session.enc_counter));

	r = SC_SUCCESS;
err:

	free(sbuf);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
#endif

	EVP_CIPHER_CTX_free(ed_ctx);

	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_get_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu)
{
	int r = SC_SUCCESS;
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!plain || !sm_apdu)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* Does card support SM? Should not be here */
	if (priv->csID == 0 || cs == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_SM_NOT_APPLIED);

	switch (plain->ins) {
		case 0xCB: /* GET_DATA */
			/* If not contactless, could read in clear */
			/* Discovery object never has PIV_SM_GET_DATA_IN_CLEAR set */
			sc_log(card->ctx,"init_flags:0x%8.8x sm_flags:0x%8.8lx",priv->init_flags,priv->sm_flags);
			if (!(priv->init_flags & PIV_INIT_CONTACTLESS)
					&& !(priv->init_flags & PIV_INIT_IN_READER_LOCK_OBTAINED)
					&& (priv->sm_flags & PIV_SM_GET_DATA_IN_CLEAR)) {
					priv->sm_flags &= ~PIV_SM_GET_DATA_IN_CLEAR;
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_SM_NOT_APPLIED);
			}
			break;
		case 0x20: /* VERIFY */
			break;
		case 0x24: /* CHANGE REFERENCE DATA */
			break;
		case 0x87: /* GENERAL AUTHENTICATE */
			break;
		default: /* just issue the plain apdu */
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_SM_NOT_APPLIED);
	}

	*sm_apdu = calloc(1, sizeof(sc_apdu_t));
	if (*sm_apdu == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}

	r = piv_encode_apdu(card, plain, *sm_apdu);
	if (r < 0 && *sm_apdu) {
		piv_free_sm_apdu(card, NULL, sm_apdu);
	}

	LOG_FUNC_RETURN(card->ctx, r);
}


/* ASN1 callback to save address and len of the object */
static int piv_get_asn1_obj(sc_context_t *ctx, void *arg,  const u8 *obj, size_t len, int depth)
{
	struct sc_lv_data *al = arg;

	if (!arg)
		return SC_ERROR_INTERNAL;

	al->value = (u8 *)obj;
	al->len = len;
	return SC_SUCCESS;
}

static int piv_decode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu)
{
	int r = SC_SUCCESS;
	int i;
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;
	struct sc_lv_data ee = {NULL, 0};
	struct sc_lv_data status = {NULL, 0};
	struct sc_lv_data rmac8 = {NULL, 0};
	u8 zeros[16] = {0};
	u8 IV[16];
	u8 *p;
	int outl;
	int outli;
	int outll;
	int outdl;
	u8 lastb[16];
	u8 discard[8];
	u8 *q = NULL;
	int inlen;
	int macdatalen;

	size_t MCVlen = 16;
	size_t R_MCVlen = 0;

	EVP_CIPHER_CTX *ed_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *cmac_ctx = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n = 0;
#endif

	struct sc_asn1_entry asn1_sm_response[C_ASN1_PIV_SM_RESPONSE_SIZE];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_copy_asn1_entry(c_asn1_sm_response, asn1_sm_response);

	sc_format_asn1_entry(asn1_sm_response + 0, piv_get_asn1_obj, &ee, 0);
	sc_format_asn1_entry(asn1_sm_response + 1, piv_get_asn1_obj, &status, 0);
	sc_format_asn1_entry(asn1_sm_response + 2, piv_get_asn1_obj, &rmac8, 0);

	r = sc_asn1_decode(card->ctx, asn1_sm_response, sm_apdu->resp, sm_apdu->resplen, NULL, NULL);

	if (r < 0) {
		sc_log(card->ctx,"SM decode failed");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if (asn1_sm_response[0].flags & SC_ASN1_PRESENT  /* optional */
			&& ( ee.value == NULL || ee.len <= 2)) {
		sc_log(card->ctx,"SM BER-TLV not valid");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if ((asn1_sm_response[1].flags & SC_ASN1_PRESENT) == 0
			|| (asn1_sm_response[2].flags & SC_ASN1_PRESENT) == 0) {
		sc_log(card->ctx,"SM missing status or R-MAC");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if (status.len != 2
			|| status.value == NULL
			|| rmac8.len != 8
			|| rmac8.value == NULL) {
		sc_log(card->ctx,"SM status or R-MAC length invalid");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
	cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);
	cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
	if (mac == NULL || (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	/*  MCV is first, then BER TLV Encoded Encrypted PIV Data and Status */
	macdatalen = status.value + status.len - sm_apdu->resp;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (CMAC_Init(cmac_ctx, priv->sm_session.SKrmac, priv->sm_session.aes_size, (*cs->cipher_cbc)(), NULL) != 1
			|| CMAC_Update(cmac_ctx, priv->sm_session.R_MCV, MCVlen) != 1
			|| CMAC_Update(cmac_ctx, sm_apdu->resp, macdatalen) != 1
			|| CMAC_Final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen) != 1) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	if(!EVP_MAC_init(cmac_ctx, (const unsigned char *)priv->sm_session.SKrmac,
				priv->sm_session.aes_size, cmac_params)
			|| !EVP_MAC_update(cmac_ctx, priv->sm_session.R_MCV, MCVlen)
			|| !EVP_MAC_update(cmac_ctx, sm_apdu->resp, macdatalen)
			|| !EVP_MAC_final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen, MCVlen)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	if (memcmp(priv->sm_session.R_MCV, rmac8.value, 8) != 0) {
		sc_log(card->ctx, "SM 8 bytes of R-MAC do not match received R-MAC");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	ed_ctx = EVP_CIPHER_CTX_new();
	if (ed_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* generate same IV used to encrypt response on card */
	if (EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_ecb)(), NULL, priv->sm_session.SKenc, zeros) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
			|| EVP_EncryptUpdate(ed_ctx, IV, &outli, priv->sm_session.resp_enc_counter, 16) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"SM encode failed in OpenSSL");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* some commands do not have response data */
	if (ee.value == NULL) {
		plain->resplen = 0;
	} else {
		p = ee.value;
		inlen = ee.len;
		if (inlen < 17 || *p != 0x01) { /*padding and padding indicator are required */
			sc_log(card->ctx, "SM padding indicator not 0x01");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		p++; /* skip padding indicator */
		inlen --;

		if ((inlen % 16) != 0) {
			sc_log(card->ctx,"SM encrypted data not multiple of 16");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/*
		 * Encrypted data has 1 to 16 pad bytes, so may be 1 to 16 bytes longer
		 * then expected. i.e. plain->resp and resplen.So will do last block
		 * and recombine.
		 */

		inlen -= 16;
		if (plain->resplen < (unsigned) inlen || plain->resp == NULL) {
			sc_log(card->ctx, "SM response will not fit in resp,resplen");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		q = plain->resp;

		/* first round encryptes counter with zero IV, and does not save the output */
		if (EVP_CIPHER_CTX_reset(ed_ctx) != 1
				|| EVP_DecryptInit_ex(ed_ctx, (*cs->cipher_cbc)(), NULL, priv->sm_session.SKenc, IV) != 1
				|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
				|| EVP_DecryptUpdate(ed_ctx, q ,&outl, p, inlen) != 1
				|| EVP_DecryptUpdate(ed_ctx, lastb, &outll, p + inlen, 16 ) != 1
				|| EVP_DecryptFinal_ex(ed_ctx, discard, &outdl) != 1
				|| outdl != 0
				|| outll != 16) {  /* should not happen */
			sc_log_openssl(card->ctx);
			sc_log(card->ctx,"SM _decode failed in OpenSSL");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* unpad last block and get bytes in last block */
		for (i = 15; i >  0 ; i--) {
			if (lastb[i] == 0x80)
				break;
			if (lastb[i] == 0x00)
				continue;
			sc_log(card->ctx, "SM Padding not correct");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		if (lastb[i] != 0x80) {
			sc_log(card->ctx, "SM Padding not correct");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* will response fit in plain resp buffer */
		if ((unsigned)inlen + i > plain->resplen || plain->resp == NULL) {
			sc_log(card->ctx,"SM response bigger then resplen");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* copy bytes in last block  if any */
		memcpy(plain->resp + inlen, lastb, i);
		plain->resplen = inlen + i;
	}

	plain->sw1 = *(status.value);
	plain->sw2 = *(status.value + 1);

	piv_inc(priv->sm_session.resp_enc_counter, sizeof(priv->sm_session.resp_enc_counter));

	r = SC_SUCCESS;
err:
	if (r != 0 && plain) {
		plain->sw1 = 0x69;
		plain->sw2 = 0x88;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
#endif

	EVP_CIPHER_CTX_free(ed_ctx);

	LOG_FUNC_RETURN(card->ctx, r);
}

static int piv_free_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!sm_apdu)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (!(*sm_apdu))
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (plain) {
		plain->sw1 = (*sm_apdu)->sw1;
		plain->sw2 = (*sm_apdu)->sw2;
		if (((*sm_apdu)->sw1 == 0x90 && (*sm_apdu)->sw2 == 00)
				|| (*sm_apdu)->sw1 == 61){
			r  = piv_decode_apdu(card, plain, *sm_apdu);
			goto err;
		}
		sc_log(card->ctx,"SM response sw1:0x%2.2x sw2:0x%2.2x", plain->sw1, plain->sw2);
		if (plain->sw1 == 0x69 && plain->sw2 == 0x88) {
			/* BUT plain->sw1 and sw2 are not passed back as expected */
			r = SC_ERROR_SM_INVALID_CHECKSUM; /* will use this one one for now */
			goto err;
		} else {
			r = SC_ERROR_SM;
			goto err;
		}
	}

err:
	free((unsigned char **)(*sm_apdu)->data);
	free((*sm_apdu)->resp);
	free(*sm_apdu);
	*sm_apdu = NULL;

	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_sm_close(sc_card_t *card)
{
	int r = 0;
	piv_private_data_t * priv = PIV_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, "priv->sm_flags: 0x%8.8lu", priv->sm_flags);

	/* sm.c tries to restart sm. Will defer */
	if ((priv->sm_flags & PIV_SM_FLAGS_SM_IS_ACTIVE)) {
		priv->sm_flags |= PIV_SM_FLAGS_DEFER_OPEN;
		priv->sm_flags &= ~PIV_SM_FLAGS_SM_IS_ACTIVE;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static void piv_clear_cvc_content(piv_cvc_t *cvc)
{
	if (!cvc)
		return;
	free(cvc->body);
	free(cvc->signature);
	free(cvc->publicPoint);
	free(cvc->der.value);
	memset(cvc, 0, sizeof(piv_cvc_t));
	return;
}

static void piv_clear_sm_session(piv_sm_session_t *session)
{
	if (!session)
		return;
	sc_mem_clear(session, sizeof(piv_sm_session_t));
	return;
}

/*
 * Decode a card verifiable certificate as defined in NIST 800-73-4
 */
static int piv_decode_cvc(sc_card_t * card, u8 **buf, size_t *buflen,
	piv_cvc_t *cvc)
{
	struct sc_asn1_entry asn1_piv_cvc[C_ASN1_PIV_CVC_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_body[C_ASN1_PIV_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_pubkey[C_ASN1_PIV_CVC_PUBKEY_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_dsobj[C_ASN1_PIV_CVC_DSOBJ_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_dssig[C_ASN1_PIV_CVC_DSSIG_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_alg_id[C_ASN1_PIV_CVC_ALG_ID_SIZE];
	struct sc_lv_data roleIDder = {NULL, 0};
	int r;
	const u8 *buf_tmp;
	unsigned int cla_out, tag_out;
	size_t taglen;
	size_t signaturebits;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (buf == NULL || *buf == NULL || cvc == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* If already read and matches previous version return SC_SUCCESS */
	if (cvc->der.value && (cvc->der.len == *buflen) && (memcmp(cvc->der.value, *buf, *buflen) == 0))
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	piv_clear_cvc_content(cvc);

	memset(cvc, 0, sizeof(piv_cvc_t));
	cvc->issuerIDlen = sizeof(cvc->issuerID);
	cvc->subjectIDlen = sizeof(cvc->subjectID);

	sc_copy_asn1_entry(c_asn1_piv_cvc, asn1_piv_cvc);
	sc_copy_asn1_entry(c_asn1_piv_cvc_body, asn1_piv_cvc_body);
	sc_copy_asn1_entry(c_asn1_piv_cvc_pubkey, asn1_piv_cvc_pubkey);
	sc_copy_asn1_entry(c_asn1_piv_cvc_dsobj, asn1_piv_cvc_dsobj);
	sc_copy_asn1_entry(c_asn1_piv_cvc_dssig, asn1_piv_cvc_dssig);
	sc_copy_asn1_entry(c_asn1_piv_cvc_alg_id, asn1_piv_cvc_alg_id);

	sc_format_asn1_entry(asn1_piv_cvc_alg_id    , &cvc->signatureAlgOID, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_alg_id + 1, NULL, NULL, 1); /* NULL */

	sc_format_asn1_entry(asn1_piv_cvc_dssig    , &asn1_piv_cvc_alg_id, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_dssig + 1, &cvc->signature, &signaturebits, 1);

	sc_format_asn1_entry(asn1_piv_cvc_dsobj    , &asn1_piv_cvc_dssig, NULL, 1);

	sc_format_asn1_entry(asn1_piv_cvc_pubkey    , &cvc->pubKeyOID, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_pubkey + 1, &cvc->publicPoint, &cvc->publicPointlen, 1);

	sc_format_asn1_entry(asn1_piv_cvc_body    , &cvc->cpi, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 1, &cvc->issuerID, &cvc->issuerIDlen, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 2, &cvc->subjectID, &cvc->subjectIDlen, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 3, &asn1_piv_cvc_pubkey, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 4, piv_get_asn1_obj, &roleIDder, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 5, &asn1_piv_cvc_dsobj, NULL, 1);

	sc_format_asn1_entry(asn1_piv_cvc, &asn1_piv_cvc_body, NULL, 1);

	r = sc_asn1_decode(card->ctx, asn1_piv_cvc, *buf, *buflen, NULL, NULL) ; /*(const u8 **) &buf_tmp, &len);*/
	if (r < 0) {
		piv_clear_cvc_content(cvc);
		sc_log(card->ctx, "Could not decode card verifiable certificate");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	cvc->signaturelen = signaturebits / 8;

	if (roleIDder.len != 1)
		LOG_TEST_RET(card->ctx, SC_ERROR_SM_AUTHENTICATION_FAILED, "roleID wrong length");

	cvc->roleID = *roleIDder.value;

	/* save body der for verification */
	buf_tmp = *buf;
	r = sc_asn1_read_tag(&buf_tmp, *buflen, &cla_out, &tag_out, &taglen);
	LOG_TEST_RET(card->ctx, r," failed to read tag");

	cvc->bodylen = (roleIDder.value + roleIDder.len) - buf_tmp;

	cvc->body = malloc(cvc->bodylen);
	if (cvc->body == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(cvc->body, buf_tmp, cvc->bodylen);

	/* save to reuse */
	cvc->der.value = malloc(*buflen);
	if (cvc->der.value == NULL) {
		free(cvc->body);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	cvc->der.len = *buflen;
	memcpy(cvc->der.value, *buf, cvc->der.len);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int piv_parse_pairing_code(sc_card_t *card, const char *option)
{
	size_t i;

	if (strlen(option) != PIV_PAIRING_CODE_LEN) {
		sc_log(card->ctx, "pairing code length invalid must be %d", PIV_PAIRING_CODE_LEN);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	for (i = 0; i < PIV_PAIRING_CODE_LEN; i++) {
		if (!isdigit(option[i])) {
			sc_log(card->ctx, "pairing code must be %d decimal digits",PIV_PAIRING_CODE_LEN);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}
	return SC_SUCCESS;
}
#endif

static int piv_load_options(sc_card_t *card)
{
	int r;
	size_t i, j;
	scconf_block **found_blocks, *block;

#ifdef ENABLE_PIV_SM
	piv_private_data_t * priv = PIV_DATA(card);
	const char *option = NULL;
	int piv_pairing_code_found = 0;
	int piv_use_sm_found = 0;

	/* pairing code is 8 decimal digits and is card specific */
	if ((option = getenv("PIV_PAIRING_CODE")) != NULL) {
		sc_log(card->ctx,"getenv(\"PIV_PAIRING_CODE\") found");
		if (piv_parse_pairing_code(card, option) == SC_SUCCESS) {
			memcpy(priv->pairing_code, option, PIV_PAIRING_CODE_LEN);
			piv_pairing_code_found = 1;
		}
	}

	if ((option = getenv("PIV_USE_SM"))!= NULL) {
		sc_log(card->ctx,"getenv(\"PIV_USE_SM\")=\"%s\"", option);
		if (!strcmp(option, "never")) {
			priv->sm_flags |= PIV_SM_FLAGS_NEVER;
			piv_use_sm_found = 1;
		}
		else if (!strcmp(option, "always")) {
			priv->sm_flags |= PIV_SM_FLAGS_ALWAYS;
			piv_use_sm_found = 1;
		}
		else {
			sc_log(card->ctx,"Invalid piv_use_sm: \"%s\"", option);
		}
	}
#endif

	for (i = 0; card->ctx->conf_blocks[i]; i++) {
		found_blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
				"card_driver", "PIV-II");
		if (!found_blocks)
			continue;

		for (j = 0, block = found_blocks[j]; block; j++, block = found_blocks[j]) {

#ifdef ENABLE_PIV_SM

/*
 * FIXME TODO - Names and locations of piv_pairing_code and piv_use_sm are likely to change in the future.
 * See https://github.com/OpenSC/OpenSC/pull/2053/files#r1267388721
 */
			/*
			 * "piv_use_sm" if card supports NIST sp800-73-4 sm, when should it be used
			 * never - use card like 800-73-3, i.e. contactless is very limited on
			 * true PIV cards. Some  PIV-like" card may allow this.
			 * this security risk
			 * always - Use even for contact interface.
			 * PINS, crypto and reading of object will not show up in logs
			 * or over network.
			 */

			if (piv_use_sm_found == 0) {
				option = scconf_get_str(block, "piv_use_sm", "default");
				sc_log(card->ctx,"conf: \"piv_use_sm\"=\"%s\"", option);
				if  (!strcmp(option,"default")) {
					/* no new flags */
				}
				else if (!strcmp(option, "never")) {
					priv->sm_flags |= PIV_SM_FLAGS_NEVER;
				}
				else if (!strcmp(option, "always")) {
					priv->sm_flags |= PIV_SM_FLAGS_ALWAYS;
				}
				else {
					sc_log(card->ctx,"Invalid piv_use_sm: \"%s\"", option);
				}
			}

			/* This is really a card specific value and should not be in the conf file */
			if (piv_pairing_code_found == 0) {
				option = scconf_get_str(block, "piv_pairing_code", NULL);
				if (option && piv_parse_pairing_code(card, option) == SC_SUCCESS) {
					memcpy(priv->pairing_code, option, PIV_PAIRING_CODE_LEN);
				}
			}
#endif
		}
		free(found_blocks);
	 }
	 r = SC_SUCCESS;
	 return r;
}

static int
piv_find_obj_by_containerid(sc_card_t *card, const u8 * str)
{
	int i;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "str=0x%02X%02X\n", str[0], str[1]);

	for (i = 0; piv_objects[i].enumtag < PIV_OBJ_LAST_ENUM; i++) {
		if ( str[0] == piv_objects[i].containerid[0] && str[1] == piv_objects[i].containerid[1])
			LOG_FUNC_RETURN(card->ctx, i);
	}

	LOG_FUNC_RETURN(card->ctx, -1);
}

/*
 * Send a command and receive data. There is always something to send.
 * Used by  GET DATA, PUT DATA, GENERAL AUTHENTICATE
 * and GENERATE ASYMMETRIC KEY PAIR.
 */

static int piv_general_io(sc_card_t *card, int ins, int p1, int p2,
	const u8 * sendbuf, size_t sendbuflen, u8 *recvbuf,
	size_t recvbuflen)
{
	int r;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

	sc_format_apdu(card, &apdu,
			recvbuf ? SC_APDU_CASE_4_SHORT: SC_APDU_CASE_3_SHORT,
			ins, p1, p2);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
#ifdef ENABLE_PIV_SM
	if (card->sm_ctx.sm_mode != SM_MODE_NONE && sendbuflen > 255) {
		/* tell apdu.c to not do the chaining, let the SM get_apdu do it */
		apdu.flags |= SC_APDU_FLAGS_SM_CHAINING;
	}
#endif
	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf && recvbuflen) {
		apdu.le = (recvbuflen > 256) ? 256 : recvbuflen;
		apdu.resplen = recvbuflen;
	} else {
		apdu.le = 0;
		apdu.resplen = 0;
	}
	apdu.resp =  recvbuf;

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	/* adpu will not have sw1,sw2 set because sc_sm_single_transmit called sc_sm_stop, */
	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}

	if (apdu.sw1 == 0x69 && apdu.sw2 ==  0x88)
		r = SC_ERROR_SM_INVALID_SESSION_KEY;
	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r < 0) {
		sc_log(card->ctx,  "Card returned error ");
		goto err;
	}

	r = (int)apdu.resplen;

err:
	sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
}


#ifdef ENABLE_PIV_SM
/* convert q as 04||x||y used in standard point formats to expanded leading
 * zeros and concatenated X||Y as specified in SP80056A Appendix C.2
 * Field-Element-to-Byte-String Conversion which
 * OpenSSL has already converted X and Y to big endian and skipped leading
 * zero bytes.
 */
static int Q2OS(int fsize, u8 *Q, size_t Qlen, u8 * OS, size_t *OSlen)
{
	size_t i;
	size_t f = fsize/8;

	i = (Qlen - 1)/2;

	if (!OS || *OSlen < f * 2 || !Q || i > f)
		return SC_ERROR_INTERNAL;

	memset(OS, 0, f * 2);
	/* Check this if x and y have leading zero bytes,
	 * In UNCOMPRESSED FORMAT, x and Y must be same length, to tell when
	 * one ends and the other starts */
	memcpy(OS + f - i, Q + 1, i);
	memcpy(OS + 2 * f - i, Q + f + 1, i);
	*OSlen = f * 2;
	return 0;
}

/*
 * if needed, send VCI pairing code to card just after the
 * SM key establishment. Called from piv_sm_open under same lock
 */
static int piv_send_vci_pairing_code(struct sc_card *card, u8 *paring_code)
{
	int r;
	piv_private_data_t * priv = PIV_DATA(card);
	sc_apdu_t plain;
	sc_apdu_t sm_apdu;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (priv->pin_policy & PIV_PP_VCI_WITHOUT_PC)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS); /* Not needed */

	if ((priv->pin_policy & PIV_PP_VCI_IMPL) == 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NO_CARD_SUPPORT);

	sc_format_apdu(card, &plain, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x98);
	plain.datalen = plain.lc = 8;
	plain.data = paring_code;
	plain.resp = NULL;
	plain.resplen = plain.le = 0;

	memset(&sm_apdu,0,sizeof(sm_apdu));
	/* build sm_apdu and set alloc sm_apdu.resp */
	r = piv_encode_apdu(card, &plain, &sm_apdu);
	if (r < 0) {
		free(sm_apdu.resp);
		sc_log(card->ctx, "piv_encode_apdu failed");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	sm_apdu.flags += SC_APDU_FLAGS_NO_SM; /* run as is */
	r = sc_transmit_apdu(card, &sm_apdu);
	if (r < 0) {
		free(sm_apdu.resp);
		sc_log(card->ctx, "transmit failed");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	r = piv_decode_apdu(card, &plain, &sm_apdu);
	free(sm_apdu.resp);
	LOG_TEST_RET(card->ctx, r, "piv_decode_apdu failed");

	r = sc_check_sw(card, plain.sw1, plain.sw2);
	if (r < 0)
		r = SC_ERROR_PIN_CODE_INCORRECT;

	LOG_FUNC_RETURN(card->ctx, r);
}

/* Verify one signature using pubkey */
static int piv_sm_verify_sig(struct sc_card *card, const EVP_MD *type,
		EVP_PKEY *pkey,
		u8 *data, size_t data_size,
		unsigned char *sig, size_t siglen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;
	int r = 0;
	EVP_MD_CTX *md_ctx = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (cs == NULL) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if ((md_ctx = EVP_MD_CTX_new()) == NULL
			|| EVP_DigestVerifyInit(md_ctx, NULL, type, NULL, pkey) != 1
			|| EVP_DigestVerifyUpdate(md_ctx, data, data_size) != 1
			|| EVP_DigestVerifyFinal(md_ctx, sig, siglen) != 1) {
		sc_log_openssl(card->ctx);
		sc_log (card->ctx, "EVP_DigestVerifyFinal failed");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	r = SC_SUCCESS;
err:
	EVP_MD_CTX_free(md_ctx);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * If sm_in_cvc is present, verify PIV_OBJ_SM_CERT_SIGNER signed sm_in_cvc
 * and sm_in_cvc signed sm_cvc.
 * If sm_in_cvc is not present verify PIV_OBJ_SM_CERT_SIGNER signed sm_cvc.
 */


static int piv_sm_verify_certs(struct sc_card *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;
	int r = 0;
	u8 *cert_blob_unzipped = NULL; /* free */
	u8 *cert_blob = NULL; /* do not free */
	size_t cert_bloblen = 0;

	u8 *rbuf; /* do not free*/
	size_t rbuflen;
	X509 *cert = NULL;
	EVP_PKEY *cert_pkey =  NULL; /* do not free */
	EVP_PKEY *in_cvc_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP *in_cvc_group = NULL;
	EC_POINT *in_cvc_point = NULL;
	EC_KEY *in_cvc_eckey = NULL;
#else
	EVP_PKEY_CTX *in_cvc_pkey_ctx = NULL;
	OSSL_PARAM params[3];
	size_t params_n;
#endif

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* TODO if already verified we could return
	 * may need to verify again, if card reset?
	 */

	if (cs == NULL) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/*
	 * Get the PIV_OBJ_SM_CERT_SIGNER and optional sm_in_cvc in cache
	 * both are in same object. Rbuf, and rbuflen are needed but not used here
	 * sm_cvc and sm_in_cvc both have EC_keys sm_in_cvc may have RSA signature
	 */
	r = piv_get_cached_data(card, PIV_OBJ_SM_CERT_SIGNER, &rbuf, &rbuflen);
	if (r < 0) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	r = piv_cache_internal_data(card,PIV_OBJ_SM_CERT_SIGNER);
	if (r < 0) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	priv->sm_flags |= PIV_SM_FLAGS_SM_CERT_SIGNER_PRESENT; /* set for debugging */

	/* get PIV_OBJ_SM_CERT_SIGNER cert DER  from cache */
	if (priv->obj_cache[PIV_OBJ_SM_CERT_SIGNER].flags & PIV_OBJ_CACHE_COMPRESSED) {
#ifdef ENABLE_ZLIB
		if (SC_SUCCESS != sc_decompress_alloc(&cert_blob_unzipped, &cert_bloblen,
				priv->obj_cache[PIV_OBJ_SM_CERT_SIGNER].internal_obj_data,
				priv->obj_cache[PIV_OBJ_SM_CERT_SIGNER].internal_obj_len,
				COMPRESSION_AUTO)) {
			sc_log(card->ctx, "PIV decompression of SM CERT_SIGNER failed");
			r = SC_ERROR_OBJECT_NOT_VALID;
			goto err;
		}
		cert_blob = cert_blob_unzipped;
#else
		sc_log(card->ctx, "PIV compression not supported, no zlib");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
#endif

	} else {
		cert_blob = priv->obj_cache[PIV_OBJ_SM_CERT_SIGNER].internal_obj_data;
		cert_bloblen = priv->obj_cache[PIV_OBJ_SM_CERT_SIGNER].internal_obj_len;
	}

	if (cert_blob == NULL || cert_bloblen == 0) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if ((cert = d2i_X509(NULL, (const u8 **)&cert_blob, cert_bloblen)) == NULL
			|| (cert_pkey = X509_get0_pubkey(cert)) == NULL) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"OpenSSL failed to get pubkey from SM_CERT_SIGNER");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* if intermediate sm_in_cvc present, cert signed it and sm_cvc is signed by sm_in_cvc */
	if (priv->sm_flags & PIV_SM_FLAGS_SM_IN_CVC_PRESENT) {
		r = piv_sm_verify_sig(card, cs->kdf_md(), cert_pkey,
				priv->sm_in_cvc.body, priv->sm_in_cvc.bodylen,
				priv->sm_in_cvc.signature,priv->sm_in_cvc.signaturelen);
		if (r < 0) {
			sc_log(card->ctx,"sm_in_cvc signature invalid");
			r =  SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if ((in_cvc_group = EC_GROUP_new_by_curve_name(cs->nid)) == NULL
				|| (in_cvc_pkey = EVP_PKEY_new()) == NULL
				|| (in_cvc_eckey = EC_KEY_new_by_curve_name(cs->nid)) == NULL
				|| (in_cvc_point = EC_POINT_new(in_cvc_group)) == NULL
				|| EC_POINT_oct2point(in_cvc_group, in_cvc_point,
					priv->sm_in_cvc.publicPoint, priv->sm_in_cvc.publicPointlen, NULL) <= 0
				|| EC_KEY_set_public_key(in_cvc_eckey, in_cvc_point) <= 0
				|| EVP_PKEY_set1_EC_KEY(in_cvc_pkey, in_cvc_eckey) != 1) {
			sc_log_openssl(card->ctx);
			sc_log(card->ctx, "OpenSSL failed to set EC pubkey, during verify");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
#else
		params_n = 0;
		params[params_n++] = OSSL_PARAM_construct_utf8_string("group", cs->curve_group, 0);
		params[params_n++] = OSSL_PARAM_construct_octet_string("pub",
				priv->sm_in_cvc.publicPoint, priv->sm_in_cvc.publicPointlen);
		params[params_n] = OSSL_PARAM_construct_end();

		if (!(in_cvc_pkey_ctx = EVP_PKEY_CTX_new_from_name(PIV_LIBCTX, "EC", NULL))
				|| !EVP_PKEY_fromdata_init(in_cvc_pkey_ctx)
				|| !EVP_PKEY_fromdata(in_cvc_pkey_ctx, &in_cvc_pkey, EVP_PKEY_PUBLIC_KEY, params)
				|| !in_cvc_pkey) {
			sc_log_openssl(card->ctx);
			sc_log(card->ctx, "OpenSSL failed to set EC pubkey, during verify");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
#endif
		r = piv_sm_verify_sig(card, cs->kdf_md(), in_cvc_pkey,
				priv->sm_cvc.body, priv->sm_cvc.bodylen,
				priv->sm_cvc.signature,priv->sm_cvc.signaturelen);

	} else { /* cert signed  sm_cvc */
		r = piv_sm_verify_sig(card, cs->kdf_md(), cert_pkey,
				priv->sm_cvc.body, priv->sm_cvc.bodylen,
				priv->sm_cvc.signature,priv->sm_cvc.signaturelen);
	}
	if (r < 0) {
		sc_log(card->ctx,"sm_cvc signature invalid");
		r =  SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* cert chain signatures match for oncard certs */
	/* TODO check dates and other info as per 800-73-4 */

	/* TODO check against off card CA chain if present,
	 * Need opensc.conf options:
	 *	where is CA cert chain?
	 *	is it required?
	 *	check for revocation?
	 *	How often to check for revocation?
	 *	When is SM used?
	 *		Using NFC?
	 *			(yes, main point of using SM)
	 *		Should reading certificates be done in clear?
	 *			(performance vs security)
	 *		All crypto operations and PIN ?
	 *			(yes for security)
	 */
err:
	X509_free(cert);
	free(cert_blob_unzipped);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP_free(in_cvc_group);
	EC_POINT_free(in_cvc_point);
	EC_KEY_free(in_cvc_eckey);
#else
	EVP_PKEY_CTX_free(in_cvc_pkey_ctx);
#endif
	EVP_PKEY_free(in_cvc_pkey);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


/*
 * NIST SP800-73-4  4.1 The key Establishment Protocol
 * Variable names and Steps  are based on Client Application (h)
 * and PIV Card Application (icc)
 * Capital leters used for variable, and lower case for subscript names
 */
static int piv_sm_open(struct sc_card *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	cipher_suite_t *cs = priv->cs;
	int r = 0;
	int i;
	int reps;
	u8 CBh;
	u8 CBicc;
	u8 *p;

	/* ephemeral EC key */
	EVP_PKEY_CTX *eph_ctx = NULL;
	EVP_PKEY *eph_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *eph_eckey = NULL; /* don't free _get0_*/
	const EC_GROUP *eph_group = NULL; /* don't free _get0_ */
#else
	OSSL_PARAM eph_params[5];
	size_t eph_params_n;
	size_t Qehxlen = 0;
	u8 *Qehx = NULL;
#endif
	size_t Qehlen = 0;
	u8 Qeh[2 * PIV_SM_MAX_FIELD_LENGTH/8 + 1]; /*  big enough for 384 04||x||y  if x and y have leading zeros, length may be less */
	size_t Qeh_OSlen = 0;
	u8 Qeh_OS[2 * PIV_SM_MAX_FIELD_LENGTH/8]; /* no leading 04, with leading zeros in X and Y */
	size_t Qsicc_OSlen = 0;
	u8 Qsicc_OS[2 * PIV_SM_MAX_FIELD_LENGTH/8]; /* no leading 04, with leading zeros  in X and Y */

	/* pub EC key from card Cicc in sm_cvc */
	EVP_PKEY_CTX *Cicc_ctx = NULL;
	EVP_PKEY *Cicc_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *Cicc_eckey = NULL;
	EC_POINT *Cicc_point = NULL;
	EC_GROUP *Cicc_group = NULL;
#endif

	/* shared secret key Z */
	EVP_PKEY_CTX *Z_ctx = NULL;
	u8 *Z = NULL;
	size_t Zlen = 0;

	u8  IDsh[8] = {0};
	unsigned long  pid;

	u8 *sbuf = NULL;
	size_t sbuflen;
	int len2a, len2b;

	u8 rbuf[4096];
	size_t rbuflen = sizeof(rbuf);

	const u8 *body, *payload;
	size_t bodylen, payloadlen;
	u8 Nicc[24]; /* nonce */
	u8 AuthCryptogram[16];

	u8 *cvcder = NULL;
	size_t cvclen = 0;
	size_t len; /* temp len */

	u8 *kdf_in = NULL;
	size_t kdf_inlen = 0;
	unsigned int hashlen = 0;
	u8 aeskeys[SHA384_DIGEST_LENGTH * 3] = {0}; /*  4 keys, Hash function is run 2 or 3 times max is 3 * 384/8 see below */
	EVP_MD_CTX *hash_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *cmac_ctx = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n = 0;
	OSSL_PARAM Cicc_params[3];
	size_t Cicc_params_n = 0;
#endif

	u8 IDsicc[8]; /* will only use 8 bytes for step H6 */

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/*
	 * The SM routines try and call this on their own.
	 * This routine should only be called by the card driver.
	 * which has set PIV_SM_FLAGS_DEFER_OPEN and unset in
	 * in reader_lock_obtained
	 * after testing PIC applet is active so SM is setup in same transaction
	 * as the command we are trying to run with SM.
	 * this avoids situation where the SM is established, and then reset by
	 * some other application without getting anything done or in
	 * a loop, each trying to reestablish a SM session and run command.
	 */
	if (!(priv->sm_flags & PIV_SM_FLAGS_DEFER_OPEN)) {
		LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_ALLOWED);
	}
	if (cs == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = sc_lock(card);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "sc_lock failed");
		return r;
	}

	/* use for several hash operations */
	if ((hash_ctx = EVP_MD_CTX_new()) == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Step 1 set CBh = 0 */
	CBh = 0;

	/* Step H2 generate ephemeral EC */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if ((eph_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL
			|| EVP_PKEY_keygen_init(eph_ctx) <= 0
			|| EVP_PKEY_CTX_set_ec_paramgen_curve_nid(eph_ctx, cs->nid) <= 0
			|| EVP_PKEY_keygen(eph_ctx, &eph_pkey) <= 0
			|| (eph_eckey = EVP_PKEY_get0_EC_KEY(eph_pkey)) == NULL
			|| (eph_group = EC_KEY_get0_group(eph_eckey)) == NULL
			|| (Qehlen = EC_POINT_point2oct(eph_group, EC_KEY_get0_public_key(eph_eckey),
				POINT_CONVERSION_UNCOMPRESSED, NULL, Qehlen, NULL)) <= 0 /* get length */
			|| Qehlen > cs->Qlen
			|| (Qehlen = EC_POINT_point2oct(eph_group, EC_KEY_get0_public_key(eph_eckey),
				POINT_CONVERSION_UNCOMPRESSED, Qeh, Qehlen, NULL)) <= 0
			|| Qehlen > cs->Qlen) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"OpenSSL failed to create ephemeral EC key");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	/* generate Qeh */
	eph_params_n = 0;
	eph_params[eph_params_n++] = OSSL_PARAM_construct_utf8_string( "group", cs->curve_group, 0);
	eph_params[eph_params_n++] = OSSL_PARAM_construct_utf8_string( "point-format","uncompressed", 0);
	eph_params[eph_params_n] = OSSL_PARAM_construct_end();
	if (!(eph_ctx = EVP_PKEY_CTX_new_from_name(PIV_LIBCTX, "EC", NULL))  /* TODO should be FIPS */
			|| !EVP_PKEY_keygen_init(eph_ctx)
			|| !EVP_PKEY_CTX_set_params(eph_ctx, eph_params)
			|| !EVP_PKEY_generate(eph_ctx, &eph_pkey)
			|| !(Qehxlen = EVP_PKEY_get1_encoded_public_key(eph_pkey, &Qehx))
			|| !Qehx
			|| Qehxlen > cs->Qlen
			) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"OpenSSL failed to create ephemeral EC key");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	memcpy(Qeh, Qehx, Qehxlen);
	Qehlen = Qehxlen;
#endif

	/* For later use, get  Qeh without 04 and full size  X || Y */
	Qeh_OSlen = sizeof(Qeh_OS);
	if (Q2OS(cs->field_length, Qeh, Qehlen, Qeh_OS, &Qeh_OSlen)) {
		sc_log(card->ctx,"Q2OS for Qeh failed");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = len2a = sc_asn1_put_tag(0x81, NULL, 1 + sizeof(IDsh) + Qehlen, NULL, 0, NULL);
	if (r < 0)
		goto err;
	r = len2b = sc_asn1_put_tag(0x80, NULL, 0, NULL, 0, NULL);
	if (r < 0)
		goto err;
	r = sbuflen = sc_asn1_put_tag(0x7C, NULL, len2a + len2b, NULL, 0, NULL);
	if (r < 0)
		goto err;

	sbuf = malloc(sbuflen);
	if (sbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	p = sbuf;

	r =  sc_asn1_put_tag(0x7C, NULL, len2a + len2b, sbuf, sbuflen, &p);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_asn1_put_tag(0x81, NULL, 1 + sizeof(IDsh) + Qehlen, p, sbuflen - (p - sbuf), &p);
	if (r != SC_SUCCESS)
		goto err;

	/* Step H1 set CBh to 0x00 */
	*p++ = CBh;

#ifdef WIN32
	pid = (unsigned long) GetCurrentProcessId();
#else
	pid = (unsigned long) getpid(); /* use PID as our ID so different from other processes */
#endif
	memcpy(IDsh, &pid, MIN(sizeof(pid), sizeof(IDsh)));
	memcpy(p, IDsh, sizeof(IDsh));
	p += sizeof(IDsh);
	memcpy(p, Qeh, Qehlen);
	p += Qehlen;

	r = sc_asn1_put_tag(0x82, NULL, 0, p, sbuflen - (p - sbuf), &p); /* null data */
	if (r != SC_SUCCESS)
		goto err;

	/* Step H3 send CBh||IDsh|| Qeh  Qeh in 04||x||y */
	/* Or call sc_transmit directly */
	r = piv_general_io(card, 0x87, cs->p1, 0x04, sbuf, (p - sbuf), rbuf, rbuflen);
	if (r <= 0)
		goto err;

	rbuflen = r;
	p = rbuf;

	body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x7C, &bodylen);
	if (body == NULL || bodylen < 20 || rbuf[0] != 0x7C) {
		sc_log(card->ctx, "SM response data to short");
		r = SC_ERROR_SM_NO_SESSION_KEYS;
		goto err;
	}

	payload = sc_asn1_find_tag(card->ctx, body, bodylen, 0x82, &payloadlen);
	if (payload == NULL || payloadlen < 1 + cs->Nicclen + cs->AuthCryptogramlen || *body != 0x82) {
		sc_log(card->ctx, "SM response data to short");
		r = SC_ERROR_SM_NO_SESSION_KEYS;
		goto err;
	}

	/* payload is CBicc (1) || Nicc (16 or 24) || AuthCryptogram (CMAC 16 or 16) ||Cicc (variable) */
	p = (u8 *) payload;

	/* Step H4 check CBicc == 0x00 */
	CBicc = *p++;
	if  (CBicc != 0x00) { /* CBicc must be  zero */
		sc_log(card->ctx, "SM card did not accept request");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	memcpy(Nicc, p, cs->Nicclen);
	p += cs->Nicclen;

	memcpy(AuthCryptogram, p, cs->AuthCryptogramlen);
	p += cs->AuthCryptogramlen;

	if (p > payload + payloadlen) {
		sc_log(card->ctx, "SM card CVC is to short");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	cvclen = len = payloadlen - (p - payload);
	if (len) {
		cvcder = p; /* in rbuf */

		r = piv_decode_cvc(card, &p, &len, &priv->sm_cvc);
		if (r != SC_SUCCESS) {
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
		priv->sm_flags |= PIV_SM_FLAGS_SM_CVC_PRESENT;
	}

	/* Step H5 Verify Cicc CVC and pubkey */
	/* Verify Cicc (sm_cvc) is signed by sm_in_cvc or PIV_OBJ_SM_CERT_SIGNER  */
	/* sm_in_cvc is signed by PIV_OBJ_SM_CERT_SIGNER */

	/* Verify the cert chain is valid. */
	r = piv_sm_verify_certs(card);
	if (r < 0) {
		sc_log(card->ctx, "SM  piv_sm_verify_certs r:%d", r);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* Step H6  need left most 8 bytes of hash of sm_cvc */
	{
		u8 hash[SHA256_DIGEST_LENGTH] = {0};
		const u8* tag;
		size_t taglen;
		const u8* tmpder;
		size_t tmpderlen;

		if ((tag = sc_asn1_find_tag(card->ctx, cvcder, cvclen, 0x7F21, &taglen)) == NULL
				|| *cvcder != 0x7F || *(cvcder + 1) != 0x21) {

			r = SC_ERROR_INTERNAL;
			goto err;
		}

		/* debug choice */
		tmpder =  cvcder;
		tmpderlen = cvclen;

		if (EVP_DigestInit(hash_ctx,EVP_sha256()) != 1
				|| EVP_DigestUpdate(hash_ctx, tmpder, tmpderlen) != 1
				|| EVP_DigestFinal_ex(hash_ctx, hash, NULL) != 1) {
			sc_log_openssl(card->ctx);
			sc_log(card->ctx,"IDsicc hash failed");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		memcpy(IDsicc, hash, sizeof(IDsicc)); /* left 8 bytes */
	}

	/* Step H7 get the cards public key Qsicc into OpenSSL Cicc_eckey */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if ((Cicc_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL
			|| (Cicc_group = EC_GROUP_new_by_curve_name(cs->nid)) == NULL
			|| (Cicc_pkey = EVP_PKEY_new()) == NULL
			|| (Cicc_eckey = EC_KEY_new_by_curve_name(cs->nid)) == NULL
			|| (Cicc_point = EC_POINT_new(Cicc_group)) == NULL
			|| EC_POINT_oct2point(Cicc_group, Cicc_point,
				priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen, NULL) <= 0
			|| EC_KEY_set_public_key(Cicc_eckey, Cicc_point) <= 0
			|| EVP_PKEY_set1_EC_KEY(Cicc_pkey, Cicc_eckey) <= 0) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"OpenSSL failed to get card's EC pubkey");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	Cicc_params_n = 0;
	Cicc_params[Cicc_params_n++] = OSSL_PARAM_construct_utf8_string( "group", cs->curve_group, 0);
	Cicc_params[Cicc_params_n++] = OSSL_PARAM_construct_octet_string("pub",
			priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen);
	Cicc_params[Cicc_params_n] = OSSL_PARAM_construct_end();

	if (!(Cicc_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL))
			|| !EVP_PKEY_fromdata_init(Cicc_ctx)
			|| !EVP_PKEY_fromdata(Cicc_ctx, &Cicc_pkey, EVP_PKEY_PUBLIC_KEY, Cicc_params)
			|| !Cicc_pkey) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx, "OpenSSL failed to set EC pubkey for Cicc");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#endif

	/* Qsicc without 04 and expanded x||y */
	Qsicc_OSlen = sizeof(Qsicc_OS);
	if (Q2OS(cs->field_length, priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen, Qsicc_OS, &Qsicc_OSlen)) {
		sc_log(card->ctx,"Q2OS for Qsicc failed");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Step H8 Compute the shared secret Z */
	if ((Z_ctx = EVP_PKEY_CTX_new(eph_pkey, NULL)) == NULL
			|| EVP_PKEY_derive_init(Z_ctx) <= 0
			|| EVP_PKEY_derive_set_peer(Z_ctx, Cicc_pkey) <= 0
			|| EVP_PKEY_derive(Z_ctx, NULL, &Zlen) <= 0
			|| Zlen != cs->Zlen
			|| (Z = malloc(Zlen)) == NULL
			|| EVP_PKEY_derive(Z_ctx, Z, &Zlen) <= 0
			|| Zlen != cs->Zlen) {
		sc_log_openssl(card->ctx);
		sc_log(card->ctx,"OpenSSL failed to create secret Z");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	sc_log(card->ctx, "debug Zlen:%"SC_FORMAT_LEN_SIZE_T"u Z[0]:0x%2.2x", Zlen, Z[0]);

	/* Step H9 zeroize deh from step H2 */
	EVP_PKEY_free(eph_pkey); /* OpenSSL  BN_clear_free calls OPENSSL_cleanse */
	eph_pkey = NULL;

	/* Step H10 Create AES session Keys */
	/* kdf in is 4byte counter || Z || otherinfo  800-56A 5.8.1 */

	kdf_inlen = 4 + Zlen + cs->otherinfolen;
	kdf_in = malloc(kdf_inlen);
	if (kdf_in == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	p = kdf_in;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x01;
	memcpy(p, Z, cs->Zlen);
	p += Zlen;

	/* otherinfo */
	*p++ = cs->o0len;
	for (i = 0; i <  cs->o0len; i++)
		*p++ = cs->o0_char; /* 0x09 or 0x0d */

	*p++ = sizeof(IDsh);
	memcpy(p, IDsh, sizeof(IDsh));
	p += sizeof(IDsh);

	*p++ = cs->CBhlen;
	memcpy(p, &CBh, cs->CBhlen);
	p += cs->CBhlen;

	*p++ = cs->T16Qehlen;
	/* First 16 bytes of Qeh without 04 800-56A Appendix C.2 */
	memcpy(p, Qeh_OS, cs->T16Qehlen);
	p += cs->T16Qehlen;

	*p++ = cs->IDsicclen;
	memcpy(p, IDsicc, cs->IDsicclen);
	p += cs->IDsicclen;

	*p++ = cs->Nicclen;
	memcpy(p, Nicc, cs->Nicclen);
	p += cs->Nicclen;

	*p++ = cs->CBicclen;
	memcpy(p, &CBicc, cs->CBicclen);
	p += cs->CBicclen;

	if (p != kdf_in + kdf_inlen) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* 4 keys needs reps =  ceil (naeskeys * aeskeylen) / kdf_hash_size) */
	/* 800-56A-2007, 5.8.1 Process and 800-56C rev 3 2018 4.1 Process. */
	/* so it is 2 times for 128 or 3 times for 256 bit AES keys */
	p = aeskeys; /* 4 keys + overflow */
	reps = (cs->naeskeys * cs->aeskeylen + cs->kdf_hash_size - 1) / (cs->kdf_hash_size);

	EVP_MD_CTX_reset(hash_ctx);
	for (i = 0; i < reps; i++) {
		if (EVP_DigestInit(hash_ctx,(*cs->kdf_md)()) != 1
				|| EVP_DigestUpdate(hash_ctx, kdf_in, kdf_inlen) != 1
				|| EVP_DigestFinal_ex(hash_ctx, p, &hashlen) != 1) {
			sc_log_openssl(card->ctx);
			sc_log(card->ctx,"KDF hash failed");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		kdf_in[3]++;  /* inc the counter */
		p += cs->kdf_hash_size;
	}

	/* copy keys used for APDU */
	memset(&priv->sm_session, 0, sizeof(piv_sm_session_t)); /* clear */
	priv->sm_session.aes_size = cs->aeskeylen;
	memcpy(&priv->sm_session.SKcfrm, &aeskeys[cs->aeskeylen * 0], cs->aeskeylen);
	memcpy(&priv->sm_session.SKmac, &aeskeys[cs->aeskeylen * 1], cs->aeskeylen);
	memcpy(&priv->sm_session.SKenc, &aeskeys[cs->aeskeylen * 2], cs->aeskeylen);
	memcpy(&priv->sm_session.SKrmac, &aeskeys[cs->aeskeylen * 3], cs->aeskeylen);
	sc_mem_clear(&aeskeys, sizeof(aeskeys));

	priv->sm_session.enc_counter[15] = 0x01;
	priv->sm_session.resp_enc_counter[0] = 0x80;
	priv->sm_session.resp_enc_counter[15] = 0x01;
	/* C_MCV is zero */
	/* R_MCV is zero */

	/*  Step H11 Zeroize Z (and kdf_in which has Z) */
	if (Z && Zlen) {
		sc_mem_clear(Z, Zlen);
		free(Z);
		Z=NULL;
		Zlen = 0;
	}
	if (kdf_in && kdf_inlen) {
		sc_mem_clear(kdf_in, kdf_inlen);
		free(kdf_in);
		kdf_in = NULL;
		kdf_inlen = 0;
	}

	/* Step H12 check AuthCryptogramting our version  */
	/* Generate CMAC */

	{
		u8 Check_AuthCryptogram[32];
		size_t Check_Alen = 0;

		u8 MacData[200];
		int MacDatalen;
		memset(MacData, 0, sizeof(MacData));

		p = MacData;
		memcpy(p, "\x4B\x43\x5f\x31\x5f\x56", 6);
		p += 6;
		memcpy(p, IDsicc, cs->IDsicclen);
		p += cs->IDsicclen;
		memcpy(p, IDsh, sizeof(IDsh));
		p += sizeof(IDsh);

		memcpy(p, Qeh_OS, Qeh_OSlen);
		p += Qeh_OSlen;
		MacDatalen = p - MacData;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if ((cmac_ctx = CMAC_CTX_new()) == NULL
				|| CMAC_Init(cmac_ctx, priv->sm_session.SKcfrm, cs->aeskeylen, (*cs->cipher_cbc)(), NULL) != 1
				|| CMAC_Update(cmac_ctx, MacData, MacDatalen) != 1
				|| CMAC_Final(cmac_ctx, Check_AuthCryptogram, &Check_Alen) != 1) {
			r = SC_ERROR_INTERNAL;
			sc_log_openssl(card->ctx);
			sc_log(card->ctx,"AES_CMAC failed %d",r);
			goto err;
		}
#else
		mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
		cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);

		cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
		if (mac == NULL
				|| (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL
				|| !EVP_MAC_init(cmac_ctx, priv->sm_session.SKcfrm,
					priv->sm_session.aes_size, cmac_params)
				|| !EVP_MAC_update( cmac_ctx, MacData, MacDatalen)
				|| !EVP_MAC_final(cmac_ctx, Check_AuthCryptogram, &Check_Alen, cs->AuthCryptogramlen)) {
			sc_log_openssl(card->ctx);
			r = SC_ERROR_INTERNAL;
			sc_log(card->ctx,"AES_CMAC failed %d",r);
			goto err;
		}
#endif

		if (0 == memcmp(AuthCryptogram, Check_AuthCryptogram, cs->AuthCryptogramlen)) {
			sc_log(card->ctx,"AuthCryptogram compare");
			r = 0;
		} else {
			sc_log(card->ctx,"AuthCryptogram compare failed");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
	}

	/* VCI only needed for contactless */
	if (priv->init_flags & PIV_INIT_CONTACTLESS) {
		/* Is pairing code required? */
		if (!(priv->pin_policy & PIV_PP_VCI_WITHOUT_PC)) {
			r = piv_send_vci_pairing_code(card, priv->pairing_code);
			if (r < 0)
				goto err;
		}
	}

	r = 0;
	priv->sm_flags |= PIV_SM_FLAGS_SM_IS_ACTIVE;
	card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;

err:
	priv->sm_flags &= ~PIV_SM_FLAGS_DEFER_OPEN;
	if (r != 0) {
		memset(&priv->sm_session, 0, sizeof(piv_sm_session_t));
		sc_log_openssl(card->ctx); /* catch any not logged above */
	}

	sc_unlock(card);

	free(sbuf);
	free(kdf_in);
	free(Z);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP_free(Cicc_group);
	EC_POINT_free(Cicc_point);
	EC_KEY_free(Cicc_eckey);
#endif

	EVP_PKEY_free(eph_pkey); /* in case not cleared in step H9 */
	EVP_PKEY_CTX_free(eph_ctx);
	EVP_PKEY_free(Cicc_pkey);
	EVP_PKEY_CTX_free(Cicc_ctx);
	EVP_PKEY_CTX_free(Z_ctx);
	EVP_MD_CTX_free(hash_ctx);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
	OPENSSL_free(Qehx);
#endif

	LOG_FUNC_RETURN(card->ctx, r);
}
#endif /* ENABLE_PIV_SM */

/* Add the PIV-II operations */
/* Should use our own keydata, actually should be common to all cards */
/* RSA and EC are added. */

static int piv_generate_key(sc_card_t *card,
		sc_cardctl_piv_genkey_info_t *keydata)
{
	int r;
	u8 rbuf[4096];
	u8 *p;
	const u8 *tag;
	u8 tagbuf[16];
	u8 outdata[3]; /* we could also add tag 81 for exponent */
	size_t taglen;
	size_t out_len;
	size_t in_len;
	unsigned int cla_out, tag_out;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	keydata->exponent = NULL;
	keydata->exponent_len = 0;
	keydata->pubkey = NULL;
	keydata->pubkey_len = 0;
	keydata->ecparam = NULL; /* will show size as we only support 2 curves */
	keydata->ecparam_len = 0;
	keydata->ecpoint = NULL;
	keydata->ecpoint_len = 0;

	out_len = 3;
	outdata[0] = 0x80;
	outdata[1] = 0x01;
	outdata[2] = keydata->key_algid;
	switch (keydata->key_algid) {
		case 0x05: keydata->key_bits = 3072; break;
		case 0x06: keydata->key_bits = 1024; break;
		case 0x07: keydata->key_bits = 2048; break;
		case 0x11: keydata->key_bits = 0;
			keydata->ecparam = 0; /* we only support prime256v1 for 11 */
			keydata->ecparam_len =0;
			break;
		case 0x14: keydata->key_bits = 0;
			keydata->ecparam = 0; /* we only support secp384r1 */
			keydata->ecparam_len = 0;
			break;
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	p = tagbuf;

	r = sc_asn1_put_tag(0xAC, outdata, out_len, tagbuf, sizeof(tagbuf), &p);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Failed to encode ASN1 tag");
		goto err;
	}

	r = piv_general_io(card, 0x47, 0x00, keydata->key_num,
			tagbuf, p - tagbuf, rbuf, sizeof rbuf);

	if (r >= 0) {
		const u8 *cp;

		cp = rbuf;
		in_len = r;

		/* expected tag is 0x7f49,returned as cla_out == 0x60 and tag_out = 0x1F49 */
		r = sc_asn1_read_tag(&cp, in_len, &cla_out, &tag_out, &in_len);
		if (r < 0 || cp == NULL || in_len == 0 || cla_out != 0x60 || tag_out != 0x1f49) {
			r = SC_ERROR_ASN1_OBJECT_NOT_FOUND;
		}
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "Tag buffer not found");
			goto err;
		}

		/* if RSA vs EC */
		if (keydata->key_bits > 0 ) {
			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x82, &taglen);
			if (tag != NULL && taglen <= 4) {
				keydata->exponent = malloc(taglen);
				if (keydata->exponent == NULL)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
				keydata->exponent_len = taglen;
				memcpy (keydata->exponent, tag, taglen);
			}

			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x81, &taglen);
			if (tag != NULL && taglen > 0) {
				keydata->pubkey = malloc(taglen);
				if (keydata->pubkey == NULL) {
					free(keydata->exponent);
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
				}
				keydata->pubkey_len = taglen;
				memcpy (keydata->pubkey, tag, taglen);
			}
		}
		else { /* must be EC */
			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x86, &taglen);
			if (tag != NULL && taglen > 0) {
				keydata->ecpoint = malloc(taglen);
				if (keydata->ecpoint == NULL)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
				keydata->ecpoint_len = taglen;
				memcpy (keydata->ecpoint, tag, taglen);
			}
		}

		/* TODO: -DEE Could add key to cache so could use engine to generate key,
		 * and sign req in single operation */
		r = 0;
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_select_aid(sc_card_t* card, u8* aid, size_t aidlen, u8* response, size_t *responselen)
{
	sc_apdu_t apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu,
		response == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aidlen;
	apdu.data = aid;
	apdu.datalen = aidlen;
	apdu.resp = response;
	apdu.resplen = responselen ? *responselen : 0;
	apdu.le = response == NULL ? 0 : 256; /* could be 21  for fci */

	r = sc_transmit_apdu(card, &apdu);
	if (responselen)
		*responselen = apdu.resplen;
	LOG_TEST_RET(card->ctx, r, "PIV select failed");

	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/* find the PIV AID on the card. If card->type already filled in,
 * then look for specific AID only
 */

static int piv_find_aid(sc_card_t * card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r,i;
	const u8 *tag;
	size_t taglen;
	const u8 *nextac;
	const u8 *pix;
	size_t pixlen;
	const u8 *actag;  /* Cipher Suite */
	size_t actaglen;
	const u8 *csai; /* Cipher Suite Algorithm Identifier */
	size_t csailen;
	size_t resplen = sizeof(rbuf);
#ifdef ENABLE_PIV_SM
	int found_csai = 0;
#endif

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);


	/* first  see if the default application will return a template
	 * that we know about.
	 */

	r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, rbuf, &resplen);
	if (r > 0 && priv->aid_der.value && resplen == priv->aid_der.len  && !memcmp(priv->aid_der.value, rbuf, resplen)) {
		LOG_FUNC_RETURN(card->ctx,SC_SUCCESS);
		/* no need to parse again, same as last time */
	}
	if (r >= 0 && resplen > 2 ) {
		tag = sc_asn1_find_tag(card->ctx, rbuf, resplen, 0x61, &taglen);
		if (tag != NULL) {
			priv->init_flags |= PIV_INIT_AID_PARSED;
			/* look for 800-73-4 0xAC for Cipher Suite Algorithm Identifier Table 14 */
			/* There may be more than one 0xAC tag, loop to find all */

			nextac = tag;
			while((actag = sc_asn1_find_tag(card->ctx, nextac, taglen - (nextac - tag),
					0xAC, &actaglen)) != NULL) {
				nextac = actag + actaglen;

				csai = sc_asn1_find_tag(card->ctx, actag, actaglen, 0x80, &csailen);
				if (csai != NULL) {
					if (csailen == 1) {
						sc_log(card->ctx,"found csID=0x%2.2x",*csai);
#ifdef ENABLE_PIV_SM
						for (i = 0; i < PIV_CSS_SIZE; i++) {
							if (*csai != css[i].id)
								continue;
							if (found_csai) {
								sc_log(card->ctx,"found multiple csIDs, using first");
							} else {
								priv->cs = &css[i];
								priv->csID = *csai;
								found_csai++;
								priv->init_flags |= PIV_INIT_AID_AC;
							}
						}
#endif /* ENABLE_PIV_SM */
					}
				}
			}

			pix = sc_asn1_find_tag(card->ctx, tag, taglen, 0x4F, &pixlen);
			if (pix != NULL ) {
				sc_log(card->ctx, "found PIX");

				/* early cards returned full AID, rather then just the pix */
				for (i = 0; piv_aids[i].len_long != 0; i++) {
					if ((pixlen >= 6 && memcmp(pix, piv_aids[i].value + 5, piv_aids[i].len_long - 5 ) == 0)
							|| ((pixlen >=  piv_aids[i].len_short && memcmp(pix, piv_aids[i].value,
								piv_aids[i].len_short) == 0))) {
						free(priv->aid_der.value);  /* free previous value if any */
						if ((priv->aid_der.value = malloc(resplen)) == NULL) {
							LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
						}
						memcpy(priv->aid_der.value, rbuf, resplen);
						priv->aid_der.len = resplen;
						LOG_FUNC_RETURN(card->ctx,i);
					}
				}
			}
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NO_CARD_SUPPORT);
}

/*
 * Read a DER encoded object from a file. Allocate and return the buf.
 * Used to read the file defined in offCardCertURL from a cache.
 * Also used for testing of History and Discovery objects from a file
 * when testing with a card that does not support these new objects.
 */
static int piv_read_obj_from_file(sc_card_t * card, char * filename,
	u8 **buf, size_t *buf_len)
{
	int r;
	int r_tag;
	int f = -1;
	size_t len;
	u8 tagbuf[16];
	size_t rbuflen;
	const u8 * body;
	unsigned int cla_out, tag_out;
	size_t bodylen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	*buf = NULL;
	*buf_len = 0;
	f = open(filename, O_RDONLY);
	if (f < 0) {
		sc_log(card->ctx, "Unable to load PIV off card file: \"%s\"",filename);
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
	}
	len = read(f, tagbuf, sizeof(tagbuf)); /* get tag and length */
	if (len < 2 || len > sizeof(tagbuf)) {
		sc_log(card->ctx, "Problem with \"%s\"",filename);
		r =  SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto err;
	}
	body = tagbuf;
	/* accept any tag for now, just get length */
	r_tag = sc_asn1_read_tag(&body, len, &cla_out, &tag_out, &bodylen);
	if ((r_tag != SC_SUCCESS && r_tag != SC_ERROR_ASN1_END_OF_CONTENTS)
			|| body == NULL) {
		sc_log(card->ctx, "DER problem");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}
	rbuflen = body - tagbuf + bodylen;
	*buf = malloc(rbuflen);
	if (!*buf) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(*buf, tagbuf, len); /* copy first or only part */
	/* read rest of file */
	if (rbuflen > len + sizeof(tagbuf)) {
		len = read(f, *buf + sizeof(tagbuf), rbuflen - sizeof(tagbuf)); /* read rest */
		if (len != rbuflen - sizeof(tagbuf)) {
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			free (*buf);
			*buf = NULL;
			goto err;
		}
	}
	r = (int)rbuflen;
	*buf_len = rbuflen;
err:
	if (f >= 0)
		close(f);
	LOG_FUNC_RETURN(card->ctx, r);
}

/* the tag is the PIV_OBJ_*  */
static int
piv_get_data(sc_card_t * card, int enumtag, u8 **buf, size_t *buf_len)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8 *p;
	u8 *tbuf;
	int r = 0;
	u8 tagbuf[8];
	size_t tag_len;
	int alloc_buf = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, "#%d, %s", enumtag, piv_objects[enumtag].name);

	r = sc_lock(card); /* do check len and get data in same transaction */
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "sc_lock failed");
		return r;
	}

	tag_len = piv_objects[enumtag].tag_len;

	p = tagbuf;
	r = sc_asn1_put_tag(0x5c, piv_objects[enumtag].tag_value, tag_len, tagbuf, sizeof(tagbuf), &p);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "Failed to encode ASN1 tag");
		goto err;
	}

	if (*buf_len == 1 && *buf == NULL){
		*buf_len = priv->max_object_size; /* will allocate below */
		alloc_buf = 1;
	}

	sc_log(card->ctx,
	       "buffer for #%d *buf=0x%p len=%"SC_FORMAT_LEN_SIZE_T"u",
	       enumtag, *buf, *buf_len);
	if (*buf == NULL && *buf_len > 0) {
		if (*buf_len > MAX_FILE_SIZE) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		*buf = malloc(*buf_len);
		if (*buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}

#ifdef ENABLE_PIV_SM
	/*
	 * Over contact reader, OK to read non sensitive object in clear even when SM is active
	 * but only if using default policy and we are not in reader_lock_obtained
	 * Discovery object will use SM from reader_lock_obtained to catch if SM is still valid
	 * i.e. no interference from other applications
	 */
	sc_log(card->ctx,"enumtag:%d sm_ctx.sm_mode:%d piv_objects[enumtag].flags:0x%8.8x sm_flags:0x%8.8lx it_flags:0x%8.8x",
			enumtag, card->sm_ctx.sm_mode, piv_objects[enumtag].flags, priv->sm_flags, priv->init_flags);
	if (priv->sm_flags & PIV_SM_FLAGS_SM_IS_ACTIVE
			&& enumtag != PIV_OBJ_DISCOVERY
			&& card->sm_ctx.sm_mode == SM_MODE_TRANSMIT
			&& !(piv_objects[enumtag].flags & PIV_OBJECT_NEEDS_PIN)
			&& !(priv->sm_flags & (PIV_SM_FLAGS_NEVER | PIV_SM_FLAGS_ALWAYS))
			&& !(priv->init_flags & ( PIV_INIT_CONTACTLESS | PIV_INIT_IN_READER_LOCK_OBTAINED))) {
			sc_log(card->ctx,"Set PIV_SM_GET_DATA_IN_CLEAR");
		priv->sm_flags |= PIV_SM_GET_DATA_IN_CLEAR;
	}

#endif /* ENABLE_PIV_SM */
	r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf, *buf, *buf_len);
	if (r > 0) {
		int r_tag;
		unsigned int cla_out, tag_out;
		size_t bodylen = 0;
		const u8 *body = *buf;
		r_tag = sc_asn1_read_tag(&body, r, &cla_out, &tag_out, &bodylen);
		if (r_tag != SC_SUCCESS
				|| body == NULL
				|| ((cla_out << 24 | tag_out) != piv_objects[enumtag].resp_tag)) {
			sc_log(card->ctx, "invalid tag or length r_tag:%d body:%p", r_tag, body);
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		}
		*buf_len = (body - *buf) + bodylen;
	} else if ( r == 0 ) {
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	} else {
		goto err;
	}

	if (alloc_buf && *buf) {
		tbuf = malloc(r);
		if (tbuf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		memcpy(tbuf, *buf, r);
		free (*buf);
		alloc_buf = 0;
		*buf = tbuf;
	}

err:
	if (alloc_buf) {
		free(*buf);
		*buf = NULL;
	}
	sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_get_cached_data(sc_card_t * card, int enumtag, u8 **buf, size_t *buf_len)
{

	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM);

	sc_log(card->ctx, "#%d, %s", enumtag, piv_objects[enumtag].name);

	/* see if we have it cached */
	if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_VALID) {

		sc_log(card->ctx,
				"found #%d %p:%"SC_FORMAT_LEN_SIZE_T"u %p:%"SC_FORMAT_LEN_SIZE_T"u",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);

		if (priv->obj_cache[enumtag].obj_len == 0) {
			r = SC_ERROR_FILE_NOT_FOUND;
			sc_log(card->ctx, "#%d found but len=0", enumtag);
			goto err;
		}
		*buf = priv->obj_cache[enumtag].obj_data;
		*buf_len = priv->obj_cache[enumtag].obj_len;
		r = (int)*buf_len;
		goto ok;
	}

	/*
	 * If we know it can not be on the card  i.e. History object
	 * has been read, and we know what other certs may or
	 * may not be on the card. We can avoid extra overhead
	 * Also used if object on card was not parsable
	 */

	if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_NOT_PRESENT) {
		sc_log(card->ctx, "no_obj #%d", enumtag);
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}

	/* Not cached, try to get it, piv_get_data will allocate a buf */
	sc_log(card->ctx, "get #%d",  enumtag);
	rbuflen = 1;
	r = piv_get_data(card, enumtag, &rbuf, &rbuflen);
	if (r > 0) {
		priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
		priv->obj_cache[enumtag].obj_len = r;
		priv->obj_cache[enumtag].obj_data = rbuf;
		*buf = rbuf;
		*buf_len = r;

		sc_log(card->ctx,
				"added #%d  %p:%"SC_FORMAT_LEN_SIZE_T"u %p:%"SC_FORMAT_LEN_SIZE_T"u",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);

	} else {
		free(rbuf);
		if (r == 0 || r == SC_ERROR_FILE_NOT_FOUND) {
			r = SC_ERROR_FILE_NOT_FOUND;
			priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
			priv->obj_cache[enumtag].obj_len = 0;
		} else {
			goto err;
		}
	}
ok:

err:
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_cache_internal_data(sc_card_t *card, int enumtag)
{
	piv_private_data_t * priv = PIV_DATA(card);
	const u8* tag;
	const u8* body;
	size_t taglen;
	size_t bodylen;
	int compressed = 0;
	int r = SC_SUCCESS;
#ifdef ENABLE_PIV_SM
	u8* cvc_start = NULL;
	size_t cvc_len = 0;
#endif

	/* if already cached */
	if (priv->obj_cache[enumtag].internal_obj_data && priv->obj_cache[enumtag].internal_obj_len) {
		sc_log(card->ctx,
				"#%d found internal %p:%"SC_FORMAT_LEN_SIZE_T"u",
				enumtag,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	body = sc_asn1_find_tag(card->ctx,
			priv->obj_cache[enumtag].obj_data,
			priv->obj_cache[enumtag].obj_len,
			0x53, &bodylen);

	if (body == NULL || priv->obj_cache[enumtag].obj_data[0] != 0x53)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

	/* get the certificate out */
	 if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_CERT) {

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x71, &taglen);
		/* 800-72-1 not clear if this is 80 or 01 Sent comment to NIST for 800-72-2 */
		/* 800-73-3 says it is 01, keep dual test so old cards still work */
		if (tag && taglen > 0 && (((*tag) & 0x80) || ((*tag) & 0x01)))
			compressed = 1;

#ifdef ENABLE_PIV_SM
		cvc_start = (u8 *)tag + taglen; /* save for later as cvs (if present) follows  0x71 */
#endif

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x70, &taglen);
		if (tag == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

		if(compressed) {
			priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_COMPRESSED;
		}
		/* internal certificate remains compressed */
		if (!(priv->obj_cache[enumtag].internal_obj_data = malloc(taglen)))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

		memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
		priv->obj_cache[enumtag].internal_obj_len = taglen;

#ifdef ENABLE_PIV_SM
		/* PIV_OBJ_SM_CERT_SIGNER  CERT OBJECT may also have a intermediate CVC */
		if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_CVC) {
			/* cvc if present should be at cvc_start.
			 * find the tag(T) and get value(V) and len(L) from TLV.
			 * Could reconstruct ASN1 of (T)(L) stating location from length and known tag.
			 * as the size of (L) depends on the length of value
			 */
			if ((tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x7F21, &taglen)) != NULL
					&& cvc_start && cvc_start < tag
					&& cvc_start[0] == 0x7f && cvc_start[1] == 0x21) {
				cvc_len = tag - cvc_start + taglen;
				/* decode the intermediate CVC */
				r = piv_decode_cvc(card, &cvc_start, &cvc_len, &priv->sm_in_cvc);
				if (r < 0) {
					sc_log(card->ctx,"unable to parse intermediate CVC: %d skipping",r);
				}
				priv->sm_flags |= PIV_SM_FLAGS_SM_IN_CVC_PRESENT;
			}
		}
#endif /* ENABLE_PIV_SM */

	/* convert pub key to internal */
	}
	else if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {
		tag = sc_asn1_find_tag(card->ctx, body, bodylen, *body, &taglen);
		if (tag == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

		if (!(priv->obj_cache[enumtag].internal_obj_data = malloc(taglen)))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

		memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
		priv->obj_cache[enumtag].internal_obj_len = taglen;
	}
	else {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	sc_log(card->ctx, "added #%d internal %p:%"SC_FORMAT_LEN_SIZE_T"u",
	       enumtag,
	       priv->obj_cache[enumtag].internal_obj_data,
	       priv->obj_cache[enumtag].internal_obj_len);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


/*
 * Callers of this may be expecting a certificate,
 * select file will have saved the object type for us
 * as well as set that we want the cert from the object.
 */
static int
piv_read_binary(sc_card_t *card, unsigned int idx, unsigned char *buf, size_t count, unsigned long *flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag;
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	const u8 *body;
	size_t bodylen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv->selected_obj < 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	enumtag = piv_objects[priv->selected_obj].enumtag;

	if (priv->rwb_state == -1) {
		r = piv_get_cached_data(card, enumtag, &rbuf, &rbuflen);

		if (r >=0) {
			/* an object with no data will be considered not found */
			/* Discovery tag = 0x73, all others are 0x53 */
			if (!rbuf || rbuf[0] == 0x00 || ((rbuf[0]&0xDF) == 0x53 && rbuf[1] == 0x00)) {
				r = SC_ERROR_FILE_NOT_FOUND;
				goto err;
			}

		/* TODO Biometric Information Templates Group Template uses tag 7f61 */

			body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, rbuf[0], &bodylen);
			if (body == NULL) {
				/* if missing, assume its the body */
				/* DEE bug in the beta card */
				sc_log(card->ctx, " ***** tag 0x53 MISSING");
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
			if (bodylen > body - rbuf + rbuflen) {
				sc_log(card->ctx,
						" ***** tag length > then data: %"SC_FORMAT_LEN_SIZE_T"u>%"SC_FORMAT_LEN_PTRDIFF_T"u+%"SC_FORMAT_LEN_SIZE_T"u",
						bodylen, body - rbuf, rbuflen);
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
			/* if cached obj has internal interesting data (cert or pub key) */
			if (priv->return_only_cert || piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {
				r = piv_cache_internal_data(card, enumtag);
				if (r < 0)
					goto err;
			}

		}
		priv->rwb_state = 0;
	}

	if (priv->return_only_cert || piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {
		rbuf = priv->obj_cache[enumtag].internal_obj_data;
		rbuflen = priv->obj_cache[enumtag].internal_obj_len;
		if ((priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_COMPRESSED) && flags) {
			*flags |= SC_FILE_FLAG_COMPRESSED_AUTO;
		}
	} else {
		rbuf = priv->obj_cache[enumtag].obj_data;
		rbuflen = priv->obj_cache[enumtag].obj_len;
	}
	/* rbuf rbuflen has pointer and length to cached data */

	if ( rbuflen < idx + count)
		count = rbuflen - idx;
	if (count <= 0) {
		r = 0;
		priv->rwb_state = 1;
	} else {
		memcpy(buf, rbuf + idx, count);
		r = (int)count;
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * the tag is the PIV_OBJ_*
 * The buf should have the 0x53 tag+len+tags and data
 */

static int
piv_put_data(sc_card_t *card, int tag, const u8 *buf, size_t buf_len)
{
	int r;
	u8 * sbuf;
	size_t sbuflen;
	u8 * p;
	size_t tag_len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	tag_len = piv_objects[tag].tag_len;
	r = sc_asn1_put_tag(0x5c, piv_objects[tag].tag_value, tag_len, NULL, 0, NULL);
	if (r <= 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	sbuflen = r + buf_len;
	if (!(sbuf = malloc(sbuflen))) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	p = sbuf;
	r = sc_asn1_put_tag(0x5c, piv_objects[tag].tag_value, tag_len, sbuf, sbuflen, &p);
	if (r != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* This is safe as we calculated the size of buffer above */
	memcpy(p, buf, buf_len);
	p += buf_len;

	r = piv_general_io(card, 0xDB, 0x3F, 0xFF, sbuf, p - sbuf, NULL, 0);

	if (sbuf)
		free(sbuf);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_write_certificate(sc_card_t *card, const u8* buf, size_t count, unsigned long flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag, tmplen, tmplen2, tmplen3;
	int r = SC_SUCCESS;
	u8 *sbuf = NULL;
	u8 *p;
	size_t sbuflen;
	size_t taglen;

	if ((tmplen = sc_asn1_put_tag(0x70, buf, count, NULL, 0, NULL)) <= 0 ||
			(tmplen2 = sc_asn1_put_tag(0x71, NULL, 1, NULL, 0, NULL)) <= 0 ||
			(tmplen3 = sc_asn1_put_tag(0xFE, NULL, 0, NULL, 0, NULL)) <= 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	taglen = tmplen + tmplen2 + tmplen3;
	tmplen = sc_asn1_put_tag(0x53, NULL, taglen, NULL, 0, NULL);
	if (tmplen <= 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	sbuflen = tmplen;
	sbuf = malloc(sbuflen);
	if (sbuf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	p = sbuf;
	if ((r = sc_asn1_put_tag(0x53, NULL, taglen, sbuf, sbuflen, &p)) != SC_SUCCESS ||
	    (r = sc_asn1_put_tag(0x70, buf, count, p, sbuflen - (p - sbuf), &p)) != SC_SUCCESS ||
	    (r = sc_asn1_put_tag(0x71, NULL, 1, p, sbuflen - (p - sbuf), &p)) != SC_SUCCESS) {
		goto out;
	}
	/* Use 01 as per NIST 800-73-3 */
	*p++ = (flags) ? 0x01 : 0x00; /* certinfo, i.e. gzipped? */
	r = sc_asn1_put_tag(0xFE, NULL, 0, p, sbuflen - (p - sbuf), &p);
	if (r != SC_SUCCESS) {
		goto out;
	}

	enumtag = piv_objects[priv->selected_obj].enumtag;
	r = piv_put_data(card, enumtag, sbuf, sbuflen);

out:
	free(sbuf);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * For certs we need to add the 0x53 tag and other specific tags,
 * and call the piv_put_data
 * Note: the select file will have saved the object type for us
 * Write is used by piv-tool, so we will use flags:
 *  length << 8 | 8bits:
 * object            xxxx0000
 * uncompressed cert xxx00001
 * compressed cert   xxx10001
 * pubkey            xxxx0010
 *
 * to indicate we are writing a cert and if is compressed
 * or if we are writing a pubkey in to the cache.
 * if its not a cert or pubkey its an object.
 *
 * Therefore when idx=0, we will get the length of the object
 * and allocate a buffer, so we can support partial writes.
 * When the last chuck of the data is sent, we will write it.
 */

static int piv_write_binary(sc_card_t *card, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int enumtag;

	LOG_FUNC_CALLED(card->ctx);

	if (priv->selected_obj < 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	enumtag = piv_objects[priv->selected_obj].enumtag;

	if (priv->rwb_state == 1)  /* trying to write at end */
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (priv->rwb_state == -1) {

		/* if  cached, remove old entry */
		if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_VALID) {
			piv_obj_cache_free_entry(card, enumtag, 0);
		}

		if (idx != 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NO_CARD_SUPPORT);

		priv->w_buf_len = flags>>8;
		if (priv->w_buf_len == 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

		priv->w_buf = malloc(priv->w_buf_len);
		priv-> rwb_state = 0;
	}

	/* on each pass make sure we have w_buf */
	if (priv->w_buf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	if (idx + count > priv->w_buf_len)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

	memcpy(priv->w_buf + idx, buf, count); /* copy one chunk */

	/* if this was not the last chunk, return to get rest */
	if (idx + count < priv->w_buf_len)
		LOG_FUNC_RETURN(card->ctx, (int)count);

	priv-> rwb_state = 1; /* at end of object */

	switch (flags & 0x0f) {
		case 1:
			r = piv_write_certificate(card, priv->w_buf, priv->w_buf_len, flags & 0x10);
			break;
		case 2: /* pubkey to be added to cache, it should have 0x53 and 0x99 tags. */
		/* TODO: -DEE this is not fully implemented and not used */
			r = (int)priv->w_buf_len;
			break;
		default:
			r = piv_put_data(card, enumtag, priv->w_buf, priv->w_buf_len);
			break;
	}
	/* if it worked, will cache it */
	if (r >= 0 && priv->w_buf) {
		priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
		priv->obj_cache[enumtag].obj_data = priv->w_buf;
		priv->obj_cache[enumtag].obj_len = priv->w_buf_len;
	} else {
		if (priv->w_buf)
			free(priv->w_buf);
	}
	priv->w_buf = NULL;
	priv->w_buf_len = 0;
	LOG_FUNC_RETURN(card->ctx, (r < 0)? r : (int)count);
}

/*
 * Card initialization is NOT standard.
 * Some cards use mutual or external authentication using 3des or aes key. We
 * will read in the key from a file either binary or hex encoded.
 * This is only needed during initialization/personalization of the card
 */

#ifdef ENABLE_OPENSSL
static EVP_CIPHER *get_cipher_for_algo(sc_card_t *card, int alg_id)
{
	const char *algo;
	switch (alg_id) {
		case 0x0:
		case 0x1: /* 2TDES */
		case 0x3:
			algo = "DES-EDE3-ECB";
			break;
		case 0x8:
			algo = "AES-128-ECB";
			break;
		case 0xA:
			algo = "AES-192-ECB";
			break;
		case 0xC:
			algo = "AES-256-ECB";
			break;
		default: return NULL;
	}
	return sc_evp_cipher(card->ctx, algo);
}

static int get_keylen(unsigned int alg_id, size_t *size)
{
	switch(alg_id) {
	case 0x01: *size = 192/8; /* 2TDES still has 3 single des keys  phase out by 12/31/2010 */
		break;
	case 0x00:
	case 0x03: *size = 192/8;
		break;
	case 0x08: *size = 128/8;
		break;
	case 0x0A: *size = 192/8;
		break;
	case 0x0C: *size = 256/8;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	return SC_SUCCESS;
}

static int piv_get_key(sc_card_t *card, unsigned int alg_id, u8 **key, size_t *len)
{

	int r;
	size_t fsize;
	FILE *f = NULL;
	char * keyfilename = NULL;
	size_t expected_keylen;
	size_t keylen, readlen;
	u8 * keybuf = NULL;
	u8 * tkey = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	keyfilename = (char *)getenv("PIV_EXT_AUTH_KEY");

	if (keyfilename == NULL) {
		sc_log(card->ctx,
			"Unable to get PIV_EXT_AUTH_KEY=(null) for general_external_authenticate");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}

	r = get_keylen(alg_id, &expected_keylen);
	if(r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid cipher selector, none found for:  %02x", alg_id);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	f = fopen(keyfilename, "rb");
	if (!f) {
		sc_log(card->ctx, " Unable to load key from file\n");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}

	if (0 > fseek(f, 0L, SEEK_END))
		r = SC_ERROR_INTERNAL;
	fsize = ftell(f);
	if (0 > (long) fsize)
		r = SC_ERROR_INTERNAL;
	if (0 > fseek(f, 0L, SEEK_SET))
		r = SC_ERROR_INTERNAL;
	if(r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read %s\n", keyfilename);
		goto err;
	}

	keybuf = malloc(fsize+1); /* if not binary, need null to make it a string */
	if (!keybuf) {
		sc_log(card->ctx, " Unable to allocate key memory");
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	keybuf[fsize] = 0x00;    /* in case it is text need null */

	if ((readlen = fread(keybuf, 1, fsize, f)) != fsize) {
		sc_log(card->ctx, " Unable to read key\n");
		r = SC_ERROR_WRONG_LENGTH;
		goto err;
	}
	keybuf[readlen] = '\0';

	tkey = malloc(expected_keylen);
	if (!tkey) {
		sc_log(card->ctx, " Unable to allocate key memory");
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	if (fsize == expected_keylen) { /* it must be binary */
		memcpy(tkey, keybuf, expected_keylen);
	} else {
		/* if the key-length is larger then binary length, we assume hex encoded */
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Treating key as hex-encoded!\n");
		sc_right_trim(keybuf, fsize);
		keylen = expected_keylen;
		r = sc_hex_to_bin((char *)keybuf, tkey, &keylen);
		if (keylen !=expected_keylen || r != 0 ) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error formatting key\n");
			if (r == 0)
				r = SC_ERROR_INCOMPATIBLE_KEY;
			goto err;
		}
	}
	*key = tkey;
	tkey = NULL;
	*len = expected_keylen;
	r = SC_SUCCESS;

err:
	if (f)
		fclose(f);
	if (keybuf) {
		free(keybuf);
	}
	if (tkey) {
		free(tkey);
	}

	LOG_FUNC_RETURN(card->ctx, r);
	return r;
}
#endif

/*
 * will only deal with 3des for now
 * assumptions include:
 *  size of encrypted data is same as unencrypted
 *  challenges, nonces etc  from card are less then 114 (keeps tags simple)
 */

static int piv_general_mutual_authenticate(sc_card_t *card,
	unsigned int key_ref, unsigned int alg_id)
{
	int r;
#ifdef ENABLE_OPENSSL
	int N;
	int locked = 0;
	u8 rbuf[4096];
	u8 *nonce = NULL;
	size_t nonce_len;
	u8 *p;
	u8 *key = NULL;
	size_t keylen;
	u8 *plain_text = NULL;
	size_t plain_text_len = 0;
	u8 *tmp;
	size_t tmplen, tmplen2;
	u8 *built = NULL;
	size_t built_len;
	const u8 *body = NULL;
	size_t body_len;
	const u8 *witness_data = NULL;
	size_t witness_len;
	const u8 *challenge_response = NULL;
	size_t challenge_response_len;
	u8 *decrypted_reponse = NULL;
	size_t decrypted_reponse_len;
	EVP_CIPHER_CTX * ctx = NULL;

	u8 sbuf[255];
	EVP_CIPHER *cipher = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	cipher = get_cipher_for_algo(card, alg_id);
	if(!cipher) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid cipher selector, none found for:  %02x\n", alg_id);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	r = piv_get_key(card, alg_id, &key, &keylen);
	if (r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error getting General Auth key\n");
		goto err;
	}

	r = sc_lock(card);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "sc_lock failed\n");
		goto err; /* cleanup */
	}
	locked = 1;

	p = sbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x80;
	*p++ = 0x00;

	/* get the encrypted nonce */
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, rbuf, sizeof rbuf);

	if (r < 0) goto err;

	/* Remove the encompassing outer TLV of 0x7C and get the data */
	body = sc_asn1_find_tag(card->ctx, rbuf,
		r, 0x7C, &body_len);
	if (!body || rbuf[0] != 0x7C) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid Witness Data response of NULL\n");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* Get the witness data indicated by the TAG 0x80 */
	witness_data = sc_asn1_find_tag(card->ctx, body,
		body_len, 0x80, &witness_len);
	if (!witness_len || body_len == 0 || body[0] != 0x80) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid Challenge Data none found in TLV\n");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* Allocate an output buffer for openssl */
	plain_text = malloc(witness_len);
	if (!plain_text) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not allocate buffer for plain text\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* decrypt the data from the card */
	if (!EVP_DecryptInit(ctx, cipher, key, NULL)) {
		/* may fail if des parity of key is wrong. depends on OpenSSL options */
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);

	p = plain_text;
	if (!EVP_DecryptUpdate(ctx, p, &N, witness_data, (int)witness_len)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	plain_text_len = tmplen = N;
	p += tmplen;

	if(!EVP_DecryptFinal(ctx, p, &N)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	tmplen = N;
	plain_text_len += tmplen;

	if (plain_text_len != witness_len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			 "Encrypted and decrypted lengths do not match: %"SC_FORMAT_LEN_SIZE_T"u:%"SC_FORMAT_LEN_SIZE_T"u\n",
			 witness_len, plain_text_len);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Build a response to the card of:
	 * [GEN AUTH][ 80<decrypted witness>81 <challenge> ]
	 * Start by computing the nonce for <challenge> the
	 * nonce length should match the witness length of
	 * the card.
	 */
	nonce = malloc(witness_len);
	if(!nonce) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			 "OOM allocating nonce (%"SC_FORMAT_LEN_SIZE_T"u : %"SC_FORMAT_LEN_SIZE_T"u)\n",
			 witness_len, plain_text_len);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	nonce_len = witness_len;

	r = RAND_bytes(nonce, (int)witness_len);
	if(!r) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			 "Generating random for nonce (%"SC_FORMAT_LEN_SIZE_T"u : %"SC_FORMAT_LEN_SIZE_T"u)\n",
			 witness_len, plain_text_len);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* nonce for challenge */
	r = sc_asn1_put_tag(0x81, NULL, witness_len, NULL, 0, NULL);
	if (r <= 0) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	tmplen = r;

	/* plain text witness keep a length separate for the 0x7C tag */
	r = sc_asn1_put_tag(0x80, NULL, witness_len, NULL, 0, NULL);
	if (r <= 0) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	tmplen += r;
	tmplen2 = tmplen;

	/* outside 7C tag with 81:80 as innards */
	r = sc_asn1_put_tag(0x7C, NULL, tmplen, NULL, 0, NULL);
	if (r <= 0) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	built_len = r;

	/* Build the response buffer */
	p = built = malloc(built_len);
	if(!built) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "OOM Building witness response and challenge\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = built;

	/* Start with the 7C Tag */
	r = sc_asn1_put_tag(0x7C, NULL, tmplen2, p, built_len, &p);
	if (r != SC_SUCCESS) {
		goto err;
	}

	/* Add the DECRYPTED witness, tag 0x80 */
	r = sc_asn1_put_tag(0x80, plain_text, witness_len, p, built_len - (p - built), &p);
	if (r != SC_SUCCESS) {
		goto err;
	}

	/* Add the challenge, tag 0x81 */
	r = sc_asn1_put_tag(0x81, nonce, witness_len, p, built_len - (p - built), &p);
	if (r != SC_SUCCESS) {
		goto err;
	}

	/* Send constructed data */
	r = piv_general_io(card, 0x87, alg_id, key_ref, built, built_len, rbuf, sizeof rbuf);
	if (r < 0) {
		goto err;
	}

	/* Remove the encompassing outer TLV of 0x7C and get the data */
	body = sc_asn1_find_tag(card->ctx, rbuf,
		r, 0x7C, &body_len);
	if(!body || rbuf[0] != 0x7C) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not find outer tag 0x7C in response");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* SP800-73 not clear if  80 or 82 */
	challenge_response = sc_asn1_find_tag(card->ctx, body,
		body_len, 0x82, &challenge_response_len);
	if(!challenge_response) {
		challenge_response = sc_asn1_find_tag(card->ctx, body,
				body_len, 0x80, &challenge_response_len);
		if(!challenge_response) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not find tag 0x82 or 0x80 in response");
			r =  SC_ERROR_INVALID_DATA;
			goto err;
		}
	}

	/* Decrypt challenge and check against nonce */
	decrypted_reponse = malloc(challenge_response_len);
	if(!decrypted_reponse) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "OOM Allocating decryption buffer");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	EVP_CIPHER_CTX_reset(ctx);

	if (!EVP_DecryptInit(ctx, cipher, key, NULL)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);

	tmp = decrypted_reponse;
	if (!EVP_DecryptUpdate(ctx, tmp, &N, challenge_response, (int)challenge_response_len)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	decrypted_reponse_len = tmplen = N;
	tmp += tmplen;

	if(!EVP_DecryptFinal(ctx, tmp, &N)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	tmplen = N;
	decrypted_reponse_len += tmplen;

	if (decrypted_reponse_len != nonce_len || memcmp(nonce, decrypted_reponse, nonce_len) != 0) {
		sc_log(card->ctx,
				"mutual authentication failed, card returned wrong value %"SC_FORMAT_LEN_SIZE_T"u:%"SC_FORMAT_LEN_SIZE_T"u",
				decrypted_reponse_len, nonce_len);
		r = SC_ERROR_DECRYPT_FAILED;
		goto err;
	}
	r = SC_SUCCESS;

err:
	sc_evp_cipher_free(cipher);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	if (locked)
		sc_unlock(card);
	if (decrypted_reponse)
		free(decrypted_reponse);
	if (built)
		free(built);
	if (plain_text)
		free(plain_text);
	if (nonce)
		free(nonce);
	if (key)
		free(key);

#else
	sc_log(card->ctx, "OpenSSL Required");
	r = SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */

	LOG_FUNC_RETURN(card->ctx, r);
}


/* Currently only used for card administration */
static int piv_general_external_authenticate(sc_card_t *card,
		unsigned int key_ref, unsigned int alg_id)
{
	int r;
#ifdef ENABLE_OPENSSL
	size_t tmplen;
	int outlen;
	int locked = 0;
	u8 *p;
	u8 rbuf[4096];
	u8 *key = NULL;
	u8 *cipher_text = NULL;
	u8 *output_buf = NULL;
	const u8 *body = NULL;
	const u8 *challenge_data = NULL;
	size_t body_len;
	size_t output_len;
	size_t challenge_len;
	size_t keylen = 0;
	size_t cipher_text_len = 0;
	u8 sbuf[255];
	EVP_CIPHER_CTX * ctx = NULL;
	EVP_CIPHER *cipher = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Selected cipher for algorithm id: %02x\n", alg_id);

	cipher = get_cipher_for_algo(card, alg_id);
	if(!cipher) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid cipher selector, none found for:  %02x\n", alg_id);
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	r = piv_get_key(card, alg_id, &key, &keylen);
	if (r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error getting General Auth key\n");
		goto err;
	}

	r = sc_lock(card);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "sc_lock failed\n");
		goto err; /* cleanup */
	}
	locked = 1;

	p = sbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x81;
	*p++ = 0x00;

	/* get a challenge */
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, rbuf, sizeof rbuf);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error getting Challenge\n");
		goto err;
	}

	/*
	 * the value here corresponds with the response size, so we use this
	 * to alloc the response buffer, rather than re-computing it.
	 */
	output_len = r;

	/* Remove the encompassing outer TLV of 0x7C and get the data */
	body = sc_asn1_find_tag(card->ctx, rbuf,
		r, 0x7C, &body_len);
	if (!body || rbuf[0] != 0x7C) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid Challenge Data response of NULL\n");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* Get the challenge data indicated by the TAG 0x81 */
	challenge_data = sc_asn1_find_tag(card->ctx, body,
		body_len, 0x81, &challenge_len);
	if (!challenge_data) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid Challenge Data none found in TLV\n");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* Store this to sanity check that plaintext length and ciphertext lengths match */
	tmplen = challenge_len;

	/* Encrypt the challenge with the secret */
	if (!EVP_EncryptInit(ctx, cipher, key, NULL)) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Encrypt fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	cipher_text = malloc(challenge_len);
	if (!cipher_text) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not allocate buffer for cipher text\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	EVP_CIPHER_CTX_set_padding(ctx,0);
	if (!EVP_EncryptUpdate(ctx, cipher_text, &outlen, challenge_data, (int)challenge_len)) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Encrypt update fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	cipher_text_len += outlen;

	if (!EVP_EncryptFinal(ctx, cipher_text + cipher_text_len, &outlen)) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Final fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	cipher_text_len += outlen;

	/*
	 * Actually perform the sanity check on lengths plaintext length vs
	 * encrypted length
	 */
	if (cipher_text_len != tmplen) {
		sc_log_openssl(card->ctx);
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Length test fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	output_buf = malloc(output_len);
	if(!output_buf) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not allocate output buffer: %s\n",
				strerror(errno));
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = output_buf;

	/*
	 * Build: 7C<len>[82<len><challenge>]
	 * Start off by capturing the data of the response:
	 *     - 82<len><encrypted challenege response>
	 * Build the outside TLV (7C)
	 * Advance past that tag + len
	 * Build the body (82)
	 * memcopy the body past the 7C<len> portion
	 * Transmit
	 */
	tmplen = sc_asn1_put_tag(0x82, NULL, cipher_text_len, NULL, 0, NULL);
	if (tmplen <= 0) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = sc_asn1_put_tag(0x7C, NULL, tmplen, p, output_len, &p);
	if (r != SC_SUCCESS) {
		goto err;
	}

	/* Build the 0x82 TLV and append to the 7C<len> tag */
	r = sc_asn1_put_tag(0x82, cipher_text, cipher_text_len, p, output_len - (p - output_buf), &p);
	if (r != SC_SUCCESS) {
		goto err;
	}

	/* Sanity check the lengths again */
	tmplen = sc_asn1_put_tag(0x7C, NULL, tmplen, NULL, 0, NULL);
	if (output_len != (size_t)tmplen) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Allocated and computed lengths do not match! "
			 "Expected %"SC_FORMAT_LEN_SIZE_T"d, found: %zu\n", output_len, tmplen);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = piv_general_io(card, 0x87, alg_id, key_ref, output_buf, output_len, NULL, 0);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Got response  challenge\n");

err:
	sc_evp_cipher_free(cipher);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if (locked)
		sc_unlock(card);

	if (key) {
		sc_mem_clear(key, keylen);
		free(key);
	}

	if (cipher_text)
		free(cipher_text);

	if (output_buf)
		free(output_buf);
#else
	sc_log(card->ctx, "OpenSSL Required");
	r = SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */

	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * with sp800-73-4 and SM GUID is also in sm_cvc.subjectID
 */
static int
piv_get_serial_nr_from_CHUI(sc_card_t* card, sc_serial_number_t* serial)
{
	int r;
	int i;
	u8 gbits;
	u8 *rbuf = NULL;
	const u8 *body;
	const u8 *fascn;
	const u8 *guid;
	size_t rbuflen = 0, bodylen, fascnlen, guidlen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->serialnr.len)   {
		*serial = card->serialnr;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	/*
	 * 800-73-3 Part 1 and CIO Council docs say for PIV Compatible cards
	 * the FASC-N Agency code should be 9999 and there should be a GUID
	 * based on RFC 4122. If GUID present and not zero
	 * we will use the GUID as the serial number.
	 */

	r = piv_get_cached_data(card, PIV_OBJ_CHUI, &rbuf, &rbuflen);
	LOG_TEST_RET(card->ctx, r, "Failure retrieving CHUI");

	r = SC_ERROR_INTERNAL;
	if (rbuflen != 0) {
		body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x53, &bodylen); /* Pass the outer wrapper asn1 */
		if (body != NULL && bodylen != 0 && rbuf[0] == 0x53) {
			fascn = sc_asn1_find_tag(card->ctx, body, bodylen, 0x30, &fascnlen); /* Find the FASC-N data */
			guid = sc_asn1_find_tag(card->ctx, body, bodylen, 0x34, &guidlen);

			gbits = 0; /* if guid is valid, gbits will not be zero */
			if (guid && guidlen == 16) {
				for (i = 0; i < 16; i++) {
					gbits = gbits | guid[i]; /* if all are zero, gbits will be zero */
				}
			}
			sc_log(card->ctx,
					"fascn=%p,fascnlen=%"SC_FORMAT_LEN_SIZE_T"u,guid=%p,guidlen=%"SC_FORMAT_LEN_SIZE_T"u,gbits=%2.2x",
					fascn, fascnlen, guid, guidlen, gbits);

			if (fascn && fascnlen == 25) {
				/* test if guid and the fascn starts with ;9999 (in ISO 4bit + parity code) */
				if (!(gbits && fascn[0] == 0xD4 && fascn[1] == 0xE7
							&& fascn[2] == 0x39 && (fascn[3] | 0x7F) == 0xFF)) {
					/* fascnlen is 25 */
					serial->len = fascnlen;
					memcpy (serial->value, fascn, serial->len);
					r = SC_SUCCESS;
					gbits = 0; /* set to skip using guid below */
				}
			}
			if (guid && gbits) {
				/* guidlen is 16 */
				serial->len = guidlen;
				memcpy (serial->value, guid, serial->len);
				r = SC_SUCCESS;
			}
		}
	}

	card->serialnr = *serial;
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * If the object can not be present on the card, because the History
 * object is not present or the History object says its not present,
 * return 1. If object may be present return 0.
 * Cuts down on overhead, by not showing non existent objects to pkcs11
 * The path for the object is passed in and the first 2 bytes are used.
 * Note: If the History or Discovery object is not found the
 * PIV_OBJ_CACHE_NOT_PRESENT is set, as older cards do not have these.
 * pkcs15-piv.c calls this via cardctl.
 */

static int piv_is_object_present(sc_card_t *card, u8 *ptr)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r = 0;
	int enumtag;

	enumtag = piv_find_obj_by_containerid(card, ptr);
	if (enumtag >= 0 && priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_NOT_PRESENT)
		r = 1;

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * NIST 800-73-3 allows the default pin to be the PIV application 0x80
 * or the global pin for the card 0x00. Look at Discovery object to get this.
 * called by pkcs15-piv.c  via cardctl when setting up the pins.
 */
static int piv_get_pin_preference(sc_card_t *card, int *pin_ref)
{
	piv_private_data_t * priv = PIV_DATA(card);

	*pin_ref = priv->pin_preference;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int piv_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8 * opts; /*  A or M, key_ref, alg_id */

	LOG_FUNC_CALLED(card->ctx);

	if (priv == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	switch(cmd) {
		case SC_CARDCTL_PIV_AUTHENTICATE:
			opts = (u8 *)ptr;
			switch (*opts) {
				case 'A':
					return piv_general_external_authenticate(card,
						*(opts+1), *(opts+2));
					break;
				case 'M':
					return piv_general_mutual_authenticate(card,
						*(opts+1), *(opts+2));
					break;
			}
			break;
		case SC_CARDCTL_PIV_GENERATE_KEY:
			return piv_generate_key(card,
				(sc_cardctl_piv_genkey_info_t *) ptr);
			break;
		case SC_CARDCTL_GET_SERIALNR:
			return piv_get_serial_nr_from_CHUI(card, (sc_serial_number_t *) ptr);
			break;
		case SC_CARDCTL_PIV_PIN_PREFERENCE:
			return piv_get_pin_preference(card, ptr);
			break;
		case SC_CARDCTL_PIV_OBJECT_PRESENT:
			return piv_is_object_present(card, ptr);
			break;
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static int piv_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	/* Dynamic Authentication Template (Challenge) */
	u8 sbuf[] = {0x7c, 0x02, 0x81, 0x00};
	u8 rbuf[4096];
	const u8 *p;
	size_t out_len = 0;
	int r;
	unsigned int tag_out = 0, cla_out = 0;
	piv_private_data_t * priv = PIV_DATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (priv->card_issues & CI_NO_RANDOM) {
		r = SC_ERROR_NOT_SUPPORTED;
		LOG_TEST_GOTO_ERR(card->ctx, r, "No support for random data");
	}

	/* NIST 800-73-3 says use 9B, previous versions used 00 */
	r = piv_general_io(card, 0x87, 0x00, 0x9B, sbuf, sizeof sbuf, rbuf, sizeof rbuf);
	/*
	 * piv_get_challenge is called in a loop.
	 * some cards may allow 1 challenge expecting it to be part of
	 * NIST 800-73-3 part 2 "Authentication of PIV Card Application Administrator"
	 * and return "6A 80" if last command was a get_challenge.
	 * Now that the card returned error, we can try one more time.
	 */
	 if (r == SC_ERROR_INCORRECT_PARAMETERS) {
		r = piv_general_io(card, 0x87, 0x00, 0x9B, sbuf, sizeof sbuf, rbuf, sizeof rbuf);
		if (r == SC_ERROR_INCORRECT_PARAMETERS) {
			r = SC_ERROR_NOT_SUPPORTED;
		}
	}
	LOG_TEST_GOTO_ERR(card->ctx, r, "GENERAL AUTHENTICATE failed");

	p = rbuf;
	r = sc_asn1_read_tag(&p, r, &cla_out, &tag_out, &out_len);
	if (r < 0 || (cla_out|tag_out) != 0x7C) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find Dynamic Authentication Template");
	}

	r = sc_asn1_read_tag(&p, out_len, &cla_out, &tag_out, &out_len);
	if (r < 0 || (cla_out|tag_out) != 0x81) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find Challenge");
	}

	if (len < out_len) {
		out_len = len;
	}
	memcpy(rnd, p, out_len);

	r = (int) out_len;

err:
	LOG_FUNC_RETURN(card->ctx, r);

}

static int
piv_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx,
			"flags=%08lx op=%d alg=%lu algf=%08lx algr=%08lx kr0=%02x, krfl=%"SC_FORMAT_LEN_SIZE_T"u",
			env->flags, env->operation, env->algorithm, env->algorithm_flags,
			env->algorithm_ref, env->key_ref[0], env->key_ref_len);

	priv->operation = env->operation;
	priv->algorithm = env->algorithm;

	if (env->algorithm == SC_ALGORITHM_RSA) {
		priv->alg_id = 0x06; /* Say it is RSA, set 5, 6, 7 later */
	} else if (env->algorithm == SC_ALGORITHM_EC) {
		if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
			switch (env->algorithm_ref) {
				case 256:
					priv->alg_id = 0x11; /* Say it is EC 256 */
					priv->key_size = 256;
					break;
				case 384:
					priv->alg_id = 0x14;
					priv->key_size = 384;
					break;
				default:
					r = SC_ERROR_NO_CARD_SUPPORT;
			}
		} else
			r = SC_ERROR_NO_CARD_SUPPORT;
	} else
		r = SC_ERROR_NO_CARD_SUPPORT;
	priv->key_ref = env->key_ref[0];

	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_restore_security_env(sc_card_t *card, int se_num)
{
	LOG_FUNC_CALLED(card->ctx);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int piv_validate_general_authentication(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r, tmplen, tmplen2;
	u8 *p;
	const unsigned char *p2;
	size_t taglen;
	size_t bodylen;
	unsigned int cla, tag;
	unsigned int real_alg_id, op_tag;

	u8 sbuf[4096]; /* needs work. for 3072 keys, needs 384+10 or so */
	size_t sbuflen = sizeof(sbuf);
	u8 rbuf[4096];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* should assume large send data */
	p = sbuf;
	tmplen = sc_asn1_put_tag(0xff, NULL, datalen, NULL, 0, NULL);
	tmplen2 = sc_asn1_put_tag(0x82, NULL, 0, NULL, 0, NULL);
	if (tmplen <= 0 || tmplen2 <= 0) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	tmplen += tmplen2;
	if ((r = sc_asn1_put_tag(0x7c, NULL, tmplen, p, sbuflen, &p)) != SC_SUCCESS ||
	    (r = sc_asn1_put_tag(0x82, NULL, 0, p, sbuflen - (p - sbuf), &p)) != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}
	if (priv->operation == SC_SEC_OPERATION_DERIVE
			&& priv->algorithm == SC_ALGORITHM_EC) {
		op_tag = 0x85;
	} else {
		op_tag = 0x81;
	}
	r = sc_asn1_put_tag(op_tag, data, datalen, p, sbuflen - (p - sbuf), &p);
	if (r != SC_SUCCESS) {
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/*
	 * alg_id=06 is a place holder for all RSA keys.
	 * Derive the real alg_id based on the size of the
	 * the data, as we are always using raw mode.
	 * Non RSA keys needs some work in this area.
	 */

	real_alg_id = priv->alg_id;
	if (priv->alg_id == 0x06) {
		switch  (datalen) {
			case 128: real_alg_id = 0x06; break;
			case 256: real_alg_id = 0x07; break;
			case 384: real_alg_id = 0x05; break;
			default:
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NO_CARD_SUPPORT);
		}
	}
	/* EC alg_id was already set */

	r = piv_general_io(card, 0x87, real_alg_id, priv->key_ref,
			sbuf, p - sbuf, rbuf, sizeof rbuf);
	if (r < 0)
		goto err;

	p2 = rbuf;
	r = sc_asn1_read_tag(&p2, r, &cla, &tag, &bodylen);
	if (p2 == NULL || r < 0 || bodylen == 0 || (cla|tag) != 0x7C) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find 0x7C");
	}

	r = sc_asn1_read_tag(&p2, bodylen, &cla, &tag, &taglen);
	if (p2 == NULL || r < 0 || taglen == 0 || (cla|tag) != 0x82) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find 0x82");
	}

	if (taglen > outlen) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "data read longer then buffer");
	}

	memcpy(out, p2, taglen);
	r = (int)taglen;

err:
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_compute_signature(sc_card_t *card, const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	size_t nLen;
	u8 rbuf[128]; /* For EC conversions  384 will fit */

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* The PIV returns a DER SEQUENCE{INTEGER, INTEGER}
	 * Which may have leading 00 to force a positive integer
	 * But PKCS11 just wants 2* field_length in bytes
	 * So we have to strip out the integers
	 * and pad on left if too short.
	 */

	if (priv->alg_id == 0x11 || priv->alg_id == 0x14 ) {
		nLen = BYTES4BITS(priv->key_size);
		if (outlen < 2*nLen) {
			sc_log(card->ctx,
					" output too small for EC signature %"SC_FORMAT_LEN_SIZE_T"u < %"SC_FORMAT_LEN_SIZE_T"u",
					outlen, 2 * nLen);
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}

		r = piv_validate_general_authentication(card, data, datalen, rbuf, sizeof rbuf);
		if (r < 0)
			goto err;

		r = sc_asn1_decode_ecdsa_signature(card->ctx, rbuf, r, nLen, &out, outlen);
	} else { /* RSA is all set */
		r = piv_validate_general_authentication(card, data, datalen, out, outlen);
	}

err:
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static int
piv_decipher(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, piv_validate_general_authentication(card, data, datalen, out, outlen));
}

/*
 * the PIV-II does not always support files, but we will simulate
 * files and reading/writing using get/put_data
 * The path is the containerID number
 * We can use this to determine the type of data requested, like a cert
 * or pub key.
 * We only support write from the piv_tool with file_out==NULL
 * All other requests should be to read.
 * Only if file_out != null, will we read to get length.
 */
static int piv_select_file(sc_card_t *card, const sc_path_t *in_path,
	sc_file_t **file_out)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i;
	const u8 *path;
	size_t pathlen;
	sc_file_t *file = NULL;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	path = in_path->value;
	pathlen = in_path->len;

	/* only support single EF in current application */
	/*
	 * PIV emulates files, and only does so because sc_pkcs15_* uses
	 * select_file and read_binary. The emulation adds path emulated structures
	 * so piv_select_file will find it.
	 * there is no dir. Only direct access to emulated files
	 * thus opensc-tool and opensc-explorer can not read the emulated files
	 */

	if (memcmp(path, "\x3F\x00", 2) == 0) {
		if (pathlen > 2) {
			path += 2;
			pathlen -= 2;
		}
	}

	i = piv_find_obj_by_containerid(card, path);

	if (i < 0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

	/*
	 * pkcs15 will use a 2 byte path or a 4 byte path
	 * with cece added to path to request only the cert from the cert obj
	 * PIV "Container ID" is used as the path, and are two bytes long
	 */
	priv->return_only_cert = (pathlen == 4 && path[2] == 0xce && path[3] == 0xce);

	priv->selected_obj = i;
	priv->rwb_state = -1;

	/* make it look like the file was found. */
	/* We don't want to read it now  unless we need the length */

	if (file_out) {
		/* we need to read it now, to get length into cache */
		r = piv_get_cached_data(card, i, &rbuf, &rbuflen);

		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

		/* get the cert or the pub key out and into the cache too */
		if (priv->return_only_cert || piv_objects[i].flags & PIV_OBJECT_TYPE_PUBKEY) {
			r = piv_cache_internal_data(card, i);
			if (r < 0)
				LOG_FUNC_RETURN(card->ctx, r);
		}

		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

		file->path = *in_path;
		/* this could be like the FCI */
		file->type =  SC_FILE_TYPE_DF;
		file->shareable = 0;
		file->ef_structure = 0;
		if (priv->return_only_cert)
			file->size = priv->obj_cache[i].internal_obj_len;
		else
			file->size = priv->obj_cache[i].obj_len;

		file->id = (piv_objects[i].containerid[0]<<8) + piv_objects[i].containerid[1];

		*file_out = file;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

}

static int piv_parse_discovery(sc_card_t *card, u8 * rbuf, size_t rbuflen, int aid_only)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r = 0;
	const u8 * body;
	size_t bodylen;
	const u8 * aid;
	size_t aidlen;
	const u8 * pinp;
	size_t pinplen;
	unsigned int cla_out, tag_out;

	if (rbuflen != 0) {
		body = rbuf;
		if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS
				|| body == NULL
				|| bodylen == 0
				|| ((cla_out|tag_out) != 0x7E)) {
			sc_log(card->ctx, "DER problem %d",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

		sc_log(card->ctx,
				"Discovery 0x%2.2x 0x%2.2x %p:%"SC_FORMAT_LEN_SIZE_T"u",
				cla_out, tag_out, body, bodylen);
		aidlen = 0;
		aid = sc_asn1_find_tag(card->ctx, body, bodylen, 0x4F, &aidlen);
		if (aid == NULL || aidlen < piv_aids[0].len_short ||
			memcmp(aid,piv_aids[0].value,piv_aids[0].len_short) != 0) {
			sc_log(card->ctx, "Discovery object not PIV");
			r = SC_ERROR_INVALID_CARD; /* This is an error */
			goto err;
		}
		if (aid_only == 0) {
			pinp = sc_asn1_find_tag(card->ctx, body, bodylen, 0x5F2F, &pinplen);
			if (pinp && pinplen == 2) {
				priv->init_flags |= PIV_INIT_DISCOVERY_PP;
				priv->pin_policy = (*pinp << 8) + *(pinp + 1);
				sc_log(card->ctx, "Discovery pinp flags=0x%2.2x 0x%2.2x",*pinp, *(pinp+1));
				if ((priv->pin_policy & (PIV_PP_PIN | PIV_PP_GLOBAL))
						== (PIV_PP_PIN | PIV_PP_GLOBAL)
						&& priv->pin_policy & PIV_PP_GLOBAL_PRIMARY) {
					sc_log(card->ctx, "Pin Preference - Global");
					priv->pin_preference = 0x00;
				}
			}
		}
		r = SC_SUCCESS;
		priv->init_flags |= PIV_INIT_DISCOVERY_PARSED;
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}


/* normal way to get the discovery object via cache */
static int piv_process_discovery(sc_card_t *card)
{
	int r;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;

	r = piv_get_cached_data(card, PIV_OBJ_DISCOVERY, &rbuf, &rbuflen);
	/* Note rbuf and rbuflen are now pointers into cache */
	if (r < 0)
		goto err;

	/* the object is now cached, see what we have */
	r = piv_parse_discovery(card, rbuf, rbuflen, 0);

err:
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * parse a CCC to test  if this is a Dual CAC/PIV
 * We read the CCC using the PIV API.
 * Look for CAC RID=A0 00 00 00 79
 */
static int piv_parse_ccc(sc_card_t *card, u8* rbuf, size_t rbuflen)
{
	int r = 0;
	const u8 * body;
	size_t bodylen;
	unsigned int cla_out, tag_out;

	u8  tag;
	const u8 * end;
	size_t len;

	piv_private_data_t * priv = PIV_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (rbuf == NULL || rbuflen == 0) {
		r = SC_ERROR_WRONG_LENGTH;
		goto  err;
	}

	/* Outer layer is a DER tlv */
	body = rbuf;
	if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS
			|| body == NULL
			|| bodylen == 0
			|| ((cla_out << 24 | tag_out) != piv_objects[PIV_OBJ_CCC].resp_tag)) {
		sc_log(card->ctx, "DER problem %d",r);
		r = SC_ERROR_INVALID_ASN1_OBJECT;
		goto err;
	}

	priv->ccc_flags |= PIV_CCC_FOUND;

	/* CCC  entries are simple tlv */
	end = body + bodylen;
	for(; (body < end); body += len) {
		r = sc_simpletlv_read_tag(&body, end - body , &tag, &len);
		if (r < 0)
			goto err;
		switch (tag) {
			case PIV_CCC_TAG_F0:
				if (len == 0x15) {
					if (memcmp(body ,"\xA0\x00\x00\x03\08", 5) == 0)
						priv->ccc_flags |= PIV_CCC_F0_PIV;
					else if (memcmp(body ,"\xA0\x00\x00\x00\x79", 5) == 0)
						priv->ccc_flags |= PIV_CCC_F0_CAC;
					if (*(body + 6) == 0x02)
						priv->ccc_flags |= PIV_CCC_F0_JAVA;
				}
				break;
			case PIV_CCC_TAG_F3:
				if (len == 0x10) {
					if (memcmp(body ,"\xA0\x00\x00\x00\x79\x04", 6) == 0)
						priv->ccc_flags |= PIV_CCC_F3_CAC_PKI;
				}
				break;
		}
	}

err:
	LOG_FUNC_RETURN(card->ctx, r);
}

static int piv_process_ccc(sc_card_t *card)
{
	int r = 0;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	r = piv_get_cached_data(card, PIV_OBJ_CCC, &rbuf, &rbuflen);

	if (r < 0)
		goto err;

	/* the object is now cached, see what we have */
	r = piv_parse_ccc(card, rbuf, rbuflen);
err:
	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_find_discovery(sc_card_t *card)
{
	int r = 0;
	size_t rbuflen;
	u8 * rbuf  = NULL;
	piv_private_data_t * priv = PIV_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/*
	 * During piv_card_reader_lock_obtained,
	 * we use the discovery object to test if card present, and
	 * if PIV AID is active.
	 */
	if (priv->obj_cache[PIV_OBJ_DISCOVERY].flags & PIV_OBJ_CACHE_NOT_PRESENT) {
		r = SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto end;
	}

	/* If not valid: read, test,  cache */
	if (!(priv->obj_cache[PIV_OBJ_DISCOVERY].flags & PIV_OBJ_CACHE_VALID)) {
		r = piv_process_discovery(card);
	} else {
		/* if already in cache,force read */
		rbuflen = 1;
		r = piv_get_data(card, PIV_OBJ_DISCOVERY, &rbuf, &rbuflen);
		/* if same response as last, no need to parse */
		if ( r == 0 && priv->obj_cache[PIV_OBJ_DISCOVERY].obj_len == 0)
			goto end;

		if (r >= 0 && priv->obj_cache[PIV_OBJ_DISCOVERY].obj_len == rbuflen
				&& priv->obj_cache[PIV_OBJ_DISCOVERY].obj_data
				&& !memcmp(rbuf, priv->obj_cache[PIV_OBJ_DISCOVERY].obj_data, rbuflen)) {
				goto end;
		}
		/* This should not happen  bad card */
		sc_log(card->ctx,"Discovery not the same as previously read object");
		r = SC_ERROR_CORRUPTED_DATA;
		goto end;
	}

end:
	free(rbuf);
	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * The history object lists what retired keys and certs are on the card
 * or listed in the offCardCertURL. The user may have read the offCardURL file,
 * ahead of time, and if so will use it for the certs listed.
 * TODO: -DEE
 * If the offCardCertURL is not cached by the user, should we wget it here?
 * Its may be out of scope to have OpenSC read the URL.
 */
static int
piv_process_history(sc_card_t *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i, tmplen, tmplen2, tmplen3;
	int enumtag;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;
	const u8 * body;
	size_t bodylen;
	const u8 * num;
	size_t numlen;
	const u8 * url = NULL;
	size_t urllen;
	u8 * ocfhfbuf = NULL;
	unsigned int cla_out, tag_out;
	size_t ocfhflen;
	const u8 * seq;
	const u8 * seqtag;
	size_t seqlen;
	const u8 * keyref;
	size_t keyreflen;
	const u8 * cert;
	size_t certlen;
	size_t certobjlen, i2;
	u8 * certobj;
	u8 * cp;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = piv_get_cached_data(card, PIV_OBJ_HISTORY, &rbuf, &rbuflen);
	if (r == SC_ERROR_FILE_NOT_FOUND)
		r = 0;			/* OK if not found */
	if (r <= 0) {
		priv->obj_cache[PIV_OBJ_HISTORY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
		goto err;		/* no file, must be pre 800-73-3 card and not on card */
	}

	/* the object is now cached, see what we have */
	if (rbuflen != 0) {
		body = rbuf;
		if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS
				|| ((cla_out << 24 | tag_out) != piv_objects[PIV_OBJ_HISTORY].resp_tag)) {
			sc_log(card->ctx, "DER problem %d",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

		if (body != NULL && bodylen != 0) {
			numlen = 0;
			num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC1, &numlen);
			if (num) {
				if (numlen != 1 || *num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INVALID_ASN1_OBJECT;
					goto err;
				}

				priv->keysWithOnCardCerts = *num;
			}

			numlen = 0;
			num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC2, &numlen);
			if (num) {
				if (numlen != 1 || *num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INVALID_ASN1_OBJECT;
					goto err;
				}

				priv->keysWithOffCardCerts = *num;
			}

			url = sc_asn1_find_tag(card->ctx, body, bodylen, 0xF3, &urllen);
			if (url) {
				priv->offCardCertURL = calloc(1,urllen+1);
				if (priv->offCardCertURL == NULL)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
				memcpy(priv->offCardCertURL, url, urllen);
			}
		}
		else {
			sc_log(card->ctx, "Problem with History object\n");
			r = SC_SUCCESS;              /* OK if not found */
			goto err;
		}
	}
	sc_log(card->ctx, "History on=%d off=%d URL=%s",
			priv->keysWithOnCardCerts, priv->keysWithOffCardCerts,
			priv->offCardCertURL ? priv->offCardCertURL:"NONE");

	/* now mark what objects are on the card */
	for (i=0; i<priv->keysWithOnCardCerts; i++)
		priv->obj_cache[PIV_OBJ_RETIRED_X509_1+i].flags &= ~PIV_OBJ_CACHE_NOT_PRESENT;

	/*
	 * If user has gotten copy of the file from the offCardCertsURL,
	 * we will read in and add the certs to the cache as listed on
	 * the card. some of the certs may be on the card as well.
	 *
	 * Get file name from url. verify that the filename is valid
	 * The URL ends in a SHA1 string. We will use this as the filename
	 * in the directory used for the  PKCS15 cache
	 */

	r = 0;
	if (priv->offCardCertURL) {
		char * fp;
		char filename[PATH_MAX];

		if (strncmp("http://", priv->offCardCertURL, 7)) {
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
		/* find the last /  so we have the filename part */
		fp = strrchr(priv->offCardCertURL + 7,'/');
		if (fp == NULL) {
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
		fp++;

		/* Use the same directory as used for other OpenSC cached items */
		r = sc_get_cache_dir(card->ctx, filename, sizeof(filename) - strlen(fp) - 2);
		if (r != SC_SUCCESS)
			goto err;
#ifdef _WIN32
		strcat(filename,"\\");
#else
		strcat(filename,"/");
#endif
		strcat(filename,fp);

		r = piv_read_obj_from_file(card, filename,
			 &ocfhfbuf, &ocfhflen);
		if (r == SC_ERROR_FILE_NOT_FOUND) {
			r = 0;
			goto err;
		}

		/*
		 * Its a seq of seq of a key ref and cert
		 */

		body = ocfhfbuf;
		if (sc_asn1_read_tag(&body, ocfhflen, &cla_out, &tag_out, &bodylen) != SC_SUCCESS
				|| body == NULL
				|| bodylen == 0
				|| (cla_out|tag_out) != 0x30) {
			sc_log(card->ctx, "DER problem");
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}
		seq = body;
		while (bodylen > 0) {
			seqtag = seq;
			if (sc_asn1_read_tag(&seq, bodylen, &cla_out, &tag_out, &seqlen) != SC_SUCCESS
					|| seq == 0
					|| seqlen == 0
					|| (cla_out|tag_out) != 0x30) {
				sc_log(card->ctx, "DER problem");
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}
			keyref = sc_asn1_find_tag(card->ctx, seq, seqlen, 0x04, &keyreflen);
			if (!keyref || keyreflen != 1 ||
					(*keyref < 0x82 || *keyref > 0x95)) {
				sc_log(card->ctx, "DER problem");
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}
			cert = keyref + keyreflen;
			certlen = seqlen - (cert - seq);

			enumtag = PIV_OBJ_RETIRED_X509_1 + *keyref - 0x82;
			/* now add the cert like another object */

			if ((tmplen = sc_asn1_put_tag(0x70, NULL, certlen, NULL, 0, NULL)) <= 0 ||
			    (tmplen2 = sc_asn1_put_tag(0x71, NULL, 1, NULL, 0, NULL)) <= 0 ||
			    (tmplen3 = sc_asn1_put_tag(0xFE, NULL, 0, NULL, 0, NULL)) <= 0) {
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}
			i2 = tmplen + tmplen2 + tmplen3;
			tmplen = sc_asn1_put_tag(0x53, NULL, i2, NULL, 0, NULL);
			if (tmplen <= 0) {
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}

			certobjlen = tmplen;
			certobj = malloc(certobjlen);
			if (certobj == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			cp = certobj;
			if ((r = sc_asn1_put_tag(0x53, NULL, i2, cp, certobjlen, &cp)) != SC_SUCCESS ||
			    (r = sc_asn1_put_tag(0x70, cert, certlen, cp, certobjlen - (cp - certobj), &cp)) != SC_SUCCESS ||
			    (r = sc_asn1_put_tag(0x71, NULL, 1, cp, certobjlen - (cp - certobj), &cp)) != SC_SUCCESS) {
				goto err;
			}
			*cp++ = 0x00;
			r = sc_asn1_put_tag(0xFE, NULL, 0, cp, certobjlen - (cp - certobj), &cp);
			if (r != SC_SUCCESS) {
				goto err;
			}

			priv->obj_cache[enumtag].obj_data = certobj;
			priv->obj_cache[enumtag].obj_len = certobjlen;
			priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
			priv->obj_cache[enumtag].flags &= ~PIV_OBJ_CACHE_NOT_PRESENT;

			r = piv_cache_internal_data(card, enumtag);
			sc_log(card->ctx, "got internal r=%d",r);

			sc_log(card->ctx,
			       "Added from off card file #%d %p:%"SC_FORMAT_LEN_SIZE_T"u 0x%02X",
			       enumtag,
			       priv->obj_cache[enumtag].obj_data,
			       priv->obj_cache[enumtag].obj_len, *keyref);

			bodylen -= (seqlen + seq - seqtag);
			seq += seqlen;
		}
	}
err:
	if (ocfhfbuf)
		free(ocfhfbuf);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
piv_obj_cache_free_entry(sc_card_t *card, int enumtag, int flags)
{
	piv_private_data_t * priv = PIV_DATA(card);

	if (priv->obj_cache[enumtag].obj_data)
		free(priv->obj_cache[enumtag].obj_data);
	priv->obj_cache[enumtag].obj_data = NULL;
	priv->obj_cache[enumtag].obj_len = 0;

	if (priv->obj_cache[enumtag].internal_obj_data)
		free(priv->obj_cache[enumtag].internal_obj_data);
	priv->obj_cache[enumtag].internal_obj_data = NULL;
	priv->obj_cache[enumtag].internal_obj_len = 0;
	priv->obj_cache[enumtag].flags = flags;

return SC_SUCCESS;
}

static int
piv_finish(sc_card_t *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		if (priv->context_specific) {
			sc_log(card->ctx, "Clearing CONTEXT_SPECIFIC lock");
			priv->context_specific = 0;
			sc_unlock(card);
		}
		free(priv->aid_der.value);
		if (priv->w_buf)
			free(priv->w_buf);
		if (priv->offCardCertURL)
			free(priv->offCardCertURL);
		for (i = 0; i < PIV_OBJ_LAST_ENUM - 1; i++) {
			piv_obj_cache_free_entry(card, i, 0);
		}
#ifdef ENABLE_PIV_SM
		piv_clear_cvc_content(&priv->sm_cvc);
		piv_clear_cvc_content(&priv->sm_in_cvc);
		piv_clear_sm_session(&priv->sm_session);
#endif /* ENABLE_PIV_SM */

		free(priv);
		card->drv_data = NULL; /* priv */
	}
	return 0;
}

static int piv_match_card(sc_card_t *card)
{
	int r = 0;

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d\n", card->type);
	/* piv_match_card may be called with card->type, set by opensc.conf */
	/* user provided card type must be one we know */
	switch (card->type) {
		case -1:
		case SC_CARD_TYPE_PIV_II_BASE:
		case SC_CARD_TYPE_PIV_II_GENERIC:
		case SC_CARD_TYPE_PIV_II_HIST:
		case SC_CARD_TYPE_PIV_II_NEO:
		case SC_CARD_TYPE_PIV_II_YUBIKEY4:
		case SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GI_DE:
		case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GEMALTO:
		case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_OBERTHUR:
		case SC_CARD_TYPE_PIV_II_PIVKEY:
		case SC_CARD_TYPE_PIV_II_SWISSBIT:
		case SC_CARD_TYPE_PIV_II_800_73_4:
			break;
		default:
			return 0; /* can not handle the card */
	}

	r = sc_lock(card);
	if (r < 0)
		return 0;
	/* its one we know, or we can test for it in piv_init */
	r = piv_match_card_continued(card);
	sc_unlock(card);

	if (r < 0 || !card->drv_data) {
		/* clean up what we left in card */
		piv_finish(card);
		return 0; /* match failed */
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r:%d\n", card->type,r);
	return 1; /* matched */
}


static int piv_match_card_continued(sc_card_t *card)
{
	int i, r = 0, r2 = 0;
	int type  = -1;
	piv_private_data_t *priv = NULL;
	int saved_type = card->type;
	sc_apdu_t apdu;
	u8 yubico_version_buf[3] = {0};

	/* piv_match_card may be called with card->type, set by opensc.conf */
	/* User provided card type must be one we know */

	switch (card->type) {
		case -1:
		case SC_CARD_TYPE_PIV_II_BASE:
		case SC_CARD_TYPE_PIV_II_GENERIC:
		case SC_CARD_TYPE_PIV_II_HIST:
		case SC_CARD_TYPE_PIV_II_NEO:
		case SC_CARD_TYPE_PIV_II_YUBIKEY4:
		case SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GI_DE:
		case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GEMALTO:
		case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_OBERTHUR:
		case SC_CARD_TYPE_PIV_II_PIVKEY:
		case SC_CARD_TYPE_PIV_II_SWISSBIT:
		case SC_CARD_TYPE_PIV_II_800_73_4:
			type = card->type;
			break;
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);
	}
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d type:%d r:%d\n", card->type, type, r);
	if (type == -1) {
		/*
		 * Try to identify card by ATR or historical data in ATR
		 * currently all PIV card will respond to piv_find_aid
		 * the same. But in future may need to know card type first,
		 * so do it here.
		 */

		if (card->reader->atr_info.hist_bytes != NULL) {
			if (card->reader->atr_info.hist_bytes_len == 8 &&
					!(memcmp(card->reader->atr_info.hist_bytes, "Yubikey4", 8))) {
				type = SC_CARD_TYPE_PIV_II_YUBIKEY4;
			}
			else if (card->reader->atr_info.hist_bytes_len >= 7 &&
					!(memcmp(card->reader->atr_info.hist_bytes, "Yubikey", 7))) {
				type = SC_CARD_TYPE_PIV_II_NEO;
			}
			else if (card->reader->atr_info.hist_bytes_len >= 6 &&
					!(memcmp(card->reader->atr_info.hist_bytes, "PIVKEY", 6))) {
				type = SC_CARD_TYPE_PIV_II_PIVKEY;
			}
			/* look for TLV historic data */
			else if (card->reader->atr_info.hist_bytes_len > 0
					&& card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
				size_t datalen;
				const u8 *data;

				if ((data = sc_compacttlv_find_tag(card->reader->atr_info.hist_bytes + 1,
						card->reader->atr_info.hist_bytes_len - 1, 0x50, &datalen))) {
					if (datalen == 7 && !(memcmp(data, "YubiKey", 7))) {
						type = SC_CARD_TYPE_PIV_II_YUBIKEY4;   /* reader says 4  really 5 */
					}
					/* Yubikey 5 NFC ATR using ACR122 contactless reader does not match
					 * https://developers.yubico.com/PIV/Introduction/Yubico_extensions.html
					 * On Windows 10, using Omnikey 5021, the ATR is correct
					 * will look at only 6 bytes that do match
					 */
					else if (datalen == 7 && !(memcmp(data, "YubiKe", 6))) {
						type = SC_CARD_TYPE_PIV_II_YUBIKEY4;   /* reader says 4 really 5 */
					}
				} else if ((data = sc_compacttlv_find_tag(card->reader->atr_info.hist_bytes + 1,
						card->reader->atr_info.hist_bytes_len - 1, 0xF0, &datalen))) {
					int k;

					for (k = 0; piv_aids[k].len_long != 0; k++) {
						if (datalen == piv_aids[k].len_long
							&& !memcmp(data, piv_aids[k].value, datalen)) {
							type = SC_CARD_TYPE_PIV_II_HIST;
							break;
						}
					}
				}
			}
		}
		sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d type:%d r:%d\n", card->type, type, r);

		if (type == -1) {
			/* use known ATRs  */
			i = _sc_match_atr(card, piv_atrs, &type);
			if (i < 0)
				type = SC_CARD_TYPE_PIV_II_BASE; /* May be some newer unknown card including CAC or PIV-like card */

		}
	}

	card->type = type;

	/* we either found via ATR historic bytes or ATR directly */
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d type:%d r:%d\n", card->type, type, r);

	/* allocate and init basic fields */
	priv = calloc(1, sizeof(piv_private_data_t));

	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	card->drv_data = priv; /* will free if no match, or pass on to piv_init */
	/*
	 * Largest object defined in NIST sp800-73-3 and sp800-73-4 is 12710 bytes
	 * If for some reason future cards have larger objects, this value needs to
	 * be increased here.
	 */
	priv->max_object_size = MAX_FILE_SIZE - 256; /* fix SM apdu resplen issue */
	priv->selected_obj = -1;
	priv->pin_preference = 0x80; /* 800-73-3 part 1, table 3 */
	/* TODO Dual CAC/PIV are bases on 800-73-1 where priv->pin_preference = 0. need to check later */
	priv->logged_in = SC_PIN_STATE_UNKNOWN;
	priv->pstate = PIV_STATE_MATCH;

#ifdef ENABLE_PIV_SM
	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
	card->sm_ctx.ops.open =  piv_sm_open;
	card->sm_ctx.ops.get_sm_apdu = piv_get_sm_apdu;
	card->sm_ctx.ops.free_sm_apdu = piv_free_sm_apdu;
	card->sm_ctx.ops.close = piv_sm_close;
#endif /* ENABLE_PIV_SM */

	/* see if contactless */
	if (card->reader->atr.len >= 4
			&& card->reader->atr.value[0] == 0x3b
			&& (card->reader->atr.value[1] & 0xF0) == 0x80
			&& card->reader->atr.value[2] == 0x80
			&& card->reader->atr.value[3] == 0x01) {
		priv->init_flags |= PIV_INIT_CONTACTLESS;
	}

	for (i=0; i < PIV_OBJ_LAST_ENUM -1; i++)
		if(piv_objects[i].flags & PIV_OBJECT_NOT_PRESENT)
			priv->obj_cache[i].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
	/*
	 * Detect if active AID is PIV. NIST 800-73 says only one PIV application per card
	 * and PIV must be the default application.
	 * Try to avoid doing a select_aid and losing the login state on some cards.
	 * We may get interference on some cards by other drivers trying SELECT_AID before
	 * we get to see if PIV application is still active. Putting PIV driver first might help.
	 *
	 * Discovery Object introduced in 800-73-3 so will return OK if found and PIV applet active.
	 * Will fail with SC_ERROR_FILE_NOT_FOUND if 800-73-3 and no Discovery object.
	 * But some other card could also return SC_ERROR_FILE_NOT_FOUND.
	 * Will fail for other reasons if wrong applet is selected or bad PIV implementation.
	 */

	/*
	* if ATR matched or user forced card type 
	* test if PIV is active applet without using AID If fails use the AID 
	*/

	if (card->type != SC_CARD_TYPE_PIV_II_BASE)
		r = piv_find_discovery(card);
	else
		r = SC_CARD_TYPE_UNKNOWN;

	if (r < 0) {
		piv_obj_cache_free_entry(card, PIV_OBJ_DISCOVERY, 0); /* don't cache  on failure */
		r = piv_find_aid(card);
	}

	/*if both fail, its not a PIV card */
	if (r < 0) {
		goto err;
	}

	 /* Assumes all Yubikey cards are identified via ATR Historic bytes */
	switch (card->type) {
		case SC_CARD_TYPE_PIV_II_NEO:
		case SC_CARD_TYPE_PIV_II_YUBIKEY4:
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xFD, 0x00, 0x00);
			apdu.lc = 0;
			apdu.data = NULL;
			apdu.datalen = 0;
			apdu.resp = yubico_version_buf;
			apdu.resplen = sizeof(yubico_version_buf);
			apdu.le = apdu.resplen;
			r2 = sc_transmit_apdu(card, &apdu); /* on error yubico_version == 0 */
			if (r2 >= 3) {
				priv->yubico_version = (yubico_version_buf[0]<<16) | (yubico_version_buf[1] <<8) | yubico_version_buf[2];
				sc_log(card->ctx, "Yubico card->type=%d, r=0x%08x version=0x%08x", card->type, r, priv->yubico_version);
			}
	}
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);

	 /* We now know PIV AID is active, test CCC object. 800-73-* say CCC is required */
	 /* CCC not readable over contactless, unless using VCI. but dont need CCC for SC_CARD_TYPE_PIV_II_800_73_4 */
	switch (card->type) {
		/*
		 * For cards that may also be CAC, try and read the CCC
		 * CCC is required and all Dual PIV/CAC will have a CCC
		 * Currently Dual PIV/CAC are based on NIST 800-73-1 which does not have Discovery or History
		 */
		case SC_CARD_TYPE_PIV_II_BASE: /* i.e. really dont know what this is */
		case SC_CARD_TYPE_PIV_II_GENERIC:
		case SC_CARD_TYPE_PIV_II_HIST:
		case SC_CARD_TYPE_PIV_II_GI_DE:
		case SC_CARD_TYPE_PIV_II_GEMALTO:
		case SC_CARD_TYPE_PIV_II_OBERTHUR:
			r2 = piv_process_ccc(card);
			sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d ccc_flags:%08x CI:%08x r:%d\n",
					card->type, r2, priv->ccc_flags, priv->card_issues, r);
			/* Ignore any error. */
			/* If CCC says it has CAC with PKI on card set to one of the SC_CARD_TYPE_PIV_II_*_DUAL_CAC */
			if (priv->ccc_flags & PIV_CCC_F3_CAC_PKI) {
				switch (card->type)  {
					case SC_CARD_TYPE_PIV_II_BASE:
					case SC_CARD_TYPE_PIV_II_GENERIC:
					case SC_CARD_TYPE_PIV_II_HIST:
					case SC_CARD_TYPE_PIV_II_GI_DE:
						card->type = SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC;
						priv->card_issues |= CI_DISCOVERY_USELESS;
						priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
						break;
					case SC_CARD_TYPE_PIV_II_GEMALTO:
						card->type = SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC;
						priv->card_issues |= CI_DISCOVERY_USELESS;
						priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
						break;
					case SC_CARD_TYPE_PIV_II_OBERTHUR:
						card->type =  SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC;
						priv->card_issues |= CI_DISCOVERY_USELESS;
						priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
						break;
				}
			}
			break;

		case SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
			priv->card_issues |= CI_DISCOVERY_USELESS;
			priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
			break;
	}
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);

	/* Read AID if needed for these cards types */
	if (!(priv->init_flags & PIV_INIT_AID_PARSED)) {
		switch(card->type) {
			case SC_CARD_TYPE_PIV_II_BASE:
			case SC_CARD_TYPE_PIV_II_800_73_4:
				r2 = piv_find_aid(card);
		}
	}

	/* If SM is supported, set SC_CARD_TYPE_PIV_II_800_73_4 */
	if (priv->init_flags & PIV_INIT_AID_AC) {
		card->type = SC_CARD_TYPE_PIV_II_800_73_4;
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);

#ifdef ENABLE_PIV_SM
	/* Discovery object has pin policy. 800-74-4 bits, its at least SC_CARD_TYPE_PIV_II_800_73_4 */
	if ((priv->pin_policy & (PIV_PP_OCC | PIV_PP_VCI_IMPL | PIV_PP_VCI_WITHOUT_PC)) != 0) {
		card->type = SC_CARD_TYPE_PIV_II_800_73_4;
	}
#endif
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);

	/*
	 * Set card_issues flags based card->type and version numbers if available.
	 *
	 * YubiKey NEO, Yubikey 4 and other devices with PIV applets, have compliance
	 * issues with the NIST 800-73-3 specs. The OpenSC developers do not have
	 * access to all the different devices or versions of the devices.
	 * Vendor and user input is welcome on any compliance issues.
	 *
	 * For the Yubico devices The assumption is also made that if a bug is
	 * fixed in a Yubico version that means it is fixed on both NEO and Yubikey 4.
	 *
	 * The flags CI_CANT_USE_GETDATA_FOR_STATE and CI_DISCOVERY_USELESS
	 * may be set earlier or later then in the following code.
	 */

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d CI:%08x r:%d\n", card->type, priv->card_issues, r);
	switch(card->type) {
		case SC_CARD_TYPE_PIV_II_NEO:
			priv->card_issues |= CI_NO_EC384
				| CI_VERIFY_630X
				| CI_OTHER_AID_LOSE_STATE
				| CI_LEAKS_FILE_NOT_FOUND
				| CI_NFC_EXPOSE_TOO_MUCH;
			if (priv->yubico_version  < 0x00040302)
				priv->card_issues |= CI_VERIFY_LC0_FAIL;
			break;

		case SC_CARD_TYPE_PIV_II_YUBIKEY4:
			priv->card_issues |=  CI_OTHER_AID_LOSE_STATE
				| CI_LEAKS_FILE_NOT_FOUND;
			if (priv->yubico_version  < 0x00040302)
				priv->card_issues |= CI_VERIFY_LC0_FAIL;
			break;

		case SC_CARD_TYPE_PIV_II_GI_DE:
		case SC_CARD_TYPE_PIV_II_OBERTHUR:
		case SC_CARD_TYPE_PIV_II_GEMALTO:
		case SC_CARD_TYPE_PIV_II_SWISSBIT:
			priv->card_issues |= 0; /* could add others here */
			break;

		case SC_CARD_TYPE_PIV_II_BASE:
		case SC_CARD_TYPE_PIV_II_HIST:
		case SC_CARD_TYPE_PIV_II_800_73_4:
			priv->card_issues |= 0; /* could add others here */
			break;

		case SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
		case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
			priv->card_issues |= CI_VERIFY_LC0_FAIL
				| CI_PIV_AID_LOSE_STATE
				| CI_NO_RANDOM
				| CI_OTHER_AID_LOSE_STATE;
			/* TODO may need more research */
			break;

		case SC_CARD_TYPE_PIV_II_GENERIC:
			priv->card_issues |= CI_VERIFY_LC0_FAIL
				| CI_OTHER_AID_LOSE_STATE;
			break;

		case SC_CARD_TYPE_PIV_II_PIVKEY:
			priv->card_issues |= CI_VERIFY_LC0_FAIL
				| CI_PIV_AID_LOSE_STATE /* be conservative */
				| CI_NO_EC384 | CI_NO_EC
				| CI_NO_RANDOM; /* does not have 9B key */
				/* Discovery object returns 6A 82 so is not on card by default */
				/*  TODO may need more research */
			break;

		default:
			priv->card_issues |= CI_VERIFY_LC0_FAIL
				| CI_OTHER_AID_LOSE_STATE;
			/* opensc.conf may have it wrong, continue anyway */
			sc_log(card->ctx, "Unknown PIV card->type %d", card->type);
			card->type = SC_CARD_TYPE_PIV_II_GENERIC;
	}
	sc_log(card->ctx, "PIV card-type=%d card_issues=0x%08x", card->type, priv->card_issues);
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);

	if (!(priv->card_issues & CI_DISCOVERY_USELESS) && !(priv->init_flags & PIV_INIT_DISCOVERY_PARSED) ) {
		/*
		 * We now know PIV AID is active, test DISCOVERY object again
		 * Some PIV don't support DISCOVERY and return
		 * SC_ERROR_INCORRECT_PARAMETERS. Any error
		 * including SC_ERROR_FILE_NOT_FOUND means we cannot use discovery
		 * to test for active AID.
		 */
		r2 = piv_find_discovery(card);

		if (r2 < 0) {
			priv->card_issues |= CI_DISCOVERY_USELESS;
			piv_obj_cache_free_entry(card, PIV_OBJ_DISCOVERY,PIV_OBJ_CACHE_NOT_PRESENT);
		}
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);
	/* Matched, caller will use or free priv and sc_lock as needed */
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

err:
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r2:%d CI:%08x r:%d\n", card->type, r2, priv->card_issues, r);
	/* don't match. Does not have a PIV applet. */
	piv_finish(card);
	card->type = saved_type;
	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_init(sc_card_t *card)
{
	int r = 0;
	piv_private_data_t * priv = PIV_DATA(card);
	unsigned long flags;
	unsigned long ext_flags;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_lock(card); /* hold until match or init is complete */
	LOG_TEST_RET(card->ctx, r, "sc_lock failed");

	/* piv_match_card_continued called from card match should have left card->drv_data */
	if (priv == NULL) {
		r = piv_match_card_continued(card);
		priv = PIV_DATA(card);
		if (r < 0 || !priv) {
			sc_log(card->ctx,"piv_match_card_continued failed card->type:%d", card->type);
			sc_unlock(card);
			piv_finish(card);
			/* tell sc_connect_card to try other driver */
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
		}
	}

	/* read "card_driver PIV-II" opensc.conf options, and env parameters */
	piv_load_options(card);

	priv->pstate=PIV_STATE_INIT;

	sc_log(card->ctx,
			"Max send = %"SC_FORMAT_LEN_SIZE_T"u recv = %"SC_FORMAT_LEN_SIZE_T"u card->type = %d",
			card->max_send_size, card->max_recv_size, card->type);
	card->cla = 0x00;
	if (card->name == NULL)
		card->name = card->driver->name;

	priv->enumtag = piv_aids[0].enumtag;

	/* PKCS#11 may try to generate session keys, and get confused
	 * if SC_ALGORITHM_ONBOARD_KEY_GEN is present
	 * piv-tool can still do this, just don't tell PKCS#11
	 */

	flags = SC_ALGORITHM_RSA_RAW;

	if (card->type == SC_CARD_TYPE_PIV_II_SWISSBIT) {
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	}

	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* mandatory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */

	if (!(priv->card_issues & CI_NO_EC)) {
		int i;
		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

		for (i = 0; ec_curves[i].oid.value[0] >= 0; i++) {
			if (!(priv->card_issues & CI_NO_EC384 && ec_curves[i].size == 384))
				_sc_card_add_ec_alg(card, ec_curves[i].size, flags, ext_flags, &ec_curves[i].oid);
		}
	}

	if (!(priv->card_issues & CI_NO_RANDOM))
		card->caps |= SC_CARD_CAP_RNG;

	/* May turn off SC_CARD_CAP_ISO7816_PIN_INFO later */
	card->caps |=  SC_CARD_CAP_ISO7816_PIN_INFO;

	/*
	 * 800-73-3 cards may have discovery. "piv-like cards may or may not.
	 * 800-73-4 with VCI must have it as it has the pin policy needed for VCI .
	 */

#ifdef ENABLE_PIV_SM
	/*
	 * 800-73-4
	 * Response of AID says if SM is supported. Look for Cipher Suite
	 */
	if (priv->csID && priv->cs != NULL) {
		/*
		 * TODO look closer at reset of card by other process
		 * Main point in SM and VCI is to allow contactless access
		 */
		/* Only piv_init and piv_reader_lock_obtained should call piv_sm_open */

		/* If user said PIV_SM_FLAGS_NEVER, dont start SM; implies limited contatless access */
		if (priv->sm_flags & PIV_SM_FLAGS_NEVER) {
			sc_log(card->ctx,"User has requested PIV_SM_FLAGS_NEVER");
			r = SC_SUCCESS; /* Users choice */

		} else if ((priv->init_flags & PIV_INIT_CONTACTLESS)
				&& !(priv->pin_policy & PIV_PP_VCI_IMPL)) {
			sc_log(card->ctx,"Contactless and no card support for VCI");
			r = SC_SUCCESS; /* User should know VCI is not possible with their card; use like 800-73-3 contactless  */

		} else if ((priv->init_flags & PIV_INIT_CONTACTLESS)
				&& !(priv->pin_policy & PIV_PP_VCI_WITHOUT_PC)
				&& (priv->pairing_code[0] == 0x00)) {
			sc_log(card->ctx,"Contactless, pairing_code required and no pairing code");
			r = SC_ERROR_PIN_CODE_INCORRECT; /* User should know they need to set pairing code */

		} else {
			priv->sm_flags |= PIV_SM_FLAGS_DEFER_OPEN; /* tell priv_sm_open, OK to open */
			r = piv_sm_open(card);
			sc_log(card->ctx,"piv_sm_open returned:%d", r);
		}

		/* If failed, and user said PIV_SM_FLAGS_ALWAYS quit */
		if (priv->sm_flags & PIV_SM_FLAGS_ALWAYS && r < 0) {
			sc_log(card->ctx,"User has requested PIV_SM_FLAGS_ALWAYS, SM has failed to start, don't use the card");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_ALLOWED);
		}

		/* user has wrong or no required pairing code */
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
			LOG_FUNC_RETURN(card->ctx, r);

		/* If SM did not start, or is not expected to start, continue on without it */
	}
#endif /* ENABLE_PIV_SM */

	/*
	 * 800-73-3 cards may have a history object
	 * We want to process it now as this has information on what
	 * keys and certs. "piv like" cards may or may not have history
	 */
	piv_process_history(card);

	priv->pstate=PIV_STATE_NORMAL;
	sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int piv_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	int r;
#ifdef ENABLE_PIV_SM
	int i;
#endif
	piv_private_data_t * priv = PIV_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* may be called before piv_init has allocated priv */
	if (priv) {
		/* need to save sw1 and sw2 if trying to determine card_state from pin_cmd */

		if (priv->pin_cmd_verify) {
			priv->pin_cmd_verify_sw1 = sw1;
			priv->pin_cmd_verify_sw2 = sw2;
		} else {
			/* a command has completed and it is not verify
			 * If we are in a context_specific sequence, unlock
			 * This just decrements the extra lock count
			 */
			if (priv->context_specific) {
				sc_log(card->ctx,"Clearing CONTEXT_SPECIFIC lock");
				priv->context_specific = 0;
				sc_unlock(card);
			}
		}

		if (priv->card_issues & CI_VERIFY_630X) {

		/* Handle the Yubikey NEO or any other PIV card which returns in response to a verify
		 * 63 0X rather than 63 CX indicate the number of remaining PIN retries.
		 * Perhaps they misread the spec and thought 0xCX meant "clear" or "don't care", not a literal 0xC!
		 */
			if (priv->pin_cmd_verify && sw1 == 0x63U) {
				priv->pin_cmd_verify_sw2 |= 0xC0U; /* make it easier to test in other code */
				if ((sw2 & ~0x0fU) == 0x00U) {
					sc_log(card->ctx, "Verification failed (remaining tries: %d)", (sw2 & 0x0f));
					return SC_ERROR_PIN_CODE_INCORRECT;
					/* this is what the iso_check_sw returns for 63 C0 */
				}
			}
		}
	}
#ifdef ENABLE_PIV_SM
	/* Note 6982 is map to SC_ERROR_SM_NO_SESSION_KEYS but iso maps it to SC_ERROR_SECURITY_STATUS_NOT_SATISFIED */
	/* we do this because 6982 could also mean a verify is not allowed over contactless without VCI */
	/* we stashed the sw1 and sw2 above for verify */
	/* Check specific NIST sp800-73-4 SM  errors */
	for (i = 0; piv_sm_errors[i].SWs != 0; i++) {
		if (piv_sm_errors[i].SWs == ((sw1 << 8) | sw2)) {
			sc_log(card->ctx, "%s", piv_sm_errors[i].errorstr);
			return piv_sm_errors[i].errorno;
		}
	}
#endif
	r = iso_drv->ops->check_sw(card, sw1, sw2);
	return r;
}


static int
piv_check_protected_objects(sc_card_t *card)
{
	int r = 0;
	int i;
	piv_private_data_t * priv = PIV_DATA(card);
	u8 buf[8]; /* tag of 53 with 82 xx xx  will fit in 4 */
	u8 * rbuf;
	size_t buf_len;
	static int protected_objects[] = {PIV_OBJ_PI, PIV_OBJ_CHF, PIV_OBJ_IRIS_IMAGE};

	LOG_FUNC_CALLED(card->ctx);
	/*
	 * routine only called from piv_pin_cmd after verify lc=0 did not return 90 00
	 * We will test for a protected object using GET DATA.
	 *
	 * Based on observations, of cards using the GET DATA APDU,
	 * SC_ERROR_SECURITY_STATUS_NOT_SATISFIED  means the PIN not verified,
	 * SC_SUCCESS means PIN has been verified even if it has length 0
	 * SC_ERROR_FILE_NOT_FOUND (which is the bug) does not tell us anything
	 * about the state of the PIN and we will try the next object.
	 *
	 * If we can't determine the security state from this process,
	 * set card_issues CI_CANT_USE_GETDATA_FOR_STATE
	 * and return SC_ERROR_PIN_CODE_INCORRECT
	 * The circumvention is to add a dummy Printed Info object in the card.
	 * so we will have an object to test.
	 *
	 * We save the object's number to use in the future.
	 *
	 */
	if (priv->object_test_verify == 0) {
		for (i = 0; i < (int)(sizeof(protected_objects)/sizeof(int)); i++) {
			buf_len = sizeof(buf);
			rbuf = buf;
			r = piv_get_data(card, protected_objects[i], &rbuf, &buf_len);
			/* TODO may need to check sw1 and sw2 to see what really happened */
			if (r >= 0 || r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {

				/* we can use this object next time if needed */
				priv->object_test_verify = protected_objects[i];
				break;
			}
		}
		if (priv->object_test_verify == 0) {
			/*
			 * none of the objects returned acceptable sw1, sw2
			 */
			sc_log(card->ctx, "No protected objects found, setting CI_CANT_USE_GETDATA_FOR_STATE");
			priv->card_issues |= CI_CANT_USE_GETDATA_FOR_STATE;
			r = SC_ERROR_PIN_CODE_INCORRECT;
		}
	} else {
		/* use the one object we found earlier. Test is security status has changed */
		buf_len = sizeof(buf);
		rbuf = buf;
		r = piv_get_data(card, priv->object_test_verify, &rbuf, &buf_len);
	}
	if (r == SC_ERROR_FILE_NOT_FOUND)
		r = SC_ERROR_PIN_CODE_INCORRECT;
	else if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		r = SC_ERROR_PIN_CODE_INCORRECT;
	else if (r > 0)
		r = SC_SUCCESS;

	sc_log(card->ctx, "object_test_verify=%d, card_issues = 0x%08x", priv->object_test_verify, priv->card_issues);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int r = 0;
	piv_private_data_t * priv = PIV_DATA(card);

	/* Extra validation of (new) PIN during a PIN change request, to
	 * ensure it's not outside the FIPS 201 4.1.6.1 (numeric only) and
	 * FIPS 140-2 (6 character minimum) requirements.
	 */
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, "piv_pin_cmd tries_left=%d, logged_in=%d", priv->tries_left, priv->logged_in);
	if (data->cmd == SC_PIN_CMD_CHANGE) {
		size_t i = 0;
		if (data->pin2.len < 6) {
			return SC_ERROR_INVALID_PIN_LENGTH;
		}
		for(i=0; i < data->pin2.len; ++i) {
			if (!isdigit(data->pin2.data[i])) {
				return SC_ERROR_INVALID_DATA;
			}
		}
	}

	priv->pin_cmd_verify_sw1 = 0x00U;

	if (data->cmd == SC_PIN_CMD_GET_INFO) { /* fill in what we think it should be */
		data->pin1.logged_in = priv->logged_in;
		data->pin1.tries_left = priv->tries_left;
		if (tries_left)
			*tries_left = priv->tries_left;

		/*
		 * If called to check on the login state for a context specific login
		 * return not logged in. Needed because of logic in e6f7373ef066
		 */
		if (data->pin_type == SC_AC_CONTEXT_SPECIFIC) {
			data->pin1.logged_in = 0;
			 LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}

		if (priv->logged_in == SC_PIN_STATE_LOGGED_IN) {
			/* Avoid status requests when the user is logged in to handle NIST
			 * 800-73-4 Part 2:
			 * The PKI cryptographic function (see Table 4b) is protected with
			 * a “PIN Always” or “OCC Always” access rule. In other words, the
			 * PIN or OCC data must be submitted and verified every time
			 * immediately before a digital signature key operation.  This
			 * ensures cardholder participation every time the private key is
			 * used for digital signature generation */
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}
	}

	/*
	 * If this was for a CKU_CONTEXT_SPECFIC login, lock the card one more time.
	 * to avoid any interference from other applications.
	 * Sc_unlock will be called at a later time after the next card command
	 * that should be a crypto operation. If its not then it is a error by the
	 * calling application.
	 */
	if (data->cmd == SC_PIN_CMD_VERIFY && data->pin_type == SC_AC_CONTEXT_SPECIFIC) {
		priv->context_specific = 1;
		sc_log(card->ctx,"Starting CONTEXT_SPECIFIC verify");
		r = sc_lock(card);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, "sc_lock failed");
			return r;
		}
	}

	priv->pin_cmd_verify = 1; /* tell piv_check_sw its a verify to save sw1, sw2 */
	r = iso_drv->ops->pin_cmd(card, data, tries_left);
	priv->pin_cmd_verify = 0;

	/* tell user verify not supported on contactless without VCI */
	if (priv->pin_cmd_verify_sw1 == 0x69 && priv->pin_cmd_verify_sw2 == 0x82
			&& priv->init_flags & PIV_INIT_CONTACTLESS
			&& card->type == SC_CARD_TYPE_PIV_II_800_73_4) {
				sc_log(card->ctx, "Token does not support pin verify over contacless reader");
				/* TODO maybe true for other contactless cards */
				r = SC_ERROR_NOT_SUPPORTED;
	}


	/* if verify failed, release the lock */
	if (data->cmd == SC_PIN_CMD_VERIFY && r < 0 &&  priv->context_specific) {
		sc_log(card->ctx,"Clearing CONTEXT_SPECIFIC");
		priv->context_specific = 0;
		sc_unlock(card);
	}

	/* if access to applet is know to be reset by other driver  we select_aid and try again */
	if ( priv->card_issues & CI_OTHER_AID_LOSE_STATE && priv->pin_cmd_verify_sw1 == 0x6DU) {
		sc_log(card->ctx, "AID may be lost doing piv_find_aid and retry pin_cmd");
		piv_find_aid(card);

		priv->pin_cmd_verify = 1; /* tell piv_check_sw its a verify to save sw1, sw2 */
		r = iso_drv->ops->pin_cmd(card, data, tries_left);
		priv->pin_cmd_verify = 0;
	}

	/* If verify worked, we are logged_in */
	if (data->cmd == SC_PIN_CMD_VERIFY) {
		if (r >= 0)
			priv->logged_in = SC_PIN_STATE_LOGGED_IN;
		else
			priv->logged_in = SC_PIN_STATE_LOGGED_OUT;
	}

	/* Some cards never return 90 00  for SC_PIN_CMD_GET_INFO even if the card state is verified */
	/* PR 797 has changed the return codes from pin_cmd, and added a data->pin1.logged_in flag */

	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		if (priv->card_issues & CI_CANT_USE_GETDATA_FOR_STATE) {
			sc_log(card->ctx, "CI_CANT_USE_GETDATA_FOR_STATE set, assume logged_in=%d", priv->logged_in);
			data->pin1.logged_in =  priv->logged_in; /* use what ever we saw last */
		} else if (priv->card_issues & CI_VERIFY_LC0_FAIL
			&& priv->pin_cmd_verify_sw1 == 0x63U ) { /* can not use modified return codes from iso->drv->pin_cmd */
			/* try another method, looking at a protected object this may require adding one of these to NEO */
			r = piv_check_protected_objects(card);
			if (r == SC_SUCCESS)
				data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
			else if (r ==  SC_ERROR_PIN_CODE_INCORRECT) {
				if (priv->card_issues & CI_CANT_USE_GETDATA_FOR_STATE) { /* we still can not determine login state */

					data->pin1.logged_in = priv->logged_in; /* may have be set from SC_PIN_CMD_VERIFY */
					/* TODO a reset may have logged us out. need to detect resets */
				} else {
					data->pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
				}
				r = SC_SUCCESS;
			}
		}
		priv->logged_in = data->pin1.logged_in;
		priv->tries_left = data->pin1.tries_left;
	}

	sc_log(card->ctx, "piv_pin_cmd tries_left=%d, logged_in=%d",priv->tries_left, priv->logged_in);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int piv_logout(sc_card_t *card)
{
	int r = SC_ERROR_INTERNAL;
	piv_private_data_t * priv = PIV_DATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (priv) {
		/* logout defined since 800-73-4 */
		r = iso7816_logout(card, priv->pin_preference);
		if (r == SC_SUCCESS) {
			priv->logged_in = SC_PIN_STATE_LOGGED_OUT;
		}
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * Called when a sc_lock gets a reader lock and PCSC SCardBeginTransaction
 * If SCardBeginTransaction may pass back that a card reset was seen since
 * the last transaction  completed.
 * There may have been one or more resets, by other card drivers in different
 * processes, and they may have taken action already
 * and changed the AID and or may have sent a  VERIFY with PIN
 * So test the state of the card.
 * this is very similar to what the piv_match routine does,
 */

/* TODO card.c also calls piv_sm_open before this if a reset was done, but
 * does not say if a reset was done or not. May need to ignore the call
 * the piv_sm_open in this case, but how? may need a open is active flag,
 * in case it is the APDU done from open caused  triggered the case.
 */
 /* TODO may be called recursively to handle reset.
  * need we are active, and if called again with was_reset save this
  * and return to let first call handle the reset
  */
static int piv_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = 0;
	u8 temp[SC_MAX_APDU_BUFFER_SIZE];
	size_t templen = sizeof(temp);
	piv_private_data_t * priv = PIV_DATA(card); /* may be null */

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* We have a PCSC transaction and sc_lock */
	if (priv == NULL || priv->pstate == PIV_STATE_MATCH) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				priv ? "PIV_STATE_MATCH" : "priv==NULL");
		r = 0; /* do nothing, piv_match will take care of it */
		goto err;
	}

	priv->init_flags |= PIV_INIT_IN_READER_LOCK_OBTAINED;

	/* make sure our application is active */

	/* first see if AID is active AID by reading discovery object '7E' */
	/* If not try selecting AID */

	/* but if card does not support DISCOVERY object we can not use it */
	if (priv->card_issues & CI_DISCOVERY_USELESS) {
		r =  SC_ERROR_NO_CARD_SUPPORT;
	} else {
		r = piv_find_discovery(card);
#ifdef ENABLE_PIV_SM
		/*
		 * All 800-73-4 cards that support SM, also have a discovery object with
		 * the pin_policy, so can not have CI_DISCOVERY_USELESS
		 * Discovery object can be read with contact or contactless
		 * If read with SM and fails with 69 88  SC_ERROR_SM_INVALID_SESSION_KEY
		 * sm.c will close the SM connectrion, and set defer
		 * TODO may be with reset?
		 */
		 if (was_reset == 0 && (r == SC_ERROR_SM_INVALID_SESSION_KEY || priv->sm_flags & PIV_SM_FLAGS_DEFER_OPEN)) {
			sc_log(card->ctx,"SC_ERROR_SM_INVALID_SESSION_KEY || PIV_SM_FLAGS_DEFER_OPEN");
			piv_sm_open(card);
			r = piv_find_discovery(card);
			}
#endif /* ENABLE_PIV_SM */
	}

	if (r < 0) {
		if (was_reset > 0 || !(priv->card_issues & CI_PIV_AID_LOSE_STATE)) {
			r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, temp, &templen);
			sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "piv_select_aid card->type:%d r:%d\n", card->type, r);
		} else {
			r = 0; /* can't do anything with this card, hope there was no interference */
		}
	}

	if (r < 0) /* bad error return will show up in sc_lock as error*/
		goto err;

	if (was_reset > 0)
		priv->logged_in =  SC_PIN_STATE_UNKNOWN;

	r = 0;

err:
	if (priv)
		priv->init_flags &= ~PIV_INIT_IN_READER_LOCK_OBTAINED;
	LOG_FUNC_RETURN(card->ctx, r);
}



static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	piv_ops = *iso_drv->ops;
	piv_ops.match_card = piv_match_card;
	piv_ops.init = piv_init;
	piv_ops.finish = piv_finish;

	piv_ops.select_file =  piv_select_file; /* must use get/put, could emulate? */
	piv_ops.get_challenge = piv_get_challenge;
	piv_ops.logout = piv_logout;
	piv_ops.read_binary = piv_read_binary;
	piv_ops.write_binary = piv_write_binary;
	piv_ops.set_security_env = piv_set_security_env;
	piv_ops.restore_security_env = piv_restore_security_env;
	piv_ops.compute_signature = piv_compute_signature;
	piv_ops.decipher =  piv_decipher;
	piv_ops.check_sw = piv_check_sw;
	piv_ops.card_ctl = piv_card_ctl;
	piv_ops.pin_cmd = piv_pin_cmd;
	piv_ops.card_reader_lock_obtained = piv_card_reader_lock_obtained;

	return &piv_drv;
}

struct sc_card_driver * sc_get_piv_driver(void)
{
	return sc_get_driver();
}

