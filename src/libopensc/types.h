/*
 * types.h: OpenSC general types
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#ifndef _OPENSC_TYPES_H
#define _OPENSC_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char u8;

/* various maximum values */
#define SC_MAX_CARD_DRIVERS		48
#define SC_MAX_CARD_DRIVER_SNAME_SIZE	16
#define SC_MAX_CARD_APPS		8
#define SC_MAX_APDU_BUFFER_SIZE		261 /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
#define SC_MAX_APDU_DATA_SIZE		0xFF
#define SC_MAX_APDU_RESP_SIZE		(0xFF+1)
#define SC_MAX_EXT_APDU_BUFFER_SIZE	65538
#define SC_MAX_EXT_APDU_DATA_SIZE		0xFFFF
#define SC_MAX_EXT_APDU_RESP_SIZE		(0xFFFF+1)
#define SC_MAX_PIN_SIZE			256 /* OpenPGP card has 254 max */
#define SC_MAX_ATR_SIZE			33
#define SC_MAX_UID_SIZE			10
#define SC_MAX_AID_SIZE			16
#define SC_MAX_AID_STRING_SIZE		(SC_MAX_AID_SIZE * 2 + 3)
#define SC_MAX_IIN_SIZE			10
#define SC_MAX_OBJECT_ID_OCTETS		16
#define SC_MAX_PATH_SIZE		16
#define SC_MAX_PATH_STRING_SIZE		(SC_MAX_PATH_SIZE * 2 + 3)
#define SC_MAX_SDO_ACLS			8
#define SC_MAX_CRTS_IN_SE		12
#define SC_MAX_SE_NUM			8

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c,
 * src/libopensc/pkcs15-prkey.c and src/libopensc/pkcs15-skey.c
 * `grep "src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as"'
 */
#define SC_MAX_SUPPORTED_ALGORITHMS	16

struct sc_lv_data {
	unsigned char *value;
	size_t len;
};

struct sc_tlv_data {
	unsigned tag;
	unsigned char *value;
	size_t len;
};

struct sc_object_id {
	int value[SC_MAX_OBJECT_ID_OCTETS];
};

struct sc_aid {
	unsigned char value[SC_MAX_AID_SIZE];
	size_t len;
};

struct sc_atr {
	unsigned char value[SC_MAX_ATR_SIZE];
	size_t len;
};

struct sc_uid {
	unsigned char value[SC_MAX_UID_SIZE];
	size_t len;
};

/* Issuer ID */
struct sc_iid {
	unsigned char value[SC_MAX_IIN_SIZE];
	size_t len;
};

struct sc_version {
	unsigned char hw_major;
	unsigned char hw_minor;

	unsigned char fw_major;
	unsigned char fw_minor;
};

/* Discretionary ASN.1 data object */
struct sc_ddo {
	struct sc_aid aid;
	struct sc_iid iid;
	struct sc_object_id oid;

	size_t len;
	unsigned char *value;
};

#define SC_PATH_TYPE_FILE_ID		0
#define SC_PATH_TYPE_DF_NAME		1
#define SC_PATH_TYPE_PATH		2
/* path of a file containing EnvelopedData objects */
#define SC_PATH_TYPE_PATH_PROT		3
#define SC_PATH_TYPE_FROM_CURRENT	4
#define SC_PATH_TYPE_PARENT		5

typedef struct sc_path {
	u8 value[SC_MAX_PATH_SIZE];
	size_t len;

	/* The next two fields are used in PKCS15, where
	 * a Path object can reference a portion of a file -
	 * count octets starting at offset index.
	 */
	int index;
	int count;

	int type;

	struct sc_aid aid;
} sc_path_t;

/* Control reference template */
struct sc_crt {
	unsigned tag;
	unsigned usage;		/* Usage Qualifier Byte */
	unsigned algo;		/* Algorithm ID */
	unsigned refs[8];	/* Security Object References */
};

/* Access Control flags */
#define SC_AC_NONE			0x00000000
#define SC_AC_CHV			0x00000001 /* Card Holder Verif. */
#define SC_AC_TERM			0x00000002 /* Terminal auth. */
#define SC_AC_PRO			0x00000004 /* Secure Messaging */
#define SC_AC_AUT			0x00000008 /* Key auth. */
#define SC_AC_SYMBOLIC			0x00000010 /* internal use only */
#define SC_AC_SEN                       0x00000020 /* Security Environment. */
#define SC_AC_SCB                       0x00000040 /* IAS/ECC SCB byte. */
#define SC_AC_IDA                       0x00000080 /* PKCS#15 authentication ID */
#define SC_AC_SESSION			0x00000100 /* Session PIN */
#define SC_AC_CONTEXT_SPECIFIC		0x00000200 /* Context specific login */

#define SC_AC_UNKNOWN			0xFFFFFFFE
#define SC_AC_NEVER			0xFFFFFFFF

/* Operations relating to access control */
#define SC_AC_OP_SELECT			0
#define SC_AC_OP_LOCK			1
#define SC_AC_OP_DELETE			2
#define SC_AC_OP_CREATE			3
#define SC_AC_OP_REHABILITATE		4
#define SC_AC_OP_INVALIDATE		5
#define SC_AC_OP_LIST_FILES		6
#define SC_AC_OP_CRYPTO			7
#define SC_AC_OP_DELETE_SELF		8
#define SC_AC_OP_PSO_DECRYPT		9
#define SC_AC_OP_PSO_ENCRYPT		10
#define SC_AC_OP_PSO_COMPUTE_SIGNATURE	11
#define SC_AC_OP_PSO_VERIFY_SIGNATURE	12
#define SC_AC_OP_PSO_COMPUTE_CHECKSUM	13
#define SC_AC_OP_PSO_VERIFY_CHECKSUM	14
#define SC_AC_OP_INTERNAL_AUTHENTICATE	15
#define SC_AC_OP_EXTERNAL_AUTHENTICATE	16
#define SC_AC_OP_PIN_DEFINE		17
#define SC_AC_OP_PIN_CHANGE		18
#define SC_AC_OP_PIN_RESET		19
#define SC_AC_OP_ACTIVATE		20
#define SC_AC_OP_DEACTIVATE		21
#define SC_AC_OP_READ			22
#define SC_AC_OP_UPDATE			23
#define SC_AC_OP_WRITE			24
#define SC_AC_OP_RESIZE			25
#define SC_AC_OP_GENERATE		26
#define SC_AC_OP_CREATE_EF		27
#define SC_AC_OP_CREATE_DF		28
#define SC_AC_OP_ADMIN			29
#define SC_AC_OP_PIN_USE		30
/* If you add more OPs here, make sure you increase SC_MAX_AC_OPS*/
#define SC_MAX_AC_OPS			31

/* the use of SC_AC_OP_ERASE is deprecated, SC_AC_OP_DELETE should be used
 * instead  */
#define SC_AC_OP_ERASE			SC_AC_OP_DELETE

#define SC_AC_KEY_REF_NONE	0xFFFFFFFF

typedef struct sc_acl_entry {
	unsigned int method;	/* See SC_AC_* */
	unsigned int key_ref;	/* SC_AC_KEY_REF_NONE or an integer */
	struct sc_acl_entry *next;
} sc_acl_entry_t;

/* File types */
#define SC_FILE_TYPE_UNKNOWN		0x00
#define SC_FILE_TYPE_DF			0x04
#define SC_FILE_TYPE_INTERNAL_EF	0x03
#define SC_FILE_TYPE_WORKING_EF		0x01
#define SC_FILE_TYPE_BSO		0x10

/* EF structures */
#define SC_FILE_EF_UNKNOWN		0x00
#define SC_FILE_EF_TRANSPARENT		0x01
#define SC_FILE_EF_LINEAR_FIXED		0x02
#define SC_FILE_EF_LINEAR_FIXED_TLV	0x03
#define SC_FILE_EF_LINEAR_VARIABLE	0x04
#define SC_FILE_EF_LINEAR_VARIABLE_TLV	0x05
#define SC_FILE_EF_CYCLIC		0x06
#define SC_FILE_EF_CYCLIC_TLV		0x07

/* File status flags */
/* ISO7816-4: Unless otherwise specified, the security attributes are valid for the operational state.*/
#define SC_FILE_STATUS_ACTIVATED	0x00 /* ISO7816-4: Operational state (activated)   (5, 7) */
#define SC_FILE_STATUS_INVALIDATED	0x01 /* ISO7816-4: Operational state (deactivated) (4, 6) */

/* Full access in this state, (at least for SetCOS 4.4 ) */
#define SC_FILE_STATUS_CREATION		0x02 /* ISO7816-4: Creation state, (1) */

#define SC_FILE_STATUS_INITIALISATION	0x03 /* ISO7816-4: Initialisation state, (3) */
#define SC_FILE_STATUS_NO_INFO		0x04 /* ISO7816-4: No information given, (0) */
#define SC_FILE_STATUS_TERMINATION	0x0c /* ISO7816-4: Termination state (12,13,14,15) */
#define SC_FILE_STATUS_PROPRIETARY	0xf0 /* ISO7816-4: codes > 15 */

/* reserved for future use by ISO/IEC */
#define SC_FILE_STATUS_RFU_2		0x07 /* ISO7816-4: (0x02) */
#define SC_FILE_STATUS_RFU_8		0x08 /* ISO7816-4: (0x08) */
#define SC_FILE_STATUS_RFU_9		0x09 /* ISO7816-4: (0x09) */
#define SC_FILE_STATUS_RFU_10		0x0a /* ISO7816-4: (0x0a) */
#define SC_FILE_STATUS_RFU_11		0x0b /* ISO7816-4: (0x0b) */

#define SC_FILE_STATUS_UNKNOWN		0xff /* if tag 0x8A is missing, there is no information about LCSB */

typedef struct sc_file {
	struct sc_path path;
	unsigned char name[16];	/* DF name */
	size_t namelen; /* length of DF name */

	unsigned int type, ef_structure, status; /* See constant values defined above */
	unsigned int shareable;                  /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */
	size_t size;	/* Size of file (in bytes) */
	int id;		/* file identifier (2 bytes) */
	int sid;	/* short EF identifier (1 byte) */
	struct sc_acl_entry *acl[SC_MAX_AC_OPS]; /* Access Control List */

	size_t record_length; /* max. length in case of record-oriented EF */
	size_t record_count;  /* Valid, if not transparent EF or DF */

	unsigned char *sec_attr;	/* security data in proprietary format. tag '86' */
	size_t sec_attr_len;

	unsigned char *prop_attr;	/* proprietary information. tag '85'*/
	size_t prop_attr_len;

	unsigned char *type_attr;	/* file descriptor data. tag '82'.
					   replaces the file's type information (DF, EF, ...) */
	size_t type_attr_len;

	unsigned char *encoded_content;	/* file's content encoded to be used in the file creation command */
	size_t encoded_content_len;	/* size of file's encoded content in bytes */

	unsigned int magic;
} sc_file_t;


/* Different APDU cases */
#define SC_APDU_CASE_NONE		0x00
#define SC_APDU_CASE_1			0x01
#define SC_APDU_CASE_2_SHORT		0x02
#define SC_APDU_CASE_3_SHORT		0x03
#define SC_APDU_CASE_4_SHORT		0x04
#define SC_APDU_SHORT_MASK		0x0f
#define SC_APDU_EXT			0x10
#define SC_APDU_CASE_2_EXT		SC_APDU_CASE_2_SHORT | SC_APDU_EXT
#define SC_APDU_CASE_3_EXT		SC_APDU_CASE_3_SHORT | SC_APDU_EXT
#define SC_APDU_CASE_4_EXT		SC_APDU_CASE_4_SHORT | SC_APDU_EXT
/* following types let OpenSC decides whether to use short or extended APDUs */
#define SC_APDU_CASE_2			0x22
#define SC_APDU_CASE_3			0x23
#define SC_APDU_CASE_4			0x24

/* use command chaining if the Lc value is greater than normally allowed */
#define SC_APDU_FLAGS_CHAINING		0x00000001UL
/* do not automatically call GET RESPONSE to read all available data */
#define SC_APDU_FLAGS_NO_GET_RESP	0x00000002UL
/* do not automatically try a re-transmit with a new length if the card 
 * returns 0x6Cxx (wrong length)
 */
#define SC_APDU_FLAGS_NO_RETRY_WL	0x00000004UL
/* APDU is from Secure Messaging  */
#define SC_APDU_FLAGS_NO_SM		0x00000008UL

#define SC_APDU_ALLOCATE_FLAG		0x01
#define SC_APDU_ALLOCATE_FLAG_DATA	0x02
#define SC_APDU_ALLOCATE_FLAG_RESP	0x04

typedef struct sc_apdu {
	int cse;			/* APDU case */
	unsigned char cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
	size_t lc, le;			/* Lc and Le bytes */
	const unsigned char *data;	/* S-APDU data */
	size_t datalen;			/* length of data in S-APDU */
	unsigned char *resp;		/* R-APDU data buffer */
	size_t resplen;			/* in: size of R-APDU buffer,
					 * out: length of data returned in R-APDU */
	unsigned char control;		/* Set if APDU should go to the reader */
	unsigned allocation_flags;	/* APDU allocation flags */

	unsigned int sw1, sw2;		/* Status words returned in R-APDU */
	unsigned char mac[8];
	size_t mac_len;

	unsigned long flags;

	struct sc_apdu *next;
} sc_apdu_t;

/* Card manager Production Life Cycle data (CPLC) 
 * (from the Open Platform specification) */
#define SC_CPLC_TAG		0x9F7F
#define SC_CPLC_DER_SIZE	45
struct sc_cplc {
	unsigned char ic_fabricator[2];
	unsigned char ic_type[2];
	unsigned char os_data[6];
	unsigned char ic_date[2];
	unsigned char ic_serial[4];
	unsigned char ic_batch_id[2];
	unsigned char ic_module_data[4];
	unsigned char icc_manufacturer[2];
	unsigned char ic_embed_date[2];
	unsigned char pre_perso_data[6];
	unsigned char personalizer_data[6];

	unsigned char value[SC_CPLC_DER_SIZE];
	size_t len;
};

/* 'Issuer Identification Number' is a part of ISO/IEC 7812 PAN definition */
struct sc_iin {
	unsigned char mii;              /* industry identifier */
	unsigned country;               /* country identifier */
	unsigned long issuer_id;        /* issuer identifier */
};

/* structure for the card serial number (normally the ICCSN) */
#define SC_MAX_SERIALNR         32
typedef struct sc_serial_number {
	unsigned char value[SC_MAX_SERIALNR];
	size_t len;

	struct sc_iin iin;
} sc_serial_number_t;

/**
 * @struct sc_remote_apdu data
 * Structure to supply the linked APDU data used in
 * communication with the external (SM) modules.
 */
#define SC_REMOTE_APDU_FLAG_NOT_FATAL		0x01
#define SC_REMOTE_APDU_FLAG_RETURN_ANSWER	0x02
struct sc_remote_apdu {
	unsigned char sbuf[2*SC_MAX_APDU_BUFFER_SIZE];
	unsigned char rbuf[2*SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	unsigned flags;

	struct sc_remote_apdu *next;
};

/**
 * @struct sc_remote_data 
 * Frame for the list of the @c sc_remote_apdu data with
 * the handlers to allocate and free.
 */
struct sc_remote_data {
	struct sc_remote_apdu *data;
	int length;

	/**
         * Handler to allocate a new @c sc_remote_apdu data and add it to the list.
 	 * @param rdata Self pointer to the @c sc_remote_data
	 * @param out Pointer to newle allocated member
  	 */
	int (*alloc)(struct sc_remote_data *rdata, struct sc_remote_apdu **out);
	/**
         * Handler to free the list of @c sc_remote_apdu data 
 	 * @param rdata Self pointer to the @c sc_remote_data
  	 */
	void (*free)(struct sc_remote_data *rdata);
};


#ifdef __cplusplus
}
#endif

#endif
