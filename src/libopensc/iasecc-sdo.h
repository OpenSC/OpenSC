/*
 * iasecc-sdo.h: Support for IAS/ECC smart cards
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

#ifndef SC_IASECC_SDO_H
#define SC_IASECC_SDO_H

#include "libopensc/types.h"

#define IASECC_SDO_TAG_HEADER	0xBF

#define IASECC_SDO_TEMPLATE_TAG	0x70

#define IASECC_DOCP_TAG				0xA0
#define IASECC_DOCP_TAG_NAME			0x84
#define IASECC_DOCP_TAG_TRIES_MAXIMUM		0x9A
#define IASECC_DOCP_TAG_TRIES_REMAINING		0x9B
#define IASECC_DOCP_TAG_USAGE_MAXIMUM		0x9C
#define IASECC_DOCP_TAG_USAGE_REMAINING		0x9D
#define IASECC_DOCP_TAG_NON_REPUDIATION 		0x9E
#define IASECC_DOCP_TAG_SIZE			0x80
#define IASECC_DOCP_TAG_ACLS			0xA1
#define IASECC_DOCP_TAG_ACLS_CONTACT		0x8C
#define IASECC_DOCP_TAG_ACLS_CONTACTLESS	0x9C
#define IASECC_DOCP_TAG_ISSUER_DATA_BER		0xA5
#define IASECC_DOCP_TAG_ISSUER_DATA		0x85

#define IASECC_ACLS_CHV_CHANGE		0
#define IASECC_ACLS_CHV_VERIFY		1
#define IASECC_ACLS_CHV_RESET		2
#define IASECC_ACLS_CHV_PUT_DATA	5
#define IASECC_ACLS_CHV_GET_DATA	6

#define IASECC_ACLS_RSAKEY_PSO_SIGN		0
#define IASECC_ACLS_RSAKEY_INTERNAL_AUTH	1
#define IASECC_ACLS_RSAKEY_PSO_DECIPHER		2
#define IASECC_ACLS_RSAKEY_GENERATE		3
#define IASECC_ACLS_RSAKEY_PUT_DATA		5
#define IASECC_ACLS_RSAKEY_GET_DATA		6

#define IASECC_ACLS_KEYSET_EXTERNAL_AUTH	1
#define IASECC_ACLS_KEYSET_MUTUAL_AUTH		3
#define IASECC_ACLS_KEYSET_PUT_DATA		5
#define IASECC_ACLS_KEYSET_GET_DATA		6

#define IASECC_SDO_CHV_TAG		0x7F41
#define IASECC_SDO_CHV_TAG_SIZE_MAX	0x80
#define IASECC_SDO_CHV_TAG_SIZE_MIN	0x81
#define IASECC_SDO_CHV_TAG_VALUE	0x82

#define IASECC_SDO_PRVKEY_TAG			0x7F48
#define IASECC_SDO_PRVKEY_TAG_P			0x92
#define IASECC_SDO_PRVKEY_TAG_Q			0x93
#define IASECC_SDO_PRVKEY_TAG_IQMP		0x94
#define IASECC_SDO_PRVKEY_TAG_DMP1		0x95
#define IASECC_SDO_PRVKEY_TAG_DMQ1		0x96
#define IASECC_SDO_PRVKEY_TAG_COMPULSORY	0x80

#define IASECC_SDO_PUBKEY_TAG			0x7F49
#define IASECC_SDO_PUBKEY_TAG_N			0x81
#define IASECC_SDO_PUBKEY_TAG_E			0x82
#define IASECC_SDO_PUBKEY_TAG_COMPULSORY	0x80
#define IASECC_SDO_PUBKEY_TAG_CHR		0x5F20
#define IASECC_SDO_PUBKEY_TAG_CHA		0x5F4C

#define IASECC_SDO_KEYSET_TAG			0xA2
#define IASECC_SDO_KEYSET_TAG_MAC		0x90
#define IASECC_SDO_KEYSET_TAG_ENC		0x91
#define IASECC_SDO_KEYSET_TAG_COMPULSORY	0x80

#define IASECC_SCB_METHOD_NEED_ALL	0x80
#define IASECC_SCB_METHOD_MASK		0x70
#define IASECC_SCB_METHOD_MASK_REF	0x0F
#define IASECC_SCB_METHOD_SM		0x40
#define IASECC_SCB_METHOD_EXT_AUTH	0x20
#define IASECC_SCB_METHOD_USER_AUTH	0x10

#define IASECC_SCB_NEVER	0xFF
#define IASECC_SCB_ALWAYS	0x00

#define IASECC_SDO_CLASS_CHV		0x01
#define IASECC_SDO_CLASS_KEYSET		0x0A
#define IASECC_SDO_CLASS_RSA_PRIVATE	0x10
#define IASECC_SDO_CLASS_RSA_PUBLIC	0x20
#define IASECC_SDO_CLASS_SE		0x7B

#define IASECC_CRT_TAG_AT	0xA4
#define IASECC_CRT_TAG_CT	0xB8
#define IASECC_CRT_TAG_CCT	0xB4
#define IASECC_CRT_TAG_DST	0xB6
#define IASECC_CRT_TAG_HT	0xAA
#define IASECC_CRT_TAG_KAT	0xA6

#define IASECC_CRT_TAG_USAGE		0x95
#define IASECC_CRT_TAG_REFERENCE	0x83
#define IASECC_CRT_TAG_ALGO		0x80

#define IASECC_ALGORITHM_SYMMETRIC		0x0C
#define IASECC_ALGORITHM_DH			0x0B
#define IASECC_ALGORITHM_RSA_PKCS		0x02
#define IASECC_ALGORITHM_RSA_9796_2		0x01
#define IASECC_ALGORITHM_RSA_PKCS_DECRYPT	0x0A
#define IASECC_ALGORITHM_SHA1			0x10
#define IASECC_ALGORITHM_SHA2			0x40

#define IASECC_ALGORITHM_ROLE_AUTH		0x1C
#define IASECC_ALGORITHM_SYMMETRIC_SHA1		0x0C
#define IASECC_ALGORITHM_SYMMETRIC_SHA256	0x8C

#define IASECC_UQB_AT_MUTUAL_AUTHENTICATION	0xC0
#define IASECC_UQB_AT_EXTERNAL_AUTHENTICATION	0x80
#define IASECC_UQB_AT_AUTHENTICATION		0x40
#define IASECC_UQB_AT_USER_PASSWORD		0x08
#define IASECC_UQB_AT_USER_BIOMETRIC		0x04

#define IASECC_UQB_DST_VERIFICATION		0x80
#define IASECC_UQB_DST_COMPUTATION		0x40

#define IASECC_UQB_CT_ENCIPHERMENT		0x80
#define IASECC_UQB_CT_DECIPHERMENT		0x40
#define IASECC_UQB_CT_SM_RESPONSE		0x20
#define IASECC_UQB_CT_SM_COMMAND		0x10

#define IASECC_UQB_CCT_VERIFICATION		0x80
#define IASECC_UQB_CCT_COMPUTATION		0x40
#define IASECC_UQB_CCT_SM_RESPONSE		0x20
#define IASECC_UQB_CCT_SM_COMMAND		0x10

#define IASECC_UQB_KAT				0x80

#define IASECC_ACL_GET_DATA			0x01
#define IASECC_ACL_PUT_DATA			0x02
#define IASECC_ACL_GENERATE_KEY			0x08
#define IASECC_ACL_PSO_DECIPHER			0x10
#define IASECC_ACL_INTERNAL_AUTHENTICATE	0x20
#define IASECC_ACL_PSO_SIGNATURE		0x40

#define IASECC_SDO_TAGS_UPDATE_MAX	16

//#define IASECC_SE_CRTS_MAX	24

#define _MAKE_IASECC_SDO_MAGIC(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | ((d)))

#define IASECC_SDO_MAGIC		_MAKE_IASECC_SDO_MAGIC('E', 'C', 'S', 'D')
#define IASECC_SDO_MAGIC_UPDATE		_MAKE_IASECC_SDO_MAGIC('E', 'C', 'U', 'D')
#define IASECC_SDO_MAGIC_UPDATE_RSA	_MAKE_IASECC_SDO_MAGIC('E', 'C', 'U', 'R')

#define IASECC_MAX_SCBS		7
//#define IASECC_MAX_CRTS_IN_SE	24

struct iasecc_extended_tlv {
	unsigned tag;
	unsigned parent_tag;

	unsigned char *value;
	size_t size;

	unsigned on_card;
};

struct iasecc_sdo_docp  {
	struct iasecc_extended_tlv name;
	struct iasecc_extended_tlv tries_maximum;
	struct iasecc_extended_tlv tries_remaining;
	struct iasecc_extended_tlv usage_maximum;
	struct iasecc_extended_tlv usage_remaining;
	struct iasecc_extended_tlv non_repudiation;
	struct iasecc_extended_tlv size;
	struct iasecc_extended_tlv acls_contact;
	struct iasecc_extended_tlv acls_contactless;
	struct iasecc_extended_tlv issuer_data;

	unsigned char amb, scbs[IASECC_MAX_SCBS];
};

struct iasecc_sdo_chv {
	struct iasecc_extended_tlv size_max;
	struct iasecc_extended_tlv size_min;
	struct iasecc_extended_tlv value;
};

struct iasecc_sdo_prvkey  {
	struct iasecc_extended_tlv p;
	struct iasecc_extended_tlv q;
	struct iasecc_extended_tlv iqmp;
	struct iasecc_extended_tlv dmp1;
	struct iasecc_extended_tlv dmq1;
	struct iasecc_extended_tlv compulsory;
};

struct iasecc_sdo_pubkey  {
	struct iasecc_extended_tlv n;
	struct iasecc_extended_tlv e;
	struct iasecc_extended_tlv compulsory;
	struct iasecc_extended_tlv chr;
	struct iasecc_extended_tlv cha;
};

struct iasecc_sdo_keyset  {
	struct iasecc_extended_tlv mac;
	struct iasecc_extended_tlv enc;
	struct iasecc_extended_tlv compulsory;
};

struct iasecc_sdo  {
	unsigned char sdo_class;
	unsigned char sdo_ref;

	unsigned int usage;

	struct iasecc_sdo_docp docp;

	union {
		struct iasecc_sdo_chv chv;
		struct iasecc_sdo_prvkey prv_key;
		struct iasecc_sdo_pubkey pub_key;
		struct iasecc_sdo_keyset keyset;
	} data;

	unsigned not_on_card;
	unsigned magic;
};

struct iasecc_sdo_update  {
	unsigned char sdo_class;
	unsigned char sdo_ref;

	struct iasecc_extended_tlv fields[IASECC_SDO_TAGS_UPDATE_MAX];

	unsigned magic;
};

struct iasecc_sdo_rsa_update  {
	struct iasecc_sdo *sdo_prv_key;
	struct iasecc_sdo *sdo_pub_key;
	struct sc_pkcs15_prkey_rsa *p15_rsa;

	struct iasecc_sdo_update update_prv;
	struct iasecc_sdo_update update_pub;

	unsigned magic;
};

struct iasecc_se_info {
	struct iasecc_sdo_docp docp;
	int reference;

	struct sc_crt crts[SC_MAX_CRTS_IN_SE];

	struct sc_file *df;
	struct iasecc_se_info *next;

	unsigned magic;
};

struct iasecc_sm_card_answer  {
	unsigned char data[SC_MAX_APDU_BUFFER_SIZE];
	size_t data_len;

	unsigned sw;

	unsigned char mac[8];
	unsigned char ticket[14];
};

struct iasecc_ctl_get_free_reference {
	size_t key_size;
	unsigned usage;
	unsigned access;
	int index;
};

enum IASECC_KEY_TYPE {
	IASECC_SDO_CLASS_RSA_PRV = 0x10,
	IASECC_SDO_CLASS_RSA_PUB = 0x20
};

struct iasecc_sm_cmd_update_binary {
	const unsigned char *data;
	size_t offs, count;
};

struct iasecc_sm_cmd_create_file {
	const unsigned char *data;
	size_t size;
};

struct sc_card;
int iasecc_sdo_convert_acl(struct sc_card *, struct iasecc_sdo *, unsigned char, unsigned *, unsigned *);
void iasecc_sdo_free_fields(struct sc_card *, struct iasecc_sdo *);
void iasecc_sdo_free(struct sc_card *, struct iasecc_sdo *);
int iasecc_se_parse(struct sc_card *, unsigned char *, size_t, struct iasecc_se_info *);
int iasecc_sdo_parse(struct sc_card *, unsigned char *, size_t, struct iasecc_sdo *);
int iasecc_sdo_allocate_and_parse(struct sc_card *, unsigned char *, size_t, struct iasecc_sdo **);
int iasecc_encode_size(size_t, unsigned char *);
int iasecc_sdo_encode_create(struct sc_context*, struct iasecc_sdo *, unsigned char **);
int iasecc_sdo_encode_update_field(struct sc_context *, unsigned char, unsigned char,
		struct iasecc_extended_tlv *, unsigned char **);
int iasecc_se_get_crt(struct sc_card *, struct iasecc_se_info *, struct sc_crt *);
int iasecc_se_get_crt_by_usage(struct sc_card *, struct iasecc_se_info *,
		unsigned char, unsigned char, struct sc_crt *);
int iasecc_sdo_encode_rsa_update(struct sc_context *, struct iasecc_sdo *, struct sc_pkcs15_prkey_rsa *, struct iasecc_sdo_update *);
int iasecc_sdo_parse_card_answer(struct sc_context *, unsigned char *, size_t, struct iasecc_sm_card_answer *);
int iasecc_docp_copy(struct sc_context *, struct iasecc_sdo_docp *, struct iasecc_sdo_docp *);
int iasecc_se_get_info(struct sc_card *card, struct iasecc_se_info *se);

int iasecc_sm_external_authentication(struct sc_card *card, unsigned skey_ref, int *tries_left);
int iasecc_sm_pin_verify(struct sc_card *card, unsigned se_num, struct sc_pin_cmd_data *data, int *tries_left);
int iasecc_sm_pin_reset(struct sc_card *card, unsigned se_num, struct sc_pin_cmd_data *data);
int iasecc_sm_update_binary(struct sc_card *card, unsigned se_num, size_t offs, const unsigned char *buff, size_t count);
int iasecc_sm_read_binary(struct sc_card *card, unsigned se_num, size_t offs, unsigned char *buff, size_t count);
int iasecc_sm_create_file(struct sc_card *card, unsigned se_num, unsigned char *fcp, size_t fcp_len);
int iasecc_sm_delete_file(struct sc_card *card, unsigned se_num, unsigned int file_id);
int iasecc_sm_rsa_generate(struct sc_card *card, unsigned se_num, struct iasecc_sdo *sdo);
int iasecc_sm_rsa_update(struct sc_card *card, unsigned se_num, struct iasecc_sdo_rsa_update *udata);
int iasecc_sm_sdo_update(struct sc_card *card, unsigned se_num, struct iasecc_sdo_update *update);
#endif
