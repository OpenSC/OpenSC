/*
 * opensc-pkcs15.h: OpenSC PKCS#15 header file
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#ifndef _SC_PKCS15_H
#define _SC_PKCS15_H

#include "opensc.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define SC_PKCS15_CACHE_DIR		".eid"

#define SC_PKCS15_PIN_MAGIC		0x31415926
#define SC_PKCS15_MAX_PINS		2
#define SC_PKCS15_MAX_CERTS		3
#define SC_PKCS15_MAX_PRKEYS		2
#define SC_PKCS15_MAX_LABEL_SIZE	32
#define SC_PKCS15_MAX_ID_SIZE		16

struct sc_pkcs15_id {
	u8 value[SC_PKCS15_MAX_ID_SIZE];
	int len;
};

struct sc_pkcs15_common_obj_attr {
	char label[SC_PKCS15_MAX_LABEL_SIZE];	/* zero terminated */
	int flags;
	struct sc_pkcs15_id auth_id;

	int user_consent;
	/* FIXME: add accessControlRules */
};

struct sc_pkcs15_pin_info {
	struct sc_pkcs15_common_obj_attr com_attr;

	struct sc_pkcs15_id auth_id;
	int flags, type;
	int min_length, stored_length;
	u8 pad_char;
	struct sc_path path;
	int tries_left;

	unsigned int magic;
};

#define SC_PKCS15_ALGO_OP_COMPUTE_CHECKSUM	0x01
#define SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE	0x02
#define SC_PKCS15_ALGO_OP_VERIFY_CHECKSUM	0x04
#define SC_PKCS15_ALGO_OP_VERIFY_SIGNATURE	0x08
#define SC_PKCS15_ALGO_OP_ENCIPHER		0x10
#define SC_PKCS15_ALGO_OP_DECIPHER		0x20
#define SC_PKCS15_ALGO_OP_HASH			0x40
#define SC_PKCS15_ALGO_OP_GENERATE_KEY		0x80

struct sc_pkcs15_algorithm_info {
	int reference;
	int algorithm, supported_operations;
};

struct sc_pkcs15_rsa_pubkey {
	u8 *modulus;
	int modulus_len;
	unsigned int exponent;
	
	u8 *data;	/* DER encoded raw key */
	int data_len;
};

struct sc_pkcs15_cert {
	int version;
	unsigned long long serial;
	
	struct sc_pkcs15_rsa_pubkey key;
	u8 *data;	/* DER encoded raw cert */
	int data_len;
};

struct sc_pkcs15_cert_info {
	struct sc_pkcs15_common_obj_attr com_attr;

	struct sc_pkcs15_id id;	/* correlates to private RSA key id */
	int authority;		/* boolean */
	/* identifiers [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} */
	struct sc_path path;
};

#define SC_PKCS15_PRKEY_USAGE_ENCRYPT		0x01
#define SC_PKCS15_PRKEY_USAGE_DECRYPT		0x02
#define SC_PKCS15_PRKEY_USAGE_SIGN		0x04
#define SC_PKCS15_PRKEY_USAGE_SIGNRECOVER	0x08
#define SC_PKCS15_PRKEY_USAGE_WRAP		0x10
#define SC_PKCS15_PRKEY_USAGE_UNWRAP		0x20
#define SC_PKCS15_PRKEY_USAGE_VERIFY		0x40
#define SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER	0x80
#define SC_PKCS15_PRKEY_USAGE_DERIVE		0x100
#define SC_PKCS15_PRKEY_USAGE_NONREPUDIATION	0x200

#define SC_PKCS15_PRKEY_ACCESS_SENSITIVE	0x01
#define SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE	0x02
#define SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE	0x04
#define SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE	0x08
#define SC_PKCS15_PRKEY_ACCESS_LOCAL		0x10

struct sc_pkcs15_prkey_info {
	struct sc_pkcs15_common_obj_attr com_attr;

	struct sc_pkcs15_id id;	/* correlates to public certificate id */
	int usage, access_flags;
	int key_reference;

	struct sc_path file_id;
	int modulus_length;
};

struct sc_pkcs15_card {
	struct sc_card *card;
	char *label;
	/* fields from TokenInfo: */
	int version;
	char *serial_number, *manufacturer_id;
	int flags;
	struct sc_pkcs15_algorithm_info alg_info[1];
	struct sc_pkcs15_cert_info cert_info[SC_PKCS15_MAX_CERTS];
	int cert_count;
	struct sc_pkcs15_prkey_info prkey_info[SC_PKCS15_MAX_PRKEYS];
	int prkey_count;
	struct sc_pkcs15_pin_info pin_info[SC_PKCS15_MAX_PINS];
	int pin_count;

	struct sc_file file_dir, file_ao1, file_app;
	/* in app DF */
	struct sc_file file_tokeninfo, file_odf;
	struct sc_file file_prkdf;
	struct sc_file file_aodf, file_ao2;
	struct sc_file file_cdf1, file_cdf2, file_cdf3;
	struct sc_file file_dodf;
};

#define SC_PKCS15_CARD_FLAG_READONLY		0x01
#define SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED	0x02
#define SC_PKCS15_CARD_FLAG_PRN_GENERATION	0x04
#define SC_PKCS15_CARD_FLAG_EID_COMPLIANT	0x08

struct sc_pkcs15_defaults {
	const char *ef_dir_dump;
	int (*defaults_func)(struct sc_pkcs15_card *, int arg);
	int arg;
};

int sc_pkcs15_init(struct sc_card *card,
		   struct sc_pkcs15_card **pkcs15_card);
int sc_pkcs15_destroy(struct sc_pkcs15_card *card);

int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_prkey_info *prkey,
		       const u8 *in, int inlen, u8 *out, int outlen);

#define SC_PKCS15_HASH_NONE	0
#define SC_PKCS15_HASH_SHA1	1

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_prkey_info *prkey,
				int hash, const u8 *in, int inlen, u8 *out,
				int outlen);

void sc_pkcs15_print_card(const struct sc_pkcs15_card *card);

void sc_pkcs15_print_cert_info(const struct sc_pkcs15_cert_info *cert);
int sc_pkcs15_enum_certificates(struct sc_pkcs15_card *card);
int sc_pkcs15_read_certificate(struct sc_pkcs15_card *card,
			       const struct sc_pkcs15_cert_info *info,
			       struct sc_pkcs15_cert **cert);
void sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert);
int sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *card,
			      const struct sc_pkcs15_id *id,
			      struct sc_pkcs15_cert_info **out);

void sc_pkcs15_print_prkey_info(const struct sc_pkcs15_prkey_info *prkey);
int sc_pkcs15_enum_private_keys(struct sc_pkcs15_card *card);
int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *card,
			       const struct sc_pkcs15_id *id,
			       struct sc_pkcs15_prkey_info **out);

void sc_pkcs15_print_pin_info(const struct sc_pkcs15_pin_info *pin);
int sc_pkcs15_enum_pins(struct sc_pkcs15_card *card);
int sc_pkcs15_verify_pin(struct sc_pkcs15_card *card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *pincode, int pinlen);
int sc_pkcs15_change_pin(struct sc_pkcs15_card *card,
			 struct sc_pkcs15_pin_info *pin,
			 char *oldpincode,
			 int oldpinlen, char *newpincode, int newpinlen);
int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *card,
				  const struct sc_pkcs15_id *id,
				  struct sc_pkcs15_pin_info **out);

int sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1,
			 const struct sc_pkcs15_id *id2);
void sc_pkcs15_print_id(const struct sc_pkcs15_id *id);
int sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out);

int sc_pkcs15_parse_common_object_attr(struct sc_pkcs15_common_obj_attr *attr,
				       const u8 * buf, int buflen);

extern const struct sc_pkcs15_defaults sc_pkcs15_card_table[];

#ifdef  __cplusplus
}
#endif

#endif
