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

#ifndef _OPENSC_PKCS15_H
#define _OPENSC_PKCS15_H

#include "opensc.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define SC_PKCS15_CACHE_DIR		".eid"

#define SC_PKCS15_PIN_MAGIC		0x31415926
#define SC_PKCS15_MAX_PINS		2
#define SC_PKCS15_MAX_PRKEYS		2
#define SC_PKCS15_MAX_PUBKEYS		2
#define SC_PKCS15_MAX_LABEL_SIZE	32
#define SC_PKCS15_MAX_ID_SIZE		16
#define SC_PKCS15_MAX_DFS		4
#define SC_PKCS15_MAX_CERTS		4	/* Total certificates */

struct sc_pkcs15_id {
	u8 value[SC_PKCS15_MAX_ID_SIZE];
	size_t len;
};

#define SC_PKCS15_CO_FLAG_PRIVATE	0x00000001
#define SC_PKCS15_CO_FLAG_MODIFIABLE	0x00000002
#define SC_PKCS15_CO_FLAG_OBJECT_SEEN	0x80000000 /* for PKCS #11 module */

#define SC_PKCS15_PIN_FLAG_CASE_SENSITIVE		0x0001
#define SC_PKCS15_PIN_FLAG_LOCAL			0x0002
#define SC_PKCS15_PIN_FLAG_CHANGE_DISABLED		0x0004
#define SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED		0x0008
#define SC_PKCS15_PIN_FLAG_INITIALIZED			0x0010
#define SC_PKCS15_PIN_FLAG_NEEDS_PADDING		0x0020
#define SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN		0x0040
#define SC_PKCS15_PIN_FLAG_SO_PIN			0x0080
#define SC_PKCS15_PIN_FLAG_DISABLE_ALLOW		0x0100
#define SC_PKCS15_PIN_FLAG_INTEGRITY_PROTECTED		0x0200
#define SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED	0x0400
#define SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA		0x0800

#define SC_PKCS15_PIN_TYPE_BCD				0
#define SC_PKCS15_PIN_TYPE_ASCII_NUMERIC		1
#define SC_PKCS15_PIN_TYPE_UTF8				2

struct sc_pkcs15_pin_info {
	struct sc_pkcs15_id auth_id;
	int reference;
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

struct sc_pkcs15_pubkey_rsa {
	u8 *modulus;
	int modulus_len;
	unsigned int exponent;

	u8 *data;	/* DER encoded raw key */
	int data_len;
};

struct sc_pkcs15_cert {
	int version;
	u8 *serial;
	size_t serial_len;
	u8 *issuer;
	size_t issuer_len;

	struct sc_pkcs15_pubkey_rsa key;
	u8 *data;	/* DER encoded raw cert */
	size_t data_len;
};

struct sc_pkcs15_cert_info {
	struct sc_pkcs15_id id;	/* correlates to private key id */
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
	struct sc_pkcs15_id id;	/* correlates to public certificate id */
	unsigned int usage, access_flags;
	int native, key_reference;
	int modulus_length;

	struct sc_path path;
};

struct sc_pkcs15_pubkey_info {
	struct sc_pkcs15_id id;	/* correlates to private key id */
	unsigned int usage, access_flags;
	int native, key_reference;
	int modulus_length;

	struct sc_path path;
};

#define SC_PKCS15_TYPE_CLASS_MASK		0xF00

#define SC_PKCS15_TYPE_PRKEY			0x100
#define SC_PKCS15_TYPE_PRKEY_RSA		0x101
#define SC_PKCS15_TYPE_PRKEY_DSA		0x102

#define SC_PKCS15_TYPE_PUBKEY			0x200
#define SC_PKCS15_TYPE_PUBKEY_RSA		0x201
#define SC_PKCS15_TYPE_PUBKEY_DSA		0x202

#define SC_PKCS15_TYPE_CERT			0x400
#define SC_PKCS15_TYPE_CERT_X509		0x401
#define SC_PKCS15_TYPE_CERT_SPKI		0x402

#define SC_PKCS15_TYPE_DATA_OBJECT		0x500
#define SC_PKCS15_TYPE_AUTH			0x600
#define SC_PKCS15_TYPE_AUTH_PIN			0x601

struct sc_pkcs15_object {
	int type;
	/* CommonObjectAttributes */
	char label[SC_PKCS15_MAX_LABEL_SIZE];	/* zero terminated */
	int flags;
	struct sc_pkcs15_id auth_id;

	int user_consent;

	/* Object type specific data */
	void *data;

	struct sc_pkcs15_object *next; /* used only internally */
};

#define SC_PKCS15_PRKDF			0
#define SC_PKCS15_PUKDF			1
#define SC_PKCS15_PUKDF_TRUSTED		2
#define SC_PKCS15_SKDF			3
#define SC_PKCS15_CDF			4
#define SC_PKCS15_CDF_TRUSTED		5
#define SC_PKCS15_CDF_USEFUL		6
#define SC_PKCS15_DODF			7
#define SC_PKCS15_AODF			8
#define SC_PKCS15_DF_TYPE_COUNT		9

#define SC_PKCS15_MAX_DFS		4

struct sc_pkcs15_df {
	struct sc_file *file[SC_PKCS15_MAX_DFS];
	struct sc_pkcs15_object *obj[SC_PKCS15_MAX_DFS];
	int count, record_length, type;
	int enumerated;
};

#define SC_PKCS15_CARD_MAGIC		0x10203040

struct sc_pkcs15_card {
	struct sc_card *card;
	char *label;
	/* fields from TokenInfo: */
	int version;
	char *serial_number, *manufacturer_id;
	unsigned long flags;
	struct sc_pkcs15_algorithm_info alg_info[1];

	struct sc_file *file_app;
	struct sc_file *file_tokeninfo, *file_odf;
	struct sc_pkcs15_df df[SC_PKCS15_DF_TYPE_COUNT];

	int use_cache;
	
	unsigned int magic;
};

#define SC_PKCS15_CARD_FLAG_READONLY		0x01
#define SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED	0x02
#define SC_PKCS15_CARD_FLAG_PRN_GENERATION	0x04
#define SC_PKCS15_CARD_FLAG_EID_COMPLIANT	0x08

/* sc_pkcs15_bind:  Binds a card object to a PKCS #15 card object
 * and initializes a new PKCS #15 card object.  Will return
 * SC_ERROR_PKCS15_APP_NOT_FOUND, if the card hasn't got a
 * valid PKCS #15 file structure. */
int sc_pkcs15_bind(struct sc_card *card,
		   struct sc_pkcs15_card **pkcs15_card);
/* sc_pkcs_unbind:  Releases a PKCS #15 card object, and frees any
 * memory allocations done on the card object. */
int sc_pkcs15_unbind(struct sc_pkcs15_card *card);

int sc_pkcs15_get_objects(struct sc_pkcs15_card *card, int type,
			  struct sc_pkcs15_object **ret, int ret_count);
int sc_pkcs15_get_objects_cond(struct sc_pkcs15_card *card, int type,
			       int (* func)(struct sc_pkcs15_object *, void *),
			       void *func_arg,
			       struct sc_pkcs15_object **ret, int ret_count);

struct sc_pkcs15_card * sc_pkcs15_card_new();
void sc_pkcs15_card_free(struct sc_pkcs15_card *p15card);

int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_object *prkey_obj,
		       const u8 *in, size_t inlen, u8 *out, size_t outlen);

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_object *prkey_obj,
				unsigned long alg_flags, const u8 *in,
				size_t inlen, u8 *out, size_t outlen);

void sc_pkcs15_print_card(const struct sc_pkcs15_card *card);

int sc_pkcs15_read_pubkey(struct sc_pkcs15_card *card,
			  const struct sc_pkcs15_pubkey_info *info,
			  struct sc_pkcs15_pubkey_rsa **out);
int sc_pkcs15_parse_pubkey_rsa(struct sc_context *ctx,
	       		   struct sc_pkcs15_pubkey_rsa *pubkey);
void sc_pkcs15_free_pubkey(struct sc_pkcs15_pubkey_rsa *pubkey);

void sc_pkcs15_print_cert_info(const struct sc_pkcs15_cert_info *cert);
int sc_pkcs15_read_certificate(struct sc_pkcs15_card *card,
			       const struct sc_pkcs15_cert_info *info,
			       struct sc_pkcs15_cert **cert);
void sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert);
int sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *card,
			      const struct sc_pkcs15_id *id,
			      struct sc_pkcs15_object **out);
/* sc_pkcs15_create_cdf:  Creates a new certificate DF on a card pointed
 * by <card>.  Information about the file, such as the file ID, is read
 * from <file>.  <certs> has to be NULL-terminated. */
int sc_pkcs15_create_cdf(struct sc_pkcs15_card *card,
			 struct sc_file *file,
			 const struct sc_pkcs15_cert_info **certs);
int sc_pkcs15_create(struct sc_pkcs15_card *p15card, struct sc_card *card);

void sc_pkcs15_print_prkey_info(const struct sc_pkcs15_prkey_info *prkey);
int sc_pkcs15_find_prkey_by_id(struct sc_pkcs15_card *card,
			       const struct sc_pkcs15_id *id,
			       struct sc_pkcs15_object **out);

void sc_pkcs15_print_pin_info(const struct sc_pkcs15_pin_info *auth);
int sc_pkcs15_verify_pin(struct sc_pkcs15_card *card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *pincode, size_t pinlen);
int sc_pkcs15_change_pin(struct sc_pkcs15_card *card,
			 struct sc_pkcs15_pin_info *pin,
			 const u8 *oldpincode, size_t oldpinlen,
			 const u8 *newpincode, size_t newpinlen);
int sc_pkcs15_find_pin_by_auth_id(struct sc_pkcs15_card *card,
				  const struct sc_pkcs15_id *id,
				  struct sc_pkcs15_object **out);

int sc_pkcs15_encode_dir(struct sc_context *ctx,
			struct sc_pkcs15_card *card,
			u8 **buf, size_t *buflen);
int sc_pkcs15_encode_tokeninfo(struct sc_context *ctx,
			struct sc_pkcs15_card *card,
			u8 **buf, size_t *buflen);
int sc_pkcs15_encode_odf(struct sc_context *ctx,
			struct sc_pkcs15_card *card,
			u8 **buf, size_t *buflen);
int sc_pkcs15_encode_df(struct sc_context *ctx,
			struct sc_pkcs15_df *df, int file_nr,
			u8 **buf, size_t *bufsize);
int sc_pkcs15_encode_cdf_entry(struct sc_context *ctx,
			const struct sc_pkcs15_object *obj, u8 **buf,
			size_t *bufsize);
int sc_pkcs15_encode_prkdf_entry(struct sc_context *ctx,
			const struct sc_pkcs15_object *obj, u8 **buf,
			size_t *bufsize);
int sc_pkcs15_encode_pukdf_entry(struct sc_context *ctx,
			const struct sc_pkcs15_object *obj, u8 **buf,
			size_t *bufsize);
int sc_pkcs15_encode_aodf_entry(struct sc_context *ctx,
			const struct sc_pkcs15_object *obj, u8 **buf,
			size_t *bufsize);

int sc_pkcs15_parse_df(struct sc_pkcs15_card *p15card,
		       struct sc_pkcs15_df *df, int file_nr);
int sc_pkcs15_read_df(struct sc_pkcs15_card *p15card,
		      struct sc_pkcs15_df *df, int file_nr);
int sc_pkcs15_decode_cdf_entry(struct sc_pkcs15_card *p15card,
			       struct sc_pkcs15_object *obj,
			       const u8 **buf, size_t *bufsize);
int sc_pkcs15_decode_aodf_entry(struct sc_pkcs15_card *p15card,
			        struct sc_pkcs15_object *obj,
			        const u8 **buf, size_t *bufsize);
int sc_pkcs15_decode_prkdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 **buf, size_t *bufsize);
int sc_pkcs15_decode_pukdf_entry(struct sc_pkcs15_card *p15card,
				 struct sc_pkcs15_object *obj,
				 const u8 **buf, size_t *bufsize);

int sc_pkcs15_compare_id(const struct sc_pkcs15_id *id1,
			 const struct sc_pkcs15_id *id2);
void sc_pkcs15_print_id(const struct sc_pkcs15_id *id);
void sc_pkcs15_format_id(const char *id_in, struct sc_pkcs15_id *id_out);
int sc_pkcs15_add_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df,
                         int file_nr, struct sc_pkcs15_object *obj);
                         
int sc_pkcs15_hex_string_to_id(const char *in, struct sc_pkcs15_id *out);

/* Caching functions */
int sc_pkcs15_read_cached_file(struct sc_pkcs15_card *p15card,
                               const struct sc_path *path,
                               u8 **buf, size_t *bufsize);
int sc_pkcs15_cache_file(struct sc_pkcs15_card *p15card,
			 const struct sc_path *path,
			 const u8 *buf, size_t bufsize);
#ifdef  __cplusplus
}
#endif

#endif
