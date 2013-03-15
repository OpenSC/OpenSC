#ifndef pkcs15_oberthur_h
#define  pkcs15_oberthur_h

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef ENABLE_OPENSSL
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#define COSM_TLV_TAG		0x00

#define TLV_TYPE_V	0
#define TLV_TYPE_LV	1
#define TLV_TYPE_LLV	2

/* Should be greater then SC_PKCS15_TYPE_CLASS_MASK */
#define SC_DEVICE_SPECIFIC_TYPE	 0x1000

#define COSM_PUBLIC_LIST	(SC_DEVICE_SPECIFIC_TYPE | 0x02)
#define COSM_PRIVATE_LIST	(SC_DEVICE_SPECIFIC_TYPE | 0x03)
#define COSM_CONTAINER_LIST	(SC_DEVICE_SPECIFIC_TYPE | 0x04)
#define COSM_TOKENINFO		(SC_DEVICE_SPECIFIC_TYPE | 0x05)
#define COSM_TYPE_PRKEY_RSA	(SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PRKEY_RSA)
#define COSM_TYPE_PUBKEY_RSA	(SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PUBKEY_RSA)
#define COSM_TYPE_PRIVDATA_OBJECT	(SC_DEVICE_SPECIFIC_TYPE | 0x06)

#define COSM_TITLE "OberthurAWP"

#define COSM_LIST_TAG		0xFF

#define COSM_TAG_CONTAINER	0x0000
#define COSM_TAG_CERT		0x0001
#define COSM_TAG_PRVKEY_RSA	0x04B1
#define COSM_TAG_PUBKEY_RSA	0x0349
#define COSM_TAG_DES		0x0679
#define COSM_TAG_DATA		0x0001
#define COSM_IMPORTED		0x0000
#define COSM_GENERATED		0x0004

#define NAME_MAX_LEN    64

#define PUBKEY_512_ASN1_SIZE    0x4A
#define PUBKEY_1024_ASN1_SIZE	0x8C
#define PUBKEY_2048_ASN1_SIZE   0x10E

#define AWP_CONTAINER_RECORD_LEN 12

struct awp_crypto_container {
	int type;
	unsigned cert_id;
	unsigned prkey_id;
	unsigned pubkey_id;
};

struct awp_lv {
	unsigned len;
	unsigned char *value;
};

struct awp_key_info {
	unsigned flags;
	unsigned usage;
	struct awp_lv label;
	struct awp_lv id;
	struct awp_lv subject;
	struct awp_lv exponent, modulus;
};

struct awp_cert_info {
	unsigned flags;
	struct awp_lv label;
	struct awp_lv cn, subject, issuer;
	struct awp_lv id;
	struct awp_lv serial;
	X509 *x509;
};

struct awp_data_info {
	unsigned flags;
	struct awp_lv label, app, oid;
};

extern int cosm_delete_file(struct sc_pkcs15_card *, struct sc_profile *, struct sc_file *);
extern int awp_update_df_create(struct sc_pkcs15_card *, struct sc_profile *, struct sc_pkcs15_object *);
extern int awp_update_df_delete(struct sc_pkcs15_card *, struct sc_profile *, struct sc_pkcs15_object *);

#endif /* #ifdef ENABLE_OPENSSL */
#endif /* #ifndef pkcs15_oberthur_h*/
