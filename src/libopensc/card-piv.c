/*
 * card-piv.c: Support for PIV-II from NIST SP800-73
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005,2006,2007,2008,2009,2010 Douglas E. Engert <deengert@anl.gov>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#ifdef ENABLE_OPENSSL
	/* openssl only needed for card administration */
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#endif /* ENABLE_OPENSSL */

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif

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
 * These objects will only be present if the history object says
 * they are on the card, or the discovery or history object in not present.
 * If the file lilsted in the history object offCardCertURL was found,
 * its certs will be read into the cache and PIV_OBJ_CACHE_VALID set
 * and PIV_OBJ_CACHE_NOT_PRESENT unset.
 */

#define PIV_OBJ_CACHE_VALID			1
#define PIV_OBJ_CACHE_NOT_PRESENT	8

typedef struct piv_obj_cache {
	u8* obj_data;
	size_t obj_len;
	u8* internal_obj_data; /* like a cert in the object */
	size_t internal_obj_len;
	int flags;
} piv_obj_cache_t;

typedef struct piv_private_data {
	sc_file_t *aid_file;
	int enumtag;
	int  selected_obj; /* The index into the piv_objects last selected */
	int  return_only_cert; /* return the cert from the object */
	int  rwb_state; /* first time -1, 0, in middle, 1 at eof */
	int operation; /* saved from set_security_env */
	int algorithm; /* saved from set_security_env */
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
} piv_private_data_t;

#define PIV_DATA(card) ((piv_private_data_t*)card->drv_data)

struct piv_aid {
	int enumtag;
	size_t len_short;	/* min lenght without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};

/*
 * The Generic entry should be the "A0 00 00 03 08 00 00 01 00 "
 * NIST published  this on 10/6/2005
 * 800-73-2 Part 1 now refers to version "02 00"
 * i.e. "A0 00 00 03 08 00 00 01 00 02 00".
 * but we don't need the version number. but could get it from the PIX.
 *
 * 800-73-3 Part 1 now referes to "01 00" i.e. going back to 800-73-1.
 * The main differences between 73-1, and 73-3 are the addition of the
 * key History object and keys, as well as Discovery and Iris objects.
 */

static struct piv_aid piv_aids[] = {
	{SC_CARD_TYPE_PIV_II_GENERIC,
		 9, 9, (u8 *) "\xA0\x00\x00\x03\x08\x00\x00\x10\x00" },
	{0,  9, 0, NULL }
};

/* The EC curves supported by PIV */
#if 0
static u8 oid_prime256v1[] = {"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"};
static u8 oid_secp384r1[] = {"\x06\x05\x2b\x81\x04\x00\x22"};
#endif

/*
 * Flags in the piv_object:
 * PIV_OBJECT_NOT_PRESENT: the presents of the object is
 * indicated by the History object.
 */

#define PIV_OBJECT_TYPE_CERT		1
#define PIV_OBJECT_TYPE_PUBKEY		2
#define PIV_OBJECT_NOT_PRESENT		4

struct piv_object {
	int enumtag;
	const char * name;
	const char * oidstring;
	size_t tag_len;
	u8  tag_value[3];
	u8  containerid[2];	/* will use as relative paths for simulation */
	int flags;              /* object has some internal object like a cert */
};

/* Must be in order, and one per enumerated PIV_OBJ */
static const struct piv_object piv_objects[] = {
	{ PIV_OBJ_CCC, "Card Capability Container",
			"2.16.840.1.101.3.7.1.219.0", 3, "\x5F\xC1\x07", "\xDB\x00", 0},
	{ PIV_OBJ_CHUI, "Card Holder Unique Identifier",
			"2.16.840.1.101.3.7.2.48.0", 3, "\x5F\xC1\x02", "\x30\x00", 0},
	{ PIV_OBJ_X509_PIV_AUTH, "X.509 Certificate for PIV Authentication",
			"2.16.840.1.101.3.7.2.1.1", 3, "\x5F\xC1\x05", "\x01\x01", PIV_OBJECT_TYPE_CERT} ,
	{ PIV_OBJ_CHF, "Card Holder Fingerprints",
			"2.16.840.1.101.3.7.2.96.16", 3, "\x5F\xC1\x03", "\x60\x10", 0},
	{ PIV_OBJ_PI, "Printed Information",
			"2.16.840.1.101.3.7.2.48.1", 3, "\x5F\xC1\x09", "\x30\x01", 0},
	{ PIV_OBJ_CHFI, "Cardholder Facial Images",
			"2.16.840.1.101.3.7.2.96.48", 3, "\x5F\xC1\x08", "\x60\x30", 0},
	{ PIV_OBJ_X509_DS, "X.509 Certificate for Digital Signature",
			"2.16.840.1.101.3.7.2.1.0", 3, "\x5F\xC1\x0A", "\x01\x00", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_X509_KM, "X.509 Certificate for Key Management",
			"2.16.840.1.101.3.7.2.1.2", 3, "\x5F\xC1\x0B", "\x01\x02", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_X509_CARD_AUTH, "X.509 Certificate for Card Authentication",
			"2.16.840.1.101.3.7.2.5.0", 3, "\x5F\xC1\x01", "\x05\x00", PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_SEC_OBJ, "Security Object",
			"2.16.840.1.101.3.7.2.144.0", 3, "\x5F\xC1\x06", "\x90\x00", 0},
	{ PIV_OBJ_DISCOVERY, "Discovery Object",
			"2.16.840.1.101.3.7.2.96.80", 1, "\x7E", "\x60\x50", 0},
	{ PIV_OBJ_HISTORY, "Key History Object",
			"2.16.840.1.101.3.7.2.96.96", 3, "\x5F\xC1\x0C", "\x60\x60", 0},

/* 800-73-3, 21 new objects, 20 history certificates */
	{ PIV_OBJ_RETIRED_X509_1, "Retired X.509 Certificate for Key Management 1",
			"2.16.840.1.101.3.7.2.16.1", 3, "\x5F\xC1\x0D", "\x10\x01",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_2, "Retired X.509 Certificate for Key Management 2",
			"2.16.840.1.101.3.7.2.16.2", 3, "\x5F\xC1\x0E", "\x10\x02",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_3, "Retired X.509 Certificate for Key Management 3",
			"2.16.840.1.101.3.7.2.16.3", 3, "\x5F\xC1\x0F", "\x10\x03",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_4, "Retired X.509 Certificate for Key Management 4",
			"2.16.840.1.101.3.7.2.16.4", 3, "\x5F\xC1\x10", "\x10\x04",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_5, "Retired X.509 Certificate for Key Management 5",
			"2.16.840.1.101.3.7.2.16.5", 3, "\x5F\xC1\x11", "\x10\x05",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_6, "Retired X.509 Certificate for Key Management 6",
			"2.16.840.1.101.3.7.2.16.6", 3, "\x5F\xC1\x12", "\x10\x06",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_7, "Retired X.509 Certificate for Key Management 7",
			"2.16.840.1.101.3.7.2.16.7", 3, "\x5F\xC1\x13", "\x10\x07",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_8, "Retired X.509 Certificate for Key Management 8",
			"2.16.840.1.101.3.7.2.16.8", 3, "\x5F\xC1\x14", "\x10\x08",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_9, "Retired X.509 Certificate for Key Management 9",
			"2.16.840.1.101.3.7.2.16.9", 3, "\x5F\xC1\x15", "\x10\x09",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_10, "Retired X.509 Certificate for Key Management 10",
			"2.16.840.1.101.3.7.2.16.10", 3, "\x5F\xC1\x16", "\x10\x0A",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_11, "Retired X.509 Certificate for Key Management 11",
			"2.16.840.1.101.3.7.2.16.11", 3, "\x5F\xC1\x17", "\x10\x0B",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_12, "Retired X.509 Certificate for Key Management 12",
			"2.16.840.1.101.3.7.2.16.12", 3, "\x5F\xC1\x18", "\x10\x0C",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_13, "Retired X.509 Certificate for Key Management 13",
			"2.16.840.1.101.3.7.2.16.13", 3, "\x5F\xC1\x19", "\x10\x0D",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_14, "Retired X.509 Certificate for Key Management 14",
			"2.16.840.1.101.3.7.2.16.14", 3, "\x5F\xC1\x1A", "\x10\x0E",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_15, "Retired X.509 Certificate for Key Management 15",
			"2.16.840.1.101.3.7.2.16.15", 3, "\x5F\xC1\x1B", "\x10\x0F",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_16, "Retired X.509 Certificate for Key Management 16",
			"2.16.840.1.101.3.7.2.16.16", 3, "\x5F\xC1\x1C", "\x10\x10",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_17, "Retired X.509 Certificate for Key Management 17",
			"2.16.840.1.101.3.7.2.16.17", 3, "\x5F\xC1\x1D", "\x10\x11",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_18, "Retired X.509 Certificate for Key Management 18",
			"2.16.840.1.101.3.7.2.16.18", 3, "\x5F\xC1\x1E", "\x10\x12",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_19, "Retired X.509 Certificate for Key Management 19",
			"2.16.840.1.101.3.7.2.16.19", 3, "\x5F\xC1\x1F", "\x10\x13",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},
	{ PIV_OBJ_RETIRED_X509_20, "Retired X.509 Certificate for Key Management 20",
			"2.16.840.1.101.3.7.2.16.20", 3, "\x5F\xC1\x20", "\x10\x14",
			PIV_OBJECT_NOT_PRESENT|PIV_OBJECT_TYPE_CERT},

	{ PIV_OBJ_IRIS_IMAGE, "Cardholder Iris Images",
			"2.16.840.1.101.3.7.2.16.21", 3, "\x5F\xC1\x21", "\x10\x15", 0},

/* following not standard , to be used by piv-tool only for testing */
	{ PIV_OBJ_9B03, "3DES-ECB ADM",
			"2.16.840.1.101.3.7.2.9999.3", 2, "\x9B\x03", "\x9B\x03", 0},
	/* Only used when signing a cert req, usually from engine
	 * after piv-tool generated the key and saved the pub key
	 * to a file. Note RSA key can be 1024, 2048 or 3072
	 * but still use the "9x06" name.
	 */
	{ PIV_OBJ_9A06, "RSA 9A Pub key from last genkey",
			"2.16.840.1.101.3.7.2.9999.20", 2, "\x9A\x06", "\x9A\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9C06, "Pub 9C key from last genkey",
			"2.16.840.1.101.3.7.2.9999.21", 2, "\x9C\x06", "\x9C\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9D06, "Pub 9D key from last genkey",
			"2.16.840.1.101.3.7.2.9999.22", 2, "\x9D\x06", "\x9D\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9E06, "Pub 9E key from last genkey",
			"2.16.840.1.101.3.7.2.9999.23", 2, "\x9E\x06", "\x9E\x06", PIV_OBJECT_TYPE_PUBKEY},

	{ PIV_OBJ_8206, "Pub 82 key ",
			"2.16.840.1.101.3.7.2.9999.101", 2, "\x82\x06", "\x82\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8306, "Pub 83 key ",
			"2.16.840.1.101.3.7.2.9999.102", 2, "\x83\x06", "\x83\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8406, "Pub 84 key ",
			"2.16.840.1.101.3.7.2.9999.103", 2, "\x84\x06", "\x84\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8506, "Pub 85 key ",
			"2.16.840.1.101.3.7.2.9999.104", 2, "\x85\x06", "\x85\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8606, "Pub 86 key ",
			"2.16.840.1.101.3.7.2.9999.105", 2, "\x86\x06", "\x86\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8706, "Pub 87 key ",
			"2.16.840.1.101.3.7.2.9999.106", 2, "\x87\x06", "\x87\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8806, "Pub 88 key ",
			"2.16.840.1.101.3.7.2.9999.107", 2, "\x88\x06", "\x88\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8906, "Pub 89 key ",
			"2.16.840.1.101.3.7.2.9999.108", 2, "\x89\x06", "\x89\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8A06, "Pub 8A key ",
			"2.16.840.1.101.3.7.2.9999.109", 2, "\x8A\x06", "\x8A\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8B06, "Pub 8B key ",
			"2.16.840.1.101.3.7.2.9999.110", 2, "\x8B\x06", "\x8B\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8C06, "Pub 8C key ",
			"2.16.840.1.101.3.7.2.9999.111", 2, "\x8C\x06", "\x8C\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8D06, "Pub 8D key ",
			"2.16.840.1.101.3.7.2.9999.112", 2, "\x8D\x06", "\x8D\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8E06, "Pub 8E key ",
			"2.16.840.1.101.3.7.2.9999.113", 2, "\x8E\x06", "\x8E\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_8F06, "Pub 8F key ",
			"2.16.840.1.101.3.7.2.9999.114", 2, "\x8F\x06", "\x8F\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9006, "Pub 90 key ",
			"2.16.840.1.101.3.7.2.9999.115", 2, "\x90\x06", "\x90\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9106, "Pub 91 key ",
			"2.16.840.1.101.3.7.2.9999.116", 2, "\x91\x06", "\x91\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9206, "Pub 92 key ",
			"2.16.840.1.101.3.7.2.9999.117", 2, "\x92\x06", "\x92\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9306, "Pub 93 key ",
			"2.16.840.1.101.3.7.2.9999.118", 2, "\x93\x06", "\x93\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9406, "Pub 94 key ",
			"2.16.840.1.101.3.7.2.9999.119", 2, "\x94\x06", "\x94\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_9506, "Pub 95 key ",
			"2.16.840.1.101.3.7.2.9999.120", 2, "\x95\x06", "\x95\x06", PIV_OBJECT_TYPE_PUBKEY},
	{ PIV_OBJ_LAST_ENUM, "", "", 0, "", "", 0}
};

static struct sc_card_operations piv_ops;

static struct sc_card_driver piv_drv = {
	"PIV-II  for multiple cards",
	"piv",
	&piv_ops,
	NULL, 0, NULL
};

static int piv_find_obj_by_containerid(sc_card_t *card, const u8 * str)
{
	int i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "str=0x%02X%02X\n", str[0], str[1]);

	for (i = 0; piv_objects[i].enumtag < PIV_OBJ_LAST_ENUM; i++) {
		if ( str[0] == piv_objects[i].containerid[0]
			&& str[1] == piv_objects[i].containerid[1])
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, i);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, -1);
}

/*
 * If ptr == NULL, just return the size of the tag and lenght and data
 * otherwise, store tag and length at **ptr, and increment
 */

static size_t put_tag_and_len(unsigned int tag, size_t len, u8 **ptr)
{
	int i;
	u8 *p;

	if (len < 128) {
		i = 2;
	} else if (len < 256) {
		i = 3;
	} else {
		i = 4;
	}

	if (ptr) {
		p = *ptr;
		*p++ = (u8)tag;
		switch (i) {
			case 2:
				*p++ = len;
				break;
			case 3:
				*p++ = 0x81;
				*p++ = len;
				break;
			case 4:
				*p++ = 0x82;
				*p++ = (u8) (len >> 8);
				*p++ = (u8) (len & 0xff);
				break;
		}
		*ptr = p;
	} else {
		i += len;
	}
	return i;
}

/*
 * Send a command and receive data. There is always something to send.
 * Used by  GET DATA, PUT DATA, GENERAL AUTHENTICATE
 * and GENERATE ASYMMETRIC KEY PAIR.
 * GET DATA may call to get the first 128 bytes to get the lenght from the tag.
 *
 * A caller may provide a buffer, and length to read. If not provided,
 * an internal 4096 byte buffer is used, and a copy is returned to the
 * caller. that need to be freed by the caller.
 */

static int piv_general_io(sc_card_t *card, int ins, int p1, int p2,
	const u8 * sendbuf, size_t sendbuflen, u8 ** recvbuf,
	size_t * recvbuflen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbufinitbuf[4096];
	u8 *rbuf;
	size_t rbuflen;
	unsigned int cla_out, tag_out;
	const u8 *body;
	size_t bodylen;


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "%02x %02x %02x %d : %d %d\n",
		 ins, p1, p2, sendbuflen , card->max_send_size, card->max_recv_size);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	/* if caller provided a buffer and length */
	if (recvbuf && *recvbuf && recvbuflen && *recvbuflen) {
		rbuf = *recvbuf;
		rbuflen = *recvbuflen;
	}

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);

	sc_format_apdu(card, &apdu,
			recvbuf ? SC_APDU_CASE_4_SHORT: SC_APDU_CASE_3_SHORT,
			ins, p1, p2);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf) {
		apdu.resp = rbuf;
		apdu.le = (rbuflen > 256) ? 256 : rbuflen;
		apdu.resplen = rbuflen;
	} else {
		 apdu.resp =  rbuf;
		 apdu.le = 0;
		 apdu.resplen = 0;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"calling sc_transmit_apdu flags=%x le=%d, resplen=%d, resp=%p",
		apdu.flags, apdu.le, apdu.resplen, apdu.resp);

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DEE r=%d apdu.resplen=%d sw1=%02x sw2=%02x",
			r, apdu.resplen, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Transmit failed");
		goto err;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

/* TODO: - DEE look later at tag vs size read too */
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Card returned error ");
		goto err;
	}

	/*
	 * See how much we read and make sure it is asn1
	 * if not, return 0 indicating no data found
	 */


	rbuflen = 0;  /* in case rseplen < 3  i.e. not parseable */
	if ( recvbuflen && recvbuf && apdu.resplen > 3) {
		*recvbuflen = 0;
		/* we should have all the tag data, so we have to tell sc_asn1_find_tag
		 * the buffer is bigger, so it will not produce "ASN1.tag too long!" */

		body = rbuf;
		if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS) 		{
			/* only early beta cards had this problem */
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "***** received buffer tag MISSING ");
			body = rbuf;
			/* some readers/cards might return 6c 00 */
			if (apdu.sw1 == 0x61  || apdu.sw2 == 0x6c )
				bodylen = 12000;
			else
				bodylen = apdu.resplen;
		}

		rbuflen = body - rbuf + bodylen;

		/* if using internal buffer, alloc new one */
		if (rbuf == rbufinitbuf) {
			*recvbuf = malloc(rbuflen);
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "DEE got buffer %p len %d",*recvbuf,  rbuflen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}

			memcpy(*recvbuf, rbuf, rbuflen); /* copy tag too */
		}
	}

	if (recvbuflen) {
		*recvbuflen =  rbuflen;
		r = *recvbuflen;
	}

err:
	sc_unlock(card);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/* Add the PIV-II operations */
/* Should use our own keydata, actually should be common to all cards */
/* RSA and EC are added. */

static int piv_generate_key(sc_card_t *card,
		sc_cardctl_piv_genkey_info_t *keydata)
{
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	u8 *p;
	const u8 *tag;
	u8 tagbuf[16];
	u8 outdata[3]; /* we could also add tag 81 for exponent */
	size_t taglen, i;
	size_t out_len;
	size_t in_len;
	unsigned int cla_out, tag_out;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	keydata->exponent = 0;
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
		/* TODO: - DEE For EC, also set the curve parameter as the OID */
		case 0x11: keydata->key_bits = 0;
			keydata->ecparam =0; /* we only support prime256v1 for 11 */
			keydata->ecparam_len =0;
			break;
		case 0x14: keydata->key_bits = 0;
			keydata->ecparam = 0; /* we only support secp384r1 */
			keydata->ecparam_len = 0;
			break;
		default:
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);
	}

	p = tagbuf;

	put_tag_and_len(0xAC, out_len, &p);

	memcpy(p, outdata, out_len);
	p+=out_len;

	r = piv_general_io(card, 0x47, 0x00, keydata->key_num,
			tagbuf, p - tagbuf, &rbuf, &rbuflen);

	if (r >= 0) {
		const u8 *cp;
		keydata->exponent = 0;

		/* expected tag is 7f49.  */
		/* we will whatever tag is present */

		cp = rbuf;
		in_len = rbuflen;

		r = sc_asn1_read_tag(&cp, rbuflen, &cla_out, &tag_out, &in_len);
		if (r != SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Tag buffer not found");
			goto err;
		}

		/* if RSA vs EC */
		if (keydata->key_bits > 0 ) {
			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x82, &taglen);
			if (tag != NULL && taglen <= 4) {
				keydata->exponent = 0;
				for (i = 0; i < taglen;i++) {
					keydata->exponent = (keydata->exponent<<8) + tag[i];
				}
			}
			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x81, &taglen);

			if (tag != NULL && taglen > 0) {
				keydata->pubkey = malloc(taglen);
				if (keydata->pubkey == NULL)
					SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
				keydata->pubkey_len = taglen;
				memcpy (keydata->pubkey, tag, taglen);
			}
		} else { /* must be EC */
			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x86, &taglen);
			if (tag != NULL && taglen > 0) {
				keydata->ecpoint = malloc(taglen);
				if (keydata->ecpoint == NULL)
					SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
				keydata->ecpoint_len = taglen;
				memcpy (keydata->ecpoint, tag, taglen);
            }
		}

		/* TODO: -DEE Could add key to cache so could use engine to generate key,
	 	 * and sign req in single operation */
		r = 0;
	}

err:
	if (rbuf)
		free(rbuf);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


static int piv_select_aid(sc_card_t* card, u8* aid, size_t aidlen, u8* response, size_t *responselen)
{
	sc_apdu_t apdu;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"Got args: aid=%x, aidlen=%d, response=%x, responselen=%d\n",
		aid, aidlen, response, responselen ? *responselen : 0);

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
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "PIV select failed");
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/* find the PIV AID on the card. If card->type already filled in,
 * then look for specific AID only
 * Assumes that priv may not be present
 */

static int piv_find_aid(sc_card_t * card, sc_file_t *aid_file)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r,i;
	const u8 *tag;
	size_t taglen;
	const u8 *pix;
	size_t pixlen;
	size_t resplen = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* first  see if the default applcation will return a template
	 * that we know about.
	 */

	if (card->type == SC_CARD_TYPE_PIV_II_GENERIC)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);

	r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, rbuf, &resplen);
	if (r >= 0 && resplen > 2 ) {
		tag = sc_asn1_find_tag(card->ctx, rbuf, resplen, 0x61, &taglen);
		if (tag != NULL) {
			pix = sc_asn1_find_tag(card->ctx, tag, taglen, 0x4F, &pixlen);
			if (pix != NULL ) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"found PIX");

				/* early cards returned full AID, rather then just the pix */
				for (i = 0; piv_aids[i].len_long != 0; i++) {
					if ((pixlen >= 6 && memcmp(pix, piv_aids[i].value + 5,
									piv_aids[i].len_long - 5 ) == 0)
						 || ((pixlen >=  piv_aids[i].len_short &&
							memcmp(pix, piv_aids[i].value,
							piv_aids[i].len_short) == 0))) {
						if (card->type > SC_CARD_TYPE_PIV_II_BASE &&
							card->type < SC_CARD_TYPE_PIV_II_BASE+1000 &&
							card->type == piv_aids[i].enumtag) {
							SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, i);
						} else {
							SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, i);
						}
					}
				}
			}
		}
	}

	/* for testing, we can force the use of a specific AID
	 *  by using the card= parameter in conf file
	 */
	for (i = 0; piv_aids[i].len_long != 0; i++) {
		if (card->type > SC_CARD_TYPE_PIV_II_BASE &&
			card->type < SC_CARD_TYPE_PIV_II_BASE+1000 &&
			card->type != piv_aids[i].enumtag) {
				continue;
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
		apdu.lc = piv_aids[i].len_long;
		apdu.data = piv_aids[i].value;

		apdu.datalen = apdu.lc;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;

		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);


		if (r)  {
			if (card->type != 0 && card->type == piv_aids[i].enumtag) {
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, i);
			}
			continue;
		}

		if ( apdu.resplen == 0 && r == 0) {
			/* could be the MSU card */
			continue; /* other cards will return a FCI */
		}

		if (apdu.resp[0] != 0x6f || apdu.resp[1] > apdu.resplen - 2 )
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NO_CARD_SUPPORT);

		card->ops->process_fci(card, aid_file, apdu.resp+2, apdu.resp[1]);
		if (aid_file->name == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NO_CARD_SUPPORT);

		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, i);
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NO_CARD_SUPPORT);
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
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"Unable to load PIV off card file: \"%s\"\n",filename);
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
	}
	len = read(f, tagbuf, sizeof(tagbuf)); /* get tag and length */
	if (len < 2 || len > sizeof(tagbuf)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Problem with \"%s\"\n",filename);
		r =  SC_ERROR_DATA_OBJECT_NOT_FOUND;
		goto err;
	}
	body = tagbuf;
	if (sc_asn1_read_tag(&body, 0xfffff, &cla_out,
			&tag_out, &bodylen) != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "DER problem\n");
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
	}
	rbuflen = body - tagbuf + bodylen;
	*buf = malloc(rbuflen);
	if (!*buf) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(*buf, tagbuf, len); /* copy first or only part */
	if (rbuflen > len) {
		len = read(f, *buf + sizeof(tagbuf), rbuflen - sizeof(tagbuf)); /* read rest */
		if (len != rbuflen - sizeof(tagbuf)) {
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			free (*buf);
			*buf = NULL;
			goto err;
		}
	}
	r = rbuflen;
	*buf_len = rbuflen;
err:
	if (f >= 0)
		close(f);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/* the tag is the PIV_OBJ_*  */
static int piv_get_data(sc_card_t * card, int enumtag,
			u8 **buf, size_t *buf_len)
{
	u8 *p;
	int r = 0;
	u8 tagbuf[8];
	size_t tag_len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "#%d \n", enumtag);

	/* assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM); */

	tag_len = piv_objects[enumtag].tag_len;

	p = tagbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[enumtag].tag_value, tag_len);
	p += tag_len;

	if (*buf_len == 1 && *buf == NULL) { /* we need to get the length */
		u8 rbufinitbuf[8]; /* tag of 53 with 82 xx xx  will fit in 4 */
		u8 *rbuf;
		size_t rbuflen;
		size_t bodylen;
		unsigned int cla_out, tag_out;
		const u8 *body;

		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"get len of #%d", enumtag);
		rbuf = rbufinitbuf;
		rbuflen = sizeof(rbufinitbuf);
		r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf,
				&rbuf, &rbuflen);
		if (r > 0) {
			body = rbuf;
			if (sc_asn1_read_tag(&body, 0xffff, &cla_out, &tag_out, &bodylen) !=  SC_SUCCESS) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "***** received buffer tag MISSING ");
				r = SC_ERROR_FILE_NOT_FOUND;
				goto err;
			}
		    *buf_len = r;
		} else if ( r == 0) {
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		} else {
			goto err;
		}
	}
sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"get buffer for #%d len %d", enumtag, *buf_len);
	if (*buf == NULL && *buf_len > 0) {
		*buf = malloc(*buf_len);
		if (*buf == NULL ) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}

	r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf,
		buf, buf_len);

err:

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int piv_get_cached_data(sc_card_t * card, int enumtag,
			u8 **buf, size_t *buf_len)
{

	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 *rbuf = NULL;
	size_t rbuflen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "#%d", enumtag);

	assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM);

	/* see if we have it cached */
	if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_VALID) {

		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"found #%d %p:%d %p:%d",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);


		if (priv->obj_cache[enumtag].obj_len == 0) {
			r = SC_ERROR_FILE_NOT_FOUND;
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"#%d found but len=0",
					enumtag);
			goto err;
		}
		*buf = priv->obj_cache[enumtag].obj_data;
		*buf_len = priv->obj_cache[enumtag].obj_len;
		r = *buf_len;
		goto ok;
	}

	/*
	 * If we know it can not be on the card  i.e. History object
	 * has been read, and we know what other certs may or
	 * may not be on the card. We can avoid extra overhead
 	 */

	if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_NOT_PRESENT) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"no_obj #%d", enumtag);
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}

	/* Not cached, try to get it, piv_get_data will allocate a buf */
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"get #%d",  enumtag);
	rbuflen = 1;
	r = piv_get_data(card, enumtag, &rbuf, &rbuflen);
	if (r > 0) {
		priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
		priv->obj_cache[enumtag].obj_len = r;
		priv->obj_cache[enumtag].obj_data = rbuf;
		*buf = rbuf;
		*buf_len = r;

		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"added #%d  %p:%d %p:%d",
				enumtag,
				priv->obj_cache[enumtag].obj_data,
				priv->obj_cache[enumtag].obj_len,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);

	} else if (r == 0 || r == SC_ERROR_FILE_NOT_FOUND) {
		r = SC_ERROR_FILE_NOT_FOUND;
		priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
		priv->obj_cache[enumtag].obj_len = 0;
	} else if ( r < 0) {
		goto err;
	}
ok:

err:

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int piv_cache_internal_data(sc_card_t *card, int enumtag)
{
	piv_private_data_t * priv = PIV_DATA(card);
	const u8* tag;
	const u8* body;
	size_t taglen;
	size_t bodylen;
	int compressed = 0;

	/* if already cached */
	if (priv->obj_cache[enumtag].internal_obj_data && priv->obj_cache[enumtag].internal_obj_len) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"#%d found internal %p:%d", enumtag,
				priv->obj_cache[enumtag].internal_obj_data,
				priv->obj_cache[enumtag].internal_obj_len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);
	}

	body = sc_asn1_find_tag(card->ctx,
			priv->obj_cache[enumtag].obj_data,
			priv->obj_cache[enumtag].obj_len,
			0x53, &bodylen);

	if (body == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_VALID);

	/* get the certificate out */
	 if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_CERT) {

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x71, &taglen);
		/* 800-72-1 not clear if this is 80 or 01 Sent comment to NIST for 800-72-2 */
		if (tag && (((*tag) & 0x80) || ((*tag) & 0x01))) {
			compressed = 1;
		}
		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x70, &taglen);
		if (tag == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);

			if(compressed) {
#ifdef ENABLE_ZLIB
			size_t len;
			u8* newBuf = NULL;
			if(SC_SUCCESS != sc_decompress_alloc(&newBuf, &len, tag, taglen, COMPRESSION_AUTO)) {
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_VALID);
			}
			priv->obj_cache[enumtag].internal_obj_data = newBuf;
			priv->obj_cache[enumtag].internal_obj_len = len;
#else
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"PIV compression not supported, no zlib");
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
#endif
		} else {
			if (!(priv->obj_cache[enumtag].internal_obj_data = malloc(taglen)))
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

			memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
			priv->obj_cache[enumtag].internal_obj_len = taglen;
		}

	/* convert pub key to internal */
/* TODO: -DEE need to fix ...  would only be used if we cache the pub key, but we don't today */
	} else if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_PUBKEY) {

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, *body, &taglen);
		if (tag == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);

		if (!(priv->obj_cache[enumtag].internal_obj_data = malloc(taglen)))
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

		memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
		priv->obj_cache[enumtag].internal_obj_len = taglen;
	} else {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"added #%d internal %p:%d", enumtag,
		priv->obj_cache[enumtag].internal_obj_data,
		priv->obj_cache[enumtag].internal_obj_len);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);
}


/*
 * Callers of this may be expecting a certificate,
 * select file will have saved the object type for us
 * as well as set that we want the cert from the object.
 */
static int piv_read_binary(sc_card_t *card, unsigned int idx,
		unsigned char *buf, size_t count, unsigned long flags)
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
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "DEE rbuf=%p,rbuflen=%d,",rbuf, rbuflen);
			body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, rbuf[0], &bodylen);
			if (body == NULL) {
				/* if missing, assume its the body */
				/* DEE bug in the beta card */
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL," ***** tag 0x53 MISSING \n");
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
			if (bodylen > body - rbuf + rbuflen) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL," ***** tag length > then data: %d>%d+%d",
					bodylen , body - rbuf, rbuflen);
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
			r = count;
		}
err:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


/*
 * the tag is the PIV_OBJ_*
 * The buf should have the 0x53 tag+len+tags and data
 */

static int piv_put_data(sc_card_t *card, int tag,
		const u8 *buf, size_t buf_len)
{
	int r;
	u8 * sbuf;
	size_t sbuflen;
	u8 * p;
	size_t tag_len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	tag_len = piv_objects[tag].tag_len;
	sbuflen = put_tag_and_len(0x5c, tag_len, NULL) + buf_len;
	if (!(sbuf = malloc(sbuflen)))
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

	p = sbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[tag].tag_value, tag_len);
	p += tag_len;

	memcpy(p, buf, buf_len);
	p += buf_len;

	r = piv_general_io(card, 0xDB, 0x3F, 0xFF,
			sbuf, p - sbuf, NULL, NULL);

	if (sbuf)
		free(sbuf);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


static int piv_write_certificate(sc_card_t *card,
		const u8* buf, size_t count,
		unsigned long flags) {
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag;
	int r = SC_SUCCESS;
	u8 *sbuf = NULL;
	u8 *p;
	size_t sbuflen;
	size_t taglen;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DEE cert len=%d",count);
	taglen = put_tag_and_len(0x70, count, NULL)
		+ put_tag_and_len(0x71, 1, NULL)
		+ put_tag_and_len(0xFE, 0, NULL);

	sbuflen =  put_tag_and_len(0x53, taglen, NULL);

	sbuf = malloc(sbuflen);
	if (sbuf == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	p = sbuf;
	put_tag_and_len(0x53, taglen, &p);

	put_tag_and_len(0x70, count, &p);
	memcpy(p, buf, count);
	p += count;
	put_tag_and_len(0x71, 1, &p);
	*p++ = (flags)? 0x80:0x00; /* certinfo, i.e. gziped? */
	put_tag_and_len(0xFE,0,&p); /* LRC tag */

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DEE buf %p len %d %d", sbuf, p -sbuf, sbuflen);

	enumtag = piv_objects[priv->selected_obj].enumtag;
	r = piv_put_data(card, enumtag, sbuf, sbuflen);
	if (sbuf)
		free(sbuf);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * For certs we need to add the 0x53 tag and other specific tags,
 * and call the piv_put_data
 * Note: the select file will have saved the object type for us
 * Write is used by piv-tool, so we will use flags:
 *  length << 8 | 8bits:
 * object           xxxx0000
 * uncompresed cert xxx00001
 * compressed cert  xxx10001
 * pubkey           xxxx0010
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

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (priv->selected_obj < 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

	enumtag = piv_objects[priv->selected_obj].enumtag;

	if (priv->rwb_state == 1)  /* trying to write at end */
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);

	if (priv->rwb_state == -1) {

		/* if  cached, remove old entry */
		if (priv->obj_cache[enumtag].flags & PIV_OBJ_CACHE_VALID) {
			priv->obj_cache[enumtag].flags = 0;
			if (priv->obj_cache[enumtag].obj_data) {
				free(priv->obj_cache[enumtag].obj_data);
				priv->obj_cache[enumtag].obj_data = NULL;
				priv->obj_cache[enumtag].obj_len = 0;
			}
			if (priv->obj_cache[enumtag].internal_obj_data) {
				free(priv->obj_cache[enumtag].internal_obj_data);
				priv->obj_cache[enumtag].internal_obj_data = NULL;
				priv->obj_cache[enumtag].internal_obj_len = 0;
			}
		}

		if (idx != 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NO_CARD_SUPPORT);

		priv->w_buf_len = flags>>8;
		if (priv->w_buf_len == 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);

		priv->w_buf = malloc(priv->w_buf_len);
		priv-> rwb_state = 0;
	}

	/* on each pass make sure we have w_buf */
	if (priv->w_buf == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

	if (idx + count > priv->w_buf_len)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OBJECT_NOT_VALID);

	memcpy(priv->w_buf + idx, buf, count); /* copy one chunk */

	/* if this was not the last chunk, return to get rest */
	if (idx + count < priv->w_buf_len)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, count);

	priv-> rwb_state = 1; /* at end of object */

	switch (flags & 0x0f) {
		case 1:
			r = piv_write_certificate(card, priv->w_buf, priv->w_buf_len,
				flags & 0x10);
			break;
		case 2: /* pubkey to be added to cache, it should have 0x53 and 0x99 tags. */
	/* TODO: -DEE this is not fully implemented and not used */
			r = priv->w_buf_len;
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
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, (r < 0)? r : (int)count);
}

/*
 * Card initialization is not standard.
 * Some cards use mutual or external authentication using s 3des key. We
 * will read in the key from a file.
 * This is only needed during initialization/personalization of the card
 */

static int piv_get_3des_key(sc_card_t *card, u8 *key)
{

	int r;
	int f = -1;
	char keybuf[24*3];  /* 3des key as three sets of xx:xx:xx:xx:xx:xx:xx:xx
		                   * with a : between which is 71 bytes */
	char * keyfilename = NULL;
	size_t outlen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	keyfilename = (char *)getenv("PIV_EXT_AUTH_KEY");

	if (keyfilename == NULL) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"Unable to get PIV_EXT_AUTH_KEY=filename for general_external_authenticate\n");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}
	if ((f = open(keyfilename, O_RDONLY)) < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL," Unable to load 3des key for general_external_authenticate\n");
		r = SC_ERROR_FILE_NOT_FOUND;
		goto err;
	}
	if (read(f, keybuf, 71) != 71) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL," Unable to read 3des key for general_external_authenticate\n");
		r = SC_ERROR_WRONG_LENGTH;
		goto err;
	}
	keybuf[23] = '\0';
	keybuf[47] = '\0';
	keybuf[71] = '\0';
	outlen = 8;
	r = sc_hex_to_bin(keybuf, key, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+24, key+8, &outlen);
	if (r) goto err;
	outlen = 8;
	r = sc_hex_to_bin(keybuf+48, key+16, &outlen);
	if (r) goto err;

err:
	if (f >=0)
		close(f);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

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
	int locked = 0, outl, outl2;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 nonce[8] = {0xDE, 0xE0, 0xDE, 0xE1, 0xDE, 0xE2, 0xDE, 0xE3};
	u8 sbuf[255], key[24];
	u8 *p, *q;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	EVP_CIPHER_CTX_init(&ctx);

	switch (alg_id) {
		case 1: cipher=EVP_des_ede3_ecb(); break;
		case 2: cipher=EVP_des_ede3_cbc(); break;
		case 3: cipher=EVP_des_ede3_ecb(); break;
		case 4: cipher=EVP_des_ede3_cbc(); break;
		default: cipher=EVP_des_ede3_ecb(); break;
	}

	r = piv_get_3des_key(card, key);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		goto err;
	locked = 1;

	p = sbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x80;
	*p++ = 0x00;

	/* get the encrypted nonce */

	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen);

 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| (*q++ != 0x80)
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}
	N = *(rbuf + 3); /* assuming N + sizeof(nonce) + 6 < 128 */

	/* prepare the response */
	p = sbuf;
	*p++ = 0x7c;
	*p++ = N + sizeof(nonce)+ 4;
	*p++ = 0x80;
	*p++ = (u8)N;

	/* decrypt the data from the card */
	if (!EVP_DecryptInit(&ctx, cipher, key, NULL)) {
		/* may fail if des parity of key is wrong. depends on OpenSSL options */
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_DecryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if(!EVP_DecryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (outl+outl2 != N) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p += N;

	*p++ = 0x81;
	*p++ = sizeof(nonce);
	memcpy(p, &nonce, sizeof(nonce)); /* we use a fixed nonce for now */
	p += sizeof(nonce);

	free(rbuf);
	rbuf = NULL;

	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen);
 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| ((*q++ | 0x02) != 0x82)    /* SP800-73 not clear if  80 or 82 */
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}
	N = *(rbuf + 3);

	p = sbuf;

	EVP_CIPHER_CTX_cleanup(&ctx);
	EVP_CIPHER_CTX_init(&ctx);

	if (!EVP_DecryptInit(&ctx, cipher, key, NULL)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_DecryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if(!EVP_DecryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (outl+outl2 != sizeof(nonce) || memcmp(nonce, p, sizeof(nonce)) != 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "mutual authentication failed, card returned wrong value");
		r = SC_ERROR_DECRYPT_FAILED;
		goto err;
	}
	r = SC_SUCCESS;

err:
	EVP_CIPHER_CTX_cleanup(&ctx);
	if (locked)
		sc_unlock(card);
	if (rbuf)
		free(rbuf);

#else
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"OpenSSL Required");
	r = SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/* Currently only used for card administration */
static int piv_general_external_authenticate(sc_card_t *card,
		unsigned int key_ref, unsigned int alg_id)
{
	int r;
#ifdef ENABLE_OPENSSL
	int outl, outl2;
	int N;
	int locked = 0;
	u8  *rbuf = NULL;
	size_t rbuflen;
	u8 sbuf[255], key[24];
	u8 *p, *q;
	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	EVP_CIPHER_CTX_init(&ctx);

	switch (alg_id) {
		case 1: cipher=EVP_des_ede3_ecb(); break;
		case 2: cipher=EVP_des_ede3_cbc(); break;
		case 3: cipher=EVP_des_ede3_ecb(); break;
		case 4: cipher=EVP_des_ede3_cbc(); break;
		default: cipher=EVP_des_ede3_ecb(); break;
	}

	r = piv_get_3des_key(card, key);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		goto err;
	locked = 1;

	p = sbuf;
	*p++ = 0x7C;
	*p++ = 0x02;
	*p++ = 0x81;
	*p++ = 0x00;

	/* get a challenge */
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen);

 	if (r < 0) goto err;
	q = rbuf;
	if ( (*q++ != 0x7C)
		|| (*q++ != rbuflen - 2)
		|| (*q++ != 0x81)
		|| (*q++ != rbuflen - 4)) {
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* assuming challenge and response are same size  i.e. des3 */
	p = sbuf;
	*p++ = 0x7c;
	*p++ = *(rbuf + 1);
	*p++ = 0x82;
	*p++ = *(rbuf + 3);
	N = *(rbuf + 3); /* assuming 2 * N + 6 < 128 */

	if (!EVP_EncryptInit(&ctx, cipher, key, NULL)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(&ctx,0);
	if (!EVP_EncryptUpdate(&ctx, p, &outl, q, N)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if(!EVP_EncryptFinal(&ctx, p+outl, &outl2)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if (outl+outl2 != N) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	p += N;

	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, NULL, NULL);

err:
	if (locked)
		sc_unlock(card);
	EVP_CIPHER_CTX_cleanup(&ctx);
	sc_mem_clear(key, sizeof(key));
	if (rbuf)
		free(rbuf);
#else
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"OpenSSL Required");
	r = SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int piv_get_serial_nr_from_CHUI(sc_card_t* card, sc_serial_number_t* serial)
{
	int r;
	int i;
	u8 gbits;
	u8 *rbuf = NULL;
	const u8 *body;
	const u8 *fascn;
	const u8 *guid;
	size_t rbuflen = 0, bodylen, fascnlen, guidlen;
	u8 temp[2000];
	size_t templen = sizeof(temp);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (card->serialnr.len)   {
		*serial = card->serialnr;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
	}

	/* ensure we've got the PIV selected, and nothing else is in process */
	/* This fixes several problems due to previous incomplete APDUs during card detection */
	/* Note: We need the temp because (some?) Oberthur cards don't like selecting an applet without response data */
	/* 800-73-3 part1 draft, and CIO Council docs  imply for PIV Compatible card
     * The FASC-N Agency code should be 9999 and there should be a GUID
     * based on RFC 4122. RIf so and the GUID is not all 0's
	 * we will use the GUID as the serial number.
	 */
	piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, temp, &templen);

	r = piv_get_cached_data(card, PIV_OBJ_CHUI, &rbuf, &rbuflen);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Failure retrieving CHUI");

	r = SC_ERROR_INTERNAL;
	if (rbuflen != 0) {
		body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x53, &bodylen); /* Pass the outer wrapper asn1 */
		if (body != NULL && bodylen != 0) {
			fascn = sc_asn1_find_tag(card->ctx, body, bodylen, 0x30, &fascnlen); /* Find the FASC-N data */
			guid = sc_asn1_find_tag(card->ctx, body, bodylen, 0x34, &guidlen);

			gbits = 0; /* if guid is valid, gbits will not be zero */
			if (guid && guidlen == 16) {
				for (i = 0; i < 16; i++) {
					gbits = gbits | guid[i]; /* if all are zero, gbits will be zero */
				}
			}
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"fascn=%p,fascnlen=%d,guid=%p,guidlen=%d,gbits=%2.2x\n",
					fascn, fascnlen, guid, guidlen, gbits);

			if (fascn && fascnlen == 25) {
				/* test if guid and the fascn starts with ;9999 (in ISO 4bit + partiy code) */
				if (!(gbits && fascn[0] == 0xD4 && fascn[1] == 0xE7
						    && fascn[2] == 0x39 && (fascn[3] | 0x7F) == 0xFF)) {
					serial->len = fascnlen < SC_MAX_SERIALNR ? fascnlen : SC_MAX_SERIALNR;
					memcpy (serial->value, fascn, serial->len);
					r = SC_SUCCESS;
					gbits = 0; /* set to skip using guid below */
				}
			}
			if (guid && gbits) {
				serial->len = guidlen < SC_MAX_SERIALNR ? guidlen : SC_MAX_SERIALNR;
				memcpy (serial->value, guid, serial->len);
				r = SC_SUCCESS;
			}
		}
	}

	card->serialnr = *serial;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
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

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * NIST 800-73-3 allows the default pin to be the PIV application 0x80
 * or the global pin for the card 0x00. Look at Discovery object to get this.
 * called by pkcs15-piv.c  via cardctl when setting up the pins.
 */
static int piv_get_pin_preference(sc_card_t *card, int *ptr)
{
	piv_private_data_t * priv = PIV_DATA(card);

	*ptr = priv->pin_preference;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int piv_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	piv_private_data_t * priv = PIV_DATA(card);
	u8 * opts; /*  A or M, key_ref, alg_id */

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"cmd=%ld ptr=%p");
	if (priv == NULL) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	switch(cmd) {
		case SC_CARDCTL_PIV_AUTHENTICATE:
			opts = (u8 *)ptr;
			switch (*opts) {
				case 'A':
					return piv_general_external_authenticate(card,
						*(opts+1), *(opts+2));
					break;
				case'M':
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

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
}

static int piv_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	u8 sbuf[16];
	u8 *rbuf = NULL;
	size_t rbuflen = 0;
	u8 *p, *q;
	int r;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"challenge len=%d",len);

	sc_lock(card);

	p = sbuf;
	*p++ = 0x7c;
	*p++ = 0x02;
	*p++ = 0x81;
	*p++ = 0x00;

	/* assuming 8 byte response ? */
	/* should take what the card returns */
	while (len > 0) {
		size_t n = len > 8 ? 8 : len;

		/* NIST 800-73-3 says use 9B, previous verisons used 00 */
		r = piv_general_io(card, 0x87, 0x00, 0x9B, sbuf, p - sbuf,
				&rbuf, &rbuflen);
 		if (r < 0) {
			sc_unlock(card);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
		}
		q = rbuf;
		if ( (*q++ != 0x7C)
			|| (*q++ != rbuflen - 2)
			|| (*q++ != 0x81)
			|| (*q++ != rbuflen - 4)) {
			r =  SC_ERROR_INVALID_DATA;
			sc_unlock(card);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
		}
		memcpy(rnd, q, n);
		len -= n;
		rnd += n;
		free(rbuf);
		rbuf = NULL;
	}

	sc_unlock(card);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);

}

static int piv_set_security_env(sc_card_t *card,
                    const sc_security_env_t *env,
                    int se_num)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"flags=%08x op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%d\n",
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

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static int piv_restore_security_env(sc_card_t *card, int se_num)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);
}


static int piv_validate_general_authentication(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 *p;
	const u8 *tag;
	size_t taglen;
	const u8 *body;
	size_t bodylen;
	unsigned int real_alg_id;

	u8 sbuf[4096]; /* needs work. for 3072 keys, needs 384+10 or so */
	u8 *rbuf = NULL;
	size_t rbuflen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* should assume large send data */
	p = sbuf;
	put_tag_and_len(0x7c, (2 + put_tag_and_len(0, datalen, NULL)) , &p);
	put_tag_and_len(0x82, 0, &p);
	if (priv->operation == SC_SEC_OPERATION_DERIVE
			&& priv->algorithm == SC_ALGORITHM_EC)
		put_tag_and_len(0x85, datalen, &p);
	else
		put_tag_and_len(0x81, datalen, &p);

	memcpy(p, data, datalen);
	p += datalen;

	/*
	 * alg_id=06 is a place holder for all RSA keys.
 	 * Derive the real alg_id based on the size of the
	 * the data, as we are always using raw mode.
	 * Non RSA keys needs some work in thia area.
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
			sbuf, p - sbuf, &rbuf, &rbuflen);

	if ( r >= 0) {
	 	body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x7c, &bodylen);

		if (body) {
			tag = sc_asn1_find_tag(card->ctx, body,  bodylen, 0x82, &taglen);
			if (tag) {
				memcpy(out, tag, taglen);
				r = taglen;
			}
		} else
			r = SC_ERROR_INVALID_DATA;
	}

	if (rbuf)
		free(rbuf);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

static int piv_compute_signature(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i;
	int nLen;
	u8 rbuf[128]; /* For EC conversions  384 will fit */
	size_t rbuflen = sizeof(rbuf);
	const u8 * body;
	size_t bodylen;
	const u8 * tag;
	size_t taglen;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* The PIV returns a DER SEQUENCE{INTEGER, INTEGER}
	 * Which may have leading 00 to force positive
	 * TODO: -DEE should check if PKCS15 want the same
	 * But PKCS11 just wants 2* filed_length in bytes
	 * So we have to strip out the integers
	 * if present and pad on left if too short.
	 */

	if (priv->alg_id == 0x11 || priv->alg_id == 0x14 ) {
		nLen = (priv->key_size + 7) / 8;
		if (outlen < 2*nLen) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL," output too small for EC signature %d < %d", outlen, 2*nLen);
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
		memset(out, 0, outlen);

		r = piv_validate_general_authentication(card, data, datalen, rbuf, rbuflen);
		if (r < 0)
			goto err;

		if ( r >= 0) {
	 		body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x30, &bodylen);

			for (i = 0; i<2; i++) {
				if (body) {
					tag = sc_asn1_find_tag(card->ctx, body,  bodylen, 0x02, &taglen);
					if (tag) {
						bodylen -= taglen - (tag - body);
						body = tag + taglen;

						if (taglen > nLen) { /* drop leading 00 if present */
							if (*tag != 0x00) {
								r = SC_ERROR_INVALID_DATA;
								goto err;
							}
							tag++;
							taglen--;
						}
						memcpy(out + nLen*i + nLen - taglen , tag, taglen);
					} else {
						r = SC_ERROR_INVALID_DATA;
						goto err;
					}
				} else  {
					r = SC_ERROR_INVALID_DATA;
					goto err;
				}
			}
			r = 2 * nLen;
		}
	} else { /* RSA is all set */
		r = piv_validate_general_authentication(card, data, datalen, out, outlen);
	}

err:
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int piv_decipher(sc_card_t *card,
					 const u8 * data, size_t datalen,
					 u8 * out, size_t outlen)
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
	int pathlen;
	sc_file_t *file = NULL;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	path = in_path->value;
	pathlen = in_path->len;

	/* only support single EF in current application */

	if (memcmp(path, "\x3F\x00", 2) == 0) {
		if (pathlen == 2)   {
			r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, NULL, NULL);
			SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Cannot select PIV AID");

			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
		}
		else if (pathlen > 2) {
			path += 2;
			pathlen -= 2;
		}
	}

	i = piv_find_obj_by_containerid(card, path);

	if (i < 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);

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
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);

		/* get the cert or the pub key out and into the cache too */
		if (priv->return_only_cert || piv_objects[i].flags & PIV_OBJECT_TYPE_PUBKEY) {
			r = piv_cache_internal_data(card, i);
			if (r < 0)
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
		}

		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

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

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, 0);

}

static int piv_process_discovery(sc_card_t *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	u8 * rbuf = NULL;
	size_t rbuflen = 0;
	const u8 * body;
	size_t bodylen;
	const u8 * aid;
	size_t aidlen;
	const u8 * pinp;
	size_t pinplen;
	unsigned int cla_out, tag_out;


	r = piv_get_cached_data(card, PIV_OBJ_DISCOVERY, &rbuf, &rbuflen);
	if (r <= 0) {
		priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
		/* Discovery object is only object that has 3 byte Lc= 50017E
		 * and pree 800-73-3 cards may treat this as a strange error.
		 * So treat any error as not present
		 */
		r = 0;
		goto err;
	}

sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Discovery = %p:%d",rbuf, rbuflen);
	/* the object is now cached, see what we have */
	if (rbuflen != 0) {
		body = rbuf;
		if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DER problem %d\n",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Discovery 0x%2.2x 0x%2.2x %p:%d",
				cla_out, tag_out, body, bodylen);
        if ( cla_out+tag_out == 0x7E && body != NULL && bodylen != 0) {
            aidlen = 0;
            aid = sc_asn1_find_tag(card->ctx, body, bodylen, 0x4F, &aidlen);
sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Discovery aid=%p:%d",aid,aidlen);
		 	if (aid == NULL || aidlen < piv_aids[0].len_short ||
				memcmp(aid,piv_aids[0].value,piv_aids[0].len_short) != 0) { /*TODO look at long */
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Discovery object not PIV");
				r = SC_SUCCESS; /* not an error could be some other appl */
				goto err;
			}
			pinp = sc_asn1_find_tag(card->ctx, body, bodylen, 0x5F2F, &pinplen);
sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Discovery pinp=%p:%d",pinp,pinplen);
			if (pinp && pinplen == 2) {
sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Discovery pinp flags=0x%2.2x 0x%2.2x",*pinp, *(pinp+1));
				r = SC_SUCCESS;
				if (*pinp == 0x60 && *(pinp+1) == 0x20) { /* use Global pin */
					sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Pin Preference - Global");
					priv->pin_preference = 0x00;
				}
			}
		}
	}
	err:
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

/*
 * The history object lists what retired keys and certs are on the card
 * or listed in the offCardCertURL. The user may have read the offCardURL file,
 * ahead of time, and if so will use it for the certs listed.
 * TODO: -DEE
 * If the offCardCertURL is not cached by the user, should we wget it here?
 * Its may be out of scope to have OpenSC read the URL.
 */

static int piv_process_history(sc_card_t *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i;
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
		if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DER problem %d\n",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

        if ( cla_out+tag_out == 0x53 && body != NULL && bodylen != 0) {
            numlen = 0;
            num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC1, &numlen);
            if (num) {
				if (numlen != 1 ||
						*num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INTERNAL; /* TODO some other error */
                	goto err;
				}
                priv->keysWithOnCardCerts = *num;
			}

            numlen = 0;
            num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC2, &numlen);
            if (num) {
				if (numlen != 1 ||
						*num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INTERNAL; /* TODO some other error */
					goto err;
				}
                priv->keysWithOffCardCerts = *num;
			}

            url = sc_asn1_find_tag(card->ctx, body, bodylen, 0xF3, &urllen);
            if (url) {
                priv->offCardCertURL = calloc(1,urllen+1);
                if (priv->offCardCertURL == NULL)
                    SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
				memcpy(priv->offCardCertURL, url, urllen);
			}
		} else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Problem with Histroy object\n");
			goto err;
		}
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "History on=%d off=%d URL=%s\n",
				priv->keysWithOnCardCerts, priv->keysWithOffCardCerts,
				priv->offCardCertURL ? priv->offCardCertURL:"NONE");

	/* now mark what objects are on the card */
	for (i=0; i<priv->keysWithOnCardCerts; i++) {
		priv->obj_cache[PIV_OBJ_RETIRED_X509_1+i].flags &= ~PIV_OBJ_CACHE_NOT_PRESENT;
	}

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
		r = sc_get_cache_dir(card->ctx, filename,
				sizeof(filename) - strlen(fp) - 2);
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
		if (sc_asn1_read_tag(&body, ocfhflen, &cla_out,
				&tag_out, &bodylen) != SC_SUCCESS ||
				cla_out+tag_out != 0x30) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "DER problem\n");
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}
		seq = body;
		while (bodylen > 0) {
			seqtag = seq;
			if (sc_asn1_read_tag(&seq, bodylen, &cla_out,
					&tag_out, &seqlen) != SC_SUCCESS ||
					cla_out+tag_out != 0x30) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DER problem\n");
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}
			keyref = sc_asn1_find_tag(card->ctx,
				seq, seqlen, 0x04, &keyreflen);
			if (!keyref || keyreflen != 1 ||
					(*keyref < 0x82 && *keyref > 0x95)) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DER problem\n");
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				goto err;
			}
			cert = keyref + keyreflen;
			certlen = seqlen - (cert - seq);

			enumtag = PIV_OBJ_RETIRED_X509_1 + *keyref - 0x82;
			/* now add the cert like another object */

			i2 = put_tag_and_len(0x70,certlen, NULL)
					+ put_tag_and_len(0x71, 1, NULL)
					+ put_tag_and_len(0xFE, 0, NULL);

			certobjlen = put_tag_and_len(0x53, i2, NULL);

			certobj = malloc(certobjlen);
			if (certobj == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			cp = certobj;
			put_tag_and_len(0x53, i2, &cp);
			put_tag_and_len(0x70,certlen, &cp);
			memcpy(cp, cert, certlen);
			cp += certlen;
			put_tag_and_len(0x71, 1,&cp);
			*cp++ = 0x00;
			put_tag_and_len(0xFE, 0, &cp);

			priv->obj_cache[enumtag].obj_data = certobj;
			priv->obj_cache[enumtag].obj_len = certobjlen;
			priv->obj_cache[enumtag].flags |= PIV_OBJ_CACHE_VALID;
			priv->obj_cache[enumtag].flags &= ~PIV_OBJ_CACHE_NOT_PRESENT;

			r = piv_cache_internal_data(card, enumtag);
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got internal r=%d\n",r);

			certobj = NULL;

			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
				"Added from off card file #%d %p:%d 0x%02X \n",
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
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


static int piv_finish(sc_card_t *card)
{
 	piv_private_data_t * priv = PIV_DATA(card);
	int i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		if (priv->aid_file)
			sc_file_free(priv->aid_file);
		if (priv->w_buf)
			free(priv->w_buf);
		if (priv->offCardCertURL)
			free(priv->offCardCertURL);
		for (i = 0; i < PIV_OBJ_LAST_ENUM - 1; i++) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"DEE freeing #%d, 0x%02x %p:%d %p:%d", i,
				priv->obj_cache[i].flags,
				priv->obj_cache[i].obj_data, priv->obj_cache[i].obj_len,
				priv->obj_cache[i].internal_obj_data, priv->obj_cache[i].internal_obj_len);
			if (priv->obj_cache[i].obj_data)
				free(priv->obj_cache[i].obj_data);
			if (priv->obj_cache[i].internal_obj_data)
				free(priv->obj_cache[i].internal_obj_data);
		}
		free(priv);
	}
	return 0;
}


static int piv_match_card(sc_card_t *card)
{
	int i;
	sc_file_t aidfile;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* Since we send an APDU, the card's logout function may be called...
	 * however it may be in dirty memory */
	card->ops->logout = NULL;

	/* Detect by selecting applet */
	i = !(piv_find_aid(card, &aidfile));
	return i; /* never match */
}


static int piv_init(sc_card_t *card)
{
	int r, i;
	unsigned long flags;
	unsigned long ext_flags;
	piv_private_data_t *priv;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	priv = calloc(1, sizeof(piv_private_data_t));

	if (!priv)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	priv->aid_file = sc_file_new();
	priv->selected_obj = -1;
	priv->pin_preference = 0x80; /* 800-73-3 part 1, table 3 */

	/* Some objects will only be present if Histroy object says so */
	for (i=0; i < PIV_OBJ_LAST_ENUM -1; i++) {
		if(piv_objects[i].flags & PIV_OBJECT_NOT_PRESENT)
			priv->obj_cache[i].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Max send = %d recv = %d\n",
			card->max_send_size, card->max_recv_size);
	card->drv_data = priv;
	card->cla = 0x00;
	card->name = "PIV-II card";

	r = piv_find_aid(card, priv->aid_file);
	if (r < 0) {
		 sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Failed to initialize %s\n", card->name);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	priv->enumtag = piv_aids[r].enumtag;
	card->type = piv_aids[r].enumtag;

	/* PKCS#11 may try to generate session keys, and get confused
	 * if SC_ALGORITHM_ONBOARD_KEY_GEN is present
	 * piv-tool can still do this, just don't tell PKCS#11
	 */

	 flags = SC_ALGORITHM_RSA_RAW;

	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* manditory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */

	flags = SC_ALGORITHM_ECDSA_RAW;
	ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

	_sc_card_add_ec_alg(card, 256, flags, ext_flags);
	_sc_card_add_ec_alg(card, 384, flags, ext_flags);

	card->caps |= SC_CARD_CAP_RNG;

	/*
	 * 800-73-3 cards may have a history object and/or a discovery object
	 * We want to process them now as this has information on what
	 * keys and certs the card has and how the pin might be used.
	 */
	r = piv_process_history(card);

	r = piv_process_discovery(card);

	if (r > 0)
		r = 0;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}


static int piv_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
                       int *tries_left)
{
	/* Extra validation of (new) PIN during a PIN change request, to
	 * ensure it's not outside the FIPS 201 4.1.6.1 (numeric only) and
	 * FIPS 140-2 (6 character minimum) requirements.
	 */
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	if (data->cmd == SC_PIN_CMD_CHANGE) {
		int i = 0;
		if (data->pin2.len < 6) {
			return SC_ERROR_INVALID_PIN_LENGTH;
		}
		for(i=0; i < data->pin2.len; ++i) {
			if (!isdigit(data->pin2.data[i])) {
				return SC_ERROR_INVALID_DATA;
			}
		}
	}
	return iso_drv->ops->pin_cmd(card, data, tries_left);
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
	piv_ops.read_binary = piv_read_binary;
	piv_ops.write_binary = piv_write_binary;
	piv_ops.set_security_env = piv_set_security_env;
	piv_ops.restore_security_env = piv_restore_security_env;
	piv_ops.compute_signature = piv_compute_signature;
	piv_ops.decipher =  piv_decipher;
	piv_ops.card_ctl = piv_card_ctl;
	piv_ops.pin_cmd = piv_pin_cmd;

	return &piv_drv;
}


#if 1
struct sc_card_driver * sc_get_piv_driver(void)
{
	return sc_get_driver();
}
#endif

