/*
 * card-piv.c: Support for PIV-II from NIST SP800-73
 * card-default.c: Support for cards with no driver
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2005-2018  Douglas E. Engert <deengert@gmail.com>
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

#if HAVE_CONFIG_H
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
	/* openssl only needed for card administration */
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#endif /* ENABLE_OPENSSL */

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#ifdef ENABLE_ZLIB
#include "compression.h"
#endif
#include "simpletlv.h"

#define PIV_MAX_FILE_SIZE 65535

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

typedef struct piv_private_data {
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
} piv_private_data_t;

#define PIV_DATA(card) ((piv_private_data_t*)card->drv_data)

struct piv_aid {
	int enumtag;
	size_t len_short;	/* min length without version */
	size_t len_long;	/* With version and other stuff */
	u8 *value;
};

/*
 * The Generic entry should be the "A0 00 00 03 08 00 00 10 00 "
 * NIST published  this on 10/6/2005
 * 800-73-2 Part 1 now refers to version "02 00"
 * i.e. "A0 00 00 03 08 00 00 01 00 02 00".
 * but we don't need the version number. but could get it from the PIX.
 *
 * 800-73-3 Part 1 now refers to "01 00" i.e. going back to 800-73-1.
 * The main differences between 73-1, and 73-3 are the addition of the
 * key History object and keys, as well as Discovery and Iris objects.
 * These can be discovered by trying GET DATA
 */

/* ATRs of cards known to have PIV applet. But must still be tested for a PIV applet */
static const struct sc_atr_table piv_atrs[] = {
	/* CAC cards with PIV from: CAC-utilziation-and-variation-matrix-v2.03-20May2016.doc */
	/* Oberthur Card Systems (PIV Endpoint) with PIV endpoint applet and PIV auth cert OBSOLETE */
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:77:E3:03:00:82:90.00:C1", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },

	/* Gemalto (PIV Endpoint) with PIV endpoint applet and PIV auth cert OBSOLETE */
	{ "3B 7D 96 00 00 80 31 80 65 B0 83 11 13 AC 83 00 90 00", NULL, NULL, SC_CARD_TYPE_PIV_II_GEMALTO, 0, NULL },

	/* Gemalto (PIV Endpoint) 2 entries */
	{ "3B:7D:96:00:00:80:31:80:65:B0:83:11:17:D6:83:00:90:00", NULL, NULL, SC_CARD_TYPE_PIV_II_GEMALTO, 0, NULL },

	/* Oberthur Card System (PIV Endpoint)  2 entries*/
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:B0:F3:10:00:07:90:00:80", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },
	/* Oberthur Card System  with LCS 0F - Some VA cards have Terminated state */
	{ "3B:DB:96:00:80:1F:03:00:31:C0:64:B0:F3:10:00:0F:90:00:88", NULL, NULL, SC_CARD_TYPE_PIV_II_OBERTHUR, 0, NULL },

	/* Giesecke & Devrient (PIV Endpoint)  2 entries */
	{ "3B:7A:18:00:00:73:66:74:65:20:63:64:31:34:34", NULL, NULL, SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC, 0, NULL },

	/* PIVKEY from Taligo */
	/* PIVKEY T600 token and T800  on Feitian eJAVA */
	{ "3B:FC:18:00:00:81:31:80:45:90:67:46:4A:00:64:2D:70:C1:72:FE:E0:FE", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },

	/* PIVKEY C910 */
	{ "3b:fc:18:00:00:81:31:80:45:90:67:46:4a:00:64:16:06:f2:72:7e:00:e0", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },

	/* PIVKEY C980 */
	{ "3B:f9:96:00:00:81:31:fe:45:53:50:49:56:4b:45:59:37:30:28", NULL, NULL, SC_CARD_TYPE_PIV_II_PIVKEY, 0, NULL },

	{ NULL, NULL, NULL, 0, 0, NULL }
};

/* all have same AID */
static struct piv_aid piv_aids[] = {
	{SC_CARD_TYPE_PIV_II_GENERIC, /* TODO not really card type but what PIV AID is supported */
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
	"Personal Identity Verification Card",
	"PIV-II",
	&piv_ops,
	NULL, 0, NULL
};

static int piv_match_card_continued(sc_card_t *card);

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
 * If ptr == NULL, just return the size of the tag and length and data
 * otherwise, store tag and length at **ptr, and increment
 */

static size_t
put_tag_and_len(unsigned int tag, size_t len, u8 **ptr)
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
 * GET DATA may call to get the first 128 bytes to get the length from the tag.
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


	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	rbuf = rbufinitbuf;
	rbuflen = sizeof(rbufinitbuf);

	/* if caller provided a buffer and length */
	if (recvbuf && *recvbuf && recvbuflen && *recvbuflen) {
		rbuf = *recvbuf;
		rbuflen = *recvbuflen;
	}

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

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

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r < 0) {
		sc_log(card->ctx,  "Card returned error ");
		goto err;
	}

	if (recvbuflen) {
		if (recvbuf && *recvbuf == NULL) {
			*recvbuf =  malloc(apdu.resplen);
			if (*recvbuf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			memcpy(*recvbuf, rbuf, apdu.resplen); /* copy tag too */
		}
		*recvbuflen =  apdu.resplen;
		r = *recvbuflen;
	}

err:
	sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
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
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
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
		if (cp == NULL) {
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
				keydata->exponent = 0;
				for (i = 0; i < taglen;i++)
					keydata->exponent = (keydata->exponent<<8) + tag[i];
			}

			tag = sc_asn1_find_tag(card->ctx, cp, in_len, 0x81, &taglen);
			if (tag != NULL && taglen > 0) {
				keydata->pubkey = malloc(taglen);
				if (keydata->pubkey == NULL)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
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
	if (rbuf)
		free(rbuf);
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
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r,i;
	const u8 *tag;
	size_t taglen;
	const u8 *pix;
	size_t pixlen;
	size_t resplen = sizeof(rbuf);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* first  see if the default application will return a template
	 * that we know about.
	 */

	r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, rbuf, &resplen);
	if (r >= 0 && resplen > 2 ) {
		tag = sc_asn1_find_tag(card->ctx, rbuf, resplen, 0x61, &taglen);
		if (tag != NULL) {
			pix = sc_asn1_find_tag(card->ctx, tag, taglen, 0x4F, &pixlen);
			if (pix != NULL ) {
				sc_log(card->ctx, "found PIX");

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
							LOG_FUNC_RETURN(card->ctx, i);
						} else {
							LOG_FUNC_RETURN(card->ctx, i);
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
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)  {
			if (card->type != 0 && card->type == piv_aids[i].enumtag)
				LOG_FUNC_RETURN(card->ctx, (r < 0)? r: i);
			continue;
		}

		if ( apdu.resplen == 0 && r == 0) {
			/* could be the MSU card */
			continue; /* other cards will return a FCI */
		}

		if (apdu.resp[0] != 0x6f || apdu.resp[1] > apdu.resplen - 2 )
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NO_CARD_SUPPORT);

		LOG_FUNC_RETURN(card->ctx, i);
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
	if (rbuflen > len + sizeof(tagbuf)) {
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
	LOG_FUNC_RETURN(card->ctx, r);
}

/* the tag is the PIV_OBJ_*  */
static int
piv_get_data(sc_card_t * card, int enumtag, u8 **buf, size_t *buf_len)
{
	u8 *p;
	int r = 0;
	u8 tagbuf[8];
	size_t tag_len;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, "#%d", enumtag);

	r = sc_lock(card); /* do check len and get data in same transaction */
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "sc_lock failed");
		return r;
	}

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

		sc_log(card->ctx, "get len of #%d", enumtag);
		rbuf = rbufinitbuf;
		rbuflen = sizeof(rbufinitbuf);
		r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf, &rbuf, &rbuflen);
		if (r > 0) {
			int r_tag;
			body = rbuf;
			r_tag = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out, &bodylen);
			if ((r_tag != SC_SUCCESS && r_tag != SC_ERROR_ASN1_END_OF_CONTENTS)
					|| body == NULL) {
				sc_log(card->ctx, "r_tag:%d body:%p", r_tag, body);
				r = SC_ERROR_FILE_NOT_FOUND;
				goto err;
			}
			*buf_len = (body - rbuf) + bodylen;
		} else if ( r == 0 ) {
			r = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		} else {
			goto err;
		}
	}

	sc_log(card->ctx,
	       "buffer for #%d *buf=0x%p len=%"SC_FORMAT_LEN_SIZE_T"u",
	       enumtag, *buf, *buf_len);
	if (*buf == NULL && *buf_len > 0) {
		if (*buf_len > PIV_MAX_FILE_SIZE) {
			goto err;
		}
		*buf = malloc(*buf_len);
		if (*buf == NULL ) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}

	r = piv_general_io(card, 0xCB, 0x3F, 0xFF, tagbuf,  p - tagbuf, buf, buf_len);

err:
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
	sc_log(card->ctx, "#%d", enumtag);

	assert(enumtag >= 0 && enumtag < PIV_OBJ_LAST_ENUM);

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
		r = *buf_len;
		goto ok;
	}

	/*
	 * If we know it can not be on the card  i.e. History object
	 * has been read, and we know what other certs may or
	 * may not be on the card. We can avoid extra overhead
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
		} else if ( r < 0) {
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

	/* if already cached */
	if (priv->obj_cache[enumtag].internal_obj_data && priv->obj_cache[enumtag].internal_obj_len) {
		sc_log(card->ctx,
		       "#%d found internal %p:%"SC_FORMAT_LEN_SIZE_T"u",
		       enumtag,
		       priv->obj_cache[enumtag].internal_obj_data,
		       priv->obj_cache[enumtag].internal_obj_len);
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	body = sc_asn1_find_tag(card->ctx,
			priv->obj_cache[enumtag].obj_data,
			priv->obj_cache[enumtag].obj_len,
			0x53, &bodylen);

	if (body == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

	/* get the certificate out */
	 if (piv_objects[enumtag].flags & PIV_OBJECT_TYPE_CERT) {

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x71, &taglen);
		/* 800-72-1 not clear if this is 80 or 01 Sent comment to NIST for 800-72-2 */
		/* 800-73-3 says it is 01, keep dual test so old cards still work */
		if (tag && (((*tag) & 0x80) || ((*tag) & 0x01)))
			compressed = 1;

		tag = sc_asn1_find_tag(card->ctx, body, bodylen, 0x70, &taglen);
		if (tag == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

		if (taglen == 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_NOT_FOUND);

		if(compressed) {
#ifdef ENABLE_ZLIB
			size_t len;
			u8* newBuf = NULL;

			if(SC_SUCCESS != sc_decompress_alloc(&newBuf, &len, tag, taglen, COMPRESSION_AUTO))
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);

			priv->obj_cache[enumtag].internal_obj_data = newBuf;
			priv->obj_cache[enumtag].internal_obj_len = len;
#else
			sc_log(card->ctx, "PIV compression not supported, no zlib");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
#endif
		}
		else {
			if (!(priv->obj_cache[enumtag].internal_obj_data = malloc(taglen)))
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

			memcpy(priv->obj_cache[enumtag].internal_obj_data, tag, taglen);
			priv->obj_cache[enumtag].internal_obj_len = taglen;
		}

	/* convert pub key to internal */
/* TODO: -DEE need to fix ...  would only be used if we cache the pub key, but we don't today */
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
piv_read_binary(sc_card_t *card, unsigned int idx, unsigned char *buf, size_t count, unsigned long flags)
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
	sbuflen = put_tag_and_len(0x5c, tag_len, NULL) + buf_len;
	if (!(sbuf = malloc(sbuflen)))
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	p = sbuf;
	put_tag_and_len(0x5c, tag_len, &p);
	memcpy(p, piv_objects[tag].tag_value, tag_len);
	p += tag_len;

	memcpy(p, buf, buf_len);
	p += buf_len;

	r = piv_general_io(card, 0xDB, 0x3F, 0xFF, sbuf, p - sbuf, NULL, NULL);

	if (sbuf)
		free(sbuf);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_write_certificate(sc_card_t *card, const u8* buf, size_t count, unsigned long flags)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int enumtag;
	int r = SC_SUCCESS;
	u8 *sbuf = NULL;
	u8 *p;
	size_t sbuflen;
	size_t taglen;

	taglen = put_tag_and_len(0x70, count, NULL)
		+ put_tag_and_len(0x71, 1, NULL)
		+ put_tag_and_len(0xFE, 0, NULL);

	sbuflen =  put_tag_and_len(0x53, taglen, NULL);

	sbuf = malloc(sbuflen);
	if (sbuf == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	p = sbuf;
	put_tag_and_len(0x53, taglen, &p);

	put_tag_and_len(0x70, count, &p);
	memcpy(p, buf, count);
	p += count;
	put_tag_and_len(0x71, 1, &p);
	/* Use 01 as per NIST 800-73-3 */
	*p++ = (flags)? 0x01:0x00; /* certinfo, i.e. gzipped? */
	put_tag_and_len(0xFE,0,&p); /* LRC tag */

	enumtag = piv_objects[priv->selected_obj].enumtag;
	r = piv_put_data(card, enumtag, sbuf, sbuflen);
	if (sbuf)
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
		LOG_FUNC_RETURN(card->ctx, count);

	priv-> rwb_state = 1; /* at end of object */

	switch (flags & 0x0f) {
		case 1:
			r = piv_write_certificate(card, priv->w_buf, priv->w_buf_len, flags & 0x10);
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
	LOG_FUNC_RETURN(card->ctx, (r < 0)? r : (int)count);
}

/*
 * Card initialization is NOT standard.
 * Some cards use mutual or external authentication using 3des or aes key. We
 * will read in the key from a file either binary or hex encoded.
 * This is only needed during initialization/personalization of the card
 */

#ifdef ENABLE_OPENSSL
static const EVP_CIPHER *get_cipher_for_algo(int alg_id)
{
	switch (alg_id) {
		case 0x0: return EVP_des_ede3_ecb();
		case 0x1: return EVP_des_ede3_ecb(); /* 2TDES */
		case 0x3: return EVP_des_ede3_ecb();
		case 0x8: return EVP_aes_128_ecb();
		case 0xA: return EVP_aes_192_ecb();
		case 0xC: return EVP_aes_256_ecb();
		default: return NULL;
	}
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
	u8  *rbuf = NULL;
	size_t rbuflen;
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
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	cipher = get_cipher_for_algo(alg_id);
	if(!cipher) {
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
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen);

 	if (r < 0) goto err;

	/* Remove the encompassing outer TLV of 0x7C and get the data */
	body = sc_asn1_find_tag(card->ctx, rbuf,
		r, 0x7C, &body_len);
	if (!body) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Invalid Witness Data response of NULL\n");
		r =  SC_ERROR_INVALID_DATA;
		goto err;
	}

	/* Get the witness data indicated by the TAG 0x80 */
	witness_data = sc_asn1_find_tag(card->ctx, body,
		body_len, 0x80, &witness_len);
	if (!witness_len) {
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
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);

	p = plain_text;
	if (!EVP_DecryptUpdate(ctx, p, &N, witness_data, witness_len)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	plain_text_len = tmplen = N;
	p += tmplen;

	if(!EVP_DecryptFinal(ctx, p, &N)) {
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

	r = RAND_bytes(nonce, witness_len);
	if(!r) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
			 "Generating random for nonce (%"SC_FORMAT_LEN_SIZE_T"u : %"SC_FORMAT_LEN_SIZE_T"u)\n",
			 witness_len, plain_text_len);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* nonce for challenge */
	tmplen = put_tag_and_len(0x81, witness_len, NULL);

	/* plain text witness keep a length separate for the 0x7C tag */
	tmplen += put_tag_and_len(0x80, witness_len, NULL);
	tmplen2 = tmplen;

	/* outside 7C tag with 81:80 as innards */
	tmplen = put_tag_and_len(0x7C, tmplen, NULL);

	built_len = tmplen;

	/* Build the response buffer */
	p = built = malloc(built_len);
	if(!built) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "OOM Building witness response and challenge\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = built;

	/* Start with the 7C Tag */
	put_tag_and_len(0x7C, tmplen2, &p);

	/* Add the DECRYPTED witness, tag 0x80 */
	put_tag_and_len(0x80, witness_len, &p);
	memcpy(p, plain_text, witness_len);
	p += witness_len;

	/* Add the challenge, tag 0x81 */
	put_tag_and_len(0x81, witness_len, &p);
	memcpy(p, nonce, witness_len);

	/* Don't leak rbuf from above */
	free(rbuf);
	rbuf = NULL;

	/* Send constructed data */
	r = piv_general_io(card, 0x87, alg_id, key_ref, built,built_len, &rbuf, &rbuflen);
 	if (r < 0) goto err;

	/* Remove the encompassing outer TLV of 0x7C and get the data */
	body = sc_asn1_find_tag(card->ctx, rbuf,
		r, 0x7C, &body_len);
	if(!body) {
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

	EVP_CIPHER_CTX_cleanup(ctx);

	if (!EVP_DecryptInit(ctx, cipher, key, NULL)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	EVP_CIPHER_CTX_set_padding(ctx,0);

	tmp = decrypted_reponse;
	if (!EVP_DecryptUpdate(ctx, tmp, &N, challenge_response, challenge_response_len)) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	decrypted_reponse_len = tmplen = N;
	tmp += tmplen;

	if(!EVP_DecryptFinal(ctx, tmp, &N)) {
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
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	if (locked)
		sc_unlock(card);
	if (rbuf)
		free(rbuf);
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
	int tmplen;
	int outlen;
	int locked = 0;
	u8 *p;
	u8 *rbuf = NULL;
	u8 *key = NULL;
	u8 *cypher_text = NULL;
	u8 *output_buf = NULL;
	const u8 *body = NULL;
	const u8 *challenge_data = NULL;
	size_t rbuflen;
	size_t body_len;
	size_t output_len;
	size_t challenge_len;
	size_t keylen = 0;
	size_t cypher_text_len = 0;
	u8 sbuf[255];
	EVP_CIPHER_CTX * ctx = NULL;
	const EVP_CIPHER *cipher;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
	    r = SC_ERROR_OUT_OF_MEMORY;
	    goto err;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Selected cipher for algorithm id: %02x\n", alg_id);

	cipher = get_cipher_for_algo(alg_id);
	if(!cipher) {
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
	r = piv_general_io(card, 0x87, alg_id, key_ref, sbuf, p - sbuf, &rbuf, &rbuflen);
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
	if (!body) {
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

	/* Store this to sanity check that plaintext length and cyphertext lengths match */
	/* TODO is this required */
	tmplen = challenge_len;

	/* Encrypt the challenge with the secret */
	if (!EVP_EncryptInit(ctx, cipher, key, NULL)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Encrypt fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	cypher_text = malloc(challenge_len);
	if (!cypher_text) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not allocate buffer for cipher text\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	EVP_CIPHER_CTX_set_padding(ctx,0);
	if (!EVP_EncryptUpdate(ctx, cypher_text, &outlen, challenge_data, challenge_len)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Encrypt update fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	cypher_text_len += outlen;

	if (!EVP_EncryptFinal(ctx, cypher_text + cypher_text_len, &outlen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Final fail\n");
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	cypher_text_len += outlen;

	/*
	 * Actually perform the sanity check on lengths plaintext length vs
	 * encrypted length
	 */
	if (cypher_text_len != (size_t)tmplen) {
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
	tmplen = put_tag_and_len(0x82, cypher_text_len, NULL);

	tmplen = put_tag_and_len(0x7C, tmplen, &p);

	/* Build the 0x82 TLV and append to the 7C<len> tag */
	tmplen += put_tag_and_len(0x82, cypher_text_len, &p);

	memcpy(p, cypher_text, cypher_text_len);
	p += cypher_text_len;
	tmplen += cypher_text_len;

	/* Sanity check the lengths again */
	if(output_len != (size_t)tmplen) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Allocated and computed lengths do not match! "
			 "Expected %"SC_FORMAT_LEN_SIZE_T"d, found: %d\n", output_len, tmplen);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = piv_general_io(card, 0x87, alg_id, key_ref, output_buf, output_len, NULL, NULL);
	sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Got response  challenge\n");

err:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	if (locked)
		sc_unlock(card);

	if (key) {
		sc_mem_clear(key, keylen);
		free(key);
	}

	if (rbuf)
		free(rbuf);

	if (cypher_text)
		free(cypher_text);

	if (output_buf)
		free(output_buf);
#else
	sc_log(card->ctx, "OpenSSL Required");
	r = SC_ERROR_NOT_SUPPORTED;
#endif /* ENABLE_OPENSSL */

	LOG_FUNC_RETURN(card->ctx, r);
}


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
		if (body != NULL && bodylen != 0) {
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
static int piv_get_pin_preference(sc_card_t *card, int *ptr)
{
	piv_private_data_t * priv = PIV_DATA(card);

	*ptr = priv->pin_preference;
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
	u8 *rbuf = NULL;
	const u8 *p;
	size_t rbuf_len = 0, out_len = 0;
	int r;
	unsigned int tag, cla;
	piv_private_data_t * priv = PIV_DATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (priv->card_issues & CI_NO_RANDOM) {
		r = SC_ERROR_NOT_SUPPORTED;
		LOG_TEST_GOTO_ERR(card->ctx, r, "No support for random data");
	}

	/* NIST 800-73-3 says use 9B, previous verisons used 00 */
	r = piv_general_io(card, 0x87, 0x00, 0x9B, sbuf, sizeof sbuf, &rbuf, &rbuf_len);
	/*
	 * piv_get_challenge is called in a loop.
	 * some cards may allow 1 challenge expecting it to be part of
	 * NIST 800-73-3 part 2 "Authentication of PIV Card Application Administrator"
	 * and return "6A 80" if last command was a get_challenge.
	 * Now that the card returned error, we can try one more time.
	 */
	 if (r == SC_ERROR_INCORRECT_PARAMETERS) {
		if (rbuf)
			free(rbuf);
		rbuf_len = 0;
		r = piv_general_io(card, 0x87, 0x00, 0x9B, sbuf, sizeof sbuf, &rbuf, &rbuf_len);
		if (r == SC_ERROR_INCORRECT_PARAMETERS) {
			r = SC_ERROR_NOT_SUPPORTED;
		}
	}
	LOG_TEST_GOTO_ERR(card->ctx, r, "GENERAL AUTHENTICATE failed");

	p = rbuf;
	r = sc_asn1_read_tag(&p, rbuf_len, &cla, &tag, &out_len);
	if (r < 0 || (cla|tag) != 0x7C) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find Dynamic Authentication Template");
	}

	rbuf_len = out_len;
	r = sc_asn1_read_tag(&p, rbuf_len, &cla, &tag, &out_len);
	if (r < 0 || (cla|tag) != 0x81) {
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_DATA, "Can't find Challenge");
	}

	if (len < out_len) {
		out_len = len;
	}
	memcpy(rnd, p, out_len);

	r = (int) out_len;

err:
	free(rbuf);

	LOG_FUNC_RETURN(card->ctx, r);

}

static int
piv_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx,
	       "flags=%08lx op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%"SC_FORMAT_LEN_SIZE_T"u",
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
	int r;
	u8 *p;
	const u8 *tag;
	size_t taglen;
	const u8 *body;
	size_t bodylen;
	unsigned int real_alg_id;

	u8 sbuf[4096]; /* needs work. for 3072 keys, needs 384+10 or so */
	u8 *rbuf = NULL;
	size_t rbuflen = 0;

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
			sbuf, p - sbuf, &rbuf, &rbuflen);

	if (r >= 0) {
		body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x7c, &bodylen);
		if (body) {
			tag = sc_asn1_find_tag(card->ctx, body,  bodylen, 0x82, &taglen);
			if (tag) {
				memcpy(out, tag, taglen);
				r = taglen;
			} else
				r = SC_ERROR_INVALID_DATA;
		} else
			r = SC_ERROR_INVALID_DATA;
	}

	if (rbuf)
		free(rbuf);

	LOG_FUNC_RETURN(card->ctx, r);
}


static int
piv_compute_signature(sc_card_t *card, const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int r;
	int i;
	size_t nLen;
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
			sc_log(card->ctx,
			       " output too small for EC signature %"SC_FORMAT_LEN_SIZE_T"u < %"SC_FORMAT_LEN_SIZE_T"u",
			       outlen, 2 * nLen);
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
		memset(out, 0, outlen);

		r = piv_validate_general_authentication(card, data, datalen, rbuf, rbuflen);
		if (r < 0)
			goto err;

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
	int pathlen;
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
		if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS) {
			sc_log(card->ctx, "DER problem %d",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

		sc_log(card->ctx,
				"Discovery 0x%2.2x 0x%2.2x %p:%"SC_FORMAT_LEN_SIZE_T"u",
				cla_out, tag_out, body, bodylen);
		if ( cla_out+tag_out == 0x7E && body != NULL && bodylen != 0) {
			aidlen = 0;
			aid = sc_asn1_find_tag(card->ctx, body, bodylen, 0x4F, &aidlen);
			if (aid == NULL || aidlen < piv_aids[0].len_short ||
				memcmp(aid,piv_aids[0].value,piv_aids[0].len_short) != 0) { /*TODO look at long */
				sc_log(card->ctx, "Discovery object not PIV");
				r = SC_ERROR_INVALID_CARD; /* This is an error */
				goto err;
			}
			if (aid_only == 0) {
				pinp = sc_asn1_find_tag(card->ctx, body, bodylen, 0x5F2F, &pinplen);
				if (pinp && pinplen == 2) {
					sc_log(card->ctx, "Discovery pinp flags=0x%2.2x 0x%2.2x",*pinp, *(pinp+1));
					r = SC_SUCCESS;
					if (*pinp == 0x60 && *(pinp+1) == 0x20) { /* use Global pin */
						sc_log(card->ctx, "Pin Preference - Global");
						priv->pin_preference = 0x00;
					}
				}
			}
		}
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
 * We read teh CCC using the PIV API.
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
	if ((r = sc_asn1_read_tag(&body, rbuflen, &cla_out, &tag_out,  &bodylen)) != SC_SUCCESS) {
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
	u8  rbuf[256];
	size_t rbuflen = sizeof(rbuf);
	u8 * arbuf = rbuf;
	piv_private_data_t * priv = PIV_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/*
	 * During piv_match or piv_card_reader_lock_obtained,
	 * we use the discovery object to test if card present, and 
	 * if PIV AID is active. So we can not use the cache
	 */

	/* If not valid, read, cache and test */
	if (!(priv->obj_cache[PIV_OBJ_DISCOVERY].flags & PIV_OBJ_CACHE_VALID)) {
		r = piv_process_discovery(card);
	} else {
		/* if already in cache,force read */
		r = piv_get_data(card, PIV_OBJ_DISCOVERY, &arbuf, &rbuflen);
		if (r >= 0)
			/* make sure it is PIV AID */
			r = piv_parse_discovery(card, rbuf, rbuflen, 1);
	}

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
			sc_log(card->ctx, "DER problem %d",r);
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}

		if ( cla_out+tag_out == 0x53 && body != NULL && bodylen != 0) {
			numlen = 0;
			num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC1, &numlen);
			if (num) {
				if (numlen != 1 || *num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INTERNAL; /* TODO some other error */
					goto err;
				}

				priv->keysWithOnCardCerts = *num;
			}

			numlen = 0;
			num = sc_asn1_find_tag(card->ctx, body, bodylen, 0xC2, &numlen);
			if (num) {
				if (numlen != 1 || *num > PIV_OBJ_RETIRED_X509_20-PIV_OBJ_RETIRED_X509_1+1) {
					r = SC_ERROR_INTERNAL; /* TODO some other error */
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
		if (sc_asn1_read_tag(&body, ocfhflen, &cla_out,
					&tag_out, &bodylen) != SC_SUCCESS
				|| cla_out+tag_out != 0x30) {
			sc_log(card->ctx, "DER problem");
			r = SC_ERROR_INVALID_ASN1_OBJECT;
			goto err;
		}
		seq = body;
		while (bodylen > 0) {
			seqtag = seq;
			if (sc_asn1_read_tag(&seq, bodylen, &cla_out,
						&tag_out, &seqlen) != SC_SUCCESS
					|| cla_out+tag_out != 0x30) {
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
			sc_log(card->ctx, "got internal r=%d",r);

			certobj = NULL;

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
piv_finish(sc_card_t *card)
{
	piv_private_data_t * priv = PIV_DATA(card);
	int i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (priv) {
		if (priv->w_buf)
			free(priv->w_buf);
		if (priv->offCardCertURL)
			free(priv->offCardCertURL);
		for (i = 0; i < PIV_OBJ_LAST_ENUM - 1; i++) {
			if (priv->obj_cache[i].obj_data)
				free(priv->obj_cache[i].obj_data);
			if (priv->obj_cache[i].internal_obj_data)
				free(priv->obj_cache[i].internal_obj_data);
		}
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
	/* user provide card type must be one we know */
	switch (card->type) {
		case -1:
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
			break;
		default:
			return 0; /* can not handle the card */
	}
	/* its one we know, or we can test for it in piv_init */
	/* 
	 * We will call piv_match_card_continued here then 
	 * again in piv_init to avoid any issues with passing
	 * anything from piv_match_card
	 * to piv_init as had been done in the past
	 */
	r = piv_match_card_continued(card);
	if (r == 1) {
		/* clean up what we left in card */
		sc_unlock(card);
		piv_finish(card);
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d r:%d\n", card->type,r);
	return r;
}


static int piv_match_card_continued(sc_card_t *card)
{
	int i, r = 0;
	int type  = -1;
	piv_private_data_t *priv = NULL;
	int saved_type = card->type;

	/* Since we send an APDU, the card's logout function may be called...
	 * however it may be in dirty memory */
	card->ops->logout = NULL;

	/* piv_match_card may be called with card->type, set by opensc.conf */
	/* user provide card type must be one we know */
	switch (card->type) {
		case -1:
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
			type = card->type;
			break;
		default:
			return 0; /* can not handle the card */
	}
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d type:%d r:%d\n", card->type, type, r);
	if (type == -1) {

		/*
		 *try to identify card by ATR or historical data in ATR
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
			else if (card->reader->atr_info.hist_bytes_len > 0
					&& card->reader->atr_info.hist_bytes[0] == 0x80u) { /* compact TLV */
				size_t datalen;
				const u8 *data = sc_compacttlv_find_tag(card->reader->atr_info.hist_bytes + 1,
									card->reader->atr_info.hist_bytes_len - 1,
									0xF0, &datalen);

				if (data != NULL) {
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
				type = SC_CARD_TYPE_PIV_II_GENERIC; /* may still be CAC with PIV Endpoint */
		}
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d type:%d r:%d\n", card->type, type, r);
	/* allocate and init basic fields */

	priv = calloc(1, sizeof(piv_private_data_t));

	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	if (card->type == -1)
		card->type = type;

	card->drv_data = priv; /* will free if no match, or pass on to piv_init */
	priv->selected_obj = -1;
	priv->pin_preference = 0x80; /* 800-73-3 part 1, table 3 */
	/* TODO Dual CAC/PIV are bases on 800-73-1 where priv->pin_preference = 0. need to check later */
	priv->logged_in = SC_PIN_STATE_UNKNOWN;
	priv->tries_left = 10; /* will assume OK at start */
	priv->pstate = PIV_STATE_MATCH;

	/* Some objects will only be present if History object says so */
	for (i=0; i < PIV_OBJ_LAST_ENUM -1; i++)
		if(piv_objects[i].flags & PIV_OBJECT_NOT_PRESENT)
			priv->obj_cache[i].flags |= PIV_OBJ_CACHE_NOT_PRESENT;

	r = sc_lock(card);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "sc_lock failed\n");
		piv_finish(card);
		card->type = saved_type;
		return 0;
	}

	/*
	 * Detect if active AID is PIV. NIST 800-73 says only one PIV application per card
	 * and PIV must be the default application.
	 * Try to avoid doing a select_aid and losing the login state on some cards.
	 * We may get interference on some cards by other drivers trying SELECT_AID before
	 * we get to see if PIV application is still active
	 * putting PIV driver first might help. 
	 * This may fail if the wrong AID is active.
	 * Discovery Object introduced in 800-73-3 so will return 0 if found and PIV applet active.
	 * Will fail with SC_ERROR_FILE_NOT_FOUND if 800-73-3 and no Discovery object.
	 * But some other card could also return SC_ERROR_FILE_NOT_FOUND.
	 * Will fail for other reasons if wrong applet is selected, or bad PIV implimentation. 
	 */
	
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d CI:%08x r:%d\n", card->type,  priv->card_issues, r);
	if (priv->card_issues & CI_DISCOVERY_USELESS) /* TODO may be in wrong place */
		i = -1;
	else
		i = piv_find_discovery(card);

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i:%d CI:%08x r:%d\n", card->type, i, priv->card_issues, r);
	if (i < 0) {
		/* Detect by selecting applet */
		i = piv_find_aid(card);
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i:%d CI:%08x r:%d\n", card->type, i, priv->card_issues, r);
	if (i >= 0) {
		int iccc = 0;
		 /* We now know PIV AID is active, test CCC object  800-73-* say CCC is required */
		switch (card->type)  {
			/*
			 * For cards that may also be CAC, try and read the CCC
			 * CCC is required and all Dual PIV/CAC will have a CCC
			 * Currently Dual PIV/CAC are based on NIST 800-73-1 which does not have Discovery or History
			 */
			case SC_CARD_TYPE_PIV_II_GENERIC: /* i.e. really dont know what this is */
			case SC_CARD_TYPE_PIV_II_HIST:
			case SC_CARD_TYPE_PIV_II_GI_DE:
			case SC_CARD_TYPE_PIV_II_GEMALTO:
			case SC_CARD_TYPE_PIV_II_OBERTHUR:
				iccc = piv_process_ccc(card);
				sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d iccc:%d ccc_flags:%08x CI:%08x r:%d\n",
						card->type, iccc, priv->ccc_flags, priv->card_issues, r);
				/* ignore an error? */
				/* if CCC says it has CAC with PKI on card set to one of the SC_CARD_TYPE_PIV_II_*_DUAL_CAC */
				if (priv->ccc_flags & PIV_CCC_F3_CAC_PKI) {
					switch (card->type)  {
						case SC_CARD_TYPE_PIV_II_GENERIC:
						case SC_CARD_TYPE_PIV_II_HIST:
						case SC_CARD_TYPE_PIV_II_GI_DE:
						    card->type = SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC;
						    priv->card_issues |= CI_DISCOVERY_USELESS;
						    priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
						    break;
						case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
						case SC_CARD_TYPE_PIV_II_GEMALTO:
							card->type = SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC;
							priv->card_issues |= CI_DISCOVERY_USELESS;
							priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
							break;
						case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
						case SC_CARD_TYPE_PIV_II_OBERTHUR:
							card->type =  SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC;
							priv->card_issues |= CI_DISCOVERY_USELESS;
							priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
							break;
					}
				}
				break;

				/* if user forced it to be one of the CAC types, assume it is CAC */
			case SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC:
			case SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC:
			case SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC:
				priv->card_issues |= CI_DISCOVERY_USELESS;
				priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
				break;
			}
		}
	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i:%d CI:%08x r:%d\n", card->type, i, priv->card_issues, r);
	if (i >= 0 && (priv->card_issues & CI_DISCOVERY_USELESS) == 0) {
		/*
		 * We now know PIV AID is active, test DISCOVERY object again 
		 * Some PIV don't support DISCOVERY and return 
		 * SC_ERROR_INCORRECT_PARAMETERS. Any error 
		 * including SC_ERROR_FILE_NOT_FOUND means we cannot use discovery 
		 * to test for active AID.
		 */
		int i7e = piv_find_discovery(card);

		sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i7e:%d CI:%08x r:%d\n", card->type, i7e, priv->card_issues, r);
		if (i7e < 0) {
			priv->card_issues |= CI_DISCOVERY_USELESS;
			priv->obj_cache[PIV_OBJ_DISCOVERY].flags |= PIV_OBJ_CACHE_NOT_PRESENT;
		}
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i:%d CI:%08x r:%d\n", card->type, i, priv->card_issues, r);
	if (i < 0) {
		/* don't match. Does not have a PIV applet. */
		sc_unlock(card);
		piv_finish(card);
		card->type = saved_type;
		return 0;
	}

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d i:%d CI:%08x r:%d\n", card->type, i, priv->card_issues, r);
	/* Matched, caller will use or free priv and sc_lock as needed */
	priv->pstate=PIV_STATE_INIT;
	return 1; /* match */
}


static int piv_init(sc_card_t *card)
{
	int r = 0;
	piv_private_data_t * priv = NULL;
	sc_apdu_t apdu;
	unsigned long flags;
	unsigned long ext_flags;
	u8 yubico_version_buf[3];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* continue the matching get a lock and the priv */
	r = piv_match_card_continued(card);
	if (r != 1)  {
		sc_log(card->ctx,"piv_match_card_continued failed card->type:%d", card->type);
		piv_finish(card);
		/* tell sc_connect_card to try other drivers */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}
		
	priv = PIV_DATA(card);

	/* can not force the PIV driver to use non-PIV cards as tested in piv_card_match_continued */
	if (!priv || card->type == -1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);

	sc_log(card->ctx,
	       "Max send = %"SC_FORMAT_LEN_SIZE_T"u recv = %"SC_FORMAT_LEN_SIZE_T"u card->type = %d",
	       card->max_send_size, card->max_recv_size, card->type);
	card->cla = 0x00;
	if(card->name == NULL)
		card->name = card->driver->name;

	/*
	 * Set card_issues based on card type either set by piv_match_card or by opensc.conf
	 */

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d CI:%08x r:%d\n", card->type, priv->card_issues, r);
	switch(card->type) {
		case SC_CARD_TYPE_PIV_II_NEO:
		case SC_CARD_TYPE_PIV_II_YUBIKEY4:
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xFD, 0x00, 0x00);
			apdu.lc = 0;
			apdu.data = NULL;
			apdu.datalen = 0;
			apdu.resp = yubico_version_buf;
			apdu.resplen = sizeof(yubico_version_buf);
			apdu.le = apdu.resplen;
			r = sc_transmit_apdu(card, &apdu);
			priv->yubico_version = (yubico_version_buf[0]<<16) | (yubico_version_buf[1] <<8) | yubico_version_buf[2];
			sc_log(card->ctx, "Yubico card->type=%d, r=0x%08x version=0x%08x", card->type, r, priv->yubico_version);
			break;
	}

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
			priv->card_issues |= 0; /* could add others here */
			break;

		case SC_CARD_TYPE_PIV_II_HIST:
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
			/* TODO may need more research */
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

	sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH card->type:%d CI:%08x r:%d\n", card->type, priv->card_issues, r);

	priv->enumtag = piv_aids[0].enumtag;

	/* PKCS#11 may try to generate session keys, and get confused
	 * if SC_ALGORITHM_ONBOARD_KEY_GEN is present
	 * piv-tool can still do this, just don't tell PKCS#11
	 */

	 flags = SC_ALGORITHM_RSA_RAW;

	_sc_card_add_rsa_alg(card, 1024, flags, 0); /* mandatory */
	_sc_card_add_rsa_alg(card, 2048, flags, 0); /* optional */
	_sc_card_add_rsa_alg(card, 3072, flags, 0); /* optional */

	if (!(priv->card_issues & CI_NO_EC)) {
		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

		_sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
		if (!(priv->card_issues & CI_NO_EC384))
			_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);
	}

	if (!(priv->card_issues & CI_NO_RANDOM))
		card->caps |= SC_CARD_CAP_RNG;

	/* May turn off SC_CARD_CAP_ISO7816_PIN_INFO later */
	card->caps |=  SC_CARD_CAP_ISO7816_PIN_INFO;

	/*
	 * 800-73-3 cards may have a history object and/or a discovery object
	 * We want to process them now as this has information on what
	 * keys and certs the card has and how the pin might be used.
	 * If they fail, ignore it there are optional and introduced in
	 * NIST 800-73-3 and NIST 800-73-2 so some older cards may 
	 * not handle the request.
	 */
	piv_process_history(card);

	piv_process_discovery(card);

	priv->pstate=PIV_STATE_NORMAL;
	sc_unlock(card) ; /* obtained in piv_match */
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int piv_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	int r;
	piv_private_data_t * priv = PIV_DATA(card);

	/* may be called before piv_init  has allocated priv */
	if (priv) {
		/* need to save sw1 and sw2 if trying to determine card_state from pin_cmd */
		if (priv->pin_cmd_verify) {
			priv->pin_cmd_verify_sw1 = sw1;
			priv->pin_cmd_verify_sw2 = sw2;
		} else {
			/* a command has completed and it is not verify */
			/* If we are in a context_specific sequence, unlock */
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
	int r = SC_ERROR_NOT_SUPPORTED; /* TODO Some PIV cards may support a logout */
	/* piv_private_data_t * priv = PIV_DATA(card); */

	LOG_FUNC_CALLED(card->ctx);

	/* TODO 800-73-3 does not define a logout, 800-73-4 does */

	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * Called when a sc_lock gets a reader lock and PCSC SCardBeginTransaction
 * If SCardBeginTransaction may pass back tha a card reset was seen since
 * the last transaction  completed.
 * There may have been one or more resets, by other card drivers in different
 * processes, and they may have taken action already
 * and changed the AID and or may have sent a  VERIFY with PIN
 * So test the state of the card.
 * this is very similar to what the piv_match routine does,
 */

static int piv_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	int r = 0;
	u8 temp[256];
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

	/* make sure our application is active */

	/* first see if AID is active AID by reading discovery object '7E' */
	/* If not try selecting AID */

	/* but if card does not support DISCOVERY object we can not use it */
	if (priv->card_issues & CI_DISCOVERY_USELESS) {
	    r =  SC_ERROR_NO_CARD_SUPPORT;
	} else {
	    r = piv_find_discovery(card);
	    sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH piv_find_discovery card->type:%d r:%d\n", card->type, r);
	}

	if (r < 0) {
		if (was_reset > 0 || !(priv->card_issues & CI_PIV_AID_LOSE_STATE)) {
			r = piv_select_aid(card, piv_aids[0].value, piv_aids[0].len_short, temp, &templen);
			sc_debug(card->ctx,SC_LOG_DEBUG_MATCH, "PIV_MATCH piv_select_aid card->type:%d r:%d\n", card->type, r);
		} else {
			r = 0; /* cant do anything with this card, hope there was no interference */
		}
	}

	if (r < 0) /* bad error return will show up in sc_lock as error*/
		goto err;
	
	if (was_reset > 0)
		priv->logged_in =  SC_PIN_STATE_UNKNOWN;

	r = 0;

err:
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


#if 1
struct sc_card_driver * sc_get_piv_driver(void)
{
	return sc_get_driver();
}
#endif

