/*
 * p15card-helper.h: Utility library to assist in PKCS#15 emulation on Non-filesystem cards
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
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

#ifndef P15CARD_HELPER_H
#define P15CARD_HELPER_H

#include "libopensc/pkcs15.h"


#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION | \
			SC_PKCS15_PRKEY_USAGE_SIGN
#define USAGE_DS	SC_PKCS15_PRKEY_USAGE_SIGN
#define USAGE_CRYPTO	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN


typedef struct objdata_st {
	const char *id;
	const char *label;
	const char *aoid;
	int     authority;
	const char *path;
	int         obj_flags;
} objdata;

typedef struct cdata_st {
	const char *id;
	const char *label;
	int	    authority;
	const char *path;
	int         obj_flags;
} cdata;

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int         flags;	
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata; 

typedef struct pubdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} pubdata;

typedef struct prdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int         usage;
	const char *path;
	int         ref;
	const char *auth_id;
	int         obj_flags;
} prdata;

typedef struct keyinfo_st {
	int fileid;
	sc_pkcs15_id_t id;
	unsigned int modulus_len;
	u8 modulus[1024/8];
} keyinfo;

typedef struct p15data_items p15data_items;

typedef int (*cert_load_function)(sc_card_t *card, u8** data, size_t* length, int* shouldFree);
#define CERT_LOAD_FUNCTION(x) int x(sc_card_t *card, u8** data, size_t*length, int *shouldFree)
typedef int (*cert_handle_function)(sc_pkcs15_card_t *p15card, p15data_items* items, const cdata* cert, u8* data, size_t length);
#define CERT_HANDLE_FUNCTION(x) int x(sc_pkcs15_card_t *p15card, p15data_items* items, const cdata* cert, u8* data, size_t length)

struct p15data_items {
	const objdata* objects;
	const cdata* certs;
	const pindata* pins;
	const pubdata* public_keys;
	const prdata* private_keys;
	
	cert_load_function cert_load;
	cert_handle_function cert_handle;
	int cert_continue; /* Continue after cert failure */
	int forced_private; /* Should add all private keys w/o cert-management */
	int forced_public; /* Should add public keys (generally not needed..) */
};

CERT_HANDLE_FUNCTION(default_cert_handle);

int sc_pkcs15emu_initialize_objects(sc_pkcs15_card_t *p15card, p15data_items* items);
int sc_pkcs15emu_initialize_certificates(sc_pkcs15_card_t *p15card, p15data_items* items);
int sc_pkcs15emu_initialize_pins(sc_pkcs15_card_t *p15card, p15data_items *items);
int sc_pkcs15emu_initialize_private_keys(sc_pkcs15_card_t *p15card, p15data_items *items);
int sc_pkcs15emu_initialize_public_keys(sc_pkcs15_card_t *p15card, p15data_items *items);
int sc_pkcs15emu_initialize_all(sc_pkcs15_card_t *p15card, p15data_items *items);

#endif

