/*
 * partial PKCS15 emulation for PIV-II cards
 * only minimal use of the authentication cert and key
 *
 * Copyright (C) 2005, Douglas E. Engert <deengert@anl.gov> 
 *               2004, Nils Larsch <larsch@trustcenter.de>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <opensc/pkcs15.h>
#include <opensc/log.h>
#include <opensc/cardctl.h>
#include <opensc/cards.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MANU_ID		"piv_II "

int sc_pkcs15emu_piv_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);


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

	

#define USAGE_NONREP	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
			SC_PKCS15_PRKEY_USAGE_DECRYPT | \
			SC_PKCS15_PRKEY_USAGE_WRAP    | \
			SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
			SC_PKCS15_PRKEY_USAGE_SIGN



static int piv_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, 1);
	if (card->type < SC_CARD_TYPE_PIV_II_GENERIC
		|| card->type >= SC_CARD_TYPE_PIV_II_GENERIC+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

static int sc_pkcs15emu_piv_init(sc_pkcs15_card_t *p15card)
{
	const objdata objects[] = {
		{"1", "Card Capability Container", 
				"2.16.840.1.101.3.7.1.219.0", 0, "DB00", 0},
		{"2", "Card Holder Unique Identifier",
				"2.16.840.1.101.3.7.2.48.0", 0 , "3000", 0},
		{"3", "Card Holder Fingerprint I",
				"2.16.840.1.101.3.7.2.96.16", 0, "6010", SC_PKCS15_CO_FLAG_PRIVATE},
		{"4", "Card Holder Fingerprint II",
				"2.16.840.1.101.3.7.2.96.17", 0, "6011", SC_PKCS15_CO_FLAG_PRIVATE},
		{"5", "Printed Information",
				"2.16.840.1.101.3.7.2.48.1", 0, "3001", SC_PKCS15_CO_FLAG_PRIVATE},
		{"6", "Card Holder Facial Image", 
				"2.16.840.1.101.3.7.2.96.48", 0, "6030", SC_PKCS15_CO_FLAG_PRIVATE},
		{"7", "Security Object",
				"2.16.840.1.101.3.7.2.144.0", 0, "9000", 0},
		{NULL, NULL, NULL, 0, NULL, 0}
	};

	/* 
	 * NIST 800-73-1 is proposing to lift the restriction on 
	 * requering pin protected certs. Thus the default will be to 
	 * not require this. But there are a number of test cards 
	 * that do enforce it. Code later on will allow SC_PKCS15_CO_FLAG_PRIVATE
	 * to be set. 
	 */
	const cdata certs[] = {
		{"1", "Certificate for PIV Authentication", 0, "0101", 0},
		{"2", "Certificate for Digital Signature", 0, "0100", 0},
		{"3", "Certificate for Key Management", 0, "0102", 0},
		{"4", "Certificate for Card Authentication", 0, "0500", 0},
		{NULL, NULL, 0, NULL, 0}
	};

	const pindata pins[] = {
		{ "1", "PIV Card Holder pin", "", 0x80,
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8, 
		  SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_LOCAL, 
		  -1, 0xFF,
		  SC_PKCS15_CO_FLAG_PRIVATE },
		{ "2", "PIV PUK", "", 0x81, 
		  SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
		  8, 4, 8, 
		  SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
		  SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_SO_PIN |
		  SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN, 
		  -1, 0xFF, 
		  SC_PKCS15_CO_FLAG_PRIVATE },
		/* there are some more key, but dont need for now */
		/* The admin 9b might fall in here */
		{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	};


	/*
	 * The size of the key or the algid is not really known
	 * but can be derived from the certificates. 
	 * DEE need to fix - We will still refer to the "key files" as 06 even of not.
	 * 07 is 2048, 05 is 3072. 
	 */
	const pubdata pubkeys[] = {

		{ "1", "AUTH pubkey", 1024, USAGE_AUT, "9A06", 
		  0x9A, "1", SC_PKCS15_CO_FLAG_PRIVATE},
		{ "2", "SIGN pubkey", 1024, USAGE_AUT, "9C06", 
		  0x9C, "1", SC_PKCS15_CO_FLAG_PRIVATE},
		{ "3", "KEY MAN pubkey", 1024, USAGE_AUT, "9D06", 
		  0x9D, "1", SC_PKCS15_CO_FLAG_PRIVATE},
		{ "4", "ADMIN pubkey", 1024, USAGE_AUT, "9B06", 
		  0x9B, "1", SC_PKCS15_CO_FLAG_PRIVATE},
		{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
		
	};

	const prdata prkeys[] = {
		{ "1", "AUTH key", 1024, USAGE_AUT, "",
		  0x9A, "1", SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_NONE | SC_PKCS15_CO_FLAG_PRIVATE},
		{ "2", " SIGN key", 1024, USAGE_AUT, "",
		  0x9B, "1", SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_NONE | SC_PKCS15_CO_FLAG_PRIVATE},
		{ "3", "KEY MAN key", 1024, USAGE_AUT, "",
		  0x9C, "1", SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_NONE | SC_PKCS15_CO_FLAG_PRIVATE},
		{ "4", "ADMIN key", 1024, USAGE_AUT, "",
		  0x9D, "1", SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_NONE | SC_PKCS15_CO_FLAG_PRIVATE},
		{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
	};

	int    r, i;
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, 1);

	/* could read this off card if needed */

	/* CSP does not like a - in the name */
	p15card->label = strdup("PIV_II");
	p15card->manufacturer_id = strdup(MANU_ID);
	/* get serial number */
	/* We could also use the CCC or CHUID info here */
#if 0
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	r = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	p15card->serial_number = strdup(buf);
#endif
        p15card->serial_number = strdup("9876543210");

	sc_debug(card->ctx, "PIV-II adding objects...");

	/* set other objects */
	for (i = 0; objects[i].label; i++) {
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object    obj_obj;

		memset(&obj_info, 0, sizeof(obj_info));
		memset(&obj_obj, 0, sizeof(obj_obj));
		sc_pkcs15_format_id(objects[i].id, &obj_info.id);
		sc_format_path(objects[i].path, &obj_info.path);
		strncpy(obj_info.app_label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		r = sc_format_oid(&obj_info.app_oid, objects[i].aoid);
		if (r != SC_SUCCESS)
			return r;

		strncpy(obj_obj.label, objects[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		obj_obj.flags = objects[i].obj_flags;
		
		r = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, 
			&obj_obj, &obj_info); 
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, r);
	}

	/* set certs */
	for (i = 0; certs[i].label; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj,  0, sizeof(cert_obj));
	
		sc_pkcs15_format_id(certs[i].id, &cert_info.id);
		cert_info.authority = certs[i].authority;
		sc_format_path(certs[i].path, &cert_info.path);

		strncpy(cert_obj.label, certs[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		cert_obj.flags = certs[i].obj_flags;

		/* Cards based on NIST 800-73 may enforce pin protected certs */
		/* But this is being dropped in 800-73-1 */
		if (card->flags & 0x10) {
			cert_obj.flags |=  SC_PKCS15_CO_FLAG_PRIVATE;
		}

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, r);
	}


	/* set pins */

	for (i = 0; pins[i].label; i++) {
		struct sc_pkcs15_pin_info pin_info;
		struct sc_pkcs15_object   pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		sc_pkcs15_format_id(pins[i].id, &pin_info.auth_id);
		pin_info.reference     = pins[i].ref;
		pin_info.flags         = pins[i].flags;
		pin_info.type          = pins[i].type;
		pin_info.min_length    = pins[i].minlen;
		pin_info.stored_length = pins[i].storedlen;
		pin_info.max_length    = pins[i].maxlen;
		pin_info.pad_char      = pins[i].pad_char;
		sc_format_path(pins[i].path, &pin_info.path);
		pin_info.tries_left    = -1;

		strncpy(pin_obj.label, pins[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags = pins[i].obj_flags;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, r);
	}



	/* set public keys */
	/* We may only need this during initialzation when genkey
	 * gets the pubkey, but it can not be read from the card 
	 * at a later time. The piv-tool can stach in file 
	 */ 

	for (i = 0; pubkeys[i].label; i++) {
		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object     pubkey_obj;

		memset(&pubkey_info, 0, sizeof(pubkey_info));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));

		sc_pkcs15_format_id(pubkeys[i].id, &pubkey_info.id);
		pubkey_info.usage         = pubkeys[i].usage;
		pubkey_info.native        = 1;
		pubkey_info.key_reference = pubkeys[i].ref;
		pubkey_info.modulus_length= pubkeys[i].modulus_len;
		/* we really don't know how many bits or module length,
		 * we will assume 1024 for now 
		 */
		sc_format_path(pubkeys[i].path, &pubkey_info.path);

		strncpy(pubkey_obj.label, pubkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);

		pubkey_obj.flags = pubkeys[i].obj_flags;

		if (pubkeys[i].auth_id)
			sc_pkcs15_format_id(pubkeys[i].auth_id, &pubkey_obj.auth_id);

		r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, r);
	}


	/* set private keys */
	for (i = 0; prkeys[i].label; i++) {
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object     prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		sc_pkcs15_format_id(prkeys[i].id, &prkey_info.id);
		prkey_info.usage         = prkeys[i].usage;
		prkey_info.native        = 1;
		prkey_info.key_reference = prkeys[i].ref;
		prkey_info.modulus_length= prkeys[i].modulus_len;
		/* we really don't know how many bits or module length,
		 * we will assume 1024 for now
		 */
		sc_format_path(prkeys[i].path, &prkey_info.path);

		strncpy(prkey_obj.label, prkeys[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);

		prkey_obj.flags = prkeys[i].obj_flags;

		if (prkeys[i].auth_id)
			sc_pkcs15_format_id(prkeys[i].auth_id, &prkey_obj.auth_id);

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, 1, r);
	}

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

int sc_pkcs15emu_piv_init_ex(sc_pkcs15_card_t *p15card,
				  sc_pkcs15emu_opt_t *opts)
{
	sc_card_t   *card = p15card->card;
	sc_context_t    *ctx = card->ctx;

	SC_FUNC_CALLED(ctx, 1);

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_piv_init(p15card);
	else {
		int r = piv_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_piv_init(p15card);
	}
}
