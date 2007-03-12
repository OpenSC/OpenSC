/*
 * partial PKCS15 emulation for PIV-II cards
 * only minimal use of the authentication cert and key
 *
 * Copyright (C) 2005, Douglas E. Engert <deengert@anl.gov> 
 *               2004, Nils Larsch <larsch@trustcenter.de>
 *
 * Copyright (C) 2006, Identity Alliance, 
 *               Thomas Harning <thomas.harning@identityalliance.com>
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
#include "strlcpy.h"
#include "p15card-helper.h"

#define MANU_ID		"piv_II "

int sc_pkcs15emu_piv_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int piv_detect_card(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, 1);
	if (card->type < SC_CARD_TYPE_PIV_II_GENERIC
		|| card->type >= SC_CARD_TYPE_PIV_II_GENERIC+1000)
		return SC_ERROR_INVALID_CARD;
	return SC_SUCCESS;
}

const objdata objects[] = {
	{"1", "Card Capability Container", 
			"2.16.840.1.101.3.7.1.219.0", 0, "DB00", 0},
	{"2", "Card Holder Unique Identifier",
			"2.16.840.1.101.3.7.2.48.0", 0 , "3000", 0},
	{"3", "Card Holder Fingerprints",
			"2.16.840.1.101.3.7.2.96.16", 0, "6010", SC_PKCS15_CO_FLAG_PRIVATE},
	{"4", "Printed Information",
			"2.16.840.1.101.3.7.2.48.1", 0, "3001", SC_PKCS15_CO_FLAG_PRIVATE},
	{"5", "Card Holder Facial Image", 
			"2.16.840.1.101.3.7.2.96.48", 0, "6030", SC_PKCS15_CO_FLAG_PRIVATE},
	{"6", "Security Object",
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
#if 0 /* Strange break */
	{"4", "Certificate for Card Authentication", 0, "0500", 0},
#endif
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
	  0x9A, "1", 0},
	{ "2", "SIGN pubkey", 1024, USAGE_AUT, "9C06", 
	  0x9C, "1", 0},
	{ "3", "KEY MAN pubkey", 1024, USAGE_AUT, "9D06", 
	  0x9E, "1", 0},
	{ "4", "ADMIN pubkey", 1024, USAGE_AUT, "9B06", 
	  0x9B, "1", 0},
	{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
	
};

const prdata prkeys[] = {
	{ "1", "AUTH key", 1024, USAGE_AUT, "",
	  0x9A, "1", 0},
	{ "2", "SIGN key", 1024, USAGE_AUT, "",
	  0x9C, "1", 0},
	{ "3", "KEY MAN key", 1024, USAGE_AUT, "",
	  0x9E, "1", 0},
	{ "4", "ADMIN key", 1024, USAGE_AUT, "",
	  0x9B, "1", 0},
	{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
};

/* TEMPORARY: Should hook into card-piv ... */
static int piv_load_cached_cert(sc_card_t *card, u8** buf, size_t* count, int* should_free) {
	/* File already selected.. just read... */
	int r;
	u8* out = malloc(4096*2);
	r = sc_read_binary(card, 0, out, 4096*2, 0);
	if(r < 0) {
		free(out);
		*buf = NULL;
		*count = 0;
		return r;
	}
	*count = r;
	*buf = out;
	*should_free = 1;
	return SC_SUCCESS;
}

#define CHECK_CERTIFICATES 1
static p15data_items items = {
	objects,
	certs,
	pins,
	NULL,
	prkeys,
#ifdef CHECK_CERTIFICATES
	piv_load_cached_cert,
#else
	NULL,
#endif
	default_cert_handle,
	1,
#ifdef CHECK_CERTIFICATES
	0,
#else
	1,
#endif
	0
};

static int sc_pkcs15emu_piv_init(sc_pkcs15_card_t *p15card)
{
	int    r;
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
	
	r = sc_pkcs15emu_initialize_all(p15card, &items);

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
