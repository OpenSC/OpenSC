/*
 * partial PKCS15 emulation for G&D Starcert V2.2 cards
 *
 * Copyright (C) 2004, Nils <larsch@trustcenter.de>
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

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MANU_ID		"Giesecke & Devrient GmbH"
#define STARCERT	"StarCertV2201"

typedef struct cdata_st {
	const char *label;
	int	    authority;
	const char *path;
	const char *id;
	int         obj_flags;
} cdata;

const cdata certs[] = {
	{"DS certificate", 0, "3F00DF01C000","1", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"CA certificate", 1, "3F00DF01C008","2", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"KE certificate", 0, "3F00DF01C200","3", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{"AUT certificate",0, "3F00DF01C500","4", SC_PKCS15_CO_FLAG_MODIFIABLE},
	{NULL, 0, NULL, 0, 0}
};

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int         ref;
	int         type;
	unsigned int maxlen;
	unsigned int minlen;
	int         flags;	
	int         tries_left;
	const char  pad_char;
	int         obj_flags;
} pindata; 

const pindata pins[] = {
	{ "99", "DS pin", "3F00DF01", 0x99, SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
	  8, 8, SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_LOCAL, 
	  -1, 0x00, 
	  SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE },
	{ NULL, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, 0}
};

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

const prdata prkeys[] = {
	{ "1", "DS key", 1024, USAGE_NONREP, "3F00DF01",
	  0x84, "99", SC_PKCS15_CO_FLAG_PRIVATE},
	{ "3", "KE key", 1024, USAGE_KE, "3F00DF01",
	  0x85, NULL, SC_PKCS15_CO_FLAG_PRIVATE},
	{ "4", "AUT key", 1024, USAGE_AUT, "3F00DF01",
	  0x82, NULL, SC_PKCS15_CO_FLAG_PRIVATE},
	{ NULL, NULL, 0, 0, NULL, 0, NULL, 0}
};

static int get_cert_len(sc_card_t *card, sc_path_t *path)
{
	int r;
	u8  buf[8];
	struct sc_file *file;

	r = sc_select_file(card, path, &file);
	if (r < 0)
		return 0;
	r = sc_read_binary(card, 0, buf, sizeof(buf), 0);
	if (r < 0)	
		return 0;
	if (buf[0] != 0x30 || buf[1] != 0x82)
		return 0;
	path->index = 0;
	path->count = ((((size_t) buf[2]) << 8) | buf[3]) + 4;
	return 1;
} 

static int starcert_detect_card(sc_pkcs15_card_t *p15card)
{
	int       r;
	u8        buf[128];
	sc_path_t path;
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "STARCOS SPK 2.3"))
		return SC_ERROR_WRONG_CARD;
	/* read EF_Info file */
	sc_format_path("3F00FE13", &path);
	card->ctx->suppress_errors++;
	r = sc_select_file(card, &path, NULL);
	card->ctx->suppress_errors--;
	if (r != SC_SUCCESS)
		return SC_ERROR_WRONG_CARD;
	r = sc_read_binary(card, 0, buf, 64, 0);
	if (r != 64)
		return SC_ERROR_WRONG_CARD;
	if (memcmp(buf + 24, STARCERT, strlen(STARCERT))) 
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

int sc_pkcs15emu_starcert_init(sc_pkcs15_card_t *p15card)
{
	int    r, i;
	u8     buf[256];
	struct sc_path path;
	struct sc_file *file = NULL;
	struct sc_card *card = p15card->card;
	struct sc_serial_number serial;

	/* get serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	r = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	if (p15card->serial_number)
		free(p15card->serial_number);
	p15card->serial_number = malloc(strlen(buf) + 1);
	if (!p15card->serial_number)
		return SC_ERROR_INTERNAL;
	strcpy(p15card->serial_number, buf);
	/* the TokenInfo version number */
	p15card->version = 0;
	/* the manufacturer ID, in this case Giesecke & Devrient GmbH */
	if (p15card->manufacturer_id)
		free(p15card->manufacturer_id);
	p15card->manufacturer_id = malloc(strlen(MANU_ID) + 1);
	if (!p15card->manufacturer_id)
		return SC_ERROR_INTERNAL;
	strcpy(p15card->manufacturer_id, MANU_ID);

	/* set certs */
	for (i = 0; certs[i].label; i++) {
		struct sc_pkcs15_id  p15Id;

		sc_format_path(certs[i].path, &path);
		if (!get_cert_len(card, &path))
			/* skip errors */
			continue;
		sc_pkcs15_format_id(certs[i].id, &p15Id);
		sc_pkcs15emu_add_cert(p15card, SC_PKCS15_TYPE_CERT_X509,
				certs[i].authority, &path, &p15Id,
				certs[i].label, certs[i].obj_flags);
	}
	/* set pins */
	for (i = 0; pins[i].label; i++) {
		struct sc_pkcs15_id  p15Id;

		sc_format_path(pins[i].path, &path);
		sc_pkcs15_format_id(pins[i].id, &p15Id);
		sc_pkcs15emu_add_pin(p15card, &p15Id, pins[i].label,
				&path, pins[i].ref, pins[i].type,
				pins[i].minlen, pins[i].maxlen, pins[i].flags,
				pins[i].tries_left, pins[i].pad_char,
				pins[i].obj_flags);
	}
	/* set private keys */
	for (i = 0; prkeys[i].label; i++) {
		struct sc_pkcs15_id p15Id, 
				    authId, *pauthId;
		sc_format_path(prkeys[i].path, &path);
		sc_pkcs15_format_id(prkeys[i].id, &p15Id);
		if (prkeys[i].auth_id) {
			sc_pkcs15_format_id(prkeys[i].auth_id, &authId);
			pauthId = &authId;
		} else	
			pauthId = NULL;
		sc_pkcs15emu_add_prkey(p15card, &p15Id, prkeys[i].label,
				SC_PKCS15_TYPE_PRKEY_RSA,
				prkeys[i].modulus_len, prkeys[i].usage,
				&path, prkeys[i].ref, pauthId,
				prkeys[i].obj_flags);
	}
		
	/* select the application DF */
	sc_format_path("3F00DF01", &path);
	r = sc_select_file(card, &path, &file);
	if (r != SC_SUCCESS || !file)
		return SC_ERROR_INTERNAL;
	/* set the application DF */
	if (p15card->file_app)
		free(p15card->file_app);
	p15card->file_app = file;

	return SC_SUCCESS;
}

int sc_pkcs15emu_starcert_init_ex(sc_pkcs15_card_t *p15card,
				  sc_pkcs15emu_opt_t *opts)
{

	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_starcert_init(p15card);
	else {
		int r = starcert_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_starcert_init(p15card);
	}
}
