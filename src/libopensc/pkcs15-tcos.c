/*
 * PKCS15 emulation layer for TCOS base preformatted cards
 *
 * Copyright (C) 2006, Peter Koch <pk_opensc@web.de>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
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
#include <opensc/pkcs15.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void
set_string(char **strp, const char *value)
{
	if (*strp) free(*strp);
	*strp = value ? strdup(value) : NULL;
}

int sc_pkcs15emu_tcos_init_ex(sc_pkcs15_card_t *p15card, sc_pkcs15emu_opt_t *opts)
{
	static const struct {
		const char *card, *manufacturer;
	} cardlist[]={
		{"Netkey E4 Card", "TeleSec GmbH"},
		{"SignTrust Card", "Deutsche Post"},
		{"Smartkey Card TypA", "Kobil GmbH"},
		{"Smartkey Card TypB", "Kobil GmbH"},
		{"Chipkarte JLU Giessen", "Kobil GmbH"}
	};
	static const struct {
		int         type, id, writable;
		const char *path;
		const char *label;
	} certlist[]={
		{ 1, 0x45, 0, "DF01C000",     "Telesec Signatur Zertifikat"},
		{-1, 0x45, 1, "DF014331",     "Signatur Zertifikat 1"},
		{-1, 0x45, 1, "DF014332",     "Signatur Zertifikat 2"},
		{-1, 0x46, 0, "DF01C100",     "Telesec Authentifizierungs Zertifikat"},
		{-1, 0x46, 1, "DF014371",     "Authentifizierungs Zertifikat 1"},
		{-1, 0x46, 1, "DF014372",     "Authentifizierungs Zertifikat 2"},
		{-1, 0x47, 0, "DF01C200",     "Telesec Verschluesselungs Zertifikat"},
		{-1, 0x47, 1, "DF0143B1",     "Verschluesselungs Zertifikat 1"},
		{-1, 0x47, 1, "DF0143B2",     "Verschluesselungs Zertifikat 2"},
		{-1, 0x48, 1, "41014352",     "W2K Logon Zertifikat"},
		{ 2, 0x45, 1, "8000DF01C000", "SignTrust Signatur Zertifikat"},
		{-2, 0x46, 1, "800082008220", "SignTrust Verschluesselungs Zertifikat"},
		{-2, 0x47, 1, "800083008320", "SignTrust Authentifizierungs Zertifikat"},
		{ 3, 0x45, 1, "41004352",     "Smartkey Zertifikat 1"},
		{-3, 0x46, 1, "41004353",     "Smartkey Zertifikat 2"},
		{ 4, 0x45, 1, "41014352",     "Smartkey Zertifikat 1"},
		{-4, 0x46, 1, "41014353",     "Smartkey Zertifikat 2"},
		{ 5, 0x45, 1, "41004352",     "UniCard Giessen Zertifikat"},
		{ 0, 0, 0, NULL, NULL}
	};
	static const struct {
		int           type, id, auth_id;
		const char   *path;
		unsigned char key_reference;
		const char   *label;
	} keylist[]={
		{1, 0x45, 4, "DF015331",     0x80, "Signatur Schluessel"},
		{1, 0x46, 3, "DF015371",     0x82, "Authentifizierungs Schluessel"},
		{1, 0x47, 3, "DF0153B1",     0x81, "Verschluesselungs Schluessel"},
		{1, 0x48, 1, "41015103",     0x83, "W2K Logon Schluessel"},
		{2, 0x45, 1, "8000DF015331", 0x80, "Signatur Schluessel"},
		{2, 0x46, 2, "800082008210", 0x80, "Verschluesselungs Schluessel"},
		{2, 0x47, 3, "800083008310", 0x80, "Authentifizierungs Schluessel"},
		{3, 0x45, 1, "41005103",     0x83, "Smartkey Schluessel 1"},
		{3, 0x46, 1, "41005104",     0x84, "Smartkey Schluessel 2"},
		{4, 0x45, 1, "41015103",     0x83, "Smartkey Schluessel 1"},
		{4, 0x46, 1, "41015104",     0x84, "Smartkey Schluessel 2"},
		{5, 0x45, 1, "3F004100",     0x83, "UniCard Giessen Schluessel"},
		{0, 0, 0, NULL, 0, NULL}
	};
	static const struct {
		int           type, id, auth_id, min_length;
		unsigned char reference;
		const char   *path;
		const char   *label;
		int           flags;
	} pinlist[]={
		{1, 1, 2, 6, 0x00, "5000", "globale PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN},
		{1, 2, 0, 8, 0x01, "5001", "globale PUK",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN},
		{1, 3, 1, 6, 0x80, "DF015080", "Netkey PIN0",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED},
		{1, 4, 1, 6, 0x81, "DF015081", "Netkey PIN1",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED},
		{2, 1, 0, 6, 0x81, "8000DF010000", "Signatur PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED},
		{2, 2, 0, 6, 0x81, "800082000040", "Verschluesselungs PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED},
		{2, 3, 0, 6, 0x81, "800083000040", "Authentifizierungs PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
			SC_PKCS15_PIN_FLAG_INITIALIZED},
		{3, 1, 2, 6, 0x00, "5000", "globale PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN},
		{3, 2, 0, 8, 0x01, "5008", "globale PUK",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN},
		{4, 1, 2, 6, 0x00, "5000", "globale PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN},
		{4, 2, 0, 8, 0x01, "5008", "globale PUK",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN},
		{5, 1, 0, 6, 0x00, "4100", "globale PIN",
			SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED},
		{0, 0, 0, 0, 0, NULL, NULL, 0}
	};
	sc_card_t         *card = p15card->card;
	sc_context_t      *ctx = p15card->card->ctx;
	sc_path_t          path;
	sc_file_t         *file;
	sc_serial_number_t serialnr;
	char               serial[30];
	int                i, r, usage, cardtype;

	/* check if we have the correct card OS unless SC_PKCS15EMU_FLAGS_NO_CHECK */
	i=(opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK);
	if (!i && strcmp(card->name, "TCOS")) return SC_ERROR_WRONG_CARD;

	/* get the card serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr);
	if (r < 0) {
		sc_debug(ctx, "unable to get ICCSN\n");
		r = SC_ERROR_WRONG_CARD;
		goto failed;
	}
        sc_bin_to_hex(serialnr.value, serialnr.len , serial, sizeof(serial), 0);
	serial[19] = '\0';
        set_string(&p15card->serial_number, serial);

	cardtype=0;
	for(i=0; certlist[i].id; ++i){
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object    cert_obj;
		unsigned char cert[20];

		if(certlist[i].type>0 && cardtype!=0 && cardtype!=certlist[i].type) continue;
		if(certlist[i].type<0 && cardtype!=-certlist[i].type) continue;

		sc_format_path(certlist[i].path, &path);
		sc_ctx_suppress_errors_on(card->ctx);
		r = sc_select_file(card, &path, NULL);
		sc_ctx_suppress_errors_off(card->ctx);
		if (r < 0) continue;
		if(certlist[i].type>0) cardtype=certlist[i].type;

		/* read first 20 bytes of certificate, first two bytes
		 * must be 0x30 0x82, otherwise this is an empty cert-file
		 * Telesec-Certificates are prefixed by an OID,
		 * for example 06:03:55:04:24. this must be skipped
		 */
		r = sc_read_binary(card, 0, cert, sizeof(cert), 0);
		if(r<0 || cert[0]!=0x30 || cert[1]!=0x82) continue;
		if(cert[4]==0x06 && cert[5]<10 && cert[6+cert[5]]==0x30 && cert[7+cert[5]]==0x82){
			path.index=6+cert[5];
			path.count=(cert[8+cert[5]]<<8) + cert[9+cert[5]] + 4;
		} else {
			path.index=0;
			path.count=(cert[2]<<8) + cert[3] + 4;
		}

		memset(&cert_info, 0, sizeof(cert_info));
		cert_info.id.len      = 1;
		cert_info.id.value[0] = certlist[i].id;
		cert_info.authority   = 0;
		cert_info.path        = path;

		memset(&cert_obj, 0, sizeof(cert_obj));
		strncpy(cert_obj.label, certlist[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		cert_obj.flags = certlist[i].writable ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			sc_debug(ctx, "sc_pkcs15emu_add_x509_cert(%s) failed\n", certlist[i].path);
			r = SC_ERROR_INTERNAL;
			goto failed;
		}
	}
	if (ctx->debug >= 1) sc_debug(ctx, "Detected TCOS-Card Type-%d\n", cardtype);
	if(cardtype<1 || cardtype>(int)(sizeof(cardlist)/sizeof(cardlist[0]))){
		r = SC_ERROR_WRONG_CARD;
		goto failed;
	}
	set_string(&p15card->label, cardlist[cardtype-1].card);
	set_string(&p15card->manufacturer_id, cardlist[cardtype-1].manufacturer);

	for(i=0; keylist[i].id; ++i){
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object     prkey_obj;

		if(keylist[i].type!=cardtype) continue;

		sc_format_path(keylist[i].path, &path);
		sc_ctx_suppress_errors_on(card->ctx);
		r = sc_select_file(card, &path, &file);
		sc_ctx_suppress_errors_off(card->ctx);
		if (r < 0) continue;

		usage = SC_PKCS15_PRKEY_USAGE_SIGN;
                if (file->prop_attr[1] & 0x04) usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT;
		if (file->prop_attr[1] & 0x08) usage |= SC_PKCS15_PRKEY_USAGE_NONREPUDIATION;

		memset(&prkey_info, 0, sizeof(prkey_info));
		prkey_info.id.len         = 1;
		prkey_info.id.value[0]    = keylist[i].id;
		prkey_info.usage          = usage;
		prkey_info.native         = 1;
		prkey_info.key_reference  = keylist[i].key_reference;
		prkey_info.modulus_length = 1024;
		sc_format_path(keylist[i].path, &prkey_info.path);

		memset(&prkey_obj, 0, sizeof(prkey_obj));
		strncpy(prkey_obj.label, keylist[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		prkey_obj.flags            = SC_PKCS15_CO_FLAG_PRIVATE;
		prkey_obj.auth_id.len      = 1;
		prkey_obj.auth_id.value[0] = keylist[i].auth_id;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		sc_file_free(file);
		if (r < 0) {
			sc_debug(ctx, "sc_pkcs15emu_add_rsa_prkey(%s) failed\n", keylist[i].path);
			r = SC_ERROR_INTERNAL;
			goto failed;
		}
	}

	for(i=0; pinlist[i].id; ++i){
		struct sc_pkcs15_pin_info pin_info;
		struct sc_pkcs15_object   pin_obj;

		if(pinlist[i].type && pinlist[i].type!=cardtype) continue;

		sc_format_path(pinlist[i].path, &path);
		sc_ctx_suppress_errors_on(card->ctx);
		r = sc_select_file(card, &path, &file);
		sc_ctx_suppress_errors_off(card->ctx);
		if (r < 0) continue;

		memset(&pin_info, 0, sizeof(pin_info));
		pin_info.auth_id.len      = 1;
		pin_info.auth_id.value[0] = pinlist[i].id;
		pin_info.reference        = pinlist[i].reference;
		pin_info.flags            = pinlist[i].flags;
		pin_info.type             = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.min_length       = pinlist[i].min_length;
		pin_info.stored_length    = 16;
		pin_info.max_length       = 16;
		pin_info.pad_char         = '\0';
		pin_info.tries_left       = file->prop_attr[3];
		sc_format_path(pinlist[i].path, &pin_info.path);

		memset(&pin_obj, 0, sizeof(pin_obj));
		strncpy(pin_obj.label, pinlist[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj.flags            = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
		pin_obj.auth_id.len      = pinlist[i].auth_id ? 0 : 1;
		pin_obj.auth_id.value[0] = pinlist[i].auth_id;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		sc_file_free(file);
		if (r < 0) {
			sc_debug(ctx, "sc_pkcs15emu_add_pin_obj(%s) failed\n", pinlist[i].path);
			r = SC_ERROR_INTERNAL;
			goto failed;
		}
	}

	/* return to MF */
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	
failed:
	if (r < 0)
		sc_debug(card->ctx, "Failed to initialize TCOS based preformatted card: %s\n", sc_strerror(r));
        return r;
}
