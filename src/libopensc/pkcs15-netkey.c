/*
 * PKCS15 emulation layer for Telesec Netkey E4 card.
 *
 * Copyright (C) 2004, Peter Koch <opensc.pkoch@dfgh.net>
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
#include "cardctl.h"
#include "pkcs15.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int sc_pkcs15emu_netkey_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static void
set_string(char **strp, const char *value)
{
	if (*strp)
		free(strp);
	*strp = value? strdup(value) : NULL;
}

static int
sc_pkcs15emu_netkey_init(sc_pkcs15_card_t *p15card) {
	static const struct {
		int           id;
		const char   *path;
		const char   *label;
		unsigned char pinref;
	} pinlist[]={
		{1, "DF015080", "lokale PIN0", 0x80},
		{2, "DF015081", "lokale PIN1", 0x81},
		{0}
	};
	static const struct {
		int           id, auth_id;
		const char   *path;
		const char   *label;
		unsigned char keyref;
		int           usage;
	} keylist[]={
		{1, 2, "DF015331", "Signatur-Schlüssel",           0x80,
                       SC_PKCS15_PRKEY_USAGE_NONREPUDIATION},
		{2, 2, "DF015371", "Authentifizierungs-Schlüssel", 0x82,
                       SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT},
		{3, 1, "DF0153B1", "Verschlüsselungs-Schlüssel",   0x81,
                       SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT},
		{0}
	};
	static const struct {
		int         id;
		const char *path;
		const char *label;
		int         obj_flags;
	} certlist[]={
		{1, "DF01C000", "Telesec Signatur Zertifikat", 0},
		{1, "DF014331", "User Signatur Zertifikat1", 
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{1, "DF014332", "User Signatur Zertifikat2",
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{2, "DF01C100", "Telesec Authentifizierungs Zertifikat", 0},
		{2, "DF014371", "User Authentifizierungs Zertifikat1",
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{2, "DF014372", "User Authentifizierungs Zertifikat2",
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{3, "DF01C200", "Telesec Verschlüsselungs Zertifikat", 0},
		{3, "DF0143B1", "User Verschlüsselungs Zertifikat1",
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{3, "DF0143B2", "User Verschlüsselungs Zertifikat2",
		 SC_PKCS15_CO_FLAG_MODIFIABLE},
		{0}
	};

	sc_card_t      *card = p15card->card;
	sc_context_t   *ctx = p15card->card->ctx;
	sc_path_t       path;
	char   serial[30];
	int             i, r;
	sc_serial_number_t serialnr;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "TCOS"))
		return SC_ERROR_WRONG_CARD;
	/* check if we have a df01 DF           */
	sc_format_path("3F00DF01", &path);
	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		r = SC_ERROR_WRONG_CARD;
		goto failed;
	}
	/* get the card serial number           */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr);
	if (r < 0) {
		sc_debug(ctx, "unable to get ICCSN\n");
		r = SC_ERROR_WRONG_CARD;
		goto failed;
	}
        sc_bin_to_hex(serialnr.value, serialnr.len , serial, sizeof(serial), 0);
	serial[19] = '\0';
        set_string(&p15card->serial_number, serial);
	set_string(&p15card->label, "Netkey E4 Card");
	set_string(&p15card->manufacturer_id, "TeleSec");

	for(i=0; pinlist[i].id; ++i){
		sc_pkcs15_id_t id;

		if (ctx->debug >= 2) sc_debug(ctx, "Netkey: Loading %s: %s\n", pinlist[i].path, pinlist[i].label);
		sc_format_path(pinlist[i].path, &path);

		id.value[0]=pinlist[i].id; id.len=1;

		sc_pkcs15emu_add_pin(
			p15card, &id, pinlist[i].label, &path, pinlist[i].pinref,
			SC_PKCS15_PIN_TYPE_ASCII_NUMERIC, 6, 16,
        		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_INITIALIZED,
			-1, 0, 
			SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE
		);
	}

	for(i=0; keylist[i].id; ++i){
		sc_pkcs15_id_t id, auth_id;

		if (ctx->debug >= 2) sc_debug(ctx, "Netkey: Loading %s\n", keylist[i].label);

		id.value[0]      = keylist[i].id;      id.len=1;
		auth_id.value[0] = keylist[i].auth_id; auth_id.len=1;

		sc_format_path(keylist[i].path, &path);

                sc_pkcs15emu_add_prkey(
			p15card, &id, keylist[i].label, SC_PKCS15_TYPE_PRKEY_RSA, 
			1024, keylist[i].usage, &path, keylist[i].keyref,
			&auth_id, SC_PKCS15_CO_FLAG_PRIVATE
		);
	}

	for(i=0; certlist[i].id; ++i){
		unsigned char   cert[20];
		sc_pkcs15_id_t  id;

		if (ctx->debug >= 2)
			sc_debug(ctx, "Netkey: Loading %s: %s\n", certlist[i].path, certlist[i].label);
		sc_format_path(certlist[i].path, &path);
		card->ctx->suppress_errors++;
		r = sc_select_file(card, &path, NULL);
		card->ctx->suppress_errors--;
		if (r < 0)
			continue;

		/* read first 20 bytes of certificate, first two bytes
		 * must be 0x30 0x82, otherwise this is an empty cert-file
		 * Telesec-Certificates are prefixed by an OID,
		 * for example 06:03:55:04:24. this must be skipped
		 */
		sc_read_binary(card, 0, cert, sizeof(cert), 0);
		if(cert[0]!=0x30 || cert[1]!=0x82) continue;
		if(cert[4]==0x06 && cert[5]<10 && cert[6+cert[5]]==0x30 && cert[7+cert[5]]==0x82){
			path.index=6+cert[5];
			path.count=(cert[8+cert[5]]<<8) + cert[9+cert[5]] + 4;
		} else {
			path.index=0;
			path.count=(cert[2]<<8) + cert[3] + 4;
		}

		id.value[0]=certlist[i].id; id.len=1;

		sc_pkcs15emu_add_cert(
			p15card, SC_PKCS15_TYPE_CERT_X509, 0,
			&path, &id, certlist[i].label, certlist[i].obj_flags);
	}

	/* return to MF */
	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
	
failed:
	if (r < 0)
		sc_debug(card->ctx, "Failed to initialize TeleSec Netkey E4 emulation: %s\n", sc_strerror(r));
        return r;
}

static int netkey_detect_card(sc_pkcs15_card_t *p15card)
{
	int       r;
	sc_path_t path;
	sc_card_t *card = p15card->card;

	/* check if we have the correct card OS */
	if (strcmp(card->name, "TCOS"))
		return SC_ERROR_WRONG_CARD;
	/* check if we have a df01 DF           */
	sc_format_path("3F00DF01", &path);
	r = sc_select_file(card, &path, NULL);
	if (r < 0)
		return SC_ERROR_WRONG_CARD;
	return SC_SUCCESS;
}
	
int sc_pkcs15emu_netkey_init_ex(sc_pkcs15_card_t *p15card,
				sc_pkcs15emu_opt_t *opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_netkey_init(p15card);
	else {
		int r = netkey_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_netkey_init(p15card);
	}
}
