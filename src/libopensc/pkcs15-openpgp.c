/*
 * PKCS15 emulation layer for OpenPGP card.
 * To see how this works, run p15dump on your OpenPGP card.
 *
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
#include "pkcs15.h"
#include "asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static char *	pgp_pin_name[3] = {
				"Signature PIN",
				"Encryption PIN",
				"Admin PIN"
			};
static char *	pgp_key_name[3] = {
				"Signature key",
				"Encryption key",
				"Authentication key"
			};
static char *	pgp_pubkey_path[3] = {
				"B601",
				"B801",
				"A401"
			};

static void
set_string(char **strp, const char *value)
{
	if (*strp)
		free(strp);
	*strp = value? strdup(value) : NULL;
}

/*
 * This function pretty much follows what find_tlv in the GNUpg
 * code does.
 */
static int
read_file(sc_card_t *card, const char *path_name, void *buf, size_t len)
{
	sc_path_t	path;
	sc_file_t	*file;
	int		r;

	sc_format_path(path_name, &path);
	if ((r = sc_select_file(card, &path, &file)) < 0)
		return r;

	if (file->size < len)
		len = file->size;
	return sc_read_binary(card, 0, (u8 *) buf, len, 0);
}

int
sc_pkcs15emu_openpgp_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	char		string[256];
	u8		buffer[256];
	size_t		length;
	int		r, i;

	set_string(&p15card->label, "OpenPGP Card");
	set_string(&p15card->manufacturer_id, "OpenPGP project");

	if ((r = read_file(card, "004f", buffer, sizeof(buffer))) < 0)
		goto failed;
	sc_bin_to_hex(buffer, r, string, sizeof(string), 0);
	set_string(&p15card->serial_number, string);
	p15card->version = (buffer[6] << 8) | buffer[7];

	p15card->flags = SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED |
			 SC_PKCS15_CARD_FLAG_PRN_GENERATION |
			 SC_PKCS15_CARD_FLAG_EID_COMPLIANT;

	/* Extract preferred language */
	r = read_file(card, "00655f2d", string, sizeof(string)-1);
	if (r < 0)
		goto failed;
	string[r] = '\0';
	set_string(&p15card->preferred_language, string);

	/* Get Application Related Data (006E) */
	if ((r = sc_get_data(card, 0x006E, buffer, sizeof(buffer))) < 0)
		goto failed;
	length = r;

	/* TBD: extract algorithm info */

	/* Get CHV status bytes:
	 *  00:		??
	 *  01-03:	max length of pins 1-3
	 *  04-07:	tries left for pins 1-3
	 */
	if ((r = read_file(card, "006E007300C4", buffer, sizeof(buffer))) < 0)
		goto failed;
	if (r != 7) {
		sc_error(ctx,
			"CHV status bytes have unexpected length "
			"(expected 7, got %d)\n", r);
		return SC_ERROR_OBJECT_NOT_VALID;
	}

	for (i = 0; i < 3; i++) {
		sc_path_t	path;
		sc_pkcs15_id_t	auth_id;
		int		flags;

		flags =	SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
			SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_LOCAL;
		if (i == 2) {
			flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED |
				 SC_PKCS15_PIN_FLAG_SO_PIN;
		}

		sc_format_path("3F00", &path);
		auth_id.value[0] = i + 1;
		auth_id.len = 1;
		sc_pkcs15emu_add_pin(p15card, &auth_id,
				pgp_pin_name[i], &path, i+1,
				SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
				0, buffer[1+i], flags, buffer[4+i], 0,
				SC_PKCS15_CO_FLAG_MODIFIABLE | 
				SC_PKCS15_CO_FLAG_PRIVATE);
	}

	for (i = 0; i < 3; i++) {
		static int	prkey_pin[3] = { 1, 2, 2 };
		static int	prkey_usage[3] = {
					SC_PKCS15_PRKEY_USAGE_SIGN
					| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER
					| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,
					SC_PKCS15_PRKEY_USAGE_DECRYPT
					| SC_PKCS15_PRKEY_USAGE_UNWRAP,
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
				};
		sc_pkcs15_id_t	id, auth_id;

		id.value[0] = i + 1;
		id.len = 1;
		auth_id.value[0] = prkey_pin[i];
		auth_id.len = 1;
		sc_pkcs15emu_add_prkey(p15card, &id,
				pgp_key_name[i],
				SC_PKCS15_TYPE_PRKEY_RSA,
				1024, prkey_usage[i],
				NULL, i,
				&auth_id, SC_PKCS15_CO_FLAG_PRIVATE |
				SC_PKCS15_CO_FLAG_MODIFIABLE);
	}

	for (i = 0; i < 3; i++) {
		static int	pubkey_usage[3] = {
					SC_PKCS15_PRKEY_USAGE_VERIFY
					| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,
					SC_PKCS15_PRKEY_USAGE_ENCRYPT
					| SC_PKCS15_PRKEY_USAGE_WRAP,
					SC_PKCS15_PRKEY_USAGE_VERIFY
				};
		sc_pkcs15_id_t	id, auth_id;
		sc_path_t	path;

		id.value[0] = i + 1;
		id.len = 1;
		auth_id.value[0] = 3;
		auth_id.len = 1;
		sc_format_path(pgp_pubkey_path[i], &path);
		sc_pkcs15emu_add_pubkey(p15card, &id,
				pgp_key_name[i],
				SC_PKCS15_TYPE_PUBKEY_RSA,
				1024, pubkey_usage[i],
				&path, 0, &auth_id, SC_PKCS15_CO_FLAG_MODIFIABLE);
	}

	return 0;

failed:	sc_error(card->ctx, "Failed to initialize OpenPGP emulation: %s\n",
			sc_strerror(r));
	return r;

}

static int openpgp_detect_card(sc_pkcs15_card_t *p15card)
{
	return strcmp(p15card->card->name, "OpenPGP");
}

int sc_pkcs15emu_openpgp_init_ex(sc_pkcs15_card_t *p15card,
				 sc_pkcs15emu_opt_t *opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_openpgp_init(p15card);
	else {
		int r = openpgp_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_openpgp_init(p15card);
	}
}
