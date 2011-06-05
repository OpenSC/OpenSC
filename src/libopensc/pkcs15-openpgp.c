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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs15.h"
#include "log.h"

int sc_pkcs15emu_openpgp_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static const char *	pgp_pin_name[3] = {
				"Signature PIN",
				"Encryption PIN",
				"Admin PIN"
			};
static const char *	pgp_key_name[3] = {
				"Signature key",
				"Encryption key",
				"Authentication key"
			};
static const char *	pgp_pubkey_path[3] = {
				"B601",
				"B801",
				"A401"
			};

static void
set_string(char **strp, const char *value)
{
	if (*strp)
		free(*strp);
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

static int
sc_pkcs15emu_openpgp_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	char		string[256];
	u8		buffer[256];
	int		r, i;

	set_string(&p15card->tokeninfo->label, "OpenPGP Card");
	set_string(&p15card->tokeninfo->manufacturer_id, "OpenPGP project");

	if ((r = read_file(card, "004f", buffer, sizeof(buffer))) < 0)
		goto failed;
	sc_bin_to_hex(buffer, (size_t)r, string, sizeof(string), 0);
	set_string(&p15card->tokeninfo->serial_number, string);

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_EID_COMPLIANT;

	/* Extract preferred language */
	r = read_file(card, "00655f2d", string, sizeof(string)-1);
	if (r < 0)
		goto failed;
	string[r] = '\0';
	set_string(&p15card->tokeninfo->preferred_language, string);

	/* Get Application Related Data (006E) */
	if ((r = sc_get_data(card, 0x006E, buffer, sizeof(buffer))) < 0)
		goto failed;

	/* TBD: extract algorithm info */

	/* Get CHV status bytes:
	 *  00:		??
	 *  01-03:	max length of pins 1-3
	 *  04-07:	tries left for pins 1-3
	 */
	if ((r = read_file(card, "006E007300C4", buffer, sizeof(buffer))) < 0)
		goto failed;
	if (r != 7) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"CHV status bytes have unexpected length "
			"(expected 7, got %d)\n", r);
		return SC_ERROR_OBJECT_NOT_VALID;
	}

	for (i = 0; i < 3; i++) {
		unsigned int	flags;

		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object   pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		flags =	SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
			SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_LOCAL;
		if (i == 2) {
			flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED |
				 SC_PKCS15_PIN_FLAG_SO_PIN;
		}

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.auth_id.len   = 1;
		pin_info.auth_id.value[0] = i + 1;
		pin_info.attrs.pin.reference     = i + 1;
		pin_info.attrs.pin.flags         = flags;
		pin_info.attrs.pin.type          = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length    = 0;
		pin_info.attrs.pin.stored_length = buffer[1+i];
		pin_info.attrs.pin.max_length    = buffer[1+i];
		pin_info.attrs.pin.pad_char      = '\0';
		sc_format_path("3F00", &pin_info.path);
		pin_info.tries_left    = buffer[4+i];

		strlcpy(pin_obj.label, pgp_pin_name[i], sizeof(pin_obj.label));
		pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
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

		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object     prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		prkey_info.id.len        = 1;
		prkey_info.id.value[0]   = i + 1;
		prkey_info.usage         = prkey_usage[i];
		prkey_info.native        = 1;
		prkey_info.key_reference = i;
		prkey_info.modulus_length= 1024;

		strlcpy(prkey_obj.label, pgp_key_name[i], sizeof(prkey_obj.label));
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE;
		prkey_obj.auth_id.len      = 1;
		prkey_obj.auth_id.value[0] = prkey_pin[i];

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}

	for (i = 0; i < 3; i++) {
		static int	pubkey_usage[3] = {
					SC_PKCS15_PRKEY_USAGE_VERIFY
					| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,
					SC_PKCS15_PRKEY_USAGE_ENCRYPT
					| SC_PKCS15_PRKEY_USAGE_WRAP,
					SC_PKCS15_PRKEY_USAGE_VERIFY
				};

		struct sc_pkcs15_pubkey_info pubkey_info;
		struct sc_pkcs15_object      pubkey_obj;

		memset(&pubkey_info, 0, sizeof(pubkey_info));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));

		pubkey_info.id.len = 1;
		pubkey_info.id.value[0] = i +1;
		pubkey_info.modulus_length = 1024;
		pubkey_info.usage    = pubkey_usage[i];
		sc_format_path(pgp_pubkey_path[i], &pubkey_info.path);

		strlcpy(pubkey_obj.label, pgp_key_name[i], sizeof(pubkey_obj.label));
		pubkey_obj.auth_id.len      = 1;
		pubkey_obj.auth_id.value[0] = 3;
		pubkey_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

		r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}

	return 0;

failed:	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Failed to initialize OpenPGP emulation: %s\n",
			sc_strerror(r));
	return r;
}

static int openpgp_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type == SC_CARD_TYPE_OPENPGP_V1 || p15card->card->type == SC_CARD_TYPE_OPENPGP_V2)
		return SC_SUCCESS;
	else
		return SC_ERROR_WRONG_CARD;
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
