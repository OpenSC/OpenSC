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


#define	PGP_USER_PIN_FLAGS	(SC_PKCS15_PIN_FLAG_CASE_SENSITIVE \
				| SC_PKCS15_PIN_FLAG_INITIALIZED \
				| SC_PKCS15_PIN_FLAG_LOCAL)
#define PGP_ADMIN_PIN_FLAGS	(PGP_USER_PIN_FLAGS \
				| SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED \
				| SC_PKCS15_PIN_FLAG_SO_PIN)

typedef struct _pgp_pin_cfg {
	const char	*label;
	int		reference;
	unsigned int	flags;
	int		min_length;
	int		do_index;
} pgp_pin_cfg_t;

/* OpenPGP cards v1:
 * "Signature PIN2 & "Encryption PIN" are two different PINs - not sync'ed by hardware
 */
static const pgp_pin_cfg_t	pin_cfg_v1[3] = {
	{ "Signature PIN",  0x81, PGP_USER_PIN_FLAGS,  6, 0 },	// used for PSO:CDS
	{ "Encryption PIN", 0x82, PGP_USER_PIN_FLAGS,  6, 1 },	// used for PSO:DEC, INT-AUT, {GET,PUT} DATA
	{ "Admin PIN",      0x83, PGP_ADMIN_PIN_FLAGS, 8, 2 }
};
/* OpenPGP cards v2:
 * "User PIN (sig)" & "User PIN" are the same PIN, but c$use different references depending on action
 */
static const pgp_pin_cfg_t	pin_cfg_v2[3] = {
	{ "User PIN (sig)", 0x81, PGP_USER_PIN_FLAGS,  6, 0 },	// used for PSO:CDS
	{ "User PIN",       0x82, PGP_USER_PIN_FLAGS,  6, 0 },	// used for PSO:DEC, INT-AUT, {GET,PUT} DATA
	{ "Admin PIN",      0x83, PGP_ADMIN_PIN_FLAGS, 8, 2 }
};


#define PGP_SIG_PRKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_SIGN \
				| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER \
				| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define	PGP_ENC_PRKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_DECRYPT \
				| SC_PKCS15_PRKEY_USAGE_UNWRAP)
#define PGP_AUTH_PRKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)

#define	PGP_SIG_PUBKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_VERIFY \
				| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER)
#define	PGP_ENC_PUBKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_ENCRYPT \
				| SC_PKCS15_PRKEY_USAGE_WRAP)
#define	PGP_AUTH_PUBKEY_USAGE	(SC_PKCS15_PRKEY_USAGE_VERIFY)

typedef	struct _pgp_key_cfg {
	const char	*label;
	const char	*pubkey_path;
	int		prkey_pin;
	int		prkey_usage;
	int		pubkey_usage;
} pgp_key_cfg_t;

static const pgp_key_cfg_t key_cfg[3] = {
	{ "Signature key",      "B601", 1, PGP_SIG_PRKEY_USAGE,  PGP_SIG_PUBKEY_USAGE  },
	{ "Encryption key",     "B801", 2, PGP_ENC_PRKEY_USAGE,  PGP_ENC_PUBKEY_USAGE  },
	{ "Authentication key", "A401", 2, PGP_AUTH_PRKEY_USAGE, PGP_AUTH_PUBKEY_USAGE }
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
	const pgp_pin_cfg_t *pin_cfg = (card->type == SC_CARD_TYPE_OPENPGP_V2) ? pin_cfg_v2 : pin_cfg_v1;

	set_string(&p15card->tokeninfo->label, "OpenPGP card");
	set_string(&p15card->tokeninfo->manufacturer_id, "OpenPGP project");

	if ((r = read_file(card, "004f", buffer, sizeof(buffer))) < 0)
		goto failed;
	sc_bin_to_hex(buffer, (size_t)r, string, sizeof(string), 0);
	set_string(&p15card->tokeninfo->serial_number, string);

	p15card->tokeninfo->version = (card->type == SC_CARD_TYPE_OPENPGP_V2) ? 2 : 1;
	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_EID_COMPLIANT;

	/* Extract preferred language */
	r = read_file(card, "0065:5f2d", string, sizeof(string)-1);
	if (r < 0)
		goto failed;
	string[r] = '\0';
	set_string(&p15card->tokeninfo->preferred_language, string);

	/* Get Application Related Data (006E) */
	if ((r = sc_get_data(card, 0x006E, buffer, sizeof(buffer))) < 0)
		goto failed;

	/* Get CHV status bytes from DO 006E/0073/00C4:
	 *  00:		1 == user consent for signature PIN
	 *		(i.e. PIN still valid for next PSO:CDS command)
	 *  01-03:	max length of pins 1-3
	 *  04-07:	tries left for pins 1-3
	 */
	if ((r = read_file(card, "006E:0073:00C4", buffer, sizeof(buffer))) < 0)
		goto failed;
	if (r != 7) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
			"CHV status bytes have unexpected length (expected 7, got %d)\n", r);
		return SC_ERROR_OBJECT_NOT_VALID;
	}

	/* Add PIN codes */
	for (i = 0; i < 3; i++) {
		sc_pkcs15_auth_info_t pin_info;
		sc_pkcs15_object_t   pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj,  0, sizeof(pin_obj));

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.auth_id.len      = 1;
		pin_info.auth_id.value[0] = i + 1;
		pin_info.attrs.pin.reference     = pin_cfg[i].reference;
		pin_info.attrs.pin.flags         = pin_cfg[i].flags;
		pin_info.attrs.pin.type          = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length    = pin_cfg[i].min_length;
		pin_info.attrs.pin.stored_length = buffer[1 + pin_cfg[i].do_index];
		pin_info.attrs.pin.max_length    = buffer[1 + pin_cfg[i].do_index];
		pin_info.attrs.pin.pad_char      = '\0';
		pin_info.tries_left = buffer[4 + pin_cfg[i].do_index];

		sc_format_path("3F00", &pin_info.path);

		strlcpy(pin_obj.label, pin_cfg[i].label, sizeof(pin_obj.label));
		pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			return SC_ERROR_INTERNAL;
	}

	/* XXX: check if "halfkeys" can be stored with gpg2. If not, add keypairs in one loop */
	for (i = 0; i < 3; i++) {
		sc_pkcs15_prkey_info_t prkey_info;
		sc_pkcs15_object_t     prkey_obj;
		char path_template[] = "006E:0073:00C0";

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj,  0, sizeof(prkey_obj));

		path_template[13] = '1' + i; /* The needed tags are C1 C2 and C3 */
		if ((r = read_file(card, path_template, buffer, sizeof(buffer))) < 0)
			goto failed;
		if (r != 6) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Key info bytes have unexpected length(expected 6, got %d)\n", r);
			return SC_ERROR_INTERNAL;
		}

		/* only add valid keys, i.e. those with a legal algorithm identifier */
		if (buffer[0] != 0) {
			prkey_info.id.len         = 1;
			prkey_info.id.value[0]    = i + 1;
			prkey_info.usage          = key_cfg[i].prkey_usage;
			prkey_info.native         = 1;
			prkey_info.key_reference  = i;
			prkey_info.modulus_length = bebytes2ushort(buffer + 1);

			strlcpy(prkey_obj.label, key_cfg[i].label, sizeof(prkey_obj.label));
			prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE;
			prkey_obj.auth_id.len      = 1;
			prkey_obj.auth_id.value[0] = key_cfg[i].prkey_pin;

			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			if (r < 0)
				return SC_ERROR_INTERNAL;
		}
	}
	/* Add public keys */
	for (i = 0; i < 3; i++) {
		sc_pkcs15_pubkey_info_t pubkey_info;
		sc_pkcs15_object_t      pubkey_obj;
		char path_template[] = "006E:0073:00C0";

		memset(&pubkey_info, 0, sizeof(pubkey_info));
		memset(&pubkey_obj,  0, sizeof(pubkey_obj));

		path_template[13] = '1' + i; /* The needed tags are C1 C2 and C3 */
		if ((r = read_file(card, path_template, buffer, sizeof(buffer))) < 0)
			goto failed;
		if (r != 6) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Key info bytes have unexpected length(expected 6, got %d)\n", r);
			return SC_ERROR_INTERNAL;
		}

		/* only add valid keys, i.e. those with a legal algorithm identifier */
		if (buffer[0] != 0) {
			pubkey_info.id.len         = 1;
			pubkey_info.id.value[0]    = i + 1;
			pubkey_info.modulus_length = bebytes2ushort(buffer + 1);
			pubkey_info.usage          = key_cfg[i].pubkey_usage;
			sc_format_path(key_cfg[i].pubkey_path, &pubkey_info.path);

			strlcpy(pubkey_obj.label, key_cfg[i].label, sizeof(pubkey_obj.label));
			pubkey_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

			r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
			if (r < 0)
				return SC_ERROR_INTERNAL;
		}
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
