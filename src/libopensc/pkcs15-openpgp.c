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

/*
 * Much of this code probably needs to be shared between
 * emulators. Will move this to pkcs15-syn.c when needed.
 */
static sc_pkcs15_df_t *
sc_pkcs15emu_get_df(sc_pkcs15_card_t *p15card, int type)
{
	sc_pkcs15_df_t	*df;
	sc_file_t	*file;
	int		created = 0;

	while (1) {
		for (df = p15card->df_list; df; df = df->next) {
			if (df->type == type) {
				if (created)
					df->enumerated = 1;
				return df;
			}
		}

		assert(created == 0);

		file = sc_file_new();
		sc_format_path("DEAD", &file->path);
		sc_pkcs15_add_df(p15card, type, &file->path, file);
		created++;
	}
}

static int
sc_pkcs15emu_add_object(sc_pkcs15_card_t *p15card, int type,
		const char *label, void *data,
		const sc_pkcs15_id_t *auth_id)
{
	sc_pkcs15_object_t *obj;
	int		df_type;

	obj = calloc(1, sizeof(*obj));
	obj->type  = type;
	obj->data  = data;
	if (label)
		strncpy(obj->label, label, sizeof(obj->label)-1);

	if (!(p15card->flags & SC_PKCS15_CARD_FLAG_READONLY))
		obj->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
	if (auth_id)
		obj->auth_id = *auth_id;

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_AUTH:
		obj->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
		df_type = SC_PKCS15_AODF;
		break;
	case SC_PKCS15_TYPE_PRKEY:
		obj->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
		df_type = SC_PKCS15_PRKDF;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		df_type = SC_PKCS15_PUKDF;
		break;
	case SC_PKCS15_TYPE_CERT:
		df_type = SC_PKCS15_CDF;
		break;
	default:
		sc_error(p15card->card->ctx,
			"Unknown PKCS15 object type %d\n", type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	obj->df = sc_pkcs15emu_get_df(p15card, df_type);
	sc_pkcs15_add_object(p15card, obj);

	return 0;
}

static int
sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id, const char *label,
		const sc_path_t *path, int ref, int type,
		unsigned int min_length,
		unsigned int max_length,
		int flags, int tries_left)
{
	sc_pkcs15_pin_info_t *info;

	info = (sc_pkcs15_pin_info_t *) calloc(1, sizeof(*info));
	info->auth_id		= *id;
	info->min_length	= min_length;
	info->max_length	= max_length;
	info->stored_length	= max_length;
	info->type		= type;
	info->reference		= ref;
	info->flags		= flags;
	info->tries_left	= tries_left;
	info->magic		= SC_PKCS15_PIN_MAGIC;

	if (path)
		info->path = *path;
	if (type == SC_PKCS15_PIN_TYPE_BCD)
		info->stored_length /= 2;

	return sc_pkcs15emu_add_object(p15card,
				SC_PKCS15_TYPE_AUTH_PIN,
				label, info, NULL);
}

static int
sc_pkcs15emu_add_prkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label,
		int type, unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		sc_pkcs15_id_t *auth_id)
{
	sc_pkcs15_prkey_info_t *info;

	info = (sc_pkcs15_prkey_info_t *) calloc(1, sizeof(*info));
	info->id		= *id;
	info->modulus_length	= modulus_length;
	info->usage		= usage;
	info->native		= 1;
	info->access_flags	= SC_PKCS15_PRKEY_ACCESS_SENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
				| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
				| SC_PKCS15_PRKEY_ACCESS_LOCAL;
	info->key_reference	= ref;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card,
				type, label, info, auth_id);
}

static int
sc_pkcs15emu_add_pubkey(sc_pkcs15_card_t *p15card,
		const sc_pkcs15_id_t *id,
		const char *label, int type,
		unsigned int modulus_length, int usage,
		const sc_path_t *path, int ref,
		const sc_pkcs15_id_t *auth_id)
{
	sc_pkcs15_pubkey_info_t *info;

	info = (sc_pkcs15_pubkey_info_t *) calloc(1, sizeof(*info));
	info->id		= *id;
	info->modulus_length	= modulus_length;
	info->usage		= usage;
	info->access_flags	= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
	info->key_reference	= ref;

	if (path)
		info->path = *path;

	return sc_pkcs15emu_add_object(p15card, type, label, info, auth_id);
}

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
	return sc_read_binary(card, 0, buf, len, 0);
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
				0, buffer[1+i], flags, buffer[4+i]);
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
				&auth_id);
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
				&path, 0, &auth_id);
	}

	return 0;

failed:	sc_error(card->ctx, "Failed to initialize OpenPGP emulation: %s\n",
			sc_strerror(r));
	return r;

}
