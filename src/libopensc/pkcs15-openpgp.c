/*
 * PKCS15 emulation layer for OpenPGP card.
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

static sc_pkcs15_object_t *
sc_pkcs15emu_add_object(sc_pkcs15_card_t *p15card, int type,
		const char *label, void *data)
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
		return NULL;
	}

	obj->df = sc_pkcs15emu_get_df(p15card, df_type);
	sc_pkcs15_add_object(p15card, obj);

	return obj;
}

static int
sc_pkcs15emu_add_pin(sc_pkcs15_card_t *p15card,
		unsigned int id, const char *label,
		const sc_path_t *path, int ref, int type,
		unsigned int min_length,
		unsigned int max_length,
		int flags, int tries_left)
{
	sc_pkcs15_pin_info_t *info;

	info = (sc_pkcs15_pin_info_t *) calloc(1, sizeof(*info));
	info->auth_id.value[0]	= id;
	info->auth_id.len	= 1;
	info->min_length	= min_length;
	info->max_length	= max_length;
	info->stored_length	= max_length;
	info->type		= type;
	info->reference		= ref;
	info->flags		= flags;
	info->tries_left	= tries_left;

	if (path)
		info->path = *path;
	if (type == SC_PKCS15_PIN_TYPE_BCD)
		info->stored_length /= 2;

	sc_pkcs15emu_add_object(p15card, SC_PKCS15_TYPE_AUTH_PIN, label, info);

	return 0;
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
get_tlv(sc_context_t *ctx, unsigned int match_tag,
		const u8 *in, size_t in_len, 
		u8 *out, size_t out_len)
{
	const u8	*end = in + in_len;
	int		r;

	while (in < end) {
		unsigned int	tag, len;
		int		composite = 0;
		unsigned char	c;

		c = *in++;
		if (c == 0x00 || c == 0xFF)
			continue;

		tag = c;
		if (tag & 0x20)
			composite = 1;
		while ((c & 0x1f) == 0x1f) {
			if (in >= end)
				goto eoc;
			c = *in++;
			tag = (tag << 8) | c;
		}

		if (in >= end)
			goto eoc;
		c = *in++;
		if (c < 0x80) {
			len = c;
		} else {
			len = 0;
			c &= 0x7F;
			while (c--) {
				if (in >= end)
					goto eoc;
				len = (len << 8) | *in++;
			}
		}

		/* Don't search past end of content */
		if (in + len > end)
			goto eoc;

		if (tag == match_tag) {
			if (len > out_len)
				len = out_len;
			memcpy(out, in, len);
			return len;
		}

		/* Recurse into composite object.
		 * No need for recursion check, as we check the buffer
		 * length and each recursion consumes at least 2 bytes */
		if (composite) {
			r = get_tlv(ctx, match_tag, in, len, out, out_len);
			if (r != SC_ERROR_OBJECT_NOT_FOUND)
				return r;
		}

		in += len;
	}

	return SC_ERROR_OBJECT_NOT_FOUND;

eoc:	sc_error(ctx, "Unexpected end of contentsn");
	return SC_ERROR_OBJECT_NOT_VALID;
}

int
sc_pkcs15emu_openpgp_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t	*card = p15card->card;
	sc_context_t	*ctx = card->ctx;
	sc_path_t	path;
	sc_file_t	*file;
	char		string[256];
	u8		buffer[256], value[256];
	size_t		length;
	int		r, i;

	/* Select OpenPGP application.
	 * We must specify a file, because the card expects a
	 * case 4 APDU and barfs if it's case 2.
	 */
	sc_format_path("D276:0001:2401", &path);
	path.type = SC_PATH_TYPE_DF_NAME;
	if ((r = sc_select_file(card, &path, &file)) < 0)
		goto failed;
	sc_file_free(file);

	set_string(&p15card->label, "OpenPGP Card");
	set_string(&p15card->manufacturer_id, "OpenPGP project");

	if ((r = sc_get_data(card, 0x004f, buffer, sizeof(buffer))) < 0)
		goto failed;
	sc_bin_to_hex(buffer, r, string, sizeof(string), 0);
	set_string(&p15card->serial_number, string);
	p15card->version = (buffer[6] << 8) | buffer[7];

	p15card->flags = SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED |
			 SC_PKCS15_CARD_FLAG_PRN_GENERATION |
			 SC_PKCS15_CARD_FLAG_EID_COMPLIANT;

	/* Get Card Holder Related Data (0065) */
	if ((r = sc_get_data(card, 0x0065, buffer, sizeof(buffer))) < 0)
		goto failed;
	length = r;

	/* Extract preferred language */
	r = get_tlv(ctx, 0x5F2D, buffer, length, string, sizeof(string)-1);
	if (r > 0) {
		string[r] = '\0';
		set_string(&p15card->preferred_language, string);
	} else if (r != SC_ERROR_OBJECT_NOT_FOUND) {
		goto failed;
	}

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
	r = get_tlv(ctx, 0x00c4, buffer, length, value, sizeof(value));
	if (r < 0)
		goto failed;
	if (r != 7) {
		sc_error(ctx,
			"CHV status bytes have unexpected length "
			"(expected 7, got %d)\n", r);
		return SC_ERROR_OBJECT_NOT_VALID;
	}

	for (i = 0; i < 3; i++) {
		static char	*pin_name[3] = {
					"User PIN",
					"User PIN 2",
					"Admin PIN"
				};
		int		flags;

		flags =	SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
			SC_PKCS15_PIN_FLAG_INITIALIZED |
			SC_PKCS15_PIN_FLAG_LOCAL;
		if (i == 2) {
			flags |= SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED |
				 SC_PKCS15_PIN_FLAG_SO_PIN;
		}
		sc_pkcs15emu_add_pin(p15card, i+1, pin_name[i], NULL, i+1,
			SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
			0, value[1+i], flags, value[4+i]);
	}

	return 0;

failed:	sc_error(card->ctx, "Failed to initialize OpenPGP emulation: %s\n",
			sc_strerror(r));
	return r;

}
