/*
 * MioCOS specific operation for PKCS15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <sys/types.h>
#include <string.h>
#include <openssl/bn.h>
#include "opensc.h"
#include "pkcs15-init.h"
#include "util.h"

static int miocos_update_pin(struct sc_card *card, struct pin_info *info)
{
	u8		buffer[20], *p = buffer;
	int		r;
	size_t		len;

	if (!info->puk.tries_left) {
		error("PUK code needed.");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	info->pin.tries_left &= 0x0f;
	*p++ = (info->pin.tries_left << 8) | info->pin.tries_left;
	*p++ = 0xFF;
	memset(p, info->pin.pad_char, 8);
	strncpy((char *) p, info->secret[0], 8);
	p += 8;
	info->puk.tries_left &= 0x0f;
	*p++ = (info->puk.tries_left << 8) | info->puk.tries_left;
	*p++ = 0xFF;
	strncpy((char *) p, info->secret[1], 8);
	p += 8;
	len = 20;

	r = sc_update_binary(card, 0, buffer, len, 0);
	if (r < 0)
		return r;
	return 0;
}

static int miocos_store_pin(struct sc_profile *profile, struct sc_card *card,
			   struct pin_info *info)
{
	struct sc_file	*pinfile;
	int		r;

	sc_file_dup(&pinfile, info->file->file);

	card->ctx->log_errors = 0;
	r = sc_select_file(card, &pinfile->path, NULL);
	card->ctx->log_errors = 1;
	pinfile->type = SC_FILE_TYPE_INTERNAL_EF;
	pinfile->ef_structure = 0;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		/* Now create the file */
		r = sc_pkcs15init_create_file(profile, card, pinfile);
		if (r < 0)
			goto out;
		/* The PIN EF is automatically selected */
	} else if (r < 0)
		goto out;

	/* If messing with the PIN file requires any sort of
	 * authentication, send it to the card now */
	r = sc_pkcs15init_authenticate(profile, card, pinfile, SC_AC_OP_UPDATE);
	if (r < 0)
		goto out;

	r = miocos_update_pin(card, info);

out:	sc_file_free(pinfile);
	return r;
}

/*
 * Initialize the Application DF and store the PINs
 */
static int miocos_init_app(struct sc_profile *profile, struct sc_card *card)
{
	struct pin_info	*pin1, *pin2;

	pin1 = sc_profile_find_pin(profile, "CHV1");
	pin2 = sc_profile_find_pin(profile, "CHV2");
	if (pin1 == NULL) {
		fprintf(stderr, "No CHV1 defined\n");
		return 1;
	}
	/* Create the application DF */
	if (sc_pkcs15init_create_file(profile, card, profile->df_info.file))
		return 1;

	if (pin2) {
		if (miocos_store_pin(profile, card, pin2))
			return 1;
	}
	if (miocos_store_pin(profile, card, pin1))
		return 1;

	return 0;
}

/*
 * Store a RSA key on the card
 */
static int miocos_store_rsa_key(struct sc_profile *profile,
				struct sc_card *card,
				struct sc_key_template *info,
			       	RSA *rsa)
{
	return 0;
}

void bind_miocos_operations(struct pkcs15_init_operations *ops)
{
	ops->erase_card = NULL;
	ops->init_app = miocos_init_app;
	ops->store_rsa = miocos_store_rsa_key;
	ops->store_dsa = NULL;
}
