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

/*
 * Initialize the Application DF and store the PINs
 *
 */
static int miocos_init_app(struct sc_profile *profile, struct sc_card *card)
{
#if 0
	struct pin_info	*pin1, *pin2;
	int		lockit = 0;

	pin1 = sc_profile_find_pin(profile, "CHV1");
	pin2 = sc_profile_find_pin(profile, "CHV2");
	if (pin1 == NULL) {
		fprintf(stderr, "No CHV1 defined\n");
		return 1;
	}

	/* XXX TODO:
	 * if the CHV2 pin file is required to create files
	 * in the application DF, create that file first */

	/* Create the application DF */
	if (do_create_file(profile, profile->df_info.file))
		return 1;

	/* Store CHV2 */
	lockit = 0;
	if (pin2) {
		if (gpk_store_pin(profile, card, pin2, &lockit))
			return 1;
		/* If both PINs reside in the same file, don't lock
		 * it yet. */
		if (pin1->file != pin2->file && lockit) {
			if (gpk_lock_pinfile(profile, card, pin2->file->file))
				return 1;
			lockit = 0;
		}
	}

	/* Store CHV1 */
	if (gpk_store_pin(profile, card, pin1, &lockit))
		return 1;
	
	if (lockit && gpk_lock_pinfile(profile, card, pin2->file->file))
		return 1;
#endif
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
