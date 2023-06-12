/*
 * Support for the eOI card.
 *
 * Copyright (C) 2022 Luka Logar <luka.logar@iname.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "log.h"
#include "pkcs15.h"

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)

#include "cards.h"
#include "card-eoi.h"

int sc_pkcs15emu_eoi_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_card *card = p15card->card;
	struct eoi_privdata *privdata = (struct eoi_privdata *)card->drv_data;
	struct sc_pkcs15_search_key sk;
	struct sc_pkcs15_object *objs[MAX_OBJECTS];
	int i, j, len;

	LOG_FUNC_CALLED(card->ctx);

	if (card->type != SC_CARD_TYPE_EOI && card->type != SC_CARD_TYPE_EOI_CONTACTLESS)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_CARD);

	if (!privdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	/*
	 * Some of the data is not accessible over the unencrypted channel
	 * when contactless reader is used. So start SM now (if not yet establisahed).
	 */
	if (card->type == SC_CARD_TYPE_EOI_CONTACTLESS && card->sm_ctx.sm_mode == SM_MODE_NONE) {
		int r = card->sm_ctx.ops.open(card);
		if (r != SC_SUCCESS)
			LOG_FUNC_RETURN(card->ctx, r);
	}

	/*
	 * Get the card objects, so we can manipulate them. See below
	 */
	LOG_TEST_RET(card->ctx, sc_pkcs15_bind_internal(p15card, aid),
		"sc_pkcs15_bind_internal failed");

	/*
	 * PIN objects:
	 * 1) Find the "Card CAN" PIN and store it's path, so we'll be able to fetch the CAN and do the PACE auth
	 * 2) Add PIN's auth_info->path to the list of paths that can fail on select. sc_pin_cmd would break otherwise
	 */
	memset(&sk, 0, sizeof(sk));
	sk.class_mask = SC_PKCS15_SEARCH_CLASS_AUTH;
	len = sc_pkcs15_search_objects(p15card, &sk, (struct sc_pkcs15_object **)&objs, MAX_OBJECTS);
	for (i = 0, j = 0; i < len; i++) {
		struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *)objs[i]->data;
		if (auth_info && auth_info->auth_id.len == 8 && !strcmp((char*)auth_info->auth_id.value, "Card CAN")) {
			auth_info->path.type = SC_PATH_TYPE_PATH;
			/* Read the file that contains serial and encrypted CAN */
			if (sc_pkcs15_read_file(p15card, &auth_info->path, &privdata->enc_can.value, &privdata->enc_can.len, 0) == SC_SUCCESS) {
				/* File should be 24 bytes long */
				if (privdata->enc_can.len != 24)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_CORRUPTED_DATA);
				if (strlen(p15card->tokeninfo->serial_number) != 20)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_CORRUPTED_DATA);
				/* First 8 bytes are used as serial number */
				sc_bin_to_hex(privdata->enc_can.value, 8, &p15card->tokeninfo->serial_number[4], 17, 0);
			}
			/* Do not add "Card CAN" to the list of PIN paths to ignore, otherwise the 2nd PKCS#15 app can not access it */
			auth_info = NULL;
			/* Mark "Card CAN" as NOT a PIN object, so that it doesn't get it's own PKCS#11 slot */
			objs[i]->type &= ~SC_PKCS15_TYPE_AUTH_PIN;
		}
		/*
		 * For some reason QES app has "Norm PUK" not flagged as unblocking PIN and thus "Norm PUK" appears as a slot in
		 * PKCS#11. Flag it as unblockingPin, so it doesn't appear as a separate slot.
		 */
		if (auth_info && auth_info->auth_id.len == 8 && !strcmp((char*)auth_info->auth_id.value, "Norm PUK")) {
			auth_info->attrs.pin.flags |= SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
		}
		if (auth_info) {
			privdata->pin_paths[j++] = &auth_info->path;
		}
	}

	/*
	 * Private key objects:
	 * 1) Rename "Card PIN" to "Norm PIN" as it's the later name that is used throughout the PKCS#15 objects
	 * 2) Add the key references to the prkey_mappings array, as it seems that eOI expects them counted from 0xA0 up (starting from 1 within each app)
	 *    Currently there are 3 private keys on the card
	 *     key_ref
	 *       2 - for pinless entry (Prijava brez PIN-a), maps to 0xA1
	 *       1 - for authentication in QES app (Podpis in prijava), maps to 0xA1
	 *       3 - for signing in QES app (Podpis in prijava), maps to 0xA2
	 */
	memset(&sk, 0, sizeof(sk));
	sk.class_mask = SC_PKCS15_SEARCH_CLASS_PRKEY;
	len = sc_pkcs15_search_objects(p15card, &sk, (struct sc_pkcs15_object **)&objs, MAX_OBJECTS);
	/*
	 * If both PKCS#15 apps are enabled, prkey_mappings can already be partially filled up from the first PKCS#15 app
	 * as the privdata is shared between both apps which use the same driver
	  */
	for (j = 0; privdata->prkey_mappings[j][1] != 0; j++) {
		/* NOP */
	}
	for (i = 0; i < len; i++) {
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)objs[i]->data;
		if ((objs[i]->auth_id.len == 8) && !strncmp((char*)objs[i]->auth_id.value, "Card PIN", 8)) {
			memcpy(objs[i]->auth_id.value, "Norm PIN", 8);
		}
		if (prkey_info) {
			privdata->prkey_mappings[j][0] = prkey_info->key_reference;
			privdata->prkey_mappings[j++][1] = 0xA0 + (i + 1);
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

#else

int sc_pkcs15emu_eoi_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_WRONG_CARD);
}

#endif
