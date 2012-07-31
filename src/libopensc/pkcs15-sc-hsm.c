/*
 * pkcs15-sc-hsm.c : Initialize PKCS#15 emulation
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany
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

#include "internal.h"
#include "pkcs15.h"
#include "asn1.h"

#include "card-sc-hsm.h"


/* Our AID */
static struct sc_aid sc_hsm_aid = { { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 }, 11 };

/*
 * Initialize PKCS#15 emulation with user PIN, private keys and certificate objects
 *
 */
static int sc_pkcs15emu_sc_hsm_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	sc_file_t *file = NULL;
	sc_path_t path;
	u8 filelist[MAX_EXT_APDU_LENGTH];
	int filelistlength;
	int r, i;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	p15card->tokeninfo->label = strdup("SmartCard-HSM");
	p15card->tokeninfo->manufacturer_id = strdup("CardContact");

	struct sc_app_info *appinfo = calloc(1, sizeof(struct sc_app_info));

	if (appinfo == NULL) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	}

	appinfo->label = strdup(p15card->tokeninfo->label);
	appinfo->aid = sc_hsm_aid;

	appinfo->ddo.aid = sc_hsm_aid;
	p15card->app = appinfo;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_select_file(card, &path, &file);

	// ToDo: Extract version number
	sc_file_free(file);

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not select SmartCard-HSM application");

	// Define UserPIN
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;

	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = 1;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = 0x81;
	pin_info.attrs.pin.flags = 0;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 4;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length = 16;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = 3;
	pin_info.max_tries = 3;

	strlcpy(pin_obj.label, "UserPIN", sizeof(pin_obj.label));
	pin_obj.flags = pin_info.attrs.pin.flags;

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	if (r < 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);

	filelistlength = sc_list_files(card, filelist, sizeof(filelist));
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not enumerate file and key identifier");

	for (i = 0; i < filelistlength; i += 2) {
		/* Look for private key files */
		if (filelist[i] != KEY_PREFIX) {
			continue;
		}

		u8 fid[2];
		u8 prkdbin[512];
		sc_pkcs15_object_t prkd;
		u8 keyid = filelist[i + 1];

		fid[0] = PRKD_PREFIX;
		fid[1] = keyid;

		/* Try to select a related EF containing the PKCS#15 description of the key */
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, &file);

		if (r != SC_SUCCESS) {
			continue;
		}

		sc_file_free(file);
		r = sc_read_binary(p15card->card, 0, prkdbin, sizeof(prkdbin), 0);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not read EF.PRKD");

		memset(&prkd, 0, sizeof(prkd));
		const u8 *ptr = prkdbin;
		size_t len = r;

		sc_pkcs15_decode_prkdf_entry(p15card, &prkd, &ptr, &len);

		/* All keys require user PIN authentication */
		prkd.auth_id.len = 1;
		prkd.auth_id.value[0] = 1;

		/*
		 * Set private key flag as all keys are private anyway
		 */
		prkd.flags |= SC_PKCS15_CO_FLAG_PRIVATE;

		sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *)prkd.data;
		key_info->key_reference = keyid;

		/*
		 * Set path.aid.len to 0 to prevent re-selection of applet when using the key
		 */
		key_info->path.aid.len = 0;

		if (prkd.type == SC_PKCS15_TYPE_PRKEY_RSA) {
			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkd, key_info);
		} else {
			r = sc_pkcs15emu_add_ec_prkey(p15card, &prkd, key_info);
		}
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not decode EF.PRKD");

		/* Check if we also have a certificate for the private key */
		fid[0] = EE_CERTIFICATE_PREFIX;

		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0);
		r = sc_select_file(card, &path, &file);

		if (r != SC_SUCCESS) {
			continue;
		}

		sc_file_free(file);

		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id.value[0] = keyid;
		cert_info.id.len = 1;
		cert_info.path = path;
		cert_info.path.count = -1;

		strlcpy(cert_obj.label, prkd.label, sizeof(cert_obj.label));
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Could not add certificate");
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}



int sc_pkcs15emu_sc_hsm_init_ex(sc_pkcs15_card_t *p15card,
				sc_pkcs15emu_opt_t *opts)
{
	if (opts && (opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		return sc_pkcs15emu_sc_hsm_init(p15card);
	} else {
		if (p15card->card->type != SC_CARD_TYPE_SC_HSM) {
			return SC_ERROR_WRONG_CARD;
		}
		return sc_pkcs15emu_sc_hsm_init(p15card);
	}
}
