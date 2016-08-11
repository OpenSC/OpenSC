/*
 * PKCS15 emulation layer for JPKI(Japanese Individual Number Cards).
 *
 * Copyright (C) 2016, HAMANO Tsukasa <hamano@osstech.co.jp>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/compat_strlcpy.h"
#include "common/compat_strlcat.h"

#include "internal.h"
#include "pkcs15.h"
#include "jpki.h"

int sc_pkcs15emu_jpki_init_ex(sc_pkcs15_card_t *, struct sc_aid *,
		sc_pkcs15emu_opt_t *);

static int
sc_pkcs15emu_jpki_init(sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	struct jpki_private_data *drvdata = JPKI_DRVDATA(card);
	int i, rc;

	LOG_FUNC_CALLED(p15card->card->ctx);

	p15card->tokeninfo->label = strdup("JPKI");
	p15card->tokeninfo->manufacturer_id = strdup("JPKI");
	/* set NULL until we found serial number */
	p15card->tokeninfo->serial_number = NULL;

	/* Select application directory */
	if (drvdata->selected != SELECT_JPKI_AP) {
		rc = jpki_select_ap(card);
		LOG_TEST_RET(card->ctx, rc, "select AP failed");
		drvdata->selected = SELECT_JPKI_AP;
	}

	/* add certificates */
	for (i = 0; i < 2; i++) {
		static const char *jpki_cert_names[2] = {
			"User Authentication Certificate",
			"Digital Signature Certificate"
		};
		static char const *jpki_cert_paths[2] = {
			"000A",
			"0001"
		};
		static int jpki_cert_ids[2] = { 1, 2 };

		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;
		memset(&cert_info, 0, sizeof (cert_info));
		memset(&cert_obj, 0, sizeof (cert_obj));

		cert_info.id.value[0] = jpki_cert_ids[i];
		cert_info.id.len = 1;
		sc_format_path(jpki_cert_paths[i], &cert_info.path);
		cert_info.path.type = SC_PATH_TYPE_FILE_ID;

		strlcpy(cert_obj.label, jpki_cert_names[i], sizeof (cert_obj.label));
		cert_obj.flags = 0;

		rc = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (rc < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	}

	/* add pins */
	for (i = 0; i < 2; i++) {
		static const char *jpki_pin_names[2] = {
			"User Authentication PIN",
			"Digital Signature PIN"
		};
		static const int jpki_pin_min[2] = { 4, 6 };
		static const int jpki_pin_max[2] = { 4, 16 };
		static const int jpki_pin_ref[2] = { 1, 2 };
		static const int jpki_pin_authid[2] = { 1, 2 };
		static const int jpki_pin_flags[2] = { 0, 0 };
		static const int jpki_pin_max_tries[2] = { 5, 3 };

		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;
		struct sc_pin_cmd_data pin_cmd_data;
		memset(&pin_info, 0, sizeof (pin_info));
		memset(&pin_obj, 0, sizeof (pin_obj));
		memset(&pin_cmd_data, 0, sizeof(pin_cmd_data));

		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = jpki_pin_authid[i];
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.attrs.pin.reference = jpki_pin_ref[i];
		pin_info.attrs.pin.flags = jpki_pin_flags[i];
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = jpki_pin_min[i];
		pin_info.attrs.pin.stored_length = 0;
		pin_info.attrs.pin.max_length = jpki_pin_max[i];
		pin_info.attrs.pin.pad_char = '\0';
		pin_info.max_tries = jpki_pin_max_tries[i];
		pin_info.tries_left = -1;
		pin_info.logged_in = SC_PIN_STATE_UNKNOWN;

		pin_cmd_data.cmd = SC_PIN_CMD_GET_INFO;
		pin_cmd_data.pin_type = SC_AC_CHV;
		pin_cmd_data.pin_reference = jpki_pin_ref[i];
		rc = sc_pin_cmd(card, &pin_cmd_data, &pin_info.tries_left);
		LOG_TEST_RET(card->ctx, rc, "sc_pin_cmd failed");
		strlcpy(pin_obj.label, jpki_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = jpki_pin_flags[i];

		rc = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (rc < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	/* add private keys */
	for (i = 0; i < 2; i++) {
		static int prkey_pin[2] = { 1, 2 };
		static int prkey_usage[2] = {
			SC_PKCS15_PRKEY_USAGE_SIGN,
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
		};
		static const char *prkey_name[2] = {
			"User Authentication Key",
			"Digital Signature Key"
		};

		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;

		memset(&prkey_info, 0, sizeof (prkey_info));
		memset(&prkey_obj, 0, sizeof (prkey_obj));

		prkey_info.id.len = 1;
		prkey_info.id.value[0] = prkey_pin[i];
		prkey_info.usage = prkey_usage[i];
		prkey_info.native = 1;
		prkey_info.key_reference = i + 1;
		prkey_info.modulus_length = 2048;

		strlcpy(prkey_obj.label, prkey_name[i], sizeof (prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = prkey_pin[i];
		prkey_obj.user_consent = 0;
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		rc = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (rc < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_jpki_init_ex(sc_pkcs15_card_t * p15card,
			  struct sc_aid *aid, sc_pkcs15emu_opt_t * opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK) {
		return sc_pkcs15emu_jpki_init(p15card);
	}
	else {
		if (p15card->card->type != SC_CARD_TYPE_JPKI_BASE)
			return SC_ERROR_WRONG_CARD;

		return sc_pkcs15emu_jpki_init(p15card);
	}
}
