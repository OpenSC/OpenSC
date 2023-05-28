/*
 * PKCS15 emulation layer for Slovak eID card v4
 *
 * Copyright (C) 2023 Juraj Šarinay <juraj@sarinay.com>
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

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "log.h"
#include "pkcs15.h"

static const struct sc_aid skeid4_aid_esign = {{0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E
}, 10};

static int sc_pkcs15emu_skeid4_init(sc_pkcs15_card_t * p15card)
{
	int r;
	int i;

	sc_path_t esign_path;

	sc_path_set(&esign_path, SC_PATH_TYPE_DF_NAME, skeid4_aid_esign.value, skeid4_aid_esign.len, 0, 0);
	r = sc_select_file(p15card->card, &esign_path, NULL);
	LOG_TEST_RET(p15card->card->ctx, r, "Error selecting the ESIGN application.");

	set_string(&p15card->tokeninfo->label, "eID karta");
	set_string(&p15card->tokeninfo->manufacturer_id, "Idemia Idenity & Security France");

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	const char *skeid4_cert_names[3] = {
		"Kvalifikovany certifikat pre elektronicky podpis",
		"Certifikat pre elektronicky podpis",
		"Sifrovaci certifikat"
	};

	for (int i = 0; i < 3; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		u8 *cert_der = NULL;
		size_t cert_len = 0;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id.value[0] = i + 1;
		cert_info.id.len = 1;

		strlcpy(cert_obj.label, skeid4_cert_names[i], sizeof(cert_obj.label));

		r = iso7816_read_binary_sfid(p15card->card, i+1, &cert_der, &cert_len);

		cert_info.value.value = cert_der;
		cert_info.value.len = cert_len;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding certificate.");
	}

	/* add pins */
	const char *skeid4_pin_names[2] = {
		"BOK",
		"Podpisovy PIN"
	};

	const unsigned int skeid4_pin_max_length[2] = {6, 10};
	const unsigned int skeid4_pin_max_tries[2] = {5, 3};
	const int skeid4_pin_ref[2] = {0x03, 0x81};

	const unsigned int skeid4_pin_flags[2] =	{SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA | SC_PKCS15_PIN_FLAG_INITIALIZED,
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA | SC_PKCS15_PIN_FLAG_INITIALIZED};

	for (i = 0; i < 2; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));

		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = i + 1;
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.attrs.pin.reference = skeid4_pin_ref[i];
		pin_info.attrs.pin.flags = skeid4_pin_flags[i];
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = 6;
		pin_info.attrs.pin.max_length = skeid4_pin_max_length[i];
		pin_info.max_tries = skeid4_pin_max_tries[i];

		strlcpy(pin_obj.label, skeid4_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = skeid4_pin_flags[i];

		/* sc_path_set(&pin_info.path, SC_PATH_TYPE_DF_NAME, skeid4_aid_esign.value, skeid4_aid_esign.len, 0, 0); */

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding PIN.");
	}

	/* add private keys */
	const u8 skeid4_prkey_pin[3] = {2, 1, 1};

	const int skeid4_prkey_ref[3] = {0x50, 0x60, 0x65};
	const int skeid4_prkey_usage[3] =
		{ SC_PKCS15_PRKEY_USAGE_NONREPUDIATION | SC_PKCS15_PRKEY_USAGE_SIGN,
		  SC_PKCS15_PRKEY_USAGE_SIGN,
		  SC_PKCS15_PRKEY_USAGE_DECRYPT
		};

	const char *skeid4_prkey_name[3] = {
		"Podpisovy kluc (KEP)",
		"Podpisovy kluc",
		"Sifrovaci kluc",
	};

	for (i = 0; i < 3; i++) {
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));

		prkey_info.id.len = 1;
		prkey_info.id.value[0] = i + 1;
		prkey_info.native = 1;
		prkey_info.key_reference = skeid4_prkey_ref[i];
		prkey_info.modulus_length = 3072;
		/* sc_path_set( &prkey_info.path, SC_PATH_TYPE_DF_NAME, skeid4_aid_esign.value, skeid4_aid_esign.len, 0, 0); */

		prkey_info.usage = skeid4_prkey_usage[i];

		strlcpy(prkey_obj.label, skeid4_prkey_name[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = skeid4_prkey_pin[i];
		if (i == 0) prkey_obj.user_consent = 1;

		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding private key.");
	}
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_skeid4_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	int r = SC_ERROR_WRONG_CARD;

	if (p15card->card->type == SC_CARD_TYPE_SKEID_V4) r = sc_pkcs15emu_skeid4_init(p15card);
	return r;
}
