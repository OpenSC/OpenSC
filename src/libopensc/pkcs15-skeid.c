/*
 * PKCS15 emulation layer for Slovak eID card
 *
 * Copyright (C) 2022 Juraj Šarinay <juraj@sarinay.com>
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
 *
 * based on the PKCS15 emulation layer for EstEID card by Martin Paljak
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "log.h"
#include "pkcs15.h"

static const struct sc_aid skeid_aid_qes = {{0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xA0, 0x00, 0x00, 0x08, 0x51, 0x00, 0x00, 0x11}, 13};

static int sc_pkcs15emu_skeid_init(sc_pkcs15_card_t * p15card)
{
	int r;
	int i;
	size_t sn_len;
	char *buf;

	set_string(&p15card->tokeninfo->label, "eID karta");
	set_string(&p15card->tokeninfo->manufacturer_id, "Atos Information Technology GmbH");

	sn_len = p15card->card->serialnr.len;
	if (sn_len > 0) {
		buf = malloc(2 * sn_len + 1);
		if (!buf) return SC_ERROR_OUT_OF_MEMORY;
		sc_bin_to_hex(p15card->card->serialnr.value, sn_len, buf,
			2 * sn_len + 1, 0);
		p15card->tokeninfo->serial_number = buf;
	}

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	const char *skeid_cert_names[3] = {
		"Kvalifikovany certifikat pre elektronicky podpis",
		"Certifikat pre elektronicky podpis",
		"Sifrovaci certifikat"
	};

	const char *skeid_cert_paths[3] = {
		"3f0001030201",
		"3f0001030202",
		"3f0001030203"
	};

	for (i = 0; i < 3; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id.value[0] = i + 1;
		cert_info.id.len = 1;

		sc_format_path(skeid_cert_paths[i], &cert_info.path);
		strlcpy(cert_obj.label, skeid_cert_names[i], sizeof(cert_obj.label));

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding certificate.");
	}

	/* add pins */
	const char *skeid_pin_names[2] = {
		"BOK",
		"Podpisovy PIN"
	};

	const unsigned int skeid_pin_max_length[2] = {6, 10};
	const unsigned int skeid_pin_max_tries[2] = {5, 3};
	const int skeid_pin_ref[2] = {0x03, 0x87};
	const char *skeid_pin_paths[2] = {"3F00", "3F000101"};

	const unsigned int skeid_pin_flags[2] =	{SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA | SC_PKCS15_PIN_FLAG_INITIALIZED,
		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA | SC_PKCS15_PIN_FLAG_INITIALIZED};

	for (i = 0; i < 2; i++) {
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));

		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = i + 1;
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.attrs.pin.reference = skeid_pin_ref[i];
		pin_info.attrs.pin.flags = skeid_pin_flags[i];
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = 6;
		pin_info.attrs.pin.max_length = skeid_pin_max_length[i];
		pin_info.max_tries = skeid_pin_max_tries[i];

		strlcpy(pin_obj.label, skeid_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = skeid_pin_flags[i];

		sc_format_path(skeid_pin_paths[i], &pin_info.path);

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding PIN.");
	}

	/* add private keys */
	const u8 skeid_prkey_pin[3] = {2, 1, 1};

	/* store seIdentifier rather than keyReference */
	const int skeid_prkey_ref[3] = {0x01, 0x34, 0x44};
	const int skeid_prkey_usage[3] =
		{ SC_PKCS15_PRKEY_USAGE_NONREPUDIATION | SC_PKCS15_PRKEY_USAGE_SIGN,
		  SC_PKCS15_PRKEY_USAGE_SIGN,
		  SC_PKCS15_PRKEY_USAGE_DECRYPT
		};

	const char *skeid_prkey_paths[3] = {"3F000101", "3F000102", "3F000102"};

	const char *skeid_prkey_name[3] = {
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
		prkey_info.key_reference = skeid_prkey_ref[i];
		prkey_info.modulus_length = 3072;
		sc_format_path(skeid_prkey_paths[i], &prkey_info.path);

		prkey_info.usage = skeid_prkey_usage[i];

		strlcpy(prkey_obj.label, skeid_prkey_name[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = skeid_prkey_pin[i];
		if (i == 0) prkey_obj.user_consent = 1;

		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);

		LOG_TEST_RET(p15card->card->ctx, r, "Error adding private key.");
	}
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_skeid_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	int r = SC_ERROR_WRONG_CARD;

	if (p15card->card->type == SC_CARD_TYPE_SKEID_V3
		&& (aid == NULL || (aid->len == skeid_aid_qes.len && !memcmp(aid->value, &skeid_aid_qes.value, skeid_aid_qes.len))))
		r = sc_pkcs15emu_skeid_init(p15card);

	return r;
}
