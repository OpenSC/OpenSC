/*
 * PKCS15 emulation layer for EstEID card issued from December 2025.
 *
 * Copyright (C) 2025, Raul Metsma <raul@metsma.ee>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "opensc.h"
#include "pkcs15.h"

static int
sc_pkcs15emu_esteid2025_init(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;
	u8 *buff;
	int r, i;
	size_t field_length = 0, buflen = 9, j;
	sc_path_t tmppath;
	static const u8 prkey_id[2] = {0x01, 0x02};

	set_string(&p15card->tokeninfo->label, "ID-kaart");
	set_string(&p15card->tokeninfo->manufacturer_id, "Thales");

	buff = malloc(buflen + 1);
	if (!buff)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	/* Read document number to be used as serial */
	sc_format_path("DFDD5007", &tmppath);
	r = sc_select_file(card, &tmppath, NULL);
	if (r < 0) {
		free(buff);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}
	r = sc_read_binary(card, 0, buff, buflen, 0);
	if (r < 0) {
		free(buff);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}

	for (j = 0; j < buflen; j++) {
		if (!isalnum(buff[j])) {
			free(buff);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
		}
	}
	buff[buflen] = '\0';

	free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = (char *)buff;
	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	for (i = 0; i < 2; i++) {
		static const char *cert_names[2] = {"Isikutuvastus", "Allkirjastamine"};
		static const char *cert_paths[2] = {"ADF1:3411", "ADF2:3421"};

		struct sc_pkcs15_cert_info cert_info = {
				.id = {.len = 1, .value[0] = prkey_id[i]}
		 };
		struct sc_pkcs15_object cert_obj = {0};

		strlcpy(cert_obj.label, cert_names[i], sizeof(cert_obj.label));
		sc_format_path(cert_paths[i], &cert_info.path);
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not add cert object");

		if (i != 0)
			continue;

		sc_pkcs15_cert_t *cert = NULL;
		r = sc_pkcs15_read_certificate(p15card, &cert_info, 0, &cert);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not read authentication certificate");

		if (cert->key->algorithm == SC_ALGORITHM_EC)
			field_length = cert->key->u.ec.params.field_length;

		static const struct sc_object_id cn_oid = {
				{2, 5, 4, 3, -1}
		};
		u8 *cn_name = NULL;
		size_t cn_len = 0;
		r = sc_pkcs15_get_name_from_dn(card->ctx, cert->subject, cert->subject_len, &cn_oid, &cn_name, &cn_len);
		sc_pkcs15_free_certificate(cert);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not read authentication certificate");
		if (cn_len > 0) {
			char *token_name = (char *)realloc(cn_name, cn_len + 1);
			if (token_name) {
				token_name[cn_len] = '\0';
				free(p15card->tokeninfo->label);
				p15card->tokeninfo->label = token_name;
			} else
				free(cn_name);
		}
	}

	/* add pins */
	for (i = 0; i < 3; i++) {
		static const char *pin_names[3] = {"PIN1", "PIN2", "PUK"};
		static const size_t pin_min[3] = {4, 5, 8};
		static const int pin_ref[3] = {0x81, 0x82, 0x83};
		static const u8 pin_authid[3] = {1, 2, 3};

		static const unsigned int pin_flags[3] = {
				SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
				SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
				SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN};

		struct sc_pkcs15_auth_info pin_info = {
				.auth_id = {.len = 1, .value[0] = pin_authid[i]},
				.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN,
				.attrs = {
						.pin = {
								.reference = pin_ref[i],
								.flags = pin_flags[i],
								.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
								.min_length = pin_min[i],
								.stored_length = 12,
								.max_length = 12,
								.pad_char = 0x00}},
				.tries_left = 3,
				.max_tries = 3
		      };
		struct sc_pkcs15_object pin_obj = {.flags = pin_flags[i]};

		strlcpy(pin_obj.label, pin_names[i], sizeof(pin_obj.label));

		/* Link normal PINs with PUK */
		if (i < 2) {
			pin_obj.auth_id.len = 1;
			pin_obj.auth_id.value[0] = 3;
		}

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not add pin object");
	}

	// trigger PIN counter refresh via pin_cmd
	struct sc_pkcs15_object *objs[3];
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH, objs, 3);
	if (r != 3) {
		sc_log(card->ctx, "Can not get auth objects");
		goto err;
	}
	for (i = 0; i < r; i++) {
		r = sc_pkcs15_get_pin_info(p15card, objs[i]);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not get pin object");
	}

	/* add private keys */
	for (i = 0; i < 2; i++) {
		static const u8 prkey_ref[2] = {0x01, 0x05};
		static const u8 prkey_pin[2] = {1, 2};
		static const char *prkey_name[2] = {"Isikutuvastus", "Allkirjastamine"};
		static const unsigned int prkey_usage[2] = {SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DERIVE,
				SC_PKCS15_PRKEY_USAGE_NONREPUDIATION};
		static const int prkey_consent[2] = {0, 1};

		struct sc_pkcs15_prkey_info prkey_info = {
				.id = {.len = 1, .value[0] = prkey_id[i]},
				.native = 1,
				.key_reference = prkey_ref[i],
				.field_length = field_length,
				.usage = prkey_usage[i]
		       };
		struct sc_pkcs15_object prkey_obj = {
				.auth_id = {.len = 1, .value[0] = prkey_pin[i]},
				.user_consent = prkey_consent[i],
				.flags = SC_PKCS15_CO_FLAG_PRIVATE
		  };

		strlcpy(prkey_obj.label, prkey_name[i], sizeof(prkey_obj.label));

		r = sc_pkcs15emu_add_ec_prkey(p15card, &prkey_obj, &prkey_info);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not add private key object");
	}

	return SC_SUCCESS;
err:
	sc_pkcs15_card_clear(p15card);
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
}

int
sc_pkcs15emu_esteid2025_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	if (p15card->card->type == SC_CARD_TYPE_ESTEID_2025)
		return sc_pkcs15emu_esteid2025_init(p15card);
	return SC_ERROR_WRONG_CARD;
}
