/*
 * PKCS15 emulation layer for EstEID card issued from December 2018.
 *
 * Copyright (C) 2019, Martin Paljak <martin@martinpaljak.net>
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compat_strlcpy.h"

#include "internal.h"
#include "opensc.h"
#include "pkcs15.h"

static void set_string(char **strp, const char *value) {
	if (*strp)
		free(*strp);
	*strp = value ? strdup(value) : NULL;
}

static int sc_pkcs15emu_esteid2018_init(sc_pkcs15_card_t *p15card) {
	sc_card_t *card = p15card->card;
	u8 buff[11];
	int r, i;
	size_t field_length = 0, taglen, j;
	sc_path_t tmppath;

	set_string(&p15card->tokeninfo->label, "ID-kaart");
	set_string(&p15card->tokeninfo->manufacturer_id, "IDEMIA");

	/* Read documber number to be used as serial */
	sc_format_path("3F00D003", &tmppath);
	LOG_TEST_RET(card->ctx, sc_select_file(card, &tmppath, NULL), "SELECT docnr");
	r = sc_read_binary(card, 0, buff, 11, 0);
	LOG_TEST_RET(card->ctx, r, "read document number failed");
	const unsigned char *tag = sc_asn1_find_tag(card->ctx, buff, (size_t)r, 0x04, &taglen);
	if (tag == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	for (j = 0; j < taglen; j++)
		if (!isalnum(tag[j]))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	p15card->tokeninfo->serial_number = malloc(taglen + 1);
	if (!p15card->tokeninfo->serial_number)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	p15card->tokeninfo->serial_number = memcpy(p15card->tokeninfo->serial_number, tag, taglen);
	p15card->tokeninfo->serial_number[taglen] = '\0';
	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY;

	/* add certificates */
	for (i = 0; i < 2; i++) {
		const char *esteid_cert_names[2] = {"Isikutuvastus", "Allkirjastamine"};
		const char *esteid_cert_paths[2] = {"3f00:adf1:3401", "3f00:adf2:341f"};
		const u8 esteid_cert_ids[2] = {1, 2};

		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		strlcpy(cert_obj.label, esteid_cert_names[i], sizeof(cert_obj.label));
		sc_format_path(esteid_cert_paths[i], &cert_info.path);
		cert_info.id.value[0] = esteid_cert_ids[i];
		cert_info.id.len = 1;
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

		// Read data from first cert
		if (i != 0)
			continue;

		sc_pkcs15_cert_t *cert = NULL;
		r = sc_pkcs15_read_certificate(p15card, &cert_info, &cert);
		LOG_TEST_RET(card->ctx, r, "Could not read authentication certificate");

		if (cert->key->algorithm == SC_ALGORITHM_EC)
			field_length = cert->key->u.ec.params.field_length;

		const struct sc_object_id cn_oid = {{2, 5, 4, 3, -1}};
		u8 *cn_name = NULL;
		size_t cn_len = 0;
		sc_pkcs15_get_name_from_dn(card->ctx, cert->subject, cert->subject_len, &cn_oid, &cn_name, &cn_len);
		if (cn_len > 0) {
			char *token_name = malloc(cn_len + 1);
			if (token_name) {
				memcpy(token_name, cn_name, cn_len);
				token_name[cn_len] = '\0';
				set_string(&p15card->tokeninfo->label, (const char *)token_name);
				free(token_name);
			}
		}
		free(cn_name);
		sc_pkcs15_free_certificate(cert);
	}

	/* add pins */
	for (i = 0; i < 3; i++) {
		const char *esteid_pin_names[3] = {"PIN1", "PIN2", "PUK"};
		const size_t esteid_pin_min[3] = {4, 5, 8};
		const int esteid_pin_ref[3] = {0x01, 0x85, 0x02};
		const u8 esteid_pin_authid[3] = {1, 2, 3};
		const char *esteid_pin_path[3] = {"3F00", "3F00ADF2", "3F00"};

		const unsigned int esteid_pin_flags[3] = {
		    SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED,
		    SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_LOCAL,
		    SC_PKCS15_PIN_FLAG_NEEDS_PADDING | SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN};

		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));

		sc_format_path(esteid_pin_path[i], &pin_info.path);
		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = esteid_pin_authid[i];
		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.attrs.pin.reference = esteid_pin_ref[i];
		pin_info.attrs.pin.flags = esteid_pin_flags[i];
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = esteid_pin_min[i];
		pin_info.attrs.pin.stored_length = 12;
		pin_info.attrs.pin.max_length = 12;
		pin_info.attrs.pin.pad_char = 0xFF;
		pin_info.tries_left = 3;
		pin_info.max_tries = 3;

		strlcpy(pin_obj.label, esteid_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = esteid_pin_flags[i];

		/* Link normal PINs with PUK */
		if (i < 2) {
			pin_obj.auth_id.len = 1;
			pin_obj.auth_id.value[0] = 3;
		}

		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	// trigger PIN counter refresh via pin_cmd
	struct sc_pkcs15_object *objs[3];
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH, objs, 3);
	if (r != 3) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}
	for (i = 0; i < r; i++) {
		r = sc_pkcs15_get_pin_info(p15card, objs[i]);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	/* add private keys */
	for (i = 0; i < 2; i++) {
		const u8 prkey_pin[2] = {1, 2};

		const char *prkey_name[2] = {"Isikutuvastus", "Allkirjastamine"};
		const char *prkey_path[2] = {"3F00:ADF1", "3F00:ADF2"};
		const unsigned int prkey_usage[2] = {SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DERIVE,
		                                     SC_PKCS15_PRKEY_USAGE_NONREPUDIATION};
		const int prkey_consent[2] = {0, 1};

		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));

		sc_format_path(prkey_path[i], &prkey_info.path);
		prkey_info.id.len = 1;
		prkey_info.id.value[0] = prkey_pin[i];
		prkey_info.native = 1;
		prkey_info.key_reference = i + 1;
		prkey_info.field_length = field_length;
		prkey_info.usage = prkey_usage[i];

		strlcpy(prkey_obj.label, prkey_name[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = prkey_pin[i];
		prkey_obj.user_consent = prkey_consent[i];
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_ec_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	return SC_SUCCESS;
}

int sc_pkcs15emu_esteid2018_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid) {
	if (p15card->card->type == SC_CARD_TYPE_ESTEID_2018)
		return sc_pkcs15emu_esteid2018_init(p15card);
	return SC_ERROR_WRONG_CARD;
}
