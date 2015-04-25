/*
 * PKCS15 emulation layer for Portugal eID card.
 *
 * Copyright (C) 2009, Joao Poupino <joao.poupino@ist.utl.pt>
 * Copyright (C) 2004, Martin Paljak <martin@martinpaljak.net>
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
 *
 * Based on the PKCS#15 emulation layer for EstEID card by Martin Paljak
 *
 */

/*
 * The card has a valid PKCS#15 file system. However, the private keys
 * are missing the SC_PKCS15_CO_FLAG_PRIVATE flag and this causes problems
 * with some applications (i.e. they don't work).
 *
 * The three main objectives of the emulation layer are:
 *
 * 1. Add the necessary SC_PKCS15_CO_FLAG_PRIVATE flag to private keys.
 * 2. Hide "superfluous" PKCS#15 objects, e.g. PUKs (the user can't use them).
 * 3. Improve usability by providing more descriptive names for the PINs, Keys, etc.
 *
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs15.h"

#define IAS_CARD 0
#define GEMSAFE_CARD 1

int sc_pkcs15emu_pteid_init_ex(sc_pkcs15_card_t *, sc_pkcs15emu_opt_t *);

static int sc_pkcs15emu_pteid_init(sc_pkcs15_card_t * p15card)
{
	int r, i, 				type;
	unsigned char 			*buf = NULL;
	size_t 					len;
	sc_pkcs15_tokeninfo_t 	tokeninfo;
	sc_path_t 				tmppath;
	sc_card_t 				*card = p15card->card;
	sc_context_t 			*ctx = card->ctx;

	/* Parse the TokenInfo EF */
	sc_format_path("3f004f005032", &tmppath);
	r = sc_select_file(card, &tmppath, &p15card->file_tokeninfo);
	if (r)
		goto end;
	if ( (len = p15card->file_tokeninfo->size) == 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "EF(TokenInfo) is empty\n");
		goto end;
	}
	buf = malloc(len);
	if (buf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	r = sc_read_binary(card, 0, buf, len, 0);
	if (r < 0)
		goto end;
	if (r <= 2) {
		r = SC_ERROR_PKCS15_APP_NOT_FOUND;
		goto end;
	}
	memset(&tokeninfo, 0, sizeof(tokeninfo));
	r = sc_pkcs15_parse_tokeninfo(ctx, &tokeninfo, buf, (size_t) r);
	if (r != SC_SUCCESS)
		goto end;

	*(p15card->tokeninfo) = tokeninfo;

	/* Card type detection */
	if (card->type == SC_CARD_TYPE_IAS_PTEID)
		type = IAS_CARD;
	else if (card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID)
		type = GEMSAFE_CARD;
	else {
		r = SC_ERROR_INTERNAL;
		goto end;
	}

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION
				  | SC_PKCS15_TOKEN_EID_COMPLIANT
				  | SC_PKCS15_TOKEN_READONLY;

	/* TODO: Use the cardholder's name?  */
	/* TODO: Use Portuguese descriptions? */
	
	/* Add X.509 Certificates */
	for (i = 0; i < 4; i++) {
		static const char *pteid_cert_names[4] = {
				"AUTHENTICATION CERTIFICATE",
				"SIGNATURE CERTIFICATE",
				"SIGNATURE SUB CA",
				"AUTHENTICATION SUB CA"
		};
		/* X.509 Certificate Paths */
		static const char *pteid_cert_paths[4] = {
			"3f005f00ef09", /* Authentication Certificate path */
			"3f005f00ef08", /* Digital Signature Certificate path */
			"3f005f00ef0f", /* Signature sub CA path */
			"3f005f00ef10"	/* Authentication sub CA path */
		};
		/* X.509 Certificate IDs */
		static const int pteid_cert_ids[4] = {0x45, 0x46, 0x51, 0x52};
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id.value[0] = pteid_cert_ids[i];
		cert_info.id.len = 1;
		sc_format_path(pteid_cert_paths[i], &cert_info.path);
		strlcpy(cert_obj.label, pteid_cert_names[i], sizeof(cert_obj.label));
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		if (r < 0) {
			r = SC_ERROR_INTERNAL;
			goto end;
		}
	}
	
	/* Add PINs */
	for (i = 0; i < 3; i++) {
		static const char *pteid_pin_names[3] = {
			"Auth PIN",
			"Sign PIN",
			"Address PIN"
		};
		/* PIN References */
		static const int pteid_pin_ref[2][3] = { {1, 130, 131}, {129, 130, 131} };
		/* PIN Authentication IDs */
		static const int pteid_pin_authid[3] = {1, 2, 3};
		/* PIN Paths */
		static const char *pteid_pin_paths[2][3] = { {NULL, "3f005f00", "3f005f00"},
													 {NULL, NULL, NULL} };
		struct sc_pkcs15_auth_info pin_info;
		struct sc_pkcs15_object pin_obj;

		memset(&pin_info, 0, sizeof(pin_info));
		memset(&pin_obj, 0, sizeof(pin_obj));

		pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
		pin_info.auth_id.len = 1;
		pin_info.auth_id.value[0] = pteid_pin_authid[i];
		pin_info.attrs.pin.reference = pteid_pin_ref[type][i];
		pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_NEEDS_PADDING
						 | SC_PKCS15_PIN_FLAG_INITIALIZED
						 | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE;
		pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info.attrs.pin.min_length = 4;
		pin_info.attrs.pin.stored_length = 8;
		pin_info.attrs.pin.max_length = 8;
		pin_info.attrs.pin.pad_char = type == IAS_CARD ? 0x2F : 0xFF;
		pin_info.tries_left = -1;
		if (pteid_pin_paths[type][i] != NULL)
			sc_format_path(pteid_pin_paths[type][i], &pin_info.path);
		strlcpy(pin_obj.label, pteid_pin_names[i], sizeof(pin_obj.label));
		pin_obj.flags = 0;
		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		if (r < 0) {
			r = SC_ERROR_INTERNAL;
			goto end;
		}
	}

	/* Add Private Keys */
	for (i = 0; i < 2; i++) {
		/* Key reference */
		static const int pteid_prkey_keyref[2][2] = { {1, 130}, {2, 1} };
		/* RSA Private Key usage */
		static int pteid_prkey_usage[2] = {
			SC_PKCS15_PRKEY_USAGE_SIGN,
			SC_PKCS15_PRKEY_USAGE_NONREPUDIATION};
		/* RSA Private Key IDs */
		static const int pteid_prkey_ids[2] = {0x45, 0x46};
		static const char *pteid_prkey_names[2] = {
				"CITIZEN AUTHENTICATION KEY",
				"CITIZEN SIGNATURE KEY"};
		/* RSA Private Key Paths */
		static const char *pteid_prkey_paths[2][2] = { {NULL, "3f005f00"}, {NULL, NULL} };
		struct sc_pkcs15_prkey_info prkey_info;
		struct sc_pkcs15_object prkey_obj;

		memset(&prkey_info, 0, sizeof(prkey_info));
		memset(&prkey_obj, 0, sizeof(prkey_obj));

		prkey_info.id.len = 1;
		prkey_info.id.value[0] = pteid_prkey_ids[i];
		prkey_info.usage = pteid_prkey_usage[i];
		prkey_info.native = 1;
		prkey_info.key_reference = pteid_prkey_keyref[type][i];
		prkey_info.modulus_length = 1024;
		if (pteid_prkey_paths[type][i] != NULL)
			sc_format_path(pteid_prkey_paths[type][i], &prkey_info.path);
		strlcpy(prkey_obj.label, pteid_prkey_names[i], sizeof(prkey_obj.label));
		prkey_obj.auth_id.len = 1;
		prkey_obj.auth_id.value[0] = i + 1;
		prkey_obj.user_consent = (i == 1) ? 1 : 0;
		prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

		r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
		if (r < 0) {
			r = SC_ERROR_INTERNAL;
			goto end;
		}
	}

	/* Add objects */
	for (i = 0; i < 3; i++) {
		static const char *object_ids[3] = {"1", "2", "3"};
		static const char *object_labels[3] = {"Citizen Data",
											   "Citizen Address Data",
											   "Citizen Notepad"};
		static const char *object_authids[3] = {NULL, "3", "1"};
		static const char *object_paths[3] = {"3f005f00ef02",
											  "3f005f00ef05",
											  "3f005f00ef07"};
		static const int object_flags[3] = {0,
											SC_PKCS15_CO_FLAG_PRIVATE,
											SC_PKCS15_CO_FLAG_MODIFIABLE};
		struct sc_pkcs15_data_info obj_info;
		struct sc_pkcs15_object obj_obj;

		memset(&obj_info, 0, sizeof(obj_info));
		memset(&obj_obj, 0, sizeof(obj_obj));

		sc_pkcs15_format_id(object_ids[i], &obj_info.id);
		sc_format_path(object_paths[i], &obj_info.path);
		strlcpy(obj_info.app_label, object_labels[i], SC_PKCS15_MAX_LABEL_SIZE);
		if (object_authids[i] != NULL)
			sc_pkcs15_format_id(object_authids[i], &obj_obj.auth_id);
		strlcpy(obj_obj.label, object_labels[i], SC_PKCS15_MAX_LABEL_SIZE);
		obj_obj.flags = object_flags[i];

		r = sc_pkcs15emu_object_add(p15card, SC_PKCS15_TYPE_DATA_OBJECT, &obj_obj, &obj_info);
		if (r < 0)
			goto end;
	}
end:
	if (buf != NULL) {
		free(buf);
		buf = NULL;
	}
	if (r)
		return r;

	return SC_SUCCESS;
}

static int pteid_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type == SC_CARD_TYPE_IAS_PTEID ||
		p15card->card->type == SC_CARD_TYPE_GEMSAFEV1_PTEID)
		return SC_SUCCESS;
	return SC_ERROR_WRONG_CARD;
}

int sc_pkcs15emu_pteid_init_ex(sc_pkcs15_card_t *p15card, sc_pkcs15emu_opt_t *opts)
{
	if (opts != NULL && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_pteid_init(p15card);
	else {
		int r = pteid_detect_card(p15card);
		if (r)
			return SC_ERROR_WRONG_CARD;
		return sc_pkcs15emu_pteid_init(p15card);
	}
}
