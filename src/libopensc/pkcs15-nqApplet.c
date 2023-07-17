/*
 * PKCS15 emulation for JCOP4 Cards with NQ-Applet
 *
 * Copyright (C) 2021 jozsefd <jozsef.dojcsak@gmail.com>
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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "opensc.h"
#include "cards.h"
#include "common/compat_strlcpy.h"
#include "log.h"
#include "pkcs15.h"

static const char name_Card[] = "NQ-Applet";
static const char name_Vendor[] = "NXP";

static int get_nqapplet_certificate(sc_card_t *card, u8 data_id, struct sc_pkcs15_der *cert_info)
{
	int rv;
	u8 buffer[3072];
	size_t cb_buffer = sizeof(buffer);
	LOG_FUNC_CALLED(card->ctx);

	rv = sc_get_data(card, data_id, buffer, cb_buffer);
	LOG_TEST_RET(card->ctx, rv, "GET DATA failed");
	if (rv == 0) {
		LOG_TEST_RET(card->ctx, SC_ERROR_FILE_NOT_FOUND, "No certificate data returned");
	}

	if (cert_info != NULL) {
		free(cert_info->value);
		cert_info->value = malloc(rv);
		if (cert_info->value != NULL) {
			cert_info->len = rv;
			memcpy(cert_info->value, buffer, rv);
		}
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int add_nqapplet_pin(sc_pkcs15_card_t *p15card, const char *id, u8 reference)
{
	int rv;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	sc_pkcs15_format_id(id, &pin_info.auth_id);
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = reference;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_CASE_SENSITIVE |
	                           SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL | SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_UTF8;
	pin_info.attrs.pin.min_length = 6;
	pin_info.attrs.pin.stored_length = 6;
	pin_info.attrs.pin.max_length = 6;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = -1; // TODO
	pin_info.max_tries = 3;

	strlcpy(pin_obj.label, "UserPIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

	rv = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	LOG_TEST_RET(card->ctx, rv, "sc_pkcs15emu_add_pin_obj failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int add_nqapplet_certificate(sc_pkcs15_card_t *p15card, const char *id, const char *name, u8 data_id)
{
	int rv;
	struct sc_pkcs15_cert_info cert_info;
	struct sc_pkcs15_object cert_obj;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	memset(&cert_info, 0, sizeof(cert_info));
	memset(&cert_obj, 0, sizeof(cert_obj));

	sc_pkcs15_format_id(id, &cert_info.id);
	rv = get_nqapplet_certificate(card, data_id, &cert_info.value);
	LOG_TEST_RET(card->ctx, rv, "Failed to get certificate");

	strlcpy(cert_obj.label, name, sizeof(cert_obj.label));

	rv = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
	LOG_TEST_RET(card->ctx, rv, "sc_pkcs15emu_add_x509_cert failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int add_nqapplet_private_key(sc_pkcs15_card_t *p15card, const char *id, int reference,
                                    const char *name, const char *pin_id, unsigned int usage)
{
	int rv;
	struct sc_pkcs15_prkey_info prkey_info;
	struct sc_pkcs15_object prkey_obj;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	memset(&prkey_info, 0, sizeof(prkey_info));
	memset(&prkey_obj, 0, sizeof(prkey_obj));

	sc_pkcs15_format_id(id, &prkey_info.id);
	prkey_info.usage = usage;
	prkey_info.native = 1;
	prkey_info.key_reference = reference;
	prkey_info.modulus_length = 3072;

	strlcpy(prkey_obj.label, name, sizeof(prkey_obj.label));
	prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	sc_pkcs15_format_id(pin_id, &prkey_obj.auth_id);

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	LOG_TEST_RET(card->ctx, rv, "sc_pkcs15emu_add_rsa_prkey failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int add_nqapplet_objects(sc_pkcs15_card_t *p15card)
{
	int rv;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	// 1) User PIN
	rv = add_nqapplet_pin(p15card, "1", 0x01);
	LOG_TEST_RET(card->ctx, rv, "Failed to add PIN 1");

	// 2.1) C.CH.Auth
	rv = add_nqapplet_certificate(p15card, "1", "C.CH.Auth", 0x00);
	LOG_TEST_RET(card->ctx, rv, "Failed to add Auth. certificate");

	// 2.2) PrK.CH.Auth
	rv = add_nqapplet_private_key(p15card, "1", 0x01, "PrK.CH.Auth", "1",
	                              SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT);
	LOG_TEST_RET(card->ctx, rv, "Failed to add Auth. private key");

	// 3.1) C.CH.Encr
	rv = add_nqapplet_certificate(p15card, "2", "C.CH.Encr", 0x01);
	LOG_TEST_RET(card->ctx, rv, "Failed to add Encr. certificate");

	// 3.2) PrK.CH.Encr
	rv = add_nqapplet_private_key(p15card, "2", 0x02, "PrK.CH.Encr", "1", SC_PKCS15_PRKEY_USAGE_DECRYPT);
	LOG_TEST_RET(card->ctx, rv, "Failed to add Encr. private key");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int sc_pkcs15emu_nqapplet_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	int rv = SC_ERROR_WRONG_CARD;
	sc_context_t *ctx;
	sc_card_t *card;

	if (!p15card || !p15card->card || !p15card->card->ctx) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	card = p15card->card;
	ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);

	if (card->type != SC_CARD_TYPE_NQ_APPLET) {
		sc_log(p15card->card->ctx, "Unsupported card type: %d", card->type);
		return SC_ERROR_WRONG_CARD;
	}

	rv = add_nqapplet_objects(p15card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add PKCS15");

	if (aid != NULL) {
		struct sc_file *file = sc_file_new();
		if (file != NULL) {
			/* PKCS11 depends on the file_app object, provide MF */
			sc_format_path("3f00", &file->path);
			sc_file_free(p15card->file_app);
			p15card->file_app = file;
		}
	}

	sc_pkcs15_free_tokeninfo(p15card->tokeninfo);

	p15card->tokeninfo = sc_pkcs15_tokeninfo_new();
	if (p15card->tokeninfo == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_TEST_GOTO_ERR(ctx, rv, "unable to create tokeninfo struct");
	} else {
		char serial_hex[SC_MAX_SERIALNR * 2 + 2];

		sc_bin_to_hex(card->serialnr.value, card->serialnr.len, serial_hex, sizeof(serial_hex), 0);
		set_string(&p15card->tokeninfo->serial_number, serial_hex);
		set_string(&p15card->tokeninfo->label, name_Card);
		set_string(&p15card->tokeninfo->manufacturer_id, name_Vendor);
		p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
err:
	sc_pkcs15_card_clear(p15card);
	LOG_FUNC_RETURN(ctx, rv);
}
