/*
 * pkcs15-gids.c: Support for GIDS smart cards.
 *
 * Copyright (C) 2015 Vincent Le Toux (My Smart Logon) <vincent.letoux@mysmartlogon.com>
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
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "common/compat_strlcpy.h"
#include "cardctl.h"

#ifdef ENABLE_ZLIB

#include "card-gids.h"

/*
 * Add a key from a minidriver container
 */
static int sc_pkcs15emu_gids_add_prkey(sc_pkcs15_card_t * p15card, sc_cardctl_gids_get_container_t *container) {

	sc_card_t *card = p15card->card;
	sc_pkcs15_prkey_info_t prkey_info;
	sc_pkcs15_object_t     prkey_obj;
	sc_pkcs15_pubkey_info_t pubkey_info;
	sc_pkcs15_object_t     pubkey_obj;
	sc_pkcs15_cert_info_t cert_info;
	sc_pkcs15_object_t cert_obj;
	int r;
	char ch_tmp[10];
	sc_log(card->ctx, 
		"Got args: containerIndex=%"SC_FORMAT_LEN_SIZE_T"x\n",
		 container->containernum);

	memset(&prkey_info, 0, sizeof(prkey_info));
	memset(&prkey_obj,  0, sizeof(prkey_obj));

	prkey_info.id.len = 1;
	prkey_info.id.value[0] = container->containernum;
	prkey_info.modulus_length    = container->module_length;
	prkey_info.usage             = container->prvusage;
	prkey_info.native            = 1;
	prkey_info.key_reference     = 0x81 + container->containernum;

	strlcpy(prkey_obj.label, container->label, sizeof(prkey_obj.label));
	prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	prkey_obj.auth_id.len = 1;
	prkey_obj.auth_id.value[0] = 0x80;

	r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	LOG_TEST_RET(card->ctx, r, "unable to sc_pkcs15emu_add_rsa_prkey");

	memset(&pubkey_info, 0, sizeof(pubkey_info));
	memset(&pubkey_obj,  0, sizeof(pubkey_obj));

	strlcpy(pubkey_obj.label, container->label, sizeof(pubkey_obj.label));

	snprintf(ch_tmp, sizeof(ch_tmp), "3FFFB0%02X", prkey_info.key_reference);
	sc_format_path(ch_tmp, &pubkey_info.path);
	pubkey_info.native = 1;
	pubkey_info.key_reference = prkey_info.key_reference;
	pubkey_info.modulus_length = prkey_info.modulus_length;
	pubkey_info.usage = container->pubusage;
	pubkey_info.id = prkey_info.id;

	r = sc_pkcs15emu_add_rsa_pubkey(p15card, &pubkey_obj, &pubkey_info);
	LOG_TEST_RET(card->ctx, r, "unable to sc_pkcs15emu_add_rsa_pubkey");

	if (container->certificatepath.len > 0) {
		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		cert_info.id = prkey_info.id;
		cert_info.path.count = -1;
		cert_info.path = container->certificatepath;

		strlcpy(cert_obj.label, container->label, sizeof(cert_obj.label));
		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		LOG_TEST_RET(card->ctx, r, "Could not add certificate");
	} else {
		sc_log(card->ctx,  "No certificate found");
	}

	return SC_SUCCESS;
}

/*
 * Initialize PKCS#15 emulation with user PIN, private keys, certificate and data objects
 *
 */
static int sc_pkcs15emu_gids_init (sc_pkcs15_card_t * p15card)
{
	sc_card_t *card = p15card->card;
	int r;
	size_t i;
	struct sc_pkcs15_auth_info pin_info;
	struct sc_pkcs15_object pin_obj;
	struct sc_pin_cmd_data pin_cmd_data;
	size_t recordsnum;
	int has_puk;

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_GET_ALL_CONTAINERS, &recordsnum);
	LOG_TEST_RET(card->ctx, r, "unable to get the containers. Uninitialized card ?");

	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, NULL);
	LOG_TEST_RET(card->ctx, r, "unable to get the serial number. Uninitialized card ?");

	p15card->tokeninfo->serial_number = (char*) malloc(card->serialnr.len *2 +1);
	if (!p15card->tokeninfo->serial_number) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	sc_bin_to_hex(card->serialnr.value, card->serialnr.len, p15card->tokeninfo->serial_number, card->serialnr.len *2 +1, 0);

	if (p15card->tokeninfo->label == NULL) {
		p15card->tokeninfo->label = strdup("GIDS card");
		if (p15card->tokeninfo->label == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	if ((p15card->tokeninfo->manufacturer_id != NULL) && !strcmp("(unknown)", p15card->tokeninfo->manufacturer_id)) {
		free(p15card->tokeninfo->manufacturer_id);
		p15card->tokeninfo->manufacturer_id = NULL;
	}

	if (p15card->tokeninfo->manufacturer_id == NULL) {
		p15card->tokeninfo->manufacturer_id = strdup("www.mysmartlogon.com");
		if (p15card->tokeninfo->manufacturer_id == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	if (p15card->card->type == SC_CARD_TYPE_GIDS_V2) {
		p15card->tokeninfo->version = 2;
	} else if (p15card->card->type == SC_CARD_TYPE_GIDS_V1) {
		p15card->tokeninfo->version = 1;
	}

	memset(&pin_info, 0, sizeof(pin_info));
	memset(&pin_obj, 0, sizeof(pin_obj));

	pin_info.auth_id.len = 1;
	pin_info.auth_id.value[0] = 0x80;
	pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pin_info.attrs.pin.reference = 0x80;
	pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_INITIALIZED;
	pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pin_info.attrs.pin.min_length = 4;
	pin_info.attrs.pin.stored_length = 0;
	pin_info.attrs.pin.max_length = 15;
	pin_info.attrs.pin.pad_char = '\0';
	pin_info.tries_left = -1;
	pin_info.max_tries = -1;

	memset(&pin_cmd_data, 0, sizeof(pin_cmd_data));
	pin_cmd_data.cmd = SC_PIN_CMD_GET_INFO;
	pin_cmd_data.pin_type = SC_AC_CHV;
	pin_cmd_data.pin_reference = pin_info.attrs.pin.reference;

	r = sc_pin_cmd(card, &pin_cmd_data, NULL);
	if (r == SC_SUCCESS) {
		pin_info.max_tries = pin_cmd_data.pin1.max_tries;
		pin_info.tries_left = pin_cmd_data.pin1.tries_left;
	}

	strlcpy(pin_obj.label, "UserPIN", sizeof(pin_obj.label));
	pin_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE|SC_PKCS15_CO_FLAG_MODIFIABLE;

	/*
	 * check whether PUK is available on this card and then optionally
	 * link PIN with PUK.
	 */
	pin_cmd_data.pin_reference = 0x81;
	has_puk = sc_pin_cmd(card, &pin_cmd_data, NULL) == SC_SUCCESS;
	if (has_puk) {
		pin_obj.auth_id.len = 1;
		pin_obj.auth_id.value[0] = 0x81;
	}

	r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
	LOG_TEST_RET(card->ctx, r, "unable to sc_pkcs15emu_add_pin_obj");

	if (has_puk) {
		pin_info.auth_id.value[0] = 0x81;
		pin_info.attrs.pin.flags = SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
		pin_info.attrs.pin.reference = 0x81;
		pin_info.max_tries = pin_cmd_data.pin1.max_tries;
		pin_info.tries_left = pin_cmd_data.pin1.tries_left;
		strlcpy(pin_obj.label, "PUK", sizeof(pin_obj.label));
		pin_obj.auth_id.len = 0;
		r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
		LOG_TEST_RET(card->ctx, r, "unable to sc_pkcs15emu_add_pin_obj with PUK");
	}

	r = sc_card_ctl(card, SC_CARDCTL_GIDS_GET_ALL_CONTAINERS, &recordsnum);
	LOG_TEST_RET(card->ctx, r, "sc_card_ctl SC_CARDCTL_GIDS_GET_ALL_CONTAINERS");

	for (i = 0; i < recordsnum; i++) {
		sc_cardctl_gids_get_container_t container;
		memset(&container, 0, sizeof(sc_cardctl_gids_get_container_t));
		container.containernum = i;
		r = sc_card_ctl(card, SC_CARDCTL_GIDS_GET_CONTAINER_DETAIL, &container);
		if (r < 0) {
			// one of the container information couldn't be retrieved
			// ignore it
			continue;
		}
		sc_pkcs15emu_gids_add_prkey(p15card, &container);
	}
	return SC_SUCCESS;
}

int sc_pkcs15emu_gids_init_ex(sc_pkcs15_card_t *p15card,
				struct sc_aid *aid,
				sc_pkcs15emu_opt_t *opts)
{
	if (opts && (opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)) {
		return sc_pkcs15emu_gids_init(p15card);
	} else {
		if (p15card->card->type != SC_CARD_TYPE_GIDS_GENERIC && p15card->card->type != SC_CARD_TYPE_GIDS_V1 && p15card->card->type != SC_CARD_TYPE_GIDS_V2) {
			return SC_ERROR_WRONG_CARD;
		}
		return sc_pkcs15emu_gids_init(p15card);
	}
}

#else

int sc_pkcs15emu_gids_init_ex(sc_pkcs15_card_t *p15card,
				struct sc_aid *aid,
				sc_pkcs15emu_opt_t *opts)
{
	return SC_ERROR_WRONG_CARD;
}

#endif
