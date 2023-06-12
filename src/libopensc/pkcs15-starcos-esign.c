/**
 * PKCS15 emulation layer for Giesecke & Devrient StarCOS 3.x cards 
 * with eSign application
 *
 * Copyright (C) 2022, jozsefd
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
#include <config.h>
#endif

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "log.h"
#include "pkcs15.h"
#include "cards.h"

#include <stdlib.h>
#include <string.h>

/* compile time option: define ENABLE_ESIGN_ISSUER_CONTAINERS to enable containers holding the issuer certificates */

static const char name_Card[] = "ESIGN";
static const char name_Vendor[] = "Giesecke & Devrient";
static const char name_ESign[] = "ESIGN";
static const unsigned char aid_ESIGN[] = {0xA0, 0x00, 0x00, 0x02, 0x45, 0x53, 0x69, 0x67, 0x6E};

typedef struct cdata_st {
	const char *label;
	int authority;
	const char *path;
	const char *id;
	int obj_flags;
} cdata, *pcdata;

typedef struct pdata_st {
	const char *id;
	const char *label;
	const char *path;
	int ref;
	int type;
	unsigned int maxlen;
	unsigned int minlen;
	unsigned int storedlen;
	int flags;
	int tries_left;
	int max_tries;
	const char pad_char;
	int obj_flags;
} pindata, *ppindata;

typedef struct prdata_st {
	const char *id;
	const char *label;
	unsigned int modulus_len;
	int usage;
	const char *path;
	int ref;
	const char *auth_id;
	int obj_flags;
} prdata, *pprdata;

typedef struct container_st {
	const char *id;
	const pcdata certdata;
	const ppindata pindata;
	const pprdata prdata;
} container;

#define USAGE_NONREP SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
#define USAGE_KE     SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
				 SC_PKCS15_PRKEY_USAGE_DECRYPT | \
				 SC_PKCS15_PRKEY_USAGE_WRAP | \
				 SC_PKCS15_PRKEY_USAGE_UNWRAP
#define USAGE_AUT SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
				  SC_PKCS15_PRKEY_USAGE_DECRYPT | \
				  SC_PKCS15_PRKEY_USAGE_WRAP | \
				  SC_PKCS15_PRKEY_USAGE_UNWRAP | \
				  SC_PKCS15_PRKEY_USAGE_SIGN
#define USER_PIN  SC_PKCS15_PIN_FLAG_INITIALIZED | \
				SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | \
				SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL | \
				SC_PKCS15_PIN_AUTH_TYPE_PIN

static int
get_cert_size(sc_card_t *card, sc_path_t *path, size_t *psize)
{
	int r;
	sc_file_t *file = NULL;

	r = sc_select_file(card, path, &file);
	LOG_TEST_RET(card->ctx, r, "Failed to select EF certificate");

	*psize = file->size;
	sc_file_free(file);

	return SC_SUCCESS;
}

static int
add_app(sc_pkcs15_card_t *p15card, const container *containers, int container_count)
{
	int i, containers_added = 0, r = SC_SUCCESS;
	ppindata installed_pins[4];
	size_t installed_pin_count = 0;
	sc_card_t *card = p15card->card;

	LOG_FUNC_CALLED(card->ctx);

	for (i = 0; i < container_count; i++) {
		struct sc_pkcs15_cert_info cert_info;
		struct sc_pkcs15_object cert_obj;
		size_t cert_size;

		memset(&cert_info, 0, sizeof(cert_info));
		memset(&cert_obj, 0, sizeof(cert_obj));

		sc_pkcs15_format_id(containers[i].id, &cert_info.id);
		cert_info.authority = containers[i].certdata->authority;
		sc_format_path(containers[i].certdata->path, &cert_info.path);

		r = get_cert_size(card, &cert_info.path, &cert_size);
		if ( r != SC_SUCCESS ) {
			sc_log(card->ctx, "Failed to determine size of certificate %s, ignoring container", containers[i].certdata->label);
			continue;
		}

		strlcpy(cert_obj.label, containers[i].certdata->label, sizeof(cert_obj.label));
		cert_obj.flags = containers[i].certdata->obj_flags;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		LOG_TEST_RET(card->ctx, r, "Failed to add certificate");

		if (containers[i].pindata != 0) {
			size_t j;
			int is_pin_installed = 0;

			/* A pin object could be used by more than 1 container, ensure it is added only once */
			for (j = 0; j < installed_pin_count; j++) {
				if (installed_pins[j] == containers[i].pindata) {
					is_pin_installed = 1;
					break;
				}
			}

			if (!is_pin_installed) {
				struct sc_pkcs15_auth_info pin_info;
				struct sc_pkcs15_object pin_obj;

				if (installed_pin_count < (int)(sizeof(installed_pins) / sizeof(ppindata))) {
					installed_pins[installed_pin_count++] = containers[i].pindata;
				} else {
					sc_log(card->ctx, "Warning: cannot add more than 4 pins");
					continue;
				}

				memset(&pin_info, 0, sizeof(pin_info));
				memset(&pin_obj, 0, sizeof(pin_obj));

				sc_pkcs15_format_id(containers[i].pindata->id, &pin_info.auth_id);
				pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
				pin_info.attrs.pin.reference = containers[i].pindata->ref;
				pin_info.attrs.pin.flags = containers[i].pindata->flags;
				pin_info.attrs.pin.type = containers[i].pindata->type;
				pin_info.attrs.pin.min_length = containers[i].pindata->minlen;
				pin_info.attrs.pin.stored_length = containers[i].pindata->storedlen;
				pin_info.attrs.pin.max_length = containers[i].pindata->maxlen;
				pin_info.attrs.pin.pad_char = containers[i].pindata->pad_char;
				if (containers[i].pindata->path != NULL)
					sc_format_path(containers[i].pindata->path, &pin_info.path);
				pin_info.tries_left = -1;
				pin_info.max_tries = containers[i].pindata->max_tries;

				strlcpy(pin_obj.label, containers[i].pindata->label, sizeof(pin_obj.label));
				pin_obj.flags = containers[i].pindata->obj_flags;

				r = sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info);
				LOG_TEST_RET(card->ctx, r, "Failed to add PIN object");
			}
		}

		if (containers[i].prdata != 0) {
			struct sc_pkcs15_prkey_info prkey_info;
			struct sc_pkcs15_object prkey_obj;
			int modulus_len = containers[i].prdata->modulus_len;
			memset(&prkey_info, 0, sizeof(prkey_info));
			memset(&prkey_obj, 0, sizeof(prkey_obj));

			sc_pkcs15_format_id(containers[i].id, &prkey_info.id);
			prkey_info.usage = containers[i].prdata->usage;
			prkey_info.native = 1;
			prkey_info.key_reference = containers[i].prdata->ref;
			prkey_info.modulus_length = modulus_len;
			sc_format_path(containers[i].prdata->path, &prkey_info.path);

			strlcpy(prkey_obj.label, containers[i].prdata->label, sizeof(prkey_obj.label));
			prkey_obj.flags = containers[i].prdata->obj_flags;
			if (containers[i].prdata->auth_id) {
				sc_pkcs15_format_id(containers[i].prdata->auth_id, &prkey_obj.auth_id);
			}

			r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
			LOG_TEST_RET(card->ctx, r, "Failed to add RSA prkey");
		}

		containers_added++;
	}

	if (containers_added == 0) {
		r = SC_ERROR_INVALID_CARD;
	} else {
		r = SC_SUCCESS;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * adds the PKCS15 objects of the ESIGN application. The app may contain
 * 1) Authentication container
 *  - 2048-bit RSA key
 *  - CH certificate
 * 2) Encryption container
 *  - 2048-bit RSA key
 *  - CH certificate
 * 3) Authentication Issuer container
 *  - issuer certificate
 * 3) Encryption Issuer container
 *  - issuer certificate
 * Depending on the card profile, some containers may be missing.
 * Both RSA keys are protected with the UserPIN. The app may have a PUK, not
 * supported by this emulator.
 * 
 * The issuer certificates are not included by default, define ENABLE_ESIGN_ISSUER_CONTAINERS
 * to enable them.
 */
static int
starcos_add_esign_app(sc_pkcs15_card_t *p15card)
{
	static cdata auth_cert = {"C.CH.AUT", 0, "3F00060843F1", "1", 0};
	static cdata encr_cert = {"C.CH.ENC", 0, "3F0006084301", "2", 0};
#ifdef ENABLE_ESIGN_ISSUER_CONTAINERS
	const cdata auth_root_cert = { "C.RootCA_Auth", 1, "3F00060843F0", "3", 0 };
	const cdata encr_root_cert = { "C.RootCA_Enc", 1, "3F0006084300", "4", 0 };
#endif

	static prdata auth_key = {"1", "PrK.CH.AUT", 2048, USAGE_AUT, "3F000608", 0x81, "1", SC_PKCS15_CO_FLAG_PRIVATE};
	static prdata encr_key = {"2", "PrK.CH.ENC", 2048, USAGE_KE, "3F000608", 0x83, "1", SC_PKCS15_CO_FLAG_PRIVATE};

	static pindata auth_pin = {"1", "UserPIN", "3F00", 0x01, SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
			USER_PIN, -1, 3, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE};

	static pindata auth_pin_v35 = {"1", "UserPIN", "3F00", 0x06, SC_PKCS15_PIN_TYPE_UTF8, 16, 6, 0,
			USER_PIN, -1, 3, 0x00, SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE};

	ppindata auth = (p15card->card->type == SC_CARD_TYPE_STARCOS_V3_5_ESIGN) ? &auth_pin_v35 : &auth_pin;

	const container containers[] = {
			{"1", &auth_cert, auth, &auth_key},
			{"2", &encr_cert, auth, &encr_key},
#ifdef ENABLE_ESIGN_ISSUER_CONTAINERS
			{ "3", &auth_root_cert, 0, 0 },
			{ "4", &encr_root_cert, 0, 0 },
#endif
	};

	return add_app(p15card, containers, sizeof(containers) / sizeof(container));
}

static int
starcos_esign_init(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	sc_card_t *card = p15card->card;
	sc_context_t *ctx = card->ctx;
	const char *label = name_Card;
	int r;
	int apps_added = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);

	if (card->type != SC_CARD_TYPE_STARCOS_V3_4_ESIGN && card->type != SC_CARD_TYPE_STARCOS_V3_5_ESIGN) {
		return SC_ERROR_WRONG_CARD;
	}

	if (aid == NULL) {
		// no aid: in this case all emulated apps are added, currently only the esign_app
		r = starcos_add_esign_app(p15card);
		if (r == SC_SUCCESS)
			apps_added++;
	} else {
		// aid specified: only the matching app is added
		if (aid->len == sizeof(aid_ESIGN) && memcmp(aid->value, aid_ESIGN, sizeof(aid_ESIGN)) == 0) {
			r = starcos_add_esign_app(p15card);
			if (r == SC_SUCCESS) {
				label = name_ESign;
				apps_added++;
			}
		}

		if (apps_added > 0) {
			// pkcs11 requires the file_app
			struct sc_path path;
			struct sc_file *file = NULL;
			sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid->value, aid->len, 0, 0);
			r = sc_select_file(card, &path, &file);
			if (r != SC_SUCCESS || !file)
				return SC_ERROR_INTERNAL;
			sc_file_free(p15card->file_app);
			p15card->file_app = file;
		}
	}

	if (apps_added == 0) {
		LOG_TEST_RET(ctx, SC_ERROR_WRONG_CARD, "No supported app found on this card");
	}

	sc_pkcs15_free_tokeninfo(p15card->tokeninfo);

	p15card->tokeninfo = sc_pkcs15_tokeninfo_new();
	if (!p15card->tokeninfo) {
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "unable to create tokeninfo struct");
	} else {
		sc_serial_number_t serial;
		char serial_hex[SC_MAX_SERIALNR * 2 + 2];
		r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
		LOG_TEST_RET(ctx, r, "Failed to query card serial number");

		r = sc_bin_to_hex(serial.value, serial.len, serial_hex, sizeof serial_hex, 0);
		LOG_TEST_RET(ctx, r, "Failed to convert S/N to hex");
		p15card->tokeninfo->serial_number = strdup(serial_hex);
		p15card->tokeninfo->label = strdup(label);
		p15card->tokeninfo->manufacturer_id = strdup(name_Vendor);
		p15card->tokeninfo->flags = SC_PKCS15_TOKEN_READONLY;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_starcos_esign_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	int r = SC_ERROR_WRONG_CARD;

	if (!p15card || !p15card->card || !p15card->card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	r = starcos_esign_init(p15card, aid);
	LOG_FUNC_RETURN(p15card->card->ctx, r);
}
