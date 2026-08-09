/*
 * pkcs15-starsign.c: static PKCS#15 profile for G&D StarSign CUT S tokens
 *
 * Copyright (C) 2026 Diego Ribeiro de Souza
 *
 * The card's own AODF/PrKDF entries are confusing enough (missing PIN
 * reference, zeroed key references) that patching them after a generic
 * sc_pkcs15_parse_df() made card-starsign.c's SELECT logic hard to justify.
 * Per review feedback from the OpenSC maintainer, this instead supplies the
 * card's PKCS#15 layout as static, internal data (see pkcs15-esteid2025.c
 * for the same pattern) for every field that is structural -- i.e. fixed by
 * the StarSign CUT S / SafeSign applet across every token of this model,
 * regardless of cardholder. Confirmed against physical hardware via a debug
 * trace of the previously-working dynamic discovery path.
 *
 * Fields that are genuinely per-cardholder (token label, serial number,
 * manufacturer ID) are NOT hardcoded here -- they are read from the card's
 * own EF(TokenInfo) at runtime, same as any other OpenSC card driver, so
 * this works correctly for every StarSign CUT S holder, not just one.
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

#include <string.h>

#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs15.h"

/* EF(TokenInfo): direct child of the MF, same FID on every StarSign CUT S
 * token. Its *content* (label, serial, manufacturer) is cardholder-specific
 * and is read from the card below, not hardcoded. */
#define STARSIGN_TOKENINFO_PATH "3f005032"

/* Correlation IDs assigned by this driver -- purely internal bookkeeping to
 * link a certificate to its private/public key object. They are not read
 * from the card (the card's own CDF stores the cardholder's name as the ID,
 * which must not end up hardcoded into a driver shared by every StarSign
 * user) and do not need to match any value stored on the card. */
static const struct sc_pkcs15_id starsign_id_current = {.value = {0x01}, .len = 1};
static const struct sc_pkcs15_id starsign_id_legacy = {.value = {0x02}, .len = 1};

/* Certificate slots: MF -> [virtual 0x3FFF placeholder, never selected] ->
 * DF 4302 -> EF <final>. This 4-slot layout (leaf, two intermediates, root)
 * is fixed by the applet; only the DER content of each EF is personal. */
static const struct {
	const char *path;
	const char *label;
} starsign_certs[4] = {
		{"3f0043020114", "Signature Certificate"},
		{"3f00430205a0", "Intermediate CA Certificate 1"},
		{"3f00430213ae", "Intermediate CA Certificate 2"},
		{"3f0043021371", "Root CA Certificate"},
};

static int
starsign_read_tokeninfo(struct sc_pkcs15_card *p15card)
{
	sc_card_t *card = p15card->card;
	sc_path_t path;
	u8 buf[512];
	int r;

	sc_format_path(STARSIGN_TOKENINFO_PATH, &path);
	r = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, r, "Selecting EF(TokenInfo) failed");

	r = sc_read_binary(card, 0, buf, sizeof(buf), 0);
	LOG_TEST_RET(card->ctx, r, "Reading EF(TokenInfo) failed");

	return sc_pkcs15_parse_tokeninfo(card->ctx, p15card->tokeninfo, buf, (size_t)r);
}

static int
starsign_add_pins(struct sc_pkcs15_card *p15card)
{
	sc_card_t *card = p15card->card;
	int r;

	struct sc_pkcs15_auth_info so_pin_info = {
			.auth_id = {.value = {0x01}, .len = 1},
			.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN,
			.tries_left = -1,
			.max_tries = -1,
			.attrs = {.pin = {
					.reference = 0x01,
					.flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
						 SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
						 SC_PKCS15_PIN_FLAG_SO_PIN | SC_PKCS15_PIN_FLAG_DISABLE_ALLOW |
						 SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA,
					.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
					.min_length = 4,
					.stored_length = 15,
					.max_length = 15,
					.pad_char = 0x00}}
	};
	struct sc_pkcs15_object so_pin_obj = {.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE};

	struct sc_pkcs15_auth_info user_pin_info = {
			.auth_id = {.value = {0x02}, .len = 1},
			.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN,
			.tries_left = -1,
			.max_tries = -1,
			.attrs = {.pin = {
					.reference = 0x02,
					.flags = SC_PKCS15_PIN_FLAG_CASE_SENSITIVE | SC_PKCS15_PIN_FLAG_LOCAL |
						 SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_NEEDS_PADDING |
						 SC_PKCS15_PIN_FLAG_DISABLE_ALLOW | SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA,
					.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC,
					.min_length = 4,
					.stored_length = 15,
					.max_length = 15,
					.pad_char = 0x00}}
	};
	/* Points at the SO Pin's own id: the SO Pin can unblock/reset this one. */
	struct sc_pkcs15_object user_pin_obj = {
			.auth_id = {.value = {0x01}, .len = 1},
			.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE,
	};

	sc_format_path("3f00", &user_pin_info.path);
	strlcpy(user_pin_obj.label, "User Pin", sizeof(user_pin_obj.label));
	r = sc_pkcs15emu_add_pin_obj(p15card, &user_pin_obj, &user_pin_info);
	LOG_TEST_RET(card->ctx, r, "Could not add User PIN object");

	sc_format_path("3f00", &so_pin_info.path);
	strlcpy(so_pin_obj.label, "SO Pin", sizeof(so_pin_obj.label));
	r = sc_pkcs15emu_add_pin_obj(p15card, &so_pin_obj, &so_pin_info);
	LOG_TEST_RET(card->ctx, r, "Could not add SO PIN object");

	return SC_SUCCESS;
}

static int
starsign_add_certs(struct sc_pkcs15_card *p15card)
{
	sc_card_t *card = p15card->card;
	int i, r;

	for (i = 0; i < 4; i++) {
		struct sc_pkcs15_cert_info cert_info = {0};
		struct sc_pkcs15_object cert_obj = {0};

		if (i == 0) {
			/* Leaf certificate: correlates to the current signing key. */
			cert_info.id = starsign_id_current;
		} else {
			/* CA-chain certs don't correlate to any key on this token;
			 * give each a distinct id (0x03, 0x04, 0x05) so they don't
			 * collide with each other or with the key ids (0x01, 0x02). */
			cert_info.id.value[0] = 0x02 + i;
			cert_info.id.len = 1;
		}
		cert_info.authority = 0;
		sc_format_path(starsign_certs[i].path, &cert_info.path);

		strlcpy(cert_obj.label, starsign_certs[i].label, sizeof(cert_obj.label));
		cert_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;

		r = sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info);
		LOG_TEST_RET(card->ctx, r, "Could not add certificate object");
	}

	return SC_SUCCESS;
}

static int
starsign_add_keys(struct sc_pkcs15_card *p15card)
{
	sc_card_t *card = p15card->card;
	int r;

	/* Current signing key: the only one with a live matching certificate. */
	struct sc_pkcs15_prkey_info prkey_info = {
			.id = starsign_id_current,
			.usage = SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_SIGN |
				 SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_UNWRAP,
			.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE | SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE,
			.native = 1,
			.key_reference = 1,
			.modulus_length = 2048,
	};
	struct sc_pkcs15_object prkey_obj = {
			.auth_id = {.value = {0x02}, .len = 1}, /* linked to the User Pin */
			.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE,
	};

	/* Legacy key from a previous certificate cycle: no live certificate,
	 * kept only so it doesn't silently vanish for holders who still have
	 * one provisioned. Real hardware exposes it at key_reference 0.
	 *
	 * Deliberately no paired native pubkey object here (unlike the current
	 * key below). A holder who has renewed their ICP-Brasil certificate and
	 * cleared the old one via the standard SafeSign/XCA workflow -- normal,
	 * expected lifecycle, not a corner case -- no longer has any on-card EF
	 * backing this key's public half. Declaring a native pubkey_info for it
	 * anyway makes the generic PKCS#11 layer try to read modulus bytes that
	 * don't exist, which fails with SC_ERROR_INTERNAL (-1400). The private
	 * key object alone is still useful (matches hardware reality, doesn't
	 * disappear for holders who haven't cleared the old cycle); it just
	 * won't be discoverable by PKCS#11 clients that only enumerate via
	 * public keys (e.g. XCA) -- acceptable, since without a certificate it
	 * can't be used for anything verifiable anyway. */
	struct sc_pkcs15_prkey_info legacy_prkey_info = {
			.id = starsign_id_legacy,
			.usage = SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_SIGN |
				 SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_UNWRAP,
			.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE | SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE |
					SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_LOCAL,
			.native = 1,
			.key_reference = 0,
			.modulus_length = 2048,
	};
	struct sc_pkcs15_object legacy_prkey_obj = {
			.auth_id = {.value = {0x02}, .len = 1},
			.flags = SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE,
	};

	strlcpy(prkey_obj.label, "Signature Key", sizeof(prkey_obj.label));
	r = sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info);
	LOG_TEST_RET(card->ctx, r, "Could not add current private key object");

	strlcpy(legacy_prkey_obj.label, "Legacy Key", sizeof(legacy_prkey_obj.label));
	r = sc_pkcs15emu_add_rsa_prkey(p15card, &legacy_prkey_obj, &legacy_prkey_info);
	LOG_TEST_RET(card->ctx, r, "Could not add legacy private key object");

	return SC_SUCCESS;
}

static int
sc_pkcs15emu_starsign_init(struct sc_pkcs15_card *p15card)
{
	sc_card_t *card = p15card->card;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = starsign_read_tokeninfo(p15card);
	LOG_TEST_RET(card->ctx, r, "Could not read EF(TokenInfo)");

	r = starsign_add_pins(p15card);
	LOG_TEST_RET(card->ctx, r, "Could not add PIN objects");

	r = starsign_add_certs(p15card);
	LOG_TEST_RET(card->ctx, r, "Could not add certificate objects");

	r = starsign_add_keys(p15card);
	LOG_TEST_RET(card->ctx, r, "Could not add key objects");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int
sc_pkcs15emu_starsign_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
	if (p15card->card->type == SC_CARD_TYPE_STARSIGN)
		return sc_pkcs15emu_starsign_init(p15card);
	return SC_ERROR_WRONG_CARD;
}
