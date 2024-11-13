/*
 * fuzz_pkcs15init.c: Fuzzer for functions processing pkcs15 init
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fuzzer_reader.h"
#include "pkcs15init/pkcs15-lib.c"
#include "scconf/scconf.h"
#include "pkcs15init/pkcs15-init.h"
#include "pkcs15init/profile.c"
#include "pkcs15init/profile.h"

int fuzz_profile_load(struct sc_profile *profile, const uint8_t *data, size_t size)
{
    int rv = 0;
    scconf_context	*conf = NULL;
    conf = scconf_new(NULL);
    if (!conf)
        return 0;

    if ((rv = scconf_parse_string(conf, (char *)data)) < 0) {
        scconf_free(conf);
        return rv;
    }

    rv = process_conf(profile, conf);
    scconf_free(conf);
    return rv;
}

void fuzz_pkcs15init_bind(struct sc_card *card, struct sc_profile **result,
                          const uint8_t *data, size_t size)
{
    struct sc_profile *profile = NULL;
    const char	      *driver;
    struct sc_pkcs15init_operations * (* func)(void) = NULL;
    int r = 0;

    if (!card || !card->driver || !result)
        return;

    *result = NULL;

    r = sc_pkcs15init_set_lifecycle(card, SC_CARDCTRL_LIFECYCLE_ADMIN);
    if (r < 0 && r != SC_ERROR_NOT_SUPPORTED) {
        return;
    }

	profile = sc_profile_new();
    if (!profile)
        return;
    profile->card = card;
    driver = card->driver->short_name;

    for (int i = 0; profile_operations[i].name; i++) {
		if (!strcasecmp(driver, profile_operations[i].name)) {
			func = (struct sc_pkcs15init_operations *(*)(void)) profile_operations[i].func;
			break;
		}
	}
    if (func) {
        profile->ops = func();
    } else {
        sc_profile_free(profile);
        return;
    }
    profile->name = strdup("Fuzz profile");

    r = sc_pkcs15init_read_info(card, profile);
    if (r < 0) {
		sc_profile_free(profile);
        return;
	}

    if (fuzz_profile_load(profile, data, size) < 0) {
        sc_profile_free(profile);
        return;
    }

    if (sc_profile_finish(profile, NULL) < 0) {
        sc_profile_free(profile);
        return;
    }
    *result = profile;
}

int fuzz_get_reader_data(const uint8_t *from, size_t from_size, const uint8_t **to, size_t *to_size)
{
    size_t i = 0;
    while(i < from_size - 1 && from[i] != '\0')
        i++;

    if (from[i] != '\0')
        return 0;

    *to_size = from_size - (i + 1);
    *to = from + (i + 1);
    return 1;
}

void do_init_app(struct sc_profile *profile, struct sc_pkcs15_card *p15card, sc_card_t *card,
                 unsigned char *so_pin, unsigned char *so_puk)
{
    struct sc_pkcs15init_initargs init_args;
    sc_pkcs15_auth_info_t         info;
    int                           so_puk_disabled = 0;

    memset(&init_args, 0, sizeof(init_args));
    memset(&info, 0, sizeof(info));
    sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &info);
    if ((info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED) &&
        (info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
        so_puk_disabled = 1;

    sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &info);

    init_args.so_pin = so_pin;
    init_args.so_pin_len = 8;

    if (!so_puk_disabled) {
        init_args.so_puk = so_puk;
        init_args.so_puk_len = 8;
    }

    sc_pkcs15init_add_app(card, profile, &init_args);
}

void do_store_pin(struct sc_profile *profile, struct sc_pkcs15_card *p15card, sc_card_t *card,
                  unsigned char *pin, unsigned char *so_pin)
{
    struct sc_pkcs15init_pinargs pin_args;
    char   pin_id[SC_PKCS15_MAX_ID_SIZE] = "1\0";
    sc_pkcs15init_set_p15card(profile, p15card);

    memcpy(pin, "1234555678\0", 11); /* Set new pin */
    memset(&pin_args, 0, sizeof(pin_args));

    sc_pkcs15_format_id(pin_id, &pin_args.auth_id);
    pin_args.pin = pin;
    pin_args.pin_len = 6;
    pin_args.label = "Basic PIN";

    pin_args.puk = so_pin;
    pin_args.puk_len = 8;

    sc_pkcs15init_store_pin(p15card, profile, &pin_args);
}

void do_store_data_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card, sc_card_t *card,
                          uint8_t *buf, size_t len)
{
    struct sc_pkcs15init_dataargs args;
    char value[SC_MAX_OBJECT_ID_OCTETS];

    memcpy(value, buf, SC_MAX_OBJECT_ID_OCTETS);
    value[len < SC_MAX_OBJECT_ID_OCTETS ? len : SC_MAX_OBJECT_ID_OCTETS - 1] = '\0';

    memset(&args, 0, sizeof(args));
    sc_init_oid(&args.app_oid);
    args.label = "label";
    args.app_label = "pkcs15-init";

    sc_format_oid(&args.app_oid, value);

    args.der_encoded.value = buf;
    args.der_encoded.len = len;
    sc_pkcs15init_store_data_object(p15card, profile, &args, NULL);
}

void do_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card, sc_card_t *card)
{
    struct sc_pkcs15init_keygen_args keygen_args;
    int algorithms[] = { SC_ALGORITHM_RSA, SC_ALGORITHM_EC };
    unsigned int keybits[] = { 1024, 0 };

    memset(&keygen_args, 0, sizeof(keygen_args));
    sc_pkcs15_format_id("01", &(keygen_args.prkey_args.auth_id));
    keygen_args.prkey_args.access_flags |=
                    SC_PKCS15_PRKEY_ACCESS_SENSITIVE
                | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
                | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
                | SC_PKCS15_PRKEY_ACCESS_LOCAL;

    for (int i = 0; i < 2; i++) {
        keygen_args.prkey_args.key.algorithm = algorithms[i];
        if (algorithms[i] == SC_ALGORITHM_EC) /* strdup called also in parse_alg_spec() */
            keygen_args.prkey_args.key.u.ec.params.named_curve = strdup("prime256v1");
        sc_pkcs15init_generate_key(p15card, profile, &keygen_args, keybits[i], NULL);
        if (algorithms[i] == SC_ALGORITHM_EC)
            free(keygen_args.prkey_args.key.u.ec.params.named_curve);
    }
}

void do_generate_skey(struct sc_profile *profile, struct sc_pkcs15_card *p15card, sc_card_t *card)
{
    struct sc_pkcs15init_skeyargs skey_args;
    int algorithms[] = { SC_ALGORITHM_DES, SC_ALGORITHM_3DES, SC_ALGORITHM_AES };
    unsigned int keybits[] = { 64, 192, 128 };

    /* init keygen_args*/
    memset(&skey_args, 0, sizeof(skey_args));
    skey_args.label = "label";
    skey_args.usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT;
    skey_args.user_consent = 0;

    for (int i = 0; i < 3; i++) {
        skey_args.algorithm = algorithms[i];
        skey_args.value_len = keybits[i];
        sc_pkcs15init_generate_secret_key(p15card, profile, &skey_args, NULL);
    }
}

void do_store_secret_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
                         sc_card_t *card, uint8_t *buf)
{
    struct sc_pkcs15init_skeyargs args;
    int algorithms[] = { SC_ALGORITHM_AES, SC_ALGORITHM_DES, SC_ALGORITHM_3DES };
    unsigned int keybits[] = { 128, 64, 192 };

    memset(&args, 0, sizeof(args));
    args.access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_SENSITIVE;
    args.usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT;
    sc_pkcs15_format_id("02", &(args.auth_id));

    for (int i = 0; i < 3; i++) {
        size_t keybytes = BYTES4BITS(keybits[i]);
        args.key.data = malloc(keybytes);
        memcpy(args.key.data, buf, keybytes);
        args.key.data_len = keybytes;
        args.algorithm = algorithms[i];
        args.value_len = keybits[i];

        sc_pkcs15init_store_secret_key(p15card, profile, &args, NULL);
        if (args.key.data)
            free(args.key.data);
    }
}

void do_erase(struct sc_profile *profile, sc_card_t *card)
{
    struct sc_pkcs15_card *p15card;

    p15card = sc_pkcs15_card_new();
    p15card->card = card;

    sc_pkcs15init_erase_card(p15card, profile, NULL);
    sc_pkcs15_card_free(p15card);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    sc_context_t          *ctx = NULL;
    sc_card_t             *card = NULL;
    struct sc_pkcs15_card *p15card = NULL;
    struct sc_profile     *profile = NULL;
    struct sc_reader      *reader = NULL;
    const uint8_t         *reader_data = NULL;
    size_t                 reader_data_size = 0;
    uint8_t               *buf = NULL;
    uint16_t               len = size < 256 ? size : 256;
    unsigned char         *pin = NULL;
    unsigned char         *so_pin = NULL;
    unsigned char         *puk = NULL;
    unsigned char         *so_puk = NULL;
    struct sc_pkcs15_card *tmp_p15_data = NULL;

#ifdef FUZZING_ENABLED
    fclose(stdout);
#endif

    if (size == 0)
        return 0;

    if (!fuzz_get_reader_data(data, size, &reader_data, &reader_data_size)) {
        return 0;
    }

    /* Establish context for fuzz app*/
    sc_establish_context(&ctx, "fuzz");
    if (!ctx)
        return 0;

    if (fuzz_connect_card(ctx, &card, &reader, reader_data, reader_data_size) != SC_SUCCESS)
        goto end;

    /* Load profile and bind with card */
    fuzz_pkcs15init_bind(card, &profile, data, size - reader_data_size);

    if(!profile)
        goto end;

    pin = malloc(11);
    so_pin = malloc(9);
    puk = malloc(9);
    so_puk = malloc(9);
    buf = malloc(len * sizeof(char));
    if (!pin || !so_pin || !puk || !so_puk || !buf)
        goto end_release;

    memcpy(pin, "123456\0", 7);
    memcpy(so_pin, "12345678\0", 9);
    memcpy(puk, "12345678\0", 9);
    memcpy(so_puk, "12345678\0", 9);
    memcpy(buf, data, len);

    /* test pkcs15-init functionality*/
    do_init_app(profile, p15card, card, so_pin, so_puk);

    if (!sc_pkcs15_bind(card, NULL, &p15card)) { /* First and only sc_pkcs15_bind calling, is omitted in next cases*/
        do_store_pin(profile, p15card, card, pin, so_pin);
    }

    /* sc_pkcs15_bind failed, no point in testing next cases */
    if (!p15card)
        goto end_release;

    do_store_data_object(profile, p15card, card, buf, len);
    do_generate_key(profile, p15card, card);
    do_generate_skey(profile, p15card, card);
    do_store_secret_key(profile, p15card, card, buf);

    sc_pkcs15init_finalize_card(card, profile);
    sc_pkcs15init_sanity_check(p15card, profile);

    do_erase(profile, card);

end_release:
    free(pin);
    free(puk);
    free(so_pin);
    free(so_puk);
    free(buf);

end:
	if (profile) {
		tmp_p15_data = profile->p15_data;
		sc_pkcs15init_unbind(profile);
		if (tmp_p15_data != p15card)
			sc_pkcs15_unbind(tmp_p15_data);
	}
	if (p15card) {
		sc_pkcs15_unbind(p15card);
	}
    if (card)
	    sc_disconnect_card(card);
    sc_release_context(ctx);

    return 0;
}
