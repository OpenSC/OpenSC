/*
 * PKCS15 emulation layer for DIN 66291–4 profile.
 *
 * Copyright (C) 2017, Frank Morgner
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
#include <config.h>
#endif

#include "common/compat_strlcpy.h"
#include "log.h"
#include "pkcs15.h"
#include <stdlib.h>
#include <string.h>

static const unsigned char aid_CIA[] = {0xE8, 0x28, 0xBD, 0x08, 0x0F,
    0xA0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4E};
static const unsigned char aid_ESIGN[] = {0xA0, 0x00, 0x00, 0x01, 0x67,
    0x45, 0x53, 0x49, 0x47, 0x4E};

int din_66291_match_p15card(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    int ok = 0, r;
    sc_path_t path;
    unsigned char *tokeninfo_content = NULL;
    struct sc_file *file_tokeninfo = NULL;
    struct sc_pkcs15_tokeninfo *tokeninfo = sc_pkcs15_tokeninfo_new();

    if (!p15card || !tokeninfo
            || (aid && (aid->len != sizeof aid_CIA
                    || 0 != memcmp(aid->value, aid_CIA, sizeof aid_CIA))))
        goto err;

    if (p15card->tokeninfo
            && p15card->tokeninfo->profile_indication.name
            && 0 == strcmp("DIN V 66291",
                p15card->tokeninfo->profile_indication.name)) {
        ok = 1;
        goto err;
    }

    /* it is possible that p15card->tokeninfo has not been touched yet */
    sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid_CIA, sizeof aid_CIA, 0, 0);
    if (SC_SUCCESS != sc_select_file(p15card->card, &path, NULL))
        goto err;

    sc_format_path("5032", &path);
    if (SC_SUCCESS != sc_select_file(p15card->card, &path, &file_tokeninfo))
        goto err;

    tokeninfo_content = malloc(file_tokeninfo->size);
    if (!tokeninfo_content)
        goto err;
    r = sc_read_binary(p15card->card, 0, tokeninfo_content, file_tokeninfo->size, 0);
    if (r < 0)
        goto err;
    r = sc_pkcs15_parse_tokeninfo(p15card->card->ctx, tokeninfo, tokeninfo_content, r);
    if (r != SC_SUCCESS)
        goto err;

    if (tokeninfo->profile_indication.name
            && 0 == strcmp("DIN V 66291",
                tokeninfo->profile_indication.name)) {
        ok = 1;
        /* save tokeninfo and file_tokeninfo */
        sc_pkcs15_free_tokeninfo(p15card->tokeninfo);
        sc_file_free(p15card->file_tokeninfo);
        p15card->tokeninfo = tokeninfo;
        p15card->file_tokeninfo = file_tokeninfo;
        tokeninfo = NULL;
        file_tokeninfo = NULL;
    }

err:
    sc_pkcs15_free_tokeninfo(tokeninfo);
    sc_file_free(file_tokeninfo);
    free(tokeninfo_content);

    return ok;
}

    static int
sc_pkcs15emu_din_66291_init(sc_pkcs15_card_t *p15card)
{
    /*  EF.C.CH.AUT
     *  fileIdentifier ´C5 00´
     *  shortFileIdentifier ´01´= 1 
     *  PrK.CH.AUT 
     *  keyIdentifier ´02´ = 2
     *  privateKey …, Moduluslänge 2048 Bit 
     *
     *  EF.C.CH.ENC 
     *  fileIdentifier ´C2 00´
     *  shortFileIdentifier ´02´= 2
     *  PrK.CH.ENC 
     *  keyIdentifier ´03´ = 3
     *  privateKey …, Moduluslänge 2048 Bit 
     */
    sc_path_t path;
    size_t i;
    struct sc_pin_cmd_data data;
    const unsigned char user_pin_ref = 0x02;
	sc_serial_number_t serial;

    sc_path_set(&path, SC_PATH_TYPE_DF_NAME, aid_ESIGN, sizeof aid_ESIGN, 0, 0);
    if (SC_SUCCESS != sc_select_file(p15card->card, &path, NULL))
        return SC_ERROR_WRONG_CARD;

    memset(&data, 0, sizeof(data));
    data.cmd = SC_PIN_CMD_GET_INFO;
    data.pin_type = SC_AC_CHV;
    data.pin_reference = user_pin_ref;

    if (SC_SUCCESS == sc_pin_cmd(p15card->card, &data, NULL)) {
        const unsigned char user_pin_id = 1;

        for (i = 0; i < 2; i++) {
            const char *pin_names[3] = { "PIN", "PUK" };
            const int pin_min[] = {6, 10};
            const int pin_max[] = {8, 8};
            const unsigned char user_puk_id = 2;
            const int pin_id[] = {user_pin_id, user_puk_id};
            const int pin_flags[] = {SC_PKCS15_PIN_FLAG_INITIALIZED,
                SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN|SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED};
            const int max_tries[] = {3, 10};
            struct sc_pkcs15_auth_info pin_info;
            struct sc_pkcs15_object pin_obj;

            memset(&pin_info, 0, sizeof(pin_info));
            memset(&pin_obj, 0, sizeof(pin_obj));

            pin_info.auth_id.value[0] = pin_id[i];
            pin_info.auth_id.len = 1;
            pin_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;	
            pin_info.attrs.pin.flags = pin_flags[i];
            pin_info.attrs.pin.type = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
            pin_info.attrs.pin.min_length = pin_min[i];
            pin_info.attrs.pin.stored_length = pin_max[i];
            pin_info.attrs.pin.max_length = pin_max[i];
            pin_info.max_tries = max_tries[i];

            strlcpy(pin_obj.label, pin_names[i], sizeof(pin_obj.label));

            /* catch the differences between PIN and PUK */
            if (pin_flags[i] & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN) {
                pin_info.tries_left = max_tries[i];
            } else {
                pin_info.attrs.pin.reference = user_pin_ref;
                pin_info.tries_left = data.pin1.tries_left;
                pin_info.logged_in = data.pin1.logged_in;
                pin_obj.auth_id.value[0] = user_puk_id;
                pin_obj.auth_id.len = 1;
            }

            if (0 > sc_pkcs15emu_add_pin_obj(p15card, &pin_obj, &pin_info))
                return SC_ERROR_INTERNAL;
        }

        for (i = 0; i < 2; i++) {
            struct sc_aid aid;
            const char *din_66291_cert_fids[] = { "C500", "C200"};
            const char prk_id[] = { 0x10, 0x11,};
            struct sc_pkcs15_cert_info cert_info;
            struct sc_pkcs15_object cert_obj;
            struct sc_pkcs15_prkey_info prkey_info;
            struct sc_pkcs15_object prkey_obj;
            const int prk_usage[2] = {
                SC_PKCS15_PRKEY_USAGE_ENCRYPT
                    | SC_PKCS15_PRKEY_USAGE_DECRYPT
                    | SC_PKCS15_PRKEY_USAGE_SIGN,
                SC_PKCS15_PRKEY_USAGE_NONREPUDIATION};

            memcpy(aid.value, aid_CIA, sizeof aid_CIA);
            aid.len = sizeof aid_CIA;

            memset(&prkey_info, 0, sizeof(prkey_info));
            memset(&prkey_obj, 0, sizeof(prkey_obj));
            memset(&cert_info, 0, sizeof(cert_info));
            memset(&cert_obj, 0, sizeof(cert_obj));


            sc_format_path(din_66291_cert_fids[i], &cert_info.path);
            if (SC_SUCCESS != sc_select_file(p15card->card, &cert_info.path, NULL))
                continue;
            cert_info.path.aid = aid;

            cert_info.id.value[0] = prk_id[i];
            cert_info.id.len = 1;

            if (0 > sc_pkcs15emu_add_x509_cert(p15card, &cert_obj, &cert_info))
                continue;

            if (i == 0) {
                sc_pkcs15_cert_t *cert;
                if (SC_SUCCESS == sc_pkcs15_read_certificate(p15card, &cert_info, &cert)) {
                    static const struct sc_object_id cn_oid = {{ 2, 5, 4, 3, -1 }};
                    u8 *cn_name = NULL;
                    size_t cn_len = 0;
                    sc_pkcs15_get_name_from_dn(p15card->card->ctx, cert->subject,
                            cert->subject_len, &cn_oid, &cn_name, &cn_len);
                    if (cn_len > 0) {
                        char *token_name = malloc(cn_len+1);
                        if (token_name) {
                            memcpy(token_name, cn_name, cn_len);
                            token_name[cn_len] = '\0';
                            free(p15card->tokeninfo->label);
                            p15card->tokeninfo->label = token_name;
                        }
                    }
                    free(cn_name);
                    sc_pkcs15_free_certificate(cert);
                }
            }

            memset(&prkey_info, 0, sizeof(prkey_info));
            memset(&prkey_obj, 0, sizeof(prkey_obj));

            prkey_info.id.value[0] = prk_id[i];
            prkey_info.id.len = 1;
            prkey_info.usage  = prk_usage[i];
            prkey_info.native = 1;
            prkey_info.key_reference = prk_id[i];
            prkey_info.modulus_length = 2048;
            prkey_obj.auth_id.value[0] = user_pin_id;
            prkey_obj.auth_id.len = 1;
            prkey_obj.user_consent = 0;
            prkey_obj.flags = SC_PKCS15_CO_FLAG_PRIVATE;

            if (0 > sc_pkcs15emu_add_rsa_prkey(p15card, &prkey_obj, &prkey_info))
                continue;
        }
    }

	/* get the card serial number */
	if (!p15card->tokeninfo->serial_number
            && SC_SUCCESS == sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &serial)) {
        char serial_hex[SC_MAX_SERIALNR*2+2];
        sc_bin_to_hex(serial.value, serial.len , serial_hex, sizeof serial_hex, 0);
        p15card->tokeninfo->serial_number = strdup(serial_hex);
    }

    return SC_SUCCESS;
}

int sc_pkcs15emu_din_66291_init_ex(sc_pkcs15_card_t *p15card, struct sc_aid *aid)
{
    int r;

    if (!p15card || ! p15card->card)
        return SC_ERROR_INVALID_ARGUMENTS;

    SC_FUNC_CALLED(p15card->card->ctx, 1);

    /* Check card */
    if (!din_66291_match_p15card(p15card, aid))
        return SC_ERROR_WRONG_CARD;

    /* Init card */
    r = sc_pkcs15emu_din_66291_init(p15card);
    if (r != SC_SUCCESS) {
        sc_pkcs15_free_tokeninfo(p15card->tokeninfo);
        sc_file_free(p15card->file_tokeninfo);
        p15card->tokeninfo = NULL;
        p15card->file_tokeninfo = NULL;
    }

    return r;
}
