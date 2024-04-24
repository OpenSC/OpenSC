/*
 * Copyright (C) 2019 Frank Morgner <frankmorgner@gmail.com>
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

#include "fuzzer_reader.h"
#include "libopensc/pkcs15.h"

const char *__asan_default_options() {
  return "verbosity=0:mallocator_may_return_null=1";
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct sc_context *ctx = NULL;
    struct sc_card *card = NULL;
    struct sc_pkcs15_card *p15card = NULL;
    struct sc_reader *reader = NULL;
    struct sc_pkcs15_object *obj;

    sc_establish_context(&ctx, "fuzz");
    if (!ctx)
        return 0;

    if (fuzz_connect_card(ctx, &card, &reader, Data, Size) != SC_SUCCESS)
        goto err;

    if (SC_SUCCESS == sc_pkcs15_bind(card, NULL, &p15card)
        && p15card) {
        const uint8_t *in, *param;
        uint16_t in_len, param_len;
        fuzz_get_chunk(reader, &in, &in_len);
        fuzz_get_chunk(reader, &param, &param_len);
        for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
            u8 buf[0xFFFF];
            size_t i;

            int decipher_flags[] = {SC_ALGORITHM_RSA_RAW,
                SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02, SC_ALGORITHM_RSA_PAD_ANSI,
                SC_ALGORITHM_RSA_PAD_ISO9796};
            for (i = 0; i < sizeof decipher_flags/sizeof *decipher_flags; i++) {
                sc_pkcs15_decipher(p15card, obj, decipher_flags[i],
                        in, in_len, buf, sizeof buf, NULL);
            }

            i = sizeof buf;
            sc_pkcs15_derive(p15card, obj, 0,
                    in, in_len, buf, &i);

            int wrap_flags[] = {0, SC_ALGORITHM_AES_ECB, SC_ALGORITHM_AES_CBC_PAD,
                SC_ALGORITHM_AES_CBC};
            for (i = 0; i < sizeof wrap_flags/sizeof *wrap_flags; i++) {
                /* see `pkcs15_create_secret_key` in
                 * `src/pkcs11/framework-pkc15.c` for creating a temporary
                 * secret key for wrapping/unwrapping */
                size_t l = sizeof buf;
                struct sc_pkcs15_object target_key;
                struct sc_pkcs15_skey_info skey_info;
                uint16_t len;
                memset(&target_key, 0, sizeof target_key);
                memset(&skey_info, 0, sizeof skey_info);
                target_key.type = SC_PKCS15_TYPE_SKEY;
                target_key.flags = 2; /* TODO not sure what these mean */
                target_key.session_object = 1;
                target_key.data = &skey_info;
                skey_info.usage = SC_PKCS15_PRKEY_USAGE_UNWRAP | SC_PKCS15_PRKEY_USAGE_WRAP
                    | SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT;
                skey_info.native = 0; /* card can not use this */
                skey_info.access_flags = 0; /* looks like not needed */
                skey_info.key_type = 0x1fUL; /* CKK_AES */
                skey_info.value_len = 128;
                fuzz_get_chunk(reader, (const u8 **) &skey_info.data.value, &len);
                skey_info.data.len = len;

                sc_pkcs15_unwrap(p15card, obj, &target_key, wrap_flags[i],
                        in, in_len, param, param_len);
                sc_pkcs15_wrap(p15card, obj, &target_key, wrap_flags[i],
                        buf, &l, in, in_len);
            }

            int signature_flags[] = {SC_ALGORITHM_RSA_RAW,
                SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01, SC_ALGORITHM_RSA_PAD_ANSI,
                SC_ALGORITHM_RSA_PAD_ISO9796,
                SC_ALGORITHM_RSA_PAD_PSS|SC_ALGORITHM_MGF1_SHA1,
                SC_ALGORITHM_RSA_PAD_PSS|SC_ALGORITHM_MGF1_SHA256,
                SC_ALGORITHM_RSA_PAD_PSS|SC_ALGORITHM_MGF1_SHA384,
                SC_ALGORITHM_RSA_PAD_PSS|SC_ALGORITHM_MGF1_SHA512,
                SC_ALGORITHM_RSA_PAD_PSS|SC_ALGORITHM_MGF1_SHA224,
                SC_ALGORITHM_ECDSA_RAW, SC_ALGORITHM_ECDSA_HASH_SHA1,
                SC_ALGORITHM_ECDSA_HASH_SHA224, SC_ALGORITHM_ECDSA_HASH_SHA256,
                SC_ALGORITHM_ECDSA_HASH_SHA384, SC_ALGORITHM_ECDSA_HASH_SHA512,
                SC_ALGORITHM_GOSTR3410_RAW, SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411,
                SC_ALGORITHM_GOSTR3410_HASHES,
            };
            for (i = 0; i < sizeof signature_flags/sizeof *signature_flags; i++) {
                sc_pkcs15_compute_signature(p15card, obj, signature_flags[i],
                        in, in_len, buf, sizeof buf, NULL);
            }

            if (obj->type == SC_PKCS15_TYPE_AUTH_PIN) {
                sc_pkcs15_verify_pin(p15card, obj, in, in_len);
                sc_pkcs15_change_pin(p15card, obj, in, in_len, param, param_len);
                sc_pkcs15_unblock_pin(p15card, obj, in, in_len, param, param_len);
                sc_pkcs15_get_pin_info(p15card, obj);
            }
        }
        sc_pkcs15_card_free(p15card);
    }

err:
    sc_disconnect_card(card);
    sc_release_context(ctx);

    return 0;
}
