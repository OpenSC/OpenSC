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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "libopensc/pkcs15.h"
#include "libopensc/internal.h"
#include <stdlib.h>
#include <string.h>

const char *__asan_default_options() {
  return "verbosity=0:mallocator_may_return_null=1";
}

/* private data structures */
struct driver_data {
    const uint8_t *Data;
    size_t Size;
};

static struct sc_reader_operations fuzz_ops = {0};
static struct sc_reader_driver fuzz_drv = {
    "Fuzzing reader",
    "fuzz",
    &fuzz_ops,
    NULL
};

void fuzz_get_chunk(sc_reader_t *reader, const uint8_t **chunk, uint16_t *chunk_size)
{
    struct driver_data *data;
    uint16_t c_size;
    const uint8_t *c;

    if (chunk)
        *chunk = NULL;
    if (chunk_size)
        *chunk_size = 0;

    if (!chunk || !chunk_size || !reader) {
        sc_debug(reader->ctx, SC_LOG_DEBUG_VERBOSE_TOOL, "Invalid Arguments");
        return;
    }
    data = reader->drv_data;
    if (!data || !data->Data || data->Size < sizeof c_size) {
        sc_debug(reader->ctx, SC_LOG_DEBUG_VERBOSE_TOOL, "Invalid Arguments");
        return;
    }

    /* parse the length of the returned data on two bytes */
    c_size = *((uint16_t *) data->Data);
    /* consume two bytes from the fuzzing data */
    data->Size -= sizeof c_size;
    data->Data += sizeof c_size;

    if (data->Size < c_size) {
        c_size = data->Size;
    }

    /* consume the bytes from the fuzzing data */
    c = data->Data;
    data->Size -= c_size;
    data->Data += c_size;

    sc_debug_hex(reader->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
        "Returning fuzzing chunk", c, c_size);

    *chunk = c;
    *chunk_size = c_size;
}

static int fuzz_reader_release(sc_reader_t *reader)
{
    if (reader) {
        free(reader->drv_data);
        reader->drv_data = NULL;
    }

    return SC_SUCCESS;
}

static int fuzz_reader_connect(sc_reader_t *reader)
{
    uint16_t chunk_size;
    const uint8_t *chunk;

    fuzz_get_chunk(reader, &chunk, &chunk_size);

    if (chunk_size > SC_MAX_ATR_SIZE)
        chunk_size = SC_MAX_ATR_SIZE;
    else
        reader->atr.len = chunk_size;

    if (chunk_size > 0)
        memcpy(reader->atr.value, chunk, chunk_size);

    return SC_SUCCESS;
}

static int fuzz_reader_disconnect(sc_reader_t *reader)
{
    return SC_SUCCESS;
}

static int fuzz_reader_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
    const uint8_t *chunk;
    uint16_t chunk_size;

    fuzz_get_chunk(reader, &chunk, &chunk_size);

    if (chunk_size >= 2) {
        /* set the SW1 and SW2 status bytes (the last two bytes of
         * the response */
        apdu->sw1 = (unsigned int)chunk[chunk_size - 2];
        apdu->sw2 = (unsigned int)chunk[chunk_size - 1];
        chunk_size -= 2;
        /* set output length and copy the returned data if necessary */
        if (chunk_size <= apdu->resplen)
            apdu->resplen = chunk_size;

        if (apdu->resplen != 0)
            memcpy(apdu->resp, chunk, apdu->resplen);
    } else {
        apdu->sw1 = 0x6D;
        apdu->sw2 = 0x00;
        apdu->resplen = 0;
    }

    return SC_SUCCESS;
}

struct sc_reader_driver *sc_get_fuzz_driver(void)
{
    fuzz_ops.release = fuzz_reader_release;
    fuzz_ops.connect = fuzz_reader_connect;
    fuzz_ops.disconnect = fuzz_reader_disconnect;
    fuzz_ops.transmit = fuzz_reader_transmit;
    return &fuzz_drv;
}

void fuzz_add_reader(struct sc_context *ctx, const uint8_t *Data, size_t Size)
{
    sc_reader_t	*reader;
    struct driver_data *data;
    char name[64] = {0};

    if (!(reader = calloc(1, sizeof(*reader)))
            || !(data = (calloc(1, sizeof(*data))))) {
        free(reader);
        return;
    }

    data->Data = Data;
    data->Size = Size;

    reader->driver = &fuzz_drv;
    reader->ops = &fuzz_ops;
    reader->drv_data = data;
    snprintf(name, sizeof name - 1, "%zu random byte%s reader (%p)",
            Size, Size == 1 ? "" : "s", Data);
    reader->name = strdup(name);

    reader->ctx = ctx;
    list_append(&ctx->readers, reader);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct sc_context *ctx = NULL;
    struct sc_card *card = NULL;
    struct sc_pkcs15_card *p15card = NULL;
    struct sc_reader *reader;
    struct sc_pkcs15_object *obj;

    sc_establish_context(&ctx, "fuzz");
    if (!ctx)
        return 0;
    /* copied from sc_release_context() */
    while (list_size(&ctx->readers)) {
        sc_reader_t *rdr = (sc_reader_t *) list_get_at(&ctx->readers, 0);
        _sc_delete_reader(ctx, rdr);
    }
    if (ctx->reader_driver->ops->finish != NULL)
        ctx->reader_driver->ops->finish(ctx);

    ctx->reader_driver = sc_get_fuzz_driver();

    fuzz_add_reader(ctx, Data, Size);

    reader = sc_ctx_get_reader(ctx, 0);
    sc_connect_card(reader, &card);
    sc_pkcs15_bind(card, NULL, &p15card);

    if (p15card) {
        const uint8_t *in, *param;
        uint16_t in_len, param_len;
        fuzz_get_chunk(reader, &in, &in_len);
        fuzz_get_chunk(reader, &param, &param_len);
        for (obj = p15card->obj_list; obj != NULL; obj = obj->next) {
            u8 buf[0xFFFF];
            size_t i;

            int decipher_flags[] = {SC_ALGORITHM_RSA_RAW,
                SC_ALGORITHM_RSA_PAD_PKCS1, SC_ALGORITHM_RSA_PAD_ANSI,
                SC_ALGORITHM_RSA_PAD_ISO9796};
            for (i = 0; i < sizeof decipher_flags/sizeof *decipher_flags; i++) {
                sc_pkcs15_decipher(p15card, obj, decipher_flags[i],
                        in, in_len, buf, sizeof buf);
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
                unsigned long l = sizeof buf;
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
                SC_ALGORITHM_RSA_PAD_PKCS1, SC_ALGORITHM_RSA_PAD_ANSI,
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
                        in, in_len, buf, sizeof buf);
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

    sc_disconnect_card(card);
    sc_release_context(ctx);

    return 0;
}
