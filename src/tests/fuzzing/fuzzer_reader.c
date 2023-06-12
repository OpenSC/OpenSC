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

#include "fuzzer_reader.h"

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
        if (reader)
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

static int fuzz_reader_lock(sc_reader_t *reader)
{
    return 0;
}

static int fuzz_reader_unlock(sc_reader_t *reader)
{
    return 0;
}

struct sc_reader_driver *sc_get_fuzz_driver(void)
{
    fuzz_ops.release = fuzz_reader_release;
    fuzz_ops.connect = fuzz_reader_connect;
    fuzz_ops.disconnect = fuzz_reader_disconnect;
    fuzz_ops.transmit = fuzz_reader_transmit;
    fuzz_ops.lock = fuzz_reader_lock;
    fuzz_ops.unlock = fuzz_reader_unlock;
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

int fuzz_connect_card(sc_context_t *ctx, sc_card_t **card, sc_reader_t **reader_out,
                      const uint8_t *data, size_t size)
{
    struct sc_reader *reader = NULL;

    /* Erase possible readers from ctx */
    while (list_size(&ctx->readers)) {
        sc_reader_t *rdr = (sc_reader_t *) list_get_at(&ctx->readers, 0);
        _sc_delete_reader(ctx, rdr);
    }
    if (ctx->reader_driver->ops->finish != NULL)
        ctx->reader_driver->ops->finish(ctx);

    /* Create virtual reader */
    ctx->reader_driver = sc_get_fuzz_driver();
    fuzz_add_reader(ctx, data, size);
    reader = sc_ctx_get_reader(ctx, 0);

    /* Connect card */
    if (sc_connect_card(reader, card))
        return SC_ERROR_INTERNAL;

    if (reader_out)
        *reader_out = reader;

    return SC_SUCCESS;
}
