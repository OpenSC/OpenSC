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

static struct sc_context *ctx = NULL;
static struct sc_pkcs15_card *p15card = NULL;
static sc_card_t card = {0};

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int (* decode_entries[])(struct sc_pkcs15_card *, struct sc_pkcs15_object *,
            const u8 **nbuf, size_t *nbufsize) = {
        sc_pkcs15_decode_prkdf_entry, sc_pkcs15_decode_pukdf_entry,
        sc_pkcs15_decode_skdf_entry, sc_pkcs15_decode_cdf_entry,
        sc_pkcs15_decode_dodf_entry, sc_pkcs15_decode_aodf_entry
    };
    size_t i;

    if (!ctx)
        sc_establish_context(&ctx, "fuzz");
    if (!p15card) {
        card.ctx = ctx;
        p15card = sc_pkcs15_card_new();
        if (p15card) {
            p15card->card = &card;
        }
    }

    for (i = 0; i < sizeof decode_entries/sizeof *decode_entries; i++) {
        struct sc_pkcs15_object *obj;
        const u8 *p = Data;
        size_t len = Size;
        obj = calloc(1, sizeof *obj);
        while (SC_SUCCESS == decode_entries[i](p15card, obj, &p, &len)) {
            sc_pkcs15_free_object(obj);
            obj = calloc(1, sizeof *obj);
        }
        sc_pkcs15_free_object(obj);
    }

    struct sc_pkcs15_pubkey *pubkey = calloc(1, sizeof *pubkey);
    sc_pkcs15_decode_pubkey(ctx, pubkey, Data, Size);
    sc_pkcs15_free_pubkey(pubkey);

    struct sc_pkcs15_tokeninfo *tokeninfo = sc_pkcs15_tokeninfo_new();
    sc_pkcs15_parse_tokeninfo(ctx, tokeninfo, Data, Size);
    sc_pkcs15_free_tokeninfo(tokeninfo);

    sc_pkcs15_parse_unusedspace(Data, Size, p15card);

    return 0;
}
