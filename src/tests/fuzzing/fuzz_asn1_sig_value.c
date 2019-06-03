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

#include "libopensc/asn1.h"
#include <stdlib.h>
#include <string.h>

static unsigned char *in = NULL, *out = NULL;
static size_t inlen = 0, outlen = 0;
static struct sc_context *ctx = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (!ctx)
        sc_establish_context(&ctx, "fuzz");

    if (outlen < Size*2) {
        unsigned char *p = realloc(out, Size*2);
        if (p) {
            out = p;
            outlen = Size*2;
        }
    }

    if (inlen < Size) {
        unsigned char *p = realloc(in, Size);
        if (p) {
            in = p;
        }
    }
    memcpy(in, Data, Size);

    sc_asn1_sig_value_sequence_to_rs(ctx,
            Data, Size,
            out, outlen);

    unsigned char *p = NULL;
    size_t plen = 0;
    sc_asn1_sig_value_rs_to_sequence(ctx,
            in, Size,
            &p, &plen);
    free(p);

    return 0;
}
