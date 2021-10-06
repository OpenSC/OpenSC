/*
 * fuzz_scconf_parse_string.c: Fuzz target for scconf_parse_string
 *
 * Copyright (C) 2021 Red Hat, Inc.
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "scconf/scconf.h"
#include "libopensc/internal.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    scconf_context *ctx = scconf_new(NULL);

    if (!ctx)
        return 1;
    const char *buf = (const char *)data;
    scconf_parse_string(ctx, buf);

    scconf_free(ctx);
    return 0;
}
