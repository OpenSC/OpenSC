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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "scconf/scconf.h"
#include "libopensc/internal.h"
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 16000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    scconf_context *ctx = NULL;
    char *buf = NULL;

    if (size > MAX_SIZE)
        return 0;

    if (!(buf = malloc(size + 1)))
        return 0;
    if (!(ctx = scconf_new(NULL))) {
        free(buf);
        return 0;
    }

    memcpy(buf, data, size);
    buf[size] = '\0';

    scconf_parse_string(ctx, buf);

    scconf_free(ctx);
    free(buf);
    return 0;
}
