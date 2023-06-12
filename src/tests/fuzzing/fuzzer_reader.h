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

#ifndef FUZZER_READER_H
#define FUZZER_READER_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "libopensc/internal.h"

void fuzz_get_chunk(sc_reader_t *reader, const uint8_t **chunk, uint16_t *chunk_size);
struct sc_reader_driver *sc_get_fuzz_driver(void);
void fuzz_add_reader(struct sc_context *ctx, const uint8_t *Data, size_t Size);
int fuzz_connect_card(sc_context_t *ctx, sc_card_t **card, sc_reader_t **reader_out,
                      const uint8_t *data, size_t size);

#endif /* FUZZER_TOOL_H */
