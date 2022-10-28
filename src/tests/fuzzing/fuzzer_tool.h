/*
 * fuzzer_tool.c: Implementation of general tool-fuzzing functions
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

#ifndef FUZZER_TOOL_H
#define FUZZER_TOOL_H

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#define HALF_BYTE ((sizeof(uint8_t) * 8 * 8) / 2)

const uint8_t *get_word(const uint8_t *, size_t);
char *extract_word(const uint8_t **, size_t *);
int get_fuzzed_argv(const char *, const uint8_t *, size_t ,
                    char***, int *, const uint8_t **, size_t *);
uint16_t get_buffer(const uint8_t **, size_t, const uint8_t **, size_t *, size_t);
int create_input_file(char **, const uint8_t **, size_t *);
void remove_file(char *);
void free_arguments(int, char **);

#endif /* FUZZER_TOOL_H */
