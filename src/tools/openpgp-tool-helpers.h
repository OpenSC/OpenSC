/*
 * openpgp-tool-helpers.h: OpenPGP card utility
 *
 * Copyright (C) 2012-2020 Peter Marschall <peter@adpm.de>
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

#ifndef OPENPGP_TOOL_HELPERS_H
#define OPENPGP_TOOL_HELPERS_H

#include "util.h"


char *prettify_hex(const u8 *data, size_t length, char *buffer, size_t buflen);
char *prettify_algorithm(const u8 *data, size_t length);
char *prettify_date(const u8 *data, size_t length);
char *prettify_version(const u8 *data, size_t length);
char *prettify_manufacturer(const u8 *data, size_t length);
char *prettify_serialnumber(const u8 *data, size_t length);
char *prettify_name(const u8 *data, size_t length);
char *prettify_language(const u8 *data, size_t length);
char *prettify_gender(const u8 *data, size_t length);


#endif /* OPENPGP_TOOL_HELPERS_H */
