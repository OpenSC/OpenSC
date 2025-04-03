/*
 * fuzz_pkcs11_uri.c: Fuzz target for PKCS #11 URI parser
 *
 * Copyright (C) 2025 Red Hat, Inc.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tools/pkcs11_uri.h>

#undef stderr
#define stderr stdout
 
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	char *input_string = NULL;
	struct pkcs11_uri *uri = NULL;
	if (Size == 0)
		return 0;
	if ((input_string = malloc(Size + 1)) == NULL)
		return 0;
	memcpy(input_string, Data, Size);
	input_string[Size] = 0;

	if ((uri = pkcs11_uri_new()) == NULL)
		return 0;
	parse_pkcs11_uri(input_string, uri);

	pkcs11_uri_free(uri);
	free(input_string);
	return 0;
}
 