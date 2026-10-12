/*
 * Copyright (C) 2010 Frank Morgner
 *
 * This file is part of OpenSC.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fread_to_eof(const char *file, unsigned char **buf, size_t *buflen)
{
	FILE *input = NULL;
	unsigned char *p = NULL;
	size_t allocated = 0, len = 0, n = 0;

	if (!buflen || !buf || !file)
		return 0;

	input = fopen(file, "rb");
	if (!input)
		return 0;

	allocated = 4096;
	p = (unsigned char *)realloc(*buf, allocated);
	if (!p) {
		fclose(input);
		return 0;
	}
	*buf = p;

	while (!feof(input)) {
		if (len == allocated) {
			if (allocated > ((size_t)-1) / 2) {
				fclose(input);
				return 0;
			}
			allocated *= 2;
			p = (unsigned char *)realloc(*buf, allocated);
			if (!p) {
				fclose(input);
				return 0;
			}
			*buf = p;
		}
		n = fread(*buf + len, 1, allocated - len, input);
		if (ferror(input)) {
			fclose(input);
			return 0;
		}
		len += n;
	}

	fclose(input);
	*buflen = len;
	return 1;
}
