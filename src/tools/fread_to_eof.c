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
	int r = 0;
	unsigned char *p;

	if (!buflen || !buf || !file)
		goto err;

#define MAX_READ_LEN 0xfff
	p = realloc(*buf, MAX_READ_LEN);
	if (!p)
		goto err;
	*buf = p;

	input = fopen(file, "rb");
	if (!input) {
		goto err;
	}

	*buflen = 0;
	while (feof(input) == 0 && *buflen < MAX_READ_LEN) {
		*buflen += fread(*buf+*buflen, 1, MAX_READ_LEN-*buflen, input);
		if (ferror(input)) {
			goto err;
		}
	}

	r = 1;
err:
	if (input)
		fclose(input);

	return r;
}
