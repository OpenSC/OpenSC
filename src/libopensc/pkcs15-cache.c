/*
 * pkcs15-cache.c: PKCS #15 file caching functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include "pkcs15.h"
#include "log.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <assert.h>

static int generate_cache_filename(struct sc_pkcs15_card *p15card,
				   const struct sc_path *path,
				   char *buf, size_t bufsize)
{
	char dir[80];
        char pathname[SC_MAX_PATH_SIZE*2+1];
	int i, r;
        const u8 *pathptr;
        size_t pathlen;

	if (path->type != SC_PATH_TYPE_PATH)
                return SC_ERROR_INVALID_ARGUMENTS;
	assert(path->len <= SC_MAX_PATH_SIZE);
	r = sc_get_cache_dir(p15card->card->ctx, dir, sizeof(dir));
	if (r)
		return r;
	pathptr = path->value;
	pathlen = path->len;
	if (pathlen > 2 && memcmp(pathptr, "\x3F\x00", 2) == 0) {
                pathptr += 2;
		pathlen -= 2;
	}
	for (i = 0; i < pathlen; i++)
                sprintf(pathname + 2*i, "%02X", pathptr[i]);
	r = snprintf(buf, bufsize, "%s/%s_%s_%s_%s", dir,
		     p15card->manufacturer_id, p15card->label,
		     p15card->serial_number, pathname);
	if (r < 0)
		return SC_ERROR_BUFFER_TOO_SMALL;
        return 0;
}

int sc_pkcs15_read_cached_file(struct sc_pkcs15_card *p15card,
			       const struct sc_path *path,
			       u8 **buf, size_t *bufsize)
{
	char fname[160];
	int r;
	FILE *f;
	size_t c;
	struct stat stbuf;
	u8 *data = NULL;

	r = generate_cache_filename(p15card, path, fname, sizeof(fname));
	if (r != 0)
		return r;
	r = stat(fname, &stbuf);
	if (r)
		return SC_ERROR_FILE_NOT_FOUND;
	c = stbuf.st_size;
	if (*buf == NULL) {
		data = (u8 *) malloc(stbuf.st_size);
		if (data == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	} else
		if (c > *bufsize)
			return SC_ERROR_BUFFER_TOO_SMALL;
	f = fopen(fname, "r");
	if (f == NULL) {
		if (data)
			free(data);
		return SC_ERROR_FILE_NOT_FOUND;
	}
	if (data)
		*buf = data;
	c = fread(*buf, 1, c, f);
        fclose(f);
	if (c != stbuf.st_size) {
		if (data)
			free(data);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	*bufsize = c;
	if (data)
		*buf = data;
        return 0;
}

int sc_pkcs15_cache_file(struct sc_pkcs15_card *p15card,
			 const struct sc_path *path,
			 const u8 *buf, size_t bufsize)
{
	char fname[160];
	int r;
        FILE *f;
        size_t c;

	r = generate_cache_filename(p15card, path, fname, sizeof(fname));
	if (r != 0)
		return r;
	f = fopen(fname, "w");
	if (f == NULL)
		return 0;
	c = fwrite(buf, 1, bufsize, f);
        fclose(f);
	if (c != bufsize) {
		error(p15card->card->ctx, "fwrite() wrote only %d bytes", c);
		unlink(fname);
		return SC_ERROR_INTERNAL;
	}
        return 0;
}
