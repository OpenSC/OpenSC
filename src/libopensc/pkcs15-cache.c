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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "internal.h"
#include "pkcs15.h"

static int generate_cache_filename(struct sc_pkcs15_card *p15card,
				   const sc_path_t *path,
				   char *buf, size_t bufsize)
{
	char dir[PATH_MAX];
        char pathname[SC_MAX_PATH_SIZE*2+1];
	int  r;
        const u8 *pathptr;
        size_t i, pathlen;

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
	if (p15card->tokeninfo->serial_number != NULL) {
		char *last_update = sc_pkcs15_get_lastupdate(p15card);
		if (last_update != NULL)
			r = snprintf(buf, bufsize, "%s/%s_%s_%s", dir, p15card->tokeninfo->serial_number,
					last_update, pathname);
		else
			r = snprintf(buf, bufsize, "%s/%s_DATE_%s", dir,
					p15card->tokeninfo->serial_number, pathname);
		if (r < 0)
			return SC_ERROR_BUFFER_TOO_SMALL;
	} else
		return SC_ERROR_INVALID_ARGUMENTS;
        return SC_SUCCESS;
}

int sc_pkcs15_read_cached_file(struct sc_pkcs15_card *p15card,
			       const sc_path_t *path,
			       u8 **buf, size_t *bufsize)
{
	char fname[PATH_MAX];
	int r;
	FILE *f;
	size_t count, offset, got;
	struct stat stbuf;
	u8 *data = NULL;

	r = generate_cache_filename(p15card, path, fname, sizeof(fname));
	if (r != 0)
		return r;
	r = stat(fname, &stbuf);
	if (r)
		return SC_ERROR_FILE_NOT_FOUND;
	if (path->count < 0) {
		count = stbuf.st_size;
		offset = 0;
	} else {
		count = path->count;
		offset = path->index;
		if (offset + count > (size_t)stbuf.st_size)
			return SC_ERROR_FILE_NOT_FOUND; /* cache file bad? */
	}
	if (*buf == NULL) {
		data = malloc((size_t)stbuf.st_size);
		if (data == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
	} else
		if (count > *bufsize)
			return SC_ERROR_BUFFER_TOO_SMALL;
	f = fopen(fname, "rb");
	if (f == NULL) {
		if (data)
			free(data);
		return SC_ERROR_FILE_NOT_FOUND;
	}
	if (offset) {
		if (0 != fseek(f, (long)offset, SEEK_SET)) {
			fclose(f);
			free(data);
			return SC_ERROR_FILE_NOT_FOUND;
		}
	}
	if (data)
		*buf = data;
	got = fread(*buf, 1, count, f);
	fclose(f);
	if (got != count) {
		if (data)
			free(data);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	*bufsize = count;
	if (data)
		*buf = data;
	return 0;
}

int sc_pkcs15_cache_file(struct sc_pkcs15_card *p15card,
			 const sc_path_t *path,
			 const u8 *buf, size_t bufsize)
{
	char fname[PATH_MAX];
	int r;
        FILE *f;
        size_t c;

	r = generate_cache_filename(p15card, path, fname, sizeof(fname));
	if (r != 0)
		return r;

	f = fopen(fname, "wb");
	/* If the open failed because the cache directory does
	 * not exist, create it and a re-try the fopen() call.
	 */
	if (f == NULL && errno == ENOENT) {
		if ((r = sc_make_cache_dir(p15card->card->ctx)) < 0)
			return r;
		f = fopen(fname, "wb");
	}
	if (f == NULL)
		return 0;

	c = fwrite(buf, 1, bufsize, f);
        fclose(f);
	if (c != bufsize) {
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "fwrite() wrote only %d bytes", c);
		unlink(fname);
		return SC_ERROR_INTERNAL;
	}
        return 0;
}
