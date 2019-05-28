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
#include "common/compat_strlcpy.h"

#define RANDOM_UID_INDICATOR 0x08
static int generate_cache_filename(struct sc_pkcs15_card *p15card,
				   const sc_path_t *path,
				   char *buf, size_t bufsize)
{
	char dir[PATH_MAX];
	char *last_update = NULL;
	int  r;
	unsigned u;

	if (p15card->tokeninfo->serial_number == NULL
			&& (p15card->card->uid.len == 0
				|| p15card->card->uid.value[0] == RANDOM_UID_INDICATOR))
		return SC_ERROR_INVALID_ARGUMENTS;

	assert(path->len <= SC_MAX_PATH_SIZE);
	r = sc_get_cache_dir(p15card->card->ctx, dir, sizeof(dir));
	if (r)
		return r;
	snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir), "/");

	last_update = sc_pkcs15_get_lastupdate(p15card);
	if (!last_update)
		last_update = "NODATE";

	if (p15card->tokeninfo->serial_number) {
		snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir),
				"%s_%s", p15card->tokeninfo->serial_number,
				last_update);
	} else {
		snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir),
				"uid-%s_%s", sc_dump_hex(
					p15card->card->uid.value,
					p15card->card->uid.len), last_update);
	}

	if (path->aid.len &&
		(path->type == SC_PATH_TYPE_FILE_ID || path->type == SC_PATH_TYPE_PATH))   {
		snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir), "_");
		for (u = 0; u < path->aid.len; u++)
			snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir),
					"%02X",  path->aid.value[u]);
	}
	else if (path->type != SC_PATH_TYPE_PATH)  {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (path->len)   {
		size_t offs = 0;

		if (path->len > 2 && memcmp(path->value, "\x3F\x00", 2) == 0)
			offs = 2;
		snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir), "_");
		for (u = 0; u < path->len - offs; u++)
			snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir),
					"%02X",  path->value[u + offs]);
	}

	if (!buf)
		return SC_ERROR_BUFFER_TOO_SMALL;
	strlcpy(buf, dir, bufsize);

	return SC_SUCCESS;
}

int sc_pkcs15_read_cached_file(struct sc_pkcs15_card *p15card,
				const sc_path_t *path,
				u8 **buf, size_t *bufsize)
{
	char fname[PATH_MAX];
	int rv;
	FILE *f;
	size_t count;
	struct stat stbuf;
	u8 *data = NULL;

	if (path->len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Accept full path or FILE-ID path with AID */
	if ((path->type != SC_PATH_TYPE_PATH) && (path->type != SC_PATH_TYPE_FILE_ID || path->aid.len == 0))
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_log(p15card->card->ctx, "try to read cache for %s", sc_print_path(path));
	rv = generate_cache_filename(p15card, path, fname, sizeof(fname));
	if (rv != SC_SUCCESS)
		return rv;
	sc_log(p15card->card->ctx, "read cached file %s", fname);

	f = fopen(fname, "rb");
	if (!f)
		return SC_ERROR_FILE_NOT_FOUND;
	if (fstat(fileno(f), &stbuf))   {
		fclose(f);
		return  SC_ERROR_FILE_NOT_FOUND;
	}

	if (path->count < 0) {
		count = stbuf.st_size;
	}
	else {
		count = path->count;
		if (path->index + count > (size_t)stbuf.st_size)   {
			rv = SC_ERROR_FILE_NOT_FOUND; /* cache file bad? */
			goto err;
		}

		if (0 != fseek(f, (long)path->index, SEEK_SET)) {
			rv = SC_ERROR_FILE_NOT_FOUND;
			goto err;
		}
	}

	if (*buf == NULL) {
		data = malloc((size_t)stbuf.st_size);
		if (data == NULL)   {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
	}
	else {
		if (count > *bufsize) {
			rv =  SC_ERROR_BUFFER_TOO_SMALL;
			goto err;
		}
		data = *buf;
	}

	if (count != fread(data, 1, count, f)) {
		rv = SC_ERROR_BUFFER_TOO_SMALL;
		goto err;
	}
	*buf = data;
	*bufsize = count;

	rv = SC_SUCCESS;

err:
	if (rv != SC_SUCCESS) {
		if (data != *buf) {
			free(data);
		}
	}

	fclose(f);
	return rv;
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
		sc_log(p15card->card->ctx, 
			 "fwrite() wrote only %"SC_FORMAT_LEN_SIZE_T"u bytes",
			 c);
		unlink(fname);
		return SC_ERROR_INTERNAL;
	}
	return 0;
}
