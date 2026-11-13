/*
 * card-cedulauy-cache.h: MRZ cache of the Uruguayan eID card (cédula de identidad)
 *
 * Copyright (C) 2026 Nicolás Gutiérrez <ngutierreztassano@gmail.com>
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

#ifndef _CARD_CEDULAUY_CACHE_H
#define _CARD_CEDULAUY_CACHE_H

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "common/compat_strlcat.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"

/* the three TD1 lines of 30 characters, concatenated */
#define CEDULAUY_MRZ_LEN	90
#define CEDULAUY_MRZ_CACHE_FILE "cedulauy_mrz"

static inline int
cedulauy_mrz_cache_path(sc_context_t *ctx, char *buf, size_t buflen)
{
	int r = sc_get_cache_dir(ctx, buf, buflen);
	if (r < 0)
		return r;

	if (strlcat(buf, "/" CEDULAUY_MRZ_CACHE_FILE, buflen) >= buflen)
		return SC_ERROR_BUFFER_TOO_SMALL;

	return SC_SUCCESS;
}

static inline FILE *
cedulauy_create_mrz_cache(sc_context_t *ctx, const char *path)
{
#ifdef _WIN32
	(void)ctx;
	/* the profile directory ACL already restricts access to the user */
	return fopen(path, "wb");
#else
	FILE *f;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	if (fd < 0)
		return NULL;

	/* O_CREAT does not change the mode of an existing file */
	if (fchmod(fd, S_IRUSR | S_IWUSR) < 0)
		sc_log(ctx, "Cannot restrict the permissions of %s", path);

	f = fdopen(fd, "wb");
	if (f == NULL)
		close(fd);

	return f;
#endif
}

/* returns 1 if a complete MRZ was read, 0 otherwise */
static inline int
cedulauy_read_mrz_cache(sc_context_t *ctx, unsigned char mrz[CEDULAUY_MRZ_LEN])
{
	char path[PATH_MAX];
	FILE *f;
	size_t got;

	if (cedulauy_mrz_cache_path(ctx, path, sizeof path) < 0)
		return 0;

	f = fopen(path, "rb");
	if (f == NULL)
		return 0;

	got = fread(mrz, 1, CEDULAUY_MRZ_LEN, f);
	fclose(f);

	if (got != CEDULAUY_MRZ_LEN) {
		sc_log(ctx, "Ignoring %s, it is not %d characters long", path, CEDULAUY_MRZ_LEN);
		return 0;
	}

	return 1;
}

static inline int
cedulauy_write_mrz_cache(sc_context_t *ctx, const unsigned char mrz[CEDULAUY_MRZ_LEN])
{
	char path[PATH_MAX];
	FILE *f;
	size_t written;
	int r;

	LOG_FUNC_CALLED(ctx);

	r = cedulauy_mrz_cache_path(ctx, path, sizeof path);
	LOG_TEST_RET(ctx, r, "Cannot determine the cache directory");

	f = cedulauy_create_mrz_cache(ctx, path);
	if (f == NULL && errno == ENOENT) {
		r = sc_make_cache_dir(ctx);
		LOG_TEST_RET(ctx, r, "Cannot create the cache directory");
		f = cedulauy_create_mrz_cache(ctx, path);
	}
	if (f == NULL) {
		sc_log(ctx, "Cannot open %s: %s", path, strerror(errno));
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	written = fwrite(mrz, 1, CEDULAUY_MRZ_LEN, f);
	if (fclose(f) != 0 || written != CEDULAUY_MRZ_LEN) {
		sc_log(ctx, "Cannot write %s: %s", path, strerror(errno));
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "MRZ stored in %s", path);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static inline int
cedulauy_delete_mrz_cache(sc_context_t *ctx)
{
	char path[PATH_MAX];
	int r;

	LOG_FUNC_CALLED(ctx);

	r = cedulauy_mrz_cache_path(ctx, path, sizeof path);
	LOG_TEST_RET(ctx, r, "Cannot determine the cache directory");

	if (remove(path) != 0) {
		int err = errno;
		sc_log(ctx, "Cannot remove %s: %s", path, strerror(err));
		LOG_FUNC_RETURN(ctx, err == ENOENT ? SC_ERROR_FILE_NOT_FOUND : SC_ERROR_INTERNAL);
	}

	sc_log(ctx, "MRZ removed from %s", path);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

#endif
