/*
 * Copyright (c) 2023 Luka Logar <luka.logar@iname.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_STRNDUP
#include <stdlib.h>
#include <string.h>
#include "common/compat_strnlen.h"

char *_strndup(const char *str, size_t n)
{
	char *dst;
	if (!str)
		return NULL;
	n = strnlen(str, n);
	dst = (char*)malloc(n + 1);
	if (!dst)
		return NULL;
	memcpy(dst, str, n);
	dst[n] = '\0';
	return dst;
};

#endif
