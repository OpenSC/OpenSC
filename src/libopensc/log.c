/*
 * log.c: Miscellaneous logging functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
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
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

/* Although not used, we need this for consistent exports */
void _sc_error(sc_context_t *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, SC_LOG_TYPE_ERROR, NULL, 0, NULL, format, ap);
	va_end(ap);
}

/* Although not used, we need this for consistent exports */
void _sc_debug(sc_context_t *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, SC_LOG_TYPE_DEBUG, NULL, 0, NULL, format, ap);
	va_end(ap);
}

void sc_do_log(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, type, file, line, func, format, ap);
	va_end(ap);
}

void sc_do_log_va(sc_context_t *ctx, int type, const char *file, int line, const char *func, const char *format, va_list args)
{
	int	(*display_fn)(sc_context_t *, const char *);
	char	buf[1836], *p;
	const char *tag = "";
	int	r;
	size_t	left;

	assert(ctx != NULL);

	switch (type) {
	case SC_LOG_TYPE_ERROR:
		if (!ctx->suppress_errors) {
			display_fn = &sc_ui_display_error;
			tag = "error:";
			break;
		}
		/* Fall thru - suppressed errors are logged as
		 * debug messages */
		tag = "error (suppressed):";
		type = SC_LOG_TYPE_DEBUG;

	case SC_LOG_TYPE_DEBUG:
		if (ctx->debug == 0)
			return;
		display_fn = &sc_ui_display_debug;
		break;

	default:
		return;
	}

	if (file != NULL) {
		r = snprintf(buf, sizeof(buf), "[%s] %s:%d:%s: ", 
			ctx->app_name, file, line, func ? func : "");
		if (r < 0 || (unsigned int)r > sizeof(buf))
			return;
	} else {
		r = 0;
	}
	p = buf + r;
	left = sizeof(buf) - r;

	r = vsnprintf(p, left, format, args);
	if (r < 0)
		return;
	p += r;
	left -= r;

	display_fn(ctx, buf);
}

void sc_hex_dump(sc_context_t *ctx, const u8 * in, size_t count, char *buf, size_t len)
{
	char *p = buf;
	int lines = 0;

	assert(buf != NULL && in != NULL);
	buf[0] = 0;
	if ((count * 5) > len)
		return;
	while (count) {
		char ascbuf[17];
		size_t i;

		for (i = 0; i < count && i < 16; i++) {
			sprintf(p, "%02X ", *in);
			if (isprint(*in))
				ascbuf[i] = *in;
			else
				ascbuf[i] = '.';
			p += 3;
			in++;
		}
		count -= i;
		ascbuf[i] = 0;
		for (; i < 16 && lines; i++) {
			strcat(p, "   ");
			p += 3;
		}
		strcat(p, ascbuf);
		p += strlen(p);
		sprintf(p, "\n");
		p++;
		lines++;
	}
}
