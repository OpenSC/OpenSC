/*
 * log.c: Miscellaneous logging functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-log.h"
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>

#ifndef __GNUC__
void error(struct sc_context *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	do_log2(ctx, SC_LOG_TYPE_ERROR, NULL, 0, "", format, ap);
	va_end(ap);
}

void debug(struct sc_context *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	do_log2(ctx, SC_LOG_TYPE_DEBUG, NULL, 0, "", format, ap);
	va_end(ap);
}

#endif

void do_log(struct sc_context *ctx, int facility, const char *file,
	    int line, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	do_log2(ctx, facility, file, line, func, format, ap);
	va_end(ap);
}

int use_color(struct sc_context *ctx, FILE *outf)
{
	static char *term = NULL;
	static const char *terms[] = { "linux", "xterm", "Eterm" };
	int term_count = sizeof(terms)/sizeof(terms[0]);
	int do_color = 0;
	int i;

	if (!ctx->use_std_output)
		return 0;
	if (term == NULL) {
		term = getenv("TERM");
		if (term == NULL)
			return 0;
	}
	do_color = 0;
	for (i = 0; i < term_count; i++)
		if (strcmp(terms[i], term) == 0) {
			do_color = 1;
			break;
		}
	if (!do_color)
		return 0;
	if (!isatty(fileno(outf)))
		return 0;
	return do_color;
}

void do_log2(struct sc_context *ctx, int type, const char *file,
	     int line, const char *func, const char *format, va_list args)
{
	FILE *outf = NULL;
	char buf[1024], *p;
	int left, r;
	struct timeval tv;

	assert(ctx != NULL);
	gettimeofday(&tv, NULL);
	if (ctx->use_std_output) {
		switch (type) {
		case SC_LOG_TYPE_ERROR:
			outf = stderr;
			break;

		case SC_LOG_TYPE_DEBUG:
			outf = stdout;
		}
		if (outf == NULL)
			return;
	}
	r = 0;
	if (file != NULL) {
		r = snprintf(buf, sizeof(buf), "%s:%d:%s: ", file, line, func);
		if (r < 0)
			return;
	}
	p = buf + r;
	left = sizeof(buf) - r;

	if (vsnprintf(p, left, format, args) < 0)
		return;
	if (ctx->use_std_output) {
		const char *color_pfx = "", *color_sfx = "";
		if (use_color(ctx, outf)) {
			color_sfx = "\33[0m";
			switch (type) {
			case SC_LOG_TYPE_ERROR:
				color_pfx = "\33[01;31m";
				break;
			case SC_LOG_TYPE_DEBUG:
				color_pfx = "\33[00;32m";
				break;
			}
		}
		fprintf(outf, "%s%s%s", color_pfx, buf, color_sfx);
		fflush(outf);
	}
}

void sc_hex_dump(struct sc_context *ctx, const u8 *in, size_t count,
		 char *buf, size_t len)
{
	char *p = buf;
	int lines = 0;

	assert(buf != NULL && in != NULL);
	buf[0] = 0;
	if (count*5 > len)
		return;
 	while (count) {
		char ascbuf[17];
		int i;

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

void sc_perror(struct sc_context *ctx, int sc_errno, const char *str)
{
	error(ctx, "%s: %s\n", str, sc_strerror(sc_errno));
}
