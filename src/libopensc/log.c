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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#include "internal.h"

static void sc_do_log_va(sc_context_t *ctx, int level, const char *file, int line, const char *func, int color, const char *format, va_list args);

void sc_do_log(sc_context_t *ctx, int level, const char *file, int line, const char *func, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, level, file, line, func, 0, format, ap);
	va_end(ap);
}

void sc_do_log_color(sc_context_t *ctx, int level, const char *file, int line, const char *func, int color, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, level, file, line, func, color, format, ap);
	va_end(ap);
}

void sc_do_log_noframe(sc_context_t *ctx, int level, const char *format, va_list args)
{
	sc_do_log_va(ctx, level, NULL, 0, NULL, 0, format, args);
}

static void sc_do_log_va(sc_context_t *ctx, int level, const char *file, int line, const char *func, int color, const char *format, va_list args)
{
	char	buf[4096];
#ifdef _WIN32
	SYSTEMTIME st;
#else
	struct tm *tm;
	struct timeval tv;
	char time_string[40];
#endif

	if (!ctx || ctx->debug < level)
		return;

#ifdef _WIN32
	/* In Windows, file handles can not be shared between DLL-s, each DLL has a
	 * separate file handle table. Make sure we always have a valid file
	 * descriptor. */
	if (sc_ctx_log_to_file(ctx, ctx->debug_filename) < 0)
		return;
#endif
	if (ctx->debug_file == NULL)
		return;

#ifdef _WIN32
	GetLocalTime(&st);
	sc_color_fprintf(SC_COLOR_FG_GREEN|SC_COLOR_BOLD,
			ctx, ctx->debug_file,
			"P:%lu; T:%lu",
			(unsigned long)GetCurrentProcessId(),
			(unsigned long)GetCurrentThreadId());
	sc_color_fprintf(SC_COLOR_FG_GREEN,
			ctx, ctx->debug_file,
			" %i-%02i-%02i %02i:%02i:%02i.%03i",
			st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
	sc_color_fprintf(SC_COLOR_FG_GREEN|SC_COLOR_BOLD,
			ctx, ctx->debug_file,
			"P:%lu; T:0x%lu",
			(unsigned long)getpid(),
			(unsigned long)pthread_self());
	gettimeofday (&tv, NULL);
	tm = localtime (&tv.tv_sec);
	strftime (time_string, sizeof(time_string), "%H:%M:%S", tm);
	sc_color_fprintf(SC_COLOR_FG_GREEN,
			ctx, ctx->debug_file,
			" %s.%03ld",
			time_string,
			(long)tv.tv_usec / 1000);
#endif

	sc_color_fprintf(SC_COLOR_FG_YELLOW,
			ctx, ctx->debug_file,
			" [");
	sc_color_fprintf(SC_COLOR_FG_YELLOW|SC_COLOR_BOLD,
			ctx, ctx->debug_file,
			"%s",
			ctx->app_name);
	sc_color_fprintf(SC_COLOR_FG_YELLOW,
			ctx, ctx->debug_file,
			"] ");

	if (file != NULL) {
		sc_color_fprintf(SC_COLOR_FG_YELLOW,
				ctx, ctx->debug_file,
				"%s:%d:%s: ",
				file, line, func ? func : "");
	}

	if (vsnprintf(buf, sizeof buf, format, args) >= 0) {
		sc_color_fprintf(color, ctx, ctx->debug_file, "%s", buf);
		if (strlen(buf) == 0 || buf[strlen(buf)-1] != '\n')
			sc_color_fprintf(color, ctx, ctx->debug_file, "\n");
	}
	fflush(ctx->debug_file);

#ifdef _WIN32
	if (ctx->debug_file && (ctx->debug_file != stderr && ctx->debug_file != stdout))
		fclose(ctx->debug_file);
	ctx->debug_file = NULL;
#endif
}

void _sc_debug(struct sc_context *ctx, int level, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, level, NULL, 0, NULL, 0, format, ap);
	va_end(ap);
}

void _sc_log(struct sc_context *ctx, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	sc_do_log_va(ctx, SC_LOG_DEBUG_NORMAL, NULL, 0, NULL, 0, format, ap);
	va_end(ap);
}

#ifdef _WIN32
#define set_color(sc_color, win_color, vt100_color) \
	do { if (colors & sc_color) { attr |= win_color; } } while (0)
#else
#define set_color(sc_color, win_color, vt100_color) \
	do { if (colors & sc_color) { fprintf(stream, vt100_color); } } while (0)
#endif

int sc_color_fprintf(int colors, struct sc_context *ctx, FILE * stream, const char * format, ...)
{
	va_list ap;
	int r;
#ifdef _WIN32
	WORD old_attr = 0;
	int fd = stream ? fileno(stream) : -1;
	HANDLE handle = fd >= 0 ? (HANDLE) _get_osfhandle(fd) : INVALID_HANDLE_VALUE;
#endif

	if (colors && (!ctx || (!(ctx->flags & SC_CTX_FLAG_DISABLE_COLORS)))) {
#ifdef _WIN32
		WORD attr = 0;
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(handle, &csbi);
		old_attr = csbi.wAttributes;
#endif
		set_color(SC_COLOR_FG_RED,
				FOREGROUND_RED,
				"\x1b[31m");
		set_color(SC_COLOR_FG_GREEN,
				FOREGROUND_GREEN,
				"\x1b[32m");
		set_color(SC_COLOR_FG_YELLOW,
				FOREGROUND_GREEN|FOREGROUND_RED,
				"\x1b[33m");
		set_color(SC_COLOR_FG_BLUE,
				FOREGROUND_BLUE,
				"\x1b[34m");
		set_color(SC_COLOR_FG_MAGENTA,
				FOREGROUND_BLUE|FOREGROUND_RED,
				"\x1b[35m");
		set_color(SC_COLOR_FG_CYAN,
				FOREGROUND_BLUE|FOREGROUND_GREEN,
				"\x1b[36m");
		set_color(SC_COLOR_BG_RED,
				FOREGROUND_RED,
				"\x1b[41m");
		set_color(SC_COLOR_BG_GREEN,
				BACKGROUND_GREEN,
				"\x1b[42m");
		set_color(SC_COLOR_BG_YELLOW,
				BACKGROUND_GREEN|BACKGROUND_RED,
				"\x1b[43m");
		set_color(SC_COLOR_BG_BLUE,
				BACKGROUND_BLUE,
				"\x1b[44m");
		set_color(SC_COLOR_BG_MAGENTA,
				BACKGROUND_BLUE|BACKGROUND_RED,
				"\x1b[45m");
		set_color(SC_COLOR_BG_CYAN,
				BACKGROUND_BLUE|BACKGROUND_GREEN,
				"\x1b[46m");
		set_color(SC_COLOR_BOLD,
				FOREGROUND_INTENSITY,
				"\x1b[1m");
#ifdef _WIN32
		SetConsoleTextAttribute(handle, attr);
#endif
	}

	va_start(ap, format);
	r = vfprintf(stream, format, ap);
	va_end(ap);

	if (colors && (!ctx || (!(ctx->flags & SC_CTX_FLAG_DISABLE_COLORS)))) {
#ifdef _WIN32
		SetConsoleTextAttribute(handle, old_attr);
#else
		fprintf(stream, "\x1b[0m");
#endif
	}

	return r;
}

void _sc_debug_hex(sc_context_t *ctx, int type, const char *file, int line,
		const char *func, const char *label, const u8 *data, size_t len)
{
	size_t blen = len * 5 + 128;
	char *buf = malloc(blen);
	if (buf == NULL)
		return;

	sc_hex_dump(data, len, buf, blen);

	if (label)
		sc_do_log(ctx, type, file, line, func,
			"\n%s (%"SC_FORMAT_LEN_SIZE_T"u byte%s):\n%s",
			label, len, len==1?"":"s", buf);
	else
		sc_do_log(ctx, type, file, line, func,
			"%"SC_FORMAT_LEN_SIZE_T"u byte%s:\n%s",
			len, len==1?"":"s", buf);

	free(buf);
}

void sc_hex_dump(const u8 * in, size_t count, char *buf, size_t len)
{
	char *p = buf;
	int lines = 0;

	if (buf == NULL || (in == NULL && count != 0)) {
		return;
	}
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

const char *
sc_dump_hex(const u8 * in, size_t count)
{
	static char dump_buf[0x1000];
	size_t ii, size = sizeof(dump_buf) - 0x10;
	size_t offs = 0;

	memset(dump_buf, 0, sizeof(dump_buf));
	if (in == NULL)
		return dump_buf;

	for (ii=0; ii<count; ii++) {
		if (ii && !(ii%16))   {
			if (!(ii%48))
				snprintf(dump_buf + offs, size - offs, "\n");
			else
				snprintf(dump_buf + offs, size - offs, " ");
			offs = strlen(dump_buf);
		}

		snprintf(dump_buf + offs, size - offs, "%02X", *(in + ii));
		offs += 2;

		if (offs > size)
			break;
	}

	if (ii<count)
		snprintf(dump_buf + offs, sizeof(dump_buf) - offs, "....\n");

	return dump_buf;
}

const char *
sc_dump_oid(const struct sc_object_id *oid)
{
	static char dump_buf[SC_MAX_OBJECT_ID_OCTETS * 20];
        size_t ii;

	memset(dump_buf, 0, sizeof(dump_buf));
	if (oid)
		for (ii=0; ii<SC_MAX_OBJECT_ID_OCTETS && oid->value[ii] != -1; ii++)
			snprintf(dump_buf + strlen(dump_buf), sizeof(dump_buf) - strlen(dump_buf), "%s%i", (ii ? "." : ""), oid->value[ii]);

	return dump_buf;
}
