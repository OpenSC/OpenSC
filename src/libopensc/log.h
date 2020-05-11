/*
 * log.h: Logging functions header file
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

#ifndef _OPENSC_LOG_H
#define _OPENSC_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include "libopensc/opensc.h"

enum {
	SC_LOG_DEBUG_VERBOSE_TOOL = 1,	/* tools only: verbose */
	SC_LOG_DEBUG_VERBOSE,		/* helps users */
	SC_LOG_DEBUG_NORMAL,		/* helps developers */
	SC_LOG_DEBUG_RFU1,		/* RFU */
	SC_LOG_DEBUG_SM,		/* secure messaging */
	SC_LOG_DEBUG_ASN1,		/* asn1.c */
	SC_LOG_DEBUG_MATCH,		/* card matching */
	SC_LOG_DEBUG_PIN,		/* PIN commands */
};

#define SC_COLOR_FG_RED			0x0001
#define SC_COLOR_FG_GREEN		0x0002
#define SC_COLOR_FG_YELLOW		0x0004
#define SC_COLOR_FG_BLUE		0x0008
#define SC_COLOR_FG_MAGENTA		0x0010
#define SC_COLOR_FG_CYAN   		0x0020
#define SC_COLOR_BG_RED			0x0100
#define SC_COLOR_BG_GREEN		0x0200
#define SC_COLOR_BG_YELLOW		0x0400
#define SC_COLOR_BG_BLUE		0x0800
#define SC_COLOR_BG_MAGENTA		0x1000
#define SC_COLOR_BG_CYAN		0x2000
#define SC_COLOR_BOLD			0x8080

/* You can't do #ifndef __FUNCTION__ */
#if !defined(__GNUC__) && !defined(__IBMC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1300))
#define __FUNCTION__ NULL
#endif

#if defined(__GNUC__)
#define sc_debug(ctx, level, format, args...)	sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#define sc_log(ctx, format, args...)   sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#else
#define sc_debug _sc_debug
#define sc_log _sc_log
#endif

#if defined(__GNUC__)
#if defined(__MINGW32__) && defined (__MINGW_PRINTF_FORMAT)
#define SC_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#else
#define SC_PRINTF_FORMAT printf
#endif

/* GCC can check format and param correctness for us */
void sc_do_log(struct sc_context *ctx, int level, const char *file, int line,
	       const char *func, const char *format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 6, 7)));
void sc_do_log_color(struct sc_context *ctx, int level, const char *file, int line,
	       const char *func, int color, const char *format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 7, 8)));
void sc_do_log_noframe(sc_context_t *ctx, int level, const char *format,
		       va_list args) __attribute__ ((format (SC_PRINTF_FORMAT, 3, 0)));
void _sc_debug(struct sc_context *ctx, int level, const char *format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 3, 4)));
void _sc_log(struct sc_context *ctx, const char *format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 2, 3)));
int sc_color_fprintf(int colors, struct sc_context *ctx, FILE * stream, const char * format, ...)
	__attribute__ ((format (SC_PRINTF_FORMAT, 4, 5)));
#else
void sc_do_log(struct sc_context *ctx, int level, const char *file, int line, const char *func,
		const char *format, ...);
void sc_do_log_color(struct sc_context *ctx, int level, const char *file, int line, const char *func, int color,
		const char *format, ...);
void sc_do_log_noframe(sc_context_t *ctx, int level, const char *format, va_list args);
void _sc_debug(struct sc_context *ctx, int level, const char *format, ...);
void _sc_log(struct sc_context *ctx, const char *format, ...);
int sc_color_fprintf(int colors, struct sc_context *ctx, FILE * stream, const char * format, ...);
#endif
/** 
 * @brief Log binary data to a sc context
 * 
 * @param[in] ctx   Context for logging
 * @param[in] level
 * @param[in] label Label to prepend to the buffer
 * @param[in] data  Binary data
 * @param[in] len   Length of \a data
 */
#define sc_debug_hex(ctx, level, label, data, len) \
    _sc_debug_hex(ctx, level, __FILE__, __LINE__, __FUNCTION__, label, data, len)
#define sc_log_hex(ctx, label, data, len) \
    sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, label, data, len)
/** 
 * @brief Log binary data
 *
 * @param[in] ctx   Context for logging
 * @param[in] level Debug level
 * @param[in] file  File name to be prepended
 * @param[in] line  Line to be prepended
 * @param[in] func  Function to be prepended
 * @param[in] label label to prepend to the buffer
 * @param[in] data  binary data
 * @param[in] len   length of \a data
 */
void _sc_debug_hex(struct sc_context *ctx, int level, const char *file, int line,
        const char *func, const char *label, const u8 *data, size_t len);

void sc_hex_dump(const u8 *buf, size_t len, char *out, size_t outlen);
const char * sc_dump_hex(const u8 * in, size_t count);
const char * sc_dump_oid(const struct sc_object_id *oid);
#define SC_FUNC_CALLED(ctx, level) do { \
	 sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, "called\n"); \
} while (0)
#define LOG_FUNC_CALLED(ctx) SC_FUNC_CALLED((ctx), SC_LOG_DEBUG_NORMAL)

#define SC_FUNC_RETURN(ctx, level, r) do { \
	int _ret = r; \
	if (_ret <= 0) { \
		sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, _ret ? SC_COLOR_FG_RED : 0, \
			"returning with: %d (%s)\n", _ret, sc_strerror(_ret)); \
	} else { \
		sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
			"returning with: %d\n", _ret); \
	} \
	return _ret; \
} while(0)
#define LOG_FUNC_RETURN(ctx, r) SC_FUNC_RETURN((ctx), SC_LOG_DEBUG_NORMAL, (r))

#define SC_TEST_RET(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, SC_COLOR_FG_RED, \
			"%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
		return _ret; \
	} \
} while(0)
#define LOG_TEST_RET(ctx, r, text) SC_TEST_RET((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))

#define SC_TEST_GOTO_ERR(ctx, level, r, text) do { \
	int _ret = (r); \
	if (_ret < 0) { \
		sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, SC_COLOR_FG_RED, \
			"%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
		goto err; \
	} \
} while(0)
#define LOG_TEST_GOTO_ERR(ctx, r, text) SC_TEST_GOTO_ERR((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))

#ifdef __cplusplus
}
#endif

#endif
