/*
 * sc-log: Logging functions header file
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

#ifndef _SC_LOG_H
#define _SC_LOG_H

#include "opensc.h"
#include <stdarg.h>

#define SC_LOG_ERROR	0
#define SC_LOG_NORMAL	1
#define SC_LOG_VERBOSE	2
#define SC_LOG_DEBUG	3
#define SC_LOG_DEBUG2	4

#ifdef __GNUC__
#define error(ctx, format, args...)	do_log(ctx, SC_LOG_ERROR,  __FILE__, __LINE__, __FUNCTION__ , format , ## args)
#define log(ctx, format, args...)	do_log(ctx, SC_LOG_NORMAL, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#define debug(ctx, format, args...)	do_log(ctx, SC_LOG_DEBUG,  __FILE__, __LINE__, __FUNCTION__, format , ## args)
#define debug2(ctx, format, args...)	do_log(ctx, SC_LOG_DEBUG2, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#else

void error(struct sc_context *ctx, const char *format, ...);
void log(struct sc_context *ctx, const char *format, ...);
void debug(struct sc_context *ctx, const char *format, ...);
void debug2(struct sc_context *ctx, const char *format, ...);

#endif

#define SC_FUNC_CALLED(ctx) {\
	if (sc_debug > 2)\
		 debug(ctx, "called\n"); }
#define SC_FUNC_RETURN(ctx, r) {\
	int _ret = r;\
	if (sc_debug > 2) {\
		if (_ret < 0)\
			debug(ctx, "returning with: %s\n", sc_strerror(_ret));\
		else\
			debug(ctx, "returning with: %d\n", _ret);\
	}\
	return _ret; }
#define SC_TEST_RET(ctx, r, text) {\
	int _ret = r;\
	if (_ret < 0) {\
		error(ctx, text": %s\n", sc_strerror(r));\
		return _ret;\
	}\
}

void do_log(struct sc_context *ctx, int facility, const char *file,
	    int line, const char *func, const char *format, ...);
void do_log2(struct sc_context *ctx, int facility, const char *file,
	     int line, const char *func, const char *format,
	     va_list args);

void sc_hex_dump(struct sc_context *ctx, const u8 *buf, int len,
		 char *out, int outlen);

#endif
