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

#define SC_LOG_TYPE_ERROR	0
#define SC_LOG_TYPE_VERBOSE	1
#define SC_LOG_TYPE_DEBUG	2

#ifdef __GNUC__
#define error(ctx, format, args...)	do_log(ctx, SC_LOG_TYPE_ERROR,  __FILE__, __LINE__, __FUNCTION__ , format , ## args)
#define debug(ctx, format, args...)	do_log(ctx, SC_LOG_TYPE_DEBUG,  __FILE__, __LINE__, __FUNCTION__, format , ## args)

#else

void error(struct sc_context *ctx, const char *format, ...);
void debug(struct sc_context *ctx, const char *format, ...);

#endif

#define SC_FUNC_CALLED(ctx, level) {\
	if ((ctx)->debug >= level)\
		 debug(ctx, "called\n"); }
#define SC_FUNC_RETURN(ctx, level, r) {\
	int _ret = r;\
	if (_ret < 0) {\
		error(ctx, "returning with: %s\n", sc_strerror(_ret));\
	} else if ((ctx)->debug >= level) {\
		debug(ctx, "returning with: %d\n", _ret);\
	}\
	return _ret; }
#define SC_TEST_RET(ctx, r, text) {\
	int _ret = r;\
	if (_ret < 0) {\
		error(ctx, text": %s\n", sc_strerror(_ret));\
		return _ret;\
	}\
}

void do_log(struct sc_context *ctx, int facility, const char *file,
	    int line, const char *func, const char *format, ...);
void do_log2(struct sc_context *ctx, int facility, const char *file,
	     int line, const char *func, const char *format,
	     va_list args);

void sc_hex_dump(struct sc_context *ctx, const u8 *buf, size_t len,
		 char *out, size_t outlen);
void sc_perror(struct sc_context *ctx, int sc_errno, const char *str);

#endif
