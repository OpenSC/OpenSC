/*
 * Copyright (C) 2011-2015 Frank Morgner
 *
 * This file is part of OpenSC.
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
#ifndef _SC_SSLUTIL_H
#define _SC_SSLUTIL_H

#include <libopensc/opensc.h>
#include <libopensc/log.h>

#ifdef ENABLE_OPENSSL
#include <openssl/err.h>

#define ssl_error(ctx) { \
	unsigned long _r; \
	ERR_load_crypto_strings(); \
	for (_r = ERR_get_error(); _r; _r = ERR_get_error()) { \
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "%s", ERR_error_string(_r, NULL)); \
	} \
	ERR_free_strings(); \
}
#endif

#endif
