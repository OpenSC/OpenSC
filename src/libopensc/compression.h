/*
 * compression.h: Generic wrapper for compression of data
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <thomas.harning@identityalliance.com>
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
#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "libopensc/opensc.h"
#include "libopensc/types.h"

#define COMPRESSION_AUTO	0
#define COMPRESSION_ZLIB	1
#define COMPRESSION_GZIP	2
#define COMPRESSION_UNKNOWN (-1)

int sc_decompress_alloc(u8** out, size_t* outLen, const u8* in, size_t inLen, int method);
int sc_decompress(u8* out, size_t* outLen, const u8* in, size_t inLen, int method);

#endif

