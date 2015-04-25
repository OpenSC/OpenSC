/*
 * compression.c: Generic wrapper for compression of data
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_ZLIB	/* empty file without zlib */
#include <zlib.h>
#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "errors.h"
#include "compression.h"

static int zerr_to_opensc(int err) {
	switch(err) {
	case Z_OK:
	case Z_STREAM_END:
		return SC_SUCCESS;
	case Z_UNKNOWN:
		return SC_ERROR_UNKNOWN;
	case Z_BUF_ERROR: /* XXX: something else than OOM ? */
	case Z_MEM_ERROR:
		return SC_ERROR_OUT_OF_MEMORY;
	case Z_VERSION_ERROR:
	case Z_DATA_ERROR:
	case Z_STREAM_ERROR:
	/* case Z_NEED_DICT: */
	default:
		return SC_ERROR_INTERNAL;
	}
}
static int detect_method(const u8* in, size_t inLen) {
	if(inLen > 2 && in[0] == 0x1f && in[1] == 0x8b) { /* GZIP */
		return COMPRESSION_GZIP;
	} else if(inLen > 1 /*&& (in[0] & 0x10) == Z_DEFLATED*/) {
		/* REALLY SIMPLE ZLIB TEST -- 
		 * Check for the compression method to be set to 8...
		 * many things can spoof this, but this is ok for now
		 * */
		return COMPRESSION_ZLIB;
	} else {
		return COMPRESSION_UNKNOWN;
	}
}

static int sc_decompress_gzip(u8* out, size_t* outLen, const u8* in, size_t inLen) {
	/* Since uncompress does not offer a way to make it uncompress gzip... manually set it up */
	z_stream gz;
	int err;
	int window_size = 15 + 0x20;
	memset(&gz, 0, sizeof(gz));

	gz.next_in = (u8*)in;
	gz.avail_in = inLen;
	gz.next_out = out;
	gz.avail_out = *outLen;

	err = inflateInit2(&gz, window_size);
	if(err != Z_OK) return zerr_to_opensc(err);
	err = inflate(&gz, Z_FINISH);
	if(err != Z_STREAM_END) {
		inflateEnd(&gz);
		return zerr_to_opensc(err);
	}
	*outLen = gz.total_out;

	err = inflateEnd(&gz);
	return zerr_to_opensc(err);	
}

int sc_decompress(u8* out, size_t* outLen, const u8* in, size_t inLen, int method) {
	unsigned long zlib_outlen;
	int rc;

	if(method == COMPRESSION_AUTO) {
		method = detect_method(in, inLen);
		if(method == COMPRESSION_UNKNOWN) {
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
	}
	switch(method) {
	case COMPRESSION_ZLIB:
		zlib_outlen = *outLen;	
		rc = zerr_to_opensc(uncompress(out, &zlib_outlen, in, inLen));
		*outLen = zlib_outlen;
		return rc;
	case COMPRESSION_GZIP:
		return sc_decompress_gzip(out, outLen, in, inLen);
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}

static int sc_decompress_zlib_alloc(u8** out, size_t* outLen, const u8* in, size_t inLen, int gzip) {
	/* Since uncompress does not offer a way to make it uncompress gzip... manually set it up */
	z_stream gz;
	int err;
	int window_size = 15;
	const int startSize = inLen < 1024 ? 2048 : inLen * 2;
	const int blockSize = inLen < 1024 ? 512 : inLen / 2;
	int bufferSize = startSize;
	if(gzip)
		window_size += 0x20;
	memset(&gz, 0, sizeof(gz));
	
	gz.next_in = (u8*)in;
	gz.avail_in = inLen;

	err = inflateInit2(&gz, window_size);
	if(err != Z_OK) return zerr_to_opensc(err);

	*outLen = 0;

	while(1) {
		/* Setup buffer... */
		int num;
		u8* buf = realloc(*out, bufferSize);
		if(!buf) {
			if(*out)
				free(*out);
			*out = NULL;
			return Z_MEM_ERROR;
		}
		*out = buf;
		gz.next_out = buf + *outLen;
		gz.avail_out = bufferSize - *outLen;

		err = inflate(&gz, Z_FULL_FLUSH);
		if(err != Z_STREAM_END && err != Z_OK) {
			if(*out)
				free(*out);
			*out = NULL;
			break;
		}
		num = bufferSize - *outLen - gz.avail_out;
		if(num > 0) {
			*outLen += num;
			bufferSize += num + blockSize;
		}
		if(err == Z_STREAM_END) {
			buf = realloc(buf, *outLen); /* Shrink it down, if it fails, just use old data */
			if(buf) {
				*out = buf;
			}
			break;
		}
	}
	inflateEnd(&gz);
	return zerr_to_opensc(err);
}
int sc_decompress_alloc(u8** out, size_t* outLen, const u8* in, size_t inLen, int method) {
	if(method == COMPRESSION_AUTO) {
		method = detect_method(in, inLen);
		if(method == COMPRESSION_UNKNOWN) {
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
	}
	switch(method) {
	case COMPRESSION_ZLIB:
		return sc_decompress_zlib_alloc(out, outLen, in, inLen, 0);
	case COMPRESSION_GZIP:
		return sc_decompress_zlib_alloc(out, outLen, in, inLen, 1);
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}
#endif /* ENABLE_ZLIB */
