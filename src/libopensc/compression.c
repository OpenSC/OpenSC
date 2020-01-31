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
	case Z_DATA_ERROR:
	case Z_BUF_ERROR:
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	case Z_MEM_ERROR:
		return SC_ERROR_OUT_OF_MEMORY;
	case Z_VERSION_ERROR:
	case Z_STREAM_ERROR:
	/* case Z_NEED_DICT: */
	default:
		return SC_ERROR_INTERNAL;
	}
}
static int detect_method(const u8* in, size_t inLen) {
	if (in != NULL && inLen > 1) {
		if (in[0] == 0x1f && in[1] == 0x8b)
			return COMPRESSION_GZIP;
		/*
		 * A zlib stream has the following structure:
		 *   0   1
		 * +---+---+
		 * |CMF|FLG|   (more-->)
		 * +---+---+
		 *
		 * FLG (FLaGs)
		 * 	This flag byte is divided as follows:
		 *
		 * 	bits 0 to 4  FCHECK  (check bits for CMF and FLG)
		 * 	bit  5       FDICT   (preset dictionary)
		 * 	bits 6 to 7  FLEVEL  (compression level)
		 *
		 * 	The FCHECK value must be such that CMF and FLG, when viewed as
		 * 	a 16-bit unsigned integer stored in MSB order (CMF*256 + FLG),
		 * 	is a multiple of 31.
		 */
		if ((((uint16_t) in[0])*256 + in[1]) % 31 == 0)
			return COMPRESSION_ZLIB;
	}
	return COMPRESSION_UNKNOWN;
}

static int sc_compress_gzip(u8* out, size_t* outLen, const u8* in, size_t inLen) {
	/* Since compress does not offer a way to make it compress gzip... manually set it up */
	z_stream gz;
	int err;
	int window_size = 15 + 0x10;
	memset(&gz, 0, sizeof(gz));

	gz.next_in = (u8*)in;
	gz.avail_in = inLen;
	gz.next_out = out;
	gz.avail_out = *outLen;

	err = deflateInit2(&gz, Z_BEST_COMPRESSION, Z_DEFLATED, window_size, 9, Z_DEFAULT_STRATEGY);
	if(err != Z_OK) return zerr_to_opensc(err);
	err = deflate(&gz, Z_FINISH);
	if(err != Z_STREAM_END) {
		deflateEnd(&gz);
		return zerr_to_opensc(err);
	}
	*outLen = gz.total_out;

	err = deflateEnd(&gz);
	return zerr_to_opensc(err);
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

	*outLen = 0;

	err = inflateInit2(&gz, window_size);
	if (err != Z_OK) return zerr_to_opensc(err);
	err = inflate(&gz, Z_FINISH);
	if(err != Z_STREAM_END) {
		inflateEnd(&gz);
		return zerr_to_opensc(err);
	}
	*outLen = gz.total_out;

	err = inflateEnd(&gz);
	if (*outLen == 0) {
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	return zerr_to_opensc(err);	
}

int sc_compress(u8* out, size_t* outLen, const u8* in, size_t inLen, int method) {
	unsigned long zlib_outlen;
	int rc;

	switch(method) {
	case COMPRESSION_ZLIB:
		zlib_outlen = *outLen;
		rc = zerr_to_opensc(compress(out, &zlib_outlen, in, inLen));
		*outLen = zlib_outlen;
		return rc;
	case COMPRESSION_GZIP:
		return sc_compress_gzip(out, outLen, in, inLen);
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
}

int sc_decompress(u8* out, size_t* outLen, const u8* in, size_t inLen, int method) {
	unsigned long zlib_outlen;
	int rc;

	if(method == COMPRESSION_AUTO) {
		method = detect_method(in, inLen);
		if (method == COMPRESSION_UNKNOWN) {
			*outLen = 0;
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
	const size_t startSize = inLen < 1024 ? 2048 : inLen * 2;
	const size_t blockSize = inLen < 1024 ? 512 : inLen / 2;
	size_t bufferSize = startSize;
	if (gzip)
		window_size += 0x20;
	memset(&gz, 0, sizeof(gz));

	if (!out || !outLen)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	gz.next_in = (u8*)in;
	gz.avail_in = inLen;

	err = inflateInit2(&gz, window_size);
	if (err != Z_OK)
		return zerr_to_opensc(err);

	*outLen = 0;

	while (1) {
		/* Setup buffer... */
		size_t num;
		u8* buf = realloc(*out, bufferSize);
		if (!buf) {
			free(*out);
			*out = NULL;
			return SC_ERROR_OUT_OF_MEMORY;
		}
		*out = buf;
		gz.next_out = buf + *outLen;
		gz.avail_out = bufferSize - *outLen;

		err = inflate(&gz, Z_FULL_FLUSH);
		if (err != Z_STREAM_END && err != Z_OK) {
			free(*out);
			*out = NULL;
			break;
		}
		num = *outLen + gz.avail_out;
		if (bufferSize > num) {
			*outLen += bufferSize - num;
			bufferSize += bufferSize - num + blockSize;
		}
		if (err == Z_STREAM_END) {
			if (*outLen > 0) {
				/* Shrink it down, if it fails, just use old data */
				buf = realloc(buf, *outLen);
				if (buf) {
					*out = buf;
				}
			} else {
				free(*out);
				*out = NULL;
				err = Z_DATA_ERROR;
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
