/*
 * sc-base64.c: Base64 converting functions
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

#include "opensc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

static const u8 base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	"0123456789+/=";

static const u8 bin_table[128] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xE0,0xF0,0xFF,0xFF,0xF1,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xE0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0x3E,0xFF,0xF2,0xFF,0x3F,
        0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,
        0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
        0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
        0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
        0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
        0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
};

static void to_base64(unsigned int i, u8 *out, int fillers)
{
	unsigned int c, s = 18;
	
	for (c = 0; c < 4; c++) {
		if (fillers >= 4 - c)
			*out = base64_table[64];
		else
			*out = base64_table[(i >> s) & 0x3f];
		out++;
		s -= 6;
	}
}

int sc_base64_encode(const u8 *in, int len, u8 *out, int outlen, int linelength)
{
	unsigned int i, chars = 0;
	int c;

	linelength -= linelength & 0x03;
	if (linelength < 0)
		return SC_ERROR_INVALID_ARGUMENTS;
	while (len >= 3) {
		i = in[2] + (in[1] << 8) + (in[0] << 16);
		in += 3;
		len -= 3;
		if (outlen < 4)
			return SC_ERROR_BUFFER_TOO_SMALL;
		to_base64(i, out, 0);
		out += 4;
		outlen -= 4;
		chars += 4;
		if (chars >= linelength && linelength > 0) {
			if (outlen < 1)
				return SC_ERROR_BUFFER_TOO_SMALL;
			*out = '\n';
			out++;
			outlen--;
			chars = 0;
		}
	}
	i = c = 0;
	while (c < len)
		i |= *in++ << ((2 - c++) << 3);
	if (len) {
		if (outlen < 4)
			return SC_ERROR_BUFFER_TOO_SMALL;
		to_base64(i, out, 3-len);
		out += 4;
		outlen -= 4;
		chars += 4;
	}
	if (chars && linelength > 0) {
		if (outlen < 1)
			return SC_ERROR_BUFFER_TOO_SMALL;
		*out = '\n';
		out++;
		outlen--;
	}
	if (outlen < 1)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*out = 0;

	return 0;
}
