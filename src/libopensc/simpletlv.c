/*
 * simpletlv.c: Simple TLV encoding and decoding functions
 *
 * Copyright (C) 2016  Red Hat, Inc.
 *
 * Authors: Robert Relyea <rrelyea@redhat.com>
 *          Jakub Jelen <jjelen@redhat.com>
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

#include "internal.h"
#include "simpletlv.h"

/*
 * Put a tag/length record to a file in Simple TLV based on the  datalen
 * content length.
 */
int
sc_simpletlv_put_tag(u8 tag, size_t datalen, u8 *out, size_t outlen, u8 **ptr)
{
	u8 *p = out;

	if (outlen < 2 || (outlen < 4 && datalen >= 0xff))
		return SC_ERROR_INVALID_ARGUMENTS;

	/* tag is just number between 0x01 and 0xFE */
	if (tag == 0x00 || tag == 0xff)
		return SC_ERROR_INVALID_ARGUMENTS;

	*p++ = tag; /* tag is single byte */
	if (datalen < 0xff) {
		/* short value up to 255 */
		*p++ = (u8)datalen; /* is in the second byte */
	} else if (datalen < 0xffff) {
		/* longer values up to 65535 */
		*p++ = (u8)0xff; /* first byte is 0xff */
		*p++ = (u8)datalen & 0xff;
		*p++ = (u8)(datalen >> 8) & 0xff; /* LE */
	} else {
		/* we can't store more than two bytes in Simple TLV */
		return SC_ERROR_WRONG_LENGTH;
	}
	if (ptr != NULL)
		*ptr = p;
	return SC_SUCCESS;
}

/* Read the TL file and return appropriate tag and the length of associated
 * content.
 */
int
sc_simpletlv_read_tag(u8 **buf, size_t buflen, u8 *tag_out, size_t *taglen)
{
	u8 tag;
	size_t left = buflen, len;
	u8 *p = *buf;

	*buf = NULL;

	if (left < 2) {
		return SC_ERROR_INVALID_TLV_OBJECT;
	}
	tag = *p;
	p++;
	len = *p;
	p++;
	left -= 2;

	if (len == 0xff) {
		/* don't crash on bad data */
		if (left < 2) {
			return SC_ERROR_INVALID_TLV_OBJECT;
		}
		/* skip two bytes (the size) */
		len = lebytes2ushort(p);
		p += 2;
		left -= 2;
	}

	*tag_out = tag;
	*taglen = len;
	*buf = p;

	if (len > left)
		return SC_ERROR_TLV_END_OF_CONTENTS;

	return SC_SUCCESS;
}
