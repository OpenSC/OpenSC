/*
 * asn1.c: ASN.1 decoding functions (DER)
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "asn1.h"

static int asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
		       const u8 *in, size_t len, const u8 **newp, size_t *len_left,
		       int choice, int depth);
static int asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		       u8 **ptr, size_t *size, int depth);
static int asn1_write_element(sc_context_t *ctx, unsigned int tag,
		const u8 * data, size_t datalen, u8 ** out, size_t * outlen);

static const char *tag2str(unsigned int tag)
{
	static const char *tags[] = {
		"EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING",	/* 0-4 */
		"NULL", "OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL",	/* 5-9 */
		"ENUMERATED", "<ASN1 11>", "UTF8STRING", "<ASN1 13>",	/* 10-13 */
		"<ASN1 14>", "<ASN1 15>", "SEQUENCE", "SET",	/* 15-17 */
		"NUMERICSTRING", "PRINTABLESTRING", "T61STRING",	/* 18-20 */
		"VIDEOTEXSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME",	/* 21-24 */
		"GRAPHICSTRING", "VISIBLESTRING", "GENERALSTRING",	/* 25-27 */
		"UNIVERSALSTRING", "<ASN1 29>", "BMPSTRING"	/* 28-30 */
	};

	if (tag > 30)
		return "(unknown)";
	return tags[tag];
}

int sc_asn1_read_tag(const u8 ** buf, size_t buflen, unsigned int *cla_out,
		     unsigned int *tag_out, size_t *taglen)
{
	const u8 *p = *buf;
	size_t left = buflen, len;
	unsigned int cla, tag, i;

	if (left < 2)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	*buf = NULL;
	if (*p == 0xff || *p == 0) {
		/* end of data reached */
		*taglen = 0;
		*tag_out = SC_ASN1_TAG_EOC;
		return SC_SUCCESS;
	}
	/* parse tag byte(s)
	 * Resulted tag is presented by integer that has not to be
	 * confused with the 'tag number' part of ASN.1 tag.
	 */
	cla = (*p & SC_ASN1_TAG_CLASS) | (*p & SC_ASN1_TAG_CONSTRUCTED);
	tag = *p & SC_ASN1_TAG_PRIMITIVE;
	p++;
	left--;
	if (tag == SC_ASN1_TAG_PRIMITIVE) {
		/* high tag number */
		size_t n = SC_ASN1_TAGNUM_SIZE - 1;
		/* search the last tag octet */
		while (left-- != 0 && n != 0) {
			tag <<= 8;
			tag |= *p;
			if ((*p++ & 0x80) == 0)
				break;
			n--;
		}
		if (left == 0 || n == 0)
			/* either an invalid tag or it doesn't fit in
			 * unsigned int */
			return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	/* parse length byte(s) */
	len = *p & 0x7f;
	if (*p++ & 0x80) {
		unsigned int a = 0;
		if (len > 4 || len > left)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		left -= len;
		for (i = 0; i < len; i++) {
			a <<= 8;
			a |= *p;
			p++;
		}
		len = a;
	}
	if (len > left)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	*cla_out = cla;
	*tag_out = tag;
	*taglen = len;
	*buf = p;
	return SC_SUCCESS;
}

void sc_format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg,
			  int set_present)
{
	entry->parm = parm;
	entry->arg  = arg;
	if (set_present)
		entry->flags |= SC_ASN1_PRESENT;
}

void sc_copy_asn1_entry(const struct sc_asn1_entry *src,
			struct sc_asn1_entry *dest)
{
	while (src->name != NULL) {
		*dest = *src;
		dest++;
		src++;
	}
	dest->name = NULL;
}

static void sc_asn1_print_octet_string(const u8 * buf, size_t buflen)
{
	size_t i;

	for (i = 0; i < buflen; i++)
		printf("%02X", buf[i]);
}

static void sc_asn1_print_utf8string(const u8 * buf, size_t buflen)
{
	size_t i;

	for (i = 0; i < buflen; i++)
		printf("%c", buf[i]);
}

static void sc_asn1_print_integer(const u8 * buf, size_t buflen)
{
#ifndef _WIN32
	long long a = 0;
#else
	__int64 a = 0;
#endif
	size_t i;

	if (buflen > sizeof(a)) {
		printf("too long");
		return;
	}
	for (i = 0; i < buflen; i++) {
		a <<= 8;
		a |= buf[i];
	}
	printf("%lld", a);
}

static void sc_asn1_print_boolean(const u8 * buf, size_t buflen)
{
	if (!buflen)
		return;

	if (buf[0])
		printf("true");
	else
		printf("false");
}

static void sc_asn1_print_bit_string(const u8 * buf, size_t buflen)
{
#ifndef _WIN32
	long long a = 0;
#else
	__int64 a = 0;
#endif
	int r, i;

	if (buflen > sizeof(a) + 1) {
		printf("too long");
		return;
	}
	r = sc_asn1_decode_bit_string(buf, buflen, &a, sizeof(a));
	if (r < 0) {
		printf("decode error");
		return;
	}
	for (i = r - 1; i >= 0; i--) {
		printf("%c", ((a >> i) & 1) ? '1' : '0');
	}
}

static void sc_asn1_print_object_id(const u8 * buf, size_t buflen)
{
	struct sc_object_id oid;
	int i = 0;
	char tmp[12];
	char sbuf[(sizeof tmp)*SC_MAX_OBJECT_ID_OCTETS];

	if (sc_asn1_decode_object_id(buf, buflen, &oid)) {
		printf("decode error");
		return;
	}

	sbuf[0] = 0;
	for (i = 0; (i < SC_MAX_OBJECT_ID_OCTETS) && (oid.value[i] != -1); i++)   {

		if (i)
			strcat(sbuf, ".");
		sprintf(tmp, "%d", oid.value[i]);
		strcat(sbuf, tmp);
	}
	printf("%s", sbuf);
}

static void sc_asn1_print_generalizedtime(const u8 * buf, size_t buflen)
{
	size_t ii;
	for (ii=0; ii<buflen; ii++)
		printf("%c", *(buf + ii));
}

static void print_tags_recursive(const u8 * buf0, const u8 * buf,
				 size_t buflen, int depth)
{
	int i, r;
	size_t bytesleft = buflen;
	const char *classes[4] = {
		"Univ", "Appl", "Cntx", "Priv"
	};
	const u8 *p = buf;

	while (bytesleft >= 2) {
		unsigned int cla = 0, tag = 0, hlen;
		const u8 *tagp = p;
		size_t len;

		r = sc_asn1_read_tag(&tagp, bytesleft, &cla, &tag, &len);
		if (r != SC_SUCCESS) {
			printf("Error in decoding.\n");
			return;
		}
		hlen = tagp - p;
		if (cla == 0 && tag == 0) {
			printf("Zero tag, finishing\n");
			break;
		}
		for (i = 0; i < depth; i++) {
			putchar(' ');
			putchar(' ');
		}
		printf("%02X %s: tag 0x%02X, length %3d: ",
		       cla | tag, classes[cla >> 6], tag & 0x1f, (int) len);
		if (len + hlen > bytesleft) {
			printf(" Illegal length!\n");
			return;
		}
		p += hlen + len;
		bytesleft -= hlen + len;
		if ((cla & SC_ASN1_TAG_CLASS) == SC_ASN1_TAG_UNIVERSAL)
			printf("%s", tag2str(tag));

		if (cla & SC_ASN1_TAG_CONSTRUCTED) {
			putchar('\n');
			print_tags_recursive(buf0, tagp, len, depth + 1);
			continue;
		}
		if ((cla & SC_ASN1_TAG_CLASS) == SC_ASN1_TAG_UNIVERSAL) {
			printf(" [");
			switch (tag) {
			case SC_ASN1_TAG_BIT_STRING:
				sc_asn1_print_bit_string(tagp, len);
				break;
			case SC_ASN1_TAG_OCTET_STRING:
				sc_asn1_print_octet_string(tagp, len);
				break;
			case SC_ASN1_TAG_OBJECT:
				sc_asn1_print_object_id(tagp, len);
				break;
			case SC_ASN1_TAG_INTEGER:
			case SC_ASN1_TAG_ENUMERATED:
				sc_asn1_print_integer(tagp, len);
				break;
			case SC_ASN1_TAG_T61STRING:
			case SC_ASN1_TAG_PRINTABLESTRING:
			case SC_ASN1_TAG_UTF8STRING:
				sc_asn1_print_utf8string(tagp, len);
				break;
			case SC_ASN1_TAG_BOOLEAN:
				sc_asn1_print_boolean(tagp, len);
				break;
			case SC_ASN1_GENERALIZEDTIME:
				sc_asn1_print_generalizedtime(tagp, len);
				break;
			}
			printf("]");
		}

		if ((cla & SC_ASN1_TAG_CLASS) == SC_ASN1_TAG_APPLICATION)
			printf(" <raw content> [%s]", sc_dump_hex(tagp, len));

		if ((cla & SC_ASN1_TAG_CLASS) == SC_ASN1_TAG_CONTEXT)
			printf(" <raw content> [%s]", sc_dump_hex(tagp, len));

		putchar('\n');
	}
	return;
}

void sc_asn1_print_tags(const u8 * buf, size_t buflen)
{
	printf("Printing tags for buffer of length %d\n", (int) buflen);
	print_tags_recursive(buf, buf, buflen, 0);
}

const u8 *sc_asn1_find_tag(sc_context_t *ctx, const u8 * buf,
	size_t buflen, unsigned int tag_in, size_t *taglen_in)
{
	size_t left = buflen, taglen;
	const u8 *p = buf;

	*taglen_in = 0;
	while (left >= 2) {
		unsigned int cla, tag, mask = 0xff00;

		buf = p;
		/* read a tag */
		if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) != SC_SUCCESS)
			return NULL;
		if (left < (size_t)(p - buf)) {
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "invalid TLV object\n");
			return NULL;
		}
		left -= (p - buf);
		/* we need to shift the class byte to the leftmost
		 * byte of the tag */
		while ((tag & mask) != 0) {
			cla  <<= 8;
			mask <<= 8;
		}
		/* compare the read tag with the given tag */
		if ((tag | cla) == tag_in) {
			/* we have a match => return length and value part */
			if (taglen > left)
				return NULL;
			*taglen_in = taglen;
			return p;
		}
		/* otherwise continue reading tags */
		if (left < taglen) {
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "invalid TLV object\n");
			return NULL;
		}
		left -= taglen;
		p += taglen;
	}
	return NULL;
}

const u8 *sc_asn1_skip_tag(sc_context_t *ctx, const u8 ** buf, size_t *buflen,
			   unsigned int tag_in, size_t *taglen_out)
{
	const u8 *p = *buf;
	size_t len = *buflen, taglen;
	unsigned int cla, tag;

	if (sc_asn1_read_tag((const u8 **) &p, len, &cla, &tag, &taglen) != SC_SUCCESS)
		return NULL;
	switch (cla & 0xC0) {
	case SC_ASN1_TAG_UNIVERSAL:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_UNI)
			return NULL;
		break;
	case SC_ASN1_TAG_APPLICATION:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_APP)
			return NULL;
		break;
	case SC_ASN1_TAG_CONTEXT:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_CTX)
			return NULL;
		break;
	case SC_ASN1_TAG_PRIVATE:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_PRV)
			return NULL;
		break;
	}
	if (cla & SC_ASN1_TAG_CONSTRUCTED) {
		if ((tag_in & SC_ASN1_CONS) == 0)
			return NULL;
	} else
		if (tag_in & SC_ASN1_CONS)
			return NULL;
	if ((tag_in & SC_ASN1_TAG_MASK) != tag)
		return NULL;
	len -= (p - *buf);	/* header size */
	if (taglen > len) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "too long ASN.1 object (size %d while only %d available)\n",
		      taglen, len);
		return NULL;
	}
	*buflen -= (p - *buf) + taglen;
	*buf = p + taglen;	/* point to next tag */
	*taglen_out = taglen;
	return p;
}

const u8 *sc_asn1_verify_tag(sc_context_t *ctx, const u8 * buf, size_t buflen,
			     unsigned int tag_in, size_t *taglen_out)
{
	return sc_asn1_skip_tag(ctx, &buf, &buflen, tag_in, taglen_out);
}

static int decode_bit_string(const u8 * inbuf, size_t inlen, void *outbuf,
			     size_t outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out = (u8 *) outbuf;
	int zero_bits = *in & 0x07;
	size_t octets_left = inlen - 1;
	int i, count = 0;

	memset(outbuf, 0, outlen);
	in++;
	if (outlen < octets_left)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (inlen < 1)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	while (octets_left) {
		/* 1st octet of input:  ABCDEFGH, where A is the MSB */
		/* 1st octet of output: HGFEDCBA, where A is the LSB */
		/* first bit in bit string is the LSB in first resulting octet */
		int bits_to_go;

		*out = 0;
		if (octets_left == 1)
			bits_to_go = 8 - zero_bits;
		else
			bits_to_go = 8;
		if (invert)
			for (i = 0; i < bits_to_go; i++) {
				*out |= ((*in >> (7 - i)) & 1) << i;
			}
		else {
			*out = *in;
		}
		out++;
		in++;
		octets_left--;
		count++;
	}
	return (count * 8) - zero_bits;
}

int sc_asn1_decode_bit_string(const u8 * inbuf, size_t inlen,
			      void *outbuf, size_t outlen)
{
	return decode_bit_string(inbuf, inlen, outbuf, outlen, 1);
}

int sc_asn1_decode_bit_string_ni(const u8 * inbuf, size_t inlen,
				 void *outbuf, size_t outlen)
{
	return decode_bit_string(inbuf, inlen, outbuf, outlen, 0);
}

static int encode_bit_string(const u8 * inbuf, size_t bits_left, u8 **outbuf,
			     size_t *outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out;
	size_t bytes;
	int skipped = 0;

	bytes = (bits_left + 7)/8 + 1;
	*outbuf = out = malloc(bytes);
	if (out == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	*outlen = bytes;
	out += 1;
	while (bits_left) {
		int i, bits_to_go = 8;

		*out = 0;
		if (bits_left < 8) {
			bits_to_go = bits_left;
			skipped = 8 - bits_left;
		}
		if (invert) {
			for (i = 0; i < bits_to_go; i++)
				*out |= ((*in >> i) & 1) << (7 - i);
		} else {
			*out = *in;
			if (bits_left < 8)
				return SC_ERROR_NOT_SUPPORTED; /* FIXME */
		}
		bits_left -= bits_to_go;
		out++, in++;
	}
	out = *outbuf;
	out[0] = skipped;
	return 0;
}

/*
 * Bitfields are just bit strings, stored in an unsigned int
 * (taking endianness into account)
 */
static int decode_bit_field(const u8 * inbuf, size_t inlen, void *outbuf, size_t outlen)
{
	u8		data[sizeof(unsigned int)];
	unsigned int	field = 0;
	int		i, n;

	if (outlen != sizeof(data))
		return SC_ERROR_BUFFER_TOO_SMALL;

	n = decode_bit_string(inbuf, inlen, data, sizeof(data), 1);
	if (n < 0)
		return n;

	for (i = 0; i < n; i += 8) {
		field |= (data[i/8] << i);
	}
	memcpy(outbuf, &field, outlen);
	return 0;
}

static int encode_bit_field(const u8 *inbuf, size_t inlen,
			    u8 **outbuf, size_t *outlen)
{
	u8		data[sizeof(unsigned int)];
	unsigned int	field = 0;
	size_t		i, bits;

	if (inlen != sizeof(data))
		return SC_ERROR_BUFFER_TOO_SMALL;

	/* count the bits */
	memcpy(&field, inbuf, inlen);
	for (bits = 0; field; bits++)
		field >>= 1;

	memcpy(&field, inbuf, inlen);
	for (i = 0; i < bits; i += 8)
		data[i/8] = field >> i;

	return encode_bit_string(data, bits, outbuf, outlen, 1);
}

int sc_asn1_decode_integer(const u8 * inbuf, size_t inlen, int *out)
{
	int    a = 0;
	size_t i;

	if (inlen > sizeof(int))
		return SC_ERROR_INVALID_ASN1_OBJECT;
	if (inbuf[0] & 0x80)
		a = -1;
	for (i = 0; i < inlen; i++) {
		a <<= 8;
		a |= *inbuf++;
	}
	*out = a;
	return 0;
}

static int asn1_encode_integer(int in, u8 ** obj, size_t * objsize)
{
	int i = sizeof(in) * 8, skip_zero, skip_sign;
	u8 *p, b;

	if (in < 0)
	{
		skip_sign = 1;
		skip_zero= 0;
	}
	else
	{
		skip_sign = 0;
		skip_zero= 1;
	}
	*obj = p = malloc(sizeof(in)+1);
	if (*obj == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	do {
		i -= 8;
		b = in >> i;
		if (skip_sign)
		{
			if (b != 0xff)
				skip_sign = 0;
			if (b & 0x80)
			{
				*p = b;
				if (0xff == b)
					continue;
			}
			else
			{
				p++;
				skip_sign = 0;
			}
		}
		if (b == 0 && skip_zero)
			continue;
		if (skip_zero) {
			skip_zero = 0;
			/* prepend 0x00 if MSb is 1 and integer positive */
			if ((b & 0x80) != 0 && in > 0)
				*p++ = 0;
		}
		*p++ = b;
	} while (i > 0);
	if (skip_sign)
		p++;
	*objsize = p - *obj;
	if (*objsize == 0) {
		*objsize = 1;
		(*obj)[0] = 0;
	}
	return 0;
}

int
sc_asn1_decode_object_id(const u8 *inbuf, size_t inlen, struct sc_object_id *id)
{
	int a;
	const u8 *p = inbuf;
	int *octet;

	if (inlen == 0 || inbuf == NULL || id == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_init_oid(id);
	octet = id->value;

	a = *p;
	*octet++ = a / 40;
	*octet++ = a % 40;
	inlen--;

	while (inlen) {
		p++;
		a = *p & 0x7F;
		inlen--;
		while (inlen && *p & 0x80) {
			p++;
			a <<= 7;
			a |= *p & 0x7F;
			inlen--;
		}
		*octet++ = a;
		if (octet - id->value >= SC_MAX_OBJECT_ID_OCTETS)   {
			sc_init_oid(id);
			return SC_ERROR_INVALID_ASN1_OBJECT;
		}
	};

	return 0;
}

int
sc_asn1_encode_object_id(u8 **buf, size_t *buflen, const struct sc_object_id *id)
{
	u8 temp[SC_MAX_OBJECT_ID_OCTETS*5], *p = temp;
	int	i;

	if (!buflen || !id)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* an OID must have at least two components */
	if (id->value[0] == -1 || id->value[1] == -1)
		return SC_ERROR_INVALID_ARGUMENTS;

	for (i = 0; i < SC_MAX_OBJECT_ID_OCTETS; i++) {
		unsigned int k, shift;

		if (id->value[i] == -1)
			break;

		k = id->value[i];
		switch (i) {
		case 0:
			if (k > 2)
				return SC_ERROR_INVALID_ARGUMENTS;
			*p = k * 40;
			break;
		case 1:
			if (k > 39)
				return SC_ERROR_INVALID_ARGUMENTS;
			*p++ += k;
			break;
		default:
			shift = 28;
			while (shift && (k >> shift) == 0)
				shift -= 7;
			while (shift) {
				*p++ = 0x80 | ((k >> shift) & 0x7f);
				shift -= 7;
			}
			*p++ = k & 0x7F;
			break;
		}
	}

	*buflen = p - temp;

	if (buf)   {
		*buf = malloc(*buflen);
		if (!*buf)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(*buf, temp, *buflen);
	}
	return 0;
}

static int sc_asn1_decode_utf8string(const u8 *inbuf, size_t inlen,
			      u8 *out, size_t *outlen)
{
	if (inlen+1 > *outlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*outlen = inlen+1;
	memcpy(out, inbuf, inlen);
	out[inlen] = 0;
	return 0;
}

int sc_asn1_put_tag(unsigned int tag, const u8 * data, size_t datalen, u8 * out, size_t outlen, u8 **ptr)
{
	size_t c = 0;
	size_t tag_len;
	size_t ii;
	u8 *p = out;
	u8 tag_char[4] = {0, 0, 0, 0};

	/* Check tag */
	if (tag == 0 || tag > 0xFFFFFFFF) {
		/* A tag of 0x00 is not valid and at most 4-byte tag names are supported. */
		return SC_ERROR_INVALID_DATA;
	}
	for (tag_len = 0; tag; tag >>= 8) {
		/* Note: tag char will be reversed order. */
		tag_char[tag_len++] = tag & 0xFF;
	}

	if (tag_len > 1)   {
		if ((tag_char[tag_len - 1] & SC_ASN1_TAG_PRIMITIVE) != SC_ASN1_TAG_ESCAPE_MARKER) {
			/* First byte is not escape marker. */
			return SC_ERROR_INVALID_DATA;
		}
		for (ii = 1; ii < tag_len - 1; ii++) {
			if ((tag_char[ii] & 0x80) != 0x80) {
				/* MS bit is not 'one'. */
				return SC_ERROR_INVALID_DATA;
			}
		}
		if ((tag_char[0] & 0x80) != 0x00) {
			/* MS bit of the last byte is not 'zero'. */
			return SC_ERROR_INVALID_DATA;
		}
	}

	/* Calculate the number of additional bytes necessary to encode the length. */
	/* c+1 is the size of the length field. */
	if (datalen > 127) {
		c = 1;
		while (datalen >> (c << 3))
			c++;
	}
	if (outlen == 0 || out == NULL) {
		/* Caller only asks for the length that would be written. */
		return tag_len + (c+1) + datalen;
	}
	/* We will write the tag, so check the length. */
	if (outlen < tag_len + (c+1) + datalen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	for (ii=0;ii<tag_len;ii++)
		*p++ = tag_char[tag_len - ii - 1];

	if (c > 0) {
		*p++ = 0x80 | c;
		while (c--)
			*p++ = (datalen >> (c << 3)) & 0xFF;
	}
	else {
		*p++ = datalen & 0x7F;
	}
	if(data && datalen > 0) {
		memcpy(p, data, datalen);
		p += datalen;
	}
	if (ptr != NULL)
		*ptr = p;
	return 0;
}

int sc_asn1_write_element(sc_context_t *ctx, unsigned int tag,
	const u8 * data, size_t datalen, u8 ** out, size_t * outlen)
{
	return asn1_write_element(ctx, tag, data, datalen, out, outlen);
}

static int asn1_write_element(sc_context_t *ctx, unsigned int tag,
	const u8 * data, size_t datalen, u8 ** out, size_t * outlen)
{
	unsigned char t;
	unsigned char *buf, *p;
	int c = 0;
	unsigned short_tag;
	unsigned char tag_char[3] = {0, 0, 0};
	size_t tag_len, ii;

	short_tag = tag & SC_ASN1_TAG_MASK;
	for (tag_len = 0; short_tag >> (8 * tag_len); tag_len++)
		tag_char[tag_len] = (short_tag >> (8 * tag_len)) & 0xFF;
	if (!tag_len)
		tag_len = 1;

	if (tag_len > 1)   {
		if ((tag_char[tag_len - 1] & SC_ASN1_TAG_PRIMITIVE) != SC_ASN1_TAG_ESCAPE_MARKER)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "First byte of the long tag is not 'escape marker'");

		for (ii = 1; ii < tag_len - 1; ii++)
			if (!(tag_char[ii] & 0x80))
				SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "MS bit expected to be 'one'");

		if (tag_char[0] & 0x80)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_INVALID_DATA, "MS bit of the last byte expected to be 'zero'");
	}

	t = tag_char[tag_len - 1] & 0x1F;

	switch (tag & SC_ASN1_CLASS_MASK) {
	case SC_ASN1_UNI:
		break;
	case SC_ASN1_APP:
		t |= SC_ASN1_TAG_APPLICATION;
		break;
	case SC_ASN1_CTX:
		t |= SC_ASN1_TAG_CONTEXT;
		break;
	case SC_ASN1_PRV:
		t |= SC_ASN1_TAG_PRIVATE;
		break;
	}
	if (tag & SC_ASN1_CONS)
		t |= SC_ASN1_TAG_CONSTRUCTED;
	if (datalen > 127) {
		c = 1;
		while (datalen >> (c << 3))
			c++;
	}

	*outlen = tag_len + 1 + c + datalen;
	buf = malloc(*outlen);
	if (buf == NULL)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_OUT_OF_MEMORY);

	*out = p = buf;
	*p++ = t;
	for (ii=1;ii<tag_len;ii++)
		*p++ = tag_char[tag_len - ii - 1];

	if (c) {
		*p++ = 0x80 | c;
		while (c--)
			*p++ = (datalen >> (c << 3)) & 0xFF;
	}
	else   {
		*p++ = datalen & 0x7F;
	}
	memcpy(p, data, datalen);

	return SC_SUCCESS;
}

static const struct sc_asn1_entry c_asn1_path_ext[3] = {
	{ "aid",  SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x0F, 0, NULL, NULL },
	{ "path", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_path[5] = {
	{ "path",   SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "index",  SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "length", SC_ASN1_INTEGER, SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
/* For some multi-applications PKCS#15 card the ODF records can hold the references to
 * the xDF files and objects placed elsewhere then under the application DF of the ODF itself.
 * In such a case the 'path' ASN1 data includes also the ID of the target application (AID).
 * This path extension do not make a part of PKCS#15 standard.
 */
	{ "pathExtended", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_decode_path(sc_context_t *ctx, const u8 *in, size_t len,
			    sc_path_t *path, int depth)
{
	int idx, count, r;
	struct sc_asn1_entry asn1_path_ext[3], asn1_path[5];
	unsigned char path_value[SC_MAX_PATH_SIZE], aid_value[SC_MAX_AID_SIZE];
	size_t path_len = sizeof(path_value), aid_len = sizeof(aid_value);

	memset(path, 0, sizeof(struct sc_path));

	sc_copy_asn1_entry(c_asn1_path_ext, asn1_path_ext);
	sc_copy_asn1_entry(c_asn1_path, asn1_path);

	sc_format_asn1_entry(asn1_path_ext + 0, aid_value, &aid_len, 0);
	sc_format_asn1_entry(asn1_path_ext + 1, path_value, &path_len, 0);

	sc_format_asn1_entry(asn1_path + 0, path_value, &path_len, 0);
	sc_format_asn1_entry(asn1_path + 1, &idx, NULL, 0);
	sc_format_asn1_entry(asn1_path + 2, &count, NULL, 0);
	sc_format_asn1_entry(asn1_path + 3, asn1_path_ext, NULL, 0);

	r = asn1_decode(ctx, asn1_path, in, len, NULL, NULL, 0, depth + 1);
	if (r)
		return r;

	if (asn1_path[3].flags & SC_ASN1_PRESENT)   {
		/* extended path present: set 'path' and 'aid' */
		memcpy(path->aid.value, aid_value, aid_len);
		path->aid.len = aid_len;

		memcpy(path->value, path_value, path_len);
		path->len = path_len;
	}
	else if (asn1_path[0].flags & SC_ASN1_PRESENT)   {
		/* path present: set 'path' */
		memcpy(path->value, path_value, path_len);
		path->len = path_len;
	}
	else   {
		/* failed if both 'path' and 'pathExtended' are absent */
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;
	}

	if (path->len == 2)
		path->type = SC_PATH_TYPE_FILE_ID;
	else   if (path->aid.len && path->len > 2)
		path->type = SC_PATH_TYPE_FROM_CURRENT;
	else
		path->type = SC_PATH_TYPE_PATH;

	if ((asn1_path[1].flags & SC_ASN1_PRESENT) && (asn1_path[2].flags & SC_ASN1_PRESENT)) {
		path->index = idx;
		path->count = count;
	}
	else {
		path->index = 0;
		path->count = -1;
	}

	return SC_SUCCESS;
}

static int asn1_encode_path(sc_context_t *ctx, const sc_path_t *path,
			    u8 **buf, size_t *bufsize, int depth, unsigned int parent_flags)
{
	int r;
 	struct sc_asn1_entry asn1_path[5];
	sc_path_t tpath = *path;

	sc_copy_asn1_entry(c_asn1_path, asn1_path);
	sc_format_asn1_entry(asn1_path + 0, (void *) &tpath.value, (void *) &tpath.len, 1);

	asn1_path[0].flags |= parent_flags;
	if (path->count > 0) {
		sc_format_asn1_entry(asn1_path + 1, (void *) &tpath.index, NULL, 1);
		sc_format_asn1_entry(asn1_path + 2, (void *) &tpath.count, NULL, 1);
	}
	r = asn1_encode(ctx, asn1_path, buf, bufsize, depth + 1);
	return r;
}


static const struct sc_asn1_entry c_asn1_se[2] = {
	{ "seInfo", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_se_info[4] = {
	{ "se",   SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "owner",SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "aid",  SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_decode_se_info(sc_context_t *ctx, const u8 *obj, size_t objlen,
			       sc_pkcs15_sec_env_info_t ***se, size_t *num, int depth)
{
	struct sc_pkcs15_sec_env_info **ses;
	const unsigned char *ptr = obj;
	size_t idx, ptrlen = objlen;
	int ret;

	ses = calloc(SC_MAX_SE_NUM, sizeof(sc_pkcs15_sec_env_info_t *));
	if (ses == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	for (idx=0; idx < SC_MAX_SE_NUM && ptrlen; )   {
		struct sc_asn1_entry asn1_se[2];
		struct sc_asn1_entry asn1_se_info[4];
		struct sc_pkcs15_sec_env_info si;

		sc_copy_asn1_entry(c_asn1_se, asn1_se);
		sc_copy_asn1_entry(c_asn1_se_info, asn1_se_info);

		si.aid.len = sizeof(si.aid.value);
		sc_format_asn1_entry(asn1_se_info + 0, &si.se, NULL, 0);
		sc_format_asn1_entry(asn1_se_info + 1, &si.owner, NULL, 0);
		sc_format_asn1_entry(asn1_se_info + 2, &si.aid.value, &si.aid.len, 0);
		sc_format_asn1_entry(asn1_se + 0, asn1_se_info, NULL, 0);

		ret = asn1_decode(ctx, asn1_se, ptr, ptrlen, &ptr, &ptrlen, 0, depth+1);
		if (ret != SC_SUCCESS)
			goto err;
		if (!(asn1_se_info[1].flags & SC_ASN1_PRESENT))
			sc_init_oid(&si.owner);

		ses[idx] = calloc(1, sizeof(sc_pkcs15_sec_env_info_t));
		if (ses[idx] == NULL) {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(ses[idx], &si, sizeof(struct sc_pkcs15_sec_env_info));
		idx++;
	}

	*se  = ses;
	*num = idx;
	ret = SC_SUCCESS;
err:
	if (ret != SC_SUCCESS) {
		size_t i;
		for (i = 0; i < idx; i++)
			if (ses[i])
				free(ses[i]);
		free(ses);
	}

	return ret;
}


static int asn1_encode_se_info(sc_context_t *ctx,
		struct sc_pkcs15_sec_env_info **se, size_t se_num,
		unsigned char **buf, size_t *bufsize, int depth)
{
	unsigned char *ptr = NULL, *out = NULL, *p;
	size_t ptrlen = 0, outlen = 0, idx;
	int ret;

	for (idx=0; idx < se_num; idx++)   {
		struct sc_asn1_entry asn1_se[2];
		struct sc_asn1_entry asn1_se_info[4];

		sc_copy_asn1_entry(c_asn1_se, asn1_se);
		sc_copy_asn1_entry(c_asn1_se_info, asn1_se_info);

		sc_format_asn1_entry(asn1_se_info + 0, &se[idx]->se, NULL, 1);
		if (sc_valid_oid(&se[idx]->owner))
			sc_format_asn1_entry(asn1_se_info + 1, &se[idx]->owner, NULL, 1);
		if (se[idx]->aid.len)
			sc_format_asn1_entry(asn1_se_info + 2, &se[idx]->aid.value, &se[idx]->aid.len, 1);
		sc_format_asn1_entry(asn1_se + 0, asn1_se_info, NULL, 1);

		ret = sc_asn1_encode(ctx, asn1_se, &ptr, &ptrlen);
		if (ret != SC_SUCCESS)
			goto err;

		p = (unsigned char *) realloc(out, outlen + ptrlen);
		if (!p)   {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		out = p;
		memcpy(out + outlen, ptr, ptrlen);
		outlen += ptrlen;
		free(ptr);
		ptr = NULL;
		ptrlen = 0;
	}

	*buf = out;
	*bufsize = outlen;
	ret = SC_SUCCESS;
err:
	if (ret != SC_SUCCESS && out != NULL)
		free(out);
	return ret;
}

/* TODO: According to specification type of 'SecurityCondition' is 'CHOICE'.
 *       Do it at least for SC_ASN1_PKCS15_ID(authId), SC_ASN1_STRUCT(authReference) and NULL(always). */
static const struct sc_asn1_entry c_asn1_access_control_rule[3] = {
	{ "accessMode", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "securityCondition", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

/*
 * in src/libopensc/pkcs15.h SC_PKCS15_MAX_ACCESS_RULES  defined as 8
 */
static const struct sc_asn1_entry c_asn1_access_control_rules[SC_PKCS15_MAX_ACCESS_RULES + 1] = {
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRule", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_com_obj_attr[6] = {
	{ "label", SC_ASN1_UTF8STRING, SC_ASN1_TAG_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "flags", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "authId", SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "userConsent", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRules", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_p15_obj[5] = {
	{ "commonObjectAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "classAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "subClassAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "typeAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_decode_p15_object(sc_context_t *ctx, const u8 *in,
				  size_t len, struct sc_asn1_pkcs15_object *obj,
				  int depth)
{
	struct sc_pkcs15_object *p15_obj = obj->p15_obj;
	struct sc_asn1_entry asn1_c_attr[6], asn1_p15_obj[5];
	struct sc_asn1_entry asn1_ac_rules[SC_PKCS15_MAX_ACCESS_RULES + 1], asn1_ac_rule[SC_PKCS15_MAX_ACCESS_RULES][3];
	size_t flags_len = sizeof(p15_obj->flags);
	size_t label_len = sizeof(p15_obj->label);
	size_t access_mode_len = sizeof(p15_obj->access_rules[0].access_mode);
	int r, ii;

	for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)
		sc_copy_asn1_entry(c_asn1_access_control_rule, asn1_ac_rule[ii]);
	sc_copy_asn1_entry(c_asn1_access_control_rules, asn1_ac_rules);


	sc_copy_asn1_entry(c_asn1_com_obj_attr, asn1_c_attr);
	sc_copy_asn1_entry(c_asn1_p15_obj, asn1_p15_obj);
	sc_format_asn1_entry(asn1_c_attr + 0, p15_obj->label, &label_len, 0);
	sc_format_asn1_entry(asn1_c_attr + 1, &p15_obj->flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_c_attr + 2, &p15_obj->auth_id, NULL, 0);
	sc_format_asn1_entry(asn1_c_attr + 3, &p15_obj->user_consent, NULL, 0);

	for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)   {
		sc_format_asn1_entry(asn1_ac_rule[ii] + 0, &p15_obj->access_rules[ii].access_mode, &access_mode_len, 0);
		sc_format_asn1_entry(asn1_ac_rule[ii] + 1, &p15_obj->access_rules[ii].auth_id, NULL, 0);
		sc_format_asn1_entry(asn1_ac_rules + ii, asn1_ac_rule[ii], NULL, 0);
	}
	sc_format_asn1_entry(asn1_c_attr + 4, asn1_ac_rules, NULL, 0);

	sc_format_asn1_entry(asn1_p15_obj + 0, asn1_c_attr, NULL, 0);
	sc_format_asn1_entry(asn1_p15_obj + 1, obj->asn1_class_attr, NULL, 0);
	sc_format_asn1_entry(asn1_p15_obj + 2, obj->asn1_subclass_attr, NULL, 0);
	sc_format_asn1_entry(asn1_p15_obj + 3, obj->asn1_type_attr, NULL, 0);

	r = asn1_decode(ctx, asn1_p15_obj, in, len, NULL, NULL, 0, depth + 1);
	return r;
}

static int asn1_encode_p15_object(sc_context_t *ctx, const struct sc_asn1_pkcs15_object *obj,
				  u8 **buf, size_t *bufsize, int depth)
{
	struct sc_pkcs15_object p15_obj = *obj->p15_obj;
	struct sc_asn1_entry    asn1_c_attr[6], asn1_p15_obj[5];
	struct sc_asn1_entry asn1_ac_rules[SC_PKCS15_MAX_ACCESS_RULES + 1], asn1_ac_rule[SC_PKCS15_MAX_ACCESS_RULES][3];
	size_t label_len = strlen(p15_obj.label);
	size_t flags_len;
	size_t access_mode_len;
	int r, ii;

	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "encode p15 obj(type:0x%X,access_mode:0x%X)", p15_obj.type, p15_obj.access_rules[0].access_mode);
	if (p15_obj.access_rules[0].access_mode)   {
		for (ii=0; ii<SC_PKCS15_MAX_ACCESS_RULES; ii++)   {
			sc_copy_asn1_entry(c_asn1_access_control_rule, asn1_ac_rule[ii]);
			if (p15_obj.access_rules[ii].auth_id.len == 0)   {
				asn1_ac_rule[ii][1].type = SC_ASN1_NULL;
				asn1_ac_rule[ii][1].tag = SC_ASN1_TAG_NULL;
			}
		}
		sc_copy_asn1_entry(c_asn1_access_control_rules, asn1_ac_rules);
	}

	sc_copy_asn1_entry(c_asn1_com_obj_attr, asn1_c_attr);
	sc_copy_asn1_entry(c_asn1_p15_obj, asn1_p15_obj);
	if (label_len != 0)
		sc_format_asn1_entry(asn1_c_attr + 0, (void *) p15_obj.label, &label_len, 1);
	if (p15_obj.flags) {
		flags_len = sizeof(p15_obj.flags);
		sc_format_asn1_entry(asn1_c_attr + 1, (void *) &p15_obj.flags, &flags_len, 1);
	}
	if (p15_obj.auth_id.len)
		sc_format_asn1_entry(asn1_c_attr + 2, (void *) &p15_obj.auth_id, NULL, 1);
	if (p15_obj.user_consent)
		sc_format_asn1_entry(asn1_c_attr + 3, (void *) &p15_obj.user_consent, NULL, 1);

	if (p15_obj.access_rules[0].access_mode)   {
		for (ii=0; p15_obj.access_rules[ii].access_mode; ii++)   {
			access_mode_len = sizeof(p15_obj.access_rules[ii].access_mode);
			sc_format_asn1_entry(asn1_ac_rule[ii] + 0, (void *) &p15_obj.access_rules[ii].access_mode, &access_mode_len, 1);
			sc_format_asn1_entry(asn1_ac_rule[ii] + 1, (void *) &p15_obj.access_rules[ii].auth_id, NULL, 1);
			sc_format_asn1_entry(asn1_ac_rules + ii, asn1_ac_rule[ii], NULL, 1);
		}
		sc_format_asn1_entry(asn1_c_attr + 4, asn1_ac_rules, NULL, 1);
	}

	sc_format_asn1_entry(asn1_p15_obj + 0, asn1_c_attr, NULL, 1);
	sc_format_asn1_entry(asn1_p15_obj + 1, obj->asn1_class_attr, NULL, 1);
	if (obj->asn1_subclass_attr != NULL && obj->asn1_subclass_attr->name)
		sc_format_asn1_entry(asn1_p15_obj + 2, obj->asn1_subclass_attr, NULL, 1);
	sc_format_asn1_entry(asn1_p15_obj + 3, obj->asn1_type_attr, NULL, 1);

	r = asn1_encode(ctx, asn1_p15_obj, buf, bufsize, depth + 1);
	return r;
}

static int asn1_decode_entry(sc_context_t *ctx,struct sc_asn1_entry *entry,
			     const u8 *obj, size_t objlen, int depth)
{
	void *parm = entry->parm;
	int (*callback_func)(sc_context_t *nctx, void *arg, const u8 *nobj,
			     size_t nobjlen, int ndepth);
	size_t *len = (size_t *) entry->arg;
	int r = 0;

	callback_func = parm;

	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*sdecoding '%s'\n", depth, depth, "", entry->name);

	switch (entry->type) {
	case SC_ASN1_STRUCT:
		if (parm != NULL)
			r = asn1_decode(ctx, (struct sc_asn1_entry *) parm, obj,
				       objlen, NULL, NULL, 0, depth + 1);
		break;
	case SC_ASN1_NULL:
		break;
	case SC_ASN1_BOOLEAN:
		if (parm != NULL) {
			if (objlen != 1) {
				sc_debug(ctx, SC_LOG_DEBUG_ASN1, "invalid ASN.1 object length: %d\n", objlen);
				r = SC_ERROR_INVALID_ASN1_OBJECT;
			} else
				*((int *) parm) = obj[0] ? 1 : 0;
		}
		break;
	case SC_ASN1_INTEGER:
	case SC_ASN1_ENUMERATED:
		if (parm != NULL) {
			r = sc_asn1_decode_integer(obj, objlen, (int *) entry->parm);
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*sdecoding '%s' returned %d\n", depth, depth, "",
					entry->name, *((int *) entry->parm));
		}
		break;
	case SC_ASN1_BIT_STRING_NI:
	case SC_ASN1_BIT_STRING:
		if (parm != NULL) {
			int invert = entry->type == SC_ASN1_BIT_STRING ? 1 : 0;
			assert(len != NULL);
			if (objlen < 1) {
				r = SC_ERROR_INVALID_ASN1_OBJECT;
				break;
			}
			if (entry->flags & SC_ASN1_ALLOC) {
				u8 **buf = (u8 **) parm;
				*buf = malloc(objlen-1);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				*len = objlen-1;
				parm = *buf;
			}
			r = decode_bit_string(obj, objlen, (u8 *) parm, *len, invert);
			if (r >= 0) {
				*len = r;
				r = 0;
			}
		}
		break;
	case SC_ASN1_BIT_FIELD:
		if (parm != NULL)
			r = decode_bit_field(obj, objlen, (u8 *) parm, *len);
		break;
	case SC_ASN1_OCTET_STRING:
		if (parm != NULL) {
			size_t c;
			assert(len != NULL);

			/* Strip off padding zero */
			if ((entry->flags & SC_ASN1_UNSIGNED)
			 && obj[0] == 0x00 && objlen > 1) {
				objlen--;
				obj++;
			}

			/* Allocate buffer if needed */
			if (entry->flags & SC_ASN1_ALLOC) {
				u8 **buf = (u8 **) parm;
				*buf = malloc(objlen);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				c = *len = objlen;
				parm = *buf;
			} else
				c = objlen > *len ? *len : objlen;

			memcpy(parm, obj, c);
			*len = c;
		}
		break;
	case SC_ASN1_GENERALIZEDTIME:
		if (parm != NULL) {
			size_t c;
			assert(len != NULL);
			if (entry->flags & SC_ASN1_ALLOC) {
				u8 **buf = (u8 **) parm;
				*buf = malloc(objlen);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				c = *len = objlen;
				parm = *buf;
			} else
				c = objlen > *len ? *len : objlen;

			memcpy(parm, obj, c);
			*len = c;
		}
		break;
	case SC_ASN1_OBJECT:
		if (parm != NULL)
			r = sc_asn1_decode_object_id(obj, objlen, (struct sc_object_id *) parm);
		break;
	case SC_ASN1_PRINTABLESTRING:
	case SC_ASN1_UTF8STRING:
		if (parm != NULL) {
			assert(len != NULL);
			if (entry->flags & SC_ASN1_ALLOC) {
				u8 **buf = (u8 **) parm;
				*buf = malloc(objlen+1);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				*len = objlen+1;
				parm = *buf;
			}
			r = sc_asn1_decode_utf8string(obj, objlen, (u8 *) parm, len);
			if (entry->flags & SC_ASN1_ALLOC) {
				*len -= 1;
			}
		}
		break;
	case SC_ASN1_PATH:
		if (entry->parm != NULL)
			r = asn1_decode_path(ctx, obj, objlen, (sc_path_t *) parm, depth);
		break;
	case SC_ASN1_PKCS15_ID:
		if (entry->parm != NULL) {
			struct sc_pkcs15_id *id = (struct sc_pkcs15_id *) parm;
			size_t c = objlen > sizeof(id->value) ? sizeof(id->value) : objlen;

			memcpy(id->value, obj, c);
			id->len = c;
		}
		break;
	case SC_ASN1_PKCS15_OBJECT:
		if (entry->parm != NULL)
			r = asn1_decode_p15_object(ctx, obj, objlen, (struct sc_asn1_pkcs15_object *) parm, depth);
		break;
	case SC_ASN1_ALGORITHM_ID:
		if (entry->parm != NULL)
			r = sc_asn1_decode_algorithm_id(ctx, obj, objlen, (struct sc_algorithm_id *) parm, depth);
		break;
	case SC_ASN1_SE_INFO:
		if (entry->parm != NULL)
			r = asn1_decode_se_info(ctx, obj, objlen, (sc_pkcs15_sec_env_info_t ***)entry->parm, len, depth);
		break;
	case SC_ASN1_CALLBACK:
		if (entry->parm != NULL)
			r = callback_func(ctx, entry->arg, obj, objlen, depth);
		break;
	default:
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "invalid ASN.1 type: %d\n", entry->type);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (r) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "decoding of ASN.1 object '%s' failed: %s\n", entry->name,
		      sc_strerror(r));
		return r;
	}
	entry->flags |= SC_ASN1_PRESENT;
	return 0;
}

static int asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
		       const u8 *in, size_t len, const u8 **newp, size_t *len_left,
		       int choice, int depth)
{
	int r, idx = 0;
	const u8 *p = in, *obj;
	struct sc_asn1_entry *entry = asn1;
	size_t left = len, objlen;

	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*scalled, left=%u, depth %d%s\n",
			       	depth, depth, "",
				left, depth,
				choice ? ", choice" : "");

	if (!p)
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;
	if (left < 2) {
		while (asn1->name && (asn1->flags & SC_ASN1_OPTIONAL))
			asn1++;
		/* If all elements were optional, there's nothing
		 * to complain about */
		if (asn1->name == NULL)
			return 0;
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "End of ASN.1 stream, "
			      "non-optional field \"%s\" not found\n",
			      asn1->name);
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;
	}
	if (p[0] == 0 || p[0] == 0xFF || len == 0)
		return SC_ERROR_ASN1_END_OF_CONTENTS;

	for (idx = 0; asn1[idx].name != NULL; idx++) {
		entry = &asn1[idx];

		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "Looking for '%s', tag 0x%x%s%s\n",
			entry->name, entry->tag, choice? ", CHOICE" : "",
			(entry->flags & SC_ASN1_OPTIONAL)? ", OPTIONAL": "");

		/* Special case CHOICE has no tag */
		if (entry->type == SC_ASN1_CHOICE) {
			r = asn1_decode(ctx,
				(struct sc_asn1_entry *) entry->parm,
				p, left, &p, &left, 1, depth + 1);
			if (r >= 0)
				r = 0;
			goto decode_ok;
		}

		obj = sc_asn1_skip_tag(ctx, &p, &left, entry->tag, &objlen);
		if (obj == NULL) {
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "not present\n");
			if (choice)
				continue;
			if (entry->flags & SC_ASN1_OPTIONAL)
				continue;
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "mandatory ASN.1 object '%s' not found\n", entry->name);
			if (left) {
				u8 line[128], *linep = line;
				size_t i;

				line[0] = 0;
				for (i = 0; i < 10 && i < left; i++) {
					sprintf((char *) linep, "%02X ", p[i]);
					linep += 3;
				}
				sc_debug(ctx, SC_LOG_DEBUG_ASN1, "next tag: %s\n", line);
			}
			SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
		}
		r = asn1_decode_entry(ctx, entry, obj, objlen, depth);

decode_ok:
		if (r)
			return r;
		if (choice)
			break;
 	}
 	if (choice && asn1[idx].name == NULL) /* No match */
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
 	if (newp != NULL)
		*newp = p;
 	if (len_left != NULL)
		*len_left = left;
	if (choice)
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, idx);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_ASN1, 0);
}

int sc_asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
		   const u8 *in, size_t len, const u8 **newp, size_t *len_left)
{
	return asn1_decode(ctx, asn1, in, len, newp, len_left, 0, 0);
}

int sc_asn1_decode_choice(sc_context_t *ctx, struct sc_asn1_entry *asn1,
			  const u8 *in, size_t len, const u8 **newp, size_t *len_left)
{
	return asn1_decode(ctx, asn1, in, len, newp, len_left, 1, 0);
}

static int asn1_encode_entry(sc_context_t *ctx, const struct sc_asn1_entry *entry,
			     u8 **obj, size_t *objlen, int depth)
{
	void *parm = entry->parm;
	int (*callback_func)(sc_context_t *nctx, void *arg, u8 **nobj,
			     size_t *nobjlen, int ndepth);
	const size_t *len = (const size_t *) entry->arg;
	int r = 0;
	u8 * buf = NULL;
	size_t buflen = 0;

	callback_func = parm;

	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*sencoding '%s'%s\n",
	       	depth, depth, "", entry->name,
		(entry->flags & SC_ASN1_PRESENT)? "" : " (not present)");
	if (!(entry->flags & SC_ASN1_PRESENT))
		goto no_object;
	sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*stype=%d, tag=0x%02x, parm=%p, len=%u\n",
		depth, depth, "",
		entry->type, entry->tag, parm, len? *len : 0);

	if (entry->type == SC_ASN1_CHOICE) {
		const struct sc_asn1_entry *list, *choice = NULL;

		list = (const struct sc_asn1_entry *) parm;
		while (list->name != NULL) {
			if (list->flags & SC_ASN1_PRESENT) {
				if (choice) {
					sc_debug(ctx, SC_LOG_DEBUG_ASN1,
						"ASN.1 problem: more than "
						"one CHOICE when encoding %s: "
						"%s and %s both present\n",
						entry->name,
						choice->name,
						list->name);
					return SC_ERROR_INVALID_ASN1_OBJECT;
				}
				choice = list;
			}
			list++;
		}
		if (choice == NULL)
			goto no_object;
		return asn1_encode_entry(ctx, choice, obj, objlen, depth + 1);
	}

	if (entry->type != SC_ASN1_NULL && parm == NULL) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "unexpected parm == NULL\n");
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	switch (entry->type) {
	case SC_ASN1_STRUCT:
		r = asn1_encode(ctx, (const struct sc_asn1_entry *) parm, &buf,
				&buflen, depth + 1);
		break;
	case SC_ASN1_NULL:
		buf = NULL;
		buflen = 0;
		break;
	case SC_ASN1_BOOLEAN:
		buf = malloc(1);
		if (buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		buf[0] = *((int *) parm) ? 0xFF : 0;
		buflen = 1;
		break;
	case SC_ASN1_INTEGER:
	case SC_ASN1_ENUMERATED:
		r = asn1_encode_integer(*((int *) entry->parm), &buf, &buflen);
		break;
	case SC_ASN1_BIT_STRING_NI:
	case SC_ASN1_BIT_STRING:
		assert(len != NULL);
		if (entry->type == SC_ASN1_BIT_STRING)
			r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 1);
		else
			r = encode_bit_string((const u8 *) parm, *len, &buf, &buflen, 0);
		break;
	case SC_ASN1_BIT_FIELD:
		assert(len != NULL);
		r = encode_bit_field((const u8 *) parm, *len, &buf, &buflen);
		break;
	case SC_ASN1_PRINTABLESTRING:
	case SC_ASN1_OCTET_STRING:
	case SC_ASN1_UTF8STRING:
		assert(len != NULL);
		buf = malloc(*len + 1);
		if (buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		buflen = 0;
		/* If the integer is supposed to be unsigned, insert
		 * a padding byte if the MSB is one */
		if ((entry->flags & SC_ASN1_UNSIGNED)
		 && (((u8 *) parm)[0] & 0x80)) {
			buf[buflen++] = 0x00;
		}
		memcpy(buf + buflen, parm, *len);
		buflen += *len;
		break;
	case SC_ASN1_GENERALIZEDTIME:
		assert(len != NULL);
		buf = malloc(*len);
		if (buf == NULL) {
			r = SC_ERROR_OUT_OF_MEMORY;
			break;
		}
		memcpy(buf, parm, *len);
		buflen = *len;
		break;
	case SC_ASN1_OBJECT:
		r = sc_asn1_encode_object_id(&buf, &buflen, (struct sc_object_id *) parm);
		break;
	case SC_ASN1_PATH:
		r = asn1_encode_path(ctx, (const sc_path_t *) parm, &buf, &buflen, depth, entry->flags);
		break;
	case SC_ASN1_PKCS15_ID:
		{
			const struct sc_pkcs15_id *id = (const struct sc_pkcs15_id *) parm;

			buf = malloc(id->len);
			if (buf == NULL) {
				r = SC_ERROR_OUT_OF_MEMORY;
				break;
			}
			memcpy(buf, id->value, id->len);
			buflen = id->len;
		}
		break;
	case SC_ASN1_PKCS15_OBJECT:
		r = asn1_encode_p15_object(ctx, (const struct sc_asn1_pkcs15_object *) parm, &buf, &buflen, depth);
		break;
	case SC_ASN1_ALGORITHM_ID:
		r = sc_asn1_encode_algorithm_id(ctx, &buf, &buflen, (const struct sc_algorithm_id *) parm, depth);
		break;
	case SC_ASN1_SE_INFO:
		if (!len)
			return SC_ERROR_INVALID_ASN1_OBJECT;
		r = asn1_encode_se_info(ctx, (struct sc_pkcs15_sec_env_info **)parm, *len, &buf, &buflen, depth);
		break;
	case SC_ASN1_CALLBACK:
		r = callback_func(ctx, entry->arg, &buf, &buflen, depth);
		break;
	default:
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "invalid ASN.1 type: %d\n", entry->type);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (r) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "encoding of ASN.1 object '%s' failed: %s\n", entry->name,
		      sc_strerror(r));
		if (buf)
			free(buf);
		return r;
	}

	/* Treatment of OPTIONAL elements:
	 *  -	if the encoding has 0 length, and the element is OPTIONAL,
	 *	we don't write anything (unless it's an ASN1 NULL and the
	 *      SC_ASN1_PRESENT flag is set).
	 *  -	if the encoding has 0 length, but the element is non-OPTIONAL,
	 *	constructed, we write a empty element (e.g. a SEQUENCE of
	 *      length 0). In case of an ASN1 NULL just write the tag and
	 *      length (i.e. 0x05,0x00).
	 *  -	any other empty objects are considered bogus
	 */
no_object:
	if (!buflen && entry->flags & SC_ASN1_OPTIONAL && !(entry->flags & SC_ASN1_PRESENT)) {
		/* This happens when we try to encode e.g. the
		 * subClassAttributes, which may be empty */
		*obj = NULL;
		*objlen = 0;
		r = 0;
	} else if (!buflen && (entry->flags & SC_ASN1_EMPTY_ALLOWED)) {
		*obj = NULL;
		*objlen = 0;
		r = asn1_write_element(ctx, entry->tag, buf, buflen, obj, objlen);
		if (r)
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "error writing ASN.1 tag and length: %s\n", sc_strerror(r));
	} else if (buflen || entry->type == SC_ASN1_NULL || entry->tag & SC_ASN1_CONS) {
		r = asn1_write_element(ctx, entry->tag, buf, buflen, obj, objlen);
		if (r)
			sc_debug(ctx, SC_LOG_DEBUG_ASN1, "error writing ASN.1 tag and length: %s\n",
					sc_strerror(r));
	} else if (!(entry->flags & SC_ASN1_PRESENT)) {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "cannot encode non-optional ASN.1 object: not given by caller\n");
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	} else {
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "cannot encode empty non-optional ASN.1 object\n");
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (buf)
		free(buf);
	if (r >= 0)
		sc_debug(ctx, SC_LOG_DEBUG_ASN1, "%*.*slength of encoded item=%u\n", depth, depth, "", *objlen);
	return r;
}

static int asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		      u8 **ptr, size_t *size, int depth)
{
	int r, idx = 0;
	u8 *obj = NULL, *buf = NULL, *tmp;
	size_t total = 0, objsize;

	for (idx = 0; asn1[idx].name != NULL; idx++) {
		r = asn1_encode_entry(ctx, &asn1[idx], &obj, &objsize, depth);
		if (r) {
			if (obj)
				free(obj);
			if (buf)
				free(buf);
			return r;
		}
		/* in case of an empty (optional) element continue with
		 * the next asn1 element */
		if (!objsize)
			continue;
		tmp = (u8 *) realloc(buf, total + objsize);
		if (!tmp) {
			if (obj)
				free(obj);
			if (buf)
				free(buf);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		buf = tmp;
		memcpy(buf + total, obj, objsize);
		free(obj);
		obj = NULL;
		total += objsize;
	}
	*ptr = buf;
	*size = total;
	return 0;
}

int sc_asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		   u8 **ptr, size_t *size)
{
	return asn1_encode(ctx, asn1, ptr, size, 0);
}

int _sc_asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		    u8 **ptr, size_t *size, int depth)
{
	return asn1_encode(ctx, asn1, ptr, size, depth);
}

int
_sc_asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
		       const u8 *in, size_t len, const u8 **newp, size_t *left,
		       int choice, int depth)
{
	return asn1_decode(ctx, asn1, in, len, newp, left, choice, depth);
}

int
sc_der_copy(sc_pkcs15_der_t *dst, const sc_pkcs15_der_t *src)
{
	if (!dst)
		return SC_ERROR_INVALID_ARGUMENTS;
	memset(dst, 0, sizeof(*dst));
	if (src->len) {
		dst->value = malloc(src->len);
		if (!dst->value)
			return SC_ERROR_OUT_OF_MEMORY;
		dst->len = src->len;
		memcpy(dst->value, src->value, src->len);
	}
	return SC_SUCCESS;
}

int
sc_encode_oid (struct sc_context *ctx, struct sc_object_id *id,
		unsigned char **out, size_t *size)
{
	static const struct sc_asn1_entry c_asn1_object_id[2] = {
		{ "oid", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_object_id[2];
	int rv;

	sc_copy_asn1_entry(c_asn1_object_id, asn1_object_id);
	sc_format_asn1_entry(asn1_object_id + 0, id, NULL, 1);

	rv = _sc_asn1_encode(ctx, asn1_object_id, out, size, 1);
	LOG_TEST_RET(ctx, rv, "Cannot encode object ID");

	return SC_SUCCESS;
}


#define C_ASN1_SIG_VALUE_SIZE 2
static struct sc_asn1_entry c_asn1_sig_value[C_ASN1_SIG_VALUE_SIZE] = {
		{ "ECDSA-Sig-Value", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE 3
static struct sc_asn1_entry c_asn1_sig_value_coefficients[C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE] = {
		{ "r", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ "s", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
};


int
sc_asn1_sig_value_rs_to_sequence(struct sc_context *ctx, unsigned char *in, size_t inlen,
		unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_sig_value[C_ASN1_SIG_VALUE_SIZE];
	struct sc_asn1_entry asn1_sig_value_coefficients[C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE];
	unsigned char *r = in, *s = in + inlen/2;
	size_t r_len = inlen/2, s_len = inlen/2;
	int rv;

	LOG_FUNC_CALLED(ctx);

	/* R/S are filled up with zeroes, we do not want that in sequence format */
	while(r_len > 1 && *r == 0x00) {
		r++;
		r_len--;
	}
	while(s_len > 1 && *s == 0x00) {
		s++;
		s_len--;
	}

	sc_copy_asn1_entry(c_asn1_sig_value, asn1_sig_value);
	sc_format_asn1_entry(asn1_sig_value + 0, asn1_sig_value_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_sig_value_coefficients, asn1_sig_value_coefficients);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 0, r, &r_len, 1);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 1, s, &s_len, 1);

	rv = sc_asn1_encode(ctx, asn1_sig_value, buf, buflen);
	LOG_TEST_RET(ctx, rv, "ASN.1 encoding ECDSA-SIg-Value failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sc_asn1_sig_value_sequence_to_rs(struct sc_context *ctx, unsigned char *in, size_t inlen,
		unsigned char *buf, size_t buflen)
{
	struct sc_asn1_entry asn1_sig_value[C_ASN1_SIG_VALUE_SIZE];
	struct sc_asn1_entry asn1_sig_value_coefficients[C_ASN1_SIG_VALUE_COEFFICIENTS_SIZE];
	unsigned char *r, *s;
	size_t r_len, s_len, halflen = buflen/2;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!buf || !buflen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_copy_asn1_entry(c_asn1_sig_value, asn1_sig_value);
	sc_format_asn1_entry(asn1_sig_value + 0, asn1_sig_value_coefficients, NULL, 0);

	sc_copy_asn1_entry(c_asn1_sig_value_coefficients, asn1_sig_value_coefficients);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 0, &r, &r_len, 0);
	sc_format_asn1_entry(asn1_sig_value_coefficients + 1, &s, &s_len, 0);

	rv = sc_asn1_decode(ctx, asn1_sig_value, in, inlen, NULL, NULL);
	LOG_TEST_RET(ctx, rv, "ASN.1 decoding ECDSA-Sig-Value failed");

	if (halflen < r_len || halflen < s_len)   {
		rv = SC_ERROR_BUFFER_TOO_SMALL;
		goto done;
	}

	memset(buf, 0, buflen);
	memcpy(buf + (halflen - r_len), r, r_len);
	memcpy(buf + (buflen - s_len), s, s_len);

	sc_log(ctx, "r(%i): %s", halflen, sc_dump_hex(buf, halflen));
	sc_log(ctx, "s(%i): %s", halflen, sc_dump_hex(buf + halflen, halflen));

	rv = SC_SUCCESS;
done:
	free(r);
	free(s);

	LOG_FUNC_RETURN(ctx, rv);
}
