/*
 * sc-asn1.c: ASN.1 decoding functions (DER)
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
#include "sc-asn1.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

const char *tag2str(int tag)
{
	const static char *tags[] = {
		"EOC", "BOOLEAN", "INTEGER", "BIT STRING", "OCTET STRING",	/* 0-4 */
		"NULL", "OBJECT", "OBJECT DESCRIPTOR", "EXTERNAL", "REAL",	/* 5-9 */
		"ENUMERATED", "<ASN1 11>", "UTF8STRING", "<ASN1 13>",	/* 10-13 */
		"<ASN1 14>", "<ASN1 15>", "SEQUENCE", "SET",	/* 15-17 */
		"NUMERICSTRING", "PRINTABLESTRING", "T61STRING",	/* 18-20 */
		"VIDEOTEXSTRING", "IA5STRING", "UTCTIME", "GENERALIZEDTIME",	/* 21-24 */
		"GRAPHICSTRING", "VISIBLESTRING", "GENERALSTRING",	/* 25-27 */
		"UNIVERSALSTRING", "<ASN1 29>", "BMPSTRING"	/* 28-30 */
	};

	if (tag < 0 || tag > 30)
		return "(unknown)";
	return tags[tag];
}

static int read_tag(const u8 ** buf,
		    int buflen, int *cla_out, int *tag_out, int *taglen)
{
	const u8 *p = *buf;
	int left = buflen;
	int cla, tag, len, i;

	*buf = NULL;
	if (*p == 0)
		return 0;
	cla = (*p & ASN1_TAG_CLASS) | (*p & ASN1_TAG_CONSTRUCTED);
	tag = *p & ASN1_TAG_PRIMITIVE;
	if (tag == ASN1_TAG_PRIMITIVE) {	/* 0x1F */
		fprintf(stderr, "Tag number >= 0x1F not supported!\n");
		goto error;
	}
	p++;
	if (--left == 0)
		goto error;
	len = *p & 0x7f;
	if (*p++ & 0x80) {
		int a = 0;
		if (len > 4) {
			fprintf(stderr, "ASN.1 tag too long!\n");
			goto error;
		}
		for (i = 0; i < len; i++) {
			a <<= 8;
			a |= *p;
			p++;
		}
		len = a;
	}
	*cla_out = cla;
	*tag_out = tag;
	*taglen = len;
	*buf = p;
	return 1;
      error:
	return -1;
}

static void sc_asn1_print_octet_string(const u8 * buf, int buflen)
{
	int i;

	for (i = 0; i < buflen; i++)
		printf("%02X", buf[i]);
}

static void sc_asn1_print_utf8string(const u8 * buf, int buflen)
{
	int i;

	for (i = 0; i < buflen; i++)
		printf("%c", buf[i]);
}

static void sc_asn1_print_integer(const u8 * buf, int buflen)
{
	long long a = 0;
	int i;

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

static void sc_asn1_print_bit_string(const u8 * buf, int buflen)
{
	unsigned long long a = 0;
	int i, r;

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

static void sc_asn1_print_object_id(const u8 * buf, int buflen)
{
	int i = 0;
	struct sc_object_id oid;
	char sbuf[256];

	if (sc_asn1_decode_object_id(buf, buflen, &oid)) {
		printf("decode error");
		return;
	}
	sbuf[0] = 0;
	while (oid.value[i] >= 0) {
		char tmp[12];
		
		if (i)
			strcat(sbuf, ".");
		sprintf(tmp, "%d", oid.value[i]);
		strcat(sbuf, tmp);
		i++;
	}
	printf("%s", sbuf);
}

static void print_tags_recursive(const u8 * buf0,
				 const u8 * buf, int buflen, int depth)
{
	int i, r, bytesleft = buflen;
	const char *classes[4] = {
		"Univ", "Appl", "Cntx", "Priv"
	};
	const u8 *p = buf;

	while (bytesleft >= 2) {
		int cla, tag, len, hlen;
		const u8 *tagp = p;

		r = read_tag(&tagp, bytesleft, &cla, &tag, &len);
		if (r < 0) {
			printf("Error in decoding.\n");
			return;
		}
		hlen = tagp - p;
		if (r == 0)
			return;
		if (cla == 0 && tag == 0) {
			printf("Zero tag, finishing\n");
			break;
		}
		for (i = 0; i < depth; i++) {
			putchar(' ');
			putchar(' ');
		}
		printf("%02X %s: tag 0x%02X, length %3d: ",
		       cla | tag, classes[cla >> 6], tag & 0x1f, len);
		if (len + hlen > bytesleft) {
			printf(" Illegal length!\n");
			return;
		}
		p += hlen + len;
		bytesleft -= hlen + len;
		if ((cla & ASN1_TAG_CLASS) == ASN1_TAG_UNIVERSAL)
			printf("%s", tag2str(tag));

		if (cla & ASN1_TAG_CONSTRUCTED) {
			putchar('\n');
			print_tags_recursive(buf0, tagp, len, depth + 1);
			continue;
		}
		if ((cla & ASN1_TAG_CLASS) == ASN1_TAG_UNIVERSAL) {
			printf(" [");
			switch (tag) {
			case ASN1_BIT_STRING:
				sc_asn1_print_bit_string(tagp, len);
				break;
			case ASN1_OCTET_STRING:
				sc_asn1_print_octet_string(tagp, len);
				break;
			case ASN1_OBJECT:
				sc_asn1_print_object_id(tagp, len);
				break;
			case ASN1_INTEGER:
			case ASN1_ENUMERATED:
				sc_asn1_print_integer(tagp, len);
				break;
			case ASN1_T61STRING:
			case ASN1_PRINTABLESTRING:
			case ASN1_UTF8STRING:
				sc_asn1_print_utf8string(tagp, len);
				break;
			}
			printf("]");
		}
		putchar('\n');
	}
	return;
}

void sc_asn1_print_tags(const u8 * buf, int buflen)
{
	printf("Printing tags for buffer of length %d\n", buflen);
	print_tags_recursive(buf, buf, buflen, 0);
}

const u8 *sc_asn1_find_tag(const u8 * buf, int buflen, int tag_in, int *taglen_in)
{
	int left = buflen, cla, tag, taglen;
	const u8 *p = buf;

	*taglen_in = 0;
	while (left >= 2) {
		buf = p;
		if (read_tag(&p, left, &cla, &tag, &taglen) != 1)
			return NULL;
		left -= (p - buf);
		if ((tag | cla) == tag_in) {
			if (taglen > left)
				return NULL;
			*taglen_in = taglen;
			return p;
		}
		if ((cla | tag) == 0xF0) {	/* skip 0xF0 foobar tags */
			fprintf(stderr, "Foobar tag skipped\n");
			taglen = 0;
		}
		left -= taglen;
		p += taglen;
	}
	return NULL;
}

const u8 *sc_asn1_skip_tag(const u8 ** buf, int *buflen, int tag_in, int *taglen_out)
{
	const u8 *p = *buf;
	int len = *buflen, cla, tag, taglen;

	if (read_tag((const u8 **) &p, len, &cla, &tag, &taglen) != 1)
		return NULL;
	if ((tag | cla) != tag_in)
		return NULL;
	len -= (p - *buf);	/* header size */
	if (taglen > len) {
		fprintf(stderr, "skip_tag(): too long tag\n");
		return NULL;
	}
	*buflen -= (p - *buf) + taglen;
	*buf = p + taglen;	/* point to next tag */
	*taglen_out = taglen;
	return p;
}

const u8 *sc_asn1_verify_tag(const u8 * buf, int buflen, int tag_in, int *taglen_out)
{
	return sc_asn1_skip_tag(&buf, &buflen, tag_in, taglen_out);
}

static int decode_bit_string(const u8 * inbuf, int inlen, void *outbuf,
			     int outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out = (u8 *) outbuf;
	int zero_bits = *in & 0x07;
	int octets_left = inlen - 1;
	int i, count = 0;

	in++;
	if (outlen < octets_left)
		return SC_ERROR_INVALID_ARGUMENTS;
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
	return  (count * 8) - zero_bits;
}

int sc_asn1_decode_bit_string(const u8 * inbuf,
			      int inlen, void *outbuf, int outlen)
{
	return decode_bit_string(inbuf, inlen, outbuf, outlen, 1);
}

int sc_asn1_decode_bit_string_ni(const u8 * inbuf,
			      int inlen, void *outbuf, int outlen)
{
	return decode_bit_string(inbuf, inlen, outbuf, outlen, 0);
}

int sc_asn1_decode_integer(const u8 * inbuf, int inlen, int *out)
{
	int i, a = 0;

	if (inlen > sizeof(int))
		return SC_ERROR_INVALID_ASN1_OBJECT;
	for (i = 0; i < inlen; i++) {
		a <<= 8;
		a |= *inbuf++;
	}
	*out = a;
	return 0;
}

int sc_asn1_decode_object_id(const u8 * inbuf, int inlen,
                             struct sc_object_id *id)
{
	int i, a;
	const u8 *p = inbuf;
	int *octet = id->value;
	
	assert(id != NULL);
	if (inlen < 1)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	for (i = 0; i < SC_ASN1_MAX_OBJECT_ID_OCTETS; i++)
		id->value[i] = -1;
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
		if (octet - id->value >= SC_ASN1_MAX_OBJECT_ID_OCTETS-1)
			return SC_ERROR_INVALID_ASN1_OBJECT;
	};
	
	return 0;
}

int sc_asn1_put_tag(int tag, const u8 * data, int datalen, u8 * out, int outlen, u8 **ptr)
{
	u8 *p = out;

	if (outlen < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (datalen < 0 || datalen > 127)
		return SC_ERROR_INVALID_ARGUMENTS;
	*p++ = tag & 0xFF;	/* FIXME: Support longer tags */
	outlen--;
	*p++ = datalen;
	outlen--;
	if (outlen < datalen)
		return SC_ERROR_INVALID_ARGUMENTS;
		
	memcpy(p, data, datalen);
	p += datalen;
	if (ptr != NULL)
		*ptr = p;
	return 0;
}
