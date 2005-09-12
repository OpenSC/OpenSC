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

#include "internal.h"
#include "asn1.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>

static int asn1_decode(sc_context_t *ctx, struct sc_asn1_entry *asn1,
		       const u8 *in, size_t len, const u8 **newp, size_t *len_left,
		       int choice, int depth);
static int asn1_encode(sc_context_t *ctx, const struct sc_asn1_entry *asn1,
		       u8 **ptr, size_t *size, int depth);

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
		goto error;
	*buf = NULL;
	if (*p == 0)
		return 0;
	if (*p == 0xFF) /* FIXME */
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
		unsigned int a = 0;
		if (len > 4 || len > left) {
			fprintf(stderr, "ASN.1 tag too long!\n");
			goto error;
		}
		left -= len;
		for (i = 0; i < len; i++) {
			a <<= 8;
			a |= *p;
			p++;
		}
		len = a;
	}
	if (len > left) {
		fprintf(stderr, "ASN.1 value too long!\n");
		goto error;
	}
	*cla_out = cla;
	*tag_out = tag;
	*taglen = len;
	*buf = p;
	return 1;
      error:
	return -1;
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
		unsigned int cla, tag, hlen;
		const u8 *tagp = p;
		size_t len;

		r = sc_asn1_read_tag(&tagp, bytesleft, &cla, &tag, &len);
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
		       cla | tag, classes[cla >> 6], tag & 0x1f, (int) len);
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

void sc_asn1_print_tags(const u8 * buf, size_t buflen)
{
	printf("Printing tags for buffer of length %d\n", (int) buflen);
	print_tags_recursive(buf, buf, buflen, 0);
}

const u8 *sc_asn1_find_tag(sc_context_t *ctx, const u8 * buf,
			   size_t buflen, unsigned int tag_in, size_t *taglen_in)
{
	size_t left = buflen, taglen;
	unsigned int cla, tag;
	const u8 *p = buf;

	*taglen_in = 0;
	while (left >= 2) {
		buf = p;
		if (sc_asn1_read_tag(&p, left, &cla, &tag, &taglen) != 1)
			return NULL;
		if (left < (size_t)(p - buf)) {
			sc_error(ctx, "invalid TLV object\n");
			return NULL;
		}
		left -= (p - buf);
		if ((tag | cla) == tag_in) {
			if (taglen > left)
				return NULL;
			*taglen_in = taglen;
			return p;
		}
		if (left < taglen) {
			sc_error(ctx, "invalid TLV object\n");
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

	if (sc_asn1_read_tag((const u8 **) &p, len, &cla, &tag, &taglen) != 1)
		return NULL;
	switch (cla & 0xC0) {
	case ASN1_TAG_UNIVERSAL:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_UNI)
			return NULL;
		break;
	case ASN1_TAG_APPLICATION:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_APP)
			return NULL;
		break;
	case ASN1_TAG_CONTEXT:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_CTX)
			return NULL;
		break;
	case ASN1_TAG_PRIVATE:
		if ((tag_in & SC_ASN1_CLASS_MASK) != SC_ASN1_PRV)
			return NULL;
		break;
	}
	if (cla & ASN1_TAG_CONSTRUCTED) {
		if ((tag_in & SC_ASN1_CONS) == 0)
			return NULL;
	} else
		if (tag_in & SC_ASN1_CONS)
			return NULL;
	if ((tag_in & SC_ASN1_TAG_MASK) != tag)
		return NULL;
	len -= (p - *buf);	/* header size */
	if (taglen > len) {
		sc_error(ctx, "too long ASN.1 object (size %d while only %d available)\n",
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
	*outbuf = out = (u8 *) malloc(bytes);
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
	for (i = 0; i < inlen; i++) {
		a <<= 8;
		a |= *inbuf++;
	}
	*out = a;
	return 0;
}

static int asn1_encode_integer(int in, u8 ** obj, size_t * objsize)
{
	int i = sizeof(in) * 8, skip = 1;
	u8 *p, b;

	*obj = p = (u8 *) malloc(sizeof(in));
	if (*obj == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	do {
		i -= 8;
		b = in >> i;
		if (b == 0 && skip)
			continue;
		skip = 0;
		*p++ = b;
	} while (i > 0);
	*objsize = p - *obj;
	if (*objsize == 0) {
		*objsize = 1;
		(*obj)[0] = 0;
	}
	return 0;
}

int sc_asn1_decode_object_id(const u8 * inbuf, size_t inlen,
                             struct sc_object_id *id)
{
	int i, a;
	const u8 *p = inbuf;
	int *octet;
	
	if (inlen == 0 || inbuf == NULL || id == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	octet = id->value;
	for (i = 0; i < SC_MAX_OBJECT_ID_OCTETS; i++)
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
		if (octet - id->value >= SC_MAX_OBJECT_ID_OCTETS-1)
			return SC_ERROR_INVALID_ASN1_OBJECT;
	};
	
	return 0;
}

static int sc_asn1_encode_object_id(u8 **buf, size_t *buflen,
			     const struct sc_object_id *id)
{
	u8 temp[SC_MAX_OBJECT_ID_OCTETS*5], *p = temp;
	size_t	count = 0;
	int	i;
	const int *value = (const int *) id->value;

	for (i = 0; value[i] > 0 && i < SC_MAX_OBJECT_ID_OCTETS; i++) {
		unsigned int k, shift;

		k = value[i];
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
	*buflen = count = p - temp;
	*buf = (u8 *) malloc(count);
	if (!*buf)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(*buf, temp, count);
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

int sc_asn1_put_tag(int tag, const u8 * data, size_t datalen, u8 * out, size_t outlen, u8 **ptr)
{
	u8 *p = out;

	if (outlen < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (datalen > 127)
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

static int asn1_write_element(sc_context_t *ctx, unsigned int tag,
	const u8 * data, size_t datalen, u8 ** out, size_t * outlen)
{
	u8 t;
	u8 *buf, *p;
	int c = 0;
	
	t = tag & 0x1F;
	if (t != (tag & SC_ASN1_TAG_MASK)) {
		sc_error(ctx, "Long tags not supported\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	switch (tag & SC_ASN1_CLASS_MASK) {
	case SC_ASN1_UNI:
		break;
	case SC_ASN1_APP:
		t |= ASN1_TAG_APPLICATION;
		break;
	case SC_ASN1_CTX:
		t |= ASN1_TAG_CONTEXT;
		break;
	case SC_ASN1_PRV:
		t |= ASN1_TAG_PRIVATE;
		break;
	}
	if (tag & SC_ASN1_CONS)
		t |= ASN1_TAG_CONSTRUCTED;
	if (datalen > 127) {
		c = 1;
		while (datalen >> (c << 3))
			c++;
	}
	*outlen = 2 + c + datalen;
	buf = (u8 *) malloc(*outlen);
	if (buf == NULL)
		SC_FUNC_RETURN(ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	*out = p = buf;
	*p++ = t;
	if (c) {
		*p++ = 0x80 | c;
		while (c--)
			*p++ = (datalen >> (c << 3)) & 0xFF;
	} else
		*p++ = datalen & 0x7F;
	memcpy(p, data, datalen);
	
	return 0;
}

static const struct sc_asn1_entry c_asn1_path[4] = {
	{ "path",   SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, NULL, NULL },
	{ "index",  SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "length", SC_ASN1_INTEGER, SC_ASN1_CTX | 0, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_decode_path(sc_context_t *ctx, const u8 *in, size_t len,
			    sc_path_t *path, int depth)
{
	int idx, count, r;
	struct sc_asn1_entry asn1_path[4];
	
	sc_copy_asn1_entry(c_asn1_path, asn1_path);
	sc_format_asn1_entry(asn1_path + 0, &path->value, &path->len, 0);
	sc_format_asn1_entry(asn1_path + 1, &idx, NULL, 0);
	sc_format_asn1_entry(asn1_path + 2, &count, NULL, 0);
	path->len = SC_MAX_PATH_SIZE;
	r = asn1_decode(ctx, asn1_path, in, len, NULL, NULL, 0, depth + 1);
	if (r)
		return r;
	if (path->len == 2)
		path->type = SC_PATH_TYPE_FILE_ID;
	else
		path->type = SC_PATH_TYPE_PATH;
	if ((asn1_path[1].flags & SC_ASN1_PRESENT)
	 && (asn1_path[2].flags & SC_ASN1_PRESENT)) {
		path->index = idx;
		path->count = count;
	} else {
		path->index = 0;
		path->count = -1;
	}
	return 0;
}

static int asn1_encode_path(sc_context_t *ctx, const sc_path_t *path,
			    u8 **buf, size_t *bufsize, int depth)
{
	int r;
 	struct sc_asn1_entry asn1_path[4];
	sc_path_t tpath = *path;

	sc_copy_asn1_entry(c_asn1_path, asn1_path);
	sc_format_asn1_entry(asn1_path + 0, (void *) &tpath.value, (void *) &tpath.len, 1);
	if (path->count > 0) {
		sc_format_asn1_entry(asn1_path + 1, (void *) &tpath.index, NULL, 1);
		sc_format_asn1_entry(asn1_path + 2, (void *) &tpath.count, NULL, 1);
	}
	r = asn1_encode(ctx, asn1_path, buf, bufsize, depth + 1);
	return r;	
}

static const struct sc_asn1_entry c_asn1_com_obj_attr[6] = {
	{ "label", SC_ASN1_UTF8STRING, ASN1_UTF8STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "flags", SC_ASN1_BIT_FIELD, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "authId", SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "userConsent", SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "accessControlRules", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static const struct sc_asn1_entry c_asn1_p15_obj[5] = {
	{ "commonObjectAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "classAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ "subClassAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "typeAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

static int asn1_decode_p15_object(sc_context_t *ctx, const u8 *in,
				  size_t len, struct sc_asn1_pkcs15_object *obj,
				  int depth)
{
	int r;
	struct sc_pkcs15_object *p15_obj = obj->p15_obj;
	struct sc_asn1_entry asn1_c_attr[6], asn1_p15_obj[5];
	size_t flags_len = sizeof(p15_obj->flags);
	size_t label_len = sizeof(p15_obj->label);

	sc_copy_asn1_entry(c_asn1_com_obj_attr, asn1_c_attr);
	sc_copy_asn1_entry(c_asn1_p15_obj, asn1_p15_obj);
	sc_format_asn1_entry(asn1_c_attr + 0, p15_obj->label, &label_len, 0);
	sc_format_asn1_entry(asn1_c_attr + 1, &p15_obj->flags, &flags_len, 0);
	sc_format_asn1_entry(asn1_c_attr + 2, &p15_obj->auth_id, NULL, 0);
	sc_format_asn1_entry(asn1_c_attr + 3, &p15_obj->user_consent, NULL, 0);
	/* FIXME: encode accessControlRules */
	sc_format_asn1_entry(asn1_c_attr + 4, NULL, NULL, 0);
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
	int r;
	struct sc_pkcs15_object p15_obj = *obj->p15_obj;
	struct sc_asn1_entry    asn1_c_attr[6], asn1_p15_obj[5];
	size_t label_len = strlen(p15_obj.label);
	size_t flags_len;

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
	/* FIXME: decode accessControlRules */
	sc_format_asn1_entry(asn1_p15_obj + 0, asn1_c_attr, NULL, 1);
	sc_format_asn1_entry(asn1_p15_obj + 1, obj->asn1_class_attr, NULL, 1);
	if (obj->asn1_subclass_attr != NULL)
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

	*(void **)(&callback_func) = parm;

	if (ctx->debug >= 3)
		sc_debug(ctx, "%*.*sdecoding '%s'\n", depth, depth, "", entry->name);

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
				sc_error(ctx, "invalid ASN.1 object length: %d\n", objlen);
				r = SC_ERROR_INVALID_ASN1_OBJECT;
			} else
				*((int *) parm) = obj[0] ? 1 : 0;
		}
		break;
	case SC_ASN1_INTEGER:
	case SC_ASN1_ENUMERATED:
		if (parm != NULL)
			r = sc_asn1_decode_integer(obj, objlen, (int *) entry->parm);
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
				*buf = (u8 *) malloc(objlen-1);
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
				*buf = (u8 *) malloc(objlen);
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
				*buf = (u8 *) malloc(objlen);
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
				*buf = (u8 *) malloc(objlen-1);
				if (*buf == NULL) {
					r = SC_ERROR_OUT_OF_MEMORY;
					break;
				}
				*len = objlen-1;
				parm = *buf;
			}
			r = sc_asn1_decode_utf8string(obj, objlen, (u8 *) parm, len);
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
	case SC_ASN1_CALLBACK:
		if (entry->parm != NULL)
			r = callback_func(ctx, entry->arg, obj, objlen, depth);
		break;
	default:
		sc_error(ctx, "invalid ASN.1 type: %d\n", entry->type);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (r) {
		sc_error(ctx, "decoding of ASN.1 object '%s' failed: %s\n", entry->name,
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

	if (ctx->debug >= 3)
		sc_debug(ctx, "%*.*scalled, left=%u, depth %d%s\n",
			       	depth, depth, "",
				left, depth,
				choice ? ", choice" : "");

	if (left < 2) {
		while (asn1->name && (asn1->flags & SC_ASN1_OPTIONAL))
			asn1++;
		/* If all elements were optional, there's nothing
		 * to complain about */
		if (asn1->name == NULL)
			return 0;
		sc_error(ctx, "End of ASN.1 stream, "
			      "non-optional field \"%s\" not found\n",
			      asn1->name);
		return SC_ERROR_ASN1_OBJECT_NOT_FOUND;
	}
	if (p[0] == 0 || p[0] == 0xFF || len == 0)
		return SC_ERROR_ASN1_END_OF_CONTENTS;

	for (idx = 0; asn1[idx].name != NULL; idx++) {
		entry = &asn1[idx];
		r = 0;

		if (ctx->debug >= 3) {
			sc_debug(ctx, "Looking for '%s', tag 0x%x%s%s\n",
					entry->name, entry->tag,
					choice? ", CHOICE" : "",
					(entry->flags & SC_ASN1_OPTIONAL)? ", OPTIONAL": "");
		}

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
			if (ctx->debug >= 3)
				sc_debug(ctx, "not present\n");
			if (choice)
				continue;
			if (entry->flags & SC_ASN1_OPTIONAL)
				continue;
			sc_error(ctx, "mandatory ASN.1 object '%s' not found\n", entry->name);
			if (ctx->debug && left) {
				u8 line[128], *linep = line;
				size_t i;

				line[0] = 0;
				for (i = 0; i < 10 && i < left; i++) {
					sprintf((char *) linep, "%02X ", p[i]);
					linep += 3;
				}
				sc_debug(ctx, "next tag: %s\n", line);
			}
			SC_FUNC_RETURN(ctx, 3, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
		}
		r = asn1_decode_entry(ctx, entry, obj, objlen, depth);

decode_ok:
		if (r)
			return r;
		if (choice)
			break;
 	}
 	if (choice && asn1[idx].name == NULL) /* No match */
		SC_FUNC_RETURN(ctx, 3, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
 	if (newp != NULL)
		*newp = p;
 	if (len_left != NULL)
		*len_left = left;
	if (choice)
		SC_FUNC_RETURN(ctx, 3, idx);
	SC_FUNC_RETURN(ctx, 3, 0);
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

	*(void **)(&callback_func) = parm;

	if (ctx->debug >= 3)
		sc_debug(ctx, "%*.*sencoding '%s'%s\n",
			       	depth, depth, "",
			       	entry->name,
				(entry->flags & SC_ASN1_PRESENT)? "" : " (not present)");
	if (!(entry->flags & SC_ASN1_PRESENT))
		goto no_object;
	if (ctx->debug >= 6)
		sc_debug(ctx, "%*.*stype=%d, tag=0x%02x, parm=%p, len=%u\n",
				depth, depth, "",
				entry->type, entry->tag, parm, len? *len : 0);

	if (entry->type == SC_ASN1_CHOICE) {
		const struct sc_asn1_entry *list, *choice = NULL;

		list = (const struct sc_asn1_entry *) parm;
		while (list->name != NULL) {
			if (list->flags & SC_ASN1_PRESENT) {
				if (choice) {
					sc_error(ctx,
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
		sc_error(ctx, "unexpected parm == NULL\n");
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
		buf = (u8 *) malloc(1);
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
		buf = (u8 *) malloc(*len + 1);
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
		buf = (u8 *) malloc(*len);
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
		r = asn1_encode_path(ctx, (const sc_path_t *) parm, &buf, &buflen, depth);
		break;
	case SC_ASN1_PKCS15_ID:
		{
			const struct sc_pkcs15_id *id = (const struct sc_pkcs15_id *) parm;

			buf = (u8 *) malloc(id->len);
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
	case SC_ASN1_CALLBACK:
		r = callback_func(ctx, entry->arg, &buf, &buflen, depth);
		break;
	default:
		sc_error(ctx, "invalid ASN.1 type: %d\n", entry->type);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (r) {
		sc_error(ctx, "encoding of ASN.1 object '%s' failed: %s\n", entry->name,
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
	if (!buflen && entry->flags & SC_ASN1_OPTIONAL &&
	    !(entry->flags & SC_ASN1_PRESENT)) {
		/* This happens when we try to encode e.g. the
		 * subClassAttributes, which may be empty */
		*obj = NULL;
		*objlen = 0;
		r = 0;
	} else if (buflen || entry->type == SC_ASN1_NULL ||
	           entry->tag & SC_ASN1_CONS) {
		r = asn1_write_element(ctx, entry->tag,
					buf, buflen, obj, objlen);
		if (r)
			sc_error(ctx, "error writing ASN.1 tag and length: %s\n",
					sc_strerror(r));
	} else if (!(entry->flags & SC_ASN1_PRESENT)) {
		sc_error(ctx, "cannot encode non-optional ASN.1 object: not given by caller\n");
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	} else {
		sc_error(ctx, "cannot encode empty non-optional ASN.1 object\n");
		r = SC_ERROR_INVALID_ASN1_OBJECT;
	}
	if (buf)
		free(buf);
	if (r >= 0 && ctx->debug >= 3)
		sc_debug(ctx, "%*.*slength of encoded item=%u\n", depth, depth, "", *objlen);
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

void
sc_der_copy(sc_pkcs15_der_t *dst, const sc_pkcs15_der_t *src)
{
	memset(dst, 0, sizeof(*dst));
	if (src->len) {
		dst->value = (u8 *) malloc(src->len);
		if (!dst->value)
			return;
		dst->len = src->len;
		memcpy(dst->value, src->value, src->len);
	}
}

void
sc_der_clear(sc_pkcs15_der_t *der)
{
	if (der->value)
		free(der->value);
	memset(der, 0, sizeof(*der));
}
