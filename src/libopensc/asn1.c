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

#include "sc-internal.h"
#include "sc-asn1.h"
#include "sc-log.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdlib.h>


static int asn1_parse(struct sc_context *ctx, struct sc_asn1_struct *asn1,
		      const u8 *in, int len, const u8 **newp, int *len_left,
		      int choice, int depth);

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

	if (left < 2)
		goto error;
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

const u8 *sc_asn1_find_tag(struct sc_context *ctx, const u8 * buf,
			   size_t buflen, unsigned int tag_in, size_t *taglen_in)
{
	size_t left = buflen, taglen;
	unsigned int cla, tag;
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
		left -= taglen;
		p += taglen;
	}
	return NULL;
}

const u8 *sc_asn1_skip_tag(struct sc_context *ctx, const u8 ** buf, size_t *buflen,
			   unsigned int tag_in, size_t *taglen_out)
{
	const u8 *p = *buf;
	size_t len = *buflen, taglen;
	unsigned int cla, tag;

	if (read_tag((const u8 **) &p, len, &cla, &tag, &taglen) != 1)
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
		error(ctx, "too long ASN.1 object (size %d while only %d available)\n",
		      taglen, len);
		return NULL;
	}
	*buflen -= (p - *buf) + taglen;
	*buf = p + taglen;	/* point to next tag */
	*taglen_out = taglen;
	return p;
}

const u8 *sc_asn1_verify_tag(struct sc_context *ctx, const u8 * buf, size_t buflen,
			     unsigned int tag_in, size_t *taglen_out)
{
	return sc_asn1_skip_tag(ctx, &buf, &buflen, tag_in, taglen_out);
}

static int decode_bit_string(const u8 * inbuf, int inlen, void *outbuf,
			     int outlen, int invert)
{
	const u8 *in = inbuf;
	u8 *out = (u8 *) outbuf;
	int zero_bits = *in & 0x07;
	int octets_left = inlen - 1;
	int i, count = 0;

	memset(outbuf, 0, outlen);
	in++;
	if (outlen < octets_left)
		return SC_ERROR_BUFFER_TOO_SMALL;
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

int sc_asn1_decode_utf8string(const u8 * inbuf, int inlen,
			      u8 *out, int *outlen)
{
	if (inlen+1 > *outlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*outlen = inlen+1;
	memcpy(out, inbuf, inlen);
	out[inlen] = 0;
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

static int asn1_parse_path(struct sc_context *ctx, const u8 *in, int len,
			      struct sc_path *path, int depth)
{
	int idx, r;
	struct sc_asn1_struct asn1_path[] = {
		{ "path",   SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, &path->value, &path->len },
		{ "index",  SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, &idx },
		{ NULL }
	};
	path->len = SC_MAX_PATH_SIZE;
	r = asn1_parse(ctx, asn1_path, in, len, NULL, NULL, 0, depth + 1);
	if (r)
		return r;
	path->type = SC_PATH_TYPE_PATH;

	return 0;
}

static int asn1_parse_p15_object(struct sc_context *ctx, const u8 *in, int len,
				    struct sc_pkcs15_object *obj, int depth)
{
	int r;
	struct sc_pkcs15_common_obj_attr *com_attr = obj->com_attr;
	int flags_len = sizeof(com_attr->flags);
	int label_len = sizeof(com_attr->label);
	struct sc_asn1_struct asn1_com_obj_attr[] = {
		{ "label", SC_ASN1_UTF8STRING, ASN1_UTF8STRING, SC_ASN1_OPTIONAL, com_attr->label, &label_len },
		{ "flags", SC_ASN1_BIT_STRING, ASN1_BIT_STRING, SC_ASN1_OPTIONAL, &com_attr->flags, &flags_len },
		{ "authId", SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, SC_ASN1_OPTIONAL, &com_attr->auth_id },
		{ "userConsent", SC_ASN1_INTEGER, ASN1_INTEGER, SC_ASN1_OPTIONAL, &com_attr->user_consent },
		{ "accessControlRules", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL },
		{ NULL }
	};
	struct sc_asn1_struct asn1_p15_obj[] = {
		{ "commonObjectAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_com_obj_attr },
		{ "classAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, obj->asn1_class_attr },
		{ "subClassAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, obj->asn1_subclass_attr },
		{ "typeAttributes", SC_ASN1_STRUCT, SC_ASN1_CTX | 1 | SC_ASN1_CONS, 0, obj->asn1_type_attr },
		{ NULL }
	};
	r = asn1_parse(ctx, asn1_p15_obj, in, len, NULL, NULL, 0, depth + 1);
	return r;
}

static int asn1_decode_entry(struct sc_context *ctx, struct sc_asn1_struct *entry,
			     const u8 *obj, size_t objlen, int depth)
{
	void *parm = entry->parm;
	int (*callback_func)(struct sc_context *ctx, void *arg, const u8 *obj,
			     size_t objlen, int depth) =
		(int (*)(struct sc_context *, void *, const u8 *, size_t, int)) parm;
	int *len = (int *) entry->arg;
	int r = 0;

	if (ctx->debug >= 3) {
		u8 line[128], *linep = line;
		int i;
		
		line[0] = 0;
		for (i = 0; i < depth; i++) {
			strcpy(linep, "  ");
			linep += 2;
		}
		sprintf(linep, "decoding '%s'\n", entry->name);
		debug(ctx, line);
	}
		
	switch (entry->type) {
	case SC_ASN1_STRUCT:
		if (parm != NULL)
			r = asn1_parse(ctx, (struct sc_asn1_struct *) parm, obj,
				       objlen, NULL, NULL, 0, depth + 1);
		break;
	case SC_ASN1_BOOLEAN:
		if (parm != NULL) {
			if (objlen != 1) {
				error(ctx, "invalid ASN.1 object length: %d\n", objlen);
				r = SC_ERROR_INVALID_ASN1_OBJECT;
			} else
				*((u8 *) parm) = obj[0] ? 1 : 0;
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
	case SC_ASN1_OCTET_STRING:
		if (parm != NULL) {
			int c;
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
	case SC_ASN1_UTF8STRING:
		if (parm != NULL) {
			assert(len != NULL);
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
			r = sc_asn1_decode_utf8string(obj, objlen, parm, len);
		}
		break;
	case SC_ASN1_PATH:
		if (entry->parm != NULL)
			r = asn1_parse_path(ctx, obj, objlen, (struct sc_path *) parm, depth);
		break;
	case SC_ASN1_PKCS15_ID:
		if (entry->parm != NULL) {
			struct sc_pkcs15_id *id = parm;
			int c = objlen > sizeof(id->value) ? sizeof(id->value) : objlen;
			
			memcpy(id->value, obj, c);
			id->len = c;
		}
		break;
	case SC_ASN1_PKCS15_OBJECT:
		if (entry->parm != NULL)
			r = asn1_parse_p15_object(ctx, obj, objlen, (struct sc_pkcs15_object *) parm, depth);
		break;
	case SC_ASN1_CALLBACK:
		if (entry->parm != NULL)
			r = callback_func(ctx, entry->arg, obj, objlen, depth);
		break;
	default:
		error(ctx, "invalid ASN.1 type: %d\n", entry->type);
		assert(0);
	}
	if (r) {
		error(ctx, "decoding of ASN.1 object '%s' failed: %s\n", entry->name,
		      sc_strerror(r));
		return r;
	}
	entry->flags |= SC_ASN1_PRESENT;
	return 0;
}

static int asn1_parse(struct sc_context *ctx, struct sc_asn1_struct *asn1,
		      const u8 *in, int len, const u8 **newp, int *len_left,
		      int choice, int depth)
{
	int r, idx = 0;
	const u8 *p = in, *obj;
	struct sc_asn1_struct *entry = asn1;
	int left = len, objlen;

	if (ctx->debug >= 3)
		debug(ctx, "called, depth %d%s\n", depth, choice ? ", choice" : "");
	if (left < 2)
		return SC_ERROR_ASN1_END_OF_CONTENTS;
	if (p[0] == 0 && p[1] == 0)
		return SC_ERROR_ASN1_END_OF_CONTENTS;
	for (idx = 0; asn1[idx].name != NULL; idx++) {
		entry = &asn1[idx];
		r = 0;
		obj = sc_asn1_skip_tag(ctx, &p, &left, entry->tag, &objlen);
		if (obj == NULL) {
			if (choice)
				continue;
			if (entry->flags & SC_ASN1_OPTIONAL) {
				if (ctx->debug >= 3)
					debug(ctx, "optional ASN.1 object '%s' not present\n",
					      entry->name);
				continue;
			}
			error(ctx, "mandatory ASN.1 object '%s' not found\n", entry->name);
			if (ctx->debug && left) {
				u8 line[128], *linep = line;
				int i;

				line[0] = 0;
				for (i = 0; i < 10 && i < left; i++) {
					sprintf(linep, "%02X ", p[i]);
					linep += 3;
				}
				debug(ctx, "next tag: %s\n", line);
			}
			SC_FUNC_RETURN(ctx, 3, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
		}
		r = asn1_decode_entry(ctx, entry, obj, objlen, depth);
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

int sc_asn1_parse(struct sc_context *ctx, struct sc_asn1_struct *asn1,
		  const u8 *in, int len, const u8 **newp, int *len_left)
{
	return asn1_parse(ctx, asn1, in, len, newp, len_left, 0, 0);
}

int sc_asn1_parse_choice(struct sc_context *ctx, struct sc_asn1_struct *asn1,
			 const u8 *in, int len, const u8 **newp, int *len_left)
{
	return asn1_parse(ctx, asn1, in, len, newp, len_left, 1, 0);
}
