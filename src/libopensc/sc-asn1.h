/*
 * sc-asn1.h: ASN.1 header file
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

#ifndef _SC_ASN1_H
#define _SC_ASN1_H

/* DER tag and length parsing */
const u8 *sc_asn1_find_tag(const u8 * buf, int buflen, int tag, int *taglen);
const u8 *sc_asn1_verify_tag(const u8 * buf, int buflen, int tag, int *taglen);
const u8 *sc_asn1_skip_tag(const u8 ** buf, int *buflen, int tag, int *taglen);

/* ASN.1 printing functions */
void sc_asn1_print_tags(const u8 * buf, int buflen);

/* ASN.1 object decoding functions */
int sc_asn1_utf8string_to_ascii(const u8 * buf, int buflen,
				u8 * outbuf, int outlen);
int sc_asn1_decode_bit_string(const u8 * inbuf, int inlen,
			      void *outbuf, int outlen);
/* non-inverting version */
int sc_asn1_decode_bit_string_ni(const u8 * inbuf, int inlen,
				 void *outbuf, int outlen);
int sc_asn1_decode_integer(const u8 * inbuf, int inlen, int *out);
int sc_asn1_decode_object_id(const u8 * inbuf, int inlen,
			     struct sc_object_id *id);

#define ASN1_TAG_CLASS			0xC0
#define ASN1_TAG_UNIVERSAL		0x00
#define ASN1_TAG_APPLICATION		0x40
#define ASN1_TAG_CONTEXT		0x80
#define ASN1_TAG_PRIVATE		0xC0

#define ASN1_TAG_CONSTRUCTED		0x20
#define ASN1_TAG_PRIMITIVE		0x1F

#define ASN1_EOC                      0
#define ASN1_BOOLEAN                  1
#define ASN1_INTEGER                  2
#define ASN1_NEG_INTEGER              (2 | ASN1_NEG)
#define ASN1_BIT_STRING               3
#define ASN1_OCTET_STRING             4
#define ASN1_NULL                     5
#define ASN1_OBJECT                   6
#define ASN1_OBJECT_DESCRIPTOR        7
#define ASN1_EXTERNAL                 8
#define ASN1_REAL                     9
#define ASN1_ENUMERATED               10
#define ASN1_NEG_ENUMERATED           (10 | ASN1_NEG)
#define ASN1_UTF8STRING               12
#define ASN1_SEQUENCE                 16
#define ASN1_SET                      17
#define ASN1_NUMERICSTRING            18
#define ASN1_PRINTABLESTRING          19
#define ASN1_T61STRING                20
#define ASN1_TELETEXSTRING            20
#define ASN1_VIDEOTEXSTRING           21
#define ASN1_IA5STRING                22
#define ASN1_UTCTIME                  23
#define ASN1_GENERALIZEDTIME          24
#define ASN1_GRAPHICSTRING            25
#define ASN1_ISO64STRING              26
#define ASN1_VISIBLESTRING            26
#define ASN1_GENERALSTRING            27
#define ASN1_UNIVERSALSTRING          28
#define ASN1_BMPSTRING                30

#endif
