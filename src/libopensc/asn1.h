
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */

#ifndef _SC_ASN1_H
#define _SC_ASN1_H

#define ASN1_TAG_CLASS			0xC0
#define ASN1_TAG_UNIVERSAL		0x00
#define ASN1_TAG_APPLICATION		0x40
#define ASN1_TAG_CONTEXT		0x80
#define ASN1_TAG_PRIVATE		0xC0

#define ASN1_TAG_CONSTRUCTED		0x20
#define ASN1_TAG_PRIMITIVE		0x1F

#define ASN1_EOC                      0
#define ASN1_BOOLEAN                  1 /**/
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
#define ASN1_NUMERICSTRING            18 /**/
#define ASN1_PRINTABLESTRING          19
#define ASN1_T61STRING                20
#define ASN1_TELETEXSTRING            20	/* alias */
#define ASN1_VIDEOTEXSTRING           21 /**/
#define ASN1_IA5STRING                22
#define ASN1_UTCTIME                  23
#define ASN1_GENERALIZEDTIME          24 /**/
#define ASN1_GRAPHICSTRING            25 /**/
#define ASN1_ISO64STRING              26 /**/
#define ASN1_VISIBLESTRING            26	/* alias */
#define ASN1_GENERALSTRING            27 /**/
#define ASN1_UNIVERSALSTRING          28 /**/
#define ASN1_BMPSTRING                30
#endif
