/*
 * types.h: OpenSC general types
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

#ifndef _OPENSC_TYPES_H
#define _OPENSC_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char u8;

#define SC_MAX_OBJECT_ID_OCTETS		16

struct sc_object_id {
	int value[SC_MAX_OBJECT_ID_OCTETS];
};

#define SC_PATH_TYPE_FILE_ID	0
#define SC_PATH_TYPE_DF_NAME	1
#define SC_PATH_TYPE_PATH	2
#define SC_PATH_TYPE_PATH_PROT	3	/* path of a file containing
					   EnvelopedData objects */
#define SC_PATH_TYPE_FROM_CURRENT   4
#define SC_PATH_TYPE_PARENT   5

#define SC_MAX_PATH_SIZE		16
#define SC_MAX_PATH_STRING_SIZE		(SC_MAX_PATH_SIZE * 2 + 1)

typedef struct sc_path {
	u8 value[SC_MAX_PATH_SIZE];
	size_t len;

	/* The next two fields are used in PKCS15, where
	 * a Path object can reference a portion of a file -
	 * count octets starting at offset index.
	 */
	int index;
	int count;

	int type;
} sc_path_t;

typedef struct sc_acl_entry {
	unsigned int method;	/* See SC_AC_* */
	unsigned int key_ref;	/* SC_AC_KEY_REF_NONE or an integer */

	struct sc_acl_entry *next;
} sc_acl_entry_t;

#define SC_MAX_AC_OPS			9

typedef struct sc_file {
	struct sc_path path;
	u8 name[16];	/* DF name */
	size_t namelen; /* length of DF name */

	int type, shareable, ef_structure;
	size_t size;	/* Size of file (in bytes) */
	int id;		/* Short file id (2 bytes) */
	int status;	/* Status flags */
	struct sc_acl_entry *acl[SC_MAX_AC_OPS]; /* Access Control List */

	int record_length; /* In case of fixed-length or cyclic EF */
	int record_count;  /* Valid, if not transparent EF or DF */

	u8 *sec_attr;
	size_t sec_attr_len;
	u8 *prop_attr;
	size_t prop_attr_len;
	u8 *type_attr;
	size_t type_attr_len;

	unsigned int magic;
} sc_file_t;

/* use command chaining if the Lc value is greater than normally
 * allowed
 */
#define SC_APDU_FLAGS_CHAINING		0x00000001UL
/* do not automatically call GET RESPONSE to read all available
 * data
 */
#define SC_APDU_FLAGS_NO_GET_RESP	0x00000002UL
/* do not automatically try a re-transmit with a new length
 * if the card returns 0x6Cxx (wrong length)
 */
#define SC_APDU_FLAGS_NO_RETRY_WL	0x00000004UL

typedef struct sc_apdu {
	int cse;		/* APDU case */
	u8 cla, ins, p1, p2;	/* CLA, INS, P1 and P2 bytes */
	size_t lc, le;		/* Lc and Le bytes */
	const u8 *data;		/* C-APDU data */
	size_t datalen;		/* length of data in C-APDU */
	u8 *resp;		/* R-APDU data buffer */
	size_t resplen;		/* in: size of R-APDU buffer,
				 * out: length of data returned in R-APDU */
	u8 sensitive;		/* Set if either the command or
				 * the response contains secrets,
				 * e.g. a PIN. */
	u8 control;		/* Set if APDU should go to the reader */

	unsigned int sw1, sw2;	/* Status words returned in R-APDU */

	unsigned long flags;
} sc_apdu_t;

#ifdef __cplusplus
}
#endif

#endif
