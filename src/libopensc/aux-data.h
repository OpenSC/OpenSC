/*
 * aux-data.h: Non PKCS#15, non ISO7816 data
 *             Used to pass auxiliary data from non PKCS#15, non ISO7816 appliations (like minidriver)
 *             to card specific part through the standard PKCS#15 and ISO7816 frameworks
 *
 * Copyright (C) 2016  Viktor Tarasov <viktor.tarasov@gmail.com>
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

#ifndef _AUX_DATA_H
#define _AUX_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cardctl.h"
#include "errors.h"
#include "asn1.h"
#include "types.h"

#define SC_AUX_DATA_TYPE_NO_DATA	0x00
#define SC_AUX_DATA_TYPE_MD_CMAP_RECORD	0x01

/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN       39
 * #define CONTAINER_MAP_VALID_CONTAINER        1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER      2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *      WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *      BYTE bFlags;
 *      BYTE bReserved;
 *      WORD wSigKeySizeBits;
 *      WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
#define SC_MD_MAX_CONTAINER_NAME_LEN	39
#define SC_MD_CONTAINER_MAP_VALID_CONTAINER	0x01
#define SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER	0x02

struct sc_md_cmap_record {
	unsigned char guid[SC_MD_MAX_CONTAINER_NAME_LEN + 1];
	size_t guid_len;
	unsigned flags;
	unsigned keysize_sign;
	unsigned keysize_keyexchange;
};

struct sc_auxiliary_data {
	unsigned type;
	union {
		struct sc_md_cmap_record cmap_record;
	} data;
};

int sc_aux_data_set_md_flags(struct sc_context *, struct sc_auxiliary_data *, unsigned char);
int sc_aux_data_allocate(struct sc_context *, struct sc_auxiliary_data **, struct sc_auxiliary_data *);
int sc_aux_data_set_md_guid(struct sc_context *, struct sc_auxiliary_data *, char *);
void sc_aux_data_free(struct sc_auxiliary_data **);
int sc_aux_data_get_md_guid(struct sc_context *, struct sc_auxiliary_data *, unsigned,
		unsigned char *, size_t *);
int sc_aux_data_get_md_flags(struct sc_context *, struct sc_auxiliary_data *, unsigned char *);

#ifdef __cplusplus
}
#endif

#endif /* ifndef _AUX_DATA_H */
