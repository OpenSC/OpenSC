/*
 * card-cac-common.h: Code shared among CAC1 and CAC2 drivers
 *
 * Copyright (C) 2018, Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#ifndef HAVE_CARD_CAC_COMMON_H
#define HAVE_CARD_CAC_COMMON_H

#define CAC_MAX_SIZE 4096		/* arbitrary, just needs to be 'large enough' */

typedef struct cac_cuid {
	u8 gsc_rid[5];
	u8 manufacturer_id;
	u8 card_type;
	u8 card_id;
} cac_cuid_t;

/* data structures to store meta data about CAC objects */
typedef struct cac_object {
	const char *name;
	int fd;
	sc_path_t path;
} cac_object_t;

/*
 * CAC private data per card state
 */
typedef struct cac_private_data {
	int object_type;		/* select set this so we know how to read the file */
	int cert_next;			/* index number for the next certificate found in the list */
	u8 *cache_buf;			/* cached version of the currently selected file */
	size_t cache_buf_len;		/* length of the cached selected file */
	int cached;			/* is the cached selected file valid */
	cac_cuid_t cuid;                /* card unique ID from the CCC */
	u8 *cac_id;                     /* card serial number */
	size_t cac_id_len;              /* card serial number len */
	list_t pki_list;                /* list of pki containers */
	cac_object_t *pki_current;      /* current pki object _ctl function */
	list_t general_list;            /* list of general containers */
	cac_object_t *general_current;  /* current object for _ctl function */
	sc_path_t *aca_path;		/* ACA path to be selected before pin verification */
} cac_private_data_t;

#define CAC_DATA(card) ((cac_private_data_t*)card->drv_data)

/*
 * Set up the normal CAC paths
 */
#define CAC_1_RID "\xA0\x00\x00\x00\x79"
#define CAC_TO_AID(x) x, sizeof(x)-1


#define MAX_CAC_SLOTS 16		/* Maximum number of slots is 16 now */

/* template for a CAC pki object */
static const cac_object_t cac_cac_pki_obj = {
	"CAC Certificate", 0x0, { { 0 }, 0, 0, 0, SC_PATH_TYPE_DF_NAME,
	{ CAC_TO_AID(CAC_1_RID "\x01\x00") } }
};

/* template for emulated cuid */
static const cac_cuid_t cac_cac_cuid = {
	{ 0xa0, 0x00, 0x00, 0x00, 0x79 },
	2, 2, 0
};

cac_private_data_t *cac_new_private_data(void);
void cac_free_private_data(cac_private_data_t *priv);
int cac_add_object_to_list(list_t *list, const cac_object_t *object);
const char *get_cac_label(int index);

#endif /* HAVE_CARD_CAC_COMMON_H */
