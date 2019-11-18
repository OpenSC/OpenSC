/*
 * gp.h: Global Platform Related functions
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#ifndef _LIBOPENSC_GP_H
#define _LIBOPENSC_GP_H

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* returned by the iso get status apdu with the global platform cplc data parameters */
typedef struct global_platform_cplc_data {
	u8 tag[2];
	u8 length;
	u8 ic_fabricator[2];
	u8 ic_type[2];
	u8 os_id[2];
	u8 os_date[2];
	u8 os_level[2];
	u8 fabrication_data[2];
	u8 ic_serial_number[4];
	u8 ic_batch[2];
	u8 module_fabricator[2];
	u8 packing_data[2];
	u8 icc_manufacturer[2];
	u8 ic_embedding_data[2];
	u8 pre_personalizer[2];
	u8 ic_pre_personalization_data[2];
	u8 ic_pre_personalization_id[4];
	u8 ic_personalizaer[2];
	u8 ic_personalization_data[2];
	u8 ic_personalization_id[4];
} global_platform_cplc_data_t;

int gp_select_aid(struct sc_card *card, const struct sc_aid *aid);
int gp_select_card_manager(struct sc_card *card);
int gp_select_isd_rid(struct sc_card *card);
int gp_get_cplc_data(struct sc_card *card, global_platform_cplc_data_t *cplc_data);

#ifdef __cplusplus
}
#endif

#endif
