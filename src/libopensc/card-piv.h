/*
 * card-piv.h
 *
 * Copyright (C) 2021 Frank Morgner <frankmorgner@gmail.com>
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

#ifndef CARD_PIV_H_
#define CARD_PIV_H_

enum piv_enumtag {
	PIV_OBJ_CCC = 0,
	PIV_OBJ_CHUI,
	/*  PIV_OBJ_UCHUI is not in new with 800-73-2 */
	PIV_OBJ_X509_PIV_AUTH,
	PIV_OBJ_CHF,
	PIV_OBJ_PI,
	PIV_OBJ_CHFI,
	PIV_OBJ_X509_DS,
	PIV_OBJ_X509_KM,
	PIV_OBJ_X509_CARD_AUTH,
	PIV_OBJ_SEC_OBJ,
	PIV_OBJ_DISCOVERY,
	PIV_OBJ_HISTORY,
	PIV_OBJ_RETIRED_X509_1,
	PIV_OBJ_RETIRED_X509_2,
	PIV_OBJ_RETIRED_X509_3,
	PIV_OBJ_RETIRED_X509_4,
	PIV_OBJ_RETIRED_X509_5,
	PIV_OBJ_RETIRED_X509_6,
	PIV_OBJ_RETIRED_X509_7,
	PIV_OBJ_RETIRED_X509_8,
	PIV_OBJ_RETIRED_X509_9,
	PIV_OBJ_RETIRED_X509_10,
	PIV_OBJ_RETIRED_X509_11,
	PIV_OBJ_RETIRED_X509_12,
	PIV_OBJ_RETIRED_X509_13,
	PIV_OBJ_RETIRED_X509_14,
	PIV_OBJ_RETIRED_X509_15,
	PIV_OBJ_RETIRED_X509_16,
	PIV_OBJ_RETIRED_X509_17,
	PIV_OBJ_RETIRED_X509_18,
	PIV_OBJ_RETIRED_X509_19,
	PIV_OBJ_RETIRED_X509_20,
	PIV_OBJ_IRIS_IMAGE,
	PIV_OBJ_9B03,
	PIV_OBJ_9A06,
	PIV_OBJ_9C06,
	PIV_OBJ_9D06,
	PIV_OBJ_9E06,
	PIV_OBJ_8206,
	PIV_OBJ_8306,
	PIV_OBJ_8406,
	PIV_OBJ_8506,
	PIV_OBJ_8606,
	PIV_OBJ_8706,
	PIV_OBJ_8806,
	PIV_OBJ_8906,
	PIV_OBJ_8A06,
	PIV_OBJ_8B06,
	PIV_OBJ_8C06,
	PIV_OBJ_8D06,
	PIV_OBJ_8E06,
	PIV_OBJ_8F06,
	PIV_OBJ_9006,
	PIV_OBJ_9106,
	PIV_OBJ_9206,
	PIV_OBJ_9306,
	PIV_OBJ_9406,
	PIV_OBJ_9506,
	PIV_OBJ_LAST_ENUM
};

struct piv_object {
	int enumtag;
	const char * name;
	const char * oidstring;
	size_t tag_len;
	u8  tag_value[3];
	u8  containerid[2];	/* will use as relative paths for simulation */
	int flags;              /* object has some internal object like a cert */
};

extern const struct piv_object piv_objects[];

#endif
