/*
 * jpki.h: Support for JPKI(Japanese Individual Number Cards).
 *
 * Copyright (C) 2016, HAMANO Tsukasa <hamano@osstech.co.jp>
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

#ifndef _OPENSC_JPKI_H
#define _OPENSC_JPKI_H

#define SELECT_MF 0
#define SELECT_JPKI_AP 1

#define AID_JPKI "D392f000260100000001"
#define JPKI_AUTH_KEY "0017"
#define JPKI_AUTH_PIN "0018"

#define JPKI_SIGN_KEY "001A"
#define JPKI_SIGN_PIN "001B"

#define JPKI_DRVDATA(card) ((struct jpki_private_data *) ((card)->drv_data))

struct jpki_private_data {
	sc_file_t *mf;
	int selected;
};

int jpki_select_ap(struct sc_card *card);

#endif
