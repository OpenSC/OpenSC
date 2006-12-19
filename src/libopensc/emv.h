/*
 * emv.h: OpenSC EMV header file
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

#ifndef _OPENSC_EMV_H
#define _OPENSC_EMV_H

#include <opensc/opensc.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sc_emv_card {
	struct sc_card *card;
};

int sc_emv_bind(struct sc_card *card, struct sc_emv_card **emv_card);
int sc_emv_unbind(struct sc_emv_card *emv_card);

#ifdef __cplusplus
}
#endif

#endif
