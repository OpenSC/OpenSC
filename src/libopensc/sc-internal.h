/*
 * sc-internal.h: Internal definitions for libopensc
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

#ifndef _LIBOPENSC_H
#define _LIBOPENSC_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "opensc.h"

#define SC_FILE_MAGIC			0x14426950
#define SC_CARD_MAGIC			0x27182818

/* Internal use only */
int sc_sw_to_errorcode(struct sc_card *card, int sw1, int sw2);

#endif
