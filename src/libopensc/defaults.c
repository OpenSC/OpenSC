/*
 * sc-default.c: Card specific defaults
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

#include "opensc.h"
#include "opensc-pkcs15.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int fineid_defaults(void *arg)
{
	struct sc_card *card = (struct sc_card *) arg;
	
	card->cla = 0;
	
	return 0;
}

static int multiflex_defaults(void *arg)
{
	struct sc_card *card = (struct sc_card *) arg;
	
	card->cla = 0xC0;
	return 0;
}

const struct sc_defaults sc_card_table[] = {
	{ "3B:9F:94:40:1E:00:67:11:43:46:49:53:45:10:52:66:FF:81:90:00", fineid_defaults },
	{ "3B:19:14:55:90:01:02:02:00:05:04:B0", multiflex_defaults },
	{ NULL, NULL }
};
