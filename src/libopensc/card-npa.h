/*
 * Copyright (C) 2014-2015 Frank Morgner
 *
 * This file is part of OpenSC.
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

#ifndef _CARD_NPA_H
#define _CARD_NPA_H

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char esign_chat[] = {
	0x7F, 0x4C, 0x0E,
		0x06, 0x09, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x03, 0x01, 0x02, 0x03,
		0x53, 0x01, 0x03,
};

const unsigned char df_esign_aid[]  = { 0xa0, 0x00, 0x00, 0x01, 0x67, 0x45, 0x53, 0x49, 0x47, 0x4e};

#ifdef  __cplusplus
}
#endif
#endif
