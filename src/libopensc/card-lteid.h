/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _CARD_LTEID_H
#define _CARD_LTEID_H

#define DRVDATA(card)	 ((struct lteid_drv_data *)((card)->drv_data))
#define LTEID_CAN_LENGTH 6

struct lteid_drv_data {
	unsigned char pace;
	unsigned char pace_pin_ref;
	unsigned char can[LTEID_CAN_LENGTH];
	unsigned char can_from_file;
};

#endif