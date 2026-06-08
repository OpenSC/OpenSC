/*
 * card-srbeid.h: Shared definitions for Serbian CardEdge card and PKCS#15 drivers.
 *
 * Copyright (C) 2026 LibreSCRS contributors
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef CARD_SRBEID_H
#define CARD_SRBEID_H

#include "types.h"

/* CardEdge PKI applet AID  (A0 00 00 00 63 50 4B 43 53 2D 31 35) */
static const u8 AID_PKCS15[] = {
		0xA0, 0x00, 0x00, 0x00, 0x63,
		0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
#define AID_PKCS15_LEN (sizeof(AID_PKCS15))

/* Base address of key files: key FID = CE_KEYS_BASE_FID | container/type bits */
#define CE_KEYS_BASE_FID 0x6000u

#endif /* CARD_SRBEID_H */
