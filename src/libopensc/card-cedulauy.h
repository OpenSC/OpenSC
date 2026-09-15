/*
 * card-cedulauy.h: Constants of the Uruguayan eID card (cédula de identidad)
 *
 * Copyright (C) 2026 Nicolás Gutiérrez <ngutierreztassano@gmail.com>
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

#ifndef _CARD_CEDULAUY_H
#define _CARD_CEDULAUY_H

/* IAS application AID (AGESIC, documented) */
static const unsigned char cedulauy_aid[] = {
		0xA0, 0x00, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x01, 0x63, 0x42, 0x00};

/* Public identity data files under DF 7000 (AGESIC layout), all readable
 * without PIN; absolute paths, the MF is emulated by the driver */
#define CEDULAUY_DF_PATH	 "3F007000"
#define CEDULAUY_DOC_NUMBER_PATH CEDULAUY_DF_PATH "7001"
#define CEDULAUY_BIO_DATA_PATH	 CEDULAUY_DF_PATH "7002"
#define CEDULAUY_PHOTO_PATH	 CEDULAUY_DF_PATH "7004"
#define CEDULAUY_MRZ_PATH	 CEDULAUY_DF_PATH "700B"

#endif
