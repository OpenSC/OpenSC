/*
 * cards.h: Registered card types for sc_card_t->type
 *
 * Copyright (C) 2005  Antti Tapaninen <aet@cc.hut.fi>
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

#ifndef _OPENSC_CARDS_H
#define _OPENSC_CARDS_H

#include <opensc/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	/* Generic card types */
	SC_CARD_TYPE_UNKNOWN = -1,
	SC_CARD_TYPE_GENERIC_BASE = 0,
	SC_CARD_TYPE_GENERIC,

	/* Cards without registered type, yet */
	SC_CARD_TYPE_TEST_BASE = 500,

	/* cardos driver */
	SC_CARD_TYPE_CARDOS_BASE = 1000,
	SC_CARD_TYPE_CARDOS_GENERIC,
	SC_CARD_TYPE_CARDOS_M4_01,
	SC_CARD_TYPE_CARDOS_M4_2,
	SC_CARD_TYPE_CARDOS_M4_3,
	SC_CARD_TYPE_CARDOS_M4_2B, /* 4.2b is after 4.3b */
	SC_CARD_TYPE_CARDOS_M4_2C,

	/* flex/cyberflex drivers */
	SC_CARD_TYPE_FLEX_BASE = 2000,
	SC_CARD_TYPE_FLEX_GENERIC,
	SC_CARD_TYPE_FLEX_CRYPTO,
	SC_CARD_TYPE_FLEX_MULTI,
	SC_CARD_TYPE_FLEX_CYBER,

	/* gpk driver */
	SC_CARD_TYPE_GPK_BASE = 3000,
	SC_CARD_TYPE_GPK_GENERIC,
	SC_CARD_TYPE_GPK_GPK4000_su256 = 3040,
	SC_CARD_TYPE_GPK_GPK4000_s,
	SC_CARD_TYPE_GPK_GPK4000_sp,
	SC_CARD_TYPE_GPK_GPK4000_sdo,
	SC_CARD_TYPE_GPK_GPK8000 = 3080,
	SC_CARD_TYPE_GPK_GPK8000_8K,
	SC_CARD_TYPE_GPK_GPK8000_16K,
	SC_CARD_TYPE_GPK_GPK16000 = 3160,

	/* miocos driver */
	SC_CARD_TYPE_MIOCOS_BASE = 4000,
	SC_CARD_TYPE_MIOCOS_GENERIC,

	/* mcrd driver */
	SC_CARD_TYPE_MCRD_BASE = 5000,
	SC_CARD_TYPE_MCRD_GENERIC,
	SC_CARD_TYPE_MCRD_ESTEID,
	SC_CARD_TYPE_MCRD_DTRUST,

	/* setcos driver */
	SC_CARD_TYPE_SETCOS_BASE = 6000,
	SC_CARD_TYPE_SETCOS_GENERIC,
	SC_CARD_TYPE_SETCOS_PKI,
	SC_CARD_TYPE_SETCOS_FINEID,
	SC_CARD_TYPE_SETCOS_FINEID_V2,
	SC_CARD_TYPE_SETCOS_NIDEL,
	SC_CARD_TYPE_SETCOS_44 = 6100,
	SC_CARD_TYPE_SETCOS_EID_V2_0,
	SC_CARD_TYPE_SETCOS_EID_V2_1,

	/* starcos driver */
	SC_CARD_TYPE_STARCOS_BASE = 7000,
	SC_CARD_TYPE_STARCOS_GENERIC,

	/* tcos driver */
	SC_CARD_TYPE_TCOS_BASE = 8000,
	SC_CARD_TYPE_TCOS_GENERIC,
	SC_CARD_TYPE_TCOS_V2,
	SC_CARD_TYPE_TCOS_V3,

	/* openpgp driver */
	SC_CARD_TYPE_OPENPGP_BASE = 9000,
	SC_CARD_TYPE_OPENPGP_GENERIC,

	/* jcop driver */
	SC_CARD_TYPE_JCOP_BASE = 10000,
	SC_CARD_TYPE_JCOP_GENERIC,

	/* oberthur driver */
	SC_CARD_TYPE_OBERTHUR_BASE = 11000,
	SC_CARD_TYPE_OBERTHUR_GENERIC,
	SC_CARD_TYPE_OBERTHUR_32K,
	SC_CARD_TYPE_OBERTHUR_32K_BIO,
	SC_CARD_TYPE_OBERTHUR_64K,

	/* belpic driver */
	SC_CARD_TYPE_BELPIC_BASE = 12000,
	SC_CARD_TYPE_BELPIC_GENERIC,
	SC_CARD_TYPE_BELPIC_EID,

	/* incrypto34 driver */
	SC_CARD_TYPE_INCRYPTO34_BASE = 13000,
	SC_CARD_TYPE_INCRYPTO34_GENERIC,

	/* PIV-II type cards */
	SC_CARD_TYPE_PIV_II_BASE = 14000,
	SC_CARD_TYPE_PIV_II_GENERIC,
	
	/* Muscle cards */
	SC_CARD_TYPE_MUSCLE_BASE = 15000,
	SC_CARD_TYPE_MUSCLE_GENERIC,

	/* ACOS5 driver */
	SC_CARD_TYPE_ACOS5_BASE = 16000,
	SC_CARD_TYPE_ACOS5_GENERIC,

	/* Athena APCOS cards */
	SC_CARD_TYPE_ASEPCOS_BASE = 17000,
	SC_CARD_TYPE_ASEPCOS_GENERIC,
	SC_CARD_TYPE_ASEPCOS_JAVA,

	/* TUBITAK UEKAE cards */
	SC_CARD_TYPE_AKIS_BASE = 18000,
	SC_CARD_TYPE_AKIS_GENERIC,

	/* EnterSafe cards */
	SC_CARD_TYPE_ENTERSAFE_BASE = 19000,
	SC_CARD_TYPE_ENTERSAFE_3K,
};

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDS_H */
