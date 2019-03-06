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

#include "libopensc/types.h"

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
	SC_CARD_TYPE_CARDOS_CIE_V1, /* Italian CIE (eID) v1 */
	SC_CARD_TYPE_CARDOS_M4_4,
	SC_CARD_TYPE_CARDOS_V5_0,

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
	SC_CARD_TYPE_MCRD_ESTEID_V30,
	SC_CARD_TYPE_MCRD_DTRUST,

	/* setcos driver */
	SC_CARD_TYPE_SETCOS_BASE = 6000,
	SC_CARD_TYPE_SETCOS_GENERIC,
	SC_CARD_TYPE_SETCOS_PKI,
	SC_CARD_TYPE_SETCOS_FINEID,
	SC_CARD_TYPE_SETCOS_FINEID_V2,
	SC_CARD_TYPE_SETCOS_NIDEL,
	SC_CARD_TYPE_SETCOS_FINEID_V2_2048,
	SC_CARD_TYPE_SETCOS_44 = 6100,
	SC_CARD_TYPE_SETCOS_EID_V2_0,
	SC_CARD_TYPE_SETCOS_EID_V2_1,

	/* starcos driver */
	SC_CARD_TYPE_STARCOS_BASE = 7000,
	SC_CARD_TYPE_STARCOS_GENERIC,
	SC_CARD_TYPE_STARCOS_V3_4,
	SC_CARD_TYPE_STARCOS_V3_5,

	/* tcos driver */
	SC_CARD_TYPE_TCOS_BASE = 8000,
	SC_CARD_TYPE_TCOS_GENERIC,
	SC_CARD_TYPE_TCOS_V2,
	SC_CARD_TYPE_TCOS_V3,

	/* openpgp driver */
	SC_CARD_TYPE_OPENPGP_BASE = 9000,
	SC_CARD_TYPE_OPENPGP_V1,
	SC_CARD_TYPE_OPENPGP_V2,
	SC_CARD_TYPE_OPENPGP_V3,
	SC_CARD_TYPE_OPENPGP_GNUK,

	/* jcop driver */
	SC_CARD_TYPE_JCOP_BASE = 10000,
	SC_CARD_TYPE_JCOP_GENERIC,

	/* oberthur driver */
	SC_CARD_TYPE_OBERTHUR_BASE = 11000,
	SC_CARD_TYPE_OBERTHUR_GENERIC,
	SC_CARD_TYPE_OBERTHUR_32K,
	SC_CARD_TYPE_OBERTHUR_32K_BIO,
	SC_CARD_TYPE_OBERTHUR_64K,
	/* Oberthur 'COSMO v7' with applet 'AuthentIC v3.2' */
        SC_CARD_TYPE_OBERTHUR_AUTHENTIC_3_2 = 11100,

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
	SC_CARD_TYPE_PIV_II_HIST,
	SC_CARD_TYPE_PIV_II_NEO,
	SC_CARD_TYPE_PIV_II_YUBIKEY4,
	SC_CARD_TYPE_PIV_II_GI_DE_DUAL_CAC,
	SC_CARD_TYPE_PIV_II_GI_DE,
	SC_CARD_TYPE_PIV_II_GEMALTO_DUAL_CAC,
	SC_CARD_TYPE_PIV_II_GEMALTO,
	SC_CARD_TYPE_PIV_II_OBERTHUR_DUAL_CAC,
	SC_CARD_TYPE_PIV_II_OBERTHUR,
	SC_CARD_TYPE_PIV_II_PIVKEY,

	/* MuscleApplet */
	SC_CARD_TYPE_MUSCLE_BASE = 15000,
	SC_CARD_TYPE_MUSCLE_GENERIC,
	SC_CARD_TYPE_MUSCLE_V1,
	SC_CARD_TYPE_MUSCLE_V2,
	SC_CARD_TYPE_MUSCLE_ETOKEN_72K,
	SC_CARD_TYPE_MUSCLE_JCOP241,
	SC_CARD_TYPE_MUSCLE_JCOP242R2_NO_EXT_APDU,

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
	SC_CARD_TYPE_ENTERSAFE_FTCOS_PK_01C,
	SC_CARD_TYPE_ENTERSAFE_FTCOS_EPASS2003,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_PK_01C,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_PK_01C_T0,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_H10CR_PK_01C_T1,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_D11CR_PK_01C_T1,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_C21C_PK_01C_T1,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_A22CR_PK_01C_T1,
	SC_CARD_TYPE_ENTERSAFE_EJAVA_A40CR_PK_01C_T1,

	/* MyEID cards */
	SC_CARD_TYPE_MYEID_BASE = 20000,
	SC_CARD_TYPE_MYEID_GENERIC,

	/* GemsafeV1 cards */
	SC_CARD_TYPE_GEMSAFEV1_BASE = 21000,
	SC_CARD_TYPE_GEMSAFEV1_GENERIC,
	SC_CARD_TYPE_GEMSAFEV1_PTEID,
	SC_CARD_TYPE_GEMSAFEV1_SEEID,

	/* Italian CNS cards */
	SC_CARD_TYPE_ITACNS_BASE = 23000,
	SC_CARD_TYPE_ITACNS_GENERIC,
	SC_CARD_TYPE_ITACNS_CNS,
	SC_CARD_TYPE_ITACNS_CIE_V2,
	SC_CARD_TYPE_ITACNS_CIE_V1,

	/* Generic JavaCards without supported applet */
	SC_CARD_TYPE_JAVACARD_BASE = 24000,
	SC_CARD_TYPE_JAVACARD,

	/* IAS/ECC cards */
	SC_CARD_TYPE_IASECC_BASE = 25000,
	SC_CARD_TYPE_IASECC_GEMALTO,
	SC_CARD_TYPE_IASECC_OBERTHUR,
	SC_CARD_TYPE_IASECC_SAGEM,
	SC_CARD_TYPE_IASECC_AMOS,
	SC_CARD_TYPE_IASECC_MI,
	SC_CARD_TYPE_IASECC_MI2,

	/* SmartCard-HSM */
	SC_CARD_TYPE_SC_HSM = 26000,
	SC_CARD_TYPE_SC_HSM_SOC = 26001,
	SC_CARD_TYPE_SC_HSM_GOID = 26002,

	/* Spanish DNIe card */
	SC_CARD_TYPE_DNIE_BASE = 27000,
	SC_CARD_TYPE_DNIE_BLANK, /* ATR LC byte: 00 */
	SC_CARD_TYPE_DNIE_ADMIN, /* ATR LC byte: 01 */
	SC_CARD_TYPE_DNIE_USER,  /* ATR LC byte: 03 */
	SC_CARD_TYPE_DNIE_TERMINATED, /* ATR LC byte: 0F */

	/* JavaCards with isoApplet */
	SC_CARD_TYPE_ISO_APPLET_BASE = 28000,
	SC_CARD_TYPE_ISO_APPLET_GENERIC,

	/* Masktech cards */
	SC_CARD_TYPE_MASKTECH_BASE = 29000,
	SC_CARD_TYPE_MASKTECH_GENERIC,

	/* GIDS cards */
	SC_CARD_TYPE_GIDS_BASE = 30000,
	SC_CARD_TYPE_GIDS_GENERIC,
	SC_CARD_TYPE_GIDS_V1,
	SC_CARD_TYPE_GIDS_V2,

	/* JPKI cards */
	SC_CARD_TYPE_JPKI_BASE = 31000,

	SC_CARD_TYPE_COOLKEY_BASE = 32000,
	SC_CARD_TYPE_COOLKEY_GENERIC,

	/* CAC cards */
	SC_CARD_TYPE_CAC_BASE = 33000,
	SC_CARD_TYPE_CAC_GENERIC,
	SC_CARD_TYPE_CAC_I,
	SC_CARD_TYPE_CAC_II,

	/* nPA cards */
	SC_CARD_TYPE_NPA = 34000,
	SC_CARD_TYPE_NPA_TEST,
	SC_CARD_TYPE_NPA_ONLINE,
};

extern sc_card_driver_t *sc_get_default_driver(void);
extern sc_card_driver_t *sc_get_cardos_driver(void);
extern sc_card_driver_t *sc_get_cryptoflex_driver(void);
extern sc_card_driver_t *sc_get_cyberflex_driver(void);
extern sc_card_driver_t *sc_get_gpk_driver(void);
extern sc_card_driver_t *sc_get_gemsafeV1_driver(void);
extern sc_card_driver_t *sc_get_miocos_driver(void);
extern sc_card_driver_t *sc_get_mcrd_driver(void);
extern sc_card_driver_t *sc_get_setcos_driver(void);
extern sc_card_driver_t *sc_get_starcos_driver(void);
extern sc_card_driver_t *sc_get_tcos_driver(void);
extern sc_card_driver_t *sc_get_openpgp_driver(void);
extern sc_card_driver_t *sc_get_jcop_driver(void);
extern sc_card_driver_t *sc_get_oberthur_driver(void);
extern sc_card_driver_t *sc_get_belpic_driver(void);
extern sc_card_driver_t *sc_get_atrust_acos_driver(void);
extern sc_card_driver_t *sc_get_incrypto34_driver(void);
extern sc_card_driver_t *sc_get_piv_driver(void);
extern sc_card_driver_t *sc_get_muscle_driver(void);
extern sc_card_driver_t *sc_get_asepcos_driver(void);
extern sc_card_driver_t *sc_get_akis_driver(void);
extern sc_card_driver_t *sc_get_entersafe_driver(void);
extern sc_card_driver_t *sc_get_rutoken_driver(void);
extern sc_card_driver_t *sc_get_rtecp_driver(void);
extern sc_card_driver_t *sc_get_westcos_driver(void);
extern sc_card_driver_t *sc_get_myeid_driver(void);
extern sc_card_driver_t *sc_get_sc_hsm_driver(void);
extern sc_card_driver_t *sc_get_itacns_driver(void);
extern sc_card_driver_t *sc_get_authentic_driver(void);
extern sc_card_driver_t *sc_get_iasecc_driver(void);
extern sc_card_driver_t *sc_get_epass2003_driver(void);
extern sc_card_driver_t *sc_get_dnie_driver(void);
extern sc_card_driver_t *sc_get_isoApplet_driver(void);
extern sc_card_driver_t *sc_get_masktech_driver(void);
extern sc_card_driver_t *sc_get_gids_driver(void);
extern sc_card_driver_t *sc_get_jpki_driver(void);
extern sc_card_driver_t *sc_get_coolkey_driver(void);
extern sc_card_driver_t *sc_get_cac_driver(void);
extern sc_card_driver_t *sc_get_cac1_driver(void);
extern sc_card_driver_t *sc_get_npa_driver(void);

#ifdef __cplusplus
}
#endif

#endif /* _OPENSC_CARDS_H */
