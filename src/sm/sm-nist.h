/*
 * Copyright (C) 2011-2015 Frank Morgner
 * Copyright (C) 2025 Douglas E. Engert <deengert@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/**
 * @file
 * @defgroup NIST 800-73-4 Secure Messaging
 * @{
 */
#ifndef _SC_SM_NIST_H
#define _SC_SM_NIST_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_ZLIB
#include "libopensc/compression.h"
#endif
#include "libopensc/opensc.h"
#include "libopensc/internal.h"
#include "sm/sm-iso.h"

#define PIV_PAIRING_CODE_LEN	8

/* for sm_flags  must match flag in card-piv.c*/

#define PIV_SM_FLAGS_SM_CERT_SIGNER_VERIFIED	0x00000001lu
#define PIV_SM_FLAGS_SM_CVC_VERIFIED		0x00000002lu
#define PIV_SM_FLAGS_SM_IN_CVC_VERIFIED		0x00000004lu
#define PIV_SM_FLAGS_SM_CERT_SIGNER_PRESENT	0x00000010lu
#define PIV_SM_FLAGS_SM_CVC_PRESENT		0x00000020lu
#define PIV_SM_FLAGS_SM_IN_CVC_PRESENT		0x00000040lu
#define PIV_SM_FLAGS_SM_IS_ACTIVE		0x00000080lu	/* SM has been started */
	/* if card supports SP800-73-4 SM: */
#define PIV_SM_FLAGS_NEVER			0x00000100lu	/* Don't use SM even if card support it */
								/* Default is use if card supports it */
								/* will use VCI if card supports it for contactless */
#define PIV_SM_FLAGS_ALWAYS			0x00000200lu	/* Use SM or quit, VCI requires SM */
#define PIV_SM_FLAGS_DEFER_OPEN			0x00001000lu	/* call sm_open from reader_lock_obtained */
#define PIV_SM_VCI_ACTIVE			0x00002000lu    /* VCI is active */
#define PIV_SM_GET_DATA_IN_CLEAR		0x00004000lu	/* OK to do this GET DATA in the clear */
#define PIV_SM_FLAGS_SM_CERT_SIGNER_COMPRESSED	0x00008000lu	/* compressed */
#define PIV_SM_CONTACTLESS			0x00010000lu	/* contacless */

#ifdef __cplusplus
extern "C" {
#endif

int
sm_nist_start(sc_card_t *card,
		u8 *signer_cert, size_t signer_cert_len,
		u8 *sm_in_cvc, size_t sm_in_len,
		unsigned long *sm_flags, /* shared with caller */
		unsigned long pin_policy,
		u8 pairing_code[PIV_PAIRING_CODE_LEN],
		u8 cipher_suite_id);

#ifdef  __cplusplus
}
#endif
#endif
/* @} */
