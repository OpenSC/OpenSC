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
#include "libopensc/internal.h"
#include "libopensc/opensc.h"
#include "sm/sm-iso.h"

#define PIV_PAIRING_CODE_LEN 8

/* sm_flags */

#define NIST_SM_FLAGS_SM_CERT_SIGNER_VERIFIED	0x00000001lu
#define NIST_SM_FLAGS_SM_CVC_VERIFIED		0x00000002lu
#define NIST_SM_FLAGS_SM_IN_CVC_VERIFIED	0x00000004lu
#define NIST_SM_FLAGS_SM_CERT_SIGNER_PRESENT	0x00000010lu
#define NIST_SM_FLAGS_SM_CVC_PRESENT		0x00000020lu
#define NIST_SM_FLAGS_SM_IN_CVC_PRESENT		0x00000040lu
#define NIST_SM_FLAGS_SM_IS_ACTIVE		0x00000080lu /* SM has been started */
#define NIST_SM_FLAGS_NEVER			0x00000100lu /* Don't use SM even if card support it */
/* Default is use if card supports it */
/* will use VCI if card supports it for contactless */
#define NIST_SM_FLAGS_ALWAYS			0x00000200lu /* Use SM or quit, VCI requires SM */
#define NIST_SM_FLAGS_DEFER_OPEN		0x00001000lu /* call sm_open from reader_lock_obtained */
#define NIST_SM_VCI_ACTIVE			0x00002000lu /* VCI is active */
#define NIST_SM_GET_DATA_IN_CLEAR		0x00004000lu /* OK to do this GET DATA in the clear */
#define NIST_SM_FLAGS_SM_CERT_SIGNER_COMPRESSED 0x00008000lu /* compressed */
#define NIST_SM_CONTACTLESS			0x00010000lu /* contacless */
#define NIST_SM_FLAGS_FORCE_SM_ON		0x00020000lu /* override sm_nist_pre and use SM */
#define NIST_SM_FLAGS_FORCE_SM_OFF		0x00040000lu /* override sm-nist_pre and not use SM */
#define NIST_SM_FLAGS_SM_CLOSE_ACCEPT_ERRORS	0x00080000lu /* Don't close on errors */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parameters shared between card driver and sm_nist
 * Owned by card driver and cleared by sc_nist_parms_cleanup
 */

typedef struct sm_nist_params {
	unsigned long flags; /* NIST_SM_* */
	u8 *signer_cert_der;
	size_t signer_cert_der_len;
	u8 *sm_in_cvc_der;
	size_t sm_in_cvc_der_len;
	unsigned long pin_policy;
	u8 pairing_code[PIV_PAIRING_CODE_LEN];
	u8 csID; /* 0x27 or 0x2E */
	u8 last_sw1;
	u8 last_sw2;
} sm_nist_params_t;

int
sm_nist_start(sc_card_t *card, sm_nist_params_t *params);

int
sm_nist_open(sc_card_t *card);


int
sm_nist_params_cleanup(sm_nist_params_t *params);

#ifdef __cplusplus
}
#endif
#endif
/* @} */
