/*
 * sm-module.h: Support for the external Secure Messaging module for
 *               IAS/ECC and 'AuthentIC v3' cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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

#ifndef _SM_MODULE_H
#define _SM_MODULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/des.h>
#include <openssl/sha.h>

#include "libopensc/sm.h"
#include "sm/sm-common.h"

/* Global Platform definitions */
int sm_gp_get_mac(struct sc_context *ctx,
		unsigned char *key, sm_des_cblock *icv,
		unsigned char *in, int in_len,
		sm_des_cblock *out);
int sm_gp_get_cryptogram(struct sc_context *ctx, unsigned char *session_key,
		unsigned char *left, unsigned char *right,
		unsigned char *out, int out_len);
int sm_gp_external_authentication(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len,
		struct sc_remote_data *out,
		int (*diversify_keyset)(struct sc_context *ctx, struct sm_info *sm_info,
			unsigned char *idata, size_t idata_len));
int sm_gp_initialize(struct sc_context *ctx, struct sm_info *sm_info,
		struct sc_remote_data *out);
int sm_gp_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info,
		char *init_data, struct sc_apdu *apdu);
int sm_gp_decode_card_answer(struct sc_context *ctx, struct sc_remote_data *rdata,
		unsigned char *out, size_t out_len);
void sm_gp_close_session(struct sc_context *ctx, struct sm_gp_session *gp_session);


/* CWA-14890 helper functions */
int sm_cwa_initialize(struct sc_context *ctx, struct sm_info *sm_info,
		struct sc_remote_data *out);
int sm_cwa_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *out, int release_sm);
int sm_cwa_decode_card_data(struct sc_context *ctx, struct sm_info *sm_info, char *str_data,
		unsigned char *out, size_t out_len);
int sm_cwa_securize_apdu(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_apdu *rapdu);
int sm_cwa_decode_authentication_data(struct sc_context *ctx, struct sm_cwa_keyset *keyset,
		struct sm_cwa_session *session_data, unsigned char *auth_data);
int sm_cwa_init_session_keys(struct sc_context *ctx, struct sm_cwa_session *session_data,
		unsigned char mechanism);

/* SM AuthentIC v3 definitions */
int sm_authentic_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *out, int release_sm);

/* SM IAS/ECC definitions */
int sm_iasecc_get_apdus(struct sc_context *ctx, struct sm_info *sm_info,
		unsigned char *init_data, size_t init_len, struct sc_remote_data *out, int release_sm);
int sm_iasecc_decode_card_data(struct sc_context *ctx, struct sm_info *sm_info, struct sc_remote_data *rdata,
		unsigned char *out, size_t out_len);
#ifdef __cplusplus
}
#endif

#endif

