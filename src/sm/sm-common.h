/*
 * sm-commot.h: Common SM cryptographic procedures
 *
 * Copyright (C) 2013  Viktor Tarasov <viktor.tarasov@gmail.com>
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

#ifndef _SM_COMMON_H
#define _SM_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/des.h>
#include <openssl/sha.h>

#include "libopensc/sm.h"

unsigned int DES_cbc_cksum_3des(struct sc_context *ctx,
		const unsigned char *in, sm_des_cblock *output, long length,
		unsigned char *key, sm_const_des_cblock *ivec);
unsigned int DES_cbc_cksum_3des_emv96(struct sc_context *ctx,
		const unsigned char *in, sm_des_cblock *output,
		long length, unsigned char *key,
		sm_const_des_cblock *ivec);
int sm_encrypt_des_ecb3(struct sc_context *ctx,
		unsigned char *key, unsigned char *data, int data_len,
		unsigned char **out, int *out_len);
int sm_encrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int
		not_force_pad);
int sm_decrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		unsigned char *data, size_t data_len, unsigned char **out, size_t *out_len);
void sm_incr_ssc(unsigned char *ssc, size_t ssc_len);
#ifdef __cplusplus
}
#endif

#endif

