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

DES_LONG DES_cbc_cksum_3des(const unsigned char *in, DES_cblock *output, long length,
		DES_key_schedule *schedule, DES_key_schedule *schedule2, const_DES_cblock *ivec);
DES_LONG DES_cbc_cksum_3des_emv96(const unsigned char *in, DES_cblock *output,
		long length, DES_key_schedule *schedule, DES_key_schedule *schedule2,
		const_DES_cblock *ivec);
int sm_encrypt_des_ecb3(unsigned char *key, unsigned char *data, int data_len,
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

