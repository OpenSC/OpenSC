/*
 * sm-common.c: Common cryptographic procedures related to
 *		Secure Messaging
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#ifndef ENABLE_OPENSSL
#error "Need OpenSSL"
#endif

#include <openssl/des.h>
#include <openssl/sha.h>

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"

#include "sm-common.h"

/*
 * From crypto/des/des_locl.h of OpenSSL .
 */
#define c2l(c,l)	(l =((DES_LONG)(*((c)++)))	, \
			 l|=((DES_LONG)(*((c)++)))<< 8L, \
			 l|=((DES_LONG)(*((c)++)))<<16L, \
			 l|=((DES_LONG)(*((c)++)))<<24L)

#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((DES_LONG)(*(--(c))))<<24L; \
			case 7: l2|=((DES_LONG)(*(--(c))))<<16L; \
			case 6: l2|=((DES_LONG)(*(--(c))))<< 8L; \
			case 5: l2|=((DES_LONG)(*(--(c))));	 \
			case 4: l1 =((DES_LONG)(*(--(c))))<<24L; \
			case 3: l1|=((DES_LONG)(*(--(c))))<<16L; \
			case 2: l1|=((DES_LONG)(*(--(c))))<< 8L; \
			case 1: l1|=((DES_LONG)(*(--(c))));	 \
				} \
			}

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)	 )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24L)&0xff))


/*
 * Inspired by or taken from OpenSSL crypto/des/cbc3_enc.c
 */
static void
DES_3cbc_encrypt(DES_cblock *input, DES_cblock *output, long length,
		 DES_key_schedule *ks1, DES_key_schedule *ks2, DES_cblock *iv,
		 int enc)
	{
	int off=((int)length-1)/8;
	long l8=((length+7)/8)*8;
	DES_cblock icv_out;

	memset(&icv_out, 0, sizeof(icv_out));
	if (enc == DES_ENCRYPT)   {
		DES_cbc_encrypt((unsigned char*)input,
				(unsigned char*)output,length,ks1,iv,enc);
		DES_cbc_encrypt((unsigned char*)output,
				(unsigned char*)output,l8,ks2,iv,!enc);
		DES_cbc_encrypt((unsigned char*)output,
				(unsigned char*)output,l8,ks1,iv,enc);
		if ((unsigned)length >= sizeof(DES_cblock))
			memcpy(icv_out,output[off],sizeof(DES_cblock));
	}
	else   {
		if ((unsigned)length >= sizeof(DES_cblock))
			memcpy(icv_out,input[off],sizeof(DES_cblock));
		DES_cbc_encrypt((unsigned char*)input,
				(unsigned char*)output,l8,ks1,iv,enc);
		DES_cbc_encrypt((unsigned char*)output,
				(unsigned char*)output,l8,ks2,iv,!enc);
		DES_cbc_encrypt((unsigned char*)output,
				(unsigned char*)output,length,ks1,iv,enc);
	}
	memcpy(*iv,icv_out,sizeof(DES_cblock));
}


DES_LONG
DES_cbc_cksum_3des_emv96(const unsigned char *in, DES_cblock *output,
			   long length, DES_key_schedule *schedule, DES_key_schedule *schedule2,
			   const_DES_cblock *ivec)
{
	register DES_LONG tout0,tout1,tin0,tin1;
	register long l=length;
	DES_LONG tin[2];
	unsigned char *out = &(*output)[0];
	const unsigned char *iv = &(*ivec)[0];

	c2l(iv,tout0);
	c2l(iv,tout1);

	for (; l>8; l-=8)   {
		if (l >= 16)
			{
			c2l(in,tin0);
			c2l(in,tin1);
			}
		else
			c2ln(in,tin0,tin1,l);

		tin0^=tout0; tin[0]=tin0;
		tin1^=tout1; tin[1]=tin1;
		DES_encrypt1((DES_LONG *)tin,schedule, DES_ENCRYPT);
		tout0=tin[0];
		tout1=tin[1];
	}

	if (l == 8)   {
		c2l(in,tin0);
		c2l(in,tin1);
	}
	else
		c2ln(in,tin0,tin1,l);

	tin0^=tout0; tin[0]=tin0;
	tin1^=tout1; tin[1]=tin1;
	DES_encrypt3((DES_LONG *)tin,schedule,schedule2,schedule);
	tout0=tin[0];
	tout1=tin[1];

	if (out != NULL)
		{
		l2c(tout0,out);
		l2c(tout1,out);
		}
	tout0=tin0=tin1=tin[0]=tin[1]=0;
	/*
	  Transform the data in tout1 so that it will
	  match the return value that the MIT Kerberos
	  mit_des_cbc_cksum API returns.
	*/
	tout1 = ((tout1 >> 24L) & 0x000000FF)
		  | ((tout1 >> 8L)  & 0x0000FF00)
		  | ((tout1 << 8L)  & 0x00FF0000)
		  | ((tout1 << 24L) & 0xFF000000);
	return(tout1);
}


DES_LONG
DES_cbc_cksum_3des(const unsigned char *in, DES_cblock *output,
		       long length, DES_key_schedule *schedule, DES_key_schedule *schedule2,
		       const_DES_cblock *ivec)
{
	register DES_LONG tout0,tout1,tin0,tin1;
	register long l=length;
	DES_LONG tin[2];
	unsigned char *out = &(*output)[0];
	const unsigned char *iv = &(*ivec)[0];

	c2l(iv,tout0);
	c2l(iv,tout1);

	for (; l>0; l-=8)
		{
		if (l >= 8)
			{
			c2l(in,tin0);
			c2l(in,tin1);
			}
		else
			c2ln(in,tin0,tin1,l);

		tin0^=tout0; tin[0]=tin0;
		tin1^=tout1; tin[1]=tin1;
		DES_encrypt3((DES_LONG *)tin,schedule,schedule2,schedule);
		/* fix 15/10/91 eay - thanks to keithr@sco.COM */
		tout0=tin[0];
		tout1=tin[1];
		}
	if (out != NULL)
		{
		l2c(tout0,out);
		l2c(tout1,out);
		}
	tout0=tin0=tin1=tin[0]=tin[1]=0;
	/*
	  Transform the data in tout1 so that it will
	  match the return value that the MIT Kerberos
	  mit_des_cbc_cksum API returns.
	*/
	tout1 = ((tout1 >> 24L) & 0x000000FF)
	      | ((tout1 >> 8L)  & 0x0000FF00)
	      | ((tout1 << 8L)  & 0x00FF0000)
	      | ((tout1 << 24L) & 0xFF000000);
	return(tout1);
}


int
sm_encrypt_des_ecb3(unsigned char *key, unsigned char *data, int data_len,
		unsigned char **out, int *out_len)
{
	int ii;
	DES_cblock kk,k2;
	DES_key_schedule ks,ks2;


	if (!out || !out_len)
		return -1;


	*out_len = data_len + 7;
	*out_len -= *out_len % 8;

	*out = malloc(*out_len);
	if (!(*out))
		return -1;

	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);

	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);

	for (ii=0; ii<data_len; ii+=8)
		DES_ecb2_encrypt( (DES_cblock *)(data + ii),
				(DES_cblock *)(*out + ii), &ks, &ks2, DES_ENCRYPT);

	return 0;
}


int
sm_decrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		unsigned char *data, size_t data_len,
		unsigned char **out, size_t *out_len)
{
	DES_cblock kk,k2;
	DES_key_schedule ks,ks2;
	DES_cblock icv={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	size_t st;

	LOG_FUNC_CALLED(ctx);
	if (!out || !out_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM decrypt_des_cbc3: invalid input arguments");

	*out_len = data_len + 7;
	*out_len -= *out_len % 8;

	*out = malloc(*out_len);
	if (!(*out))
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM decrypt_des_cbc3: allocation error");

	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);

	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);

	for (st=0; st<data_len; st+=8)
		DES_3cbc_encrypt((DES_cblock *)(data + st),
				(DES_cblock *)(*out + st), 8, &ks, &ks2, &icv, DES_DECRYPT);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int
sm_encrypt_des_cbc3(struct sc_context *ctx, unsigned char *key,
		const unsigned char *in, size_t in_len,
		unsigned char **out, size_t *out_len, int not_force_pad)
{
	DES_cblock kk,k2;
	DES_key_schedule ks,ks2;
	DES_cblock icv={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char *data;
	size_t data_len, st;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM encrypt_des_cbc3: not_force_pad:%i,in_len:%i", not_force_pad, in_len);
	if (!out || !out_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "SM encrypt_des_cbc3: invalid input arguments");

	if (!in)
		in_len = 0;

	*out = NULL;
	*out_len = 0;

	data = malloc(in_len + 8);
	if (data == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM encrypt_des_cbc3: allocation error");

	if (in)
		memcpy(data, in, in_len);

	memcpy(data + in_len, "\x80\0\0\0\0\0\0\0", 8);
	data_len = in_len + (not_force_pad ? 7 : 8);
	data_len -= (data_len%8);
	sc_log(ctx, "SM encrypt_des_cbc3: data to encrypt (len:%i,%s)", data_len, sc_dump_hex(data, data_len));

	*out_len = data_len;
	*out = malloc(data_len + 8);
	if (*out == NULL) {
		free(data);
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SM encrypt_des_cbc3: failure");
	}

	memcpy(&kk, key, 8);
	memcpy(&k2, key + 8, 8);

	DES_set_key_unchecked(&kk,&ks);
	DES_set_key_unchecked(&k2,&ks2);

	for (st=0; st<data_len; st+=8)
		DES_3cbc_encrypt((DES_cblock *)(data + st), (DES_cblock *)(*out + st), 8, &ks, &ks2, &icv, DES_ENCRYPT);

	free(data);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


void
sm_incr_ssc(unsigned char *ssc, size_t ssc_len)
{
	int ii;

	if (!ssc)
		return;

	for (ii = ssc_len - 1;ii >= 0; ii++)   {
		*(ssc + ii) += 1;
		if (*(ssc + ii) != 0)
			break;
	}
}
