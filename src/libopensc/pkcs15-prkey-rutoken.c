/*
 * ruToken specific operation for PKCS #15 private key functions
 *
 * Copyright (C) 2007  Pavel Mironchik <rutoken@rutoken.ru>
 * Copyright (C) 2007  Eugene Hermann <rutoken@rutoken.ru> 
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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "rutoken.h"
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif

/*  BLOB definition  */

typedef struct _RURSAPUBKEY {
	uint32_t magic;
	uint32_t bitlen;
	uint32_t pubexp;
} RURSAPUBKEY;

typedef struct _RUPUBLICKEYSTRUC {
	u8 bType;
	u8 bVersion;
	uint16_t reserved;
	uint32_t aiKeyAlg;
} RUBLOBHEADER;

typedef struct _RUPRIVATEKEYBLOB {
	RUBLOBHEADER blobheader;
	RURSAPUBKEY rsapubkey;
	u8 *modulus;
	u8 *prime1;
	u8 *prime2;
	u8 *exponent1;
	u8 *exponent2;
	u8 *coefficient;
	u8 *privateExponent;
} RUPRIVATEKEYBLOB;


static void ArrayReverse(u8 *buf, size_t size)
{
	size_t i;
	u8 tmp;

	for (i=0; i < size/2; ++i)
	{
		tmp = buf[i];
		buf[i] = buf[size-1-i];
		buf[size-1-i] = tmp;
	}
}

static int free_private_blob(RUPRIVATEKEYBLOB *pr_blob)
{
	free(pr_blob->modulus);
	free(pr_blob->prime1);
	free(pr_blob->prime2);
	free(pr_blob->exponent1);
	free(pr_blob->exponent2);
	free(pr_blob->coefficient);
	free(pr_blob->privateExponent);
	return 0;
}

static int bin_to_private_blob(RUPRIVATEKEYBLOB *pr_blob, const u8* buf, size_t buf_len)
{
	const u8 *tmp;
	size_t len = 2 + sizeof(pr_blob->blobheader) + sizeof(pr_blob->rsapubkey);
	uint32_t bitlen;

	if (buf_len < len)
		return -1;

	tmp = buf + 2;
	memcpy(&pr_blob->blobheader, tmp, sizeof(pr_blob->blobheader));
	tmp += sizeof(pr_blob->blobheader);

	memcpy(&pr_blob->rsapubkey, tmp, sizeof(pr_blob->rsapubkey));
	tmp += sizeof(pr_blob->rsapubkey);

	bitlen = pr_blob->rsapubkey.bitlen;

	len += bitlen/8 * 2  +  bitlen/16 * 5;
	if (buf_len < len)
		return -1;

	pr_blob->modulus = malloc(bitlen/8);
	pr_blob->prime1 = malloc(bitlen/16);
	pr_blob->prime2 = malloc(bitlen/16);
	pr_blob->exponent1 = malloc(bitlen/16);
	pr_blob->exponent2 = malloc(bitlen/16);
	pr_blob->coefficient = malloc(bitlen/16);
	pr_blob->privateExponent = malloc(bitlen/8);
	if (!pr_blob->modulus || !pr_blob->prime1 || !pr_blob->prime2
			|| !pr_blob->exponent1 || !pr_blob->exponent2
			|| !pr_blob->coefficient || !pr_blob->privateExponent
	)
	{
		free_private_blob(pr_blob);
	        return -1;
	}
	memcpy(pr_blob->modulus, tmp, bitlen/8);
	tmp += bitlen/8;
	memcpy(pr_blob->prime1, tmp, bitlen/16);
	tmp += bitlen/16;
	memcpy(pr_blob->prime2, tmp, bitlen/16);
	tmp += bitlen/16;
	memcpy(pr_blob->exponent1, tmp, bitlen/16);
	tmp += bitlen/16;
	memcpy(pr_blob->exponent2, tmp, bitlen/16);
	tmp += bitlen/16;
	memcpy(pr_blob->coefficient, tmp, bitlen/16);
	tmp += bitlen/16;
	memcpy(pr_blob->privateExponent, tmp, bitlen/8);
	tmp += bitlen/8;
	return 0;
}

static int create_private_blob(RUPRIVATEKEYBLOB *pr_blob, const struct sc_pkcs15_prkey_rsa *key)
{
	size_t n;
	const uint32_t bitlen = key->modulus.len*8;

	if (    key->modulus.len != bitlen/8
	     || key->p.len       != bitlen/16
	     || key->q.len       != bitlen/16
	     || key->dmp1.len    != bitlen/16
	     || key->dmq1.len    != bitlen/16
	     || key->iqmp.len    != bitlen/16
	     || key->d.len       != bitlen/8
	)
		return -1;

	/*  blobheader  */
	/*  u8 bType;  */
	pr_blob->blobheader.bType = 0x07;
	/*  u8 bVersion;  */
	pr_blob->blobheader.bVersion = 0x02;  
	/*  u16 reserved;  */
	pr_blob->blobheader.reserved = 0;
	/*  u32 aiKeyAlg;  */
	pr_blob->blobheader.aiKeyAlg = 0x0000a400;

	pr_blob->rsapubkey.magic     = 0x32415352;     /* "RSA2"  */
	pr_blob->rsapubkey.bitlen    = bitlen;

	pr_blob->rsapubkey.pubexp = 0;
	for (n=0; n < key->exponent.len  &&  n < sizeof(pr_blob->rsapubkey.pubexp); ++n)
		pr_blob->rsapubkey.pubexp += 
			(uint32_t)key->exponent.data[key->exponent.len - n - 1] << 8*n;

	pr_blob->modulus = malloc(bitlen/8);
	pr_blob->prime1 = malloc(bitlen/16);
	pr_blob->prime2 = malloc(bitlen/16);
	pr_blob->exponent1 = malloc(bitlen/16);
	pr_blob->exponent2 = malloc(bitlen/16);
	pr_blob->coefficient = malloc(bitlen/16);
	pr_blob->privateExponent = malloc(bitlen/8);
	if (!pr_blob->modulus || !pr_blob->prime1 || !pr_blob->prime2
			|| !pr_blob->exponent1 || !pr_blob->exponent2
			|| !pr_blob->coefficient || !pr_blob->privateExponent
	)
	{
		free_private_blob(pr_blob);
		return -1;
	}

	memcpy(pr_blob->modulus, key->modulus.data, key->modulus.len);
	ArrayReverse(pr_blob->modulus, key->modulus.len);
	memcpy(pr_blob->prime1, key->p.data, key->p.len);
	ArrayReverse(pr_blob->prime1, key->p.len);
	memcpy(pr_blob->prime2, key->q.data, key->q.len);
	ArrayReverse(pr_blob->prime2, key->q.len);
	memcpy(pr_blob->exponent1, key->dmp1.data, key->dmp1.len);
	ArrayReverse(pr_blob->exponent1, key->dmp1.len);
	memcpy(pr_blob->exponent2, key->dmq1.data, key->dmq1.len);
	ArrayReverse(pr_blob->exponent2, key->dmq1.len);
	memcpy(pr_blob->coefficient, key->iqmp.data, key->iqmp.len);
	ArrayReverse(pr_blob->coefficient, key->iqmp.len);
	memcpy(pr_blob->privateExponent, key->d.data, key->d.len);
	ArrayReverse(pr_blob->privateExponent, key->d.len);
	return 0;
}

static int get_sc_pksc15_prkey_rsa(const RUPRIVATEKEYBLOB *pr_blob, struct sc_pkcs15_prkey_rsa *key)
{
	static const u8 Exp[3] = { 0x01, 0x00, 0x01 }; /* big endian */

	const uint32_t bitlen = pr_blob->rsapubkey.bitlen;

	key->modulus.data = malloc(bitlen/8);
	key->modulus.len = bitlen/8;
	key->p.data = malloc(bitlen/16);
	key->p.len = bitlen/16;
	key->q.data = malloc(bitlen/16);
	key->q.len = bitlen/16;
	key->dmp1.data = malloc(bitlen/16);
	key->dmp1.len = bitlen/16;
	key->dmq1.data = malloc(bitlen/16);
	key->dmq1.len = bitlen/16;  /* ?!  bitlen/16 - 1; */
	key->iqmp.data = malloc(bitlen/16);
	key->iqmp.len = bitlen/16;
	key->d.data = malloc(bitlen/8);
	key->d.len = bitlen/8;
	key->exponent.data = malloc(sizeof(Exp));
	key->exponent.len = sizeof(Exp);
	if(!key->modulus.data || !key->p.data || !key->q.data || !key->dmp1.data
			|| !key->dmq1.data || !key->iqmp.data || !key->d.data
			|| !key->exponent.data
	)
	{
		free(key->modulus.data);
		free(key->p.data);
		free(key->q.data);
		free(key->dmp1.data);
		free(key->dmq1.data);
		free(key->iqmp.data);
		free(key->d.data);
		free(key->exponent.data);
		memset(key, 0, sizeof(*key));
		return -1;
	}
	
	memcpy(key->exponent.data, &Exp, sizeof(Exp));
	memcpy(key->modulus.data, pr_blob->modulus, key->modulus.len);
	ArrayReverse(key->modulus.data, key->modulus.len);
	memcpy(key->p.data, pr_blob->prime1, key->p.len);
	ArrayReverse(key->p.data, key->p.len);
	memcpy(key->q.data, pr_blob->prime2, key->q.len);
	ArrayReverse(key->q.data, key->q.len);
	memcpy(key->dmp1.data, pr_blob->exponent1, key->dmp1.len);
	ArrayReverse(key->dmp1.data, key->dmp1.len);
	memcpy(key->dmq1.data, pr_blob->exponent2, key->dmq1.len);
	ArrayReverse(key->dmq1.data, key->dmq1.len);
	memcpy(key->iqmp.data, pr_blob->coefficient, key->iqmp.len);
	ArrayReverse(key->iqmp.data, key->iqmp.len);
	memcpy(key->d.data, pr_blob->privateExponent, key->d.len);
	ArrayReverse(key->d.data, key->d.len);
	return 0;
}

static int private_blob_to_bin(const RUPRIVATEKEYBLOB *pr_blob, u8 *buf, size_t *buf_len)
{
	u8 *tmp;
	size_t len = 2 + sizeof(pr_blob->blobheader) + sizeof(pr_blob->rsapubkey);

	if(*buf_len < len)
		return -1;

	buf[0] = 2;
	buf[1] = 1;
	tmp = buf + 2;
	memcpy(tmp, &pr_blob->blobheader, sizeof(pr_blob->blobheader));
	tmp += sizeof(pr_blob->blobheader);

	memcpy(tmp, &pr_blob->rsapubkey, sizeof(pr_blob->rsapubkey));
	tmp += sizeof(pr_blob->rsapubkey);

	len += pr_blob->rsapubkey.bitlen/8 * 2  +  pr_blob->rsapubkey.bitlen/16 * 5;
	if (*buf_len < len)
		return -1;

	memcpy(tmp, pr_blob->modulus, pr_blob->rsapubkey.bitlen/8);
	tmp += pr_blob->rsapubkey.bitlen/8;

	memcpy(tmp, pr_blob->prime1, pr_blob->rsapubkey.bitlen/16);
	tmp += pr_blob->rsapubkey.bitlen/16;

	memcpy(tmp, pr_blob->prime2, pr_blob->rsapubkey.bitlen/16);
	tmp += pr_blob->rsapubkey.bitlen/16;

	memcpy(tmp, pr_blob->exponent1, pr_blob->rsapubkey.bitlen/16);
	tmp += pr_blob->rsapubkey.bitlen/16;

	memcpy(tmp, pr_blob->exponent2, pr_blob->rsapubkey.bitlen/16);
	tmp += pr_blob->rsapubkey.bitlen/16;

	memcpy(tmp, pr_blob->coefficient, pr_blob->rsapubkey.bitlen/16);
	tmp += pr_blob->rsapubkey.bitlen/16;

	memcpy(tmp, pr_blob->privateExponent, pr_blob->rsapubkey.bitlen/8);
	tmp += pr_blob->rsapubkey.bitlen/8;

	*buf_len = len;
	return 0;
}

static int clean_prkey_private_blob(const RUPRIVATEKEYBLOB* pr_blob)
{
	const uint32_t bitlen = pr_blob->rsapubkey.bitlen;

	memset(pr_blob->modulus, 0, bitlen/8);
	memset(pr_blob->prime1, 0, bitlen/16);
	memset(pr_blob->prime2, 0, bitlen/16);
	memset(pr_blob->exponent1, 0, bitlen/16);
	memset(pr_blob->exponent2, 0, bitlen/16);
	memset(pr_blob->coefficient, 0, bitlen/16);
	memset(pr_blob->privateExponent, 0, bitlen/8);
	return 0;
}

int sc_rutoken_get_prkey_from_bin(const u8 *data, size_t len, struct sc_pkcs15_prkey **key)
{
	int ret = -1;
	RUPRIVATEKEYBLOB pr_blob;

	if (data && key)
	{
		*key = malloc(sizeof(struct sc_pkcs15_prkey));
		if (*key)
		{
			memset(*key, 0, sizeof(**key));
			ret = bin_to_private_blob(&pr_blob, data, len);
			if (ret == 0)
			{
				ret = get_sc_pksc15_prkey_rsa(&pr_blob, &(*key)->u.rsa);
				if (ret == 0)
					(*key)->algorithm = SC_ALGORITHM_RSA;
				clean_prkey_private_blob(&pr_blob);
				free_private_blob(&pr_blob);
				memset(&pr_blob, 0, sizeof(pr_blob));
			}
		}
	}
	return ret;
}

int sc_rutoken_get_bin_from_prkey(const struct sc_pkcs15_prkey_rsa *rsa, u8 *key, size_t *keysize)
{
	int r = -1;
	RUPRIVATEKEYBLOB prkeyblob;

	if (rsa && key && keysize)
	{
		r = create_private_blob(&prkeyblob, rsa);
		if (r == 0)
		{
			r = private_blob_to_bin(&prkeyblob, key, keysize);
			clean_prkey_private_blob(&prkeyblob);
			free_private_blob(&prkeyblob);
			memset(&prkeyblob, 0, sizeof(prkeyblob));
		}
	}
	return r;
}

