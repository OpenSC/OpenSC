/*
 * padding.c: miscellaneous padding functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003 - 2007  Nils Larsch <larsch@trustcenter.de>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "pkcs11/pkcs11.h"
/* TODO doxygen comments */

/*
 * Prefixes for pkcs-v1 signatures
 */
static const u8 hdr_md5[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const u8 hdr_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
	0x05, 0x00, 0x04, 0x14
};
static const u8 hdr_sha256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const u8 hdr_sha384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const u8 hdr_sha512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const u8 hdr_sha224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const u8 hdr_ripemd160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};


static const struct digest_info_prefix {
	unsigned int	algorithm;
	const u8 *	hdr;
	size_t		hdr_len;
	size_t		hash_len;
} digest_info_prefix[] = {
      { SC_ALGORITHM_RSA_HASH_NONE,     NULL,           0,                      0      },
      {	SC_ALGORITHM_RSA_HASH_MD5,	hdr_md5,	sizeof(hdr_md5),	16	},
      { SC_ALGORITHM_RSA_HASH_SHA1,	hdr_sha1,	sizeof(hdr_sha1),	20	},
      { SC_ALGORITHM_RSA_HASH_SHA256,	hdr_sha256,	sizeof(hdr_sha256),	32	},
      { SC_ALGORITHM_RSA_HASH_SHA384,	hdr_sha384,	sizeof(hdr_sha384),	48	},
      { SC_ALGORITHM_RSA_HASH_SHA512,	hdr_sha512,	sizeof(hdr_sha512),	64	},
      { SC_ALGORITHM_RSA_HASH_SHA224,	hdr_sha224,	sizeof(hdr_sha224),	28	},
      { SC_ALGORITHM_RSA_HASH_RIPEMD160,hdr_ripemd160,	sizeof(hdr_ripemd160),	20	},
      { SC_ALGORITHM_RSA_HASH_MD5_SHA1,	NULL,		0,			36	},
      {	0,				NULL,		0,			0	}
};

/* add/remove pkcs1 BT01 padding */

static int sc_pkcs1_add_01_padding(const u8 *in, size_t in_len,
	u8 *out, size_t *out_len, size_t mod_length)
{
	size_t i;

	if (*out_len < mod_length)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (in_len + 11 > mod_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	i = mod_length - in_len;
	memmove(out + i, in, in_len);
	*out++ = 0x00;
	*out++ = 0x01;
	
	memset(out, 0xFF, i - 3);
	out += i - 3;
	*out = 0x00;

	*out_len = mod_length;
	return SC_SUCCESS;
}

int
sc_pkcs1_strip_01_padding(struct sc_context *ctx, const u8 *in_dat, size_t in_len,
		u8 *out, size_t *out_len)
{
	const u8 *tmp = in_dat;
	size_t    len;

	if (in_dat == NULL || in_len < 10)
		return SC_ERROR_INTERNAL;
	/* skip leading zero byte */
	if (*tmp == 0) {
		tmp++;
		in_len--;
	}
	len = in_len;
	if (*tmp != 0x01)
		return SC_ERROR_WRONG_PADDING;
	for (tmp++, len--; *tmp == 0xff && len != 0; tmp++, len--)
		;
	if (!len || (in_len - len) < 9 || *tmp++ != 0x00)
		return SC_ERROR_WRONG_PADDING;
	len--;
	if (out == NULL)
		/* just check the padding */
		return SC_SUCCESS;
	if (*out_len < len)
		return SC_ERROR_INTERNAL;
	memmove(out, tmp, len);
	*out_len = len;
	return SC_SUCCESS;
}


/* remove pkcs1 BT02 padding (adding BT02 padding is currently not
 * needed/implemented) */
int
sc_pkcs1_strip_02_padding(sc_context_t *ctx, const u8 *data, size_t len, u8 *out, size_t *out_len)
{
	unsigned int	n = 0;

	LOG_FUNC_CALLED(ctx);
	if (data == NULL || len < 3)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	/* skip leading zero byte */
	if (*data == 0) {
		data++;
		len--;
	}
	if (data[0] != 0x02)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
	/* skip over padding bytes */
	for (n = 1; n < len && data[n]; n++)
		;
	/* Must be at least 8 pad bytes */
	if (n >= len || n < 9)
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
	n++;
	if (out == NULL)
		/* just check the padding */
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	/* Now move decrypted contents to head of buffer */
	if (*out_len < len - n)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	*out_len = len - n;
	memmove(out, data + n, *out_len);

	sc_log(ctx, "stripped output(%"SC_FORMAT_LEN_SIZE_T"u): %s", len - n,
	       sc_dump_hex(out, len - n));
	LOG_FUNC_RETURN(ctx, len - n);
}

#ifdef ENABLE_OPENSSL
static int mgf1(u8 *mask, size_t len, u8 *seed, size_t seedLen, const EVP_MD *dgst)
{
	int i;
	size_t outlen = 0;
	u8 cnt[4];
	EVP_MD_CTX *md_ctx = NULL;
	int mdlen;
	u8 md[EVP_MAX_MD_SIZE];
	int rv = 1;

	if (!(md_ctx = EVP_MD_CTX_new()))
		goto out;

	mdlen = EVP_MD_size(dgst);
	if (mdlen < 0)
		goto out;

	for (i = 0; outlen < len; i++) {
		cnt[0] = (u8) ((i >> 24) & 255);
		cnt[1] = (u8) ((i >> 16) & 255);
		cnt[2] = (u8) ((i >> 8) & 255);
		cnt[3] = (u8) ((i >> 0) & 255);
		if (!EVP_DigestInit_ex(md_ctx, dgst, NULL)
		    || !EVP_DigestUpdate(md_ctx, seed, seedLen)
		    || !EVP_DigestUpdate(md_ctx, cnt, 4))
			goto out;
		if (outlen + mdlen <= len) {
			if (!EVP_DigestFinal_ex(md_ctx, mask + outlen, NULL))
				goto out;
			outlen += mdlen;
		} else {
			if (!EVP_DigestFinal_ex(md_ctx, md, NULL))
				goto out;
			memcpy(mask + outlen, md, len - outlen);
			outlen = len;
		}
	}
	rv = 0;
 out:
	OPENSSL_cleanse(md, sizeof(md));
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	return rv;
}

/* forward declarations */
static EVP_MD *mgf1_flag2md(sc_context_t *ctx, unsigned int mgf1);
static EVP_MD *hash_flag2md(sc_context_t *ctx, unsigned int hash);

/* check/remove OAEP - RFC 8017 padding */
int sc_pkcs1_strip_oaep_padding(sc_context_t *ctx, u8 *data, size_t len, unsigned long flags, uint8_t *param, size_t paramlen)
{
	size_t i,j;
	size_t mdlen, dblen;
	u8 seed[EVP_MAX_MD_SIZE];
	EVP_MD *mgf1_md = NULL, *hash_md = NULL;
	u8 db[512];		/* up to RSA 4096 */
	u8 label[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *md_ctx;
	unsigned int hash_len = 0;

	LOG_FUNC_CALLED(ctx);
	if (data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	/* https://www.rfc-editor.org/rfc/pdfrfc/rfc8017.txt.pdf, page 26, 3.a. */
	hash_md = hash_flag2md(ctx, flags);
	if (!hash_md)
		return SC_ERROR_NOT_SUPPORTED;

	memset(label, 0, sizeof(label));
	if ((md_ctx = EVP_MD_CTX_new())) {
		if (!EVP_DigestInit_ex(md_ctx, hash_md, NULL)
		    || !EVP_DigestUpdate(md_ctx, param, paramlen)
		    || !EVP_DigestFinal_ex(md_ctx, label, &hash_len))
			hash_len = 0;
		EVP_MD_CTX_free(md_ctx);
	}
	sc_evp_md_free(hash_md);
	hash_md = NULL;
	if (!hash_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

	mgf1_md = mgf1_flag2md(ctx, flags);
	if (!mgf1_md)
		return SC_ERROR_NOT_SUPPORTED;

	mdlen = EVP_MD_size(mgf1_md);

	if (len < 2 * mdlen + 2) {
		sc_evp_md_free(mgf1_md);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
	}

	if (*data != 0) {
		sc_evp_md_free(mgf1_md);
		LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
	}

	dblen = len - 1 - mdlen;
	if (dblen > sizeof(db)) {
		sc_evp_md_free(mgf1_md);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}

	if (mgf1(seed, mdlen, data + mdlen + 1, dblen, mgf1_md)) {
		sc_evp_md_free(mgf1_md);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	for (i = 0; i < mdlen; i++)
		seed[i] ^= data[i + 1];

	if (mgf1(db, dblen, seed, mdlen, mgf1_md)) {
		sc_evp_md_free(mgf1_md);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
	sc_evp_md_free(mgf1_md);
	for (i = 0; i < dblen; i++) {
		db[i] ^= data[i + mdlen + 1];
		/* clear lHash' if same as lHash */
		if (i < hash_len)
			db[i] ^= label[i];
	}
	/* if the padding is correct, it is a concatenation:
	 *   00...00 || 01 || plaintext
	 * check padding but do not leak information about error:
	 */
	for (j = 0, i = 0; i < dblen;) {
		j += db[i++] + 1;
		if (i > mdlen) {
			if (j == i + 1) {
				/* OK correct padding found */
				len = dblen - i;
				memcpy(data, db + i, len);
				LOG_FUNC_RETURN(ctx, len);
			}
		}
	}
	LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
}
#endif

/* add/remove DigestInfo prefix */
static int sc_pkcs1_add_digest_info_prefix(unsigned int algorithm,
	const u8 *in, size_t in_len, u8 *out, size_t *out_len)
{
	int i;

	for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
		if (algorithm == digest_info_prefix[i].algorithm) {
			const u8 *hdr      = digest_info_prefix[i].hdr;
			size_t    hdr_len  = digest_info_prefix[i].hdr_len,
			          hash_len = digest_info_prefix[i].hash_len;

			if (in_len != hash_len || *out_len < (hdr_len + hash_len))
				return SC_ERROR_INTERNAL;

			memmove(out + hdr_len, in, hash_len);
			memmove(out, hdr, hdr_len);
			*out_len = hdr_len + hash_len;

			return SC_SUCCESS;
		}
	}

	return SC_ERROR_INTERNAL;
}

int sc_pkcs1_strip_digest_info_prefix(unsigned int *algorithm,
	const u8 *in_dat, size_t in_len, u8 *out_dat, size_t *out_len)
{
	int i;

	for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
		size_t    hdr_len  = digest_info_prefix[i].hdr_len,
		          hash_len = digest_info_prefix[i].hash_len;
		const u8 *hdr      = digest_info_prefix[i].hdr;
		
		if (in_len == (hdr_len + hash_len) &&
		    !memcmp(in_dat, hdr, hdr_len)) {
			if (algorithm)
				*algorithm = digest_info_prefix[i].algorithm;
			if (out_dat == NULL)
				/* just check the DigestInfo prefix */
				return SC_SUCCESS;
			if (*out_len < hash_len)
				return SC_ERROR_INTERNAL;
			memmove(out_dat, in_dat + hdr_len, hash_len);
			*out_len = hash_len;
			return SC_SUCCESS;
		}
	}
	return SC_ERROR_INTERNAL;
}

#ifdef ENABLE_OPENSSL

static EVP_MD* hash_flag2md(sc_context_t *ctx, unsigned int hash)
{
	switch (hash & SC_ALGORITHM_RSA_HASHES) {
	case SC_ALGORITHM_RSA_HASH_SHA1:
		return sc_evp_md(ctx, "SHA1");
	case SC_ALGORITHM_RSA_HASH_SHA224:
		return sc_evp_md(ctx, "SHA224");
	case SC_ALGORITHM_RSA_HASH_SHA256:
		return sc_evp_md(ctx, "SHA256");
	case SC_ALGORITHM_RSA_HASH_SHA384:
		return sc_evp_md(ctx, "SHA384");
	case SC_ALGORITHM_RSA_HASH_SHA512:
		return sc_evp_md(ctx, "SHA512");
	default:
		return NULL;
	}
}

static EVP_MD* mgf1_flag2md(sc_context_t *ctx, unsigned int mgf1)
{
	switch (mgf1 & SC_ALGORITHM_MGF1_HASHES) {
	case SC_ALGORITHM_MGF1_SHA1:
		return sc_evp_md(ctx, "SHA1");
	case SC_ALGORITHM_MGF1_SHA224:
		return sc_evp_md(ctx, "SHA224");
	case SC_ALGORITHM_MGF1_SHA256:
		return sc_evp_md(ctx, "SHA256");
	case SC_ALGORITHM_MGF1_SHA384:
		return sc_evp_md(ctx, "SHA384");
	case SC_ALGORITHM_MGF1_SHA512:
		return sc_evp_md(ctx, "SHA512");
	default:
		return NULL;
	}
}

/* large enough up to RSA 4096 */
#define PSS_MAX_SALT_SIZE 512
/* add PKCS#1 v2.0 PSS padding */
static int sc_pkcs1_add_pss_padding(sc_context_t *scctx, unsigned int hash, unsigned int mgf1_hash,
    const u8 *in, size_t in_len, u8 *out, size_t *out_len, size_t mod_bits, size_t sLen)
{
	/* hLen = sLen in our case */
	int rv = SC_ERROR_INTERNAL, i, j, hlen, dblen, plen, round, mgf_rounds;
	int mgf1_hlen;
	EVP_MD* md = NULL, *mgf1_md = NULL;
	EVP_MD_CTX* ctx = NULL;
	u8 buf[8];
	u8 salt[PSS_MAX_SALT_SIZE], mask[EVP_MAX_MD_SIZE];
	size_t mod_length = (mod_bits + 7) / 8;

	if (*out_len < mod_length)
		return SC_ERROR_BUFFER_TOO_SMALL;

	md = hash_flag2md(scctx, hash);
	if (md == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	hlen = EVP_MD_size(md);
	dblen = mod_length - hlen - 1; /* emLen - hLen - 1 */
	plen = mod_length - sLen - hlen - 1;
	if (in_len != (unsigned)hlen) {
		sc_evp_md_free(md);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (sLen + (unsigned)hlen + 2 > mod_length) {
		/* RSA key too small for chosen hash (1296 bits or higher needed for
		 * signing SHA-512 hashes) */
		sc_evp_md_free(md);
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (sLen > PSS_MAX_SALT_SIZE) {
		sc_evp_md_free(md);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (RAND_bytes(salt, sLen) != 1) {
		sc_evp_md_free(md);
		return SC_ERROR_INTERNAL;
	}

	/* Hash M' to create H */
	if (!(ctx = EVP_MD_CTX_create()))
		goto done;
	memset(buf, 0x00, 8);
	if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
	    EVP_DigestUpdate(ctx, buf, 8) != 1 ||
	    EVP_DigestUpdate(ctx, in, hlen) != 1 || /* mHash */
	    EVP_DigestUpdate(ctx, salt, sLen) != 1) {
		goto done;
	}

	/* Construct padding2, salt, H, and BC in the output block */
	/* DB = PS || 0x01 || salt */
	memset(out, 0x00, plen - 1); /* emLen - sLen - hLen - 2 */
	out[plen - 1] = 0x01;
	memcpy(out + plen, salt, sLen);
	if (EVP_DigestFinal_ex(ctx, out + dblen, NULL) != 1) { /* H */
		goto done;
	}
	out[dblen + hlen] = 0xBC;
	/* EM = DB* || H || 0xbc
	 *  *the first part is masked later */

	/* Construct the DB mask block by block and XOR it in. */
	mgf1_md = mgf1_flag2md(scctx, mgf1_hash);
	if (mgf1_md == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	mgf1_hlen = EVP_MD_size(mgf1_md);

	mgf_rounds = (dblen + mgf1_hlen - 1) / mgf1_hlen; /* round up */
	for (round = 0; round < mgf_rounds; ++round) {
		buf[0] = (round&0xFF000000U) >> 24;
		buf[1] = (round&0x00FF0000U) >> 16;
		buf[2] = (round&0x0000FF00U) >> 8;
		buf[3] = (round&0x000000FFU);
		if (EVP_DigestInit_ex(ctx, mgf1_md, NULL) != 1 ||
		    EVP_DigestUpdate(ctx, out + dblen, hlen) != 1 || /* H (Z parameter of MGF1) */
		    EVP_DigestUpdate(ctx, buf, 4) != 1 || /* C */
		    EVP_DigestFinal_ex(ctx, mask, NULL) != 1) {
			goto done;
		}
		/* this is no longer part of the MGF1, but actually
		 * XORing mask with DB to create maskedDB inplace */
		for (i = round * mgf1_hlen, j = 0; i < dblen && j < mgf1_hlen; ++i, ++j) {
			out[i] ^= mask[j];
		}
	}

	/* Set leftmost N bits in leftmost octet in maskedDB to zero
	 * to make sure the result is smaller than the modulus ( +1)
	 */
	out[0] &= (0xff >> (8 * mod_length - mod_bits + 1));

	*out_len = mod_length;
	rv = SC_SUCCESS;

done:
	OPENSSL_cleanse(salt, sizeof(salt));
	OPENSSL_cleanse(mask, sizeof(mask));
	sc_evp_md_free(md);
	sc_evp_md_free(mgf1_md);
	if (ctx) {
		EVP_MD_CTX_destroy(ctx);
	}
	return rv;
}

static int hash_len2algo(size_t hash_len)
{
	switch (hash_len) {
	case SHA_DIGEST_LENGTH:
		return SC_ALGORITHM_RSA_HASH_SHA1;
	case SHA224_DIGEST_LENGTH:
		return SC_ALGORITHM_RSA_HASH_SHA224;
	case SHA256_DIGEST_LENGTH:
		return SC_ALGORITHM_RSA_HASH_SHA256;
	case SHA384_DIGEST_LENGTH:
		return SC_ALGORITHM_RSA_HASH_SHA384;
	case SHA512_DIGEST_LENGTH:
		return SC_ALGORITHM_RSA_HASH_SHA512;
	}
	/* Should never happen -- the mechanism and data should be already
	 * verified to match one of the above. If not, we will fail later
	 */
	return SC_ALGORITHM_RSA_HASH_NONE;
}
#endif

/* general PKCS#1 encoding function */
int sc_pkcs1_encode(sc_context_t *ctx, unsigned long flags,
	const u8 *in, size_t in_len, u8 *out, size_t *out_len, size_t mod_bits, void *pMechanism)
{
	int    rv, i;
	size_t tmp_len = *out_len;
	const u8    *tmp = in;
	unsigned int hash_algo, pad_algo;
	size_t mod_len = (mod_bits + 7) / 8;
#ifdef ENABLE_OPENSSL
	size_t sLen;
	EVP_MD* md = NULL;
	unsigned int mgf1_hash;
#endif

	LOG_FUNC_CALLED(ctx);

	hash_algo = flags & SC_ALGORITHM_RSA_HASHES;
	pad_algo  = flags & SC_ALGORITHM_RSA_PADS;
	if (pad_algo == 0)
		pad_algo = SC_ALGORITHM_RSA_PAD_NONE;
	sc_log(ctx, "hash algorithm 0x%X, pad algorithm 0x%X", hash_algo, pad_algo);

	if ((pad_algo == SC_ALGORITHM_RSA_PAD_PKCS1 || pad_algo == SC_ALGORITHM_RSA_PAD_NONE) &&
	    hash_algo != SC_ALGORITHM_RSA_HASH_NONE) {
		i = sc_pkcs1_add_digest_info_prefix(hash_algo, in, in_len, out, &tmp_len);
		if (i != SC_SUCCESS) {
			sc_log(ctx, "Unable to add digest info 0x%x", hash_algo);
			LOG_FUNC_RETURN(ctx, i);
		}
		tmp = out;
	} else   {
		tmp_len = in_len;
	}

	switch(pad_algo) {
	case SC_ALGORITHM_RSA_PAD_NONE:
		/* padding done by card => nothing to do */
		if (out != tmp)
			memcpy(out, tmp, tmp_len);
		*out_len = tmp_len;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	case SC_ALGORITHM_RSA_PAD_PKCS1:
		/* add pkcs1 bt01 padding */
		rv = sc_pkcs1_add_01_padding(tmp, tmp_len, out, out_len, mod_len);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_ALGORITHM_RSA_PAD_PSS:
		/* add PSS padding */
#ifdef ENABLE_OPENSSL
		mgf1_hash = flags & SC_ALGORITHM_MGF1_HASHES;
		if (hash_algo == SC_ALGORITHM_RSA_HASH_NONE) {
			/* this is generic RSA_PKCS1_PSS mechanism with hash
			 * already done outside of the module. The parameters
			 * were already checked so we need to adjust the hash
			 * algorithm to do the padding with the correct hash
			 * function.
			 */
			hash_algo = hash_len2algo(tmp_len);
		}
		/* sLen is by default same as hash length */
		if (!(md = hash_flag2md(ctx, hash_algo)))
			return SC_ERROR_NOT_SUPPORTED;
		sLen = EVP_MD_size(md);
		sc_evp_md_free(md);
		/* if application provide sLen, use it */
		if (pMechanism != NULL) {
			CK_MECHANISM *mech = (CK_MECHANISM *)pMechanism;
			CK_RSA_PKCS_PSS_PARAMS *pss_params;
			if (mech->pParameter && sizeof(CK_RSA_PKCS_PSS_PARAMS) == mech->ulParameterLen) {
				pss_params = mech->pParameter;
				sLen = pss_params->sLen;
			}
		}
		rv = sc_pkcs1_add_pss_padding(ctx, hash_algo, mgf1_hash,
		    tmp, tmp_len, out, out_len, mod_bits, sLen);
#else
		rv = SC_ERROR_NOT_SUPPORTED;
#endif
		LOG_FUNC_RETURN(ctx, rv);
	default:
		/* We shouldn't be called with an unexpected padding type, we've already
		 * returned SC_ERROR_NOT_SUPPORTED if the card can't be used. */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	}
}

int sc_get_encoding_flags(sc_context_t *ctx,
	unsigned long iflags, unsigned long caps,
	unsigned long *pflags, unsigned long *sflags)
{
	LOG_FUNC_CALLED(ctx);
	if (pflags == NULL || sflags == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "iFlags 0x%lX, card capabilities 0x%lX", iflags, caps);

	/* For ECDSA and GOSTR, we don't do any padding or hashing ourselves, the
	 * card has to support the requested operation.  Similarly, for RSA with
	 * raw padding (raw RSA) and ISO9796, we require the card to do it for us.
	 * Finally, for PKCS1 (v1.5 and PSS) and ASNI X9.31 we can apply the padding
	 * ourselves if the card supports raw RSA. */

	/* TODO: Could convert GOSTR3410_HASH_GOSTR3411 -> GOSTR3410_RAW and
	 *       ECDSA_HASH_ -> ECDSA_RAW using OpenSSL (not much benefit though). */

	if ((caps & iflags) == iflags) {
		/* Card supports the signature operation we want to do, great, let's
		 * go with it then. */
		*sflags = iflags;
		*pflags = 0;

	} else if ((caps & SC_ALGORITHM_RSA_PAD_PSS) &&
			(iflags & SC_ALGORITHM_RSA_PAD_PSS)) {
		*sflags |= SC_ALGORITHM_RSA_PAD_PSS;
		*sflags |= iflags & SC_ALGORITHM_MGF1_HASHES;
		*pflags = iflags & ~(iflags & (SC_ALGORITHM_MGF1_HASHES | SC_ALGORITHM_RSA_PAD_PSS));

	} else if ((caps & SC_ALGORITHM_RSA_RAW) &&
				(iflags & SC_ALGORITHM_RSA_PAD_PKCS1
				|| iflags & SC_ALGORITHM_RSA_PAD_PSS
#ifdef ENABLE_OPENSSL
				|| iflags & SC_ALGORITHM_RSA_PAD_OAEP
#endif
				|| iflags & SC_ALGORITHM_RSA_PAD_NONE)) {
		/* Use the card's raw RSA capability on the padded input */
		*sflags = SC_ALGORITHM_RSA_PAD_NONE;
		*pflags = iflags;

	} else if ((caps & (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) &&
			(iflags & SC_ALGORITHM_RSA_PAD_PKCS1)) {
		/* A corner case - the card can partially do PKCS1, if we prepend the
		 * DigestInfo bit it will do the rest. */
		*sflags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
		*pflags = iflags & SC_ALGORITHM_RSA_HASHES;

	} else if ((iflags & SC_ALGORITHM_AES) == SC_ALGORITHM_AES) { /* TODO: seems like this constant does not belong to the same set of flags used form asymmetric algos. Fix this! */
		*sflags = 0;
		*pflags = 0;

	} else if ((iflags & SC_ALGORITHM_AES_FLAGS) > 0) {
		*sflags = iflags & SC_ALGORITHM_AES_FLAGS;
		if (iflags & SC_ALGORITHM_AES_CBC_PAD)
			*pflags = SC_ALGORITHM_AES_CBC_PAD;
		else
			*pflags = 0;

	} else {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported algorithm");
	}

	sc_log(ctx, "pad flags 0x%lX, secure algorithm flags 0x%lX", *pflags, *sflags);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
