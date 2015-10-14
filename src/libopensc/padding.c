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

#include <string.h>
#include <stdlib.h>

#include "internal.h"

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

	sc_log(ctx, "stripped output(%i): %s", len - n, sc_dump_hex(out, len - n));
	LOG_FUNC_RETURN(ctx, len - n);
}

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

/* general PKCS#1 encoding function */
int sc_pkcs1_encode(sc_context_t *ctx, unsigned long flags,
	const u8 *in, size_t in_len, u8 *out, size_t *out_len, size_t mod_len)
{
	int    rv, i;
	size_t tmp_len = *out_len;
	const u8    *tmp = in;
	unsigned int hash_algo, pad_algo;

	LOG_FUNC_CALLED(ctx);

	hash_algo = flags & (SC_ALGORITHM_RSA_HASHES | SC_ALGORITHM_RSA_HASH_NONE);
	pad_algo  = flags & SC_ALGORITHM_RSA_PADS;
	sc_log(ctx, "hash algorithm 0x%X, pad algorithm 0x%X", hash_algo, pad_algo);

	if (hash_algo != SC_ALGORITHM_RSA_HASH_NONE) {
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
	default:
		/* currently only pkcs1 padding is supported */
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Unsupported padding algorithm 0x%x", pad_algo);
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
}

int sc_get_encoding_flags(sc_context_t *ctx,
	unsigned long iflags, unsigned long caps,
	unsigned long *pflags, unsigned long *sflags)
{
	size_t i;

	LOG_FUNC_CALLED(ctx);
	if (pflags == NULL || sflags == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "iFlags 0x%X, card capabilities 0x%X", iflags, caps);
	for (i = 0; digest_info_prefix[i].algorithm != 0; i++) {
		if (iflags & digest_info_prefix[i].algorithm) {
			if (digest_info_prefix[i].algorithm != SC_ALGORITHM_RSA_HASH_NONE &&
			    caps & digest_info_prefix[i].algorithm)
				*sflags |= digest_info_prefix[i].algorithm;
			else
				*pflags |= digest_info_prefix[i].algorithm;
			break;
		}
	}

	if (iflags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if (caps & SC_ALGORITHM_RSA_PAD_PKCS1)
			*sflags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		else
			*pflags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	} else if ((iflags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
		
		/* Work with RSA, EC and maybe GOSTR? */
		if (!(caps & SC_ALGORITHM_RAW_MASK))
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "raw encryption is not supported");

		*sflags |= (caps & SC_ALGORITHM_RAW_MASK); /* adds in the one raw type */
		*pflags = 0;
	} else {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported algorithm");
	}

	sc_log(ctx, "pad flags 0x%X, secure algorithm flags 0x%X", *pflags, *sflags);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
