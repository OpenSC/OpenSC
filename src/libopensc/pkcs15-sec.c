/*
 * pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include "pkcs15.h"
#include "log.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/*
 * Prefixes for pkcs-v1 signatures
 */
static const u8 hdr_md5[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const u8 hdr_sha1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
static const u8 hdr_ripemd160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14
};

#define DIGEST_INFO_COUNT 5
static struct digest_info_prefix {
	unsigned int	algorithm;
	const u8 *	hdr;
	size_t		hdr_len;
	int		hash_len;
} digest_info_prefix[DIGEST_INFO_COUNT] = {
      {	SC_ALGORITHM_RSA_HASH_MD5,	hdr_md5,	sizeof(hdr_md5),	16	},
      { SC_ALGORITHM_RSA_HASH_SHA1,	hdr_sha1,	sizeof(hdr_sha1),	20	},
      { SC_ALGORITHM_RSA_HASH_RIPEMD160,hdr_ripemd160,	sizeof(hdr_ripemd160),	20	},
      { SC_ALGORITHM_RSA_HASH_MD5_SHA1,	NULL,		0,			36	},
      {	0,				NULL,		0,			-1	}
};


static int pkcs1_strip_padding(u8 *data, size_t len)
{
	unsigned int	n = 0;

	if (data[0] != 0x00 && data[1] != 0x02)
		return SC_ERROR_DECRYPT_FAILED;
	/* Skip over padding bytes */
	for (n = 2; n < len && data[n]; n++)
		;
	/* Must be at least 8 pad bytes */
	if (n >= len || n < 10)
		return SC_ERROR_DECRYPT_FAILED;
	n++;

	/* Now move decrypted contents to head of buffer */
	memmove(data, data + n, len - n);
	return len - n;
}

static int select_key_file(struct sc_pkcs15_card *p15card,
			   const struct sc_pkcs15_prkey_info *prkey,
			   struct sc_security_env *senv)
{
	struct sc_path path, file_id;
	int r;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (prkey->path.len == 2) {
		/* Path is relative to app. DF */
		path = p15card->file_app->path;
		file_id = prkey->path;
		sc_append_path(&path, &file_id);
	} else {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
	}
	senv->file_ref = file_id;
	senv->flags |= SC_SEC_ENV_FILE_REF_PRESENT;
	r = sc_select_file(p15card->card, &path, NULL);
	SC_TEST_RET(p15card->card->ctx, r, "sc_select_file() failed");

	return 0;
}
 
int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_object *obj,
		       unsigned long flags,
		       const u8 * in, size_t inlen, u8 *out, size_t outlen)
{
	int r;
	struct sc_algorithm_info *alg_info;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
        const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	unsigned long pad_flags = 0;

	SC_FUNC_CALLED(ctx, 1);
	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	alg_info = _sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
	if (alg_info == NULL) {
		error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
		return SC_ERROR_NOT_SUPPORTED;
	}
	senv.algorithm = SC_ALGORITHM_RSA;
	senv.algorithm_flags = 0;

	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1))
			pad_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	} else if ((flags & SC_ALGORITHM_RSA_PAD_ANSI) ||
		   (flags & SC_ALGORITHM_RSA_PAD_ISO9796)) {
		error(ctx, "Only PKCS #1 padding method supported\n");
		return SC_ERROR_NOT_SUPPORTED;
	} else {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_RAW)) {
			error(ctx, "Card requires RSA padding\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		senv.algorithm_flags |= SC_ALGORITHM_RSA_RAW;
	}

	senv.operation = SC_SEC_OPERATION_DECIPHER;
	senv.key_ref_len = 1;
	senv.key_ref[0] = prkey->key_reference & 0xFF;
	senv.flags = SC_SEC_ENV_KEY_REF_PRESENT;
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	r = sc_lock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_lock() failed");

	r = select_key_file(p15card, prkey, &senv);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, r, "Unable to select private key file");
	}

	r = sc_set_security_env(p15card->card, &senv, 0);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	}
	r = sc_decipher(p15card->card, in, inlen, out, outlen);
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_decipher() failed");

	/* Strip any padding */
	if (pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		r = pkcs1_strip_padding(out, r);
                SC_TEST_RET(ctx, r, "Invalid PKCS#1 padding");
	}

	return r;
}

/*
 * No padding required - card will add the padding itself
 */
static int add_no_padding(struct digest_info_prefix *pfx,
		          const u8 *in, size_t inlen,
			  u8 *out, size_t *outlen,
			  size_t mod_length)
{
	size_t msglen = pfx->hdr_len + inlen;

	if (msglen > mod_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (msglen > *outlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(out, pfx->hdr, pfx->hdr_len);
	memcpy(out + pfx->hdr_len, in, inlen);

	*outlen = msglen;
	return 0;
}

/*
 * Add pkcs1 padding
 */
static int add_pkcs1_padding(struct digest_info_prefix *pfx,
			     const u8 *in, size_t inlen,
			     u8 *out, size_t *outlen,
			     size_t mod_length)
{
	size_t msglen = pfx->hdr_len + inlen;
	int i;

	if (*outlen < mod_length)
		return SC_ERROR_BUFFER_TOO_SMALL;
	if (msglen + 11 > mod_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	*out++ = 0x00;
	*out++ = 0x01;
	
	i = mod_length - 3 - msglen;
	memset(out, 0xFF, i);
	out += i;
	*out++ = 0x00;
	memcpy(out, pfx->hdr, pfx->hdr_len);
	memcpy(out + pfx->hdr_len, in, inlen);

	*outlen = mod_length;
	return 0;
}

static int add_padding(struct sc_context *ctx, const u8 *in, size_t inlen, u8 *out,
		       size_t *outlen, unsigned long flags, unsigned int mod_length)
{
	struct digest_info_prefix *pfx;
	int j, hash_algo, pad_algo;

	hash_algo = flags & SC_ALGORITHM_RSA_HASHES;
	pad_algo  = flags & SC_ALGORITHM_RSA_PADS;

	for (j = DIGEST_INFO_COUNT, pfx = digest_info_prefix; j--; pfx++) {
		if (pfx->algorithm == hash_algo)
			break;
	}
	if (j <= 0) {
		error(ctx, "Unsupported digest algorithm 0x%x\n", hash_algo);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (pfx->hash_len > 0 && inlen != pfx->hash_len)
		return SC_ERROR_WRONG_LENGTH;

	switch (pad_algo) {
	case 0: /* padding done by card */
		return add_no_padding(pfx, in, inlen, out, outlen, mod_length);
	case SC_ALGORITHM_RSA_PAD_PKCS1:
		return add_pkcs1_padding(pfx, in, inlen, out, outlen, mod_length);
	default:
		error(ctx, "Unsupported padding algorithm 0x%x\n", pad_algo);
		return SC_ERROR_NOT_SUPPORTED;
	}
}

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_object *obj,
				unsigned long flags, const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_algorithm_info *alg_info;
        const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	u8 buf[512];
	size_t buflen;
	unsigned long pad_flags = 0;

	SC_FUNC_CALLED(ctx, 1);
	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	alg_info = _sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
	if (alg_info == NULL) {
		error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
		return SC_ERROR_NOT_SUPPORTED;
	}
	senv.algorithm = SC_ALGORITHM_RSA;

	/* Probably never happens, but better make sure */
	if (inlen > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(buf, in, inlen);
        senv.algorithm_flags = 0;
	if (flags & SC_ALGORITHM_RSA_HASH_SHA1) {
		if (inlen != 20)
			SC_FUNC_RETURN(ctx, 0, SC_ERROR_WRONG_LENGTH);
		if (!(alg_info->flags & SC_ALGORITHM_RSA_HASH_SHA1))
			pad_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
	} else if (flags & SC_ALGORITHM_RSA_HASH_MD5) {
		if (inlen != 16)
			SC_FUNC_RETURN(ctx, 0, SC_ERROR_WRONG_LENGTH);
		if (!(alg_info->flags & SC_ALGORITHM_RSA_HASH_MD5))
			pad_flags |= SC_ALGORITHM_RSA_HASH_MD5;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_MD5;
	} else if (flags & SC_ALGORITHM_RSA_HASH_RIPEMD160) {
		if (inlen != 20)
			SC_FUNC_RETURN(ctx, 0, SC_ERROR_WRONG_LENGTH);
		if (!(alg_info->flags & SC_ALGORITHM_RSA_HASH_RIPEMD160))
			pad_flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;
	} else if (flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1) {
		if (inlen != 36)
			SC_FUNC_RETURN(ctx, 0, SC_ERROR_WRONG_LENGTH);
		if (!(alg_info->flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1))
			pad_flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1;
	} else {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_HASH_NONE)) {
			error(ctx, "Raw RSA not supported\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
                senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_NONE;
	}
	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1))
			pad_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		else
                        senv.algorithm_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	} else if ((flags & SC_ALGORITHM_RSA_PAD_ANSI) ||
		   (flags & SC_ALGORITHM_RSA_PAD_ISO9796)) {
		error(ctx, "Only PKCS #1 padding method supported\n");
		return SC_ERROR_NOT_SUPPORTED;
	} else {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_RAW)) {
			error(ctx, "Card requires RSA padding\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		senv.algorithm_flags |= SC_ALGORITHM_RSA_RAW;
	}
	if (pad_flags) {
                buflen = sizeof(buf);
		r = add_padding(ctx, in, inlen, buf, &buflen, pad_flags,
			        prkey->modulus_length/8);
                SC_TEST_RET(ctx, r, "Unable to add padding");
		in = buf;
		inlen = buflen;
	}

	senv.operation = SC_SEC_OPERATION_SIGN;
	senv.key_ref_len = 1;
	senv.key_ref[0] = prkey->key_reference & 0xFF;
	senv.flags = SC_SEC_ENV_KEY_REF_PRESENT;
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	r = sc_lock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_lock() failed");

	r = select_key_file(p15card, prkey, &senv);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, r, "Unable to select private key file");
	}

	r = sc_set_security_env(p15card->card, &senv, 0);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	}

	/* XXX: Should we adjust outlen to match the size of
	 * the signature we expect? CardOS for instance will
	 * barf if the LE value doesn't match the size of the
	 * signature exactly.
	 *
	 * Right now we work around this by assuming that eToken keys
	 * always have algorithm RSA_PURE_SIG so the input buffer
	 * is padded and has the same length as the signature. --okir */
	r = sc_compute_signature(p15card->card, in, inlen, out, outlen);
	if (pad_flags)
                memset(buf, 0, inlen);
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
