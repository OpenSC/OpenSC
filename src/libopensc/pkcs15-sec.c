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
#include <unistd.h>

int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_object *obj,
		       const u8 * in, size_t inlen, u8 *out, size_t outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path path, file_id;
        const struct sc_pkcs15_prkey_info *prkey = obj->data;

	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (prkey->path.len == 2) {
		path = p15card->file_app->path;
		file_id = prkey->path;
	} else {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
		path.len -= 2;
	}
	senv.algorithm = SC_ALGORITHM_RSA;
	senv.algorithm_flags = 0;

	senv.file_ref = file_id;
	senv.operation = SC_SEC_OPERATION_DECIPHER;
	senv.key_ref_len = 1;
	senv.key_ref[0] = prkey->key_reference & 0xFF;
	senv.flags = SC_SEC_ENV_KEY_REF_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT;
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	SC_FUNC_CALLED(ctx, 1);
	r = sc_select_file(p15card->card, &path, NULL);
	SC_TEST_RET(ctx, r, "sc_select_file() failed");
#if 0
	/* FIXME! */
	r = sc_restore_security_env(p15card->card, 0); /* empty SE */
	SC_TEST_RET(ctx, r, "sc_restore_security_env() failed");
#endif
	r = sc_set_security_env(p15card->card, &senv, 0);
	SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	r = sc_decipher(p15card->card, in, inlen, out, outlen);
	SC_TEST_RET(ctx, r, "sc_decipher() failed");
	return r;
}

static int pkcs1_add_padding(const u8 *in, size_t inlen, u8 *out, size_t outlen)
{
	int i;
	
	if (inlen + 11 > outlen)
		return SC_ERROR_INVALID_ARGUMENTS;
	*out++ = 0x00;
	*out++ = 0x01;
	
	i = outlen - 3 - inlen;
	memset(out, 0xFF, i);
	out += i;
	*out++ = 0x00;
	memcpy(out, in, inlen);

	return 0;
}

static int add_padding(struct sc_context *ctx, const u8 *in, size_t inlen, u8 *out,
		       size_t *outlen, unsigned long flags, unsigned int mod_length)
{
	u8 buf[64];
        size_t buflen;
	const u8 *hdr_md5 =  (const u8 *) "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x05\x00\x04\x10";
        size_t hdr_md5_len = 19;
	const u8 *hdr_sha1 = (const u8 *) "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x10";
        size_t hdr_sha1_len = 15;

	if (flags & SC_ALGORITHM_RSA_HASH_SHA1) {
		if (inlen != 20)
                        return SC_ERROR_WRONG_LENGTH;
		memcpy(buf, hdr_sha1, hdr_sha1_len);
		memcpy(buf + hdr_sha1_len, in, 20);
                buflen = 20 + hdr_sha1_len;
	} else if (flags & SC_ALGORITHM_RSA_HASH_MD5) {
		if (inlen != 16)
                        return SC_ERROR_WRONG_LENGTH;
		memcpy(buf, hdr_md5, hdr_md5_len);
		memcpy(buf + hdr_md5_len, in, 16);
                buflen = 16 + hdr_md5_len;
	} else if (flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1) {
		if (inlen != 36)
                        return SC_ERROR_WRONG_LENGTH;
		memcpy(buf, in, 36);
                buflen = 36;
	} else
                buflen = 0;
	if (buflen) {
		in = buf;
                inlen = buflen;
	}
	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		int r;

		if (*outlen < mod_length)
                        return SC_ERROR_BUFFER_TOO_SMALL;
		r = pkcs1_add_padding(in, inlen, out, mod_length);
		if (r)
			return r;
                *outlen = mod_length;
	} else {
		if (*outlen < inlen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(out, in, inlen);
                *outlen = inlen;
	}
	if (buflen)
                memset(buf, 0, buflen);
        return 0;
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
        const struct sc_pkcs15_prkey_info *prkey = obj->data;
	u8 buf[512];
	size_t buflen;
	struct sc_path path, file_id;
	unsigned long pad_flags = 0;

	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (prkey->path.len == 2) {
		path = p15card->file_app->path;
		file_id = prkey->path;
	} else {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
		path.len -= 2;
	}
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

        senv.file_ref = file_id;
	senv.operation = SC_SEC_OPERATION_SIGN;
	senv.key_ref_len = 1;
	senv.key_ref[0] = prkey->key_reference & 0xFF;
	senv.flags = SC_SEC_ENV_KEY_REF_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT;
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	r = sc_select_file(p15card->card, &path, NULL);
	SC_TEST_RET(ctx, r, "sc_select_file() failed");
#if 0
	/* FIXME! */
	r = sc_restore_security_env(p15card->card, 0); /* empty SE */
	SC_TEST_RET(ctx, r, "sc_restore_security_env() failed");
#endif
	r = sc_set_security_env(p15card->card, &senv, 0);
	SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	r = sc_compute_signature(p15card->card, in, inlen, out, outlen);
	if (pad_flags)
                memset(buf, 0, inlen);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
