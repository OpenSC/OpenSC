/*
 * pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyrigth (C) 2007        Nils Larsch <nils@larsch.net>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static int select_key_file(struct sc_pkcs15_card *p15card,
			   const struct sc_pkcs15_prkey_info *prkey,
			   sc_security_env_t *senv)
{
	sc_path_t path, file_id;
	int r;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* For pkcs15-emulated cards, the file_app may be NULL,
	   in that case we allways assume an absolute path */
	if (prkey->path.len == 2 && p15card->file_app != NULL) {
		/* Path is relative to app. DF */
		path = p15card->file_app->path;
		file_id = prkey->path;
		sc_append_path(&path, &file_id);
	} else {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
		file_id.type = SC_PATH_TYPE_FILE_ID;
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
	sc_algorithm_info_t *alg_info;
	sc_security_env_t senv;
	sc_context_t *ctx = p15card->card->ctx;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	unsigned long pad_flags = 0, sec_flags = 0;

	SC_FUNC_CALLED(ctx, 1);
	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP))) {
		sc_error(ctx, "This key cannot be used for decryption\n");
		return SC_ERROR_NOT_ALLOWED;
	}

	alg_info = _sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
	if (alg_info == NULL) {
		sc_error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
		return SC_ERROR_NOT_SUPPORTED;
	}
	senv.algorithm = SC_ALGORITHM_RSA;

	r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
	if (r != SC_SUCCESS)
		return r;

	senv.algorithm_flags = sec_flags;
	senv.operation       = SC_SEC_OPERATION_DECIPHER;
	senv.flags           = 0;
	/* optional keyReference attribute (the default value is -1) */
	if (prkey->key_reference >= 0) {
		senv.key_ref_len = 1;
		senv.key_ref[0] = prkey->key_reference & 0xFF;
		senv.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
	}
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	r = sc_lock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_lock() failed");

	if (prkey->path.len != 0)
	{
		r = select_key_file(p15card, prkey, &senv);
		if (r < 0) {
			sc_unlock(p15card->card);
			SC_TEST_RET(ctx,r,"Unable to select private key file");
		}
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
		r = sc_pkcs1_strip_02_padding(out, (size_t)r, out, (size_t *) &r);
		SC_TEST_RET(ctx, r, "Invalid PKCS#1 padding");
	}

	return r;
}

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_object *obj,
				unsigned long flags, const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	int r;
	sc_security_env_t senv;
	sc_context_t *ctx = p15card->card->ctx;
	sc_algorithm_info_t *alg_info;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	u8 buf[512], *tmp;
	size_t modlen = prkey->modulus_length / 8;
	unsigned long pad_flags = 0, sec_flags = 0;

	SC_FUNC_CALLED(ctx, 1);

	/* some strange cards/setups need decrypt to sign ... */
	if (p15card->flags & SC_PKCS15_CARD_FLAG_SIGN_WITH_DECRYPT) {
		size_t tmplen = sizeof(buf);
		if (flags & SC_ALGORITHM_RSA_RAW) {
			return sc_pkcs15_decipher(p15card, obj,flags,
				in, inlen, out, outlen);
		}
		if (modlen > tmplen) {
			sc_error(ctx, "Buffer too small, needs recompile!\n");
			return SC_ERROR_NOT_ALLOWED;
		}
		r = sc_pkcs1_encode(ctx, flags, in, inlen, buf, &tmplen, modlen);

		/* no padding needed - already done */
		flags &= ~SC_ALGORITHM_RSA_PADS;
		/* instead use raw rsa */
		flags |= SC_ALGORITHM_RSA_RAW;

		SC_TEST_RET(ctx, r, "Unable to add padding");
		r = sc_pkcs15_decipher(p15card, obj,flags, buf, modlen,
			out, outlen);
		return r;
	}

	/* If the key is extractable, the caller should extract the
	 * key and do the crypto himself */
	if (!prkey->native)
		return SC_ERROR_EXTRACTABLE_KEY;

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER|
	                      SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))) {
		sc_error(ctx, "This key cannot be used for signing\n");
		return SC_ERROR_NOT_ALLOWED;
	}

	alg_info = _sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
	if (alg_info == NULL) {
		sc_error(ctx, "Card does not support RSA with key length %d\n", prkey->modulus_length);
		return SC_ERROR_NOT_SUPPORTED;
	}
	senv.algorithm = SC_ALGORITHM_RSA;

	/* Probably never happens, but better make sure */
	if (inlen > sizeof(buf) || outlen < modlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(buf, in, inlen);
	tmp = buf;

	/* flags: the requested algo
	 * algo_info->flags: what is supported by the card 
	 * senv.algorithm_flags: what the card will have to do */

	/* If the card doesn't support the requested algorithm, see if we
	 * can strip the input so a more restrictive algo can be used */
	if ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) &&
	    !(alg_info->flags & (SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_NONE))) {
		unsigned int algo;
		size_t tmplen = sizeof(buf);
		r = sc_pkcs1_strip_digest_info_prefix(&algo, tmp, inlen, tmp, &tmplen);
		if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE) {
			sc_mem_clear(buf, sizeof(buf));
			return SC_ERROR_INVALID_DATA;
		}
		flags &= ~SC_ALGORITHM_RSA_HASH_NONE;
		flags |= algo;
		inlen = tmplen;
	}

	r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
	if (r != SC_SUCCESS) {
		sc_mem_clear(buf, sizeof(buf));
		return r;
	}
	senv.algorithm_flags = sec_flags;

	/* add the padding bytes (if necessary) */
	if (pad_flags != 0) {
		size_t tmplen = sizeof(buf);
		r = sc_pkcs1_encode(ctx, pad_flags, tmp, inlen, tmp, &tmplen, modlen);
		SC_TEST_RET(ctx, r, "Unable to add padding");
		inlen = tmplen;
	} else if ((flags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
		/* Add zero-padding if input is shorter than the modulus */
		if (inlen < modlen) {
			if (modlen > sizeof(buf))
				return SC_ERROR_BUFFER_TOO_SMALL;
			memmove(tmp+modlen-inlen, tmp, inlen);
			memset(tmp, 0, modlen-inlen);
		}
	}

	senv.operation = SC_SEC_OPERATION_SIGN;
	senv.flags = 0;
	/* optional keyReference attribute (the default value is -1) */
	if (prkey->key_reference >= 0) {
		senv.key_ref_len = 1;
		senv.key_ref[0] = prkey->key_reference & 0xFF;
		senv.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
	}
	senv.flags |= SC_SEC_ENV_ALG_PRESENT;

	r = sc_lock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_lock() failed");

	if (prkey->path.len != 0) {
		r = select_key_file(p15card, prkey, &senv);
		if (r < 0) {
			sc_unlock(p15card->card);
			SC_TEST_RET(ctx,r,"Unable to select private key file");
		}
	}

	r = sc_set_security_env(p15card->card, &senv, 0);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	}

	r = sc_compute_signature(p15card->card, tmp, inlen, out, outlen);
	sc_mem_clear(buf, sizeof(buf));
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
