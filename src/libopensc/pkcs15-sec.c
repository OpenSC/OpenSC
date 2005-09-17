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
#include <assert.h>
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
	unsigned long pad_flags = 0;

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
	senv.algorithm_flags = 0;

	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1))
			pad_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		else
			senv.algorithm_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	} else if ((flags & SC_ALGORITHM_RSA_PAD_ANSI) ||
		   (flags & SC_ALGORITHM_RSA_PAD_ISO9796)) {
		sc_error(ctx, "Only PKCS #1 padding method supported\n");
		return SC_ERROR_NOT_SUPPORTED;
	} else {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_RAW)) {
			sc_error(ctx, "Card requires RSA padding\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		senv.algorithm_flags |= SC_ALGORITHM_RSA_RAW;
	}

	senv.operation = SC_SEC_OPERATION_DECIPHER;
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
	u8 buf[512], *tmpin, *tmpout, *help;
	size_t tmpoutlen;
	unsigned long pad_flags = 0;

	SC_FUNC_CALLED(ctx, 1);
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
	if (inlen > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(buf, in, inlen);
	tmpin = buf;
	if (outlen < (prkey->modulus_length + 7) / 8)
		return SC_ERROR_BUFFER_TOO_SMALL;
	tmpout = out;

	/* flags: the requested algo
	 * algo_info->flags: what is supported by the card 
	 * senv.algorithm_flags: what the card will have to do */

	/* If the card doesn't support the requested algorithm, see if we
	 * can strip the input so a more restrictive algo can be used */
	if ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) &&
	    !(alg_info->flags & (SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_NONE))) {
		unsigned int algo;
		tmpoutlen = sizeof(buf);
		r = sc_pkcs1_strip_digest_info_prefix(&algo, tmpin, inlen, tmpout, &tmpoutlen);
		if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE)
			return SC_ERROR_INVALID_DATA;
		help = tmpin;
		tmpin = tmpout;
		tmpout = help;
		inlen = tmpoutlen;
		flags &= ~SC_ALGORITHM_RSA_HASH_NONE;
		flags |= algo;
	}

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
	} else if (flags & SC_ALGORITHM_RSA_HASH_NONE ||
		   (flags & SC_ALGORITHM_RSA_HASHES) == 0) {
		pad_flags |= SC_ALGORITHM_RSA_HASH_NONE;
	}

	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1))
			pad_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		else
			senv.algorithm_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	} else if ((flags & SC_ALGORITHM_RSA_PAD_ANSI) ||
		   (flags & SC_ALGORITHM_RSA_PAD_ISO9796)) {
		sc_error(ctx, "Only PKCS #1 padding method supported\n");
		return SC_ERROR_NOT_SUPPORTED;
	} else {
		if (!(alg_info->flags & SC_ALGORITHM_RSA_RAW)) {
			sc_error(ctx, "Card requires RSA padding\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		senv.algorithm_flags |= SC_ALGORITHM_RSA_RAW;
		pad_flags = 0;

		/* Add zero-padding if input shorter than modulus */
		if (inlen < prkey->modulus_length/8) {
			unsigned int	modulus_len = prkey->modulus_length/8;
			if (modulus_len > sizeof(buf))
				return SC_ERROR_BUFFER_TOO_SMALL;
			memset(tmpout, 0, sizeof(buf));
			memcpy(tmpout + modulus_len - inlen, tmpin, inlen);
			inlen = modulus_len;
			help = tmpin;
			tmpin = tmpout;
			tmpout = help;
		}
	}

	if (pad_flags) {
		tmpoutlen = sizeof(buf);
		r = sc_pkcs1_encode(ctx, pad_flags, tmpin, inlen, tmpout, &tmpoutlen,
		                    prkey->modulus_length/8);
		SC_TEST_RET(ctx, r, "Unable to add padding");
		help = tmpin;
		tmpin = tmpout;
		tmpout = help;
		inlen = tmpoutlen;
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

	/* XXX: Should we adjust outlen to match the size of
	 * the signature we expect? CardOS for instance will
	 * barf if the LE value doesn't match the size of the
	 * signature exactly.
	 *
	 * Right now we work around this by assuming that eToken keys
	 * always have algorithm RSA_PURE_SIG so the input buffer
	 * is padded and has the same length as the signature. --okir 
	 */
	if (tmpin == out) {
		memcpy(tmpout, tmpin, inlen);
		tmpin = tmpout;
	}
	r = sc_compute_signature(p15card->card, tmpin, inlen, out, outlen);
	sc_mem_clear(buf, sizeof(buf));
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
