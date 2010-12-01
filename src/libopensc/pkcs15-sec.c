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

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "internal.h"
#include "pkcs15.h"

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
	SC_TEST_RET(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, r, "sc_select_file() failed");

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

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&senv, 0, sizeof(senv));

	/* If the key is not native, we can't operate with it. */
	if (!prkey->native)
		return SC_ERROR_NOT_SUPPORTED;

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP))) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "This key cannot be used for decryption\n");
		return SC_ERROR_NOT_ALLOWED;
	}

	/* Note ECDSA can not decrypt, so code is assuming RSA */

	alg_info = sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
	if (alg_info == NULL) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Card does not support RSA with key length %d\n", prkey->modulus_length);
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
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_lock() failed");

	if (prkey->path.len != 0)
	{
		r = select_key_file(p15card, prkey, &senv);
		if (r < 0) {
			sc_unlock(p15card->card);
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL,r,"Unable to select private key file");
		}
	}

	r = sc_set_security_env(p15card->card, &senv, 0);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_set_security_env() failed");
	}
	r = sc_decipher(p15card->card, in, inlen, out, outlen);
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		if (sc_pkcs15_pincache_revalidate(p15card, obj) == SC_SUCCESS)
			r = sc_decipher(p15card->card, in, inlen, out, outlen);
	}                                           
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_decipher() failed");

	/* Strip any padding */
	if (pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		size_t s = r;
		r = sc_pkcs1_strip_02_padding(out, s, out, &s);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Invalid PKCS#1 padding");
	}

	return r;
}

/* copied from pkcs15-cardos.c */
#define USAGE_ANY_SIGN          (SC_PKCS15_PRKEY_USAGE_SIGN|\
                                 SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_ANY_DECIPHER      (SC_PKCS15_PRKEY_USAGE_DECRYPT|\
                                 SC_PKCS15_PRKEY_USAGE_UNWRAP)

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
	size_t modlen;
	unsigned long pad_flags = 0, sec_flags = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	memset(&senv, 0, sizeof(senv));

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PRKEY) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "This is not a private key");
		return SC_ERROR_NOT_ALLOWED;
	}
		
	/* If the key is not native, we can't operate with it. */
	if (!prkey->native)
		return SC_ERROR_NOT_SUPPORTED;

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER|
	                      SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "This key cannot be used for signing\n");
		return SC_ERROR_NOT_ALLOWED;
	}

	switch (obj->type) {
		/* FIXME -DEE GOSTR is misusing the sc_card_find_rsa_alg */
		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PRKEY_RSA:
			modlen = prkey->modulus_length / 8;
			alg_info = sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);

			if (alg_info == NULL) {
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Card does not support RSA with key length %d\n", prkey->modulus_length);
				return SC_ERROR_NOT_SUPPORTED;
			}
			senv.flags |= SC_SEC_ENV_ALG_PRESENT;
			senv.algorithm = SC_ALGORITHM_RSA;
			break;

		case SC_PKCS15_TYPE_PRKEY_EC:
			modlen = ((prkey->field_length +7) / 8) * 2;  /* 2*nLen */ 
			alg_info = sc_card_find_ec_alg(p15card->card, prkey->field_length);
			if (alg_info == NULL) {
				sc_debug(ctx, SC_LOG_DEBUG_NORMAL, 
						"Card does not support EC with field_size %d",
						prkey->field_length);
				return SC_ERROR_NOT_SUPPORTED;
			}
			senv.algorithm = SC_ALGORITHM_EC;
			senv.flags |= SC_SEC_ENV_ALG_PRESENT;

			senv.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
			senv.algorithm_ref = prkey->field_length;
			break;
			/* add other crypto types here */
		default:
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Key type not supported");
			return SC_ERROR_NOT_SUPPORTED;
	}

	/* Probably never happens, but better make sure */
	if (inlen > sizeof(buf) || outlen < modlen)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(buf, in, inlen);
	tmp = buf;

	/* flags: the requested algo
	 * algo_info->flags: what is supported by the card 
	 * senv.algorithm_flags: what the card will have to do */

	/* if the card has SC_ALGORITHM_NEED_USAGE set, and the
	   key is for signing and decryption, we need to emulate signing */
	/* TODO: -DEE assume only RSA keys will ever use _NEED_USAGE */

	if ((alg_info->flags & SC_ALGORITHM_NEED_USAGE) && 
		((prkey->usage & USAGE_ANY_SIGN) &&
		(prkey->usage & USAGE_ANY_DECIPHER)) ) {
		size_t tmplen = sizeof(buf);
		if (flags & SC_ALGORITHM_RSA_RAW) {
			return sc_pkcs15_decipher(p15card, obj,flags,
				in, inlen, out, outlen);
		}
		if (modlen > tmplen) {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Buffer too small, needs recompile!\n");
			return SC_ERROR_NOT_ALLOWED;
		}
		r = sc_pkcs1_encode(ctx, flags, in, inlen, buf, &tmplen, modlen);

		/* no padding needed - already done */
		flags &= ~SC_ALGORITHM_RSA_PADS;
		/* instead use raw rsa */
		flags |= SC_ALGORITHM_RSA_RAW;

		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to add padding");
		r = sc_pkcs15_decipher(p15card, obj,flags, buf, modlen,
			out, outlen);
		return r;
	}
	

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

sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "DEE flags:0x%8.8x alg_info->flags:0x%8.8x pad:0x%8.8x sec:0x%8.8x",
		flags, alg_info->flags, pad_flags, sec_flags);
 

	/* add the padding bytes (if necessary) */
	if (pad_flags != 0) {
		size_t tmplen = sizeof(buf);
		r = sc_pkcs1_encode(ctx, pad_flags, tmp, inlen, tmp, &tmplen, modlen);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to add padding");
		inlen = tmplen;
	} else if ( senv.algorithm == SC_ALGORITHM_RSA && 
			(flags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
		/* Add zero-padding if input is shorter than the modulus */
		if (inlen < modlen) {
			if (modlen > sizeof(buf))
				return SC_ERROR_BUFFER_TOO_SMALL;
			memmove(tmp+modlen-inlen, tmp, inlen);
			memset(tmp, 0, modlen-inlen);
		}
	}

	senv.operation = SC_SEC_OPERATION_SIGN;

	/* optional keyReference attribute (the default value is -1) */
	if (prkey->key_reference >= 0) {
		senv.key_ref_len = 1;
		senv.key_ref[0] = prkey->key_reference & 0xFF;
		senv.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
	}

	r = sc_lock(p15card->card);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_lock() failed");

	if (prkey->path.len != 0) {
		r = select_key_file(p15card, prkey, &senv);
		if (r < 0) {
			sc_unlock(p15card->card);
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL,r,"Unable to select private key file");
		}
	}

	r = sc_set_security_env(p15card->card, &senv, 0);
	if (r < 0) {
		sc_unlock(p15card->card);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_set_security_env() failed");
	}

	r = sc_compute_signature(p15card->card, tmp, inlen, out, outlen);
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		if (sc_pkcs15_pincache_revalidate(p15card, obj) == SC_SUCCESS)
			r = sc_compute_signature(p15card->card, tmp, inlen, out, outlen);
	}
	sc_mem_clear(buf, sizeof(buf));
	sc_unlock(p15card->card);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "sc_compute_signature() failed");

	return r;
}
