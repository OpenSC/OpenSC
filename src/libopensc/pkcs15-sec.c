/*
 * pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-internal.h"
#include "opensc-pkcs15.h"
#include "sc-log.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		       const struct sc_pkcs15_prkey_info *prkey,
		       const u8 * in, size_t inlen, u8 *out, size_t outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path path, file_id;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (prkey->path.len == 2) {
		path = p15card->file_app->path;
		sc_append_path(&path, &prkey->path);
		file_id = prkey->path;
	} else {	/* path.len > 2 */
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
	}
	senv.algorithm = SC_ALGORITHM_RSA;
	senv.algorithm_flags = SC_ALGORITHM_RSA_PKCS1_PAD;

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

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_prkey_info *prkey,
				unsigned int hash, const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	u8 buf[256];
	struct sc_path path, file_id;

	if (prkey->path.len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (prkey->path.len == 2) {
		path = p15card->file_app->path;
		memcpy(path.value + path.len, prkey->path.value, prkey->path.len);
		path.len += prkey->path.len;
		file_id = prkey->path;
	} else {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
	}
	senv.algorithm = SC_ALGORITHM_RSA;
	senv.algorithm_flags = SC_ALGORITHM_RSA_PKCS1_PAD;
	if (hash & SC_PKCS15_HASH_SHA1)
		senv.algorithm_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
	if (hash & SC_PKCS15_PAD_PKCS1_V1_5) {
		size_t modlen = prkey->modulus_length >> 3;
		
		if (inlen > (modlen - 11)) {
			error(ctx, "Input data length too large.\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (modlen > sizeof(buf)) {
			error(ctx, "Too large modulus.\n");
			return SC_ERROR_INTERNAL;
		}
		r = pkcs1_add_padding(in, inlen, buf, modlen);
		SC_TEST_RET(p15card->card->ctx, r, "Error adding PKCS #1 padding");
		in = buf;
		inlen = modlen;
	}
	senv.file_ref = file_id;
	senv.operation = SC_SEC_OPERATION_SIGN;
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
	r = sc_compute_signature(p15card->card, in, inlen, out, outlen);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
