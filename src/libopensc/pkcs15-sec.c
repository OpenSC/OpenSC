/*
 * sc-pkcs15-sec.c: PKCS#15 cryptography functions
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
		       const u8 * in, int inlen, u8 *out, int outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	
	senv.algorithm_ref = 0x02;
	senv.key_file_id = prkey->file_id;
	senv.operation = SC_SEC_OPERATION_DECIPHER;
	senv.key_ref = prkey->key_reference;
	
	SC_FUNC_CALLED(ctx, 1);
	r = sc_select_file(p15card->card, &p15card->file_app.path,
			   NULL);
	SC_TEST_RET(ctx, r, "sc_select_file() failed");
#if 0
	/* FIXME! */
	r = sc_restore_security_env(p15card->card, 0); /* empty SE */
	SC_TEST_RET(ctx, r, "sc_restore_security_env() failed");
#endif
	r = sc_set_security_env(p15card->card, &senv);
	SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	r = sc_decipher(p15card->card, in, inlen, out, outlen);
	SC_TEST_RET(ctx, r, "sc_decipher() failed");
	return r;
}

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_prkey_info *prkey,
				int hash, const u8 *in, int inlen, u8 *out,
				int outlen)
{
	int r;
	struct sc_security_env senv;
	struct sc_context *ctx = p15card->card->ctx;
	
	senv.algorithm_ref = 0x02;
	switch (hash) {
	case SC_PKCS15_HASH_SHA1:
		senv.algorithm_ref |= 0x10;
		break;
	case SC_PKCS15_HASH_NONE:
	default:
		break;
	}
	senv.key_file_id = prkey->file_id;
	senv.operation = SC_SEC_OPERATION_SIGN;
	senv.key_ref = prkey->key_reference;
	
	SC_FUNC_CALLED(ctx, 1);
	r = sc_select_file(p15card->card, &p15card->file_app.path,
			   NULL);
	SC_TEST_RET(ctx, r, "sc_select_file() failed");
#if 0
	/* FIXME! */
	r = sc_restore_security_env(p15card->card, 0); /* empty SE */
	SC_TEST_RET(ctx, r, "sc_restore_security_env() failed");
#endif
	r = sc_set_security_env(p15card->card, &senv);
	SC_TEST_RET(ctx, r, "sc_set_security_env() failed");
	r = sc_compute_signature(p15card->card, in, inlen, out, outlen);
	SC_TEST_RET(ctx, r, "sc_compute_signature() failed");

	return r;
}
