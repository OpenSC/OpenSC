/* crypto/engine/hw_opensc.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 * Copied/modified by Kevin Stefanik (kstef@mtppi.org) for the OpenSC
 * project 2003.
 */
/* ====================================================================
 * Copyright (c) 1999-2001 The OpenSSL Project.  All rights reserved.
 * Portions Copyright (c) 2003 Kevin Stefanik (kstef@mtppi.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif
#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "engine_opensc.h"

#define OPENSC_ENGINE_ID "opensc"
#define OPENSC_ENGINE_NAME "opensc engine"

#define CMD_SO_PATH		ENGINE_CMD_BASE
#define CMD_PIN			(ENGINE_CMD_BASE+1)

static int opensc_engine_destroy(ENGINE * e);
static int opensc_engine_init(ENGINE * e);
static int opensc_engine_finish(ENGINE * e);
static int opensc_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ());

/* The definitions for control commands specific to this engine */

/* need to add function to pass in reader id? or user reader:key as key id string? */

static const ENGINE_CMD_DEFN opensc_cmd_defns[] = {
	{CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the 'opensc-engine' shared library",
	 ENGINE_CMD_FLAG_STRING},
	{CMD_PIN,
	 "PIN",
	 "Specifies the pin code",
	 ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

static int opensc_engine_finish(ENGINE * e)
{
	return opensc_finish();
}

static int opensc_engine_init(ENGINE * e)
{
	return opensc_init();
}

/* Destructor */
static int opensc_engine_destroy(ENGINE * e)
{
	return 1;
}

static int opensc_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	switch (cmd) {
	case CMD_PIN:
		return set_pin((const char *) p);
	default:
		break;
	}
	return 0;
}

/* set up default rsa_meth_st with overloaded rsa functions */
/* the actual implementation needs to be in another object */

static int (*orig_finish) (RSA * rsa);

static int opensc_engine_rsa_finish(RSA * rsa)
{
	opensc_rsa_finish(rsa);

	if (orig_finish)
		orig_finish(rsa);
	return 1;
}

static RSA_METHOD *sc_get_rsa_method(void)
{
	static RSA_METHOD smart_rsa;
	const RSA_METHOD *def = RSA_get_default_method();

	/* use the OpenSSL version */
	memcpy(&smart_rsa, def, sizeof(smart_rsa));

	smart_rsa.name = "opensc";

	/* overload */
	smart_rsa.rsa_priv_enc = sc_private_encrypt;
	smart_rsa.rsa_priv_dec = sc_private_decrypt;
	smart_rsa.rsa_sign = sc_sign;

	/* save original */
	orig_finish = def->finish;
	smart_rsa.finish = opensc_engine_rsa_finish;

	/* set flags for sign version */
	smart_rsa.flags |= RSA_FLAG_SIGN_VER;
	return &smart_rsa;
}

/* This internal function is used by ENGINE_opensc() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, OPENSC_ENGINE_ID) ||
	    !ENGINE_set_destroy_function(e, opensc_engine_destroy) ||
	    !ENGINE_set_init_function(e, opensc_engine_init) ||
	    !ENGINE_set_finish_function(e, opensc_engine_finish) ||
	    !ENGINE_set_ctrl_function(e, opensc_engine_ctrl) ||
	    !ENGINE_set_cmd_defns(e, opensc_cmd_defns) ||
	    !ENGINE_set_name(e, OPENSC_ENGINE_NAME) ||
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, sc_get_rsa_method()) ||
#endif
#ifndef OPENSSL_NO_DSA
	    !ENGINE_set_DSA(e, DSA_get_default_method()) ||
#endif
#ifndef OPENSSL_NO_DH
	    !ENGINE_set_DH(e, DH_get_default_method()) ||
#endif
	    !ENGINE_set_RAND(e, RAND_SSLeay()) ||
#if 0
	    !ENGINE_set_BN_mod_exp(e, BN_mod_exp) ||
#endif
	    !ENGINE_set_load_pubkey_function(e, opensc_load_public_key) ||
	    !ENGINE_set_load_privkey_function(e, opensc_load_private_key)) {
		return 0;
	} else {
		return 1;
	}
}

static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, OPENSC_ENGINE_ID) != 0)) {
		fprintf(stderr, "bad engine id\n");
		return 0;
	}
	if (!bind_helper(e)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn);
