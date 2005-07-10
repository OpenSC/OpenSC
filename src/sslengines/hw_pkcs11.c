/* crypto/engine/hw_pkcs11.c */
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

#include <libp11.h>
#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#ifndef ENGINE_CMD_BASE
#error did not get engine.h
#endif
#include <openssl/crypto.h>
#include <openssl/dso.h>
#include "engine_pkcs11.h"

#define PKCS11_ENGINE_ID "pkcs11"
#define PKCS11_ENGINE_NAME "pkcs11 engine"

#define CMD_SO_PATH		ENGINE_CMD_BASE
#define CMD_MODULE_PATH 	(ENGINE_CMD_BASE+1)
#define CMD_PIN		(ENGINE_CMD_BASE+2)
#define CMD_VERBOSE		(ENGINE_CMD_BASE+3)
#define CMD_QUIET		(ENGINE_CMD_BASE+4)
#define CMD_LOAD_CERT_CTRL	(ENGINE_CMD_BASE+5)

static int pkcs11_engine_destroy(ENGINE * e);
static int pkcs11_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ());

/* The definitions for control commands specific to this engine */

/* need to add function to pass in reader id? or user reader:key as key id string? */

static const ENGINE_CMD_DEFN pkcs11_cmd_defns[] = {
	{CMD_SO_PATH,
	 "SO_PATH",
	 "Specifies the path to the 'pkcs11-engine' shared library",
	 ENGINE_CMD_FLAG_STRING},
	{CMD_MODULE_PATH,
	 "MODULE_PATH",
	 "Specifies the path to the pkcs11 module shared library",
	 ENGINE_CMD_FLAG_STRING},
	{CMD_PIN,
	 "PIN",
	 "Specifies the pin code",
	 ENGINE_CMD_FLAG_STRING},
	{CMD_VERBOSE,
	 "VERBOSE",
	 "Print additional details",
	 ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_QUIET,
	 "QUIET",
	 "Remove additional details",
	 ENGINE_CMD_FLAG_NO_INPUT},
	{CMD_LOAD_CERT_CTRL,
	 "LOAD_CERT_CTRL",
	 "Get the certificate from card",
	 ENGINE_CMD_FLAG_INTERNAL},
	{0, NULL, NULL, 0}
};

/* Destructor */
static int pkcs11_engine_destroy(ENGINE * e)
{
	return 1;
}

static int pkcs11_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ())
{
	/*int initialised = ((pkcs11_dso == NULL) ? 0 : 1); */
	switch (cmd) {
	case CMD_MODULE_PATH:
		return set_module((const char *) p);
	case CMD_PIN:
		return set_pin((const char *) p);
	case CMD_VERBOSE:
		return inc_verbose();
	case CMD_LOAD_CERT_CTRL:
		return load_cert_ctrl(e, p);
	default:
		break;
	}
	return 0;
}

/* set up default rsa_meth_st with overloaded rsa functions */
/* the actual implementation needs to be in another object */

static int (*orig_finish) (RSA * rsa);

static int pkcs11_engine_rsa_finish(RSA * rsa)
{

	pkcs11_rsa_finish(rsa);

	if (orig_finish)
		orig_finish(rsa);
	return 1;

}

/* This internal function is used by ENGINE_pkcs11() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE * e)
{
	if (!ENGINE_set_id(e, PKCS11_ENGINE_ID) ||
	    !ENGINE_set_destroy_function(e, pkcs11_engine_destroy) ||
	    !ENGINE_set_init_function(e, pkcs11_init) ||
	    !ENGINE_set_finish_function(e, pkcs11_finish) ||
	    !ENGINE_set_ctrl_function(e, pkcs11_engine_ctrl) ||
	    !ENGINE_set_cmd_defns(e, pkcs11_cmd_defns) ||
	    !ENGINE_set_name(e, PKCS11_ENGINE_NAME) ||
#ifndef OPENSSL_NO_RSA
	    !ENGINE_set_RSA(e, pkcs11_get_rsa_method()) ||
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
	    !ENGINE_set_load_pubkey_function(e, pkcs11_load_public_key) ||
	    !ENGINE_set_load_privkey_function(e, pkcs11_load_private_key)) {
		return 0;
	} else {
		return 1;
	}
}

static int bind_fn(ENGINE * e, const char *id)
{
	if (id && (strcmp(id, PKCS11_ENGINE_ID) != 0)) {
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
