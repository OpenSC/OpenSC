/*
 * Copyright (c) 2002 Juha Yrjölä.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.
 * Copyright (c) 2002 Olaf Kirch
 * Copyright (c) 2003 Kevin Stefanik
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */



#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include "pkcs11-internal.h"
#include "engine_pkcs11.h"

#define fail(msg) { fprintf(stderr,msg); return NULL;}

PKCS11_CTX	*ctx;
char* pin;
int quiet=1;

#ifndef _WIN32
const char *module = "opensc-pkcs11.so";
#else
const char *module = "opensc-pkcs11";  /* no need to add .dll */
#endif

int set_module(const char *modulename) {
	module=modulename;
	return 1;
}

char* get_pin(UI_METHOD* ui_method, char* sc_pin, int maxlen) {
	UI* ui;
	ui=UI_new();
	UI_set_method(ui,ui_method);
	if(!UI_add_input_string(ui, "SmartCard Password: ", 0, sc_pin, 1, maxlen)) {
			fprintf(stderr, "UI_add_input_string failed"); 
			UI_free(ui); return NULL; }
	if(!UI_process(ui)) {
			fprintf(stderr, "UI_process failed"); return NULL;}
	UI_free(ui);
	return sc_pin;

}

int pkcs11_finish(ENGINE *engine) {
	
	if (ctx) {
		PKCS11_CTX_free(ctx);
	}

	return 1;
}

int pkcs11_init(ENGINE *engine) {
	int r=0;
	
	if(!quiet)
		fprintf(stderr,"initializing engine");

	ctx = PKCS11_CTX_new();
	if (PKCS11_CTX_load(ctx, module) < 0) {
		fprintf(stderr, "unable to load module");
		return 0;
	}

	return 1;
}

int
pkcs11_rsa_finish(RSA* rsa) {
	
	if(pin) {free(pin);}
	/* need to free RSA_ex_data? */
	return 1;

}


EVP_PKEY *pkcs11_load_key(ENGINE *e, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data, int private) {

	PKCS11_SLOT	*slot_list, *slot;
	PKCS11_TOKEN	*tok;
	PKCS11_KEY	*keys;
	PKCS11_CERT	*certs;
	EVP_PKEY	*pk;
	unsigned int	count, n, m;

	char		flags[64];
	int		logged_in = 0;
 
	/* if(pin) {free(pin); pin=NULL;} // keep cached key? */

	if (PKCS11_enumerate_slots(ctx, &slot_list, &count) < 0)
		fail("failed to enumerate slots");

	printf("Found %u slot%s\n", count, (count <= 1)? "" : "s");
again:
	for (n = 0; n < count; n++) {
		slot = slot_list + n;
		flags[0] = '\0';
		if (slot->token) {
			if (!slot->token->initialized)
				strcat(flags, "uninitialized, ");
			else if (!slot->token->userPinSet)
				strcat(flags, "no pin, ");
			if (slot->token->loginRequired)
				strcat(flags, "login, ");
			if (slot->token->readOnly)
				strcat(flags, "ro, ");
		} else {
			strcpy(flags, "no token");
		}
		if ((m = strlen(flags)) != 0) {
			flags[m-2] = '\0';
		}
		printf("[%u] %-25.25s  %-16s", n, slot->description, flags);
		if (slot->token) {
			printf("  (%s)",
				slot->token->label[0]?
					slot->token->label : "no label");
		}
		printf("\n");
	}

	if (!(slot = PKCS11_find_token(ctx)))
		fail("didn't find any tokens");
	tok = slot->token;

	if (!tok->initialized) {
		printf("Found uninitialized token; \n"); 
		return NULL;


	}

	 if (private && !tok->userPinSet && !tok->readOnly) {
		printf("Found slot without user PIN\n");
		return NULL;
	}

	printf("Found slot:  %s\n", slot->description);
	printf("Found token: %s\n", slot->token->label);

	if (PKCS11_enumerate_certs(tok, &certs, &count))
		fail("unable to enumerate certificates");

	printf("Found %u certificate%s:\n", count, (count <= 1)? "" : "s");
	for (n = 0; n < count; n++) {
		PKCS11_CERT	*c = certs + n;
		char		*dn = NULL;

		printf("  %2u    %s", n+1,
			c->label);
		if (c->x509)
			dn = X509_NAME_oneline(X509_get_subject_name(c->x509), NULL, 0);
		if (dn) {
			printf(" (%s)", dn);
			OPENSSL_free(dn);
		}
		printf("\n");
	}

	while (1) {
		if (PKCS11_enumerate_keys(tok, &keys, &count))
			fail("unable to enumerate keys");
		if (count)
			break;
		if (logged_in || !tok->loginRequired)
			break;
		if (pin == NULL) {
			pin=malloc(12);
			get_pin(ui_method,pin,12); 
		}
		if (PKCS11_login(slot, 0, pin))
			fail("Card login failed");
		logged_in++;
	}

	if (count == 0) {
		printf("No keys found.\n");
		return NULL;
	}

	printf("Found %u key%s:\n", count, (count <= 1)? "" : "s");
	for (n = 0; n < count; n++) {
		PKCS11_KEY	*k = keys + n;

		printf("  %2u %c%c %s\n", n+1,
			k->private? 'P' : ' ',
			k->needLogin? 'L' : ' ',
			k->label);
	}

	if (count == 0)
		return NULL;

	if(private) {
		pk = PKCS11_get_private_key(&keys[0]);
	} else {
		/*pk = PKCS11_get_public_key(&keys[0]);
		need a get_public_key? */
		pk = PKCS11_get_private_key(&keys[0]);
	}

	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE *e, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data) {
	EVP_PKEY *pk;
	pk=pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL)
			fail("PKCS11_load_public_key returned NULL");
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE *e, const char *s_key_id,
	UI_METHOD *ui_method, void *callback_data) {
		EVP_PKEY* pk;
		pk=pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
		if (pk == NULL)
			fail("PKCS11_get_private_key returned NULL");
		return pk;
}
