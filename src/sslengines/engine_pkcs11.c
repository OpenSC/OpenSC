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

#include "pkcs11-internal.h"
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include "engine_pkcs11.h"

#define fail(msg) { fprintf(stderr,msg); return NULL;}

PKCS11_CTX *ctx;
char *pin = NULL;
int verbose = 0;

char *module = PKCS11_DEFAULT_MODULE_NAME;
int default_module = 1;

int set_module(const char *modulename)
{
	module = strdup (modulename);
	default_module = 0;
	return 1;
}

int set_pin(const char *_pin)
{
	pin = strdup(_pin);
	return 1;
}

int inc_verbose()
{
	verbose++;
	return 1;
}

char *get_pin(UI_METHOD * ui_method, char *sc_pin, int maxlen)
{
	UI *ui;

	ui = UI_new();
	if (ui_method != NULL)
	    UI_set_method(ui, ui_method);
	if (!UI_add_input_string(ui, "SmartCard PIN: ", 0, sc_pin, 1, maxlen)) {
		fprintf(stderr, "UI_add_input_string failed\n");
		UI_free(ui);
		return NULL;
	}
	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		UI_free(ui);
		return NULL;
	}
	UI_free(ui);
	return sc_pin;
}

int pkcs11_finish(ENGINE * engine)
{
	if (ctx) {
		PKCS11_CTX_free(ctx);
	}
	return 1;
}

int pkcs11_init(ENGINE * engine)
{
	if (verbose) {
		fprintf(stderr, "initializing engine\n");
	}
	ctx = PKCS11_CTX_new();
	if (PKCS11_CTX_load(ctx, module) < 0) {
		fprintf(stderr, "unable to load module %s\n", module);
		return 0;
	}
	return 1;
}

int pkcs11_rsa_finish(RSA * rsa)
{
	if (pin) {
		free(pin);
	}
	if (!default_module && module) {
		free(module);
	}
	/* need to free RSA_ex_data? */
	return 1;
}

static int hex_to_bin(const char *in, unsigned char *out, size_t * outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;
		char c;

		while (nybbles-- && *in && *in != ':') {
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				fprintf(stderr,"hex_to_bin(): invalid char '%c' in hex string\n", c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
			fprintf(stderr,"hex_to_bin(): hex string too long");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char) byte;
		left--;
		c++;
	}

	*outlen = count;
	return 1;
}

#define MAX_VALUE_LEN	200

EVP_PKEY *pkcs11_load_key(ENGINE * e, const char *s_slot_key_id,
			  UI_METHOD * ui_method, void *callback_data, int isPrivate)
{
	PKCS11_SLOT *slot_list, *slot;
	PKCS11_TOKEN *tok;
	PKCS11_KEY *keys, *selected_key = NULL;
	PKCS11_CERT *certs;
	EVP_PKEY *pk;
	unsigned int count, n, m;
	unsigned char key_id[MAX_VALUE_LEN / 2];
	char *s_key_id = NULL, buf[MAX_VALUE_LEN];
	size_t key_id_len = sizeof(key_id);
	int slot_nr = -1;
	char flags[64];
	int logged_in = 0;

	/* Parse s_slot_key_id: [slot_<slotNr>][-][id_<keyID>] or NULL,
	   with slotNr in decimal (0 = first slot, ...), and keyID in hex.
	   E.g. "slot_1" or "id_46" or "slot_1-id_46 */
	while (s_slot_key_id != NULL && *s_slot_key_id != '\0') {
		char *p_sep1, *p_sep2;
		char val[MAX_VALUE_LEN];
		int val_len;;

		p_sep1 = strchr(s_slot_key_id, '_');
		if (p_sep1 == NULL) {
			fprintf(stderr,"No \'_\' found in \"-key\" option \"%s\"\n", s_slot_key_id);
			fprintf(stderr,"Format: [slot_<slotNr>][-][id_<keyID>]\n");
			fprintf(stderr,"  with slotNr = 0, 1, ... and keyID = a hex string\n");
			return NULL;
		}

		p_sep2 = strchr(p_sep1, '-');
		if (p_sep2 == NULL)
			p_sep2 = p_sep1 + strlen(p_sep1);

		/* val = the string between the _ and the - (or '\0') */
		val_len = p_sep2 - p_sep1 - 1;
		if (val_len >= MAX_VALUE_LEN || val_len == 0)
			fail("Too long or empty value after the \'-\' sign\n");
		memcpy(val, p_sep1 + 1, val_len);
		val[val_len] = '\0';

		if (strncasecmp(s_slot_key_id, "slot", p_sep1 - s_slot_key_id) == 0) {
			if (val_len >= 3) {
				fprintf(stderr,"Slot number \"%s\" should be a small integer\n", val);
				return NULL;
			}
			slot_nr = atoi(val);
			if (slot_nr == 0 && val[0] != '0') {
				fprintf(stderr,"Slot number \"%s\" should be an integer\n", val);
				return NULL;
			}
		} else if (strncasecmp(s_slot_key_id, "id", p_sep1 - s_slot_key_id)
			   == 0) {
			if (!hex_to_bin(val, key_id, &key_id_len)) {
				fprintf(stderr,"Key id \"%s\" should be a hex string\n", val);
				return NULL;
			}
			strcpy(buf, val);
			s_key_id = buf;
		} else {
			memcpy(val, s_slot_key_id, p_sep1 - s_slot_key_id);
			val[p_sep1 - s_slot_key_id] = '\0';
			fprintf(stderr,"Now allowed in -key: \"%s\"\n", val);
			return NULL;
		}
		s_slot_key_id = (*p_sep2 == '\0' ? p_sep2 : p_sep2 + 1);
	}

	if (PKCS11_enumerate_slots(ctx, &slot_list, &count) < 0)
		fail("failed to enumerate slots\n");

	if(verbose) {
		fprintf(stderr,"Found %u slot%s\n", count, (count <= 1) ? "" : "s");
	}
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
			flags[m - 2] = '\0';
		}
		
		if(verbose) {
			fprintf(stderr,"[%u] %-25.25s  %-16s", n, slot->description, flags);
			if (slot->token) {
				fprintf(stderr,"  (%s)",
				       slot->token->label[0] ?
				       slot->token->label : "no label");
			}
			fprintf(stderr,"\n");
		}
	}

	if (slot_nr == -1) {
		if (!(slot = PKCS11_find_token(ctx)))
			fail("didn't find any tokens\n");
	} else if (slot_nr >= 0 && slot_nr < count)
		slot = slot_list + slot_nr;
	else {
		fprintf(stderr,"Invalid slot number: %d\n", slot_nr);
		return NULL;
	}
	tok = slot->token;

	if (tok == NULL) {
		fprintf(stderr,"Found empty token; \n");
		return NULL;
	}
#if 0 // Removed for interop with some other pkcs11 libs.
	if (!tok->initialized) {
		fprintf(stderr,"Found uninitialized token; \n");
		return NULL;
	}
#endif
	if (isPrivate && !tok->userPinSet && !tok->readOnly) {
		fprintf(stderr,"Found slot without user PIN\n");
		return NULL;
	}

	if(verbose) {
		fprintf(stderr,"Found slot:  %s\n", slot->description);
		fprintf(stderr,"Found token: %s\n", slot->token->label);
	}

	if (PKCS11_enumerate_certs(tok, &certs, &count))
		fail("unable to enumerate certificates\n");

	if(verbose) {
		fprintf(stderr,"Found %u certificate%s:\n", count, (count <= 1) ? "" : "s");
		for (n = 0; n < count; n++) {
			PKCS11_CERT *c = certs + n;
			char *dn = NULL;

			fprintf(stderr,"  %2u    %s", n + 1, c->label);
			if (c->x509)
				dn = X509_NAME_oneline(X509_get_subject_name(c->x509), NULL, 0);
			if (dn) {
				fprintf(stderr," (%s)", dn);
				OPENSSL_free(dn);
			}
			fprintf(stderr,"\n");
		}
	}

	while (1) {
		if (PKCS11_enumerate_keys(tok, &keys, &count))
			fail("unable to enumerate keys\n");
		if (count)
			break;
		if (logged_in || !tok->loginRequired)
			break;
		if (pin == NULL) {
			pin = (char *) malloc(12);
			get_pin(ui_method, pin, 12);
		}
		if (PKCS11_login(slot, 0, pin)) {
			if(pin != NULL) {
				free(pin);
				pin = NULL;
			}
			fail("Card login failed\n");
		}
		logged_in++;
	}

	if (count == 0) {
		fprintf(stderr,"No keys found.\n");
		return NULL;
	}

	if(verbose) {
		fprintf(stderr,"Found %u key%s:\n", count, (count <= 1) ? "" : "s");
	}
	for (n = 0; n < count; n++) {
		PKCS11_KEY *k = keys + n;

		if(verbose) {
			fprintf(stderr,"  %2u %c%c %s\n", n + 1,
			       k->isPrivate ? 'P' : ' ', k->needLogin ? 'L' : ' ', k->label);
		}
		if (key_id_len != 0 && k->id_len == key_id_len &&
		    memcmp(k->id, key_id, key_id_len) == 0) {
			if(verbose) {
				fprintf(stderr,"        ID = %s\n", s_key_id);
			}
			selected_key = k;
		}
	}

	if (selected_key == NULL) {
		if (s_key_id != NULL) {
			fprintf(stderr,"No key with ID \"%s\" found.\n", s_key_id);
			return NULL;
		} else		/* Take the first key that was found */
			selected_key = &keys[0];
	}

	if (isPrivate) {
		pk = PKCS11_get_private_key(selected_key);
	} else {
		/*pk = PKCS11_get_public_key(&keys[0]);
		   need a get_public_key? */
		pk = PKCS11_get_private_key(selected_key);
	}

	return pk;
}

EVP_PKEY *pkcs11_load_public_key(ENGINE * e, const char *s_key_id,
				 UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 0);
	if (pk == NULL)
		fail("PKCS11_load_public_key returned NULL\n");
	return pk;
}

EVP_PKEY *pkcs11_load_private_key(ENGINE * e, const char *s_key_id,
				  UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *pk;

	pk = pkcs11_load_key(e, s_key_id, ui_method, callback_data, 1);
	if (pk == NULL)
		fail("PKCS11_get_private_key returned NULL\n");
	return pk;
}
