/*
 * Copyright (c) 2002 Juha Yrjölä.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "engine_opensc.h"

/* static state info one card/reader at a time */
static int verbose = 0;
static int sc_reader_id = 0;
static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static sc_pkcs15_card_t *p15card = NULL;
static char *sc_pin = NULL;

int opensc_finish(void)
{
	if (p15card) {
		sc_pkcs15_unbind(p15card);
		p15card = NULL;
	}
	if (card) {
		sc_disconnect_card(card, 0);
		card = NULL;
	}
	if (ctx) {
		sc_release_context(ctx);
		ctx = NULL;
	}
	unset_pin();
	return 1;
}

int opensc_init(void)
{
	int r = 0;

	if (verbose)
		fprintf(stderr, "initializing engine");

	r = sc_establish_context(&ctx, "openssl");
	if (r)
		goto err;

	r = sc_connect_card(ctx->reader[sc_reader_id], 0, &card);
	if (r)
		goto err;
	r = sc_pkcs15_bind(card, &p15card);
	if (r)
		goto err;
	return 1;
      err:
	/* need to do engine stuff? */
	fprintf(stderr, "error: %d", r);
	opensc_finish();
	return 0;
}

int opensc_rsa_finish(RSA * rsa)
{
	struct sc_pkcs15_key_id *key_id;

	key_id = (struct sc_pkcs15_key_id *) RSA_get_app_data(rsa);
	free(key_id);
	unset_pin();
	return 1;
}

BIGNUM *sc_bignum_t_to_BIGNUM(sc_pkcs15_bignum_t * bignum, BIGNUM * BN)
{
	BN_bin2bn((unsigned char *) bignum->data, bignum->len, BN);
	return BN;
}

void sc_set_pubkey_data(EVP_PKEY * key_out, sc_pkcs15_pubkey_t * pubkey)
{
	key_out->pkey.rsa->n =
	    sc_bignum_t_to_BIGNUM(&(pubkey->u.rsa.modulus), BN_new());
	key_out->pkey.rsa->e =
	    sc_bignum_t_to_BIGNUM(&(pubkey->u.rsa.exponent), BN_new());
}

/* private key operations */

#define SC_USAGE_DECRYPT	SC_PKCS15_PRKEY_USAGE_DECRYPT | \
				SC_PKCS15_PRKEY_USAGE_UNWRAP

#define SC_USAGE_SIGN 		SC_PKCS15_PRKEY_USAGE_SIGN | \
				SC_PKCS15_PRKEY_USAGE_SIGNRECOVER

int sc_prkey_op_init(const RSA * rsa, struct sc_pkcs15_object **key_obj_out,
	unsigned int usage)
{
	int r;
	struct sc_pkcs15_object *key_obj;
	struct sc_pkcs15_prkey_info *key;
	struct sc_pkcs15_id *key_id;
	struct sc_pkcs15_object *pin_obj;
	struct sc_pkcs15_pin_info *pin;

	key_id = (struct sc_pkcs15_id *) RSA_get_app_data(rsa);
	if (key_id == NULL) {
		fprintf(stderr, "key not loaded yet");
		return -1;
	}

	if (p15card == NULL) {
		opensc_finish();
		r = opensc_init();
		if (r) {
			fprintf(stderr, "SmartCard init failed: %s", sc_strerror(r));
			goto err;
		}
	}
	r = sc_pkcs15_find_prkey_by_id_usage(p15card, key_id, usage, &key_obj);
	if (r) {
		fprintf(stderr, "Unable to find private key from SmartCard: %s",
			sc_strerror(r));
		goto err;
	}
	key = (struct sc_pkcs15_prkey_info *) key_obj->data;
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &key_obj->auth_id, &pin_obj);
	if (r) {
		fprintf(stderr, "Unable to find PIN object from SmartCard: %s",
			sc_strerror(r));
		goto err;
	}
	pin = (struct sc_pkcs15_pin_info *) pin_obj->data;

	r = sc_lock(card);
	if (r) {
		fprintf(stderr, "Unable to lock smartcard: %s", sc_strerror(r));
		goto err;
	}
	if (sc_pin != NULL) {
		r = sc_pkcs15_verify_pin(p15card, pin, (const u8 *) sc_pin,
					 strlen(sc_pin));
		if (r) {
			sc_unlock(card);
			fprintf(stderr, "PIN code verification failed: %s",
				sc_strerror(r));
			/* forget the pin if verification fails */
			unset_pin();
			goto err;
		}
	} else {
		fprintf(stderr, "Warning: PIN not verified");
	}
	*key_obj_out = key_obj;
	return 0;
      err:
	return -1;
}

EVP_PKEY *opensc_load_public_key(ENGINE * e, const char *s_key_id,
				 UI_METHOD * ui_method, void *callback_data)
{
	int r;
	struct sc_pkcs15_id *id;
	struct sc_pkcs15_object *obj;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	sc_pkcs15_cert_t *cert = NULL;
	EVP_PKEY *key_out = NULL;

	if (verbose)
		fprintf(stderr, "Loading public key!\n");
	id = (struct sc_pkcs15_id *) malloc(sizeof(struct sc_pkcs15_id));
	if (sc_pkcs15_hex_string_to_id(s_key_id, id) < 0) {
		fprintf(stderr, "failed convert hex pkcs15 id\n");
		free(id);
		return NULL;
	}

	r = sc_pkcs15_find_pubkey_by_id(p15card, id, &obj);
	if (r >= 0) {
		if (verbose)
			printf("Reading public key with ID '%s'\n", s_key_id);
		r = sc_pkcs15_read_pubkey(p15card, obj, &pubkey);
	} else if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		/* No pubkey - try if there's a certificate */
		r = sc_pkcs15_find_cert_by_id(p15card, id, &obj);
		if (r >= 0) {
			if (verbose)
				printf("Reading certificate with ID '%s'\n",
				       s_key_id);
			r = sc_pkcs15_read_certificate(p15card,
						       (sc_pkcs15_cert_info_t *)
						       obj->data, &cert);
		}
		if (r >= 0)
			pubkey = &cert->key;
	}

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		fprintf(stderr, "Public key with ID '%s' not found.\n", s_key_id);
		free(id);
		return NULL;
	}
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n",
			sc_strerror(r));
		free(id);
		return NULL;
	}

	/* now, set EVP_PKEY data from pubkey object */
	key_out = EVP_PKEY_new();
	if (!key_out) {
		fprintf(stderr, "failed to create new EVP_PKEY\n");
		return NULL;
	};
	EVP_PKEY_assign_RSA(key_out, RSA_new_method(e));
#if 0
	RSA_set_method(keyout->rsa, sc_get_rsa_method());
#endif
	key_out->pkey.rsa->flags |= RSA_FLAG_EXT_PKEY || RSA_FLAG_SIGN_VER;
	RSA_set_app_data(key_out->pkey.rsa, id);
	sc_set_pubkey_data(key_out, pubkey);

	if (cert)
		sc_pkcs15_free_certificate(cert);
	else if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);
	return key_out;
}

void unset_pin(void)
{
	if (sc_pin) {
		free(sc_pin);
		sc_pin = NULL;
	}
}

int set_pin(const char *_pin)
{
	/* free the old pin if set */
	unset_pin();
	if (!_pin) {
		return 0;
	}
	sc_pin = strdup(_pin);
	if (!sc_pin) {
		return 0;
	}
	return 1;
}

char *get_pin(UI_METHOD * ui_method, char *sc_pin, int maxlen)
{
	UI *ui;

	ui = UI_new();
	if (ui_method)
		UI_set_method(ui, ui_method);
	if (!UI_add_input_string(ui, "SmartCard Password: ", 0, sc_pin, 1, maxlen)) {
		fprintf(stderr, "UI_add_input_string failed");
		UI_free(ui);
		return NULL;
	}
	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed");
		UI_free(ui);
		return NULL;
	}
	UI_free(ui);
	return sc_pin;
}

EVP_PKEY *opensc_load_private_key(ENGINE * e, const char *s_key_id,
				  UI_METHOD * ui_method, void *callback_data)
{
	EVP_PKEY *key_out;

	if (verbose)
		fprintf(stderr, "Loading private key!");
	key_out = opensc_load_public_key(e, s_key_id, ui_method, callback_data);
	if (!key_out) {
		fprintf(stderr, "Failed to load public key");
		return NULL;
	}
	if (!sc_pin) {
		sc_pin = (char *) malloc(12);
		if (!sc_pin) {
			EVP_PKEY_free(key_out);
			return NULL;
		}
		if (!get_pin(ui_method, sc_pin, 12)) {
			fprintf(stderr, "Failed to get pin");
			unset_pin();
			EVP_PKEY_free(key_out);
			return NULL;
		}
		/* do this here, when storing sc_pin in RSA */
	}
	return key_out;
}

int
sc_private_decrypt(int flen, const unsigned char * from, unsigned char * to,
		   RSA * rsa, int padding)
{
	struct sc_pkcs15_object *key_obj;
	int r;
	unsigned long flags = 0;

	r = sc_prkey_op_init(rsa, &key_obj, SC_USAGE_DECRYPT);
	if (r)
		return -1;
	/* set padding flags */
	if (padding == RSA_PKCS1_PADDING)
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	else if (padding == RSA_NO_PADDING)
		flags |= SC_ALGORITHM_RSA_RAW;
	else	/* not supported */
		return -1;
		
	r = sc_pkcs15_decipher(p15card, key_obj, flags, from, flen, to, flen);
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "sc_pkcs15_decipher() failed: %s", sc_strerror(r));
		goto err;
	}
	return r;
      err:
	return -1;
}

int
sc_sign(int type, const unsigned char * m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, const RSA * rsa)
{
	struct sc_pkcs15_object *key_obj;
	int r;
	unsigned long flags = 0;

	if (verbose)
		fprintf(stderr, "signing with type %d\n", type);
	r = sc_prkey_op_init(rsa, &key_obj, SC_USAGE_SIGN);
	if (r)
		return -1;
	/* FIXME: length of sigret correct? */
	/* FIXME: check 'type' and modify flags accordingly */
	flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	if (type == NID_sha1)
		flags |= SC_ALGORITHM_RSA_HASH_SHA1;
	if (type == NID_md5)
		flags |= SC_ALGORITHM_RSA_HASH_MD5;
	r = sc_pkcs15_compute_signature(p15card, key_obj, flags,
					m, m_len, sigret, RSA_size(rsa));
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "sc_pkcs15_compute_signature() failed: %s",
			sc_strerror(r));
		goto err;
	}
	*siglen = r;
	return 1;
      err:
	return 0;
}

int
sc_private_encrypt(int flen, const unsigned char * from, unsigned char * to,
		   RSA * rsa, int padding)
{
	fprintf(stderr, "Private key encryption not supported");
	return -1;
}
