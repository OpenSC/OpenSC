/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if defined(HAVE_OPENSSL) && defined(HAVE_LDAP)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <pwd.h>
#include <sys/stat.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/scldap.h>
#include <opensc/scrandom.h>
#include "scam.h"

typedef struct _scam_method_data {
	struct sc_context *ctx;
	struct sc_card *card;
	struct sc_pkcs15_card *p15card;
	scldap_context *lctx;
	int card_locked;

	struct sc_pkcs15_object *objs[32];
	struct sc_pkcs15_cert_info *cinfo;
	struct sc_pkcs15_object *prkey, *pin;
} scam_method_data;

const char *p15_ldap_usage(void)
{
	static char buf[500];

	memset(buf, 0, 500);
	snprintf(buf, 500,
		 " -r <reader>	Reader name\n"
		 "LDAP specific options:\n%s", scldap_show_arguments()
	    );
	return &buf[0];
}

int p15_ldap_init(scam_context * sctx, int argc, const char **argv)
{
	scam_method_data *data = NULL;
	char *reader_name = NULL;
	int r, i, reader = 0;

	if (sctx->method_data) {
		return SCAM_FAILED;
	}
	sctx->method_data = (scam_method_data *) malloc(sizeof(scam_method_data));
	if (!sctx->method_data) {
		return SCAM_FAILED;
	}
	memset(sctx->method_data, 0, sizeof(scam_method_data));
	data = (scam_method_data *) sctx->method_data;
	r = sc_establish_context(&data->ctx, "scam");
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_establish_context: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	for (i = 0; i < argc; i++) {
		if (argv[i][0] == '-') {
			char *optarg = (char *) argv[i + 1];
			if (!optarg)
				continue;
			switch (argv[i][1]) {
			case 'r':
				reader_name = strdup(optarg);
				break;
			}
		}
	}
	if (!reader_name) {
		for (i = 0; i < data->ctx->reader_count; i++) {
			printf("Reader #%d - %s%s\n", i + 1, data->ctx->reader[i]->name, reader == i ? " (*)" : "");
		}
	} else {
		for (i = 0; i < data->ctx->reader_count; i++) {
			if ((strlen(reader_name) < strlen(data->ctx->reader[i]->name))) {
				if (!strncmp(reader_name, data->ctx->reader[i]->name, strlen(reader_name))) {
					reader = i;
					printf("Reader #%d - %s selected\n", i + 1, data->ctx->reader[reader]->name);
					break;
				}
			}
		}
		free(reader_name);
	}

	if ((r = sc_connect_card(data->ctx->reader[reader], 0, &data->card)) != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_connect_card: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	sc_lock(data->card);
	data->card_locked = 1;

	r = sc_pkcs15_bind(data->card, &data->p15card);
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_bind: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_get_objects(data->p15card, SC_PKCS15_TYPE_CERT_X509, data->objs, 32);
	if (r < 0) {
		scam_print_msg(sctx, "sc_pkcs15_get_objects: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	if (r == 0)		/* No certificates found */
		return SCAM_FAILED;

	/* FIXME: Add support for selecting certificate by ID */
	data->cinfo = (struct sc_pkcs15_cert_info *) data->objs[0]->data;

	r = sc_pkcs15_find_prkey_by_id_usage(data->p15card,
				&data->cinfo->id,
				SC_PKCS15_PRKEY_USAGE_SIGN,
				&data->prkey);
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_find_prkey_by_id_usage: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_find_pin_by_auth_id(data->p15card, &data->prkey->auth_id, &data->pin);
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_find_pin_by_auth_id: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	data->lctx = scldap_parse_parameters(SCLDAP_CONF_PATH);
	if (!data->lctx) {
		return SCAM_FAILED;
	}
	scldap_parse_arguments(&data->lctx, argc, argv);
	return SCAM_SUCCESS;
}

const char *p15_ldap_pinentry(scam_context * sctx)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;
	struct sc_pkcs15_pin_info *pininfo = NULL;
	static char buf[64];

	if (!sctx->method_data) {
		return NULL;
	}
	pininfo = (struct sc_pkcs15_pin_info *) data->pin->data;
	snprintf(buf, 64, "Enter PIN%d [%s]: ", pininfo->reference, data->pin->label);
	return buf;
}

int p15_ldap_qualify(scam_context * sctx, unsigned char *password)
{
	if (!sctx->method_data) {
		return SCAM_FAILED;
	}
	if (!password)
		return SCAM_FAILED;
	/* FIXME */
#if 0
	if (scQualifyPin(password) < 0)
		return SCAM_FAILED;
#endif
	return SCAM_SUCCESS;
}

int p15_ldap_auth(scam_context * sctx, int argc, const char **argv,
		  const char *user, const char *password)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;
	struct sc_pkcs15_cert *p15cert = NULL;
	u8 random_data[20], chg[256], txt[256];
	int r, err = SCAM_FAILED, chglen;
	EVP_PKEY *pubkey = NULL;
	X509 *cert = NULL;
	unsigned char *ptr = NULL;

	if (!sctx->method_data) {
		return SCAM_FAILED;
	}
	r = sc_pkcs15_read_certificate(data->p15card, data->cinfo, &p15cert);
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_read_certificate: %s\n", sc_strerror(r));
		goto end;
	}
	cert = X509_new();
	ptr = p15cert->data;
	if (!d2i_X509(&cert, &ptr, p15cert->data_len)) {
		scam_log_msg(sctx, "Invalid certificate. (user %s)\n", user);
		goto end;
	}
	pubkey = X509_get_pubkey(cert);
	if (!pubkey) {
		scam_log_msg(sctx, "Invalid public key. (user %s)\n", user);
		goto end;
	}
	chglen = RSA_size(pubkey->pkey.rsa);
	if (chglen > sizeof(chg)) {
		scam_print_msg(sctx, "RSA key too big.\n");
		goto end;
	}
	r = scrandom_get_data(random_data, sizeof(random_data));
	if (r < 0) {
		scam_log_msg(sctx, "scrandom_get_data failed.\n");
		goto end;
	}
	RAND_seed(random_data, sizeof(random_data));
	r = sc_pkcs15_verify_pin(data->p15card, (struct sc_pkcs15_pin_info *) data->pin->data, (const u8 *) password, strlen(password));
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_verify_pin: %s\n", sc_strerror(r));
		goto end;
	}
	r = sc_pkcs15_compute_signature(data->p15card, data->prkey, SC_ALGORITHM_RSA_PAD_PKCS1,
					random_data, 20, chg, chglen);
	if (r < 0) {
		scam_print_msg(sctx, "sc_pkcs15_compute_signature: %s\n", sc_strerror(r));
		goto end;
	}
	r = RSA_public_decrypt(chglen, chg, txt, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (r < 0) {
		scam_print_msg(sctx, "Signature verification failed.\n");
		goto end;
	}
	if (r == sizeof(random_data) && !memcmp(txt, random_data, r)) {
		err = SCAM_SUCCESS;
	}
      end:
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (cert)
		X509_free(cert);
	if (p15cert)
		sc_pkcs15_free_certificate(p15cert);
	return err;
}

void p15_ldap_deinit(scam_context * sctx)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;

	if (!sctx->method_data) {
		return;
	}
	if (data->lctx) {
		scldap_free_parameters(data->lctx);
	}
	data->lctx = NULL;
	if (data->card_locked) {
		sc_unlock(data->card);
	}
	data->card_locked = 0;
	if (data->p15card) {
		sc_pkcs15_unbind(data->p15card);
	}
	data->p15card = NULL;
	if (data->card) {
		sc_disconnect_card(data->card, 0);
	}
	data->card = NULL;
	if (data->ctx) {
		sc_release_context(data->ctx);
	}
	data->ctx = NULL;
	free(sctx->method_data);
	sctx->method_data = NULL;
}

struct scam_framework_ops scam_fw_p15_ldap =
{
	"pkcs15-ldap",		/* name */
	p15_ldap_usage,		/* usage */
	p15_ldap_init,		/* init */
	p15_ldap_pinentry,	/* pinentry */
	p15_ldap_qualify,	/* qualify */
	p15_ldap_auth,		/* auth */
	p15_ldap_deinit,	/* deinit */
#if defined(HAVE_OPENSSL) && defined(HAVE_LDAP) && defined(HAVE_SCIDI)
	sp_open_session,	/* open_session */
	sp_close_session	/* close_session */
#else
	NULL,			/* open_session */
	NULL			/* close_session */
#endif
};

#endif
