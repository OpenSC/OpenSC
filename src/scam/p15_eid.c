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
#if defined(HAVE_OPENSSL)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/scrandom.h>
#include "scam.h"

static struct sc_context *ctx = NULL;
static struct sc_card *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;
static int card_locked = 0;

static struct sc_pkcs15_object *objs[32];
static struct sc_pkcs15_cert_info *cinfo = NULL;
static struct sc_pkcs15_object *prkey = NULL, *pin = NULL;

static const char *eid_path = ".eid";
static const char *auth_cert_file = "authorized_certificates";

const char *p15_eid_usage(void)
{
	static char buf[500];

	memset(buf, 0, 500);
	snprintf(buf, 500,
		 " -r <reader>	Reader name\n"
	    );
	return &buf[0];
}

int p15_eid_init(scam_context * scamctx, int argc, const char **argv)
{
	char *reader_name = NULL;
	int r, i, reader = 0;

	if (ctx) {
		return SCAM_FAILED;
	}
	r = sc_establish_context(&ctx, "scam");
	if (r != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_establish_context: %s\n", sc_strerror(r));
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
		for (i = 0; i < ctx->reader_count; i++) {
			printf("Reader #%d - %s%s\n", i + 1, ctx->reader[i]->name, reader == i ? " (*)" : "");
		}
	} else {
		for (i = 0; i < ctx->reader_count; i++) {
			if ((strlen(reader_name) < strlen(ctx->reader[i]->name))) {
				if (!strncmp(reader_name, ctx->reader[i]->name, strlen(reader_name))) {
					reader = i;
					printf("Reader #%d - %s selected\n", i + 1, ctx->reader[reader]->name);
					break;
				}
			}
		}
		free(reader_name);
	}

	if ((r = sc_connect_card(ctx->reader[reader], 0, &card)) != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_connect_card: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	sc_lock(card);
	card_locked = 1;

	r = sc_pkcs15_bind(card, &p15card);
	if (r != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_pkcs15_bind: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		scam_print_msg(scamctx, "sc_pkcs15_get_objects: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	if (r == 0)		/* No certificates found */
		return SCAM_FAILED;

	/* FIXME: Add support for selecting certificate by ID */
	cinfo = objs[0]->data;

	r = sc_pkcs15_find_prkey_by_id(p15card, &cinfo->id, &prkey);
	if (r != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_pkcs15_find_prkey_by_id: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &prkey->auth_id, &pin);
	if (r != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_pkcs15_find_pin_by_auth_id: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	return SCAM_SUCCESS;
}

const char *p15_eid_pinentry(scam_context * scamctx)
{
	struct sc_pkcs15_pin_info *pininfo = NULL;
	static char buf[64];

	if (!ctx || !pin) {
		return NULL;
	}
	pininfo = pin->data;
	snprintf(buf, 64, "Enter PIN%d [%s]: ", pininfo->reference, pin->label);
	return buf;
}

int p15_eid_qualify(scam_context * scamctx, unsigned char *password)
{
	if (!password)
		return SCAM_FAILED;
	/* FIXME */
#if 0
	if (scQualifyPin(password) < 0)
		return SCAM_FAILED;
#endif
	return SCAM_SUCCESS;
}

static int format_eid_dir_path(const char *user, char **buf)
{
	struct passwd *pwent = getpwnam(user);
	char *dir = NULL;

	if (!pwent)
		return SCAM_FAILED;
	dir = malloc(strlen(pwent->pw_dir) + strlen(eid_path) + 2);
	if (!dir)
		return SCAM_FAILED;
	strcpy(dir, pwent->pw_dir);
	strcat(dir, "/");
	strcat(dir, eid_path);
	*buf = dir;
	return SCAM_SUCCESS;
}

static int is_eid_dir_present(const char *user)
{
	char *eid_dir = NULL;
	struct stat stbuf;
	int r;

	r = format_eid_dir_path(user, &eid_dir);
	if (r != SCAM_SUCCESS)
		return r;
	r = stat(eid_dir, &stbuf);
	/* FIXME: Check if owned by myself and if group/world-writable */
	free(eid_dir);
	if (r)
		return SCAM_FAILED;	/* User has no .eid, or .eid unreadable */
	return SCAM_SUCCESS;
}

static int get_certificate(const char *user, X509 ** cert_out)
{
	char *dir = NULL, *cert_path = NULL;
	int r;
	BIO *in = NULL;
	X509 *cert = NULL;
	int err = SCAM_FAILED;

	r = format_eid_dir_path(user, &dir);
	if (r != SCAM_SUCCESS)
		return r;
	cert_path = malloc(strlen(dir) + strlen(auth_cert_file) + 2);
	if (!cert_path) {
		goto end;
	}
	strcpy(cert_path, dir);
	strcat(cert_path, "/");
	strcat(cert_path, auth_cert_file);
	in = BIO_new(BIO_s_file());
	if (!in) {
		goto end;
	}
	if (BIO_read_filename(in, cert_path) <= 0) {
		goto end;
	}
	cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
	if (!cert)
		goto end;
	*cert_out = cert;
	err = SCAM_SUCCESS;
      end:
	if (in)
		BIO_free(in);
	if (dir)
		free(dir);
	if (cert_path)
		free(cert_path);
	return err;
}

int p15_eid_auth(scam_context * scamctx, int argc, const char **argv,
		 const char *user, const char *password)
{
	u8 random_data[20], chg[256], txt[256];
	int r, err = SCAM_FAILED, chglen;
	EVP_PKEY *pubkey = NULL;
	X509 *cert = NULL;

	if (!ctx)
		return SCAM_FAILED;
	r = is_eid_dir_present(user);
	if (r != SCAM_SUCCESS) {
		scam_print_msg(scamctx, "No such user, user has no .eid directory or .eid unreadable.\n");
		goto end;
	}
	r = get_certificate(user, &cert);
	if (r != SCAM_SUCCESS) {
		scam_print_msg(scamctx, "get_certificate failed.\n");
		goto end;
	}
	pubkey = X509_get_pubkey(cert);
	if (!pubkey) {
		scam_log_msg(scamctx, "Invalid public key. (user %s)\n", user);
		goto end;
	}
	chglen = RSA_size(pubkey->pkey.rsa);
	if (chglen > sizeof(chg)) {
		scam_print_msg(scamctx, "RSA key too big.\n");
		goto end;
	}
	r = scrandom_get_data(random_data, sizeof(random_data));
	if (r < 0) {
		scam_log_msg(scamctx, "scrandom_get_data failed.\n");
		goto end;
	}
	r = sc_pkcs15_verify_pin(p15card, pin->data, (const u8 *) password, strlen(password));
	if (r != SC_SUCCESS) {
		scam_print_msg(scamctx, "sc_pkcs15_verify_pin: %s\n", sc_strerror(r));
		goto end;
	}
	r = sc_pkcs15_compute_signature(p15card, prkey, SC_ALGORITHM_RSA_PAD_PKCS1,
					random_data, 20, chg, chglen);
	if (r < 0) {
		scam_print_msg(scamctx, "sc_pkcs15_compute_signature: %s\n", sc_strerror(r));
		goto end;
	}
	r = RSA_public_decrypt(chglen, chg, txt, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (r < 0) {
		scam_print_msg(scamctx, "Signature verification failed.\n");
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
	return err;
}

void p15_eid_deinit(scam_context * scamctx)
{
	if (card_locked) {
		sc_unlock(card);
	}
	card_locked = 0;
	if (p15card) {
		sc_pkcs15_unbind(p15card);
	}
	p15card = NULL;
	if (card) {
		sc_disconnect_card(card, 0);
	}
	card = NULL;
	if (ctx) {
		sc_release_context(ctx);
	}
	ctx = NULL;
}

#ifdef ATR_SUPPORT
static const char *p15_eid_atrs[] =
{
	"3B:9F:94:40:1E:00:67:11:43:46:49:53:45:10:52:66:FF:81:90:00",
	NULL
};
#endif

struct scam_framework_ops scam_fw_p15_eid =
{
	"pkcs15-eid",		/* name */
#ifdef ATR_SUPPORT
	p15_eid_atrs,		/* atrs */
#endif
	p15_eid_usage,		/* usage */
	p15_eid_init,		/* init */
	p15_eid_pinentry,	/* pinentry */
	p15_eid_qualify,	/* qualify */
	p15_eid_auth,		/* auth */
	p15_eid_deinit,		/* deinit */
#ifndef HAVE_SCIDI
	NULL,			/* open_session */
	NULL			/* close_session */
#else
	sp_open_session,	/* open_session */
	sp_close_session	/* close_session */
#endif
};

#endif
