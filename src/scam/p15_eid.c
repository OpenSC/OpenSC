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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <pwd.h>
#include <sys/stat.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/scrandom.h>
#include "scam.h"

static const char *eid_path = ".eid";
static const char *auth_cert_file = "authorized_certificates";

typedef struct _scam_method_data {
	struct sc_context *ctx;
	struct sc_card *card;
	struct sc_pkcs15_card *p15card;
	int card_locked;

	struct sc_pkcs15_object *objs[32];
	struct sc_pkcs15_cert_info *cinfo;
	struct sc_pkcs15_object *prkey, *pin;
} scam_method_data;

const char *p15_eid_usage(void)
{
	static char buf[500];

	memset(buf, 0, 500);
	snprintf(buf, 500,
		 " -r <reader>	Reader name\n"
	    );
	return &buf[0];
}

/*
 * Select a card reader
 */
static sc_reader_t *
p15_eid_select_reader(scam_context *sctx, const char *name)
{
	sc_context_t	*ctx = ((scam_method_data *) sctx->method_data)->ctx;
	sc_reader_t	*reader;
	int		i;

	if (name) {
		int	name_len = strlen(name);

		for (i = 0; i < ctx->reader_count; i++) {
			reader = ctx->reader[i];
			if (name_len <= strlen(reader->name)
			 && !strncmp(name, reader->name, name_len))
			 	return reader;
		}
		scam_print_msg(sctx,
				"Card Reader \"%s\" not present\n",
				name);
		return NULL;
	}

	for (i = 0; i < ctx->reader_count; i++) {
		reader = ctx->reader[i];
		if (sc_detect_card_presence(reader, 0) & SC_SLOT_CARD_PRESENT)
			return reader;
	}

	scam_print_msg(sctx, "No smart card present\n");
	return NULL;
}

int p15_eid_init(scam_context * sctx, int argc, const char **argv)
{
	scam_method_data *data = NULL;
	const char *reader_name = NULL;
	sc_reader_t *reader;
	int r, i;

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
				reader_name = optarg;
				break;
			}
		}
	}

	/* Select a card reader */
	if (!(reader = p15_eid_select_reader(sctx, reader_name)))
		return SCAM_FAILED;

	scam_print_msg(sctx, "Using card reader %s\n", reader->name);

	if ((r = sc_connect_card(reader, 0, &data->card)) != SC_SUCCESS) {
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
	return SCAM_SUCCESS;
}

const char *p15_eid_pinentry(scam_context * sctx)
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

int p15_eid_qualify(scam_context * sctx, unsigned char *password)
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

static int format_eid_dir_path(const char *user, char **buf)
{
	struct passwd *pwent = getpwnam(user);
	char *dir = NULL;

	if (!pwent)
		return SCAM_FAILED;
	dir = (char *) malloc(strlen(pwent->pw_dir) + strlen(eid_path) + 2);
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
	cert_path = (char *) malloc(strlen(dir) + strlen(auth_cert_file) + 2);
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

int p15_eid_auth(scam_context * sctx, int argc, const char **argv,
		 const char *user, const char *password)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;
	u8 random_data[20], chg[256];
	int r, err = SCAM_FAILED, chglen;
	EVP_PKEY *pubkey = NULL;
	X509 *cert = NULL;

	if (!sctx->method_data) {
		return SCAM_FAILED;
	}
	r = is_eid_dir_present(user);
	if (r != SCAM_SUCCESS) {
		scam_print_msg(sctx, "No such user, user has no .eid directory or .eid unreadable.\n");
		goto end;
	}
	r = get_certificate(user, &cert);
	if (r != SCAM_SUCCESS) {
		scam_print_msg(sctx, "get_certificate failed.\n");
		goto end;
	}
	pubkey = X509_get_pubkey(cert);
	if (!pubkey || pubkey->type != EVP_PKEY_RSA) {
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

	/* We currently assume that all cards are capable of signing
	 * a SHA1 digest - that's a much safer bet than going for
	 * raw RSA.
	 * The best solution would be to look at the list of supported
	 * algorithms and pick an appropriate hash.
	 *
	 * Note the hash algorithm must match the first argument in the
	 * call to RSA_verify below
	 */
	r = sc_pkcs15_compute_signature(data->p15card, data->prkey,
					SC_ALGORITHM_RSA_PAD_PKCS1
					| SC_ALGORITHM_RSA_HASH_SHA1,
					random_data, 20, chg, chglen);
	if (r < 0) {
		scam_print_msg(sctx, "sc_pkcs15_compute_signature: %s\n", sc_strerror(r));
		goto end;
	}

	r = RSA_verify(NID_sha1, random_data, 20, chg, chglen, pubkey->pkey.rsa);
	if (r != 1) {
		scam_print_msg(sctx, "Signature verification failed.\n");
		goto end;
	}
	err = SCAM_SUCCESS;
      end:
	if (pubkey)
		EVP_PKEY_free(pubkey);
	if (cert)
		X509_free(cert);
	return err;
}

void p15_eid_deinit(scam_context * sctx)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;

	if (!sctx->method_data) {
		return;
	}
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

struct scam_framework_ops scam_fw_p15_eid =
{
	"pkcs15-eid",		/* name */
	p15_eid_usage,		/* usage */
	p15_eid_init,		/* init */
	p15_eid_pinentry,	/* pinentry */
	p15_eid_qualify,	/* qualify */
	p15_eid_auth,		/* auth */
	p15_eid_deinit,		/* deinit */
	NULL,			/* open_session */
	NULL			/* close_session */
};

#endif
