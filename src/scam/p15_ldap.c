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
#ifdef HAVE_LDAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <scrandom.h>
#include <scldap.h>
#include <opensc.h>
#include <opensc-pkcs15.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include "scam.h"

#if defined(HAVE_PAM)
static pam_handle_t *p15_ldap_pamh = NULL;
static unsigned int *p15_ldap_ctrl = NULL;
#elif defined(HAVE_OSF_SIA)
static sia_collect_func_t *p15_ldap_collect = NULL;
static SIAENTITY *p15_ldap_entity = NULL;
#endif

extern struct scam_framework_ops scam_fw_p15_ldap;

static scldap_context *lctx = NULL;

static struct sc_context *ctx = NULL;
static struct sc_card *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;
static int card_locked = 0;

static struct sc_pkcs15_object *objs[32];
static struct sc_pkcs15_cert_info *cinfo = NULL;
static struct sc_pkcs15_object *prkey = NULL, *pin = NULL;

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

void p15_ldap_handles(void *ctx1, void *ctx2, void *ctx3)
{
#if defined(HAVE_PAM)
	p15_ldap_pamh = (pam_handle_t *) ctx1;
	p15_ldap_ctrl = (unsigned int *) ctx2;
#elif defined(HAVE_OSF_SIA)
	p15_ldap_collect = (sia_collect_func_t *) ctx1;
	p15_ldap_entity = (SIAENTITY *) ctx2;
#endif
}

void p15_ldap_printmsg(char *str,...)
{
	va_list ap;
	char buf[128];

	va_start(ap, str);
	memset(buf, 0, 128);
	vsnprintf(buf, 128, str, ap);
	va_end(ap);
#if defined(HAVE_PAM)
	if (p15_ldap_pamh && p15_ldap_ctrl)
		opensc_pam_msg(p15_ldap_pamh, *p15_ldap_ctrl, PAM_TEXT_INFO, buf);
#elif defined(HAVE_OSF_SIA)
#endif
}

void p15_ldap_logmsg(char *str,...)
{
	va_list ap;
	char buf[1024];

	va_start(ap, str);
	memset(buf, 0, 1024);
	vsnprintf(buf, 1024, str, ap);
	va_end(ap);
#if defined(HAVE_PAM)
	if (p15_ldap_pamh)
		opensc_pam_log(LOG_NOTICE, p15_ldap_pamh, buf);
#elif defined(HAVE_OSF_SIA)
	opensc_sia_log(buf);
#endif
}

int p15_ldap_init(int argc, const char **argv)
{
	char *reader_name = NULL;
	int r, i, reader = 0;

	if (ctx || lctx) {
		return SCAM_FAILED;
	}
	r = sc_establish_context(&ctx);
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_establish_context: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	ctx->error_file = stderr;
	ctx->debug_file = stdout;
	ctx->debug = 0;

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
			log_message("Reader #%d - %s%s\n", i + 1, ctx->reader[i]->name, reader == i ? " (*)" : "");
		}
	} else {
		for (i = 0; i < ctx->reader_count; i++) {
			if ((strlen(reader_name) < strlen(ctx->reader[i]->name))) {
				if (!strncmp(reader_name, ctx->reader[i]->name, strlen(reader_name))) {
					reader = i;
					log_message("Reader #%d - %s selected\n", i + 1, ctx->reader[reader]->name);
					break;
				}
			}
		}
		free(reader_name);
	}

	if ((r = sc_connect_card(ctx->reader[reader], 0, &card)) != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_connect_card: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	sc_lock(card);
	card_locked = 1;

	r = sc_pkcs15_bind(card, &p15card);
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_bind: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_get_objects: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	if (r == 0)		/* No certificates found */
		return SCAM_FAILED;

	/* FIXME: Add support for selecting certificate by ID */
	cinfo = objs[0]->data;

	r = sc_pkcs15_find_prkey_by_id(p15card, &cinfo->id, &prkey);
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_find_prkey_by_id: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &prkey->auth_id, &pin);
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_find_pin_by_auth_id: %s\n", sc_strerror(r));
		return SCAM_FAILED;
	}
	lctx = scldap_parse_parameters(SCLDAP_CONFIG);
	if (!lctx) {
		return SCAM_FAILED;
	}
	scldap_parse_arguments(&lctx, argc, argv);
	return SCAM_SUCCESS;
}

const char *p15_ldap_pinentry(void)
{
	struct sc_pkcs15_pin_info *pininfo = NULL;
	static char buf[64];

	if (!ctx || !lctx || !pin) {
		return NULL;
	}
	pininfo = pin->data;
	snprintf(buf, 64, "Enter PIN%d [%s]: ", pininfo->reference, pin->label);
	return buf;
}

int p15_ldap_qualify(unsigned char *password)
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

int p15_ldap_auth(int argc, const char **argv,
		  const char *user, const char *password)
{
	struct sc_pkcs15_cert *p15cert = NULL;
	u8 random_data[20], chg[256], txt[256];
	int r, err = SCAM_FAILED, chglen;
	EVP_PKEY *pubkey = NULL;
	X509 *cert = NULL;

	if (!lctx || !ctx)
		return SCAM_FAILED;
	r = sc_pkcs15_read_certificate(p15card, cinfo, &p15cert);
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_read_certificate: %s\n", sc_strerror(r));
		goto end;
	}
	cert = X509_new();
	if (!d2i_X509(&cert, &p15cert->data, p15cert->data_len)) {
		scam_fw_p15_ldap.logmsg("Invalid certificate. (user %s)\n", user);
		goto end;
	}
	pubkey = X509_get_pubkey(cert);
	if (!pubkey) {
		scam_fw_p15_ldap.logmsg("Invalid public key. (user %s)\n", user);
		goto end;
	}
	chglen = RSA_size(pubkey->pkey.rsa);
	if (chglen > sizeof(chg)) {
		scam_fw_p15_ldap.printmsg("RSA key too big.\n");
		goto end;
	}
	r = scrandom_get_data(random_data, sizeof(random_data));
	if (r < 0) {
		scam_fw_p15_ldap.logmsg("scrandom_get_data failed.\n");
		goto end;
	}
	r = sc_pkcs15_verify_pin(p15card, pin->data, (const u8 *) password, strlen(password));
	if (r != SC_SUCCESS) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_verify_pin: %s\n", sc_strerror(r));
		goto end;
	}
	r = sc_pkcs15_compute_signature(p15card, prkey, SC_ALGORITHM_RSA_PAD_PKCS1,
					random_data, 20, chg, chglen);
	if (r < 0) {
		scam_fw_p15_ldap.printmsg("sc_pkcs15_compute_signature: %s\n", sc_strerror(r));
		goto end;
	}
	r = RSA_public_decrypt(chglen, chg, txt, pubkey->pkey.rsa, RSA_PKCS1_PADDING);
	if (r < 0) {
		scam_fw_p15_ldap.printmsg("Signature verification failed.\n");
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

void p15_ldap_deinit(void)
{
	if (lctx) {
		scldap_free_parameters(lctx);
	}
	lctx = NULL;
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
		sc_destroy_context(ctx);
	}
	ctx = NULL;
}

int p15_ldap_open_session(int argc, const char **argv, const char *user)
{
	struct passwd *userstr = NULL;
	uid_t useruid = 65534, uid = 65534;
	gid_t gid = 65534;
	int r;

	if (!user) {
		log_messagex(L_DEBUG, "No user.\n");
		return SCAM_FAILED;
	}
	userstr = getpwnam(user);
	if (!userstr) {
		log_messagex(L_DEBUG, "Can't get user structure. (%s)", user);
		return SCAM_FAILED;
	}
	useruid = userstr->pw_uid;
	r = GetIdentity(&uid, &gid);
	if (r < 0) {
		scam_fw_p15_ldap.logmsg("Could not get uid/gid for pcscd.\n");
		return SCAM_FAILED;
	}
#ifdef PCSCLITE_SERVER_PATH
	r = chown(PCSCLITE_SERVER_PATH, useruid, gid);
	if (r < 0) {
		log_messagex(L_DEBUG, "Opening session failed, cannot chown socket to user %.", user);
		return SCAM_FAILED;
	}
#endif
	return SCAM_SUCCESS;
}

int p15_ldap_close_session(int argc, const char **argv, const char *user)
{
	uid_t uid = 65534;
	gid_t gid = 65534;
	int r;

	if (!user) {
		log_messagex(L_DEBUG, "No user.\n");
		return SCAM_FAILED;
	}
	r = GetIdentity(&uid, &gid);
	if (r < 0) {
		scam_fw_p15_ldap.logmsg("Could not get uid/gid for pcscd.\n");
		return SCAM_FAILED;
	}
#ifdef PCSCLITE_SERVER_PATH
	r = chown(PCSCLITE_SERVER_PATH, uid, gid);
	if (r < 0) {
		log_messagex(L_DEBUG, "Closing session failed, cannot chown socket to smartcard user.");
		return SCAM_SUCCESS;
	}
	r = CleanupClientSockets();
	if (r == -1) {
		scam_fw_p15_ldap.logmsg("CleanupClientSockets failed.\n");
		return SCAM_FAILED;
	}
#endif
	return SCAM_SUCCESS;
}

#ifdef ATR_SUPPORT
static const char *p15_ldap_atrs[] =
{
	"3B:9F:94:40:1E:00:67:11:43:46:49:53:45:10:52:66:FF:81:90:00",
	NULL
};
#endif

struct scam_framework_ops scam_fw_p15_ldap =
{
	"opensc-pkcs15-ldap",	/* name */
#ifdef ATR_SUPPORT
	p15_ldap_atrs,		/* atrs */
#endif
	p15_ldap_usage,		/* usage */
	p15_ldap_handles,	/* handles */
	p15_ldap_printmsg,	/* printmsg */
	p15_ldap_logmsg,	/* logmsg */
	p15_ldap_init,		/* init */
	p15_ldap_pinentry,	/* pinentry */
	p15_ldap_qualify,	/* qualify */
	p15_ldap_auth,		/* auth */
	p15_ldap_deinit,	/* deinit */
	p15_ldap_open_session,	/* open_session */
	p15_ldap_close_session	/* close_session */
};

#endif
