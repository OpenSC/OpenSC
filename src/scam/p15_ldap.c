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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/scldap.h>
#include <opensc/scrandom.h>
#include <opensc/log.h>
#include "cert_support.h"
#include "scam.h"

typedef struct _scam_method_data {
	struct sc_context *ctx;
	struct sc_card *card;
	struct sc_pkcs15_card *p15card;
	int card_locked;

	struct sc_pkcs15_object *objs[32];
	struct sc_pkcs15_cert_info *cinfo;
	struct sc_pkcs15_object *prkey, *pin;

	scldap_context *lctx;
	char *scldap_entry;
} scam_method_data;

#define MAX_PATHLEN 10
#define MAX_ENTRYLEN 256

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

int p15_ldap_init(scam_context * sctx, int argc, const char **argv)
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
	data->lctx = scldap_parse_parameters(SCLDAP_CONF_PATH);
	if (!data->lctx) {
		return SCAM_FAILED;
	}
	scldap_parse_arguments(&data->lctx, argc, argv);
	data->scldap_entry = (char *) malloc(MAX_ENTRYLEN);
	if (!data->scldap_entry) {
		return SCAM_FAILED;
	}
	memset(data->scldap_entry, 0, MAX_ENTRYLEN);
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

static int copy_result(scldap_result * lresult, unsigned char **result, unsigned long *resultlen)
{
	if (!lresult)
		return -1;
	*result = NULL;
	*resultlen = 0;
	*result = (unsigned char *) malloc(lresult->result[0].datalen + 1);
	if (!*result)
		return -1;
	memset(*result, 0, lresult->result[0].datalen + 1);
	memcpy(*result, lresult->result[0].data, lresult->result[0].datalen);
	*resultlen = lresult->result[0].datalen;
	return 0;
}

static void modify_base(scam_context * sctx, const char *entry, char *dn)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;
	char approx_entry[MAX_ENTRYLEN];
	int entrynum = -1;

	if (!sctx || !entry || !dn)
		return;
	entrynum = scldap_get_entry(data->lctx, entry);
	if (entrynum < 0) {
		return;
	}
	snprintf(approx_entry, MAX_ENTRYLEN, "%s %s approx base", data->p15card->label, data->p15card->manufacturer_id);
	if (scldap_approx_base_by_dn(data->lctx, approx_entry, dn, &data->lctx->entry[entrynum].base) < 0) {
		return;
	}
	sc_debug(data->ctx, "modify_base: %s\n", data->lctx->entry[entrynum].base);
}

int p15_ldap_auth(scam_context * sctx, int argc, const char **argv,
		  const char *user, const char *password)
{
	scam_method_data *data = (scam_method_data *) sctx->method_data;
	struct sc_pkcs15_cert *p15cert = NULL;
	scCertificate *CardCert = NULL, *Cert = NULL, *CACerts[MAX_PATHLEN];
	X509 *currcert = NULL;
	u8 random_data[20], chg[256];
	scldap_result *lresult = NULL;
	int r = 0, i = 0, err = SCAM_FAILED, chglen;
	char *dn;

	if (!sctx->method_data) {
		return SCAM_FAILED;
	}
	for (i = 0; i < MAX_PATHLEN; i++) {
		CACerts[i] = NULL;
	}
	Cert = certAlloc();
	if (!Cert) {
		goto end;
	}
	CardCert = certAlloc();
	if (!CardCert) {
		goto end;
	}
	r = sc_pkcs15_read_certificate(data->p15card, data->cinfo, &p15cert);
	if (r != SC_SUCCESS) {
		scam_print_msg(sctx, "sc_pkcs15_read_certificate: %s\n", sc_strerror(r));
		goto end;
	}

	/* FIXME */
	CardCert->len = p15cert->data_len;
	CardCert->buf = (unsigned char *) malloc(CardCert->len);
	if (!CardCert->buf) {
		scam_print_msg(sctx, "out of memory\n", sc_strerror(r));
		goto end;
	}
	memcpy(CardCert->buf, p15cert->data, p15cert->data_len);

	/* Parse user certificate just once into a x509 structure
	   and not for each individual operation */
	if (!(CardCert->cert = certParseCertificate(CardCert->buf, CardCert->len))) {
		scam_print_msg(sctx, "certParseCertificate failed: invalid certificate.\n");
		goto end;
	}
	snprintf(data->scldap_entry, MAX_ENTRYLEN, "%s %s auth certificate", data->p15card->label, data->p15card->manufacturer_id);
	dn = certGetSubject(CardCert->cert);
	modify_base(sctx, data->scldap_entry, dn);
	free(dn);
	r = scldap_search(data->lctx, data->scldap_entry, &lresult, 1, user);
	if ((r < 0) || (copy_result(lresult, &Cert->buf, &Cert->len) < 0)) {
		scam_print_msg(sctx, "Search failed: no auth certificate found.\n");
		goto end;
	}
	scldap_free_result(lresult);
	lresult = NULL;
	if (memcmp(CardCert->buf, Cert->buf, Cert->len) != 0) {
		scam_print_msg(sctx, "Certificate comparing failed.\n");
		goto end;
	}
	certFree(CardCert);
	CardCert = NULL;

	/* Parse user certificate just once into a x509 structure
	   and not for each individual operation */
	if (!(Cert->cert = certParseCertificate(Cert->buf, Cert->len))) {
		scam_print_msg(sctx, "certParseCertificate failed: invalid certificate.\n");
		goto end;
	}
	/* Do not accept self signed user certificates or certificates 
	   without issuer or subject fields */
	if (certIsSelfSigned(Cert->cert) != 0) {
		scam_print_msg(sctx, "certIsSelfSigned failed: certificate is not signed by a CA.\n");
		goto end;
	}
	/* We want an encipherment key */
	if ((r = certCheckKeyUsage(Cert->cert, DATA_ENCIPHERMENT)) < 1) {
		scam_print_msg(sctx, "certCheckKeyUsage failed: certificate cannot be used for encipherment.\n");
		if (r == -1) {
			scam_log_msg(sctx, "KeyUsage check failed (user %s).\n", user);
		} else {
			scam_log_msg(sctx, "Wrong certificate type (user %s).\n", user);
		}
		goto end;
	}
	if (!(Cert->pubkey = certParsePublicKey(Cert->cert))) {
		scam_print_msg(sctx, "certParsePublicKey failed: invalid public key in certificate.\n");
		scam_log_msg(sctx, "Invalid public key (user %s).\n", user);
		goto end;
	}
	if (Cert->pubkey->type != EVP_PKEY_RSA) {
		scam_log_msg(sctx, "Invalid public key. (user %s)\n", user);
		goto end;
	}
	chglen = RSA_size(Cert->pubkey->pkey.rsa);
	if (chglen > sizeof(chg)) {
		scam_print_msg(sctx, "RSA key too big.\n");
		goto end;
	}
	/* Parse issuer from each one certificate
	   in turn when you get them from the LDAP serer and stuff them
	   all into the chain when we have other certificates than FINEID
	   until issuer == subject. */
	do {
		char *distpoint = NULL;

		/* Find empty slot */
		for (i = 0; i < MAX_PATHLEN; i++) {
			if (!(CACerts[i])) {
				break;
			}
		}

		/* Path length exceeded */
		if (i == MAX_PATHLEN) {
			goto end;
		}
		CACerts[i] = certAlloc();
		if (!(CACerts[i])) {
			goto end;
		}
		snprintf(data->scldap_entry, MAX_ENTRYLEN, "%s %s ca certificate", data->p15card->label, data->p15card->manufacturer_id);
		modify_base(sctx, data->scldap_entry, certGetIssuer(Cert->cert));
		r = scldap_search(data->lctx, data->scldap_entry, &lresult, 1, NULL);
		if ((r < 0) || (copy_result(lresult, &CACerts[i]->buf, &CACerts[i]->len) < 0)) {
			scam_print_msg(sctx, "Search failed: no CA certificate.\n");
			goto end;
		}
		scldap_free_result(lresult);
		lresult = NULL;

		/* Parse CA certificate into a x509 structure */
		if (!(CACerts[i]->cert = certParseCertificate(CACerts[i]->buf, CACerts[i]->len))) {
			scam_print_msg(sctx, "certParseCertificate failed: invalid CA certificate.\n");
			goto end;
		}
		distpoint = certGetCRLDistributionPoint(Cert->cert);
		snprintf(data->scldap_entry, MAX_ENTRYLEN, "%s %s crl", data->p15card->label, data->p15card->manufacturer_id);

		if (scldap_is_valid_url(distpoint)) {
			if (scldap_url_to_entry(data->lctx, data->scldap_entry, distpoint) < 0) {
				scam_print_msg(sctx, "scldap_url_to_entry failed: invalid CRL.\n");
				free(distpoint);
				distpoint = NULL;
				goto end;
			}
		}
		free(distpoint);
		distpoint = NULL;
		r = scldap_search(data->lctx, data->scldap_entry, &lresult, 1, NULL);
		if ((r < 0) || (copy_result(lresult, &CACerts[i]->crlbuf, &CACerts[i]->crllen) < 0)) {
			scam_print_msg(sctx, "Search failed: CRL not found.\n");
			goto end;
		}
		scldap_free_result(lresult);
		lresult = NULL;

		if (!(CACerts[i]->crl = certParseCRL(CACerts[i]->crlbuf, CACerts[i]->crllen))) {
			scam_print_msg(sctx, "certParseCRL failed: invalid CRL.\n");
			scam_log_msg(sctx, "Could not parse CA CRL.\n");
			goto end;
		}
		currcert = CACerts[i]->cert;
	} while (!certIsSelfSigned(currcert));

	if ((r = certVerifyCAChain(CACerts, Cert->cert)) != 0) {
		scam_print_msg(sctx, "certVerifyCAChain failed: certificate has invalid information.\n");
		scam_log_msg(sctx, "certVerifyCAChain failed: %s.\n", certError((unsigned long) r));
		goto end;
	}
	certFreeAll(CACerts);

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

	r = RSA_verify(NID_sha1, random_data, 20, chg, chglen, Cert->pubkey->pkey.rsa);
	if (r != 1) {
		scam_print_msg(sctx, "Signature verification failed.\n");
		goto end;
	}
	err = SCAM_SUCCESS;
      end:
	if (CardCert)
		certFree(CardCert);
	if (Cert)
		certFree(Cert);
	certFreeAll(CACerts);
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
	if (data->scldap_entry) {
		free(data->scldap_entry);
	}
	data->scldap_entry = NULL;
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
	NULL,			/* open_session */
	NULL			/* close_session */
};

#endif
