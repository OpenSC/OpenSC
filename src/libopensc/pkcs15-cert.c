/*
 * pkcs15-cert.c: PKCS #15 certificate functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>

#include "internal.h"
#include "asn1.h"
#include "pkcs15.h"

static int
parse_x509_cert(sc_context_t *ctx, struct sc_pkcs15_der *der, struct sc_pkcs15_cert *cert)
{
	int r;
	struct sc_algorithm_id sig_alg;
	struct sc_pkcs15_pubkey *pubkey = NULL;
	unsigned char *serial = NULL, *issuer = NULL, *subject = NULL, *buf =  der->value;
	size_t serial_len = 0, issuer_len = 0, subject_len = 0, data_len = 0, buflen = der->len;
	struct sc_asn1_entry asn1_version[] = {
		{ "version", SC_ASN1_INTEGER, SC_ASN1_TAG_INTEGER, 0, &cert->version, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_x509v3[] = {
		{ "certificatePolicies",	SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "subjectKeyIdentifier",	SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "crlDistributionPoints",	SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, &cert->crl, &cert->crl_len },
		{ "authorityKeyIdentifier",	SC_ASN1_OCTET_STRING, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
		{ "keyUsage",			SC_ASN1_BOOLEAN, SC_ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_extensions[] = {
		{ "x509v3",		SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_x509v3, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_tbscert[] = {
		{ "version",		SC_ASN1_STRUCT,    SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_version, NULL },
		{ "serialNumber",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, &serial, &serial_len },
		{ "signature",		SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "issuer",		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &issuer, &issuer_len },
		{ "validity",		SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
		{ "subject",		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &subject, &subject_len },
		/* Use a callback to get the algorithm, parameters and pubkey into sc_pkcs15_pubkey */
		{ "subjectPublicKeyInfo",SC_ASN1_CALLBACK, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, sc_pkcs15_pubkey_from_spki_fields,  &pubkey },
		{ "extensions",		SC_ASN1_STRUCT,    SC_ASN1_CTX | 3 | SC_ASN1_CONS, SC_ASN1_OPTIONAL, asn1_extensions, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_cert[] = {
		{ "tbsCertificate",	SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, asn1_tbscert, NULL },
		{ "signatureAlgorithm",	SC_ASN1_ALGORITHM_ID, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, &sig_alg, NULL },
		{ "signatureValue",	SC_ASN1_BIT_STRING, SC_ASN1_TAG_BIT_STRING, 0, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_serial_number[] = {
		{ "serialNumber", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_subject[] = {
		{ "subject", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};
	struct sc_asn1_entry asn1_issuer[] = {
		{ "issuer", SC_ASN1_OCTET_STRING, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	const u8 *obj;
	size_t objlen;

	memset(cert, 0, sizeof(*cert));
	obj = sc_asn1_verify_tag(ctx, buf, buflen, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &objlen);
	if (obj == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "X.509 certificate not found");

	data_len = objlen + (obj - buf);
	cert->data.value = malloc(data_len);
	if (!cert->data.value)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(cert->data.value, buf, data_len);
	cert->data.len = data_len;

	r = sc_asn1_decode(ctx, asn1_cert, obj, objlen, NULL, NULL);
	LOG_TEST_RET(ctx, r, "ASN.1 parsing of certificate failed");

	cert->version++;

	if (!pubkey)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "Unable to decode subjectPublicKeyInfo from cert");
	cert->key = pubkey;

	sc_asn1_clear_algorithm_id(&sig_alg);

	if (serial && serial_len)   {
		sc_format_asn1_entry(asn1_serial_number + 0, serial, &serial_len, 1);
		r = sc_asn1_encode(ctx, asn1_serial_number, &cert->serial, &cert->serial_len);
		free(serial);
		LOG_TEST_RET(ctx, r, "ASN.1 encoding of serial failed");
	}

	if (subject && subject_len)   {
		sc_format_asn1_entry(asn1_subject + 0, subject, &subject_len, 1);
		r = sc_asn1_encode(ctx, asn1_subject, &cert->subject, &cert->subject_len);
		free(subject);
		LOG_TEST_RET(ctx, r, "ASN.1 encoding of subject");
	}

	if (issuer && issuer_len)   {
		sc_format_asn1_entry(asn1_issuer + 0, issuer, &issuer_len, 1);
		r = sc_asn1_encode(ctx, asn1_issuer, &cert->issuer, &cert->issuer_len);
		free(issuer);
		LOG_TEST_RET(ctx, r, "ASN.1 encoding of issuer");
	}

	return SC_SUCCESS;
}


int
sc_pkcs15_pubkey_from_cert(struct sc_context *ctx,
		struct sc_pkcs15_der *cert_blob, struct sc_pkcs15_pubkey **out)
{
	int rv;
	struct sc_pkcs15_cert * cert;

	cert =  calloc(1, sizeof(struct sc_pkcs15_cert));
	if (cert == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	rv = parse_x509_cert(ctx, cert_blob, cert);

	*out = cert->key;
	cert->key = NULL;
	sc_pkcs15_free_certificate(cert);

	LOG_FUNC_RETURN(ctx, rv);
}


int
sc_pkcs15_read_certificate(struct sc_pkcs15_card *p15card, const struct sc_pkcs15_cert_info *info,
		struct sc_pkcs15_cert **cert_out)
{
	struct sc_context *ctx = NULL;
	struct sc_pkcs15_cert *cert = NULL;
	struct sc_pkcs15_der der;
	int r;

	assert(p15card != NULL && info != NULL && cert_out != NULL);
	ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);

	if (info->value.len && info->value.value)   {
		sc_der_copy(&der, &info->value);
	}
	else if (info->path.len) {
		r = sc_pkcs15_read_file(p15card, &info->path, &der.value, &der.len);
		LOG_TEST_RET(ctx, r, "Unable to read certificate file.");
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}

	cert = malloc(sizeof(struct sc_pkcs15_cert));
	if (cert == NULL) {
		free(der.value);
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memset(cert, 0, sizeof(struct sc_pkcs15_cert));
	if (parse_x509_cert(ctx, &der, cert)) {
		free(der.value);
		sc_pkcs15_free_certificate(cert);
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ASN1_OBJECT);
	}
	free(der.value);

	*cert_out = cert;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static const struct sc_asn1_entry c_asn1_cred_ident[] = {
	{ "idType",	SC_ASN1_INTEGER,      SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ "idValue",	SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_com_cert_attr[] = {
	{ "iD",         SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "authority",  SC_ASN1_BOOLEAN,   SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "identifier", SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	/* FIXME: Add rest of the optional fields */
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_x509_cert_value_choice[] = {
	{ "path",	SC_ASN1_PATH,	   SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "direct",	SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0 | SC_ASN1_CONS, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_x509_cert_attr[] = {
	{ "value",	SC_ASN1_CHOICE, 0, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_type_cert_attr[] = {
	{ "x509CertificateAttributes", SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
static const struct sc_asn1_entry c_asn1_cert[] = {
	{ "x509Certificate", SC_ASN1_PKCS15_OBJECT, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


int
sc_pkcs15_decode_cdf_entry(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj,
		const u8 ** buf, size_t *buflen)
{
        sc_context_t *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info info;
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2], asn1_x509_cert_value_choice[3];
	struct sc_asn1_pkcs15_object cert_obj = { obj, asn1_com_cert_attr, NULL,
					     asn1_type_cert_attr };
	sc_pkcs15_der_t *der = &info.value;
	u8 id_value[128];
	int id_type;
	size_t id_value_len = sizeof(id_value);
	int r;

	sc_copy_asn1_entry(c_asn1_cred_ident, asn1_cred_ident);
	sc_copy_asn1_entry(c_asn1_com_cert_attr, asn1_com_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_attr, asn1_x509_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_value_choice, asn1_x509_cert_value_choice);
	sc_copy_asn1_entry(c_asn1_type_cert_attr, asn1_type_cert_attr);
	sc_copy_asn1_entry(c_asn1_cert, asn1_cert);

	sc_format_asn1_entry(asn1_cred_ident + 0, &id_type, NULL, 0);
	sc_format_asn1_entry(asn1_cred_ident + 1, &id_value, &id_value_len, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 1, &info.authority, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 2, asn1_cred_ident, NULL, 0);
	sc_format_asn1_entry(asn1_x509_cert_attr + 0, asn1_x509_cert_value_choice, NULL, 0);
	sc_format_asn1_entry(asn1_x509_cert_value_choice + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_x509_cert_value_choice + 1, &der->value, &der->len, 0);
	sc_format_asn1_entry(asn1_type_cert_attr + 0, asn1_x509_cert_attr, NULL, 0);
	sc_format_asn1_entry(asn1_cert + 0, &cert_obj, NULL, 0);

        /* Fill in defaults */
        memset(&info, 0, sizeof(info));
	info.authority = 0;

	r = sc_asn1_decode(ctx, asn1_cert, *buf, *buflen, buf, buflen);
	/* In case of error, trash the cert value (direct coding) */
	if (r < 0 && der->value)
		free(der->value);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	LOG_TEST_RET(ctx, r, "ASN.1 decoding failed");

	if (!p15card->app || !p15card->app->ddo.aid.len)   {
		r = sc_pkcs15_make_absolute_path(&p15card->file_app->path, &info.path);
		LOG_TEST_RET(ctx, r, "Cannot make absolute path");
	}
	else   {
		info.path.aid = p15card->app->ddo.aid;
	}
	sc_log(ctx, "Certificate path '%s'", sc_print_path(&info.path));

	obj->type = SC_PKCS15_TYPE_CERT_X509;
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}


int
sc_pkcs15_encode_cdf_entry(sc_context_t *ctx, const struct sc_pkcs15_object *obj,
		u8 **buf, size_t *bufsize)
{
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2], asn1_x509_cert_value_choice[3];
	struct sc_pkcs15_cert_info *infop = (sc_pkcs15_cert_info_t *) obj->data;
	sc_pkcs15_der_t *der = &infop->value;
	struct sc_asn1_pkcs15_object cert_obj = { (struct sc_pkcs15_object *) obj,
							asn1_com_cert_attr, NULL,
							asn1_type_cert_attr };
	int r;

	sc_copy_asn1_entry(c_asn1_cred_ident, asn1_cred_ident);
	sc_copy_asn1_entry(c_asn1_com_cert_attr, asn1_com_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_attr, asn1_x509_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_value_choice, asn1_x509_cert_value_choice);
	sc_copy_asn1_entry(c_asn1_type_cert_attr, asn1_type_cert_attr);
	sc_copy_asn1_entry(c_asn1_cert, asn1_cert);

	sc_format_asn1_entry(asn1_com_cert_attr + 0, (void *) &infop->id, NULL, 1);
	if (infop->authority)
		sc_format_asn1_entry(asn1_com_cert_attr + 1, (void *) &infop->authority, NULL, 1);
	if (infop->path.len || !der->value) {
		sc_format_asn1_entry(asn1_x509_cert_value_choice + 0, &infop->path, NULL, 1);
	} else {
		sc_format_asn1_entry(asn1_x509_cert_value_choice + 1, der->value, &der->len, 1);
	}
	sc_format_asn1_entry(asn1_type_cert_attr + 0, &asn1_x509_cert_value_choice, NULL, 1);
	sc_format_asn1_entry(asn1_cert + 0, (void *) &cert_obj, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_cert, buf, bufsize);

	return r;
}


void
sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert)
{
	assert(cert != NULL);

	if (cert->key)
		sc_pkcs15_free_pubkey(cert->key);
	free(cert->subject);
	free(cert->issuer);
	free(cert->serial);
	free(cert->data.value);
	free(cert->crl);
	free(cert);
}


void
sc_pkcs15_free_cert_info(sc_pkcs15_cert_info_t *cert)
{
	if (!cert)
		return;
	if (cert->value.value)
		free(cert->value.value);
	free(cert);
}
