/*
 * pkcs15-cert.c: PKCS #15 certificate functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-internal.h"
#include "opensc-pkcs15.h"
#include "sc-log.h"
#include "sc-asn1.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

struct asn1_algorithm_id {
	struct sc_object_id id;
};

static int parse_algorithm_id(struct sc_context *ctx, void *arg, const u8 *obj,
			      size_t objlen, int depth)
{
	struct asn1_algorithm_id *alg_id = (struct asn1_algorithm_id *) arg;
	struct sc_asn1_entry asn1_alg_id[] = {
		{ "algorithm",	SC_ASN1_OBJECT, ASN1_OBJECT, 0, &alg_id->id },
		{ "parameters", SC_ASN1_STRUCT, 0, SC_ASN1_OPTIONAL, NULL },
		{ NULL }
	};
	int r;
	
	r = sc_asn1_decode(ctx, asn1_alg_id, obj, objlen, NULL, NULL);
	SC_TEST_RET(ctx, r, "ASN.1 parsing failed");
	
	return 0;
}

static int parse_x509_cert(struct sc_context *ctx, const u8 *buf, size_t buflen, struct sc_pkcs15_cert *cert)
{
	int r;
	struct sc_pkcs15_pubkey_rsa *key = &cert->key;
	struct asn1_algorithm_id pk_alg, sig_alg;
	u8 *pk = NULL;
	size_t pklen = 0;
	struct sc_asn1_entry asn1_version[] = {
		{ "version",		SC_ASN1_INTEGER,   ASN1_INTEGER, 0, &cert->version },
		{ NULL }
	};
	struct sc_asn1_entry asn1_pkinfo[] = {
		{ "algorithm",		SC_ASN1_CALLBACK,      ASN1_SEQUENCE | SC_ASN1_CONS, 0, (void *) parse_algorithm_id, &pk_alg },
		{ "subjectPublicKey",	SC_ASN1_BIT_STRING_NI, ASN1_BIT_STRING, SC_ASN1_ALLOC, &pk, &pklen },
		{ NULL }
	};
	struct sc_asn1_entry asn1_tbscert[] = {
		{ "version",		SC_ASN1_STRUCT,    SC_ASN1_CTX | 0 | SC_ASN1_CONS, 0, asn1_version },
		{ "serialNumber",	SC_ASN1_OCTET_STRING, ASN1_INTEGER, SC_ASN1_ALLOC, &cert->serial, &cert->serial_len },
		{ "signature",		SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
		{ "issuer",		SC_ASN1_OCTET_STRING, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &cert->issuer, &cert->issuer_len },
		{ "validity",		SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
		{ "subject",		SC_ASN1_OCTET_STRING, ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_ALLOC, &cert->subject, &cert->subject_len },
		{ "subjectPublicKeyInfo",SC_ASN1_STRUCT,   ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_pkinfo },
		{ NULL }
	};
	struct sc_asn1_entry asn1_cert[] = {
		{ "tbsCertificate",	SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_tbscert },
		{ "signatureAlgorithm",	SC_ASN1_CALLBACK,  ASN1_SEQUENCE | SC_ASN1_CONS, 0, (void *) parse_algorithm_id, &sig_alg },
		{ "signatureValue",	SC_ASN1_BIT_STRING,ASN1_BIT_STRING, 0, NULL, 0 },
		{ NULL }
	};
	const u8 *obj;
	size_t objlen;
	
	obj = sc_asn1_verify_tag(ctx, buf, buflen, ASN1_SEQUENCE | SC_ASN1_CONS,
				 &objlen);
	if (obj == NULL) {
		error(ctx, "X.509 certificate not found\n");
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	cert->data_len = objlen + (obj - buf);
	r = sc_asn1_decode(ctx, asn1_cert, obj, objlen, NULL, NULL);
	SC_TEST_RET(ctx, r, "ASN.1 parsing failed");

	cert->version++;
	pklen >>= 3;	/* convert number of bits to bytes */
	key->data = pk;
	key->data_len = pklen;
	/* FIXME: ignore the object id for now, and presume it's RSA */
	r = sc_pkcs15_parse_pubkey_rsa(ctx, key);
	if (r) {
		free(key->data);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	return 0;
}

int sc_pkcs15_read_certificate(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_cert_info *info,
			       struct sc_pkcs15_cert **cert_out)
{
	int r;
	struct sc_pkcs15_cert *cert;
	struct sc_file *file = NULL;
	u8 *data = NULL;
	size_t len;
	
	assert(p15card != NULL && info != NULL && cert_out != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	r = sc_pkcs15_read_cached_file(p15card, &info->path, &data, &len);
	if (r) {
		r = sc_lock(p15card->card);
		SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
		r = sc_select_file(p15card->card, &info->path, &file);
		if (r) {
			sc_unlock(p15card->card);
			return r;
		}
		len = file->size;
		sc_file_free(file);
		data = malloc(len);
		if (data == NULL) {
			sc_unlock(p15card->card);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		r = sc_read_binary(p15card->card, 0, data, len, 0);
		if (r < 0) {
			sc_unlock(p15card->card);
			free(data);
			return r;
		}
		len = len;
		sc_unlock(p15card->card);
	}
	cert = malloc(sizeof(struct sc_pkcs15_cert));
	if (cert == NULL) {
		free(data);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	memset(cert, 0, sizeof(struct sc_pkcs15_cert));
	if (parse_x509_cert(p15card->card->ctx, data, len, cert)) {
		free(data);
		free(cert);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	cert->data = data;
	*cert_out = cert;
	return 0;
}

static const struct sc_asn1_entry c_asn1_cred_ident[] = {
	{ "idType",	SC_ASN1_INTEGER,      ASN1_INTEGER, 0, NULL },
	{ "idValue",	SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_com_cert_attr[] = {
	{ "iD",         SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, NULL },
	{ "authority",  SC_ASN1_BOOLEAN,   ASN1_BOOLEAN, SC_ASN1_OPTIONAL, NULL },
	{ "identifier", SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL },
	/* FIXME: Add rest of the optional fields */
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_x509_cert_attr[] = {
	{ "value",	SC_ASN1_PATH,	   ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_type_cert_attr[] = {
	{ "x509CertificateAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};
static const struct sc_asn1_entry c_asn1_cert[] = {
	{ "x509Certificate", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
	{ NULL }
};

int sc_pkcs15_decode_cdf_entry(struct sc_pkcs15_card *p15card,
			       struct sc_pkcs15_object *obj,
			       const u8 ** buf, size_t *buflen)
{
        struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info info;
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2];
	struct sc_asn1_pkcs15_object cert_obj = { obj, asn1_com_cert_attr, NULL,
					     asn1_type_cert_attr };
	u8 id_value[128];
	int id_type, id_value_len = sizeof(id_value);
	int r;

	sc_copy_asn1_entry(c_asn1_cred_ident, asn1_cred_ident);
	sc_copy_asn1_entry(c_asn1_com_cert_attr, asn1_com_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_attr, asn1_x509_cert_attr);
	sc_copy_asn1_entry(c_asn1_type_cert_attr, asn1_type_cert_attr);
	sc_copy_asn1_entry(c_asn1_cert, asn1_cert);
	
	sc_format_asn1_entry(asn1_cred_ident + 0, &id_type, NULL, 0);
	sc_format_asn1_entry(asn1_cred_ident + 1, &id_value, &id_value_len, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 0, &info.id, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 1, &info.authority, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 2, asn1_cred_ident, NULL, 0);
	sc_format_asn1_entry(asn1_x509_cert_attr + 0, &info.path, NULL, 0);
	sc_format_asn1_entry(asn1_type_cert_attr + 0, asn1_x509_cert_attr, NULL, 0);
	sc_format_asn1_entry(asn1_cert + 0, &cert_obj, NULL, 0);

        /* Fill in defaults */
        memset(&info, 0, sizeof(info));
	info.authority = 0;
	
	r = sc_asn1_decode(ctx, asn1_cert, *buf, *buflen, buf, buflen);
	if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
		return r;
	SC_TEST_RET(ctx, r, "ASN.1 decoding failed");
	obj->type = SC_PKCS15_TYPE_CERT_X509;
	obj->data = malloc(sizeof(info));
	if (obj->data == NULL)
		SC_FUNC_RETURN(ctx, 0, SC_ERROR_OUT_OF_MEMORY);
	memcpy(obj->data, &info, sizeof(info));

	return 0;
}

int sc_pkcs15_encode_cdf_entry(struct sc_context *ctx,
			       const struct sc_pkcs15_object *obj,
			       u8 **buf, size_t *bufsize)
{
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2];
	struct sc_pkcs15_cert_info *infop =
		(struct sc_pkcs15_cert_info *) obj->data;
	const struct sc_asn1_pkcs15_object cert_obj = { (struct sc_pkcs15_object *) obj,
							asn1_com_cert_attr, NULL,
							asn1_type_cert_attr };
	int r;

	sc_copy_asn1_entry(c_asn1_cred_ident, asn1_cred_ident);
	sc_copy_asn1_entry(c_asn1_com_cert_attr, asn1_com_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_attr, asn1_x509_cert_attr);
	sc_copy_asn1_entry(c_asn1_type_cert_attr, asn1_type_cert_attr);
	sc_copy_asn1_entry(c_asn1_cert, asn1_cert);
	
	sc_format_asn1_entry(asn1_com_cert_attr + 0, (void *) &infop->id, NULL, 1);
	if (infop->authority)
		sc_format_asn1_entry(asn1_com_cert_attr + 1, (void *) &infop->authority, NULL, 1);
	sc_format_asn1_entry(asn1_x509_cert_attr + 0, (void *) &infop->path, NULL, 1);
	sc_format_asn1_entry(asn1_type_cert_attr + 0, (void *) asn1_x509_cert_attr, NULL, 1);
	sc_format_asn1_entry(asn1_cert + 0, (void *) &cert_obj, NULL, 1);

	r = sc_asn1_encode(ctx, asn1_cert, buf, bufsize);

	return r;
}

void sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert)
{
	assert(cert != NULL);

	free(cert->key.data);
	free(cert->key.modulus);
	free(cert->subject);
	free(cert->issuer);
	free(cert->serial);
	free(cert->data);
	free(cert);
}
