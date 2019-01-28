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
	struct sc_asn1_entry asn1_extensions[] = {
		{ "x509v3",		SC_ASN1_OCTET_STRING,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL| SC_ASN1_ALLOC, &cert->extensions, &cert->extensions_len },
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
	cert->key = pubkey;
	cert->version++;

	LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 parsing of certificate failed");

	if (!pubkey)
		LOG_TEST_GOTO_ERR(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "Unable to decode subjectPublicKeyInfo from cert");

	sc_asn1_clear_algorithm_id(&sig_alg);

	if (serial && serial_len)   {
		sc_format_asn1_entry(asn1_serial_number + 0, serial, &serial_len, 1);
		r = sc_asn1_encode(ctx, asn1_serial_number, &cert->serial, &cert->serial_len);
		LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 encoding of serial failed");
	}

	if (subject && subject_len)   {
		sc_format_asn1_entry(asn1_subject + 0, subject, &subject_len, 1);
		r = sc_asn1_encode(ctx, asn1_subject, &cert->subject, &cert->subject_len);
		LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 encoding of subject");
	}

	if (issuer && issuer_len)   {
		sc_format_asn1_entry(asn1_issuer + 0, issuer, &issuer_len, 1);
		r = sc_asn1_encode(ctx, asn1_issuer, &cert->issuer, &cert->issuer_len);
		LOG_TEST_GOTO_ERR(ctx, r, "ASN.1 encoding of issuer");
	}

err:
	free(serial);
	free(subject);
	free(issuer);

	return r;
}


/* Get a component of Distinguished Name (e.i. subject or issuer) USING the oid tag.
 * dn can be either cert->subject or cert->issuer.
 * dn_len would be cert->subject_len or cert->issuer_len.
 *
 * Common types:
 *   CN:      struct sc_object_id type = {{2, 5, 4, 3, -1}};
 *   Country: struct sc_object_id type = {{2, 5, 4, 6, -1}};
 *   L:       struct sc_object_id type = {{2, 5, 4, 7, -1}};
 *   S:       struct sc_object_id type = {{2, 5, 4, 8, -1}};
 *   O:       struct sc_object_id type = {{2, 5, 4, 10, -1}};
 *   OU:      struct sc_object_id type = {{2, 5, 4, 11, -1}};
 *
 * if *name is NULL, sc_pkcs15_get_name_from_dn will allocate space for name.
 */
int
sc_pkcs15_get_name_from_dn(struct sc_context *ctx, const u8 *dn, size_t dn_len,
	const struct sc_object_id *type, u8 **name, size_t *name_len)
{
	const u8 *rdn = NULL;
	const u8 *next_ava = NULL;
	size_t rdn_len = 0;
	size_t next_ava_len = 0;
	int rv;

	rdn = sc_asn1_skip_tag(ctx, &dn, &dn_len, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &rdn_len);
	if (rdn == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of Distinguished Name");

	for (next_ava = rdn, next_ava_len = rdn_len; next_ava_len; ) {
		const u8 *ava, *dummy, *oidp;
		struct sc_object_id oid;
		size_t ava_len, dummy_len, oid_len;

		/* unwrap the set and point to the next ava */
		ava = sc_asn1_skip_tag(ctx, &next_ava, &next_ava_len, SC_ASN1_TAG_SET | SC_ASN1_CONS, &ava_len);
		if (ava == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of AVA");

		/* It would be nice to use sc_asn1_decode here to parse the entire AVA, but we are missing 1 critical
		 *	function in the templates: the ability to accept any tag for value. This prevents us from just
		 *	grabbing the value as is out of the template. AVA's can have tags of PRINTABLE_STRING,
		 *	TELETEXSTRING, T61STRING or UTF8_STRING with PRINTABLE_STRING and UTF8_STRING being the most common.
		 * The other feature that would be nice is returning a pointer to our requested data using the space
		 *	of the parent (basically what this code is doing here), rather than allocating and copying.
		 */

		/* unwrap the sequence */
		dummy = ava; dummy_len = ava_len;
		ava = sc_asn1_skip_tag(ctx, &dummy, &dummy_len, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &ava_len);
		if (ava == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of AVA");

		/* unwrap the oid */
		oidp = sc_asn1_skip_tag(ctx, &ava, &ava_len, SC_ASN1_TAG_OBJECT, &oid_len);
		if (ava == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of AVA OID");

		/* Convert to OID */
		rv = sc_asn1_decode_object_id(oidp, oid_len, &oid);
		if (rv != SC_SUCCESS)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of AVA OID");

		if (sc_compare_oid(&oid, type) == 0)
			continue;

		/* Yes, then return the name */
		dummy = sc_asn1_skip_tag(ctx, &ava, &ava_len, ava[0] & SC_ASN1_TAG_PRIMITIVE, &dummy_len);
		if (*name == NULL) {
			*name = malloc(dummy_len);
			if (*name == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			*name_len = dummy_len;
		}

		*name_len = MIN(dummy_len, *name_len);
		memcpy(*name, dummy, *name_len);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
}


/* Get a specific extension from the cert.
 * The extension is identified by it's oid value.
 * NOTE: extensions can occur in any number or any order, which is why we
 *	can't parse them with a single pass of the asn1 decoder.
 * If is_critical is supplied, then it is set to 1 if the extension is critical
 * and 0 if it is not.
 * The data in the extension is extension specific.
 * The following are common extension values:
 *   Subject Key ID:		struct sc_object_id type = {{2, 5, 29, 14, -1}};
 *   Key Usage:			struct sc_object_id type = {{2, 5, 29, 15, -1}};
 *   Subject Alt Name:		struct sc_object_id type = {{2, 5, 29, 17, -1}};
 *   Basic Constraints:		struct sc_object_id type = {{2, 5, 29, 19, -1}};
 *   CRL Distribution Points:	struct sc_object_id type = {{2, 5, 29, 31, -1}};
 *   Certificate Policies:	struct sc_object_id type = {{2, 5, 29, 32, -1}};
 *   Extended Key Usage:	struct sc_object_id type = {{2, 5, 29, 37, -1}};
 *
 * if *ext_val is NULL, sc_pkcs15_get_extension will allocate space for ext_val.
 */
int
sc_pkcs15_get_extension(struct sc_context *ctx, struct sc_pkcs15_cert *cert,
	const struct sc_object_id *type, u8 **ext_val,
	size_t *ext_val_len, int *is_critical)
{
	const u8 *ext = NULL;
	const u8 *next_ext = NULL;
	size_t ext_len = 0;
	size_t next_ext_len = 0;
	struct sc_object_id oid;
	u8 *val = NULL;
	size_t val_len = 0;
	int critical;
	int r;
	struct sc_asn1_entry asn1_cert_ext[] = {
		{ "x509v3 entry OID", SC_ASN1_OBJECT, SC_ASN1_TAG_OBJECT, 0, &oid, 0 },
		{ "criticalFlag",  SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, &critical, NULL },
		{ "extensionValue",SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, &val, &val_len },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	for (next_ext = cert->extensions, next_ext_len = cert->extensions_len; next_ext_len; ) {
		/* unwrap the set and point to the next ava */
		ext = sc_asn1_skip_tag(ctx, &next_ext, &next_ext_len,
			SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, &ext_len);
		if (ext == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ASN1_OBJECT, "ASN.1 decoding of AVA");

		/*
		 * use the sc_asn1_decoder for clarity. NOTE it would be more efficient to do this by hand
		 * so we avoid the many malloc/frees here, but one hopes that one day the asn1_decode will allow
		 * a 'static pointer' flag that returns a const pointer to the actual asn1 space so we only need
		 * to make a final copy of the extension value before we return */
		critical = 0;
		r = sc_asn1_decode(ctx, asn1_cert_ext, ext, ext_len, NULL, NULL);
		if (r < 0)
			LOG_FUNC_RETURN(ctx, r);

		/* is it the RN we are looking for */
		if (sc_compare_oid(&oid, type) != 0) {
			if (*ext_val == NULL) {
				*ext_val = val;
				val = NULL;
				*ext_val_len = val_len;
				/* do not free here -- return the allocated value to caller */
			}
			else {
				*ext_val_len = MIN(*ext_val_len, val_len);
				if (val) {
					memcpy(*ext_val, val, *ext_val_len);
					free(val);
				}
			}

			if (is_critical)
				*is_critical = critical;

			r = val_len;
			LOG_FUNC_RETURN(ctx, r);
		}
		if (val) {
			free(val);
			val = NULL;
		}
	}
	if (val)
	    free(val);

	LOG_FUNC_RETURN(ctx, SC_ERROR_ASN1_OBJECT_NOT_FOUND);
}

/*
 *  Get an extension whose value is a bit string. These include keyUsage and extendedKeyUsage.
 *  See above for the other parameters.
 */
int
sc_pkcs15_get_bitstring_extension(struct sc_context *ctx,
	struct sc_pkcs15_cert *cert, const struct sc_object_id *type,
	unsigned int *value, int *is_critical)
{
	int r;
	u8 *bit_string = NULL;
	size_t bit_string_len=0, val_len = sizeof(*value);
	struct sc_asn1_entry asn1_bit_string[] = {
		{ "bitString", SC_ASN1_BIT_FIELD, SC_ASN1_TAG_BIT_STRING, 0, value, &val_len },
		{ NULL, 0, 0, 0, NULL, NULL }
	};

	r = sc_pkcs15_get_extension(ctx, cert, type, &bit_string, &bit_string_len, is_critical);
	LOG_TEST_RET(ctx, r, "Get extension error");

	r = sc_asn1_decode(ctx, asn1_bit_string, bit_string, bit_string_len, NULL, NULL);
	LOG_TEST_RET(ctx, r, "Decoding extension bit string");
	free(bit_string);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
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

	if (p15card == NULL || info == NULL || cert_out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
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
	{ "iD",		SC_ASN1_PKCS15_ID, SC_ASN1_TAG_OCTET_STRING, 0, NULL, NULL },
	{ "authority",	SC_ASN1_BOOLEAN,   SC_ASN1_TAG_BOOLEAN, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "identifier",	SC_ASN1_STRUCT,    SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, SC_ASN1_OPTIONAL, NULL, NULL },
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
	struct sc_asn1_pkcs15_object cert_obj = {
		obj, asn1_com_cert_attr, NULL,
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
	if (cert == NULL) {
		return;
	}

	sc_pkcs15_free_pubkey(cert->key);
	free(cert->subject);
	free(cert->issuer);
	free(cert->serial);
	free(cert->data.value);
	free(cert->extensions);
	free(cert);
}


void
sc_pkcs15_free_cert_info(sc_pkcs15_cert_info_t *cert)
{
	if (!cert)
		return;
	free(cert->value.value);
	free(cert);
}
