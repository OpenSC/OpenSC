/*
 * pkcs15-cert.c: PKCS#15 certificate functions
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

#undef CACHE_CERTS

static int parse_rsa_pubkey(struct sc_context *ctx, struct sc_pkcs15_rsa_pubkey *key)
{
	struct sc_asn1_entry asn1_rsa_pubkey[] = {
		{ "modulus",	    SC_ASN1_OCTET_STRING, ASN1_INTEGER, SC_ASN1_ALLOC, &key->modulus, &key->modulus_len },
		{ "publicExponent", SC_ASN1_INTEGER, ASN1_INTEGER, 0, &key->exponent },
		{ NULL }
	};
	const u8 *obj;
	size_t objlen;
	int r;
	
	obj = sc_asn1_verify_tag(ctx, key->data, key->data_len, ASN1_SEQUENCE | SC_ASN1_CONS,
				 &objlen);
	if (obj == NULL) {
		error(ctx, "RSA public key not found\n");
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	r = sc_asn1_decode(ctx, asn1_rsa_pubkey, obj, objlen, NULL, NULL);
	SC_TEST_RET(ctx, r, "ASN.1 parsing failed");

	return 0;
}

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
	struct sc_pkcs15_rsa_pubkey *key = &cert->key;
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
		{ "serialNumber",	SC_ASN1_INTEGER,   ASN1_INTEGER, 0, &cert->serial },
		{ "signature",		SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
		{ "issuer",		SC_ASN1_STRUCT,	   ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
		{ "validity",		SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
		{ "subject",		SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, NULL },
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
	r = parse_rsa_pubkey(ctx, key);
	if (r) {
		free(key->data);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}

	return 0;
}

static int generate_cert_filename(struct sc_pkcs15_card *p15card,
				  const struct sc_pkcs15_cert_info *info,
				  char *fname, int len)
{
	char *homedir;
	char cert_id[SC_PKCS15_MAX_ID_SIZE*2+1];
	int i, r;

	homedir = getenv("HOME");
	if (homedir == NULL)
		return -1;
	cert_id[0] = 0;
	for (i = 0; i < info->id.len; i++) {
		char tmp[3];

		sprintf(tmp, "%02X", info->id.value[i]);
		strcat(cert_id, tmp);
	}
	r = snprintf(fname, len, "%s/%s/%s_%s_%s.crt", homedir,
		     SC_PKCS15_CACHE_DIR, p15card->label,
		     p15card->serial_number, cert_id);
	if (r < 0)
		return -1;
	return 0;
}

static int find_cached_cert(struct sc_pkcs15_card *p15card,
			const struct sc_pkcs15_cert_info *info,
			u8 **out, int *outlen)
{
	int r;
	u8 *data;
	char fname[1024];
	FILE *crtf; 
	struct stat stbuf;

	if (getuid() != geteuid())  /* no caching in SUID processes */
		return -1;
	if (p15card->use_cache == 0)
		return -1;
	
	r = generate_cert_filename(p15card, info, fname, sizeof(fname));
	if (r)
		return SC_ERROR_UNKNOWN;
	r = stat(fname, &stbuf);
	if (r)
		return SC_ERROR_OBJECT_NOT_FOUND;
	crtf = fopen(fname, "r");
	if (crtf == NULL)
		return SC_ERROR_OBJECT_NOT_FOUND;
	data = malloc(stbuf.st_size);
	if (data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	r = fread(data, 1, stbuf.st_size, crtf);
	fclose(crtf);
	if (r <= 0) {
		free(data);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	*outlen = r;
	*out = data;

	return 0;
}

#ifdef CACHE_CERTS
static int store_cert_to_cache(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_cert_info *info,
			       u8 *data, int len)
{
	char fname[1024];
	FILE *crtf;
	int r;
	
	if (getuid() != geteuid())  /* no caching in SUID processes */
		return 0;

	r = generate_cert_filename(p15card, info, fname, sizeof(fname));
	if (r)
		return SC_ERROR_UNKNOWN;
	
	crtf = fopen(fname, "w");
	if (crtf == NULL)
		return SC_ERROR_UNKNOWN;
	fwrite(data, len, 1, crtf);
	fclose(crtf);
	return 0;
}
#endif

int sc_pkcs15_read_certificate(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_cert_info *info,
			       struct sc_pkcs15_cert **cert_out)
{
	int r, len = 0;
	struct sc_file file;
	u8 *data = NULL;
	struct sc_pkcs15_cert *cert;

	assert(p15card != NULL && info != NULL && cert_out != NULL);
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	r = find_cached_cert(p15card, info, &data, &len);
	if (r) {
		r = sc_lock(p15card->card);
		SC_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");
		r = sc_select_file(p15card->card, &info->path, &file);
		if (r) {
			sc_unlock(p15card->card);
			return r;
		}
		data = malloc(file.size);
		if (data == NULL) {
			sc_unlock(p15card->card);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		r = sc_read_binary(p15card->card, 0, data, file.size, 0);
		if (r < 0) {
			sc_unlock(p15card->card);
			free(data);
			return r;
		}
		len = r;
#ifdef CACHE_CERTS
		store_cert_to_cache(p15card, info, data, len);
#endif
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

static int parse_x509_cert_info(struct sc_context *ctx,
				struct sc_pkcs15_cert_info *cert,
				const u8 ** buf, size_t *buflen)
{
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2];
	struct sc_asn1_pkcs15_object cert_obj = { &cert->com_attr, asn1_com_cert_attr, NULL,
					     asn1_type_cert_attr };
	u8 id_value[128];
	int id_type, id_value_len = sizeof(id_value);
	int r;

	cert->authority = 0;
	
	sc_copy_asn1_entry(c_asn1_cred_ident, asn1_cred_ident);
	sc_copy_asn1_entry(c_asn1_com_cert_attr, asn1_com_cert_attr);
	sc_copy_asn1_entry(c_asn1_x509_cert_attr, asn1_x509_cert_attr);
	sc_copy_asn1_entry(c_asn1_type_cert_attr, asn1_type_cert_attr);
	sc_copy_asn1_entry(c_asn1_cert, asn1_cert);
	
	sc_format_asn1_entry(asn1_cred_ident + 0, &id_type, NULL, 0);
	sc_format_asn1_entry(asn1_cred_ident + 1, &id_value, &id_value_len, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 0, &cert->id, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 1, &cert->authority, NULL, 0);
	sc_format_asn1_entry(asn1_com_cert_attr + 2, asn1_cred_ident, NULL, 0);
	sc_format_asn1_entry(asn1_x509_cert_attr + 0, &cert->path, NULL, 0);
	sc_format_asn1_entry(asn1_type_cert_attr + 0, asn1_x509_cert_attr, NULL, 0);
	sc_format_asn1_entry(asn1_cert + 0, &cert_obj, NULL, 0);

	r = sc_asn1_decode(ctx, asn1_cert, *buf, *buflen, buf, buflen);

	return r;
}

int sc_pkcs15_encode_cdf_entry(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_object *obj,
			       u8 **buf, size_t *bufsize)
{
	struct sc_asn1_entry	asn1_cred_ident[3], asn1_com_cert_attr[4],
				asn1_x509_cert_attr[2], asn1_type_cert_attr[2],
				asn1_cert[2];
	struct sc_pkcs15_cert_info *infop =
		(struct sc_pkcs15_cert_info *) obj->data;
	const struct sc_asn1_pkcs15_object cert_obj = { &infop->com_attr, asn1_com_cert_attr, NULL,
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

	r = sc_asn1_encode(p15card->card->ctx, asn1_cert, buf, bufsize);

	return r;
}

void sc_pkcs15_print_cert_info(const struct sc_pkcs15_cert_info *cert)
{
	int i;
	printf("X.509 Certificate [%s]\n", cert->com_attr.label);
	printf("\tFlags    : %d\n", cert->com_attr.flags);
	printf("\tAuthority: %s\n", cert->authority ? "yes" : "no");
	printf("\tPath     : ");
	for (i = 0; i < cert->path.len; i++)
		printf("%02X", cert->path.value[i]);
	printf("\n");
	printf("\tID       : ");
	sc_pkcs15_print_id(&cert->id);
	printf("\n");
}

static int get_certs_from_file(struct sc_pkcs15_card *p15card,
			       struct sc_pkcs15_df *df,
			       int file_nr)
{
	int r;
	size_t bytes_left;
	u8 buf[2048];
	const u8 *p = buf;
	struct sc_file *file = df->file[file_nr];

	r = sc_select_file(p15card->card, &file->path, file);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(p15card->card, 0, buf, file->size, 0);
	if (r < 0)
		return r;
	bytes_left = r;
	do {
		struct sc_pkcs15_cert_info info, *infop;
		struct sc_pkcs15_object *objp;

		memset(&info, 0, sizeof(info));
		r = parse_x509_cert_info(p15card->card->ctx,
					 &info, &p, &bytes_left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r)
			return r;
		infop = malloc(sizeof(info));
		if (infop == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(infop, &info, sizeof(info));
		objp = malloc(sizeof(struct sc_pkcs15_object));
		if (objp == NULL) {
			free(infop);
			return SC_ERROR_OUT_OF_MEMORY;
		}
		objp->type = SC_PKCS15_TYPE_CERT_X509;
		objp->data = infop;
		r = sc_pkcs15_add_object(p15card->card->ctx, df, file_nr, objp);
		if (r) {
			free(infop);
			free(objp);
			return r;
		}
                if (p15card->cert_count >= SC_PKCS15_MAX_PRKEYS)
			break;
		p15card->cert_info[p15card->cert_count] = info;
		p15card->cert_count++;
	} while (bytes_left);

	return 0;
}

int sc_pkcs15_enum_certificates(struct sc_pkcs15_card *card)
{
	int r = 0, i, j, type;
	const int df_types[] = {
		SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED, SC_PKCS15_CDF_USEFUL
	};
	const int nr_types = sizeof(df_types)/sizeof(df_types[0]);
				
	assert(card != NULL);

	if (card->cert_count)
		return card->cert_count;	/* already enumerated */
	r = sc_lock(card->card);
	SC_TEST_RET(card->card->ctx, r, "sc_lock() failed");
	for (j = 0; j < nr_types; j++) {
		type = df_types[j];
		
		for (i = 0; i < card->df[type].count; i++) {
			r = get_certs_from_file(card, &card->df[type], i);
			if (r != 0)
				break;
		}
		if (r != 0)
			break;
	}
	sc_unlock(card->card);
	if (r != 0)
		return r;
	return card->cert_count;
}

void sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert)
{
	assert(cert != NULL);

	free(cert->key.data);
	free(cert->key.modulus);
	free(cert->data);
	free(cert);
}

int sc_pkcs15_find_cert_by_id(struct sc_pkcs15_card *card,
			      const struct sc_pkcs15_id *id,
			      struct sc_pkcs15_cert_info **cert_out)
{
	int r, i;
	
	r = sc_pkcs15_enum_certificates(card);
	if (r < 0)
		return r;
	for (i = 0; i < card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cert = &card->cert_info[i];
		if (sc_pkcs15_compare_id(&cert->id, id) == 1) {
			*cert_out = cert;
			return 0;
		}
	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}
