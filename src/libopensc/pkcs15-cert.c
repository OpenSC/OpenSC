/*
 * sc-pkcs15-cert.c: PKCS#15 certificate functions
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

static int parse_rsa_pubkey(const u8 *buf, int buflen, struct sc_pkcs15_rsa_pubkey *key)
{
	const u8 *tag;
	int taglen;

	buf = sc_asn1_verify_tag(buf, buflen, 0x30, &buflen);
	if (buf == NULL)
		return -1;

	tag = sc_asn1_verify_tag(buf, buflen, 0x02, &taglen);
	if (tag == NULL)
		return -1;
	key->modulus = malloc(taglen);
	memcpy(key->modulus, tag, taglen);
	key->modulus_len = taglen;
	tag += taglen;
	buflen -= tag - buf;
	tag = sc_asn1_verify_tag(tag, buflen, 0x02, &taglen);
	if (sc_asn1_decode_integer(tag, taglen, (int *) &key->exponent)) {
		free(key->modulus);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	return 0;
}

static int parse_cert(const u8 *buf, int buflen, struct sc_pkcs15_cert *cert)
{
	const u8 *tag, *p;
	u8 *tmpbuf;
	int taglen, left, r;
	struct sc_pkcs15_rsa_pubkey *key = &cert->key;
	const u8 *buf0 = buf;
	
	buf = sc_asn1_verify_tag(buf, buflen, 0x30, &buflen); /* SEQUENCE */
	if (buf == NULL)				   /* Certificate */
		return SC_ERROR_INVALID_ASN1_OBJECT;
	cert->data_len = (buf - buf0) + buflen;
	p = sc_asn1_skip_tag(&buf, &buflen, 0x30, &left);     /* SEQUENCE */
	if (p == NULL)					/* tbsCertificate */
		return SC_ERROR_INVALID_ASN1_OBJECT;
	cert->version = 0;
	tag = sc_asn1_skip_tag(&p, &left, 0xA0, &taglen);     /* Version */
	if (tag != NULL) {
		tag = sc_asn1_verify_tag(tag, taglen, 0x02, &taglen);
		if (tag != NULL) {
			sc_asn1_decode_integer(tag, taglen, &cert->version);
			cert->version++;
		}
	}
	tag = sc_asn1_skip_tag(&p, &left, 0x02, &taglen);     /* INTEGER */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	sc_asn1_decode_integer(tag, taglen, (int *) &cert->serial);

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);  /* signatureId */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);       /* issuer */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);     /* validity */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);      /* subject */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);  /* subjectPKInfo */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	/* FIXME: get the algorithm ID */
	tag = sc_asn1_find_tag(tag, taglen, 0x03, &taglen); /* subjectPubKey */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	tmpbuf = malloc(taglen-1);

	r = sc_asn1_decode_bit_string_ni(tag, taglen, tmpbuf, taglen-1);
	if (r < 0) {
		free(tmpbuf);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	r >>= 3;
	key->data = tmpbuf;
	key->data_len = taglen-1;
	r = parse_rsa_pubkey(tmpbuf, r, key);
	if (r) {
		free(tmpbuf);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	return 0;
}

static int generate_cert_filename(struct sc_pkcs15_card *p15card,
				  const struct sc_pkcs15_cert_info *info,
				  char *fname, int len)
{
	char *homedir;
	u8 cert_id[SC_PKCS15_MAX_ID_SIZE*2+1];
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
	u8 fname[1024];
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
	u8 fname[1024];
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
	if (parse_cert(data, len, cert)) {
		free(data);
		free(cert);
		return SC_ERROR_INVALID_ASN1_OBJECT;
	}
	cert->data = data;
	*cert_out = cert;
	return 0;
}

static int parse_x509_cert_info(struct sc_context *ctx,
				struct sc_pkcs15_cert_info *cert,
				const u8 ** buf, int *buflen)
{
	u8 id_value[128];
	int id_type, id_value_len = sizeof(id_value);
	int r;
	
	struct sc_asn1_struct asn1_cred_ident[] = {
		{ "idType",	SC_ASN1_INTEGER,      ASN1_INTEGER, 0, &id_type },
		{ "idValue",	SC_ASN1_OCTET_STRING, ASN1_OCTET_STRING, 0, &id_value, &id_value_len },
		{ NULL }
	};
	struct sc_asn1_struct asn1_com_cert_attr[] = {
		{ "iD",         SC_ASN1_PKCS15_ID, ASN1_OCTET_STRING, 0, &cert->id, NULL },
		{ "authority",  SC_ASN1_BOOLEAN,   ASN1_BOOLEAN, SC_ASN1_OPTIONAL, &cert->authority, NULL },
		{ "identifier", SC_ASN1_STRUCT,    ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_cred_ident },
		{ NULL }
	};
	struct sc_asn1_struct asn1_x509_cert_attr[] = {
		{ "value",	SC_ASN1_PATH,	   ASN1_SEQUENCE | SC_ASN1_CONS, 0, &cert->path },
		{ NULL }
	};
	struct sc_asn1_struct asn1_type_cert_attr[] = {
		{ "x509CertificateAttributes", SC_ASN1_STRUCT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, asn1_x509_cert_attr },
		{ NULL }
	};
	struct sc_pkcs15_object cert_obj = { &cert->com_attr, asn1_com_cert_attr, NULL,
					     asn1_type_cert_attr };
	struct sc_asn1_struct asn1_cert[] = {
		{ "x509Certificate", SC_ASN1_PKCS15_OBJECT, ASN1_SEQUENCE | SC_ASN1_CONS, 0, &cert_obj },
		{ NULL }
	};

	r = sc_asn1_parse(ctx, asn1_cert, *buf, *buflen, buf, buflen);

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

static int get_certs_from_file(struct sc_pkcs15_card *card,
			       struct sc_file *file)
{
	int r, bytes_left;
	u8 buf[2048];
	const u8 *p = buf;

	r = sc_select_file(card->card, &file->path, file);
	if (r)
		return r;
	if (file->size > sizeof(buf))
		return SC_ERROR_BUFFER_TOO_SMALL;
	r = sc_read_binary(card->card, 0, buf, file->size, 0);
	if (r < 0)
		return r;
	bytes_left = r;
	do {
		struct sc_pkcs15_cert_info tmp;

		r = parse_x509_cert_info(card->card->ctx,
					 &tmp, &p, &bytes_left);
		if (r == SC_ERROR_ASN1_END_OF_CONTENTS)
			break;
		if (r)
			return r;
		if (card->cert_count >= SC_PKCS15_MAX_CERTS)
			return SC_ERROR_TOO_MANY_OBJECTS;
                card->cert_info[card->cert_count] = tmp;
		card->cert_count++;
	} while (bytes_left);

	return 0;
}

int sc_pkcs15_enum_certificates(struct sc_pkcs15_card *card)
{
	int r = 0, i;
	assert(card != NULL);

	if (card->cert_count)
		return card->cert_count;	/* already enumerated */
	r = sc_lock(card->card);
	SC_TEST_RET(card->card->ctx, r, "sc_lock() failed");
	for (i = 0; i < card->cdf_count; i++) {
		r = get_certs_from_file(card, &card->file_cdf[i]);
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
