/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 */

#include "sc.h"
#include "sc-pkcs15.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

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

int sc_pkcs15_read_certificate(struct sc_pkcs15_card *p15card,
			       const struct sc_pkcs15_cert_info *info,
			       struct sc_pkcs15_cert **cert_out)
{
	int r, len;
	struct sc_file file;
	char *data;
	struct sc_pkcs15_cert *cert;
	char fname[50];
	u8 buf[2048];
	FILE *crtf;
	int cert_found = 0;
	

	assert(p15card != NULL && info != NULL && cert_out != NULL);

	/* FIXME: Remove this kludge */
	sprintf(fname, "/tmp/fineid-%02X.crt", info->id.value[0]);
	crtf = fopen(fname, "r");
	if (crtf != NULL) {
		r = fread(buf, 1, sizeof(buf), crtf);
		if (r > 0) {
			data = malloc(r);
			memcpy(data, buf, r);
			len = r;
			cert_found = 1;
		}
		fclose(crtf);
	}
	if (!cert_found) {
		r = sc_select_file(p15card->card, &file, &info->path,
				   SC_SELECT_FILE_BY_PATH);
		if (r)
			return r;
		data = malloc(file.size);
		if (data == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		r = sc_read_binary(p15card->card, 0, data, file.size);
		if (r < 0) {
			free(data);
			return r;
		}
		len = r;
		/* FIXME: kludge! */
		crtf = fopen(fname, "w");
		if (crtf != NULL) {
			fwrite(data, len, 1, crtf);
			fclose(crtf);
		}
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

static int parse_x509_cert_info(struct sc_pkcs15_cert_info *cert,
				const u8 * buf, int buflen)
{
	const u8 *tag, *p;
	int taglen, left;

	tag = sc_asn1_skip_tag(&buf, &buflen, 0x30, &taglen);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	sc_pkcs15_parse_common_object_attr(&cert->com_attr, tag, taglen);
	p = sc_asn1_skip_tag(&buf, &buflen, 0x30, &left);	/* SEQUENCE */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;

	tag = sc_asn1_skip_tag(&p, &left, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	memcpy(cert->id.value, tag, taglen);
	cert->id.len = taglen;

	tag = sc_asn1_find_tag(p, left, 0x01, &taglen);	/* BOOLEAN */
	if (tag != NULL && taglen > 0) {
		if (tag[0])
			cert->authority = 1;
		else
			cert->authority = 0;
	} else
		cert->authority = 0;

	/* FIXME */
	tag = sc_asn1_find_tag(buf, buflen, 0xA1, &taglen);
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	tag = sc_asn1_verify_tag(tag, taglen, 0x30, &taglen);	/* SEQUENCE 1 */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	tag = sc_asn1_verify_tag(tag, taglen, 0x30, &taglen);	/* SEQUENCE 2 */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	tag = sc_asn1_verify_tag(tag, taglen, 0x04, &taglen);	/* OCTET STRING */
	if (tag == NULL)
		return SC_ERROR_INVALID_ASN1_OBJECT;
	memcpy(cert->path.value, tag, taglen);
	cert->path.len = taglen;

	return 0;
}

void sc_pkcs15_print_cert_info(const struct sc_pkcs15_cert_info *cert)
{
	int i;
	printf("X.509 Certificate [%s]\n", cert->com_attr.label);
	printf("\tFlags    : %d\n", cert->com_attr.flags);
	printf("\tTrustable: %s\n", cert->authority ? "yes" : "no");
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
	int r, taglen, left;
	u8 buf[MAX_BUFFER_SIZE];
	const u8 *tag, *p;
	int count = 0;

	r = sc_select_file(card->card, file, &file->path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	r = sc_read_binary(card->card, 0, buf, file->size);
	if (r < 0)
		return r;

	left = r;
	p = buf;
	count = 0;
	while (card->cert_count < SC_PKCS15_MAX_CERTS) {
		tag = sc_asn1_skip_tag(&p, &left, 0x30, &taglen);	/* SEQUENCE */
		if (tag == NULL)
			break;
		if (parse_x509_cert_info
		    (&card->cert_info[card->cert_count], tag, taglen))
			break;
		card->cert_count++;
	}
	return 0;
}

int sc_pkcs15_enum_certificates(struct sc_pkcs15_card *card)
{
	int r;
	assert(card != NULL);

	card->cert_count = 0;
	r = get_certs_from_file(card, &card->file_cdf1);
	if (r != 0)
		return r;
	if (card->file_cdf2.path.len) {
		r = get_certs_from_file(card, &card->file_cdf2);
		if (r != 0)
			return r;
	}
	r = get_certs_from_file(card, &card->file_cdf3);
	if (r != 0)
		return r;
	return card->cert_count;
}

void sc_pkcs15_free_certificate(struct sc_pkcs15_cert *cert)
{
	assert(cert != NULL);

	free(cert->key.data);
	free(cert->data);
	free(cert);
}
