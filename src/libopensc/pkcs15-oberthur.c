/*
 * PKCS15 emulation layer for Oberthur card.
 *
 * Copyright (C) 2010, Viktor Tarasov <vtarasov@opentrust.com>
 * Copyright (C) 2005, Andrea Frigido <andrea@frisoft.it>
 * Copyright (C) 2005, Sirio Capizzi <graaf@virgilio.it>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../common/compat_strlcpy.h"

#include "pkcs15.h"
#include "log.h"
#include "asn1.h"
#include "internal.h"

#ifdef ENABLE_OPENSSL
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#define OBERTHUR_ATTR_MODIFIABLE	0x0001
#define OBERTHUR_ATTR_TRUSTED		0x0002
#define OBERTHUR_ATTR_LOCAL		0x0004
#define OBERTHUR_ATTR_ENCRYPT		0x0008
#define OBERTHUR_ATTR_DECRYPT		0x0010
#define OBERTHUR_ATTR_SIGN		0x0020
#define OBERTHUR_ATTR_VERIFY		0x0040
#define OBERTHUR_ATTR_RSIGN		0x0080
#define OBERTHUR_ATTR_RVERIFY		0x0100
#define OBERTHUR_ATTR_WRAP		0x0200
#define OBERTHUR_ATTR_UNWRAP		0x0400
#define OBERTHUR_ATTR_DERIVE		0x0800

#define USAGE_PRV_ENC	(SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT |\
			 SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_UNWRAP)
#define USAGE_PRV_AUT	 SC_PKCS15_PRKEY_USAGE_SIGN
#define USAGE_PRV_SIGN	(SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_PUB_ENC	(SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_WRAP)
#define USAGE_PUB_AUT	 SC_PKCS15_PRKEY_USAGE_VERIFY
#define USAGE_PUB_SIGN	(SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER)

#define PIN_DOMAIN_LABEL	"SCM"
const unsigned char PinDomainID[3] = {0x53, 0x43, 0x4D};

#define AWP_PIN_DF		"3F005011"
#define AWP_TOKEN_INFO		"3F0050111000"
#define AWP_PUK_FILE		"3F0050112000"
#define AWP_CONTAINERS_MS	"3F0050113000"
#define AWP_OBJECTS_LIST_PUB	"3F0050114000"
#define AWP_OBJECTS_LIST_PRV	"3F0050115000"
#define AWP_OBJECTS_DF_PUB	"3F0050119001"
#define AWP_OBJECTS_DF_PRV	"3F0050119002"
#define AWP_BASE_RSA_PRV	"3F00501190023000"
#define AWP_BASE_RSA_PUB	"3F00501190011000"
#define AWP_BASE_CERTIFICATE	"3F00501190012000"

#define BASE_ID_PUB_RSA   0x10
#define BASE_ID_CERT	  0x20
#define BASE_ID_PRV_RSA   0x30
#define BASE_ID_PRV_DES   0x40
#define BASE_ID_PUB_DATA  0x50
#define BASE_ID_PRV_DATA  0x60
#define BASE_ID_PUB_DES   0x70

static int sc_pkcs15emu_oberthur_add_prvkey(struct sc_pkcs15_card *, unsigned, unsigned);
static int sc_pkcs15emu_oberthur_add_pubkey(struct sc_pkcs15_card *, unsigned, unsigned);
static int sc_pkcs15emu_oberthur_add_cert(struct sc_pkcs15_card *, unsigned);
static int sc_pkcs15emu_oberthur_add_data(struct sc_pkcs15_card *, unsigned, unsigned, int);

int sc_pkcs15emu_oberthur_init_ex(struct sc_pkcs15_card *, struct sc_aid *, struct sc_pkcs15emu_opt *);

static int sc_oberthur_parse_tokeninfo (struct sc_pkcs15_card *, unsigned char *, size_t, int);
static int sc_oberthur_parse_containers (struct sc_pkcs15_card *, unsigned char *, size_t, int);
static int sc_oberthur_parse_publicinfo (struct sc_pkcs15_card *, unsigned char *, size_t, int);
static int sc_oberthur_parse_privateinfo (struct sc_pkcs15_card *, unsigned char *, size_t, int);

static int sc_awp_parse_df(struct sc_pkcs15_card *, struct sc_pkcs15_df *);
static void sc_awp_clear(struct sc_pkcs15_card *);

struct crypto_container {
	unsigned  id_pub;
	unsigned  id_prv;
	unsigned  id_cert;
};

struct container {
	char uuid[37];
	struct crypto_container exchange;
	struct crypto_container sign;

	struct container *next;
	struct container *prev;
};

struct container *Containers = NULL;

static struct {
	const char *name;
	const char *path;
	unsigned char *content;
	size_t len;
	int (*parser)(struct sc_pkcs15_card *, unsigned char *, size_t, int);
	int postpone_allowed;
} oberthur_infos[] = {
	/* Never change the following order */
	{ "Token info",			AWP_TOKEN_INFO, 	NULL, 0, sc_oberthur_parse_tokeninfo, 	0},
	{ "Containers MS",		AWP_CONTAINERS_MS, 	NULL, 0, sc_oberthur_parse_containers, 	0},
	{ "Public objects list",	AWP_OBJECTS_LIST_PUB, 	NULL, 0, sc_oberthur_parse_publicinfo, 	0},
	{ "Private objects list",	AWP_OBJECTS_LIST_PRV,	NULL, 0, sc_oberthur_parse_privateinfo, 1},
	{ NULL, NULL, NULL, 0, NULL, 0}
};


static unsigned
sc_oberthur_decode_usage(unsigned flags)
{
	unsigned ret = 0;

	if (flags & OBERTHUR_ATTR_ENCRYPT)
		ret |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
	if (flags & OBERTHUR_ATTR_DECRYPT)
		ret |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
	if (flags & OBERTHUR_ATTR_SIGN)
		ret |= SC_PKCS15_PRKEY_USAGE_SIGN;
	if (flags & OBERTHUR_ATTR_RSIGN)
		ret |= SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
	if (flags & OBERTHUR_ATTR_WRAP)
		ret |= SC_PKCS15_PRKEY_USAGE_WRAP;
	if (flags & OBERTHUR_ATTR_UNWRAP)
		ret |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
	if (flags & OBERTHUR_ATTR_VERIFY)
		ret |= SC_PKCS15_PRKEY_USAGE_VERIFY;
	if (flags & OBERTHUR_ATTR_RVERIFY)
		ret |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
	if (flags & OBERTHUR_ATTR_DERIVE)
		ret |= SC_PKCS15_PRKEY_USAGE_DERIVE;
	return ret;
}


static int
sc_oberthur_get_friends (unsigned int id, struct crypto_container *ccont)
{
	struct container *cont;

	for (cont = Containers; cont; cont = cont->next)   {
		if (cont->exchange.id_pub == id || cont->exchange.id_prv == id || cont->exchange.id_cert == id)   {
			if (ccont)
				memcpy(ccont, &cont->exchange, sizeof(struct crypto_container));
			break;
		}

		if (cont->sign.id_pub == id || cont->sign.id_prv == id || cont->sign.id_cert == id)   {
			if (ccont)
				memcpy(ccont, &cont->sign, sizeof(struct crypto_container));
			break;
		}
	}

	return cont ? 0 : SC_ERROR_TEMPLATE_NOT_FOUND;
}


static int
sc_oberthur_get_certificate_authority(struct sc_pkcs15_der *der, int *out_authority)
{
#ifdef ENABLE_OPENSSL
	X509	*x;
	BUF_MEM buf_mem;
	BIO *bio = NULL;
	BASIC_CONSTRAINTS *bs = NULL;

	if (!der)
		return SC_ERROR_INVALID_ARGUMENTS;

	buf_mem.data = malloc(der->len);
	if (!buf_mem.data)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(buf_mem.data, der->value, der->len);
	buf_mem.max = buf_mem.length = der->len;

	bio = BIO_new(BIO_s_mem());
	if (!bio) {
		free(buf_mem.data);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	BIO_set_mem_buf(bio, &buf_mem, BIO_NOCLOSE);
	x = d2i_X509_bio(bio, 0);
	BIO_free(bio);
	if (!x)
		return SC_ERROR_INVALID_DATA;

	bs = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(x, NID_basic_constraints, NULL, NULL);
	if (out_authority)
		*out_authority = (bs && bs->ca);

	X509_free(x);

	return SC_SUCCESS;
#else
	return SC_ERROR_NOT_SUPPORTED;
#endif
}


static int
sc_oberthur_read_file(struct sc_pkcs15_card *p15card, const char *in_path,
		unsigned char **out, size_t *out_len,
		int verify_pin)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file *file = NULL;
	struct sc_path path;
	size_t sz;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!in_path || !out || !out_len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot read oberthur file");

	sc_log(ctx, "read file '%s'; verify_pin:%i", in_path, verify_pin);

	*out = NULL;
	*out_len = 0;

	sc_format_path(in_path, &path);
	rv = sc_select_file(card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select oberthur file to read");

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT)
		sz = file->size;
	else
		sz = (file->record_length + 2) * file->record_count;

	*out = calloc(sz, 1);
	if (*out == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot read oberthur file");

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT)   {
		rv = sc_read_binary(card, 0, *out, sz, 0);
	}
	else	{
		int rec;
		int offs = 0;
		int rec_len = file->record_length;

		for (rec = 1; ; rec++)   {
			rv = sc_read_record(card, rec, *out + offs + 2, rec_len, SC_RECORD_BY_REC_NR);
			if (rv == SC_ERROR_RECORD_NOT_FOUND)   {
				rv = 0;
				break;
			}
			else if (rv < 0)   {
				break;
			}

			rec_len = rv;

			*(*out + offs) = 'R';
			*(*out + offs + 1) = rv;

			offs += rv + 2;
		}

		sz = offs;
	}

	sc_log(ctx, "read oberthur file result %i", rv);
	if (verify_pin && rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)   {
		struct sc_pkcs15_object *objs[0x10], *pin_obj = NULL;
		const struct sc_acl_entry *acl = sc_file_get_acl_entry(file, SC_AC_OP_READ);
		int ii;

		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 0x10);
		LOG_TEST_RET(ctx, rv, "Cannot read oberthur file: get AUTH objects error");

		for (ii=0; ii<rv; ii++)   {
			struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) objs[ii]->data;
			sc_log(ctx, "compare PIN/ACL refs:%i/%i, method:%i/%i",
					auth_info->attrs.pin.reference, acl->key_ref, auth_info->auth_method, acl->method);
			if (auth_info->attrs.pin.reference == (int)acl->key_ref && auth_info->auth_method == (unsigned)acl->method)   {
				pin_obj = objs[ii];
				break;
			}
		}

		if (!pin_obj || !pin_obj->content.value)    {
			rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		}
		else    {
			rv = sc_pkcs15_verify_pin(p15card, pin_obj, pin_obj->content.value, pin_obj->content.len);
			if (!rv)
				rv = sc_oberthur_read_file(p15card, in_path, out, out_len, 0);
		}
	};

	sc_file_free(file);

	if (rv < 0)   {
		free(*out);
		*out = NULL;
		*out_len = 0;
	}

	*out_len = sz;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_oberthur_parse_tokeninfo (struct sc_pkcs15_card *p15card,
		unsigned char *buff, size_t len, int postpone_allowed)
{
	struct sc_context *ctx = p15card->card->ctx;
	char label[0x21];
	unsigned flags;
	int ii;

	LOG_FUNC_CALLED(ctx);
	if (!buff || len < 0x24)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot parse token info");

	memset(label, 0, sizeof(label));

	memcpy(label, buff, 0x20);
	ii = 0x20;
	while (*(label + --ii)==' ' && ii)
		;
	*(label + ii + 1) = '\0';

	flags = *(buff + 0x22) * 0x100 + *(buff + 0x23);

	p15card->tokeninfo->label = strdup(label);
	p15card->tokeninfo->manufacturer_id = strdup("Oberthur/OpenSC");

	if (flags & 0x01)
		p15card->tokeninfo->flags |= SC_PKCS15_TOKEN_PRN_GENERATION;

	sc_log(ctx, "label %s", p15card->tokeninfo->label);
	sc_log(ctx, "manufacturer_id %s", p15card->tokeninfo->manufacturer_id);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_oberthur_parse_containers (struct sc_pkcs15_card *p15card,
		unsigned char *buff, size_t len, int postpone_allowed)
{
	struct sc_context *ctx = p15card->card->ctx;
	size_t offs;

	LOG_FUNC_CALLED(ctx);

	while (Containers)   {
		struct container *next = Containers->next;

		free (Containers);
		Containers = next;
	}

	for (offs=0; offs < len;)  {
		struct container *cont;
		unsigned char *ptr =  buff + offs + 2;

		sc_log(ctx,
		       "parse contaniers offs:%"SC_FORMAT_LEN_SIZE_T"u, len:%"SC_FORMAT_LEN_SIZE_T"u",
		       offs, len);
		if (*(buff + offs) != 'R')
			return SC_ERROR_INVALID_DATA;

		cont = (struct container *)calloc(sizeof(struct container), 1);
		if (!cont)
			return SC_ERROR_OUT_OF_MEMORY;

		cont->exchange.id_pub = *ptr * 0x100 + *(ptr + 1);  ptr += 2;
		cont->exchange.id_prv = *ptr * 0x100 + *(ptr + 1);  ptr += 2;
		cont->exchange.id_cert = *ptr * 0x100 + *(ptr + 1); ptr += 2;

		cont->sign.id_pub = *ptr * 0x100 + *(ptr + 1);  ptr += 2;
		cont->sign.id_prv = *ptr * 0x100 + *(ptr + 1);  ptr += 2;
		cont->sign.id_cert = *ptr * 0x100 + *(ptr + 1); ptr += 2;

		memcpy(cont->uuid, ptr + 2, 36);
		sc_log(ctx, "UUID: %s; 0x%X, 0x%X, 0x%X", cont->uuid,
				cont->exchange.id_pub, cont->exchange.id_prv, cont->exchange.id_cert);

		if (!Containers)  {
			Containers = cont;
		}
		else   {
			cont->next = Containers;
			Containers->prev = (void *)cont;
			Containers = cont;
		}

		offs += *(buff + offs + 1) + 2;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_oberthur_parse_publicinfo (struct sc_pkcs15_card *p15card,
		unsigned char *buff, size_t len, int postpone_allowed)
{
	struct sc_context *ctx = p15card->card->ctx;
	size_t ii;
	int rv;

	LOG_FUNC_CALLED(ctx);
	for (ii=0; ii<len; ii+=5)   {
		unsigned int file_id, size;

		if(*(buff+ii) != 0xFF)
			continue;

		file_id = 0x100 * *(buff+ii + 1) + *(buff+ii + 2);
		size = 0x100 * *(buff+ii + 3) + *(buff+ii + 4);
		sc_log(ctx, "add public object(file-id:%04X,size:%X)", file_id, size);

		switch (*(buff+ii + 1))   {
		case BASE_ID_PUB_RSA :
			rv = sc_pkcs15emu_oberthur_add_pubkey(p15card, file_id, size);
			LOG_TEST_RET(ctx, rv, "Cannot parse public key info");
			break;
		case BASE_ID_CERT :
			rv = sc_pkcs15emu_oberthur_add_cert(p15card, file_id);
			LOG_TEST_RET(ctx, rv, "Cannot parse certificate info");
			break;
		case BASE_ID_PUB_DES :
			break;
		case BASE_ID_PUB_DATA :
			rv = sc_pkcs15emu_oberthur_add_data(p15card, file_id, size, 0);
			LOG_TEST_RET(ctx, rv, "Cannot parse data info");
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Public object parse error");
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
sc_oberthur_parse_privateinfo (struct sc_pkcs15_card *p15card,
		unsigned char *buff, size_t len, int postpone_allowed)
{
	struct sc_context *ctx = p15card->card->ctx;
	size_t ii;
	int rv;
	int no_more_private_keys = 0, no_more_private_data = 0;

	LOG_FUNC_CALLED(ctx);

	for (ii=0; ii<len; ii+=5)   {
		unsigned int file_id, size;

		if(*(buff+ii) != 0xFF)
			continue;

		file_id = 0x100 * *(buff+ii + 1) + *(buff+ii + 2);
		size = 0x100 * *(buff+ii + 3) + *(buff+ii + 4);
		sc_log(ctx, "add private object (file-id:%04X, size:%X)", file_id, size);

		switch (*(buff+ii + 1))   {
		case BASE_ID_PRV_RSA :
			if (no_more_private_keys)
				break;

			rv = sc_pkcs15emu_oberthur_add_prvkey(p15card, file_id, size);
			if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED && postpone_allowed)   {
				struct sc_path path;

				sc_log(ctx, "postpone adding of the private keys");
				sc_format_path("5011A5A5", &path);
				rv = sc_pkcs15_add_df(p15card, SC_PKCS15_PRKDF, &path);
				LOG_TEST_RET(ctx, rv, "Add PrkDF error");
				no_more_private_keys = 1;
			}
			LOG_TEST_RET(ctx, rv, "Cannot parse private key info");
			break;
		case BASE_ID_PRV_DES :
			break;
		case BASE_ID_PRV_DATA :
			sc_log(ctx, "*(buff+ii + 1):%X", *(buff+ii + 1));
			if (no_more_private_data)
				break;

			rv = sc_pkcs15emu_oberthur_add_data(p15card, file_id, size, 1);
			if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED && postpone_allowed)   {
				struct sc_path path;

				sc_log(ctx, "postpone adding of the private data");
				sc_format_path("5011A6A6", &path);
				rv = sc_pkcs15_add_df(p15card, SC_PKCS15_DODF, &path);
				LOG_TEST_RET(ctx, rv, "Add DODF error");
				no_more_private_data = 1;
			}
			LOG_TEST_RET(ctx, rv, "Cannot parse private data info");
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Private object parse error");
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/* Public key info:
 * 	flags:2,
 * 	CN(len:2,value:<variable length>),
 * 	ID(len:2,value:(SHA1 value)),
 * 	StartDate(Ascii:8)
 * 	EndDate(Ascii:8)
 * 	??(0x00:2)
 */
static int
sc_pkcs15emu_oberthur_add_pubkey(struct sc_pkcs15_card *p15card,
		unsigned int file_id, unsigned int size)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info key_info;
	struct sc_pkcs15_object key_obj;
	char ch_tmp[0x100];
	unsigned char *info_blob;
	size_t len, info_len, offs;
	unsigned flags;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "public key(file-id:%04X,size:%X)", file_id, size);

	memset(&key_info, 0, sizeof(key_info));
	memset(&key_obj, 0, sizeof(key_obj));

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PUB, file_id | 0x100);
	rv = sc_oberthur_read_file(p15card, ch_tmp, &info_blob, &info_len, 1);
	LOG_TEST_RET(ctx, rv, "Failed to add public key: read oberthur file error");

	/* Flags */
	offs = 2;
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add public key: no 'tag'");
	flags = *(info_blob + 0) * 0x100 + *(info_blob + 1);
	key_info.usage = sc_oberthur_decode_usage(flags);
	if (flags & OBERTHUR_ATTR_MODIFIABLE)
		key_obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE;
	sc_log(ctx, "Public key key-usage:%04X", key_info.usage);

	/* Label */
	if (offs + 2 > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add public key: no 'Label'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (len)   {
		if (len > sizeof(key_obj.label) - 1)
			len = sizeof(key_obj.label) - 1;
		memcpy(key_obj.label, info_blob + offs + 2, len);
	}
	offs += 2 + len;

	/* ID */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add public key: no 'ID'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (!len || len > sizeof(key_info.id.value))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Failed to add public key: invalid 'ID' length");
	memcpy(key_info.id.value, info_blob + offs + 2, len);
	key_info.id.len = len;

	/* Ignore Start/End dates */

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PUB, file_id);
	sc_format_path(ch_tmp, &key_info.path);

	key_info.native = 1;
	key_info.key_reference = file_id & 0xFF;
	key_info.modulus_length = size;

	rv = sc_pkcs15emu_add_rsa_pubkey(p15card, &key_obj, &key_info);

	LOG_FUNC_RETURN(ctx, rv);
}


/* Certificate info:
 * 	flags:2,
 * 	Label(len:2,value:),
 * 	ID(len:2,value:(SHA1 value)),
 * 	Subject in ASN.1(len:2,value:)
 * 	Issuer in ASN.1(len:2,value:)
 * 	Serial encoded in LV or ASN.1	FIXME
 */
static int
sc_pkcs15emu_oberthur_add_cert(struct sc_pkcs15_card *p15card, unsigned int file_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info cinfo;
	struct sc_pkcs15_object cobj;
	unsigned char *info_blob, *cert_blob;
	size_t info_len, cert_len, len, offs;
	unsigned flags;
	int rv;
	char ch_tmp[0x20];

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "add certificate(file-id:%04X)", file_id);

	memset(&cinfo, 0, sizeof(cinfo));
	memset(&cobj, 0, sizeof(cobj));

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PUB, file_id | 0x100);
	rv = sc_oberthur_read_file(p15card, ch_tmp, &info_blob, &info_len, 1);
	LOG_TEST_RET(ctx, rv, "Failed to add certificate: read oberthur file error");

	if (info_len < 2)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add certificate: no 'tag'");
	flags = *(info_blob + 0) * 0x100 + *(info_blob + 1);
	offs = 2;

	/* Label */
	if (offs + 2 > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add certificate: no 'CN'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (len)   {
		if (len > sizeof(cobj.label) - 1)
			len = sizeof(cobj.label) - 1;
		memcpy(cobj.label, info_blob + offs + 2, len);
	}
	offs += 2 + len;

	/* ID */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add certificate: no 'ID'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (len > sizeof(cinfo.id.value))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Failed to add certificate: invalid 'ID' length");
	memcpy(cinfo.id.value, info_blob + offs + 2, len);
	cinfo.id.len = len;

	/* Ignore subject, issuer and serial */

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PUB, file_id);
	sc_format_path(ch_tmp, &cinfo.path);
	rv = sc_oberthur_read_file(p15card, ch_tmp, &cert_blob, &cert_len, 1);
	LOG_TEST_RET(ctx, rv, "Failed to add certificate: read certificate error");

	cinfo.value.value = cert_blob;
	cinfo.value.len = cert_len;

	rv = sc_oberthur_get_certificate_authority(&cinfo.value, &cinfo.authority);
	LOG_TEST_RET(ctx, rv, "Failed to add certificate: get certificate attributes error");

	if (flags & OBERTHUR_ATTR_MODIFIABLE)
		cobj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;

	rv = sc_pkcs15emu_add_x509_cert(p15card, &cobj, &cinfo);

	LOG_FUNC_RETURN(p15card->card->ctx, rv);
}


/* Private key info:
 * 	flags:2,
 * 	CN(len:2,value:),
 * 	ID(len:2,value:(SHA1 value)),
 * 	StartDate(Ascii:8)
 * 	EndDate(Ascii:8)
 * 	Subject in ASN.1(len:2,value:)
 * 	modulus(value:)
 *	exponent(length:1, value:3)
 */
static int
sc_pkcs15emu_oberthur_add_prvkey(struct sc_pkcs15_card *p15card,
		unsigned int file_id, unsigned int size)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info kinfo;
	struct sc_pkcs15_object kobj;
	struct crypto_container ccont;
	unsigned char *info_blob = NULL;
	size_t info_len = 0;
	unsigned flags;
	size_t offs, len;
	char ch_tmp[0x100];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "add private key(file-id:%04X,size:%04X)", file_id, size);

	memset(&kinfo, 0, sizeof(kinfo));
	memset(&kobj, 0, sizeof(kobj));
	memset(&ccont, 0, sizeof(ccont));

	rv = sc_oberthur_get_friends (file_id, &ccont);
	LOG_TEST_RET(ctx, rv, "Failed to add private key: get friends error");

	if (ccont.id_cert)   {
		struct sc_pkcs15_object *objs[32];
		int ii;

		sc_log(ctx, "friend certificate %04X", ccont.id_cert);
		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
		LOG_TEST_RET(ctx, rv, "Failed to add private key: get certificates error");

		for (ii=0; ii<rv; ii++) {
			struct sc_pkcs15_cert_info *cert = (struct sc_pkcs15_cert_info *)objs[ii]->data;
			struct sc_path path = cert->path;
			unsigned int id = path.value[path.len - 2] * 0x100 + path.value[path.len - 1];

			if (id == ccont.id_cert)   {
				strlcpy(kobj.label, objs[ii]->label, sizeof(kobj.label));
				break;
			}
		}

		if (ii == rv)
			LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_PROFILE, "Failed to add private key: friend not found");
	}

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PRV, file_id | 0x100);
	rv = sc_oberthur_read_file(p15card, ch_tmp, &info_blob, &info_len, 1);
	LOG_TEST_RET(ctx, rv, "Failed to add private key: read oberthur file error");

	if (info_len < 2)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add private key: no 'tag'");
	flags = *(info_blob + 0) * 0x100 + *(info_blob + 1);
	offs = 2;

	/* CN */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add private key: no 'CN'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (len && !strlen(kobj.label))   {
		if (len > sizeof(kobj.label) - 1)
			len = sizeof(kobj.label) - 1;
		strncpy(kobj.label, (char *)(info_blob + offs + 2), len);
	}
	offs += 2 + len;

	/* ID */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add private key: no 'ID'");
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (!len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add private key: zero length ID");
	else if (len > sizeof(kinfo.id.value))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Failed to add private key: invalid ID length");
	memcpy(kinfo.id.value, info_blob + offs + 2, len);
	kinfo.id.len = len;
	offs += 2 + len;

	/* Ignore Start/End dates */
	offs += 16;

	/* Subject encoded in ASN1 */
	if (offs > info_len)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (len)   {
		kinfo.subject.value = malloc(len);
		if (!kinfo.subject.value)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to add private key: memory allocation error");
		kinfo.subject.len = len;
		memcpy(kinfo.subject.value, info_blob + offs + 2, len);
	}

	/* Modulus and exponent are ignored */

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", AWP_OBJECTS_DF_PRV, file_id);
	sc_format_path(ch_tmp, &kinfo.path);
	sc_log(ctx, "Private key info path %s", ch_tmp);

	kinfo.modulus_length	= size;
	kinfo.native		= 1;
	kinfo.key_reference	 = file_id & 0xFF;

	kinfo.usage = sc_oberthur_decode_usage(flags);
	kobj.flags = SC_PKCS15_CO_FLAG_PRIVATE;
	if (flags & OBERTHUR_ATTR_MODIFIABLE)
		kobj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;

	kobj.auth_id.len = sizeof(PinDomainID) > sizeof(kobj.auth_id.value)
			? sizeof(kobj.auth_id.value) : sizeof(PinDomainID);
	memcpy(kobj.auth_id.value, PinDomainID, kobj.auth_id.len);

	sc_log(ctx, "Parsed private key(reference:%i,usage:%X,flags:%X)", kinfo.key_reference, kinfo.usage, kobj.flags);

	rv = sc_pkcs15emu_add_rsa_prkey(p15card, &kobj, &kinfo);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_pkcs15emu_oberthur_add_data(struct sc_pkcs15_card *p15card,
		unsigned int file_id, unsigned int size, int private)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info dinfo;
	struct sc_pkcs15_object dobj;
	unsigned flags;
	unsigned char *info_blob = NULL, *label = NULL, *app = NULL, *oid = NULL;
	size_t info_len, label_len, app_len, oid_len, offs;
	char ch_tmp[0x100];
	int rv;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(ctx, "Add data(file-id:%04X,size:%i,is-private:%i)", file_id, size, private);
	memset(&dinfo, 0, sizeof(dinfo));
	memset(&dobj, 0, sizeof(dobj));

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", private ? AWP_OBJECTS_DF_PRV : AWP_OBJECTS_DF_PUB, file_id | 0x100);

	rv = sc_oberthur_read_file(p15card, ch_tmp, &info_blob, &info_len, 1);
	LOG_TEST_RET(ctx, rv, "Failed to add data: read oberthur file error");

	if (info_len < 2)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add certificate: no 'tag'");
	flags = *(info_blob + 0) * 0x100 + *(info_blob + 1);
	offs = 2;

	/* Label */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add data: no 'label'");
	label = info_blob + offs + 2;
	label_len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (label_len > sizeof(dobj.label) - 1)
		label_len = sizeof(dobj.label) - 1;
	offs += 2 + *(info_blob + offs + 1);

	/* Application */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add data: no 'application'");
	app = info_blob + offs + 2;
	app_len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (app_len > sizeof(dinfo.app_label) - 1)
		app_len = sizeof(dinfo.app_label) - 1;
	offs += 2 + app_len;

	/* OID encode like DER(ASN.1(oid)) */
	if (offs > info_len)
		LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add data: no 'OID'");
	oid_len = *(info_blob + offs + 1) + *(info_blob + offs) * 0x100;
	if (oid_len)   {
		oid = info_blob + offs + 2;
		if (*oid != 0x06 || (*(oid + 1) != oid_len - 2))
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Failed to add data: invalid 'OID' format");
		oid += 2;
		oid_len -= 2;
	}

	snprintf(ch_tmp, sizeof(ch_tmp), "%s%04X", private ? AWP_OBJECTS_DF_PRV : AWP_OBJECTS_DF_PUB, file_id);

	sc_format_path(ch_tmp, &dinfo.path);

	memcpy(dobj.label, label, label_len);
	memcpy(dinfo.app_label, app, app_len);
	if (oid_len)
		sc_asn1_decode_object_id(oid, oid_len, &dinfo.app_oid);

	if (flags & OBERTHUR_ATTR_MODIFIABLE)
		dobj.flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;

	if (private)   {
		dobj.auth_id.len = sizeof(PinDomainID) > sizeof(dobj.auth_id.value)
				? sizeof(dobj.auth_id.value) : sizeof(PinDomainID);
		memcpy(dobj.auth_id.value, PinDomainID, dobj.auth_id.len);

		dobj.flags |= SC_PKCS15_CO_FLAG_PRIVATE;
	}

	rv = sc_pkcs15emu_add_data_object(p15card, &dobj, &dinfo);

	LOG_FUNC_RETURN(p15card->card->ctx, rv);
}


static int
sc_pkcs15emu_oberthur_init(struct sc_pkcs15_card * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info auth_info;
	struct sc_pkcs15_object   obj;
	struct sc_card *card = p15card->card;
	struct sc_path path;
	int rv, ii, tries_left;
	char serial[0x10];
	unsigned char sopin_reference = 0x04;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_bin_to_hex(card->serialnr.value, card->serialnr.len, serial, sizeof(serial), 0);
	p15card->tokeninfo->serial_number = strdup(serial);

	p15card->ops.parse_df = sc_awp_parse_df;
	p15card->ops.clear = sc_awp_clear;

	sc_log(ctx, "Oberthur init: serial %s", p15card->tokeninfo->serial_number);

	sc_format_path(AWP_PIN_DF, &path);
	rv = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(ctx, rv, "Oberthur init failed: cannot select PIN dir");

	tries_left = -1;
	rv = sc_verify(card, SC_AC_CHV, sopin_reference, (unsigned char *)"", 0, &tries_left);
	if (rv && rv != SC_ERROR_PIN_CODE_INCORRECT)   {
		sopin_reference = 0x84;
		rv = sc_verify(card, SC_AC_CHV, sopin_reference, (unsigned char *)"", 0, &tries_left);
	}
	if (rv && rv != SC_ERROR_PIN_CODE_INCORRECT)
		LOG_TEST_RET(ctx, rv, "Invalid state of SO-PIN");

	/* add PIN */
	memset(&auth_info, 0, sizeof(auth_info));
	memset(&obj,  0, sizeof(obj));

	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.auth_method	= SC_AC_CHV;
	auth_info.auth_id.len = 1;
	auth_info.auth_id.value[0] = 0xFF;
	auth_info.attrs.pin.min_length		= 4;
	auth_info.attrs.pin.max_length		= 64;
	auth_info.attrs.pin.stored_length	= 64;
	auth_info.attrs.pin.type		= SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	auth_info.attrs.pin.reference		= sopin_reference;
	auth_info.attrs.pin.pad_char		= 0xFF;
	auth_info.attrs.pin.flags		= SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
				| SC_PKCS15_PIN_FLAG_INITIALIZED
				| SC_PKCS15_PIN_FLAG_NEEDS_PADDING
				| SC_PKCS15_PIN_FLAG_SO_PIN;
	auth_info.tries_left		= tries_left;
	auth_info.logged_in = SC_PIN_STATE_UNKNOWN;

	strncpy(obj.label, "SO PIN", SC_PKCS15_MAX_LABEL_SIZE-1);
	obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;

	sc_log(ctx, "Add PIN(%s,auth_id:%s,reference:%i)", obj.label,
			sc_pkcs15_print_id(&auth_info.auth_id), auth_info.attrs.pin.reference);
	rv = sc_pkcs15emu_add_pin_obj(p15card, &obj, &auth_info);
	LOG_TEST_RET(ctx, rv, "Oberthur init failed: cannot add PIN object");

	tries_left = -1;
	rv = sc_verify(card, SC_AC_CHV, 0x81, (unsigned char *)"", 0, &tries_left);
	if (rv == SC_ERROR_PIN_CODE_INCORRECT)   {
		/* add PIN */
		memset(&auth_info, 0, sizeof(auth_info));
		memset(&obj,  0, sizeof(obj));

		auth_info.auth_id.len = sizeof(PinDomainID) > sizeof(auth_info.auth_id.value)
				? sizeof(auth_info.auth_id.value) : sizeof(PinDomainID);
		memcpy(auth_info.auth_id.value, PinDomainID, auth_info.auth_id.len);
		auth_info.auth_method	= SC_AC_CHV;

		auth_info.attrs.pin.min_length		= 4;
		auth_info.attrs.pin.max_length		= 64;
		auth_info.attrs.pin.stored_length	= 64;
		auth_info.attrs.pin.type		= SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		auth_info.attrs.pin.reference		= 0x81;
		auth_info.attrs.pin.pad_char		= 0xFF;
		auth_info.attrs.pin.flags		= SC_PKCS15_PIN_FLAG_CASE_SENSITIVE
					| SC_PKCS15_PIN_FLAG_INITIALIZED
					| SC_PKCS15_PIN_FLAG_NEEDS_PADDING
					| SC_PKCS15_PIN_FLAG_LOCAL;
		auth_info.tries_left		= tries_left;

		strncpy(obj.label, PIN_DOMAIN_LABEL, SC_PKCS15_MAX_LABEL_SIZE-1);
		obj.flags = SC_PKCS15_CO_FLAG_MODIFIABLE | SC_PKCS15_CO_FLAG_PRIVATE;
		if (sopin_reference == 0x84) {
			/*
			 * auth_pin_reset_oberthur_style() in card-oberthur.c
			 * always uses PUK with reference 0x84 for
			 * unblocking of User PIN
			 */
			obj.auth_id.len = 1;
			obj.auth_id.value[0] = 0xFF;
		}

		sc_format_path(AWP_PIN_DF, &auth_info.path);
		auth_info.path.type = SC_PATH_TYPE_PATH;

		sc_log(ctx, "Add PIN(%s,auth_id:%s,reference:%i)", obj.label,
				sc_pkcs15_print_id(&auth_info.auth_id), auth_info.attrs.pin.reference);
		rv = sc_pkcs15emu_add_pin_obj(p15card, &obj, &auth_info);
		LOG_TEST_RET(ctx, rv, "Oberthur init failed: cannot add PIN object");
	}
	else if (rv != SC_ERROR_DATA_OBJECT_NOT_FOUND)    {
		LOG_TEST_RET(ctx, rv, "Oberthur init failed: cannot verify PIN");
	}

	for (ii=0; oberthur_infos[ii].name; ii++)   {
		sc_log(ctx, "Oberthur init: read %s file", oberthur_infos[ii].name);
		rv = sc_oberthur_read_file(p15card, oberthur_infos[ii].path,
				&oberthur_infos[ii].content, &oberthur_infos[ii].len, 1);
		LOG_TEST_RET(ctx, rv, "Oberthur init failed: read oberthur file error");

		sc_log(ctx,
		       "Oberthur init: parse %s file, content length %"SC_FORMAT_LEN_SIZE_T"u",
		       oberthur_infos[ii].name, oberthur_infos[ii].len);
		rv = oberthur_infos[ii].parser(p15card, oberthur_infos[ii].content, oberthur_infos[ii].len,
				oberthur_infos[ii].postpone_allowed);
		LOG_TEST_RET(ctx, rv, "Oberthur init failed: parse error");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
oberthur_detect_card(struct sc_pkcs15_card * p15card)
{
	struct sc_card *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (p15card->card->type != SC_CARD_TYPE_OBERTHUR_64K)
		LOG_FUNC_RETURN(p15card->card->ctx, SC_ERROR_WRONG_CARD);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}


int
sc_pkcs15emu_oberthur_init_ex(struct sc_pkcs15_card * p15card, struct sc_aid *aid,
				   struct sc_pkcs15emu_opt * opts)
{
	int rv;

	LOG_FUNC_CALLED(p15card->card->ctx);
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)   {
		rv = sc_pkcs15emu_oberthur_init(p15card);
	}
	else {
		rv = oberthur_detect_card(p15card);
		if (!rv)
			rv = sc_pkcs15emu_oberthur_init(p15card);
	}

	LOG_FUNC_RETURN(p15card->card->ctx, rv);
}


static int
sc_awp_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char *buf = NULL;
	size_t buf_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (df->type != SC_PKCS15_PRKDF && df->type != SC_PKCS15_DODF)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_oberthur_read_file(p15card, AWP_OBJECTS_LIST_PRV, &buf, &buf_len, 1);
	LOG_TEST_RET(ctx, rv, "Parse DF: read private objects info failed");

	rv = sc_oberthur_parse_privateinfo(p15card, buf, buf_len, 0);

	if (buf)
		free(buf);

	if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	LOG_TEST_RET(ctx, rv, "Parse DF: private info parse error");
	df->enumerated = 1;

	LOG_FUNC_RETURN(ctx, rv);
}


static void
sc_awp_clear(struct sc_pkcs15_card *p15card)
{
	LOG_FUNC_CALLED(p15card->card->ctx);
}
