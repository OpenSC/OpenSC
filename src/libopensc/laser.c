/*
 * pkcs15-laser.c: Support for JaCarta PKI applet
 *
 * Copyright (C) 2025  Andrey Khodunov <a.khodunov@aladdin.ru>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

#include "asn1.h"
#include "cardctl.h"
#include "common/compat_strlcpy.h"
#include "internal.h"
#include "pkcs11/pkcs11.h"
#include "pkcs15.h"
#include "laser.h"

#define LOG_ERROR_RET(ctx, r, text) \
	do { \
		int _ret = (r); \
		sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, FILENAME, __LINE__, __FUNCTION__, SC_COLOR_FG_RED, \
				"%s: %d (%s)\n", (text), (_ret), sc_strerror(_ret)); \
		return (r); \
	} while (0)
#define LOG_ERROR_GOTO(ctx, r, text) \
	do { \
		int _ret = (r); \
		sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, FILENAME, __LINE__, __FUNCTION__, SC_COLOR_FG_RED, \
				"%s: %d (%s)\n", (text), (_ret), sc_strerror(_ret)); \
		goto err; \
	} while (0)

#define C_ASN1_CREATE_RSA_KEY_SIZE 2
static struct sc_asn1_entry c_asn1_create_rsa_key[C_ASN1_CREATE_RSA_KEY_SIZE] = {
		/* tag 0x71 */
		{"createRsaKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x11, 0, NULL, NULL},
		{NULL,		       0,		  0,				 0, NULL, NULL}
};

#define C_ASN1_RSA_PUB_COEFFICIENTS_SIZE 3
static struct sc_asn1_entry c_asn1_create_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE] = {
		/* tag 0x90 */
		{"exponent", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x10, SC_ASN1_ALLOC, NULL, NULL},
		/* tag 0x91 */
		{"modulus",  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x11, SC_ASN1_ALLOC, NULL, NULL},
		{NULL,       0,			  0,		     0,		NULL, NULL}
};

#define C_ASN1_UPDATE_RSA_KEY_SIZE 2
static struct sc_asn1_entry c_asn1_update_rsa_key[C_ASN1_UPDATE_RSA_KEY_SIZE] = {
		/* tag 0x62 */
		{"updateRsaKeyCoefficients", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x02, 0, NULL, NULL},
		{NULL,		       0,		  0,				 0, NULL, NULL}
};

#define C_ASN1_RSA_PRV_COEFFICIENTS_SIZE 6
static struct sc_asn1_entry c_asn1_create_rsa_prv_coefficients[C_ASN1_RSA_PRV_COEFFICIENTS_SIZE] = {
		/* tag 0x90 */
		{"exponent",	     SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x10, SC_ASN1_ALLOC, NULL, NULL},
		/* tag 0x91 */
		{"modulus",		    SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x11, SC_ASN1_ALLOC, NULL, NULL},
		/* tag 0x92 */
		{"privateExponent",	    SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x12, SC_ASN1_ALLOC, NULL, NULL},
		/* tag 0x93 */
		{"privatePrimes",	  SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x13, SC_ASN1_ALLOC, NULL, NULL},
		/* tag 0x94 */
		{"privatePartialPrimes", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 0x14, SC_ASN1_ALLOC, NULL, NULL},
		{NULL,		       0,			  0,		     0,		NULL, NULL}
};

static int
laser_encode_pubkey_rsa(struct sc_context *ctx, struct sc_pkcs15_pubkey_rsa *key,
		unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_rsa_key[C_ASN1_CREATE_RSA_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_pub_coefficients[C_ASN1_RSA_PUB_COEFFICIENTS_SIZE];
	int r;

	sc_copy_asn1_entry(c_asn1_create_rsa_key, asn1_rsa_key);
	sc_format_asn1_entry(asn1_rsa_key + 0, asn1_rsa_pub_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_create_rsa_pub_coefficients, asn1_rsa_pub_coefficients);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 0, key->exponent.data, &key->exponent.len, 1);
	sc_format_asn1_entry(asn1_rsa_pub_coefficients + 1, key->modulus.data, &key->modulus.len, 1);

	r = sc_asn1_encode(ctx, asn1_rsa_key, buf, buflen);
	LOG_TEST_RET(ctx, r, "ASN.1 encoding of RSA public key failed");

	return 0;
}

int
laser_encode_pubkey(struct sc_context *ctx, struct sc_pkcs15_pubkey *key,
		unsigned char **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return laser_encode_pubkey_rsa(ctx, &key->u.rsa, buf, len);
	return SC_ERROR_NOT_SUPPORTED;
}

static int
laser_encode_prvkey_rsa(struct sc_context *ctx, struct sc_pkcs15_prkey_rsa *key,
		unsigned char **buf, size_t *buflen)
{
	struct sc_asn1_entry asn1_rsa_key[C_ASN1_UPDATE_RSA_KEY_SIZE];
	struct sc_asn1_entry asn1_rsa_coefficients[C_ASN1_RSA_PRV_COEFFICIENTS_SIZE];
	unsigned char *primes = NULL, *partial_primes = NULL;
	size_t primes_len = 0, partial_primes_len = 0;
	int rv;

	primes = malloc(key->p.len + key->q.len);
	if (!primes)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate primes");
	memcpy(primes, key->p.data, key->p.len);
	memcpy(primes + key->p.len, key->q.data, key->q.len);
	primes_len = key->p.len + key->q.len;

	partial_primes = malloc(key->dmp1.len + key->dmq1.len + key->iqmp.len);
	if (!partial_primes)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate partial primes");
	memcpy(partial_primes, key->dmp1.data, key->dmp1.len);
	memcpy(partial_primes + key->dmp1.len, key->dmq1.data, key->dmq1.len);
	memcpy(partial_primes + key->dmp1.len + key->dmq1.len, key->iqmp.data, key->iqmp.len);
	partial_primes_len = key->dmp1.len + key->dmq1.len + key->iqmp.len;

	sc_copy_asn1_entry(c_asn1_update_rsa_key, asn1_rsa_key);
	sc_format_asn1_entry(asn1_rsa_key + 0, asn1_rsa_coefficients, NULL, 1);

	sc_copy_asn1_entry(c_asn1_create_rsa_prv_coefficients, asn1_rsa_coefficients);
	sc_format_asn1_entry(asn1_rsa_coefficients + 0, key->exponent.data, &key->exponent.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 1, key->modulus.data, &key->modulus.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 2, key->d.data, &key->d.len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 3, primes, &primes_len, 1);
	sc_format_asn1_entry(asn1_rsa_coefficients + 4, partial_primes, &partial_primes_len, 1);

	rv = sc_asn1_encode(ctx, asn1_rsa_key, buf, buflen);
	LOG_TEST_GOTO_ERR(ctx, rv, "ASN.1 encoding of RSA private key failed");
err:
	free(primes);
	free(partial_primes);
	return rv;
}

int
laser_encode_prvkey(struct sc_context *ctx, struct sc_pkcs15_prkey *key,
		unsigned char **buf, size_t *len)
{
	if (key->algorithm == SC_ALGORITHM_RSA)
		return laser_encode_prvkey_rsa(ctx, &key->u.rsa, buf, len);
	return SC_ERROR_NOT_SUPPORTED;
}

static size_t
_get_attr(unsigned char *data, size_t length, size_t *in_offs, struct laser_cka *attr)
{
	size_t offs;

	if (!attr || !data || !in_offs)
		return 0;

	/*
	 * At the end of kxc/s files there are mysterious 4 bytes (like 'OD OO OD OO').
	 */
	for (offs = *in_offs; (offs < length - 4) && (*(data + offs) == 0xFF); offs++)
		;
	if (offs >= length - 4)
		return 0;

	if (*(data + offs + 0) == 0x80)
		attr->cka = CKA_VENDOR_DEFINED + *(data + offs + 1);
	else
		attr->cka = *(data + offs + 0) * 0x100 + *(data + offs + 1);
	attr->internal_cka = *(data + offs + 2);
	attr->len = *(data + offs + 3) * 0x100 + *(data + offs + 4);
	attr->val = data + offs + 5;

	*in_offs = offs + 5 + attr->len;
	return 0;
}

static int
_cka_get_unsigned(const struct laser_cka *attr, unsigned *out)
{
	int ii;

	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (attr->len != 4)
		return SC_ERROR_INVALID_DATA;

	for (ii = 0, *out = 0; ii < 4; ii++)
		*out = *out * 0x100 + *(attr->val + 3 - ii);

	return SC_SUCCESS;
}

static int
_cka_set_label(const struct laser_cka *attr, struct sc_pkcs15_object *obj)
{
	size_t len;

	if (!attr || !obj)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(obj->label, 0, sizeof(obj->label));
	len = MIN(attr->len, sizeof(obj->label) - 1);
	if (len)
		memcpy(obj->label, attr->val, len);

	return SC_SUCCESS;
}

static int
_cka_set_application(const struct laser_cka *attr, struct sc_pkcs15_data_info *info)
{
	size_t len;

	if (!attr || !info)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(info->app_label, 0, sizeof(info->app_label));
	len = MIN(attr->len, sizeof(info->app_label) - 1);
	if (len)
		memcpy(info->app_label, attr->val, len);

	return SC_SUCCESS;
}

static int
_cka_get_object_id(const struct laser_cka *attr, struct sc_pkcs15_data_info *info)
{
	int ii;

	for (ii = 0; ii < SC_MAX_OBJECT_ID_OCTETS; ii++) {
		if (ii * sizeof(int) < attr->len)
			info->app_oid.value[ii] = *((int *)(attr->val + ii * sizeof(int)));
		else
			info->app_oid.value[ii] = -1;
	}

	return SC_SUCCESS;
}

static int
_cka_get_blob(const struct laser_cka *attr, struct sc_pkcs15_der *out)
{
	struct sc_pkcs15_der der;

	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	der.value = malloc(attr->len);
	if (!der.value)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(der.value, attr->val, attr->len);
	der.len = attr->len;

	*out = der;
	return SC_SUCCESS;
}

static int
_cka_set_id(const struct laser_cka *attr, struct sc_pkcs15_id *out)
{
	if (!attr || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (attr->len > SC_PKCS15_MAX_ID_SIZE)
		return SC_ERROR_INVALID_DATA;

	memcpy(out->value, attr->val, attr->len);
	out->len = attr->len;

	return SC_SUCCESS;
}

static int
laser_add_attribute(unsigned char **buf, size_t *buf_sz, unsigned char flags,
		CK_ULONG cka, size_t cka_len, const void *data)
{
	unsigned char *ptr = NULL;
	size_t offs = 0;

	if (!buf || !buf_sz)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = realloc(*buf, *buf_sz + cka_len + 5);
	if (!ptr)
		return SC_ERROR_OUT_OF_MEMORY;

	offs = *buf_sz;
	if (cka & CKA_VENDOR_DEFINED)
		*(ptr + offs++) = (cka >> 24) & 0xFF; /* cka type: MSB | LSB */
	else
		*(ptr + offs++) = (cka >> 8) & 0xFF; /* cka type: 2 LSBs */
	*(ptr + offs++) = cka & 0xFF;
	*(ptr + offs++) = flags;
	*(ptr + offs++) = (cka_len >> 8) & 0xFF; /* cka length: 2 bytes*/
	*(ptr + offs++) = cka_len & 0xFF;

	memset(ptr + offs, 0, cka_len);
	if (data)
		memcpy(ptr + offs, (const unsigned char *)data, cka_len);
	offs += cka_len;

	*buf = ptr;
	*buf_sz = offs;

	return SC_SUCCESS;
}

int
laser_attrs_cert_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_cert_info *info,
		unsigned char *data, size_t data_len)
{
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA;

	LOG_FUNC_CALLED(ctx);

	for (next = offs = 0; offs < data_len; offs = next) {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%lX) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka) {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");
			if (uval != CKO_CERTIFICATE)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_VALUE:
			rv = _cka_get_blob(&attr, &info->value);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object value");
			break;
		case CKA_CERTIFICATE_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");
			if (uval != CKC_X_509)
				LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Other then CKC_X_509 cert type is not supported");
			break;
		case CKA_ISSUER:
			break;
		case CKA_SUBJECT:
			break;
		case CKA_SERIAL_NUMBER:
			break;
		case CKA_TRUSTED:
			info->authority = (*attr.val != 0);
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		}
	}

	if (info->value.len) {
		/* TODO: get certificate authority:
		 * see 'sc_oberthur_get_certificate_authority' and do likewise.
		 */
		if (!info->id.len) {
			struct sc_pkcs15_pubkey *pubkey = NULL;

			rv = sc_pkcs15_pubkey_from_cert(ctx, &info->value, &pubkey);
			LOG_TEST_RET(ctx, rv, "Cannot get public key from certificate data");

			SHA1(pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len, info->id.value);
			info->id.len = SHA_DIGEST_LENGTH;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_pubkey_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey_info *info,
		unsigned char *data, size_t data_len)
{
	struct sc_pkcs15_pubkey pub_key;
	struct sc_pkcs15_der der;
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA, have_public_key = 0;

	LOG_FUNC_CALLED(ctx);

	memset(&pub_key, 0, sizeof(pub_key));

	for (next = offs = 0; offs < data_len; offs = next) {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%lX) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka) {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");

			if (uval != CKO_PUBLIC_KEY)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Need to be CKO_PUBLIC_KEY CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				object->type = SC_PKCS15_TYPE_PUBKEY_RSA;
			else if (uval == CKK_EC)
				object->type = SC_PKCS15_TYPE_PUBKEY_EC;
			else if (uval == CKK_GOSTR3410)
				object->type = SC_PKCS15_TYPE_PUBKEY_GOSTR3410;
			else
				LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported public key type");
			break;
		case CKA_SUBJECT:
			break;
		case CKA_TRUSTED:
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		case CKA_ENCRYPT:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
			break;
		case CKA_WRAP:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
			break;
		case CKA_VERIFY:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
			break;
		case CKA_VERIFY_RECOVER:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER;
			break;
		case CKA_DERIVE:
			if (*attr.val)
				info->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			break;
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public key modulus");

			pub_key.algorithm = SC_ALGORITHM_RSA;
			if (attr.cka == CKA_MODULUS) {
				pub_key.u.rsa.modulus.data = der.value;
				pub_key.u.rsa.modulus.len = der.len;
			} else {
				pub_key.u.rsa.exponent.data = der.value;
				pub_key.u.rsa.exponent.len = der.len;
			}
			have_public_key = 1;
			break;
		case CKA_MODULUS_BITS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_MODULUS_BITS");
			info->modulus_length = uval;
			break;
		case CKA_LOCAL:
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		default:
			sc_log(ctx, "Unknown CKA attribute: %lX", attr.cka);
			break;
		}
	}

	if (have_public_key) {
		rv = sc_pkcs15_encode_pubkey(ctx, &pub_key, &object->content.value, &object->content.len);
		LOG_TEST_RET(ctx, rv, "Cannot encode public key");
		sc_pkcs15_erase_pubkey(&pub_key);
	}

	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_prvkey_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey_info *info,
		unsigned char *data, size_t data_len)
{
	struct sc_pkcs15_prkey_rsa key_rsa;
	struct sc_pkcs15_der der;
	size_t offs, next;
	int rv = SC_ERROR_INVALID_DATA;

	LOG_FUNC_CALLED(ctx);

	memset(&key_rsa, 0, sizeof(key_rsa));

	for (next = offs = 0; offs < data_len; offs = next) {
		struct laser_cka attr;
		unsigned uval;

		rv = _get_attr(data, data_len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%lX) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka) {
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");

			if (uval != CKO_PRIVATE_KEY)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Need to be CKO_PRIVATE_KEY CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set certificate object label");
			break;
		case CKA_TRUSTED:
			break;
		case CKA_KEY_TYPE:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CERTIFICATE_TYPE");

			if (uval == CKK_RSA)
				object->type = SC_PKCS15_TYPE_PRKEY_RSA;
			else if (uval == CKK_EC)
				object->type = SC_PKCS15_TYPE_PRKEY_EC;
			else if (uval == CKK_GOSTR3410)
				object->type = SC_PKCS15_TYPE_PRKEY_GOSTR3410;
			else
				LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported private key type");
			break;
		case CKA_SUBJECT:
			rv = _cka_get_blob(&attr, &info->subject);
			LOG_TEST_RET(ctx, rv, "Cannot set private key subject");
			break;
		case CKA_ID:
			rv = _cka_set_id(&attr, &info->id);
			LOG_TEST_RET(ctx, rv, "Cannot get CKA_ID");
			break;
		case CKA_SENSITIVE:
			sc_log(ctx, "CKA_SENSITIVE: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_SENSITIVE : 0;
			break;
		case CKA_DECRYPT:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DECRYPT : 0;
			break;
		case CKA_UNWRAP:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_UNWRAP : 0;
			break;
		case CKA_SIGN:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGN : 0;
			break;
		case CKA_SIGN_RECOVER:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_SIGNRECOVER : 0;
			break;
		case CKA_DERIVE:
			info->usage |= (*attr.val) ? SC_PKCS15_PRKEY_USAGE_DERIVE : 0;
			break;
		case CKA_START_DATE:
		case CKA_END_DATE:
			break;
		case CKA_PUBLIC_EXPONENT:
			rv = _cka_get_blob(&attr, &der);
			LOG_TEST_RET(ctx, rv, "Cannot get public exponent");
			/*
			key_rsa.exponent.data = der.value;
			key_rsa.exponent.len = der.len;
			*/
			break;
		case CKA_EXTRACTABLE:
			sc_log(ctx, "CKA_EXTRACTABLE: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE : 0;
			break;
		case CKA_LOCAL:
			sc_log(ctx, "CKA_LOCAL: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_LOCAL : 0;
			break;
		case CKA_NEVER_EXTRACTABLE:
			sc_log(ctx, "CKA_NEVER_EXTRACTABLE: %s", (*attr.val) ? "yes" : "no");
			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE : 0;
			break;
		case CKA_ALWAYS_SENSITIVE:
			sc_log(ctx, "CKA_ALWAYS_SENSITIVE: %s", (*attr.val) ? "yes" : "no");

			info->access_flags |= (*attr.val) ? SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE : 0;
			break;
		case CKA_KEY_GEN_MECHANISM:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_KEY_GEN_MECHANISM");
			sc_log(ctx, "CKA_KEY_GEN_MECHANISM: %X", uval);
			break;
		case CKA_MODIFIABLE:
			object->flags |= (*attr.val) ? SC_PKCS15_CO_FLAG_MODIFIABLE : 0;
			sc_log(ctx, "CKA_MODIFIABLE: %X", *attr.val);
			break;
		default:
			sc_log(ctx, "Unknown CKA attribute: %lX", attr.cka);
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_data_object_decode(struct sc_context *ctx,
		struct sc_pkcs15_object *object, struct sc_pkcs15_data_info *info,
		unsigned char *data, size_t data_len, unsigned char *hash_exists)
{
	size_t offs, next;

	LOG_FUNC_CALLED(ctx);

	if (hash_exists)
		*hash_exists = 0;

	sc_log(ctx, "DATA object path %s", sc_print_path(&info->path));
	for (next = offs = 0; offs < data_len; offs = next) {
		struct laser_cka attr;
		unsigned uval;
		int rv;

		rv = _get_attr(data, data_len, &next, &attr);
		LOG_TEST_RET(ctx, rv, "parsing error of laser object's attribute");
		if (next == offs)
			break;
		sc_log(ctx, "Attribute(%lX) to parse '%s'", attr.cka, sc_dump_hex(attr.val, attr.len));

		switch (attr.cka) {
		case CKA_CERT_HASH:
			if (hash_exists)
				*hash_exists = 1;
			break;
		case CKA_CLASS:
			rv = _cka_get_unsigned(&attr, &uval);
			LOG_TEST_RET(ctx, rv, "Invalid encoding of CKA_CLASS");
			if (uval != CKO_DATA)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid CKA_CLASS");
			break;
		case CKA_TOKEN:
			if (*attr.val == 0)
				LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Has to be token object");
			break;
		case CKA_PRIVATE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_PRIVATE;
			break;
		case CKA_LABEL:
			rv = _cka_set_label(&attr, object);
			LOG_TEST_RET(ctx, rv, "Cannot set data object label");
			break;
		case CKA_APPLICATION:
			rv = _cka_set_application(&attr, info);
			LOG_TEST_RET(ctx, rv, "Cannot set data object application label");
			break;
		case CKA_VALUE:
			rv = _cka_get_blob(&attr, &info->data);
			LOG_TEST_RET(ctx, rv, "Cannot set data object object value");
			break;
		case CKA_OBJECT_ID:
			rv = _cka_get_object_id(&attr, info);
			LOG_TEST_RET(ctx, rv, "Cannot set data object ID");
			break;
		case CKA_MODIFIABLE:
			if (*attr.val)
				object->flags |= SC_PKCS15_CO_FLAG_MODIFIABLE;
			break;
		}
	}

	sc_log(ctx, "DATA object path %s", sc_print_path(&info->path));
	if (info->path.len > 1) {
		unsigned file_id = info->path.value[info->path.len - 2] * 0x100 + info->path.value[info->path.len - 1];

		if (file_id == CMAP_FID) {
			if (!strlen(info->app_label))
				strncpy(info->app_label, CMAP_DO_APPLICATION_NAME, sizeof(info->app_label) - 1);
			if (!strlen(object->label))
				strncpy(object->label, "cmapfile", sizeof(object->label) - 1);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
laser_md_cmap_record_decode(struct sc_context *ctx, const struct sc_pkcs15_data *data, size_t *offs,
		struct laser_cmap_record **out)
{
	LOG_FUNC_CALLED(ctx);

	if (!data || !offs || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	*out = NULL;
	if (data->data_len - *offs < sizeof(struct laser_cmap_record))
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	*out = calloc(1, sizeof(struct laser_cmap_record));
	if (*out == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(*out, data->data + *offs, sizeof(struct laser_cmap_record));

	*offs += sizeof(struct laser_cmap_record);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
laser_md_cmap_record_guid(struct sc_context *ctx, struct laser_cmap_record *rec,
		unsigned char **out, size_t *out_len)
{
	int ii;

	LOG_FUNC_CALLED(ctx);

	if (!rec || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "cmap.record.guid(%i) 0x'%s'", rec->guid_len, sc_dump_hex(rec->guid, rec->guid_len * 2));

	if (rec->guid_len * 2 > sizeof(rec->guid))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	*out = calloc(1, rec->guid_len + 1);
	if (*out == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	for (ii = 0; ii < rec->guid_len; ii++)
		*(*out + ii) = rec->guid[2 * ii];
	*out_len = rec->guid_len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
laser_attach_cache_stamp(struct sc_pkcs15_card *p15card, int zero_stamp,
		unsigned char **buf, size_t *buf_sz)
{
	unsigned char *ptr = NULL;

	if (!buf || !buf_sz)
		return SC_ERROR_INVALID_ARGUMENTS;

	ptr = realloc(*buf, *buf_sz + 4);
	if (!ptr)
		return SC_ERROR_OUT_OF_MEMORY;

	if (zero_stamp) {
		memset(ptr + *buf_sz, 0, 4);
	} else if (p15card->md_data) {
		const struct laser_cardcf *cardcf = &p15card->md_data->cardcf;

		*(ptr + *buf_sz + 0) = cardcf->cont_freshness & 0xFF;
		*(ptr + *buf_sz + 1) = (cardcf->cont_freshness >> 8) & 0xFF;
		*(ptr + *buf_sz + 2) = cardcf->files_freshness & 0xFF;
		*(ptr + *buf_sz + 3) = (cardcf->files_freshness >> 8) & 0xFF;
	} else {
		unsigned rand_val;
		srand((unsigned)time(NULL));
		RAND_bytes((unsigned char *)&rand_val, sizeof(rand_val));
		*(ptr + *buf_sz + 0) = *(ptr + *buf_sz + 2) = rand_val & 0xFF;
		*(ptr + *buf_sz + 1) = *(ptr + *buf_sz + 3) = (rand_val >> 8) & 0xFF;
	}

	*buf = ptr;
	*buf_sz += 4;

	return SC_SUCCESS;
}

int
laser_attrs_prvkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)object->data;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_PRIVATE_KEY;
	CK_BBOOL _true = TRUE, _false = FALSE;
	const CK_BBOOL *flag;
	CK_KEY_TYPE type_rsa = CKK_RSA;
	CK_ULONG ffff = 0xFFFFFFFFl;
	int rv;

	LOG_FUNC_CALLED(ctx);

	data = malloc(7);
	if (!data)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate prv.key repr.");

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(uint32_t), &clazz);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_CLASS private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TOKEN private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_PRIVATE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LABEL private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_TYPE, sizeof(uint32_t), &type_rsa);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_KEY_TYPE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_SUBJECT, info->subject.len, info->subject.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SUBJECT private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ID private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_SENSITIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE_TO_TRUE, CKA_SENSITIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SENSITIVE private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_DECRYPT, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_DECRYPT private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_UNWRAP, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_UNWRAP private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_SIGN ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SIGN, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SIGN private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_SIGNRECOVER ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SIGN_RECOVER, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SIGN_RECOVER private key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DERIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_DERIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_DERIVE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_START_DATE, 0, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_START_DATE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_END_DATE, 0, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_START_END private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE_TO_FALSE, CKA_EXTRACTABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_EXTRACTABLE private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LOCAL, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LOCAL private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_NEVER_EXTRACTABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_NEVER_EXTRACTABLE private key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALWAYS_SENSITIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALWAYS_SENSITIVE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_GEN_MECHANISM, sizeof(uint32_t), &ffff);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_KEY_GEN_MECHANISM private key attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODIFIABLE private key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALADDIN, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN private key attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_stamp(p15card, 0, &data, &data_len);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to attach cache stamp");
	attrs_num++;

	sc_log(ctx, "Attributes(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len) {
		*out = data;
		*out_len = data_len;
		data = NULL;
	}
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_pubkey_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_pubkey pubkey;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_PUBLIC_KEY;
	CK_BBOOL _true = TRUE, _false = FALSE;
	const CK_BBOOL *flag;
	CK_KEY_TYPE type_rsa = CKK_RSA;
	int rv;

	LOG_FUNC_CALLED(ctx);

	pubkey.algorithm = SC_ALGORITHM_RSA;
	rv = sc_pkcs15_decode_pubkey(ctx, &pubkey, object->content.value, object->content.len);
	LOG_TEST_GOTO_ERR(ctx, rv, "Invalid public key data (object's content)");

	data = malloc(7);
	if (!data)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate pub.key repr.");

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(uint32_t), &clazz);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_CLASS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TOKEN public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_PRIVATE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LABEL public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_ONLY_SO_CAN_SET | CKFP_MODIFIABLE_TO_TRUE, CKA_TRUSTED, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TRUSTED public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_KEY_TYPE, sizeof(uint32_t), &type_rsa);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_KEY_TYPE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_SUBJECT, info->subject.len, info->subject.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SUBJECT public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ID public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_ENCRYPT ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ENCRYPT, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ENCRYPT public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_WRAP ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_WRAP, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_WRAP public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_VERIFY ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VERIFY, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_VERIFY public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VERIFY_RECOVER, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_VERIFY_RECOVER public key attribute");
	attrs_num++;

	flag = info->usage & SC_PKCS15_PRKEY_USAGE_DERIVE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_DERIVE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_DERIVE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_START_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_START_DATE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_END_DATE, sizeof(CK_DATE), NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_START_END public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODULUS, pubkey.u.rsa.modulus.len, pubkey.u.rsa.modulus.data);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODULUS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODULUS_BITS, sizeof(uint32_t), &info->modulus_length);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODULUS_BITS public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PUBLIC_EXPONENT, pubkey.u.rsa.exponent.len, pubkey.u.rsa.exponent.data);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_PUBLIC_EXPONENT public key attribute");
	attrs_num++;

	flag = info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_LOCAL, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LOCAL public key attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODIFIABLE public key attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALADDIN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN public key attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_stamp(p15card, 0, &data, &data_len);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to attach cache stamp");
	attrs_num++;

	sc_log(ctx, "Attributes(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len) {
		*out = data;
		*out_len = data_len;
		data = NULL;
	}
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_encode_update_key(struct sc_context *ctx, struct sc_pkcs15_prkey *prkey,
		struct sc_cardctl_laser_updatekey *update)
{
	int rv;

	if (!ctx || !prkey || !update)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(ctx);

	rv = laser_encode_prvkey(ctx, prkey, &update->data, &update->len);

	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_cert_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_cert_info *info = (struct sc_pkcs15_cert_info *)object->data;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
	CK_BBOOL _true = TRUE, _false = FALSE;
	const CK_BBOOL *flag;
	struct sc_pkcs15_cert *cert = NULL;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	size_t sha1_offs;
	int rv;

	LOG_FUNC_CALLED(ctx);

	cert = malloc(sizeof(struct sc_pkcs15_cert));
	if (!cert)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate cert.encode repr.");

	memset(cert, 0, sizeof(struct sc_pkcs15_cert));

	rv = sc_pkcs15_read_certificate(p15card, info, 0, &cert);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot read/parse X509 certificate");

	data = malloc(7);
	if (!data)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Failed to allocate a small piece");

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	memset(sha1, 0, sizeof(sha1));
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_CERT_HASH, SHA_DIGEST_LENGTH, sha1);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN certificate attribute");
	attrs_num++;
	sha1_offs = data_len - SHA_DIGEST_LENGTH;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(uint32_t), &clazz);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_CLASS certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TOKEN certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_PRIVATE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LABEL certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_VALUE, object->content.len, object->content.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_VALUE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CERTIFICATE_TYPE, sizeof(uint32_t), &cert_type);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_CERTIFICATE_TYPE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_ISSUER, cert->issuer_len, cert->issuer);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ISSUER certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_SERIAL_NUMBER, cert->serial_len, cert->serial);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SERIAL_NUMBER certificate attribute");
	attrs_num++;

	flag = info->authority ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE_TO_FALSE, CKA_TRUSTED, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TRUSTED certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_SUBJECT, cert->subject_len, cert->subject);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_SUBJECT certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_ID, info->id.len, info->id.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ID certificate attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODIFIABLE certificate attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALADDIN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN certificate attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_stamp(p15card, 0, &data, &data_len);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to attach cache stamp");
	attrs_num++;

	SHA1(data, data_len, sha1);
	memcpy(data + sha1_offs, sha1, SHA_DIGEST_LENGTH);

	sc_log(ctx, "Attributes(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len) {
		*out = data;
		*out_len = data_len;
		data = NULL;
	}
err:
	free(data);
	sc_pkcs15_free_certificate(cert);
	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_attrs_data_object_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		unsigned file_id, unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *)object->data;
	unsigned char *data = NULL;
	size_t data_len = 0, attrs_num = 0;
	CK_OBJECT_CLASS clazz = CKO_DATA;
	CK_BBOOL _true = TRUE, _false = FALSE;
	const CK_BBOOL *flag;
	unsigned char sha1[SHA_DIGEST_LENGTH];
	size_t sha1_offs;
	int rv;

	LOG_FUNC_CALLED(ctx);

	data = malloc(7);
	if (!data)
		LOG_ERROR_GOTO(ctx, rv = SC_ERROR_OUT_OF_MEMORY, "Cannot allocate obj.encode repr.");

	data_len = 0;
	*(data + data_len++) = LASER_ATTRIBUTE_VALID;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = (file_id >> 8) & 0xFF;
	*(data + data_len++) = file_id & 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;
	*(data + data_len++) = 0xFF;

	memset(sha1, 0, sizeof(sha1));
	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_CERT_HASH, SHA_DIGEST_LENGTH, sha1);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN DATA object attribute");
	attrs_num++;
	sha1_offs = data_len - SHA_DIGEST_LENGTH;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_CLASS, sizeof(uint32_t), &clazz);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_CLASS DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_TOKEN, sizeof(CK_BBOOL), &_true);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_TOKEN DATA object attribute");
	attrs_num++;

	// TEMP data object private attribute
	if ((object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0)
		rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_true);
	else
		rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_false);
	// rv = laser_add_attribute(&data, &data_len, 0x00, CKA_PRIVATE, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_PRIVATE DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_LABEL, strlen(object->label), object->label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LABEL DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_APPLICATION, strlen(info->app_label), info->app_label);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_LABEL DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_VALUE, info->data.len, info->data.value);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_VALUE DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, CKFP_MODIFIABLE, CKA_OBJECT_ID,
			sizeof(info->app_oid), (unsigned char *)(&info->app_oid.value[0]));
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_OBJECT_ID DATA object attribute");
	attrs_num++;

	flag = object->flags & SC_PKCS15_CO_FLAG_MODIFIABLE ? &_true : &_false;
	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_MODIFIABLE, sizeof(CK_BBOOL), flag);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_MODIFIABLE DATA object attribute");
	attrs_num++;

	rv = laser_add_attribute(&data, &data_len, 0x00, CKA_ALADDIN, sizeof(CK_BBOOL), &_false);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to add CKA_ALADDIN DATA object attribute");
	attrs_num++;

	*(data + 4) = (data_len >> 8) & 0xFF;
	*(data + 5) = data_len & 0xFF;
	*(data + 6) = attrs_num;

	rv = laser_attach_cache_stamp(p15card, (file_id == CMAP_FID), &data, &data_len);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to attach cache stamp");
	attrs_num++;

	SHA1(data, data_len, sha1);
	memcpy(data + sha1_offs, sha1, SHA_DIGEST_LENGTH);

	sc_log(ctx, "Attributes(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", attrs_num, sc_dump_hex(data, data_len));
	if (out && out_len) {
		*out = data;
		*out_len = data_len;
		data = NULL;
	}
err:
	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

int
laser_cmap_set_key_guid(struct sc_context *ctx, struct sc_pkcs15_prkey_info *info, int *is_converted)
{
	unsigned char guid[CMAP_GUID_INFO_SIZE / 2];
	unsigned char bits[5];
	unsigned offs;
	int MSBset = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!info)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (is_converted)
		*is_converted = 0;

	sc_log(ctx, "Encode CMAP GUID from key ID %s", sc_pkcs15_print_id(&info->id));

	memset(bits, 0, sizeof(bits));
	memset(guid, 0, sizeof(guid));

	for (offs = 0; offs < info->id.len; offs++) {
		unsigned char guid_ch, id_ch = info->id.value[offs];

		switch (id_ch) {
		case 0x5C:
		case 0xDC:
			guid_ch = 0x5B;
			break;
		case 0x00:
		case 0x80:
			guid_ch = 0x01;
			break;
		default:
			guid_ch = id_ch;
		}

		if (guid_ch & 0x80) {
			if (offs > sizeof(bits) * 7)
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

			MSBset = 1;
			guid[offs] = guid_ch & 0x7F;
			bits[offs / 7] |= 0x01 << (6 - (offs % 7));
		} else {
			guid[offs] = guid_ch;
		}
	}

	if (MSBset) {
		if (is_converted)
			*is_converted = 1;
		if (offs > sizeof(guid) - 5)
			LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
		memcpy(guid + offs, bits, 5);
		offs += 5;
	}

	if (info->aux_data != NULL && (info->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD && info->aux_data->type != SC_AUX_DATA_TYPE_NO_DATA))
		sc_aux_data_free(&info->aux_data);
	if (info->aux_data == NULL) {
		rv = sc_aux_data_allocate(ctx, &info->aux_data, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot allocate MD auxiliary data");
	}

	guid[offs] = 0;
	rv = sc_aux_data_set_md_guid(ctx, info->aux_data, (char *)guid);
	LOG_TEST_RET(ctx, rv, "Cannot set MD CMAP Guid");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
laser_cmap_record_init(struct sc_context *ctx, struct sc_pkcs15_object *key_obj,
		struct laser_cmap_record *cmap_rec)
{
	struct sc_pkcs15_prkey_info *info = NULL;
	unsigned ii;

	LOG_FUNC_CALLED(ctx);
	if (!key_obj || !cmap_rec)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	info = (struct sc_pkcs15_prkey_info *)key_obj->data;
	if (info->aux_data == NULL || info->aux_data->type != SC_AUX_DATA_TYPE_MD_CMAP_RECORD || info->aux_data->data.cmap_record.guid_len == 0)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	if ((info->aux_data->data.cmap_record.guid_len == 0) || info->aux_data->data.cmap_record.guid_len >= CMAP_GUID_INFO_SIZE / 2)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	sc_log(ctx, "encode CMAP container: guid:0x'%s', flags:0x%X",
			sc_dump_hex(info->aux_data->data.cmap_record.guid, info->aux_data->data.cmap_record.guid_len), info->aux_data->data.cmap_record.flags);
	sc_log(ctx, "key ID %s", sc_pkcs15_print_id(&info->id));

	memset(cmap_rec, 0, sizeof(struct laser_cmap_record));
	for (ii = 0; ii < info->aux_data->data.cmap_record.guid_len; ii++)
		cmap_rec->guid[2 * ii] = *(info->aux_data->data.cmap_record.guid + ii);

	cmap_rec->guid_len = ii;
	cmap_rec->flags = info->aux_data->data.cmap_record.flags;

	cmap_rec->keysize_keyexchange = info->aux_data->data.cmap_record.keysize_keyexchange;
	cmap_rec->keysize_sign = info->aux_data->data.cmap_record.keysize_sign;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
laser_cmap_encode(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object_to_ignore,
		unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *prkeys[12], *ordered_prkeys[12];
	const struct sc_pkcs15_id *ignore_id = NULL;
	int ii, prkeys_num;
	unsigned idx_max, idx;

	LOG_FUNC_CALLED(ctx);

	if (!out || !out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	*out = NULL;
	*out_len = 0;

	if (object_to_ignore)
		ignore_id = &((struct sc_pkcs15_prkey_info *)(object_to_ignore->data))->id;

	memset(ordered_prkeys, 0, sizeof(ordered_prkeys));

	prkeys_num = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, prkeys, 12);
	LOG_TEST_RET(ctx, prkeys_num, "Failed to get private key objects");

	for (ii = 0, idx_max = 0; ii < prkeys_num; ii++) {
		const struct sc_pkcs15_prkey_info *info = (const struct sc_pkcs15_prkey_info *)prkeys[ii]->data;

		idx = (info->key_reference & LASER_FS_REF_MASK) - LASER_FS_KEY_REF_MIN;
		if (idx > sizeof(ordered_prkeys) / sizeof(struct sc_pkcs15_object *) - 1)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);

		ordered_prkeys[idx] = prkeys[ii];
		if (idx_max < idx)
			idx_max = idx;
	}

	for (idx = 0; idx < idx_max + 1; idx++) {
		struct laser_cmap_record cmap_rec;

		memset(&cmap_rec, 0, sizeof(cmap_rec));

		if (ordered_prkeys[idx]) {
			struct sc_pkcs15_prkey_info *info = (struct sc_pkcs15_prkey_info *)ordered_prkeys[idx]->data;

			if (!(ignore_id && sc_pkcs15_compare_id(ignore_id, &info->id))) {
				int rv;
				rv = laser_cmap_record_init(ctx, ordered_prkeys[idx], &cmap_rec);
				LOG_TEST_RET(ctx, rv, "Failed encode CMAP record");

				if (info->id.len == SHA_DIGEST_LENGTH + 5) {
					sc_log(ctx, "Applied Laser style of CKA_ID to GUID conversion.");
					cmap_rec.rfu |= 0x80;
				}
			} else {
				sc_log(ctx, "Ignore (deleted?) key %s", sc_pkcs15_print_id(&info->id));
			}
		}

		*out = realloc(*out, *out_len + sizeof(cmap_rec));
		if (*out == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		memcpy(*out + *out_len, (unsigned char *)(&cmap_rec), sizeof(cmap_rec));
		*out_len += sizeof(cmap_rec);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
laser_get_free_index(struct sc_pkcs15_card *p15card, unsigned type, unsigned base_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *objs[32];
	struct sc_path path;
	int objs_num, idx, ii, jj, min, max;

	LOG_FUNC_CALLED(ctx);

	objs_num = sc_pkcs15_get_objects(p15card, type, objs, 32);
	LOG_TEST_RET(ctx, objs_num, "Failed to get objects");

	switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		min = LASER_FS_KEY_REF_MIN, max = LASER_FS_KEY_REF_MAX;
		break;
	case SC_PKCS15_TYPE_CERT:
		min = 0, max = 0xFF;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		min = 0, max = 0xFF;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	sc_log(ctx, "found %i objects of type %X", objs_num, type);
	for (ii = min; ii <= max; ii++) {
		for (jj = 0; jj < objs_num; jj++) {
			unsigned id;

			switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
			case SC_PKCS15_TYPE_CERT:
				path = ((struct sc_pkcs15_cert_info *)objs[jj]->data)->path;
				break;
			case SC_PKCS15_TYPE_PRKEY:
				path = ((struct sc_pkcs15_prkey_info *)objs[jj]->data)->path;
				break;
			case SC_PKCS15_TYPE_DATA_OBJECT:
				path = ((struct sc_pkcs15_data_info *)objs[jj]->data)->path;
				break;
			default:
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}

			if (path.len > 1) {
				sc_log(ctx, "object(type:%X) path %s", type, sc_print_path(&path));
				id = path.value[path.len - 1] + path.value[path.len - 2] * 0x100;
				if (id == base_id + ii)
					break;
			}
		}
		if (jj == objs_num)
			break;
	}
	if (ii > max)
		LOG_ERROR_RET(ctx, SC_ERROR_TOO_MANY_OBJECTS, "No more free object index");

	idx = ii;
	sc_log(ctx, "return free index %i", idx);
	LOG_FUNC_RETURN(ctx, idx);
}

#endif // ENABLE_OPENSSL
