/*
 * p11test_case_common.c: Functions shared between test cases.
 *
 * Copyright (C) 2016, 2017 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "p11test_case_common.h"
#include "../../libopensc/sc-ossl-compat.h"

/* Unsigned long can be up to 16 B long. We print also leading "0x" and we need trailing NULL byte */
#define FLAG_BUFFER_LEN 19
char name_buffer[FLAG_BUFFER_LEN];
char flag_buffer[FLAG_BUFFER_LEN];

void test_certs_init(test_certs_t *objects)
{
	objects->alloc_count = 0;
	objects->count = 0;
	objects->data = NULL;
}

/**
 * If the object enforces re-authentication, do it now.
 */
void always_authenticate(test_cert_t *o, token_info_t *info)
{
	CK_RV rv;
	if (!o->always_auth) {
		return;
	}

	rv = info->function_pointer->C_Login(info->session_handle,
		CKU_CONTEXT_SPECIFIC, info->pin, info->pin_length);
	if (rv != CKR_OK) {
		fail_msg(" [ SKIP %s ] Re-authentication failed", o->id_str);
		exit(1);
	}
}

/**
 * Allocate new place for next certificate to store in the list
 * and return pointer to this object
 */
test_cert_t *
add_object(test_certs_t *objects, CK_ATTRIBUTE key_id, CK_ATTRIBUTE label)
{
	test_cert_t *o = NULL;
	unsigned int i;

	if (objects->count + 1 > objects->alloc_count) {
		objects->alloc_count += 8;
		objects->data = realloc(objects->data, objects->alloc_count * sizeof(test_cert_t));
		if (objects->data == NULL)
			return NULL;
	}

	/* SoftHSM is stupid returning objects in random order. Sort here by key ID
	 * to provide deterministic JSON output */
	for (i = 0; i < objects->count; i++) {
		size_t len = MIN(objects->data[i].key_id_size, key_id.ulValueLen);
		if (memcmp(key_id.pValue, objects->data[i].key_id, len) <= 0) {
			break;
		}
	}
	if (i < objects->count) {
		memmove(&objects->data[i + 1], &objects->data[i], (objects->count - i) * sizeof(test_cert_t));
	}
	objects->count = objects->count + 1;

	o = &(objects->data[i]);
	o->private_handle = CK_INVALID_HANDLE;
	o->public_handle = CK_INVALID_HANDLE;
	o->always_auth = 0;
	o->extractable = 0;
	o->bits = 0;
	o->verify_public = 0;
	o->num_mechs = 0;
	o->type = -1;
	o->sign = 0;
	o->verify = 0;
	o->decrypt = 0;
	o->encrypt = 0;
	o->wrap = 0;
	o->unwrap = 0;
	o->derive_priv = 0;
	o->derive_pub = 0;
	o->key_type = -1;
	o->x509 = NULL; /* The "reuse" capability of d2i_X509() is strongly discouraged */
	o->key = NULL;
	o->value = NULL;

	/* Store the passed CKA_ID and CKA_LABEL */
	o->key_id = malloc(key_id.ulValueLen);
	memcpy(o->key_id, key_id.pValue, key_id.ulValueLen);
	o->key_id_size = key_id.ulValueLen;
	o->id_str = convert_byte_string(o->key_id, o->key_id_size);
	o->label = malloc(label.ulValueLen + 1);
	strncpy(o->label, label.pValue, label.ulValueLen);
	o->label[label.ulValueLen] = '\0';

	return o;
}

/*
 * Search for certificate in the list by ID and return pointer to it
 */
test_cert_t * search_certificate(test_certs_t *objects, CK_ATTRIBUTE *id)
{
	unsigned int i = 0;

	while (i < objects->count && (objects->data[i].key_id_size != id->ulValueLen ||
		memcmp(objects->data[i].key_id, id->pValue, id->ulValueLen) != 0))
		i++;

	if (i == objects->count)
		return NULL;

	return &(objects->data[i]);
}

static void
add_supported_mechs(test_cert_t *o)
{
	size_t i;

	if (o->type == EVP_PKEY_RSA) {
		if (token.num_rsa_mechs > 0 ) {
			/* Get supported mechanisms by token */
			o->num_mechs = token.num_rsa_mechs;
			for (i = 0; i < token.num_rsa_mechs; i++) {
				o->mechs[i].mech = token.rsa_mechs[i].mech;
				o->mechs[i].params = token.rsa_mechs[i].params;
				o->mechs[i].params_len = token.rsa_mechs[i].params_len;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.rsa_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_RSA_PKCS;
			o->mechs[0].params = NULL;
			o->mechs[0].params_len = 0;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_SIGN | CKF_VERIFY
				| CKF_ENCRYPT | CKF_DECRYPT;
		}
	} else if (o->type == EVP_PKEY_EC) {
		if (token.num_ec_mechs > 0 ) {
			o->num_mechs = token.num_ec_mechs;
			for (i = 0; i < token.num_ec_mechs; i++) {
				o->mechs[i].mech = token.ec_mechs[i].mech;
				o->mechs[i].params = token.ec_mechs[i].params;
				o->mechs[i].params_len = token.ec_mechs[i].params_len;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.ec_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_ECDSA;
			o->mechs[0].params = NULL;
			o->mechs[0].params_len = 0;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_SIGN | CKF_VERIFY;
		}
#ifdef EVP_PKEY_ED25519
	} else if (o->type == EVP_PKEY_ED25519) {
		if (token.num_ed_mechs > 0 ) {
			o->num_mechs = token.num_ed_mechs;
			for (i = 0; i < token.num_ed_mechs; i++) {
				o->mechs[i].mech = token.ed_mechs[i].mech;
				o->mechs[i].params = token.ed_mechs[i].params;
				o->mechs[i].params_len = token.ed_mechs[i].params_len;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.ed_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_EDDSA;
			o->mechs[0].params = NULL;
			o->mechs[0].params_len = 0;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_SIGN | CKF_VERIFY;
		}
#endif
#ifdef EVP_PKEY_X25519
	} else if (o->type == EVP_PKEY_X25519) {
		if (token.num_montgomery_mechs > 0 ) {
			o->num_mechs = token.num_montgomery_mechs;
			for (i = 0; i < token.num_montgomery_mechs; i++) {
				o->mechs[i].mech = token.montgomery_mechs[i].mech;
				o->mechs[i].params = token.montgomery_mechs[i].params;
				o->mechs[i].params_len = token.montgomery_mechs[i].params_len;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.montgomery_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_ECDH1_DERIVE;
			o->mechs[0].params = NULL;
			o->mechs[0].params_len = 0;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_DERIVE;
		}
#endif
	/* Nothing in the above enum can be used for secret keys */
	} else if (o->key_type == CKK_AES) {
		if (token.num_aes_mechs > 0 ) {
			o->num_mechs = token.num_aes_mechs;
			for (i = 0; i < token.num_aes_mechs; i++) {
				o->mechs[i].mech = token.aes_mechs[i].mech;
				o->mechs[i].params = token.aes_mechs[i].params;
				o->mechs[i].params_len = token.aes_mechs[i].params_len;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags = token.aes_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_AES_CBC;
			o->mechs[0].params = NULL;
			o->mechs[0].params_len = 0;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|CKF_UNWRAP;
		}
	}
}

/**
 * Allocate place in the structure for every certificate found
 * and store related information
 */
int callback_certificates(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned long template_size, CK_OBJECT_HANDLE object_handle)
{
	EVP_PKEY *evp = NULL;
	const u_char *cp = NULL;
	test_cert_t *o = NULL;

	if (*(CK_CERTIFICATE_TYPE *)template[3].pValue != CKC_X_509)
		return 0;

	/* Ignore objects with empty ID -- we don't know what to do with them */
	if (template[0].ulValueLen == 0) {
		return 0;
	}

	if ((o = add_object(objects, template[0], template[2])) == NULL)
		return -1;

	/* Extract public key from the certificate */
	cp = template[1].pValue;
	if (d2i_X509(&(o->x509), &cp, template[1].ulValueLen) == NULL) {
		fail_msg("d2i_X509");
		return -1;
	} else if ((evp = X509_get_pubkey(o->x509)) == NULL) {
		fail_msg("X509_get_pubkey failed.");
		return -1;
	}

	if (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		o->key = evp;
		o->type = EVP_PKEY_RSA;
		o->bits = EVP_PKEY_bits(evp);

	} else if (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		o->key = evp;
		o->type = EVP_PKEY_EC;
		o->bits = EVP_PKEY_bits(evp);

	} else {
		EVP_PKEY_free(evp);
		fprintf(stderr, "[WARN %s ]evp->type = 0x%.4X (not RSA, EC)\n",
			o->id_str, EVP_PKEY_id(evp));
	}

	debug_print(" [  OK %s ] Certificate with label %s loaded successfully",
		o->id_str, o->label);
	return 0;
}

/**
 * Pair found private keys on the card with existing certificates
 */
int callback_private_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned long template_size, CK_OBJECT_HANDLE object_handle)
{
	test_cert_t *o = NULL;
	char *key_id;

	/* Ignore objects with empty ID -- we don't know what to do with them */
	if (template[3].ulValueLen == 0) {
		return 0;
	}

	/* Search for already stored certificate with same ID */
	if ((o = search_certificate(objects, &(template[3]))) == NULL) {
		key_id = convert_byte_string(template[3].pValue,
			template[3].ulValueLen);
		fprintf(stderr, "Can't find certificate for private key with ID %s\n", key_id);
		free(key_id);

		fprintf(stderr, "Let's create a bogus structure without certificate data\n");
		if ((o = add_object(objects, template[3], template[7])) == NULL)
			return -1;
	}

	if (o->private_handle != CK_INVALID_HANDLE) {
		key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
		fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}

	/* Store attributes, flags and handles */
	o->private_handle = object_handle;
	o->sign = (template[0].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	o->decrypt = (template[1].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	o->key_type = (template[2].ulValueLen == sizeof(CK_KEY_TYPE))
		? *((CK_KEY_TYPE *) template[2].pValue) : (CK_KEY_TYPE) -1;
	o->always_auth = (template[4].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[4].pValue) : CK_FALSE;
	o->unwrap = (template[5].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[5].pValue) : CK_FALSE;
	o->derive_priv = (template[6].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[6].pValue) : CK_FALSE;
	o->extractable = (template[8].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[8].pValue) : CK_FALSE;

	debug_print(" [  OK %s ] Private key loaded successfully S:%d D:%d T:%02lX",
		o->id_str, o->sign, o->decrypt, o->key_type);
	return 0;
}

/**
 * Pair found public keys on the card with existing certificates
 */
int callback_public_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned long template_size, CK_OBJECT_HANDLE object_handle)
{
	test_cert_t *o = NULL;
	char *key_id;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM_BLD *bld = NULL;
#endif

	/* Search for already stored certificate with same ID */
	if ((o = search_certificate(objects, &(template[3]))) == NULL) {
		key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
		fprintf(stderr, "Can't find certificate for public key with ID %s\n", key_id);
		free(key_id);
		return -1;
	}

	if (o->verify_public != 0) {
		key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
		fprintf(stderr, "Object already filled? ID %s\n", key_id);
		free(key_id);
		return -1;
	}

	o->public_handle = object_handle;
	o->verify = (template[0].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	o->encrypt = (template[1].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	/* store key type in case there is no corresponding private key */
	o->key_type = (template[2].ulValueLen == sizeof(CK_KEY_TYPE))
		? *((CK_KEY_TYPE *) template[2].pValue) : (CK_KEY_TYPE) -1;
	o->wrap = (template[8].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[8].pValue) : CK_FALSE;
	o->derive_pub = (template[9].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[9].pValue) : CK_FALSE;

	/* check if we get the same public key as from the certificate */
	if (o->key_type == CKK_RSA) {
		BIGNUM *n = NULL, *e = NULL;
		n = BN_bin2bn(template[4].pValue, (int)template[4].ulValueLen, NULL);
		e = BN_bin2bn(template[5].pValue, (int)template[5].ulValueLen, NULL);
		if (o->key != NULL) {
			int rv;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			const BIGNUM *cert_n = NULL, *cert_e = NULL;
			RSA *rsa = EVP_PKEY_get0_RSA(o->key);
			RSA_get0_key(rsa, &cert_n, &cert_e, NULL);
#else
			BIGNUM *cert_n = NULL, *cert_e = NULL;
			if ((EVP_PKEY_get_bn_param(o->key, OSSL_PKEY_PARAM_RSA_N, &cert_n) != 1) ||
			    (EVP_PKEY_get_bn_param(o->key, OSSL_PKEY_PARAM_RSA_E, &cert_e) != 1)) {
				fprintf(stderr, "Failed to extract RSA key parameters");
				BN_free(cert_n);
				BN_free(n);
				BN_free(e);
				return -1;
			}
#endif
			rv = BN_cmp(cert_n, n) == 0 && BN_cmp(cert_e, e) == 0;
			if (rv == 1) {
				o->verify_public = 1;
			} else {
				debug_print(" [WARN %s ] Got different public key then from the certificate",
					o->id_str);
			}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			BN_free(cert_n);
			BN_free(cert_e);
#endif
			BN_free(n);
			BN_free(e);
		} else { /* store the public key for future use */
			o->type = EVP_PKEY_RSA;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			RSA *rsa = RSA_new();
			if (rsa == NULL) {
				fail_msg("Unable to allocate RSA key");
				return -1;
			}
			o->key = EVP_PKEY_new();
			if (o->key == NULL) {
				fail_msg("Unable to allocate EVP_PKEY");
				RSA_free(rsa);
				return -1;
			}
			if (RSA_set0_key(rsa, n, e, NULL) != 1) {
				fail_msg("Unable set RSA key params");
				EVP_PKEY_free(o->key);
				RSA_free(rsa);
				return -1;
			}
			if (EVP_PKEY_assign_RSA(o->key, rsa) != 1) {
				EVP_PKEY_free(o->key);
				RSA_free(rsa);
				fail_msg("Unable to assign RSA to EVP_PKEY");
				return -1;
			}
#else
			if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) ||
				!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_BN(bld, "n", n) != 1 ||
				OSSL_PARAM_BLD_push_BN(bld, "e", e) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
				EVP_PKEY_CTX_free(ctx);
				BN_free(n);
				BN_free(e);
				OSSL_PARAM_BLD_free(bld);
				fail_msg("Unable to set key params");
				return -1;
			}
			OSSL_PARAM_BLD_free(bld);
			if (EVP_PKEY_fromdata_init(ctx) != 1 ||
				EVP_PKEY_fromdata(ctx, &o->key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
				EVP_PKEY_CTX_free(ctx);
				BN_free(n);
				BN_free(e);
				OSSL_PARAM_free(params);
			 	fail_msg("Unable to store key");
				return -1;
			}
			EVP_PKEY_CTX_free(ctx);
			OSSL_PARAM_free(params);
			BN_free(n);
			BN_free(e);
#endif
			o->bits = EVP_PKEY_bits(o->key);
		}
	} else if (o->key_type == CKK_EC) {
		int ec_error = 1;
		ASN1_OBJECT *oid = NULL;
		ASN1_OCTET_STRING *pub_asn1 = NULL;
		const unsigned char *pub, *p;
		EC_POINT *ecpoint = NULL;
		EC_GROUP *ecgroup = NULL;
		int nid, pub_len;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EC_GROUP *cert_group = NULL;
		EC_POINT *cert_point = NULL;
#endif

		/* Parse the nid out of the EC_PARAMS */
		p = template[6].pValue;
		oid = d2i_ASN1_OBJECT(NULL, &p, template[6].ulValueLen);
		if (oid == NULL) {
			debug_print(" [WARN %s ] Failed to convert EC_PARAMS"
				" to OpenSSL format", o->id_str);
			goto ec_out;
		}
		nid = OBJ_obj2nid(oid);
		ASN1_OBJECT_free(oid);
		if (nid == NID_undef) {
			debug_print(" [WARN %s ] Failed to convert EC_PARAMS"
				" to NID", o->id_str);
			goto ec_out;
		}
		ecgroup = EC_GROUP_new_by_curve_name(nid);
		if (ecgroup == NULL) {
			debug_print(" [WARN %s ] Failed to create new EC_GROUP"
				" from NID", o->id_str);
			goto ec_out;
		}
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);

		p = template[7].pValue;
		pub_asn1 = d2i_ASN1_OCTET_STRING(NULL, &p, template[7].ulValueLen);
		pub = ASN1_STRING_get0_data(pub_asn1);
		pub_len = ASN1_STRING_length(pub_asn1);

		if (!(ecpoint = EC_POINT_new(ecgroup))) {
			debug_print(" [WARN %s ] Cannot allocate EC_POINT", o->id_str);
			goto ec_out;
		}

		if (EC_POINT_oct2point(ecgroup, ecpoint, pub, pub_len, NULL) != 1) {
			debug_print(" [WARN %s ] Cannot parse EC_POINT", o->id_str);
			goto ec_out;
		}

		if (o->key != NULL) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			EC_KEY *ec = EVP_PKEY_get0_EC_KEY(o->key);
			const EC_GROUP *cert_group = EC_KEY_get0_group(ec);
			const EC_POINT *cert_point = EC_KEY_get0_public_key(ec);
			int cert_nid = EC_GROUP_get_curve_name(cert_group);
#else
			char curve_name[80];
			size_t curve_name_len = 0;
			unsigned char pubkey[256];
			size_t pubkey_len = 0;
			int cert_nid = 0;
			if (EVP_PKEY_get_group_name(o->key, curve_name, sizeof(curve_name), &curve_name_len) != 1 ||
				(cert_nid = OBJ_txt2nid(curve_name)) == NID_undef ||
				(cert_group = EC_GROUP_new_by_curve_name(cert_nid)) == NULL) {
				debug_print(" [WARN %s ] Cannot get EC_GROUP from EVP_PKEY", o->id_str);
				goto ec_out;
			}
			cert_point = EC_POINT_new(cert_group);
			if (!cert_point ||
				EVP_PKEY_get_octet_string_param(o->key, OSSL_PKEY_PARAM_PUB_KEY, pubkey, sizeof(pubkey), &pubkey_len) != 1 ||
				EC_POINT_oct2point(cert_group, cert_point, pubkey, pubkey_len, NULL) != 1) {
				debug_print(" [WARN %s ] Cannot get EC_POINT from EVP_PKEY", o->id_str);
				goto ec_out;
			}
#endif
			if (cert_nid != nid ||
				EC_GROUP_cmp(cert_group, ecgroup, NULL) != 0 ||
				EC_POINT_cmp(ecgroup, cert_point, ecpoint, NULL) != 0) {
				debug_print(" [WARN %s ] Got different public"
					"key then from the certificate",
					o->id_str);
				goto ec_out;
			}
			o->verify_public = 1;
		} else { /* store the public key for future use */
			o->type = EVP_PKEY_EC;
			o->key = EVP_PKEY_new();
			o->bits = EC_GROUP_get_degree(ecgroup);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
			EC_KEY_set_public_key(ec, ecpoint);
			EC_KEY_set_group(ec, ecgroup);
			EVP_PKEY_set1_EC_KEY(o->key, ec);
			EC_KEY_free(ec);
#else
			ctx = EVP_PKEY_CTX_new_from_name(0, "EC", 0);

			const char *curve_name = OBJ_nid2sn(nid);
			if (!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_utf8_string(bld, "group", curve_name, strlen(curve_name)) != 1 ||
				OSSL_PARAM_BLD_push_octet_string(bld, "pub", pub, pub_len) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
				debug_print(" [WARN %s ] Cannot set params from EVP_PKEY", o->id_str);
				goto ec_out;
			}

			if (ctx == NULL || params == NULL ||
				EVP_PKEY_fromdata_init(ctx) != 1 ||
				EVP_PKEY_fromdata(ctx, &o->key, EVP_PKEY_PUBLIC_KEY, params) != 1) {
				debug_print(" [WARN %s ] Cannot set params for EVP_PKEY", o->id_str);
				goto ec_out;
			}
#endif
		}

		ec_error = 0;

	ec_out:
		ASN1_STRING_free(pub_asn1);
		EC_GROUP_free(ecgroup);
		EC_POINT_free(ecpoint);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EVP_PKEY_CTX_free(ctx);
		OSSL_PARAM_BLD_free(bld);
		OSSL_PARAM_free(params);
		EC_GROUP_free(cert_group);
		EC_POINT_free(cert_point);
#endif

		if (ec_error) {
			debug_print(" [WARN %s ] Failed to check EC public key", o->id_str);
			return -1;
		}

	} else if (o->key_type == CKK_EC_EDWARDS
		|| o->key_type == CKK_EC_MONTGOMERY) {
		EVP_PKEY *key = NULL;
		ASN1_PRINTABLESTRING *curve = NULL;
		ASN1_OBJECT *obj = NULL;
		const unsigned char *a;
		ASN1_OCTET_STRING *os;
		int evp_type;

		a = template[6].pValue;
		if (d2i_ASN1_PRINTABLESTRING(&curve, &a, (long)template[6].ulValueLen) != NULL) {
			switch (o->key_type) {
#ifdef EVP_PKEY_ED25519
			case CKK_EC_EDWARDS:
				if (strcmp((char *)curve->data, "edwards25519")) {
					debug_print(" [WARN %s ] Unknown curve name. "
						" expected edwards25519, got %s", o->id_str, curve->data);
				}
				evp_type = EVP_PKEY_ED25519;
				break;
#endif
#ifdef EVP_PKEY_X25519
			case CKK_EC_MONTGOMERY:
				if (strcmp((char *)curve->data, "curve25519")) {
					debug_print(" [WARN %s ] Unknown curve name. "
						" expected curve25519, got %s", o->id_str, curve->data);
				}
				evp_type = EVP_PKEY_X25519;
				break;
#endif
			default:
				debug_print(" [WARN %s ] Unknown key type %lu", o->id_str, o->key_type);
				return -1;
			}
			ASN1_PRINTABLESTRING_free(curve);
		} else if (d2i_ASN1_OBJECT(&obj, &a, (long)template[6].ulValueLen) != NULL) {
#if defined(EVP_PKEY_ED25519) || defined (EVP_PKEY_X25519)
			int nid = OBJ_obj2nid(obj);
#endif
			ASN1_OBJECT_free(obj);

			switch (o->key_type) {
#ifdef EVP_PKEY_ED25519
			case CKK_EC_EDWARDS:
				if (nid != NID_ED25519) {
					debug_print(" [WARN %s ] Unknown OID. "
						" expected NID_ED25519 (%d), got %d", o->id_str, NID_ED25519, nid);
				}
				evp_type = EVP_PKEY_ED25519;
				break;
#endif
#ifdef EVP_PKEY_X25519
			case CKK_EC_MONTGOMERY:
				if (nid != NID_X25519) {
					debug_print(" [WARN %s ] Unknown OID. "
						" expected NID_X25519 (%d), got %d", o->id_str, NID_X25519, nid);
				}
				evp_type = EVP_PKEY_X25519;
				break;
#endif
			default:
				debug_print(" [WARN %s ] Unknown key type %lu", o->id_str, o->key_type);
				return -1;
			}
		} else {
			debug_print(" [WARN %s ] Failed to convert EC_PARAMS"
				" to curve name or object id", o->id_str);
			return -1;
		}

		/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
		a = template[7].pValue;
		os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)template[7].ulValueLen);
		if (!os) {
			debug_print(" [WARN %s ] Cannot decode EC_POINT", o->id_str);
			return -1;
		}
		if (os->length != 32) {
			debug_print(" [WARN %s ] Invalid length of EC_POINT value", o->id_str);
			return -1;
		}
		key = EVP_PKEY_new_raw_public_key(evp_type, NULL,
			(const uint8_t *)os->data,
			os->length);
		if (key == NULL) {
			debug_print(" [WARN %s ] Out of memory", o->id_str);
			ASN1_STRING_free(os);
			return -1;
		}
		if (o->key != NULL) {
			unsigned char *pub = NULL;
			size_t publen = 0;

			/* TODO check EVP_PKEY type */

			if (EVP_PKEY_get_raw_public_key(o->key, NULL, &publen) != 1) {
				debug_print(" [WARN %s ] Cannot get size of the key", o->id_str);
				ASN1_STRING_free(os);
				return -1;
			}
			pub = malloc(publen);
			if (pub == NULL) {
				debug_print(" [WARN %s ] Out of memory", o->id_str);
				ASN1_STRING_free(os);
				return -1;
			}

			if (EVP_PKEY_get_raw_public_key(o->key, pub, &publen) != 1 ||
				publen != (size_t)os->length ||
				memcmp(pub, os->data, publen) != 0) {
				debug_print(" [WARN %s ] Got different public"
					"key then from the certificate",
					o->id_str);
				free(pub);
				ASN1_STRING_free(os);
				return -1;
			}
			free(pub);
			EVP_PKEY_free(key);
			o->verify_public = 1;
		} else { /* store the public key for future use */
			o->type = evp_type;
			o->key = key;
			o->bits = 255;
		}
		ASN1_STRING_free(os);
	} else {
		debug_print(" [WARN %s ] unknown key. Key type: %02lX",
			o->id_str, o->key_type);
		return -1;
	}

	add_supported_mechs(o);

	debug_print(" [  OK %s ] Public key loaded successfully V:%d E:%d T:%02lX",
		o->id_str, o->verify, o->encrypt, o->key_type);
	return 0;
}

/**
 * Store any secret keys
 */
int callback_secret_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned long template_size, CK_OBJECT_HANDLE object_handle)
{
	test_cert_t *o = NULL;

	/* Ignore objects with empty ID and label that are left in SoftHSM after deriving key even after
	 * destroying them */
	if (template[13].pValue == NULL || template[1].pValue == NULL) {
		return 0;
	}

	if ((o = add_object(objects, template[1], template[13])) == NULL)
		return -1;

	/* TODO generic secret
	 * there is also no respective EVP_* for AES keys in OpenSSL ...
	o->type = ??; */

	/* Store attributes, flags and handles */
	o->private_handle = object_handle;
	/* For verification/encryption, we use the same key */
	o->public_handle = object_handle;
	o->key_type = (template[0].ulValueLen == sizeof(CK_KEY_TYPE))
		? *((CK_KEY_TYPE *) template[0].pValue) : (CK_KEY_TYPE) -1;
	o->sign = (template[3].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[3].pValue) : CK_FALSE;
	o->verify = (template[4].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[4].pValue) : CK_FALSE;
	o->encrypt = (template[5].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[5].pValue) : CK_FALSE;
	o->decrypt = (template[6].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[6].pValue) : CK_FALSE;
	o->derive_priv = (template[7].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[7].pValue) : CK_FALSE;
	o->wrap = (template[8].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[8].pValue) : CK_FALSE;
	o->unwrap = (template[9].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[9].pValue) : CK_FALSE;
	o->extractable = (template[12].ulValueLen == sizeof(CK_BBOOL))
		? *((CK_BBOOL *) template[12].pValue) : CK_FALSE;

	if (template[10].ulValueLen > 0) {
		/* pass the pointer to our structure */
		o->value = template[10].pValue;
		template[10].pValue = NULL;
		/* if there is CKA_VALUE_LEN it will be rewritten later */
		o->bits = template[10].ulValueLen * 8;
	}

	if (template[11].pValue != NULL && template[11].ulValueLen > 0) {
		o->bits = *((CK_ULONG *)template[11].pValue) * 8;
	}

	add_supported_mechs(o);

	debug_print(" [  OK %s ] Secret key loaded successfully T:%02lX", o->id_str, o->key_type);
	return 0;
}


int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned long, CK_OBJECT_HANDLE))
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR object_handles = NULL;
	unsigned long i = 0, objects_length = 0;
	int j, ret = -1;

	/* FindObjects first
	 * https://wiki.oasis-open.org/pkcs11/CommonBugs
	 */
	rv = fp->C_FindObjectsInit(info->session_handle, filter, filter_size);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsInit: rv = 0x%.8lX\n", rv);
		return -1;
	}

	while(1) {
		rv = fp->C_FindObjects(info->session_handle, &object_handle, 1, &object_count);
		if (object_count == 0)
			break;
		if (rv != CKR_OK) {
			fprintf(stderr, "C_FindObjects: rv = 0x%.8lX\n", rv);
			goto out;
		}
		/* store handle */
		if (i >= objects_length) {
			CK_OBJECT_HANDLE_PTR new_object_handles = NULL;
			objects_length += 4; // do not realloc after each row
			new_object_handles = realloc(object_handles, objects_length * sizeof(CK_OBJECT_HANDLE));
			if (new_object_handles == NULL) {
		 		fail_msg("Realloc failed. Need to store object handles.\n");
				goto out;
			}
			object_handles = new_object_handles;
		}
		object_handles[i++] = object_handle;
	}
	objects_length = i; //terminate list of handles

	rv = fp->C_FindObjectsFinal(info->session_handle);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8lX\n", rv);
 		fail_msg("Could not find certificate.\n");
		goto out;
	}

	for (i = 0; i < objects_length; i++) {
		/* Find attributes one after another to handle errors
		 * https://wiki.oasis-open.org/pkcs11/CommonBugs
		 */
		for (j = 0; j < template_size; j++) {
			template[j].pValue = NULL;
			template[j].ulValueLen = 0;

			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv == CKR_ATTRIBUTE_TYPE_INVALID ||
			    rv == CKR_ATTRIBUTE_SENSITIVE ||
			    rv == CKR_DEVICE_ERROR) {
				continue;
			} else if (rv != CKR_OK) {
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
				goto out;
			}

			/* Allocate memory to hold the data we want */
			if (template[j].ulValueLen == 0) {
				continue;
			} else {
				template[j].pValue = malloc(template[j].ulValueLen);
				if (template[j].pValue == NULL) {
					fail_msg("malloc failed");
					goto out;
				}
			}
			/* Call again to get actual attribute */
			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv != CKR_OK) {
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
				goto out;
			}
		}

		callback(objects, template, template_size, object_handles[i]);
		// XXX check results
		for (j = 0; j < template_size; j++)
			free(template[j].pValue);
	}
	ret = 0;
out:
	free(object_handles);
	return ret;
}

void search_for_all_objects(test_certs_t *objects, token_info_t *info)
{
	CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &keyClass, sizeof(keyClass)},
	};
	CK_ULONG filter_size = 1;
	CK_ATTRIBUTE attrs[] = {
			{ CKA_ID, NULL_PTR, 0},
			{ CKA_VALUE, NULL_PTR, 0},
			{ CKA_LABEL, NULL_PTR, 0},
			{ CKA_CERTIFICATE_TYPE, NULL_PTR, 0},
	};
	CK_ULONG attrs_size = sizeof (attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE private_attrs[] = {
			{ CKA_SIGN, NULL, 0}, // CK_BBOOL
			{ CKA_DECRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_KEY_TYPE, NULL, 0}, // CKK_
			{ CKA_ID, NULL, 0},
			{ CKA_ALWAYS_AUTHENTICATE, NULL, 0}, // CK_BBOOL
			{ CKA_UNWRAP, NULL, 0}, // CK_BBOOL
			{ CKA_DERIVE, NULL, 0}, // CK_BBOOL
			{ CKA_LABEL, NULL_PTR, 0},
			{ CKA_EXTRACTABLE, NULL, 0}, // CK_BBOOL
	};
	CK_ULONG private_attrs_size = sizeof (private_attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE public_attrs[] = {
			{ CKA_VERIFY, NULL, 0}, // CK_BBOOL
			{ CKA_ENCRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_KEY_TYPE, NULL, 0},
			{ CKA_ID, NULL, 0},
			{ CKA_MODULUS, NULL, 0},
			{ CKA_PUBLIC_EXPONENT, NULL, 0},
			{ CKA_EC_PARAMS, NULL, 0},
			{ CKA_EC_POINT, NULL, 0},
			{ CKA_WRAP, NULL, 0}, // CK_BBOOL
			{ CKA_DERIVE, NULL, 0}, // CK_BBOOL
	};
	CK_ULONG public_attrs_size = sizeof (public_attrs) / sizeof (CK_ATTRIBUTE);
	CK_ATTRIBUTE secret_attrs[] = {
			{ CKA_KEY_TYPE, NULL, 0},
			{ CKA_ID, NULL, 0},
			{ CKA_TOKEN, NULL, 0}, // CK_BBOOL
			{ CKA_SIGN, NULL, 0}, // CK_BBOOL
			{ CKA_VERIFY, NULL, 0}, // CK_BBOOL
			{ CKA_ENCRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_DECRYPT, NULL, 0}, // CK_BBOOL
			{ CKA_DERIVE, NULL, 0}, // CK_BBOOL
			{ CKA_WRAP, NULL, 0}, // CK_BBOOL
			{ CKA_UNWRAP, NULL, 0}, // CK_BBOOL
			{ CKA_VALUE, NULL, 0},
			{ CKA_VALUE_LEN, NULL, 0},
			{ CKA_EXTRACTABLE, NULL, 0}, // CK_BBOOL
			{ CKA_LABEL, NULL_PTR, 0},
	};
	CK_ULONG secret_attrs_size = sizeof (secret_attrs) / sizeof (CK_ATTRIBUTE);

	debug_print("\nSearch for all certificates on the card");
	search_objects(objects, info, filter, filter_size,
		attrs, attrs_size, callback_certificates);


	/* do the same thing with private keys (collect handles based on the collected IDs) */
	debug_print("\nSearch for all private keys respective to the certificates");
	filter[0].pValue = &privateClass;
	// search for all and pair on the fly
	search_objects(objects, info, filter, filter_size,
		private_attrs, private_attrs_size, callback_private_keys);

	debug_print("\nSearch for all public keys respective to the certificates");
	filter[0].pValue = &publicClass;
	search_objects(objects, info, filter, filter_size,
		public_attrs, public_attrs_size, callback_public_keys);

	debug_print("\nSearch for all secret keys");
	filter[0].pValue = &secretClass;
	search_objects(objects, info, filter, filter_size, secret_attrs, secret_attrs_size,
	               callback_secret_keys);
}

void clean_all_objects(test_certs_t *objects) {
	unsigned int i;
	for (i = 0; i < objects->count; i++) {
		free(objects->data[i].key_id);
		free(objects->data[i].id_str);
		free(objects->data[i].label);
		free(objects->data[i].value);
		X509_free(objects->data[i].x509);
		EVP_PKEY_free(objects->data[i].key);
	}
	free(objects->data);
}

const char *get_mechanism_name(unsigned long mech_id)
{
	switch (mech_id) {
		case CKM_RSA_PKCS:
			return "RSA_PKCS";
		case CKM_SHA1_RSA_PKCS:
			return "SHA1_RSA_PKCS";
		case CKM_SHA224_RSA_PKCS:
			return "SHA224_RSA_PKCS";
		case CKM_SHA256_RSA_PKCS:
			return "SHA256_RSA_PKCS";
		case CKM_SHA384_RSA_PKCS:
			return "SHA384_RSA_PKCS";
		case CKM_SHA512_RSA_PKCS:
			return "SHA512_RSA_PKCS";
		case CKM_SHA3_224_RSA_PKCS:
			return "SHA3_224_RSA_PKCS";
		case CKM_SHA3_256_RSA_PKCS:
			return "SHA3_256_RSA_PKCS";
		case CKM_SHA3_384_RSA_PKCS:
			return "SHA3_384_RSA_PKCS";
		case CKM_SHA3_512_RSA_PKCS:
			return "SHA3_512_RSA_PKCS";
		case CKM_RSA_X_509:
			return "RSA_X_509";
		case CKM_ECDSA:
			return "ECDSA";
		case CKM_ECDSA_SHA1:
			return "ECDSA_SHA1";
		case CKM_ECDSA_SHA224:
			return "ECDSA_SHA224";
		case CKM_ECDSA_SHA256:
			return "ECDSA_SHA256";
		case CKM_ECDSA_SHA384:
			return "ECDSA_SHA384";
		case CKM_ECDSA_SHA512:
			return "ECDSA_SHA512";
		case CKM_ECDSA_SHA3_224:
			return "ECDSA_SHA3_224";
		case CKM_ECDSA_SHA3_256:
			return "ECDSA_SHA3_256";
		case CKM_ECDSA_SHA3_384:
			return "ECDSA_SHA3_384";
		case CKM_ECDSA_SHA3_512:
			return "ECDSA_SHA3_512";
		case CKM_EDDSA:
			return "EDDSA";
		case CKM_XEDDSA:
			return "XEDDSA";
		case CKM_ECDH1_DERIVE:
			return "ECDH1_DERIVE";
		case CKM_ECDH1_COFACTOR_DERIVE:
			return "ECDH1_COFACTOR_DERIVE";
		case CKM_EC_KEY_PAIR_GEN:
			return "EC_KEY_PAIR_GEN";
		case CKM_EC_EDWARDS_KEY_PAIR_GEN:
			return "EC_EDWARDS_KEY_PAIR_GEN";
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			return "RSA_PKCS_KEY_PAIR_GEN";
		case CKM_GENERIC_SECRET_KEY_GEN:
			return "GENERIC_SECRET_KEY_GEN";
		case CKM_MD5_RSA_PKCS:
			return "MD5_RSA_PKCS";
		case CKM_RIPEMD160_RSA_PKCS:
			return "RIPEMD160_RSA_PKCS";
		case CKM_RSA_PKCS_PSS:
			return "RSA_PKCS_PSS";
		case CKM_SHA1_RSA_PKCS_PSS:
			return "SHA1_RSA_PKCS_PSS";
		case CKM_SHA224_RSA_PKCS_PSS:
			return "SHA224_RSA_PKCS_PSS";
		case CKM_SHA256_RSA_PKCS_PSS:
			return "SHA256_RSA_PKCS_PSS";
		case CKM_SHA384_RSA_PKCS_PSS:
			return "SHA384_RSA_PKCS_PSS";
		case CKM_SHA512_RSA_PKCS_PSS:
			return "SHA512_RSA_PKCS_PSS";
		case CKM_SHA3_224_RSA_PKCS_PSS:
			return "SHA3_224_RSA_PKCS_PSS";
		case CKM_SHA3_256_RSA_PKCS_PSS:
			return "SHA3_256_RSA_PKCS_PSS";
		case CKM_SHA3_384_RSA_PKCS_PSS:
			return "SHA3_384_RSA_PKCS_PSS";
		case CKM_SHA3_512_RSA_PKCS_PSS:
			return "SHA3_512_RSA_PKCS_PSS";
		case CKM_MD5_HMAC:
			return "MD5_HMAC";
		case CKM_SHA_1_HMAC:
			return "SHA_1_HMAC";
		case CKM_SHA_1_HMAC_GENERAL:
			return "SHA_1_HMAC_GENERAL";
		case CKM_SHA224_HMAC:
			return "SHA224_HMAC";
		case CKM_SHA224_HMAC_GENERAL:
			return "SHA224_HMAC_GENERAL";
		case CKM_SHA256_HMAC:
			return "SHA256_HMAC";
		case CKM_SHA256_HMAC_GENERAL:
			return "SHA256_HMAC_GENERAL";
		case CKM_SHA384_HMAC:
			return "SHA384_HMAC";
		case CKM_SHA384_HMAC_GENERAL:
			return "SHA384_HMAC_GENERAL";
		case CKM_SHA512_HMAC:
			return "SHA512_HMAC";
		case CKM_SHA512_HMAC_GENERAL:
			return "SHA512_HMAC_GENERAL";
		case CKM_RSA_PKCS_OAEP:
			return "RSA_PKCS_OAEP";
		case CKM_RIPEMD160:
			return "RIPEMD160";
		case CKM_GOSTR3411:
			return "GOSTR3411";
		case CKM_MD5:
			return "MD5";
		case CKM_SHA_1:
			return "SHA_1";
		case CKM_SHA224:
			return "SHA224";
		case CKM_SHA256:
			return "SHA256";
		case CKM_SHA384:
			return "SHA384";
		case CKM_SHA512:
			return "SHA512";
		case CKM_SHA3_256:
			return "SHA3_256";
		case CKM_SHA3_224:
			return "SHA3_224";
		case CKM_SHA3_384:
			return "SHA3_384";
		case CKM_SHA3_512:
			return "SHA3_512";
		case CKM_AES_ECB:
			return "AES_ECB";
		case CKM_AES_ECB_ENCRYPT_DATA:
			return "AES_ECB_ENCRYPT_DATA";
		case CKM_AES_KEY_GEN:
			return "AES_KEY_GEN";
		case CKM_AES_CBC:
			return "AES_CBC";
		case CKM_AES_CBC_ENCRYPT_DATA:
			return "AES_CBC_ENCRYPT_DATA";
		case CKM_AES_CBC_PAD:
			return "AES_CBC_PAD";
		case CKM_AES_MAC:
			return "AES_MAC";
		case CKM_AES_MAC_GENERAL:
			return "AES_MAC_GENERAL";
		case CKM_AES_CFB64:
			return "AES_CFB64";
		case CKM_AES_CFB8:
			return "AES_CFB8";
		case CKM_AES_CFB128:
			return "AES_CFB128";
		case CKM_AES_OFB:
			return "AES_OFB";
		case CKM_AES_CTR:
			return "AES_CTR";
		case CKM_AES_GCM:
			return "AES_GCM";
		case CKM_AES_CCM:
			return "AES_CCM";
		case CKM_AES_CTS:
			return "AES_CTS";
		case CKM_AES_CMAC:
			return "AES_CMAC";
		case CKM_AES_CMAC_GENERAL:
			return "AES_CMAC_GENERAL";
		case CKM_DES3_CMAC:
			return "DES3_CMAC";
		case CKM_DES3_CMAC_GENERAL:
			return "DES3_CMAC_GENERAL";
		case CKM_DES3_ECB:
			return "DES3_ECB";
		case CKM_DES3_CBC:
			return "DES3_CBC";
		case CKM_DES3_CBC_PAD:
			return "DES3_CBC_PAD";
		case CKM_DES3_CBC_ENCRYPT_DATA:
			return "DES3_CBC_ENCRYPT_DATA";
		case CKM_AES_XCBC_MAC:
			return "AES_XCBC_MAC";
		case CKM_AES_XCBC_MAC_96:
			return "AES_XCBC_MAC_96";
		case CKM_AES_KEY_WRAP:
			return "AES_KEY_WRAP";
		case CKM_AES_KEY_WRAP_PAD:
			return "AES_KEY_WRAP_PAD";
		default:
			sprintf(name_buffer, "0x%.8lX", mech_id);
			return name_buffer;
	}
}

const char *get_mgf_name(unsigned long mgf_id)
{
	switch (mgf_id) {
		case CKG_MGF1_SHA1:
			return "MGF1_SHA_1";
		case CKG_MGF1_SHA224:
			return "MGF1_SHA224";
		case CKG_MGF1_SHA256:
			return "MGF1_SHA256";
		case CKG_MGF1_SHA384:
			return "MGF1_SHA384";
		case CKG_MGF1_SHA512:
			return "MGF1_SHA512";
		case CKG_MGF1_SHA3_224:
			return "MGF1_SHA3_224";
		case CKG_MGF1_SHA3_256:
			return "MGF1_SHA3_256";
		case CKG_MGF1_SHA3_384:
			return "MGF1_SHA3_384";
		case CKG_MGF1_SHA3_512:
			return "MGF1_SHA3_512";
		default:
			sprintf(name_buffer, "0x%.8lX", mgf_id);
			return name_buffer;
	}
}

const char *
get_key_type(test_cert_t * key)
{
	switch (key->key_type) {
	case CKK_RSA:
		return "RSA";
	case CKK_EC:
		return "EC";
	case CKK_EC_EDWARDS:
		return "EC_EDWARDS";
	case CKK_EC_MONTGOMERY:
		return "EC_MONTGOMERY";
	case CKK_AES:
		return "AES";
	default:
		sprintf(name_buffer, "0x%.8lX", key->key_type);
		return name_buffer;
	}
}

const char *get_mechanism_flag_name(unsigned long mech_id)
{
	switch (mech_id) {
		case CKF_HW:
			return "CKF_HW";
		case CKF_MESSAGE_ENCRYPT:
			return "CKF_MESSAGE_ENCRYPT";
		case CKF_MESSAGE_DECRYPT:
			return "CKF_MESSAGE_DECRYPT";
		case CKF_MESSAGE_SIGN:
			return "CKF_MESSAGE_SIGN";
		case CKF_MESSAGE_VERIFY:
			return "CKF_MESSAGE_VERIFY";
		case CKF_MULTI_MESSAGE:
			return "CKF_MULTI_MESSAGE";
		case CKF_ENCRYPT:
			return "CKF_ENCRYPT";
		case CKF_DECRYPT:
			return "CKF_DECRYPT";
		case CKF_DIGEST:
			return "CKF_DIGEST";
		case CKF_SIGN:
			return "CKF_SIGN";
		case CKF_SIGN_RECOVER:
			return "CKF_SIGN_RECOVER";
		case CKF_VERIFY:
			return "CKF_VERIFY";
		case CKF_VERIFY_RECOVER:
			return "CKF_VERIFY_RECOVER";
		case CKF_GENERATE:
			return "CKF_GENERATE";
		case CKF_GENERATE_KEY_PAIR:
			return "CKF_GENERATE_KEY_PAIR";
		case CKF_WRAP:
			return "CKF_WRAP";
		case CKF_UNWRAP:
			return "CKF_UNWRAP";
		case CKF_DERIVE:
			return "CKF_DERIVE";
		case CKF_EC_F_P:
			return "CKF_EC_F_P";
		case CKF_EC_F_2M:
			return "CKF_EC_F_2M";
		case CKF_EC_NAMEDCURVE:
			return "CKF_EC_NAMEDCURVE";
		case CKF_EC_UNCOMPRESS:
			return "CKF_EC_UNCOMPRESS";
		case CKF_EC_COMPRESS:
			return "CKF_EC_COMPRESS";
		case CKF_EC_ECPARAMETERS:
			return "CKF_EC_ECPARAMETERS";
		default:
			sprintf(flag_buffer, "0x%.8lX", mech_id);
			return flag_buffer;
	}
}

const char *
get_mechanism_all_flag_name(unsigned long mech_id)
{
	CK_FLAGS j;
	static char f_buffer[80];

	f_buffer[0] = '\0';
	for (j = 1; j <= CKF_EC_COMPRESS; j = j << 1)
		/* append the name of the mechanism (only for known mechanisms) */
		if ((mech_id & j) != 0 && strncmp("0x", get_mechanism_flag_name(j), 2)) {
			snprintf(f_buffer + strlen(f_buffer),
					sizeof(f_buffer) - strlen(f_buffer), "%s,", get_mechanism_flag_name(j));
		}
	/* remove comma at end of string */
	if ((strlen(f_buffer) > 0) && f_buffer[strlen(f_buffer) - 1] == ',')
		f_buffer[strlen(f_buffer) - 1] = '\0';
	return f_buffer;
}

char *convert_byte_string(unsigned char *id, unsigned long length)
{
	unsigned int i;
	char *data;
	if (length == 0) {
		return NULL;
	}

	data = malloc(3 * length * sizeof(char) + 1);
	if (data == NULL) {
		return NULL;
	}

	for (i = 0; i < length; i++) {
		sprintf(&data[i * 3], "%02X:", id[i]);
	}

	data[length * 3 - 1] = '\0';
	return data;
}

void write_data_row(token_info_t *info, int cols, ...)
{
	va_list ap;
	int i, intval, type;
	char *data;

	cols = cols*2; /* shut GCC up */
	va_start(ap, cols);
	fprintf(info->log.fd, "\n\t[");
	for (i = 1; i <= cols; i+=2) {
		if (i > 1)
			fprintf(info->log.fd, ",");
		type = va_arg(ap, int);
		if (type == 'd') {
			intval = va_arg(ap, int);
			fprintf(info->log.fd, "\n\t\t\"%d\"", intval);
		} else if (type == 's') {
			data = va_arg(ap, char*);
			fprintf(info->log.fd, "\n\t\t\"%s\"", data);
		}
	}
	fprintf(info->log.fd, "\n\t]");
	va_end(ap);
}

int is_pss_mechanism(CK_MECHANISM_TYPE mech)
{
	return (mech == CKM_RSA_PKCS_PSS ||
			mech == CKM_SHA1_RSA_PKCS_PSS ||
			mech == CKM_SHA256_RSA_PKCS_PSS ||
			mech == CKM_SHA384_RSA_PKCS_PSS ||
			mech == CKM_SHA512_RSA_PKCS_PSS ||
			mech == CKM_SHA224_RSA_PKCS_PSS ||
			mech == CKM_SHA3_256_RSA_PKCS_PSS ||
			mech == CKM_SHA3_384_RSA_PKCS_PSS ||
			mech == CKM_SHA3_512_RSA_PKCS_PSS ||
			mech == CKM_SHA3_224_RSA_PKCS_PSS);
}

CK_RV
destroy_tmp_object(token_info_t *info, CK_OBJECT_HANDLE h)
{
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	return fp->C_DestroyObject(info->session_handle, h);
}
