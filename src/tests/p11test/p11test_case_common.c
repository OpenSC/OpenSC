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

char name_buffer[11];
char flag_buffer[11];

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
	objects->count = objects->count+1;
	objects->data = realloc(objects->data, objects->count * sizeof(test_cert_t));
	if (objects->data == NULL)
		return NULL;

	o = &(objects->data[objects->count - 1]);
	o->private_handle = CK_INVALID_HANDLE;
	o->public_handle = CK_INVALID_HANDLE;
	o->always_auth = 0;
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
	o->key.rsa = NULL;
	o->key.ec = NULL;

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

	if (o->type == EVP_PK_RSA) {
		if (token.num_rsa_mechs > 0 ) {
			/* Get supported mechanisms by token */
			o->num_mechs = token.num_rsa_mechs;
			for (i = 0; i <= token.num_rsa_mechs; i++) {
				o->mechs[i].mech = token.rsa_mechs[i].mech;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.rsa_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_RSA_PKCS;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_SIGN | CKF_VERIFY
				| CKF_ENCRYPT | CKF_DECRYPT;
		}
	} else if (o->type == EVP_PK_EC) {
		if (token.num_ec_mechs > 0 ) {
			o->num_mechs = token.num_ec_mechs;
			for (i = 0; i <= token.num_ec_mechs; i++) {
				o->mechs[i].mech = token.ec_mechs[i].mech;
				o->mechs[i].result_flags = 0;
				o->mechs[i].usage_flags =
					token.ec_mechs[i].usage_flags;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_ECDSA;
			o->mechs[0].result_flags = 0;
			o->mechs[0].usage_flags = CKF_SIGN | CKF_VERIFY;
		}
	}
}

/**
 * Allocate place in the structure for every certificate found
 * and store related information
 */
int callback_certificates(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	EVP_PKEY *evp = NULL;
	const u_char *cp = NULL;
	test_cert_t *o = NULL;

	if (*(CK_CERTIFICATE_TYPE *)template[3].pValue != CKC_X_509)
		return 0;

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
		/* Extract public RSA key */
		RSA *rsa = EVP_PKEY_get0_RSA(evp);
		if ((o->key.rsa = RSAPublicKey_dup(rsa)) == NULL) {
			fail_msg("RSAPublicKey_dup failed");
			return -1;
		}
		o->type = EVP_PK_RSA;
		o->bits = EVP_PKEY_bits(evp);

	} else if (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		/* Extract public EC key */
		EC_KEY *ec = EVP_PKEY_get0_EC_KEY(evp);
		if ((o->key.ec = EC_KEY_dup(ec)) == NULL) {
			fail_msg("EC_KEY_dup failed");
			return -1;
		}
		o->type = EVP_PK_EC;
		o->bits = EVP_PKEY_bits(evp);

	} else {
		fprintf(stderr, "[WARN %s ]evp->type = 0x%.4X (not RSA, EC)\n",
			o->id_str, EVP_PKEY_id(evp));
	}
	EVP_PKEY_free(evp);

	debug_print(" [  OK %s ] Certificate with label %s loaded successfully",
		o->id_str, o->label);
	return 0;
}

/**
 * Pair found private keys on the card with existing certificates
 */
int callback_private_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	test_cert_t *o = NULL;
	char *key_id;

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
	o->sign = (template[0].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	o->decrypt = (template[1].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	o->key_type = (template[2].ulValueLen != (CK_ULONG) -1)
		? *((CK_KEY_TYPE *) template[2].pValue) : (CK_KEY_TYPE) -1;
	o->always_auth = (template[4].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[4].pValue) : CK_FALSE;
	o->unwrap = (template[5].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[5].pValue) : CK_FALSE;
	o->derive_priv = (template[6].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[6].pValue) : CK_FALSE;

	debug_print(" [  OK %s ] Private key loaded successfully S:%d D:%d T:%02lX",
		o->id_str, o->sign, o->decrypt, o->key_type);
	return 0;
}

/**
 * Pair found public keys on the card with existing certificates
 */
int callback_public_keys(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	test_cert_t *o = NULL;
	char *key_id;

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
	o->verify = (template[0].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[0].pValue) : CK_FALSE;
	o->encrypt = (template[1].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[1].pValue) : CK_FALSE;
	/* store key type in case there is no corresponding private key */
	o->key_type = (template[2].ulValueLen != (CK_ULONG) -1)
		? *((CK_KEY_TYPE *) template[2].pValue) : (CK_KEY_TYPE) -1;
	o->wrap = (template[8].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[8].pValue) : CK_FALSE;
	o->derive_pub = (template[9].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[9].pValue) : CK_FALSE;

	/* check if we get the same public key as from the certificate */
	if (o->key_type == CKK_RSA) {
		BIGNUM *n = NULL, *e = NULL;
		n = BN_bin2bn(template[4].pValue, template[4].ulValueLen, NULL);
		e = BN_bin2bn(template[5].pValue, template[5].ulValueLen, NULL);
		if (o->key.rsa != NULL) {
			const BIGNUM *cert_n = NULL, *cert_e = NULL;
			RSA_get0_key(o->key.rsa, &cert_n, &cert_e, NULL);
			if (BN_cmp(cert_n, n) != 0 ||
				BN_cmp(cert_e, e) != 0) {
				debug_print(" [WARN %s ] Got different public key then from the certificate",
					o->id_str);
				BN_free(n);
				BN_free(e);
				return -1;
			}
			BN_free(n);
			BN_free(e);
			o->verify_public = 1;
		} else { /* store the public key for future use */
			o->type = EVP_PK_RSA;
			o->key.rsa = RSA_new();
			if (RSA_set0_key(o->key.rsa, n, e, NULL) != 1) {
				fail_msg("Unable to set key params");
				return -1;
			}
			o->bits = RSA_bits(o->key.rsa);
			n = NULL;
			e = NULL;
		}
	} else if (o->key_type == CKK_EC) {
		ASN1_OBJECT *oid = NULL;
		ASN1_OCTET_STRING *s = NULL;
		const unsigned char *pub, *p;
		BIGNUM *bn = NULL;
		EC_POINT *ecpoint;
		EC_GROUP *ecgroup = NULL;
		int nid, pub_len;

		/* Parse the nid out of the EC_PARAMS */
		p = template[6].pValue;
		oid = d2i_ASN1_OBJECT(NULL, &p, template[6].ulValueLen);
		if (oid == NULL) {
			debug_print(" [WARN %s ] Failed to convert EC_PARAMS"
				" to OpenSSL format", o->id_str);
			return -1;
		}
		nid = OBJ_obj2nid(oid);
		ASN1_OBJECT_free(oid);
		if (nid == NID_undef) {
			debug_print(" [WARN %s ] Failed to convert EC_PARAMS"
				" to NID", o->id_str);
			return -1;
		}
		ecgroup = EC_GROUP_new_by_curve_name(nid);
		if (ecgroup == NULL) {
			debug_print(" [WARN %s ] Failed to create new EC_GROUP"
				" from NID", o->id_str);
			return -1;
		}
		EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);

		p = template[7].pValue;
		s = d2i_ASN1_OCTET_STRING(NULL, &p, template[7].ulValueLen);
		pub = ASN1_STRING_get0_data(s);
		pub_len = ASN1_STRING_length(s);
		bn = BN_bin2bn(pub, pub_len, NULL);
		ASN1_STRING_free(s);
		if (bn == NULL) {
			debug_print(" [WARN %s ] Can not convert EC_POINT from"
				" PKCS#11 to BIGNUM", o->id_str);
			EC_GROUP_free(ecgroup);
			return -1;
		}

		ecpoint = EC_POINT_bn2point(ecgroup, bn, NULL, NULL);
		BN_free(bn);
		if (ecpoint == NULL) {
			debug_print(" [WARN %s ] Can not convert EC_POINT from"
				" BIGNUM to OpenSSL format", o->id_str);
			EC_GROUP_free(ecgroup);
			return -1;
		}

		if (o->key.ec != NULL) {
			const EC_GROUP *cert_group = EC_KEY_get0_group(o->key.ec);
			const EC_POINT *cert_point = EC_KEY_get0_public_key(o->key.ec);
			int cert_nid = EC_GROUP_get_curve_name(cert_group);

			if (cert_nid != nid ||
				EC_GROUP_cmp(cert_group, ecgroup, NULL) != 0 ||
				EC_POINT_cmp(ecgroup, cert_point, ecpoint, NULL) != 0) {
				debug_print(" [WARN %s ] Got different public"
					"key then from the certificate",
					o->id_str);
				EC_GROUP_free(ecgroup);
				EC_POINT_free(ecpoint);
				return -1;
			}
			EC_GROUP_free(ecgroup);
			EC_POINT_free(ecpoint);
			o->verify_public = 1;
		} else { /* store the public key for future use */
			o->type = EVP_PK_EC;
			o->key.ec = EC_KEY_new_by_curve_name(nid);
			EC_KEY_set_public_key(o->key.ec, ecpoint);
			EC_KEY_set_group(o->key.ec, ecgroup);
			o->bits = EC_GROUP_get_degree(ecgroup);
		}
	} else {
		debug_print(" [WARN %s ] non-RSA, non-EC key. Key type: %02lX",
			o->id_str, o->key_type);
		return -1;
	}

	add_supported_mechs(o);

	debug_print(" [  OK %s ] Public key loaded successfully V:%d E:%d T:%02lX",
		o->id_str, o->verify, o->encrypt, o->key_type);
	return 0;
}

int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned int, CK_OBJECT_HANDLE))
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_ULONG object_count;
	CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR object_handles = NULL;
	unsigned long i = 0, objects_length = 0;
	int j;

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
			return -1;
		}
		/* store handle */
		if (i >= objects_length) {
			objects_length += 4; // do not realloc after each row
			object_handles = realloc(object_handles, objects_length * sizeof(CK_OBJECT_HANDLE));
			if (object_handles == NULL) {
		 		fail_msg("Realloc failed. Need to store object handles.\n");
				return -1;
			}
		}
		object_handles[i++] = object_handle;
	}
	objects_length = i; //terminate list of handles

	rv = fp->C_FindObjectsFinal(info->session_handle);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8lX\n", rv);
 		fail_msg("Could not find certificate.\n");
		free(object_handles);
		return -1;
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
			if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
				continue;
			} else if (rv != CKR_OK) {
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
				free(object_handles);
				return -1;
			}

			/* Allocate memory to hold the data we want */
			if (template[j].ulValueLen == 0) {
				continue;
			} else {
				template[j].pValue = malloc(template[j].ulValueLen);
				if (template[j].pValue == NULL) {
					fail_msg("malloc failed");
					free(object_handles);
					return -1;
				}
			}
			/* Call again to get actual attribute */
			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv != CKR_OK) {
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
				free(object_handles);
				return -1;
			}
		}

		callback(objects, template, template_size, object_handles[i]);
		// XXX check results
		for (j = 0; j < template_size; j++)
			free(template[j].pValue);
	}
	free(object_handles);
	return 0;
}

void search_for_all_objects(test_certs_t *objects, token_info_t *info)
{
	CK_OBJECT_CLASS keyClass = CKO_CERTIFICATE;
	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
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
}

void clean_all_objects(test_certs_t *objects) {
	unsigned int i;
	for (i = 0; i < objects->count; i++) {
		free(objects->data[i].key_id);
		free(objects->data[i].id_str);
		free(objects->data[i].label);
		X509_free(objects->data[i].x509);
		if (objects->data[i].key_type == CKK_RSA &&
		    objects->data[i].key.rsa != NULL)
			RSA_free(objects->data[i].key.rsa);
		else if (objects->data[i].key.ec != NULL)
			EC_KEY_free(objects->data[i].key.ec);
	}
	free(objects->data);
}

const char *get_mechanism_name(int mech_id)
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
		case CKM_RSA_X_509:
			return "RSA_X_509";
		case CKM_ECDSA:
			return "ECDSA";
		case CKM_ECDSA_SHA1:
			return "ECDSA_SHA1";
		case CKM_ECDSA_SHA256:
			return "ECDSA_SHA256";
		case CKM_ECDSA_SHA384:
			return "ECDSA_SHA384";
		case CKM_ECDSA_SHA512:
			return "ECDSA_SHA512";
		case CKM_ECDH1_DERIVE:
			return "ECDH1_DERIVE";
		case CKM_ECDH1_COFACTOR_DERIVE:
			return "ECDH1_COFACTOR_DERIVE";
		case CKM_EC_KEY_PAIR_GEN:
			return "EC_KEY_PAIR_GEN";
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			return "RSA_PKCS_KEY_PAIR_GEN";
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
		case CKM_MD5_HMAC:
			return "MD5_HMAC";
		case CKM_SHA_1_HMAC:
			return "SHA_1_HMAC";
		case CKM_SHA256_HMAC:
			return "SHA256_HMAC";
		case CKM_SHA384_HMAC:
			return "SHA384_HMAC";
		case CKM_SHA512_HMAC:
			return "SHA512_HMAC";
		case CKM_RSA_PKCS_OAEP:
			return "RSA_PKCS_OAEP";
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
		default:
			sprintf(name_buffer, "0x%.8X", mech_id);
			return name_buffer;
	}
}

const char *get_mgf_name(int mgf_id)
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
		default:
			sprintf(name_buffer, "0x%.8X", mgf_id);
			return name_buffer;
	}
}

const char *get_mechanism_flag_name(int mech_id)
{
	switch (mech_id) {
		case CKF_HW:
			return "CKF_HW";
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
			sprintf(flag_buffer, "0x%.8X", mech_id);
			return flag_buffer;
	}
}

char *convert_byte_string(unsigned char *id, unsigned long length)
{
	unsigned int i;
	char *data = malloc(3 * length * sizeof(char) + 1);
	for (i = 0; i < length; i++)
		sprintf(&data[i*3], "%02X:", id[i]);
	data[length*3-1] = '\0';
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
	return (mech == CKM_RSA_PKCS_PSS
		|| mech == CKM_SHA1_RSA_PKCS_PSS
		|| mech == CKM_SHA256_RSA_PKCS_PSS
		|| mech == CKM_SHA384_RSA_PKCS_PSS
		|| mech == CKM_SHA512_RSA_PKCS_PSS
		|| mech == CKM_SHA224_RSA_PKCS_PSS);
}
