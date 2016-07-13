/*
 * p11test_case_common.c: Functions shared between test caess.
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
	if (!o->always_auth)
		return;

	rv = info->function_pointer->C_Login(info->session_handle,
		CKU_CONTEXT_SPECIFIC, info->pin, info->pin_length);
	if (rv != CKR_OK) {
		fail_msg(" [ SKIP %s ] Re-authentication failed", o->id_str);
	}
}

/**
 * Allocate new place for next certificate to store in the list
 * and return pointer to this object
 */
test_cert_t * add_certificate(test_certs_t *objects)
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
	o->x509 = NULL; /* The "reuse" capability of d2i_X509() is strongly discouraged */
	return o;
}

/*
 * Search for certificate in the list by ID and return pointer to it
 */
test_cert_t * search_certificate(test_certs_t *objects, CK_ATTRIBUTE *id)
{
	unsigned int i = 0;

	while (i < objects->count && objects->data[i].key_id_size == id->ulValueLen &&
		memcmp(objects->data[i].key_id, id->pValue, id->ulValueLen) != 0)
		i++;

	if (i == objects->count)
		return NULL;

	return &(objects->data[i]);
}

/**
 * Allocate place in the structure for every certificte found
 * and store related information
 */
int callback_certificates(test_certs_t *objects,
	CK_ATTRIBUTE template[], unsigned int template_size, CK_OBJECT_HANDLE object_handle)
{
	EVP_PKEY *evp = NULL;
	const u_char *cp;
	test_cert_t *o = NULL;
	size_t i;

	if ((o = add_certificate(objects)) == NULL)
		return -1;

	/* get the type and data, store in some structure */
	o->key_id = malloc(template[0].ulValueLen);
	o->key_id = memcpy(o->key_id, template[0].pValue, template[0].ulValueLen);
	o->key_id_size = template[0].ulValueLen;
	o->id_str = convert_byte_string(o->key_id, o->key_id_size);
	o->label = malloc(template[2].ulValueLen + 1);
	strncpy(o->label, template[2].pValue, template[2].ulValueLen);
	o->label[template[2].ulValueLen] = '\0';
	cp = template[1].pValue;

	/* Extract public key from the certificate */
	if (d2i_X509(&(o->x509), &cp, template[1].ulValueLen) == NULL) {
		fail_msg("d2i_X509");
	} else if ((evp = X509_get_pubkey(o->x509)) == NULL) {
		fail_msg("X509_get_pubkey failed.");
	}

	if (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		/* Extract public RSA key */
		if ((o->key.rsa = RSAPublicKey_dup(evp->pkey.rsa)) == NULL)
			fail_msg("RSAPublicKey_dup failed");
		o->type = EVP_PK_RSA;
		o->bits = EVP_PKEY_bits(evp);

		if (token.num_rsa_mechs > 0 ) {
			/* Get supported mechanisms by token */
			o->num_mechs = token.num_rsa_mechs;
			for (i = 0; i <= token.num_rsa_mechs; i++) {
				o->mechs[i].mech = token.rsa_mechs[i].mech;
				o->mechs[i].flags = 0;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_RSA_PKCS;
			o->mechs[0].flags = 0;
		}
	} else if (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		/* Extract public EC key */
		if ((o->key.ec = EC_KEY_dup(evp->pkey.ec)) == NULL)
			fail_msg("EC_KEY_dup failed");
		o->type = EVP_PK_EC;
		o->bits = EVP_PKEY_bits(evp);

		if (token.num_ec_mechs > 0 ) {
			o->num_mechs = token.num_ec_mechs;
			for (i = 0; i <= token.num_ec_mechs; i++) {
				o->mechs[i].mech = token.ec_mechs[i].mech;
				o->mechs[i].flags = 0;
			}
		} else {
			/* Use the default list */
			o->num_mechs = 1;
			o->mechs[0].mech = CKM_ECDSA;
			o->mechs[0].flags = 0;
		}
	} else {
		debug_print("[WARN %s ]evp->type = 0x%.4X (not RSA, EC)\n", o->id_str, evp->type);
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
		key_id = convert_byte_string(template[3].pValue, template[3].ulValueLen);
		fprintf(stderr, "Can't find certificate for private key with ID %s\n", key_id);
		free(key_id);
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

	debug_print(" [  OK %s ] Private key to the certificate found successfully S:%d D:%d T:%02lX",
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
	o->wrap = (template[8].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[8].pValue) : CK_FALSE;
	o->derive_pub = (template[9].ulValueLen != (CK_ULONG) -1)
		? *((CK_BBOOL *) template[9].pValue) : CK_FALSE;

	/* check if we get the same public key as from the certificate */
	if (o->key_type == CKK_RSA) {
		RSA *rsa = RSA_new();
		rsa->n = BN_bin2bn(template[4].pValue, template[4].ulValueLen, NULL);
		rsa->e = BN_bin2bn(template[5].pValue, template[5].ulValueLen, NULL);
		if (BN_cmp(o->key.rsa->n, rsa->n) != 0 ||
			BN_cmp(o->key.rsa->e, rsa->e) != 0) {
			debug_print(" [WARN %s ] Got different public key then the from the certificate ID",
				o->id_str);
			return -1;
		}
		RSA_free(rsa);
		o->verify_public = 1;
	} else if (o->key_type == CKK_EC) {
		debug_print(" [WARN %s ] EC public key check skipped so far",
			o->id_str);

		//EC_KEY *ec = EC_KEY_new();
		//int nid = NID_X9_62_prime256v1; /* 0x11 */
		//int nid = NID_secp384r1;		/* 0x14 */
		//EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(nid);
		//EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
		//EC_POINT *ecpoint = EC_POINT_new(ecgroup);

		//EC_KEY_set_public_key(ec, ecpoint);
		return -1;
	} else {
		debug_print(" [WARN %s ] non-RSA, non-EC key\n", o->id_str);
		return -1;
	}

	debug_print(" [  OK %s ] Public key to the certificate found successfully V:%d E:%d T:%02lX",
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
			object_handles = realloc(object_handles, objects_length * sizeof(CK_OBJECT_HANDLE_PTR));
			if (object_handles == NULL)
		 		fail_msg("Realloc failed. Need to store object handles.\n");
		}
		object_handles[i++] = object_handle;
	}
	objects_length = i; //terminate list of handles

	rv = fp->C_FindObjectsFinal(info->session_handle);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_FindObjectsFinal: rv = 0x%.8lX\n", rv);
 		fail_msg("Could not find certificate.\n");
	}

	for (i = 0;i < objects_length; i++) {
		/* Find attributes one after another to handle errors
		 * https://wiki.oasis-open.org/pkcs11/CommonBugs
		 */
		for (j = 0; j < template_size; j++) {
			template[j].pValue = NULL;
			template[j].ulValueLen = 0;

			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
				continue;
			else if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);

			/* Allocate memory to hold the data we want */
			if (template[j].ulValueLen != 0) {
				template[j].pValue = malloc(template[j].ulValueLen);
				if (template[j].pValue == NULL)
					fail_msg("malloc failed");
			}
			/* Call again to get actual attribute */
			rv = fp->C_GetAttributeValue(info->session_handle, object_handles[i],
				&(template[j]), 1);
			if (rv != CKR_OK)
				fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
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
		default:
			sprintf(name_buffer, "0x%.8X", mech_id);
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

char *convert_byte_string(char *id, unsigned long length)
{
	unsigned int i;
	char *data = malloc(3 * length * sizeof(char) + 1);
	for (i = 0; i < length; i++)
		sprintf(&data[i*3], "%02X:", id[i]);
	data[length*3-1] = '\0';
	return data;
}

