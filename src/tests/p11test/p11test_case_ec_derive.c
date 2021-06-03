/*
 * p11test_case_ec_derive.c: Check the functionality of derive mechanisms
 *
 * Copyright (C) 2019 Red Hat, Inc.
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
#include "p11test_case_ec_derive.h"

size_t
pkcs11_derive(test_cert_t *o, token_info_t * info,
	unsigned char *pub, size_t pub_len, test_mech_t *mech, unsigned char **secret)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_ECDH1_DERIVE_PARAMS params = {CKD_NULL, 0, NULL_PTR, 0, NULL_PTR};
	CK_MECHANISM mechanism = { mech->mech, NULL_PTR, 0 };
	CK_OBJECT_HANDLE newkey;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_ATTRIBUTE template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_SENSITIVE, &false, sizeof(false)},
		{CKA_EXTRACTABLE, &true, sizeof(true)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)},
		{CKA_WRAP, &true, sizeof(true)},
		{CKA_UNWRAP, &true, sizeof(true)}
	};
	CK_ATTRIBUTE get_value = {CKA_VALUE, NULL_PTR, 0};
	CK_ULONG template_len = 9;

	params.pSharedData = NULL;
	params.ulSharedDataLen = 0;
	params.pPublicData = pub;
	params.ulPublicDataLen = pub_len;

	mechanism.pParameter = &params;
	mechanism.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);

	rv = fp->C_DeriveKey(info->session_handle, &mechanism, o->private_handle,
		template, template_len, &newkey);
	if (rv != CKR_OK) {
		debug_print("  C_DeriveKey: rv = 0x%.8lX\n", rv);
		return 0;
	}

	/* Lets read the derived data now */
	rv = fp->C_GetAttributeValue(info->session_handle, newkey,
		&get_value, 1);
	if (rv != CKR_OK) {
		fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
		return 0;
	}

	get_value.pValue = malloc(get_value.ulValueLen);
	if (get_value.pValue == NULL) {
		fail_msg("malloc failed");
		return 0;
	}

	rv = fp->C_GetAttributeValue(info->session_handle, newkey,
		&get_value, 1);
	if (rv != CKR_OK) {
		fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
		return 0;
	}

	*secret = get_value.pValue;
	return get_value.ulValueLen;
}

int test_derive_x25519(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	unsigned char *secret = NULL, *pkcs11_secret = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL; /* This is peer key */
	unsigned char *pub = NULL;
	size_t pub_len = 0, secret_len = 32, pkcs11_secret_len = 0;
	int rc;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 1;
	}

	if (o->type != EVP_PKEY_X25519) {
		debug_print(" [ KEY %s ] Skip non-EC key for derive", o->id_str);
		return 1;
	}

	/* First, we need to generate our key */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	if (pctx == NULL) {
		debug_print(" [ KEY %s ] EVP_PKEY_CTX_new_id failed", o->id_str);
		return 1;
	}

	rc = EVP_PKEY_keygen_init(pctx);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_keygen_init failed", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		return 1;
	}

	rc = EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_keygen failed", o->id_str);
		return 1;
	}

	/* Just here we start with key derivation in OpenSSL */
	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (pctx == NULL) {
		debug_print(" [ KEY %s ] EVP_PKEY_CTX_new failed", o->id_str);
		EVP_PKEY_free(pkey);
		return 1;
	}

	rc = EVP_PKEY_derive_init(pctx);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_derive_init failed", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return 1;
	}

	rc = EVP_PKEY_derive_set_peer(pctx, o->key.pkey);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_derive_set_peer failed", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return 1;
	}

	/* Allocate the memory for the shared secret */
	if ((secret = malloc(secret_len)) == NULL) {
		debug_print(" [ KEY %s ] Failed to allocate memory for secret", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pkey);
		return 1;
	}

	rc = EVP_PKEY_derive(pctx, secret, &secret_len);
	EVP_PKEY_CTX_free(pctx);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_derive failed", o->id_str);
		EVP_PKEY_free(pkey);
		free(secret);
		return 1;
	}

	/* Try to do the same with the card key */
	rc = EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_get_raw_public_key failed", o->id_str);
		EVP_PKEY_free(pkey);
		free(secret);
		return 1;
	}
	pub = malloc(pub_len);
	if (pub == NULL) {
		debug_print(" [ KEY %s ] failed to allocate memory", o->id_str);
		EVP_PKEY_free(pkey);
		free(secret);
		return 1;
	}
	rc = EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
	if (rc != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_get_raw_public_key failed", o->id_str);
		EVP_PKEY_free(pkey);
		free(secret);
		return 1;
	}

	pkcs11_secret_len = pkcs11_derive(o, info, pub, pub_len, mech, &pkcs11_secret);

	if (secret_len == pkcs11_secret_len && memcmp(secret, pkcs11_secret, secret_len) == 0) {
		mech->result_flags |= FLAGS_DERIVE;
		debug_print(" [ OK %s ] Derived secrets match", o->id_str);
		EVP_PKEY_free(pkey);
		free(secret);
		free(pkcs11_secret);
		return 0;
	}

	debug_print(" [ KEY %s ] Derived secret does not match", o->id_str);
	free(pub);
	EVP_PKEY_free(pkey);
	free(secret);
	free(pkcs11_secret);
	return 1;
}

int test_derive(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	int nid, field_size;
	EC_KEY *key = NULL;
	const EC_POINT *publickey = NULL;
	const EC_GROUP *group = NULL;
	unsigned char *secret = NULL, *pkcs11_secret = NULL;
	unsigned char *pub = NULL;
	size_t pub_len = 0, secret_len = 0, pkcs11_secret_len = 0;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 1;
	}

	if (o->type != EVP_PK_EC) {
		debug_print(" [ KEY %s ] Skip non-EC key for derive", o->id_str);
		return 1;
	}

	debug_print(" [ KEY %s ] Trying EC derive using CKM_%s and %lu-bit key",
	o->id_str, get_mechanism_name(mech->mech), o->bits);
	if (o->bits == 256)
		nid = NID_X9_62_prime256v1;
	else if (o->bits == 384)
		nid = NID_secp384r1;
	else if (o->bits == 521)
		nid = NID_secp521r1;
	else {
		debug_print(" [ KEY %s ] Skip key of unknown size", o->id_str);
		return 1;
	}

	/* Generate the peer private key */
	if ((key = EC_KEY_new_by_curve_name(nid)) == NULL ||
			EC_KEY_generate_key(key) != 1) {
		debug_print(" [ KEY %s ] Failed to generate peer private key", o->id_str);
		EC_KEY_free(key);
		return 1;
	}

	/* Calculate the size of the buffer for the shared secret */
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	secret_len = (field_size+7)/8;

	/* Allocate the memory for the shared secret */
	if ((secret = OPENSSL_malloc(secret_len)) == NULL) {
		debug_print(" [ KEY %s ] Failed to allocate memory for secret", o->id_str);
		EC_KEY_free(key);
		return 1;
	}

	/* Derive the shared secret locally */
	secret_len = ECDH_compute_key(secret, secret_len,
		EC_KEY_get0_public_key(o->key.ec), key, NULL);

	/* Try to do the same with the card key */

	/* Convert the public key to the octet string */
	group = EC_KEY_get0_group(key);
	publickey = EC_KEY_get0_public_key(key);
	pub_len = EC_POINT_point2oct(group, publickey,
		POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
	if (pub_len == 0) {
		debug_print(" [ KEY %s ] Failed to allocate memory for secret", o->id_str);
		EC_KEY_free(key);
		OPENSSL_free(secret);
		return 1;
	}
	pub = malloc(pub_len);
	if (pub == NULL) {
		debug_print(" [ OK %s ] Failed to allocate memory", o->id_str);
		EC_KEY_free(key);
		OPENSSL_free(secret);
		return 1;
	}
	pub_len = EC_POINT_point2oct(group, publickey,
		POINT_CONVERSION_UNCOMPRESSED, pub, pub_len, NULL);
	if (pub_len == 0) {
		debug_print(" [ KEY %s ] Failed to allocate memory for secret", o->id_str);
		EC_KEY_free(key);
		OPENSSL_free(secret);
		free(pub);
		return 1;
	}

	pkcs11_secret_len = pkcs11_derive(o, info, pub, pub_len, mech, &pkcs11_secret);
	free(pub);

	if (secret_len == pkcs11_secret_len && memcmp(secret, pkcs11_secret, secret_len) == 0) {
		mech->result_flags |= FLAGS_DERIVE;
		debug_print(" [ OK %s ] Derived secrets match", o->id_str);
		OPENSSL_free(secret);
		free(pkcs11_secret);
		return 0;
	}

	debug_print(" [ KEY %s ] Derived secret does not match", o->id_str);
	OPENSSL_free(secret);
	free(pkcs11_secret);
	return 1;
}


void derive_tests(void **state) {
	unsigned int i;
	int j;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;

	test_certs_t objects;
	objects.count = 0;
	objects.data = NULL;

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	debug_print("Check if the key derivation works.\n");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		/* Ignore if there is missing private key */
		if (objects.data[i].private_handle == CK_INVALID_HANDLE)
			continue;

		for (j = 0; j < o->num_mechs; j++) {
			if ((o->mechs[j].usage_flags & CKF_DERIVE) == 0
				|| ! o->derive_priv)
				continue;

			switch (o->key_type) {
			case CKK_EC:
				errors += test_derive(&(objects.data[i]), info,
					&(o->mechs[j]));
				break;
			case CKK_EC_MONTGOMERY:
				errors += test_derive_x25519(&(objects.data[i]), info,
					&(o->mechs[j]));
				break;
			default:
				/* Other keys do not support derivation */
				break;
			}
		}
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ]  [ PUBLIC ] [  DERIVE  ]\n");
	P11TEST_DATA_ROW(info, 3,
		's', "KEY ID",
		's', "MECHANISM",
		's', "DERIVE WORKS");
	for (i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type != CKK_EC &&
			objects.data[i].key_type != CKK_EC_MONTGOMERY)
			continue;

		test_cert_t *o = &objects.data[i];
		printf("\n[%-6s] [%s]\n",
			o->id_str,
			o->label);
		printf("[ %s ] [%6lu] [  %s  ]  [ %s%s ]\n",
			(o->key_type == CKK_EC ? " EC " :
				o->key_type == CKK_EC_MONTGOMERY ? "EC_M" : " ?? "),
			o->bits,
			o->verify_public == 1 ? " ./ " : "    ",
			o->derive_pub ? "[./]" : "[  ]",
			o->derive_priv ? "[./]" : "[  ]");
		if (!o->derive_pub && !o->derive_priv) {
			printf("  no usable attributes found ... ignored\n");
			continue;
		}
		if (objects.data[i].private_handle == CK_INVALID_HANDLE) {
			continue;
		}
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *mech = &o->mechs[j];
			if ((mech->usage_flags & CKF_DERIVE) == 0) {
				/* not applicable mechanisms are skipped */
				continue;
			}
			printf("  [ %-23s ] [   %s   ]\n",
				get_mechanism_name(mech->mech),
				mech->result_flags & FLAGS_DERIVE ? "[./]" : "    ");
			if ((mech->result_flags & FLAGS_DERIVE) == 0)
				continue; /* skip empty rows for export */
			P11TEST_DATA_ROW(info, 4,
				's', o->id_str,
				's', get_mechanism_name(mech->mech),
				's', mech->result_flags & FLAGS_DERIVE ? "YES" : "");
		}
	}
	printf(" Public == Cert -----^          ^\n");
	printf(" ECDH Derive functionality -----'\n");

	clean_all_objects(&objects);
	if (errors > 0)
		P11TEST_FAIL(info, "Not all the derive mechanisms worked.");
	P11TEST_PASS(info);
}
