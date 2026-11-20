/*
 * p11test_case_kem.c: Check the functionality of KEM mechanisms
 *
 * Copyright (C) 2026 Red Hat, LLC
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
#include "p11test_case_kem.h"
#include "libopensc/internal.h"

size_t
pkcs11_decapsulate(test_cert_t *o, token_info_t *info, test_mech_t *mech,
		unsigned char *ciphertext, size_t ciphertext_len, unsigned char **secret)
{
	CK_RV rv;
	CK_FUNCTION_LIST_3_2_PTR fp = info->function_pointer;
	CK_MECHANISM mechanism = {mech->mech, NULL_PTR, 0};
	CK_OBJECT_HANDLE newkey;
	CK_OBJECT_CLASS newkey_class = CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_ULONG newkey_len = 32;
	CK_BYTE newkey_id[] = {0x00, 0xff, 0x42};
	CK_BYTE newkey_label[] = {"Decapsulated key"};
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_ATTRIBUTE template[] = {
			{CKA_TOKEN, &_false, sizeof(_false)}, /* session only object */
			{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
			{CKA_ID, &newkey_id, sizeof(newkey_id)},
			{CKA_LABEL, &newkey_label, sizeof(newkey_label)},
			{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
			{CKA_VALUE_LEN, &newkey_len, sizeof(newkey_len)},
			{CKA_SENSITIVE, &_false, sizeof(_false)},
			{CKA_EXTRACTABLE, &_true, sizeof(_true)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_DECRYPT, &_true, sizeof(_true)},
			{CKA_WRAP, &_true, sizeof(_true)},
			{CKA_UNWRAP, &_true, sizeof(_true)},
	};
	CK_ATTRIBUTE get_value = {CKA_VALUE, NULL_PTR, 0};
	CK_ULONG template_len = 10;

	if (fp->version.major < 3 || fp->version.minor < 2) {
		debug_print(" [SKIP %s ] Decapsulate key is not supported with PKCS#11 < 3.2", o->id_str);
		return 0;
	}

	rv = fp->C_DecapsulateKey(info->session_handle, &mechanism, o->private_handle,
			template, template_len, ciphertext, ciphertext_len, &newkey);
	if (rv != CKR_OK) {
		debug_print("  C_DecapsulateKey: rv = 0x%.8lX\n", rv);
		return 0;
	}

	/* Lets read the derived data now */
	rv = fp->C_GetAttributeValue(info->session_handle, newkey, &get_value, 1);
	if (rv != CKR_OK) {
		fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
		destroy_tmp_object(info, newkey);
		return 0;
	}

	get_value.pValue = malloc(get_value.ulValueLen);
	if (get_value.pValue == NULL) {
		fail_msg("malloc failed");
		destroy_tmp_object(info, newkey);
		return 0;
	}

	rv = fp->C_GetAttributeValue(info->session_handle, newkey, &get_value, 1);
	destroy_tmp_object(info, newkey);
	if (rv != CKR_OK) {
		fail_msg("C_GetAttributeValue: rv = 0x%.8lX\n", rv);
		return 0;
	}

	*secret = get_value.pValue;
	return get_value.ulValueLen;
}

int
test_kem(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
#if OPENSSL_VERSION_NUMBER > 0x30000000L
	unsigned char *secret = NULL, *pkcs11_secret = NULL, *ciphertext = NULL;
	size_t secret_len = 0, pkcs11_secret_len = 0, ciphertext_len = 0;
	EVP_PKEY_CTX *pctx = NULL;
	int rv = 1;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 1;
	}

	if (o->key_type != CKK_ML_KEM) {
		debug_print(" [ KEY %s ] Skip non-ML-KEM key for KEM operation", o->id_str);
		return 1;
	}

	debug_print(" [ KEY %s ] Trying KEM using CKM_%s", o->id_str, get_mechanism_name(mech->mech));

	/* Start with key encapsulation in OpenSSL */
	pctx = EVP_PKEY_CTX_new(o->key, NULL);
	if (pctx == NULL || EVP_PKEY_encapsulate_init(pctx, NULL) != 1) {
		debug_print(" [ KEY %s ] Cannot encapsulate key", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		return 1;
	}

	/* Get buffer length */
	if (EVP_PKEY_encapsulate(pctx, NULL, &ciphertext_len, NULL, &secret_len) != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_encapsulate failed", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		return 1;
	}
	/* Allocate the memory for the shared secret and ciphertext */
	if ((secret = malloc(secret_len)) == NULL || (ciphertext = malloc(ciphertext_len)) == NULL) {
		debug_print(" [ KEY %s ] Failed to allocate memory for secret or ciphertext", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		free(secret);
		free(ciphertext);
		return 1;
	}

	if (EVP_PKEY_encapsulate(pctx, ciphertext, &ciphertext_len, secret, &secret_len) != 1) {
		debug_print(" [ KEY %s ] EVP_PKEY_derive failed", o->id_str);
		EVP_PKEY_CTX_free(pctx);
		free(secret);
		free(ciphertext);
		return 1;
	}
	EVP_PKEY_CTX_free(pctx);

	/* Verify the Decapsulation with on-card key results in the same secret key */
	pkcs11_secret_len = pkcs11_decapsulate(o, info, mech, ciphertext, ciphertext_len, &pkcs11_secret);
	if (secret_len == pkcs11_secret_len && memcmp(secret, pkcs11_secret, secret_len) == 0) {
		mech->result_flags |= FLAGS_KEM_OPENSSL;
		debug_print(" [ OK %s ] Decapsulated secrets match", o->id_str);
		rv = 0;
	} else {
		debug_print(" [ KEY %s ] Decapsulated secret does not match", o->id_str);
	}

	/* Try to do the same with the card key */

	return rv;
#endif
	// Not supported before OpenSSL 3.0
	return 0;
}

void
kem_tests(void **state)
{
	unsigned int i;
	size_t j;
	int errors = 0;
	token_info_t *info = (token_info_t *)*state;
	test_certs_t objects;

	test_certs_init(&objects);

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	debug_print("Check if the key encapsulation works.\n");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		/* Ignore if there is missing private key */
		if (o->private_handle == CK_INVALID_HANDLE) {
			continue;
		}

		for (j = 0; j < o->num_mechs; j++) {
			if ((o->mechs[j].usage_flags & CKF_DECAPSULATE) == 0) {
				continue;
			}

			switch (o->key_type) {
			case CKK_ML_KEM:
				errors += test_kem(o, info, &(o->mechs[j]));
				break;
			default:
				/* Other keys do not support KEM */
				break;
			}
		}
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ] [ PUBLIC ] [ KEM  ]\n");
	P11TEST_DATA_ROW(info, 3,
			's', "KEY ID",
			's', "MECHANISM",
			's', "KEM WORKS");
	for (i = 0; i < objects.count; i++) {
		if (objects.data[i].key_type != CKK_ML_KEM)
			continue;

		test_cert_t *o = &objects.data[i];
		printf("\n[%-6s] [%s]\n", o->id_str, o->label);
		printf("[%s] [%6lu] [  %s  ] [%s%s]\n",
				(o->key_type == CKK_ML_KEM ? "ML-KEM" : " ?? "),
				o->bits,
				o->verify_public == 1 ? " ./ " : "    ",
				o->encapsulate ? "[./]" : "[  ]",
				o->decapsulate ? "[./]" : "[  ]");
		if (!o->encapsulate && !o->decapsulate) {
			printf("  no usable attributes found ... ignored\n");
			continue;
		}
		if (objects.data[i].private_handle == CK_INVALID_HANDLE) {
			continue;
		}
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *mech = &o->mechs[j];
			if ((mech->usage_flags & CKF_DECAPSULATE) == 0) {
				/* not applicable mechanisms are skipped */
				continue;
			}
			printf("  [ %-22s ] [  %s  ]\n",
					get_mechanism_name(mech->mech),
					mech->result_flags & FLAGS_KEM_ANY ? "[./]" : "   ");
			if ((mech->result_flags & FLAGS_KEM_ANY) == 0)
				continue; /* skip empty rows for export */
			P11TEST_DATA_ROW(info, 3,
					's', o->id_str,
					's', get_mechanism_name(mech->mech),
					's', mech->result_flags & FLAGS_KEM_ANY ? "YES" : "");
		}
	}
	printf(" Public == Cert -----^           ^\n");
	printf(" KEM functionality --------------'\n");

	clean_all_objects(&objects);
	if (errors > 0)
		P11TEST_FAIL(info, "Not all the KEM mechanisms worked.");
	P11TEST_PASS(info);
}
