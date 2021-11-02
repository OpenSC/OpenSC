/*
 * p11test_case_wrap.c: Check the functionality of wrap mechanisms
 *
 * Copyright (C) 2021 Red Hat, Inc.
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
#include "p11test_case_wrap.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

/* returns the new length of message after stripping the pkcs7 padding */
static int
strip_pkcs7_padding(const unsigned char *message, unsigned long message_length,
                    unsigned long block_len)
{
	unsigned char pad_length = message[message_length - 1];

	if (pad_length > block_len) {
		return 0;
	}

	return message_length - pad_length;
}

static int test_wrap(test_cert_t *o, token_info_t *info, test_cert_t *key, test_mech_t *mech)
{
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM mechanism = { mech->mech, NULL_PTR, 0 };
	/* SoftHSM supports only SHA1 with OAEP encryption */
	CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL, 0};
	CK_BYTE iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	CK_AES_CTR_PARAMS ctr_params = { 64, {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	CK_BYTE aad[] = {0x00, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
	CK_GCM_PARAMS gcm_params = {
		.pIv = (void *)iv,
		.ulIvLen = 16,
		.ulIvBits = 64,
		.pAAD = aad, /* TODO: SoftHSM crashes without AAD */
		.ulAADLen = sizeof(aad),
		.ulTagBits = 128,
	};
	//unsigned char key[16];
	CK_BYTE *wrapped = NULL;
	CK_ULONG wrapped_len = 0;
	CK_BYTE *plain = NULL;
	CK_ULONG plain_len = 0;
	CK_RV rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 1;
	}

	if (o->key_type != CKK_RSA && o->key_type != CKK_AES) {
		debug_print(" [ KEY %s ] Skip non-RSA and non-AES key for wrapping", o->id_str);
		return 1;
	}

	debug_print(" [ KEY %s ] Wrap a key [%s] using CKM_%s", o->id_str, key->id_str,
	            get_mechanism_name(mech->mech));
	/* RSA mechanisms */
	if (mech->mech == CKM_RSA_X_509) {
		if (o->bits < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 1;
		}
	} else if (mech->mech == CKM_RSA_PKCS) {
		if (o->bits - 11 < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 1;
		}
	} else if (mech->mech == CKM_RSA_PKCS_OAEP) {
		if (o->bits - 2 - 2*SHA_DIGEST_LENGTH < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 1;
		}
		mech->params = &oaep_params;
		mech->params_len = sizeof(oaep_params);
	/* AES mechanisms */
	} else if (mech->mech == CKM_AES_CBC || mech->mech == CKM_AES_CBC_PAD || mech->mech == CKM_AES_ECB) {
		mech->params = &iv;
		mech->params_len = sizeof(iv);
	} else if (mech->mech == CKM_AES_CTR) {
		mech->params = &ctr_params;
		mech->params_len = sizeof(ctr_params);
	} else if (mech->mech == CKM_AES_GCM) {
		mech->params = &gcm_params;
		mech->params_len = sizeof(gcm_params);
	} else if (mech->mech == CKM_AES_KEY_WRAP || mech->mech == CKM_AES_KEY_WRAP_PAD) {
		/* Nothing special ... */
	} else {
		debug_print(" [ KEY %s ] Unknown wrapping mechanism %s",
		            o->id_str, get_mechanism_name(mech->mech));
		return 1;
	}

	/* Get the wrapped size */
	mechanism.pParameter = mech->params;
	mechanism.ulParameterLen = mech->params_len;
	rv = fp->C_WrapKey(info->session_handle, &mechanism, o->public_handle, key->private_handle,
	                   wrapped, &wrapped_len);
	if (rv != CKR_OK) {
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "  C_WrapKey: rv = 0x%.8lX\n", rv);
		return -1;
	}
	wrapped = malloc(wrapped_len);
	if (wrapped == NULL) {
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "%s: malloc failed", __func__);
		return -1;
	}
	/* Wrap the key using public RSA key through PKCS#11 */
	rv = fp->C_WrapKey(info->session_handle, &mechanism, o->public_handle, key->private_handle,
	                   wrapped, &wrapped_len);
	if (rv != CKR_OK) {
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "  C_WrapKey: rv = 0x%.8lX\n", rv);
		free(wrapped);
		return -1;
	}

	if (mech->mech == CKM_AES_KEY_WRAP || mech->mech == CKM_AES_KEY_WRAP_PAD) {
		/* good enough for now -- I dont know how to check these */
		goto out;
	}
	/* OK, we have wrapped key. Now, check it is really the key on the card.
	 * We need to decipher the wrapped key with the wrapping key, which
	 * should be generally the reverse operation to the wrapping for the
	 * simple wrapping mechanisms and which should give us a plain key.
	 */
	rv = decrypt_message(o, info, wrapped, wrapped_len, mech, &plain);
	free(wrapped);
	mech->params = NULL;
	mech->params_len = 0;
	if (rv <= 0) {
		debug_print(" [ KEY %s ] Unable to decrypt the wrapped key", o->id_str);
		return -1;
	}
	plain_len = rv;
	/*
	 * Then we need need to check it against something to make sure we have
	 * the right key. There are two ways:
	 *  1) The key is publicly readable through CKA_VALUE (not the case most of the time)
	 *  2) We encrypt something with a assumed key and decrypt it with the card key
	 */
	if (key->value) {
/*
		if (plain_len == key->bits/8 && memcmp(plain, key->value, plain_len) == 0) {
			debug_print(" [  OK %s ] Wrapped key recovered correctly", o->id_str);
		} else {
			fprintf(stderr, " [ ERROR %s ] Wrapped key does not match\n", o->id_str);
			return -1;
		}
	} else {*/
		EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
		const EVP_CIPHER *cipher = NULL;
		unsigned char plaintext[42];
		int plaintext_len = sizeof(plaintext);
		unsigned char ciphertext[100];
		int ciphertext_len = sizeof(ciphertext);
		test_mech_t aes_mech = {.mech = CKM_AES_CBC, .params = &iv, .params_len = sizeof(iv)};
		unsigned char *check = NULL;
		int check_len = 0;
		int rv, len;

		/* First, do the encryption dance with OpenSSL */
		if (ctx == NULL) {
			fprintf(stderr, "  EVP_CIPHER_CTX_new failed\n");
			return -1;
		}

		rv = RAND_bytes(plaintext, plaintext_len);
		if (rv != 1) {
			fprintf(stderr, "  RAND_bytes failed\n");
			return -1;
		}

		if (key->key_type != CKK_AES) {
			debug_print(" [SKIP %s ] Only AES for now", o->id_str);
			return 1;
		}
		if (plain_len == 32) {
			cipher = EVP_aes_256_cbc();
		} else if (plain_len == 16) {
			cipher = EVP_aes_128_cbc();
		} else {
			fprintf(stderr, "  Invalid key length %lu", plain_len);
			return -1;
		}
		rv = EVP_EncryptInit_ex(ctx, cipher, NULL, plain, iv);
		if (rv != 1) {
			fprintf(stderr, "  EVP_EncryptInit_ex failed\n");
			return -1;
		}
		rv = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
		if (rv != 1) {
			fprintf(stderr, "  EVP_EncryptUpdate failed\n");
			return -1;
		}
		rv = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
		if (rv != 1) {
			fprintf(stderr, "  EVP_EncryptFinal_ex failed\n");
			return -1;
		}
		ciphertext_len += len;
		/* Now, decrypt with the PKCS#11 */
		check_len = decrypt_message(key, info, ciphertext, ciphertext_len, &aes_mech, &check);

		check_len = strip_pkcs7_padding(check, check_len, 16);
		if (check_len <= 0) {
			fprintf(stderr, "  Failed to strip PKCS#7 padding\n");
			return -1;
		}
		if (check_len == plaintext_len && memcmp(plaintext, check, plaintext_len) == 0) {
			debug_print(" [  OK %s ] Decrypted message matches", o->id_str);
		} else {
			printf(" [ ERROR %s ] Decrypted message does not match (%d, %d)\n", o->id_str,
			       check_len, plaintext_len);
			printf("\nplaintext:\n");
			for (int i = 0; i < plaintext_len; i++) {
				printf(":%x", plaintext[i]);
			}
			printf("\ncheck:\n");
			for (int i = 0; i < check_len; i++) {
				printf(":%x", check[i]);
			}
			printf("\n");
			return -1;
		}
	}

out:
	debug_print(" [  OK %s ] Key wrapping works.", o->id_str);
	if (key->key_type == CKK_AES) {
		mech->result_flags |= FLAGS_WRAP_SYM;
	} else {
		mech->result_flags |= FLAGS_WRAP;
	}
	return 0;
}

void wrap_tests(void **state)
{
	unsigned int i;
	int j;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;
	test_certs_t objects;
	test_cert_t *aes_key = NULL, *aes2_key = NULL;
	test_cert_t *rsa_key = NULL, *rsa2_key = NULL;

	test_certs_init(&objects);

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		if (aes_key == NULL && o->key_type == CKK_AES && o->extractable) {
			aes_key = o;
		} else if (aes2_key == NULL && o->key_type == CKK_AES && o->extractable) {
			aes2_key = o;
		} else if (rsa_key == NULL && o->key_type == CKK_RSA && o->extractable) {
			rsa_key = o;
		} else if (rsa2_key == NULL && o->key_type == CKK_RSA && o->extractable) {
			rsa2_key = o;
		}
	}

	debug_print("Check if the wrap operation works.\n");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		/* Ignore if there is missing private key */
		if (o->private_handle == CK_INVALID_HANDLE)
			continue;

		for (j = 0; j < o->num_mechs; j++) {
			/*
			if ((o->mechs[j].usage_flags & CKF_WRAP) == 0 || !o->wrap)
				continue;
			if ((o->mechs[j].usage_flags & CKF_UNWRAP) == 0	|| !o->unwrap)
				continue;
			*/
			if ((o->mechs[j].usage_flags & (CKF_WRAP|CKF_UNWRAP)) == 0)
				continue;

			switch (o->key_type) {
			case CKK_RSA:
				/* We probably can not wrap one key with itself */
				if (rsa_key && o != rsa_key) {
					errors += test_wrap(o, info, rsa_key, &(o->mechs[j]));
				} else if (rsa2_key && o != rsa2_key) {
					errors += test_wrap(o, info, rsa2_key, &(o->mechs[j]));
				}
				if (aes_key) {
					errors += test_wrap(o, info, aes_key, &(o->mechs[j]));
				}
				break;
			case CKK_AES:
				/* We probably can not wrap one key with itself */
				if (aes_key && o != aes_key) {
					errors += test_wrap(o, info, aes_key, &(o->mechs[j]));
				} else if (aes2_key && o != aes2_key) {
					errors += test_wrap(o, info, aes2_key, &(o->mechs[j]));
				}
				if (rsa_key) {
					errors += test_wrap(o, info, rsa_key, &(o->mechs[j]));
				}
				break;
			default:
				/* Other keys do not support derivation */
				break;
			}
		}
	}

	/* print summary */
	printf("[KEY ID] [EXTRACTABLE] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ]              [ WRAP ] [UNWRAP]\n");
	P11TEST_DATA_ROW(info, 4,
		's', "KEY ID",
		's', "MECHANISM",
		's', "WRAP WORKS",
		's', "UNWRAP WORKS");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		if (o->key_type != CKK_RSA && o->key_type != CKK_AES)
			continue;

		printf("\n[%-6s] [     %s    ] [%s]\n",
			o->id_str,
			o->extractable ? "./" : "  ",
			o->label);
		printf("[ %s ] [%6lu]              [ [%s] ] [ [%s] ]\n",
			(o->key_type == CKK_RSA ? "RSA " :
				o->key_type == CKK_AES ? "AES " : " ?? "),
			o->bits,
			o->wrap ? "./" : "  ",
			o->unwrap ? "./" : "  ");
		/* the attributes are sometimes confusing
		if (!o->wrap && !o->unwrap) {
			printf("  no usable attributes found ... ignored\n");
			continue;
		} */
		if (o->private_handle == CK_INVALID_HANDLE) {
			continue;
		}
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *mech = &o->mechs[j];
			if ((mech->usage_flags & (CKF_WRAP | CKF_UNWRAP)) == 0) {
				/* not applicable mechanisms are skipped */
				continue;
			}
			printf("  [ %-24s ] [%s][%s] [%s][%s]\n",
				get_mechanism_name(mech->mech),
				mech->result_flags & FLAGS_WRAP_SYM ? "./" : "  ",
				mech->result_flags & FLAGS_WRAP ? "./" : "  ",
				mech->result_flags & FLAGS_UNWRAP_SYM ? "./" : "  ",
				mech->result_flags & FLAGS_UNWRAP ? "./" : "  ");
			if ((mech->result_flags & (FLAGS_WRAP | FLAGS_UNWRAP)) == 0)
				continue; /* skip empty rows for export */
			P11TEST_DATA_ROW(info, 6,
				's', o->id_str,
				's', get_mechanism_name(mech->mech),
				's', mech->result_flags & FLAGS_WRAP_SYM ? "YES" : "",
				's', mech->result_flags & FLAGS_WRAP ? "YES" : "",
				's', mech->result_flags & FLAGS_UNWRAP_SYM ? "YES" : "",
				's', mech->result_flags & FLAGS_UNWRAP ? "YES" : "");
		}
	}
	printf(" Wrapping symmetric key works --^   ^    ^   ^- Unwrapping asymmetric key works\n");
	printf(" Wrapping asymmetric key works -----'    '------- Unwrapping symmetric key works\n");

	clean_all_objects(&objects);
	if (errors > 0)
		P11TEST_FAIL(info, "Not all the wrap/unwrap mechanisms worked.");
	P11TEST_PASS(info);
}
