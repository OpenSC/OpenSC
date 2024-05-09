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
#include "p11test_case_readonly.h"

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

	return (int)message_length - pad_length;
}

/* Perform encryption and decryption of a secret key using a PKCS#11 key referenced
 * in the  pkcs11_key  object. The encryption is done in openssl and decryption in token.

 *
 * Returns
 *  * 0 for successful Encrypt&Decrypt sequence
 *  * -1 for failure
 *  * 1 for skipped test (unsupported key type)
 */
static int
check_encrypt_decrypt_secret(CK_BYTE *plain_key, CK_ULONG plain_key_len, test_cert_t *pkcs11_key,
		token_info_t *info)
{
	CK_BYTE iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher = NULL;
	unsigned char plaintext[42] = {
		0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
		0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61,
		0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x6a, 0x6b,
	};
	int plaintext_len = sizeof(plaintext);
	unsigned char ciphertext[100];
	int ciphertext_len = sizeof(ciphertext);
	test_mech_t aes_mech = {.mech = CKM_AES_CBC, .params = &iv, .params_len = sizeof(iv)};
	unsigned char *check = NULL;
	int check_len = 0;
	int rv, len;

	if (pkcs11_key->key_type != CKK_AES) {
		fprintf(stderr, "  AES supported only\n");
		return 1;
	}

	/* First, do the encryption dance with OpenSSL */
	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		EVP_CIPHER_CTX_free(ctx);
		fprintf(stderr, "  EVP_CIPHER_CTX_new failed\n");
		return -1;
	}

	if (plain_key_len == 32) {
		cipher = EVP_aes_256_cbc();
	} else if (plain_key_len == 16) {
		cipher = EVP_aes_128_cbc();
	} else {
		EVP_CIPHER_CTX_free(ctx);
		fprintf(stderr, "  Invalid key length %lu", plain_key_len);
		return -1;
	}
	rv = EVP_EncryptInit_ex(ctx, cipher, NULL, plain_key, iv);
	if (rv != 1) {
		EVP_CIPHER_CTX_free(ctx);
		fprintf(stderr, "  EVP_EncryptInit_ex failed\n");
		return -1;
	}
	rv = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
	if (rv != 1) {
		EVP_CIPHER_CTX_free(ctx);
		fprintf(stderr, "  EVP_EncryptUpdate failed\n");
		return -1;
	}
	rv = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len);
	EVP_CIPHER_CTX_free(ctx);
	if (rv != 1) {
		fprintf(stderr, "  EVP_EncryptFinal_ex failed\n");
		return -1;
	}
	ciphertext_len += len;
	/* Now, decrypt with the PKCS#11 */
	check_len = decrypt_message(pkcs11_key, info, ciphertext, ciphertext_len, &aes_mech, &check);
	if (check_len < 0) {
		fprintf(stderr, "  Cannot decrypt message\n");
		return -1;
	}

	check_len = strip_pkcs7_padding(check, check_len, 16);
	if (check_len <= 0) {
		free(check);
		fprintf(stderr, "  Failed to strip PKCS#7 padding\n");
		return -1;
	}
	if (check_len == plaintext_len && memcmp(plaintext, check, plaintext_len) == 0) {
		free(check);
		return 0;
	}
	/* else error */
	fprintf(stderr, "  Decrypted message does not match (%d, %d)\n", check_len, plaintext_len);
	fprintf(stderr, "\nplaintext:\n");
	for (int i = 0; i < plaintext_len; i++) {
		fprintf(stderr, ":%x", plaintext[i]);
	}
	fprintf(stderr, "\ncheck:\n");
	for (int i = 0; i < check_len; i++) {
		fprintf(stderr, ":%x", check[i]);
	}
	fprintf(stderr, "\n");
	free(check);
	return -1;
}

/* Perform key wrapping of a secret or private key on token  key  using a public key referenced
 * in the  o  object. The wrapped key is then decrypted to verify the operation was successful, if possible.
 *
 * Returns
 *  * 0 for successful Wrapping or skipped test
 *  * 1 for failure
 */
static int
test_wrap(test_cert_t *o, token_info_t *info, test_cert_t *key, test_mech_t *mech)
{
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM mechanism = { mech->mech, NULL_PTR, 0 };
	CK_MECHANISM tmp_mechanism = {mech->mech, NULL_PTR, 0};
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
	/* It is very unclear from the PKCS#11 specs what
	 * value we should provide here to DataLen for
	 * wrapping and unwrapping operation. */
	CK_CCM_PARAMS ccm_params = {
			.ulDataLen = key->bits,
			.pNonce = (void *)iv,
			.ulNonceLen = 13,
			.pAAD = aad,
			.ulAADLen = sizeof(aad),
			.ulMACLen = 16,
	};
	//unsigned char key[16];
	CK_BYTE *wrapped = NULL;
	CK_ULONG wrapped_len = 0;
	CK_BYTE *plain = NULL;
	CK_ULONG plain_len = 0;
	CK_RV rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 0;
	}

	if (o->key_type != CKK_RSA && o->key_type != CKK_AES) {
		debug_print(" [ SKIP %s ] Skip non-RSA and non-AES key for wrapping", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Wrap a key [%s] (%s) using CKM_%s", o->id_str, key->id_str,
			get_key_type(key), get_mechanism_name(mech->mech));
	/* RSA mechanisms */
	switch (mech->mech) {
	case CKM_RSA_X_509:
		if (o->bits < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 0;
		}
		break;
	case CKM_RSA_PKCS:
		if (o->bits - 11 < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 0;
		}
		break;
	case CKM_RSA_PKCS_OAEP:
		if (o->bits - 2 - 2*SHA_DIGEST_LENGTH < key->bits) {
			debug_print(" [SKIP %s ] The wrapping key too small", o->id_str);
			return 0;
		}
		mech->params = &oaep_params;
		mech->params_len = sizeof(oaep_params);
		break;
	/* AES mechanisms */
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_CTS:
	case CKM_AES_OFB:
	case CKM_AES_CFB8:
	case CKM_AES_CFB128:
		mech->params = &iv;
		mech->params_len = sizeof(iv);
		break;
	case CKM_AES_CTR:
		mech->params = &ctr_params;
		mech->params_len = sizeof(ctr_params);
		break;
	case CKM_AES_GCM:
		mech->params = &gcm_params;
		mech->params_len = sizeof(gcm_params);
		break;
	case CKM_AES_CCM:
		/* The CCM parameters need to match with the input data length
		 * for encryption but we do not know the size for asymmetric
		 * keys so try to figure out by querying size in different mode */
		tmp_mechanism.mechanism = CKM_AES_CTR;
		tmp_mechanism.pParameter = &ctr_params;
		tmp_mechanism.ulParameterLen = sizeof(ctr_params);
		rv = fp->C_WrapKey(info->session_handle, &tmp_mechanism, o->public_handle,
				key->private_handle, wrapped, &wrapped_len);
		if (rv != CKR_OK) {
			mech->params = NULL;
			mech->params_len = 0;
			debug_print(" [ KEY %s ] Failed to find CCM param dataLen", o->id_str);
			return 1;
		}
		ccm_params.ulDataLen = wrapped_len;
		mech->params = &ccm_params;
		mech->params_len = sizeof(ccm_params);
		break;
	case CKM_AES_ECB:
	case CKM_AES_KEY_WRAP:
	case CKM_AES_KEY_WRAP_PAD:
		/* Nothing special ... */
		break;
	default:
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
		return 1;
	}
	wrapped = malloc(wrapped_len);
	if (wrapped == NULL) {
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "%s: malloc failed", __func__);
		return 1;
	}
	/* Wrap the key using public key through PKCS#11 */
	rv = fp->C_WrapKey(info->session_handle, &mechanism, o->public_handle, key->private_handle,
	                   wrapped, &wrapped_len);
	if (rv == CKR_KEY_NOT_WRAPPABLE) {
		/* nothing we can do about this: skip */
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, " [SKIP %s ] CKR_KEY_NOT_WRAPPABLE\n", o->id_str);
		free(wrapped);
		return 0;
	}
	if (rv != CKR_OK) {
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "  C_WrapKey: rv = 0x%.8lX\n", rv);
		free(wrapped);
		return 1;
	}

	if (mech->mech == CKM_AES_KEY_WRAP || mech->mech == CKM_AES_KEY_WRAP_PAD) {
		/* good enough for now -- I dont know how to check these */
		free(wrapped);
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
		return 1;
	}
	plain_len = rv;
	/*
	 * Then we need need to check it against something to make sure we have
	 * the right key. There are two ways:
	 *  1) The key is publicly readable through CKA_VALUE (not the case most of the time)
	 *  2) We encrypt something with a assumed key and decrypt it with the card key
	 */
	if (key->value) {
		if (plain_len == key->bits/8 && memcmp(plain, key->value, plain_len) == 0) {
			debug_print(" [  OK %s ] Wrapped key recovered correctly", o->id_str);
		} else {
			fprintf(stderr, " [ ERROR %s ] Wrapped key does not match\n", o->id_str);
			fprintf(stderr, "\nplaintext:\n");
			if (plain != NULL) {
				for (unsigned long i = 0; i < plain_len; i++) {
					fprintf(stderr, ":%x", plain[i]);
				}
			} else {
				fprintf(stderr, "NULL");
			}
			fprintf(stderr, "\nkey->value:\n");
			for (unsigned long i = 0; i < key->bits / 8; i++) {
				fprintf(stderr, ":%x", key->value[i]);
			}
			fprintf(stderr, "\n");
			return 1;
		}
		free(plain);
	} else if (key->key_type == CKK_AES) {
		rv = check_encrypt_decrypt_secret(plain, plain_len, key, info);
		free(plain);
		if (rv == 0) {
			debug_print(" [  OK %s ] Decrypted message matches", o->id_str);
		} else {
			fprintf(stderr, " [ ERROR %s ] Decrypted message does not match\n", o->id_str);
			return 1;
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

static int
test_unwrap_aes(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM mechanism = {mech->mech, NULL_PTR, 0};
	/* SoftHSM supports only SHA1 with OAEP encryption */
	CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, NULL, 0};
	CK_BYTE key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	CK_BYTE *key_padded = key;
	CK_ULONG key_len = sizeof(key);
	CK_ULONG key_padded_len = sizeof(key);
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_BBOOL true = CK_TRUE;
	CK_BYTE new_id[] = {0x00, 0xff, 0x42};
	CK_BYTE new_label[] = "Unwrapped key";
	CK_ATTRIBUTE template[] = {
			{CKA_CLASS, &keyClass, sizeof(keyClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_ENCRYPT, &true, sizeof(true)},
			{CKA_DECRYPT, &true, sizeof(true)},
			{CKA_TOKEN, &true, sizeof(true)},
			{CKA_ID, &new_id, sizeof(new_id)},
			{CKA_LABEL, &new_label, sizeof(new_label)},
			{CKA_VALUE_LEN, &key_len, sizeof(key_len)}, /* keep this one last! */
	};
	CK_ULONG template_len = sizeof(template) / sizeof(template[0]);
	size_t wrapped_len;
	CK_BYTE *wrapped = NULL;
	test_cert_t tmp_key = {0};
	CK_RV rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 1;
	}

	if (o->key_type != CKK_RSA && o->key_type != CKK_AES) {
		debug_print(" [ KEY %s ] Skip non-RSA and non-AES key for wrapping", o->id_str);
		return 1;
	}

	debug_print(" [ KEY %s ] Unwrap a AES key using CKM_%s", o->id_str, get_mechanism_name(mech->mech));

	/* Wrap/encrypt the key and set up the parameters */
	switch (mech->mech) {
	case CKM_RSA_PKCS_OAEP:
		mech->params = &oaep_params;
		mech->params_len = sizeof(oaep_params);
		/* fall through */
	case CKM_RSA_X_509:
		if (mech->mech == CKM_RSA_X_509 && (key_padded = rsa_x_509_pad_message(key, &key_padded_len, o, 1)) == NULL) {
			debug_print(" [ERROR %s ] Could not pad message", o->id_str);
			return 1;
		}
		/* fall through */
	case CKM_RSA_PKCS:
		wrapped_len = encrypt_message(o, info, key_padded, key_padded_len, mech, &wrapped);
		if (wrapped_len <= 0) {
			if (key != key_padded) {
				free(key_padded);
			}
			debug_print(" [ERROR %s ] Failed to encrypt message with public key to unwrap", o->id_str);
			return 1;
		}
		break;
	/* AES mechanisms: TODO
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_AES_ECB:
		mech->params = &iv;
		mech->params_len = sizeof(iv);
		break;
	case CKM_AES_CTR:
		mech->params = &ctr_params;
		mech->params_len = sizeof(ctr_params);
		break;
	case CKM_AES_GCM:
		mech->params = &gcm_params;
		mech->params_len = sizeof(gcm_params);
		break;
	case CKM_AES_KEY_WRAP:
	case:CKM_AES_KEY_WRAP_PAD:
		// Nothing special ...
		break; */
	default:
		debug_print(" [ KEY %s ] Unknown wrapping mechanism %s", o->id_str,
				get_mechanism_name(mech->mech));
		return 1;
	}

	mechanism.pParameter = mech->params;
	mechanism.ulParameterLen = mech->params_len;
	rv = fp->C_UnwrapKey(info->session_handle, &mechanism, o->private_handle, wrapped, wrapped_len,
			template, template_len, &tmp_key.private_handle);
	if (rv == CKR_ATTRIBUTE_READ_ONLY) {
		/* The SoftHSM chokes on CKA_VALUE_LEN but MyEID requires it so first try with the attribute and retry
		 * without to make softhsm happy */
		template_len--;
		rv = fp->C_UnwrapKey(info->session_handle, &mechanism, o->private_handle, wrapped,
				wrapped_len, template, template_len, &tmp_key.private_handle);
	}
	free(wrapped);
	if (rv != CKR_OK) {
		if (key != key_padded) {
			free(key_padded);
		}
		mech->params = NULL;
		mech->params_len = 0;
		fprintf(stderr, "  C_UnwrapKey: rv = 0x%.8lX\n", rv);
		return -1;
	}

	/* now, check the key */
	/* Simple test might be the attempt to encrypt some data with the key and check it can be decrypted with
	 * the plaintext secret */
	tmp_key.public_handle = tmp_key.private_handle;
	tmp_key.key_type = CKK_AES;
	tmp_key.sign = CK_TRUE;
	tmp_key.verify = CK_TRUE;
	tmp_key.encrypt = CK_TRUE;
	tmp_key.decrypt = CK_TRUE;
	tmp_key.wrap = CK_TRUE;
	tmp_key.unwrap = CK_TRUE;
	tmp_key.extractable = CK_TRUE;
	tmp_key.bits = CK_TRUE;
	rv = check_encrypt_decrypt_secret(key, sizeof(key), &tmp_key, info);
	if (key != key_padded) {
		free(key_padded);
	}
	destroy_tmp_object(info, tmp_key.private_handle);
	if (rv != 0) {
		fprintf(stderr, " [ ERROR %s ] Decrypted message does not match\n", o->id_str);
		return -1;
	}
	debug_print(" [  OK %s ] Decrypted message matches", o->id_str);
	mech->result_flags |= FLAGS_UNWRAP_SYM;
	return 0;
}

void
wrap_tests(void **state)
{
	unsigned int i;
	size_t j;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;
	test_certs_t objects;
	test_cert_t *aes_key = NULL, *aes2_key = NULL;
	test_cert_t *rsa_key = NULL, *rsa2_key = NULL;
	test_cert_t *ec_key = NULL;

	test_certs_init(&objects);

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	/* Find keys to wrap */
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
		} else if (ec_key == NULL && o->key_type == CKK_EC && o->extractable) {
			ec_key = o;
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
				if (ec_key) {
					errors += test_wrap(o, info, ec_key, &(o->mechs[j]));
				}
				errors += test_unwrap_aes(o, info, &(o->mechs[j]));
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
				/* TODO differentiate the RSA and EC key */
				if (ec_key) {
					errors += test_wrap(o, info, ec_key, &(o->mechs[j]));
				}
				// errors += test_unwrap_aes(o, info, &(o->mechs[j]));
				break;
			default:
				/* Other keys do not support wrapping */
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
