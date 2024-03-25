/*
 * p11test_case_secret.c: Check the functionality of operations with secret keys
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
#include "p11test_case_secret.h"
#include "p11test_case_readonly.h"

#define MESSAGE_TO_SIGN "Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n"

const unsigned char *short_message = (unsigned char *) MESSAGE_TO_SIGN;

static unsigned char *
pkcs7_pad_message(const unsigned char *message, unsigned long message_length,
                  unsigned long block_len, unsigned long *out_len)
{
	unsigned long pad_length = block_len - (message_length % block_len);
	unsigned char *pad_message = malloc(message_length + pad_length);
	if (pad_message == NULL) {
		return NULL;
	}
	memcpy(pad_message, message, message_length);
	memset(pad_message + message_length, (int)pad_length, pad_length);
	*out_len = message_length + pad_length;
	return pad_message;
}

/* Perform encryption and decryption of a message using secret key referenced
 * in the  o  object with mechanism defined by  mech.
 *
 * NONE of the reasonable mechanisms support multipart encryption/decryption
 *
 * Returns
 *  * 0 for successful Sign&Verify sequence or skipped test (unsupported mechanism, key, ...)
 *  * 1 for failure
 *  Serious errors terminate the execution.
 */
int test_secret_encrypt_decrypt(test_cert_t *o, token_info_t *info, test_mech_t *mech,
	CK_ULONG message_length, int multipart)
{
	CK_BYTE *message = NULL;
	CK_BYTE *dec_message = NULL;
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
	CK_CCM_PARAMS ccm_params = {
			.ulDataLen = message_length,
			.pNonce = (void *)iv,
			.ulNonceLen = 13,
			.pAAD = aad,
			.ulAADLen = sizeof(aad),
			.ulMACLen = 16,
	};
	int dec_message_length = 0;
	unsigned char *enc_message = NULL;
	int enc_message_length, rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing secret key", o->id_str);
		return 1;
	}

	if (o->key_type != CKK_AES) {
		debug_print(" [ KEY %s ] Skip non-AES key for encryption", o->id_str);
		return 0;
	}

	switch (mech->mech) {
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
		mech->params = &ccm_params;
		mech->params_len = sizeof(ccm_params);
		break;
	case CKM_AES_ECB:
		/* No parameters needed */
		break;
	default:
		debug_print(" [SKIP %s ] Unknown mechanism %s", o->id_str, get_mechanism_name(mech->mech));
		return 0;
	}
	if (mech->mech == CKM_AES_CBC || mech->mech == CKM_AES_ECB) {
		/* This mechanism requires the blocks to be aligned to block size */
		message = pkcs7_pad_message(short_message, message_length, 16, &message_length);
	} else {
		message = (CK_BYTE *)strndup(MESSAGE_TO_SIGN, message_length);
	}

	debug_print(" [ KEY %s ] Encrypt message using CKM_%s",
		o->id_str, get_mechanism_name(mech->mech));
	enc_message_length = encrypt_message(o, info, message, message_length,
	    mech, &enc_message);
	if (enc_message_length <= 0) {
		mech->params = NULL;
		mech->params_len = 0;
		free(enc_message);
		free(message);
		return 1;
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	dec_message_length = decrypt_message(o, info, enc_message,
	    enc_message_length, mech, &dec_message);
	free(enc_message);
	if (dec_message_length <= 0) {
		mech->params = NULL;
		mech->params_len = 0;
		free(message);
		return 1;
	}

	if (memcmp(dec_message, message, dec_message_length) == 0
			&& (unsigned int) dec_message_length == message_length) {
		debug_print(" [  OK %s ] Text decrypted successfully.", o->id_str);
		mech->result_flags |= FLAGS_DECRYPT;
		rv = 0;
	} else {
		dec_message[dec_message_length] = '\0';
		debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
			o->id_str, dec_message);
		rv = 1;
	}
	mech->params = NULL;
	mech->params_len = 0;
	free(dec_message);
	free(message);
	return rv;
}

/* Perform signature and verification of a message using secret key referenced
 * in the  o  object with mechanism defined by  mech. Message length can be
 * specified using argument  message_length.
 *
 * Returns
 *  * 0 for successful Sign&Verify sequence or skipped test (unsupported mechanism, key, ...)
 *  * 1 for failure
 *  Serious errors terminate the execution.
 */
int test_secret_sign_verify(test_cert_t *o, token_info_t *info, test_mech_t *mech,
    CK_ULONG message_length, int multipart)
{
	CK_BYTE *message = NULL;
	CK_ULONG sig_len = 42;
	CK_BYTE *sign = NULL;
	CK_ULONG sign_length = 0;
	int rv = 0;

	if (message_length > strlen(MESSAGE_TO_SIGN)) {
		fail_msg("Truncate (%lu) is longer than the actual message (%lu)",
			message_length, strlen(MESSAGE_TO_SIGN));
		return 0;
	}

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing secret key handle", o->id_str);
		return 1;
	}

	if (o->key_type != CKK_AES) {
		debug_print(" [SKIP %s ] Skip non-AES key", o->id_str);
		return 0;
	}

	if (mech->mech == CKM_AES_CMAC) {
		message = (CK_BYTE *) strndup(MESSAGE_TO_SIGN, message_length);
	} else if (mech->mech == CKM_AES_CMAC_GENERAL) {
		message = (CK_BYTE *) strndup(MESSAGE_TO_SIGN, message_length);
		/* This mechanism requires parameter denoting the requested output length */
		mech->params = &sig_len;
		mech->params_len = sizeof(sig_len);
	} else {
		debug_print(" [SKIP %s ] Unknown mechanism", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Signing message of length %lu using CKM_%s",
		o->id_str, message_length, get_mechanism_name(mech->mech));
	rv = sign_message(o, info, message, message_length, mech, &sign, multipart);
	if (rv <= 0) {
		mech->params = NULL;
		mech->params_len = 0;
		free(message);
		return 1;
	}
	sign_length = (unsigned long) rv;

	debug_print(" [ KEY %s ] Verify message signature", o->id_str);
	rv = verify_message(o, info, message, message_length, mech,
		sign, sign_length, multipart);
	mech->params = NULL;
	mech->params_len = 0;
	free(sign);
	free(message);
	/* the semantics is different in the verify function */
	return rv == 1 ? 0 : 1;
}

void secret_tests(void **state)
{
	unsigned int i;
	size_t j;
	int errors = 0;
	token_info_t *info = (token_info_t *) *state;
	test_certs_t objects;

	test_certs_init(&objects);

	P11TEST_START(info);
	search_for_all_objects(&objects, info);

	/* Make sure to try the pkcs11 functions */
	info->verify_support = 1;
	info->encrypt_support = 1;

	debug_print("Check operations on secret keys.\n");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		if (o->key_type != CKK_AES)
			continue;
		/* Ignore if there is missing private key */
		if (o->private_handle == CK_INVALID_HANDLE)
			continue;

		for (j = 0; j < o->num_mechs; j++) {
			if (o->key_type == CKK_AES) {
				if (o->mechs[j].usage_flags & CKF_SIGN) {
					errors += test_secret_sign_verify(&(objects.data[i]),
					                                  info, &(o->mechs[j]), 42, 0);
				}
				if (o->mechs[j].usage_flags & CKF_DECRYPT) {
					errors += test_secret_encrypt_decrypt(&(objects.data[i]),
					                                      info, &(o->mechs[j]), 42, 0);
				}
			}
		}
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ] [SIGN&VERIFY] [ENC&DECRYPT]\n");
	P11TEST_DATA_ROW(info, 4,
		's', "KEY ID",
		's', "MECHANISM",
		's', "SIGN&VERIFY WORKS",
		's', "ENCRYPT&DECRYPT WORKS");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];

		if (o->key_type != CKK_AES)
			continue;

		printf("\n[%-6s] [%s]\n",
			o->id_str,
			o->label);
		printf("[ %s ] [%6lu] [%s%s] [%s%s]\n",
			"AES ",
			o->bits,
			o->sign ? "[./] " : "[  ] ",
			o->verify ? " [./] " : " [  ] ",
			o->encrypt ? "[./] " : "[  ] ",
			o->decrypt ? " [./] " : " [  ] ");
		if (!o->sign && !o->verify && !o->encrypt && !o->decrypt) {
			printf("  no usable attributes found ... ignored\n");
			continue;
		}
		if (o->private_handle == CK_INVALID_HANDLE) {
			continue;
		}
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *mech = &o->mechs[j];
			if ((mech->usage_flags & (CKF_SIGN|CKF_DECRYPT)) == 0) {
				/* not applicable mechanisms are skipped */
				continue;
			}
			printf("  [ %-11s ] [   %s    ] [   %s    ]\n",
				get_mechanism_name(mech->mech),
				mech->result_flags & FLAGS_SIGN_ANY ? "[./]" : "    ",
				mech->result_flags & FLAGS_DECRYPT_ANY ? "[./]" : "    ");
			if ((mech->result_flags & FLAGS_SIGN_ANY) == 0 &&
				(mech->result_flags & FLAGS_DECRYPT_ANY) == 0)
				continue; /* skip empty rows for export */
			P11TEST_DATA_ROW(info, 4,
				's', o->id_str,
				's', get_mechanism_name(mech->mech),
				's', mech->result_flags & FLAGS_SIGN_ANY ? "YES" : "",
				's', mech->result_flags & FLAGS_DECRYPT_ANY ? "YES" : "");
		}
	}
	printf(" Sign Attribute ----^  ^  ^       ^  ^  ^---- Decrypt Attribute\n");
	printf(" Sign&Verify works ----'  |       |  '------- Enc&Dec works\n");
	printf(" Verify Attribute --------'       '---------- Encrypt Attribute\n");

	clean_all_objects(&objects);
	if (errors > 0)
		P11TEST_FAIL(info, "Not all the secret key operation worked.");
	P11TEST_PASS(info);
}
