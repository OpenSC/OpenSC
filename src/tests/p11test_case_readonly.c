/*
 * p11test_case_readonly.c: Sign & Verify tests
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

#include "p11test_case_readonly.h"

void always_authenticate(test_cert_t *o, token_info_t *info)
{
	CK_RV rv;
	if (!o->always_auth)
		return;

	rv = info->function_pointer->C_Login(info->session_handle,
		CKU_CONTEXT_SPECIFIC, info->pin, info->pin_length);
	if (rv != CKR_OK) {
		debug_print(" [ SKIP %s ] Re-authentication failed", o->id_str);
	}
}

int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_ULONG message_length = strlen((char*) message);
	CK_BYTE dec_message[BUFFER_SIZE];
	CK_ULONG dec_message_length = BUFFER_SIZE;
	unsigned char *enc_message;
	int enc_message_length;

	if ((mech->flags & CKF_DECRYPT) == 0) {
		debug_print(" [ KEY %s ] Skip for encryption for non-supportring mechanism", o->id_str);
		return 0;
	}

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA key for encryption", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Encrypt message", o->id_str);
	enc_message = malloc(RSA_size(o->key.rsa));
	if (enc_message == NULL)
		fail_msg("malloc returned null");

	enc_message_length = RSA_public_encrypt(message_length, message,
		enc_message, o->key.rsa, RSA_PKCS1_PADDING);
	if (enc_message_length < 0) {
		free(enc_message);
		fail_msg("RSA_public_encrypt: rv = 0x%.8X\n", enc_message_length);
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	rv = info->function_pointer->C_DecryptInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		free(enc_message);
		return 0;
	}
	if (rv != CKR_OK)
		fail_msg("C_DecryptInit: rv = 0x%.8X\n", rv);

	always_authenticate(o, info);

	rv = info->function_pointer->C_Decrypt(info->session_handle, enc_message,
		enc_message_length, dec_message, &dec_message_length);
	free(enc_message);
	if (rv != CKR_OK)
		fail_msg("C_Decrypt: rv = 0x%.8X\n", rv);

	dec_message[dec_message_length] = '\0';
	if (memcmp(dec_message, message, dec_message_length) == 0
			&& dec_message_length == message_length) {
		debug_print(" [ OK %s ] Text decrypted successfully.", o->id_str);
		mech->flags |= VERIFY_DECRYPT;
	} else {
		debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
			o->id_str, dec_message);
		return 0;
	}
	return 1;
}

int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
	CK_ULONG message_length)
{
	CK_RV rv;
	CK_MECHANISM sign_mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE *message = (CK_BYTE *)SHORT_MESSAGE_TO_SIGN;
	CK_BYTE *sign = NULL;
	CK_ULONG sign_length = 0;
	unsigned int nlen;
	int dec_message_length;

	if (message_length > strlen((char *)message))
		fail_msg("Truncate is longer than the actual message");

	sign_mechanism.mechanism = mech->mech;
	if (o->type != EVP_PK_EC && o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA and non-EC key", o->id_str);
		return 0;
	}

	debug_print(" [ KEY %s ] Signing message of length %lu", o->id_str, message_length);

	rv = info->function_pointer->C_SignInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [ SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	} else if (rv == CKR_MECHANISM_INVALID) {
		debug_print(" [ SKIP %s ] Bad mechanism. Not supported?", o->id_str);
		return 0;
	} else if (rv != CKR_OK)
		fail_msg("C_SignInit: rv = 0x%.8X\n", rv);

	always_authenticate(o, info);

	/* Call C_Sign with NULL argument to find out the real size of signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK)
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);

	sign = malloc(sign_length);
	if (sign == NULL)
		fail_msg("malloc failed");

	/* Call C_Sign with allocated buffer to the the actual signature */
	rv = info->function_pointer->C_Sign(info->session_handle,
		message, message_length, sign, &sign_length);
	if (rv != CKR_OK) {
		free(sign);
		fail_msg("C_Sign: rv = 0x%.8X\n", rv);
	}

	debug_print(" [ KEY %s ] Verify message sinature", o->id_str);
	dec_message_length = 0;
	if (o->type == EVP_PK_RSA) {
		CK_BYTE dec_message[BUFFER_SIZE];
		dec_message_length = RSA_public_decrypt(sign_length, sign,
			dec_message, o->key.rsa, RSA_PKCS1_PADDING);
		free(sign);
		if (dec_message_length < 0)
			fail_msg("RSA_public_decrypt: rv = %d: %s\n", dec_message_length,
				ERR_error_string(ERR_peek_last_error(), NULL));
		dec_message[dec_message_length] = '\0';
		if (memcmp(dec_message, message, dec_message_length) == 0
				&& dec_message_length == (int) message_length) {
			debug_print(" [ OK %s ] Signature is valid.", o->id_str);
			mech->flags |= VERIFY_SIGN;
		 } else {
			debug_print(" [ ERROR %s ] Signature is not valid. Recovered text: %s",
				o->id_str, dec_message);
			return 0;
		}
	} else if (o->type == EVP_PK_EC) {
		ECDSA_SIG *sig = ECDSA_SIG_new();
		if (sig == NULL)
			fail_msg("ECDSA_SIG_new: failed");
		nlen = sign_length/2;
		BN_bin2bn(&sign[0], nlen, sig->r);
		BN_bin2bn(&sign[nlen], nlen, sig->s);
		free(sign);
		if ((rv = ECDSA_do_verify(message, message_length, sig, o->key.ec)) == 1) {
			debug_print(" [ OK %s ] EC Signature of length %lu is valid.",
				o->id_str, message_length);
			mech->flags |= VERIFY_SIGN;
		} else {
			fail_msg("ECDSA_do_verify: rv = %d: %s\n", rv,
				ERR_error_string(ERR_peek_last_error(), NULL));
		}
		ECDSA_SIG_free(sig);
	} else {
		debug_print(" [ KEY %s ] Unknown type. Not verifying", o->id_str);
		return 0;
	}

	return 1;
}

void readonly_tests(void **state) {

	token_info_t *info = (token_info_t *) *state;
	unsigned int i;
	int used;
	test_certs_t objects;

	objects.count = 0;
	objects.data = NULL;

	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (i = 0; i < objects.count; i++) {
		used = 0;
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		/* XXX some keys do not have appropriate flags, but we can use them
		 * or vice versa */
		//if (objects.data[i].sign && objects.data[i].verify)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= sign_verify_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]), 32);

		//if (objects.data[i].encrypt && objects.data[i].decrypt)
			for (int j = 0; j < objects.data[i].num_mechs; j++)
				used |= encrypt_decrypt_test(&(objects.data[i]), info,
					&(objects.data[i].mechs[j]));

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02lX",
			objects.data[i].id_str, objects.data[i].key_type);
		}
	}

	if (objects.count == 0) {
		printf(" [WARN] No objects to display\n");
		return;
	}

	/* print summary */
	printf("[KEY ID] [TYPE] [SIZE] [PUBLIC] [SIGN&VERIFY] [ENC&DECRYPT] [LABEL]\n");
	for (i = 0; i < objects.count; i++) {
		printf("[%-6s] [%s] [%4lu] [ %s ] [%s%s] [%s%s] [%s]\n",
			objects.data[i].id_str,
			objects.data[i].key_type == CKK_RSA ? "RSA " :
				objects.data[i].key_type == CKK_EC ? " EC " : " ?? ",
			objects.data[i].bits,
			objects.data[i].verify_public == 1 ? " ./ " : "    ",
			objects.data[i].sign ? "[./] " : "[  ] ",
			objects.data[i].verify ? " [./] " : " [  ] ",
			objects.data[i].encrypt ? "[./] " : "[  ] ",
			objects.data[i].decrypt ? " [./] " : " [  ] ",
			objects.data[i].label);
		for (int j = 0; j < objects.data[i].num_mechs; j++)
			printf("         [ %-18s ] [   %s    ] [   %s    ]\n",
				get_mechanism_name(objects.data[i].mechs[j].mech),
				objects.data[i].mechs[j].flags & VERIFY_SIGN ? "[./]" : "    ",
				objects.data[i].mechs[j].flags & VERIFY_DECRYPT ? "[./]" : "    ");
		printf("\n");
	}
	printf(" Public == Cert ----------^       ^  ^  ^       ^  ^  ^\n");
	printf(" Sign Attribute ------------------'  |  |       |  |  '---- Decrypt Attribute\n");
	printf(" Sign&Verify functionality ----------'  |       |  '------- Enc&Dec functionality\n");
	printf(" Verify Attribute ----------------------'       '---------- Encrypt Attribute\n");

	clean_all_objects(&objects);
}
