/*
 * p11test_case_readonly.c: Sign & Verify tests
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

#include "p11test_case_readonly.h"

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "libopensc/internal.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/provider.h>
#endif

#define MESSAGE_TO_SIGN "Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n" \
	"Simple message for signing & verifying. " \
	"It needs to be little bit longer to fit also longer keys and allow the truncation.\n"
#define MESSAGE_DIGEST	"\x30\x21\x30\x09\x06\x05\x2b\x0e" \
			"\x03\x02\x1a\x05\x00\x04\x14\xd9" \
			"\xdd\xa3\x76\x44\x2f\x50\xe1\xec" \
			"\xd3\x8b\xcd\x6f\xc6\xce\x4e\xfd" \
			"\xd3\x1a\x3f"
#define BUFFER_SIZE		4096

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
OSSL_PROVIDER *legacy_provider = NULL;
#endif

const unsigned char *const_message = (unsigned char *) MESSAGE_TO_SIGN;

unsigned char *
rsa_x_509_pad_message(const unsigned char *message, unsigned long *message_length, test_cert_t *o, int encrypt)
{
	unsigned long pad_message_length = BYTES4BITS(o->bits);
	unsigned char *pad_message = NULL;
	size_t padding_len = pad_message_length - (*message_length) - 3;

	if (pad_message_length - (*message_length) <= 11) {
		debug_print("Cannot pad message - buffer too small");
		return NULL;
	}
	if ((pad_message = malloc(pad_message_length)) == NULL) {
		fprintf(stderr, "System error: unable to allocate memory\n");
		return NULL;
	}

	pad_message[0] = 0x00;
	pad_message[pad_message_length - 1] = 0x00;
	if (!encrypt) {
		pad_message[1] = 0x01;
		memset(pad_message + 2, 0xff, padding_len);
	} else {
		pad_message[1] = 0x02;
		if (RAND_bytes(pad_message + 2, (int)padding_len) != 1) {
			debug_print("Cannot generate random bytes.");
		}
	}
	memcpy(pad_message + 2 + padding_len, message, (*message_length) * sizeof(unsigned char));

	*message_length = pad_message_length;
	return pad_message;
}

int encrypt_message_openssl(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **enc_message)
{
	int rv = -1, padding;
	size_t outlen = 0;
	EVP_PKEY_CTX *ctx = NULL;

	/* allocate the buffer if none provided */
	if (*enc_message == NULL) {
		outlen = EVP_PKEY_size(o->key);
		*enc_message = malloc(outlen);
		if (*enc_message == NULL) {
			debug_print("malloc returned null");
			return -1;
		}
	}

	/* Prepare padding for RSA_X_509 */
	padding = ((mech->mech == CKM_RSA_X_509) ? RSA_NO_PADDING : RSA_PKCS1_PADDING);

	ctx = EVP_PKEY_CTX_new(o->key, NULL);
	if (!ctx || (rv = EVP_PKEY_encrypt_init(ctx)) <= 0 ||
	    (rv = EVP_PKEY_CTX_set_rsa_padding(ctx, padding)) <= 0 ||
	    (rv = EVP_PKEY_encrypt(ctx, *enc_message, &outlen, message, message_length)) <= 0) {
		free(*enc_message);
		*enc_message = NULL;
		EVP_PKEY_CTX_free(ctx);
		fprintf(stderr, " [ ERROR %s ] OpenSSL encrypt failed: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		return -1;
	}
	EVP_PKEY_CTX_free(ctx);
	return (int)outlen;
}

int encrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **enc_message)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM enc_mechanism = { mech->mech, mech->params, mech->params_len };
	CK_ULONG enc_message_length;

	if (!info->encrypt_support)
		goto openssl_encrypt;

	rv = fp->C_EncryptInit(info->session_handle, &enc_mechanism,
		o->public_handle);
	if (rv != CKR_OK) {
		debug_print("   C_EncryptInit: rv = 0x%.8lX", rv);
		info->encrypt_support = 0; /* avoid trying over and over again */
		goto openssl_encrypt;
	}

	/* get the expected length */
	rv = fp->C_Encrypt(info->session_handle, message, message_length,
	    NULL, &enc_message_length);
	if (rv != CKR_OK) {
		debug_print("   C_Encrypt: rv = 0x%.8lX", rv);
		goto openssl_encrypt;
	}
	*enc_message = malloc(enc_message_length);
	if (*enc_message == NULL) {
		debug_print("malloc returned null");
		return -1;
	}

	/* Do the actual encryption with allocated buffer */
	rv = fp->C_Encrypt(info->session_handle, message, message_length,
		*enc_message, &enc_message_length);
	if (rv == CKR_OK) {
		return (int)enc_message_length;
	}
	debug_print("   C_Encrypt: rv = 0x%.8lX", rv);

openssl_encrypt:
	debug_print(" [ KEY %s ] Falling back to openssl encryption", o->id_str);
	return encrypt_message_openssl(o, info, message, message_length, mech,
	    enc_message);
}

int decrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *enc_message,
    CK_ULONG enc_message_length, test_mech_t *mech, unsigned char **dec_message)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM dec_mechanism = { mech->mech, mech->params, mech->params_len };
	CK_ULONG dec_message_length = BUFFER_SIZE;

	rv = fp->C_DecryptInit(info->session_handle, &dec_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		return 0;
	} else if (rv != CKR_OK) {
		debug_print("C_DecryptInit: rv = 0x%.8lX\n", rv);
		return -1;
	}

	*dec_message = malloc(dec_message_length);

	always_authenticate(o, info);

	rv = fp->C_Decrypt(info->session_handle, enc_message,
		enc_message_length, *dec_message, &dec_message_length);
	if (rv != CKR_OK) {
		free(*dec_message);
		*dec_message = NULL;
		debug_print("  C_Decrypt: rv = 0x%.8lX\n", rv);
		return -1;
	}
	return (int) dec_message_length;
}

/* Perform encryption and decryption of a message using private key referenced
 * in the  o  object with mechanism defined by  mech.
 *
 * NONE of the reasonable mechanisms support multipart encryption/decryption
 *
 * Returns
 *  * 1 for successful Encrypt&Decrypt sequence
 *  * 0 for skipped test (unsupported mechanism, key, ...)
 *  * -1 otherwise.
 *  Serious errors terminate the execution.
 */
int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
	CK_ULONG message_length, int multipart)
{
	CK_BYTE *message = NULL;
	CK_BYTE *dec_message = NULL;
	int dec_message_length = 0;
	unsigned char *enc_message = NULL;
	int enc_message_length, rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 0;
	}

	if (o->type != EVP_PKEY_RSA) {
		debug_print(" [SKIP %s ] Skip non-RSA key for encryption", o->id_str);
		return 0;
	}

	if (mech->mech == CKM_RSA_PKCS_OAEP) {
		mech->usage_flags &= ~CKF_DECRYPT;
		debug_print(" [SKIP %s ] RSA-OAEP tested separately", o->id_str);
		return 0;
	}

	if (mech->mech != CKM_RSA_X_509 && mech->mech != CKM_RSA_PKCS) {
		debug_print(" [ KEY %s ] Skip encryption for non-supported mechanism %s",
			o->id_str, get_mechanism_name(mech->mech));
		return 0;
	}

	if (mech->mech == CKM_RSA_X_509) {
		if ((message = rsa_x_509_pad_message(const_message,
			&message_length, o, 1)) == NULL) {
			debug_print(" [SKIP %s ] Could not pad message", o->id_str);
			return -1;
		}
	} else {
		message = (CK_BYTE *) strdup(MESSAGE_TO_SIGN);
	}


	debug_print(" [ KEY %s ] Encrypt message using CKM_%s",
		o->id_str, get_mechanism_name(mech->mech));
	enc_message_length = encrypt_message(o, info, message, message_length,
	    mech, &enc_message);
	if (enc_message_length <= 0) {
		free(enc_message);
		free(message);
		return -1;
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	dec_message_length = decrypt_message(o, info, enc_message,
	    enc_message_length, mech, &dec_message);
	free(enc_message);
	if (dec_message_length <= 0) {
		free(message);
		return -1;
	}

	if ((unsigned int) dec_message_length == message_length &&
	    memcmp(dec_message, message, dec_message_length) == 0) {
		debug_print(" [  OK %s ] Text decrypted successfully.", o->id_str);
		mech->result_flags |= FLAGS_DECRYPT;
		rv = 1;
	} else {
		dec_message[dec_message_length] = '\0';
		debug_print(" [ ERROR %s ] Text decryption failed. Recovered text: %s",
			o->id_str, dec_message);
		rv = 0;
	}
	free(dec_message);
	free(message);
	return rv;
}

int sign_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **sign,
    int multipart)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM sign_mechanism = { mech->mech, mech->params, mech->params_len };
	CK_ULONG sign_length = 0;
	char *name;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!legacy_provider) {
		if (!(legacy_provider = OSSL_PROVIDER_try_load(NULL, "legacy", 1))) {
			debug_print(" [SKIP %s ] Failed to load legacy provider", o->id_str);
			return 0;
		}
	}
#endif
	rv = fp->C_SignInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	} else if (rv == CKR_MECHANISM_INVALID) {
		debug_print(" [SKIP %s ] Bad mechanism. Not supported?", o->id_str);
		return 0;
	} else if (rv != CKR_OK) {
		debug_print(" [SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	}

	always_authenticate(o, info);

	if (multipart) {
		unsigned long part = message_length / 3;
		rv = fp->C_SignUpdate(info->session_handle, message, part);
		if (rv == CKR_MECHANISM_INVALID) {
			fprintf(stderr, "  Multipart Signature not supported with CKM_%s\n",
				get_mechanism_name(mech->mech));
			return -1;
		} else if (rv != CKR_OK) {
			fprintf(stderr, "  C_SignUpdate: rv = 0x%.8lX\n", rv);
			return -1;
		}
		rv = fp->C_SignUpdate(info->session_handle, message + part, message_length - part);
		if (rv != CKR_OK) {
			fprintf(stderr, "  C_SignUpdate: rv = 0x%.8lX\n", rv);
			return -1;
		}
		/* Call C_SignFinal with NULL argument to find out the real size of signature */
		rv = fp->C_SignFinal(info->session_handle, *sign, &sign_length);
		if (rv != CKR_OK) {
			fprintf(stderr, "  C_SignFinal: rv = 0x%.8lX\n", rv);
			return -1;
		}

		*sign = malloc(sign_length);
		if (*sign == NULL) {
			fprintf(stderr, "%s: malloc failed", __func__);
			return -1;
		}

		/* Call C_SignFinal with allocated buffer to the actual signature */
		rv = fp->C_SignFinal(info->session_handle, *sign, &sign_length);
		name = "C_SignFinal";
	} else {
		/* Call C_Sign with NULL argument to find out the real size of signature */
		rv = fp->C_Sign(info->session_handle,
			message, message_length, *sign, &sign_length);
		if (rv != CKR_OK) {
			fprintf(stderr, "  C_Sign: rv = 0x%.8lX\n", rv);
			return -1;
		}

		*sign = malloc(sign_length);
		if (*sign == NULL) {
			fprintf(stderr, "%s: malloc failed", __func__);
			return -1;
		}

		/* Call C_Sign with allocated buffer to the actual signature */
		rv = fp->C_Sign(info->session_handle,
			message, message_length, *sign, &sign_length);
		name = "C_Sign";
	}
	if (rv != CKR_OK) {
		free(*sign);
		fprintf(stderr, "  %s: rv = 0x%.8lX\n", name, rv);
		return -1;
	}
	return (int)sign_length;
}

int verify_message_openssl(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char *sign,
    CK_ULONG sign_length)
{
	CK_RV rv;
	CK_BYTE *cmp_message = NULL;
	unsigned int cmp_message_length = 0;

	if (o->type == EVP_PKEY_RSA) {
		const EVP_MD *md = NULL;
		EVP_MD_CTX *mdctx = NULL;
		EVP_PKEY_CTX *ctx = NULL;
		int padding = RSA_PKCS1_PADDING;

		/* Digest mechanisms */
		switch (mech->mech) {
		case CKM_RSA_X_509:
			padding = RSA_NO_PADDING;
			/* fall through */
		case CKM_RSA_PKCS:
			if ((ctx = EVP_PKEY_CTX_new(o->key, NULL)) == NULL ||
			    (rv = EVP_PKEY_verify_init(ctx)) <= 0 ||
			    (rv = EVP_PKEY_CTX_set_rsa_padding(ctx, padding)) <= 0 ||
			    (rv = EVP_PKEY_verify(ctx, sign, sign_length, message, message_length)) != 1) {
				fprintf(stderr, " [ ERROR %s ] Signature is not valid. Error: %s\n",
					o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
				EVP_PKEY_CTX_free(ctx);
				return -1;
			}
			mech->result_flags |= FLAGS_SIGN_OPENSSL;
			debug_print(" [  OK %s ] Signature is valid.", o->id_str);
			EVP_PKEY_CTX_free(ctx);
			return 1;
			break;
		case CKM_SHA1_RSA_PKCS:
			md = EVP_sha1();
			break;
		case CKM_SHA224_RSA_PKCS:
			md = EVP_sha224();
			break;
		case CKM_SHA256_RSA_PKCS:
			md = EVP_sha256();
			break;
		case CKM_SHA384_RSA_PKCS:
			md = EVP_sha384();
			break;
		case CKM_SHA512_RSA_PKCS:
			md = EVP_sha512();
			break;
		case CKM_SHA3_224_RSA_PKCS:
			md = EVP_sha3_224();
			break;
		case CKM_SHA3_256_RSA_PKCS:
			md = EVP_sha3_256();
			break;
		case CKM_SHA3_384_RSA_PKCS:
			md = EVP_sha3_384();
			break;
		case CKM_SHA3_512_RSA_PKCS:
			md = EVP_sha3_512();
			break;
		case CKM_MD5_RSA_PKCS:
			md = EVP_md5();
			break;
		case CKM_RIPEMD160_RSA_PKCS:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			if (!legacy_provider) {
				if (!(legacy_provider = OSSL_PROVIDER_try_load(NULL, "legacy", 1))) {
					debug_print(" [SKIP %s ] Failed to load legacy provider", o->id_str);
					return 0;
				}
			}
#endif
			md = EVP_ripemd160();
			break;
		default:
			debug_print(" [SKIP %s ] Skip verify of unknown mechanism", o->id_str);
			return 0;
		}

		if ((mdctx = EVP_MD_CTX_new()) == NULL ||
		    (rv = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, o->key) <= 0) ||
		    (rv = EVP_DigestVerify(mdctx, sign, sign_length, message, message_length)) != 1) {
			fprintf(stderr, " [ ERROR %s ] Signature is not valid. Error: %s\n",
				o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
			EVP_MD_CTX_free(mdctx);
			return -1;
		}
		mech->result_flags |= FLAGS_SIGN_OPENSSL;
		debug_print(" [  OK %s ] Signature is valid.", o->id_str);
		EVP_MD_CTX_free(mdctx);
		return 1;
	} else if (o->type == EVP_PKEY_EC) {
		int nlen;
		const EVP_MD *md = NULL;
		ECDSA_SIG *sig = ECDSA_SIG_new();
		BIGNUM *r = NULL, *s = NULL;
		EVP_PKEY_CTX *ctx = NULL;
		ctx = EVP_PKEY_CTX_new(o->key, NULL);

		if (!sig || !ctx) {
			fprintf(stderr, "Verification failed");
			EVP_PKEY_CTX_free(ctx);
			ECDSA_SIG_free(sig);
			return -1;
		}
		nlen = (int)sign_length / 2;
		r = BN_bin2bn(&sign[0], nlen, NULL);
		s = BN_bin2bn(&sign[nlen], nlen, NULL);
		ECDSA_SIG_set0(sig, r, s);

		switch (mech->mech) {
		case CKM_ECDSA_SHA512:
			md = EVP_sha512();
			break;
		case CKM_ECDSA_SHA384:
			md = EVP_sha384();
			break;
		case CKM_ECDSA_SHA256:
			md = EVP_sha256();
			break;
		case CKM_ECDSA_SHA1:
			md = EVP_sha1();
			break;
		case CKM_ECDSA:
			cmp_message = message;
			cmp_message_length = (unsigned)message_length;
			break;
		case CKM_ECDSA_SHA3_224:
			md = EVP_sha3_224();
			break;
		case CKM_ECDSA_SHA3_256:
			md = EVP_sha3_256();
			break;
		case CKM_ECDSA_SHA3_384:
			md = EVP_sha3_384();
			break;
		case CKM_ECDSA_SHA3_512:
			md = EVP_sha3_512();
			break;
		default:
			debug_print(" [SKIP %s ] Skip verify of unknown mechanism", o->id_str);
			EVP_PKEY_CTX_free(ctx);
			ECDSA_SIG_free(sig);
			return 0;
		}
		int sig_asn1_len = 0;
		unsigned char *sig_asn1 = NULL;
		sig_asn1_len = i2d_ECDSA_SIG(sig, &sig_asn1);
		ECDSA_SIG_free(sig);

		if (md != NULL) {
			cmp_message = malloc(EVP_MAX_MD_SIZE);
			if (cmp_message == NULL) {
				fprintf(stderr, "malloc failed\n");
				return -1;
			}
			rv = EVP_Digest(message, message_length, cmp_message, &cmp_message_length, md, NULL);
			if (rv != 1) {
				fprintf(stderr, "EVP_Digest failed\n");
				free(cmp_message);
				return -1;
			}
		}

		if (EVP_PKEY_verify_init(ctx) != 1) {
			fprintf(stderr, "EVP_PKEY_verify_init\n");
			free(cmp_message);
			return -1;
		}

		rv = EVP_PKEY_verify(ctx, sig_asn1, sig_asn1_len, cmp_message, cmp_message_length);
		OPENSSL_free(sig_asn1);
		if (md != NULL) {
			free(cmp_message);
		}
		EVP_PKEY_CTX_free(ctx);
		if (rv == 1) {
			debug_print(" [  OK %s ] EC Signature of length %lu is valid.",
				o->id_str, message_length);
			mech->result_flags |= FLAGS_SIGN_OPENSSL;
			return 1;
		} else {
			fprintf(stderr, " [FAIL %s ] EVP_PKEY_verify: rv = %lu: %s\n", o->id_str,
				rv, ERR_error_string(ERR_peek_last_error(), NULL));
			return -1;
		}
#ifdef EVP_PKEY_ED25519
	} else if (o->type == EVP_PKEY_ED25519) {
		/* need to be created even though we do not do any MD */
		EVP_MD_CTX *ctx = EVP_MD_CTX_create();

		rv = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, o->key);
		if (rv != 1) {
			fprintf(stderr, " [FAIL %s ] EVP_DigestVerifyInit: rv = %lu: %s\n", o->id_str,
				rv, ERR_error_string(ERR_peek_last_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return -1;
		}

		rv = EVP_DigestVerify(ctx, sign, sign_length, message, message_length);
		if (rv == 1) {
			debug_print(" [  OK %s ] EdDSA Signature of length %lu is valid.",
				o->id_str, message_length);
			mech->result_flags |= FLAGS_SIGN_OPENSSL;
			EVP_MD_CTX_free(ctx);
			return 1;
		} else {
			fprintf(stderr, " [FAIL %s ] EVP_DigestVerifyInit: rv = %lu: %s\n", o->id_str,
				rv, ERR_error_string(ERR_peek_last_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return -1;
		}
#endif
	} else {
		fprintf(stderr, " [ KEY %s ] Unknown type. Not verifying\n", o->id_str);
	}
	return 0;
}

int verify_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char *sign,
    CK_ULONG sign_length, int multipart)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM sign_mechanism = { mech->mech, NULL_PTR, 0 };
	static int verify_support = 1;
	char *name;

	if (!verify_support)
		goto openssl_verify;

	/* try C_Verify() if it is supported */
	rv = fp->C_VerifyInit(info->session_handle, &sign_mechanism,
		o->public_handle);
	if (rv != CKR_OK) {
		debug_print("   C_VerifyInit: rv = 0x%.8lX", rv);
		verify_support = 0; /* avoid trying over and over again */
		goto openssl_verify;
	}
	if (multipart) {
		unsigned long part = message_length / 3;
		/* First part */
		rv = fp->C_VerifyUpdate(info->session_handle, message, part);
		if (rv != CKR_OK) {
			debug_print("   C_VerifyUpdate: rv = 0x%.8lX", rv);
			goto openssl_verify;
		}
		/* Second part */
		rv = fp->C_VerifyUpdate(info->session_handle, message + part,
		    message_length - part);
		if (rv != CKR_OK) {
			debug_print("   C_VerifyUpdate: rv = 0x%.8lX", rv);
			goto openssl_verify;
		}
		/* Final */
		rv = fp->C_VerifyFinal(info->session_handle,
			sign, sign_length);
		name = "C_VerifyFinal";
	} else {
		rv = fp->C_Verify(info->session_handle,
			message, message_length, sign, sign_length);
		name = "C_Verify";
	}
	if (rv == CKR_OK) {
		mech->result_flags |= FLAGS_SIGN;
		debug_print(" [  OK %s ] [PKCS11] Verification successful", o->id_str);
		return 1;
	}
	debug_print("   %s: rv = 0x%.8lX", name, rv);
	verify_support = 0; /* avoid trying over and over again */

openssl_verify:
	debug_print(" [ KEY %s ] Falling back to openssl verification", o->id_str);
	return verify_message_openssl(o, info, message, message_length, mech,
		sign, sign_length);
}

/* Perform signature and verification of a message using private key referenced
 * in the  o  object with mechanism defined by  mech. Message length can be
 * specified using argument  message_length.
 *
 * Returns
 *  * 1 for successful Sign&Verify sequence
 *  * 0 for skipped test (unsupported mechanism, key, ...)
 *  * -1 otherwise.
 *  Serious errors terminate the execution.
 */
int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
    CK_ULONG message_length, int multipart)
{
	CK_BYTE *message = NULL;
	CK_BYTE *sign = NULL;
	CK_ULONG sign_length = 0;
	int rv = 0;

	if (message_length > strlen(MESSAGE_TO_SIGN)) {
		fail_msg("Truncate is longer than the actual message");
		return -1;
	}

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 0;
	}

	if (o->type != EVP_PKEY_EC && o->type != EVP_PKEY_RSA
#ifdef EVP_PKEY_ED25519
			&& o->type != EVP_PKEY_ED25519
#endif
			) {
		debug_print(" [SKIP %s ] Skip non-RSA and non-EC key", o->id_str);
		return 0;
	}

	if (is_pss_mechanism(mech->mech)) {
		mech->usage_flags &= ~CKF_SIGN;
		debug_print(" [SKIP %s ] RSA-PSS tested separately", o->id_str);
		return 0;
	}

	if (mech->mech == CKM_RSA_X_509) /* manually add padding */
		message = rsa_x_509_pad_message(const_message,
			&message_length, o, 0);
	else if (mech->mech == CKM_RSA_PKCS) {
		/* DigestInfo + SHA1(message) */
		message_length = 35;
		message = malloc(message_length * sizeof(unsigned char));
		memcpy(message, MESSAGE_DIGEST, message_length);
	} else
		message = (CK_BYTE *) strdup(MESSAGE_TO_SIGN);

	debug_print(" [ KEY %s ] Signing message of length %lu using CKM_%s",
		o->id_str, message_length, get_mechanism_name(mech->mech));
	rv = sign_message(o, info, message, message_length, mech, &sign, multipart);
	if (rv <= 0) {
		free(message);
		return rv;
	}
	sign_length = (unsigned long) rv;

	debug_print(" [ KEY %s ] Verify message signature", o->id_str);
	rv = verify_message(o, info, message, message_length, mech,
		sign, sign_length, multipart);
	free(sign);
	free(message);
	return rv;
}

void readonly_tests(void **state) {

	token_info_t *info = (token_info_t *) *state;
	unsigned int i;
	int used;
	size_t j;
	test_certs_t objects;

	test_certs_init(&objects);

	search_for_all_objects(&objects, info);

	P11TEST_START(info);
	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		used = 0;
		if (o->private_handle == CK_INVALID_HANDLE) {
			debug_print(" [SKIP %s ] Missing private key", o->id_str);
			continue;
		}
		/* XXX some keys do not have appropriate flags, but we can use them
		 * or vice versa */
		// if (o->sign && o->verify)
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *m = &(objects.data[i].mechs[j]);
			if ((m->usage_flags & CKF_SIGN) == 0) {
				/* Skip non-signature mechanisms (for example derive ones) */
				continue;
			}
			used |= sign_verify_test(o, info, m, 32, 0);
		}

		// if (o->encrypt && o->decrypt)
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *m = &(objects.data[i].mechs[j]);
			if ((m->usage_flags & CKF_DECRYPT) == 0) {
				/* Skip non-decrypt mechanisms (for example derive ones) */
				continue;
			}
			used |= encrypt_decrypt_test(o, info, m, 32, 0);
		}

		if (!used) {
			debug_print(" [WARN %s ] Private key with unknown purpose T:%02lX", o->id_str,
					o->key_type);
		}
	}

	if (objects.count == 0) {
		printf(" [WARN] No objects to display\n");
		return;
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ] [PUBLIC] [SIGN&VERIFY] [ENC&DECRYPT]\n");
	P11TEST_DATA_ROW(info, 4,
		's', "KEY ID",
		's', "MECHANISM",
		's', "SIGN&VERIFY WORKS",
		's', "ENCRYPT&DECRYPT WORKS");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];

		if (o->key_type != CKK_RSA &&
		    o->key_type != CKK_EC &&
		    o->key_type != CKK_EC_EDWARDS &&
		    o->key_type != CKK_EC_MONTGOMERY)
			continue;

		printf("\n[%-6s] [%s]\n",
			o->id_str,
			o->label);
		printf("[ %s ] [%6lu] [ %s ] [%s%s] [%s%s]\n",
			(o->key_type == CKK_RSA ? "RSA " :
				o->key_type == CKK_EC ? " EC " :
				o->key_type == CKK_EC_EDWARDS ? "EC_E" :
				o->key_type == CKK_EC_MONTGOMERY ? "EC_M" : " ?? "),
			o->bits,
			o->verify_public == 1 ? " ./ " : "    ",
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
			printf("  [ %-20s ] [   %s    ] [   %s    ]\n",
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
	printf(" Public == Cert -----^       ^  ^  ^       ^  ^  ^\n");
	printf(" Sign Attribute -------------'  |  |       |  |  '---- Decrypt Attribute\n");
	printf(" Sign&Verify functionality -----'  |       |  '------- Enc&Dec functionality\n");
	printf(" Verify Attribute -----------------'       '---------- Encrypt Attribute\n");

	clean_all_objects(&objects);
	P11TEST_PASS(info);
}
