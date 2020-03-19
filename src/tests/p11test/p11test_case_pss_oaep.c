/*
 * p11test_case_pss_oaep.c: RSA-PSS and RSA-OAEP tests
 *
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "p11test_case_pss_oaep.h"
#include "libopensc/internal.h"

#include <openssl/sha.h>
#include <openssl/evp.h>

#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying. It needs to be little bit longer to fit also longer keys and allow the truncation.\n"
#define BUFFER_SIZE		4096

const unsigned char *global_message = (unsigned char *) SHORT_MESSAGE_TO_SIGN;
size_t global_message_length = sizeof(SHORT_MESSAGE_TO_SIGN);

const CK_MECHANISM_TYPE *
get_oaep_mechanism_hashes(CK_MECHANISM_TYPE mech)
{
	static CK_MECHANISM_TYPE h[6];

	switch (mech) {
	case CKM_RSA_PKCS_OAEP:
		h[0] = CKM_SHA_1;
		h[1] = CKM_SHA224;
		h[2] = CKM_SHA256;
		h[3] = CKM_SHA384;
		h[4] = CKM_SHA512;
		h[5] = -1;
		break;

	default:
		h[0] = -1;
		break;
	}

	return h;
}
const CK_MECHANISM_TYPE *
get_pss_mechanism_hashes(CK_MECHANISM_TYPE mech)
{
	static CK_MECHANISM_TYPE h[6];

	switch (mech) {
	case CKM_RSA_PKCS_PSS:
		h[0] = CKM_SHA_1;
		h[1] = CKM_SHA224;
		h[2] = CKM_SHA256;
		h[3] = CKM_SHA384;
		h[4] = CKM_SHA512;
		h[5] = -1;
		break;

	case CKM_SHA1_RSA_PKCS_PSS:
		h[0] = CKM_SHA_1;
		h[1] = -1;
		break;

	case CKM_SHA224_RSA_PKCS_PSS:
		h[0] = CKM_SHA224;
		h[1] = -1;
		break;

	case CKM_SHA256_RSA_PKCS_PSS:
		h[0] = CKM_SHA256;
		h[1] = -1;
		break;

	case CKM_SHA384_RSA_PKCS_PSS:
		h[0] = CKM_SHA384;
		h[1] = -1;
		break;

	case CKM_SHA512_RSA_PKCS_PSS:
		h[0] = CKM_SHA512;
		h[1] = -1;
		break;

	default:
		h[0] = -1;
		break;
	}

	return h;
}

const CK_MECHANISM_TYPE *
get_mechanism_hashes(CK_MECHANISM_TYPE mech)
{
	if (mech == CKM_RSA_PKCS_OAEP)
		return get_oaep_mechanism_hashes(mech);
	else
		return get_pss_mechanism_hashes(mech);
}

const CK_RSA_PKCS_MGF_TYPE *
get_mgfs(void)
{
	static CK_RSA_PKCS_MGF_TYPE h[6];
	h[0] = CKG_MGF1_SHA1;
	h[1] = CKG_MGF1_SHA224;
	h[2] = CKG_MGF1_SHA256;
	h[3] = CKG_MGF1_SHA384;
	h[4] = CKG_MGF1_SHA512;
	h[5] = -1;
	return h;
}

const EVP_MD *mgf_cryptoki_to_ossl(CK_RSA_PKCS_MGF_TYPE mgf)
{
	switch (mgf) {
	case CKG_MGF1_SHA224:
		return EVP_sha224();

	case CKG_MGF1_SHA256:
		return EVP_sha256();

	case CKG_MGF1_SHA384:
		return EVP_sha384();

	case CKG_MGF1_SHA512:
		return EVP_sha512();

	case CKG_MGF1_SHA1:
	default:
		return EVP_sha1();

	}
}

const EVP_MD *md_cryptoki_to_ossl(CK_MECHANISM_TYPE hash)
{
	/* Digest mechanisms */
	switch (hash) {
	case CKM_SHA224:
		return EVP_sha224();

	case CKM_SHA256:
		return EVP_sha256();

	case CKM_SHA384:
		return EVP_sha384();

	case CKM_SHA512:
		return EVP_sha512();

	case CKM_SHA_1:
	default:
		return EVP_sha1();

	}
}

size_t get_hash_length(CK_MECHANISM_TYPE mech)
{
	switch (mech) {
	case CKM_SHA224:
		return SHA224_DIGEST_LENGTH;
	case CKM_SHA256:
		return SHA256_DIGEST_LENGTH;
	case CKM_SHA384:
		return SHA384_DIGEST_LENGTH;
	case CKM_SHA512:
		return SHA512_DIGEST_LENGTH;
	default:
	case CKM_SHA_1:
		return SHA_DIGEST_LENGTH;
	}
}

CK_BYTE *hash_message(const CK_BYTE *message, size_t message_length,
    CK_MECHANISM_TYPE hash)
{
	switch (hash) {
	case CKM_SHA224:
		return SHA224(message, message_length, NULL);

	case CKM_SHA256:
		return SHA256(message, message_length, NULL);

	case CKM_SHA384:
		return SHA384(message, message_length, NULL);

	case CKM_SHA512:
		return SHA512(message, message_length, NULL);

	case CKM_SHA_1:
	default:
		return SHA1(message, message_length, NULL);

	}
}

int oaep_encrypt_message_openssl(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **enc_message)
{
	size_t enc_length = 0;
	CK_RV rv = -1;
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *md = EVP_md_null();
	const EVP_MD *mgf1_md = EVP_md_null();
	EVP_PKEY *key = NULL;

	md = md_cryptoki_to_ossl(mech->hash);
	mgf1_md = mgf_cryptoki_to_ossl(mech->mgf);

	if ((key = EVP_PKEY_new()) == NULL
		|| RSA_up_ref(o->key.rsa) < 1
		|| EVP_PKEY_set1_RSA(key, o->key.rsa) != 1) {
		fprintf(stderr, " [ ERROR %s ] Failed to initialize EVP_PKEY. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	if ((pctx = EVP_PKEY_CTX_new(key, NULL)) == NULL
		|| EVP_PKEY_encrypt_init(pctx) != 1
		|| EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) != 1
		|| EVP_PKEY_CTX_set_rsa_oaep_md(pctx, md) != 1
		|| EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1_md) != 1) {
		fprintf(stderr, " [ ERROR %s ] Failed to initialize EVP_PKEY_CTX. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	if (EVP_PKEY_encrypt(pctx, NULL, &enc_length, message, message_length) <= 0) {
		fprintf(stderr, " [ ERROR %s ] Failed get signature length. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	*enc_message = OPENSSL_malloc(enc_length);

	rv = EVP_PKEY_encrypt(pctx, *enc_message, &enc_length, message, message_length);
	if (rv <= 0) {
		fprintf(stderr, " [ ERROR %s ] Signature is not valid. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
	}
out:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(key);
	return enc_length;
}

void fill_oaep_params(CK_RSA_PKCS_OAEP_PARAMS *oaep_params,
    test_mech_t *mech)
{
	oaep_params->hashAlg = mech->hash;
	oaep_params->mgf = mech->mgf;
	oaep_params->source = CKZ_DATA_SPECIFIED;
	oaep_params->pSourceData = NULL;
	oaep_params->ulSourceDataLen = 0;

}

int oaep_encrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **enc_message)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM enc_mechanism = { mech->mech, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_ULONG enc_message_length;
	static int encrypt_support = 1;

	fill_oaep_params(&oaep_params, mech);
	enc_mechanism.pParameter = &oaep_params;
	enc_mechanism.ulParameterLen = sizeof(oaep_params);

	if (!encrypt_support)
		goto openssl_encrypt;

	rv = fp->C_EncryptInit(info->session_handle, &enc_mechanism,
		o->public_handle);
	if (rv != CKR_OK) {
		debug_print("   C_EncryptInit: rv = 0x%.8lX", rv);
		encrypt_support = 0; /* avoid trying over and over again */
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
		mech->result_flags |= FLAGS_DECRYPT_OPENSSL;
		return enc_message_length;
	}
	debug_print("   C_Encrypt: rv = 0x%.8lX", rv);

openssl_encrypt:
	debug_print(" [ KEY %s ] Falling back to openssl encryption", o->id_str);
	return oaep_encrypt_message_openssl(o, info, message, message_length, mech,
	    enc_message);
}

int oaep_decrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *enc_message,
    CK_ULONG enc_message_length, test_mech_t *mech, unsigned char **dec_message)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM dec_mechanism = { mech->mech, NULL_PTR, 0 };
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_ULONG dec_message_length = BUFFER_SIZE;

	fill_oaep_params(&oaep_params, mech);
	dec_mechanism.pParameter = &oaep_params;
	dec_mechanism.ulParameterLen = sizeof(oaep_params);

	rv = fp->C_DecryptInit(info->session_handle, &dec_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [SKIP %s ] Not allowed to decrypt with this key?", o->id_str);
		return 0;
	} else if (rv != CKR_OK) {
		debug_print("  C_DecryptInit: rv = 0x%.8lX\n", rv);
		return -1;
	}

	*dec_message = malloc(dec_message_length);

	always_authenticate(o, info);

	rv = fp->C_Decrypt(info->session_handle, enc_message,
		enc_message_length, *dec_message, &dec_message_length);
	if (rv != CKR_OK) {
		free(*dec_message);
		debug_print("  C_Decrypt: rv = 0x%.8lX\n", rv);
		return -1;
	}
	return (int) dec_message_length;
}

/* Perform encryption and decryption of a message using private key referenced
 * in the  o  object with mechanism defined by  mech.
 *
 * NONE of the reasonable mechanisms support encryption/decryption
 *
 * Returns
 *  * 1 for successful Encrypt&Decrypt sequence
 *  * 0 for skipped test (unsupported mechanism, key, ...)
 *  * -1 otherwise.
 *  Serious errors terminate the execution.
 */
int oaep_encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	CK_BYTE *message = (CK_BYTE *) SHORT_MESSAGE_TO_SIGN;
	CK_BYTE *dec_message = NULL;
	int dec_message_length = 0;
	int message_length = 16;
	unsigned char *enc_message = NULL;
	int enc_message_length, rv;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 0;
	}

	if (o->type != EVP_PK_RSA) {
		debug_print(" [ KEY %s ] Skip non-RSA key for encryption", o->id_str);
		return 0;
	}

	if (mech->mech != CKM_RSA_PKCS_OAEP) {
		mech->usage_flags &= ~CKF_DECRYPT;
		debug_print(" [SKIP %s ] non RSA-OAEP mechanism", o->id_str);
		return 0;
	}

	message_length = MIN((int)global_message_length,
		(int)((o->bits+7)/8 - 2*get_hash_length(mech->hash) - 2));

	/* will not work for 1024b RSA key and SHA512 hash: It has max size -2 */
	if (message_length < 0) {
		mech->usage_flags &= ~CKF_DECRYPT;
		debug_print(" [SKIP %s ] Too small modulus (%ld bits)"
			" or too large hash %s (%lu B) for OAEP", o->id_str,
			o->bits, get_mechanism_name(mech->hash),
			get_hash_length(mech->hash));
		return 0;
	}

	debug_print(" [ KEY %s ] Encrypt message of length %d using CKM_%s, "
		"hash CKM_%s, mgf=CKG_%s", o->id_str, (unsigned) message_length,
		get_mechanism_name(mech->mech), get_mechanism_name(mech->hash),
		get_mgf_name(mech->mgf));
	enc_message_length = oaep_encrypt_message(o, info, message,
		(unsigned) message_length, mech, &enc_message);
	if (enc_message_length <= 0) {
		return -1;
	}

	debug_print(" [ KEY %s ] Decrypt message", o->id_str);
	dec_message_length = oaep_decrypt_message(o, info, enc_message,
	    enc_message_length, mech, &dec_message);
	free(enc_message);
	if (dec_message_length <= 0) {
		return -1;
	}

	if (memcmp(dec_message, message, dec_message_length) == 0
			&& dec_message_length == message_length) {
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
	return rv;
}

static int get_max_salt_len(unsigned long bits, CK_MECHANISM_TYPE hash)
{
	return (bits + 7)/8 - get_hash_length(hash) - 2;
}

int fill_pss_params(CK_RSA_PKCS_PSS_PARAMS *pss_params,
    test_mech_t *mech, test_cert_t *o)
{
	pss_params->hashAlg = mech->hash;
	pss_params->mgf = mech->mgf;
	switch (mech->salt){
	case -2:
		/* max possible ( modlen - hashlen -2 ) */
		pss_params->sLen = get_max_salt_len(o->bits,mech->hash);
		break;
	case -1:
		/* digest length */
		/* will not work with SHA512 and 1024b keys (max is 62b!) */
		if ((int) get_hash_length(mech->hash) > get_max_salt_len(o->bits, mech->hash)) {
			return -1;
		}
		pss_params->sLen = get_hash_length(mech->hash);
		break;
	case 0:
	default:
		pss_params->sLen = 0;
		break;
	}
	return 1;
}

int pss_sign_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **sign)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM sign_mechanism = { mech->mech, NULL_PTR, 0 };
	CK_ULONG sign_length = 0;
	CK_RSA_PKCS_PSS_PARAMS pss_params;

	if (fill_pss_params(&pss_params, mech, o) != 1) {
		debug_print(" [SKIP %s ] Impossible to use requested salt length", o->id_str);
		return 0;
	}
	sign_mechanism.pParameter = &pss_params;
	sign_mechanism.ulParameterLen = sizeof(pss_params);

	rv = fp->C_SignInit(info->session_handle, &sign_mechanism,
		o->private_handle);
	if (rv == CKR_KEY_TYPE_INCONSISTENT) {
		debug_print(" [SKIP %s ] Not allowed to sign with this key?", o->id_str);
		return 0;
	} else if (rv == CKR_MECHANISM_INVALID) {
		debug_print(" [SKIP %s ] Bad mechanism. Not supported?", o->id_str);
		return 0;
	} else if (rv != CKR_OK) {
		debug_print("  C_SignInit: rv = 0x%.8lX\n", rv);
		return -1;
	}

	always_authenticate(o, info);

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

	if (rv != CKR_OK) {
		free(*sign);
		fprintf(stderr, "  C_Sign: rv = 0x%.8lX\n", rv);
		return -1;
	}
	return sign_length;
}

int pss_verify_message_openssl(test_cert_t *o, token_info_t *info,
    CK_BYTE *message, CK_ULONG message_length, test_mech_t *mech,
    unsigned char *sign, CK_ULONG sign_length)
{
	CK_RV rv = -1;
	EVP_PKEY_CTX *pctx = NULL;
	const CK_BYTE *my_message;
	CK_ULONG my_message_length;
	const EVP_MD *mgf_md = EVP_md_null();
	const EVP_MD *md = EVP_md_null();
	EVP_PKEY *key = NULL;

	md = md_cryptoki_to_ossl(mech->hash);
	mgf_md = mgf_cryptoki_to_ossl(mech->mgf);

	if (mech->mech != CKM_RSA_PKCS_PSS) {
		my_message = hash_message(message, message_length, mech->hash);
		my_message_length = get_hash_length(mech->hash);
	} else {
		my_message = message;
		my_message_length = message_length;
	}

	if ((key = EVP_PKEY_new()) == NULL
		|| RSA_up_ref(o->key.rsa) < 1
		|| EVP_PKEY_set1_RSA(key, o->key.rsa) != 1) {
		fprintf(stderr, " [ ERROR %s ] Failed to initialize EVP_PKEY. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	if ((pctx = EVP_PKEY_CTX_new(key, NULL)) == NULL
		|| EVP_PKEY_verify_init(pctx) != 1
		|| EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1
		|| EVP_PKEY_CTX_set_signature_md(pctx, md) != 1
		|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, mech->salt) != 1
		|| EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf_md) != 1) {
		fprintf(stderr, " [ ERROR %s ] Failed to initialize EVP_PKEY_CTX. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}

	rv = EVP_PKEY_verify(pctx, sign, sign_length, my_message, my_message_length);
	if (rv == 1) {
		debug_print(" [  OK %s ] Signature is valid.", o->id_str);
		mech->result_flags |= FLAGS_SIGN_OPENSSL;
	 } else {
		fprintf(stderr, " [ ERROR %s ] Signature is not valid. Error: %s\n",
			o->id_str, ERR_error_string(ERR_peek_last_error(), NULL));
		goto out;
	}
out:
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_free(key);
	return rv;
}

int pss_verify_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char *sign,
    CK_ULONG sign_length)
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR fp = info->function_pointer;
	CK_MECHANISM sign_mechanism = { mech->mech, NULL_PTR, 0 };
	CK_RSA_PKCS_PSS_PARAMS pss_params;
	static int verify_support = 1;

	if (!verify_support)
		goto openssl_verify;

	fill_pss_params(&pss_params, mech, o);
	sign_mechanism.pParameter = &pss_params;
	sign_mechanism.ulParameterLen = sizeof(pss_params);

	/* try C_Verify() if it is supported */
	rv = fp->C_VerifyInit(info->session_handle, &sign_mechanism,
		o->public_handle);
	if (rv != CKR_OK) {
		debug_print("   C_VerifyInit: rv = 0x%.8lX", rv);
		verify_support = 0; /* avoid trying over and over again */
		goto openssl_verify;
	}

	rv = fp->C_Verify(info->session_handle,
		message, message_length, sign, sign_length);

	if (rv == CKR_OK) {
		mech->result_flags |= FLAGS_SIGN;
		debug_print(" [  OK %s ] Verification successful", o->id_str);
		return 1;
	}
	debug_print("   C_Verify: rv = 0x%.8lX", rv);
	verify_support = 0; /* avoid trying over and over again */

openssl_verify:
	debug_print(" [ KEY %s ] Falling back to openssl verification", o->id_str);
	return pss_verify_message_openssl(o, info, message, message_length, mech,
		sign, sign_length);
}

/* Perform signature and verification of a message using private key referenced
 * in the  o  object with mechanism defined by  mech.
 *
 * Returns
 *  * 1 for successful Sign&Verify sequence
 *  * 0 for skipped test (unsupported mechanism, key, ...)
 *  * -1 otherwise.
 *  Serious errors terminate the execution.
 */
int pss_sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech)
{
	CK_BYTE *message = NULL;
	size_t message_length = global_message_length;
	CK_BYTE *sign = NULL;
	CK_ULONG sign_length = 0;
	int rv = 0;

	if (o->private_handle == CK_INVALID_HANDLE) {
		debug_print(" [SKIP %s ] Missing private key", o->id_str);
		return 0;
	}

	if (o->type != EVP_PK_RSA) {
		debug_print(" [SKIP %s ] Skip non-RSA key", o->id_str);
		return 0;
	}

	if (!is_pss_mechanism(mech->mech)) {
		mech->usage_flags &= ~CKF_SIGN;
		debug_print(" [SKIP %s ] non RSA-PSS mechanism %s", o->id_str,
			get_mechanism_name(mech->mech));
		return 0;
	}

	if (mech->mech == CKM_RSA_PKCS_PSS) {
		message = hash_message(global_message, global_message_length,
			mech->hash);
		message_length = get_hash_length(mech->hash);
	} else {
		message = (unsigned char *) SHORT_MESSAGE_TO_SIGN;
	}

	debug_print(" [ KEY %s ] Signing message using CKM_%s, CKM_%s,"
		" CKG_%s, salt_len=%d", o->id_str,
		get_mechanism_name(mech->mech), get_mechanism_name(mech->hash),
		get_mgf_name(mech->mgf), mech->salt);
	rv = pss_sign_message(o, info, message, message_length, mech, &sign);
	if (rv <= 0) {
		return rv;
	}
	sign_length = (unsigned long) rv;

	debug_print(" [ KEY %s ] Verify message signature", o->id_str);
	rv = pss_verify_message(o, info, message, message_length, mech,
		sign, sign_length);
	free(sign);
	return rv;
}

/* ignore the prefilled mechanisms and list all combinations of mechanisms
 * found, all resonable hash functions, MGFs and salt lengths
 */
void fill_object_pss_mechanisms(token_info_t *info, test_cert_t *o)
{
	const CK_MECHANISM_TYPE *h;
	const CK_RSA_PKCS_MGF_TYPE *mgf;
	int n = 0, s;
	unsigned int j;

	for (j = 0; j < token.num_rsa_mechs; j++) {
		test_mech_t *source_mech = &token.rsa_mechs[j];

		/* skip non-RSA-PSS mechs early */
		if (!is_pss_mechanism(source_mech->mech) && 
			source_mech->mech != CKM_RSA_PKCS_OAEP) {
			continue;
		}

		h = get_mechanism_hashes(source_mech->mech);
		for (; *h != (CK_MECHANISM_TYPE) -1; h++) {
			mgf = get_mgfs();
			for (; *mgf != (CK_RSA_PKCS_MGF_TYPE) -1; mgf++) {
				/* OAEP does not have salt */
				if (source_mech->mech == CKM_RSA_PKCS_OAEP)
					s = 0;
				else
					s = -2;

				for (; s <= 0; s++) {
					test_mech_t *mech = &o->mechs[n++];
					mech->mech = source_mech->mech;
					mech->hash = *h;
					mech->mgf = *mgf;
					mech->salt = s;
					mech->usage_flags =
						source_mech->usage_flags;
					mech->result_flags = 0;
					if (n >= MAX_MECHS)
						P11TEST_FAIL(info,
							"Too many mechanisms (%d)",
							MAX_MECHS);
				}
			}
		}

	}
	o->num_mechs = n;
}

int have_pss_oaep_mechanisms()
{
	unsigned have = 0, i;
	for (i = 0; i <= token.num_rsa_mechs; i++) {
		if (is_pss_mechanism(token.rsa_mechs[i].mech) ||
			token.rsa_mechs[i].mech == CKM_RSA_PKCS_OAEP) {
				have++;
		}
	}
	return have;
}

void pss_oaep_test(void **state) {

	token_info_t *info = (token_info_t *) *state;
	unsigned int i;
	int used, j;
	test_certs_t objects;

	P11TEST_START(info);

	if (have_pss_oaep_mechanisms() == 0) {
		fprintf(stderr, "Token does not support any RSA-PSS or OAEP mechanisms. Skipping.\n");
		skip();
	}

	objects.count = 0;
	objects.data = NULL;
	search_for_all_objects(&objects, info);

	debug_print("\nCheck functionality of Sign&Verify and/or Encrypt&Decrypt");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];
		/* do the Sign&Verify and/or Encrypt&Decrypt */
		used = 0;
		if (o->private_handle == CK_INVALID_HANDLE) {
			debug_print(" [SKIP %s ] Missing private key",
				o->id_str);
			continue;
		}
		fill_object_pss_mechanisms(info, o);
		for (j = 0; j < o->num_mechs; j++)
			if (o->mechs[j].mech != CKM_RSA_PKCS_OAEP)
				used |= pss_sign_verify_test(o, info,
					&(o->mechs[j]));

		for (j = 0; j < o->num_mechs; j++)
			if (o->mechs[j].mech == CKM_RSA_PKCS_OAEP)
				used |= oaep_encrypt_decrypt_test(o, info,
					&(o->mechs[j]));

		if (!used) {
			debug_print(" [ WARN %s ] Private key with unknown purpose T:%02lX",
			o->id_str, o->key_type);
		}
	}

	if (objects.count == 0) {
		printf(" [WARN] No objects to display\n");
		return;
	}

	/* print summary */
	printf("[KEY ID] [LABEL]\n");
	printf("[ TYPE ] [ SIZE ] [PUBLIC]                               [SIGN&VERIFY] [ENC&DECRYPT]\n");
	printf("[ MECHANISM              ] [ HASH ] [    MGF    ] [SALT] [   WORKS   ] [   WORKS   ]\n");
	P11TEST_DATA_ROW(info, 7,
		's', "KEY ID",
		's', "MECHANISM",
		's', "HASH",
		's', "MGF",
		's', "SALT",
		's', "SIGN&VERIFY WORKS",
		's', "ENCRYPT&DECRYPT WORKS");
	for (i = 0; i < objects.count; i++) {
		test_cert_t *o = &objects.data[i];

		/* Do not go through incomplete pairs */
		if (o->private_handle == CK_INVALID_HANDLE)
			continue;

		/* Do not list non-RSA keys here */
		if (o->type != EVP_PK_RSA)
			continue;

		printf("\n[%-6s] [%s]\n",
			o->id_str,
			o->label);
		printf("[ %s ] [%6lu] [ %s ]                               [%s%s] [%s%s]\n",
			o->key_type == CKK_RSA ? "RSA " :
				o->key_type == CKK_EC ? " EC " : " ?? ",
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
		for (j = 0; j < o->num_mechs; j++) {
			test_mech_t *mech = &o->mechs[j];
			printf("  [ %-20s ] [%-6s] [%-11s] [%4d] [   %s    ] [   %s    ]\n",
				get_mechanism_name(mech->mech),
				get_mechanism_name(mech->hash),
				get_mgf_name(mech->mgf),
				mech->salt,
				mech->result_flags & FLAGS_SIGN_ANY
				? "[./]" : "    ",
				mech->result_flags & FLAGS_DECRYPT_ANY
				? "[./]" : "    ");
			if ((mech->result_flags & FLAGS_SIGN_ANY) == 0 &&
				(mech->result_flags & FLAGS_DECRYPT_ANY) == 0)
				continue; /* skip empty rows for export */
			P11TEST_DATA_ROW(info, 7,
				's', o->id_str,
				's', get_mechanism_name(mech->mech),
				's', get_mechanism_name(mech->hash),
				's', get_mgf_name(mech->mgf),
				'd', mech->salt,
				's', mech->result_flags & FLAGS_SIGN_ANY
				? "YES" : "",
				's', mech->result_flags & FLAGS_DECRYPT_ANY
				? "YES" : "");
		}
	}
	printf(" Public == Cert ----------^                                ^  ^  ^       ^  ^  ^\n");
	printf(" Sign Attribute -------------------------------------------'  |  |       |  |  |\n");
	printf(" Sign&Verify functionality -----------------------------------'  |       |  |  |\n");
	printf(" Verify Attribute -----------------------------------------------'       |  |  |\n");
	printf(" Encrypt Attribute ------------------------------------------------------'  |  |\n");
	printf(" Encrypt & Decrypt functionality -------------------------------------------'  |\n");
	printf(" Decrypt Attribute ------------------------------------------------------------'\n");

	clean_all_objects(&objects);
	P11TEST_PASS(info);
}
