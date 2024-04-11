/*
 * Copyright (C) 2011-2018 Frank Morgner
 * Copyright (C) 2023 Douglas E. Engert <deengert@gmail.com>
 *
 * This file is part of OpenSC.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sm-iso.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/internal.h"
//#include "cardctl.h"
//#include "simpletlv.h"

#include "sm-nist.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM) && !defined(OPENSSL_NO_EC) && !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
#else
#undef ENABLE_NIST_SM
#endif

#if defined(ENABLE_NIST_SM) && defined(ENABLE_SM)
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>

#define PIV_PAIRING_CODE_LEN     8

/* 800-73-4 Cipher Suite Table 14 */
#define PIV_CS_CS2              0x27
#define PIV_CS_CS7              0x2E

#ifdef USE_OPENSSL3_LIBCTX
#define PIV_LIBCTX card->ctx->ossl3ctx->libctx
#else
#define PIV_LIBCTX NULL
#endif

	/* Table 14 and other constants */
	typedef struct cipher_suite {
		u8 id; /* taken from AID "AC" tag */
		int field_length;
		int nid;     /* for OpenSSL curves */
		struct sc_object_id oid; /* for opensc */
		int p1;	     /* for APDU */
		size_t Qlen; /* size of pubkey 04||x||y for all keys */
		size_t AuthCryptogramlen; /* both H and ICC must match */
		size_t Zlen; /* size of shared secret from ECDH */
		size_t otherinfolen; /* used in 4.1.6  Key Derivation */

		int o0len; /* first in otherinfo */
		u8 o0_char;
		size_t IDshlen;
		size_t CBhlen;
		size_t T16Qehlen;
		size_t IDsicclen;
		size_t Nicclen;
		size_t CBicclen; /* last in otherinfo */

		int naeskeys; /* number of aes key generated */
		int aeskeylen; /* size of aes key bytes*/
		int kdf_hash_size; /* size of hash in bytes */
		EVP_MD *(*kdf_md)(void);
		const EVP_CIPHER *(*cipher_cbc)(void);
		const EVP_CIPHER *(*cipher_ecb)(void);
		char *cipher_cbc_name;
		char *cipher_ecb_name;
		char *curve_group; /* curve name TODO or is this just p-256 or p-384?*/
	} cipher_suite_t;

// clang-fromat off
#define PIV_CSS_SIZE 2
static cipher_suite_t css[PIV_CSS_SIZE] = {
		{PIV_CS_CS2, 256, NID_X9_62_prime256v1, {{1, 2, 840, 10045, 3, 1, 7, -1}},
		PIV_CS_CS2, 65, 16, 32, 61,
		4, 0x09, 8, 1, 16, 8, 16, 1,
		4, 128/8, SHA256_DIGEST_LENGTH,
		(EVP_MD *(*)(void)) EVP_sha256,
		(const EVP_CIPHER *(*)(void)) EVP_aes_128_cbc,
		(const EVP_CIPHER *(*)(void)) EVP_aes_128_ecb,
		"aes-128-cbc", "aes-128-ecb",
		"prime256v1"},

		{PIV_CS_CS7, 384, NID_secp384r1, {{1, 3, 132, 0, 34, -1}},
		PIV_CS_CS7, 97, 16, 48, 69,
		4, 0x0D, 8, 1, 16, 8, 24, 1,
		4, 256/8, SHA384_DIGEST_LENGTH,
		(EVP_MD *(*)(void)) EVP_sha384,
		(const EVP_CIPHER *(*)(void)) EVP_aes_256_cbc,
		(const EVP_CIPHER *(*)(void)) EVP_aes_256_ecb,
		"aes-256-cbc", "aes-256-ecb",
		"secp384r1"}
	};
// clang-format on

/* 800-73-4  4.1.5 Card Verifiable Certificates */
typedef struct piv_cvc {
	sc_pkcs15_der_t der;					// Previous read der
	int cpi;						// Certificate profile indicator (0x80)
	char issuerID[8];					// Issuer Identification Number
	size_t issuerIDlen;					//  8 bytes of sha-1 or 16 byte for GUID
	u8  subjectID[16];					//  Subject Identifier (8) or GUID (16)  == CHUI
	size_t subjectIDlen;					//  8 bytes of sha-1 or 16 byte for GUID
	struct sc_object_id pubKeyOID;				// Public key algorithm object identifier
	u8 *publicPoint;					// Public point for ECC
	size_t publicPointlen;
	int roleID;						// Role Identifier 0x00 or 0x12
	u8 *body;						// signed part of CVC in DER
	size_t bodylen;
	struct sc_object_id  signatureAlgOID;			// Signature Algroithm Identifier
	u8 *signature;						// Certificate signature DER
	size_t signaturelen;
} piv_cvc_t;

#define PIV_SM_MAX_FIELD_LENGTH  384
#define PIV_SM_MAX_MD_LENGTH	SHA384_DIGEST_LENGTH

/* 800-73-4 3.3.2 Discovery Object - PIN Usage Policy */
#define PIV_PP_PIN              0x00004000u
#define PIV_PP_GLOBAL           0x00002000u
#define PIV_PP_OCC              0x00001000u
#define PIV_PP_VCI_IMPL         0x00000800u
#define PIV_PP_VCI_WITHOUT_PC   0x00000400u
#define PIV_PP_PIV_PRIMARY      0x00000010u
#define PIV_PP_GLOBAL_PRIMARY   0x00000020u

typedef struct piv_sm_session {
	/* set by piv_sm_open */
	int aes_size; /* 128 or 256 */

	u8 SKcfrm[32];
	u8 SKmac[32];
	u8 SKenc[32];  /* keys are either AES 128 or AES 256 */
	u8 SKrmac[32];
	u8 enc_counter[16];
	u8 enc_counter_last[16];

	u8 resp_enc_counter[16];
	u8 C_MCV[16];
	u8 C_MCV_last[16];
	u8 R_MCV[16];
	u8 R_MCV_last[16];
} piv_sm_session_t;

#define C_ASN1_PIV_CVC_PUBKEY_SIZE 3
	/* ECC key only */
static const struct sc_asn1_entry c_asn1_piv_cvc_pubkey[C_ASN1_PIV_CVC_PUBKEY_SIZE] = {
	{ "publicKeyOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "publicPoint", SC_ASN1_OCTET_STRING, SC_ASN1_CTX | 6, SC_ASN1_OPTIONAL | SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_DSOBJ_SIZE 2
static const struct sc_asn1_entry c_asn1_piv_cvc_dsobj[C_ASN1_PIV_CVC_DSOBJ_SIZE] = {
	{ "DigitalSignature", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_DSSIG_SIZE 3
static const struct sc_asn1_entry c_asn1_piv_cvc_dssig[C_ASN1_PIV_CVC_DSSIG_SIZE] = {
	{ "signatureAlgorithmID", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_TAG_SEQUENCE, 0, NULL, NULL },
	{ "signatureValue", SC_ASN1_BIT_STRING_NI, SC_ASN1_TAG_BIT_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_ALG_ID_SIZE 3
static const struct sc_asn1_entry c_asn1_piv_cvc_alg_id[C_ASN1_PIV_CVC_ALG_ID_SIZE] = {
	{ "signatureAlgorithmOID", SC_ASN1_OBJECT, SC_ASN1_UNI | SC_ASN1_OBJECT, 0, NULL, NULL },
	{ "nullParam",  SC_ASN1_NULL, SC_ASN1_UNI | SC_ASN1_TAG_NULL, SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#define C_ASN1_PIV_CVC_BODY_SIZE 7
static const struct sc_asn1_entry c_asn1_piv_cvc_body[C_ASN1_PIV_CVC_BODY_SIZE] = {
	{ "certificateProfileIdentifier", SC_ASN1_INTEGER, SC_ASN1_APP | 0x1F29, 0, NULL, NULL },
	{ "Issuer ID Number", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 2, 0, NULL, NULL },
	{ "Subject Identifier", SC_ASN1_OCTET_STRING, SC_ASN1_APP | 0x1F20, 0, NULL, NULL },
	{ "publicKey", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F49, 0, NULL, NULL },
	{ "roleIdentifier", SC_ASN1_CALLBACK, SC_ASN1_APP | 0x1F4C, 0, NULL, NULL },
	/* signature is over the above 5 entries  treat roleIdentifier special to get end */
	{ "DSignatureObject", SC_ASN1_STRUCT, SC_ASN1_APP | 0x1F37, SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};


#define C_ASN1_PIV_CVC_SIZE 2
static const struct sc_asn1_entry c_asn1_piv_cvc[C_ASN1_PIV_CVC_SIZE] = {
	{ "CVC certificate", SC_ASN1_STRUCT, SC_ASN1_CONS | SC_ASN1_APP | 0x1F21, 0, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#if 0
#define C_ASN1_PIV_SM_RESPONSE_SIZE 4
static const struct sc_asn1_entry c_asn1_sm_response[C_ASN1_PIV_SM_RESPONSE_SIZE] = {
	{ "encryptedData",      SC_ASN1_CALLBACK,   SC_ASN1_CTX | 7,        SC_ASN1_OPTIONAL,       NULL, NULL },
	{ "statusWord",         SC_ASN1_CALLBACK,   SC_ASN1_CTX | 0x19,     0,                      NULL, NULL },
	{ "mac",                SC_ASN1_CALLBACK,   SC_ASN1_CTX | 0x0E,     0,                      NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};
#endif /* 0 */

#if 0
/*
 * SW internal apdu response table.
 *
 * Override APDU response error codes from iso7816.c to allow
 * handling of SM specific error
 */
static const struct sc_card_error piv_sm_errors[] = {
	{0x6882, SC_ERROR_SM, "SM not supported"},
	{0x6982, SC_ERROR_SM_NO_SESSION_KEYS, "SM Security status not satisfied"}, /* no session established */
	{0x6987, SC_ERROR_SM, "Expected SM Data Object missing"},
	{0x6988, SC_ERROR_SM_INVALID_SESSION_KEY, "SM Data Object incorrect"}, /* other process interference */
	{0, 0, NULL}
};
#endif /* 0 */

/* TODO not the same piv_private_data as in card-piv.c */
/* needs name changed and added to sm-nist.h */
typedef struct piv_private_data {
	int magic;
	cipher_suite_t *cs; /* active cypher_suite */
	u8 csID;
	X509 *signer_cert;
	piv_cvc_t sm_cvc;  /* 800-73-4:  SM CVC Table 15 */
	piv_cvc_t sm_in_cvc; /* Intermediate CVC Table 16 */
	unsigned long *sm_flags; /* flags shared with caller */
	unsigned long pin_policy;
	unsigned char pairing_code[PIV_PAIRING_CODE_LEN]; /* 8 ASCII digits */
	piv_sm_session_t sm_session;
} piv_private_data_t;

//TODO fix to look at iso_sm_ctx  priv data
#define ISO_CTX_FROM_CARD ((struct iso_sm_ctx *)card->sm_ctx.info.cmd_data)
#define PIV_PRIV_FROM_CARD ((piv_private_data_t *)((struct iso_sm_ctx *)card->sm_ctx.info.cmd_data)->priv_data)
#define PIV_PRIV_FROM(isoctx) ((piv_private_data_t *)((struct iso_sm_ctx *)isoctx)->priv_data)

static int nist_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc);
static int nist_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data);
static int nist_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **outdata);
static int nist_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *mac, size_t maclen,
		const u8 *macdata, size_t macdatalen);
static int nist_sm_pre_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu);
static int nist_sm_post_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *sm_apdu);
static int nist_sm_finish(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu);
static void nist_sm_clear_free(const struct iso_sm_ctx *ctx);

static void piv_inc(u8 *counter, size_t size);
//static int piv_encode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu);
//static int piv_get_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu);
//static int piv_free_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu);
static int piv_get_asn1_obj(sc_context_t *ctx, void *arg,  const u8 *obj, size_t len, int depth);
static int piv_sm_open(struct sc_card *card);
//static int piv_decode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu);
// TODO is piv_sm_close needed
// static int piv_sm_close(sc_card_t *card);
static void piv_clear_cvc_content(piv_cvc_t *cvc);
static void piv_clear_sm_session(piv_sm_session_t *session);
static int piv_decode_cvc(sc_card_t * card, u8 **buf, size_t *buflen, piv_cvc_t *cvc);
// TODO   static int piv_parse_pairing_code(sc_card_t *card, const char *option);
static int Q2OS(int fsize, u8 *Q, size_t Qlen, u8 * OS, size_t *OSlen);
// TODO comment for now static int piv_send_vci_pairing_code(struct sc_card *card, u8 *paring_code);
static int piv_sm_verify_sig(struct sc_card *card, const EVP_MD *type,
		EVP_PKEY *pkey, u8 *data, size_t data_size,
		unsigned char *sig, size_t siglen);
static int piv_sm_verify_certs(struct sc_card *card);


/* convert q as 04||x||y used in standard point formats to expanded leading
 * zeros and concatenated X||Y as specified in SP80056A Appendix C.2
 * Field-Element-to-Byte-String Conversion which
 * OpenSSL has already converted X and Y to big endian and skipped leading
 * zero bytes.
 */
static int Q2OS(int fsize, u8 *Q, size_t Qlen, u8 * OS, size_t *OSlen)
{
	size_t i;
	size_t f = fsize/8;

	i = (Qlen - 1)/2;

	if (!OS || *OSlen < f * 2 || !Q || i > f)
		return SC_ERROR_INTERNAL;

	memset(OS, 0, f * 2);
	/* Check this if x and y have leading zero bytes,
	 * In UNCOMPRESSED FORMAT, x and Y must be same length, to tell when
	 * one ends and the other starts */
	memcpy(OS + f - i, Q + 1, i);
	memcpy(OS + 2 * f - i, Q + f + 1, i);
	*OSlen = f * 2;
	return 0;
}

#if 0
/*  TODO Should card driver do thisa?  */
/*
 * if needed, send VCI pairing code to card just after the
 * SM key establishment. Called from piv_sm_open under same lock
 */
static int piv_send_vci_pairing_code(struct sc_card *card, u8 *paring_code)
{
	int r;
	piv_private_data_t * priv = PIV_PRIV_FROM_CARD;
	struct iso_sm_ctx *ctx = NULL;
	sc_apdu_t plain;
	sc_apdu_t sm_apdu;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	priv = (piv_private_data_t *)((struct iso_sm_ctx *)card->sm_ctx.info.cmd_data)->priv_data;

	if (priv->pin_policy & PIV_PP_VCI_WITHOUT_PC)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS); /* Not needed */

	if ((priv->pin_policy & PIV_PP_VCI_IMPL) == 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NO_CARD_SUPPORT);

	sc_format_apdu(card, &plain, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x98);
	plain.datalen = plain.lc = 8;
	plain.data = paring_code;
	plain.resp = NULL;
	plain.resplen = plain.le = 0;
//TODO Needs work to send with or without SM
	memset(&sm_apdu,0,sizeof(sm_apdu));
	/* build sm_apdu and set alloc sm_apdu.resp */
	r = piv_encode_apdu(card, &plain, &sm_apdu);
	if (r < 0) {
		free(sm_apdu.resp);
		sc_log(card->ctx, "piv_encode_apdu failed");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	sm_apdu.flags |= SC_APDU_FLAGS_NO_SM; /* run as is */
	r = sc_transmit_apdu(card, &sm_apdu);
	if (r < 0) {
		free(sm_apdu.resp);
		sc_log(card->ctx, "transmit failed");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	r = piv_decode_apdu(card, &plain, &sm_apdu);
	free(sm_apdu.resp);
	LOG_TEST_RET(card->ctx, r, "piv_decode_apdu failed");
	r = sc_check_sw(card, plain.sw1, plain.sw2);
	if (r < 0)
		r = SC_ERROR_PIN_CODE_INCORRECT;

	LOG_FUNC_RETURN(card->ctx, r);
}
#endif /* TODO */

/* Verify one signature using pubkey */
static int piv_sm_verify_sig(struct sc_card *card, const EVP_MD *type,
		EVP_PKEY *pkey,
		u8 *data, size_t data_size,
		unsigned char *sig, size_t siglen)
{
	piv_private_data_t * priv = PIV_PRIV_FROM_CARD;
	cipher_suite_t *cs = priv->cs;
	int r = 0;
	EVP_MD_CTX *md_ctx = NULL;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (cs == NULL) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if ((md_ctx = EVP_MD_CTX_new()) == NULL
			|| EVP_DigestVerifyInit(md_ctx, NULL, type, NULL, pkey) != 1
			|| EVP_DigestVerifyUpdate(md_ctx, data, data_size) != 1
			|| EVP_DigestVerifyFinal(md_ctx, sig, siglen) != 1) {
		sc_log (card->ctx, "EVP_DigestVerifyFinal failed");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	r = SC_SUCCESS;
err:
	EVP_MD_CTX_free(md_ctx);
	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 * If sm_in_cvc is present, verify PIV_OBJ_SM_CERT_SIGNER signed sm_in_cvc
 * and sm_in_cvc signed sm_cvc.
 * If sm_in_cvc is not present verify PIV_OBJ_SM_CERT_SIGNER signed sm_cvc.
 */


static int piv_sm_verify_certs(struct sc_card *card)
{
	piv_private_data_t * priv = PIV_PRIV_FROM_CARD;
	cipher_suite_t *cs = priv->cs;
	int r = 0;
//	u8 *cert_blob = NULL; /* do not free */
//	size_t cert_bloblen = 0;

//	u8 *rbuf; /* do not free*/
//	size_t rbuflen;
	EVP_PKEY *cert_pkey =  NULL; /* do not free */
	EVP_PKEY *in_cvc_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP *in_cvc_group = NULL;
	EC_POINT *in_cvc_point = NULL;
	EC_KEY *in_cvc_eckey = NULL;
#else
	EVP_PKEY_CTX *in_cvc_pkey_ctx = NULL;
	OSSL_PARAM params[3];
	size_t params_n;
#endif

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* TODO if already verified we could return
	 * may need to verify again, if card reset?
	 */

	if (cs == NULL) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/*
	 * Get the PIV_OBJ_SM_CERT_SIGNER and optional sm_in_cvc
	 * which were passed 
	 */
	*priv->sm_flags |= PIV_SM_FLAGS_SM_CERT_SIGNER_PRESENT; /* set for debugging */

	if (priv->signer_cert == NULL || (cert_pkey = X509_get0_pubkey(priv->signer_cert)) == NULL) {
		sc_log(card->ctx,"OpenSSL failed to get pubkey from SM_CERT_SIGNER");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* if intermediate sm_in_cvc present, cert signed it and sm_cvc is signed by sm_in_cvc */
	if (*priv->sm_flags & PIV_SM_FLAGS_SM_IN_CVC_PRESENT) {
		r = piv_sm_verify_sig(card, cs->kdf_md(), cert_pkey,
				priv->sm_in_cvc.body, priv->sm_in_cvc.bodylen,
				priv->sm_in_cvc.signature,priv->sm_in_cvc.signaturelen);
		if (r < 0) {
			sc_log(card->ctx,"sm_in_cvc signature invalid");
			r =  SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if ((in_cvc_group = EC_GROUP_new_by_curve_name(cs->nid)) == NULL
				|| (in_cvc_pkey = EVP_PKEY_new()) == NULL
				|| (in_cvc_eckey = EC_KEY_new_by_curve_name(cs->nid)) == NULL
				|| (in_cvc_point = EC_POINT_new(in_cvc_group)) == NULL
				|| EC_POINT_oct2point(in_cvc_group, in_cvc_point,
					priv->sm_in_cvc.publicPoint, priv->sm_in_cvc.publicPointlen, NULL) <= 0
				|| EC_KEY_set_public_key(in_cvc_eckey, in_cvc_point) <= 0
				|| EVP_PKEY_set1_EC_KEY(in_cvc_pkey, in_cvc_eckey) != 1) {
			sc_log(card->ctx, "OpenSSL failed to set EC pubkey, during verify");
			sc_log_openssl(card->ctx);
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
#else
		params_n = 0;
		params[params_n++] = OSSL_PARAM_construct_utf8_string("group", cs->curve_group, 0);
		params[params_n++] = OSSL_PARAM_construct_octet_string("pub",
				priv->sm_in_cvc.publicPoint, priv->sm_in_cvc.publicPointlen);
		params[params_n] = OSSL_PARAM_construct_end();

		if (!(in_cvc_pkey_ctx = EVP_PKEY_CTX_new_from_name(PIV_LIBCTX, "EC", NULL))
				|| !EVP_PKEY_fromdata_init(in_cvc_pkey_ctx)
				|| !EVP_PKEY_fromdata(in_cvc_pkey_ctx, &in_cvc_pkey, EVP_PKEY_PUBLIC_KEY, params)
				|| !in_cvc_pkey) {
			sc_log(card->ctx, "OpenSSL failed to set EC pubkey, during verify");
			sc_log_openssl(card->ctx);
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
#endif
		r = piv_sm_verify_sig(card, cs->kdf_md(), in_cvc_pkey,
				priv->sm_cvc.body, priv->sm_cvc.bodylen,
				priv->sm_cvc.signature,priv->sm_cvc.signaturelen);

	} else { /* cert signed  sm_cvc */
		r = piv_sm_verify_sig(card, cs->kdf_md(), cert_pkey,
				priv->sm_cvc.body, priv->sm_cvc.bodylen,
				priv->sm_cvc.signature,priv->sm_cvc.signaturelen);
	}
	if (r < 0) {
		sc_log(card->ctx,"sm_cvc signature invalid");
		r =  SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* cert chain signatures match for oncard certs */
	/* TODO check dates and other info as per 800-73-4 */

	/* TODO check against off card CA chain if present,
	 * Need opensc.conf options:
	 *	where is CA cert chain?
	 *	is it required?
	 *	check for revocation?
	 *	How often to check for revocation?
	 *	When is SM used?
	 *		Using NFC?
	 *			(yes, main point of using SM)
	 *		Should reading certificates be done in clear?
	 *			(performance vs security)
	 *		All crypto operations and PIN ?
	 *			(yes for security)
	 */
err:

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP_free(in_cvc_group);
	EC_POINT_free(in_cvc_point);
	EC_KEY_free(in_cvc_eckey);
#else
	EVP_PKEY_CTX_free(in_cvc_pkey_ctx);
#endif
	EVP_PKEY_free(in_cvc_pkey);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int piv_sm_general_io(sc_card_t *card, int ins, int p1, int p2,
	const u8 * sendbuf, size_t sendbuflen, u8 *recvbuf,
	size_t recvbuflen)
{
	int r;
	sc_apdu_t apdu;
	int saved_sm_mode = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(card->ctx, r);

	sc_format_apdu(card, &apdu,
			recvbuf ? SC_APDU_CASE_4_SHORT: SC_APDU_CASE_3_SHORT,
			ins, p1, p2);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

//	if (card->sm_ctx.sm_mode != SM_MODE_NONE) {
		/* tell apdu.c to not do the chaining, let the SM get_apdu do it */
		apdu.flags |= SC_APDU_FLAGS_SM_CHAINING;
//	}


	apdu.lc = sendbuflen;
	apdu.datalen = sendbuflen;
	apdu.data = sendbuf;

	if (recvbuf && recvbuflen) {
		apdu.le = (recvbuflen > 256) ? 256 : recvbuflen;
		apdu.resplen = recvbuflen;
	} else {
		apdu.le = 0;
		apdu.resplen = 0;
	}
	apdu.resp =  recvbuf;

	saved_sm_mode = card->sm_ctx.sm_mode;
//	if (card->sm_ctx.sm_mode != SM_MODE_NONE) {
//		card->sm_ctx.sm_mode = SM_MODE_NONE;
//	}

	/* with new adpu.c and chaining, this actually reads the whole object */
	r = sc_transmit_apdu(card, &apdu);

	
	/* adpu will not have sw1,sw2 set because sc_sm_single_transmit called sc_sm_stop, */
	if (r < 0) {
		sc_log(card->ctx, "Transmit failed");
		goto err;
	}

	card->sm_ctx.sm_mode = saved_sm_mode;

	if (apdu.sw1 == 0x69 && apdu.sw2 ==  0x88)
		r = SC_ERROR_SM_INVALID_SESSION_KEY;
	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0) {
		sc_log(card->ctx,  "Card returned error ");
		goto err;
	}

	r = (int)apdu.resplen;

err:
	sc_unlock(card);
	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * NIST SP800-73-4  4.1 The key Establishment Protocol
 * Variable names and Steps  are based on Client Application (h)
 * and PIV Card Application (icc)
 * Capital leters used for variable, and lower case for subscript names
 */
 // TODO is sctx or priv needed here?
static int piv_sm_open(struct sc_card *card)
{
	piv_private_data_t * priv = PIV_PRIV_FROM_CARD;
//	struct iso_sm_ctx *sctx = NULL;
	cipher_suite_t *cs = priv->cs;
	int r = 0;
	int i;
	int reps;
	u8 CBh;
	u8 CBicc;
	u8 *p;

	/* ephemeral EC key */
	EVP_PKEY_CTX *eph_ctx = NULL;
	EVP_PKEY *eph_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *eph_eckey = NULL; /* don't free _get0_*/
	const EC_GROUP *eph_group = NULL; /* don't free _get0_ */
#else
	OSSL_PARAM eph_params[5];
	size_t eph_params_n;
	size_t Qehxlen = 0;
	u8 *Qehx = NULL;
#endif
	size_t Qehlen = 0;
	u8 Qeh[2 * PIV_SM_MAX_FIELD_LENGTH/8 + 1]; /*  big enough for 384 04||x||y  if x and y have leading zeros, length may be less */
	size_t Qeh_OSlen = 0;
	u8 Qeh_OS[2 * PIV_SM_MAX_FIELD_LENGTH/8]; /* no leading 04, with leading zeros in X and Y */
	size_t Qsicc_OSlen = 0;
	u8 Qsicc_OS[2 * PIV_SM_MAX_FIELD_LENGTH/8]; /* no leading 04, with leading zeros  in X and Y */

	/* pub EC key from card Cicc in sm_cvc */
	EVP_PKEY_CTX *Cicc_ctx = NULL;
	EVP_PKEY *Cicc_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *Cicc_eckey = NULL;
	EC_POINT *Cicc_point = NULL;
	EC_GROUP *Cicc_group = NULL;
#endif

	/* shared secret key Z */
	EVP_PKEY_CTX *Z_ctx = NULL;
	u8 *Z = NULL;
	size_t Zlen = 0;

	u8  IDsh[8] = {0};
	unsigned long  pid;

	u8 *sbuf = NULL;
	size_t sbuflen;
	int len2a, len2b;

	u8 rbuf[4096];
	size_t rbuflen = sizeof(rbuf);

	const u8 *body, *payload;
	size_t bodylen, payloadlen;
	u8 Nicc[24]; /* nonce */
	u8 AuthCryptogram[16];

	u8 *cvcder = NULL;
	size_t cvclen = 0;
	size_t len; /* temp len */

	u8 *kdf_in = NULL;
	size_t kdf_inlen = 0;
	unsigned int hashlen = 0;
	u8 aeskeys[SHA384_DIGEST_LENGTH * 3] = {0}; /*  4 keys, Hash function is run 2 or 3 times max is 3 * 384/8 see below */
	EVP_MD_CTX *hash_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *cmac_ctx = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n = 0;
	OSSL_PARAM Cicc_params[3];
	size_t Cicc_params_n = 0;
#endif

	u8 IDsicc[8]; /* will only use 8 bytes for step H6 */

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/*
	 * The SM routines try and call this on their own.
	 * This routine should only be called by the card driver.
	 * which has set PIV_SM_FLAGS_DEFER_OPEN and unset in
	 * in reader_lock_obtained
	 * after testing PIC applet is active so SM is setup in same transaction
	 * as the command we are trying to run with SM.
	 * this avoids situation where the SM is established, and then reset by
	 * some other application without getting anything done or in
	 * a loop, each trying to reestablish a SM session and run command.
	 */

	 
	if (!(*priv->sm_flags & PIV_SM_FLAGS_DEFER_OPEN)) {
		LOG_FUNC_RETURN(card->ctx,SC_ERROR_NOT_ALLOWED);
	}
	if (cs == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	sc_lock(card);

	/* use for several hash operations */
	if ((hash_ctx = EVP_MD_CTX_new()) == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* Step 1 set CBh = 0 */
	CBh = 0;

	/* Step H2 generate ephemeral EC */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if ((eph_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL
			|| EVP_PKEY_keygen_init(eph_ctx) <= 0
			|| EVP_PKEY_CTX_set_ec_paramgen_curve_nid(eph_ctx, cs->nid) <= 0
			|| EVP_PKEY_keygen(eph_ctx, &eph_pkey) <= 0
			|| (eph_eckey = EVP_PKEY_get0_EC_KEY(eph_pkey)) == NULL
			|| (eph_group = EC_KEY_get0_group(eph_eckey)) == NULL
			|| (Qehlen = EC_POINT_point2oct(eph_group, EC_KEY_get0_public_key(eph_eckey),
				POINT_CONVERSION_UNCOMPRESSED, NULL, Qehlen, NULL)) <= 0 /* get length */
			|| Qehlen > cs->Qlen
			|| (Qehlen = EC_POINT_point2oct(eph_group, EC_KEY_get0_public_key(eph_eckey),
				POINT_CONVERSION_UNCOMPRESSED, Qeh, Qehlen, NULL)) <= 0
			|| Qehlen > cs->Qlen) {
		sc_log(card->ctx,"OpenSSL failed to create ephemeral EC key");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	/* generate Qeh */
	eph_params_n = 0;
	eph_params[eph_params_n++] = OSSL_PARAM_construct_utf8_string( "group", cs->curve_group, 0);
	eph_params[eph_params_n++] = OSSL_PARAM_construct_utf8_string( "point-format","uncompressed", 0);
	eph_params[eph_params_n] = OSSL_PARAM_construct_end();
	if (!(eph_ctx = EVP_PKEY_CTX_new_from_name(PIV_LIBCTX, "EC", NULL))  /* TODO should be FIPS */
			|| !EVP_PKEY_keygen_init(eph_ctx)
			|| !EVP_PKEY_CTX_set_params(eph_ctx, eph_params)
			|| !EVP_PKEY_generate(eph_ctx, &eph_pkey)
			|| !(Qehxlen = EVP_PKEY_get1_encoded_public_key(eph_pkey, &Qehx))
			|| !Qehx
			|| Qehxlen > cs->Qlen
			) {
		sc_log(card->ctx,"OpenSSL failed to create ephemeral EC key");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	memcpy(Qeh, Qehx, Qehxlen);
	Qehlen = Qehxlen;
#endif

	/* For later use, get  Qeh without 04 and full size  X || Y */
	Qeh_OSlen = sizeof(Qeh_OS);
	if (Q2OS(cs->field_length, Qeh, Qehlen, Qeh_OS, &Qeh_OSlen)) {
		sc_log(card->ctx,"Q2OS for Qeh failed");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = len2a = sc_asn1_put_tag(0x81, NULL, 1 + cs->IDshlen + Qehlen, NULL, 0, NULL);
	if (r < 0)
		goto err;
	r = len2b = sc_asn1_put_tag(0x80, NULL, 0, NULL, 0, NULL);
	if (r < 0)
		goto err;
	r = sbuflen = sc_asn1_put_tag(0x7C, NULL, len2a + len2b, NULL, 0, NULL);
	if (r < 0)
		goto err;

	sbuf = malloc(sbuflen);
	if (sbuf == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	p = sbuf;

	r =  sc_asn1_put_tag(0x7C, NULL, len2a + len2b, sbuf, sbuflen, &p);
	if (r != SC_SUCCESS)
		goto err;

	r = sc_asn1_put_tag(0x81, NULL, 1 + cs->IDshlen + Qehlen, p, sbuflen - (p - sbuf), &p);
	if (r != SC_SUCCESS)
		goto err;

	/* Step H1 set CBh to 0x00 */
	*p++ = CBh;

#ifdef WIN32
	pid = (unsigned long) GetCurrentProcessId();
#else
	pid = (unsigned long) getpid(); /* use PID as our ID so different from other processes */
#endif
	memcpy(IDsh, &pid, MIN(sizeof(pid), cs->IDshlen));
	memcpy(p, IDsh, cs->IDshlen);
	p += cs->IDshlen;
	memcpy(p, Qeh, Qehlen);
	p += Qehlen;

	r = sc_asn1_put_tag(0x82, NULL, 0, p, sbuflen - (p - sbuf), &p); /* null data */
	if (r != SC_SUCCESS)
		goto err;

	/* Step H3 send CBh||IDsh|| Qeh  Qeh in 04||x||y */
	/* Or call sc_transmit directly */

	r = piv_sm_general_io(card, 0x87, cs->p1, 0x04, sbuf, (p - sbuf), rbuf, rbuflen);
	if (r <= 0)
		goto err;

	rbuflen = r;
	p = rbuf;

	body = sc_asn1_find_tag(card->ctx, rbuf, rbuflen, 0x7C, &bodylen);
	if (body == NULL || bodylen < 20 || rbuf[0] != 0x7C) {
		sc_log(card->ctx, "SM response data to short");
		r = SC_ERROR_SM_NO_SESSION_KEYS;
		goto err;
	}

	payload = sc_asn1_find_tag(card->ctx, body, bodylen, 0x82, &payloadlen);
	if (payload == NULL || payloadlen < 1 + cs->Nicclen + cs->AuthCryptogramlen || *body != 0x82) {
		sc_log(card->ctx, "SM response data to short");
		r = SC_ERROR_SM_NO_SESSION_KEYS;
		goto err;
	}

	/* payload is CBicc (1) || Nicc (16 or 24) || AuthCryptogram (CMAC 16 or 16) ||Cicc (variable) */
	p = (u8 *) payload;

	/* Step H4 check CBicc == 0x00 */
	CBicc = *p++;
	if  (CBicc != 0x00) { /* CBicc must be  zero */
		sc_log(card->ctx, "SM card did not accept request");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	memcpy(Nicc, p, cs->Nicclen);
	p += cs->Nicclen;

	memcpy(AuthCryptogram, p, cs->AuthCryptogramlen);
	p += cs->AuthCryptogramlen;

	if (p > payload + payloadlen) {
		sc_log(card->ctx, "SM card CVC is to short");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
	cvclen = len = payloadlen - (p - payload);
	if (len) {
		cvcder = p; /* in rbuf */

		r = piv_decode_cvc(card, &p, &len, &priv->sm_cvc);
		if (r != SC_SUCCESS) {
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
		*priv->sm_flags |= PIV_SM_FLAGS_SM_CVC_PRESENT;
	}

	/* Step H5 Verify Cicc CVC and pubkey */
	/* Verify Cicc (sm_cvc) is signed by sm_in_cvc or PIV_OBJ_SM_CERT_SIGNER  */
	/* sm_in_cvc is signed by PIV_OBJ_SM_CERT_SIGNER */

	/* Verify the cert chain is valid. */
	r = piv_sm_verify_certs(card);
	if (r < 0) {
		sc_log(card->ctx, "SM  piv_sm_verify_certs r:%d", r);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* Step H6  need left most 8 bytes of hash of sm_cvc */
	{
		u8 hash[SHA256_DIGEST_LENGTH] = {0};
		const u8* tag;
		size_t taglen;
		const u8* tmpder;
		size_t tmpderlen;

		if ((tag = sc_asn1_find_tag(card->ctx, cvcder, cvclen, 0x7F21, &taglen)) == NULL
				|| *cvcder != 0x7F || *(cvcder + 1) != 0x21) {

			r = SC_ERROR_INTERNAL;
			goto err;
		}

		/* debug choice */
		tmpder =  cvcder;
		tmpderlen = cvclen;

		if (EVP_DigestInit(hash_ctx,EVP_sha256()) != 1
				|| EVP_DigestUpdate(hash_ctx, tmpder, tmpderlen) != 1
				|| EVP_DigestFinal_ex(hash_ctx, hash, NULL) != 1) {
			sc_log(card->ctx,"IDsicc hash failed");
			sc_log_openssl(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		memcpy(IDsicc, hash, sizeof(IDsicc)); /* left 8 bytes */
	}

	/* Step H7 get the cards public key Qsicc into OpenSSL Cicc_eckey */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if ((Cicc_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL
			|| (Cicc_group = EC_GROUP_new_by_curve_name(cs->nid)) == NULL
			|| (Cicc_pkey = EVP_PKEY_new()) == NULL
			|| (Cicc_eckey = EC_KEY_new_by_curve_name(cs->nid)) == NULL
			|| (Cicc_point = EC_POINT_new(Cicc_group)) == NULL
			|| EC_POINT_oct2point(Cicc_group, Cicc_point,
				priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen, NULL) <= 0
			|| EC_KEY_set_public_key(Cicc_eckey, Cicc_point) <= 0
			|| EVP_PKEY_set1_EC_KEY(Cicc_pkey, Cicc_eckey) <= 0) {
		sc_log(card->ctx,"OpenSSL failed to get card's EC pubkey");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	Cicc_params_n = 0;
	Cicc_params[Cicc_params_n++] = OSSL_PARAM_construct_utf8_string( "group", cs->curve_group, 0);
	Cicc_params[Cicc_params_n++] = OSSL_PARAM_construct_octet_string("pub",
			priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen);
	Cicc_params[Cicc_params_n] = OSSL_PARAM_construct_end();

	if (!(Cicc_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL))
			|| !EVP_PKEY_fromdata_init(Cicc_ctx)
			|| !EVP_PKEY_fromdata(Cicc_ctx, &Cicc_pkey, EVP_PKEY_PUBLIC_KEY, Cicc_params)
			|| !Cicc_pkey) {
		sc_log(card->ctx, "OpenSSL failed to set EC pubkey for Cicc");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#endif

	/* Qsicc without 04 and expanded x||y */
	Qsicc_OSlen = sizeof(Qsicc_OS);
	if (Q2OS(cs->field_length, priv->sm_cvc.publicPoint, priv->sm_cvc.publicPointlen, Qsicc_OS, &Qsicc_OSlen)) {
		sc_log(card->ctx,"Q2OS for Qsicc failed");
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* Step H8 Compute the shared secret Z */
	if ((Z_ctx = EVP_PKEY_CTX_new(eph_pkey, NULL)) == NULL
			|| EVP_PKEY_derive_init(Z_ctx) <= 0
			|| EVP_PKEY_derive_set_peer(Z_ctx, Cicc_pkey) <= 0
			|| EVP_PKEY_derive(Z_ctx, NULL, &Zlen) <= 0
			|| Zlen != cs->Zlen
			|| (Z = malloc(Zlen)) == NULL
			|| EVP_PKEY_derive(Z_ctx, Z, &Zlen) <= 0
			|| Zlen != cs->Zlen) {
		sc_log(card->ctx,"OpenSSL failed to create secret Z");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	sc_log(card->ctx, "debug Zlen:%"SC_FORMAT_LEN_SIZE_T"u Z[0]:0x%2.2x", Zlen, Z[0]);

	/* Step H9 zeroize deh from step H2 */
	EVP_PKEY_free(eph_pkey); /* OpenSSL  BN_clear_free calls OPENSSL_cleanse */
	eph_pkey = NULL;

	/* Step H10 Create AES session Keys */
	/* kdf in is 4byte counter || Z || otherinfo  800-56A 5.8.1 */

	kdf_inlen = 4 + Zlen + cs->otherinfolen;
	kdf_in = malloc(kdf_inlen);
	if (kdf_in == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	p = kdf_in;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x00;
	*p++ = 0x01;
	memcpy(p, Z, cs->Zlen);
	p += Zlen;

	/* otherinfo */
	*p++ = cs->o0len;
	for (i = 0; i <  cs->o0len; i++)
		*p++ = cs->o0_char; /* 0x09 or 0x0d */

	*p++ = cs->IDshlen;
	memcpy(p, IDsh, cs->IDshlen);
	p += cs->IDshlen;

	*p++ = cs->CBhlen;
	memcpy(p, &CBh, cs->CBhlen);
	p += cs->CBhlen;

	*p++ = cs->T16Qehlen;
	/* First 16 bytes of Qeh without 04 800-56A Appendix C.2 */
	memcpy(p, Qeh_OS, cs->T16Qehlen);
	p += cs->T16Qehlen;

	*p++ = cs->IDsicclen;
	memcpy(p, IDsicc, cs->IDsicclen);
	p += cs->IDsicclen;

	*p++ = cs->Nicclen;
	memcpy(p, Nicc, cs->Nicclen);
	p += cs->Nicclen;

	*p++ = cs->CBicclen;
	memcpy(p, &CBicc, cs->CBicclen);
	p += cs->CBicclen;

	if (p != kdf_in + kdf_inlen) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* 4 keys needs reps =  ceil (naeskeys * aeskeylen) / kdf_hash_size) */
	/* 800-56A-2007, 5.8.1 Process and 800-56C rev 3 2018 4.1 Process. */
	/* so it is 2 times for 128 or 3 times for 256 bit AES keys */
	p = aeskeys; /* 4 keys + overflow */
	reps = (cs->naeskeys * cs->aeskeylen + cs->kdf_hash_size - 1) / (cs->kdf_hash_size);

	EVP_MD_CTX_reset(hash_ctx);
	for (i = 0; i < reps; i++) {
		if (EVP_DigestInit(hash_ctx,(*cs->kdf_md)()) != 1
				|| EVP_DigestUpdate(hash_ctx, kdf_in, kdf_inlen) != 1
				|| EVP_DigestFinal_ex(hash_ctx, p, &hashlen) != 1) {
			sc_log(card->ctx,"KDF hash failed");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		kdf_in[3]++;  /* inc the counter */
		p += cs->kdf_hash_size;
	}

	/* copy keys used for APDU */
	memset(&priv->sm_session, 0, sizeof(piv_sm_session_t)); /* clear */
	priv->sm_session.aes_size = cs->aeskeylen;
	memcpy(&priv->sm_session.SKcfrm, &aeskeys[cs->aeskeylen * 0], cs->aeskeylen);
	memcpy(&priv->sm_session.SKmac, &aeskeys[cs->aeskeylen * 1], cs->aeskeylen);
	memcpy(&priv->sm_session.SKenc, &aeskeys[cs->aeskeylen * 2], cs->aeskeylen);
	memcpy(&priv->sm_session.SKrmac, &aeskeys[cs->aeskeylen * 3], cs->aeskeylen);
	sc_mem_clear(&aeskeys, sizeof(aeskeys));

	priv->sm_session.enc_counter[15] = 0x01;
	priv->sm_session.resp_enc_counter[0] = 0x80;
	priv->sm_session.resp_enc_counter[15] = 0x01;
	/* C_MCV is zero */
	/* R_MCV is zero */

	/*  Step H11 Zeroize Z (and kdf_in which has Z) */
	if (Z && Zlen) {
		sc_mem_clear(Z, Zlen);
		free(Z);
		Z=NULL;
		Zlen = 0;
	}
	if (kdf_in && kdf_inlen) {
		sc_mem_clear(kdf_in, kdf_inlen);
		free(kdf_in);
		kdf_in = NULL;
		kdf_inlen = 0;
	}

	/* Step H12 check AuthCryptogramting our version  */
	/* Generate CMAC */

	{
		u8 Check_AuthCryptogram[32];
		size_t Check_Alen = 0;

		u8 MacData[200];
		int MacDatalen;
		memset(MacData, 0, sizeof(MacData));

		p = MacData;
		memcpy(p, "\x4B\x43\x5f\x31\x5f\x56", 6);
		p += 6;
		memcpy(p, IDsicc, cs->IDsicclen);
		p += cs->IDsicclen;
		memcpy(p, IDsh, cs->IDshlen);
		p += cs->IDshlen;

		memcpy(p, Qeh_OS, Qeh_OSlen);
		p += Qeh_OSlen;
		MacDatalen = (int)(p - MacData);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if ((cmac_ctx = CMAC_CTX_new()) == NULL
				|| CMAC_Init(cmac_ctx, priv->sm_session.SKcfrm, cs->aeskeylen, (*cs->cipher_cbc)(), NULL) != 1
				|| CMAC_Update(cmac_ctx, MacData, MacDatalen) != 1
				|| CMAC_Final(cmac_ctx, Check_AuthCryptogram, &Check_Alen) != 1) {
			r = SC_ERROR_INTERNAL;
			sc_log(card->ctx,"AES_CMAC failed %d",r);
			goto err;
		}
#else
		mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
		cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);

		cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
		if (mac == NULL
				|| (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL
				|| !EVP_MAC_init(cmac_ctx, priv->sm_session.SKcfrm,
					priv->sm_session.aes_size, cmac_params)
				|| !EVP_MAC_update( cmac_ctx, MacData, MacDatalen)
				|| !EVP_MAC_final(cmac_ctx, Check_AuthCryptogram, &Check_Alen, cs->AuthCryptogramlen)) {
			sc_log_openssl(card->ctx);
			r = SC_ERROR_INTERNAL;
			sc_log(card->ctx,"AES_CMAC failed %d",r);
			goto err;
		}
#endif

		if (0 == memcmp(AuthCryptogram, Check_AuthCryptogram, cs->AuthCryptogramlen)) {
			sc_log(card->ctx,"AuthCryptogram compare");
			r = 0;
		} else {
			sc_log(card->ctx,"AuthCryptogram compare failed");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
	}

#if 0 
	/* VCI only needed for contactless */
	if (*priv->sm_flags & PIV_SM_CONTACTLESS) {
		/* Is pairing code required? */
		if (!(priv->pin_policy & PIV_PP_VCI_WITHOUT_PC)) {
			r = piv_send_vci_pairing_code(card, priv->pairing_code);
			if (r < 0)
				goto err;
		}
	}
#endif /* 0 */

	r = 0;
	*priv->sm_flags |= PIV_SM_FLAGS_SM_IS_ACTIVE;
	card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;

err:
	*priv->sm_flags &= ~PIV_SM_FLAGS_DEFER_OPEN;
	if (r != 0)
		 memset(&priv->sm_session, 0, sizeof(piv_sm_session_t));
	sc_log_openssl(card->ctx); /* catch any not logged above */

	sc_unlock(card);

	free(sbuf);
	free(kdf_in);
	free(Z);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_GROUP_free(Cicc_group);
	EC_POINT_free(Cicc_point);
	EC_KEY_free(Cicc_eckey);
#endif

	EVP_PKEY_free(eph_pkey); /* in case not cleared in step H9 */
	EVP_PKEY_CTX_free(eph_ctx);
	EVP_PKEY_free(Cicc_pkey);
	EVP_PKEY_CTX_free(Cicc_ctx);
	EVP_PKEY_CTX_free(Z_ctx);
	EVP_MD_CTX_free(hash_ctx);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
	OPENSSL_free(Qehx);
#endif

	LOG_FUNC_RETURN(card->ctx, r);
}

static void piv_inc(u8 *counter, size_t size)
{
	unsigned int c = 1;
	unsigned int b;
	int i;
	for (i = (int)size - 1; c != 0 && i >= 0; i--){
			b = c + counter[i];
			counter[i] = b & 0xff;
			c = b>>8;
	}
}



/* ASN1 callback to save address and len of the object */
static int piv_get_asn1_obj(sc_context_t *ctx, void *arg,  const u8 *obj, size_t len, int depth)
{
	struct sc_lv_data *al = arg;

	if (!arg)
		return SC_ERROR_INTERNAL;

	al->value = (u8 *)obj;
	al->len = len;
	return SC_SUCCESS;
}

#if 0
static int piv_decode_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t *sm_apdu)
{
	int r = SC_SUCCESS;
	int i;
	piv_private_data_t * priv = PIV_PRIV_FROM(card);
	cipher_suite_t *cs = priv->cs;
	struct sc_lv_data ee = {NULL, 0};
	struct sc_lv_data status = {NULL, 0};
	struct sc_lv_data rmac8 = {NULL, 0};
	u8 zeros[16] = {0};
	u8 IV[16];
	u8 *p;
	int outl;
	int outli;
	int outll;
	int outdl;
	u8 lastb[16];
	u8 discard[8];
	u8 *q = NULL;
	int inlen;
	int macdatalen;

	size_t MCVlen = 16;
	size_t R_MCVlen = 0;

	EVP_CIPHER_CTX *ed_ctx = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *cmac_ctx = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n = 0;
#endif

	struct sc_asn1_entry asn1_sm_response[C_ASN1_PIV_SM_RESPONSE_SIZE];

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_copy_asn1_entry(c_asn1_sm_response, asn1_sm_response);

	sc_format_asn1_entry(asn1_sm_response + 0, piv_get_asn1_obj, &ee, 0);
	sc_format_asn1_entry(asn1_sm_response + 1, piv_get_asn1_obj, &status, 0);
	sc_format_asn1_entry(asn1_sm_response + 2, piv_get_asn1_obj, &rmac8, 0);

	r = sc_asn1_decode(card->ctx, asn1_sm_response, sm_apdu->resp, sm_apdu->resplen, NULL, NULL);

	if (r < 0) {
		sc_log(card->ctx,"SM decode failed");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if (asn1_sm_response[0].flags & SC_ASN1_PRESENT  /* optional */
			&& ( ee.value == NULL || ee.len <= 2)) {
		sc_log(card->ctx,"SM BER-TLV not valid");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if ((asn1_sm_response[1].flags & SC_ASN1_PRESENT) == 0
			|| (asn1_sm_response[2].flags & SC_ASN1_PRESENT) == 0) {
		sc_log(card->ctx,"SM missing status or R-MAC");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if (status.len != 2
			|| status.value == NULL
			|| rmac8.len != 8
			|| rmac8.value == NULL) {
		sc_log(card->ctx,"SM status or R-MAC length invalid");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
	cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);
	cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
	if (mac == NULL || (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	/*  MCV is first, then BER TLV Encoded Encrypted PIV Data and Status */
	macdatalen = status.value + status.len - sm_apdu->resp;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (CMAC_Init(cmac_ctx, priv->sm_session.SKrmac, priv->sm_session.aes_size, (*cs->cipher_cbc)(), NULL) != 1
			|| CMAC_Update(cmac_ctx, priv->sm_session.R_MCV, MCVlen) != 1
			|| CMAC_Update(cmac_ctx, sm_apdu->resp, macdatalen) != 1
			|| CMAC_Final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen) != 1) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	if(!EVP_MAC_init(cmac_ctx, (const unsigned char *)priv->sm_session.SKrmac,
				priv->sm_session.aes_size, cmac_params)
			|| !EVP_MAC_update(cmac_ctx, priv->sm_session.R_MCV, MCVlen)
			|| !EVP_MAC_update(cmac_ctx, sm_apdu->resp, macdatalen)
			|| !EVP_MAC_final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen, MCVlen)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	if (memcmp(priv->sm_session.R_MCV, rmac8.value, 8) != 0) {
		sc_log(card->ctx, "SM 8 bytes of R-MAC do not match received R-MAC");
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	ed_ctx = EVP_CIPHER_CTX_new();
	if (ed_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* generate same IV used to encrypt response on card */
	if (EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_ecb)(), NULL, priv->sm_session.SKenc, zeros) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
			|| EVP_EncryptUpdate(ed_ctx, IV, &outli, priv->sm_session.resp_enc_counter, 16) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {
		sc_log(card->ctx,"SM encode failed in OpenSSL");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* some commands do not have response data */
	if (ee.value == NULL) {
		plain->resplen = 0;
	} else {
		p = ee.value;
		inlen = ee.len;
		if (inlen < 17 || *p != 0x01) { /*padding and padding indicator are required */
			sc_log(card->ctx, "SM padding indicator not 0x01");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		p++; /* skip padding indicator */
		inlen --;

		if ((inlen % 16) != 0) {
			sc_log(card->ctx,"SM encrypted data not multiple of 16");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/*
		 * Encrypted data has 1 to 16 pad bytes, so may be 1 to 16 bytes longer
		 * then expected. i.e. plain->resp and resplen.So will do last block
		 * and recombine.
		 */

		inlen -= 16;
		if (plain->resplen < (unsigned) inlen || plain->resp == NULL) {
			sc_log(card->ctx, "SM response will not fit in resp,resplen");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		q = plain->resp;

		/* first round encryptes counter with zero IV, and does not save the output */
		if (EVP_CIPHER_CTX_reset(ed_ctx) != 1
				|| EVP_DecryptInit_ex(ed_ctx, (*cs->cipher_cbc)(), NULL, priv->sm_session.SKenc, IV) != 1
				|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
				|| EVP_DecryptUpdate(ed_ctx, q ,&outl, p, inlen) != 1
				|| EVP_DecryptUpdate(ed_ctx, lastb, &outll, p + inlen, 16 ) != 1
				|| EVP_DecryptFinal_ex(ed_ctx, discard, &outdl) != 1
				|| outdl != 0
				|| outll != 16) {  /* should not happen */
			sc_log(card->ctx,"SM _decode failed in OpenSSL");
			sc_log_openssl(card->ctx);
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* unpad last block and get bytes in last block */
		for (i = 15; i >  0 ; i--) {
			if (lastb[i] == 0x80)
				break;
			if (lastb[i] == 0x00)
				continue;
			sc_log(card->ctx, "SM Padding not correct");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		if (lastb[i] != 0x80) {
			sc_log(card->ctx, "SM Padding not correct");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* will response fit in plain resp buffer */
		if ((unsigned)inlen + i > plain->resplen || plain->resp == NULL) {
			sc_log(card->ctx,"SM response bigger then resplen");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}

		/* copy bytes in last block  if any */
		memcpy(plain->resp + inlen, lastb, i);
		plain->resplen = inlen + i;
	}

	plain->sw1 = *(status.value);
	plain->sw2 = *(status.value + 1);

	piv_inc(priv->sm_session.resp_enc_counter, sizeof(priv->sm_session.resp_enc_counter));

	r = SC_SUCCESS;
err:
	if (r != 0 && plain) {
		plain->sw1 = 0x69;
		plain->sw2 = 0x88;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
#endif

	EVP_CIPHER_CTX_free(ed_ctx);

	LOG_FUNC_RETURN(card->ctx, r);
}
#endif

#if 0
static int piv_free_sm_apdu(sc_card_t *card, sc_apdu_t *plain, sc_apdu_t **sm_apdu)
{
	int r = SC_SUCCESS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (!sm_apdu)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (!(*sm_apdu))
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	if (plain) {
		plain->sw1 = (*sm_apdu)->sw1;
		plain->sw2 = (*sm_apdu)->sw2;
		if (((*sm_apdu)->sw1 == 0x90 && (*sm_apdu)->sw2 == 00)
				|| (*sm_apdu)->sw1 == 61){
			r  = piv_decode_apdu(card, plain, *sm_apdu);
			goto err;
		}
		sc_log(card->ctx,"SM response sw1:0x%2.2x sw2:0x%2.2x", plain->sw1, plain->sw2);
		if (plain->sw1 == 0x69 && plain->sw2 == 0x88) {
			/* BUT plain->sw1 and sw2 are not passed back as expected */
			r = SC_ERROR_SM_INVALID_CHECKSUM; /* will use this one one for now */
			goto err;
		} else {
			r = SC_ERROR_SM;
			goto err;
		}
	}

err:
	free((unsigned char **)(*sm_apdu)->data);
	free((*sm_apdu)->resp);
	free(*sm_apdu);
	*sm_apdu = NULL;

	LOG_FUNC_RETURN(card->ctx, r);
}
#endif

#if 0
static int piv_sm_close(sc_card_t *card)
{
	int r = 0;
	piv_private_data_t * priv = NULL;
	struct iso_sm_ctx * ctx = NULL;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->sm_ctx.info.cmd_data;
	if (!ctx)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx, "priv->sm_flags: 0x%8.8lu", *priv->sm_flags);

	/* sm.c tries to restart sm. Will defer */
	if ((*priv->sm_flags & PIV_SM_FLAGS_SM_IS_ACTIVE)) {
		*priv->sm_flags |= PIV_SM_FLAGS_DEFER_OPEN;
		*priv->sm_flags &= ~PIV_SM_FLAGS_SM_IS_ACTIVE;
	}

	LOG_FUNC_RETURN(card->ctx, r);
}
#endif /* 0 */

static void piv_clear_cvc_content(piv_cvc_t *cvc)
{
	if (!cvc)
		return;
	free(cvc->body);
	free(cvc->signature);
	free(cvc->publicPoint);
	free(cvc->der.value);
	memset(cvc, 0, sizeof(piv_cvc_t));
	return;
}

static void piv_clear_sm_session(piv_sm_session_t *session)
{
	if (!session)
		return;
	sc_mem_clear(session, sizeof(piv_sm_session_t));
	return;
}

/*
 * Decode a card verifiable certificate as defined in NIST 800-73-4
 */
static int piv_decode_cvc(sc_card_t * card, u8 **buf, size_t *buflen,
	piv_cvc_t *cvc)
{
	struct sc_asn1_entry asn1_piv_cvc[C_ASN1_PIV_CVC_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_body[C_ASN1_PIV_CVC_BODY_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_pubkey[C_ASN1_PIV_CVC_PUBKEY_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_dsobj[C_ASN1_PIV_CVC_DSOBJ_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_dssig[C_ASN1_PIV_CVC_DSSIG_SIZE];
	struct sc_asn1_entry asn1_piv_cvc_alg_id[C_ASN1_PIV_CVC_ALG_ID_SIZE];
	struct sc_lv_data roleIDder = {NULL, 0};
	int r;
	const u8 *buf_tmp;
	unsigned int cla_out, tag_out;
	size_t taglen;
	size_t signaturebits;

	if (!card  ||  !buf || !*buf || !cvc)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* If already read and matches previous version return SC_SUCCESS */
	if (cvc->der.value && (cvc->der.len == *buflen) && buf && *buf
			&& (memcmp(cvc->der.value, *buf, *buflen) == 0))
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	piv_clear_cvc_content(cvc);

	memset(cvc, 0, sizeof(piv_cvc_t));
	cvc->issuerIDlen = sizeof(cvc->issuerID);
	cvc->subjectIDlen = sizeof(cvc->subjectID);

	sc_copy_asn1_entry(c_asn1_piv_cvc, asn1_piv_cvc);
	sc_copy_asn1_entry(c_asn1_piv_cvc_body, asn1_piv_cvc_body);
	sc_copy_asn1_entry(c_asn1_piv_cvc_pubkey, asn1_piv_cvc_pubkey);
	sc_copy_asn1_entry(c_asn1_piv_cvc_dsobj, asn1_piv_cvc_dsobj);
	sc_copy_asn1_entry(c_asn1_piv_cvc_dssig, asn1_piv_cvc_dssig);
	sc_copy_asn1_entry(c_asn1_piv_cvc_alg_id, asn1_piv_cvc_alg_id);

	sc_format_asn1_entry(asn1_piv_cvc_alg_id    , &cvc->signatureAlgOID, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_alg_id + 1, NULL, NULL, 1); /* NULL */

	sc_format_asn1_entry(asn1_piv_cvc_dssig    , &asn1_piv_cvc_alg_id, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_dssig + 1, &cvc->signature, &signaturebits, 1);

	sc_format_asn1_entry(asn1_piv_cvc_dsobj    , &asn1_piv_cvc_dssig, NULL, 1);

	sc_format_asn1_entry(asn1_piv_cvc_pubkey    , &cvc->pubKeyOID, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_pubkey + 1, &cvc->publicPoint, &cvc->publicPointlen, 1);

	sc_format_asn1_entry(asn1_piv_cvc_body    , &cvc->cpi, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 1, &cvc->issuerID, &cvc->issuerIDlen, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 2, &cvc->subjectID, &cvc->subjectIDlen, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 3, &asn1_piv_cvc_pubkey, NULL, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 4, piv_get_asn1_obj, &roleIDder, 1);
	sc_format_asn1_entry(asn1_piv_cvc_body + 5, &asn1_piv_cvc_dsobj, NULL, 1);

	sc_format_asn1_entry(asn1_piv_cvc, &asn1_piv_cvc_body, NULL, 1);

	r = sc_asn1_decode(card->ctx, asn1_piv_cvc, *buf, *buflen, NULL, NULL) ; /*(const u8 **) &buf_tmp, &len);*/
	if (r < 0) {
		piv_clear_cvc_content(cvc);
		sc_log(card->ctx, "Could not decode card verifiable certificate");
		LOG_FUNC_RETURN(card->ctx, r);
	}

	cvc->signaturelen = signaturebits / 8;

	if (roleIDder.len != 1)
		LOG_TEST_RET(card->ctx, SC_ERROR_SM_AUTHENTICATION_FAILED, "roleID wrong length");

	cvc->roleID = *roleIDder.value;

	/* save body der for verification */
	buf_tmp = *buf;
	r = sc_asn1_read_tag(&buf_tmp, *buflen, &cla_out, &tag_out, &taglen);
	LOG_TEST_RET(card->ctx, r," failed to read tag");

	cvc->bodylen = (roleIDder.value + roleIDder.len) - buf_tmp;

	cvc->body = malloc(cvc->bodylen);
	if (cvc->body == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memcpy(cvc->body, buf_tmp, cvc->bodylen);

	/* save to reuse */
	cvc->der.value = malloc(*buflen);
	if (cvc->der.value == NULL) {
		free(cvc->body);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	cvc->der.len = *buflen;
	memcpy(cvc->der.value, *buf, cvc->der.len);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

#if 0
static int nist_parse_pairing_code(sc_card_t *card, const char *option)
{
	size_t i;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (strlen(option) != PIV_PAIRING_CODE_LEN) {
		sc_log(card->ctx, "pairing code length invalid must be %d", PIV_PAIRING_CODE_LEN);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	for (i = 0; i < PIV_PAIRING_CODE_LEN; i++) {
		if (!isdigit(option[i])) {
			sc_log(card->ctx, "pairing code must be %d decimal digits",PIV_PAIRING_CODE_LEN);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}
	return SC_SUCCESS;
}
#endif /* 0 */

static piv_private_data_t *piv_private_data_create()
{
	piv_private_data_t *out = malloc(sizeof(piv_private_data_t));
	if (!out)
		goto err;
	memset(out, 0, sizeof(piv_private_data_t));

	out->magic = 0xDEE1;
err:
	return out;
}

int sm_nist_start(sc_card_t *card,
		u8 *signer_cert_der, size_t signer_cert_len,
		u8 *sm_in_cvc_der, size_t sm_in_cvc_len,
		unsigned long *sm_flags, /* shared with caller */
		unsigned long pin_policy,
		u8 pairing_code[PIV_PAIRING_CODE_LEN],
		u8 csID)
{
	int r;
	int i;
	struct iso_sm_ctx *sctx = NULL;
	struct piv_private_data *priv = NULL;
//	u8 *p = 0;


	sctx = iso_sm_ctx_create();
	if (!sctx) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

        sctx->priv_data = piv_private_data_create();
        if (!sctx->priv_data) {
                r = SC_ERROR_OUT_OF_MEMORY;
                goto err;
        }

	priv = (piv_private_data_t *)sctx->priv_data;

	if (!sm_flags) {
		sc_log(card->ctx, "sm_flags required parameter is NULL");
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	priv->sm_flags = sm_flags;

	for (i = 0; i < PIV_CSS_SIZE; i++) {
		if (csID == css[i].id) {
			priv->cs = &css[i];
			break;
		}
	}
	
	if (!priv->cs) {
		sc_log(card->ctx, "Invalid SM csID: 0x%2.2x", csID);
		r =  SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	if (signer_cert_der && signer_cert_len) {
		u8 *cert_blob = signer_cert_der;
		size_t cert_blob_len = signer_cert_len;
		const u8 *p = signer_cert_der;
		int len;

		if (*priv->sm_flags & PIV_SM_FLAGS_SM_CERT_SIGNER_COMPRESSED) {
#ifdef ENABLE_ZLIB
			cert_blob = NULL;
			cert_blob_len = 0;
			if (SC_SUCCESS != sc_decompress_alloc(&cert_blob, &cert_blob_len,
					signer_cert_der, signer_cert_len, COMPRESSION_AUTO)) {
				sc_log(card->ctx, "PIV decompression of SM CERT_SIGNER failed");
				r = SC_ERROR_SM_AUTHENTICATION_FAILED;
				goto err;
			}
#else
			sc_log(card->ctx,"ZLIB Decompression not configured - fail");
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
#endif /* ENABLE_ZLIB */
		}
		
		len = (int)cert_blob_len;
		p = cert_blob;
		if ((priv->signer_cert = d2i_X509(NULL, &p, len)) == NULL) {
			sc_log(card->ctx,"OpenSSL failed to parse CERTIFICATE SIGNER");
			sc_log_openssl(card->ctx);
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
	}
	*priv->sm_flags |= PIV_SM_FLAGS_SM_IN_CVC_PRESENT;

	if (sm_in_cvc_der && sm_in_cvc_len) {
		u8 *pp = sm_in_cvc_der;
		r = piv_decode_cvc(card, &pp, &sm_in_cvc_len, &priv->sm_in_cvc);

		if (r !=  SC_SUCCESS) {
			r = SC_ERROR_SM_AUTHENTICATION_FAILED;
			goto err;
		}
		*priv->sm_flags |= PIV_SM_FLAGS_SM_IN_CVC_PRESENT;
	}

	memcpy(priv->pairing_code, pairing_code, PIV_PAIRING_CODE_LEN);
	priv->csID = csID;

	sctx->authenticate = nist_sm_authenticate;
	sctx->encrypt = nist_sm_encrypt;
	sctx->decrypt = nist_sm_decrypt;
	sctx->verify_authentication = nist_sm_verify_authentication;
	sctx->pre_transmit = nist_sm_pre_transmit;
	sctx->post_transmit = nist_sm_post_transmit;
	sctx->finish = nist_sm_finish;
	sctx->clear_free = nist_sm_clear_free;
	sctx->padding_indicator = SM_ISO_PADDING;
	sctx->padding_tag = 1;
	sctx->use_sm_chaining = 1;
	sctx->get_response_in_clear = 1;
	sctx->block_length = 16; /* 800-73-4 uses 16 for both cipher suites */

	r = iso_sm_start(card, sctx);

	/* We want to control if SM is on or not from driver, so set it off. */
	card->sm_ctx.sm_mode = SM_MODE_NONE;

	r = piv_sm_open(card);
	if (r < 0) {
		sc_log(card->ctx, "piv_sm_open failed with r:%d", r);
		goto err;
	}

	card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
// TODO need shared sm_flags or way to test or control from driver

// TODO set piv_sm_open here or in driver or add it to  card->sm_ctx.sm_mode

	/*
	 * sm-iso does not set an operation for sm_open which in our case
	 * is piv_sm_open. which we will control from calling driver. 
	 * so unset sm_mode
	 */
//	card->sm_ctx.sm_mode = SM_MODE_NONE;

err:
	if (r < 0)
		iso_sm_ctx_clear_free(sctx);


	return r;
}


static int
nist_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc)
{
	int r;
	piv_private_data_t * priv = NULL;
	cipher_suite_t *cs = NULL;
	EVP_CIPHER_CTX *ed_ctx = NULL;
	u8 *out = NULL;
	u8 IV[16];
	u8 zeros[16] = {0x00};
	int outli = 0;
	int outl = 0;
//	int outll = 0;
	int outdl = 0;
	u8 discard[16];

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (!ctx || !data || !ctx->priv_data || !enc)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;
	cs = priv->cs;

	out = (u8 *)malloc(datalen);
	if (!out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ed_ctx = EVP_CIPHER_CTX_new();
	if (ed_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* first round encryptes Enc counter with zero IV, to create a new IV */
	if (EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_ecb)(), NULL, priv->sm_session.SKenc, zeros) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx, 0) != 1
			|| EVP_EncryptUpdate(ed_ctx, IV, &outli, priv->sm_session.enc_counter, 16) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {
		sc_log(card->ctx,"SM encode failed in OpenSSL");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	/* first round above encryptes Enc counter with zero IV, and does not save the output */
	/* input is padded already */
	if (EVP_CIPHER_CTX_reset(ed_ctx) != 1
			|| EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_cbc)(), NULL, priv->sm_session.SKenc, IV) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1 /* i.e no padding */
			|| EVP_EncryptUpdate(ed_ctx, out ,&outl, data, (int)datalen) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {  /* should not happen */
		sc_log(card->ctx,"SM _encode failed in OpenSSL");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	*enc = out;
	out = NULL;
	r = (int)datalen;

err:
	EVP_CIPHER_CTX_free(ed_ctx);
	free(out);

	return r;
}

static int
nist_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data)
{
	int r;
	piv_private_data_t * priv = NULL;
	cipher_suite_t *cs;
	u8 zeros[16] = {0};
	u8 IV[16];
//	u8 *p = NULL;
	u8 *out = NULL;
	int outl = 0;
	int outli = 0;
	int outdl = 0;
//	u8 lastb[16];
	u8 discard[8];
//	u8 *q = NULL;
	EVP_CIPHER_CTX *ed_ctx = NULL;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if ( !ctx || !data || !ctx->priv_data || !data)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;
	cs = priv->cs;

	out = malloc(enclen);
	if (!out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ed_ctx = EVP_CIPHER_CTX_new();
	if (ed_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
	goto err;
	}


	/* generate same IV used to encrypt response on card */
	if (EVP_EncryptInit_ex(ed_ctx, (*cs->cipher_ecb)(), NULL, priv->sm_session.SKenc, zeros) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
			|| EVP_EncryptUpdate(ed_ctx, IV, &outli, priv->sm_session.resp_enc_counter, 16) != 1
			|| EVP_EncryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {  /* should not happen */
		sc_log(card->ctx,"SM encode failed in OpenSSL");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}

	/* first round encryptes counter with zero IV, and does not save the output */
	if (EVP_CIPHER_CTX_reset(ed_ctx) != 1
			|| EVP_DecryptInit_ex(ed_ctx, (*cs->cipher_cbc)(), NULL, priv->sm_session.SKenc, IV) != 1
			|| EVP_CIPHER_CTX_set_padding(ed_ctx,0) != 1
			|| EVP_DecryptUpdate(ed_ctx, out ,&outl, enc, (int)enclen) != 1
			|| EVP_DecryptFinal_ex(ed_ctx, discard, &outdl) != 1
			|| outdl != 0) {  /* should not happen */
		sc_log(card->ctx,"SM _decode failed in OpenSSL");
		sc_log_openssl(card->ctx);
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
		}
	
	*data = out;
	out = NULL;
	r = (int)enclen;

err:
	free(out);
	return r;
}


static int
nist_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **macdata)
{

//	u8 *p = NULL;
	int r;
	piv_private_data_t  *priv = NULL;
	cipher_suite_t *cs = NULL;
	int MCVlen = 16;
	int macdatalen = 8;
	size_t C_MCVlen = 16; /* debugging*/

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC_CTX *cmac_ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n;
#endif
	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if ( !ctx || !data || !ctx->priv_data || !macdata)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;
	cs = priv->cs;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
	cmac_params_n = 0;
	cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);
	cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
	if (mac == NULL
			|| (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	memcpy(priv->sm_session.C_MCV_last, priv->sm_session.C_MCV, MCVlen); /* save is case fails */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (CMAC_Init(cmac_ctx, priv->sm_session.SKmac, priv->sm_session.aes_size, (*cs->cipher_cbc)(), NULL) != 1
			|| CMAC_Update(cmac_ctx, priv->sm_session.C_MCV, MCVlen) != 1
			|| CMAC_Update(cmac_ctx, data,  datalen) != 1
			|| CMAC_Final(cmac_ctx, priv->sm_session.C_MCV, &C_MCVlen) != 1) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	if(!EVP_MAC_init(cmac_ctx, (const unsigned char *)priv->sm_session.SKmac,
				priv->sm_session.aes_size, cmac_params)
			|| !EVP_MAC_update(cmac_ctx, priv->sm_session.C_MCV, MCVlen)
			|| !EVP_MAC_update(cmac_ctx, data,  datalen)
			|| !EVP_MAC_final(cmac_ctx, priv->sm_session.C_MCV, &C_MCVlen, MCVlen)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	*macdata = malloc(macdatalen);
	if (*macdata == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(*macdata, priv->sm_session.C_MCV, macdatalen);
	r = macdatalen;

err:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX_free(cmac_ctx);
#else
	EVP_MAC_CTX_free(cmac_ctx);
	EVP_MAC_free(mac);
#endif

	return r;
}

static int
nist_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *rmac, size_t rmaclen,
		const u8 *macdata, size_t macdatalen)
{
//	u8 *p = NULL;
	int r;
	piv_private_data_t  *priv = NULL;
	cipher_suite_t *cs = NULL;
	int MCVlen = 16;
	size_t R_MCVlen = 0;
//	size_t C_MCVlen = 16; /* debugging*/

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	CMAC_CTX *cmac_ctx  = NULL;
#else
	EVP_MAC_CTX *cmac_ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM cmac_params[2];
	size_t cmac_params_n = 0;
#endif

	if (!card)
	   return SC_ERROR_INVALID_ARGUMENTS;

	if(!ctx || !ctx->priv_data || !rmac || !macdata)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;
	cs = priv->cs;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	cmac_ctx = CMAC_CTX_new();
	if (cmac_ctx == NULL) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#else
	mac = EVP_MAC_fetch(PIV_LIBCTX, "cmac", NULL);
	cmac_params_n = 0;
	cmac_params[cmac_params_n++] = OSSL_PARAM_construct_utf8_string("cipher", cs->cipher_cbc_name, 0);
	cmac_params[cmac_params_n] = OSSL_PARAM_construct_end();
	if (mac == NULL || (cmac_ctx = EVP_MAC_CTX_new(mac)) == NULL) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif
	/*  MCV is first, then BER TLV Encoded Encrypted PIV Data and Status */

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (CMAC_Init(cmac_ctx, priv->sm_session.SKrmac, priv->sm_session.aes_size, (*cs->cipher_cbc)(), NULL) != 1
			|| CMAC_Update(cmac_ctx, priv->sm_session.R_MCV, MCVlen) != 1
			|| CMAC_Update(cmac_ctx, macdata, macdatalen) != 1
			|| CMAC_Final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen) != 1) {
		r = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto err;
	}
#else
	if(!EVP_MAC_init(cmac_ctx, (const unsigned char *)priv->sm_session.SKrmac,
				priv->sm_session.aes_size, cmac_params)
			|| !EVP_MAC_update(cmac_ctx, priv->sm_session.R_MCV, MCVlen)
			|| !EVP_MAC_update(cmac_ctx, macdata, macdatalen)
			|| !EVP_MAC_final(cmac_ctx, priv->sm_session.R_MCV, &R_MCVlen, MCVlen)) {
		sc_log_openssl(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
#endif

	if (rmaclen != 8 || R_MCVlen != 16 ||
			memcmp(priv->sm_session.R_MCV, rmac, rmaclen) != 0) {
		r = SC_ERROR_OBJECT_NOT_VALID;
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"Authentication data not verified");
		goto err;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_SM, "Authentication data verified");

	r = SC_SUCCESS;

err:

	return r;
}

static int
nist_sm_pre_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu)
{
	int r = 0;

	piv_private_data_t *priv;

	if (!card)
	   return SC_ERROR_INVALID_ARGUMENTS;

	if(!ctx || !ctx->priv_data || !apdu)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;

// TODO 230923 to make more general, may need more work
	switch (apdu->ins) {
		case 0xCB: /* GET_DATA */
			if (*priv->sm_flags & PIV_SM_GET_DATA_IN_CLEAR) {
				*priv->sm_flags &= ~PIV_SM_GET_DATA_IN_CLEAR;
				r = SC_ERROR_SM_NOT_APPLIED;
			}
			break;
		case 0x20: /* VERIFY */
			break;
		case 0x24: /* CHANGE REFERENCE DATA */
			break;
		case 0x87: /* GENERAL AUTHENTICATE */
			break;
		case 0xC0: /* GET RESPONSE */
			r = SC_ERROR_SM_NOT_APPLIED;
			break;
		default: /* just issue the plain apdu */
			r = SC_ERROR_SM_NOT_APPLIED;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
}

static int
nist_sm_post_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *sm_apdu)
{
	int r = 0;
	piv_private_data_t *priv;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if(!ctx || !ctx->priv_data || !sm_apdu)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);

	priv = (piv_private_data_t *)ctx->priv_data;

	memcpy(priv->sm_session.enc_counter_last, priv->sm_session.enc_counter, sizeof(priv->sm_session.enc_counter));
	piv_inc(priv->sm_session.enc_counter, sizeof(priv->sm_session.enc_counter));

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
}

static int
nist_sm_finish(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu)
{
	piv_private_data_t *priv;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	if(!ctx || !ctx->priv_data || !apdu)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_ERROR_INVALID_ARGUMENTS);
	priv = (piv_private_data_t *)ctx->priv_data;

	piv_inc(priv->sm_session.resp_enc_counter, sizeof(priv->sm_session.resp_enc_counter));

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, SC_SUCCESS);
}

static void
nist_sm_clear_free(const struct iso_sm_ctx *ctx)
{
	if (ctx) {
		struct piv_private_data *priv = PIV_PRIV_FROM(ctx);

		if (priv) {
			piv_clear_sm_session(&priv->sm_session);
			X509_free(priv->signer_cert);
			piv_clear_cvc_content(&priv->sm_in_cvc);
			piv_clear_cvc_content(&priv->sm_cvc);
			free(priv);
			/* TODO IS this needed? ctx->priv_data = NULL; */
		}
	}
}

#else  /* correct versions of OpenSSL or not enabled */
//TODO add dummy  nist_sm_start 
#endif /* ENABLE_NIST_SM */
