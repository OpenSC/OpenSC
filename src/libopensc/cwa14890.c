/**
 * cwa14890.c: Implementation of Secure Messaging according CWA-14890-1 and CWA-14890-2 standards.
 * 
 * Copyright (C) 2010 Juan Antonio Martinez <jonsito@terra.es>
 *
 * This work is derived from many sources at OpenSC Project site,
 * (see references) and the information made public by Spanish 
 * Direccion General de la Policia y de la Guardia Civil
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define __CWA14890_C__
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(ENABLE_OPENSSL) && defined(ENABLE_SM)	/* empty file without openssl or sm */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "opensc.h"
#include "cardctl.h"
#include "internal.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "cwa14890.h"
#include "cwa-dnie.h"

#define MAX_RESP_BUFFER_SIZE 2048

/**
 * Structure used to compose BER-TLV encoded data
 * according to iso7816-4 sect 5.2.2.
 *
 * Notice that current implementation does not handle properly
 * multibyte tag id. Just assume that tag is 1-byte length
 * Also, encodings for data length longer than 0x01000000 bytes
 * are not supported (tag 0x84)
 */
typedef struct cwa_tlv_st {
        u8 *buf;                /** local copy of TLV byte array */
        size_t buflen;          /** lengt of buffer */
        unsigned int tag;       /** tag ID */
        size_t len;             /** length of data field */
        u8 *data;               /** pointer to start of data in buf buffer */
} cwa_tlv_t;

/*********************** utility functions ************************/

/**
 * Dump an APDU before SM translation.
 *
 * This is mainly for debugging purposes. programmer should disable
 * this function in a production environment, as APDU will be shown
 * in text-plain on debug traces
 *
 * @param card Pointer to card driver data structure
 * @param apdu APDU to be encoded, or APDU response after decoded
 * @param flag 0: APDU is to be encoded: 1; APDU decoded response
 */
static void cwa_trace_apdu(sc_card_t * card, sc_apdu_t * apdu, int flag)
{
	char buf[2048];
	if (!card || !card->ctx || !apdu || card->ctx->debug < SC_LOG_DEBUG_NORMAL)
		return;
	if (flag == 0) {	/* apdu command */
		if (apdu->datalen > 0) {	/* apdu data to show */
			sc_hex_dump(apdu->data, apdu->datalen, buf, sizeof(buf));
			sc_log(card->ctx,
			       "\nAPDU before encode: ==================================================\nCLA: %02X INS: %02X P1: %02X P2: %02X Lc: %02"SC_FORMAT_LEN_SIZE_T"X Le: %02"SC_FORMAT_LEN_SIZE_T"X DATA: [%5"SC_FORMAT_LEN_SIZE_T"u bytes]\n%s======================================================================\n",
			       apdu->cla, apdu->ins, apdu->p1, apdu->p2,
			       apdu->lc, apdu->le, apdu->datalen, buf);
		} else {	/* apdu data field is empty */
			sc_log(card->ctx,
			       "\nAPDU before encode: ==================================================\nCLA: %02X INS: %02X P1: %02X P2: %02X Lc: %02"SC_FORMAT_LEN_SIZE_T"X Le: %02"SC_FORMAT_LEN_SIZE_T"X (NO DATA)\n======================================================================\n",
			       apdu->cla, apdu->ins, apdu->p1, apdu->p2,
			       apdu->lc, apdu->le);
		}
	} else {		/* apdu response */
		sc_hex_dump(apdu->resp, apdu->resplen, buf, sizeof(buf));
		sc_log(card->ctx,
		       "\nAPDU response after decode: ==========================================\nSW1: %02X SW2: %02X RESP: [%5"SC_FORMAT_LEN_SIZE_T"u bytes]\n%s======================================================================\n",
		       apdu->sw1, apdu->sw2, apdu->resplen, buf);
	}
}

/**
 * Increase send sequence counter SSC.
 *
 * @param card smart card info structure
 * @return SC_SUCCESS if ok; else error code
 *
 * TODO: to further study: what about using bignum arithmetics?
 */
static int cwa_increase_ssc(sc_card_t * card)
{
	int n;
	struct sm_cwa_session * sm = &card->sm_ctx.info.session.cwa;

	/* preliminary checks */
	if (!card || !card->ctx )
		return SC_ERROR_INVALID_ARGUMENTS;
	LOG_FUNC_CALLED(card->ctx);
	/* u8 arithmetic; exit loop if no carry */
	sc_log(card->ctx, "Curr SSC: '%s'", sc_dump_hex(sm->ssc, 8));
	for (n = 7; n >= 0; n--) {
		sm->ssc[n]++;
		if ((sm->ssc[n]) != 0x00)
			break;
	}
	sc_log(card->ctx, "Next SSC: '%s'", sc_dump_hex(sm->ssc, 8));
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/**
 * ISO 7816 padding.
 *
 * Adds an 0x80 at the end of buffer and as many zeroes to get len 
 * multiple of 8
 * Buffer must be long enough to store additional bytes
 *
 * @param buffer where to compose data
 * @param len pointer to buffer length
 */
static void cwa_iso7816_padding(u8 * buf, size_t * buflen)
{
	buf[*buflen] = 0x80;
	(*buflen)++;
	for (; *buflen & 0x07; (*buflen)++)
		buf[*buflen] = 0x00;
}

/**
 * compose a BER-TLV data in provided buffer.
 *
 * Multibyte tag id are not supported
 * Also multibyte id 0x84 is unhandled
 *
 * Notice that TLV is composed starting at offset length from
 * the buffer. Consecutive calls to cwa_add_tlv, appends a new
 * TLV at the end of the buffer
 *
 * @param card card info structure
 * @param tag tag id
 * @param len data length
 * @param value data buffer
 * @param out pointer to dest data
 * @param outlen length of composed tlv data
 * @return SC_SUCCESS if ok; else error
 */
static int cwa_compose_tlv(sc_card_t * card,
			   u8 tag,
			   size_t len, u8 * data, u8 ** out, size_t * outlen)
{
	u8 *pt;
	size_t size;
	sc_context_t *ctx;
	/* preliminary checks */
	if (!card || !card->ctx || !out || !outlen)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* commodity vars */
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	pt = *out;
	size = *outlen;

	/* assume tag id is not multibyte */
	*(pt + size++) = tag;
	/* evaluate tag length value according iso7816-4 sect 5.2.2 */
	if (len < 0x80) {
		*(pt + size++) = len;
	} else if (len < 0x00000100) {
		*(pt + size++) = 0x81;
		*(pt + size++) = 0xff & len;
	} else if (len < 0x00010000) {
		*(pt + size++) = 0x82;
		*(pt + size++) = 0xff & (len >> 8);
		*(pt + size++) = 0xff & len;
	} else if (len < 0x01000000) {
		*(pt + size++) = 0x83;
		*(pt + size++) = 0xff & (len >> 16);
		*(pt + size++) = 0xff & (len >> 8);
		*(pt + size++) = 0xff & len;
	} else {		/* do not handle tag length 0x84 */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	/* copy remaining data to buffer */
	if (len != 0)
		memcpy(pt + size, data, len);
	size += len;
	*outlen = size;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/**
 * Parse and APDU Response and extract specific BER-TLV data.
 *
 * NOTICE that iso7816 sect 5.2.2 states that Tag length may be 1 to n bytes
 * length. In this code we'll assume always tag length = 1 byte
 *
 * FIXME use `sc_asn1_read_tag` or similar instead
 *
 * @param card card info structure
 * @param data Buffer to look for tlv into
 * @param datalen Buffer len
 * @param tlv  array of TLV structure to store results into
 * @return SC_SUCCESS if OK; else error code
 */
static int cwa_parse_tlv(sc_card_t * card,
			 u8 * buffer, size_t datalen,
			 cwa_tlv_t tlv_array[]
    )
{
	size_t n = 0;
	size_t next = 0;
	sc_context_t *ctx = NULL;

	/* preliminary checks */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* commodity vars */
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	if (!tlv_array)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	for (n = 0; n < datalen; n += next) {
		cwa_tlv_t *tlv = NULL;	/* pointer to TLV structure to store info */
		size_t j = 2;	/* TLV has at least two bytes */
		switch (*(buffer + n)) {
		case CWA_SM_PLAIN_TAG:
			tlv = &tlv_array[0];
			break;	/* 0x81 Plain  */
		case CWA_SM_CRYPTO_TAG:
			tlv = &tlv_array[1];
			break;	/* 0x87 Crypto */
		case CWA_SM_MAC_TAG:
			tlv = &tlv_array[2];
			break;	/* 0x8E MAC CC */
		case CWA_SM_STATUS_TAG:
			tlv = &tlv_array[3];
			break;	/* 0x99 Status */
		default:	/* CWA_SM_LE_TAG (0x97) is not valid here */
			sc_log(ctx, "Invalid TLV Tag type: '0x%02X'",
			       *(buffer + n));
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
		}
		tlv->buf = buffer + n;
		tlv->tag = 0xff & *(buffer + n);
		tlv->len = 0;	/* temporary */
		/* evaluate len and start of data */
		switch (0xff & *(buffer + n + 1)) {
		case 0x84:
			tlv->len = (0xff & *(buffer + n + j++));
			/* fall through */
		case 0x83:
			tlv->len =
			    (tlv->len << 8) + (0xff & *(buffer + n + j++));
			/* fall through */
		case 0x82:
			tlv->len =
			    (tlv->len << 8) + (0xff & *(buffer + n + j++));
			/* fall through */
		case 0x81:
			tlv->len =
			    (tlv->len << 8) + (0xff & *(buffer + n + j++));
			break;
			/* case 0x80 is not standard, but official code uses it */
		case 0x80:
			tlv->len =
			    (tlv->len << 8) + (0xff & *(buffer + n + j++));
			break;
		default:
			if ((*(buffer + n + 1) & 0xff) < 0x80) {
				tlv->len = 0xff & *(buffer + n + 1);
			} else {
				sc_log(ctx, "Invalid tag length indicator: %d",
				       *(buffer + n + 1));
				LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
			}
		}
		tlv->data = buffer + n + j;
		tlv->buflen = j + tlv->len;;
		sc_log(ctx, "Found Tag: '0x%02X': Length: '%"SC_FORMAT_LEN_SIZE_T"u' Value:\n%s",
		       tlv->tag, tlv->len, sc_dump_hex(tlv->data, tlv->len));
		/* set index to next Tag to jump to */
		next = tlv->buflen;
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);	/* mark no error */
}

/*********************** authentication routines *******************/

/**
 * Verify certificates provided by card.
 *
 * This routine uses Root CA public key data From Annex III of manual
 * to verify intermediate CA icc certificate provided by card
 * if verify success, then extract public keys from intermediate CA
 * and verify icc certificate
 *
 * @param card pointer to sc_card_contex
 * @param sub_ca_cert icc intermediate CA certificate read from card
 * @param icc_ca icc certificate from card
 * @return SC_SUCCESS if verification is ok; else error code
 */
static int cwa_verify_icc_certificates(sc_card_t * card,
				       cwa_provider_t * provider,
				       X509 * sub_ca_cert, X509 * icc_cert)
{
	char *msg = NULL;
	int res = SC_SUCCESS;
	EVP_PKEY *root_ca_key = NULL;
	EVP_PKEY *sub_ca_key = NULL;
	sc_context_t *ctx = NULL;

	/* safety check */
	if (!card || !card->ctx || !provider)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!sub_ca_cert || !icc_cert)	/* check received arguments */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* retrieve root ca pkey from provider */
	res = provider->cwa_get_root_ca_pubkey(card, &root_ca_key);
	if (res != SC_SUCCESS) {
		msg = "Cannot get root CA public key";
		res = SC_ERROR_INTERNAL;
		goto verify_icc_certificates_end;
	}

	/* verify sub_ca_cert against root_ca_key */
	res = X509_verify(sub_ca_cert, root_ca_key);
	if (!res) {
		msg = "Cannot verify icc Sub-CA certificate";
		res = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto verify_icc_certificates_end;
	}

	/* extract sub_ca_key from sub_ca_cert */
	sub_ca_key = X509_get_pubkey(sub_ca_cert);

	/* verify icc_cert against sub_ca_key */
	res = X509_verify(icc_cert, sub_ca_key);
	if (!res) {
		msg = "Cannot verify icc certificate";
		res = SC_ERROR_SM_AUTHENTICATION_FAILED;
		goto verify_icc_certificates_end;
	}

	/* arriving here means certificate verification success */
	res = SC_SUCCESS;
 verify_icc_certificates_end:
	if (root_ca_key)
		EVP_PKEY_free(root_ca_key);
	if (sub_ca_key)
		EVP_PKEY_free(sub_ca_key);
	if (res != SC_SUCCESS)
		sc_log(ctx, "%s", msg);
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * Verify CVC certificates in SM establishment process.
 *
 * This is done by mean of 00 2A 00 AE 
 * (Perform Security Operation: Verify Certificate )
 *
 * @param card pointer to card data
 * @param cert Certificate in CVC format
 * @param len  length of CVC certificate
 * @return SC_SUCCESS if ok; else error code
 */
static int cwa_verify_cvc_certificate(sc_card_t * card,
				      const u8 * cert, size_t len)
{
	sc_apdu_t apdu;
	int result = SC_SUCCESS;
	sc_context_t *ctx = NULL;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!cert || (len <= 0))	/* check received arguments */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* compose apdu for Perform Security Operation (Verify cert) cmd */
	dnie_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x00, 0xAE, 0, len,
					NULL, 0, cert, len);

	/* send composed apdu and parse result */
	result = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, result, "Verify CVC certificate failed");
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(ctx, result);
}

/**
 * Alternate implementation for set_security environment.
 *
 * Used to handle raw apdu data in set_security_env() on SM establishment
 * Standard set_security_env() method has sc_security_env->buffer limited
 * to 8 bytes; so cannot send some of required SM commands.
 *
 * @param card pointer to card data 
 * @param p1 apdu P1 parameter
 * @param p2 apdu P2 parameter
 * @param buffer raw data to be inserted in apdu
 * @param length size of buffer
 * @return SC_SUCCESS if ok; else error code
 */
static int cwa_set_security_env(sc_card_t * card,
				u8 p1, u8 p2, u8 * buffer, size_t length)
{
	sc_apdu_t apdu;
	int result = SC_SUCCESS;
	sc_context_t *ctx = NULL;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!buffer || (length <= 0))	/* check received arguments */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* compose apdu for Manage Security Environment cmd */
	dnie_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, p1, p2, 0, length,
					NULL, 0, buffer, length);

	/* send composed apdu and parse result */
	result = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, result, "SM Set Security Environment failed");
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(ctx, result);
}

/**
 * SM internal authenticate.
 *
 * Internal (Card) authentication (let the card verify sent ifd certs)
 *
 * @param card pointer to card data 
 * @param sig signature buffer
 * @param dig_len signature buffer length
 * @param data data to be sent in apdu
 * @param datalen length of data to send
 * @return SC_SUCCESS if OK: else error code
 */
static int cwa_internal_auth(sc_card_t * card, u8 * sig, size_t sig_len, u8 * data, size_t datalen)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int result = SC_SUCCESS;
	sc_context_t *ctx = NULL;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!data || (datalen <= 0))	/* check received arguments */
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* compose apdu for Internal Authenticate cmd */
	dnie_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, 0x00, 0x80, datalen,
					rbuf, sizeof(rbuf), data, datalen);

	/* send composed apdu and parse result */
	result = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, result, "SM internal auth failed");

	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, result, "SM internal auth invalid response");

	if (apdu.resplen != sig_len)	/* invalid number of bytes received */
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	memcpy(sig, apdu.resp, apdu.resplen);	/* copy result to buffer */
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/**
 * Compose signature data for external auth according CWA-14890.
 * 
 * This code prepares data to be sent to ICC for external
 * authentication procedure
 *
 * Store resulting data  into sm->sig
 *
 * @param card pointer to st_card_t card data information
 * @param icc_pubkey public key of card
 * @param ifd_privkey private RSA key of ifd
 * @param sn_icc card serial number
 * @param sig signature buffer
 * @param sig_len signature buffer length
 * @return SC_SUCCESS if ok; else errorcode
 */
static int cwa_prepare_external_auth(sc_card_t * card,
				     RSA * icc_pubkey,
				     RSA * ifd_privkey,
				     u8 * sig,
				     size_t sig_len)
{
	/* we have to compose following message:
	   data = E[PK.ICC.AUT](SIGMIN)
	   SIGMIN = min ( SIG, N.IFD-SIG )
	   SIG= DS[SK.IFD.AUT] (
	   0x6A  || - padding according iso 9796-2
	   PRND2 || - (74 bytes) random data to make buffer 128 bytes length
	   Kifd  || - (32 bytes)- ifd random generated key
	   sha1_hash(
	   PRND2   ||  
	   Kifd    || 
	   RND.ICC || - (8 bytes) response to get_challenge() cmd
	   SN.ICC  - (8 bytes) serial number from get_serialnr() cmd
	   ) || 
	   0xBC - iso 9796-2 padding
	   ) - total: 128 bytes

	   then, we should encrypt with our private key and then with icc pub key
	   returning resulting data
	 */
	char *msg = NULL;		/* to store error messages */
	int res = SC_SUCCESS;
	u8 *buf1;		/* where to encrypt with icc pub key */
	u8 *buf2;		/* where to encrypt with ifd pub key */
	u8 *buf3;		/* where to compose message to be encrypted */
	int len1, len2, len3;
	u8 *sha_buf;		/* to compose message to be sha'd */
	u8 *sha_data;		/* sha signature data */
	BIGNUM *bn = NULL;
	BIGNUM *bnsub = NULL;
	BIGNUM *bnres = NULL;
	sc_context_t *ctx = NULL;
	const BIGNUM *ifd_privkey_n, *ifd_privkey_e, *ifd_privkey_d;
	struct sm_cwa_session * sm = &card->sm_ctx.info.session.cwa;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	/* check received arguments */
	if (!icc_pubkey || !ifd_privkey || !sm)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	buf1 = calloc(128, sizeof(u8));
	buf2 = calloc(128, sizeof(u8));
	buf3 = calloc(128, sizeof(u8));
	sha_buf = calloc(74 + 32 + 8 + 8, sizeof(u8));
	sha_data = calloc(SHA_DIGEST_LENGTH, sizeof(u8));
	/* alloc() resources */
	if (!buf1 || !buf2 || !buf3 || !sha_buf || !sha_data) {
		msg = "prepare external auth: calloc error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto prepare_external_auth_end;
	}

	/* compose buffer data */
	buf3[0] = 0x6A;		/* iso padding */
	RAND_bytes(buf3 + 1, 74);	/* pRND */
	RAND_bytes(sm->ifd.k, 32);	/* Kifd */
	memcpy(buf3 + 1 + 74, sm->ifd.k, 32);	/* copy Kifd into buffer */
	/* prepare data to be hashed */
	memcpy(sha_buf, buf3 + 1, 74);	/* copy pRND into sha_buf */
	memcpy(sha_buf + 74, buf3 + 1 + 74, 32);	/* copy kifd into sha_buf */
	memcpy(sha_buf + 74 + 32, sm->icc.rnd, 8);	/* copy 8 byte icc challenge */
	memcpy(sha_buf + 74 + 32 + 8, sm->icc.sn, 8);	/* copy serialnr, 8 bytes */
	SHA1(sha_buf, 74 + 32 + 8 + 8, sha_data);
	/* copy hashed data into buffer */
	memcpy(buf3 + 1 + 74 + 32, sha_data, SHA_DIGEST_LENGTH);
	buf3[127] = 0xBC;	/* iso padding */

	/* encrypt with ifd private key */
	len2 = RSA_private_decrypt(128, buf3, buf2, ifd_privkey, RSA_NO_PADDING);
	if (len2 < 0) {
		msg = "Prepare external auth: ifd_privk encrypt failed";
		res = SC_ERROR_SM_ENCRYPT_FAILED;
		goto prepare_external_auth_end;
	}

	/* evaluate value of minsig and store into buf3 */
	bn = BN_bin2bn(buf2, len2, NULL);
	bnsub = BN_new();
	if (!bn || !bnsub) {
		msg = "Prepare external auth: BN creation failed";
		res = SC_ERROR_INTERNAL;
		goto prepare_external_auth_end;
	}
	RSA_get0_key(ifd_privkey, &ifd_privkey_n, &ifd_privkey_e, &ifd_privkey_d);
	res = BN_sub(bnsub, ifd_privkey_n, bn);	/* eval N.IFD-SIG */
	if (res == 0) {		/* 1:success 0 fail */
		msg = "Prepare external auth: BN sigmin evaluation failed";
		res = SC_ERROR_INTERNAL;
		goto prepare_external_auth_end;
	}
	bnres = (BN_cmp(bn, bnsub) < 0) ? bn : bnsub;	/* choose min(SIG,N.IFD-SIG) */
	if (BN_num_bytes(bnres) > 128) {
		msg = "Prepare external auth: BN sigmin result is too big";
		res = SC_ERROR_INTERNAL;
		goto prepare_external_auth_end;
	}
	len3 = BN_bn2bin(bnres, buf3);	/* convert result back into buf3 */
	if (len3 <= 0) {
		msg = "Prepare external auth: BN to buffer conversion failed";
		res = SC_ERROR_INTERNAL;
		goto prepare_external_auth_end;
	}

	/* re-encrypt result with icc public key */
	len1 = RSA_public_encrypt(len3, buf3, buf1, icc_pubkey, RSA_NO_PADDING);
	if (len1 <= 0 || (size_t) len1 != sig_len) {
		msg = "Prepare external auth: icc_pubk encrypt failed";
		res = SC_ERROR_SM_ENCRYPT_FAILED;
		goto prepare_external_auth_end;
	}

	/* process done: copy result into cwa_internal buffer and return success */
	memcpy(sig, buf1, len1);
	res = SC_SUCCESS;

 prepare_external_auth_end:
	if (bn)
		BN_free(bn);
	if (bnsub)
		BN_free(bnsub);
	if (buf1) {
		sc_mem_clear(buf1, 128);
		free(buf1);
	}
	if (buf2) {
		sc_mem_clear(buf2, 128);
		free(buf2);
	}
	if (buf3) {
		sc_mem_clear(buf3, 128);
		free(buf3);
	}
	if (sha_buf) {
		sc_mem_clear(sha_buf, 74 + 32 + 8 + 1 + 7);
		free(sha_buf);
	}
	if (sha_data) {
		free(sha_data);
	}

	if (res != SC_SUCCESS)
		sc_log(ctx, "%s", msg);
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * SM external authenticate.
 *
 * Perform external (IFD) authenticate procedure (8.4.1.2)
 *
 * @param card pointer to card data 
 * @param sig signature buffer
 * @param sig signature buffer length
 * @return SC_SUCCESS if OK: else error code
 */
static int cwa_external_auth(sc_card_t * card, u8 * sig, size_t sig_len)
{
	sc_apdu_t apdu;
	int result = SC_SUCCESS;
	sc_context_t *ctx = NULL;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* compose apdu for External Authenticate cmd */
	dnie_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x00, 0x00, 0, sig_len,
					NULL, 0, sig, sig_len);

	/* send composed apdu and parse result */
	result = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, result, "SM external auth failed");
	result = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, result, "SM external auth invalid response");
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/**
 * SM creation of session keys.
 *
 * Compute Kenc,Kmac, and SSC  and store it into sm data
 *
 * @param card pointer to sc_card_t data
 * @return SC_SUCCESS if ok; else error code
 */
static int cwa_compute_session_keys(sc_card_t * card)
{

	char *msg = NULL;
	int n = 0;
	int res = SC_SUCCESS;
	u8 *kseed;		/* to compose kifd ^ kicc */
	u8 *data;		/* to compose kenc and kmac to be hashed */
	u8 *sha_data;		/* to store hash result */
	u8 kenc[4] = { 0x00, 0x00, 0x00, 0x01 };
	u8 kmac[4] = { 0x00, 0x00, 0x00, 0x02 };
	sc_context_t *ctx = NULL;
	struct sm_cwa_session * sm = &card->sm_ctx.info.session.cwa;

	/* safety check */
	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	/* Just a literal transcription of cwa14890-1 sections 8.7.2 to 8.9 */
	kseed = calloc(32, sizeof(u8));
	data = calloc(32 + 4, sizeof(u8));
	sha_data = calloc(SHA_DIGEST_LENGTH, sizeof(u8));
	if (!kseed || !data || !sha_data) {
		msg = "Compute Session Keys: calloc() failed";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto compute_session_keys_end;
	}
	/* compose kseed  (cwa-14890-1 sect 8.7.2) */
	for (n = 0; n < 32; n++)
		*(kseed + n) = sm->icc.k[n] ^ sm->ifd.k[n];

	/* evaluate kenc (cwa-14890-1 sect 8.8) */
	memcpy(data, kseed, 32);
	memcpy(data + 32, kenc, 4);
	SHA1(data, 32 + 4, sha_data);
	memcpy(sm->session_enc, sha_data, 16);	/* kenc=16 fsb sha((kifd^kicc)||00000001) */

	/* evaluate kmac */
	memset(data, 0, 32 + 4);
	memset(sha_data, 0, SHA_DIGEST_LENGTH);	/* clear buffers */

	memcpy(data, kseed, 32);
	memcpy(data + 32, kmac, 4);
	SHA1(data, 32 + 4, sha_data);
	memcpy(sm->session_mac, sha_data, 16);	/* kmac=16 fsb sha((kifd^kicc)||00000002) */

	/* evaluate send sequence counter  (cwa-14890-1 sect 8.9 & 9.6 */
	memcpy(sm->ssc, sm->icc.rnd + 4, 4);	/* 4 least significant bytes of rndicc */
	memcpy(sm->ssc + 4, sm->ifd.rnd + 4, 4);	/* 4 least significant bytes of rndifd */

	/* arriving here means process ok */
	res = SC_SUCCESS;

 compute_session_keys_end:
	if (kseed) {
		sc_mem_clear(kseed, 32);
		free(kseed);
	}
	if (data) {
		sc_mem_clear(data, 32 + 4);
		free(data);
	}
	if (sha_data) {
		free(sha_data);
	}
	if (res != SC_SUCCESS)
		sc_log(ctx, "%s", msg);
	else {
		sc_log(ctx, "Kenc: %s", sc_dump_hex(sm->session_enc, 16));
		sc_log(ctx, "Kmac: %s", sc_dump_hex(sm->session_mac, 16));
		sc_log(ctx, "SSC:  %s", sc_dump_hex(sm->ssc, 8));
	}
	LOG_FUNC_RETURN(ctx, res);
}

/*
 * Compare signature for internal auth procedure.
 *
 * @param data Received data to be checked
 * @param dlen data length
 * @param expected results
 * @return SC_SUCCESS or error code
 */
static int cwa_compare_signature(u8 * data, size_t dlen, u8 * ifd_data)
{
	u8 *buf = calloc(74 + 32 + 32, sizeof(u8));
	u8 *sha = calloc(SHA_DIGEST_LENGTH, sizeof(u8));
	int res = SC_SUCCESS;
	if (!buf || !sha) {
		res = SC_ERROR_OUT_OF_MEMORY;
		goto compare_signature_end;
	}
	res = SC_ERROR_INVALID_DATA;
	if (dlen != 128)
		goto compare_signature_end;	/* check length */
	if (data[0] != 0x6a)
		goto compare_signature_end;	/* iso 9796-2 padding */
	if (data[127] != 0xBC)
		goto compare_signature_end;	/* iso 9796-2 padding */
	memcpy(buf, data + 1, 74 + 32);
	memcpy(buf + 74 + 32, ifd_data, 16);
	SHA1(buf, 74 + 32 + 16, sha);
	if (memcmp(data + 127 - SHA_DIGEST_LENGTH, sha, SHA_DIGEST_LENGTH) == 0)
		res = SC_SUCCESS;
 compare_signature_end:
	if (buf)
		free(buf);
	if (sha)
		free(sha);
	return res;
}

/** 
 * check the result of internal_authenticate operation.
 *
 * Checks icc received data from internal auth procedure against
 * expected results
 *
 * @param card Pointer to sc_card_t data
 * @param icc_pubkey icc public key
 * @param ifd_privkey ifd private key
 * @param ifdbuf buffer containing ( RND.IFD || SN.IFD )
 * @param ifdlen buffer length; should be 16
 * @param sig signature buffer
 * @param sig_len signature buffer length
 * @return SC_SUCCESS if ok; else error code
 */
static int cwa_verify_internal_auth(sc_card_t * card,
				    RSA * icc_pubkey,
				    RSA * ifd_privkey,
				    u8 * ifdbuf,
				    size_t ifdlen,
				    u8 * sig,
				    size_t sig_len)
{
	int res = SC_SUCCESS;
	char *msg = NULL;
	u8 *buf1 = NULL;	/* to decrypt with our private key */
	u8 *buf2 = NULL;	/* to try SIGNUM==SIG */
	u8 *buf3 = NULL;	/* to try SIGNUM==N.ICC-SIG */
	int len1 = 0;
	int len2 = 0;
	int len3 = 0;
	BIGNUM *bn = NULL;
	BIGNUM *sigbn = NULL;
	sc_context_t *ctx = NULL;
	const BIGNUM *icc_pubkey_n, *icc_pubkey_e, *icc_pubkey_d;
	struct sm_cwa_session * sm = &card->sm_ctx.info.session.cwa;

	if (!card || !card->ctx)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
	if (!ifdbuf || (ifdlen != 16)) {
		res = SC_ERROR_INVALID_ARGUMENTS;
		msg = "Null buffers received as parameters";
		goto verify_internal_done;
	}
	if (!icc_pubkey || !ifd_privkey) {
		res = SC_ERROR_SM_NO_SESSION_KEYS;
		msg = "Either provided icc_pubk or ifd_privk are null";
		goto verify_internal_done;
	}
	buf1 = (u8 *) calloc(128, sizeof(u8));	/* 128: RSA key len in bytes */
	buf2 = (u8 *) calloc(128, sizeof(u8));
	buf3 = (u8 *) calloc(128, sizeof(u8));
	if (!buf1 || !buf2 || !buf3) {
		msg = "Verify Signature: calloc() error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto verify_internal_done;
	}

	/* 
	   We have received data with this format:
	   sigbuf = E[PK.IFD.AUT](SIGMIN)
	   SIGMIN = min ( SIG, N.ICC-SIG )
	   SIG= DS[SK.ICC.AUT] (
	   0x6A  ||
	   PRND1 ||
	   Kicc  ||
	   sha1_hash(PRND1 || Kicc || RND.IFD || SN.IFD) ||
	   0xBC 
	   )
	   So we should reverse the process and try to get valid results
	 */

	/* decrypt data with our ifd priv key */
	len1 = RSA_private_decrypt(sig_len, sig, buf1, ifd_privkey, RSA_NO_PADDING);
	if (len1 <= 0) {
		msg = "Verify Signature: decrypt with ifd privk failed";
		res = SC_ERROR_SM_ENCRYPT_FAILED;
		goto verify_internal_done;
	}

	/* OK: now we have SIGMIN in buf1 */
	/* check if SIGMIN data matches SIG or N.ICC-SIG */
	/* evaluate DS[SK.ICC.AUTH](SIG) trying to decrypt with icc pubk */
	len3 = RSA_public_encrypt(len1, buf1, buf3, icc_pubkey, RSA_NO_PADDING);
	if (len3 <= 0)
		goto verify_nicc_sig;	/* evaluate N.ICC-SIG and retry */
	res = cwa_compare_signature(buf3, len3, ifdbuf);
	if (res == SC_SUCCESS)
		goto verify_internal_ok;

 verify_nicc_sig:
	/* 
	 * Arriving here means need to evaluate N.ICC-SIG 
	 * So convert buffers to bignums to operate
	 */
	bn = BN_bin2bn(buf1, len1, NULL);	/* create BN data */
	sigbn = BN_new();
	if (!bn || !sigbn) {
		msg = "Verify Signature: cannot bignums creation error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto verify_internal_done;
	}
	RSA_get0_key(icc_pubkey, &icc_pubkey_n, &icc_pubkey_e, &icc_pubkey_d);
	res = BN_sub(sigbn, icc_pubkey_n, bn);	/* eval N.ICC-SIG */
	if (!res) {
		msg = "Verify Signature: evaluation of N.ICC-SIG failed";
		res = SC_ERROR_INTERNAL;
		goto verify_internal_done;
	}
	len2 = BN_bn2bin(sigbn, buf2);	/* copy result to buffer */
	if (len2 <= 0) {
		msg = "Verify Signature: cannot convert bignum to buffer";
		res = SC_ERROR_INTERNAL;
		goto verify_internal_done;
	}
	/* ok: check again with new data */
	/* evaluate DS[SK.ICC.AUTH](I.ICC-SIG) trying to decrypt with icc pubk */
	len3 = RSA_public_encrypt(len2, buf2, buf3, icc_pubkey, RSA_NO_PADDING);
	if (len3 <= 0) {
		msg = "Verify Signature: cannot get valid SIG data";
		res = SC_ERROR_INVALID_DATA;
		goto verify_internal_done;
	}
	res = cwa_compare_signature(buf3, len3, ifdbuf);
	if (res != SC_SUCCESS) {
		msg = "Verify Signature: cannot get valid SIG data";
		res = SC_ERROR_INVALID_DATA;
		goto verify_internal_done;
	}
	/* arriving here means OK: complete data structures */
 verify_internal_ok:
	memcpy(sm->icc.k, buf3 + 1 + 74, 32);	/* extract Kicc from buf3 */
	res = SC_SUCCESS;
 verify_internal_done:
	if (buf1)
		free(buf1);
	if (buf2)
		free(buf2);
	if (buf3)
		free(buf3);
	if (bn)
		BN_free(bn);
	if (sigbn)
		BN_free(sigbn);
	if (res != SC_SUCCESS)
		sc_log(ctx, "%s", msg);
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * Create Secure Messaging channel.
 *
 * This is the main entry point for CWA14890 SM channel creation.
 * It closely follows cwa standard, with a minor modification:
 * - ICC serial number is taken at the beginning of SM creation
 * - ICC and IFD certificate agreement process is reversed, to allow
 * card to retain key references on further process (this behavior
 * is also defined in standard)
 *
 * Based on Several documents:
 * - "Understanding the DNIe"
 * - "Manual de comandos del DNIe"
 * - ISO7816-4 and CWA14890-{1,2}
 *
 * @param card card info structure
 * @param provider cwa14890 info provider
 * @param flag requested init method ( OFF, COLD, WARM )
 * @return SC_SUCCESS if OK; else error code
 */
int cwa_create_secure_channel(sc_card_t * card,
			      cwa_provider_t * provider, int flag)
{
	u8 *cert = NULL;
	size_t certlen;

	int res = SC_SUCCESS;
	char *msg = "Success";

	/* data to get and parse certificates */
	X509 *icc_cert = NULL;
	X509 *ca_cert = NULL;
	EVP_PKEY *icc_pubkey = NULL;
	EVP_PKEY *ifd_privkey = NULL;
	sc_context_t *ctx = NULL;
	struct sm_cwa_session * sm = &card->sm_ctx.info.session.cwa;
	u8 sig[128];

	/* several buffer and buffer pointers */
	u8 *buffer = NULL;
	size_t bufferlen;
	u8 *tlv = NULL;		/* buffer to compose TLV messages */
	size_t tlvlen = 0;
	u8 rndbuf[16]; /* 8 RND.IFD + 8 SN.IFD */

	/* preliminary checks */
	if (!card || !card->ctx )
		return SC_ERROR_INVALID_ARGUMENTS;
	if (!provider)
		return SC_ERROR_SM_NOT_INITIALIZED;
	/* commodity vars */
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	/* check requested initialization method */
	switch (flag) {
	case CWA_SM_OFF:	/* disable SM */
		card->sm_ctx.sm_mode = SM_MODE_NONE;
		sc_log(ctx, "Setting CWA SM status to none");
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	case CWA_SM_ON:	/* force sm initialization process */
		sc_log(ctx, "CWA SM initialization requested");
		break;
	default:
		sc_log(ctx, "Invalid provided SM initialization flag");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	/* OK: lets start process */

	/* call provider pre-operation method */
	sc_log(ctx, "CreateSecureChannel pre-operations");
	if (provider->cwa_create_pre_ops) {
		res = provider->cwa_create_pre_ops(card, provider);
		if (res != SC_SUCCESS) {
			msg = "Create SM: provider pre_ops() failed";
			sc_log(ctx, "%s", msg);
			goto csc_end;
		}
	}

	/* retrieve icc serial number */
	sc_log(ctx, "Retrieve ICC serial number");
	if (provider->cwa_get_sn_icc) {
		res = provider->cwa_get_sn_icc(card);
		if (res != SC_SUCCESS) {
			msg = "Retrieve ICC failed";
			sc_log(ctx, "%s", msg);
			goto csc_end;
		}
	} else {
		msg = "Don't know how to obtain ICC serial number";
		sc_log(ctx, "%s", msg);
		res = SC_ERROR_INTERNAL;
		goto csc_end;
	}

	/* 
	 * Notice that this code inverts ICC and IFD certificate standard
	 * checking sequence.
	 */

	/* Read Intermediate CA from card */
	if (!provider->cwa_get_icc_intermediate_ca_cert) {
		sc_log(ctx,
		       "Step 8.4.1.6: Skip Retrieving ICC intermediate CA");
		ca_cert = NULL;
	} else {
		sc_log(ctx, "Step 8.4.1.7: Retrieving ICC intermediate CA");
		res =
		    provider->cwa_get_icc_intermediate_ca_cert(card, &ca_cert);
		if (res != SC_SUCCESS) {
			msg =
			    "Cannot get ICC intermediate CA certificate from provider";
			goto csc_end;
		}
	}

	/* Read ICC certificate from card */
	sc_log(ctx, "Step 8.4.1.8: Retrieve ICC certificate");
	res = provider->cwa_get_icc_cert(card, &icc_cert);
	if (res != SC_SUCCESS) {
		msg = "Cannot get ICC certificate from provider";
		goto csc_end;
	}

	/* Verify icc Card certificate chain */
	/* Notice that Some implementations doesn't verify cert chain
	 * but simply verifies that icc_cert is a valid certificate */
	if (ca_cert) {
		sc_log(ctx, "Verifying ICC certificate chain");
		res =
		    cwa_verify_icc_certificates(card, provider, ca_cert,
						icc_cert);
		if (res != SC_SUCCESS) {
			res = SC_ERROR_SM_AUTHENTICATION_FAILED;
			msg = "Icc Certificates verification failed";
			goto csc_end;
		}
	} else {
		sc_log(ctx, "Cannot verify Certificate chain. skip step");
	}

	/* Extract public key from ICC certificate */
	icc_pubkey = X509_get_pubkey(icc_cert);

	/* Select Root CA in card for ifd certificate verification */
	sc_log(ctx,
	       "Step 8.4.1.2: Select Root CA in card for IFD cert verification");
	res = provider->cwa_get_root_ca_pubkey_ref(card, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot get Root CA key reference from provider";
		goto csc_end;
	}
	tlvlen = 0;
	tlv = calloc(10 + bufferlen, sizeof(u8));
	if (!tlv) {
		msg = "calloc error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto csc_end;
	}
	res = cwa_compose_tlv(card, 0x83, bufferlen, buffer, &tlv, &tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot compose tlv for setting Root CA key reference";
		goto csc_end;
	}
	res = cwa_set_security_env(card, 0x81, 0xB6, tlv, tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Select Root CA key ref failed";
		goto csc_end;
	}

	/* Send IFD intermediate CA in CVC format C_CV_CA */
	sc_log(ctx,
	       "Step 8.4.1.3: Send CVC IFD intermediate CA Cert for ICC verification");
	res = provider->cwa_get_cvc_ca_cert(card, &cert, &certlen);
	if (res != SC_SUCCESS) {
		msg = "Get CVC CA cert from provider failed";
		goto csc_end;
	}
	res = cwa_verify_cvc_certificate(card, cert, certlen);
	if (res != SC_SUCCESS) {
		msg = "Verify CVC CA failed";
		goto csc_end;
	}

	/* select public key reference for sent IFD intermediate CA certificate */
	sc_log(ctx,
	       "Step 8.4.1.4: Select Intermediate CA pubkey ref for ICC verification");
	res =
	    provider->cwa_get_intermediate_ca_pubkey_ref(card, &buffer,
							 &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot get intermediate CA key reference from provider";
		goto csc_end;
	}
	tlvlen = 0;
	free(tlv);
	tlv = calloc(10 + bufferlen, sizeof(u8));
	if (!tlv) {
		msg = "calloc error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto csc_end;
	}
	res = cwa_compose_tlv(card, 0x83, bufferlen, buffer, &tlv, &tlvlen);
	if (res != SC_SUCCESS) {
		msg =
		    "Cannot compose tlv for setting intermediate CA key reference";
		goto csc_end;
	}
	res = cwa_set_security_env(card, 0x81, 0xB6, tlv, tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Select CVC CA pubk failed";
		goto csc_end;
	}

	/* Send IFD certificate in CVC format C_CV_IFD */
	sc_log(ctx,
	       "Step 8.4.1.5: Send CVC IFD Certificate for ICC verification");
	res = provider->cwa_get_cvc_ifd_cert(card, &cert, &certlen);
	if (res != SC_SUCCESS) {
		msg = "Get CVC IFD cert from provider failed";
		goto csc_end;
	}
	res = cwa_verify_cvc_certificate(card, cert, certlen);
	if (res != SC_SUCCESS) {
		msg = "Verify CVC IFD failed";
		goto csc_end;
	}

	/* remember that this code changes IFD and ICC Cert verification steps */

	/* select public key of ifd certificate and icc private key */
	sc_log(ctx,
	       "Step 8.4.1.9: Send IFD pubk and ICC privk key references for Internal Auth");
	res = provider->cwa_get_ifd_pubkey_ref(card, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot get ifd public key reference from provider";
		goto csc_end;
	}
	tlvlen = 0;
	free(tlv);
	tlv = calloc(10 + bufferlen, sizeof(u8));
	if (!tlv) {
		msg = "calloc error";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto csc_end;
	}
	res = cwa_compose_tlv(card, 0x83, bufferlen, buffer, &tlv, &tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot compose tlv for setting ifd pubkey reference";
		goto csc_end;
	}
	res = provider->cwa_get_icc_privkey_ref(card, &buffer, &bufferlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot get icc private key reference from provider";
		goto csc_end;
	}
	/* add this tlv to old one; do not call calloc */
	res = cwa_compose_tlv(card, 0x84, bufferlen, buffer, &tlv, &tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Cannot compose tlv for setting ifd pubkey reference";
		goto csc_end;
	}

	res = cwa_set_security_env(card, 0xC1, 0xA4, tlv, tlvlen);
	if (res != SC_SUCCESS) {
		msg = "Select CVC IFD pubk failed";
		goto csc_end;
	}

	/* Internal (Card) authentication (let the card verify sent ifd certs) 
	   SN.IFD equals 8 lsb bytes of ifd.pubk ref according cwa14890 sec 8.4.1 */
	sc_log(ctx, "Step 8.4.1.10: Perform Internal authentication");
	res = provider->cwa_get_sn_ifd(card);
	if (res != SC_SUCCESS) {
		msg = "Cannot get ifd serial number from provider";
		goto csc_end;
	}
	RAND_bytes(sm->ifd.rnd, 8);	/* generate 8 random bytes */
	memcpy(rndbuf, sm->ifd.rnd, 8);	/* insert RND.IFD into rndbuf */
	memcpy(rndbuf + 8, sm->ifd.sn, 8);	/* insert SN.IFD into rndbuf */
	res = cwa_internal_auth(card, sig, 128, rndbuf, 16);
	if (res != SC_SUCCESS) {
		msg = "Internal auth cmd failed";
		goto csc_end;
	}

	/* retrieve ifd private key from provider */
	res = provider->cwa_get_ifd_privkey(card, &ifd_privkey);
	if (res != SC_SUCCESS) {
		msg = "Cannot retrieve IFD private key from provider";
		res = SC_ERROR_SM_NO_SESSION_KEYS;
		goto csc_end;
	}

	/* verify received signature */
	sc_log(ctx, "Verify Internal Auth command response");
	res = cwa_verify_internal_auth(card, EVP_PKEY_get0_RSA(icc_pubkey),	/* evaluated icc public key */
				       EVP_PKEY_get0_RSA(ifd_privkey),	/* evaluated from DGP's Manual Annex 3 Data */
				       rndbuf,	/* RND.IFD || SN.IFD */
				       16,	/* rndbuf length; should be 16 */
				       sig, 128
	    );
	if (res != SC_SUCCESS) {
		msg = "Internal Auth Verify failed";
		goto csc_end;
	}

	/* get challenge: retrieve 8 random bytes from card */
	sc_log(ctx, "Step 8.4.1.11: Prepare External Auth: Get Challenge");
	res = sc_get_challenge(card, sm->icc.rnd, sizeof(sm->icc.rnd));
	if (res != SC_SUCCESS) {
		msg = "Get Challenge failed";
		goto csc_end;
	}

	/* compose signature data for external auth */
	res = cwa_prepare_external_auth(card,
					EVP_PKEY_get0_RSA(icc_pubkey),
					EVP_PKEY_get0_RSA(ifd_privkey), sig, 128);
	if (res != SC_SUCCESS) {
		msg = "Prepare external auth failed";
		goto csc_end;
	}

	/* External (IFD)  authentication */
	sc_log(ctx, "Step 8.4.1.12: Perform External (IFD) Authentication");
	res = cwa_external_auth(card, sig, 128);
	if (res != SC_SUCCESS) {
		msg = "External auth cmd failed";
		goto csc_end;
	}

	/* Session key generation */
	sc_log(ctx, "Step 8.4.2: Compute Session Keys");
	res = cwa_compute_session_keys(card);
	if (res != SC_SUCCESS) {
		msg = "Session Key generation failed";
		goto csc_end;
	}

	/* call provider post-operation method */
	sc_log(ctx, "CreateSecureChannel post-operations");
	if (provider->cwa_create_post_ops) {
		res = provider->cwa_create_post_ops(card, provider);
		if (res != SC_SUCCESS) {
			sc_log(ctx, "Create SM: provider post_ops() failed");
			goto csc_end;
		}
	}

	/* arriving here means ok: cleanup */
	res = SC_SUCCESS;
 csc_end:
	free(tlv);
	if (icc_cert)
		X509_free(icc_cert);
	if (ca_cert)
		X509_free(ca_cert);
	if (icc_pubkey)
		EVP_PKEY_free(icc_pubkey);
	if (ifd_privkey)
		EVP_PKEY_free(ifd_privkey);
	/* setup SM state according result */
	if (res != SC_SUCCESS) {
		sc_log(ctx, "%s", msg);
		card->sm_ctx.sm_mode = SM_MODE_NONE;
	} else {
		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
	}
	LOG_FUNC_RETURN(ctx, res);
}

/******************* SM internal APDU encoding / decoding functions ******/

/**
 * Encode an APDU.
 *
 * Calling this functions means that It's has been verified
 * That source apdu needs encoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 * @param card card info structure
 * @param sm Secure Messaging state information
 * @param from APDU to be encoded
 * @param to where to store encoded apdu
 * @return SC_SUCCESS if ok; else error code
 */
int cwa_encode_apdu(sc_card_t * card,
		    cwa_provider_t * provider, sc_apdu_t * from, sc_apdu_t * to)
{
	u8 *apdubuf = NULL;		/* to store resulting apdu */
	size_t apdulen, tlv_len;
	u8 *ccbuf = NULL;		/* where to store data to eval cryptographic checksum CC */
	size_t cclen = 0;
	u8 macbuf[8];		/* to store and compute CC */
	DES_key_schedule k1;
	DES_key_schedule k2;
	char *msg = NULL;

	size_t i, j;		/* for xor loops */
	int res = SC_SUCCESS;
	sc_context_t *ctx = NULL;
	struct sm_cwa_session * sm_session = &card->sm_ctx.info.session.cwa;
	u8 *msgbuf = NULL;	/* to encrypt apdu data */
	u8 *cryptbuf = NULL;

	/* mandatory check */
	if (!card || !card->ctx || !provider)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	/* check remaining arguments */
	if (!from || !to || !sm_session)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_NOT_INITIALIZED);
	if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_INVALID_LEVEL);

	/* reserve extra bytes for padding and tlv header */
	msgbuf = calloc(12 + from->lc, sizeof(u8));	/* to encrypt apdu data */
	cryptbuf = calloc(12 + from->lc, sizeof(u8));
	if (!msgbuf || !cryptbuf) {
		res = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* check if APDU is already encoded */
	if ((from->cla & 0x0C) != 0) {
		memcpy(to, from, sizeof(sc_apdu_t));
		res = SC_SUCCESS;	/* already encoded */
		goto encode_end;
	}
	if (from->ins == 0xC0) {
		memcpy(to, from, sizeof(sc_apdu_t));
		res = SC_SUCCESS;	/* dont encode GET Response cmd */
		goto encode_end;
	}

	/* trace APDU before encoding process */
	cwa_trace_apdu(card, from, 0);

	/* reserve enough space for apdulen+tlv bytes
	 * to-be-crypted buffer and result apdu buffer */
	 /* TODO DEE add 4 more bytes for testing.... */
	apdubuf = calloc(MAX(SC_MAX_APDU_BUFFER_SIZE, 20 + from->datalen),
		   sizeof(u8));
	ccbuf = calloc(MAX(SC_MAX_APDU_BUFFER_SIZE, 20 + from->datalen),
		   sizeof(u8));
	/* always create a new buffer for the encoded response */
	to->resp = calloc(MAX_RESP_BUFFER_SIZE, sizeof(u8));
	to->resplen = MAX_RESP_BUFFER_SIZE;
	if (!apdubuf || !ccbuf || (!from->resp && !to->resp)) {
		res = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* set up data on destination apdu */
	to->cse = SC_APDU_CASE_4_SHORT;
	to->cla = from->cla | 0x0C;	/* mark apdu as encoded */
	to->ins = from->ins;
	to->p1 = from->p1;
	to->p2 = from->p2;
	to->le = from->le;
	if (!to->le)
		to->le = 255;
	to->lc = 0;		/* to be evaluated */
	/* fill buffer with header info */
	*(ccbuf + cclen++) = to->cla;
	*(ccbuf + cclen++) = to->ins;
	*(ccbuf + cclen++) = to->p1;
	*(ccbuf + cclen++) = to->p2;
	cwa_iso7816_padding(ccbuf, &cclen);	/* pad header (4 bytes pad) */

	/* if no data, skip data encryption step */
	if (from->lc != 0) {
		size_t dlen = from->lc;

		/* prepare keys */
		DES_cblock iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
		DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_enc[0]),
				      &k1);
		DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_enc[8]),
				      &k2);

		/* pad message */
		memcpy(msgbuf, from->data, dlen);
		cwa_iso7816_padding(msgbuf, &dlen);

		/* start kriptbuff with iso padding indicator */
		*cryptbuf = 0x01;
		/* apply TDES + CBC with kenc and iv=(0,..,0) */
		DES_ede3_cbc_encrypt(msgbuf, cryptbuf + 1, dlen, &k1, &k2, &k1,
				     &iv, DES_ENCRYPT);
		/* compose data TLV and add to result buffer */
		res =
		    cwa_compose_tlv(card, 0x87, dlen + 1, cryptbuf, &ccbuf,
				    &cclen);
		if (res != SC_SUCCESS) {
			msg = "Error in compose tag 8x87 TLV";
			goto encode_end;
		}
	} else if ((0xff & from->le) > 0) {

	/* if le byte is declared, compose and add Le TLV */
	/* FIXME: For DNIe we must not send the le bytes
	  when le == 256 but this goes against the standard
	  and might break other cards reusing this code */
        /* NOTE: In FNMT MultiPKCS11 code this is an if, i.e.,
           the le is only sent if no data (lc) is set.
           In DNIe 3.0 pin verification sending both TLV return
           69 88 "SM Data Object incorrect". For the moment it is
           fixed sendind le=0 in pin verification apdu */
	    u8 le = 0xff & from->le;
	    res = cwa_compose_tlv(card, 0x97, 1, &le, &ccbuf, &cclen);
	    if (res != SC_SUCCESS) {
		msg = "Encode APDU compose_tlv(0x97) failed";
		goto encode_end;
	    }
	}
	/* copy current data to apdu buffer (skip header and header padding) */
	memcpy(apdubuf, ccbuf + 8, cclen - 8);
	apdulen = cclen - 8;
	/* pad again ccbuffer to compute CC */
	cwa_iso7816_padding(ccbuf, &cclen);

	/* sc_log(ctx,"data to compose mac: %s",sc_dump_hex(ccbuf,cclen)); */
	/* compute MAC Cryptographic Checksum using kmac and increased SSC */
	res = cwa_increase_ssc(card); /* increase send sequence counter */
	if (res != SC_SUCCESS) {
		msg = "Error in computing SSC";
		goto encode_end;
	}
	/* set up keys for mac computing */
	DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_mac[0]),&k1);
	DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_mac[8]),&k2);

	memcpy(macbuf, sm_session->ssc, 8);	/* start with computed SSC */
	for (i = 0; i < cclen; i += 8) {	/* divide data in 8 byte blocks */
		/* compute DES */
		DES_ecb_encrypt((const_DES_cblock *) macbuf,
				(DES_cblock *) macbuf, &k1, DES_ENCRYPT);
		/* XOR with next data and repeat */
		for (j = 0; j < 8; j++)
			macbuf[j] ^= ccbuf[i + j];
	}
	/* and apply 3DES to result */
	DES_ecb2_encrypt((const_DES_cblock *) macbuf, (DES_cblock *) macbuf,
			 &k1, &k2, DES_ENCRYPT);

	/* compose and add computed MAC TLV to result buffer */
	tlv_len = (card->atr.value[15] >= DNIE_30_VERSION)? 8 : 4;
	sc_log(ctx, "Using TLV length: %"SC_FORMAT_LEN_SIZE_T"u", tlv_len);
	res = cwa_compose_tlv(card, 0x8E, tlv_len, macbuf, &apdubuf, &apdulen);
	if (res != SC_SUCCESS) {
		msg = "Encode APDU compose_tlv(0x87) failed";
		goto encode_end;
	}

	/* rewrite resulting header */
	to->lc = apdulen;
	to->data = apdubuf;
	to->datalen = apdulen;

	/* that's all folks */
	res = SC_SUCCESS;
	goto encode_end_apdu_valid;

err:
encode_end:
	if (apdubuf)
		free(apdubuf);
	if (from->resp != to->resp)
		free(to->resp);
encode_end_apdu_valid:
	if (msg)
		sc_log(ctx, "%s", msg);
	free(msgbuf);
	free(cryptbuf);
	free(ccbuf);
	LOG_FUNC_RETURN(ctx, res);
}

/**
 * Decode an APDU response.
 *
 * Calling this functions means that It's has been verified
 * That apdu response comes in TLV encoded format and needs decoding
 * Based on section 9 of CWA-14890 and Sect 6 of iso7816-4 standards
 * And DNIe's manual
 *
 * @param card card info structure
 * @param sm Secure Messaging state information
 * @param from APDU with response to be decoded
 * @param to where to store decoded apdu
 * @return SC_SUCCESS if ok; else error code
 */
int cwa_decode_response(sc_card_t * card,
			cwa_provider_t * provider,
			sc_apdu_t * apdu)
{
	size_t i, j, tlv_len;
	cwa_tlv_t tlv_array[4];
	cwa_tlv_t *p_tlv = &tlv_array[0];	/* to store plain data (Tag 0x81) */
	cwa_tlv_t *e_tlv = &tlv_array[1];	/* to store pad encoded data (Tag 0x87) */
	cwa_tlv_t *m_tlv = &tlv_array[2];	/* to store mac CC (Tag 0x8E) */
	cwa_tlv_t *s_tlv = &tlv_array[3];	/* to store sw1-sw2 status (Tag 0x99) */
	u8 *buffer = NULL;	/* buffer for data. pointers to this buffer are in tlv_array */
	u8 *ccbuf = NULL;	/* buffer for mac CC calculation */
	size_t cclen = 0;	/* ccbuf len */
	u8 macbuf[8];		/* where to calculate mac */
	size_t resplen = 0;	/* respbuf length */
	DES_key_schedule k1;
	DES_key_schedule k2;
	int res = SC_SUCCESS;
	char *msg = NULL;	/* to store error messages */
	sc_context_t *ctx = NULL;
	struct sm_cwa_session * sm_session = &card->sm_ctx.info.session.cwa;

	/* mandatory check */
	if (!card || !card->ctx || !provider)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);
	/* check remaining arguments */
	if ((apdu == NULL) || (sm_session == NULL))
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_NOT_INITIALIZED);
	if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SM_INVALID_LEVEL);

	/* cwa14890 sect 9.3: check SW1 or SW2 for SM related errors */
	if (apdu->sw1 == 0x69) {
		if ((apdu->sw2 == 0x88) || (apdu->sw2 == 0x87)) {
			/* configure the driver to re-establish the SM */
			msg = "SM related errors in APDU response";
			cwa_create_secure_channel(card, provider, CWA_SM_OFF);
			res = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
			goto response_decode_end;
		}
	}
	/* if response is null/empty assume unencoded apdu */
	if (!apdu->resp || (apdu->resplen == 0)) {
		sc_log(ctx, "Empty APDU response: assume not cwa encoded");
		return SC_SUCCESS;
	}
	/* checks if apdu response needs decoding by checking tags in response */
	switch (*apdu->resp) {
	case CWA_SM_PLAIN_TAG:
	case CWA_SM_CRYPTO_TAG:
	case CWA_SM_MAC_TAG:
	case CWA_SM_LE_TAG:
	case CWA_SM_STATUS_TAG:
		break;		/* cwa tags found: continue decoding */
	default:		/* else apdu response seems not to be cwa encoded */
		sc_log(card->ctx, "APDU Response seems not to be cwa encoded");
		return SC_SUCCESS;	/* let process continue */
	}

	/* parse response to find TLV's data and check results */
	memset(tlv_array, 0, 4 * sizeof(cwa_tlv_t));
	/* create buffer and copy data into */
	buffer = calloc(apdu->resplen, sizeof(u8));
	if (!buffer) {
		msg = "Cannot allocate space for response buffer";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto response_decode_end;
	}
	memcpy(buffer, apdu->resp, apdu->resplen);

	res = cwa_parse_tlv(card, buffer, apdu->resplen, tlv_array);
	if (res != SC_SUCCESS) {
		msg = "Error in TLV parsing";
		goto response_decode_end;
	}

	/* check consistency of received TLV's */
	if (p_tlv->buf && e_tlv->buf) {
		msg =
		    "Plain and Encoded data are mutually exclusive in apdu response";
		res = SC_ERROR_INVALID_DATA;
		goto response_decode_end;
	}
	if (!m_tlv->buf) {
		msg = "No MAC TAG found in apdu response";
		res = SC_ERROR_INVALID_DATA;
		goto response_decode_end;
	}
	tlv_len = (card->atr.value[15] >= DNIE_30_VERSION)? 8 : 4;
	if (m_tlv->len != tlv_len) {
		msg = "Invalid MAC TAG Length";
		res = SC_ERROR_INVALID_DATA;
		goto response_decode_end;
	}

	/* compose buffer to evaluate mac */

	/* reserve enough space for data+status+padding */
	ccbuf =
	    calloc(e_tlv->buflen + s_tlv->buflen + p_tlv->buflen + 8,
		   sizeof(u8));
	if (!ccbuf) {
		msg = "Cannot allocate space for mac checking";
		res = SC_ERROR_OUT_OF_MEMORY;
		goto response_decode_end;
	}
	/* copy data into buffer */
	cclen = 0;
	if (e_tlv->buf) {	/* encoded data */
		memcpy(ccbuf, e_tlv->buf, e_tlv->buflen);
		cclen = e_tlv->buflen;
	}
	if (p_tlv->buf) {	/* plain data */
		memcpy(ccbuf, p_tlv->buf, p_tlv->buflen);
		cclen += p_tlv->buflen;
	}
	if (s_tlv->buf) {	/* response status */
		if (s_tlv->len != 2) {
			msg = "Invalid SW TAG length";
			res = SC_ERROR_INVALID_DATA;
			goto response_decode_end;
		}
		memcpy(ccbuf + cclen, s_tlv->buf, s_tlv->buflen);
		cclen += s_tlv->buflen;
		apdu->sw1 = s_tlv->data[0];
		apdu->sw2 = s_tlv->data[1];
	}		/* if no response status tag, use sw1 and sw2 from apdu */
	/* add iso7816 padding */
	cwa_iso7816_padding(ccbuf, &cclen);

	/* evaluate mac by mean of kmac and increased SendSequence Counter SSC */

	/* increase SSC */
	res = cwa_increase_ssc(card);	/* increase send sequence counter */
	if (res != SC_SUCCESS) {
		msg = "Error in computing SSC";
		goto response_decode_end;
	}
	/* set up keys for mac computing */
	DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_mac[0]), &k1);
	DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_mac[8]), &k2);

	memcpy(macbuf, sm_session->ssc, 8);	/* start with computed SSC */
	for (i = 0; i < cclen; i += 8) {	/* divide data in 8 byte blocks */
		/* compute DES */
		DES_ecb_encrypt((const_DES_cblock *) macbuf,
				(DES_cblock *) macbuf, &k1, DES_ENCRYPT);
		/* XOR with data and repeat */
		for (j = 0; j < 8; j++)
			macbuf[j] ^= ccbuf[i + j];
	}
	/* finally apply 3DES to result */
	DES_ecb2_encrypt((const_DES_cblock *) macbuf, (DES_cblock *) macbuf,
			 &k1, &k2, DES_ENCRYPT);

	/* check evaluated mac with provided by apdu response */

	res = memcmp(m_tlv->data, macbuf, 4);	/* check first 4 bytes */
	if (res != 0) {
		msg = "Error in MAC CC checking: value doesn't match";
		res = SC_ERROR_SM_ENCRYPT_FAILED;
		goto response_decode_end;
	}

	/* allocate response buffer */
	resplen = 10 + MAX(p_tlv->len, e_tlv->len);	/* estimate response buflen */
	if (apdu->resplen < resplen) {
		msg = "Cannot allocate buffer to store response";
		res = SC_ERROR_BUFFER_TOO_SMALL;
		goto response_decode_end;
	}
	apdu->resplen = resplen;

	/* fill destination response apdu buffer with data */

	/* if plain data, just copy TLV data into apdu response */
	if (p_tlv->buf) {	/* plain data */
		memcpy(apdu->resp, p_tlv->data, p_tlv->len);
		apdu->resplen = p_tlv->len;
	}

	/* if encoded data, decode and store into apdu response */
	else if (e_tlv->buf) {	/* encoded data */
		DES_cblock iv = { 0, 0, 0, 0, 0, 0, 0, 0 };
		/* check data len */
		if ((e_tlv->len < 9) || ((e_tlv->len - 1) % 8) != 0) {
			msg = "Invalid length for Encoded data TLV";
			res = SC_ERROR_INVALID_DATA;
			goto response_decode_end;
		}
		/* first byte is padding info; check value */
		if (e_tlv->data[0] != 0x01) {
			msg = "Encoded TLV: Invalid padding info value";
			res = SC_ERROR_INVALID_DATA;
			goto response_decode_end;
		}
		/* prepare keys to decode */
		DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_enc[0]),
				      &k1);
		DES_set_key_unchecked((const_DES_cblock *) & (sm_session->session_enc[8]),
				      &k2);
		/* decrypt into response buffer
		 * by using 3DES CBC by mean of kenc and iv={0,...0} */
		DES_ede3_cbc_encrypt(&e_tlv->data[1], apdu->resp, e_tlv->len - 1,
				     &k1, &k2, &k1, &iv, DES_DECRYPT);
		apdu->resplen = e_tlv->len - 1;
		/* remove iso padding from response length */
		for (; (apdu->resplen > 0) && *(apdu->resp + apdu->resplen - 1) == 0x00; apdu->resplen--) ;	/* empty loop */

		if (*(apdu->resp + apdu->resplen - 1) != 0x80) {	/* check padding byte */
			msg =
			    "Decrypted TLV has no 0x80 iso padding indicator!";
			res = SC_ERROR_INVALID_DATA;
			goto response_decode_end;
		}
		/* everything ok: remove ending 0x80 from response */
		apdu->resplen--;
	}

	else
		apdu->resplen = 0;	/* neither plain, nor encoded data */

	/* that's all folks */
	res = SC_SUCCESS;

 response_decode_end:
	if (buffer)
		free(buffer);
	if (ccbuf)
		free(ccbuf);
	if (msg) {
		sc_log(ctx, "%s", msg);
	} else {
		cwa_trace_apdu(card, apdu, 1);
	}			/* trace apdu response */
	LOG_FUNC_RETURN(ctx, res);
}

/********************* default provider for cwa14890 ****************/

/* pre and post operations */

static int default_create_pre_ops(sc_card_t * card, cwa_provider_t * provider)
{
	return SC_SUCCESS;
}

static int default_create_post_ops(sc_card_t * card, cwa_provider_t * provider)
{
	return SC_SUCCESS;
}

static int default_get_root_ca_pubkey(sc_card_t * card, EVP_PKEY ** root_ca_key)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* retrieve CVC intermediate CA certificate and length */
static int default_get_cvc_ca_cert(sc_card_t * card, u8 ** cert,
				   size_t * length)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* retrieve CVC IFD certificate and length */
static int default_get_cvc_ifd_cert(sc_card_t * card, u8 ** cert,
				    size_t * length)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int default_get_ifd_privkey(sc_card_t * card, EVP_PKEY ** ifd_privkey)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* get ICC intermediate CA  path */
static int default_get_icc_intermediate_ca_cert(sc_card_t * card, X509 ** cert)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* get ICC certificate path */
static int default_get_icc_cert(sc_card_t * card, X509 ** cert)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for Root CA to validate CVC intermediate CA certs */
static int default_get_root_ca_pubkey_ref(sc_card_t * card, u8 ** buf,
					  size_t * len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for intermediate CA to validate IFD certs */
static int default_get_intermediate_ca_pubkey_ref(sc_card_t * card, u8 ** buf,
						  size_t * len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for IFD certificate */
static int default_get_ifd_pubkey_ref(sc_card_t * card, u8 ** buf, size_t * len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve key reference for ICC privkey */
static int default_get_icc_privkey_ref(sc_card_t * card, u8 ** buf,
				       size_t * len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve SN.IFD (8 bytes left padded with zeroes if needed) */
static int default_get_sn_ifd(sc_card_t * card)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/* Retrieve SN.ICC (8 bytes left padded with zeroes if needed) */
static int default_get_sn_icc(sc_card_t * card)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static cwa_provider_t default_cwa_provider = {

    /************ data related with SM operations *************************/

    /************ operations related with secure channel creation *********/

	/* pre and post operations */
	default_create_pre_ops,
	default_create_post_ops,

	/* Get ICC intermediate CA  path */
	default_get_icc_intermediate_ca_cert,
	/* Get ICC certificate path */
	default_get_icc_cert,

	/* Obtain RSA public key from RootCA */
	default_get_root_ca_pubkey,
	/* Obtain RSA IFD private key */
	default_get_ifd_privkey,

	/* Retrieve CVC intermediate CA certificate and length */
	default_get_cvc_ca_cert,
	/* Retrieve CVC IFD certificate and length */
	default_get_cvc_ifd_cert,

	/* Get public key references for Root CA to validate intermediate CA cert */
	default_get_root_ca_pubkey_ref,

	/* Get public key reference for IFD intermediate CA certificate */
	default_get_intermediate_ca_pubkey_ref,

	/* Get public key reference for IFD CVC certificate */
	default_get_ifd_pubkey_ref,

	/* Get ICC private key reference */
	default_get_icc_privkey_ref,

	/* Get IFD Serial Number */
	default_get_sn_ifd,

	/* Get ICC Serial Number */
	default_get_sn_icc,


};

/**
 * Get a copy of default cwa provider.
 *
 * @param card pointer to card info structure
 * @return copy of default provider or null on error
 */
cwa_provider_t *cwa_get_default_provider(sc_card_t * card)
{
	cwa_provider_t *res = NULL;
	if (!card || !card->ctx)
		return NULL;
	LOG_FUNC_CALLED(card->ctx);
	res = calloc(1, sizeof(cwa_provider_t));
	if (!res) {
		sc_log(card->ctx, "Cannot allocate space for cwa_provider");
		return NULL;
	}
	memcpy(res, &default_cwa_provider, sizeof(cwa_provider_t));
	return res;
}

/* end of cwa14890.c */
#undef __CWA14890_C__

#endif				/* ENABLE_OPENSSL */
