/*
 * Copyright (C) 2011-2018 Frank Morgner
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sm/sm-iso.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "sm-eac.h"
#include "sslutil.h"
#include <stdlib.h>
#include <string.h>

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#else
#define ssl_error(a)
#endif

char eac_default_flags = 0;
#define ISO_MSE 0x22

#if defined(ENABLE_OPENPACE)
#include <openssl/asn1t.h>

#define ASN1_APP_IMP_OPT(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION|ASN1_TFLG_OPTIONAL, tag, stname, field, type)
#define ASN1_APP_IMP(stname, field, type, tag) ASN1_EX_TYPE(ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION, tag, stname, field, type)

/* 0x67
 * Auxiliary authenticated data */
ASN1_ITEM_TEMPLATE(ASN1_AUXILIARY_DATA) = 
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			7, AuxiliaryAuthenticatedData, CVC_DISCRETIONARY_DATA_TEMPLATE)
ASN1_ITEM_TEMPLATE_END(ASN1_AUXILIARY_DATA)
IMPLEMENT_ASN1_FUNCTIONS(ASN1_AUXILIARY_DATA)
#endif

#if defined(ENABLE_OPENPACE) && defined(ENABLE_SM)
#include <eac/ca.h>
#include <eac/cv_cert.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/ta.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>


/*
 * MSE:Set AT
 */

typedef struct {
	ASN1_OBJECT *cryptographic_mechanism_reference;
	ASN1_OCTET_STRING *key_reference1;
	ASN1_OCTET_STRING *key_reference2;
	ASN1_OCTET_STRING *eph_pub_key;
	ASN1_AUXILIARY_DATA *auxiliary_data;
	CVC_CHAT *chat;
} EAC_MSE_C;
/* Note that we can not use ASN1_AUXILIARY_DATA for the auxiliary_data element
 * here. Due to limitations of OpenSSL it is not possible to *encode* an
 * optional item template (such as auxiliary_data) in an other item template
 * (such as ASN1_AUXILIARY_DATA). However, we can do
 *
 * EAC_MSE_C->auxiliary_data = d2i_ASN1_AUXILIARY_DATA(...)
 *
 * because they both use the same underlying struct.
 *
 * See also openssl/crypto/asn1/tasn_dec.c:183
 */
ASN1_SEQUENCE(EAC_MSE_C) = {
	/* 0x80
	 * Cryptographic mechanism reference */
	ASN1_IMP_OPT(EAC_MSE_C, cryptographic_mechanism_reference, ASN1_OBJECT, 0),
	/* 0x83
	 * Reference of a public key / secret key */
	ASN1_IMP_OPT(EAC_MSE_C, key_reference1, ASN1_OCTET_STRING, 3),
	/* 0x84
	 * Reference of a private key / Reference for computing a session key */
	ASN1_IMP_OPT(EAC_MSE_C, key_reference2, ASN1_OCTET_STRING, 4),
	/* 0x91
	 * Ephemeral Public Key */
	ASN1_IMP_OPT(EAC_MSE_C, eph_pub_key, ASN1_OCTET_STRING, 0x11),
	/* 0x67
	 * Auxiliary authenticated data. See note above. */
	ASN1_APP_IMP_SEQUENCE_OF_OPT(EAC_MSE_C, auxiliary_data, CVC_DISCRETIONARY_DATA_TEMPLATE, 7),
	/* Certificate Holder Authorization Template */
	ASN1_OPT(EAC_MSE_C, chat, CVC_CHAT),
} ASN1_SEQUENCE_END(EAC_MSE_C)
DECLARE_ASN1_FUNCTIONS(EAC_MSE_C)
IMPLEMENT_ASN1_FUNCTIONS(EAC_MSE_C)


/*
 * General Authenticate for PACE
 */

/* Protocol Command Data */
typedef struct {
	ASN1_OCTET_STRING *mapping_data;
	ASN1_OCTET_STRING *eph_pub_key;
	ASN1_OCTET_STRING *auth_token;
} EAC_GEN_AUTH_PACE_C_BODY;
ASN1_SEQUENCE(EAC_GEN_AUTH_PACE_C_BODY) = {
	/* 0x81
	 * Mapping Data */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_C_BODY, mapping_data, ASN1_OCTET_STRING, 1),
	/* 0x83
	 * Ephemeral Public Key */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_C_BODY, eph_pub_key, ASN1_OCTET_STRING, 3),
	/* 0x85
	 * Authentication Token */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_C_BODY, auth_token, ASN1_OCTET_STRING, 5),
} ASN1_SEQUENCE_END(EAC_GEN_AUTH_PACE_C_BODY)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_C_BODY)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_C_BODY)

typedef EAC_GEN_AUTH_PACE_C_BODY EAC_GEN_AUTH_PACE_C;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(EAC_GEN_AUTH_PACE_C) =
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			0x1c, EAC_GEN_AUTH_PACE_C, EAC_GEN_AUTH_PACE_C_BODY)
ASN1_ITEM_TEMPLATE_END(EAC_GEN_AUTH_PACE_C)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_C)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_C)

/* Protocol Response Data */
typedef struct {
	ASN1_OCTET_STRING *enc_nonce;
	ASN1_OCTET_STRING *mapping_data;
	ASN1_OCTET_STRING *eph_pub_key;
	ASN1_OCTET_STRING *auth_token;
	ASN1_OCTET_STRING *cur_car;
	ASN1_OCTET_STRING *prev_car;
} EAC_GEN_AUTH_PACE_R_BODY;
ASN1_SEQUENCE(EAC_GEN_AUTH_PACE_R_BODY) = {
	/* 0x80
	 * Encrypted Nonce */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, enc_nonce, ASN1_OCTET_STRING, 0),
	/* 0x82
	 * Mapping Data */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, mapping_data, ASN1_OCTET_STRING, 2),
	/* 0x84
	 * Ephemeral Public Key */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, eph_pub_key, ASN1_OCTET_STRING, 4),
	/* 0x86
	 * Authentication Token */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, auth_token, ASN1_OCTET_STRING, 6),
	/* 0x87
	 * Most recent Certification Authority Reference */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, cur_car, ASN1_OCTET_STRING, 7),
	/* 0x88
	 * Previous Certification Authority Reference */
	ASN1_IMP_OPT(EAC_GEN_AUTH_PACE_R_BODY, prev_car, ASN1_OCTET_STRING, 8),
} ASN1_SEQUENCE_END(EAC_GEN_AUTH_PACE_R_BODY)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_R_BODY)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_R_BODY)

typedef EAC_GEN_AUTH_PACE_R_BODY EAC_GEN_AUTH_PACE_R;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(EAC_GEN_AUTH_PACE_R) =
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			0x1c, EAC_GEN_AUTH_PACE_R, EAC_GEN_AUTH_PACE_R_BODY)
ASN1_ITEM_TEMPLATE_END(EAC_GEN_AUTH_PACE_R)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_R)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_PACE_R)


/*
 * General Authenticate for CA
 */

/* Protocol Command Data */
typedef struct eac_gen_auth_ca_cd_st {
	ASN1_OCTET_STRING *eph_pub_key;
} EAC_GEN_AUTH_CA_C_BODY;
ASN1_SEQUENCE(EAC_GEN_AUTH_CA_C_BODY) = {
	/* 0x80
	 * Ephemeral Public Key */
	ASN1_IMP_OPT(EAC_GEN_AUTH_CA_C_BODY, eph_pub_key, ASN1_OCTET_STRING, 0),
} ASN1_SEQUENCE_END(EAC_GEN_AUTH_CA_C_BODY)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_C_BODY)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_C_BODY)

typedef EAC_GEN_AUTH_CA_C_BODY EAC_GEN_AUTH_CA_C;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(EAC_GEN_AUTH_CA_C) =
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			0x1c, EAC_GEN_AUTH_CA_C, EAC_GEN_AUTH_CA_C_BODY)
ASN1_ITEM_TEMPLATE_END(EAC_GEN_AUTH_CA_C)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_C)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_C)

/* Protocol Response Data */
typedef struct eac_gen_auth_ca_rapdu_body_st {
	ASN1_OCTET_STRING *nonce;
	ASN1_OCTET_STRING *auth_token;
} EAC_GEN_AUTH_CA_R_BODY;
ASN1_SEQUENCE(EAC_GEN_AUTH_CA_R_BODY) = {
	/* 0x81
	 * Nonce */
	ASN1_IMP_OPT(EAC_GEN_AUTH_CA_R_BODY, nonce, ASN1_OCTET_STRING, 1),
	/* 0x82
	 * Authentication Token */
	ASN1_IMP_OPT(EAC_GEN_AUTH_CA_R_BODY, auth_token, ASN1_OCTET_STRING, 2),
} ASN1_SEQUENCE_END(EAC_GEN_AUTH_CA_R_BODY)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_R_BODY)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_R_BODY)

typedef EAC_GEN_AUTH_CA_R_BODY EAC_GEN_AUTH_CA_R;
/* 0x7C
 * Dynamic Authentication Data */
ASN1_ITEM_TEMPLATE(EAC_GEN_AUTH_CA_R) =
	ASN1_EX_TEMPLATE_TYPE(
			ASN1_TFLG_IMPTAG|ASN1_TFLG_APPLICATION,
			0x1c, EAC_GEN_AUTH_CA_R, EAC_GEN_AUTH_CA_R_BODY)
ASN1_ITEM_TEMPLATE_END(EAC_GEN_AUTH_CA_R)
DECLARE_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_R)
IMPLEMENT_ASN1_FUNCTIONS(EAC_GEN_AUTH_CA_R)



/** @brief NPA secure messaging context */
struct eac_sm_ctx {
	/** @brief EAC context */
	EAC_CTX *ctx;
	/** @brief Certificate Description given on initialization of PACE */
	BUF_MEM *certificate_description;
	/** @brief picc's compressed ephemeral public key of PACE */
	BUF_MEM *id_icc;
	/** @brief PCD's compressed ephemeral public key of CA */
	BUF_MEM *eph_pub_key;
	/** @brief Auxiliary Data */
	BUF_MEM *auxiliary_data;
	char flags;
};


/* included in OpenPACE, but not propagated */
extern BUF_MEM *BUF_MEM_create(size_t len);
extern BUF_MEM *BUF_MEM_create_init(const void *buf, size_t len);


static int eac_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc);
static int eac_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data);
static int eac_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **outdata);
static int eac_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *mac, size_t maclen,
		const u8 *macdata, size_t macdatalen);
static int eac_sm_pre_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu);
static int eac_sm_post_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *sm_apdu);
static int eac_sm_finish(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu);
static void eac_sm_clear_free(const struct iso_sm_ctx *ctx);




static struct eac_sm_ctx *
eac_sm_ctx_create(EAC_CTX *ctx, const unsigned char *certificate_description,
		size_t certificate_description_length,
		const unsigned char *id_icc, size_t id_icc_length)
{
	struct eac_sm_ctx *out = malloc(sizeof *out);
	if (!out)
		goto err;

	out->ctx = ctx;

	if (certificate_description && certificate_description_length) {
		out->certificate_description =
			BUF_MEM_create_init(certificate_description,
					certificate_description_length);
		if (!out->certificate_description)
			goto err;
	} else
		out->certificate_description = NULL;

	if (id_icc && id_icc_length) {
		out->id_icc = BUF_MEM_create_init(id_icc, id_icc_length);
		if (!out->id_icc)
			goto err;
	} else
		out->id_icc = NULL;

	out->eph_pub_key = NULL;
	out->auxiliary_data = NULL;

	out->flags = eac_default_flags;
	if (out->flags & EAC_FLAG_DISABLE_CHECK_TA)
		TA_disable_checks(out->ctx);
	if (out->flags & EAC_FLAG_DISABLE_CHECK_CA)
		CA_disable_passive_authentication(out->ctx);

	return out;

err:
	free(out);
	return NULL;
}

static int
eac_sm_start(sc_card_t *card, EAC_CTX *eac_ctx,
		const unsigned char *certificate_description,
		size_t certificate_description_length,
		const unsigned char *id_icc, size_t id_icc_length)
{
	int r;
	struct iso_sm_ctx *sctx = NULL;

	if (!eac_ctx || !eac_ctx->key_ctx) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	sctx = iso_sm_ctx_create();
	if (!sctx) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	sctx->priv_data = eac_sm_ctx_create(eac_ctx,
			certificate_description, certificate_description_length,
			id_icc, id_icc_length);
	if (!sctx->priv_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	sctx->authenticate = eac_sm_authenticate;
	sctx->encrypt = eac_sm_encrypt;
	sctx->decrypt = eac_sm_decrypt;
	sctx->verify_authentication = eac_sm_verify_authentication;
	sctx->pre_transmit = eac_sm_pre_transmit;
	sctx->post_transmit = eac_sm_post_transmit;
	sctx->finish = eac_sm_finish;
	sctx->clear_free = eac_sm_clear_free;
	sctx->padding_indicator = SM_ISO_PADDING;
	sctx->block_length = EVP_CIPHER_block_size(eac_ctx->key_ctx->cipher);

	r = iso_sm_start(card, sctx);

err:
	if (r < 0)
		iso_sm_ctx_clear_free(sctx);

	return r;
}

static int get_ef_card_access(sc_card_t *card,
		u8 **ef_cardaccess, size_t *length_ef_cardaccess)
{
	return iso7816_read_binary_sfid(card, SFID_EF_CARDACCESS, ef_cardaccess, length_ef_cardaccess);
}

static int format_mse_cdata(struct sc_context *ctx, int protocol,
		const unsigned char *key_reference1, size_t key_reference1_len,
		const unsigned char *key_reference2, size_t key_reference2_len,
		const unsigned char *eph_pub_key, size_t eph_pub_key_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len,
		const CVC_CHAT *chat, unsigned char **cdata)
{
	EAC_MSE_C *data = NULL;
	unsigned char *data_sequence = NULL;
	const unsigned char *data_no_sequence;
	unsigned char *p;
	long length;
	int r, class, tag;

	if (!cdata) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	data = EAC_MSE_C_new();
	if (!data) {
		ssl_error(ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (protocol) {
		data->cryptographic_mechanism_reference = OBJ_nid2obj(protocol);
		if (!data->cryptographic_mechanism_reference) {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting Cryptographic mechanism reference of MSE:Set AT data");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (key_reference1 && key_reference1_len) {
		data->key_reference1 = ASN1_OCTET_STRING_new();
		if (!data->key_reference1
				|| !ASN1_OCTET_STRING_set(
					data->key_reference1, key_reference1, key_reference1_len)) {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting key reference 1 of MSE:Set AT data");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (key_reference2 && key_reference2_len) {
		data->key_reference2 = ASN1_OCTET_STRING_new();
		if (!data->key_reference2
				|| !ASN1_OCTET_STRING_set(
					data->key_reference2, key_reference2, key_reference2_len)) {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting key reference 2 of MSE:Set AT data");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (eph_pub_key && eph_pub_key_len) {
		data->eph_pub_key = ASN1_OCTET_STRING_new();
		if (!data->eph_pub_key
				|| !ASN1_OCTET_STRING_set(
					data->eph_pub_key, eph_pub_key, eph_pub_key_len)) {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting ephemeral Public Key of MSE:Set AT data");
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (auxiliary_data && auxiliary_data_len) {
		if (!d2i_ASN1_AUXILIARY_DATA(&data->auxiliary_data, &auxiliary_data, auxiliary_data_len)) {
			sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error setting authenticated auxiliary data of MSE:Set AT data");
			ssl_error(ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	data->chat = (CVC_CHAT *) chat;


	length = i2d_EAC_MSE_C(data, &data_sequence);
	data_no_sequence = data_sequence;
	if (length < 0
			|| (0x80 & ASN1_get_object(&data_no_sequence, &length, &tag, &class, length))) {
		sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Error encoding MSE:Set AT APDU data");
		ssl_error(ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	if (length <= 0) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sc_debug_hex(ctx, SC_LOG_DEBUG_SM, "MSE command data", data_no_sequence, length);


	p = realloc(*cdata, length);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(p, data_no_sequence, length);
	*cdata = p;
	r = length;

err:
	if (data) {
		/* do not free the functions parameter chat */
		data->chat = NULL;
		EAC_MSE_C_free(data);
	}
	OPENSSL_free(data_sequence);

	return r;
}

static int eac_mse(sc_card_t *card,
		unsigned char p1, unsigned char p2, int protocol,
		const unsigned char *key_reference1, size_t key_reference1_len,
		const unsigned char *key_reference2, size_t key_reference2_len,
		const unsigned char *eph_pub_key, size_t eph_pub_key_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len,
		const CVC_CHAT *chat, u8 *sw1, u8 *sw2)
{
	sc_apdu_t apdu;
	unsigned char *d = NULL;
	int r;

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	
	r = format_mse_cdata(card->ctx, protocol, key_reference1,
			key_reference1_len, key_reference2, key_reference2_len,
			eph_pub_key, eph_pub_key_len, auxiliary_data, auxiliary_data_len,
			chat, &d);
	if (r < 0)
		goto err;
	sc_format_apdu_ex(card, &apdu, ISO_MSE, p1, p2,
			d, r, NULL, 0);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	if (apdu.resplen) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MSE:Set AT response data should be empty "
				"(contains %"SC_FORMAT_LEN_SIZE_T"u bytes)", apdu.resplen);
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}

	if (sw1)
		*sw1 = apdu.sw1;
	if (sw2)
		*sw2 = apdu.sw2;

err:
	free(d);

	return r;
}

static int eac_mse_set_at(sc_card_t *card, unsigned char p1, int protocol,
		const unsigned char *key_reference1, size_t key_reference1_len,
		const unsigned char *key_reference2, size_t key_reference2_len,
		const unsigned char *eph_pub_key, size_t eph_pub_key_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len,
		const CVC_CHAT *chat, u8 *sw1, u8 *sw2)
{
	return eac_mse(card, p1, 0xA4, protocol, key_reference1,
			key_reference1_len, key_reference2, key_reference2_len,
			eph_pub_key, eph_pub_key_len, auxiliary_data, auxiliary_data_len,
			chat, sw1, sw2);
}

static int eac_mse_set_at_pace(sc_card_t *card, int protocol,
		enum s_type secret_key, const CVC_CHAT *chat, u8 *sw1, u8 *sw2)
{
	int r, tries;
	unsigned char key = secret_key;
   
	r = eac_mse_set_at(card, 0xC1, protocol, &key, sizeof key, NULL,
			0, NULL, 0, NULL, 0, chat, sw1, sw2);
	if (0 > r)
		goto err;

	if (*sw1 == 0x63) {
		if ((*sw2 & 0xc0) == 0xc0) {
			tries = *sw2 & 0x0f;
			if (tries <= 1) {
				/* this is only a warning... */
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Remaining tries: %d (%s must be %s)\n",
						tries, eac_secret_name(secret_key),
						tries ? "resumed" : "unblocked");
			}
			r = SC_SUCCESS;
		} else {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown status bytes: SW1=%02X, SW2=%02X\n",
					*sw1, *sw2);
			r = SC_ERROR_CARD_CMD_FAILED;
		}
	} else if (*sw1 == 0x62 && *sw2 == 0x83) {
			 sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Password is deactivated\n");
			 r = SC_ERROR_AUTH_METHOD_BLOCKED;
	} else {
		r = sc_check_sw(card, *sw1, *sw2);
	}

err:
	return r;
}


#define ISO_GENERAL_AUTHENTICATE 0x86
#define ISO_COMMAND_CHAINING 0x10
static int eac_gen_auth_1_encrypted_nonce(sc_card_t *card,
		u8 **enc_nonce, size_t *enc_nonce_len)
{
	sc_apdu_t apdu;
	EAC_GEN_AUTH_PACE_C *c_data = NULL;
	EAC_GEN_AUTH_PACE_R *r_data = NULL;
	unsigned char *d = NULL, *p;
	int r, l;
	unsigned char resp[SC_MAX_EXT_APDU_RESP_SIZE];

	c_data = EAC_GEN_AUTH_PACE_C_new();
	if (!c_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	r = i2d_EAC_GEN_AUTH_PACE_C(c_data, &d);
	if (r < 0) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	sc_format_apdu_ex(card, &apdu, ISO_GENERAL_AUTHENTICATE, 0x00, 0x00,
			d, r, resp, sizeof resp);
	apdu.cla = ISO_COMMAND_CHAINING;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Encrypted Nonce) command data", apdu.data, apdu.datalen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		goto err;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Encrypted Nonce) response data", apdu.resp, apdu.resplen);

	if (!d2i_EAC_GEN_AUTH_PACE_R(&r_data,
				(const unsigned char **) &apdu.resp, apdu.resplen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (!r_data->enc_nonce
			|| r_data->mapping_data
			|| r_data->eph_pub_key
			|| r_data->auth_token
			|| r_data->cur_car
			|| r_data->prev_car) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
				"step 1 should (only) contain the encrypted nonce.");
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}
	p = r_data->enc_nonce->data;
	l = r_data->enc_nonce->length;

	*enc_nonce = malloc(l);
	if (!*enc_nonce) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	/* Flawfinder: ignore */
	memcpy(*enc_nonce, p, l);
	*enc_nonce_len = l;

err:
	if (c_data)
		EAC_GEN_AUTH_PACE_C_free(c_data);
	OPENSSL_free(d);
	if (r_data)
		EAC_GEN_AUTH_PACE_R_free(r_data);

	return r;
}
static int eac_gen_auth_2_map_nonce(sc_card_t *card,
		const u8 *in, size_t in_len,
		u8 **map_data_out, size_t *map_data_out_len)
{
	sc_apdu_t apdu;
	EAC_GEN_AUTH_PACE_C *c_data = NULL;
	EAC_GEN_AUTH_PACE_R *r_data = NULL;
	unsigned char *d = NULL, *p;
	int r, l;
	unsigned char resp[SC_MAX_EXT_APDU_RESP_SIZE];

	c_data = EAC_GEN_AUTH_PACE_C_new();
	if (!c_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	c_data->mapping_data = ASN1_OCTET_STRING_new();
	if (!c_data->mapping_data
			|| !ASN1_OCTET_STRING_set(
				c_data->mapping_data, in, in_len)) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = i2d_EAC_GEN_AUTH_PACE_C(c_data, &d);
	if (r < 0) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sc_format_apdu_ex(card, &apdu, ISO_GENERAL_AUTHENTICATE, 0x00, 0x00,
		   	d, r, resp, sizeof resp);
	apdu.cla = ISO_COMMAND_CHAINING;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Map Nonce) command data", apdu.data, apdu.datalen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		goto err;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Map Nonce) response data", apdu.resp, apdu.resplen);

	if (!d2i_EAC_GEN_AUTH_PACE_R(&r_data,
				(const unsigned char **) &apdu.resp, apdu.resplen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (r_data->enc_nonce
			|| !r_data->mapping_data
			|| r_data->eph_pub_key
			|| r_data->auth_token
			|| r_data->cur_car
			|| r_data->prev_car) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
				"step 2 should (only) contain the mapping data.");
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}
	p = r_data->mapping_data->data;
	l = r_data->mapping_data->length;

	*map_data_out = malloc(l);
	if (!*map_data_out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	/* Flawfinder: ignore */
	memcpy(*map_data_out, p, l);
	*map_data_out_len = l;

err:
	if (c_data)
		EAC_GEN_AUTH_PACE_C_free(c_data);
	OPENSSL_free(d);
	if (r_data)
		EAC_GEN_AUTH_PACE_R_free(r_data);

	return r;
}
static int eac_gen_auth_3_perform_key_agreement(sc_card_t *card,
		const u8 *in, size_t in_len,
		u8 **eph_pub_key_out, size_t *eph_pub_key_out_len)
{
	sc_apdu_t apdu;
	EAC_GEN_AUTH_PACE_C *c_data = NULL;
	EAC_GEN_AUTH_PACE_R *r_data = NULL;
	unsigned char *d = NULL, *p;
	int r, l;
	unsigned char resp[SC_MAX_EXT_APDU_RESP_SIZE];

	c_data = EAC_GEN_AUTH_PACE_C_new();
	if (!c_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	c_data->eph_pub_key = ASN1_OCTET_STRING_new();
	if (!c_data->eph_pub_key
			|| !ASN1_OCTET_STRING_set(
				c_data->eph_pub_key, in, in_len)) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = i2d_EAC_GEN_AUTH_PACE_C(c_data, &d);
	if (r < 0) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sc_format_apdu_ex(card, &apdu, ISO_GENERAL_AUTHENTICATE, 0x00, 0x00,
			d, r, resp, sizeof resp);
	apdu.cla = ISO_COMMAND_CHAINING;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		goto err;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

	if (!d2i_EAC_GEN_AUTH_PACE_R(&r_data,
				(const unsigned char **) &apdu.resp, apdu.resplen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (r_data->enc_nonce
			|| r_data->mapping_data
			|| !r_data->eph_pub_key
			|| r_data->auth_token
			|| r_data->cur_car
			|| r_data->prev_car) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
				"step 3 should (only) contain the ephemeral public key.");
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}
	p = r_data->eph_pub_key->data;
	l = r_data->eph_pub_key->length;

	*eph_pub_key_out = malloc(l);
	if (!*eph_pub_key_out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	/* Flawfinder: ignore */
	memcpy(*eph_pub_key_out, p, l);
	*eph_pub_key_out_len = l;

err:
	if (c_data)
		EAC_GEN_AUTH_PACE_C_free(c_data);
	OPENSSL_free(d);
	if (r_data)
		EAC_GEN_AUTH_PACE_R_free(r_data);

	return r;
}
static int eac_gen_auth_4_mutual_authentication(sc_card_t *card,
		const u8 *in, size_t in_len,
		u8 **auth_token_out, size_t *auth_token_out_len,
		u8 **recent_car, size_t *recent_car_len,
		u8 **prev_car, size_t *prev_car_len)
{
	sc_apdu_t apdu;
	EAC_GEN_AUTH_PACE_C *c_data = NULL;
	EAC_GEN_AUTH_PACE_R *r_data = NULL;
	unsigned char *d = NULL, *p;
	int r, l;
	unsigned char resp[SC_MAX_EXT_APDU_RESP_SIZE];

	c_data = EAC_GEN_AUTH_PACE_C_new();
	if (!c_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	c_data->auth_token = ASN1_OCTET_STRING_new();
	if (!c_data->auth_token
			|| !ASN1_OCTET_STRING_set(
				c_data->auth_token, in, in_len)) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = i2d_EAC_GEN_AUTH_PACE_C(c_data, &d);
	if (r < 0) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	sc_format_apdu_ex(card, &apdu, ISO_GENERAL_AUTHENTICATE, 0x00, 0x00,
			d, r, resp, sizeof resp);

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		goto err;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

	if (!d2i_EAC_GEN_AUTH_PACE_R(&r_data,
				(const unsigned char **) &apdu.resp, apdu.resplen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (r_data->enc_nonce
			|| r_data->mapping_data
			|| r_data->eph_pub_key
			|| !r_data->auth_token) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for "
				"step 4 should (only) contain the authentication token.");
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}
	p = r_data->auth_token->data;
	l = r_data->auth_token->length;
	if (r_data->cur_car) {
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "Most recent Certificate Authority Reference",
				r_data->cur_car->data, r_data->cur_car->length);
		*recent_car = malloc(r_data->cur_car->length);
		if (!*recent_car) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		/* Flawfinder: ignore */
		memcpy(*recent_car, r_data->cur_car->data, r_data->cur_car->length);
		*recent_car_len = r_data->cur_car->length;
	} else
		*recent_car_len = 0;
	if (r_data->prev_car) {
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "Previous Certificate Authority Reference",
				r_data->prev_car->data, r_data->prev_car->length);
		*prev_car = malloc(r_data->prev_car->length);
		if (!*prev_car) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		/* Flawfinder: ignore */
		memcpy(*prev_car, r_data->prev_car->data, r_data->prev_car->length);
		*prev_car_len = r_data->prev_car->length;
	} else
		*prev_car_len = 0;

	*auth_token_out = malloc(l);
	if (!*auth_token_out) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	/* Flawfinder: ignore */
	memcpy(*auth_token_out, p, l);
	*auth_token_out_len = l;

err:
	if (c_data)
		EAC_GEN_AUTH_PACE_C_free(c_data);
	OPENSSL_free(d);
	if (r_data)
		EAC_GEN_AUTH_PACE_R_free(r_data);

	return r;
}

static PACE_SEC *
get_psec(sc_card_t *card, const char *pin, size_t length_pin, enum s_type pin_id)
{
	char *p = NULL;
	PACE_SEC *r;
	/* Flawfinder: ignore */
	char buf[EAC_MAX_MRZ_LEN > 32 ? EAC_MAX_MRZ_LEN : 32];

	if (!length_pin || !pin) {
		if (0 > snprintf(buf, sizeof buf, "Please enter your %s: ",
					eac_secret_name(pin_id))) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create password prompt.\n");
			return NULL;
		}
		p = malloc(EAC_MAX_MRZ_LEN+1);
		if (!p) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for %s.\n",
					eac_secret_name(pin_id));
			return NULL;
		}
		if (0 > EVP_read_pw_string_min(p, 0, EAC_MAX_MRZ_LEN, buf, 0)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read %s.\n",
					eac_secret_name(pin_id));
			return NULL;
		}
		length_pin = strlen(p);
		if (length_pin > EAC_MAX_MRZ_LEN) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "MRZ too long");
			return NULL;
		}
		pin = p;
	}

	r = PACE_SEC_new(pin, length_pin, pin_id);

	if (p) {
		OPENSSL_cleanse(p, length_pin);
		free(p);
	}

	return r;
}


int perform_pace(sc_card_t *card,
		struct establish_pace_channel_input pace_input,
		struct establish_pace_channel_output *pace_output,
		enum eac_tr_version tr_version)
{
	u8 *p = NULL;
	EAC_CTX *eac_ctx = NULL;
	BUF_MEM *enc_nonce = NULL, *mdata = NULL, *mdata_opp = NULL,
			*token_opp = NULL, *token = NULL, *pub = NULL, *pub_opp = NULL,
			*comp_pub = NULL, *comp_pub_opp = NULL;
	PACE_SEC *sec = NULL;
	CVC_CHAT *chat = NULL;
	BIO *bio_stdout = NULL;
	CVC_CERTIFICATE_DESCRIPTION *desc = NULL;
	int r;
	const unsigned char *pp;

	if (!card || !card->reader || !card->reader->ops || !pace_output)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* show description in advance to give the user more time to read it...
	 * This behaviour differs from TR-03119 v1.1 p. 44. */
	if (pace_input.certificate_description_length &&
			pace_input.certificate_description) {

		pp = pace_input.certificate_description;
		if (!d2i_CVC_CERTIFICATE_DESCRIPTION(&desc,
					&pp, pace_input.certificate_description_length)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse certificate description.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		if (!bio_stdout) {
			bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
			if (!bio_stdout) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
				ssl_error(card->ctx);
				r = SC_ERROR_INTERNAL;
				goto err;
			}
		}

		printf("Certificate Description\n");
		switch(certificate_description_print(bio_stdout, desc, 8)) {
			case 0:
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print certificate description.");
				ssl_error(card->ctx);
				r = SC_ERROR_INTERNAL;
				goto err;
				break;
			case 1:
				/* text format */
				break;
			case 2:
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
						"HTML format can not (yet) be handled.");
				r = SC_ERROR_NOT_SUPPORTED;
				goto err;
				break;
			case 3:
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
						"PDF format can not (yet) be handled.");
				r = SC_ERROR_NOT_SUPPORTED;
				goto err;
				break;
			default:
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Certificate description in "
						"unknown format can not be handled.");
				r = SC_ERROR_NOT_SUPPORTED;
				goto err;
				break;
		}
	}

	/* show chat in advance to give the user more time to read it...
	 * This behaviour differs from TR-03119 v1.1 p. 44. */
	if (pace_input.chat_length && pace_input.chat) {

		if (!bio_stdout) {
			bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
			if (!bio_stdout) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not create output buffer.");
				ssl_error(card->ctx);
				r = SC_ERROR_INTERNAL;
				goto err;
			}
		}

		pp = pace_input.chat;
		if (!d2i_CVC_CHAT(&chat, &pp, pace_input.chat_length)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse card holder authorization template (CHAT).");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		printf("Card holder authorization template (CHAT)\n");
		if (!cvc_chat_print(bio_stdout, chat, 8)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not print card holder authorization template (CHAT).");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
	}

	if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC
			&& card->reader->ops->perform_pace) {
		r = card->reader->ops->perform_pace(card->reader, &pace_input, pace_output);
		if (r < 0)
			goto err;
	} else {
		if (!pace_output->ef_cardaccess_length || !pace_output->ef_cardaccess) {
			r = get_ef_card_access(card, &pace_output->ef_cardaccess,
					&pace_output->ef_cardaccess_length);
			if (r < 0) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardAccess.");
				goto err;
			}
		}

		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "EF.CardAccess", pace_output->ef_cardaccess,
				pace_output->ef_cardaccess_length);

		/* XXX Card capabilities should be determined by the OpenSC card driver. We
		 * set it here to be able to use the nPA without patching OpenSC. By
		 * now we have read the EF.CardAccess so the assumption to have an nPA
		 * seems valid. */
		card->caps |= SC_CARD_CAP_APDU_EXT;

		eac_ctx = EAC_CTX_new();
		if (!eac_ctx
				|| !EAC_CTX_init_ef_cardaccess(pace_output->ef_cardaccess,
					pace_output->ef_cardaccess_length, eac_ctx)
				|| !eac_ctx->pace_ctx) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse EF.CardAccess.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		eac_ctx->tr_version = tr_version;

		r = eac_mse_set_at_pace(card, eac_ctx->pace_ctx->protocol,
				pace_input.pin_id, chat, &pace_output->mse_set_at_sw1,
				&pace_output->mse_set_at_sw2);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol properties "
					"(MSE: Set AT failed).");
			goto err;
		}

		enc_nonce = BUF_MEM_new();
		if (!enc_nonce) {
			ssl_error(card->ctx);
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		r = eac_gen_auth_1_encrypted_nonce(card, (u8 **) &enc_nonce->data,
				&enc_nonce->length);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get encrypted nonce from card "
					"(General Authenticate step 1 failed).");
			goto err;
		}
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "Encrypted nonce from MRTD", (u8 *)enc_nonce->data, enc_nonce->length);
		enc_nonce->max = enc_nonce->length;

		sec = get_psec(card, (char *) pace_input.pin, pace_input.pin_length,
				pace_input.pin_id);
		if (!sec) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encode PACE secret.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		if (!PACE_STEP2_dec_nonce(eac_ctx, sec, enc_nonce)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt MRTD's nonce.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		mdata_opp = BUF_MEM_new();
		mdata = PACE_STEP3A_generate_mapping_data(eac_ctx);
		if (!mdata || !mdata_opp) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate mapping data.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		r = eac_gen_auth_2_map_nonce(card, (u8 *) mdata->data, mdata->length,
				(u8 **) &mdata_opp->data, &mdata_opp->length);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange mapping data with card "
					"(General Authenticate step 2 failed).");
			goto err;
		}
		mdata_opp->max = mdata_opp->length;
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "Mapping data from MRTD", (u8 *) mdata_opp->data, mdata_opp->length);

		if (!PACE_STEP3A_map_generator(eac_ctx, mdata_opp)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not map generator.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		pub = PACE_STEP3B_generate_ephemeral_key(eac_ctx);
		pub_opp = BUF_MEM_new();
		if (!pub || !pub_opp) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate ephemeral domain parameter or "
					"ephemeral key pair.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		r = eac_gen_auth_3_perform_key_agreement(card, (u8 *) pub->data, pub->length,
				(u8 **) &pub_opp->data, &pub_opp->length);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange ephemeral public key with card "
					"(General Authenticate step 3 failed).");
			goto err;
		}
		pub_opp->max = pub_opp->length;
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "Ephemeral public key from MRTD", (u8 *) pub_opp->data, pub_opp->length);


		if (!PACE_STEP3B_compute_shared_secret(eac_ctx, pub_opp)
				|| !PACE_STEP3C_derive_keys(eac_ctx)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute ephemeral shared secret or "
					"derive keys for encryption and authentication.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		token = PACE_STEP3D_compute_authentication_token(eac_ctx, pub_opp);
		token_opp = BUF_MEM_new();
		if (!token || !token_opp) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute authentication token.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		r = eac_gen_auth_4_mutual_authentication(card, (u8 *) token->data, token->length,
				(u8 **) &token_opp->data, &token_opp->length,
				&pace_output->recent_car, &pace_output->recent_car_length,
				&pace_output->previous_car, &pace_output->previous_car_length);

		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not exchange authentication token with card "
					"(General Authenticate step 4 failed).");
			goto err;
		}
		token_opp->max = token_opp->length;

		if (!PACE_STEP3D_verify_authentication_token(eac_ctx, token_opp)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify authentication token.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		/* Initialize secure channel */
		if (!EAC_CTX_set_encryption_ctx(eac_ctx, EAC_ID_PACE)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize encryption.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		/* Identifier for ICC and PCD */
		comp_pub = EAC_Comp(eac_ctx, EAC_ID_PACE, pub);
		comp_pub_opp = EAC_Comp(eac_ctx, EAC_ID_PACE, pub_opp);
		if (!comp_pub || !comp_pub_opp) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compress public keys for identification.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		if (comp_pub_opp->length == 0) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		p = realloc(pace_output->id_icc, comp_pub_opp->length);
		if (!p) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID ICC.\n");
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		pace_output->id_icc = p;
		pace_output->id_icc_length = comp_pub_opp->length;
		/* Flawfinder: ignore */
		memcpy(pace_output->id_icc, comp_pub_opp->data, comp_pub_opp->length);
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "ID ICC", pace_output->id_icc,
				pace_output->id_icc_length);
		if (comp_pub->length == 0) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		p = realloc(pace_output->id_pcd, comp_pub->length);
		if (!p) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Not enough memory for ID PCD.\n");
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		pace_output->id_pcd = p;
		pace_output->id_pcd_length = comp_pub->length;
		/* Flawfinder: ignore */
		memcpy(pace_output->id_pcd, comp_pub->data, comp_pub->length);
		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "ID PCD", pace_output->id_pcd,
				pace_output->id_pcd_length);

		r = eac_sm_start(card, eac_ctx, pace_input.certificate_description,
				pace_input.certificate_description_length, pace_output->id_icc,
				pace_output->id_icc_length);
	}

err:
	if (enc_nonce)
		BUF_MEM_free(enc_nonce);
	if (mdata)
		BUF_MEM_free(mdata);
	if (mdata_opp)
		BUF_MEM_free(mdata_opp);
	if (token_opp)
		BUF_MEM_free(token_opp);
	if (token)
		BUF_MEM_free(token);
	if (pub)
		BUF_MEM_free(pub);
	if (pub_opp)
		BUF_MEM_free(pub_opp);
	if (comp_pub_opp)
		BUF_MEM_free(comp_pub_opp);
	if (comp_pub)
		BUF_MEM_free(comp_pub);
	PACE_SEC_clear_free(sec);
	if (bio_stdout)
		BIO_free_all(bio_stdout);
	if (desc)
		CVC_CERTIFICATE_DESCRIPTION_free(desc);
	if (chat)
		CVC_CHAT_free(chat);

	if (r < 0)
		EAC_CTX_clear_free(eac_ctx);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
}

static int eac_mse_set_at_ta(sc_card_t *card, int protocol,
		const unsigned char *chr, size_t chr_len,
		const unsigned char *eph_pub_key, size_t eph_pub_key_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len)
{
	return eac_mse_set_at(card, 0x81, protocol, chr, chr_len, NULL, 0,
			eph_pub_key, eph_pub_key_len, auxiliary_data, auxiliary_data_len,
			NULL, NULL, NULL);
}

static int eac_mse_set_dst(sc_card_t *card,
		const unsigned char *chr, size_t chr_len)
{
	return eac_mse(card, 0x81, 0xb6, 0, chr, chr_len, NULL, 0, NULL, 0, NULL,
			0, NULL, NULL, NULL);
}

static int eac_get_challenge(sc_card_t *card,
		unsigned char *challenge, size_t len)
{
	sc_apdu_t apdu;
	int r;

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	sc_format_apdu_ex(card, &apdu, 0x84, 0x00, 0x00, NULL, 0, challenge, len);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
	return r;
}

static int eac_verify(sc_card_t *card,
		const unsigned char *cert, size_t cert_len)
{
	sc_apdu_t apdu;
	int r, class, tag;
	long int length;

	memset(&apdu, 0, sizeof apdu);

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	if (0x80 & ASN1_get_object(&cert, &length, &tag, &class, cert_len)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error decoding Certificate");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	sc_format_apdu_ex(card, &apdu, 0x2A, 0x00, 0xbe, (unsigned char *) cert, length, NULL, 0);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
	return r;
}

static int eac_external_authenticate(sc_card_t *card,
		unsigned char *signature, size_t signature_len)
{
	int r;
	sc_apdu_t apdu;
	memset(&apdu, 0, sizeof apdu);

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	sc_format_apdu_ex(card, &apdu, 0x82, 0x00, 0x00, signature, signature_len, NULL, 0);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

err:
	return r;
}

static void eac_sm_clear_free_without_ctx(const struct iso_sm_ctx *ctx)
{
	if (ctx) {
		struct eac_sm_ctx *eacsmctx = ctx->priv_data;
		if (eacsmctx)
			eacsmctx->ctx = NULL;
		eac_sm_clear_free(ctx);
	}
}

#define TA_NONCE_LENGTH 8
int perform_terminal_authentication(sc_card_t *card,
		const unsigned char **certs, const size_t *certs_lens,
		const unsigned char *privkey, size_t privkey_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len)
{
	int r;
	const unsigned char *cert = NULL;
	size_t cert_len = 0, ef_cardaccess_length = 0;
	CVC_CERT *cvc_cert = NULL;
	BUF_MEM *nonce = NULL, *signature = NULL;
	struct iso_sm_ctx *isosmctx = NULL;
	struct eac_sm_ctx *eacsmctx = NULL;
	unsigned char *ef_cardaccess = NULL;
	EAC_CTX *eac_ctx = NULL;
	const unsigned char *chr = NULL;
	size_t chr_len = 0;

	if (!card || !certs_lens || !certs) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	if (!card->sm_ctx.info.cmd_data) {
		card->sm_ctx.info.cmd_data = iso_sm_ctx_create();
		card->sm_ctx.ops.close = iso_sm_close;
	}
	if (!card->sm_ctx.info.cmd_data) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	isosmctx = card->sm_ctx.info.cmd_data;
	if (!isosmctx->priv_data) {
		r = get_ef_card_access(card, &ef_cardaccess, &ef_cardaccess_length);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardAccess.");
			goto err;
		}

		sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "EF.CardAccess", ef_cardaccess,
				ef_cardaccess_length);

		/* XXX Card capabilities should be determined by the OpenSC card driver. We
		 * set it here to be able to use the nPA without patching OpenSC. By
		 * now we have read the EF.CardAccess so the assumption to have an nPA
		 * seems valid. */
		card->caps |= SC_CARD_CAP_APDU_EXT;

		eac_ctx = EAC_CTX_new();
		if (!eac_ctx
				|| !EAC_CTX_init_ef_cardaccess(ef_cardaccess,
					ef_cardaccess_length, eac_ctx)) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse EF.CardAccess.");
			ssl_error(card->ctx);
			r = SC_ERROR_INTERNAL;
			goto err;
		}

		isosmctx->priv_data = eac_sm_ctx_create(eac_ctx, NULL, 0, NULL, 0);
		if (!isosmctx->priv_data) {
			r = SC_ERROR_INTERNAL;
			goto err;
		}
		/* when iso_sm_ctx_clear_free is called, we want everything to be freed
		 * except the EAC_CTX, because it is needed for performing SM *after*
		 * iso_sm_start was called. */
		isosmctx->clear_free = eac_sm_clear_free_without_ctx;
		eac_ctx = NULL;
	}
	eacsmctx = isosmctx->priv_data;


	while (*certs && *certs_lens) {
		cert = *certs;
		cert_len = *certs_lens;
		if (!CVC_d2i_CVC_CERT(&cvc_cert, &cert, cert_len) || !cvc_cert
				|| !cvc_cert->body || !cvc_cert->body->certificate_authority_reference
				|| !cvc_cert->body->certificate_holder_reference) {
			ssl_error(card->ctx);
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
		cert = *certs;

		r = eac_mse_set_dst(card,
				cvc_cert->body->certificate_authority_reference->data,
				cvc_cert->body->certificate_authority_reference->length);
		if (r < 0) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol properties "
					"(MSE: Set AT failed).");
			goto err;
		}

		r = eac_verify(card, cert, cert_len);
		if (r < 0)
			goto err;

		chr = cvc_cert->body->certificate_holder_reference->data;
		chr_len = cvc_cert->body->certificate_holder_reference->length;

		certs++;
		certs_lens++;
	}


	if (!EAC_CTX_init_ta(eacsmctx->ctx, privkey, privkey_len, cert, cert_len)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize TA.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}


	if (eacsmctx->eph_pub_key)
		BUF_MEM_free(eacsmctx->eph_pub_key);
	eacsmctx->eph_pub_key = TA_STEP3_generate_ephemeral_key(eacsmctx->ctx);
	if (!eacsmctx->eph_pub_key) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate CA ephemeral key.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}


	r = eac_mse_set_at_ta(card, eacsmctx->ctx->ta_ctx->protocol, chr, chr_len,
			(unsigned char *) eacsmctx->eph_pub_key->data, eacsmctx->eph_pub_key->length,
			auxiliary_data, auxiliary_data_len);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol properties "
				"(MSE: Set AT failed).");
		goto err;
	}

	nonce = BUF_MEM_create(TA_NONCE_LENGTH);
	if (!nonce) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = eac_get_challenge(card, (unsigned char *) nonce->data, nonce->length);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get nonce for TA.");
		goto err;
	}
	if (!TA_STEP4_set_nonce(eacsmctx->ctx, nonce)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not set nonce for TA.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (eacsmctx->auxiliary_data)
		BUF_MEM_free(eacsmctx->auxiliary_data);
	eacsmctx->auxiliary_data = BUF_MEM_create_init(auxiliary_data,
			auxiliary_data_len);
	if (!eacsmctx->id_icc)
		eacsmctx->id_icc = BUF_MEM_new();
	signature = TA_STEP5_sign(eacsmctx->ctx, eacsmctx->eph_pub_key,
			eacsmctx->id_icc, eacsmctx->auxiliary_data);
	if (!signature) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not generate signature.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = eac_external_authenticate(card, (unsigned char *) signature->data,
			signature->length);

err:
	if (cvc_cert)
		CVC_CERT_free(cvc_cert);
	free(ef_cardaccess);
	EAC_CTX_clear_free(eac_ctx);
	BUF_MEM_clear_free(nonce);
	BUF_MEM_clear_free(signature);

	if (card)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
	else
		return r;
}

static int eac_mse_set_at_ca(sc_card_t *card, int protocol)
{
	return eac_mse_set_at(card, 0x41, protocol, NULL, 0, NULL, 0, NULL, 0,
			NULL, 0, NULL, NULL, NULL);
}

static int eac_gen_auth_ca(sc_card_t *card, const BUF_MEM *eph_pub_key,
		BUF_MEM **nonce, BUF_MEM **token)
{
	sc_apdu_t apdu;
	EAC_GEN_AUTH_CA_C *c_data = NULL;
	EAC_GEN_AUTH_CA_R *r_data = NULL;
	unsigned char *d = NULL;
	int r;
	unsigned char resp[SC_MAX_EXT_APDU_RESP_SIZE];

	c_data = EAC_GEN_AUTH_CA_C_new();
	if (!c_data) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	c_data->eph_pub_key = ASN1_OCTET_STRING_new();
	if (!c_data->eph_pub_key
			|| !ASN1_OCTET_STRING_set(c_data->eph_pub_key,
				(const unsigned char *) eph_pub_key->data,
				eph_pub_key->length)) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = i2d_EAC_GEN_AUTH_CA_C(c_data, &d);
	if (r < 0) {
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	sc_format_apdu_ex(card, &apdu, ISO_GENERAL_AUTHENTICATE, 0, 0, d, r, resp, sizeof resp);

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) command data", apdu.data, apdu.datalen);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0)
		goto err;

	sc_debug_hex(card->ctx, SC_LOG_DEBUG_SM, "General authenticate (Perform Key Agreement) response data", apdu.resp, apdu.resplen);

	if (!d2i_EAC_GEN_AUTH_CA_R(&r_data,
				(const unsigned char **) &apdu.resp, apdu.resplen)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse general authenticate response data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (!r_data->nonce || !r_data->auth_token) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Response data of general authenticate for CA"
				"should contain the nonce and the authentication token.");
		r = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		goto err;
	}

	if (*nonce)
		BUF_MEM_free(*nonce);
	*nonce = BUF_MEM_create_init(r_data->nonce->data,
			r_data->nonce->length);
	if (*token)
		BUF_MEM_free(*token);
	*token = BUF_MEM_create_init(r_data->auth_token->data,
			r_data->auth_token->length);
	if (!*nonce || !*token) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

err:
	if (c_data)
		EAC_GEN_AUTH_CA_C_free(c_data);
	if (r_data)
		EAC_GEN_AUTH_CA_R_free(r_data);
	OPENSSL_free(d);

	return r;
}

static int get_ef_card_security(sc_card_t *card,
		u8 **ef_security, size_t *length_ef_security)
{
	return iso7816_read_binary_sfid(card, SFID_EF_CARDSECURITY, ef_security, length_ef_security);
}

int perform_chip_authentication(sc_card_t *card,
		unsigned char **ef_cardsecurity, size_t *ef_cardsecurity_len)
{
	int r;
	BUF_MEM *picc_pubkey = NULL;
	struct iso_sm_ctx *isosmctx;
	struct eac_sm_ctx *eacsmctx;

	if (!card || !ef_cardsecurity || !ef_cardsecurity_len) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	isosmctx = card->sm_ctx.info.cmd_data;
	if (!isosmctx->priv_data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = isosmctx->priv_data;

	/* Passive Authentication */
	if (!*ef_cardsecurity && !*ef_cardsecurity_len) {
		r = get_ef_card_security(card, ef_cardsecurity, ef_cardsecurity_len);
		if (r < 0 || !ef_cardsecurity || !ef_cardsecurity_len) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not get EF.CardSecurity.");
			goto err;
		}
	}
	picc_pubkey = CA_get_pubkey(eacsmctx->ctx, *ef_cardsecurity, *ef_cardsecurity_len);
	if (!picc_pubkey) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify EF.CardSecurity.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	r = perform_chip_authentication_ex(card, eacsmctx->ctx,
			(unsigned char *) picc_pubkey->data, picc_pubkey->length);

err:
	BUF_MEM_clear_free(picc_pubkey);

	if (card)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
	else
		return r;
}

int perform_chip_authentication_ex(sc_card_t *card, void *eac_ctx,
		unsigned char *picc_pubkey, size_t picc_pubkey_len)
{
	int r;
	BUF_MEM *picc_pubkey_buf = NULL, *nonce = NULL, *token = NULL,
			*eph_pub_key = NULL;
	EAC_CTX *ctx = eac_ctx;

	if (!card || !ctx) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}


	picc_pubkey_buf = BUF_MEM_create_init(picc_pubkey, picc_pubkey_len);
	if (!picc_pubkey_buf) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not verify EF.CardSecurity.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}


	r = eac_mse_set_at_ca(card, ctx->ca_ctx->protocol);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not select protocol properties "
				"(MSE: Set AT failed).");
		goto err;
	}


	eph_pub_key = CA_STEP2_get_eph_pubkey(ctx);
	if (!eph_pub_key) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not derive keys.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	r = eac_gen_auth_ca(card, eph_pub_key, &nonce, &token);
	if (r < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "(General Authenticate failed).");
		goto err;
	}


	if (!CA_STEP4_compute_shared_secret(ctx, picc_pubkey_buf)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not compute shared secret.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}


	if (!CA_STEP6_derive_keys(ctx, nonce, token)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not derive keys.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}


	/* Initialize secure channel */
	if (!EAC_CTX_set_encryption_ctx(ctx, EAC_ID_CA)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not initialize encryption.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (card->sm_ctx.sm_mode != SM_MODE_TRANSMIT) {
		r = eac_sm_start(card, ctx, NULL, 0, NULL, 0);
	}

err:
	BUF_MEM_clear_free(picc_pubkey_buf);
	BUF_MEM_clear_free(nonce);
	BUF_MEM_clear_free(token);
	BUF_MEM_clear_free(eph_pub_key);

	if (card)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
	else
		return r;
}

static int
increment_ssc(struct eac_sm_ctx *eacsmctx)
{
	if (!eacsmctx)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (!EAC_increment_ssc(eacsmctx->ctx))
		return SC_ERROR_INTERNAL;

	return SC_SUCCESS;
}

static int
eac_sm_encrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **enc)
{
	BUF_MEM *encbuf = NULL, *databuf = NULL;
	u8 *p = NULL;
	int r;
	struct eac_sm_ctx *eacsmctx;

	if (!card || !ctx || !enc || !ctx->priv_data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = ctx->priv_data;

	databuf = BUF_MEM_create_init(data, datalen);
	encbuf = EAC_encrypt(eacsmctx->ctx, databuf);
	if (!databuf || !encbuf || !encbuf->length) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not encrypt data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = realloc(*enc, encbuf->length);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	*enc = p;
	/* Flawfinder: ignore */
	memcpy(*enc, encbuf->data, encbuf->length);
	r = encbuf->length;

err:
	BUF_MEM_clear_free(databuf);
	if (encbuf)
		BUF_MEM_free(encbuf);

	return r;
}

static int
eac_sm_decrypt(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *enc, size_t enclen, u8 **data)
{
	BUF_MEM *encbuf = NULL, *databuf = NULL;
	u8 *p = NULL;
	int r;
	struct eac_sm_ctx *eacsmctx;

	if (!card || !ctx || !enc || !ctx->priv_data || !data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = ctx->priv_data;

	encbuf = BUF_MEM_create_init(enc, enclen);
	databuf = EAC_decrypt(eacsmctx->ctx, encbuf);
	if (!encbuf || !databuf || !databuf->length) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not decrypt data.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = realloc(*data, databuf->length);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	*data = p;
	/* Flawfinder: ignore */
	memcpy(*data, databuf->data, databuf->length);
	r = databuf->length;

err:
	BUF_MEM_clear_free(databuf);
	if (encbuf)
		BUF_MEM_free(encbuf);

	return r;
}

static int
eac_sm_authenticate(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *data, size_t datalen, u8 **macdata)
{
	BUF_MEM *inbuf = NULL, *macbuf = NULL;
	u8 *p = NULL;
	int r;
	struct eac_sm_ctx *eacsmctx;

	if (!card || !ctx || !ctx->priv_data || !macdata) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = ctx->priv_data;

	inbuf = BUF_MEM_create_init(data, datalen);
	if (!inbuf) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	macbuf = EAC_authenticate(eacsmctx->ctx, inbuf);
	if (!macbuf || !macbuf->length) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"Could not compute message authentication code (MAC).");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	p = realloc(*macdata, macbuf->length);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	*macdata = p;
	/* Flawfinder: ignore */
	memcpy(*macdata, macbuf->data, macbuf->length);
	r = macbuf->length;

err:
	if (inbuf)
		BUF_MEM_free(inbuf);
	if (macbuf)
		BUF_MEM_free(macbuf);

	return r;
}

static int
eac_sm_verify_authentication(sc_card_t *card, const struct iso_sm_ctx *ctx,
		const u8 *mac, size_t maclen,
		const u8 *macdata, size_t macdatalen)
{
	int r;
	BUF_MEM *inbuf = NULL, *my_mac = NULL;
	struct eac_sm_ctx *eacsmctx;

	if (!card || !ctx || !ctx->priv_data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = ctx->priv_data;

	inbuf = BUF_MEM_create_init(macdata, macdatalen);
	if (!inbuf) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	my_mac = EAC_authenticate(eacsmctx->ctx, inbuf); 
	if (!my_mac) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"Could not compute message authentication code (MAC) for verification.");
		ssl_error(card->ctx);
		r = SC_ERROR_INTERNAL;
		goto err;
	}

	if (my_mac->length != maclen ||
			memcmp(my_mac->data, mac, maclen) != 0) {
		r = SC_ERROR_OBJECT_NOT_VALID;
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
				"Authentication data not verified");
		goto err;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_SM, "Authentication data verified");

	r = SC_SUCCESS;

err:
	if (inbuf)
		BUF_MEM_free(inbuf);
	if (my_mac)
		BUF_MEM_free(my_mac);

	return r;
}

static int
add_tag(unsigned char **asn1new, int constructed, int tag,
		int xclass, const unsigned char *data, size_t len)
{
	unsigned char *p;
	int newlen;

	if (!asn1new || !data)
		return -1;

	newlen = ASN1_object_size(constructed, len, tag);
	if (newlen <= 0)
		return newlen;

	p = OPENSSL_realloc(*asn1new, newlen);
	if (!p)
		return -1;
	*asn1new = p;

	ASN1_put_object(&p, constructed, len, tag, xclass);
	memcpy(p, data, len);

	return newlen;
}
static int
eac_sm_pre_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu)
{
	int r;
	CVC_CERT *cvc_cert = NULL;
	unsigned char *cert = NULL;
	int len;
	BUF_MEM *signature = NULL;
	unsigned char *sequence = NULL;
	EAC_MSE_C *msesetat = NULL;
	const unsigned char *p;
	struct eac_sm_ctx *eacsmctx;

	if (!card)
	   return SC_ERROR_INVALID_ARGUMENTS;
	if(!ctx || !apdu || !ctx->priv_data) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	eacsmctx = ctx->priv_data;

	if (!(eacsmctx->flags & EAC_FLAG_DISABLE_CHECK_ALL)) {
		if (apdu->ins == 0x2a && apdu->p1 == 0x00 && apdu->p2 == 0xbe) {
			/* PSO:Verify Certificate
			 * check certificate description to match given certificate */

			len = add_tag(&cert, 1, 0x21, V_ASN1_APPLICATION, apdu->data, apdu->datalen);
			p = cert;
			if (len < 0 || !CVC_d2i_CVC_CERT(&cvc_cert, &p, len)
					|| !cvc_cert || !cvc_cert->body) {
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}

			switch (CVC_get_role(cvc_cert->body->chat)) {
				case CVC_CVCA:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing CVCA certificate");
					break;

				case CVC_DV:
				case CVC_DocVer:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing DV certificate");
					break;

				case CVC_Terminal:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Processing Terminal certificate");

					if (eacsmctx->certificate_description) {
						switch (CVC_check_description(cvc_cert,
									(unsigned char *) eacsmctx->certificate_description->data,
									eacsmctx->certificate_description->length)) {
							case 1:
								sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
										"Certificate Description matches Certificate");
								break;
							case 0:
								sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
										"Certificate Description doesn't match Certificate");
								r = SC_ERROR_INVALID_DATA;
								goto err;
								break;
							default:
								sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
										"Error verifying Certificate Description");
								ssl_error(card->ctx);
								r = SC_ERROR_INTERNAL;
								goto err;
								break;
						}
					} else {
						sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
								"Warning: Certificate Description missing");
					}
					break;

				default:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Unknown type of certificate");
					r = SC_ERROR_INVALID_DATA;
					goto err;
					break;
			}

			if (!TA_STEP2_import_certificate(eacsmctx->ctx, cert, len)) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
						"Error importing certificate");
				ssl_error(card->ctx);
				r = SC_ERROR_INTERNAL;
				goto err;
			}

		} else if (apdu->ins == ISO_MSE && apdu->p2 == 0xa4) {
			/* MSE:Set AT */

			len = add_tag(&sequence, 1, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, apdu->data, apdu->datalen);
			p = sequence;
			if (len < 0 || !d2i_EAC_MSE_C(&msesetat, &p, len)) {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not parse MSE:Set AT.");
				ssl_error(card->ctx);
				r = SC_ERROR_INTERNAL;
				goto err;
			}

			if (apdu->p1 == 0x81) {
				/* CA: fetch auxiliary data and terminal's compressed ephemeral
				 * public key */

				if (msesetat->auxiliary_data) {
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's auxiliary data");
					if (eacsmctx->auxiliary_data)
						BUF_MEM_free(eacsmctx->auxiliary_data);
					eacsmctx->auxiliary_data = BUF_MEM_new();
					if (!eacsmctx->auxiliary_data) {
						r = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
					eacsmctx->auxiliary_data->length = i2d_ASN1_AUXILIARY_DATA(
							msesetat->auxiliary_data,
							(unsigned char **) &eacsmctx->auxiliary_data->data);
					if ((int) eacsmctx->auxiliary_data->length < 0) {
						sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Error encoding auxiliary data.");
						ssl_error(card->ctx);
						r = SC_ERROR_INTERNAL;
						goto err;
					}
					eacsmctx->auxiliary_data->max = eacsmctx->auxiliary_data->length;
				}
				if (msesetat->eph_pub_key) {
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving terminal's compressed ephemeral public key");
					if (eacsmctx->eph_pub_key)
						BUF_MEM_free(eacsmctx->eph_pub_key);
					eacsmctx->eph_pub_key =
						BUF_MEM_create_init(msesetat->eph_pub_key->data,
								msesetat->eph_pub_key->length);
					if (!eacsmctx->eph_pub_key) {
						r = SC_ERROR_OUT_OF_MEMORY;
						goto err;
					}
				}
			} else if (apdu->p1 == 0x41) {
				/* TA: Set CAR */

				if (msesetat->key_reference1 && msesetat->key_reference1->data &&
						msesetat->key_reference1->length) {
					/* do nothing. The trust anchor matching this CAR will be
					 * looked up when the certificate chain is imported */
				}
			}
		} else if (apdu->ins == 0x82 && apdu->p1 == 0x00 && apdu->p2 == 0x00) {
			/* External Authenticate
			 * check terminal's signature */

			signature = BUF_MEM_create_init(apdu->data, apdu->datalen);
			if (!signature) {
				r = SC_ERROR_OUT_OF_MEMORY;
				goto err;
			}
			switch (TA_STEP6_verify(eacsmctx->ctx, eacsmctx->eph_pub_key,
						eacsmctx->id_icc, eacsmctx->auxiliary_data, signature)) {
				case 1:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
							"Verified Terminal's signature");
					break;
				case 0:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
							"Terminal's signature not verified");
					r = SC_ERROR_INVALID_DATA;
					goto err;
					break;
				default:
					sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE,
							"Error verifying terminal's signature");
					ssl_error(card->ctx);
					r = SC_ERROR_INTERNAL;
					goto err;
					break;
			}
		}
	}

	r = increment_ssc(ctx->priv_data);

err:
	if (cvc_cert)
		CVC_CERT_free(cvc_cert);
	if (signature)
		BUF_MEM_free(signature);
	if (cert)
		OPENSSL_free(cert);
	if (sequence)
		OPENSSL_free(sequence);
	if (msesetat)
		EAC_MSE_C_free(msesetat);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM, r);
}

static int
eac_sm_post_transmit(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *sm_apdu)
{
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM,  
			increment_ssc(ctx->priv_data));
}

static int
eac_sm_finish(sc_card_t *card, const struct iso_sm_ctx *ctx,
		sc_apdu_t *apdu)
{
	struct eac_sm_ctx *eacsmctx;
	if (!card)
	   return SC_ERROR_INVALID_ARGUMENTS;
	if(!ctx || !ctx->priv_data || !apdu)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM,  
				SC_ERROR_INVALID_ARGUMENTS);
	eacsmctx = ctx->priv_data;

	if (!(eacsmctx->flags & EAC_FLAG_DISABLE_CHECK_ALL)) {
		if (apdu->sw1 == 0x90 && apdu->sw2 == 0x00) {
			if (apdu->ins == 0x84 && apdu->p1 == 0x00 && apdu->p2 == 0x00
					&& apdu->le == 8 && apdu->resplen == 8) {
				BUF_MEM *nonce;
				int r;
				/* Get Challenge
				 * copy challenge to EAC context */

				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Saving MRTD's nonce to later verify Terminal's signature");

				nonce = BUF_MEM_create_init(apdu->resp, apdu->resplen);
				r = TA_STEP4_set_nonce(eacsmctx->ctx, nonce);
				if (nonce)
					BUF_MEM_free(nonce);

				if (!r) {
					ssl_error(card->ctx);
					SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM,  SC_ERROR_INTERNAL);
				}
			}
		}
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_SM,  SC_SUCCESS);
}

static void
eac_sm_clear_free(const struct iso_sm_ctx *ctx)
{
	if (ctx) {
		struct eac_sm_ctx *eacsmctx = ctx->priv_data;
		if (eacsmctx) {
			EAC_CTX_clear_free(eacsmctx->ctx);
			if (eacsmctx->certificate_description)
				BUF_MEM_free(eacsmctx->certificate_description);
			if (eacsmctx->id_icc)
				BUF_MEM_free(eacsmctx->id_icc);
			if (eacsmctx->eph_pub_key)
				BUF_MEM_free(eacsmctx->eph_pub_key);
			if (eacsmctx->auxiliary_data)
				BUF_MEM_free(eacsmctx->auxiliary_data);
			free(eacsmctx);
		}
	}
}

#else

int perform_pace(sc_card_t *card,
		struct establish_pace_channel_input pace_input,
		struct establish_pace_channel_output *pace_output,
		enum eac_tr_version tr_version)
{
	int r;

	if (card && card->reader
			&& card->reader->capabilities & SC_READER_CAP_PACE_GENERIC
			&& card->reader->ops->perform_pace) {
		r = card->reader->ops->perform_pace(card->reader, &pace_input, pace_output);
	} else {
		r = SC_ERROR_NOT_SUPPORTED;
	}

	return r;
}

int perform_terminal_authentication(sc_card_t *card,
		const unsigned char **certs, const size_t *certs_lens,
		const unsigned char *privkey, size_t privkey_len,
		const unsigned char *auxiliary_data, size_t auxiliary_data_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int perform_chip_authentication(sc_card_t *card,
		unsigned char **ef_cardsecurity, size_t *ef_cardsecurity_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int perform_chip_authentication_ex(sc_card_t *card, void *eac_ctx,
		unsigned char *picc_pubkey, size_t picc_pubkey_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

#endif

static const char *MRZ_name = "MRZ";
static const char *PIN_name = "eID PIN";
static const char *PUK_name = "PUK";
static const char *CAN_name = "CAN";
static const char *UNDEF_name = "UNDEF";
const char *eac_secret_name(enum s_type pin_id) {
	switch (pin_id) {
		case PACE_MRZ:
			return MRZ_name;
		case PACE_PUK:
			return PUK_name;
		case PACE_PIN:
			return PIN_name;
		case PACE_CAN:
			return CAN_name;
		default:
			return UNDEF_name;
	}
}

int eac_pace_get_tries_left(sc_card_t *card,
		enum s_type pin_id, int *tries_left)
{
	int r;
	u8 sw1, sw2;

	if (tries_left) {
#if defined(ENABLE_OPENPACE) && defined(ENABLE_SM)
		r = eac_mse_set_at_pace(card, 0, pin_id, 0, &sw1, &sw2);
#else
		sc_apdu_t apdu;
		sc_format_apdu_ex(card, &apdu, ISO_MSE, 0xC1, 0xA4, NULL, 0, NULL, 0);
		r = sc_transmit_apdu(card, &apdu);
		sw1 = apdu.sw1;
		sw2 = apdu.sw2;
#endif

		if (r > 0 && (sw1 == 0x63) && ((sw2 & 0xc0) == 0xc0)) {
			*tries_left = sw2 & 0x0f;
		} else {
			*tries_left = -1;
		}
	} else {
		r = SC_ERROR_INVALID_ARGUMENTS;
	}

	return r;
}
