/*
 * card-sc-hsm.c
 *
 * Read-only driver for the SmartCard-HSM light-weight hardware security module
 *
 * Copyright (C) 2012 Andreas Schwier, CardContact, Minden, Germany, and others
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

#include "config.h"

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "types.h"

#include "card-sc-hsm.h"


/* Static reference to ISO driver */
static const struct sc_card_operations *iso_ops = NULL;

/* Our operations */
static struct sc_card_operations sc_hsm_ops;

/* Our driver description */
static struct sc_card_driver sc_hsm_drv = {
	"SmartCard-HSM",
	"sc-hsm",
	&sc_hsm_ops,
	NULL,
	0,
	NULL
};

/* Known ATRs for SmartCard-HSMs */
static struct sc_atr_table sc_hsm_atrs[] = {
	/* standard version */
	{"3B:FE:18:00:00:81:31:FE:45:80:31:81:54:48:53:4D:31:73:80:21:40:81:07:FA", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},
	{"3B:8E:80:01:80:31:81:54:48:53:4D:31:73:80:21:40:81:07:18", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};


/* Information the driver maintains between calls */
typedef struct sc_hsm_private_data {
	const sc_security_env_t *env;
	u8 algorithm;
} sc_hsm_private_data_t;



static int sc_hsm_match_card(struct sc_card *card)
{
	int i;

	i = _sc_match_atr(card, sc_hsm_atrs, &card->type);
	if (i < 0)
		return 0;

	return 1;
}



static int sc_hsm_read_binary(sc_card_t *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 cmdbuff[4];
	int r;

	if (idx > 0xffff) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid EF offset: 0x%X > 0xFFFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	cmdbuff[0] = 0x54;
	cmdbuff[1] = 0x02;
	cmdbuff[2] = (idx >> 8) & 0xFF;
	cmdbuff[3] = idx & 0xFF;

	assert(count <= (card->max_recv_size > 0 ? card->max_recv_size : 256));
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xB1, 0x00, 0x00);
	apdu.data = cmdbuff;
	apdu.datalen = 4;
	apdu.lc = 4;
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		LOG_FUNC_RETURN(ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_ERROR_FILE_END_REACHED)
		LOG_FUNC_RETURN(ctx, apdu.resplen);
	LOG_TEST_RET(ctx, r, "Check SW error");

	if (apdu.resplen < count)   {
		r = sc_hsm_read_binary(card, idx + apdu.resplen, buf + apdu.resplen, count - apdu.resplen, flags);
		/* Ignore all but 'corrupted data' errors */
		if (r == SC_ERROR_CORRUPTED_DATA)
			LOG_FUNC_RETURN(ctx, SC_ERROR_CORRUPTED_DATA);
		else if (r > 0)
			apdu.resplen += r;
	}

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}



static int sc_hsm_list_files(sc_card_t *card, u8 * buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 recvbuf[MAX_EXT_APDU_LENGTH];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_EXT, 0x58, 0, 0);
	apdu.cla = 0x80;
	apdu.resp = recvbuf;
	apdu.resplen = sizeof(recvbuf);
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "ENUMERATE OBJECTS APDU transmit failed");

	memcpy(buf, recvbuf, buflen);

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}



static int sc_hsm_set_security_env(sc_card_t *card,
				   const sc_security_env_t *env,
				   int se_num)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;

	priv->env = env;

	switch(env->algorithm) {
	case SC_ALGORITHM_RSA:
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
			if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
				priv->algorithm = ALGO_RSA_PKCS1_SHA1;
			} else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) {
				priv->algorithm = ALGO_RSA_PKCS1_SHA256;
			} else {
				priv->algorithm = ALGO_RSA_PKCS1;
			}
		} else {
			if (env->operation == SC_SEC_OPERATION_DECIPHER) {
				priv->algorithm = ALGO_RSA_DECRYPT;
			} else {
				priv->algorithm = ALGO_RSA_RAW;
			}
		}
		break;
	case SC_ALGORITHM_EC:
		if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_NONE) {
			priv->algorithm = ALGO_EC_RAW;
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1) {
			priv->algorithm = ALGO_EC_SHA1;
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA224) {
			priv->algorithm = ALGO_EC_SHA224;
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA256) {
			priv->algorithm = ALGO_EC_SHA256;
		} else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW) {
			if (env->operation == SC_SEC_OPERATION_DERIVE) {
				priv->algorithm = ALGO_EC_DH;
			} else {
				priv->algorithm = ALGO_EC_RAW;
			}
		} else {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_decode_ecdsa_signature(sc_card_t *card,
					const u8 * data, size_t datalen,
					u8 * out, size_t outlen) {

	int fieldsizebytes, i, r;
	const u8 *body, *tag;
	size_t bodylen, taglen;

	// Determine field size from length of signature
	if (datalen <= 58) {			// 192 bit curve = 24 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 24;
	} else if (datalen <= 66) {		// 224 bit curve = 28 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 28;
	} else if (datalen <= 74) {		// 256 bit curve = 32 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 32;
	} else if (datalen <= 90) {		// 320 bit curve = 40 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 40;
	} else {
		fieldsizebytes = 64;
	}

	sc_log(card->ctx, "Field size %d, signature buffer size %d", fieldsizebytes, outlen);

	if (outlen < (fieldsizebytes * 2)) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "output too small for EC signature");
	}
	memset(out, 0, outlen);

	// Copied from card-piv.c. Thanks
	body = sc_asn1_find_tag(card->ctx, data, datalen, 0x30, &bodylen);

	for (i = 0; i<2; i++) {
		if (body) {
			tag = sc_asn1_find_tag(card->ctx, body,  bodylen, 0x02, &taglen);
			if (tag) {
				bodylen -= taglen - (tag - body);
				body = tag + taglen;

				if (taglen > fieldsizebytes) { /* drop leading 00 if present */
					if (*tag != 0x00) {
						r = SC_ERROR_INVALID_DATA;
						goto err;
					}
					tag++;
					taglen--;
				}
				memcpy(out + fieldsizebytes*i + fieldsizebytes - taglen , tag, taglen);
			} else {
				r = SC_ERROR_INVALID_DATA;
				goto err;
			}
		} else  {
			r = SC_ERROR_INVALID_DATA;
			goto err;
		}
	}
	r = 2 * fieldsizebytes;
err:
	LOG_FUNC_RETURN(card->ctx, r);
}



static int sc_hsm_compute_signature(sc_card_t *card,
				     const u8 * data, size_t datalen,
				     u8 * out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;

	assert(card != NULL && data != NULL && out != NULL);

	if (priv->env == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_FOUND);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x68, priv->env->key_ref[0], priv->algorithm);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	memcpy(sbuf, data, datalen);
	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len;

		if ((priv->algorithm & 0xF0) == ALGO_EC_RAW) {
			len = sc_hsm_decode_ecdsa_signature(card, apdu.resp, apdu.resplen, out, outlen);
			if (len < 0) {
				LOG_FUNC_RETURN(card->ctx, len);
			}
		} else {
			len = apdu.resplen > outlen ? outlen : apdu.resplen;
			memcpy(out, apdu.resp, len);
		}
		LOG_FUNC_RETURN(card->ctx, len);
	}
	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}



static int sc_hsm_decipher(sc_card_t *card, const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;

	assert(card != NULL && crgram != NULL && out != NULL);
	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x62, priv->env->key_ref[0], priv->algorithm);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	apdu.data = crgram;
	apdu.lc = crgram_len;
	apdu.datalen = crgram_len;

	r = sc_transmit_apdu(card, &apdu);

	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		if (priv->algorithm == ALGO_EC_DH) {
			//
			// The SmartCard-HSM returns the point result of the DH operation
			// with a leading '04'
			assert(apdu.resplen > 0);
			size_t len = apdu.resplen - 1 > outlen ? outlen : apdu.resplen - 1;
			memcpy(out, apdu.resp + 1, len);
			LOG_FUNC_RETURN(card->ctx, len);
		} else {
			size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;
			memcpy(out, apdu.resp, len);
			LOG_FUNC_RETURN(card->ctx, len);
		}
	}
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}



static int sc_hsm_init(struct sc_card *card)
{
	sc_hsm_private_data_t *priv;
	int flags,ext_flags;

	LOG_FUNC_CALLED(card->ctx);

	priv = calloc(1, sizeof(sc_hsm_private_data_t));
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	card->drv_data = priv;

	flags = SC_ALGORITHM_RSA_RAW;
//	flags = SC_ALGORITHM_RSA_RAW|
//			SC_ALGORITHM_RSA_PAD_PKCS1|
//			SC_ALGORITHM_RSA_HASH_SHA1|
//			SC_ALGORITHM_RSA_HASH_SHA256;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	flags = SC_ALGORITHM_ECDSA_RAW|
		SC_ALGORITHM_ECDSA_HASH_NONE|
		SC_ALGORITHM_ECDSA_HASH_SHA1|
		SC_ALGORITHM_ECDSA_HASH_SHA224|
		SC_ALGORITHM_ECDSA_HASH_SHA256;

	ext_flags = SC_ALGORITHM_EXT_EC_F_P|
		    SC_ALGORITHM_EXT_EC_ECPARAMETERS|
		    SC_ALGORITHM_EXT_EC_UNCOMPRESES;
	_sc_card_add_ec_alg(card, 192, flags, ext_flags);
	_sc_card_add_ec_alg(card, 224, flags, ext_flags);
	_sc_card_add_ec_alg(card, 256, flags, ext_flags);
	_sc_card_add_ec_alg(card, 320, flags, ext_flags);

	card->caps |= SC_CARD_CAP_RNG|SC_CARD_CAP_APDU_EXT;
	return 0;
}



static int sc_hsm_finish(sc_card_t * card)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	free(priv);
	return SC_SUCCESS;
}



static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	sc_hsm_ops                   = *iso_drv->ops;
	sc_hsm_ops.match_card        = sc_hsm_match_card;
	sc_hsm_ops.read_binary       = sc_hsm_read_binary;
	sc_hsm_ops.list_files        = sc_hsm_list_files;
	sc_hsm_ops.set_security_env  = sc_hsm_set_security_env;
	sc_hsm_ops.compute_signature = sc_hsm_compute_signature;
	sc_hsm_ops.decipher          = sc_hsm_decipher;
	sc_hsm_ops.init              = sc_hsm_init;
	sc_hsm_ops.finish            = sc_hsm_finish;

	/* no record oriented file services */
	sc_hsm_ops.read_record       = NULL;
	sc_hsm_ops.write_record      = NULL;
	sc_hsm_ops.append_record     = NULL;
	sc_hsm_ops.update_record     = NULL;
	sc_hsm_ops.update_binary     = NULL;
	sc_hsm_ops.create_file       = NULL;
	sc_hsm_ops.delete_file       = NULL;

	return &sc_hsm_drv;
}



struct sc_card_driver * sc_get_sc_hsm_driver(void)
{
	return sc_get_driver();
}

