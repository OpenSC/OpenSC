/*
 * card-sc-hsm.c
 *
 * Driver for the SmartCard-HSM, a light-weight hardware security module
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



/* Our AID */
struct sc_aid sc_hsm_aid = { { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 }, 11 };



/* Known ATRs for SmartCard-HSMs */
static struct sc_atr_table sc_hsm_atrs[] = {
	/* standard version */
	{"3B:FE:18:00:00:81:31:FE:45:80:31:81:54:48:53:4D:31:73:80:21:40:81:07:FA", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},
	{"3B:8E:80:01:80:31:81:54:48:53:4D:31:73:80:21:40:81:07:18", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* Known ATRs for JavaCards that qualify for SmartCard-HSMs */
static struct sc_atr_table sc_hsm_jc_atrs[] = {
	/* standard version */
	{"3b:f8:13:00:00:81:31:fe:45:4a:43:4f:50:76:32:34:31:b7", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},	// JCOP 2.4.1 Default ATR contact based
	{"3b:88:80:01:4a:43:4f:50:76:32:34:31:5e", NULL, NULL, SC_CARD_TYPE_SC_HSM, 0, NULL},	// JCOP 2.4.1 Default ATR contactless
	{NULL, NULL, NULL, 0, 0, NULL}
};



static int sc_hsm_select_file(sc_card_t *card,
			       const sc_path_t *in_path,
			       sc_file_t **file_out)
{
	int rv;
	sc_file_t *file = NULL;

	if (file_out == NULL) {				// Versions before 0.16 of the SmartCard-HSM do not support P2='0C'
		if (!in_path->len && in_path->aid.len) {
			sc_log(card->ctx, "Preventing reselection of applet which would clear the security state");
			return SC_SUCCESS;
		}
		rv = sc_hsm_select_file(card, in_path, &file);
		if (file != NULL) {
			sc_file_free(file);
		}
		return rv;
	}

	if ((in_path->len == 2) && (in_path->value[0] == 0x3F) && (in_path->value[1] == 0x00)) {
		// The SmartCard-HSM is an applet that is not default selected. Simulate selection of the MF
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		file->id = 0x3F00;
		file->type = SC_FILE_TYPE_DF;
		file->magic = SC_FILE_MAGIC;

		*file_out = file;
		return SC_SUCCESS;
	}
	return (*iso_ops->select_file)(card, in_path, file_out);
}



static int sc_hsm_match_card(struct sc_card *card)
{
	sc_path_t path;
	int i, r;

	i = _sc_match_atr(card, sc_hsm_atrs, &card->type);
	if (i >= 0)
		return 1;

	i = _sc_match_atr(card, sc_hsm_jc_atrs, &card->type);
	if (i < 0)
		return 0;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);
	r = sc_hsm_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, r, "Could not select SmartCard-HSM application");

	// Select Applet to be sure
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

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_ERROR_FILE_END_REACHED) {
		LOG_TEST_RET(ctx, r, "Check SW error");
	}

	memcpy(buf, recvbuf, apdu.resplen);

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}



static int sc_hsm_update_binary(sc_card_t *card,
			       unsigned int idx, const u8 *buf, size_t count,
			       unsigned long flags)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *cmdbuff, *p;
	size_t len;
	int r;

	if (idx > 0xffff) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "invalid EF offset: 0x%X > 0xFFFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	cmdbuff = malloc(8 + count);
	if (!cmdbuff) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	p = cmdbuff;
	*p++ = 0x54;
	*p++ = 0x02;
	*p++ = (idx >> 8) & 0xFF;
	*p++ = idx & 0xFF;
	*p++ = 0x53;
	if (count < 128) {
		*p++ = count;
		len = 6;
	} else if (count < 256) {
		*p++ = 0x81;
		*p++ = count;
		len = 7;
	} else {
		*p++ = 0x82;
		*p++ = count >> 8;
		*p++ = count & 0xFF;
		len = 8;
	}

	memcpy(p, buf, count);
	len += count;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xD7, 0x00, 0x00);
	apdu.data = cmdbuff;
	apdu.datalen = len;
	apdu.lc = len;

	r = sc_transmit_apdu(card, &apdu);
	free(cmdbuff);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(ctx, count);
}



static int sc_hsm_list_files(sc_card_t *card, u8 * buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 recvbuf[MAX_EXT_APDU_LENGTH];
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	int r;

	if (priv->noExtLength) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x58, 0, 0);
	} else {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_EXT, 0x58, 0, 0);
	}
	apdu.cla = 0x80;
	apdu.resp = recvbuf;
	apdu.resplen = sizeof(recvbuf);
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);

	if ((r == SC_ERROR_TRANSMIT_FAILED) && (!priv->noExtLength)) {
		sc_log(card->ctx, "No extended length support ? Trying fall-back to short APDUs, probably breaking support for RSA 2048 operations");
		priv->noExtLength = 1;
		card->max_send_size = 248;		// 255 - 7 because of TLV in odd ins UPDATE BINARY
		return sc_hsm_list_files(card, buf, buflen);
	}
	LOG_TEST_RET(card->ctx, r, "ENUMERATE OBJECTS APDU transmit failed");

	memcpy(buf, recvbuf, buflen);

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}



static int sc_hsm_create_file(sc_card_t *card, sc_file_t *file)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 cmdbuff[] = { 0x54, 0x02, 0x00, 0x00, 0x53, 0x00 };
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD7, file->id >> 8, file->id & 0xFF);
	apdu.data = cmdbuff;
	apdu.datalen = sizeof(cmdbuff);
	apdu.lc = sizeof(cmdbuff);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}



static int sc_hsm_delete_file(sc_card_t *card, const sc_path_t *path)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 sbuf[2];
	int r;

	if ((path->type != SC_PATH_TYPE_FILE_ID) || (path->len != 2)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type has to be SC_PATH_TYPE_FILE_ID");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	sbuf[0] = path->value[0];
	sbuf[1] = path->value[1];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x02, 0x00);
	apdu.data = sbuf;
	apdu.datalen = sizeof(sbuf);
	apdu.lc = sizeof(sbuf);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
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
		int len;

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
	size_t len;
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
			len = apdu.resplen - 1 > outlen ? outlen : apdu.resplen - 1;
			memcpy(out, apdu.resp + 1, len);
			LOG_FUNC_RETURN(card->ctx, len);
		} else {
			len = apdu.resplen > outlen ? outlen : apdu.resplen;
			memcpy(out, apdu.resp, len);
			LOG_FUNC_RETURN(card->ctx, len);
		}
	}
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}



void sc_hsm_set_serialnr(sc_card_t *card, char *serial)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;

	if (priv->serialno) {
		free(priv->serialno);
	}

	priv->serialno = strdup(serial);
}



static int sc_hsm_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	if (!priv->serialno) {
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	serial->len = strlen(priv->serialno);
	strncpy(serial->value, priv->serialno, sizeof(serial->value));
	return 0;
}



static int sc_hsm_generate_keypair(sc_card_t *card, sc_cardctl_sc_hsm_keygen_info_t *keyinfo)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	u8 rbuf[1024];
	int r;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x46, keyinfo->key_id, keyinfo->auth_key_id);
	apdu.cla = 0x00;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0;

	apdu.data = keyinfo->gakprequest;
	apdu.lc = keyinfo->gakprequest_len;
	apdu.datalen = keyinfo->gakprequest_len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Check SW error");

	keyinfo->gakpresponse_len = apdu.resplen;
	keyinfo->gakpresponse = malloc(apdu.resplen);

	if (keyinfo->gakpresponse == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	memcpy(keyinfo->gakpresponse, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return sc_hsm_get_serialnr(card, (sc_serial_number_t *)ptr);
	case SC_CARDCTL_SC_HSM_GENERATE_KEY:
		return sc_hsm_generate_keypair(card, (sc_cardctl_sc_hsm_keygen_info_t *)ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
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

	flags = SC_ALGORITHM_RSA_RAW|SC_ALGORITHM_ONBOARD_KEY_GEN;

	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	flags = SC_ALGORITHM_ECDSA_RAW|
		SC_ALGORITHM_ECDSA_HASH_NONE|
		SC_ALGORITHM_ECDSA_HASH_SHA1|
		SC_ALGORITHM_ECDSA_HASH_SHA224|
		SC_ALGORITHM_ECDSA_HASH_SHA256|
		SC_ALGORITHM_ONBOARD_KEY_GEN;

	ext_flags = SC_ALGORITHM_EXT_EC_F_P|
		    SC_ALGORITHM_EXT_EC_ECPARAMETERS|
		    SC_ALGORITHM_EXT_EC_UNCOMPRESES|
		    SC_ALGORITHM_ONBOARD_KEY_GEN;
	_sc_card_add_ec_alg(card, 192, flags, ext_flags);
	_sc_card_add_ec_alg(card, 224, flags, ext_flags);
	_sc_card_add_ec_alg(card, 256, flags, ext_flags);
	_sc_card_add_ec_alg(card, 320, flags, ext_flags);

	card->caps |= SC_CARD_CAP_RNG|SC_CARD_CAP_APDU_EXT;

	card->max_send_size = 1431;		// 1439 buffer size - 8 byte TLV because of odd ins in UPDATE BINARY
	return 0;
}



static int sc_hsm_finish(sc_card_t * card)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	if (priv->serialno) {
		free(priv->serialno);
	}
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
	sc_hsm_ops.select_file       = sc_hsm_select_file;
	sc_hsm_ops.read_binary       = sc_hsm_read_binary;
	sc_hsm_ops.update_binary     = sc_hsm_update_binary;
	sc_hsm_ops.list_files        = sc_hsm_list_files;
	sc_hsm_ops.create_file       = sc_hsm_create_file;
	sc_hsm_ops.delete_file       = sc_hsm_delete_file;
	sc_hsm_ops.set_security_env  = sc_hsm_set_security_env;
	sc_hsm_ops.compute_signature = sc_hsm_compute_signature;
	sc_hsm_ops.decipher          = sc_hsm_decipher;
	sc_hsm_ops.init              = sc_hsm_init;
	sc_hsm_ops.finish            = sc_hsm_finish;
	sc_hsm_ops.card_ctl          = sc_hsm_card_ctl;

	/* no record oriented file services */
	sc_hsm_ops.read_record       = NULL;
	sc_hsm_ops.write_record      = NULL;
	sc_hsm_ops.append_record     = NULL;
	sc_hsm_ops.update_record     = NULL;

	return &sc_hsm_drv;
}



struct sc_card_driver * sc_get_sc_hsm_driver(void)
{
	return sc_get_driver();
}

