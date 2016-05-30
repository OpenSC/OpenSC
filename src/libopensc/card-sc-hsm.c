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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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



/*
 * Encode 16 hexadecimals of SO-PIN into binary form
 * Caller must check length of sopin and provide an 8 byte buffer
 */
static int sc_hsm_encode_sopin(const u8 *sopin, u8 *sopinbin)
{
	int i;
	char digit;

	memset(sopinbin, 0, 8);
	for (i = 0; i < 16; i++) {
		*sopinbin <<= 4;
		digit = *sopin++;

		if (!isxdigit(digit))
			return SC_ERROR_PIN_CODE_INCORRECT;
		digit = toupper(digit);

		if (digit >= 'A')
			digit = digit - 'A' + 10;
		else
			digit = digit & 0xF;

		*sopinbin |= digit & 0xf;
		if (i & 1)
			sopinbin++;
	}
	return SC_SUCCESS;
}



static int sc_hsm_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	sc_apdu_t apdu;
	u8 cmdbuff[16];
	int r;

	if ((data->cmd == SC_PIN_CMD_VERIFY) && (data->pin_reference == 0x88)) {
		if (data->pin1.len != 16)
			return SC_ERROR_INVALID_PIN_LENGTH;

		// Save SO PIN for later use in sc_hsm_init_pin()
		r = sc_hsm_encode_sopin(data->pin1.data, priv->sopin);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	if ((data->cmd == SC_PIN_CMD_CHANGE) && (data->pin_reference == 0x88)) {
		if ((data->pin1.len != 16) || (data->pin2.len != 16))
			return SC_ERROR_INVALID_PIN_LENGTH;

		r = sc_hsm_encode_sopin(data->pin1.data, cmdbuff);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		r = sc_hsm_encode_sopin(data->pin2.data, cmdbuff + 8);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, data->pin_reference);
		apdu.data = cmdbuff;
		apdu.datalen = sizeof(cmdbuff);
		apdu.lc = 16;
		apdu.resplen = 0;
		data->apdu = &apdu;
	}

	data->pin1.offset = 5;
	data->pin1.length_offset = 4;
	data->pin2.offset = 5;
	data->pin2.length_offset = 4;

	return (*iso_ops->pin_cmd)(card, data, tries_left);
}



static int sc_hsm_logout(sc_card_t * card)
{
	sc_path_t path;
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	memset(priv->sopin, 0, sizeof(priv->sopin));

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, sc_hsm_aid.value, sc_hsm_aid.len, 0, 0);

	return sc_hsm_select_file(card, &path, NULL);
}



static int sc_hsm_read_binary(sc_card_t *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
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

	assert(count <= sc_get_max_recv_size(card));
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0xB1, 0x00, 0x00);
	apdu.data = cmdbuff;
	apdu.datalen = 4;
	apdu.lc = 4;
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = buf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r != SC_ERROR_FILE_END_REACHED) {
		LOG_TEST_RET(ctx, r, "Check SW error");
	}

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}



static int sc_hsm_write_ef(sc_card_t *card,
			       int fid,
			       unsigned int idx, const u8 *buf, size_t count)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
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

	if (buf != NULL)
		memcpy(p, buf, count);
	len += count;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xD7, fid >> 8, fid & 0xFF);
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



static int sc_hsm_update_binary(sc_card_t *card,
			       unsigned int idx, const u8 *buf, size_t count,
			       unsigned long flags)
{
	return sc_hsm_write_ef(card, 0, idx, buf, count);
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
	int r;

	r = sc_hsm_write_ef(card, file->id, 0, NULL, 0);
	LOG_TEST_RET(card->ctx, r, "Create file failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
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

	int i, r;
	size_t fieldsizebytes;
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

	// check if datalen exceeds the buffer size
	if (datalen > SC_MAX_APDU_BUFFER_SIZE) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
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

	apdu.data = (u8 *)crgram;
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
	if (serial->len > sizeof(serial->value))
		serial->len = sizeof(serial->value);

	memcpy(serial->value, priv->serialno, serial->len);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_initialize(sc_card_t *card, sc_cardctl_sc_hsm_init_param_t *params)
{
	sc_context_t *ctx = card->ctx;
	sc_pkcs15_tokeninfo_t ti;
	struct sc_pin_cmd_data pincmd;
	int r;
	size_t tilen;
	sc_apdu_t apdu;
	u8 ibuff[50], *p;

	LOG_FUNC_CALLED(card->ctx);

	p = ibuff;
	*p++ = 0x80;	// Options
	*p++ = 0x02;
	memcpy(p, params->options, 2);
	p += 2;

	*p++ = 0x81;	// User PIN
	*p++ = params->user_pin_len;
	memcpy(p, params->user_pin, params->user_pin_len);
	p += params->user_pin_len;

	*p++ = 0x82;	// Initialization code
	*p++ = 0x08;
	memcpy(p, params->init_code, 8);
	p += 8;

	*p++ = 0x91;	// User PIN retry counter
	*p++ = 0x01;
	*p++ = params->user_pin_retry_counter;

	if (params->dkek_shares >= 0) {
		*p++ = 0x92;	// Number of DKEK shares
		*p++ = 0x01;
		*p++ = (u8)params->dkek_shares;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x50, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.data = ibuff;
	apdu.datalen = p - ibuff;
	apdu.lc = apdu.datalen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);

	if (r == SC_ERROR_NOT_ALLOWED) {
		r = SC_ERROR_PIN_CODE_INCORRECT;
	}

	LOG_TEST_RET(ctx, r, "Check SW error");

	if (params->label) {
		memset(&ti, 0, sizeof(ti));

		ti.label = params->label;
		ti.flags = SC_PKCS15_TOKEN_PRN_GENERATION;

		r = sc_pkcs15_encode_tokeninfo(ctx, &ti, &p, &tilen);
		LOG_TEST_RET(ctx, r, "Error encoding tokeninfo");

		memset(&pincmd, 0, sizeof(pincmd));
		pincmd.cmd = SC_PIN_CMD_VERIFY;
		pincmd.pin_type = SC_AC_CHV;
		pincmd.pin_reference = 0x81;
		pincmd.pin1.data = params->user_pin;
		pincmd.pin1.len = params->user_pin_len;

		r = (*iso_ops->pin_cmd)(card, &pincmd, NULL);
		LOG_TEST_RET(ctx, r, "Could not verify PIN");

		r = sc_hsm_write_ef(card, 0x2F03, 0, p, tilen);
		LOG_TEST_RET(ctx, r, "Could not write EF.TokenInfo");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_import_dkek_share(sc_card_t *card, sc_cardctl_sc_hsm_dkek_t *params)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 status[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (params->importShare) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x52, 0x00, 0x00);
		apdu.cla = 0x80;
		apdu.data = params->dkek_share;
		apdu.datalen = sizeof(params->dkek_share);
		apdu.lc = apdu.datalen;
	} else {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x52, 0x00, 0x00);
	}
	apdu.cla = 0x80;
	apdu.le = 0;
	apdu.resp = status;
	apdu.resplen = sizeof(status);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_TEST_RET(ctx, r, "Check SW error");

	assert(apdu.resplen >= (sizeof(params->key_check_value) + 2));

	params->dkek_shares = status[0];
	params->outstanding_shares = status[1];
	memcpy(params->key_check_value, status + 2, sizeof(params->key_check_value));

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_wrap_key(sc_card_t *card, sc_cardctl_sc_hsm_wrapped_key_t *params)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 data[MAX_EXT_APDU_LENGTH];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_EXT, 0x72, params->key_id, 0x92);
	apdu.cla = 0x80;
	apdu.le = 0;
	apdu.resp = data;
	apdu.resplen = sizeof(data);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_TEST_RET(ctx, r, "Check SW error");

	if (params->wrapped_key == NULL) {
		params->wrapped_key_length = apdu.resplen;
		params->wrapped_key = malloc(apdu.resplen);
		if (params->wrapped_key == NULL) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		}
	} else {
		if (apdu.resplen > params->wrapped_key_length) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
		}
		params->wrapped_key_length = apdu.resplen;
	}
	memcpy(params->wrapped_key, data, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_unwrap_key(sc_card_t *card, sc_cardctl_sc_hsm_wrapped_key_t *params)
{
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_EXT, 0x74, params->key_id, 0x93);
	apdu.cla = 0x80;
	apdu.lc = params->wrapped_key_length;
	apdu.data = params->wrapped_key;
	apdu.datalen = params->wrapped_key_length;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_init_token(sc_card_t *card, sc_cardctl_pkcs11_init_token_t *params)
{
	sc_context_t *ctx = card->ctx;
	sc_cardctl_sc_hsm_init_param_t ip;
	int r;
	char label[33],*cpo;

	LOG_FUNC_CALLED(ctx);

	if (params->so_pin_len != 16) {
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "SO PIN wrong length (!=16)");
	}

	memset(&ip, 0, sizeof(ip));
	ip.dkek_shares = -1;
	ip.options[0] = 0x00;
	ip.options[1] = 0x01;

	r = sc_hsm_encode_sopin(params->so_pin, ip.init_code);
	LOG_TEST_RET(ctx, r, "SO PIN wrong format");

	ip.user_pin = ip.init_code;		// Use the first 6 bytes of the SO-PIN as initial User-PIN value
	ip.user_pin_len = 6;
	ip.user_pin_retry_counter = 3;

	if (params->label) {
		// Strip trailing spaces
		memcpy(label, params->label, 32);
		label[32] = 0;
		cpo = label + 31;
		while ((cpo >= label) && (*cpo == ' ')) {
			*cpo = 0;
			cpo--;
		}
		ip.label = label;
	}

	r = sc_hsm_initialize(card, &ip);
	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}



static int sc_hsm_init_pin(sc_card_t *card, sc_cardctl_pkcs11_init_pin_t *params)
{
	sc_hsm_private_data_t *priv = (sc_hsm_private_data_t *) card->drv_data;
	sc_context_t *ctx = card->ctx;
	int r;
	sc_apdu_t apdu;
	u8 ibuff[50], *p;

	LOG_FUNC_CALLED(card->ctx);

	if (params->pin_len > 16) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "User PIN too long");
	}

	p = ibuff;

	memcpy(p, priv->sopin, sizeof(priv->sopin));
	p += sizeof(priv->sopin);

	memcpy(p, params->pin, params->pin_len);
	p += params->pin_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, 0x00, 0x81);
	apdu.data = ibuff;
	apdu.datalen = p - ibuff;
	apdu.lc = apdu.datalen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r =  sc_check_sw(card, apdu.sw1, apdu.sw2);

	// Cards before version 1.0 do not implement RESET_RETRY_COUNTER
	// For those cards the CHANGE REFERENCE DATA command is used instead
	if (r == SC_ERROR_INS_NOT_SUPPORTED) {
		p = ibuff;
		memcpy(p, priv->sopin, 6);
		p += 6;

		memcpy(p, params->pin, params->pin_len);
		p += params->pin_len;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, 0x81);
		apdu.data = ibuff;
		apdu.datalen = p - ibuff;
		apdu.lc = apdu.datalen;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, r, "APDU transmit failed");

		r =  sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	LOG_TEST_RET(ctx, r, "Check SW error");

	memset(priv->sopin, 0, sizeof(priv->sopin));

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}



static int sc_hsm_generate_keypair(sc_card_t *card, sc_cardctl_sc_hsm_keygen_info_t *keyinfo)
{
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
	case SC_CARDCTL_PKCS11_INIT_TOKEN:
		return sc_hsm_init_token(card, (sc_cardctl_pkcs11_init_token_t *)ptr);
	case SC_CARDCTL_PKCS11_INIT_PIN:
		return sc_hsm_init_pin(card, (sc_cardctl_pkcs11_init_pin_t *)ptr);
	case SC_CARDCTL_SC_HSM_GENERATE_KEY:
		return sc_hsm_generate_keypair(card, (sc_cardctl_sc_hsm_keygen_info_t *)ptr);
	case SC_CARDCTL_SC_HSM_INITIALIZE:
		return sc_hsm_initialize(card, (sc_cardctl_sc_hsm_init_param_t *)ptr);
	case SC_CARDCTL_SC_HSM_IMPORT_DKEK_SHARE:
		return sc_hsm_import_dkek_share(card, (sc_cardctl_sc_hsm_dkek_t *)ptr);
	case SC_CARDCTL_SC_HSM_WRAP_KEY:
		return sc_hsm_wrap_key(card, (sc_cardctl_sc_hsm_wrapped_key_t *)ptr);
	case SC_CARDCTL_SC_HSM_UNWRAP_KEY:
		return sc_hsm_unwrap_key(card, (sc_cardctl_sc_hsm_wrapped_key_t *)ptr);
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
		SC_ALGORITHM_ECDH_CDH_RAW|
		SC_ALGORITHM_ECDSA_HASH_NONE|
		SC_ALGORITHM_ECDSA_HASH_SHA1|
		SC_ALGORITHM_ECDSA_HASH_SHA224|
		SC_ALGORITHM_ECDSA_HASH_SHA256|
		SC_ALGORITHM_ONBOARD_KEY_GEN;

	ext_flags = SC_ALGORITHM_EXT_EC_F_P|
			SC_ALGORITHM_EXT_EC_ECPARAMETERS|
			SC_ALGORITHM_EXT_EC_NAMEDCURVE|
			SC_ALGORITHM_EXT_EC_UNCOMPRESES|
			SC_ALGORITHM_ONBOARD_KEY_GEN;
	_sc_card_add_ec_alg(card, 192, flags, ext_flags, NULL);
	_sc_card_add_ec_alg(card, 224, flags, ext_flags, NULL);
	_sc_card_add_ec_alg(card, 256, flags, ext_flags, NULL);
	_sc_card_add_ec_alg(card, 320, flags, ext_flags, NULL);

	card->caps |= SC_CARD_CAP_RNG|SC_CARD_CAP_APDU_EXT|SC_CARD_CAP_ISO7816_PIN_INFO;

	card->max_send_size = 1431;		// 1439 buffer size - 8 byte TLV because of odd ins in UPDATE BINARY
	card->max_recv_size = 0;		// Card supports sending with extended length APDU and without limit
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
	sc_hsm_ops.pin_cmd           = sc_hsm_pin_cmd;
	sc_hsm_ops.logout            = sc_hsm_logout;

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

