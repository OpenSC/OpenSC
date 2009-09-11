/*
 * card-westcos.c: support for westcos card
 *
 * Copyright (C) 2009 francois.leblanc@cev-sa.com 
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
#include <config.h>
#endif

#include "internal.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cardctl.h"
#include "asn1.h"

#ifdef ENABLE_OPENSSL
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif

#ifndef min
#define max(a,b) (((a)>(b))?(a):(b))
#endif

#define DEFAULT_TRANSPORT_KEY "6f:59:b0:ed:6e:62:46:4a:5d:25:37:68:23:a8:a2:2d"

#define JAVACARD (0x01)

#define TRACE do{ printf("%s %d\n", __FILE__, __LINE__); } while(0)

#ifdef ENABLE_OPENSSL
#define DEBUG_SSL
#ifdef DEBUG_SSL
static int charge = 0;
static void print_openssl_erreur(void)
{
	long r;
	if (!charge) {
		ERR_load_crypto_strings();
		charge = 1;
	}
	while ((r = ERR_get_error()) != 0)
		fprintf(stderr, "%s\n", ERR_error_string(r, NULL));
}

#endif
#endif

typedef struct {
	sc_security_env_t env;
	sc_autkey_t default_key;
	int flags;
	int file_id;
} priv_data_t;

static int westcos_get_default_key(sc_card_t * card,
				   struct sc_cardctl_default_key *data)
{
	const char *default_key;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx,
			 "westcos_get_default_key:data->method=%d, data->key_ref=%d\n",
			 data->method, data->key_ref);
	if (data->method != SC_AC_AUT || data->key_ref != 0)
		return SC_ERROR_NO_DEFAULT_KEY;
	default_key =
	    scconf_get_str(card->ctx->conf_blocks[0], "westcos_default_key",
			   DEFAULT_TRANSPORT_KEY);
	return sc_hex_to_bin(default_key, data->key_data, &data->len);
}

#if 0
static void trace_apdu(sc_card_t * card, sc_apdu_t * apdu)
{
	char buf[100];
	if (card->ctx->debug >= 5)
		sc_debug(card->ctx, "%.02X %.02X %.02X %.02X %.02X %.02X\n",
			 apdu->cla, apdu->ins, apdu->p1, apdu->p2, apdu->lc,
			 apdu->le);
	sc_bin_to_hex(apdu->data, max(apdu->datalen, 30), buf, sizeof(buf),
		      ':');
	if (card->ctx->debug >= 5)
		sc_debug(card->ctx, "data: %s\n", buf);
}
#endif


#define CRC_A 1
#define CRC_B 2

static unsigned short westcos_update_crc(unsigned char ch, unsigned short *lpwCrc)
{
	ch = (ch ^ (unsigned char)((*lpwCrc) & 0x00FF));
	ch = (ch ^ (ch << 4));
	*lpwCrc =
	    (*lpwCrc >> 8) ^ ((unsigned short)ch << 8) ^ ((unsigned short)ch <<
							  3) ^ ((unsigned short)
								ch >> 4);
	return (*lpwCrc);
}

static void westcos_compute_aetb_crc(int CRCType, 
					char *Data, 
					int Length, 
					unsigned char * TransmitFirst,
					unsigned char * TransmitSecond)
{
	unsigned char chBlock;
	unsigned short wCrc;
	switch (CRCType) {
	case CRC_A:
		wCrc = 0x6363;	// ITU-V.41
		break;
	case CRC_B:
		wCrc = 0xFFFF;	// ISO 3309
		break;
	default:
		return;
	}

	do {
		chBlock = *Data++;
		westcos_update_crc(chBlock, &wCrc);
	} while (--Length);
	if (CRCType == CRC_B)
		wCrc = ~wCrc;	// ISO 3309
	*TransmitFirst = (unsigned char) (wCrc & 0xFF);
	*TransmitSecond = (unsigned char) ((wCrc >> 8) & 0xFF);
	return;
}

#if 0
static int sc_check_sw(sc_card_t * card, unsigned int sw1, unsigned int sw2)
{
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ops->check_sw == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return card->ops->check_sw(card, sw1, sw2);
}
#endif

static int westcos_check_sw(sc_card_t * card, unsigned int sw1,
			    unsigned int sw2)
{
	if ((sw1 == 0x90) && (sw2 == 0x00))
		return SC_NO_ERROR;
	if ((sw1 == 0x67) && (sw2 == 0x00))
		return SC_ERROR_WRONG_LENGTH;
	if ((sw1 == 0x69) && (sw2 == 0x82))
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	if ((sw1 == 0x69) && (sw2 == 0x88))
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	if (sw1 == 0x6A) {
		switch (sw2) {
		case 0x82:
			return SC_ERROR_FILE_NOT_FOUND;
		case 0x83:
			return SC_ERROR_RECORD_NOT_FOUND;
		case 0x84:
			return SC_ERROR_MEMORY_FAILURE;
		case 0x86:
			return SC_ERROR_INCORRECT_PARAMETERS;
		case 0x89:
			return SC_ERROR_FILE_ALREADY_EXISTS;
		}
	}
	if ((sw1 == 0x6D) && (sw2 == 0x00))
		return SC_ERROR_INS_NOT_SUPPORTED;
	if (card->ctx->debug >= 2)
		sc_debug(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1,
			 sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

typedef struct mon_atr {
	int len;
	int flags;
	u8 *atr, *mask;
} mon_atr_t;

static mon_atr_t atrs[] = {
	{13, 0x00, 
	"\x3f\x69\x00\x00\x00\x64\x01\x00\x00\x00\x80\x90\x00",
	"\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\xf0\xff\xff"}, 
	{12, JAVACARD,
	"\x3b\x95\x94\x80\x1F\xC3\x80\x73\xC8\x21\x13\x54",
	"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"}
};

static int westcos_finish(sc_card_t * card)
{
	if (card->algorithms)
		free(card->algorithms);
	card->algorithms = NULL;
	card->algorithm_count = 0;
	if (card->drv_data)
		free(card->drv_data);
	return 0;
}

static int westcos_match_card(sc_card_t * card)
{
	u8 *p, j;
	int i;
	mon_atr_t *matr;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_match_card %d, %X:%X:%X\n",
			 card->atr_len, card->atr[0], card->atr[1],
			 card->atr[2]);
	for (i = 0; i < sizeof(atrs) / sizeof(*atrs); i++) {
		matr = &atrs[i];
		if (matr->len != card->atr_len)
			continue;
		p = card->atr;
		for (j = 0; j < card->atr_len; j++) {
			if (((matr->mask[j]) & (*p)) != (matr->atr[j]))
				break;
			p++;
			if (*p == ':')
				p++;
		}
		if (j >= card->atr_len) {
			if (matr->flags & JAVACARD) {
				int r;
				sc_apdu_t apdu;
				u8 aid[] = {
					0xA0, 0x00, 0xCE, 0x00, 0x07, 0x01
				};
				sc_format_apdu(card, &apdu,
					       SC_APDU_CASE_3_SHORT, 0xA4, 0x04,
					       0);
				apdu.cla = 0x00;
				apdu.lc = sizeof(aid);
				apdu.datalen = sizeof(aid);
				apdu.data = aid;
				sc_ctx_suppress_errors_on(card->ctx);
				r = sc_transmit_apdu(card, &apdu);
				sc_ctx_suppress_errors_off(card->ctx);
				if (r)
					continue;
				sc_ctx_suppress_errors_on(card->ctx);
				r = sc_check_sw(card, apdu.sw1, apdu.sw2);
				sc_ctx_suppress_errors_off(card->ctx);
				if (r)
					continue;
			}
			card->drv_data = malloc(sizeof(priv_data_t));
			if (card->drv_data == NULL)
				return SC_ERROR_OUT_OF_MEMORY;
			memset(card->drv_data, 0, sizeof(card->drv_data));
			if (matr->flags & JAVACARD) {
				priv_data_t *priv_data =
				    (priv_data_t *) card->drv_data;
				priv_data->flags |= JAVACARD;
			}
			return 1;
		}
	}
	return 0;
}

#if 0
static int _sc_card_add_rsa_alg(sc_card_t * card, unsigned int key_length,
				unsigned long flags, unsigned long exponent)
{
	sc_algorithm_info_t info, *p;
	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_RSA;
	info.key_length = key_length;
	info.flags = flags;
	info.u._rsa.exponent = exponent;
	p = (sc_algorithm_info_t *) realloc(card->algorithms,
					    (card->algorithm_count +
					     1) * sizeof(info));
	if (!p) {
		if (card->algorithms)
			free(card->algorithms);
		card->algorithms = NULL;
		card->algorithm_count = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	card->algorithms = p;
	p += card->algorithm_count;
	card->algorithm_count++;
	*p = info;
	return 0;
}
#endif

static int westcos_init(sc_card_t * card)
{
	int r;
	const char *default_key;
	unsigned long exponent, flags;
	if (card == NULL || card->drv_data == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	card->cla = 0x00;
	card->max_send_size = 240;
	card->max_recv_size = 240;
	exponent = 0;
	flags = SC_ALGORITHM_RSA_RAW;
	flags |= SC_ALGORITHM_RSA_HASH_NONE;
	flags |= SC_ALGORITHM_RSA_PAD_NONE | SC_ALGORITHM_RSA_PAD_PKCS1;
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
	_sc_card_add_rsa_alg(card, 128, flags, exponent);
	_sc_card_add_rsa_alg(card, 256, flags, exponent);
	_sc_card_add_rsa_alg(card, 512, flags, exponent);
	_sc_card_add_rsa_alg(card, 768, flags, exponent);
	_sc_card_add_rsa_alg(card, 1024, flags, exponent);
	_sc_card_add_rsa_alg(card, 1100, flags, exponent);
	_sc_card_add_rsa_alg(card, 1200, flags, exponent);
	_sc_card_add_rsa_alg(card, 1300, flags, exponent);
	_sc_card_add_rsa_alg(card, 1400, flags, exponent);
	_sc_card_add_rsa_alg(card, 1536, flags, exponent);
	_sc_card_add_rsa_alg(card, 2048, flags, exponent);
	default_key =
	    scconf_get_str(card->ctx->conf_blocks[0], "westcos_default_key",
			   DEFAULT_TRANSPORT_KEY);
	if (default_key) {
		priv_data_t *priv_data = (priv_data_t *) (card->drv_data);
		priv_data->default_key.key_reference = 0;
		priv_data->default_key.key_len =
		    sizeof(priv_data->default_key.key_value);
		r = sc_hex_to_bin(default_key, priv_data->default_key.key_value,
				  &(priv_data->default_key.key_len));
		if (r)
			return (r);
	}
	return 0;
}

static int westcos_select_file(sc_card_t * card, const sc_path_t * in_path,
			       sc_file_t ** file_out)
{
	sc_context_t *ctx;
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	sc_file_t *file = NULL;
	priv_data_t *priv_data = NULL;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_select_file\n");
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	priv_data = (priv_data_t *) card->drv_data;
	priv_data->file_id = 0;
	ctx = card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = (int)in_path->len;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 9;
		if (pathlen == 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			apdu.p1 = 0;
		}

		else if (pathlen > 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			apdu.p1 = 8;
			pathlen -= 2;
			memcpy(path, &in_path->value[2], pathlen);
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_3_SHORT;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.p2 = 0;	/* first record, return FCI */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;
	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 255;
	} else {
		apdu.resplen = 0;
		apdu.le = 0;
		apdu.cse = SC_APDU_CASE_3_SHORT;
	}
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			return 0;
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	switch (apdu.resp[0]) {
	case 0x6F:
		file = sc_file_new();
		if (file == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			return SC_ERROR_NOT_SUPPORTED;
		}
		if (apdu.resp[1] <= apdu.resplen)
			card->ops->process_fci(card, file, apdu.resp + 2,
					       apdu.resp[1]);
		*file_out = file;
		break;
	case 0x00:		/* proprietary coding */
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	default:
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	return 0;
}

static int _westcos2opensc_ac(u8 flag)
{
	switch (flag) {
	case 0:
		return SC_AC_NEVER;
	case 1:
		return SC_AC_CHV;
	case 2:
		return SC_AC_AUT;
	case 3:
		return SC_AC_UNKNOWN;
	case 4:
		return SC_AC_UNKNOWN;
	case 5:
		return SC_AC_UNKNOWN;
	case 6:
		return SC_AC_UNKNOWN;
	case 7:
		return SC_AC_UNKNOWN;
	case 8:
		return SC_AC_UNKNOWN;
	case 9:
		return SC_AC_UNKNOWN;
	case 10:
		return SC_AC_UNKNOWN;
	case 11:
		return SC_AC_UNKNOWN;
	case 12:
		return SC_AC_UNKNOWN;
	case 13:
		return SC_AC_UNKNOWN;
	case 14:
		return SC_AC_UNKNOWN;
	case 15:
		return SC_AC_NONE;
	}
	return SC_AC_UNKNOWN;
}

static int westcos_process_fci(sc_card_t * card, sc_file_t * file,
			       const u8 * buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;
	if (card->ctx->debug >= 5)
		sc_debug(card->ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "  file identifier: 0x%02X%02X\n",
				 tag[0], tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "  bytes in file: %d\n",
					 bytes);
			file->size = bytes;
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;
			file->shareable = 0;
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "  shareable: %s\n",
					 (file->shareable) ? "yes" : "no");
			file->ef_structure = SC_FILE_EF_UNKNOWN;
			switch (byte) {
			case 0x38:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			case 0x01:
				type = "working or internal EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = SC_FILE_EF_TRANSPARENT;
				break;
			case 0x02:
				type = "working or internal EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
				break;
			case 0x06:
				type = "working or internal EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				file->ef_structure = SC_FILE_EF_CYCLIC;
				break;
			default:
				type = "unknow";
			}
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "  type: %s\n", type);
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "  EF structure: %d\n",
					 file->ef_structure);
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		memcpy(file->name, tag, taglen);
		file->namelen = taglen;
		if (card->ctx->debug >= 5) {
			char tbuf[128];
			sc_hex_dump(ctx, file->name, file->namelen, tbuf,
				    sizeof(tbuf));
			sc_debug(card->ctx, "  File name: %s\n", tbuf);
		}
	}
	if (file->type == SC_FILE_TYPE_DF) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
		if (tag != NULL && taglen == 3) {
			file->size = tag[1] * 256 + tag[2];
		} else
			file->size = 0;
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_sec_attr(file, tag, taglen);

		/* FIXME: compact file system only */
		if (file->type == SC_FILE_TYPE_DF) {
			sc_file_add_acl_entry(file, SC_AC_OP_SELECT,
					      _westcos2opensc_ac(tag[0] >>
								 4),
					      tag[0 + 4] >> 4);
			sc_file_add_acl_entry(file, SC_AC_OP_CREATE,
					      _westcos2opensc_ac(tag[0] &
								 0x0f),
					      tag[0 + 4] & 0x0f);
			sc_file_add_acl_entry(file, SC_AC_OP_INVALIDATE,
					      _westcos2opensc_ac(tag[1] >>
								 4),
					      tag[1 + 4] >> 4);
		}

		else {
			if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
				sc_file_add_acl_entry(file, SC_AC_OP_READ,
						      _westcos2opensc_ac(tag[0]
									 >>
									 4),
						      tag[0 + 4] >> 4);
				sc_file_add_acl_entry(file, SC_AC_OP_UPDATE,
						      _westcos2opensc_ac(tag[0]
									 &
									 0x0f),
						      tag[0 + 4] & 0x0f);
				sc_file_add_acl_entry(file,
						      SC_AC_OP_INVALIDATE,
						      _westcos2opensc_ac(tag[1]
									 >>
									 4),
						      tag[1 + 4] >> 4);
				sc_file_add_acl_entry(file, SC_AC_OP_ERASE,
						      _westcos2opensc_ac(tag[1]
									 &
									 0x0f),
						      tag[1 + 4] & 0x0f);
			}

			else {
				sc_file_add_acl_entry(file, SC_AC_OP_READ,
						      _westcos2opensc_ac(tag[0]
									 >>
									 4),
						      tag[0 + 4] >> 4);
				sc_file_add_acl_entry(file, SC_AC_OP_UPDATE,
						      _westcos2opensc_ac(tag[0]
									 &
									 0x0f),
						      tag[0 + 4] & 0x0f);
				sc_file_add_acl_entry(file,
						      SC_AC_OP_INVALIDATE,
						      _westcos2opensc_ac(tag[1]
									 >>
									 4),
						      tag[1 + 4] >> 4);
			}
		}
	}
	return 0;
}

static int westcos_read_binary(sc_card_t * card,
			       unsigned int idx, u8 * buf, size_t count,
			       unsigned long flags)
{
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_read_binary\n");
	if (idx > 0x7fff) {
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx,
				 "invalid EF offset: 0x%X > 0x7FFF\n", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	memcpy(buf, recvbuf, apdu.resplen);
	return (int)apdu.resplen;
}

static int westcos_write_binary(sc_card_t * card,
				  unsigned int idx, const u8 * buf,
				  size_t count, unsigned long flags)
{
	sc_apdu_t apdu;
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (idx > 0x7fff) {
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx,
				 "invalid EF offset: 0x%X > 0x7FFF\n", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return (int)count;
} 

static int westcos_update_binary(sc_card_t * card,
				   unsigned int idx, const u8 * buf,
				   size_t count, unsigned long flags)
{
	sc_apdu_t apdu;
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_update_binary\n");
	if (idx > 0x7fff) {

		//erreur(card->ctx, 0, "invalid EF offset: 0x%X > 0x7FFF\n", idx);
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx,
				 "invalid EF offset: 0x%X > 0x7FFF\n", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return (int)count;
}

#define HIGH (0)
#define LOW (1)
static int _convertion_ac_methode(sc_file_t * file, int low,
				  unsigned int operation, u8 * buf,
				  u8 * buf_key)
{
	const struct sc_acl_entry *acl;
	acl = sc_file_get_acl_entry(file, operation);
	if (acl == NULL) {

		/* par defaut always */
		*buf = 0xff;
		*buf_key = 0x00;
		return 0;
	}
	switch (acl->method) {
	case SC_AC_NONE:
		if (low)
			*buf |= 0x0f;

		else
			*buf |= 0xf0;
		break;
	case SC_AC_CHV:	/* Card Holder Verif. */
		if (low)
			*buf |= 0x01;

		else
			*buf |= 0x10;
		break;
	case SC_AC_TERM:	/* Terminal auth. */
		return SC_ERROR_NOT_SUPPORTED;
	case SC_AC_PRO:	/* Secure Messaging */
		return SC_ERROR_NOT_SUPPORTED;
	case SC_AC_AUT:	/* Key auth. */
		if (low)
			*buf |= 0x02;

		else
			*buf |= 0x20;
		if (acl->key_ref > 15)
			return SC_ERROR_NOT_SUPPORTED;
		if (low)
			*buf_key |= acl->key_ref;

		else
			*buf_key |= (acl->key_ref) << 4;
		break;
	case SC_AC_NEVER:
		*buf |= 0;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	return 0;
}

static int westcos_create_file(struct sc_card *card, struct sc_file *file)
{
	int r;
	sc_apdu_t apdu;
	u8 buf[12], p1 = 0, p2 = 0;
	int buflen;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_create_file\n");
	memset(buf, 0, sizeof(buf));

	/* clef de transport */
	r = sc_card_ctl(card, SC_CARDCTL_WESTCOS_AUT_KEY, NULL);
	if (r)
		return (r);
	buflen = sizeof(buf);
	switch (file->type) {
	case SC_FILE_TYPE_DF:
		buf[0] = 0x00;
		buf[1] = 0x01;
		_convertion_ac_methode(file, HIGH, SC_AC_OP_SELECT, &buf[2],
				       &buf[2 + 4]);
		_convertion_ac_methode(file, LOW, SC_AC_OP_CREATE, &buf[2],
				       &buf[2 + 4]);
		_convertion_ac_methode(file, HIGH, SC_AC_OP_INVALIDATE,
				       &buf[3], &buf[3 + 4]);
		buflen = 10;
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		buf[0] |= 0x80;
	case SC_FILE_TYPE_WORKING_EF:
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			buf[0] |= 0x20;	/* pas de support transaction  */
			buf[1] |= 0;
			_convertion_ac_methode(file, HIGH, SC_AC_OP_READ,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, LOW, SC_AC_OP_UPDATE,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, HIGH, SC_AC_OP_INVALIDATE,
					       &buf[3], &buf[3 + 4]);
			_convertion_ac_methode(file, LOW, SC_AC_OP_ERASE,
					       &buf[3], &buf[3 + 4]);
			buf[10] = (u8) ((file->size) / 256);
			buf[11] = (u8) ((file->size) % 256);
			break;
		case SC_FILE_EF_LINEAR_FIXED:
			buf[0] |= 0x40;	/* pas de support transaction  */
			buf[1] |= 0;
			_convertion_ac_methode(file, HIGH, SC_AC_OP_READ,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, LOW, SC_AC_OP_UPDATE,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, HIGH, SC_AC_OP_INVALIDATE,
					       &buf[3], &buf[3 + 4]);
			buf[10] = file->record_count;
			buf[11] = file->record_length;
			break;
		case SC_FILE_EF_CYCLIC:
			buf[0] |= 0x60;	/* pas de support transaction  */
			buf[1] |= 0;
			_convertion_ac_methode(file, HIGH, SC_AC_OP_READ,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, LOW, SC_AC_OP_UPDATE,
					       &buf[2], &buf[2 + 4]);
			_convertion_ac_methode(file, HIGH, SC_AC_OP_INVALIDATE,
					       &buf[3], &buf[3 + 4]);
			buf[10] = file->record_count;
			buf[11] = file->record_length;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
		case SC_FILE_EF_UNKNOWN:
		case SC_FILE_EF_LINEAR_FIXED_TLV:
		case SC_FILE_EF_LINEAR_VARIABLE_TLV:
		case SC_FILE_EF_CYCLIC_TLV:
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (file->shareable)
		buf[0] |= 0x08;
	if (file->path.len >= 2) {
		p1 = file->path.value[file->path.len - 2];
		p2 = file->path.value[file->path.len - 1];
	}

	else if (file->id) {
		p1 = (file->id) / 256;
		p2 = (file->id) % 256;
	}
	if (card->ctx->debug >= 3)
		sc_debug(card->ctx, "create file %s, id %X size %d\n",
			 file->path.value, file->id, file->size);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, p1, p2);
	apdu.cla = 0x80;
	apdu.lc = buflen;
	apdu.datalen = buflen;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static int westcos_delete_file(sc_card_t * card, const sc_path_t * path_in)
{
	int r;
	sc_apdu_t apdu;
	if (card == NULL || path_in == NULL || path_in->len < 2)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_delete_file\n");
	if (path_in->len > 2) {
		r = sc_select_file(card, path_in, NULL);
		if (r)
			return (r);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4,
		       path_in->value[path_in->len - 2],
		       path_in->value[path_in->len - 1]);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return 0;
}

static int westcos_list_files(sc_card_t * card, u8 * buf, size_t buflen)
{
	int r;
	sc_apdu_t apdu;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_list_files\n");
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x34, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.le = buflen;
	apdu.resplen = buflen;
	apdu.resp = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return apdu.resplen;
}

static int westcos_get_crypte_challenge(sc_card_t * card, const u8 * key,
					u8 * result, size_t * len)
{
	int r;
	DES_key_schedule ks1, ks2;
	u8 buf[8];
	if ((*len) < sizeof(buf))
		return SC_ERROR_INVALID_ARGUMENTS;
	*len = 8;
	r = sc_get_challenge(card, buf, *len);
	if (r)
		return r;
	DES_set_key((const_DES_cblock *) & key[0], &ks1);
	DES_set_key((const_DES_cblock *) & key[8], &ks2);
	DES_ecb2_encrypt((const_DES_cblock *)buf, (DES_cblock*)result, &ks1, &ks2, DES_ENCRYPT);
	return 0;
}

static int westcos_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	int r;
	u8 buf[20];		//, result[20];
	sc_apdu_t apdu;
	int len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx,
			 "westcos_pin_cmd:data->pin_type=%X, data->cmd=%X\n",
			 data->pin_type, data->cmd);
	if (tries_left)
		*tries_left = -1;
	switch (data->pin_type) {
	case SC_AC_AUT:
		len = sizeof(buf);
		r = westcos_get_crypte_challenge(card, data->pin1.data, buf,
						 &len);
		if (r)
			return (r);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x00,
			       data->pin_reference);
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = buf;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
		break;
	case SC_AC_CHV:
		if (data->flags & SC_PIN_CMD_NEED_PADDING)
			pad = 1;
		if (data->flags & SC_PIN_CMD_USE_PINPAD)
			use_pin_pad = 1;
		data->pin1.offset = 0;
		data->pin1.encoding = SC_PIN_ENCODING_GLP;
		if (data->pin1.min_length == 0)
			data->pin1.min_length = 4;
		if (data->pin1.max_length == 0)
			data->pin1.max_length = 12;
		switch (data->cmd) {
		case SC_PIN_CMD_VERIFY:
			ins = 0x20;
			if ((r =
			     sc_build_pin(buf, sizeof(buf), &data->pin1,
					  pad)) < 0)
				return r;
			len = r;
			break;
		case SC_PIN_CMD_CHANGE:
			ins = 0x24;
			if (data->pin1.len != 0 || use_pin_pad) {
				if ((r =
				     sc_build_pin(buf, sizeof(buf),
						  &data->pin1, pad)) < 0)
					return r;
				len += r;
			} else {

				/* implicit test */
				p1 = 1;
			}
			data->pin2.offset = data->pin1.offset + len;
			data->pin2.encoding = SC_PIN_ENCODING_GLP;
			if ((r =
			     sc_build_pin(buf + len, sizeof(buf) - len,
					  &data->pin2, pad)) < 0)
				return r;
			len += r;
			break;
		case SC_PIN_CMD_UNBLOCK:
			ins = 0x2C;
			if (data->pin1.len != 0 || use_pin_pad) {
				if ((r =
				     sc_build_pin(buf, sizeof(buf),
						  &data->pin1, pad)) < 0)
					return r;
				len += r;
			} else {
				p1 |= 0x02;
			}
			if (data->pin2.len != 0 || use_pin_pad) {
				data->pin2.offset = data->pin1.offset + len;
				data->pin2.encoding = SC_PIN_ENCODING_GLP;
				if ((r =
				     sc_build_pin(buf + len, sizeof(buf) - len,
						  &data->pin2, pad)) < 0)
					return r;
				len += r;
			} else {
				p1 |= 0x01;
			}
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins, p1,
			       data->pin_reference);
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = buf;
		apdu.resplen = 0;
		apdu.sensitive = 1;
		if (!use_pin_pad) {

			/* Transmit the APDU to the card */
			r = sc_transmit_apdu(card, &apdu);

			/* Clear the buffer - it may contain pins */
			sc_mem_clear(buf, sizeof(buf));
		} else {
			data->apdu = &apdu;
			if (card->reader
			    && card->reader->ops
			    && card->reader->ops->perform_verify) {
				r = card->reader->ops->perform_verify(card->
								      reader,
								      card->
								      slot,
								      data);
			} else {
				r = SC_ERROR_NOT_SUPPORTED;
			}
		}
		if (r)
			return (r);
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}

static int westcos_get_response(sc_card_t * card, size_t * count, u8 * buf)
{
	sc_apdu_t apdu;
	int r;
	size_t rlen;

	/* request at most max_recv_size bytes */
	if (*count > card->max_recv_size)
		rlen = card->max_recv_size;

	else
		rlen = *count;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xC0, 0x00, 0x00);
	apdu.le = rlen;
	apdu.resplen = rlen;
	apdu.resp = buf;

	/* don't call GET RESPONSE recursively */
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	*count = apdu.resplen;
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		r = 0;		/* no more data to read */

	else if (apdu.sw1 == 0x61)
		r = apdu.sw2 == 0 ? 256 : apdu.sw2;	/* more data to read    */

	else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
		r = 0;		/* Le not reached but file/record ended */

	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static int westcos_get_challenge(sc_card_t * card, u8 * rnd, size_t len)
{
	int r;
	sc_apdu_t apdu;
	u8 buf[10];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0x00, 0x00);
	apdu.le = 8;
	apdu.resp = buf;
	apdu.resplen = 8;	/* include SW's */
	while (len > 0) {
		size_t n = len > 8 ? 8 : len;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		if (apdu.resplen != 8)
			return sc_check_sw(card, apdu.sw1, apdu.sw2);
		memcpy(rnd, apdu.resp, n);
		len -= n;
		rnd += n;
	}
	return 0;
}

static int westcos_verify(struct sc_card *card, unsigned int type,
			  int ref_qualifier, const u8 * data,
			  size_t data_len, int *tries_left)
{
	int r;
	size_t len;
	sc_apdu_t apdu;
	u8 buf[50];
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (tries_left)
		(*tries_left)--;
	switch (type) {
	case SC_AC_NONE:
		break;
	case SC_AC_CHV:	/* Card Holder Verif. */
		break;
	case SC_AC_TERM:	/* Terminal auth. */
		break;
	case SC_AC_PRO:	/* Secure Messaging */
		break;
	case SC_AC_AUT:	/* Key auth. */
		len = sizeof(buf);
		r = westcos_get_crypte_challenge(card, data, buf, &len);
		if (r)
			return (r);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x82, 0x00,
			       ref_qualifier);
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = buf;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	default:
		break;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int westcos_read_record(sc_card_t * card,
			       unsigned int rec_nr, u8 * buf, size_t count,
			       unsigned long flags)
{
	sc_apdu_t apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	memcpy(buf, recvbuf, apdu.resplen);
	return apdu.resplen;
}

static int westcos_write_record(sc_card_t * card, unsigned int rec_nr,
				const u8 * buf, size_t count,
				unsigned long flags)
{
	sc_apdu_t apdu;
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (count > 256) {
		if (card->ctx->debug >= 1)
			sc_debug(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD2, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return count;
}

static int westcos_append_record(sc_card_t * card,
				 const u8 * buf, size_t count,
				 unsigned long flags)
{
	sc_apdu_t apdu;
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (count > 256) {
		if (card->ctx->debug >= 1)
			sc_debug(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE2, 0, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return count;
}

static int westcos_update_record(sc_card_t * card, unsigned int rec_nr,
				 const u8 * buf, size_t count,
				 unsigned long flags)
{
	sc_apdu_t apdu;
	int r;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (count > 256) {
		if (card->ctx->debug >= 1)
			sc_debug(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDC, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	return count;
}

static int sc_get_atr(sc_card_t * card)
{
	int r;
	sc_apdu_t apdu;
	u8 buf[sizeof(card->atr)];
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xEC, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.le = 0x0d;
	apdu.resplen = 0x0d;
	apdu.resp = buf;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return (r);
	memcpy(card->atr, buf, sizeof(card->atr));
	card->atr_len = apdu.resplen;
	return r;
}

static int sc_lock_phase(sc_card_t * card, u8 phase)
{
	int r;
	sc_apdu_t apdu;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x16, phase, 0x00);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return (r);
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int westcos_card_ctl(sc_card_t * card, unsigned long cmd, void *ptr)
{
	int r;
	size_t buflen;
	u8 buf[256];
	sc_apdu_t apdu;
	struct sc_pin_cmd_data data;
	sc_serial_number_t *serialnr;
	priv_data_t *priv_data = NULL;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_card_ctl cmd = %X\n", cmd);
	priv_data = (priv_data_t *) card->drv_data;
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return westcos_get_default_key(card,
					       (struct sc_cardctl_default_key
						*)ptr);
		break;
	case SC_CARDCTL_LIFECYCLE_SET:
		if (1) {
			int mode = *((int *)ptr);
			switch (mode) {
			case SC_CARDCTRL_LIFECYCLE_ADMIN:
				if (priv_data->flags & JAVACARD) {
					return 0;
				}
				if (card->atr[10] == 0x80
				    || card->atr[10] == 0x81)
					return 0;
				return SC_ERROR_CARD_CMD_FAILED;
			case SC_CARDCTRL_LIFECYCLE_USER:
				if (card->atr[10] == 0x80) {
					r = sc_lock_phase(card, 0x02);
					if (r)
						return (r);
					r = sc_get_atr(card);
					if (r)
						return (r);
					r = sc_card_ctl(card,
							SC_CARDCTL_WESTCOS_AUT_KEY,
							NULL);
					if (r)
						return (r);
				}
				if (card->atr[10] == 0x81) {
					r = sc_lock_phase(card, 0x01);
					if (r)
						return (r);
					r = sc_get_atr(card);
					if (r)
						return (r);
					return 0;
				}
				return SC_ERROR_CARD_CMD_FAILED;
			case SC_CARDCTRL_LIFECYCLE_OTHER:
			default:
				break;
			}
		}
		break;
	case SC_CARDCTL_GET_SERIALNR:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xEE, 0x00,
			       0x00);
		apdu.cla = 0xb0;
		apdu.le = 8;
		apdu.resp = buf;
		apdu.resplen = 10;	/* include SW's */
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return (r);
		if (SC_MAX_SERIALNR < 8)
			return SC_ERROR_NOT_SUPPORTED;
		serialnr = (sc_serial_number_t *) ptr;
		serialnr->len = 8;
		memcpy(serialnr->value, buf, serialnr->len);
		return 0;
	case SC_CARDCTL_WESTCOS_CREATE_MF:
		buf[0] = *((u8 *) ptr);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x3F,
			       0x00);
		apdu.cla = 0x80;
		apdu.lc = 1;
		apdu.datalen = 1;
		apdu.data = buf;
		apdu.le = 0;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	case SC_CARDCTL_WESTCOS_COMMIT:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 0x00, 0x00);
		apdu.cla = 0x80;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return (r);
		return r;
	case SC_CARDCTL_WESTCOS_ROLLBACK:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x24, 0x00, 0x00);
		apdu.cla = 0x80;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return (r);
		return r;
	case SC_CARDCTL_WESTCOS_AUT_KEY:
		if (ptr != NULL)
			priv_data->default_key = *((sc_autkey_t *) ptr);
		memset(&data, 0, sizeof(data));
		data.pin_type = SC_AC_AUT;
		data.pin_reference = priv_data->default_key.key_reference;
		data.pin1.len = priv_data->default_key.key_len;
		data.pin1.data = priv_data->default_key.key_value;
		return sc_pin_cmd(card, &data, NULL);
	case SC_CARDCTL_WESTCOS_CHANGE_KEY:
		if (1) {
			int lrc;
			u8 temp[7];
			sc_changekey_t *ck = (sc_changekey_t *) ptr;
			sc_autkey_t master_key;
			if (ck->master_key.key_len != 0)
				master_key = ck->master_key;

			else
				master_key = priv_data->default_key;
			memcpy(temp, ck->key_template, sizeof(temp));
			westcos_compute_aetb_crc(CRC_A, ck->new_key.key_value,
				   ck->new_key.key_len, &temp[5], &temp[6]);
			for (r = 0, temp[4] = 0xAA, lrc = 0; r < sizeof(temp);
			     r++)
				lrc += temp[r];
			temp[4] = (lrc % 256);
			buflen = sizeof(buf);
			r = westcos_get_crypte_challenge(card,
							 master_key.key_value,
							 buf, &buflen);
			if (r)
				return (r);
			memcpy(&buf[buflen], temp, sizeof(temp));
			buflen += sizeof(temp);
			memcpy(&buf[buflen], ck->new_key.key_value,
			       ck->new_key.key_len);
			buflen += ck->new_key.key_len;
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
				       0xD8, ck->new_key.key_reference,
				       master_key.key_reference);
			apdu.cla = 0x80;
			apdu.lc = buflen;
			apdu.datalen = buflen;
			apdu.data = buf;
			r = sc_transmit_apdu(card, &apdu);
			if (r)
				return (r);
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r)
				return (r);
			return r;
		}
	case SC_CARDCTL_WESTCOS_SET_DEFAULT_KEY:
		priv_data->default_key = *((sc_autkey_t *) ptr);
		return 0;
	case SC_CARDCTL_WESTCOS_LOAD_DATA:

		/* ptr[0] = 0x01 pour generique appli, 0x81 pour appli avec pme */
		buf[0] = *((u8 *) ptr);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xB2, 0x80,
			       0x14);
		apdu.cla = 0xB0;
		apdu.lc = 1;
		apdu.datalen = 1;
		apdu.data = buf;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	return SC_ERROR_NOT_SUPPORTED;
}
static int westcos_set_security_env(struct sc_card *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	priv_data_t *priv_data = NULL;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_set_security_env\n");
	priv_data = (priv_data_t *) card->drv_data;
	priv_data->env = *env;
	return 0;
}

static int westcos_restore_security_env(struct sc_card *card, int se_num)
{
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_restore_security_env\n");
	return 0;
}

static int westcos_sign_decipher(int mode, struct sc_card *card,
				 const u8 * data, size_t data_len, u8 * out,
				 size_t outlen)
{
	int r;
	int idx = 0;
	u8 buf[180];
	sc_file_t *keyfile = sc_file_new();
	priv_data_t *priv_data = NULL;
	int pad;

#ifdef ENABLE_OPENSSL
	RSA *rsa = NULL;
	BIO *mem = BIO_new(BIO_s_mem());

#endif
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ctx->debug >= 1)
		sc_debug(card->ctx, "westcos_sign_decipher\n");
	priv_data = (priv_data_t *) card->drv_data;
	if (keyfile == NULL || mem == NULL || priv_data == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
#ifndef ENABLE_OPENSSL
	r = SC_ERROR_NOT_SUPPORTED;

#else
	if ((priv_data->env.flags) & SC_ALGORITHM_RSA_PAD_PKCS1)
		pad = RSA_PKCS1_PADDING;

	else if ((priv_data->env.flags) & SC_ALGORITHM_RSA_RAW)
		pad = RSA_NO_PADDING;

	else {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto out;
	}
	r = sc_select_file(card, &(priv_data->env.file_ref), &keyfile);
	if (r)
		goto out;

	do {
		int alire;
		alire = min(((keyfile->size) - idx), sizeof(buf));
		if (alire <= 0)
			break;
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "idx = %d, alire=%d\n", idx, alire);
		r = sc_read_binary(card, idx, buf, alire, 0);
		if (r < 0)
			goto out;
		BIO_write(mem, buf, r);
		idx += r;
	} while (1);
	BIO_set_mem_eof_return(mem, -1);
	if (!d2i_RSAPrivateKey_bio(mem, &rsa)) {
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "RSA clef invalide, %d\n",
				 ERR_get_error());
		r = SC_ERROR_UNKNOWN;
		goto out;
	}

	/* pkcs11 reroute routine cryptage vers la carte */
	rsa->meth = RSA_PKCS1_SSLeay();
	if (RSA_size(rsa) > outlen) {
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "Buffer too small\n");
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
#if 1
	if (mode) {		/* decipher */
		r = RSA_private_decrypt(data_len, data, out, rsa, pad);
		if (r == -1) {

#ifdef DEBUG_SSL
			print_openssl_erreur();

#endif
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "Decipher error %d\n",
					 ERR_get_error());
			r = SC_ERROR_UNKNOWN;
			goto out;
		}
	}

	else {			/* signature */

		r = RSA_private_encrypt(data_len, data, out, rsa, pad);
		if (r == -1) {

#ifdef DEBUG_SSL
			print_openssl_erreur();

#endif
			if (card->ctx->debug >= 5)
				sc_debug(card->ctx, "Signature error %d\n",
					 ERR_get_error());
			r = SC_ERROR_UNKNOWN;
			goto out;
		}
	}

#else
	if (RSA_sign(nid, data, data_len, out, &outlen, rsa) != 1) {
		if (card->ctx->debug >= 5)
			sc_debug(card->ctx, "RSA_sign error %d \n",
				 ERR_get_error());
		r = SC_ERROR_UNKNOWN;
		goto out;
	}
	r = outlen;

#endif
#endif /* ENABLE_OPENSSL */
      out:
#ifdef ENABLE_OPENSSL
	if (mem)
		BIO_free(mem);
	if (rsa)
		RSA_free(rsa);

#endif
	if (keyfile)
		sc_file_free(keyfile);
	return r;
}

static int westcos_compute_signature(struct sc_card *card, const u8 * data,
				     size_t data_len, u8 * out, size_t outlen)
{
	return westcos_sign_decipher(0, card, data, data_len, out, outlen);
}

static int westcos_decipher(struct sc_card *card, const u8 * crgram,
			    size_t crgram_len, u8 * out, size_t outlen)
{
	return westcos_sign_decipher(1, card, crgram, crgram_len, out, outlen);
}

static struct sc_card_operations westcos_ops = { 
	westcos_match_card, 
	westcos_init,	/* init   */
	westcos_finish,		/* finish */
	westcos_read_binary, westcos_write_binary, westcos_update_binary,
	NULL,			/* erase_binary */
	westcos_read_record, westcos_write_record, westcos_append_record,
	westcos_update_record, westcos_select_file, westcos_get_response,
	westcos_get_challenge, NULL,	/* verify */
	NULL,			/* logout */
	westcos_restore_security_env,	/* restore_security_env */
	westcos_set_security_env,	/* set_security_env */
	westcos_decipher,	/* decipher */
	westcos_compute_signature,	/* compute_signature */
	NULL,			/* change_reference_data */
	NULL,			/* reset_retry_counter   */
	westcos_create_file, westcos_delete_file,	/* delete_file */
	westcos_list_files,	/* list_files */
	westcos_check_sw, westcos_card_ctl,	/* card_ctl */
	westcos_process_fci, NULL,	/* construct_fci */
	westcos_pin_cmd, NULL,	/* get_data */
	NULL,			/* put_data */
	NULL			/* delete_record */
};

static struct sc_card_driver westcos_drv =
    { "WESTCOS compatible cards", "westcos", &westcos_ops, NULL, 0, NULL
};

struct sc_card_driver *sc_get_westcos_driver(void)
{
	return &westcos_drv;
}
