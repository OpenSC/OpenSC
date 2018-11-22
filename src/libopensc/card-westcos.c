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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

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

#define DEFAULT_TRANSPORT_KEY "6f:59:b0:ed:6e:62:46:4a:5d:25:37:68:23:a8:a2:2d"

#define JAVACARD             (0x01) /* westcos applet on javacard   */
#define RSA_CRYPTO_COMPONENT (0x02) /* card component can do crypto */

#define WESTCOS_RSA_NO_HASH_NO_PAD		(0x20)
#define WESTCOS_RSA_NO_HASH_PAD_PKCS1	(0x21)

#ifdef ENABLE_OPENSSL
#define DEBUG_SSL
#ifdef DEBUG_SSL
static void print_openssl_error(void)
{
	static int charge = 0;
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

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations westcos_ops;

static struct sc_card_driver westcos_drv = {
	"WESTCOS compatible cards", "westcos", &westcos_ops, NULL, 0, NULL
};

static int westcos_get_default_key(sc_card_t * card,
				   struct sc_cardctl_default_key *data)
{
	const char *default_key;
	sc_log(card->ctx, 
		 "westcos_get_default_key:data->method=%d, data->key_ref=%d\n",
		 data->method, data->key_ref);
	if (data->method != SC_AC_AUT || data->key_ref != 0)
		return SC_ERROR_NO_DEFAULT_KEY;
	default_key =
	    scconf_get_str(card->ctx->conf_blocks[0], "westcos_default_key",
			   DEFAULT_TRANSPORT_KEY);
	return sc_hex_to_bin(default_key, data->key_data, &data->len);
}

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
					unsigned char *Data,
					size_t Length,
					unsigned char * TransmitFirst,
					unsigned char * TransmitSecond)
{
	unsigned char chBlock;
	unsigned short wCrc;
	switch (CRCType) {
	case CRC_A:
		wCrc = 0x6363;	/* ITU-V.41 */
		break;
	case CRC_B:
		wCrc = 0xFFFF;	/* ISO 3309 */
		break;
	default:
		return;
	}

	do {
		chBlock = *Data++;
		westcos_update_crc(chBlock, &wCrc);
	} while (--Length);
	if (CRCType == CRC_B)
		wCrc = ~wCrc;	/* ISO 3309 */
	*TransmitFirst = (unsigned char) (wCrc & 0xFF);
	*TransmitSecond = (unsigned char) ((wCrc >> 8) & 0xFF);
	return;
}

static int westcos_check_sw(sc_card_t * card, unsigned int sw1,
			    unsigned int sw2)
{
	if ((sw1 == 0x69) && (sw2 == 0x88))
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	assert(iso_ops && iso_ops->check_sw);
	return iso_ops->check_sw(card, sw1, sw2);
}

static const struct sc_atr_table westcos_atrs[] = {
	/* westcos 2ko */
	{ "3F:69:00:00:00:64:01:00:00:00:80:90:00", "ff:ff:ff:ff:ff:ff:ff:00:00:00:f0:ff:ff", NULL, 0x00, 0, NULL },
	/* westcos applet */
	{ "3B:95:94:80:1F:C3:80:73:C8:21:13:54", "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff", NULL, JAVACARD, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
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
	int i;

	i = _sc_match_atr(card, westcos_atrs, &card->type);
	if (i < 0)
		return 0;
	
	/* JAVACARD, look for westcos applet */
	if (i == 1) { 
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
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return 0;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
			return 0;
	}
	
	return 1;
}

static int westcos_init(sc_card_t * card)
{
	int r;
	const char *default_key;
	unsigned long exponent, flags;
	priv_data_t *priv_data;

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
		
	card->drv_data = malloc(sizeof(priv_data_t));
	if (card->drv_data == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(card->drv_data, 0, sizeof(priv_data_t));
	
	priv_data = (priv_data_t *) card->drv_data;

	if (card->type & JAVACARD) {
		priv_data->flags |= JAVACARD;
	}
	
	/* check for crypto component */
	if(card->atr.value[9] == 0xD0)
	{
		priv_data->flags |= RSA_CRYPTO_COMPONENT;
	}
	
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
		priv_data = (priv_data_t *) (card->drv_data);
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
	priv_data_t *priv_data = (priv_data_t *) card->drv_data;

	assert(iso_ops && iso_ops->select_file);
	priv_data->file_id = 0;
	return iso_ops->select_file(card, in_path, file_out);
}

static int _westcos2opensc_ac(u8 flag)
{
	if (flag == 0)
		return SC_AC_NEVER;
	else if (flag == 1)
		return SC_AC_CHV;
	else if (flag == 2)
		return SC_AC_AUT;
	else if (flag == 15)
		return SC_AC_NONE;
	return SC_AC_UNKNOWN;
}

static int westcos_process_fci(sc_card_t * card, sc_file_t * file,
			       const u8 * buf, size_t buflen)
{
	sc_context_t *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;
	sc_log(card->ctx,  "processing FCI bytes\n");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(card->ctx, 
			"  file identifier: 0x%02X%02X\n", tag[0], tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		sc_log(card->ctx, 
			"  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			sc_log(card->ctx, 
				"  bytes in file: %d\n", bytes);
			file->size = bytes;
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;
			file->shareable = 0;
			sc_log(card->ctx, 
				"  shareable: %s\n",
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
				type = "unknown";
			}
			sc_log(card->ctx, 
				"  type: %s\n", type);
			sc_log(card->ctx, 
				"  EF structure: %d\n", file->ef_structure);
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		memcpy(file->name, tag, taglen);
		file->namelen = taglen;
		sc_log_hex(card->ctx, "  File name", file->name, file->namelen);
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

#define HIGH (0)
#define LOW (1)
static int _convertion_ac_methode(sc_file_t * file, int low,
				  unsigned int operation, u8 * buf,
				  u8 * buf_key)
{
	const struct sc_acl_entry *acl;
	acl = sc_file_get_acl_entry(file, operation);
	if (acl == NULL) {

		/* per default always */
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

static int westcos_create_file(sc_card_t *card, struct sc_file *file)
{
	int r;
	sc_apdu_t apdu;
	u8 buf[12], p1 = 0, p2 = 0;
	int buflen;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_log(card->ctx,  "westcos_create_file\n");
	memset(buf, 0, sizeof(buf));

	/* transport key */
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
		/* fall through */
	case SC_FILE_TYPE_WORKING_EF:
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			buf[0] |= 0x20; /* no transaction support */
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
			buf[0] |= 0x40; /* no transaction support */
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
			buf[0] |= 0x60; /* no transaction support */
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
	sc_log(card->ctx, 
		 "create file %s, id %X size %"SC_FORMAT_LEN_SIZE_T"u\n",
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
	sc_log(card->ctx,  "westcos_delete_file\n");
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
	sc_log(card->ctx,  "westcos_list_files\n");
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
#ifdef ENABLE_OPENSSL
	DES_key_schedule ks1, ks2;
#endif
	u8 buf[8];
	if ((*len) < sizeof(buf))
		return SC_ERROR_INVALID_ARGUMENTS;
	*len = 8;
	r = sc_get_challenge(card, buf, *len);
	if (r)
		return r;
#ifdef ENABLE_OPENSSL
	DES_set_key((const_DES_cblock *) & key[0], &ks1);
	DES_set_key((const_DES_cblock *) & key[8], &ks2);
	DES_ecb2_encrypt((const_DES_cblock *)buf, (DES_cblock*)result, &ks1, &ks2, DES_ENCRYPT);
	return SC_SUCCESS;
#else
	return SC_ERROR_NOT_SUPPORTED;
#endif
}

static int westcos_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	int r;
	u8 buf[20];
	sc_apdu_t apdu;
	size_t len = 0;
	int pad = 0, use_pin_pad = 0, ins, p1 = 0;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_log(card->ctx, 
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

static int sc_get_atr(sc_card_t * card)
{
	int r;
	sc_apdu_t apdu;
	u8 buf[sizeof(card->atr.value)];
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
	memcpy(card->atr.value, buf, sizeof(card->atr.value));
	card->atr.len = apdu.resplen;
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
	unsigned int i;
	int r;
	size_t buflen;
	u8 buf[256];
	sc_apdu_t apdu;
	struct sc_pin_cmd_data data;
	sc_serial_number_t *serialnr;
	priv_data_t *priv_data = NULL;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_log(card->ctx, 
		"westcos_card_ctl cmd = %lX\n", cmd);
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
				if (card->atr.value[10] == 0x80
				    || card->atr.value[10] == 0x81)
					return 0;
				return SC_ERROR_CARD_CMD_FAILED;
			case SC_CARDCTRL_LIFECYCLE_USER:
				if (card->atr.value[10] == 0x80) {
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
				if (card->atr.value[10] == 0x81) {
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
		{
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
			for (i = 0, temp[4] = 0xAA, lrc = 0; i < sizeof(temp);
			    i++)
				lrc += temp[i];
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

static int westcos_set_security_env(sc_card_t *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	int r = 0;
	priv_data_t *priv_data = NULL;
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_log(card->ctx, 
		"westcos_set_security_env\n");
	priv_data = (priv_data_t *) card->drv_data;
	priv_data->env = *env;
	
	if(priv_data->flags & RSA_CRYPTO_COMPONENT)
	{
		sc_apdu_t apdu;
		unsigned char mode = 0;
		u8 buf[128];

		if ((priv_data->env.flags) & SC_ALGORITHM_RSA_PAD_PKCS1)
			mode = WESTCOS_RSA_NO_HASH_PAD_PKCS1;
		else if ((priv_data->env.flags) & SC_ALGORITHM_RSA_RAW)
			mode = WESTCOS_RSA_NO_HASH_NO_PAD;

		r = sc_path_print((char *)buf, sizeof(buf), &(env->file_ref));
		if(r)
			return r;
			
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xf0, mode);
		apdu.cla = 0x00;
		apdu.lc = strlen((char *)buf);
		apdu.datalen = apdu.lc;
		apdu.data = buf;
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return (r);
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	return r;
}

static int westcos_restore_security_env(sc_card_t *card, int se_num)
{
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_log(card->ctx, 
		"westcos_restore_security_env\n");
	return 0;
}

static int westcos_sign_decipher(int mode, sc_card_t *card,
				 const u8 * data, size_t data_len, u8 * out,
				 size_t outlen)
{
	int r;
	sc_file_t *keyfile = NULL;
#ifdef ENABLE_OPENSSL
	int idx = 0;
	u8 buf[180];
	priv_data_t *priv_data = NULL;
	int pad;
	RSA *rsa = NULL;
	BIO *mem = BIO_new(BIO_s_mem());
#endif

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_log(card->ctx, 
		 "westcos_sign_decipher outlen=%"SC_FORMAT_LEN_SIZE_T"u\n",
		 outlen);

#ifndef ENABLE_OPENSSL
	r = SC_ERROR_NOT_SUPPORTED;
#else
	if (mem == NULL || card->drv_data == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	priv_data = (priv_data_t *) card->drv_data;

	if(priv_data->flags & RSA_CRYPTO_COMPONENT)
	{
		sc_apdu_t apdu;
		
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x00, mode);
		apdu.datalen = data_len;
		apdu.data = data;
		apdu.lc = data_len;
		apdu.le = outlen > 240 ? 240 : outlen;
		apdu.resp = out;
		apdu.resplen = outlen;
		
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			goto out2;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if(r)
			goto out2;
		
		/* correct */
		r = apdu.resplen;
		goto out2;
	}
	if ((priv_data->env.flags) & SC_ALGORITHM_RSA_PAD_PKCS1)
		pad = RSA_PKCS1_PADDING;

	else if ((priv_data->env.flags) & SC_ALGORITHM_RSA_RAW)
		pad = RSA_NO_PADDING;

	else {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto out;
	}
	r = sc_select_file(card, &(priv_data->env.file_ref), &keyfile);
	if (r || !keyfile)
		goto out;

	do {
		int alire;
		alire = min(((keyfile->size) - idx), sizeof(buf));
		if (alire <= 0)
			break;
		sc_log(card->ctx, 
			"idx = %d, alire=%d\n", idx, alire);
		r = sc_read_binary(card, idx, buf, alire, 0);
		if (r < 0)
			goto out;
		BIO_write(mem, buf, r);
		idx += r;
	} while (1);
	BIO_set_mem_eof_return(mem, -1);
	if (!d2i_RSAPrivateKey_bio(mem, &rsa)) {
		sc_log(card->ctx, 
			"RSA key invalid, %lu\n", ERR_get_error());
		r = SC_ERROR_UNKNOWN;
		goto out;
	}

	/* pkcs11 reset openssl functions */
	RSA_set_method(rsa, RSA_PKCS1_OpenSSL());

	if ((size_t)RSA_size(rsa) > outlen) {
		sc_log(card->ctx,  "Buffer too small\n");
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
#if 1
	if (mode) {		/* decipher */
		r = RSA_private_decrypt(data_len, data, out, rsa, pad);
		if (r == -1) {

#ifdef DEBUG_SSL
			print_openssl_error();

#endif
			sc_log(card->ctx, 
				"Decipher error %lu\n", ERR_get_error());
			r = SC_ERROR_UNKNOWN;
			goto out;
		}
	}

	else {			/* sign */

		r = RSA_private_encrypt(data_len, data, out, rsa, pad);
		if (r == -1) {

#ifdef DEBUG_SSL
			print_openssl_error();

#endif
			sc_log(card->ctx, 
				"Signature error %lu\n", ERR_get_error());
			r = SC_ERROR_UNKNOWN;
			goto out;
		}
	}

#else
	if (RSA_sign(nid, data, data_len, out, &outlen, rsa) != 1) {
		sc_log(card->ctx, 
			"RSA_sign error %d \n", ERR_get_error());
		r = SC_ERROR_UNKNOWN;
		goto out;
	}
	r = outlen;

#endif
out:
	if (mem)
		BIO_free(mem);
	if (rsa)
		RSA_free(rsa);
out2:
#endif /* ENABLE_OPENSSL */
	sc_file_free(keyfile);
	return r;
}

static int westcos_compute_signature(sc_card_t *card, const u8 * data,
				     size_t data_len, u8 * out, size_t outlen)
{
	return westcos_sign_decipher(0, card, data, data_len, out, outlen);
}

static int westcos_decipher(sc_card_t *card, const u8 * crgram,
			    size_t crgram_len, u8 * out, size_t outlen)
{
	return westcos_sign_decipher(1, card, crgram, crgram_len, out, outlen);
}

struct sc_card_driver *sc_get_westcos_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	westcos_ops = *iso_ops;

	westcos_ops.match_card = westcos_match_card;
	westcos_ops.init = westcos_init;
	westcos_ops.finish = westcos_finish;
	/* read_binary */
	/* write_binary */
	/* update_binary */
	/* read_record */
	/* write_record */
	/* append_record */
	/* update_record */
	westcos_ops.select_file = westcos_select_file;
	/* get_response */
	/* get_challenge */
	westcos_ops.restore_security_env = westcos_restore_security_env;
	westcos_ops.set_security_env = westcos_set_security_env;
	westcos_ops.decipher = westcos_decipher;
	westcos_ops.compute_signature = westcos_compute_signature;
	westcos_ops.create_file = westcos_create_file;
	westcos_ops.delete_file = westcos_delete_file;
	westcos_ops.list_files = westcos_list_files;
	westcos_ops.check_sw = westcos_check_sw;
	westcos_ops.card_ctl = westcos_card_ctl;
	westcos_ops.process_fci = westcos_process_fci;
	westcos_ops.construct_fci = NULL;
	westcos_ops.pin_cmd = westcos_pin_cmd;

	return &westcos_drv;
}

