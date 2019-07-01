/*
 * card-rutoken.c: Support for Rutoken S cards
 *
 * Copyright (C) 2007  Pavel Mironchik <rutoken@rutoken.ru>
 * Copyright (C) 2007  Eugene Hermann <rutoken@rutoken.ru>
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

#include <sys/types.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "internal.h"
#include "opensc.h"
#include "pkcs15.h"
#include "asn1.h"
#include "cardctl.h"

struct auth_senv {
	unsigned int algorithm;
};
typedef struct auth_senv auth_senv_t;

struct helper_acl_to_sec_attr
{
	unsigned int ac_op;
	size_t sec_attr_pos;
};
typedef struct helper_acl_to_sec_attr helper_acl_to_sec_attr_t;

static const helper_acl_to_sec_attr_t arr_convert_attr_df [] = {
	{ SC_AC_OP_CREATE, 0 },
	{ SC_AC_OP_CREATE, 1 },
	{ SC_AC_OP_DELETE, 6 }
};

static const helper_acl_to_sec_attr_t arr_convert_attr_ef [] = {
	{ SC_AC_OP_READ, 0 },
	{ SC_AC_OP_UPDATE, 1 },
	{ SC_AC_OP_WRITE, 1 },
	{ SC_AC_OP_DELETE, 6 }
};

static const sc_SecAttrV2_t default_sec_attr = {
	0x42,
	0, 1, 0, 0, 0, 0, 1,
	0, 0, 0, 0,
	2, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	2, 0, 0, 0,
	0, 0, 0, 0 /* reserve */
};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations rutoken_ops;

static struct sc_card_driver rutoken_drv = {
	"Rutoken driver",
	"rutoken",
	&rutoken_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table rutoken_atrs[] = {
	{ "3b:6f:00:ff:00:56:72:75:54:6f:6b:6e:73:30:20:00:00:90:00", NULL, NULL, SC_CARD_TYPE_RUTOKENS, 0, NULL }, /* Aktiv Rutoken S */
	{ "3b:6f:00:ff:00:56:75:61:54:6f:6b:6e:73:30:20:00:00:90:00", NULL, NULL, SC_CARD_TYPE_RUTOKENS, 0, NULL }, /* Aktiv uaToken S */
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static int rutoken_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	assert(card->drv_data);
	free(card->drv_data);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int rutoken_match_card(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (_sc_match_atr(card, rutoken_atrs, &card->type) >= 0)
	{
		sc_log(card->ctx,  "ATR recognized as Rutoken\n");
		LOG_FUNC_RETURN(card->ctx, 1);
	}
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int token_init(sc_card_t *card, const char *card_name)
{
	LOG_FUNC_CALLED(card->ctx);

	card->name = card_name;
	card->caps |= SC_CARD_CAP_RNG;
	card->drv_data = calloc(1, sizeof(auth_senv_t));
	if (card->drv_data == NULL)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_OUT_OF_MEMORY);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int rutoken_init(sc_card_t *card)
{
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	/* &rutoken_atrs[1] : { uaToken S ATR, NULL ATR } */
	if (_sc_match_atr(card, &rutoken_atrs[1], &card->type) >= 0)
		ret = token_init(card, "uaToken S card");
	else
		ret = token_init(card, "Rutoken S card");

	if (ret != SC_SUCCESS) {
		ret = SC_ERROR_INVALID_CARD;
	}
	LOG_FUNC_RETURN(card->ctx, ret);
}

static const struct sc_card_error rutoken_errors[] = {

	{ 0x6300, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C1, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed. One tries left"}, 
	{ 0x63C2, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed. Two tries left"}, 
	{ 0x63C3, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C4, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C5, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C6, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C7, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C8, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63C9, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CA, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CB, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CC, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CD, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CE, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 
	{ 0x63CF, SC_ERROR_PIN_CODE_INCORRECT,  "Authentication failed"}, 

	{ 0x6400, SC_ERROR_CARD_CMD_FAILED,     "Aborting"}, 

	{ 0x6500, SC_ERROR_MEMORY_FAILURE,      "Memory failure"}, 
	{ 0x6581, SC_ERROR_MEMORY_FAILURE,      "Memory failure"}, 

	{ 0x6700, SC_ERROR_WRONG_LENGTH,        "Lc or Le invalid"}, 

	{ 0x6883, SC_ERROR_CARD_CMD_FAILED,     "The finishing command of a chain is expected"}, 

	{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Required access right not granted"}, 
	{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED, "DO blocked"}, 
	{ 0x6985, SC_ERROR_CARD_CMD_FAILED,     "Command not allowed (unsuitable conditions)"}, 
	{ 0x6986, SC_ERROR_INCORRECT_PARAMETERS,"No current EF selected"}, 

	{ 0x6A80, SC_ERROR_INCORRECT_PARAMETERS,"Invalid parameters in data field"}, 
	{ 0x6A81, SC_ERROR_NOT_SUPPORTED,       "Function/mode not supported"}, 
	{ 0x6A82, SC_ERROR_FILE_NOT_FOUND,      "File (DO) not found"}, 
	{ 0x6A84, SC_ERROR_CARD_CMD_FAILED,     "Not enough memory space in the token"}, 
	{ 0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"P1 or P2 invalid"}, 
	{ 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS, "File (DO) already exists"}, 

	{ 0x6B00, SC_ERROR_INCORRECT_PARAMETERS,"Out of maximum file length"}, 

	{ 0x6C00, SC_ERROR_WRONG_LENGTH,        "Le does not fit the data to be sent"}, 

	{ 0x6D00, SC_ERROR_INS_NOT_SUPPORTED,   "Ins invalid (not supported)"}, 

	/* Own class of an error*/
	{ 0x6F01, SC_ERROR_CARD_CMD_FAILED,     "Rutoken has the exchange protocol which is not supported by the USB-driver (newer, than in the driver)"}, 
	{ 0x6F83, SC_ERROR_CARD_CMD_FAILED,     "Infringement of the exchange protocol with Rutoken is revealed"}, 
	{ 0x6F84, SC_ERROR_CARD_CMD_FAILED,     "Rutoken is busy by processing of other command"}, 
	{ 0x6F85, SC_ERROR_CARD_CMD_FAILED,     "In the current folder the maximum quantity of file system objects is already created"}, 
	{ 0x6F86, SC_ERROR_CARD_CMD_FAILED,     "Invalid access right. Already login"}, 

	{ 0x9000, SC_SUCCESS,                  NULL}
};

static int rutoken_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	size_t i;

	for (i = 0; i < sizeof(rutoken_errors)/sizeof(rutoken_errors[0]); ++i) {
		if (rutoken_errors[i].SWs == ((sw1 << 8) | sw2)) {
			if ( rutoken_errors[i].errorstr )
				sc_log(card->ctx,  "%s\n", rutoken_errors[i].errorstr);
			sc_log(card->ctx,  "sw1 = %x, sw2 = %x", sw1, sw2);
			return rutoken_errors[i].errorno;
		}
	}
	sc_log(card->ctx,  "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

static void swap_pair(u8 *buf, size_t len)
{
	size_t i;
	u8 tmp;

	for (i = 0; i + 1 < len; i += 2)
	{
		tmp = buf[i];
		buf[i] = buf[i + 1];
		buf[i + 1] = tmp;
	}
}

static void swap_four(u8 *buf, size_t len)
{
	size_t i;
	u8 tmp;

	for (i = 0; i + 3 < len; i += 4)
	{
		tmp = buf[i];
		buf[i] = buf[i + 3];
		buf[i + 3] = tmp;
		swap_pair(&buf[i + 1], 2);
	}
}

static int rutoken_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], previd[2];
	const u8 *tag;
	size_t taglen, len = 0;
	int ret;

	assert(card && card->ctx);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	assert(buf);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0, 0);
	for (;;)
	{
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		if (apdu.sw1 == 0x6A  &&  apdu.sw2 == 0x82)
			break; /* Next file not found */

		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, ret, "");

		if (apdu.resplen <= 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);

		/* save first file(dir) ID */
		tag = sc_asn1_find_tag(card->ctx, apdu.resp + 2, apdu.resplen - 2,
				0x83, &taglen);
		if (!tag || taglen != sizeof(previd))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		memcpy(previd, tag, sizeof(previd));

		if (len + sizeof(previd) <= buflen)
		{
			buf[len++] = previd[1];
			buf[len++] = previd[0];
		}

		tag = sc_asn1_find_tag(card->ctx, apdu.resp + 2, apdu.resplen - 2,
				0x82, &taglen);
		if (!tag || taglen != 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		if (tag[0] == 0x38)
		{
			/* Select parent DF of the current DF */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x03, 0);
			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			apdu.le = 256;
			ret = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
			ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_RET(card->ctx, ret, "");
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0x02);
		apdu.lc = sizeof(previd);
		apdu.data = previd;
		apdu.datalen = sizeof(previd);
	}
	LOG_FUNC_RETURN(card->ctx, len);
}

static void set_acl_from_sec_attr(sc_card_t *card, sc_file_t *file)
{
	if (file->sec_attr  &&  file->sec_attr_len == sizeof(sc_SecAttrV2_t))
	{
		sc_file_add_acl_entry(file, SC_AC_OP_SELECT,
				SC_AC_NONE, SC_AC_KEY_REF_NONE);
		if (file->sec_attr[0] & 0x40) /* if AccessMode.6 */
		{
			sc_log(card->ctx,  "SC_AC_OP_DELETE %i %i",
					(int)(*(int8_t*)&file->sec_attr[1 +6]),
					file->sec_attr[1+7 +6*4]);
			sc_file_add_acl_entry(file, SC_AC_OP_DELETE,
					(int)(*(int8_t*)&file->sec_attr[1 +6]),
					file->sec_attr[1+7 +6*4]);
		}
		if (file->sec_attr[0] & 0x01) /* if AccessMode.0 */
		{
			sc_log(card->ctx,  (file->type == SC_FILE_TYPE_DF) ?
					"SC_AC_OP_CREATE %i %i" : "SC_AC_OP_READ %i %i",
					(int)(*(int8_t*)&file->sec_attr[1 +0]),
					file->sec_attr[1+7 +0*4]);
			sc_file_add_acl_entry(file,
					(file->type == SC_FILE_TYPE_DF) ?
					SC_AC_OP_CREATE : SC_AC_OP_READ,
					(int)(*(int8_t*)&file->sec_attr[1 +0]),
					file->sec_attr[1+7 +0*4]);
		}
		if (file->type == SC_FILE_TYPE_DF)
		{
			sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES,
					SC_AC_NONE, SC_AC_KEY_REF_NONE);
		}
		else
			if (file->sec_attr[0] & 0x02) /* if AccessMode.1 */
			{
				sc_log(card->ctx,  "SC_AC_OP_UPDATE %i %i",
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1*4]);
				sc_file_add_acl_entry(file, SC_AC_OP_UPDATE,
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1*4]);
				sc_log(card->ctx,  "SC_AC_OP_WRITE %i %i",
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1*4]);
				sc_file_add_acl_entry(file, SC_AC_OP_WRITE,
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1*4]);
			}
	}
}

static int rutoken_select_file(sc_card_t *card,
			const sc_path_t *in_path, sc_file_t **file_out)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE], pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	sc_file_t *file = NULL;
	size_t pathlen;
	int ret;

	assert(card && card->ctx);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(in_path && sizeof(pathbuf) >= in_path->len);
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	/* p2 = 0; first record, return FCP */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	switch (in_path->type)
	{
	case SC_PATH_TYPE_FILE_ID:
		if (pathlen != 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	case SC_PATH_TYPE_PATH:
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0)
		{
			if (pathlen == 2)
				break; /* only 3F00 supplied */
			path += 2;
			pathlen -= 2;
		}
		apdu.p1 = 0x08;
		break;
	case SC_PATH_TYPE_DF_NAME:
	case SC_PATH_TYPE_FROM_CURRENT:
	case SC_PATH_TYPE_PARENT:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	swap_pair(path, pathlen);
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	apdu.le = 256;

	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	if (file_out == NULL)
	{
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, ret, "");

	if (apdu.resplen > 0 && apdu.resp[0] != 0x62) /* Tag 0x62 - FCP */
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	file = sc_file_new();
	if (file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	file->path = *in_path;
	if (card->ops->process_fci == NULL)
	{
		sc_file_free(file);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	if (apdu.resplen > 1  &&  apdu.resplen >= (size_t)apdu.resp[1] + 2)
	{
		ret = card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
	}
	if (file->sec_attr && file->sec_attr_len == sizeof(sc_SecAttrV2_t))
		set_acl_from_sec_attr(card, file);
	else
		ret = SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (ret != SC_SUCCESS)
		sc_file_free(file);
	else
	{
		assert(file_out);
		*file_out = file;
	}
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_process_fci(struct sc_card *card, sc_file_t *file,
			const unsigned char *buf, size_t buflen)
{
	size_t taglen;
	int ret;
	const unsigned char *tag;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	ret = iso_ops->process_fci(card, file, buf, buflen);
	if (ret == SC_SUCCESS)
	{
		/* Rutoken S returns buffers in little-endian. */
		/* Set correct file id. */
		file->id = ((file->id & 0xFF) << 8) | ((file->id >> 8) & 0xFF);
		sc_log(card->ctx,  "  file identifier: 0x%04X", file->id);
		/* Determine file size. */
		tag = sc_asn1_find_tag(card->ctx, buf, buflen, 0x80, &taglen);
		/* Rutoken S always returns 2 bytes. */
		if (tag != NULL && taglen == 2)
		{
			file->size = (tag[1] << 8) | tag[0];
			sc_log(card->ctx,  "  bytes in file: %"SC_FORMAT_LEN_SIZE_T"u", file->size);
		}
	}
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_construct_fci(sc_card_t *card, const sc_file_t *file,
			u8 *out, size_t *outlen)
{
	u8 buf[64], *p = out;

	assert(card && card->ctx);
	LOG_FUNC_CALLED(card->ctx);

	assert(file && out && outlen);
	assert(*outlen  >=  (size_t)(p - out) + 2);
	*p++ = 0x62; /* FCP template */
	p++; /* for length */

	/* 0x80 - Number of data bytes in the file, excluding structural information */
	buf[1] = (file->size >> 8) & 0xFF;
	buf[0] = file->size & 0xFF;
	sc_asn1_put_tag(0x80, buf, 2, p, *outlen - (p - out), &p);

	/* 0x82 - File descriptor byte */
	if (file->type_attr_len)
	{
		assert(sizeof(buf) >= file->type_attr_len);
		memcpy(buf, file->type_attr, file->type_attr_len);
		sc_asn1_put_tag(0x82, buf, file->type_attr_len,
				p, *outlen - (p - out), &p);
	}
	else
	{
		switch (file->type)
		{
		case SC_FILE_TYPE_WORKING_EF:
			buf[0] = 0x01;
			break;
		case SC_FILE_TYPE_DF:
			buf[0] = 0x38;
			break;
		case SC_FILE_TYPE_INTERNAL_EF:
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
		}
		buf[1] = 0;
		sc_asn1_put_tag(0x82, buf, 2, p, *outlen - (p - out), &p);
	}
	/* 0x83 - File identifier */
	buf[1] = (file->id >> 8) & 0xFF;
	buf[0] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);

	if (file->prop_attr_len)
	{
		assert(sizeof(buf) >= file->prop_attr_len);
		memcpy(buf, file->prop_attr, file->prop_attr_len);
		sc_asn1_put_tag(0x85, buf, file->prop_attr_len,
				p, *outlen - (p - out), &p);
	}
	if (file->sec_attr_len)
	{
		assert(sizeof(buf) >= file->sec_attr_len);
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
				p, *outlen - (p - out), &p);
	}
	out[1] = p - out - 2; /* length */
	*outlen = p - out;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
}

static int set_sec_attr_from_acl(sc_card_t *card, sc_file_t *file)
{
	const helper_acl_to_sec_attr_t *conv_attr;
	size_t i, n_conv_attr;
	const sc_acl_entry_t *entry;
	sc_SecAttrV2_t attr = { 0 };
	int ret = SC_SUCCESS;

	LOG_FUNC_CALLED(card->ctx);

	if (file->type == SC_FILE_TYPE_DF)
	{
		conv_attr = arr_convert_attr_df;
		n_conv_attr = sizeof(arr_convert_attr_df)/sizeof(arr_convert_attr_df[0]);
	}
	else
	{
		conv_attr = arr_convert_attr_ef;
		n_conv_attr = sizeof(arr_convert_attr_ef)/sizeof(arr_convert_attr_ef[0]);
	}
	sc_log(card->ctx,  "file->type = %i", file->type);

	for (i = 0; i < n_conv_attr; ++i)
	{
		entry = sc_file_get_acl_entry(file, conv_attr[i].ac_op);
		if (entry  &&  (entry->method == SC_AC_CHV || entry->method == SC_AC_NONE
				|| entry->method == SC_AC_NEVER)
		)
		{
			/* AccessMode.[conv_attr[i].sec_attr_pos] */
			attr[0] |= 1 << conv_attr[i].sec_attr_pos;
			sc_log(card->ctx, 
				 "AccessMode.%"SC_FORMAT_LEN_SIZE_T"u, attr[0]=0x%x",
				 conv_attr[i].sec_attr_pos, attr[0]);
			attr[1 + conv_attr[i].sec_attr_pos] = (u8)entry->method;
			sc_log(card->ctx,  "method %u", (u8)entry->method);
			if (entry->method == SC_AC_CHV)
			{
				attr[1+7 + conv_attr[i].sec_attr_pos*4] = (u8)entry->key_ref;
				sc_log(card->ctx,  "key_ref %u", (u8)entry->key_ref);
			}
		}
		else
		{
			sc_log(card->ctx,  "ACL (%u) not set, set default sec_attr",
					conv_attr[i].ac_op);
			memcpy(attr, default_sec_attr, sizeof(attr));
			break;
		}
	}
	ret = sc_file_set_sec_attr(file, attr, sizeof(attr));
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_create_file(sc_card_t *card, sc_file_t *file)
{
	int ret;

	assert(card && card->ctx);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	assert(file);
	if (file->sec_attr_len == 0)
	{
		ret = set_sec_attr_from_acl(card, file);
		LOG_TEST_RET(card->ctx, ret, "Set sec_attr from ACL failed");
	}
	assert(iso_ops && iso_ops->create_file);
	ret = iso_ops->create_file(card, file);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_delete_file(sc_card_t *card, const sc_path_t *path)
{
	u8 sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (!path || path->type != SC_PATH_TYPE_FILE_ID || (path->len != 0 && path->len != 2)) 
	{
		sc_log(card->ctx,  "File type has to be SC_PATH_TYPE_FILE_ID\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	if (path->len == sizeof(sbuf)) 
	{
		sbuf[1] = path->value[0];
		sbuf[0] = path->value[1];
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
		apdu.lc = sizeof(sbuf);
		apdu.datalen = sizeof(sbuf);
		apdu.data = sbuf;
	}
	else /* No file ID given: means currently selected file */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int rutoken_verify(sc_card_t *card, unsigned int type, int ref_qualifier,
			const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, ref_qualifier);
	ret = sc_transmit_apdu(card, &apdu);
	if (ret == SC_SUCCESS  &&  ((apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
				||  apdu.sw1 == 0x63)
	)
	{
		/* sw1 == 0x63  -  may be already login with other ref_qualifier
		 * sw1 == 0x90 && sw2 == 0x00  -  already login with ref_qualifier
		 */
		/* RESET ACCESS RIGHTS */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x40, 0x00, 0x00);
		apdu.cla = 0x80;
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, ret, "Reset access rights failed");
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, ref_qualifier);
	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (ret == SC_ERROR_PIN_CODE_INCORRECT  &&  tries_left)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, ref_qualifier);
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret == SC_ERROR_PIN_CODE_INCORRECT)
			*tries_left = (int)(apdu.sw2 & 0x0f);
	}
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	sc_path_t path;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_path("3F00", &path);
	ret = rutoken_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, ret, "Select MF failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x40, 0x00, 0x00);
	apdu.cla = 0x80;
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_change_reference_data(sc_card_t *card, unsigned int type,
			int ref_qualifier, const u8 *old, size_t oldlen,
			const u8 *newref, size_t newlen, int *tries_left)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (old && oldlen)
	{
		ret = rutoken_verify(card, type, ref_qualifier, old, oldlen, tries_left);
		LOG_TEST_RET(card->ctx, ret, "Invalid 'old' pass");
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref_qualifier);
	apdu.lc = newlen;
	apdu.datalen = newlen;
	apdu.data = newref;
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_reset_retry_counter(sc_card_t *card, unsigned int type,
			int ref_qualifier, const u8 *puk, size_t puklen,
			const u8 *newref, size_t newlen)
{
#ifdef FORCE_VERIFY_RUTOKEN
	int left;
#endif
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
#ifdef FORCE_VERIFY_RUTOKEN
	if (puk && puklen)
	{
		ret = rutoken_verify(card, type, ref_qualifier, puk, puklen, &left);
		sc_log(card->ctx,  "Tries left: %i\n", left);
		LOG_TEST_RET(card->ctx, ret, "Invalid 'puk' pass");
	}
#endif
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2c, 0x03, ref_qualifier);
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_restore_security_env(sc_card_t *card, int se_num)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 3, se_num);
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_set_security_env(sc_card_t *card, 
			const sc_security_env_t *env, 
			int se_num)
{
	sc_apdu_t apdu;
	auth_senv_t *senv;
	u8 data[3] = { 0x83, 0x01 };
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (!env)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	senv = (auth_senv_t*)card->drv_data;
	if (!senv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	if (env->algorithm != SC_ALGORITHM_GOST)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	senv->algorithm = SC_ALGORITHM_GOST;
	if (env->key_ref_len != 1)
	{
		sc_log(card->ctx,  "No or invalid key reference\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	data[2] = env->key_ref[0];
	/*  select component  */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 1, 0);
	apdu.lc = apdu.datalen = sizeof(data);
	apdu.data = data;
	switch (env->operation)
	{
		case SC_SEC_OPERATION_AUTHENTICATE:
			apdu.p2 = 0xA4;
			break;
		case SC_SEC_OPERATION_DECIPHER:
			apdu.p2 = 0xB8;
			break;
		case SC_SEC_OPERATION_SIGN:
			apdu.p2 = 0xAA;
			break;
		default:
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	/*  set SE  */
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, ret);
}

static void rutoken_set_do_hdr(u8 *data, size_t *data_len, sc_DOHdrV2_t *hdr)
{
	u8 buf[64], *p = data;

	assert(hdr && data && data_len);

	/* 0x80 - Number of data bytes in the file, excluding structural information */
	buf[1] = (hdr->wDOBodyLen >> 8) & 0xFF;
	buf[0] = hdr->wDOBodyLen & 0xFF;
	sc_asn1_put_tag(0x80, buf, 2, p, *data_len - (p - data), &p);

	/* 0x83 - Type and ID */
	buf[0] = hdr->OTID.byObjectType;
	buf[1] = hdr->OTID.byObjectID;
	sc_asn1_put_tag(0x83, buf, 2, p, *data_len - (p - data), &p);

	/* 0x85 - Options, Flags and Max count of try */
	buf[0] = hdr->OP.byObjectOptions;
	buf[1] = hdr->OP.byObjectFlags;
	buf[2] = hdr->OP.byObjectTry;
	sc_asn1_put_tag(0x85, buf, 3, p, *data_len - (p - data), &p);

	assert(sizeof(buf) >= sizeof(hdr->SA_V2));
	memcpy(buf, hdr->SA_V2, sizeof(hdr->SA_V2));
	sc_asn1_put_tag(0x86, buf, sizeof(hdr->SA_V2), p, *data_len - (p - data), &p);

	assert(*data_len >= (size_t)(p - data));
	*data_len = p - data;
}

static int rutoken_key_gen(sc_card_t *card, sc_DOHdrV2_t *pHdr)
{
	u8 data[SC_MAX_APDU_BUFFER_SIZE];
	size_t data_len = sizeof(data);
	sc_apdu_t apdu;
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	if (
	     (pHdr->wDOBodyLen != SC_RUTOKEN_DEF_LEN_DO_GOST) ||
	     (pHdr->OTID.byObjectType != SC_RUTOKEN_TYPE_KEY) ||
	     (pHdr->OP.byObjectFlags & SC_RUTOKEN_FLAGS_COMPACT_DO) ||
	     (pHdr->OP.byObjectFlags & SC_RUTOKEN_FLAGS_FULL_OPEN_DO) ||
	     (pHdr->OTID.byObjectID < SC_RUTOKEN_DO_ALL_MIN_ID) || 
	     (pHdr->OTID.byObjectID > SC_RUTOKEN_DO_NOCHV_MAX_ID_V2)
	)
	{
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	{
		pHdr->OP.byObjectTry = 0;
		rutoken_set_do_hdr(data, &data_len, pHdr);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x65);
		apdu.data = data;
		apdu.datalen = apdu.lc = data_len;
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_create_do(sc_card_t *card, sc_DO_V2_t * pDO)
{
	u8 data[SC_MAX_APDU_BUFFER_SIZE];
	size_t data_len = sizeof(data);
	sc_apdu_t apdu;
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	if (
	     ((pDO->HDR.OTID.byObjectType & SC_RUTOKEN_TYPE_CHV) &&
	      (pDO->HDR.OTID.byObjectID != SC_RUTOKEN_DEF_ID_GCHV_USER) &&
	      (pDO->HDR.OTID.byObjectID != SC_RUTOKEN_DEF_ID_GCHV_ADMIN)) ||
	     ((pDO->HDR.OTID.byObjectType == SC_RUTOKEN_ALLTYPE_GOST) && 
	      (pDO->HDR.wDOBodyLen != SC_RUTOKEN_DEF_LEN_DO_GOST)) ||
	     ((pDO->HDR.OTID.byObjectType == SC_RUTOKEN_ALLTYPE_SE) &&
	      (pDO->HDR.wDOBodyLen != SC_RUTOKEN_DEF_LEN_DO_SE)) ||
	     (pDO->HDR.OTID.byObjectID < SC_RUTOKEN_DO_ALL_MIN_ID) || 
	     (pDO->HDR.OTID.byObjectID > SC_RUTOKEN_DO_NOCHV_MAX_ID_V2) ||
	     ((pDO->HDR.OP.byObjectFlags & SC_RUTOKEN_FLAGS_COMPACT_DO) &&
	      (pDO->HDR.wDOBodyLen > SC_RUTOKEN_COMPACT_DO_MAX_LEN)) ||
	     (pDO->HDR.wDOBodyLen > SC_RUTOKEN_DO_PART_BODY_LEN)
	   )
	{
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	{
		rutoken_set_do_hdr(data, &data_len, &pDO->HDR);
		assert(sizeof(data) >= data_len + pDO->HDR.wDOBodyLen + 2);
		ret = sc_asn1_put_tag(0xA5, pDO->abyDOBody, pDO->HDR.wDOBodyLen,
				data + data_len, sizeof(data) - data_len, NULL);
		if (ret == SC_SUCCESS)
			data_len += pDO->HDR.wDOBodyLen + 2;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x62);
		apdu.data = data;
		apdu.datalen = apdu.lc = data_len;
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_get_do_info(sc_card_t *card, sc_DO_INFO_t * pInfo)
{
	u8 data[1];
	sc_apdu_t apdu;
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	if ((pInfo->SelType != select_first) &&
	    ((pInfo->DoId < SC_RUTOKEN_DO_ALL_MIN_ID) || 
	     (pInfo->DoId > SC_RUTOKEN_DO_NOCHV_MAX_ID_V2)))
	{
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x30, 0x00, 0x00);
		apdu.cla = 0x80;
		apdu.resp = pInfo->pDoData;
		apdu.resplen = sizeof(pInfo->pDoData);
		apdu.le = 255;
		memset(apdu.resp, 0, apdu.resplen);
		switch(pInfo->SelType)
		{
		case select_first:
			apdu.cse = SC_APDU_CASE_2_SHORT;
			break;
		case select_next:
			apdu.p2 = 0x02;
			/* fall through */
		case select_by_id:
			data[0] = pInfo->DoId;
			apdu.data = data;
			apdu.datalen = sizeof(data);
			apdu.lc = sizeof(data);
			break;
		default:
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
			break;
		}
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_delete_do(sc_card_t *card, u8 *pId)
{
	u8 data[1];
	sc_apdu_t apdu;
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	if ((*pId < SC_RUTOKEN_DO_ALL_MIN_ID) || 
	    (*pId > SC_RUTOKEN_DO_NOCHV_MAX_ID_V2))
	{
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x64);
		data[0] = *pId;
		apdu.data = data;
		apdu.datalen = sizeof(data);
		apdu.lc = sizeof(data);
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

/*  Both direction GOST cipher  */

static int rutoken_cipher_p(sc_card_t *card, const u8 * crgram, size_t crgram_len,
			u8 * out, size_t outlen, int p1, int p2, int isIV)
{
	u8 buf[248]; /* 248 (cipher_chunk) <= SC_MAX_APDU_BUFFER_SIZE  */
	size_t len, outlen_tail = outlen;
	int ret;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, 
		 ": crgram_len %"SC_FORMAT_LEN_SIZE_T"u; outlen %"SC_FORMAT_LEN_SIZE_T"u",
		 crgram_len, outlen);

	if (!out)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	if (crgram_len < 16 || ((crgram_len) % 8))
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_WRONG_LENGTH);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, p1, p2);
	do
	{
		len = (crgram_len > sizeof(buf)) ? sizeof(buf) : crgram_len;
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = crgram;
		crgram += len;
		crgram_len -= len;

		apdu.cla = (crgram_len == 0) ? 0x00 : 0x10;
		apdu.le = len;
		apdu.resplen = len;
		apdu.resp = buf;

		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret == SC_SUCCESS)
		{
			if (isIV)
			{
				apdu.resp += 8;
				apdu.resplen -= 8;
				isIV = 0;
			}
			if (apdu.resplen > outlen_tail)
				ret = SC_ERROR_BUFFER_TOO_SMALL;
			else
			{
				memcpy(out, apdu.resp, apdu.resplen);
				out += apdu.resplen;
				outlen_tail -= apdu.resplen;
			}
		}
	} while (ret == SC_SUCCESS  &&  crgram_len != 0);
	sc_log(card->ctx, 
		 "len out cipher %"SC_FORMAT_LEN_SIZE_T"u\n",
		 outlen - outlen_tail);
	if (ret == SC_SUCCESS)
		ret = (outlen_tail == 0) ? (int)outlen : SC_ERROR_WRONG_LENGTH;
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

/*  Launcher for cipher  */

static int rutoken_cipher_gost(sc_card_t *card, 
			struct sc_rutoken_decipherinfo *ptr, char is_encipher)
{
	int ret;

	if (is_encipher)
		ret = rutoken_cipher_p(card, ptr->inbuf, ptr->inlen, 
				ptr->outbuf, ptr->outlen, 0x86, 0x80, 0);
	else
		ret = rutoken_cipher_p(card, ptr->inbuf, ptr->inlen, 
				ptr->outbuf, ptr->outlen, 0x80, 0x86, 1);
	if (ret > 0)
	{
		if ((size_t)ret == ptr->outlen)
			ret = SC_SUCCESS;
		else
			ret = SC_ERROR_INTERNAL; /* SC_ERROR_DECRYPT_FAILED; */
	}
	return ret;

}

static int rutoken_compute_mac_gost(sc_card_t *card, 
			const u8 *in, size_t ilen, 
			u8 *out, size_t olen)
{
	const size_t signing_chunk = 248;
	size_t len;
	int ret;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	if (!in || !out || olen != 4 || ilen == 0)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	do
	{
		sc_format_apdu(card, &apdu,
				ilen > signing_chunk ?
				SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT,
				0x2A, 0x90, 0x80);
		len = (ilen > signing_chunk) ? signing_chunk : ilen;
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = in;
		in += len;
		ilen -= len;
		if (ilen == 0)
		{
			apdu.cla = 0x00;
			apdu.le = olen;
			apdu.resplen = olen;
			apdu.resp = out;
		}
		else
			apdu.cla = 0x10;
		ret = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	} while (ret == SC_SUCCESS  &&  ilen != 0);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_compute_signature(struct sc_card *card, 
			const u8 * data, size_t datalen, 
			u8 * out, size_t outlen)
{
	int ret;
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (!senv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	if (senv->algorithm == SC_ALGORITHM_GOST)
		ret = rutoken_compute_mac_gost(card, data, datalen, out, outlen);
	else
		ret = SC_ERROR_NOT_SUPPORTED;
	LOG_FUNC_RETURN(card->ctx, ret);
}

static int rutoken_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	unsigned char rbuf[32];
	size_t out_len;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->get_challenge(card, rbuf, sizeof rbuf);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE cmd failed");

	if (len < (size_t) r) {
		out_len = len;
	} else {
		out_len = (size_t) r;
	}
	memcpy(rnd, rbuf, out_len);

	LOG_FUNC_RETURN(card->ctx, out_len);
}

static int rutoken_get_serial(sc_card_t *card, sc_serial_number_t *serial)
{
	sc_apdu_t apdu;
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x81);
	apdu.resp = serial->value;
	apdu.resplen = sizeof(serial->value);
	apdu.le = 4;
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	serial->len = apdu.resplen;
	swap_four(serial->value, serial->len);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_get_info(sc_card_t *card, void *buff)
{
	sc_apdu_t apdu;
	u8 rbuf[8];
	int ret;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x89);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (ret == SC_SUCCESS)
		memcpy(buff, apdu.resp, apdu.resplen);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_format(sc_card_t *card, int apdu_ins)
{
	int ret;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, apdu_ins, 0x00, 0x00);
	apdu.cla = 0x80;
	ret = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int rutoken_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int ret = (ptr != NULL
			/*|| cmd == SC_CARDCTL_ERASE_CARD */
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_INIT
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_END
		) ? SC_SUCCESS : SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (ret == SC_SUCCESS)
	{
		switch (cmd) 
		{
		case SC_CARDCTL_RUTOKEN_CREATE_DO:
			ret = rutoken_create_do(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_GENERATE_KEY_DO:
			ret = rutoken_key_gen(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_DELETE_DO:
			ret = rutoken_delete_do(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_GET_DO_INFO:
			ret = rutoken_get_do_info(card, ptr);
			break;
		case SC_CARDCTL_GET_SERIALNR:
			ret = rutoken_get_serial(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_CHANGE_DO:
			ret = SC_ERROR_NOT_SUPPORTED;
			break;
		case SC_CARDCTL_RUTOKEN_GET_INFO:
			ret = rutoken_get_info(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_GOST_ENCIPHER:
			ret = rutoken_cipher_gost(card, ptr, 1);
			break;
		case SC_CARDCTL_RUTOKEN_GOST_DECIPHER:
			ret = rutoken_cipher_gost(card, ptr, 0);
			break;
		/* case SC_CARDCTL_ERASE_CARD: */
		case SC_CARDCTL_RUTOKEN_FORMAT_INIT:
			/* ret = rutoken_format(card, 0x7a); *//*  APDU: INIT RUTOKEN */
			ret = rutoken_format(card, 0x8a); /* APDU: NEW INIT RUTOKEN */
			break;
		case SC_CARDCTL_RUTOKEN_FORMAT_END:
			ret = rutoken_format(card, 0x7b); /* APDU: FORMAT END */
			break;
		default:
			sc_log(card->ctx,  "cmd = %lu", cmd);
			ret = SC_ERROR_NOT_SUPPORTED;
			break;
		}
	}
	LOG_FUNC_RETURN(card->ctx, ret);
}

static struct sc_card_driver* get_rutoken_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	rutoken_ops = *iso_ops;

	rutoken_ops.match_card = rutoken_match_card;
	rutoken_ops.init = rutoken_init;
	rutoken_ops.finish = rutoken_finish;
	/* read_binary */
	rutoken_ops.write_binary = NULL;
	/* update_binary */
	rutoken_ops.read_record = NULL;
	rutoken_ops.write_record = NULL;
	rutoken_ops.append_record = NULL;
	rutoken_ops.update_record = NULL;
	rutoken_ops.select_file = rutoken_select_file;
	rutoken_ops.get_response = NULL;
	rutoken_ops.get_challenge = rutoken_get_challenge;
	rutoken_ops.verify = rutoken_verify;
	rutoken_ops.logout = rutoken_logout;
	rutoken_ops.restore_security_env = rutoken_restore_security_env;
	rutoken_ops.set_security_env = rutoken_set_security_env;
	rutoken_ops.decipher = NULL;
	rutoken_ops.compute_signature = rutoken_compute_signature;
	rutoken_ops.change_reference_data = rutoken_change_reference_data;
	rutoken_ops.reset_retry_counter = rutoken_reset_retry_counter;
	rutoken_ops.create_file = rutoken_create_file;
	rutoken_ops.delete_file = rutoken_delete_file;
	rutoken_ops.list_files = rutoken_list_files;
	rutoken_ops.check_sw = rutoken_check_sw;
	rutoken_ops.card_ctl = rutoken_card_ctl;
	rutoken_ops.process_fci = rutoken_process_fci;
	rutoken_ops.construct_fci = rutoken_construct_fci;
	rutoken_ops.pin_cmd = NULL;

	return &rutoken_drv;
}

struct sc_card_driver * sc_get_rutoken_driver(void)
{
	return get_rutoken_driver();
}

