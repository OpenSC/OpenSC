/*
 *  card-rutoken.c: Support for Rutoken cards
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef __int8 int8_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "opensc.h"
#include "pkcs15.h"
#include "internal.h"
#include "cardctl.h"

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <opensc/asn1.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#endif

#define FDESCR_DF           0x38 /*00111000b*/
#define FDESCR_EF           0x01
#define ID_RESERVED_CURDF   0x3FFF /*Reserved ID for current DF*/

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
	0, 2, 0, 0, 0, 0, 2
};

static struct sc_card_operations rutoken_ops;

static struct sc_card_driver rutoken_drv = {
	"Rutoken driver",
	"rutoken",
	&rutoken_ops,
	NULL, 0, NULL
};

static struct sc_atr_table rutoken_atrs[] = {
	{ "3b:6f:00:ff:00:56:72:75:54:6f:6b:6e:73:30:20:00:00:90:00", NULL, NULL, SC_CARD_TYPE_GENERIC_BASE, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static const char *hexdump(const void *data, size_t len)
{
	static char string[1024];
	unsigned char *d = (unsigned char *)data;
	unsigned int i, left;

	string[0] = '\0';
	left = sizeof(string);
	for (i = 0; len--; i += 3) {
		if (i >= sizeof(string) - 4)
			break;
		snprintf(string + i, 4, " %02x", *d++);
	}
	return string;
}

static int rutoken_finish(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, 1);
	free(card->drv_data);
	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

static int rutoken_match_card(sc_card_t *card)
{
	SC_FUNC_CALLED(card->ctx, 1);
	if (_sc_match_atr(card, rutoken_atrs, &card->type) >= 0)
	{
		sc_debug(card->ctx, "ATR recognized as Rutoken\n");
		SC_FUNC_RETURN(card->ctx, 1, 1);
	}
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

static int token_init(sc_card_t *card, const char *card_name)
{
	unsigned int flags;

	SC_FUNC_CALLED(card->ctx, 3);

	card->name = card_name;
	card->caps |= SC_CARD_CAP_RSA_2048 | SC_CARD_CAP_NO_FCI | SC_CARD_CAP_RNG;
	card->drv_data = calloc(1, sizeof(auth_senv_t));
	if (card->drv_data == NULL)
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_OUT_OF_MEMORY);

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1;
	_sc_card_add_rsa_alg(card, 256, flags, 0);
	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	SC_FUNC_RETURN(card->ctx, 3, SC_SUCCESS);
}

static int rutoken_init(sc_card_t *card)
{
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
	ret = token_init(card, "Rutoken card");
	SC_FUNC_RETURN(card->ctx, 1, ret);
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

	{ 0x9000, SC_NO_ERROR,                  NULL}
};

static int rutoken_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	size_t i;

	for (i = 0; i < sizeof(rutoken_errors)/sizeof(rutoken_errors[0]); ++i) {
		if (rutoken_errors[i].SWs == ((sw1 << 8) | sw2)) {
			if ( rutoken_errors[i].errorstr )
				sc_error(card->ctx, "%s\n", rutoken_errors[i].errorstr);
			sc_debug(card->ctx, "sw1 = %x, sw2 = %x", sw1, sw2);
			return rutoken_errors[i].errorno;
		}
	}
	sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

static int rutoken_dir_up(sc_card_t *card)
{
	u8 rbuf[256];
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x03, 0x00);
	apdu.cla = 0x00;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.le = sizeof(rbuf);

	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	u8 rbuf[256];
	u8 previd[2];
	sc_apdu_t apdu;
	size_t len = 0;
	int ret, first = 1;

	SC_FUNC_CALLED(card->ctx, 1);
	while (1)
	{
		if (first)
			sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x00, 0x00);
		else
		{
			/*  00 a4 00 02 02 prev id - next  */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x02);
			apdu.lc = sizeof(previd);
			apdu.data = previd;
			apdu.datalen = sizeof(previd);
		}
		apdu.cla = 0x00;
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;
		apdu.le = sizeof(rbuf);
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");

		if (apdu.sw1 == 0x6A  &&  apdu.sw2 == 0x82)
			break; /*  if (first) "end list" else "empty dir"  */

		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, ret, "Get list files failed");

		/*  save first file(dir) ID  */
		if (len + 2 <= buflen)
		{
			buf[len++] = rbuf[6];
			buf[len++] = rbuf[7];
		}
		memcpy(previd, rbuf+6, sizeof(previd));
		if (rbuf[4] == FDESCR_DF)
			rutoken_dir_up(card);
		first = 0;
	}
	SC_FUNC_RETURN(card->ctx, 1, len);
}

static void rutoken_process_fcp(sc_card_t *card, u8 *pIn, sc_file_t *file)
{
	file->size = pIn[3] + ((uint16_t)pIn[2])*256;
	file->id = pIn[7] + ((uint16_t)pIn[6])*256;

	if (pIn[4] == FDESCR_DF)
	{
		file->type = SC_FILE_TYPE_DF;
	}
	else
	{
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
	}
	sc_file_set_sec_attr(file, pIn + 17, SEC_ATTR_SIZE);

	if (file->sec_attr  &&  file->sec_attr_len == SEC_ATTR_SIZE)
	{
		sc_file_add_acl_entry(file, SC_AC_OP_SELECT,
				SC_AC_NONE, SC_AC_KEY_REF_NONE);
		if (file->sec_attr[0] & 0x40) /* if AccessMode.6 */
		{
			sc_debug(card->ctx, "SC_AC_OP_DELETE %i %i",
					(int)(*(int8_t*)&file->sec_attr[1 +6]),
					file->sec_attr[1+7 +6]);
			sc_file_add_acl_entry(file, SC_AC_OP_DELETE,
					(int)(*(int8_t*)&file->sec_attr[1 +6]),
					file->sec_attr[1+7 +6]);
		}
		if (file->sec_attr[0] & 0x01) /* if AccessMode.0 */
		{
			sc_debug(card->ctx, (file->type == SC_FILE_TYPE_DF) ?
					"SC_AC_OP_CREATE %i %i" : "SC_AC_OP_READ %i %i",
					(int)(*(int8_t*)&file->sec_attr[1 +0]),
					file->sec_attr[1+7 +0]);
			sc_file_add_acl_entry(file,
					(file->type == SC_FILE_TYPE_DF) ?
					SC_AC_OP_CREATE : SC_AC_OP_READ,
					(int)(*(int8_t*)&file->sec_attr[1 +0]),
					file->sec_attr[1+7 +0]);
		}
		if (file->type == SC_FILE_TYPE_DF)
		{
			sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES,
					SC_AC_NONE, SC_AC_KEY_REF_NONE);
		}
		else
			if (file->sec_attr[0] & 0x02) /* if AccessMode.1 */
			{
				sc_debug(card->ctx, "SC_AC_OP_UPDATE %i %i",
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1]);
				sc_file_add_acl_entry(file, SC_AC_OP_UPDATE,
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1]);
				sc_debug(card->ctx, "SC_AC_OP_WRITE %i %i",
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1]);
				sc_file_add_acl_entry(file, SC_AC_OP_WRITE,
						(int)(*(int8_t*)&file->sec_attr[1 +1]),
						file->sec_attr[1+7 +1]);
			}
	}
}

static int rutoken_select_file(sc_card_t *card,
			const sc_path_t *in_path, sc_file_t **file)
{
	int ret;
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int pathlen;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!in_path || in_path->len < 2)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	pathlen = in_path->len;
	memcpy(path, in_path->value, pathlen);

	sc_debug(card->ctx, "\n\tpath = %s\n\ttype = %d",
			hexdump(path, pathlen), in_path->type);

	ret = SC_ERROR_INVALID_ARGUMENTS;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	switch (in_path->type)
	{
	case SC_PATH_TYPE_FILE_ID:
		if (pathlen == 2) /*  select file in current df  */
		{
			apdu.p1 = 2;
			ret = SC_SUCCESS;
		}
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 8;
		if (path[0] == 0x3F  && path[1] == 0x00)
		{
			if (pathlen == 2) /* select MF  */
			{
				apdu.p1 = 0;
			} 
			else /* select DF  */
			{
				path += 2;
				pathlen -= 2;
			}
		}
		ret = SC_SUCCESS;
		break;
	default:
		ret = SC_ERROR_NOT_SUPPORTED;
		break;
	}
	if (ret == SC_SUCCESS)
	{
		apdu.lc = pathlen;
		apdu.data = path;
		apdu.datalen = pathlen;

		if (file != NULL) {
			apdu.resp = buf;
			apdu.resplen = sizeof(buf);
			apdu.le = 256;
		} else {
			apdu.resplen = 0;
			apdu.le = 0;
			apdu.cse = SC_APDU_CASE_3_SHORT;
		}
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);

		if (file == NULL)
		{
			/*  We don't need file info  */
			if (apdu.sw1 == 0x61)
				SC_FUNC_RETURN(card->ctx, 2, SC_NO_ERROR);
			SC_FUNC_RETURN(card->ctx, 1, ret);
		}
		/*  New file structure  */
		if ((ret == SC_SUCCESS) && (apdu.resplen == 32))
		{
			*file = sc_file_new();
			if (*file == NULL)
				SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
			(*file)->path = *in_path;
			/*  what about selecting EF by ID (SC_PATH_TYPE_FILE_ID)?  */

			rutoken_process_fcp(card, buf, *file);

			sc_debug(card->ctx, 
				"nfile ID = %04X, path = %s, type = %02X, len = %d", 
				(*file)->id, hexdump((*file)->path.value, (*file)->path.len), 
				(*file)->type, (*file)->size);
			sc_debug(card->ctx, "sec attr = %s", 
				hexdump((*file)->sec_attr, (*file)->sec_attr_len));
		}
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_construct_fcp(sc_card_t *card, const sc_file_t *file, u8 *out)
{
	SC_FUNC_CALLED(card->ctx, 3);

	if ((!file) || (file->id == ID_RESERVED_CURDF)) 
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_INVALID_ARGUMENTS);
	memset(out, 0, 32);
	switch (file->type) 
	{
	case SC_FILE_TYPE_DF:
		out[4] = 0x38;
		out[0] = file->size / 256;
		out[1] = file->size % 256;
		break;
	case SC_FILE_TYPE_WORKING_EF:
		out[4] = 0x01;
		/*   set the length (write to wBodyLen)  */
		out[2] = file->size / 256;
		out[3] = file->size % 256;
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
	default:
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_NOT_SUPPORTED);
	}
	/*   set file ID  */
	out[6] = file->id / 256;
	out[7] = file->id % 256;

	/*  set sec_attr  */
	if (file->sec_attr_len == SEC_ATTR_SIZE)
		memcpy(out + 17, file->sec_attr, SEC_ATTR_SIZE);
	else
	{
		sc_debug(card->ctx, "set default sec_attr");
		memcpy(out + 17, &default_sec_attr, SEC_ATTR_SIZE);
	}
	SC_FUNC_RETURN(card->ctx, 3, SC_NO_ERROR);
}

static int set_sec_attr_from_acl(sc_card_t *card, sc_file_t *file)
{
	const helper_acl_to_sec_attr_t *conv_attr;
	size_t i, n_conv_attr;
	const sc_acl_entry_t *entry;
	sc_SecAttrV2_t attr = { 0 };
	int ret = SC_NO_ERROR;

	SC_FUNC_CALLED(card->ctx, 3);

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
	sc_debug(card->ctx, "file->type = %i", file->type);

	for (i = 0; i < n_conv_attr; ++i)
	{
		entry = sc_file_get_acl_entry(file, conv_attr[i].ac_op);
		if (entry  &&  (entry->method == SC_AC_CHV || entry->method == SC_AC_NONE
				|| entry->method == SC_AC_NEVER)
		)
		{
			/* AccessMode.[conv_attr[i].sec_attr_pos] */
			attr[0] |= 1 << conv_attr[i].sec_attr_pos;
			sc_debug(card->ctx, "AccessMode.%u, attr[0]=0x%x",
					conv_attr[i].sec_attr_pos, attr[0]);
			attr[1 + conv_attr[i].sec_attr_pos] = (u8)entry->method;
			sc_debug(card->ctx, "method %u", (u8)entry->method);
			if (entry->method == SC_AC_CHV)
			{
				attr[1+7 + conv_attr[i].sec_attr_pos] = (u8)entry->key_ref;
				sc_debug(card->ctx, "key_ref %u", (u8)entry->key_ref);
			}
		}
		else
		{
			sc_debug(card->ctx, "ACL (%u) not set", conv_attr[i].ac_op);
			ret = 1;
			break;
		}
	}
	if (ret != 1)
		ret = sc_file_set_sec_attr(file, attr, sizeof(attr));
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_create_file(sc_card_t *card, sc_file_t *file)
{
	int ret;
	sc_apdu_t apdu;
	u8 sbuf[32] = { 0 };

	SC_FUNC_CALLED(card->ctx, 1);

	/* trying use acl if sec_attr and acl were set */
	ret = set_sec_attr_from_acl(card, file);
	if (ret >= 0) /* (ret == 1) - acl not set */
		/* use default sec_attr if sec_attr not set */
		ret = rutoken_construct_fcp(card, file, sbuf);

	if (ret == SC_NO_ERROR)
	{
		sc_debug(card->ctx, "fcp = %s", hexdump(sbuf, 32));
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
		apdu.data = sbuf;
		apdu.datalen = 32;
		apdu.lc = 32;

		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_delete_file(sc_card_t *card, const sc_path_t *path)
{
	u8 sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!path || path->type != SC_PATH_TYPE_FILE_ID || (path->len != 0 && path->len != 2)) 
	{
		sc_error(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	if (path->len == sizeof(sbuf)) 
	{
		sbuf[0] = path->value[0];
		sbuf[1] = path->value[1];
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
		apdu.lc = sizeof(sbuf);
		apdu.datalen = sizeof(sbuf);
		apdu.data = sbuf;
	}
	else /* No file ID given: means currently selected file */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	SC_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, 1, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int rutoken_verify(sc_card_t *card, unsigned int type, int ref_qualifier,
			const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
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
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, ret, "Reset access rights failed");
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, ref_qualifier);
	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (ret == SC_ERROR_PIN_CODE_INCORRECT  &&  tries_left)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, ref_qualifier);
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret == SC_ERROR_PIN_CODE_INCORRECT)
			*tries_left = (int)(apdu.sw2 & 0x0f);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	sc_path_t path;
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_path("3F00", &path);
	ret = rutoken_select_file(card, &path, NULL);
	SC_TEST_RET(card->ctx, ret, "Select MF failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x40, 0x00, 0x00);
	apdu.cla = 0x80;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_change_reference_data(sc_card_t *card, unsigned int type,
			int ref_qualifier, const u8 *old, size_t oldlen,
			const u8 *newref, size_t newlen, int *tries_left)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
	if (old && oldlen)
	{
		ret = rutoken_verify(card, type, ref_qualifier, old, oldlen, tries_left);
		SC_TEST_RET(card->ctx, ret, "Invalid 'old' pass");
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref_qualifier);
	apdu.lc = newlen;
	apdu.datalen = newlen;
	apdu.data = newref;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
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

	SC_FUNC_CALLED(card->ctx, 1);
#ifdef FORCE_VERIFY_RUTOKEN
	if (puk && puklen)
	{
		ret = rutoken_verify(card, type, ref_qualifier, puk, puklen, &left);
		sc_error(card->ctx, "Tries left: %i\n", left);
		SC_TEST_RET(card->ctx, ret, "Invalid 'puk' pass");
	}
#endif
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2c, 0x03, ref_qualifier);
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_restore_security_env(sc_card_t *card, int se_num)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 3, se_num);
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_set_security_env(sc_card_t *card, 
			const sc_security_env_t *env, 
			int se_num)
{
	sc_apdu_t apdu;
	auth_senv_t *senv;
	u8 data[3] = { 0x83, 0x01 };
	int ret;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!env)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	senv = (auth_senv_t*)card->drv_data;
	if (!senv)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	if (env->algorithm == SC_ALGORITHM_RSA)
	{
		senv->algorithm = SC_ALGORITHM_RSA_RAW;
		SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
	}

	senv->algorithm = SC_ALGORITHM_GOST;
	if (env->key_ref_len != 1)
	{
		sc_error(card->ctx, "No or invalid key reference\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
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
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	/*  set SE  */
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static void rutoken_set_do_hdr(u8 *data, sc_DOHdrV2_t *pHdr)
{
	if (data)
	{
		data[0] = (u8)(pHdr->wDOBodyLen / 0x100);
		data[1] = (u8)(pHdr->wDOBodyLen % 0x100);
		data[2] = (u8)(pHdr->OTID.byObjectType);
		data[3] = (u8)(pHdr->OTID.byObjectID);
		data[4] = (u8)(pHdr->OP.byObjectOptions);
		data[5] = (u8)(pHdr->OP.byObjectFlags);
		data[6] = (u8)(pHdr->OP.byObjectTry);
		memcpy(data + 7, pHdr->dwReserv1, 4);
		memcpy(data + 11, pHdr->abyReserv2, 6);
		memcpy(data + 17, pHdr->SA_V2, SEC_ATTR_SIZE);
	}
}

static int rutoken_key_gen(sc_card_t *card, sc_DOHdrV2_t *pHdr)
{
	u8 data[SC_RUTOKEN_DO_HDR_LEN];
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
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
		rutoken_set_do_hdr(data, pHdr);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x65);
		apdu.data = data;
		apdu.datalen = apdu.lc = sizeof(data);
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_create_do(sc_card_t *card, sc_DO_V2_t * pDO)
{
	u8 data[SC_RUTOKEN_DO_HDR_LEN + SC_RUTOKEN_DO_PART_BODY_LEN];
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
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
		rutoken_set_do_hdr(data, &pDO->HDR);
		memcpy(data + SC_RUTOKEN_DO_HDR_LEN, pDO->abyDOBody, pDO->HDR.wDOBodyLen);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x62);
		apdu.data = data;
		apdu.datalen = apdu.lc = SC_RUTOKEN_DO_HDR_LEN + pDO->HDR.wDOBodyLen;
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_get_do_info(sc_card_t *card, sc_DO_INFO_t * pInfo)
{
	u8 data[1];
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
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
			apdu.p2  = 0x02;
		case select_by_id:
			data[0] = pInfo->DoId;
			apdu.data = data;
			apdu.datalen = sizeof(data);
			apdu.lc = sizeof(data);
			break;
		default:
			SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_INVALID_ARGUMENTS);
			break;
		}
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_delete_do(sc_card_t *card, u8 *pId)
{
	u8 data[1];
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
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
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

/*  Both direction GOST cipher  */

static int rutoken_cipher_p(sc_card_t *card, const u8 * crgram, size_t crgram_len,
			u8 * out, size_t outlen, int p1, int p2, int isIV)
{
	u8 buf[248]; /* 248 (cipher_chunk) <= SC_MAX_APDU_BUFFER_SIZE  */
	size_t len, outlen_tail = outlen;
	int ret;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_debug(card->ctx, ": crgram_len %i; outlen %i", crgram_len, outlen);

	if (!out)
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_INVALID_ARGUMENTS);
	if (crgram_len < 16 || ((crgram_len) % 8))
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_WRONG_LENGTH);

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
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret == SC_NO_ERROR)
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
	} while (ret == SC_NO_ERROR  &&  crgram_len != 0);
	sc_debug(card->ctx, "len out cipher %d\n", outlen - outlen_tail);
	if (ret == SC_NO_ERROR)
		ret = (outlen_tail == 0) ? (int)outlen : SC_ERROR_WRONG_LENGTH;
	SC_FUNC_RETURN(card->ctx, 3, ret);
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

	SC_FUNC_CALLED(card->ctx, 3);
	if (!in || !out || olen != 4 || ilen == 0)
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_INVALID_ARGUMENTS);
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
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	} while (ret == SC_NO_ERROR  &&  ilen != 0);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

/*  RSA emulation  */

#ifdef ENABLE_OPENSSL

static int rutoken_get_prkey_from_bin(const u8 *data, size_t datalen,
			struct sc_pkcs15_prkey **key)
{
	uint32_t bitlen;
	size_t i, len;
	struct sc_pkcs15_prkey_rsa *key_rsa;

	if (!data  ||  !key  ||  *key != NULL)
		return -1;

	if (datalen < 14 + sizeof(uint32_t))
		return -1;

	/* Check header */
	if (    data[0] != 2 || data[1] != 1
	     || data[2] != 0x07 /* Type */
	     || data[3] != 0x02 /* Version */
	     /* aiKeyAlg */
	     || data[6] != 0 || data[7] != 0xA4 || data[8] != 0 || data[9] != 0
	     /* magic "RSA2" */
	     || data[10] != 0x52 || data[11] != 0x53
	     || data[12] != 0x41 || data[13] != 0x32
	)
		return -1;

	len = 14;
	/* bitlen */
	bitlen = 0;
	for (i = 0; i < sizeof(uint32_t); ++i)
		bitlen += (uint32_t)data[len++] << i*8;

	if (bitlen % 16)
		return -1;
	if (datalen - len  <  sizeof(uint32_t) + bitlen/8 * 2 + bitlen/16 * 5)
		return -1;

	*key = calloc(1, sizeof(struct sc_pkcs15_prkey));
	if (!*key)
		return -1;
	key_rsa = &(*key)->u.rsa;

	key_rsa->exponent.data = malloc(sizeof(uint32_t));
	key_rsa->modulus.data = malloc(bitlen/8);
	key_rsa->p.data = malloc(bitlen/16);
	key_rsa->q.data = malloc(bitlen/16);
	key_rsa->dmp1.data = malloc(bitlen/16);
	key_rsa->dmq1.data = malloc(bitlen/16);
	key_rsa->iqmp.data = malloc(bitlen/16);
	key_rsa->d.data = malloc(bitlen/8);
	if (!key_rsa->exponent.data || !key_rsa->modulus.data
			|| !key_rsa->p.data || !key_rsa->q.data
			|| !key_rsa->dmp1.data || !key_rsa->dmq1.data
			|| !key_rsa->iqmp.data || !key_rsa->d.data
	)
	{
		free(key_rsa->exponent.data);
		free(key_rsa->modulus.data);
		free(key_rsa->p.data);
		free(key_rsa->q.data);
		free(key_rsa->dmp1.data);
		free(key_rsa->dmq1.data);
		free(key_rsa->iqmp.data);
		free(key_rsa->d.data);
		memset(key_rsa, 0, sizeof(*key_rsa));

		free(*key);
		*key = NULL;
		return -1;
	}

#define MEMCPY_KEYRSA_REVERSE_DATA(NAME, size) /* set key_rsa->NAME.len */ \
	do { \
		for (i = 0; i < (size); ++i) \
			if (data[len + (size) - 1 - i] != 0) \
				break; \
		for (; i < (size); ++i) \
			key_rsa->NAME.data[key_rsa->NAME.len++] = data[len + (size) - 1 - i]; \
		len += (size); \
	} while (0)

	MEMCPY_KEYRSA_REVERSE_DATA(exponent, sizeof(uint32_t)); /* pubexp */
	MEMCPY_KEYRSA_REVERSE_DATA(modulus, bitlen/8); /* modulus */
	MEMCPY_KEYRSA_REVERSE_DATA(p, bitlen/16); /* prime1 */
	MEMCPY_KEYRSA_REVERSE_DATA(q, bitlen/16); /* prime2 */
	MEMCPY_KEYRSA_REVERSE_DATA(dmp1, bitlen/16); /* exponent1 */
	MEMCPY_KEYRSA_REVERSE_DATA(dmq1, bitlen/16); /* exponent2 */
	MEMCPY_KEYRSA_REVERSE_DATA(iqmp, bitlen/16); /* coefficient */
	MEMCPY_KEYRSA_REVERSE_DATA(d, bitlen/8); /* privateExponent */

	(*key)->algorithm = SC_ALGORITHM_RSA;
	return 0;
}

static int rutoken_get_current_fileid(sc_card_t *card, u8 id[2])
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x11);
	apdu.resp = id;
	apdu.resplen = sizeof(id);
	apdu.le = 2;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_read_prkey(sc_card_t *card, struct sc_pkcs15_prkey **out)
{
	int r;
	u8 id[2];
	u8 *data;
	sc_path_t path;
	sc_file_t *file = NULL;

	r = sc_lock(card);
	if (r != SC_SUCCESS)
		return r;

	r = rutoken_get_current_fileid(card, id);
	if (r == SC_SUCCESS)
	{
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, id, sizeof(id), 0, -1);
		r = rutoken_select_file(card, &path, &file);
	}
	if (r == SC_SUCCESS  &&  file)
	{
		data = malloc(file->size);
		if (data == NULL)
			r = SC_ERROR_OUT_OF_MEMORY;
		else
		{
			r = sc_read_binary(card, 0, data, file->size, 0);
			if (r > 0  &&  (size_t)r == file->size)
				r = rutoken_get_prkey_from_bin(data, file->size, out);
			memset(data, 0, file->size);
			free(data);
		}
	}
	if (file)
		sc_file_free(file);
	sc_unlock(card);
	return r;
}

#define GETBN(bn)	((bn)->len? BN_bin2bn((bn)->data, (bn)->len, NULL) : NULL)

static int extract_key(sc_card_t *card, EVP_PKEY **pk)
{
	struct sc_pkcs15_prkey *key = NULL;
	int r;

	SC_FUNC_CALLED(card->ctx, 3);

	r = rutoken_read_prkey(card, &key);
	if (r < 0)
		SC_FUNC_RETURN(card->ctx, 3, r);

	if ((*pk = EVP_PKEY_new()) == NULL)
		r = SC_ERROR_OUT_OF_MEMORY;
	else
	{
		switch (key->algorithm)
		{
		case SC_ALGORITHM_RSA:
		{
			RSA *rsa = RSA_new();
			EVP_PKEY_set1_RSA(*pk, rsa);
			rsa->n = GETBN(&key->u.rsa.modulus);
			rsa->e = GETBN(&key->u.rsa.exponent);
			rsa->d = GETBN(&key->u.rsa.d);
			rsa->p = GETBN(&key->u.rsa.p);
			rsa->q = GETBN(&key->u.rsa.q);
			if((rsa->n == NULL) || (rsa->e == NULL) || (rsa->d == NULL) || 
			   (rsa->p == NULL) || (rsa->q == NULL)) 
				r = SC_ERROR_INTERNAL;
			RSA_free(rsa);
			break;
		}
		default:
			r = SC_ERROR_NOT_SUPPORTED;
		}
	}
	if ((r < 0) && (*pk != NULL))
	{
		EVP_PKEY_free(*pk);
		*pk = NULL;
	}
	if (key) sc_pkcs15_free_prkey(key);
	SC_FUNC_RETURN(card->ctx, 3, r);
}

static int cipher_ext(sc_card_t *card, const u8 *data, size_t len,
			u8 *out, size_t out_len,
			int sign /* sign==1 -> Sidn; sign==0 -> decipher */)
{
	char error[1024];
	EVP_PKEY *pkey = NULL;
	int ret, r;

	SC_FUNC_CALLED(card->ctx, 3);
	if (out_len < len)
		SC_FUNC_RETURN(card->ctx, 3, SC_ERROR_INVALID_ARGUMENTS);

	ret = extract_key(card, &pkey);
	if (ret == SC_SUCCESS)
	{
		if (sign)
			r = RSA_PKCS1_SSLeay()->rsa_priv_enc(len, data, out,
					pkey->pkey.rsa, RSA_PKCS1_PADDING);
		else
		{
			r = RSA_PKCS1_SSLeay()->rsa_priv_dec(len, data, out,
					pkey->pkey.rsa, RSA_PKCS1_PADDING);
			ret = r;
		}
		if ( r < 0)
		{
			ret = SC_ERROR_INTERNAL;
			ERR_load_crypto_strings();
			ERR_error_string(ERR_get_error(), error);
			sc_error(card->ctx, error);
			ERR_free_strings();
		}
	}
	if (pkey)
		EVP_PKEY_free(pkey);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_decipher(sc_card_t *card, 
			const u8 * data, size_t datalen, 
			u8 * out, size_t outlen)
{
	int ret;
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;

	SC_FUNC_CALLED(card->ctx, 1);

	if (!senv)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);

	if (senv->algorithm == SC_ALGORITHM_GOST)
	{
		ret = rutoken_cipher_p(card, data, datalen, out, outlen, 0x80, 0x86, 1);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		/* decipher */
		ret = cipher_ext(card, data, datalen, out, outlen, 0);
	}
	else
		ret = SC_ERROR_NOT_SUPPORTED;
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_compute_signature(struct sc_card *card, 
			const u8 * data, size_t datalen, 
			u8 * out, size_t outlen)
{
	int ret;
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!senv)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);

	if (senv->algorithm == SC_ALGORITHM_GOST)
	{
		ret = rutoken_compute_mac_gost(card, data, datalen, out, outlen);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		/* sign */
		ret = cipher_ext(card, data, datalen, out, outlen, 1);
	}
	else
		ret = SC_ERROR_NOT_SUPPORTED;
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

#endif /* ENABLE_OPENSSL */

static int rutoken_get_challenge(sc_card_t *card, u8 *rnd, size_t count)
{
	sc_apdu_t apdu;
	u8 rbuf[32];
	size_t n;
	int ret = SC_ERROR_INVALID_ARGUMENTS; /* if count == 0 */

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0x00, 0x00);
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	while (count > 0)
	{
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, ret, "Get challenge failed");
		if (apdu.resplen != sizeof(rbuf))
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN);
		n = count < sizeof(rbuf) ? count : sizeof(rbuf);
		memcpy(rnd, rbuf, n);
		count -= n;
		rnd += n;
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_get_serial(sc_card_t *card, sc_serial_number_t *serial)
{
	sc_apdu_t apdu;
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x81);
	apdu.resp = serial->value;
	apdu.resplen = sizeof(serial->value);
	apdu.le = 4;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	serial->len = apdu.le;
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_get_info(sc_card_t *card, void *buff)
{
	sc_apdu_t apdu;
	u8 rbuf[8];
	int ret;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0x89);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	memcpy(buff, apdu.resp, apdu.resplen);
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_format(sc_card_t *card, int apdu_ins)
{
	int ret;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, apdu_ins, 0x00, 0x00);
	apdu.cla = 0x80;
	ret = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
	ret = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 3, ret);
}

static int rutoken_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int ret = (ptr != NULL
			/*|| cmd == SC_CARDCTL_ERASE_CARD */
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_INIT
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_END
		) ? SC_NO_ERROR : SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);

	if (ret == SC_NO_ERROR)
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
			sc_debug(card->ctx, "cmd = %d", cmd);
			ret = SC_ERROR_NOT_SUPPORTED;
			break;
		case SC_CARDCTL_LIFECYCLE_SET:
			sc_debug(card->ctx, "SC_CARDCTL_LIFECYCLE_SET not supported");
			sc_debug(card->ctx, "returning SC_ERROR_NOT_SUPPORTED");
			/* no call sc_error (SC_FUNC_RETURN) */
			return SC_ERROR_NOT_SUPPORTED;
		}
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static struct sc_card_driver* get_rutoken_driver(void)
{
	rutoken_ops = *sc_get_iso7816_driver()->ops;

	rutoken_ops.match_card = rutoken_match_card;
	rutoken_ops.init = rutoken_init;
	rutoken_ops.finish = rutoken_finish;
	rutoken_ops.check_sw = rutoken_check_sw;
	rutoken_ops.select_file = rutoken_select_file;
	rutoken_ops.create_file = rutoken_create_file;
	rutoken_ops.delete_file = rutoken_delete_file;
	rutoken_ops.list_files = rutoken_list_files;
	rutoken_ops.card_ctl = rutoken_card_ctl;
	rutoken_ops.get_challenge = rutoken_get_challenge;
#ifdef ENABLE_OPENSSL
	rutoken_ops.decipher = rutoken_decipher;
	rutoken_ops.compute_signature = rutoken_compute_signature;
#else
	rutoken_ops.decipher = NULL;
	rutoken_ops.compute_signature = NULL;
#endif
	rutoken_ops.set_security_env = rutoken_set_security_env;
	rutoken_ops.restore_security_env = rutoken_restore_security_env;
	rutoken_ops.verify = rutoken_verify;
	rutoken_ops.logout = rutoken_logout;
	rutoken_ops.change_reference_data = rutoken_change_reference_data;
	rutoken_ops.reset_retry_counter = rutoken_reset_retry_counter;
	rutoken_ops.pin_cmd = NULL;
	rutoken_ops.read_record = NULL;
	rutoken_ops.write_record = NULL;
	rutoken_ops.append_record = NULL;
	rutoken_ops.update_record = NULL;
	rutoken_ops.write_binary = NULL;
	return &rutoken_drv;
}

struct sc_card_driver * sc_get_rutoken_driver(void)
{
	return get_rutoken_driver();
}

