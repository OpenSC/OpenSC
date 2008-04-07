/*
 *  card-rutoken.c: Support for ruToken cards
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
#include "internal.h"
#include "cardctl.h"
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs15.h"
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif

#define BIG_ENDIAN_RUTOKEN

#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <opensc/asn1.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "rutoken.h"
#endif

#define FDESCR_DF           0x38    /*00111000b*/
#define FDESCR_EF           0x01

#define ID_RESERVED_CURDF   0x3FFF      /*Reserved ID for current DF*/

#ifdef BIG_ENDIAN_RUTOKEN
#define MF_PATH             "\x3F\x00"
#else
#define MF_PATH             "\x00\x3F"
#endif

struct auth_senv {
	unsigned int algorithm;
};
typedef struct auth_senv auth_senv_t;

static const sc_SecAttrV2_t default_sec_attr = {
	0x42,
	0, 1, 0, 0, 0, 0, 1,
	0, 2, 0, 0, 0, 0, 2
};

static const struct sc_card_operations *iso_ops = NULL;

static struct sc_card_operations rutoken_ops;

static struct sc_card_driver rutoken_drv = {
	"ruToken driver",
	"rutoken",
	&rutoken_ops,
	NULL, 0, NULL
};

static struct sc_atr_table rutoken_atrs[] = {
	{ "3b:6f:00:ff:00:56:72:75:54:6f:6b:6e:73:30:20:00:00:90:00", NULL, NULL, SC_CARD_TYPE_GENERIC_BASE, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

const char *hexdump(const void *data, size_t len)
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
	return 0;
}

static int rutoken_match_card(sc_card_t *card)
{
	int i;

	SC_FUNC_CALLED(card->ctx, 1);

	i = _sc_match_atr(card, rutoken_atrs, &card->type);
	if (i < 0)
		return 0;

	sc_debug(card->ctx, "atr recognized as ruToken\n");
	return 1;
}

static int rutoken_init(sc_card_t *card)
{
	int ret = SC_ERROR_MEMORY_FAILURE;
	unsigned int flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1;
				/* SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_SHA1
				| SC_ALGORITHM_RSA_HASH_MD5_SHA1
				| SC_ALGORITHM_RSA_PAD_NONE */
	sc_algorithm_info_t info;

	SC_FUNC_CALLED(card->ctx, 1);

	card->name = "rutoken card";
	card->drv_data = malloc(sizeof(auth_senv_t));
	card->caps |= SC_CARD_CAP_RSA_2048 | SC_CARD_CAP_NO_FCI | SC_CARD_CAP_RNG;
	if (card->drv_data)
	{
		memset(card->drv_data, 0, sizeof(auth_senv_t));
		ret = SC_NO_ERROR;
	}
	/* add algorithm 
	TODO: may nid som other flag  */

	_sc_card_add_rsa_alg(card, 256, flags, 0);
	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	flags = SC_ALGORITHM_GOST_CRYPT_PZ | SC_ALGORITHM_GOST_CRYPT_GAMM
		| SC_ALGORITHM_GOST_CRYPT_GAMMOS;
	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_GOST;
	info.flags = flags;
	info.key_length = 32;
	if (_sc_card_add_algorithm(card, &info) < 0)
	    return -1;
	return ret;
}

static const struct sc_card_error rutoken_errors[] = {

	{ 0x6300, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C1, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C2, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C3, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C4, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C5, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C6, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C7, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C8, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63C9, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Ca, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Cb, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Cc, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Cd, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Ce, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 
	{ 0x63Cf, SC_ERROR_PIN_CODE_INCORRECT,"authentication failed"}, 

	{ 0x6400, SC_ERROR_CARD_CMD_FAILED,"Aborting"}, 

	{ 0x6500, SC_ERROR_MEMORY_FAILURE,	"Memory failure"}, 
	{ 0x6581, SC_ERROR_MEMORY_FAILURE,	"Memory failure"}, 

	{ 0x6700, SC_ERROR_WRONG_LENGTH,	"Lc or Le invalid"}, 

	{ 0x6883, SC_ERROR_CARD_CMD_FAILED,	"The finishing command of a chain is expected"}, 

	{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"required access right not granted"}, 
	{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED,	"bs object blocked"}, 
	{ 0x6985, SC_ERROR_CARD_CMD_FAILED,	"command not allowed (unsuitable conditions)"}, 
	{ 0x6986, SC_ERROR_INCORRECT_PARAMETERS,"no current ef selected"}, 

	{ 0x6a80, SC_ERROR_INCORRECT_PARAMETERS,"invalid parameters in data field"}, 
	{ 0x6a81, SC_ERROR_NOT_SUPPORTED,	"function/mode not supported"}, 
	{ 0x6a82, SC_ERROR_FILE_NOT_FOUND,	"file (DO) not found"}, 
	{ 0x6a84, SC_ERROR_CARD_CMD_FAILED,	"not enough memory"}, 
	{ 0x6a86, SC_ERROR_INCORRECT_PARAMETERS,"p1/p2 invalid"}, 
	{ 0x6a89, SC_ERROR_FILE_ALREADY_EXISTS,"file (DO) already exists"}, 

	{ 0x6b00, SC_ERROR_INCORRECT_PARAMETERS,"Out of file length"}, 

	{ 0x6c00, SC_ERROR_WRONG_LENGTH,	"le does not fit the data to be sent"}, 

	{ 0x6d00, SC_ERROR_INS_NOT_SUPPORTED,	"ins invalid (not supported)"}, 

	/* Own class of an error*/
	{ 0x6f01, SC_ERROR_CARD_CMD_FAILED,	"ruToken has the exchange protocol which is not supported by the USB-driver (newer, than in the driver)"},
	{ 0x6f83, SC_ERROR_CARD_CMD_FAILED,	"Infringement of the exchange protocol with ruToken is revealed"},
	{ 0x6f84, SC_ERROR_CARD_CMD_FAILED,	"ruToken is busy by processing of other command"},
	{ 0x6f85, SC_ERROR_CARD_CMD_FAILED,	"In the current folder the maximum quantity of file system objects is already created."},
	{ 0x6f86, SC_ERROR_CARD_CMD_FAILED,	"The token works not with access rights 'Visitor'"},

	{ 0x9000, SC_NO_ERROR,		NULL}
};

int rutoken_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	const int err_count = sizeof(rutoken_errors)/sizeof(rutoken_errors[0]);
	int i;

	sc_debug(card->ctx, "sw1 = %x, sw2 = %x", sw1, sw2);
			        
	for (i = 0; i < err_count; i++) {
		if (rutoken_errors[i].SWs == ((sw1 << 8) | sw2)) {
			if ( rutoken_errors[i].errorstr )
				sc_debug(card->ctx, rutoken_errors[i].errorstr);
			/*SC_FUNC_RETURN(card->ctx, 1, rutoken_errors[i].errorno);*/
			return rutoken_errors[i].errorno;
		}
	}

        sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_CARD_CMD_FAILED);
}

static int rutoken_dir_up(sc_card_t *card)
{
    u8 rbuf[256];
    int r = 0;
    sc_apdu_t apdu;
    SC_FUNC_CALLED(card->ctx, 1);
	/*sc_debug(card->ctx, "\n\tpath = %s\n\ttype = %d", hexdump(path, pathlen), in_path->type);
    	prepare & transmit APDU
	00 a4 00 04 20 - first*/
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x03, 0x00);
    apdu.cla = 0x00;
    apdu.resplen = 256;
    apdu.resp = rbuf;
    apdu.le = 256;
    r = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, r, "APDU transmit failed");
    sc_debug(card->ctx, "rbuf = %s len %d", hexdump(apdu.resp, apdu.resplen), apdu.resplen);
    sc_debug(card->ctx, "sw1 = %x, sw2 = %x", apdu.sw1, apdu.sw2);
    return 0;
}

/* make little endian path from normal path.
   return 1 if right len, otherwise 0  */
static int make_le_path(u8 *hPath, size_t len)
{
#ifdef BIG_ENDIAN_RUTOKEN
	/*   we don't need it any more  */
	return 1;
#else
	int i, ret = (len > 1) && !(len & 1);  /*  && (len <= SC_MAX_PATH_SIZE);  */
	if (ret)
	{
		for(i = 0; i < len; i += 2)
		{
			u8 b = hPath[i];
			hPath[i] = hPath[i+1];
			hPath[i+1] =  b;
		}
	}
	return ret;
#endif
}

static int rutoken_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	u8 rbuf[256];
	u8 previd[2];
	int r = 0, len=0;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	/*  sc_debug(card->ctx, "\n\tpath = %s\n\ttype = %d", hexdump(path, pathlen), in_path->type);  */
	/*  prepare & transmit APDU  */
	/*   00 a4 00 04 20 - first  */
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x00, 0x00);
	apdu.cla = 0x00;
	apdu.resplen = 256;
	apdu.resp = rbuf;
	apdu.le = 256;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	sc_debug(card->ctx, "rbuf = %s len %d", hexdump(apdu.resp, apdu.resplen), apdu.resplen);
	sc_debug(card->ctx, "sw1 = %x, sw2 = %x", apdu.sw1, apdu.sw2);
	if((apdu.sw1 == 0x6a) )
	{
		/* empty dir  */
	    return 0;
	}
	/*  todo: add check buflen  */
	/*  save first file(dir) ID  */
	memcpy(buf+len, rbuf+6, 2);
	memcpy(previd, rbuf+6, 2);
	len += 2;
	if(rbuf[4] == FDESCR_DF)
	    rutoken_dir_up(card);
	
	/*  00 a4 00 02 02 prev id - next  */
	while(1)
	{
	    sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x06);
	    apdu.cla = 0x00;
	    apdu.lc = 2;
	    apdu.data = previd;
	    apdu.datalen = 2;
	    apdu.resplen = 256;
	    apdu.resp = rbuf;
	    apdu.le = 256;
	    r = sc_transmit_apdu(card, &apdu);
	    SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	    sc_debug(card->ctx, "rbuf = %s len %d", hexdump(apdu.resp, apdu.resplen), apdu.resplen);
	    sc_debug(card->ctx, "sw1 = %x, sw2 = %x", apdu.sw1, apdu.sw2);
	    if((apdu.sw1 == 0x6a) )
	    {
		    /*  end list  */
			break;
	    }
		/*  todo: add check buflen  */
	    /*  save first file(dir) ID  */
	    memcpy(buf+len, rbuf+6, 2);
	    memcpy(previd, rbuf+6, 2);
	    len += 2;
	    if(rbuf[4] == FDESCR_DF)
			rutoken_dir_up(card);
	}
	make_le_path(buf, len);
	return len;
}

static void rutoken_process_fcp(sc_card_t *card, u8 *pIn, sc_file_t *file)
{
#ifdef BIG_ENDIAN_RUTOKEN
	file->size = pIn[3] + ((uint16_t)pIn[2])*256;
	file->id = pIn[7] + ((uint16_t)pIn[6])*256;
#else
	file->size = pIn[2] + ((uint16_t)pIn[3])*256;
	file->id = pIn[6] + ((uint16_t)pIn[7])*256;
#endif

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
}

static int rutoken_select_file(sc_card_t *card,
			      const sc_path_t *in_path,
			      sc_file_t **file)
{
	int ret = SC_ERROR_INVALID_ARGUMENTS;
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int pathlen = in_path->len;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);

	memcpy(path, in_path->value, pathlen);

	sc_debug(card->ctx, "\n\tpath = %s\n\ttype = %d", hexdump(path, pathlen), in_path->type);
	/*	prepare & transmit APDU  */
	if (make_le_path(path, pathlen)) 
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
		
		switch (in_path->type)
		{
		case SC_PATH_TYPE_FILE_ID:
			if (pathlen == 2)	/*  select file in current df  */
			{
				apdu.p1 = 2;
				ret = SC_SUCCESS;
			}
			break;
		case SC_PATH_TYPE_PATH:
			apdu.p1 = 8;
			if (memcmp(path, MF_PATH, 2) == 0)
			{
				if (pathlen == 2) /* select MF  */
				{
					apdu.p1 = 0;
				} 
				else	/* select DF  */
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
	}
	if (ret == SC_SUCCESS)
	{
		ret = SC_ERROR_CARD_CMD_FAILED;
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
		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);

		sc_debug(card->ctx, "file = %x", file);
		if (file == NULL) 
		{
			/*  We don't need file info  */
			if (apdu.sw1 == 0x61) 
				SC_FUNC_RETURN(card->ctx, 2, SC_NO_ERROR);
			SC_FUNC_RETURN(card->ctx, 2, ret);
		}
	}
	/*  New file structure  */
	if ((ret == SC_SUCCESS) && (apdu.resplen == 32))
	{
		/*  sc_file_t *tmp_  */
		*file = sc_file_new();
		if (*file == NULL)
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
		(*file)->path = *in_path;  /*  what about selecting EF by ID (SC_PATH_TYPE_FILE_ID)?  */

		rutoken_process_fcp(card, buf, *file);
		/*  *file = tmp_file;  */

		sc_debug(card->ctx, 
			"nfile ID = %04X, path = %s, type = %02X, len = %d", 
			(*file)->id, hexdump((*file)->path.value, (*file)->path.len), 
			(*file)->type, (*file)->size);
		sc_debug(card->ctx, "sec attr = %s", 
			hexdump((*file)->sec_attr, (*file)->sec_attr_len));
	}
	SC_FUNC_RETURN(card->ctx, 2, ret);
}

/*
static int rutoken_set_file_attributes(sc_card_t *card, sc_file_t *file)
{
	int ret = SC_ERROR_NOT_SUPPORTED;
	return ret;
}
*/

static int rutoken_construct_fcp(sc_card_t *card, const sc_file_t *file, u8 *out)
{
	SC_FUNC_CALLED(card->ctx, 1);
	
	if ((!file) || (file->id == ID_RESERVED_CURDF)) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	memset(out, 0, 32);
	switch (file->type) 
	{
	case SC_FILE_TYPE_DF:
		out[4] = 0x38;
#ifdef BIG_ENDIAN_RUTOKEN
		out[0] = file->size / 256;
		out[1] = file->size % 256;
#else
		out[1] = file->size / 256;
		out[0] = file->size % 256;
#endif
		break;
	case SC_FILE_TYPE_WORKING_EF:
		out[4] = 0x01;
		/*   set the length (write to wBodyLen)  */
#ifdef BIG_ENDIAN_RUTOKEN
		out[2] = file->size / 256;
		out[3] = file->size % 256;
#else
		out[3] = file->size / 256;
		out[2] = file->size % 256;
#endif
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
	default:
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
	}
	/*   set file ID  */
#ifdef BIG_ENDIAN_RUTOKEN
	out[6] = file->id / 256;
	out[7] = file->id % 256;
#else
	out[7] = file->id / 256;
	out[6] = file->id % 256;
#endif
	/*  set sec_attr  */
	if(file->sec_attr_len == SEC_ATTR_SIZE)
		memcpy(out + 17, file->sec_attr, SEC_ATTR_SIZE);
	else
		memcpy(out + 17, &default_sec_attr, SEC_ATTR_SIZE);
	
	SC_FUNC_RETURN(card->ctx, 1, SC_NO_ERROR);
}

static int rutoken_create_file(sc_card_t *card, sc_file_t *file)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;
	u8 sbuf[32];
	SC_FUNC_CALLED(card->ctx, 1);
	memset(sbuf, 0, 32);
	if((ret = rutoken_construct_fcp(card, file, sbuf)) == SC_NO_ERROR)
	{
		sc_debug(card->ctx, "fcp = %s", hexdump(sbuf, 32));
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
		apdu.data = sbuf;
		apdu.datalen = 32;
		apdu.lc = 32;

		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
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
	if (path->len == 2) 
	{
#ifdef BIG_ENDIAN_RUTOKEN
		sbuf[0] = path->value[0];
		sbuf[1] = path->value[1];
#else
		sbuf[0] = path->value[1];
		sbuf[1] = path->value[0];
#endif
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
		apdu.lc = 2;
		apdu.datalen = 2;
		apdu.data = sbuf;
	}
	else /* No file ID given: means currently selected file */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	
	SC_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	SC_FUNC_RETURN(card->ctx, 1, rutoken_check_sw(card, apdu.sw1, apdu.sw2));
}

static int rutoken_verify(sc_card_t *card, unsigned int type, int ref_qualifier,
			const u8 *data, size_t data_len, int *tries_left)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, ref_qualifier);
	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.data = data;
	if(sc_transmit_apdu(card, &apdu) >= 0)
	{
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		if(ret == SC_ERROR_PIN_CODE_INCORRECT  &&  tries_left)
		{
			sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00,
					ref_qualifier);
			ret = sc_transmit_apdu(card, &apdu);
			if(ret >= 0)
			{
				ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
				if(ret == SC_ERROR_PIN_CODE_INCORRECT)
					*tries_left = (int)(apdu.sw2 & 0x0f);
			}
		}
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_path_t path;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_path("3F00", &path);
	if (rutoken_select_file(card, &path, NULL) == SC_SUCCESS)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x40, 0x00, 0x00);
		apdu.cla = 0x80;
		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_change_reference_data(sc_card_t *card, unsigned int type,
			int ref_qualifier, const u8 *old, size_t oldlen,
			const u8 *newref, size_t newlen, int *tries_left)
{
	int left;
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	
	if(old && oldlen)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, ref_qualifier);
		if(sc_transmit_apdu(card, &apdu) >= 0
				&&  apdu.sw1 != 0x90  &&  apdu.sw2 != 0x00)
		{
			rutoken_logout(card);
			rutoken_verify(card, type, ref_qualifier, old, oldlen, &left);
		}
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, ref_qualifier);
	apdu.lc = newlen;
	apdu.datalen = newlen;
	apdu.data = newref;
	if(sc_transmit_apdu(card, &apdu) >= 0)
	{
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		if(ret == SC_ERROR_PIN_CODE_INCORRECT  &&  tries_left)
			*tries_left = (int)(apdu.sw2 & 0x0f);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_reset_retry_counter(sc_card_t *card, unsigned int type,
			int ref_qualifier, const u8 *puk, size_t puklen,
			const u8 *newref, size_t newlen)
{
#ifdef FORCE_VERIFY_RUTOKEN
	int left;
#endif
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
#ifdef FORCE_VERIFY_RUTOKEN
	if(puk && puklen)
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, ref_qualifier);
		if(sc_transmit_apdu(card, &apdu) >= 0
				&&  apdu.sw1 != 0x90  &&  apdu.sw2 != 0x00)
		{
			rutoken_logout(card);
			rutoken_verify(card, type, ref_qualifier, puk, puklen, &left);
		}
	}
#endif
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2c, 0x03, ref_qualifier);
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_restore_security_env(sc_card_t *card, int se_num)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 3, se_num);
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_set_security_env(sc_card_t *card, 
			 const sc_security_env_t *env,
			 int se_num)
{
	sc_apdu_t apdu;
	auth_senv_t *senv = (auth_senv_t*)card->drv_data;
	u8	data[3] = {0x83, 0x01, env->key_ref[0]};
	int ret = SC_NO_ERROR;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!senv || !env) return SC_ERROR_INVALID_ARGUMENTS;
	if(env->algorithm == SC_ALGORITHM_RSA)
	{
		senv->algorithm = SC_ALGORITHM_RSA_RAW;
		return ret;
	}
	else
		senv->algorithm = SC_ALGORITHM_GOST;

	if (env->key_ref_len != 1)
	{
		sc_error(card->ctx, "No or invalid key reference\n");
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	/*  select component  */
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 1, 0);
		apdu.lc = apdu.datalen = 3;
		apdu.data = data;
		switch (env->operation) 
		{
			case SC_SEC_OPERATION_AUTHENTICATE:
			{
				apdu.p2 = 0xA4;
			}
			break;
			case SC_SEC_OPERATION_DECIPHER:
			{
				apdu.p2 = 0xB8;
			}
			break;
			case SC_SEC_OPERATION_SIGN:
			{
				apdu.p2 = 0xAA;
			}
			break;
			default:
				ret = SC_ERROR_INVALID_ARGUMENTS;
		}
	}
	/*  set SE  */
	if (ret == SC_NO_ERROR)
	{
		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static void rutoken_set_do_hdr(u8 *data, sc_DOHdrV2_t *pHdr)
{
	if(data)
	{
#ifdef BIG_ENDIAN_RUTOKEN
		data[0] = (u8)(pHdr->wDOBodyLen / 0x100);
		data[1] = (u8)(pHdr->wDOBodyLen % 0x100);
#else
		data[0] = (u8)(pHdr->wDOBodyLen % 0x100);
		data[1] = (u8)(pHdr->wDOBodyLen / 0x100);
#endif
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
	int ret = SC_ERROR_CARD_CMD_FAILED;
	u8 data[SC_RUTOKEN_DO_HDR_LEN];
	sc_apdu_t	apdu;
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
		apdu.data= data;
		apdu.datalen = apdu.lc = sizeof(data);

		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_create_do(sc_card_t *card, sc_DO_V2_t * pDO)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	u8 data[SC_RUTOKEN_DO_HDR_LEN + SC_RUTOKEN_DO_PART_BODY_LEN];
	sc_apdu_t	apdu;
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
		apdu.data= data;
		apdu.datalen = apdu.lc = SC_RUTOKEN_DO_HDR_LEN + pDO->HDR.wDOBodyLen;

		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_get_do_info(sc_card_t *card, sc_DO_INFO_t * pInfo)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	u8 data[1] = {pInfo->DoId};
	sc_apdu_t	apdu;

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
		case select_by_id:
			apdu.data = data;
			apdu.datalen = apdu.lc = 1;
			break;
		case select_next:
			apdu.p2  = 0x02;
			apdu.data = data;
			apdu.datalen = apdu.lc = 1;
			break;
		default:
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
			break;
		}
		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	return ret;
}

static int rutoken_delete_do(sc_card_t *card, u8 *pId)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	u8 data[1] = {*pId};
	sc_apdu_t	apdu;
	
	if ((*pId < SC_RUTOKEN_DO_ALL_MIN_ID) || 
	    (*pId > SC_RUTOKEN_DO_NOCHV_MAX_ID_V2))
	{
		ret = SC_ERROR_INVALID_ARGUMENTS;
	}
	else
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x64);
		apdu.data = data;
		apdu.datalen = apdu.lc = 1;
		if(sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_get_serial(sc_card_t *card, sc_serial_number_t *pSerial)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t	apdu;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x81);
	apdu.resp = pSerial->value;
	apdu.le = 4;
	apdu.resplen = sizeof(pSerial->value);
	
	if(sc_transmit_apdu(card, &apdu) >= 0)
	{
		pSerial->len = apdu.le;
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

/*  Both direction GOST cipher  */

static int rutoken_cipher_p(sc_card_t *card, const u8 * crgram, size_t crgram_len,
                   u8 * out, size_t outlen, int p1, int p2, int isIV)
{
	const size_t cipher_chunk = 248;  /* cipher_chunk <= SC_MAX_APDU_BUFFER_SIZE  */
	size_t len, outlen_tail = outlen;
	u8 *buf;
	int ret;
	sc_apdu_t apdu;
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, ": crgram_len %i; outlen %i\n", crgram_len, outlen);

	if (!out)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (crgram_len < 16 || ((crgram_len) % 8))
		return SC_ERROR_WRONG_LENGTH;

	buf = malloc(cipher_chunk);
	if (!buf)
		return SC_ERROR_OUT_OF_MEMORY;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, p1, p2);
	do
	{
		len = (crgram_len > cipher_chunk) ? cipher_chunk : crgram_len;
		apdu.lc = len;
		apdu.datalen = len;
		apdu.data = crgram;
		crgram += len;
		crgram_len -= len;

		apdu.cla = (crgram_len == 0) ? 0x00 : 0x10;
		apdu.le = len;
		apdu.resplen = len;
		apdu.resp = buf;
	
		if (sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		else
			ret = SC_ERROR_CARD_CMD_FAILED;
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
	
	free(buf);
	
	sc_debug(card->ctx, "len out cipher %d\n", outlen - outlen_tail);
	if (ret == SC_NO_ERROR)
		ret = (outlen_tail == 0) ? (int)outlen : SC_ERROR_WRONG_LENGTH;

	SC_FUNC_RETURN(card->ctx, 1, ret);
}

/*  Launcher for chipher  */

static int rutoken_cipher_gost(sc_card_t *card, 
		struct sc_rutoken_decipherinfo *ptr, char is_enchiper)
{
	int ret;

	if (is_enchiper)
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

	SC_FUNC_CALLED(card->ctx, 1);

	if (!in || !out || olen != 4 || ilen == 0)
		return SC_ERROR_INVALID_ARGUMENTS;
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
		if (sc_transmit_apdu(card, &apdu) >= 0)
			ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		else
			ret = SC_ERROR_CARD_CMD_FAILED;
	} while (ret == SC_NO_ERROR  &&  ilen != 0);
	
	SC_FUNC_RETURN(card->ctx, 1, ret);
}
	
/*  RSA emulation  */

#ifdef ENABLE_OPENSSL

static int rutoken_get_current_fileid(sc_card_t *card, u8 id[2])
{
	sc_apdu_t apdu;
	int ret = SC_ERROR_CARD_CMD_FAILED;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x11);
	apdu.resp = id;
	apdu.resplen = sizeof(id);
	apdu.le = 2;
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_read_prkey(sc_card_t *card, struct sc_pkcs15_prkey **out)
{
	int r;
	u8 id[2];
	u8 *data;
	sc_path_t path;
	sc_file_t *file = NULL;
	
	r = sc_lock(card);
	if(r != SC_SUCCESS)
		return r;

	r = rutoken_get_current_fileid(card, id);
	if(r == SC_SUCCESS)
	{
		sc_path_set(&path, SC_PATH_TYPE_FILE_ID, id, sizeof(id), 0, -1);
		r = rutoken_select_file(card, &path, &file);
	}
	if(r == SC_SUCCESS  &&  file)
	{
		data = malloc(file->size);
		if(data == NULL)
			r = SC_ERROR_OUT_OF_MEMORY;
		else
		{
			r = sc_read_binary(card, 0, data, file->size, 0);
			if(r > 0  &&  (size_t)r == file->size)
				r = sc_rutoken_get_prkey_from_bin(data, file->size, out);
			memset(data, 0, file->size);
			free(data);
		}
	}
	if(file)
		sc_file_free(file);
	sc_unlock(card);
	return r;
}

#define GETBN(bn)	((bn)->len? BN_bin2bn((bn)->data, (bn)->len, NULL) : NULL)

static int extract_key(sc_card_t *card, EVP_PKEY **pk)
{
	struct sc_pkcs15_prkey	*key = NULL;
	int		r;

	SC_FUNC_CALLED(card->ctx, 1);

	r = rutoken_read_prkey(card, &key);

	if (r < 0)
		return r;

	if((*pk = EVP_PKEY_new()) == NULL)
		r = SC_ERROR_OUT_OF_MEMORY;
	else
	{
		switch (key->algorithm) 
		{
		case SC_ALGORITHM_RSA:
		{
			RSA	*rsa = RSA_new();
			
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
	if(key) sc_pkcs15_free_prkey(key);
	return r;
}

static int sign_ext(sc_card_t *card, const u8 *data, size_t len, u8 *out, size_t out_len)
{
	EVP_PKEY *pkey = NULL;
	int ret, r;

	SC_FUNC_CALLED(card->ctx, 1);

	if (out_len < len)
		return SC_ERROR_INVALID_ARGUMENTS;

	ret = extract_key(card, &pkey);
	if (ret == SC_SUCCESS)
	{
		r = RSA_private_encrypt(len, data, out, pkey->pkey.rsa, RSA_PKCS1_PADDING);
		if ( r < 0)
			{
				char error[1024];

				ret = SC_ERROR_INTERNAL;
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), error);
				sc_error(card->ctx, error);
				ERR_free_strings();
			}
	}
	if(pkey)
		EVP_PKEY_free(pkey);
	return ret;
}

static int decipher_ext(sc_card_t *card, const u8 *data, size_t len, u8 *out, size_t out_len)
{
	EVP_PKEY *pkey = NULL;
	int ret;
	
	SC_FUNC_CALLED(card->ctx, 1);

	if (out_len < len)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	ret = extract_key(card, &pkey);
	if (ret == SC_SUCCESS)
	{
		ret = RSA_private_decrypt(len, data, out, pkey->pkey.rsa, RSA_PKCS1_PADDING);
		if ( ret < 0)
			{
			char error[1024];

			ret = SC_ERROR_INTERNAL;
			ERR_load_crypto_strings();
			ERR_error_string(ERR_get_error(), error);
			sc_error(card->ctx, error);
			ERR_free_strings();
		}
	}
	if(pkey)
		EVP_PKEY_free(pkey);
	return ret;
}

static int rutoken_decipher(sc_card_t *card, 
			const u8 * data, size_t datalen, 
			u8 * out, size_t outlen)
{
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;

	SC_FUNC_CALLED(card->ctx, 1);

	if (!senv)
		return SC_ERROR_INTERNAL;

	if(senv->algorithm == SC_ALGORITHM_GOST) 
	{
		return rutoken_cipher_p(card, data, datalen, out, outlen, 0x80, 0x86, 1);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		return decipher_ext(card, data, datalen, out, outlen);
	}
	else
		return SC_ERROR_NOT_SUPPORTED;
}

static int rutoken_compute_signature(struct sc_card *card, 
			const u8 * data, size_t datalen, 
			u8 * out, size_t outlen)
{
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;
	
	SC_FUNC_CALLED(card->ctx, 1);

	if (!senv)
		return SC_ERROR_INTERNAL;

	if (senv->algorithm == SC_ALGORITHM_GOST) 
	{
		return rutoken_compute_mac_gost(card, data, datalen, out, outlen);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		return sign_ext(card, data, datalen, out, outlen);
	}
	else
	return SC_ERROR_NOT_SUPPORTED;
}
#endif

static int rutoken_get_challenge(sc_card_t *card, u8 *rnd, size_t count)
{
	int ret = SC_NO_ERROR;
	sc_apdu_t apdu;
	u8 rbuf[32];
	size_t n;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x84, 0x00, 0x00);
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	while (count > 0)
	{
		ret = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, ret, "APDU transmit failed");
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret != SC_SUCCESS)
			break;
		if (apdu.resplen != sizeof(rbuf))
		{
			ret = SC_ERROR_UNKNOWN;
			break;
		}
		n = count < sizeof(rbuf) ? count : sizeof(rbuf);
		memcpy(rnd, rbuf, n);
		count -= n;
		rnd += n;
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_get_info(sc_card_t *card, void *buff)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r = SC_ERROR_CARD_CMD_FAILED;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0x89);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;
	if(sc_transmit_apdu(card, &apdu) >= 0)
	{
		memcpy(buff, apdu.resp, apdu.resplen);
		r = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int rutoken_format(sc_card_t *card, int apdu_ins)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, apdu_ins, 0x00, 0x00);
	apdu.cla = 0x80;
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);

	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int ret = (ptr != NULL
			/*|| cmd == SC_CARDCTL_ERASE_CARD */
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_INIT
			|| cmd == SC_CARDCTL_RUTOKEN_FORMAT_END
		) ? SC_NO_ERROR : SC_ERROR_INVALID_ARGUMENTS;

	SC_FUNC_CALLED(card->ctx, 1);
	
	if(ret == SC_NO_ERROR)
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
		}
	}
	return ret;
}

static struct sc_card_driver * sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;
	rutoken_ops = *iso_ops;

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
	rutoken_ops.logout  = rutoken_logout;
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
	return sc_get_driver();
}

