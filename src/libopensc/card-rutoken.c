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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "pkcs15.h"

#define BIG_ENDIAN_RUTOKEN

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <opensc/asn1.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#endif



#define FDESCR_DF           0x38    /*00111000b*/
#define FDESCR_EF           0x01

#define ID_RESERVED_CURDF   0x3FFF      /*Reserved ID for current DF*/

int get_prkey_from_bin(u8* data, int len, struct sc_pkcs15_prkey **key);

#ifdef BIG_ENDIAN_RUTOKEN
#define MF_PATH             "\x3F\x00"
#else
#define MF_PATH             "\x00\x3F"
#endif
struct auth_senv {
	unsigned int algorithm;
	int key_file_id;
	size_t key_size;
	unsigned int algorithm_flags;
	sc_path_t path;
};
typedef struct auth_senv auth_senv_t;

static const sc_SecAttrV2_t default_sec_attr = {
	0x40, 
	0, 0, 0, 0, 0, 0, 1,
	0, 0, 0, 0, 0, 0, 2
};

static const struct sc_card_operations *iso_ops = NULL;

struct sc_card_operations rutoken_ops;
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

static int make_le_path(u8 *hPath, size_t len);
static int rutoken_get_do_info(sc_card_t *card, sc_DO_INFO_t * pInfo);

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
#ifdef DEBUG
	/*  if(!card->ctx->debug) card->ctx->debug = 1;  */
#endif
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
	unsigned int flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1; /* SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_MD5_SHA1 | SC_ALGORITHM_RSA_PAD_NONE*/

	_sc_card_add_rsa_alg(card, 256, flags, 0);
	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	sc_algorithm_info_t info;
	flags = SC_ALGORITHM_GOST_CRYPT_PZ | SC_ALGORITHM_GOST_CRYPT_GAMM | SC_ALGORITHM_GOST_CRYPT_GAMMOS;
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
			if ( rutoken_errors[i].errorstr ) sc_debug(card->ctx, rutoken_errors[i].errorstr);
			/*SC_FUNC_RETURN(card->ctx, 1, rutoken_errors[i].errorno);*/
			return rutoken_errors[i].errorno;
		}
	}

        sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_CARD_CMD_FAILED);
}

int rutoken_dir_up(sc_card_t *card)
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


static int rutoken_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	SC_FUNC_CALLED(card->ctx, 1);
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
	while(1){
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

/*  make little endian path from normal path.
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

void rutoken_process_fcp(sc_card_t *card, u8 *pIn, sc_file_t *file)
{
#ifdef BIG_ENDIAN_RUTOKEN
	file->size = pIn[3] + ((u_int16_t)pIn[2])*256;
	file->id = pIn[7] + ((u_int16_t)pIn[6])*256;
#else
	file->size = pIn[2] + ((u_int16_t)pIn[3])*256;
	file->id = pIn[6] + ((u_int16_t)pIn[7])*256;
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

static int rutoken_construct_fcp(sc_card_t *card, const sc_file_t *file,
	u8 *out)
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
		/*  *((unsigned short int*)(out) + 1) = (unsigned short int)file->size; */
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
	/*  *((unsigned short int*)(out) + 3) = (unsigned short int)file->id;  */
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

static int rutoken_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_path_t path;

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

int rutoken_set_security_env(sc_card_t *card,
			 const sc_security_env_t *env,
			 int se_num)
{
	SC_FUNC_CALLED(card->ctx, 1);
	sc_apdu_t apdu;
	auth_senv_t *senv = (auth_senv_t*)card->drv_data;
	if (!senv || !env) return SC_ERROR_INVALID_ARGUMENTS;
	u8	data[3] = {0x83, 0x01, env->key_ref[0]};
	int ret = SC_NO_ERROR;
	if(env->algorithm == SC_ALGORITHM_RSA)
	{
		const char PRK_DF[] = "3F0000000000FF001001";
		sc_debug(card->ctx, "RSA\n");
		senv->algorithm = SC_ALGORITHM_RSA_RAW;
		if(env->operation == SC_SEC_OPERATION_DECIPHER || env->operation == SC_SEC_OPERATION_SIGN)
		{
			sc_format_path(PRK_DF, &senv->path);
			sc_append_path(&senv->path, &env->file_ref);
		}
		else ret = SC_ERROR_INVALID_ARGUMENTS;
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
	/*  set driver data  */
	if (ret == SC_NO_ERROR)
	{
		/*  TODO: add check  */
		senv->algorithm = SC_ALGORITHM_GOST;
		senv->algorithm_flags = env->algorithm_flags;
		senv->key_file_id = env->key_ref[0];
		senv->key_size = 256;
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

void rutoken_set_do_hdr(u8 *data, sc_DOHdrV2_t *pHdr)
{
	if(data)
	{
		data[0] = (u8)(pHdr->wDOBodyLen % 0x100);
		data[1] = (u8)(pHdr->wDOBodyLen / 0x100);
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

void rutoken_set_do(u8 *data, sc_DO_V2_t * pDO)
{
	rutoken_set_do_hdr(data, &pDO->HDR);
	memcpy(data + SC_RUTOKEN_DO_HDR_LEN, pDO->abyDOBody, pDO->HDR.wDOBodyLen);
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
		rutoken_set_do(data, pDO);
		
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
	sc_apdu_t apdu;
	int rv = SC_NO_ERROR;
	
	sc_debug(card->ctx,": crgram_len %i;  outlen %i\n", crgram_len, outlen);
	if (!out || !outlen) 
		return SC_ERROR_INVALID_ARGUMENTS;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, p1, p2);
	
	apdu.resp = (u8*)malloc(SC_MAX_APDU_BUFFER_SIZE);
	if (!apdu.resp)
		return SC_ERROR_OUT_OF_MEMORY;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	if (crgram_len < 16 || ((crgram_len) % 8))  
		rv = SC_ERROR_WRONG_LENGTH;
	size_t cur_len = 0;
	unsigned char is_first = 1;
	unsigned int cur_data_len;	
	
	while( (rv == SC_NO_ERROR) && (cur_len != crgram_len) && (outlen > cur_len))
	{
		cur_data_len = (crgram_len - cur_len) % 248;
		if(!cur_data_len) cur_data_len = 248;
		
		apdu.data = crgram + cur_len;
		apdu.lc = apdu.datalen = cur_data_len;
		apdu.cla = crgram_len - cur_len - cur_data_len > 0 ? 0x10 : 0x00;
		apdu.le = apdu.resplen = 248;
		
		if((rv = sc_transmit_apdu(card, &apdu)) >= 0 &&
		   (rv = rutoken_check_sw(card, apdu.sw1, apdu.sw2)) == SC_NO_ERROR) 
		{
			if(isIV && is_first)
			{
				/*  break initialization vector  */
				memcpy(out, apdu.resp + 8, apdu.resplen - 8);
				out += apdu.resplen - 8;
				cur_len += apdu.resplen;
				is_first = 0;
			}
			else
			{
				/*  memcpy(out + cur_len, apdu.resp, apdu.resplen);  */
				memcpy(out, apdu.resp, apdu.resplen);
				cur_len += apdu.resplen;
				out += apdu.resplen;
			}
		}
	}
	if (rv == SC_NO_ERROR) rv = (cur_len == crgram_len) ? isIV ? cur_len - 8 : cur_len : SC_ERROR_BUFFER_TOO_SMALL;
	
	if (apdu.resp)
		free(apdu.resp);
	
	sc_debug(card->ctx, "return decipher len %d\n", rv);
	return rv;
}

/*  Launcher for chipher  */
static int rutoken_decipher(sc_card_t *card, struct sc_rutoken_decipherinfo *ptr)
{
	return rutoken_cipher_p(card, ptr->inbuf, ptr->inlen, ptr->outbuf, ptr->outlen, 0x80, 0x86, 1);
}

/*  Launcher for chipher  */

static int rutoken_encipher(sc_card_t *card, struct sc_rutoken_decipherinfo *ptr)
{
	return rutoken_cipher_p(card, ptr->inbuf, ptr->inlen, ptr->outbuf, ptr->outlen, 0x86, 0x80, 0);
}

int rutoken_read_file(sc_card_t *card, sc_path_t *path, u8 **out, int *len)
{
	int r;
	u8 *data = NULL;
	sc_file_t *file = NULL;
	r = sc_lock(card);
	SC_TEST_RET(card->ctx, r, "sc_lock() failed");
	*len = 0;
	r = rutoken_select_file(card, path, &file);
	if (r == SC_SUCCESS)
	{
		data = (u8 *) malloc(file->size);
		if (data == NULL) 
			r = SC_ERROR_OUT_OF_MEMORY;
	}
	if (r == SC_SUCCESS)
		r = sc_read_binary(card, 0, data, file->size, 0);
	if (file && r == file->size)
	{
		*len = r;
		*out = data;
		r = SC_SUCCESS;
	}
	else
		free(data);
	sc_unlock(card);
	
	if(file) sc_file_free(file);
	
	return r;
}

int rutoken_read_prkey(sc_card_t *card,
			sc_path_t *path,
			struct sc_pkcs15_prkey **out)
{
	int ret, len = 0;
	u8 *data = NULL;
	
	ret = rutoken_read_file(card, path, &data, &len);
	if (ret == SC_SUCCESS)
	{
		ret = get_prkey_from_bin(data, len, out);
	}
	
	return ret;
}

/*  RSA emulation  */

#ifdef HAVE_OPENSSL
#define GETBN(bn)	((bn)->len? BN_bin2bn((bn)->data, (bn)->len, NULL) : NULL)
static int extract_key(sc_card_t *card, sc_path_t *path, EVP_PKEY **pk)
{
	struct sc_pkcs15_prkey	*key = NULL;
	int		r;

	r = rutoken_read_prkey(card, path, &key);

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

static int sign_ext(sc_card_t *card, sc_path_t *path,
		const u8 *data, size_t len, u8 *out, size_t out_len)
{
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;
	EVP_PKEY *pkey = NULL;
	int	ret;

	out_len = 0;
	ret = extract_key(card, path, &pkey);
	if (!senv) ret = SC_ERROR_INTERNAL;
	if (ret >= 0)
	{	
		switch (senv->algorithm) 
		{
		case SC_ALGORITHM_RSA_RAW:
			ret = RSA_private_encrypt(len, data, out, pkey->pkey.rsa, 
									  RSA_PKCS1_PADDING);
			if ( ret >= 0)
				ret = out_len;
			else
			{
				ret = SC_ERROR_INTERNAL;
				char error[1024];
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), error);
				sc_error(card->ctx, error);
				ERR_free_strings();
			}
			break;
		}
	}
	if(pkey)EVP_PKEY_free(pkey);
	return ret;
}

#if 0
static int decipher_ext(sc_card_t *card, sc_path_t *path,
						const u8 *data, size_t len, u8 *out, size_t out_len)
{
	//int	r = SC_ERROR_NOT_SUPPORTED;
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;
	EVP_PKEY *pkey = NULL;
	
	int	r;

	out_len = 0;
	r = extract_key(card, path, &pkey);
	if (r < 0)
		return r;
	
	switch (senv->algorithm) 
	{
		case SC_ALGORITHM_RSA_RAW:
			r = RSA_private_decrypt(len, data, out, pkey->pkey.rsa, 
									RSA_NO_PADDING);
			if ( r >= 0)
				out_len = r;
			else
			{
				r = SC_ERROR_INTERNAL;
				char error[1024];
				ERR_load_crypto_strings();
				ERR_error_string(ERR_get_error(), error);
				sc_error(card->ctx, error);
				ERR_free_strings();
			}
			break;
	}
	if(pkey)EVP_PKEY_free(pkey);
	/*
	EVP_PKEY_RSA *pkey = NULL;

	r = extract_key(card, &senv->path, &pkey);
	if (r < 0)
		return r;

	switch (senv->algorithm) {
	case SC_ALGORITHM_RSA_RAW:
		r = EVP_PKEY_decrypt(out, data, len, pkey);
		if (r <= 0) {
			fprintf(stderr, "Decryption failed.\n");
			r = SC_ERROR_INTERNAL;
			char error[1024];
			ERR_load_crypto_strings();
			ERR_error_string(ERR_get_error(), error);
			sc_error(card->ctx, error);
			ERR_free_strings();
		}
		break;
	default:
		fprintf(stderr, "Key type not supported.\n");
		r = SC_ERROR_NOT_SUPPORTED;
	}
	
	if(pkey)EVP_PKEY_free(pkey);*/
	return r;
}
#endif

static int rutoken_decipher_rsa(sc_card_t *card, const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
#if 0    
	//TODO: Soft RSA encryption. Uncomment and check that;
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;
	if(senv->algorithm == SC_ALGORITHM_GOST) 
	{
		return rutoken_cipher_p(card, data, datalen, out, outlen, 0x80, 0x86, 1);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		int key_id = senv->key_file_id;
		return decipher_ext(card, &senv->path, data, datalen, out, outlen);
	}
	else
		return SC_ERROR_NOT_SUPPORTED;
#endif
	return SC_ERROR_NOT_SUPPORTED;
}

static int rutoken_compute_signature_gost(sc_card_t *card, const u8 *in, size_t ilen, u8 * out, size_t olen)
{
	sc_debug(card->ctx, "sign gost");
	int ret = SC_ERROR_CARD_CMD_FAILED;
	sc_apdu_t apdu = {0};
	u8 *buff[256] = {0};
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x90, 0x80);
	apdu.lc = apdu.datalen = ilen;
	apdu.data = in;
	apdu.resplen = olen;
	apdu.resp = (u8*)buff;
	apdu.le = 4;
	if(sc_transmit_apdu(card, &apdu) >= 0)
	{
		memcpy(out, apdu.resp, apdu.resplen);
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	}
	SC_FUNC_RETURN(card->ctx, 4, apdu.resplen);
}


static int rutoken_compute_signature(struct sc_card *card, const u8 * data, size_t datalen,
                                     u8 * out, size_t outlen) 
{
	sc_debug(card->ctx, "sign");
	auth_senv_t *senv = (auth_senv_t *)card->drv_data;
	if(senv->algorithm == SC_ALGORITHM_GOST) 
	{
		return rutoken_compute_signature_gost(card, data, datalen, out, outlen);
	}
	else if (senv->algorithm == SC_ALGORITHM_RSA_RAW) 
	{
		return sign_ext(card, &senv->path, data, datalen, out, outlen);
	}
	return SC_ERROR_NOT_SUPPORTED;
}
#endif



static int rutoken_get_info(sc_card_t *card, void *buff)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;
	
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

static int rutoken_tries_left(sc_card_t *card, int *chv_tries_left)
{
	int ret = SC_ERROR_INCORRECT_PARAMETERS;
	sc_apdu_t apdu;
	if (*chv_tries_left != 1 && *chv_tries_left != 2 && *chv_tries_left != 0) 
		SC_FUNC_RETURN(card->ctx, 1, ret);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, *chv_tries_left);
	if((ret = sc_transmit_apdu(card, &apdu)) >= 0)
	{
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
		if (ret == SC_ERROR_PIN_CODE_INCORRECT)
			*chv_tries_left = (int)(apdu.sw2 & 0x0f);
	}
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

static int rutoken_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	int ret = ptr != NULL ? SC_NO_ERROR : SC_ERROR_INVALID_ARGUMENTS;
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
			ret = rutoken_encipher(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_GOST_DECIPHER:
			ret = rutoken_decipher(card, ptr);
			break;
		case SC_CARDCTL_RUTOKEN_TRIES_LEFT:
			ret = rutoken_tries_left(card, ptr);
			break;
		default:
			sc_debug(card->ctx, "cmd = %d", cmd);
#if 0
		{
			sc_apdu_t *pApdu = ptr;
			if(sc_transmit_apdu(card, pApdu) >= 0)
				ret = rutoken_check_sw(card, pApdu->sw1, pApdu->sw2);
			else
				ret = SC_ERROR_CARD_CMD_FAILED;
			break;
		}
#endif
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
	/*  rutoken_ops.verify = rutoken_verify;  */
	
	#ifdef HAVE_OPENSSL
	rutoken_ops.decipher = rutoken_decipher_rsa;
	rutoken_ops.compute_signature = rutoken_compute_signature;
	#endif
	rutoken_ops.set_security_env = rutoken_set_security_env;
	rutoken_ops.restore_security_env = rutoken_restore_security_env;
	rutoken_ops.logout  = rutoken_logout;
	
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

