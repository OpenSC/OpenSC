/*
 * card-oberthur.c: Support for Oberthur smart cards 
 *		CosmopolIC  v5; 
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Viktor Tarasov <vtarasov@idealx.com>, idealx <www.idealx.com>
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
 *
 * best view with tabstop=4
 */

#include "internal.h"
#include "cardctl.h"
#include "pkcs15.h"
#ifdef HAVE_OPENSSL
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>
#include <openssl/opensslv.h>

/* keep OpenSSL 0.9.6 users happy ;-) */
#if OPENSSL_VERSION_NUMBER < 0x00907000L
#define DES_cblock			des_cblock
#define DES_key_schedule		des_key_schedule
#define DES_set_key_unchecked(a,b)	des_set_key_unchecked(a,*b)
#define DES_ecb_encrypt(a,b,c,d) 	des_ecb_encrypt(a,b,*c,d)
#endif

static struct sc_atr_table oberthur_atrs[] = {
#if 0
	{ "3B:7F:18:00:00:00:31:C0:73:9E:01:0B:64:52:D9:04:00:82:90:00", NULL, "Oberthur 32k", SC_CARD_TYPE_OBERTHUR_32K, 0, NULL },
	{ "3B:7F:18:00:00:00:31:C0:73:9E:01:0B:64:52:D9:05:00:82:90:00", NULL, "Oberthur 32k BIO", SC_CARD_TYPE_OBERTHUR_32K_BIO, 0, NULL },
#endif
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL, "Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL, "Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL, "Oberthur 64k v5", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL, "Oberthur 64k v5/2.2.0", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7B:18:00:00:00:31:C0:64:77:E3:03:00:82:90:00", NULL, "Oberthur 64k CosmopolIC v5.2/2.2", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct NTLV {
	const char *name;
	unsigned int tag;
	size_t len;
	const unsigned char *value;
};
typedef struct NTLV NTLV_t;

struct auth_application_id {
	unsigned int tag;
	u8 value[SC_MAX_AID_SIZE];
	int len;
};
typedef struct auth_application_id auth_application_id_t;

struct auth_senv {
	unsigned int algorithm;
	int key_file_id;
	size_t key_size;
};
typedef struct auth_senv auth_senv_t;

struct auth_private_data {
	struct sc_pin_cmd_pin pin_info;
	long int sn;
	auth_application_id_t aid;
	auth_senv_t senv;
};
typedef struct auth_private_data auth_private_data_t;

#define AID_OBERTHUR_V2		0x201
#define AID_OBERTHUR_V4		0x401
#define AID_OBERTHUR_V5		0x501

static NTLV_t oberthur_aids[] = {
#if 0
	{ "AuthentIC v2", AID_OBERTHUR_V2, 14,
	  (const unsigned char *) "\xA0\x00\x00\x00\x77\x58\x35\x30\x39\x23\x56\x32\x2E\x30"
	},
	{ "AuthentIC v4", AID_OBERTHUR_V4, 16,
	  (const unsigned char *) "\xA0\x00\x00\x00\x77\x01\x03\x03\x00\x20\x03\xF1\x00\x00\x00\x02"
	},
#endif
	{ "AuthentIC v5", AID_OBERTHUR_V5, 16,
	  (const unsigned char *) "\xA0\x00\x00\x00\x77\x01\x03\x03\x00\x00\x00\xF1\x00\x00\x00\x02"
	},
	{ NULL, 0, 0, NULL }
}; 

#define AUTH_PIN		1
#define AUTH_PUK		2

#define SC_OBERTHUR_MAX_ATTR_SIZE	8

#define PUBKEY_512_ASN1_SIZE	0x4A
#define PUBKEY_1024_ASN1_SIZE	0x8C
#define PUBKEY_2048_ASN1_SIZE	0x10E

static unsigned char rsa_der[PUBKEY_2048_ASN1_SIZE];
static int rsa_der_len = 0;

static sc_file_t last_selected_file;
static struct sc_card_operations auth_ops;
static struct sc_card_operations *iso_ops;
static struct sc_card_driver auth_drv = {
	"Oberthur AuthentIC.v2/CosmopolIC.v4",
	"oberthur",
	&auth_ops,
	NULL, 0, NULL
};

static int auth_get_pin_reference (sc_card_t *card,
		int type, int reference, int cmd, int *out_ref);
static int auth_read_component(sc_card_t *card, 
		enum SC_CARDCTL_OBERTHUR_KEY_TYPE type, int num, 
		unsigned char *out, size_t outlen);
static int auth_verify(sc_card_t *card, unsigned int type,
		int ref, const u8 *data, size_t data_len, int *tries_left);
static int auth_create_reference_data (sc_card_t *card,
		struct sc_cardctl_oberthur_createpin_info *args);
static int auth_get_serialnr(sc_card_t *card, sc_serial_number_t *serial);

static int 
auth_finish(sc_card_t *card)
{
	free(card->drv_data);
	return 0;
}


static int 
auth_select_aid(sc_card_t *card)
{
	sc_apdu_t apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	struct auth_private_data *data =  (struct auth_private_data *) card->drv_data;
	int rv, ii;
	unsigned char cm[7] = {0xA0,0x00,0x00,0x00,0x03,0x00,0x00};

	/* Select Card Manager (to deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = sizeof(cm);
	apdu.le = sizeof(cm)+4;
	apdu.data = cm;
	apdu.datalen = sizeof(cm);
	apdu.resplen = sizeof(apdu.resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	
	/* Get smart card serial number */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x9F, 0x7F);
	apdu.cla = 0x80;
	apdu.le = 0x2D;
	apdu.resplen = 0x30;
	apdu.resp = apdu_resp;
	sc_transmit_apdu(card, &apdu);
	if (apdu.sw1==0x90)  {
		card->serialnr.len = 4;
		memcpy(card->serialnr.value, apdu.resp+15, 4);
		sc_debug(card->ctx, "serial number %li\n", 
			*(apdu.resp+15)*0x1000000 + *(apdu.resp+16)*0x10000 +
			*(apdu.resp+17)*0x100 + *(apdu.resp+18));
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x00);
	apdu.resp = apdu_resp;

	/* Try to select known AID */
	for (ii = 0; oberthur_aids[ii].value != NULL; ii++) {
		size_t len = oberthur_aids[ii].len;
		
		apdu.lc = len;
		apdu.le = len + 4;
		apdu.data = oberthur_aids[ii].value;
		apdu.datalen = len;
		apdu.resplen = SC_MAX_AID_SIZE + 8;
		
		rv = sc_transmit_apdu(card, &apdu);
		if (rv < 0)
			continue;
		if (apdu.sw1!=0x90 || apdu.sw2!=0x00)  
			continue;
		if (!memcmp(oberthur_aids[ii].value, apdu.resp+4, len))   {
			memcpy(data->aid.value, oberthur_aids[ii].value, len);
			data->aid.len = len;
			data->aid.tag = oberthur_aids[ii].tag;
			card->name = oberthur_aids[ii].name;
			break;
		}
	}
	
	return oberthur_aids[ii].value == NULL ? -1 : 0;
}

static int 
auth_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, oberthur_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int 
auth_init(sc_card_t *card)
{
	unsigned long flags;
	struct auth_private_data *data;
	
	data = (struct auth_private_data *) malloc(sizeof(struct auth_private_data));
	if (!data)
		return SC_ERROR_OUT_OF_MEMORY;
	else
		memset(data, 0, sizeof(struct auth_private_data));

	card->cla = 0x00;
	card->drv_data = data;

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG;

	if (auth_select_aid(card))   {
		sc_error(card->ctx, "Failed to initialize %s\n", card->name);
		return SC_ERROR_INVALID_CARD;
	}
	
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ISO9796;
	flags |= SC_ALGORITHM_RSA_HASH_NONE;
	flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

	_sc_card_add_rsa_alg(card, 512, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
#if 0
	flags = SC_ALGORITHM_SKEY_CBC | SC_ALGORITHM_SKEY_ECB;
	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_DES;
	info.flags = flags;
	info.key_length = 64;
	_sc_card_add_algorithm(card, &info);
	
	flags = SC_ALGORITHM_SKEY_CBC | SC_ALGORITHM_SKEY_ECB;
	info.algorithm = SC_ALGORITHM_3DES;
	info.flags = flags;
	info.key_length = 192;
	_sc_card_add_algorithm(card, &info);
#endif
	return 0;
}


static void 
add_acl_entry(sc_card_t *card, sc_file_t *file, unsigned int op, 
		u8 acl_byte)
{
	struct auth_private_data *data = (struct auth_private_data *) card->drv_data;

	switch (data->aid.tag)   {
	case AID_OBERTHUR_V5 :
		switch (acl_byte) {
		case 0x00:
			sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE);
			break;
		case 0x21:
			sc_file_add_acl_entry(file, op, SC_AC_CHV, 1);
			break;
		case 0x24:
		case 0x0F:
			sc_file_add_acl_entry(file, op, SC_AC_CHV, 2);
			break;
		case 0x25:
			sc_file_add_acl_entry(file, op, SC_AC_CHV, 3);
			break;
		case 0xFF:
			sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
			break;
		default:
			sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
			break;
		}
		break;
	default:
		break;
	
	}
}


static int 
tlv_get(unsigned char *msg, unsigned char tag, unsigned char *ret, int *ret_len)
{
	int len = *(msg+1);
	int cur = 2;
	
	if (*msg != 0x6F || len > 0x1A)
		return SC_ERROR_INCORRECT_PARAMETERS;
	
	while (cur < len)  { 
		if (*(msg+cur)==tag)  {
			int ii, ln = *(msg+cur+1);
		
			if (ln > *ret_len)   
				return SC_ERROR_WRONG_LENGTH;

			for (ii=0; ii<ln; ii++)
				*(ret + ii) = *(msg+cur+2+ii);
			*ret_len = ln;
			
			return 0;
		}
		
		cur += 2 + *(msg+cur+1);
	}
		
	return SC_ERROR_INCORRECT_PARAMETERS;
}


static int
decode_file_structure_V5 (sc_card_t *card, unsigned char *buf, int buflen,
				   sc_file_t *file)
{
	u8 type, attr[SC_OBERTHUR_MAX_ATTR_SIZE];
	int attr_len = sizeof(attr);

	attr_len = sizeof(attr);
	if (tlv_get(buf, 0x82, attr, &attr_len)) 
		return 	SC_ERROR_UNKNOWN_DATA_RECEIVED;
	type = attr[0];
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, 0x83, attr, &attr_len)) 
		return 	SC_ERROR_UNKNOWN_DATA_RECEIVED;
	file->id = attr[0]*0x100 + attr[1];
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, type==0x01 ? 0x80 : 0x85, attr, &attr_len))
		return  SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (attr_len<2 && type != 0x04)
		return  SC_ERROR_UNKNOWN_DATA_RECEIVED;
		
	switch (type) {
	case 0x01:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = attr[0]*0x100 + attr[1];
		break;
	case 0x04:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_VARIABLE;
		file->size = attr[0];
		attr_len = sizeof(attr);
		if (tlv_get(buf, 0x82, attr, &attr_len)) 
			return 	SC_ERROR_UNKNOWN_DATA_RECEIVED;
		if (attr_len!=5)
			return  SC_ERROR_UNKNOWN_DATA_RECEIVED;
		file->record_length = attr[2]*0x100+attr[3];
		file->record_count = attr[4];
		break;
	case 0x11:
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_DES;
		file->size = attr[0]*0x100 + attr[1];
		file->size /= 8;
		break;
	case 0x12:
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
		
		file->size = attr[0]*0x100 + attr[1];
		if (file->size==512)
			file->size = PUBKEY_512_ASN1_SIZE;
		else if (file->size==1024)
			file->size = PUBKEY_1024_ASN1_SIZE;
		else if (file->size==2048)
			file->size = PUBKEY_2048_ASN1_SIZE;
		else   {
			sc_error(card->ctx, "Not supported public key size: %i\n", file->size);
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}
		break;
	case 0x14:
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
		file->size = attr[0]*0x100 + attr[1];
		break;
	case 0x38:
		file->type = SC_FILE_TYPE_DF;
		file->size = attr[0];
		sc_file_set_type_attr(file,attr,attr_len);
		break;
	default:
		sc_error(card->ctx, "invalid file type: 0x%02X\n", type);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, 0x86, attr, &attr_len))
		return  SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (attr_len<8)
		return  SC_ERROR_UNKNOWN_DATA_RECEIVED;

	if (file->type == SC_FILE_TYPE_DF) {
		add_acl_entry(card, file, SC_AC_OP_CREATE, attr[0]);
		add_acl_entry(card, file, SC_AC_OP_CRYPTO, attr[1]);
		add_acl_entry(card, file, SC_AC_OP_LIST_FILES, attr[2]);
		add_acl_entry(card, file, SC_AC_OP_DELETE, attr[3]);
#if 0
		add_acl_entry(card, file, SC_AC_OP_CHANGE_REFERENCE, attr[4]);
		add_acl_entry(card, file, SC_AC_OP_SET_REFERENCE, attr[5]);
		add_acl_entry(card, file, SC_AC_OP_RESET_COUNTER, attr[6]);
#endif
	} 
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)  { /* EF */
		switch (file->ef_structure) {
		case SC_CARDCTL_OBERTHUR_KEY_DES:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
#if 0
			add_acl_entry(card, file, SC_AC_OP_DECRYPT, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_ENCRYPT, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_CHECKSUM, attr[3]);
			add_acl_entry(card, file, SC_AC_OP_VERIFY, attr[4]);
#else
			add_acl_entry(card, file, SC_AC_OP_READ, attr[1]);
#endif
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
#if 0
			add_acl_entry(card, file, SC_AC_OP_ENCRYPT, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_VERIFY, attr[4]);
#else
			add_acl_entry(card, file, SC_AC_OP_READ, attr[2]);
#endif
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_CRT:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
#if 0
			add_acl_entry(card, file, SC_AC_OP_DECRYPT, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_SIGN, attr[3]);
#else
			add_acl_entry(card, file, SC_AC_OP_READ, attr[1]);
#endif
			break;
		}
	}
	else   {
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			add_acl_entry(card, file, SC_AC_OP_WRITE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_READ, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_ERASE, attr[3]);
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			add_acl_entry(card, file, SC_AC_OP_WRITE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_READ, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_ERASE, attr[3]);
			break;
		}
	}

	file->status = SC_FILE_STATUS_ACTIVATED;
	file->magic = SC_FILE_MAGIC;
	return 0;
}


static int 
check_path(sc_card_t *card, const u8 **pathptr, size_t *pathlen,
			  int need_info)
{
	const u8 *curptr = card->cache.current_path.value;
	const u8 *ptr = *pathptr;
	size_t curlen = card->cache.current_path.len;
	size_t len = *pathlen;

	if (curlen < 2 || len < 2)
		return 0;
	if (memcmp(ptr, "\x3F\x00", 2) != 0) {
		/* Skip the MF id */
		curptr += 2;
		curlen -= 2;
	}
	if (len == curlen && memcmp(ptr, curptr, len) == 0) {
		if (need_info)
			return 0;
		*pathptr = ptr + len;
		*pathlen = 0;
		return 1;
	}
	if (curlen < len && memcmp(ptr, curptr, curlen) == 0) {
		*pathptr = ptr + curlen;
		*pathlen = len - curlen;
		return 1;
	}

	return 0;
}

#if 0
static void 
auth_cache_path(sc_card_t *card, const sc_path_t *path)
{
	sc_path_t *curpath = &card->cache.current_path;

	switch (path->type) {
	case SC_PATH_TYPE_FILE_ID:
		if (path->value[0] == 0x3F && path->value[1] == 0x00)
			sc_format_path("3F00", curpath);
		else {
			if (curpath->len + 2 > SC_MAX_PATH_SIZE) {
				curpath->len = 0;
				return;
			}
			memcpy(curpath->value + curpath->len, path->value, 2);
			curpath->len += 2;
		}
		break;
	case SC_PATH_TYPE_PATH:
		curpath->len = 0;
		if (path->value[0] != 0x3F || path->value[1] != 0)
			sc_format_path("3F00", curpath);
		if (curpath->len + path->len > SC_MAX_PATH_SIZE) {
			curpath->len = 0;
			return;
		}
		memcpy(curpath->value + curpath->len, path->value, path->len);
		curpath->len += path->len;
		break;
	case SC_PATH_TYPE_DF_NAME:
		/* All bets are off */
		curpath->len = 0;
		break;
	}
}
#endif

static int 
select_parent(sc_card_t *card, sc_file_t **file_out)
{
	int rv;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_file_t *file;
	sc_path_t *cache_path = &card->cache.current_path;	
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;

	last_selected_file.magic = 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xA4, 0x03, 0);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x18;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");

	if (apdu.resplen < 14)  {
		sc_error(card->ctx, "invalid response length\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	else if (apdu.resp[0] != 0x6F) {
		sc_error(card->ctx, "unsupported: card returned FCI\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	
	if (cache_path->len > 2)
		cache_path->len -= 2;
	
	file = sc_file_new();
	if (prv->aid.tag == AID_OBERTHUR_V5)
		rv = decode_file_structure_V5(card, apdu.resp, apdu.resplen, file);
	else   { 
		sc_file_free(file);
		return SC_ERROR_INVALID_CARD;
	}
	
	if (rv) {
		sc_file_free(file);
		return rv;
	}
	
	memcpy(&last_selected_file, file, sizeof(sc_file_t));
	
	if (file_out) 
		*file_out = file;
	else
		sc_file_free(file);
	
	return 0;
}


static int 
select_mf(sc_card_t *card, sc_file_t **file_out)
{
	int ii,rv;
	sc_file_t *file = NULL;
	sc_path_t *cache_path = &card->cache.current_path;
	
	last_selected_file.magic = 0;
	for(ii=0;;ii++)   {	
		rv = select_parent(card, &file);
		SC_TEST_RET(card->ctx, rv, "Select parent failed");
		
		if (file->id==0x3F00)
			break;
		else
			sc_file_free(file);
		
		if (ii>5)
			return SC_ERROR_CARD_CMD_FAILED;
	}

	memcpy(cache_path->value, "\x3F\x00", 2);
	cache_path->len = 2;
	
	memcpy(&last_selected_file, file, sizeof(sc_file_t));
	if (file && file_out)
		*file_out = file;
	else if (file)
		sc_file_free(file);

	return 0;
}


static int 
select_file_id(sc_card_t *card, const u8 *buf, size_t buflen,
			  u8 p1, sc_file_t **file_out)
{
	int rv;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_file_t *file;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;

	last_selected_file.magic = 0;
	if (buflen==2 && memcmp(buf,"\x3F\x00",2)==0)   {
		rv = select_mf(card,file_out);
		SC_TEST_RET(card->ctx, rv, "Select MF failed");
		return rv;
	}

	if (!memcmp(buf,"\x00\x00",2) || !memcmp(buf,"\xFF\xFF",2) ||
				!memcmp(buf,"\x3F\xFF",2))  
		return SC_ERROR_INCORRECT_PARAMETERS;	
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, p1, 0);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.datalen = buflen;
	apdu.data = buf;
	apdu.lc = buflen;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");

	if (apdu.resplen < 14)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	
	if (apdu.resp[0] != 0x6F) {
		sc_error(card->ctx, "unsupported: card returned FCI\n");
		return SC_ERROR_UNKNOWN_DATA_RECEIVED; /* FIXME */
	}
	
	file = sc_file_new();
	if (prv->aid.tag == AID_OBERTHUR_V5)  
		rv = decode_file_structure_V5(card, apdu.resp, apdu.resplen, file);
	else   {
		sc_file_free(file);
		return SC_ERROR_INVALID_CARD;
	}

	if (rv) {
		sc_file_free(file);
		return rv;
	}
		
	memcpy(&last_selected_file, file, sizeof(sc_file_t));
	
	if (file->type == SC_FILE_TYPE_DF)   {
		sc_path_t *cache_path = &card->cache.current_path;
		size_t len = cache_path->len;

		if (len < sizeof(cache_path->value))   {
			memcpy(&cache_path->value[len], buf, 2);
			cache_path->len += 2;
		}
	}
	
	sc_debug(card->ctx, "selected %04X\n",file->id);
	if (file_out)
		*file_out = file;
	else
		sc_file_free(file);
	
	return rv;
}


static int 
auth_select_file(sc_card_t *card, const sc_path_t *path,
				 sc_file_t **file_out)
{
	int rv;
	const u8 *pathptr = path->value;
	size_t pathlen = path->len;
	int locked = 0, magic_done;
	u8 p1 = 0;

	sc_debug(card->ctx, "path; type=%d, path=%s\n",
			path->type, sc_print_path(path));
	sc_debug(card->ctx, "cache; type=%d, path=%s\n",
			card->cache.current_path.type, sc_print_path(&card->cache.current_path));
	
	switch (path->type) {
	case SC_PATH_TYPE_PATH:
		if ((pathlen & 1) != 0) /* not divisible by 2 */
			return SC_ERROR_INVALID_ARGUMENTS;
		
		magic_done = check_path(card, &pathptr, &pathlen, file_out != NULL);
		if (pathlen == 0)  
			return 0;
		
		if (pathlen != 2 || memcmp(pathptr, "\x3F\x00", 2) != 0) {
			locked = 1;
			rv = sc_lock(card);
			SC_TEST_RET(card->ctx, rv, "sc_lock() failed");
			if (!magic_done && memcmp(pathptr, "\x3F\x00", 2) != 0) {
				rv = select_file_id(card, (const u8 *) "\x3F\x00", 2, 0, NULL);
				if (rv)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, rv, "Unable to select Master File (MF)");
			}
			while (pathlen > 2) {
				rv = select_file_id(card, pathptr, 2, 0, NULL);
				if (rv)
					sc_unlock(card);
				SC_TEST_RET(card->ctx, rv, "Unable to select DF");
				pathptr += 2;
				pathlen -= 2;
			}
		}
		break;
	case SC_PATH_TYPE_DF_NAME:
		p1 = 0x01;
		break;
	case SC_PATH_TYPE_FILE_ID:
		p1 = 0x02;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	}
	
	rv = select_file_id(card, pathptr, pathlen, p1, file_out);
	
	if (locked)
		sc_unlock(card);
	
#if 0
	if (!rv)
		auth_cache_path(card, path);
#endif
	
	sc_debug(card->ctx, "return %i\n",rv);
	return rv;
}


static int 
auth_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x34, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 0x40;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	if (apdu.resplen == 0x100 && rbuf[0]==0 && rbuf[1]==0)
		return 0;
	
	buflen = buflen < apdu.resplen ? buflen : apdu.resplen;
	memcpy(buf, rbuf, buflen);
	
	return buflen;
}


static int 
auth_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int rv;
	u8 sbuf[2];
	sc_apdu_t apdu;

	sc_debug(card->ctx, "path; type=%d, path=%s\n", path->type, sc_print_path(path));
	SC_FUNC_CALLED(card->ctx, 1);
	if (path->len < 2)   {
		sc_error(card->ctx, "Invalid path length\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	
	if (path->len > 2)   {
		sc_path_t parent = *path;

		parent.len -= 2;
		parent.type = SC_PATH_TYPE_PATH;
		rv = auth_select_file(card, &parent, NULL);
		SC_TEST_RET(card->ctx, rv, "select parent failed ");
	}

	sbuf[0] = path->value[path->len - 2];
	sbuf[1] = path->value[path->len - 1];

	if (memcmp(sbuf,"\x00\x00",2)==0 || (memcmp(sbuf,"\xFF\xFF",2)==0) || 
			memcmp(sbuf,"\x3F\xFF",2)==0) 
		return SC_ERROR_INCORRECT_PARAMETERS;	
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x02, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.sw1==0x6A && apdu.sw2==0x82)   {
		/* Clean the DF contents.*/
		u8 lbuf[SC_MAX_APDU_BUFFER_SIZE];
		int ii, len;
#if 0
		sc_file_t *file;

		if (!(file = sc_file_new()))
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
		
		rv = select_file_id(card, sbuf, 2, 0x01, &file);
#else
		rv = select_file_id(card, sbuf, 2, 0x01, NULL);
#endif
		SC_TEST_RET(card->ctx, rv, "select DF failed");
		
		len = auth_list_files(card, lbuf, sizeof(lbuf));
		SC_TEST_RET(card->ctx, len, "list DF failed");
		
		for (ii=0; ii<len/2; ii++)   {
			sc_path_t tpath;

			tpath.value[0] = *(lbuf + ii*2);
			tpath.value[1] = *(lbuf + ii*2 + 1);
			tpath.len = 2;

			rv = auth_delete_file(card, &tpath);
			SC_TEST_RET(card->ctx, rv, "delete failed");
		}
#if 0
		rv = select_parent(card, &file);
#else
		rv = select_parent(card, NULL);
#endif
		SC_TEST_RET(card->ctx, rv, "select parent DF failed");
		
		apdu.p1 = 1;
		rv = sc_transmit_apdu(card, &apdu);
	}
		
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card return error");
	return rv;
}


static int 
acl_to_ac_byte(sc_card_t *card, const sc_acl_entry_t *e)
{
	struct auth_private_data *data = (struct auth_private_data *) card->drv_data;
	
	if (e == NULL)
		return -1;
	switch (data->aid.tag)   {
	case AID_OBERTHUR_V5 :
		switch (e->method) {
		case SC_AC_NONE:
			return 0x00;
		
		case SC_AC_CHV:
			if (e->key_ref == 1)   
				return 0x21;
			else if (e->key_ref == 2)  
				return 0x24;
			else if (e->key_ref == 3)  
				return 0x25;
			else
				return -1;
		
		case SC_AC_NEVER:
			return 0xff;
		}
		break;
	}
		
	sc_error(card->ctx, "unknown method or  aid %i; tag %X\n",e->method, data->aid.tag);
	return SC_ERROR_INCORRECT_PARAMETERS;
}


static int 
encode_file_structure_V5(sc_card_t *card, const sc_file_t *file,
				 u8 *buf, size_t *buflen)
{
	u8 *p = buf;
	int rv=0, size;
	size_t ii;
	unsigned char  ops[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	sc_debug(card->ctx, ": id %04X; size %i; type %i/%i\n",
			file->id, file->size, file->type, file->ef_structure);
	if (*buflen < 0x18)   {
		sc_error(card->ctx, "Insifficient buffer size.\n");
		return SC_ERROR_INCORRECT_PARAMETERS;
	}

	p[0] = 0x62, p[1] = 0x16;
	p[2] = 0x82, p[3] = 0x02;

	rv = 0;
	if (file->type == SC_FILE_TYPE_DF)  {
		p[4] = 0x38;
		p[5] = 0x00;
	}
	else  if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			p[4] = 0x01;
			p[5] = 0x01;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			p[4] = 0x04;
			p[5] = 0x01;
			break;
		default:
			rv = -1;
			break;
		}
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)  {
		switch (file->ef_structure) {
		case SC_CARDCTL_OBERTHUR_KEY_DES:
			p[4] = 0x11;
			p[5] = 0x00;
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC:
			p[4] = 0x12;
			p[5] = 0x00;
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_CRT:
			p[4] = 0x14;
			p[5] = 0x00;
			break;
		default:
			rv = -1;
			break;
		}
	}
	else
		rv = -1;

	if (rv)   {
		sc_error(card->ctx, "Invalid EF structure %i/%i\n", 
				file->type, file->ef_structure);
		return -1;
	}
	
	p[6] = 0x83;
	p[7] = 0x02;
	p[8] = file->id >> 8;
	p[9] = file->id & 0xFF;
	
	p[10] = 0x85;
	p[11] = 0x02;

	size = file->size;
	
	if (file->type == SC_FILE_TYPE_DF)   {
		size &= 0xFF;
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF && 
			file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)   {
		/*
		 * Legal sizes corresponds to 512/1024/2048 key size
		 * and 3 bytes exponent.
		 */
		sc_debug(card->ctx, "ef %s\n","SC_FILE_EF_RSA_PUBLIC");
		if (file->size == PUBKEY_512_ASN1_SIZE || file->size == 512)
			size = 512;
		else if (file->size == PUBKEY_1024_ASN1_SIZE || file->size == 1024)
			size = 1024;
		else if (file->size == PUBKEY_2048_ASN1_SIZE || file->size == 2048)
			size = 2048;
		else   {
			sc_error(card->ctx, "incorrect RSA size %X\n", file->size);
			return SC_ERROR_INCORRECT_PARAMETERS;
		}
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF &&
			file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		if (file->size == 8 || file->size == 64)
			size = 64;
		else if (file->size == 16 || file->size == 128)
			size = 128;
		else if (file->size == 24 || file->size == 192)
			size = 192;
		else   {
			sc_error(card->ctx, "incorrect DES size %X\n", file->size);
			return SC_ERROR_INCORRECT_PARAMETERS;
		}
	}

	p[12] = (size >> 8) & 0xFF;
	p[13] = size & 0xFF;
	
	p[14] = 0x86;
	p[15] = 0x08;
	
	if (file->type == SC_FILE_TYPE_DF) {
		ops[0] = SC_AC_OP_CREATE;
		ops[1] = SC_AC_OP_CRYPTO;
		ops[2] = SC_AC_OP_LIST_FILES;
		ops[3] = SC_AC_OP_DELETE;
		ops[4] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_SET_REFERENCE */
		ops[5] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_CHANGE_REFERENCE */
		ops[6] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_RESET_COUNTER */
	} 
	else if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		if (file->ef_structure == SC_FILE_EF_TRANSPARENT)   {
			sc_debug(card->ctx, "SC_FILE_EF_TRANSPARENT\n");
			ops[0] = SC_AC_OP_WRITE;
			ops[1] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_READ;
			ops[3] = SC_AC_OP_ERASE;
		}
		else if (file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE)  {
			sc_debug(card->ctx, "SC_FILE_EF_LINEAR_VARIABLE\n");
			ops[0] = SC_AC_OP_WRITE;
			ops[1] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_READ;
			ops[3] = SC_AC_OP_ERASE;
		}
	}
	else   if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
		if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)  {
			sc_debug(card->ctx, "EF_DES\n");
			ops[0] = SC_AC_OP_UPDATE;
			ops[1] = SC_AC_OP_READ;  /* SC_AC_OP_DECRYPT */
			ops[2] = SC_AC_OP_READ;  /* SC_AC_OP_ENCRYPT */
			ops[3] = SC_AC_OP_READ;  /* SC_AC_OP_CHECKSUM */
			ops[4] = SC_AC_OP_READ;  /* SC_AC_OP_CHECKSUM */
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  {
			sc_debug(card->ctx, "EF_RSA_PUBLIC\n");
			ops[0] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_READ;  /* SC_AC_OP_ENCRYPT */
			ops[4] = SC_AC_OP_READ;  /* SC_AC_OP_SIGN */
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)  {
			sc_debug(card->ctx, "EF_RSA_PRIVATE\n");
			ops[0] = SC_AC_OP_UPDATE;
			ops[1] = SC_AC_OP_READ;  /* SC_AC_OP_ENCRYPT */
			ops[3] = SC_AC_OP_READ;  /* SC_AC_OP_SIGN */
		}
	}
	
	for (ii = 0; ii < sizeof(ops); ii++) {
		const sc_acl_entry_t *entry;
		
		p[16+ii] = 0xFF;
		if (ops[ii]==0xFF)
			continue;
		entry = sc_file_get_acl_entry(file, ops[ii]);
		rv = acl_to_ac_byte(card,entry);
		SC_TEST_RET(card->ctx, rv, "Invalid ACL value");
		p[16+ii] = rv;
	}
	
	*buflen = 0x18;
	
	return 0;
}


static int 
auth_create_file(sc_card_t *card, sc_file_t *file)
{
	u8 sbuf[0x18];
	size_t sendlen = sizeof(sbuf);
	int rv, rec_nr;
	sc_apdu_t apdu;
	sc_path_t path;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;

	sc_debug(card->ctx, " create path=%s\n", sc_print_path(&file->path));
	sc_debug(card->ctx,"id %04X; size %i; type %i; ef %i\n",
			file->id, file->size, file->type, file->ef_structure);
	if (file->id==0x0000 || file->id==0xFFFF || file->id==0x3FFF)  
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_debug(card->ctx, " cache path=%s\n", 
			sc_print_path(&card->cache.current_path));

	if (file->path.len)   {
		memcpy(&path, &file->path, sizeof(path));
		if (path.len>2)   
			path.len -= 2;
	
		if (auth_select_file(card, &path, NULL))   {
			sc_error(card->ctx, "Cannot select parent DF.\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}
	
	if (prv->aid.tag == AID_OBERTHUR_V5)
		rv = encode_file_structure_V5(card, file, sbuf, &sendlen);
	else  
		return SC_ERROR_INVALID_CARD;
	
	if (rv) {
		sc_error(card->ctx, "File structure encoding failed.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	if (file->type != SC_FILE_TYPE_DF && file->ef_structure != SC_FILE_EF_TRANSPARENT)
		rec_nr = file->record_count;
	else
		rec_nr = 0;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, rec_nr);
	apdu.data = sbuf;
	apdu.datalen = sendlen;
	apdu.lc = sendlen;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	/* select created DF. */
	if (file->type == SC_FILE_TYPE_DF)   {
		u8 file_id[2] = {file->id >> 8, file->id & 0xFF};
		
		if (select_file_id(card, file_id, 2, 0x01, NULL))
			return SC_ERROR_CARD_CMD_FAILED; 
			
		if (card->cache_valid) {
			file_id[0] = file->id >> 8;
			file_id[1] = file->id & 0xFF;
			if (card->cache.current_path.len != 0)
				sc_append_path_id(&card->cache.current_path, file_id, 2);
		}
	}

	return 0;
}


static int 
auth_set_security_env(sc_card_t *card, 
		const sc_security_env_t *env, int se_num)   
{
	auth_senv_t *senv = &((struct auth_private_data *) card->drv_data)->senv;
	long unsigned pads = env->algorithm_flags & SC_ALGORITHM_RSA_PADS;
	long unsigned supported_pads = 
		SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ISO9796;
	sc_file_t *key_file = NULL;
	sc_apdu_t apdu;
	u8 rsa_sbuf[7] = {0x80, 0x01, 0xFF, 0x81, 0x02, 0xFF, 0xFF};
	int des_buf_len;
	u8 des_sbuf[17] = {0x80, 0x01, 0x01, 0x81, 0x02, 0xFF, 0xFF,
					   0x87, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
					   0xFF, 0xFF, 0xFF};
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;
	int rv;

	sc_debug(card->ctx, "op %i\n", env->operation);

	memset(senv,0,sizeof(auth_senv_t));
	
	rv = auth_select_file(card, &env->file_ref, &key_file);
	if (rv)
		return rv;
	
	switch (env->algorithm)   {
	case SC_ALGORITHM_DES:
	case SC_ALGORITHM_3DES:
		sc_debug(card->ctx, "algo SC_ALGORITHM_xDES: ref %X, flags %X\n", 
				env->algorithm_ref, env->flags);
		if (key_file->ef_structure != SC_CARDCTL_OBERTHUR_KEY_DES || 
				key_file->type != SC_FILE_TYPE_INTERNAL_EF)
			return SC_ERROR_INVALID_ARGUMENTS;

		des_buf_len = 3;
		if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)   {
			des_sbuf[5] = (key_file->id>>8) & 0xFF;
			des_sbuf[6] = key_file->id & 0xFF;
			des_buf_len += 4;
		}
		
		if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = des_buf_len;
			apdu.data = des_sbuf;
			apdu.datalen = des_buf_len;
		}
		else {
			sc_error(card->ctx, "Invalid crypto operation: %X\n", env->operation);
			return SC_ERROR_NOT_SUPPORTED;
		}
	
		break;
	case SC_ALGORITHM_RSA:
		sc_debug(card->ctx, "algo SC_ALGORITHM_RSA\n");
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) {
			sc_error(card->ctx, "Not support for hashes.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		
		if (pads & (~supported_pads))   {
			sc_error(card->ctx, "No support for this PAD: %X\n",pads);
			return SC_ERROR_NOT_SUPPORTED;
		}
	
		if (key_file->type != SC_FILE_TYPE_INTERNAL_EF ||  
				key_file->ef_structure != SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)
			return SC_ERROR_INVALID_ARGUMENTS;
	
		rsa_sbuf[5] = (key_file->id>>8) & 0xFF;
		rsa_sbuf[6] = key_file->id & 0xFF;
		if (env->operation == SC_SEC_OPERATION_SIGN)   {
			rsa_sbuf[2] = prv->aid.tag == AID_OBERTHUR_V5 ? 0x11 : 0x11;
			
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			rsa_sbuf[2] = prv->aid.tag == AID_OBERTHUR_V5 ? 0x11 : 0x02;
		
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else {
			sc_error(card->ctx, "Invalid crypto operation: %X\n", env->operation);
			return SC_ERROR_NOT_SUPPORTED;
		}
	
		break;
	default:
		sc_error(card->ctx, "Invalid crypto algorithm supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	senv->algorithm = env->algorithm;
	senv->key_file_id = key_file->id;
	senv->key_size = key_file->size;

	if (key_file)
		sc_file_free(key_file);
	
	return 0;
}


static int 
auth_restore_security_env(sc_card_t *card, int se_num)
{
	return 0;
}


static int 
auth_compute_signature(sc_card_t *card, 
		const u8 *in, size_t ilen, 	u8 * out, size_t olen)
{
	auth_senv_t *senv = &((struct auth_private_data *) card->drv_data)->senv;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	sc_debug(card->ctx, " inlen %i, outlen %i, algo %i\n", ilen, olen, senv->algorithm);
	if (!senv->key_file_id)
		return SC_ERROR_INVALID_DATA;

	switch (senv->algorithm)   {
	case SC_ALGORITHM_RSA:
		sc_debug(card->ctx, "algorithm SC_ALGORITHM_RSA\n");
		if (ilen > 96)   {
			sc_error(card->ctx, "Illegal input length for CosmopolIC v4: %d\n", ilen);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		else if (olen < ilen) {
			sc_error(card->ctx, "Output buffer too small.\n");
			return SC_ERROR_BUFFER_TOO_SMALL;
		}
	
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
		apdu.lc = ilen;
		apdu.datalen = ilen;
		apdu.data = sbuf;
		memcpy(sbuf, in, ilen);
		apdu.le = senv->key_size/8;
	
		apdu.resp = (u8 *) malloc(senv->key_size/8+8);
		if (apdu.resp==NULL)   
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
		apdu.resplen = senv->key_size/8;
		break;
	default:
		sc_error(card->ctx, "Invalid crypto algorithm supplied.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
		
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	if (apdu.resplen != senv->key_size/8)   {
		sc_error(card->ctx, "Signature failed: invalide response length %i\n",
				apdu.resplen);
		return SC_ERROR_CARD_CMD_FAILED;
	}
	
	memcpy(out, apdu.resp, apdu.resplen);
	
	if (card->ctx->debug >= 5)  {
		char debug_buf[2048];
		
		debug_buf[0] = 0;
		if (!apdu.sensitive || card->ctx->debug >= 6)
			sc_hex_dump(card->ctx, in, ilen, debug_buf, sizeof(debug_buf));
		sc_debug(card->ctx, "auth_compute_signature in %d bytes :\n%s",
				            ilen, apdu.sensitive ? ", sensitive" : "", debug_buf);
		
		debug_buf[0] = 0;
		if (!apdu.sensitive || card->ctx->debug >= 6)
			sc_hex_dump(card->ctx, out, apdu.resplen, debug_buf, sizeof(debug_buf));
		sc_debug(card->ctx, "auth_compute_signature out %d bytes :\n%s",
				            apdu.resplen, 
							apdu.sensitive ? ", sensitive" : "", debug_buf);
	}

	sc_debug(card->ctx, "Signature Template return %i\n", apdu.resplen);
	return apdu.resplen;
}

static int 
auth_decipher(sc_card_t *card, const u8 * crgram, size_t crgram_len,
				u8 * out, size_t outlen)
{
	auth_senv_t *senv = &((struct auth_private_data *) card->drv_data)->senv;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	sc_debug(card->ctx,": crgram_len %i;  outlen %i\n", crgram_len, outlen);
	if (!out || !outlen || crgram_len > SC_MAX_APDU_BUFFER_SIZE) 
		return SC_ERROR_INVALID_ARGUMENTS;
	
	if (!senv->key_file_id)
		return SC_ERROR_INVALID_DATA;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.data = sbuf;
	apdu.resp = (u8 *) malloc(SC_MAX_APDU_BUFFER_SIZE);
	if (!apdu.resp)
		return SC_ERROR_OUT_OF_MEMORY;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	
	switch (senv->algorithm)   {
	case SC_ALGORITHM_RSA:
		sc_debug(card->ctx, "algorithm SC_ALGORITHM_RSA\n");
		if (crgram_len != 64 && crgram_len != 128 && crgram_len != 256)   {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto done;
		}
		else if (outlen < senv->key_size/8)   {
			sc_error(card->ctx, "dechipher result length (%i) "
					"should be at least key_size/8 (%i) bytes\n",
					outlen, senv->key_size/8);
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto done;
		}
				
		if (senv->key_size==2048)   {
			int nn;
			if (prv->aid.tag == AID_OBERTHUR_V5)   
				nn = 8;
			else   
				nn = 1;
			
			apdu.cla |= 0x10;
			memcpy(sbuf, crgram, nn);
			apdu.lc = nn;
			apdu.datalen = nn;
			apdu.le = senv->key_size/8;
			
			rv = sc_transmit_apdu(card, &apdu);
			SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
			SC_TEST_RET(card->ctx, rv, "Card returned error");
		
			crgram_len -= nn;
			crgram += nn;

			apdu.cla &= ~0x10;
		}

		break;
	case SC_ALGORITHM_DES:
	case SC_ALGORITHM_3DES:
		sc_debug(card->ctx,"algorithm SC_ALGORITHM_DES\n");
		if (crgram_len == 0 || (crgram_len%8) != 0)  {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto done;
		}
		break;
	default:
		sc_error(card->ctx, "Invalid crypto algorithm supplied.\n");
		rv = SC_ERROR_NOT_SUPPORTED;
		goto done;
	}
		
	apdu.data = sbuf;
	memcpy(sbuf, crgram, crgram_len);
	apdu.lc = crgram_len;
	apdu.datalen = crgram_len;
	apdu.le = senv->key_size/8;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	if (apdu.resplen > senv->key_size/8)   {
		sc_error(card->ctx, "invalide response length %i\n", apdu.resplen);
		rv = SC_ERROR_CARD_CMD_FAILED;
		goto done;
	}
	
	memcpy(out, apdu.resp, apdu.resplen);
	rv = apdu.resplen;

done:
	if (apdu.resp)
		free(apdu.resp);

	sc_debug(card->ctx, "return decipher len %i\n", rv);
	return rv;
}

/* Return the default AAK for this type of card */
static int 
auth_get_default_key(sc_card_t *card, struct sc_cardctl_default_key *data)
{
	return SC_ERROR_NO_DEFAULT_KEY;
}


static int 
auth_encode_exponent(unsigned long exponent, u8 *buff, size_t buff_len)
{
	int    shift;
	size_t ii;

	for (shift=0; exponent >> (shift+8); shift += 8)
		;
	
	for (ii = 0; ii<buff_len && shift>=0 ; ii++, shift-=8) 
		*(buff + ii) = (exponent >> shift) & 0xFF;

	if (ii==buff_len)
		return 0;
	else
		return ii;
}


/* Generate key on-card */
static int 
auth_generate_key(sc_card_t *card, struct sc_cardctl_oberthur_genkey_info *data)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv = 0;
	
	sc_debug(card->ctx, " %i bits\n",data->key_bits);
	if (data->key_bits < 512 || data->key_bits > 2048 || 
			(data->key_bits%0x20)!=0)   {
		sc_error(card->ctx, "Illegal key length: %d\n", data->key_bits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	sbuf[0] = (data->id_pub >> 8) & 0xFF;
	sbuf[1] = data->id_pub & 0xFF;
	sbuf[2] = (data->id_prv >> 8) & 0xFF;
	sbuf[3] = data->id_prv & 0xFF;
	if (data->exponent != 0x10001)   {
		rv = auth_encode_exponent(data->exponent, &sbuf[5],SC_MAX_APDU_BUFFER_SIZE-6);
		if (!rv)  {
			sc_error(card->ctx, "Cannot encode exponent\n");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		sbuf[4] = rv;
		rv++;
	}
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x46, 0x00, 0x00);
	if (!(apdu.resp = (u8 *) malloc(data->key_bits/8+8)))   {
		sc_error(card->ctx, "Cannot allocate memory\n");
		return SC_ERROR_OUT_OF_MEMORY;
	}
	apdu.resplen = data->key_bits/8+8;
	apdu.lc = rv + 4;
	apdu.le = data->key_bits/8;
	apdu.data = sbuf;
	apdu.datalen = rv + 4;;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	if (apdu.resplen == 0) {
		struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;

		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC,
				prv->aid.tag == AID_OBERTHUR_V5 ? 1 : 2, 
				apdu.resp, data->key_bits/8);
		SC_TEST_RET(card->ctx, rv, "auth_read_component() returned error");
		if (rv<0)
			return rv;
		
		apdu.resplen = rv;
	}
	if (data->pubkey)   {
		if (data->pubkey_len < apdu.resplen)   
			return SC_ERROR_INVALID_ARGUMENTS;
		memcpy(data->pubkey,apdu.resp,apdu.resplen);
	}

	data->pubkey_len = apdu.resplen;
	free(apdu.resp);
	
	sc_debug(card->ctx, "resulted public key len %i\n", apdu.resplen);
	return 0;
}


static int
auth_update_component(sc_card_t *card, struct sc_cardctl_oberthur_updatekey_info *args)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE + 0x10];
	u8 ins, p1, p2;
	int rv, len;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;
	
	sc_debug(card->ctx, ": nn %i; len %i\n", args->component, args->len);
	if (args->len > sizeof(sbuf) || args->len > 0x100)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_debug(card->ctx, "nn %i; len %i\n", args->component, args->len);
	ins = 0xD8;
	p1 = args->component;
	p2 = 0x04;
	len = 0;
	if (prv->aid.tag == AID_OBERTHUR_V5)   {
		sc_debug(card->ctx, "nn %i; len %i\n", args->component, args->len);
		sbuf[len++] = args->type;
		sbuf[len++] = args->len;
		memcpy(sbuf + len, args->data, args->len);
		len += args->len;
		
		if (args->type == SC_CARDCTL_OBERTHUR_KEY_DES)   {
			unsigned char in[8];
			unsigned char out[8];
			DES_cblock kk;
			DES_key_schedule ks;

			assert(DES_KEY_SZ==8);
			
			if (args->len!=8 && args->len!=24)
				return SC_ERROR_INVALID_ARGUMENTS;
		
			p2 = 0;
			memset(in, 0, sizeof(in));
			memcpy(&kk, args->data, 8);
			DES_set_key_unchecked(&kk,&ks);
			DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks, DES_ENCRYPT);
			if (args->len==24)   {
				sc_debug(card->ctx, "nn %i; len %i\n", args->component, args->len);
				memcpy(&kk, args->data + 8, 8);
				DES_set_key_unchecked(&kk,&ks);
				memcpy(in, out, 8);
				DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks, DES_DECRYPT);
				
				sc_debug(card->ctx, "nn %i; len %i\n", args->component, args->len);
				memcpy(&kk, args->data + 16, 8);
				DES_set_key_unchecked(&kk,&ks);
				memcpy(in, out, 8);
				DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks, DES_ENCRYPT);
			}

			sbuf[len++] = 0x03;
			memcpy(sbuf + len, out, 3);
			len += 3;
		}
		else   {
			sbuf[len++] = 0;
		}
	}
	else   {
		ins = 0xDC;
		memcpy(sbuf + len, args->data, args->len);
   	    len += args->len;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins,	p1, p2);
	apdu.cla |= 0x80;
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;
	apdu.sensitive = 1;
	if (args->len == 0x100)   {
		if (prv->aid.tag == AID_OBERTHUR_V5)   {
			sbuf[0] = args->type;
			sbuf[1] = 0x20;
			memcpy(sbuf + 2, args->data, 0x20);
			sbuf[0x22] = 0;
			apdu.cla |= 0x10;
			apdu.data = sbuf;
			apdu.datalen = 0x23;
			apdu.lc = 0x23;
			rv = sc_transmit_apdu(card, &apdu);
			apdu.cla &= ~0x10;
			SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
			
			sbuf[0] = args->type;
			sbuf[1] = 0xE0;
			memcpy(sbuf + 2, args->data + 0x20, 0xE0);
			sbuf[0xE2] = 0;
			apdu.data = sbuf;
			apdu.datalen = 0xE3;
			apdu.lc = 0xE3;
		}
		else   {
			apdu.cla |= 0x10;
			apdu.datalen = 1;
			apdu.lc = 1;
			rv = sc_transmit_apdu(card, &apdu);
			apdu.cla &= ~0x10;
			SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
			
			apdu.data = sbuf + 1;
			apdu.datalen = 255;
			apdu.lc = 255;
		}
	}

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card return error");
	return rv;
}


	static int 
auth_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return auth_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_OBERTHUR_GENERATE_KEY:
		return auth_generate_key(card,
				(struct sc_cardctl_oberthur_genkey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_UPDATE_KEY:
		return auth_update_component(card, 
				(struct sc_cardctl_oberthur_updatekey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_CREATE_PIN:
		return auth_create_reference_data(card,
				(struct sc_cardctl_oberthur_createpin_info *) ptr); 
    case SC_CARDCTL_GET_SERIALNR:
        return auth_get_serialnr(card, (sc_serial_number_t *)ptr);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}


static int
auth_read_component(sc_card_t *card, enum SC_CARDCTL_OBERTHUR_KEY_TYPE type, 
		int num, unsigned char *out, size_t outlen)
{
	int rv;
	sc_apdu_t apdu;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];

	sc_debug(card->ctx, ": num %i, outlen %i, type %i\n", num, outlen, type);
	if (type!=SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)
		return SC_ERROR_NO_CARD_SUPPORT;
	else if (!outlen)
		return SC_ERROR_INCORRECT_PARAMETERS;
	
	if (prv->aid.tag == AID_OBERTHUR_V5)   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB4,	num, 0x00);
		apdu.cla |= 0x80;
		apdu.le = outlen;
		apdu.resp = resp;
		apdu.resplen = sizeof(resp);
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, rv, "Card returned error");
		
		if (outlen < apdu.resplen)
			return SC_ERROR_WRONG_LENGTH;
		
		memcpy(out, apdu.resp, apdu.resplen);
		return 	apdu.resplen;
	}
	else   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2,	num, 0x04);
		apdu.cla |= 0x80;
		apdu.le = outlen;
		apdu.resp = resp;
		apdu.resplen = sizeof(resp);
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, rv, "Card returned error");
		
		if (outlen < apdu.resplen)
			return SC_ERROR_WRONG_LENGTH;

		memcpy(out, apdu.resp, apdu.resplen);
		return 	apdu.resplen;
	}
}


static int auth_get_pin_reference (sc_card_t *card, 
	 int type, int reference, int cmd, int *out_ref)
{
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;

	if (!card || !out_ref)
		return SC_ERROR_INVALID_ARGUMENTS;
    
	switch (prv->aid.tag)   {
    case AID_OBERTHUR_V5 :
		switch (type) {
		case SC_AC_CHV:
			if (reference == 1)   {
				if (cmd==SC_PIN_CMD_VERIFY)
					*out_ref = 0x81;
				else
					*out_ref = 0x01;
			}
			else if (reference == 2)
				*out_ref = 0x04;
			else
				return SC_ERROR_INVALID_PIN_REFERENCE;
			break;

		default:
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	return 0;
}


static void 
auth_init_pin_info(sc_card_t *card, struct sc_pin_cmd_pin *pin, 
		unsigned int type)
{
	struct auth_private_data *data = (struct auth_private_data *) card->drv_data;
	
	pin->offset	 = 0;
	pin->pad_char   = 0xFF;
	pin->encoding   = SC_PIN_ENCODING_ASCII;
	
    switch (data->aid.tag)   {
	case AID_OBERTHUR_V5 :
		if (type==AUTH_PIN)   {
			pin->max_length = 64;
			pin->pad_length = 64;
		}
		else    {
			pin->max_length = 16;
			pin->pad_length = 16;
		}
		break;
	}
}

#if 0
static int
auth_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data,
	int *tries_left)
{
	int rv, pin_ref;
	
	rv = auth_get_pin_reference (card, data->pin_type, 1, SC_PIN_CMD_VERIFY, &pin_ref);
	if (rv)
		return rv;
		
	data->pin_reference = pin_ref;
	return iso_ops->pin_cmd(card, data, tries_left);
}
#endif

static int
auth_verify(sc_card_t *card, unsigned int type,
	int ref, const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int rv, pin_ref;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pinfo;

	sc_debug(card->ctx,": type %i; ref %i, data_len %i\n", type, ref, data_len);
	if (ref == 3)   {
		rv = auth_get_pin_reference (card, type, 1, SC_PIN_CMD_VERIFY, &pin_ref);
		if (rv)
			return rv;

    	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_ref);
    	apdu.lc = 0x0;
	    apdu.le = 0x0;
		apdu.resplen = 0;
		apdu.resp = NULL;
		apdu.p2 = pin_ref;
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)   {
			rv = auth_get_pin_reference (card, type, 2, SC_PIN_CMD_VERIFY, &pin_ref);
	        if (rv)
				return rv;
			
			apdu.p2 = pin_ref;
	    	rv = sc_transmit_apdu(card, &apdu);
			SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		}
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00 )   {
			if (data && data_len > 1 && *data!=ref && !isalnum(*data))   {
				rv = auth_verify(card, type, *data, 
						data+1, data_len - 1, tries_left);
			}
		}
		
		return rv;
	}

	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_VERIFY, &pin_ref);
	if (rv)
		return rv;
	sc_debug(card->ctx, " pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &pinfo, AUTH_PIN);
	if (data_len > pinfo.pad_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	memset(sbuf, pinfo.pad_char, pinfo.pad_length);
	memcpy(sbuf, data, data_len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_ref);
	apdu.data = sbuf;
	apdu.datalen = pinfo.pad_length;
	apdu.lc = pinfo.pad_length;
	apdu.sensitive = 1;
	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) 
		*tries_left = apdu.sw2 & 0x0F;
	
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return rv;
}


static int 
auth_change_reference_data (sc_card_t *card, unsigned int type,
		int ref, const u8 *old, size_t oldlen,
		const u8 *_new, size_t newlen, int *tries_left)
{
	sc_apdu_t apdu;
	int rv, pin_ref;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pinfo;
	
	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_CHANGE, &pin_ref);
	if (rv)
		return rv;
	sc_debug(card->ctx, " pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &pinfo, AUTH_PIN);
	
	if (oldlen > pinfo.pad_length || newlen > pinfo.pad_length)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	memset(sbuf, pinfo.pad_char, pinfo.pad_length * 2);
	memcpy(sbuf, old, oldlen);
	memcpy(sbuf + pinfo.pad_length, _new, newlen);
		
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, pin_ref);
	apdu.data = sbuf;
	apdu.datalen = pinfo.pad_length * 2;
	apdu.lc = pinfo.pad_length * 2;
	apdu.sensitive = 1;

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) 
		*tries_left = apdu.sw2 & 0x0F;

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	return rv;
}


static int 
auth_reset_retry_counter(sc_card_t *card, unsigned int type,
		int ref, const u8 *puk, size_t puklen,
        const u8 *pin, size_t pinlen)
{
	sc_apdu_t apdu;
	int rv, pin_ref;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pin_info, puk_info;
	
	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_UNBLOCK, &pin_ref);
	if (rv)
		return rv;
	sc_debug(card->ctx, " pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &puk_info, AUTH_PUK);
	auth_init_pin_info(card, &pin_info, AUTH_PIN);
	
	if (puklen > puk_info.pad_length || pinlen > pin_info.pad_length)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(sbuf, puk_info.pad_char, puk_info.pad_length);
	memcpy(sbuf, puk, puklen);
	len = puk_info.pad_length;
	if (pin && pinlen)   {
		memset(sbuf + len,  pin_info.pad_char, pin_info.pad_length);
		memcpy(sbuf + len,  pin, pinlen);
		len += pin_info.pad_length;
	}
		
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, 
			len == puk_info.pad_length ? 1 : 0, pin_ref);
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;
	apdu.sensitive = 1;

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	return rv;
}


static int 
auth_create_reference_data (sc_card_t *card, 
		struct sc_cardctl_oberthur_createpin_info *args)
{
	sc_apdu_t apdu;
	int rv, pin_ref, len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pin_info, puk_info;
	struct auth_private_data *prv = (struct auth_private_data *) card->drv_data;
	
	if (args->pin_tries < 1 || !args->pin || !args->pin_len)
		return SC_ERROR_INVALID_ARGUMENTS;
	
    if (prv->aid.tag == AID_OBERTHUR_V5 && args->type == SC_AC_CHV)   {
		if (args->ref == 1)  
		    pin_ref = 0x01;
		else if (args->ref == 2)
			pin_ref = 0x04;
		else
			return SC_ERROR_INVALID_PIN_REFERENCE;
	}
	else
		return SC_ERROR_INVALID_ARGUMENTS;
		
	
	sc_debug(card->ctx, " pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &puk_info, AUTH_PUK);
	auth_init_pin_info(card, &pin_info, AUTH_PIN);

	if (args->puk && args->puk_len && (args->puk_len%puk_info.pad_length))
		return SC_ERROR_INVALID_ARGUMENTS;
		
	len = 0;
	sbuf[len++] = args->pin_tries;
	sbuf[len++] = pin_info.pad_length;
	memset(sbuf + len, pin_info.pad_char, pin_info.pad_length);
	memcpy(sbuf + len, args->pin, args->pin_len);
	len += pin_info.pad_length;

	if (args->puk && args->puk_len)   {
		sbuf[len++] = args->puk_tries;
		sbuf[len++] = args->puk_len / puk_info.pad_length;
		memcpy(sbuf + len, args->puk, args->puk_len);
		len += args->puk_len;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 1, pin_ref);
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;
	apdu.sensitive = 1;

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	return rv;
}


static int 
auth_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int rv, pin_ref;
	struct auth_private_data *data = (struct auth_private_data *) card->drv_data;
	int reset_flag = (data->aid.tag == AID_OBERTHUR_V5) ? 0x20 : 0x00;
	
	rv = auth_get_pin_reference (card, SC_AC_CHV, 1, SC_PIN_CMD_UNBLOCK, &pin_ref);
	if (rv)
		return rv;

    sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x00);
    apdu.cla = 0x80;
    apdu.lc = 0x0;
    apdu.le = 0x0;
	apdu.resplen = 0;
	apdu.resp = NULL;
	apdu.p2 = pin_ref | reset_flag;
	rv = sc_transmit_apdu(card, &apdu);
	
	rv = auth_get_pin_reference (card, SC_AC_CHV, 2, SC_PIN_CMD_UNBLOCK, &pin_ref);
	if (rv)
		return rv;
	
	apdu.p2 = pin_ref | reset_flag;
    rv = sc_transmit_apdu(card, &apdu);

	return rv;
}

static int 
write_publickey (sc_card_t *card, unsigned int offset,
				const u8 *buf, size_t count)
{
	int ii, rv;
	struct sc_pkcs15_pubkey_rsa key;
	size_t len = 0, der_size = 0;
	struct sc_cardctl_oberthur_updatekey_info args;

	if (card->ctx->debug >= 5)  {
		char debug_buf[2048];
		
		debug_buf[0] = 0;
		sc_hex_dump(card->ctx, buf, count, debug_buf, sizeof(debug_buf));
		sc_debug(card->ctx, "write_publickey in %d bytes :\n%s", count, debug_buf);
	}

	if (offset > sizeof(rsa_der))
		return SC_ERROR_INVALID_ARGUMENTS;

	len = offset+count > sizeof(rsa_der) ? sizeof(rsa_der) - offset : count;
		
	memcpy(rsa_der + offset, buf, len);
	rsa_der_len = offset + len;
		
	if (rsa_der[0]==0x30)   {
		if (rsa_der[1] & 0x80)   
			for (ii=0; ii < (rsa_der[1]&0x0F); ii++)
				der_size = der_size*0x100 + rsa_der[2+ii];
		else
			der_size = rsa_der[1];
	}
	
	sc_debug(card->ctx, " der_size %i\n",der_size);
	if (offset + len < der_size + 2)
		return len;

	rv = sc_pkcs15_decode_pubkey_rsa(card->ctx, &key, rsa_der, rsa_der_len);
	rsa_der_len = 0;
	memset(rsa_der, 0, sizeof(rsa_der));
	if (rv)   {
		sc_error(card->ctx, " cannot decode public key\n");
		return SC_ERROR_INVALID_ASN1_OBJECT;			
	}
	
	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 1;
	args.data = key.modulus.data;
	args.len = key.modulus.len;
	rv = auth_update_component(card, &args);
	if (rv)
		goto end;

	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 2;
	args.data = key.exponent.data;
	args.len = key.exponent.len;
	rv = auth_update_component(card, &args);
	if (rv >= 0)
		rv = len;

end:		
	card->cla &= ~0x80;
	return rv;
}
	

static int
auth_update_binary(sc_card_t *card, unsigned int offset,
		const u8 *buf, size_t count, unsigned long flags)
{
	int rv = 0;

	sc_debug(card->ctx, "; offset %i; count %i\n", offset, count);
	sc_debug(card->ctx, "; last selected : magic %X; ef %X\n", 
			last_selected_file.magic, last_selected_file.ef_structure);
	if (offset & ~0x7FFF) {
		sc_error(card->ctx, "Invalid file offset %u",offset);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (last_selected_file.magic==SC_FILE_MAGIC && 
			 last_selected_file.ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  { 
		rv = write_publickey(card, offset, buf, count);
	}
	else if (last_selected_file.magic==SC_FILE_MAGIC && 
			last_selected_file.ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		struct sc_cardctl_oberthur_updatekey_info args;
	
		memset(&args, 0, sizeof(args));
		args.type = SC_CARDCTL_OBERTHUR_KEY_DES;
		args.component = 0;
		args.data = buf;
		args.len = count;
		rv = auth_update_component(card, &args);
	}
	else   {
		rv = iso_ops->update_binary(card, offset, buf, count, 0);
	}

	SC_TEST_RET(card->ctx, rv, "Card returned error");	
	return rv;
}


static int
auth_read_binary(sc_card_t *card, unsigned int offset,
		u8 *buf, size_t count, unsigned long flags)
{
	int rv;
	struct auth_private_data *data = (struct auth_private_data *) card->drv_data;
	
	sc_debug(card->ctx,"; offset %i; size %i; flags 0x%lX\n", offset, count, flags);
	sc_debug(card->ctx,"; last selected : magic %X; ef %X\n", 
			last_selected_file.magic, last_selected_file.ef_structure);
	if (offset & ~0x7FFF) {
		sc_error(card->ctx, "Invalid file offset %u",offset);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (last_selected_file.magic==SC_FILE_MAGIC &&
             last_selected_file.ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)   {
		int jj;
		unsigned char resp[0x100], *out = NULL;
		size_t resp_len, out_len;
		struct sc_pkcs15_bignum bn[2];
		struct sc_pkcs15_pubkey_rsa key;

		resp_len = sizeof(resp);
		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC, 
				data->aid.tag == AID_OBERTHUR_V5 ? 2 : 1,
				resp, resp_len);
		if (rv<0)
			return rv;
		
		for (jj=0; jj<rv && *(resp+jj)==0; jj++)
			;

		bn[0].data = (u8 *) malloc(rv - jj);
		bn[0].len = rv - jj;
		memcpy(bn[0].data, resp + jj, rv - jj);
		
		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC, 
				data->aid.tag == AID_OBERTHUR_V5 ? 1 : 2,
				resp, resp_len);
		if (rv <= 0)
			return rv;
		bn[1].data = (u8 *) malloc(rv);
		bn[1].len = rv;
		memcpy(bn[1].data, resp, rv);

		key.exponent = bn[0];
		key.modulus = bn[1];
			
		if (sc_pkcs15_encode_pubkey_rsa(card->ctx, &key, &out, &out_len)) {
			sc_error(card->ctx, "cannot decode public key\n");
			rv =  SC_ERROR_INVALID_ASN1_OBJECT;
		}
		else {
			rv  = out_len - offset > count ? count : out_len - offset;
			memcpy(buf, out + offset, rv);
			if (card->ctx->debug >= 5)  {
				char debug_buf[2048];
		
				debug_buf[0] = 0;
				sc_hex_dump(card->ctx, buf, rv, debug_buf, sizeof(debug_buf));
				sc_debug(card->ctx, "write_publickey in %d bytes :\n%s", 
						count, debug_buf);
			}
		}
		
		if (bn[0].data) free(bn[0].data);
		if (bn[1].data) free(bn[1].data);
		if (out) free(out);
	}
	else	 { 
		rv = iso_ops->read_binary(card, offset, buf, count, 0);	
	}

	SC_TEST_RET(card->ctx, rv, "Card returned error");
	return rv;
}


static int
auth_delete_record(sc_card_t *card, unsigned int nr_rec)
{
	int rv = 0;
	sc_apdu_t apdu;

	sc_debug(card->ctx, "auth_delete_record(): nr_rec %i\n", nr_rec);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x32, nr_rec, 0x04);
	apdu.cla = 0x80;
	apdu.lc = 0x0;
	apdu.le = 0x0;
	apdu.resplen = 0;
	apdu.resp = NULL;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	return rv;
}
		
static int
auth_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	if (!card || !serial)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (card->serialnr.len==0)
		return SC_ERROR_INTERNAL;

	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

static struct sc_card_driver * 
sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	auth_ops = *iso_ops;
	auth_ops.match_card = auth_match_card;
	auth_ops.init = auth_init;
	auth_ops.finish = auth_finish;
	auth_ops.select_file = auth_select_file;
	auth_ops.list_files = auth_list_files;
	auth_ops.delete_file = auth_delete_file;
	auth_ops.create_file = auth_create_file;
	auth_ops.read_binary = auth_read_binary;
	auth_ops.update_binary = auth_update_binary;
	auth_ops.delete_record = auth_delete_record;
	auth_ops.card_ctl = auth_card_ctl;
	auth_ops.set_security_env = auth_set_security_env;
	auth_ops.restore_security_env = auth_restore_security_env;
	auth_ops.compute_signature = auth_compute_signature;
	auth_ops.decipher = auth_decipher;

/* not yet */	
#if 0	
	auth_ops.pin_cmd = auth_pin_cmd;
#else
	auth_ops.pin_cmd = NULL;
#endif
	auth_ops.verify = auth_verify;
	auth_ops.reset_retry_counter = auth_reset_retry_counter;
	auth_ops.change_reference_data = auth_change_reference_data;
	
	auth_ops.logout = auth_logout;
	return &auth_drv;
}


struct sc_card_driver * 
sc_get_oberthur_driver(void)
{
	return sc_get_driver();
}

#endif /* HAVE_OPENSSL */
