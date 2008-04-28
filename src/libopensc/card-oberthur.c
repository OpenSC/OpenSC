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

#ifdef ENABLE_OPENSSL
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

/* keep OpenSSL 0.9.6 users happy ;-) */
#if OPENSSL_VERSION_NUMBER < 0x00907000L
#define DES_cblock			des_cblock
#define DES_key_schedule		des_key_schedule
#define DES_set_key_unchecked(a,b)	des_set_key_unchecked(a,*b)
#define DES_ecb_encrypt(a,b,c,d) 	des_ecb_encrypt(a,b,*c,d)
#endif

#define NOT_YET 1

static struct sc_atr_table oberthur_atrs[] = {
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL, 
			"Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL, 
			"Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL, 
			"Oberthur 64k v5", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL, 
			"Oberthur 64k v5/2.2.0", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7B:18:00:00:00:31:C0:64:77:E3:03:00:82:90:00", NULL, 
			"Oberthur 64k CosmopolIC v5.2/2.2", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct auth_senv {
	unsigned int algorithm;
	int key_file_id;
	size_t key_size;
};
typedef struct auth_senv auth_senv_t;

struct auth_private_data {
	unsigned char aid[SC_MAX_AID_SIZE];
	int aid_len;
	
	struct sc_pin_cmd_pin pin_info;
	auth_senv_t senv;
	
	long int sn;
};
typedef struct auth_private_data auth_private_data_t;

struct auth_update_component_info {
	enum SC_CARDCTL_OBERTHUR_KEY_TYPE  type;
	unsigned int    component;
	unsigned char   *data;
	unsigned int    len;
};
typedef struct auth_update_component_info auth_update_component_info_t;


static const unsigned char *aidAuthentIC_V5 = 
		(const u8 *)"\xA0\x00\x00\x00\x77\x01\x03\x03\x00\x00\x00\xF1\x00\x00\x00\x02";
static const int lenAidAuthentIC_V5 = 16; 
static const char *nameAidAuthentIC_V5 = "AuthentIC v5"; 

#define AUTH_PIN		1
#define AUTH_PUK		2

#define SC_OBERTHUR_MAX_ATTR_SIZE	8

#define PUBKEY_512_ASN1_SIZE	0x4A
#define PUBKEY_1024_ASN1_SIZE	0x8C
#define PUBKEY_2048_ASN1_SIZE	0x10E

static unsigned char rsa_der[PUBKEY_2048_ASN1_SIZE];
static int rsa_der_len = 0;

static sc_file_t *auth_current_ef = NULL,  *auth_current_df = NULL;
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
static int auth_select_file(sc_card_t *card, const sc_path_t *in_path,
		sc_file_t **file_out);

#ifndef NOT_YET
static int auth_sm_init (struct sc_card *card, struct sc_sm_info *sm_info, 
		int cmd, unsigned char *id, size_t id_len,
		unsigned char *resp, size_t *resp_len);
static int auth_sm_execute (struct sc_card *card, struct sc_sm_info *sm_info, 
		unsigned char *data, int data_len, unsigned char *out, size_t len);
static int auth_sm_update_rsa (struct sc_card *card,
		struct sc_cardctl_oberthur_updatekey_info *data);
static int auth_sm_reset_pin (struct sc_card *card, int type, int ref,
		const unsigned char *data, size_t len);
static int auth_sm_read_binary (struct sc_card *card, 
		unsigned char *id, size_t id_len, 
		size_t offs, unsigned char *out, size_t len);
static int auth_sm_release (struct sc_card *card, struct sc_sm_info *sm_info,
		unsigned char *data, int data_len);
#endif

#if 0
/* this function isn't used anywhere */
static void _auth_print_acls(struct sc_card *card, struct sc_file *file)
{
	int ii, jj;   
	
	for (jj=0; jj < SC_MAX_AC_OPS; jj++)   {
		const sc_acl_entry_t *acl = sc_file_get_acl_entry(file, jj);
			
		for (ii=0; acl; acl = acl->next, ii++) {
			sc_debug(card->ctx, "%i-%i: acl : meth 0x%X, ref 0x%X", 
					jj, ii, acl->method, acl->key_ref);
		}
	}
}
#endif

static int 
auth_finish(sc_card_t *card)
{
	free(card->drv_data);
	return SC_SUCCESS;
}


static int 
auth_select_aid(sc_card_t *card)
{
	sc_apdu_t apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	struct auth_private_data *data =  (struct auth_private_data *) card->drv_data;
	int rv, ii;
	unsigned char cm[7] = {0xA0,0x00,0x00,0x00,0x03,0x00,0x00};
	sc_path_t tmp_path;

	/* Select Card Manager (to deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x04, 0x0C);
	apdu.lc = sizeof(cm);
	/* apdu.le = sizeof(cm)+4; */
	apdu.le = 0;
	apdu.data = cm;
	apdu.datalen = sizeof(cm);
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	
	/* Get smart card serial number */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x9F, 0x7F);
	apdu.cla = 0x80;
	apdu.le = 0x2D;
	apdu.resplen = 0x30;
	apdu.resp = apdu_resp;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	card->serialnr.len = 4;
	memcpy(card->serialnr.value, apdu.resp+15, 4);

	for (ii=0, data->sn = 0; ii < 4; ii++) 
		data->sn += (int)(*(apdu.resp + 15 + ii)) << (3-ii)*8;
	
	sc_debug(card->ctx, "serial number %li/0x%lX\n", data->sn, data->sn);
		
	tmp_path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(tmp_path.value, aidAuthentIC_V5, lenAidAuthentIC_V5);
	tmp_path.len = lenAidAuthentIC_V5;

	rv = iso_ops->select_file(card, &tmp_path, NULL);
	sc_debug(card->ctx, "rv %i\n", rv);
	SC_TEST_RET(card->ctx, rv, "select parent failed");
	
	sc_format_path("3F00", &tmp_path);
	rv = iso_ops->select_file(card, &tmp_path, &auth_current_df);
	sc_debug(card->ctx, "rv %i\n", rv);
	SC_TEST_RET(card->ctx, rv, "select parent failed");
	
	sc_format_path("3F00", &card->cache.current_path);
	sc_file_dup(&auth_current_ef, auth_current_df);
		
	memcpy(data->aid, aidAuthentIC_V5, lenAidAuthentIC_V5);
	data->aid_len = lenAidAuthentIC_V5;
	card->name = nameAidAuthentIC_V5;

	sc_debug(card->ctx, "return %i\n", rv);
	SC_FUNC_RETURN(card->ctx, 1, rv);
}

static int 
auth_match_card(sc_card_t *card)
{
	if (_sc_match_atr(card, oberthur_atrs, &card->type) < 0)
		return 0;
	else
		return 1;
}

static int 
auth_init(sc_card_t *card)
{
	int rv = 0;
	unsigned long flags;
	struct auth_private_data *data;
	sc_path_t path;
	
	data = (struct auth_private_data *) malloc(sizeof(struct auth_private_data));
	if (!data)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	else
		memset(data, 0, sizeof(struct auth_private_data));

	card->cla = 0x00;
	card->drv_data = data;

	card->caps |= SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	if (auth_select_aid(card))   {
		sc_error(card->ctx, "Failed to initialize %s\n", card->name);
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_CARD, "Failed to initialize");
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

	sc_format_path("3F00", &path);
   	rv = auth_select_file(card, &path, NULL);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static void 
add_acl_entry(sc_card_t *card, sc_file_t *file, unsigned int op, 
		u8 acl_byte)
{
	if ((acl_byte & 0xE0) == 0x60)   {
		sc_debug(card->ctx, "called; op 0x%X; SC_AC_PRO; ref 0x%X\n", op, acl_byte);
		sc_file_add_acl_entry(file, op, SC_AC_PRO, acl_byte);
		return;
	}
	
	switch (acl_byte) {
	case 0x00:
		sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE);
		break;
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:
	case 0x25:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, acl_byte & 0x0F);
		break;
	case 0xFF:
		sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		break;
	default:
		sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
		break;
	}
}


static int 
tlv_get(const unsigned char *msg, int len,
		unsigned char tag, 
		unsigned char *ret, int *ret_len)
{
	int cur = 0;
	
	while (cur < len)  { 
		if (*(msg+cur)==tag)  {
			int ii, ln = *(msg+cur+1);
		
			if (ln > *ret_len)   
				return SC_ERROR_WRONG_LENGTH;

			for (ii=0; ii<ln; ii++)
				*(ret + ii) = *(msg+cur+2+ii);
			*ret_len = ln;
			
			return SC_SUCCESS;
		}
		
		cur += 2 + *(msg+cur+1);
	}
		
	return SC_ERROR_INCORRECT_PARAMETERS;
}


static int
auth_process_fci(struct sc_card *card, struct sc_file *file,
            const unsigned char *buf, size_t buflen)
{
	unsigned char type, attr[SC_OBERTHUR_MAX_ATTR_SIZE];
	int attr_len = sizeof(attr);
	
	SC_FUNC_CALLED(card->ctx, 1);
	attr_len = sizeof(attr);
	if (tlv_get(buf, buflen, 0x82, attr, &attr_len))
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	type = attr[0];
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, buflen, 0x83, attr, &attr_len))
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	file->id = attr[0]*0x100 + attr[1];
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, buflen, type==0x01 ? 0x80 : 0x85, attr, &attr_len))
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	if (attr_len<2 && type != 0x04)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		
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
		if (tlv_get(buf, buflen, 0x82, attr, &attr_len))
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		if (attr_len!=5)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
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
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
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
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	
	attr_len = sizeof(attr);
	if (tlv_get(buf, buflen, 0x86, attr, &attr_len))
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	if (attr_len<8)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (file->type == SC_FILE_TYPE_DF) {
		add_acl_entry(card, file, SC_AC_OP_CREATE, attr[0]);
		add_acl_entry(card, file, SC_AC_OP_CRYPTO, attr[1]);
		add_acl_entry(card, file, SC_AC_OP_LIST_FILES, attr[2]);
		add_acl_entry(card, file, SC_AC_OP_DELETE, attr[3]);
#ifndef NOT_YET		
		add_acl_entry(card, file, SC_AC_OP_PIN_SET, attr[4]);
		add_acl_entry(card, file, SC_AC_OP_PIN_CHANGE, attr[5]);
		add_acl_entry(card, file, SC_AC_OP_PIN_RESET, attr[6]);
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

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


static int 
auth_select_file(sc_card_t *card, const sc_path_t *in_path,
				 sc_file_t **file_out)
{
	int rv;
	size_t offs, ii;
	sc_path_t path;
	sc_file_t *tmp_file = NULL;

	SC_FUNC_CALLED(card->ctx, 1);
	assert(card != NULL && in_path != NULL);

	memcpy(&path, in_path, sizeof(sc_path_t));
	
	sc_debug(card->ctx, "in_path; type=%d, path=%s, out %p\n", 
			in_path->type, sc_print_path(in_path), file_out);
	sc_debug(card->ctx, "current path; type=%d, path=%s\n", 
			auth_current_df->path.type, sc_print_path(&auth_current_df->path));
	if (auth_current_ef)
		sc_debug(card->ctx, "current file; type=%d, path=%s\n", 
				auth_current_ef->path.type, sc_print_path(&auth_current_ef->path));

	if (path.type == SC_PATH_TYPE_PARENT || path.type == SC_PATH_TYPE_FILE_ID)   {
		if (auth_current_ef)
			sc_file_free(auth_current_ef);
		auth_current_ef = NULL;
		
		rv = iso_ops->select_file(card, &path, &tmp_file);
		SC_TEST_RET(card->ctx, rv, "select file failed");
		
		if (path.type == SC_PATH_TYPE_PARENT)   {
			memcpy(&tmp_file->path, &auth_current_df->path, sizeof(sc_path_t));
			if (tmp_file->path.len > 2)
				tmp_file->path.len -= 2;
			
			sc_file_free(auth_current_df);
			sc_file_dup(&auth_current_df, tmp_file);
		}
		else   {
			if (tmp_file->type == SC_FILE_TYPE_DF)   {
				sc_concatenate_path(&tmp_file->path, &auth_current_df->path, &path);
				
				sc_file_free(auth_current_df);
				sc_file_dup(&auth_current_df, tmp_file);
			}
			else   {
				if (auth_current_ef)   
					sc_file_free(auth_current_ef);

				sc_file_dup(&auth_current_ef, tmp_file);
				sc_concatenate_path(&auth_current_ef->path, &auth_current_df->path, &path);
			}
		}
		if (file_out) 
			sc_file_dup(file_out, tmp_file);
	
		sc_file_free(tmp_file);
	}
	else if (path.type == SC_PATH_TYPE_DF_NAME)   {
		rv = iso_ops->select_file(card, &path, NULL);
		if (rv)   {
			if (auth_current_ef)
				sc_file_free(auth_current_ef);
			auth_current_ef = NULL;
		}
		SC_TEST_RET(card->ctx, rv, "select file failed");
	}
	else   {
		for (offs = 0; offs < path.len && offs < auth_current_df->path.len; offs += 2)  
			if (path.value[offs] != auth_current_df->path.value[offs] ||
					path.value[offs + 1] != auth_current_df->path.value[offs + 1])
				break;

		sc_debug(card->ctx, "offs %i\n", offs);
		if (offs && offs < auth_current_df->path.len)   {
			size_t deep = auth_current_df->path.len - offs;

			sc_debug(card->ctx, "deep %i\n", deep);
			for (ii=0; ii<deep; ii+=2)   {
				sc_path_t tmp_path;

				memcpy(&tmp_path, &auth_current_df->path,  sizeof(sc_path_t));
				tmp_path.type = SC_PATH_TYPE_PARENT;
				
				rv = auth_select_file (card, &tmp_path, file_out);
				SC_TEST_RET(card->ctx, rv, "select file failed");
			}
		}
	
		if (path.len - offs > 0)   {
			sc_path_t tmp_path;
			
			tmp_path.type = SC_PATH_TYPE_FILE_ID;
			tmp_path.len = 2;
			
			for (ii=0; ii < path.len - offs; ii+=2)   {
				memcpy(tmp_path.value, path.value + offs + ii, 2);
				
				rv = auth_select_file(card, &tmp_path, file_out);
				SC_TEST_RET(card->ctx, rv, "select file failed");
			}
		}
		else if (path.len - offs == 0 && file_out)  {
			if (sc_compare_path(&path, &auth_current_df->path))   
				sc_file_dup(file_out, auth_current_df);
			else  if (auth_current_ef)
				sc_file_dup(file_out, auth_current_ef);
			else
				SC_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "No current EF");
		}
	}

	SC_FUNC_RETURN(card->ctx, 1, 0);
}


static int 
auth_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;
	
	SC_FUNC_CALLED(card->ctx, 1);
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
		SC_FUNC_RETURN(card->ctx, 1, 0);
	
	buflen = buflen < apdu.resplen ? buflen : apdu.resplen;
	memcpy(buf, rbuf, buflen);
	
	SC_FUNC_RETURN(card->ctx, 1, buflen);
}


static int 
auth_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int rv;
	u8 sbuf[2];
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (card->ctx->debug >= 1) {
		char pbuf[SC_MAX_PATH_STRING_SIZE];

		rv = sc_path_print(pbuf, sizeof(pbuf), path);
		if (rv != SC_SUCCESS)
			pbuf[0] = '\0';

		sc_debug(card->ctx, "path; type=%d, path=%s\n", path->type, pbuf);
	}

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
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x02, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.sw1==0x6A && apdu.sw2==0x82)   {
		/* Clean the DF contents.*/
        sc_path_t tmp_path;
		u8 lbuf[SC_MAX_APDU_BUFFER_SIZE];
		int ii, len;
		
		tmp_path.type = SC_PATH_TYPE_FILE_ID;
		memcpy(tmp_path.value, sbuf, 2);
		tmp_path.len = 2;
		rv = auth_select_file(card, &tmp_path, NULL);
		SC_TEST_RET(card->ctx, rv, "select DF failed");
		
		len = auth_list_files(card, lbuf, sizeof(lbuf));
		SC_TEST_RET(card->ctx, len, "list DF failed");
		
		for (ii=0; ii<len/2; ii++)   {
			sc_path_t tmp_path_x;

			tmp_path_x.type = SC_PATH_TYPE_FILE_ID;
			tmp_path_x.value[0] = *(lbuf + ii*2);
			tmp_path_x.value[1] = *(lbuf + ii*2 + 1);
			tmp_path_x.len = 2;

			rv = auth_delete_file(card, &tmp_path_x);
			SC_TEST_RET(card->ctx, rv, "delete failed");
		}

		tmp_path.type = SC_PATH_TYPE_PARENT;
		rv = auth_select_file(card, &tmp_path, NULL);
		SC_TEST_RET(card->ctx, rv, "select parent failed");
		
		apdu.p1 = 1;
		rv = sc_transmit_apdu(card, &apdu);
	}
		
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
acl_to_ac_byte(sc_card_t *card, const sc_acl_entry_t *e)
{
	if (e == NULL)
		return -1;
	
	switch (e->method) {
	case SC_AC_NONE:
		SC_FUNC_RETURN(card->ctx, 1, 0);
		
	case SC_AC_CHV:
		if (e->key_ref > 0 && e->key_ref < 6)
			SC_FUNC_RETURN(card->ctx, 1, (0x20 | e->key_ref));
		else
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
		
	case SC_AC_PRO:
		if (((e->key_ref & 0xE0) != 0x60) || ((e->key_ref & 0x18) == 0))
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
		else
			SC_FUNC_RETURN(card->ctx, 1, e->key_ref);
											
	case SC_AC_NEVER:
		return 0xff;
	}
		
	SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
}


static int 
encode_file_structure_V5(sc_card_t *card, const sc_file_t *file,
				 u8 *buf, size_t *buflen)
{
	u8 *p = buf;
	int rv=0, size;
	size_t ii;
	unsigned char  ops[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "id %04X; size %i; type %i/%i\n",
			file->id, file->size, file->type, file->ef_structure);
	
	if (*buflen < 0x18)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);

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
			rv = SC_ERROR_INVALID_ARGUMENTS;
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
		rv = SC_ERROR_INVALID_ARGUMENTS;

	if (rv)   {
		sc_error(card->ctx, "Invalid EF structure %i/%i\n", 
				file->type, file->ef_structure);
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
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
		sc_debug(card->ctx, "ef %s\n","SC_FILE_EF_RSA_PUBLIC");
		if (file->size == PUBKEY_512_ASN1_SIZE || file->size == 512)
			size = 512;
		else if (file->size == PUBKEY_1024_ASN1_SIZE || file->size == 1024)
			size = 1024;
		else if (file->size == PUBKEY_2048_ASN1_SIZE || file->size == 2048)
			size = 2048;
		else   {
			sc_error(card->ctx, "incorrect RSA size %X\n", file->size);
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
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
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
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
#ifndef NOT_YET		
		ops[4] = SC_AC_OP_PIN_SET;  /* SC_AC_OP_SET_REFERENCE */
		ops[5] = SC_AC_OP_PIN_CHANGE;  /* SC_AC_OP_CHANGE_REFERENCE */
		ops[6] = SC_AC_OP_PIN_RESET;  /* SC_AC_OP_RESET_COUNTER */
#else
		ops[4] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_SET_REFERENCE */
		ops[5] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_CHANGE_REFERENCE */
		ops[6] = SC_AC_OP_LIST_FILES;  /* SC_AC_OP_RESET_COUNTER */						
#endif
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
			ops[1] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_DECRYPT */
			ops[2] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_ENCRYPT */
			ops[3] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_CHECKSUM */
			ops[4] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_CHECKSUM */
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  {
			sc_debug(card->ctx, "EF_RSA_PUBLIC\n");
			ops[0] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_ENCRYPT */
			ops[4] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_SIGN */
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)  {
			sc_debug(card->ctx, "EF_RSA_PRIVATE\n");
			ops[0] = SC_AC_OP_UPDATE;
			ops[1] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_ENCRYPT */
			ops[3] = SC_AC_OP_CRYPTO;  /* SC_AC_OP_SIGN */
		}
	}
	
	for (ii = 0; ii < sizeof(ops); ii++) {
		const sc_acl_entry_t *entry;
		
		p[16+ii] = 0xFF;
		if (ops[ii]==0xFF)
			continue;
		entry = sc_file_get_acl_entry(file, ops[ii]);
		rv = acl_to_ac_byte(card,entry);
		SC_TEST_RET(card->ctx, rv, "Invalid ACL");
		p[16+ii] = rv;
	}
	
	*buflen = 0x18;
	
	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


static int 
auth_create_file(sc_card_t *card, sc_file_t *file)
{
	u8 sbuf[0x18];
	size_t sendlen = sizeof(sbuf);
	int rv, rec_nr;
	sc_apdu_t apdu;
	sc_path_t path;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	SC_FUNC_CALLED(card->ctx, 1);
	if (card->ctx->debug >= 1) {
		rv = sc_path_print(pbuf, sizeof(pbuf), &file->path);
		if (rv != SC_SUCCESS)
			pbuf[0] = '\0';

		sc_debug(card->ctx, " create path=%s\n", pbuf);
		sc_debug(card->ctx,"id %04X; size %i; type %i; ef %i\n",
			file->id, file->size, file->type, file->ef_structure);
	}

	if (file->id==0x0000 || file->id==0xFFFF || file->id==0x3FFF) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (card->ctx->debug >= 1) {
		rv = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
		if (rv != SC_SUCCESS)
			pbuf[0] = '\0';
	}

	if (file->path.len)   {
		memcpy(&path, &file->path, sizeof(path));
		if (path.len>2)   
			path.len -= 2;
	
		if (auth_select_file(card, &path, NULL))   {
			sc_error(card->ctx, "Cannot select parent DF.\n");
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	
	rv = encode_file_structure_V5(card, file, sbuf, &sendlen);
	SC_TEST_RET(card->ctx, rv, "File structure encoding failed");
	
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
		sc_path_t tmp_path;
		sc_file_t *df_file = NULL;

		tmp_path.type = SC_PATH_TYPE_FILE_ID;
		tmp_path.value[0] = file->id >> 8;
		tmp_path.value[1] = file->id & 0xFF;
		tmp_path.len = 2;
		
		rv = auth_select_file(card, &tmp_path, &df_file);
		sc_debug(card->ctx, "rv %i", rv);
	}

	if (auth_current_ef)
		sc_file_free(auth_current_ef);
	sc_file_dup(&auth_current_ef, file);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}

static int 
auth_set_security_env(sc_card_t *card, 
		const sc_security_env_t *env, int se_num)   
{
	auth_senv_t *auth_senv = &((struct auth_private_data *) card->drv_data)->senv;
	long unsigned pads = env->algorithm_flags & SC_ALGORITHM_RSA_PADS;
	long unsigned supported_pads = 
		SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ISO9796;
	sc_apdu_t apdu;
	u8 rsa_sbuf[3] = {
		0x80, 0x01, 0xFF
	};
	u8 des_sbuf[13] = {
		0x80, 0x01, 0x01, 
		0x87, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "op %i; path %s; key_ref 0x%X; algos 0x%X; flags 0x%X\n", 
			env->operation, sc_print_path(&env->file_ref), env->key_ref[0],
			env->algorithm_flags, env->flags);

	memset(auth_senv, 0, sizeof(auth_senv_t));
	
	if (!(env->flags & SC_SEC_ENV_FILE_REF_PRESENT))  
		SC_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Key file is not selected.");
	
	switch (env->algorithm)   {
	case SC_ALGORITHM_DES:
	case SC_ALGORITHM_3DES:
		sc_debug(card->ctx, "algo SC_ALGORITHM_xDES: ref %X, flags %X\n", 
				env->algorithm_ref, env->flags);
		
		if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = 3;
			apdu.data = des_sbuf;
			apdu.datalen = 3;
		}
		else {
			sc_error(card->ctx, "Invalid crypto operation: %X\n", env->operation);
			SC_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Invalid crypto operation");
		}
	
		break;
	case SC_ALGORITHM_RSA:
		sc_debug(card->ctx, "algo SC_ALGORITHM_RSA\n");
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) {
			SC_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "No support for hashes.");
		}
		
		if (pads & (~supported_pads))   {
			sc_error(card->ctx, "No support for PAD %X\n",pads);
			SC_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "No padding support.");
		}
	
		if (env->operation == SC_SEC_OPERATION_SIGN)   {
			rsa_sbuf[2] = 0x11;
			
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			rsa_sbuf[2] = 0x11;
		
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else {
			sc_error(card->ctx, "Invalid crypto operation: %X\n", env->operation);
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
		}
	
		break;
	default:
		SC_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Invalid crypto algorithm supplied");
	}
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	auth_senv->algorithm = env->algorithm;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_restore_security_env(sc_card_t *card, int se_num)
{
	return SC_SUCCESS;
}


static int 
auth_compute_signature(sc_card_t *card, 
		const u8 *in, size_t ilen, 	u8 * out, size_t olen)
{
	sc_apdu_t apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "inlen %i, outlen %i\n", ilen, olen);
	if (!card || !in || !out)   {
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	else if (ilen > 96)   {
		sc_error(card->ctx, "Illegal input length %d\n", ilen);
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Illegal input length");
	}
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.datalen = ilen;
	apdu.data = in;
	apdu.lc = ilen;
	apdu.le = olen > 256 ? 256 : olen;
	apdu.resp = resp;
	apdu.resplen = olen;
	
	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Compute signature failed");
	
	if (apdu.resplen > olen)   {
		sc_error(card->ctx, "Compute signature failed: invalide response length %i\n",
				apdu.resplen);
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_CARD_CMD_FAILED);
	}
	
	memcpy(out, apdu.resp, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, 1, apdu.resplen);
}


static int 
auth_decipher(sc_card_t *card, const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	sc_apdu_t apdu;
	u8 resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv, _inlen = inlen;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx,"crgram_len %i;  outlen %i\n", inlen, outlen);
	if (!out || !outlen || inlen > SC_MAX_APDU_BUFFER_SIZE) 
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	
	sc_debug(card->ctx, "algorithm SC_ALGORITHM_RSA\n");
	if (inlen % 64)   {
		rv = SC_ERROR_INVALID_ARGUMENTS;
		goto done;
	}
				
	_inlen = inlen;
	if (_inlen == 256)   {
		apdu.cla |= 0x10;
		apdu.data = in;
		apdu.datalen = 8;
		apdu.resp = resp;
		apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
		apdu.lc = 8;
		apdu.le = 256;
			
		rv = sc_transmit_apdu(card, &apdu);
		sc_debug(card->ctx, "rv %i", rv);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, rv, "Card returned error");
		
		_inlen -= 8;
		in += 8;

		apdu.cla &= ~0x10;
	}
	
#if 0
	case SC_ALGORITHM_DES:
	case SC_ALGORITHM_3DES:
		sc_debug(card->ctx,"algorithm SC_ALGORITHM_DES\n");
		if (crgram_len == 0 || (crgram_len%8) != 0)  {
			rv = SC_ERROR_INVALID_ARGUMENTS;
			goto done;
		}
		break;
#endif

	apdu.data = in;
	apdu.datalen = _inlen;
	apdu.resp = resp;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	apdu.lc = _inlen;
	apdu.le = _inlen;
	
	rv = sc_transmit_apdu(card, &apdu);
	sc_debug(card->ctx, "rv %i", rv);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	sc_debug(card->ctx, "rv %i", rv);
	SC_TEST_RET(card->ctx, rv, "Card returned error");

	if (outlen > apdu.resplen)
		outlen = apdu.resplen;
	
	memcpy(out, apdu.resp, outlen);
	rv = outlen;

done:
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/* Return the default AAK for this type of card */
static int 
auth_get_default_key(sc_card_t *card, struct sc_cardctl_default_key *data)
{
	int rv = SC_ERROR_NO_DEFAULT_KEY;

#ifndef NOT_YET
	if (data->method == SC_AC_PRO)   {
		card->sm_level = data->key_ref | 0x60;
		rv = SC_SUCCESS;
	}
#endif	
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
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
auth_generate_key(sc_card_t *card, int use_sm, 
		struct sc_cardctl_oberthur_genkey_info *data)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_path_t tmp_path;
	int rv = 0;
#ifndef NOT_YET	
	const sc_acl_entry_t *entry;
#endif
	
	SC_FUNC_CALLED(card->ctx, 1);
	if (data->key_bits < 512 || data->key_bits > 2048 || 
			(data->key_bits%0x20)!=0)   {
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Illegal key length");
	}
	
	sbuf[0] = (data->id_pub >> 8) & 0xFF;
	sbuf[1] = data->id_pub & 0xFF;
	sbuf[2] = (data->id_prv >> 8) & 0xFF;
	sbuf[3] = data->id_prv & 0xFF;
	if (data->exponent != 0x10001)   {
		rv = auth_encode_exponent(data->exponent, &sbuf[5],SC_MAX_APDU_BUFFER_SIZE-6);
		SC_TEST_RET(card->ctx, rv, "Cannot encode exponent");
		
		sbuf[4] = rv;
		rv++;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x46, 0x00, 0x00);
	if (!(apdu.resp = (u8 *) malloc(data->key_bits/8+8)))   {
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	}
	apdu.resplen = data->key_bits/8+8;
	apdu.lc = rv + 4;
	apdu.le = data->key_bits/8;
	apdu.data = sbuf;
	apdu.datalen = rv + 4;

#ifndef NOT_YET	
    entry = sc_file_get_acl_entry(auth_current_df, SC_AC_OP_CRYPTO);
	if (entry && entry->method == SC_AC_PRO) 
		if (card->sm_level < (entry->key_ref | 0x60))
			card->sm_level = entry->key_ref | 0x60;
							
	if (card->sm_level)   {
		struct sc_sm_info sm_info;
		unsigned char init_data[SC_MAX_APDU_BUFFER_SIZE];
		int init_data_len = sizeof(init_data);
		unsigned char out[SC_MAX_APDU_BUFFER_SIZE];
		int out_len = sizeof(init_data);

		rv = auth_sm_init (card, &sm_info, SC_SM_CMD_TYPE_GENERATE_RSA,
				card->serialnr.value, card->serialnr.len,  
				init_data, &init_data_len);
		SC_TEST_RET(card->ctx, rv, "SM: init failed");
	
		sm_info.p1 = data->key_bits;
		sm_info.data = apdu.data;
		sm_info.data_len = apdu.datalen;
	
		rv = auth_sm_execute (card, &sm_info, init_data, init_data_len, 
				out, out_len);
		SC_TEST_RET(card->ctx, rv, "SM: execute failed");
		
		rv = auth_sm_release (card, &sm_info, out, out_len);
		SC_TEST_RET(card->ctx, rv, "SM: release failed");

		/* TODO clean resp */
	}
	else   {
#endif		
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		SC_TEST_RET(card->ctx, rv, "Card returned error");
#ifndef NOT_YET		
	}
#endif
		
	tmp_path.type = SC_PATH_TYPE_FILE_ID;
	tmp_path.len = 2;
	memcpy(tmp_path.value, sbuf, 2);
		
	rv = auth_select_file(card, &tmp_path, NULL);
	SC_TEST_RET(card->ctx, rv, "cannot select public key");
		
	rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC,
			1, apdu.resp, data->key_bits/8);
	SC_TEST_RET(card->ctx, rv, "auth_read_component() returned error");
		
	apdu.resplen = rv;
	
	if (data->pubkey)   {
		if (data->pubkey_len < apdu.resplen)  
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

		memcpy(data->pubkey,apdu.resp,apdu.resplen);
	}

	data->pubkey_len = apdu.resplen;
	free(apdu.resp);

	sc_debug(card->ctx, "resulted public key len %i\n", apdu.resplen);
	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


static int
auth_update_component(sc_card_t *card, struct auth_update_component_info *args)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE + 0x10];
	u8 ins, p1, p2;
	int rv, len;
	
	SC_FUNC_CALLED(card->ctx, 1);
	if (args->len > sizeof(sbuf) || args->len > 0x100)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	sc_debug(card->ctx, "nn %i; len %i\n", args->component, args->len);
	ins = 0xD8;
	p1 = args->component;
	p2 = 0x04;
	len = 0;
	
	sbuf[len++] = args->type;
	sbuf[len++] = args->len;
	memcpy(sbuf + len, args->data, args->len);
	len += args->len;
		
	if (args->type == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		int outl;
		const unsigned char in[8] = {0,0,0,0,0,0,0,0};
		unsigned char out[8];
		EVP_CIPHER_CTX ctx;
			
		if (args->len!=8 && args->len!=24)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
		
		p2 = 0;
		EVP_CIPHER_CTX_init(&ctx);
		if (args->len == 24) 
			EVP_EncryptInit_ex(&ctx, EVP_des_ede(), NULL, args->data, NULL);
		else
			EVP_EncryptInit_ex(&ctx, EVP_des_ecb(), NULL, args->data, NULL);
		rv = EVP_EncryptUpdate(&ctx, out, &outl, in, 8);
		if (!EVP_CIPHER_CTX_cleanup(&ctx) || rv == 0) {
			sc_error(card->ctx, "OpenSSL encryption error.");
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
		}

		sbuf[len++] = 0x03;
		memcpy(sbuf + len, out, 3);
		len += 3;
	}
	else   {
		sbuf[len++] = 0;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins,	p1, p2);
	apdu.cla |= 0x80;
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;
	apdu.sensitive = 1;
	if (args->len == 0x100)   {
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

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int
auth_update_key(sc_card_t *card, struct sc_cardctl_oberthur_updatekey_info *info)
{
	int rv, ii;
	
	SC_FUNC_CALLED(card->ctx, 1);
	
#ifndef NOT_YET	
	if (auth_current_ef)   {
		const sc_acl_entry_t *entry = sc_file_get_acl_entry(auth_current_ef, 
				SC_AC_OP_UPDATE);
		
		if (entry && entry->method == SC_AC_PRO)
			if (card->sm_level < (entry->key_ref | 0x60))
				card->sm_level = entry->key_ref | 0x60;
	}
	
	if (card->sm_level)    
		return auth_sm_update_rsa(card, info);
#endif	
	if (info->data_len != sizeof(void *) || !info->data)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (info->type == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)   {
		struct sc_pkcs15_prkey_rsa  *rsa = (struct sc_pkcs15_prkey_rsa *)info->data;
        struct sc_pkcs15_bignum bn[5];

		sc_debug(card->ctx, "Import RSA CRT");
		bn[0] = rsa->p;
		bn[1] = rsa->q;
		bn[2] = rsa->iqmp;
		bn[3] = rsa->dmp1;
		bn[4] = rsa->dmq1;
		for (ii=0;ii<5;ii++)   {
			struct auth_update_component_info args;
			
			memset(&args, 0, sizeof(args));
			args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
			args.component = ii+1;
			args.data = bn[ii].data;
			args.len = bn[ii].len;
			
			rv = auth_update_component(card, &args);
			SC_TEST_RET(card->ctx, rv, "Update RSA component failed");
		}
	}
	else if (info->type == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		rv = SC_ERROR_NOT_SUPPORTED; 
	}
	else   {
		rv = SC_ERROR_INVALID_DATA;
	}
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return auth_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_OBERTHUR_GENERATE_KEY:
		return auth_generate_key(card, 0,
				(struct sc_cardctl_oberthur_genkey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_UPDATE_KEY:
		return auth_update_key(card, 
				(struct sc_cardctl_oberthur_updatekey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_CREATE_PIN:
		return auth_create_reference_data(card,
				(struct sc_cardctl_oberthur_createpin_info *) ptr); 
    case SC_CARDCTL_GET_SERIALNR:
        return auth_get_serialnr(card, (sc_serial_number_t *)ptr);
	case SC_CARDCTL_LIFECYCLE_GET:
	case SC_CARDCTL_LIFECYCLE_SET:
		return SC_ERROR_NOT_SUPPORTED;
	default:
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
	}
}


static int
auth_read_component(sc_card_t *card, enum SC_CARDCTL_OBERTHUR_KEY_TYPE type, 
		int num, unsigned char *out, size_t outlen)
{
	int rv;
	sc_apdu_t apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "num %i, outlen %i, type %i\n", num, outlen, type);

	if (!outlen || type!=SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCORRECT_PARAMETERS);
	
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
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_WRONG_LENGTH);
		
	memcpy(out, apdu.resp, apdu.resplen);
	SC_FUNC_RETURN(card->ctx, 1, apdu.resplen);
}


static int auth_get_pin_reference (sc_card_t *card, 
	 int type, int reference, int cmd, int *out_ref)
{
	struct auth_private_data *prv;

	if (!card || !out_ref)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	prv = (struct auth_private_data *) card->drv_data;
    
	switch (type) {
	case SC_AC_CHV:
		if (reference != 1 && reference != 2 && reference != 4)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_PIN_REFERENCE);
		
		*out_ref = reference;
		if (reference == 1 || reference == 2)
			if (cmd == SC_PIN_CMD_VERIFY)
				*out_ref |= 0x80;
		break;

	default:
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


static void 
auth_init_pin_info(sc_card_t *card, struct sc_pin_cmd_pin *pin, 
		unsigned int type)
{
	pin->offset	 = 0;
	pin->pad_char   = 0xFF;
	pin->encoding   = SC_PIN_ENCODING_ASCII;
	
	if (type==AUTH_PIN)   {
		pin->max_length = 64;
		pin->pad_length = 64;
	}
	else    {
		pin->max_length = 16;
		pin->pad_length = 16;
	}
}


static int
auth_verify(sc_card_t *card, unsigned int type,
	int ref, const u8 *data, size_t data_len, int *tries_left)
{
	sc_apdu_t apdu;
	int rv, pin_ref;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pinfo;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx,"type %i; ref %i, data_len %i\n", type, ref, data_len);

	if (ref == 3)   {
		ref = 1;
		rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_VERIFY, &pin_ref);
		SC_TEST_RET(card->ctx, rv, "Get PIN reference failed");

    	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_ref);
    	apdu.lc = 0x0;
	    apdu.le = 0x0;
		apdu.resplen = 0;
		apdu.resp = NULL;
		apdu.p2 = pin_ref;
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
		
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)   {
			ref = 2;
			rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_VERIFY, &pin_ref);
	        if (rv)
				SC_FUNC_RETURN(card->ctx, 1, rv);
			
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
		
		SC_FUNC_RETURN(card->ctx, 1, rv);
	}

	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_VERIFY, &pin_ref);
	SC_TEST_RET(card->ctx, rv, "Get PIN reference failed");
	
	sc_debug(card->ctx, " pin_ref %X\n", pin_ref);

	auth_init_pin_info(card, &pinfo, AUTH_PIN);
	if (data_len > pinfo.pad_length)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (data_len)  {
		memset(sbuf, pinfo.pad_char, pinfo.pad_length);
		memcpy(sbuf, data, data_len);

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_ref);
		apdu.data = sbuf;
		apdu.datalen = pinfo.pad_length;
		apdu.lc = pinfo.pad_length;
		apdu.sensitive = 1;
	}
	else   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, pin_ref);
		apdu.lc = 0x0;
		apdu.le = 0x0;
		apdu.resplen = 0;
		apdu.resp = NULL;
	}
		
	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0) 
		*tries_left = apdu.sw2 & 0x0F;
	
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
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
	
	SC_FUNC_CALLED(card->ctx, 1);
	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_CHANGE, &pin_ref);
	SC_TEST_RET(card->ctx, rv, "Failed to get PIN reference");
	
	sc_debug(card->ctx, " pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &pinfo, AUTH_PIN);
	
	if (oldlen > pinfo.pad_length || newlen > pinfo.pad_length)
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN length");
	
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
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
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
#ifndef NOT_YET	
	const sc_acl_entry_t *entry;
#endif
	
	SC_FUNC_CALLED(card->ctx, 1);
	rv = auth_get_pin_reference (card, type, ref, SC_PIN_CMD_CHANGE, &pin_ref);
	SC_TEST_RET(card->ctx, rv, "Failed to get PIN reference");
	
	sc_debug(card->ctx, "pin_ref 0x%X\n", pin_ref);
	sc_debug(card->ctx, "current path ; type=%d, path=%s\n", 
			auth_current_df->path.type, sc_print_path(&auth_current_df->path));
	
	auth_init_pin_info(card, &puk_info, AUTH_PUK);
	auth_init_pin_info(card, &pin_info, AUTH_PIN);
	
	if (puklen > puk_info.pad_length || pinlen > pin_info.pad_length)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

#ifndef NOT_YET	
	entry = sc_file_get_acl_entry(auth_current_df, SC_AC_OP_PIN_RESET);
	if (entry && entry->method == SC_AC_PRO)   {
		card->sm_level = entry->key_ref | 0x60; 
		rv = auth_sm_reset_pin(card, type, ref, pin, pinlen);

		SC_FUNC_RETURN(card->ctx, 1, rv);
	}
#endif	
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
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_create_reference_data (sc_card_t *card, 
		struct sc_cardctl_oberthur_createpin_info *args)
{
	sc_apdu_t apdu;
	int rv, pin_ref, len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_pin_cmd_pin pin_info, puk_info;

	SC_FUNC_CALLED(card->ctx, 1);
	
	if (args->pin_tries < 1 || !args->pin || !args->pin_len)
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN options");
	
    if (args->type == SC_AC_CHV)   {
		if (args->ref == 1)  
		    pin_ref = 0x01;
		else if (args->ref == 2)
			pin_ref = 0x02;
		else
			SC_TEST_RET(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid PIN reference");
	}
	else   {
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	
	sc_debug(card->ctx, "pin ref %X\n", pin_ref);
	
	auth_init_pin_info(card, &puk_info, AUTH_PUK);
	auth_init_pin_info(card, &pin_info, AUTH_PIN);

	if (args->puk && args->puk_len && (args->puk_len%puk_info.pad_length))
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PUK options");
		
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

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_logout(sc_card_t *card)
{
	sc_apdu_t apdu;
	int ii, rv = 0, pin_ref;
	int reset_flag = 0x20;

	for (ii=0; ii < 4; ii++)   {
		rv = auth_get_pin_reference (card, SC_AC_CHV, ii+1, SC_PIN_CMD_UNBLOCK, &pin_ref);
		SC_TEST_RET(card->ctx, rv, "Cannot get PIN reference");

	    sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x00);
    	apdu.cla = 0x80;
	    apdu.lc = 0x0;
    	apdu.le = 0x0;
		apdu.resplen = 0;
		apdu.resp = NULL;
		apdu.p2 = pin_ref | reset_flag;
		rv = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}

static int 
write_publickey (sc_card_t *card, unsigned int offset,
				const u8 *buf, size_t count)
{
	int ii, rv;
	struct sc_pkcs15_pubkey_rsa key;
	size_t len = 0, der_size = 0;
	struct auth_update_component_info args;

	SC_FUNC_CALLED(card->ctx, 1);
	if (card->ctx->debug >= 5)  {
		char debug_buf[2048];
		
		debug_buf[0] = 0;
		sc_hex_dump(card->ctx, buf, count, debug_buf, sizeof(debug_buf));
		sc_debug(card->ctx, "write_publickey in %d bytes :\n%s", count, debug_buf);
	}

	if (offset > sizeof(rsa_der))
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid offset value");

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
	
	sc_debug(card->ctx, "der_size %i\n",der_size);
	if (offset + len < der_size + 2)
		SC_FUNC_RETURN(card->ctx, 1, len);

	rv = sc_pkcs15_decode_pubkey_rsa(card->ctx, &key, rsa_der, rsa_der_len);
	rsa_der_len = 0;
	memset(rsa_der, 0, sizeof(rsa_der));
	SC_TEST_RET(card->ctx, rv, "cannot decode public key");
	
	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 1;
	args.data = key.modulus.data;
	args.len = key.modulus.len;
	rv = auth_update_component(card, &args);
	SC_TEST_RET(card->ctx, rv, "Update component failed");
	
	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 2;
	args.data = key.exponent.data;
	args.len = key.exponent.len;
	rv = auth_update_component(card, &args);
	SC_TEST_RET(card->ctx, rv, "Update component failed");
		
	SC_FUNC_RETURN(card->ctx, 1, len);
}
	

static int
auth_update_binary(sc_card_t *card, unsigned int offset,
		const u8 *buf, size_t count, unsigned long flags)
{
	int rv = 0;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "offset %i; count %i\n", offset, count);
	sc_debug(card->ctx, "last selected : magic %X; ef %X\n", 
			auth_current_ef->magic, auth_current_ef->ef_structure);
	
	if (offset & ~0x7FFF)
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid file offset");

	if (auth_current_ef->magic==SC_FILE_MAGIC && 
			 auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  { 
		rv = write_publickey(card, offset, buf, count);
	}
	else if (auth_current_ef->magic==SC_FILE_MAGIC && 
			auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		struct auth_update_component_info args;
	
		memset(&args, 0, sizeof(args));
		args.type = SC_CARDCTL_OBERTHUR_KEY_DES;
		args.component = 0;
		args.data = (u8 *)buf;
		args.len = count;
		rv = auth_update_component(card, &args);
	}
	else   {
		rv = iso_ops->update_binary(card, offset, buf, count, 0);
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);	
}


static int
auth_read_binary(sc_card_t *card, unsigned int offset,
		u8 *buf, size_t count, unsigned long flags)
{
	int rv;
#ifndef NOT_YET	
	const sc_acl_entry_t *entry;
#endif
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx,"offset %i; size %i; flags 0x%lX\n", offset, count, flags);
	sc_debug(card->ctx,"last selected : magic %X; ef %X\n", 
			auth_current_ef->magic, auth_current_ef->ef_structure);

/*	_auth_print_acls(card, auth_current_ef); */

#ifndef NOT_YET	
	entry = sc_file_get_acl_entry(auth_current_ef, SC_AC_OP_READ);
	sc_debug(card->ctx,"entry %p; %i\n", entry, SC_AC_OP_READ);
	if (entry && entry->method == SC_AC_PRO)   {
		sc_debug(card->ctx, "needs SM level 0x%X\n", entry->key_ref >> 3);

		card->sm_level = entry->key_ref | 0x60;
		rv = auth_sm_read_binary(card, 
				auth_current_ef->path.value, auth_current_ef->path.len, 
				offset, buf, count);
		
		sc_debug(card->ctx, "rv %i\n", rv);
		SC_FUNC_RETURN(card->ctx, 1, rv);
	}		
#endif	
	if (offset & ~0x7FFF)
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid file offset");

	if (auth_current_ef->magic==SC_FILE_MAGIC &&
             auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)   {
		int jj;
		unsigned char resp[0x100], *out = NULL;
		size_t resp_len, out_len;
		struct sc_pkcs15_bignum bn[2];
		struct sc_pkcs15_pubkey_rsa key;

		resp_len = sizeof(resp);
		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC, 
				2, resp, resp_len);
		SC_TEST_RET(card->ctx, rv, "read component failed");
		
		for (jj=0; jj<rv && *(resp+jj)==0; jj++)
			;

		bn[0].data = (u8 *) malloc(rv - jj);
		bn[0].len = rv - jj;
		memcpy(bn[0].data, resp + jj, rv - jj);
		
		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC, 
				1, resp, resp_len);
		SC_TEST_RET(card->ctx, rv, "Cannot read RSA public key component");
		
		bn[1].data = (u8 *) malloc(rv);
		bn[1].len = rv;
		memcpy(bn[1].data, resp, rv);

		key.exponent = bn[0];
		key.modulus = bn[1];
			
		if (sc_pkcs15_encode_pubkey_rsa(card->ctx, &key, &out, &out_len)) {
			SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ASN1_OBJECT, 
					"cannot encode RSA public key");
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
		
		if (bn[0].data) 
			free(bn[0].data);
		if (bn[1].data) 
			free(bn[1].data);
		if (out) 
			free(out);
	}
	else	 { 
		rv = iso_ops->read_binary(card, offset, buf, count, 0);	
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int
auth_read_record(struct sc_card *card, unsigned int nr_rec,
		u8 *buf, size_t count,
		unsigned long flags)
{
	int rv = 0;
	struct sc_apdu apdu;
    u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_debug(card->ctx, "auth_read_record(): nr_rec %i; count %i\n", nr_rec, count);
													
    sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2, nr_rec, 0);
    apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
    if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	rv = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);
											
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");

	SC_FUNC_RETURN(card->ctx, 1, apdu.resplen);
}
		

static int
auth_delete_record(sc_card_t *card, unsigned int nr_rec)
{
	int rv = 0;
	sc_apdu_t apdu;

	SC_FUNC_CALLED(card->ctx, 1);
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
	SC_FUNC_RETURN(card->ctx, 1, rv);
}
		
static int
auth_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	if (!card || !serial)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (card->serialnr.len==0)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);

	memcpy(serial, &card->serialnr, sizeof(*serial));

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

#ifndef NOT_YET
static int 
auth_sm_init (struct sc_card *card, struct sc_sm_info *sm_info, int cmd, 
		unsigned char *id, size_t id_len,
		unsigned char *resp, size_t *resp_len)
{
	int rv;
	struct sc_apdu apdu;
    unsigned char host_challenge[8];
    int host_challenge_len = sizeof(host_challenge);

	sc_debug(card->ctx, "called; command 0x%X\n", cmd);
	if (!card || !sm_info || !id || !id_len || !resp || !resp_len)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (!card->sm.funcs.initialize || !card->sm.funcs.get_apdus)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);

	if ((card->sm_level & 0xE0) != 0x60)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (id_len > sizeof(sm_info->id))
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	if (*resp_len < 28)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	memset(sm_info, 0, sizeof(*sm_info));
	
	sm_info->index = 0;
	sm_info->version = 1;		
	sm_info->cmd = cmd;
	sm_info->level = (card->sm_level & 0x18) >> 3;
	
	sm_info->id_len = id_len;
	memcpy(sm_info->id, id, id_len); 
	
	sm_info->status = 0;
	
	sm_info->serialnr = card->serialnr;
	
    rv = card->sm.funcs.initialize(card->ctx, sm_info, 
			host_challenge, &host_challenge_len);
	SC_TEST_RET(card->ctx, rv, "SM: INITIALIZE failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x50, 
			sm_info->version, sm_info->index);
	apdu.cla = 0x80;
	apdu.resp = resp;
	apdu.resplen = *resp_len;
	apdu.lc = 8;
	apdu.le = 12;
	apdu.data = host_challenge;
	apdu.datalen = 8;

	rv=sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, rv, "transmit APDU failed");
	
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, rv, "Card returned error");
	
	if (apdu.resplen != 28)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INTERNAL);
	
	*resp_len = 28;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_sm_execute (struct sc_card *card, struct sc_sm_info *sm_info, 
		unsigned char *data, int data_len,
		unsigned char *out, size_t len)
{
#define AUTH_SM_APDUS_MAX 6
	int rv, ii;
    struct sc_apdu apdus[AUTH_SM_APDUS_MAX];
	unsigned char sbufs[AUTH_SM_APDUS_MAX][SC_MAX_APDU_BUFFER_SIZE];
	unsigned char rbufs[AUTH_SM_APDUS_MAX][SC_MAX_APDU_BUFFER_SIZE];
	int nn_apdus = AUTH_SM_APDUS_MAX;

	if (!card->sm.funcs.initialize || !card->sm.funcs.get_apdus)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);

	memset(&apdus, 0, sizeof(apdus));
	memset(&sbufs, 0, sizeof(sbufs));
	memset(&rbufs, 0, sizeof(rbufs));
	for (ii=0; ii<nn_apdus; ii++)   {
		apdus[ii].data = &sbufs[ii][0];
		apdus[ii].resp = &rbufs[ii][0];
		apdus[ii].resplen = SC_MAX_APDU_BUFFER_SIZE;
	}

	rv = card->sm.funcs.get_apdus(card->ctx, sm_info,
			data, data_len, apdus, &nn_apdus);
	SC_TEST_RET(card->ctx, rv, "SM: GET_APDUS failed");
	
	sc_debug(card->ctx, "GET_APDUS: rv %i; nn cmds %i\n", 
			rv, nn_apdus);

	for (ii=0; ii < nn_apdus; ii++)   {
		rv = sc_transmit_apdu(card, &apdus[ii]);
		if (rv < 0) 
			break;
		
		rv = sc_check_sw(card, apdus[ii].sw1, apdus[ii].sw2);
		if (rv < 0)   
			break;
	}

	if (rv)   {
		sm_info->status = rv;
		auth_sm_release (card, sm_info, NULL, 0);
	}
	
	if (out && len > 0 && !rv)   {
		if (len > apdus[nn_apdus-1].resplen)
			len = apdus[nn_apdus-1].resplen;
		
		memcpy(out, apdus[nn_apdus-1].resp, len);
		SC_FUNC_RETURN(card->ctx, 1, len);
	}
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_sm_release (struct sc_card *card, struct sc_sm_info *sm_info,
		unsigned char *data, int data_len)
{
	int rv;
	struct sc_apdu apdu;

	card->sm_level = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x60);
	apdu.cla = 0x80;
	apdu.lc = 0x0;
	apdu.le = 0x0;
	apdu.resplen = 0;
	apdu.resp = NULL;
	
	rv = sc_transmit_apdu(card, &apdu);
    SC_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (sm_info && card->sm.funcs.finalize)   {
		rv = card->sm.funcs.finalize(card->ctx, sm_info, data, data_len);
	    SC_TEST_RET(card->ctx, rv, "SM: finalize failed");
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_sm_update_rsa (struct sc_card *card, 
		struct sc_cardctl_oberthur_updatekey_info *update_info)
{
	int rv, rvv;
	struct sc_sm_info sm_info;
	unsigned char init_data[SC_MAX_APDU_BUFFER_SIZE];
	int init_data_len = sizeof(init_data);

	sc_debug(card->ctx, "called; SM Level 0x%X\n", card->sm_level);
	if (!update_info || !card->sm_level)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	/* If rsa defined, we impose Mosilla style ID. */
	if (update_info->data && (update_info->data_len == sizeof(void *)))   {
		struct sc_pkcs15_prkey_rsa *rsa = (struct sc_pkcs15_prkey_rsa *)update_info->data;

		SHA1(rsa->modulus.data, rsa->modulus.len, update_info->id);
		update_info->id_len = SHA_DIGEST_LENGTH;
	}
	
	rv = auth_sm_init (card, &sm_info, SC_SM_CMD_TYPE_UPDATE_RSA,
			update_info->id, update_info->id_len,  init_data, &init_data_len);
	if (!rv)
		rv = auth_sm_execute (card, &sm_info, 
				init_data, init_data_len, NULL, 0);
	
	rvv = auth_sm_release (card, &sm_info, NULL, 0);

	SC_FUNC_RETURN(card->ctx, 1, (rv ? rv : rvv));
}


static int 
auth_sm_reset_pin (struct sc_card *card, int type, int ref,
		const u8 *data, size_t len)
{
	int rv;
	struct sc_sm_info sm_info;
	unsigned char init_data[SC_MAX_APDU_BUFFER_SIZE];
	int init_data_len = sizeof(init_data);

	sc_debug(card->ctx, "called; PIN ref 0x%X; data length %i\n", ref, len);

	rv = auth_sm_init (card, &sm_info, SC_SM_CMD_TYPE_RESET_PIN,
			card->serialnr.value, card->serialnr.len, init_data, &init_data_len);
	SC_TEST_RET(card->ctx, rv, "SM: init failed");

	sm_info.p1 = ref;
	sm_info.data = data;
	sm_info.data_len = len;
	
	rv = auth_sm_execute (card, &sm_info, init_data, init_data_len, NULL, 0);
	SC_TEST_RET(card->ctx, rv, "SM: execute failed");

	rv = auth_sm_release (card, &sm_info, NULL, 0);
	SC_TEST_RET(card->ctx, rv, "SM: release failed");

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
auth_sm_read_binary (struct sc_card *card, unsigned char *id, size_t id_len,
		size_t offs, unsigned char *out, size_t len)
{
	int rv;
	struct sc_sm_info sm_info;
	unsigned char init_data[SC_MAX_APDU_BUFFER_SIZE];
	int init_data_len = sizeof(init_data);

	sc_debug(card->ctx, "called; offs %i; len %i\n", offs, len);

	if (len > 0xF0)   {
		sc_error(card->ctx, "Not yet: reading length cannot be more then 240 bytes.");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
	}

	rv = auth_sm_init (card, &sm_info, SC_SM_CMD_TYPE_READ_BINARY,
			id, id_len, init_data, &init_data_len);
	SC_TEST_RET(card->ctx, rv, "SM: init failed");
	
	sm_info.p1 = offs;
	sm_info.p2 = len;
	
	rv = auth_sm_execute (card, &sm_info, init_data, init_data_len, out, len);
	SC_TEST_RET(card->ctx, rv, "SM: execute failed");

	len = rv;

	rv = auth_sm_release (card, &sm_info, out, len);
	SC_TEST_RET(card->ctx, rv, "SM: release failed");

	SC_FUNC_RETURN(card->ctx, 1, len);
}
#endif

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
	auth_ops.read_record = auth_read_record;
	auth_ops.delete_record = auth_delete_record;
	auth_ops.card_ctl = auth_card_ctl;
	auth_ops.set_security_env = auth_set_security_env;
	auth_ops.restore_security_env = auth_restore_security_env;
	auth_ops.compute_signature = auth_compute_signature;
	auth_ops.decipher = auth_decipher;
	auth_ops.process_fci = auth_process_fci;

	auth_ops.pin_cmd = NULL;
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

#endif /* ENABLE_OPENSSL */
