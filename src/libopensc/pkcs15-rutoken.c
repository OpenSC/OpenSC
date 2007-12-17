/*
 * ruToken specific operation for PKCS15 initialization
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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "../pkcs15init/pkcs15-init.h"
#include "../pkcs15init/profile.h"

#define USAGE_AUT	SC_PKCS15_PRKEY_USAGE_ENCRYPT | \
SC_PKCS15_PRKEY_USAGE_DECRYPT | \
SC_PKCS15_PRKEY_USAGE_WRAP    | \
SC_PKCS15_PRKEY_USAGE_UNWRAP  | \
SC_PKCS15_PRKEY_USAGE_SIGN

#define P15_DF(T) T & SC_PKCS15_TYPE_CERT ? SC_PKCS15_CDF \
	: T & SC_PKCS15_TYPE_PUBKEY ? SC_PKCS15_PUKDF : \
		T & SC_PKCS15_TYPE_PRKEY_RSA ? SC_PKCS15_PRKDF : SC_PKCS15_DODF

int	rutoken_erase(struct sc_profile *, sc_card_t *);

#define MAX_ID 255

const sc_SecAttrV2_t map_sec_attr = {0x42, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 2};
const sc_SecAttrV2_t pr_sec_attr = {0x43, 1, 1, 0, 0, 0, 0, 1, 2, 2, 0, 0, 0, 0, 2};
const sc_SecAttrV2_t pb_sec_attr = {0x42, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 2};

const char GCHV_DF[] = "3F0000000000";
const char APP_DF[] = "3F0000000000FF00";
const char PRK_DF[] = "3F0000000000FF001001";
const char PUK_DF[] = "3F0000000000FF001002";
const char C_DF[] = "3F0000000000FF001003";

enum DF_IDs
{
	PrKDFid = 0x1001,
	PuKDFid = 0x1002,
	CDFid = 0x1003,
	DFsId = 0xefff,
	DFsSize = 2048
};

/*  BLOB definition  */

typedef struct _RSAPUBKEY {
	int magic;
	int bitlen;
	int pubexp;
} RSAPUBKEY;

typedef struct _PUBLICKEYSTRUC {
	u8 bType;
	u8 bVersion;
	u_int16_t reserved;
	u_int32_t aiKeyAlg;
} BLOBHEADER;

typedef struct _PRIVATEKEYBLOB {
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
	u8 *modulus;
	u8 *prime1;
	u8 *prime2;
	u8 *exponent1;
	u8 *exponent2;
	u8 *coefficient;
	u8 *privateExponent;
} PRIVATEKEYBLOB;

void ArrayReverse(u8 *buf, int size);
int bin_to_privite_blob(PRIVATEKEYBLOB *pr_blob, u8 *buf, int buf_len);

/* BLOB */

int create_privite_blob(PRIVATEKEYBLOB *pr_blob, const struct sc_pkcs15_prkey_rsa *key){
    int bitlen = key->modulus.len*8;
	/*  blobheader  */
	/*  u8 bType;  */
    pr_blob->blobheader.bType = 0x07;
	/*  u8 bVersion;  */
    pr_blob->blobheader.bVersion = 0x02;  
	/*  u16 reserved;  */
    pr_blob->blobheader.reserved = 0;
	/*  u32 aiKeyAlg;  */
    pr_blob->blobheader.aiKeyAlg =  0x0000a400;
    
	pr_blob->rsapubkey.magic     = 0x32415352;         /* "RSA2"  */
    pr_blob->rsapubkey.bitlen    = bitlen;
	int n = key->exponent.len;
	while (n > 0)
	{
		((u8*)&pr_blob->rsapubkey.pubexp)[key->exponent.len - n] = key->exponent.data[n - 1]; 
		n--;
	}
    pr_blob->modulus = malloc(bitlen/8);
	pr_blob->prime1 = malloc(bitlen/16);
	pr_blob->prime2 = malloc(bitlen/16);
	pr_blob->exponent1 = malloc(bitlen/16);
	pr_blob->exponent2 = malloc(bitlen/16);
	pr_blob->coefficient = malloc(bitlen/16);
	pr_blob->privateExponent = malloc(bitlen/8);

    
    memcpy(pr_blob->modulus, key->modulus.data, key->modulus.len);
	ArrayReverse(pr_blob->modulus, key->modulus.len);
	memcpy(pr_blob->prime1, key->p.data, key->p.len);
	ArrayReverse(pr_blob->prime1, key->p.len);
	memcpy(pr_blob->prime2, key->q.data, key->q.len);
	ArrayReverse(pr_blob->prime2, key->q.len);
	memcpy(pr_blob->exponent1, key->dmp1.data, key->dmp1.len);
	ArrayReverse(pr_blob->exponent1, key->dmp1.len);
	memcpy(pr_blob->exponent2, key->dmq1.data, key->dmq1.len);
	ArrayReverse(pr_blob->exponent2, key->dmq1.len);
	memcpy(pr_blob->coefficient, key->iqmp.data, key->iqmp.len);
	ArrayReverse(pr_blob->coefficient, key->iqmp.len);
	memcpy(pr_blob->privateExponent, key->d.data, key->d.len);
	ArrayReverse(pr_blob->privateExponent, key->d.len);
	return 0;
}

int get_sc_pksc15_prkey_rsa(const PRIVATEKEYBLOB *pr_blob, struct sc_pkcs15_prkey_rsa *key){
    int bitlen = pr_blob->rsapubkey.bitlen;
	long exp = 0x00010001;
    key->modulus.data = malloc(bitlen/8);
	key->modulus.len = bitlen/8;
    key->p.data = malloc(bitlen/16);
	key->p.len = bitlen/16;
    key->q.data = malloc(bitlen/16);
	key->q.len = bitlen/16;
    key->dmp1.data = malloc(bitlen/16);
	key->dmp1.len = bitlen/16;
    key->dmq1.data = malloc(bitlen/16);
	key->dmq1.len = bitlen/16 - 1;
    key->iqmp.data = malloc(bitlen/16);
	key->iqmp.len = bitlen/16;
    key->d.data = malloc(bitlen/8);
	key->d.len = bitlen/8;
	key->exponent.data = malloc(3);
	memcpy(key->exponent.data, &exp, 3); 
	key->exponent.len = 3;
    
    memcpy(key->modulus.data, pr_blob->modulus, key->modulus.len);
	ArrayReverse(key->modulus.data, key->modulus.len);
	memcpy(key->p.data, pr_blob->prime1, key->p.len);
	ArrayReverse(key->p.data, key->p.len);
	memcpy(key->q.data, pr_blob->prime2, key->q.len);
	ArrayReverse(key->q.data, key->q.len);
	memcpy(key->dmp1.data, pr_blob->exponent1, key->dmp1.len);
	ArrayReverse(key->dmp1.data, key->dmp1.len);
	memcpy(key->dmq1.data, pr_blob->exponent2, key->dmq1.len);
	ArrayReverse(key->dmq1.data, key->dmq1.len);
	memcpy(key->iqmp.data, pr_blob->coefficient, key->iqmp.len);
	ArrayReverse(key->iqmp.data, key->iqmp.len);
	memcpy(key->d.data, pr_blob->privateExponent, key->d.len);
	ArrayReverse(key->d.data, key->d.len);
	return 0;
}

int get_privite_blob_len(const PRIVATEKEYBLOB *pr_blob){
    return sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 9*(pr_blob->rsapubkey.bitlen/16);
}

int free_privite_blob(PRIVATEKEYBLOB *pr_blob){
	free(pr_blob->modulus);
	free(pr_blob->prime1);
	free(pr_blob->prime2);
	free(pr_blob->exponent1);
	free(pr_blob->exponent2);
	free(pr_blob->coefficient);
	free(pr_blob->privateExponent);
	return 0;
}


int privite_blob_to_bin(const PRIVATEKEYBLOB *pr_blob, u8 *buf, size_t *buf_len){
    
    if(*buf_len < get_privite_blob_len(pr_blob) + 2)
	return -1;

	buf[0] = 2;
	buf[1] = 1;
	u8 *tmp = buf + 2;
    memcpy(tmp, &pr_blob->blobheader, sizeof(pr_blob->blobheader));
    tmp += sizeof(pr_blob->blobheader);
    
    memcpy(tmp, &pr_blob->rsapubkey, sizeof(pr_blob->rsapubkey));
    tmp += sizeof(pr_blob->rsapubkey);
    
    memcpy(tmp, pr_blob->modulus, pr_blob->rsapubkey.bitlen/8);
    tmp += pr_blob->rsapubkey.bitlen/8;
    
    memcpy(tmp, pr_blob->prime1, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(tmp, pr_blob->prime2, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(tmp, pr_blob->exponent1, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(tmp, pr_blob->exponent2, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(tmp, pr_blob->coefficient, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(tmp, pr_blob->privateExponent, pr_blob->rsapubkey.bitlen/8);
    tmp += pr_blob->rsapubkey.bitlen/8;
    *buf_len = get_privite_blob_len(pr_blob) + 2;
    return 0;
}

int get_prkey_from_bin(u8* data, int len, struct sc_pkcs15_prkey **key)
{
	int ret = -1;
	*key = malloc(sizeof(struct sc_pkcs15_prkey));
	if(data && *key)
	{
		PRIVATEKEYBLOB pr_blob;
		memset(*key, 0, sizeof(struct sc_pkcs15_prkey));
		bin_to_privite_blob(&pr_blob, data, len);
		ret = get_sc_pksc15_prkey_rsa(&pr_blob, &(*key)->u.rsa);
		(*key)->algorithm = SC_ALGORITHM_RSA;
		free_privite_blob(&pr_blob);
	}
	return ret;
}

void ArrayReverse(u8 *buf, int size)
{
	int i, j;
	u8 *tmp = malloc(size);
	if (tmp)
	{
		for(i = 0, j = size - 1; i < size; i++, j--)
			tmp[i] = buf[j];
		memcpy(buf, tmp, size);
		free(tmp);
	}
}

int bin_to_privite_blob(PRIVATEKEYBLOB *pr_blob, u8 *buf, int buf_len){
    
    u8 *tmp = buf + 2;
    memcpy(&pr_blob->blobheader, tmp, sizeof(pr_blob->blobheader));
    tmp += sizeof(pr_blob->blobheader);
    
    memcpy(&pr_blob->rsapubkey, tmp, sizeof(pr_blob->rsapubkey));
    tmp += sizeof(pr_blob->rsapubkey);
    
    int bitlen = pr_blob->rsapubkey.bitlen;
    pr_blob->modulus = malloc(bitlen/8);
	pr_blob->prime1 = malloc(bitlen/16);
	pr_blob->prime2 = malloc(bitlen/16);
	pr_blob->exponent1 = malloc(bitlen/16);
	pr_blob->exponent2 = malloc(bitlen/16);
	pr_blob->coefficient = malloc(bitlen/16);
	pr_blob->privateExponent = malloc(bitlen/8);

    memcpy(pr_blob->modulus, tmp, pr_blob->rsapubkey.bitlen/8);
    tmp += pr_blob->rsapubkey.bitlen/8;
    
    memcpy(pr_blob->prime1, tmp, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(pr_blob->prime2, tmp, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(pr_blob->exponent1, tmp, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(pr_blob->exponent2, tmp, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(pr_blob->coefficient, tmp, pr_blob->rsapubkey.bitlen/16);
    tmp += pr_blob->rsapubkey.bitlen/16;
    
    memcpy(pr_blob->privateExponent, tmp, pr_blob->rsapubkey.bitlen/8);
    tmp += pr_blob->rsapubkey.bitlen/8;
    
    return 0;
}

/*
 * Create/override new EF.
 */
int rutoken_create_file(sc_card_t *card, sc_path_t *path, sc_file_t *ef)
{
	int ret = SC_SUCCESS;
	if(path)
	{
		ret = card->ops->select_file(card, path, NULL);
		if (ret == SC_SUCCESS)
		{
			sc_path_t del_path;
			del_path.len = 2;
			del_path.type = SC_PATH_TYPE_FILE_ID;
			del_path.value[0] = (u8)(ef->id / 256);
			del_path.value[1] = (u8)(ef->id % 256);
			if (card->ops->select_file(card, &del_path, NULL) == SC_SUCCESS)
				ret = card->ops->delete_file(card, &del_path);
		}
	}
	if (ret == SC_SUCCESS)
	{
		ret = card->ops->create_file(card, ef);
	}
	
	return ret;
}

/*
 * Create a DF
 */
static int
rutoken_create_dir(sc_profile_t *profile, sc_card_t *card, sc_file_t *df)
{
	int ret = SC_SUCCESS;
	sc_file_t *file = NULL;
	
	SC_FUNC_CALLED(card->ctx, 1);
	ret = card->ops->select_file(card, &df->path, &file);
	if (ret == SC_ERROR_FILE_NOT_FOUND)
		ret = card->ops->create_file(card, df);
	else if(file && file->type != SC_FILE_TYPE_DF)
		ret = SC_ERROR_WRONG_CARD;
	
	if(file)
		sc_file_free(file);
	return ret;
}


/*
 * Select a key reference
 */

static int
rutoken_select_key_reference(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_prkey_info_t *key_info)
{
	SC_FUNC_CALLED(card->ctx, 1);
	/* hocus-pocus :) */
	sc_format_path(PRK_DF, &key_info->path);
	sc_append_file_id(&key_info->path, key_info->key_reference);
	//g_nKeyRef = key_info->key_reference;
	return 	key_info->key_reference >= 0 && key_info->key_reference <= MAX_ID ? SC_SUCCESS : SC_ERROR_TOO_MANY_OBJECTS;		
}

/*
 * Create a private key object.
 * This is a no-op.
 */
static int
rutoken_create_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj)
{
	SC_FUNC_CALLED(card->ctx, 1);
	return 0;
}

/*  Send the pkcs15 profile to its doom. NOTE:This change current DF!  */
static void fix_pkcs15(sc_profile_t *profile, sc_card_t *card, int type, int x)
{
	sc_file_t *df;
	
	if(profile->df[type])
		df = profile->df[type];
	else
	{
		df = sc_file_new();
		profile->df[type] = df;
	}
	
	switch(type)
	{
	case SC_PKCS15_PRKDF:
		sc_format_path(PRK_DF, &df->path);
		break;
	case SC_PKCS15_PUKDF:
		sc_format_path(PUK_DF, &df->path);
		break;
	case SC_PKCS15_CDF:
		sc_format_path(C_DF, &df->path);
		break;
	default:
		return;
	}
	df->id = DFsId;
	df->size = DFsSize;
	df->type = SC_FILE_TYPE_WORKING_EF;
	df->ef_structure = SC_FILE_EF_TRANSPARENT;
	
	sc_append_file_id(&df->path, df->id);
	sc_path_t odf_path;
	sc_format_path("3f0000000000dfff", &odf_path);
	if(card->ops->select_file(card, &odf_path, NULL) == SC_SUCCESS)
	{
		odf_path.len = 0;
		odf_path.type = SC_PATH_TYPE_FILE_ID;
		card->ops->delete_file(card, &odf_path);
	}
}

int rutoken_check_df(sc_card_t *card, int df_id)
{
	int ret = -1;
	sc_path_t path;
	
	sc_file_t *file = sc_file_new();
	if(file)
	{
		sc_format_path(GCHV_DF, &path);
		ret = card->ops->select_file(card, &path, NULL);
	}
	else
		ret = SC_ERROR_OUT_OF_MEMORY;
	if (ret == SC_SUCCESS) 
	{
		sc_format_path(APP_DF, &file->path);
		file->type = SC_FILE_TYPE_DF;
			// FIXME: change to 'df' secattr
		sc_file_set_sec_attr(file, (u8*)&pb_sec_attr, SEC_ATTR_SIZE);
		/*  appdf (ff00)  */
		file->id = 0xff00;
		ret = rutoken_create_dir(NULL, card, file);
	}
	if (ret == SC_SUCCESS) 
	{
		/*  p15df  */
		sc_format_path(APP_DF, &path);
		card->ops->select_file(card, &path, NULL);
		file->id = df_id;
		file->path = path;
		sc_append_file_id(&file->path, df_id);
		ret = rutoken_create_dir(NULL, card, file);
	}
	if(file) sc_file_free(file);
	return ret;
}

/*
 * create private key files
 */
int rutoken_create_prkeyfile(sc_card_t *card,
							 sc_pkcs15_prkey_info_t *key_info,
							 sc_file_t **prkf, size_t prsize)
{
	int ret;
	SC_FUNC_CALLED(card->ctx, 1);
	sc_path_t	path;
	int id = key_info->key_reference;
	{
		sc_file_t *file = sc_file_new();
		if (file) ret = rutoken_check_df(card, PrKDFid);
		else ret = SC_ERROR_OUT_OF_MEMORY;
		if (ret == SC_SUCCESS)
		{
			/* create key file */
			sc_format_path(PRK_DF, &path);
			file->type = SC_FILE_TYPE_WORKING_EF;
			file->id = id;
			file->size = prsize;
			sc_file_set_sec_attr(file, (u8*)&pr_sec_attr, SEC_ATTR_SIZE);
			ret = rutoken_create_file(card, &path, file);
		}
		if (file) sc_file_free(file);
	}
	return ret;
}


/*  Store a private key object. */
static int
rutoken_store_key(sc_profile_t *profile, sc_card_t *card,
			sc_pkcs15_object_t *obj,
			sc_pkcs15_prkey_t *key)
{
	SC_FUNC_CALLED(card->ctx, 1);
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	const int nKeyBufSize = 2048;
	u8 *prkeybuf = NULL;
	size_t		prsize;
	int ret;
	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) 
		return SC_ERROR_NOT_SUPPORTED;
	
	prkeybuf = calloc(nKeyBufSize, 1);
	if(!prkeybuf)
		return SC_ERROR_OUT_OF_MEMORY;
	
	/* encode private key 
	 * create key file 
	 * write a key */
	prsize = nKeyBufSize;
	
	if((ret = profile->ops->encode_private_key(profile, card, &key->u.rsa, prkeybuf, &prsize, 0)) == 0 &&
		   ( ret = rutoken_create_prkeyfile(card, key_info, NULL, prsize)) == 0)
	{
		if((ret = sc_update_binary(card, 0, prkeybuf, prsize, 0)) == prsize)
		{
			fix_pkcs15(profile, card, P15_DF(obj->type), 0);
		}
	}
	free(prkeybuf);
	return ret;
}
static int
rutoken_encode_private_key(sc_profile_t *profile, sc_card_t *card,
			struct sc_pkcs15_prkey_rsa *rsa,
			u8 *key, size_t *keysize, int key_ref)
{
	PRIVATEKEYBLOB prkeyblob;
	create_privite_blob(&prkeyblob, rsa);
	int r =  privite_blob_to_bin(&prkeyblob, key, keysize);
	free_privite_blob(&prkeyblob);
	return r;
}



int rutoken_id_in(int id, const u8 *buf, int buflen)
{
	int i;
	for (i = 0; i*2 < buflen; i++)
		if (id == (int)buf[i*2] * 0x100 + buf[i*2 + 1]) return 1;
	return 0;
}

int rutoken_find_id(sc_card_t *card, const sc_path_t *path)
{
	int ret = SC_SUCCESS;
	sc_file_t *file = NULL;
	u8 *files = malloc(2048);
	if (!files) return SC_ERROR_OUT_OF_MEMORY;
	if(path)
	{
		if((ret = card->ops->select_file(card, path, &file)) == SC_SUCCESS)
			ret = file->type == SC_FILE_TYPE_DF ? SC_SUCCESS : SC_ERROR_NOT_ALLOWED;
	}
	if(ret == SC_SUCCESS)
	{
		ret = card->ops->list_files(card, files, 2048);
		if(ret >= 0)
		{
			int i;
			for (i = 0; i < MAX_ID; i++)
				if(!rutoken_id_in(i, files, ret)) {ret = i; break;}
		}
	}
	free(files);
	if(file)sc_file_free(file);
	return ret;
}

int rutoken_new_file(struct sc_profile *profile, struct sc_card *card,
					 unsigned int type, unsigned int idx, struct sc_file **file)
{
	SC_FUNC_CALLED(card->ctx, 1);
	int ret = SC_SUCCESS, id;
	sc_path_t path;
	switch (type & SC_PKCS15_TYPE_CLASS_MASK)
	{
		case SC_PKCS15_TYPE_CERT:

			ret = rutoken_check_df(card, CDFid);
			/* find first unlished file id */
			if (ret == SC_SUCCESS) ret = (id = rutoken_find_id(card, NULL)) >= 0 ? SC_SUCCESS : SC_ERROR_TOO_MANY_OBJECTS;
			sc_format_path(C_DF, &path);
			break;
		case SC_PKCS15_TYPE_PUBKEY:
			ret = rutoken_check_df(card, PuKDFid);
			if (ret == SC_SUCCESS) ret = (id = rutoken_find_id(card, NULL)) >= 0 ? SC_SUCCESS : SC_ERROR_TOO_MANY_OBJECTS;
			sc_format_path(PUK_DF, &path);
			break;
		case SC_PKCS15_TYPE_PRKEY_RSA:
		default:
			ret = SC_ERROR_NOT_SUPPORTED;
	}
	
	if(ret == SC_SUCCESS)
	{
		*file = sc_file_new();
		(*file)->size = 0;
		(*file)->id = id; 
		sc_append_file_id(&path, (*file)->id);
		(*file)->path = path;
		sc_file_set_sec_attr(*file, (u8*)&pb_sec_attr, SEC_ATTR_SIZE);
		(*file)->type = SC_FILE_TYPE_WORKING_EF;
		/*  If target file exist than remove it */
		if (card->ops->select_file(card, &(*file)->path, NULL) == SC_SUCCESS)
		{
			sc_path_t del_path;
			del_path.len = 0;
			del_path.type = SC_PATH_TYPE_FILE_ID;
			card->ops->delete_file(card, &del_path);
		}
		fix_pkcs15(profile, card, P15_DF(type), 0);
	}
	return ret;
}

int rutoken_delete_object(struct sc_profile *profile, struct sc_card *card,
						  unsigned int type, const void *data, const sc_path_t *path)
{
	int ret = -1, tries_left = 2;
	/* try to logon as user*/
	card->ops->logout(card);
	
	u8 *pin;
	ret = card->ops->card_ctl(card, SC_CARDCTL_RUTOKEN_TRIES_LEFT, &tries_left);
	while(ret == SC_ERROR_PIN_CODE_INCORRECT && tries_left > 0) 
	{
		pin = (u8*)getpass("Please enter User PIN: ");
		ret = sc_verify(card, SC_AC_CHV, 2, pin, 8, NULL);
		if(ret != SC_SUCCESS)
		{
			tries_left = 2;
			card->ops->card_ctl(card, SC_CARDCTL_RUTOKEN_TRIES_LEFT, &tries_left);
			fprintf(stderr, "PIN code verification failed: %s\n%d tries left\n", sc_strerror(ret), tries_left);
		}
	}
	if( (ret == SC_SUCCESS) &&
			(ret = card->ops->select_file(card, path, NULL) == SC_SUCCESS))
	{
		sc_path_t del_path;
		memset(&del_path, 0, sizeof(del_path));
		del_path.type = SC_PATH_TYPE_FILE_ID;
		del_path.value[0] = path->value[path->len - 2];
		del_path.value[1] = path->value[path->len - 1];
		del_path.len = 2;

		ret = sc_delete_file(card, &del_path);
	}
	return ret;
}


/*
*  Inicialization routine
*/
		
/*  Complete initialization  */
int rutoken_check_sw(sc_card_t *, unsigned int, unsigned int);
int rutoken_finalize_card(sc_card_t *card)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	SC_FUNC_CALLED(card->ctx, 1);
	sc_apdu_t	apdu = {0};
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x7b, 0x00, 0x00);
	apdu.cla = 0x80;
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	
	SC_FUNC_RETURN(card->ctx, 1, ret);
}

/* Try to delete pkcs15 structure  */
int	rutoken_erase(struct sc_profile *profile, sc_card_t *card)
{
	int ret = SC_ERROR_CARD_CMD_FAILED;
	SC_FUNC_CALLED(card->ctx, 1);
	sc_apdu_t	apdu = {0};
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x7a, 0x00, 0x00);
	apdu.cla = 0x80;
	if(sc_transmit_apdu(card, &apdu) >= 0)
		ret = rutoken_check_sw(card, apdu.sw1, apdu.sw2);
	
	SC_FUNC_RETURN(card->ctx, 1, ret);
	
	return ret;
}

/*  create pkcs15 structure  */
int rutoken_init(sc_profile_t *profile, sc_card_t *card)
{
	return SC_ERROR_NOT_SUPPORTED;
}


static struct sc_pkcs15init_operations sc_pkcs15init_rutoken_operations = {
	rutoken_erase,
	rutoken_init,				/* init_card */
	rutoken_create_dir,
	NULL,				/* create_domain */
	NULL/*rutoken_select_pin_reference*/,
	NULL/*rutoken_create_pin*/,
	rutoken_select_key_reference,
	rutoken_create_key,
	rutoken_store_key,
		NULL, /* rutoken_generate_key,  */
	rutoken_encode_private_key,
	NULL,  /* encode private/public key */
	rutoken_finalize_card,				/* finalize_card */
	
	NULL, NULL, NULL, 
	rutoken_new_file, 
	NULL,	/* old style api */
	
	rutoken_delete_object 				/* delete_object */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_rutoken_ops(void)
{
	return &sc_pkcs15init_rutoken_operations;
}

static void set_string(char **strp, const char *value)
{
	if (*strp) free(*strp);
	*strp = value ? strdup(value) : NULL;
}

#define KEY_LABEL    "GOST 28.147-89 KEY"
#define OBJ_LABEL    "SE object"
#define RUT_LABEL    "ruToken card"
	
static const struct {
	int           type, id, auth_id, min_length;
	unsigned char reference;
	const char   *path;
	const char   *label;
	int           flags;
} pinlist[]=
{
	
	{1, 2, 2, 1, 0x02, "3f0000000000", "User PIN",
			SC_PKCS15_PIN_FLAG_LOCAL|SC_PKCS15_PIN_FLAG_CASE_SENSITIVE /*| SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN*/},
	{0, 0, 0, 0, 0, NULL, NULL, 0}
};

int sc_pkcs15emu_rutoken_init_ex(sc_pkcs15_card_t *p15card, sc_pkcs15emu_opt_t *opts);

void add_predefined_pin(sc_pkcs15_card_t *p15card)
{
	int i;
	sc_path_t          path;
	sc_pkcs15_pin_info_t *pin_info = (sc_pkcs15_pin_info_t *) calloc(1, sizeof(*pin_info));
	sc_pkcs15_object_t   *pin_obj = (sc_pkcs15_object_t *) calloc(1, sizeof(*pin_obj));
	for(i=0; pinlist[i].id; ++i)
	{
		sc_format_path(pinlist[i].path, &path);
		pin_info->auth_id.len      = 1;
		pin_info->auth_id.value[0] = 1;
		pin_info->reference        = pinlist[i].reference;
		pin_info->flags            = pinlist[i].flags;
		pin_info->type             = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
		pin_info->min_length       = pinlist[i].min_length;
		pin_info->stored_length    = 16;
		pin_info->max_length       = 16;
		pin_info->pad_char         = -1;
		pin_info->tries_left       = 1;
		sc_format_path(pinlist[i].path, &pin_info->path);

		strncpy(pin_obj->label, pinlist[i].label, SC_PKCS15_MAX_LABEL_SIZE - 1);
		pin_obj->flags            = SC_PKCS15_CO_FLAG_PRIVATE;
		
		sc_pkcs15emu_add_pin_obj(p15card, pin_obj, pin_info);
		free(pin_obj);
		free(pin_info);
	}
}

static int sc_pkcs15_rutoken_init_func(sc_pkcs15_card_t *p15card)
{
	int ret = SC_ERROR_WRONG_CARD;
	sc_card_t         *card = p15card->card;
	sc_context_t      *ctx = p15card->card->ctx;
	sc_path_t          path;
	sc_file_t         *odf;
	sc_serial_number_t serialnr;
	char               serial[30] = {0};
	u8                 info[8];
	
	/*  get the card serial number   */
	if (sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serialnr) < 0) 
	{
		sc_debug(ctx, "unable to get ICCSN");
		goto failed;
	}
	sc_bin_to_hex(serialnr.value, serialnr.len , serial, sizeof(serial), 0);
	set_string(&p15card->serial_number, serial);
	/*  ct_debug("serial_number = %s", serial);  */
	
	/*  get ruToken information  */
	if (sc_card_ctl(card, SC_CARDCTL_RUTOKEN_GET_INFO, info) < 0) 
	{
		sc_debug(ctx, "unable to get token information");
		goto failed;
	}
	set_string(&p15card->label, RUT_LABEL);
	p15card->version = (info[1] >> 4)*10 + (info[1] & 0x0f);
	sc_bin_to_hex(info + 3, 3 , serial, sizeof(serial), 0);
	set_string(&p15card->manufacturer_id, serial);
	
	odf = sc_file_new();
	if(odf)
	{
		sc_format_path("3f0000000000dfff", &odf->path);
		odf->id = 0xdfff;
		odf->type = SC_FILE_TYPE_WORKING_EF;
		odf->ef_structure = SC_FILE_EF_TRANSPARENT;
		odf->size = 1024;
		p15card->file_odf = odf;
	}
	
	add_predefined_pin(p15card);
	
	while (p15card->df_list)
		sc_pkcs15_remove_df(p15card, p15card->df_list);
	
	
	sc_file_t *df = sc_file_new();
	if (df)
	{
		df->id = DFsId;
		df->size = 0;
		df->type = SC_FILE_TYPE_WORKING_EF;
		df->ef_structure = SC_FILE_EF_TRANSPARENT;
	
	
		sc_format_path(PRK_DF, &path);
		sc_append_file_id(&path, df->id);
		if(card->ops->select_file(card, &path, NULL) == SC_SUCCESS)
		{
			df->path = path;
			sc_pkcs15_add_df(p15card, SC_PKCS15_PRKDF, &path, df);
		}
		sc_format_path(PUK_DF, &path);
		sc_append_file_id(&path, df->id);
		if(card->ops->select_file(card, &path, NULL) == SC_SUCCESS)
		{
			df->path = path;
			sc_pkcs15_add_df(p15card, SC_PKCS15_PUKDF, &path, df);
		}
		sc_format_path(C_DF, &path);
		sc_append_file_id(&path, df->id);
		if(card->ops->select_file(card, &path, NULL) == SC_SUCCESS)
		{
			df->path = path;
			sc_pkcs15_add_df(p15card, SC_PKCS15_CDF, &path, df);
		}
		sc_file_free(df);
	}
	ret = SC_SUCCESS;
failed:	
	return ret;
}

int sc_pkcs15emu_rutoken_init_ex(sc_pkcs15_card_t *p15card,
								 sc_pkcs15emu_opt_t *opts)
{
	struct sc_card *card = p15card->card;
	
	SC_FUNC_CALLED(card->ctx, 1);
	
	/* check if we have the correct card OS */
	if (strcmp(card->name, "rutoken card"))
		return SC_ERROR_WRONG_CARD;
	
	sc_debug(card->ctx, "%s found", card->name);
	return sc_pkcs15_rutoken_init_func(p15card);
}
