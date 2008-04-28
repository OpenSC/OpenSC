/*
 * Oberthur specific operation for PKCS #15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Idealx <www.idealx.org>
 *                     Viktor Tarasov <vtarasov@idealx.com>
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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif

#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "profile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COSM_TITLE "OberthurAWP"

#define COSM_TLV_TAG	0x00
#define COSM_LIST_TAG   0xFF
#define COSM_TAG_CONTAINER  0x0000
#define COSM_TAG_CERT   0x0001
#define COSM_TAG_PRVKEY_RSA      0x04B1
#define COSM_TAG_PUBKEY_RSA      0x0349
#define COSM_TAG_DES      0x0679
#define COSM_TAG_DATA      0x0001
#define COSM_IMPORTED   0x0000
#define COSM_GENERATED  0x0004

#define TLV_TYPE_V	0
#define TLV_TYPE_LV      1
#define TLV_TYPE_TLV	2

/* Should be greater then SC_PKCS15_TYPE_CLASS_MASK */
#define SC_DEVICE_SPECIFIC_TYPE	 0x1000

#define COSM_PUBLIC_LIST (SC_DEVICE_SPECIFIC_TYPE | 0x02)
#define COSM_PRIVATE_LIST (SC_DEVICE_SPECIFIC_TYPE | 0x03)
#define COSM_CONTAINER_LIST  (SC_DEVICE_SPECIFIC_TYPE | 0x04)
#define COSM_TOKENINFO (SC_DEVICE_SPECIFIC_TYPE | 0x05)

#define COSM_TYPE_PRKEY_RSA (SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PRKEY_RSA)
#define COSM_TYPE_PUBKEY_RSA (SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PUBKEY_RSA)

#define NOT_YET 1

static int cosm_update_pin(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_pin_info *info, const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len);

int cosm_delete_file(sc_card_t *card, struct sc_profile *profile,
		sc_file_t *df);

int cosm_delete_file(sc_card_t *card, struct sc_profile *profile,
		sc_file_t *df)
{
	sc_path_t  path;
	sc_file_t  *parent;
	int rv = 0;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "id %04X\n", df->id);
	if (df->type==SC_FILE_TYPE_DF)   {
		rv = sc_pkcs15init_authenticate(profile, card, df, SC_AC_OP_DELETE);
		SC_TEST_RET(card->ctx, rv, "Cannot authenticate SC_AC_OP_DELETE");
	}
	
	/* Select the parent DF */
	path = df->path;
	path.len -= 2;

	rv = sc_select_file(card, &path, &parent);
	SC_TEST_RET(card->ctx, rv, "Cannnot select parent");

	rv = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	SC_TEST_RET(card->ctx, rv, "Cannnot authenticate SC_AC_OP_DELETE");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(card, &path);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Erase the card
 */
static int cosm_erase_card(struct sc_profile *profile, sc_card_t *card)
{
	sc_file_t  *df = profile->df_info->file, *dir;
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete if before the DF because we create
	 * it *after* the DF. 
	 * */
	sc_ctx_suppress_errors_on(card->ctx);
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	sc_debug(card->ctx, "erase file ddf %04X\n",df->id);
	rv=cosm_delete_file(card, profile, df);

	if (sc_profile_get_file(profile, "private-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}
	
	if (sc_profile_get_file(profile, "public-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	rv = sc_profile_get_file(profile, COSM_TITLE"-AppDF", &dir);
	if (!rv) {
		sc_debug(card->ctx, "delete %s; r %i\n", COSM_TITLE"-AppDF", rv);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
	}

done:		
	sc_keycache_forget_key(NULL, -1, -1);
	sc_ctx_suppress_errors_off(card->ctx);

	if (rv==SC_ERROR_FILE_NOT_FOUND)
		rv=0;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Initialize the Application DF
 */
static int 
cosm_init_app(struct sc_profile *profile, sc_card_t *card,	
		struct sc_pkcs15_pin_info *pinfo,
		const u8 *pin,	size_t pin_len, 
		const u8 *puk, size_t puk_len)
{
	int rv;
	size_t ii;
	sc_file_t *file = NULL;
	static const char *create_dfs[] = {
		COSM_TITLE"-AppDF",
		"private-DF",
		"public-DF",
		COSM_TITLE"-token-info",
		COSM_TITLE"-puk-file",
		COSM_TITLE"-container-list",
		COSM_TITLE"-public-list",
		COSM_TITLE"-private-list",
		"PKCS15-AppDF",
		"PKCS15-ODF",
		"PKCS15-AODF",
		"PKCS15-PrKDF",
		"PKCS15-PuKDF",
		"PKCS15-CDF",
		"PKCS15-DODF",
		NULL
	};

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "pin_len %i; puk_len %i\n", pin_len, puk_len);
	
	/* Oberthur AWP file system is expected.*/
	/* Create private objects DF */
	for (ii = 0; create_dfs[ii]; ii++)   {
		if (sc_profile_get_file(profile, create_dfs[ii], &file))   {
			sc_error(card->ctx, "Inconsistent profile: cannot find %s", create_dfs[ii]);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
	
		rv = sc_pkcs15init_create_file(profile, card, file);
		sc_debug(card->ctx, "rv %i\n", rv);
		sc_file_free(file);
		if (rv && rv!=SC_ERROR_FILE_ALREADY_EXISTS)
			SC_TEST_RET(card->ctx, rv, "sc_pkcs15init_create_file() failed");
	}

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

static int cosm_create_reference_data(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_pin_info *pinfo, 
		const u8 *pin, size_t pin_len,	const u8 *puk, size_t puk_len )
{
	int rv;
	int puk_buff_len = 0;
	unsigned char *puk_buff = NULL;
	sc_pkcs15_pin_info_t    profile_pin;
	sc_pkcs15_pin_info_t    profile_puk;
	struct sc_cardctl_oberthur_createpin_info args;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "pin lens %i/%i\n", pin_len,  puk_len);
	if (!pin || pin_len>0x40)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (puk && !puk_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	rv = sc_select_file(card, &pinfo->path, NULL);
	SC_TEST_RET(card->ctx, rv, "Cannot select file");

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_pin);
	if (profile_pin.max_length > 0x100)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INCONSISTENT_PROFILE);

	if (puk)   {
		int ii, jj;
		const unsigned char *ptr = puk;
		
		puk_buff = (unsigned char *) malloc(0x100);
		if (!puk_buff)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_MEMORY_FAILURE);

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &profile_puk);
		if (profile_puk.max_length > 0x100) {
			free(puk_buff);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
		memset(puk_buff, profile_puk.pad_char, 0x100);
		for (ii=0; ii<8 && (size_t)(ptr-puk) < puk_len && (*ptr); ii++)   {
			jj = 0;
			while (isalnum(*ptr) && jj<16)   {
				*(puk_buff + ii*0x10 + jj++) = *ptr;
				++ptr;
			}
			while(!isalnum(*ptr) && (*ptr))
				++ptr;
		}
		
		puk_buff_len = ii*0x10;
	}

	sc_debug(card->ctx, "pinfo->reference %i; tries %i\n", 
			pinfo->reference, profile_pin.tries_left);

	sc_debug(card->ctx, "sc_card_ctl %s\n","SC_CARDCTL_OBERTHUR_CREATE_PIN");
	args.type = SC_AC_CHV;
	args.ref = pinfo->reference;
	args.pin = pin;
	args.pin_len = pin_len;
	args.pin_tries = profile_pin.tries_left;
	args.puk = puk_buff;
	args.puk_len = puk_buff_len;
	args.puk_tries = profile_puk.tries_left;
	
    rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_CREATE_PIN, &args);

	if (puk_buff)
		free(puk_buff);
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
}

/*
 * Update PIN
 */
static int cosm_update_pin(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_pin_info *pinfo, const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len )
{
	int rv;
	int tries_left = -1;
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);

	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
		sc_error(card->ctx,"Pin references should be only in the profile"
				"and in the card-oberthur.\n");
		if (pinfo->reference != 4)
			return SC_ERROR_INVALID_PIN_REFERENCE;
		
		rv = sc_change_reference_data(card, SC_AC_CHV, pinfo->reference, puk, puk_len,
				pin, pin_len, &tries_left);
		sc_debug(card->ctx, "return value %X; tries left %i\n", rv, tries_left);
		if (tries_left != -1)
			sc_error(card->ctx, "Failed to change reference data for soPin: rv %X", rv);

	}
	else   {
		rv = cosm_create_reference_data(profile, card, pinfo, 
				pin, pin_len, puk, puk_len);
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}

static int
cosm_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_pin_info_t *pin_info) 
{
	sc_file_t *pinfile;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pin_info->reference, pin_info->flags);
    if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_error(card->ctx, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}

	pin_info->path = pinfile->path;
	sc_file_free(pinfile);
	
	if (!pin_info->reference)   {
		if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   
    	    pin_info->reference = 4;
		else  
        	pin_info->reference = 1;
	}

    if (pin_info->reference < 0 || pin_info->reference > 4)
		return SC_ERROR_INVALID_PIN_REFERENCE;

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}

/*
 * Store a PIN
 */
static int
cosm_create_pin(sc_profile_t *profile, sc_card_t *card, sc_file_t *df,
		sc_pkcs15_object_t *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	sc_pkcs15_pin_info_t *pinfo = (sc_pkcs15_pin_info_t *) pin_obj->data;
	sc_file_t *pinfile;
	int rv = 0, type;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);
    if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_error(card->ctx, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}
		    
	pinfo->path = pinfile->path;
	sc_file_free(pinfile);
	
	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		type = SC_PKCS15INIT_SO_PIN;

		if (pinfo->reference != 4)  
			return SC_ERROR_INVALID_ARGUMENTS;
	} 
	else {
		type = SC_PKCS15INIT_USER_PIN;
		
		if (pinfo->reference !=1  &&  pinfo->reference != 2)
			return SC_ERROR_INVALID_PIN_REFERENCE;
	}

	if (pin && pin_len)   {
	    rv = cosm_update_pin(profile, card, pinfo, pin, pin_len,  puk, puk_len);
	}
	else   {
		sc_debug(card->ctx, "User PIN not updated");		
	}
    sc_debug(card->ctx, "return %i\n", rv);
        
	sc_keycache_set_pin_name(&pinfo->path, pinfo->reference, type);
	pinfo->flags &= ~SC_PKCS15_PIN_FLAG_LOCAL;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Allocate a file
 */
static int
cosm_new_file(struct sc_profile *profile, sc_card_t *card,
		unsigned int type, unsigned int num, sc_file_t **out)
{
	struct sc_file	*file;
	const char *_template = NULL, *desc = NULL;
	unsigned int structure = 0xFFFFFFFF;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "type %X; num %i\n",type, num);
	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
		case COSM_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			_template = "template-private-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
		case COSM_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			_template = "template-public-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
			break;
		case SC_PKCS15_TYPE_PUBKEY_DSA:
			desc = "DSA public key";
			_template = "template-public-key";
			break;
		case SC_PKCS15_TYPE_PRKEY:
			desc = "extractable private key";
			_template = "template-extractable-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			desc = "certificate";
			_template = "template-certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			_template = "template-public-data";
			break;
		}
		if (_template)
			break;
		/* If this is a specific type such as
		 * SC_PKCS15_TYPE_CERT_FOOBAR, fall back to
		 * the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			sc_error(card->ctx, "File type %X not supported by card driver", 
				type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_debug(card->ctx, "template %s; num %i\n",_template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_error(card->ctx, "Profile doesn't define %s template '%s'\n",
				desc, _template);
		return SC_ERROR_NOT_SUPPORTED;
	}
    
	file->id |= (num & 0xFF);
	file->path.value[file->path.len-1] |= (num & 0xFF);
	if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
		file->ef_structure = structure;
	}

	sc_debug(card->ctx, "file size %i; ef type %i/%i; id %04X\n",file->size, 
			file->type, file->ef_structure, file->id);
	*out = file;

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


/*
 * RSA key generation
 */
static int
cosm_old_generate_key(struct sc_profile *profile, sc_card_t *card,
		unsigned int idx, unsigned int keybits,
		sc_pkcs15_pubkey_t *pubkey,
		struct sc_pkcs15_prkey_info *info)
{
	struct sc_cardctl_oberthur_genkey_info args;
	struct sc_file	*prkf = NULL, *tmpf = NULL;
	struct sc_path path;
	int	 rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "index %i; nn %i\n", idx, keybits);
	if (keybits < 512 || keybits > 2048 || (keybits%0x20))   {
		sc_error(card->ctx, "Unsupported key size %u\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	/* Get private key file from profile. */
	if ((rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx, 
					&prkf)) < 0)
	 	goto failed;
	sc_debug(card->ctx, "prv ef type 0x%X\n",prkf->ef_structure);
	prkf->size = keybits;
	
	/* Access condition of private object DF. */
	path = prkf->path;
	path.len -= 2;

    rv = sc_select_file(card, &path, &tmpf);
    SC_TEST_RET(card->ctx, rv, "Generate RSA: no private object DF");
	
	rv = sc_pkcs15init_authenticate(profile, card, tmpf, SC_AC_OP_CRYPTO); 
	sc_debug(card->ctx, "rv %i\n",rv);
	if (rv < 0)  
		goto failed;
	
	rv = sc_pkcs15init_authenticate(profile, card, tmpf, SC_AC_OP_CREATE);
	sc_debug(card->ctx, "rv %i\n",rv);
	if (rv < 0) 
		goto failed;
	
	sc_file_free(tmpf);
	
	/* In the private key DF create the temporary public RSA file. */
	sc_debug(card->ctx, "ready to create public key\n");
	sc_file_dup(&tmpf, prkf);
	if (tmpf == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		goto failed; 
	}
	tmpf->type = SC_FILE_TYPE_INTERNAL_EF;
	tmpf->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	tmpf->id = 0x1012;
	tmpf->path.value[tmpf->path.len - 2] = 0x10;
	tmpf->path.value[tmpf->path.len - 1] = 0x12;

	rv = sc_pkcs15init_create_file(profile, card, prkf);
	sc_debug(card->ctx, "rv %i\n",rv);
	if (rv)   { 
		sc_debug(card->ctx, "prkf create file failed\n");
		goto failed;
	}
	
	rv = sc_pkcs15init_create_file(profile, card, tmpf);
	sc_debug(card->ctx, "rv %i\n",rv);
	if (rv)   {
		sc_debug(card->ctx, "pubf create failed\n");
		goto failed;
	}
	
	memset(&args, 0, sizeof(args));
	args.id_prv = prkf->id;
	args.id_pub = tmpf->id;
	args.exponent = 0x10001;
	args.key_bits = keybits;
	args.pubkey_len = keybits/8;
	args.pubkey = (unsigned char *) malloc(keybits/8);
	if (!args.pubkey)   {
		rv = SC_ERROR_OUT_OF_MEMORY;
		goto failed;
	}
	
	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_GENERATE_KEY, &args);
	if (rv < 0)
		goto failed;
	
	/* extract public key */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = keybits / 8;
	pubkey->u.rsa.modulus.data  = (u8 *) malloc(keybits / 8);
	if (!pubkey->u.rsa.modulus.data)   {
		rv = SC_ERROR_MEMORY_FAILURE;
		goto failed;
	}
	
	/* FIXME and if the exponent length is not 3? */
	pubkey->u.rsa.exponent.len  = 3;
	pubkey->u.rsa.exponent.data = (u8 *) malloc(3);
	if (!pubkey->u.rsa.exponent.data)   {
		rv = SC_ERROR_MEMORY_FAILURE;
		goto failed;
	}
	memcpy(pubkey->u.rsa.exponent.data, "\x01\x00\x01", 3);
	memcpy(pubkey->u.rsa.modulus.data, args.pubkey, args.pubkey_len);

#ifndef NOT_YET
	rv = sc_pkcs15_encode_pubkey(card->ctx, pubkey, &info->value.value, &info->value.len);
	sc_debug(card->ctx, "rv %i\n",rv);
	if (rv)   {
		sc_debug(card->ctx, "rv %i\n", rv);
		goto failed;
	}
#endif
	info->key_reference = 1;
	info->path = prkf->path;
	
	if (rv)   {
		sc_debug(card->ctx, "rv %i\n", rv);
		goto failed;
	}
	
	sc_debug(card->ctx, "delete temporary public key\n");
	if ((rv =  cosm_delete_file(card, profile, tmpf)))
		goto failed;
	
failed:	
	if (tmpf) sc_file_free(tmpf);
	if (prkf) sc_file_free(prkf);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Store a private key
 */
static int
cosm_new_key(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_prkey *key, unsigned int idx,
		struct sc_pkcs15_prkey_info *info)
{
	sc_file_t *prvfile = NULL;
	struct sc_pkcs15_prkey_rsa *rsa = NULL;
#ifndef NOT_YET
	sc_pkcs15_pubkey_t pubkey;
#endif
	int rv;
	char pbuf[SC_MAX_PATH_STRING_SIZE];
	struct sc_cardctl_oberthur_updatekey_info update_info;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "index %i; id %s\n", idx, sc_pkcs15_print_id(&info->id));
	if (key->algorithm != SC_ALGORITHM_RSA)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);

	/* Create and populate the private part. */
	rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx,
					&prvfile);
	SC_TEST_RET(card->ctx, rv, "Update RSA: cosm_new_file failed");
	
	rv = sc_path_print(pbuf, sizeof(pbuf), &prvfile->path);
	sc_debug(card->ctx, "rv %i\n", rv);
	if (rv != SC_SUCCESS)
		pbuf[0] = '\0';
	sc_debug(card->ctx, " prvfile->id %i;  path=%s\n", prvfile->id, pbuf);

	rsa = &key->u.rsa;
	
	prvfile->size = rsa->modulus.len << 3;

	rv = sc_select_file(card, &prvfile->path, NULL);
	sc_debug(card->ctx, "rv %i", rv);
	if (rv==SC_ERROR_FILE_NOT_FOUND)   {
		sc_debug(card->ctx, "Before create file");
		rv = sc_pkcs15init_create_file(profile, card, prvfile);
	}
	SC_TEST_RET(card->ctx, rv, "Update RSA: select/create key file failed");
	
	rv = sc_pkcs15init_authenticate(profile, card, prvfile, SC_AC_OP_UPDATE);
	SC_TEST_RET(card->ctx, rv, "Update RSA: no authorisation");

#ifdef ENABLE_OPENSSL	
	if (!info->id.len)   {
		SHA1(rsa->modulus.data, rsa->modulus.len, info->id.value);
		info->id.len = SHA_DIGEST_LENGTH;
		sc_debug(card->ctx, "ID: %s\n", sc_pkcs15_print_id(&info->id));		
	}
#endif
	
	if (info->id.len > sizeof(update_info.id))
		 SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	memset(&update_info, 0, sizeof(update_info));
	update_info.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
	update_info.data = (void *)rsa;
	update_info.data_len = sizeof(void *);
	update_info.id_len = info->id.len;
	memcpy(update_info.id, info->id.value, update_info.id_len);
		
	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_UPDATE_KEY, &update_info);
	SC_TEST_RET(card->ctx, rv, "Update KEY failed");
	
	info->path = prvfile->path;
	info->modulus_length = rsa->modulus.len << 3;

#ifndef NOT_YET
	/* extract public key */
	pubkey.algorithm = SC_ALGORITHM_RSA;
	pubkey.u.rsa.modulus.len   = rsa->modulus.len;
	pubkey.u.rsa.modulus.data  = (u8 *) malloc(rsa->modulus.len);
	if (!pubkey.u.rsa.modulus.data)   
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_MEMORY_FAILURE);
	
	pubkey.u.rsa.exponent.len  = rsa->exponent.len;
	pubkey.u.rsa.exponent.data = (u8 *) malloc(rsa->exponent.len);
	if (!pubkey.u.rsa.exponent.data)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_MEMORY_FAILURE);
		
	memcpy(pubkey.u.rsa.exponent.data, rsa->exponent.data, rsa->exponent.len);
	memcpy(pubkey.u.rsa.modulus.data, rsa->modulus.data, rsa->modulus.len);

	rv = sc_pkcs15_encode_pubkey(card->ctx, &pubkey, &info->value.value, &info->value.len);
	SC_TEST_RET(card->ctx, rv, "Update RSA: encode public key failed");

	free(pubkey.u.rsa.modulus.data);
	free(pubkey.u.rsa.exponent.data);
#endif

	if (prvfile) 
		sc_file_free(prvfile);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}

#ifdef COSM_EXTENDED
static int 
cosm_delete_object (struct sc_profile *profile, struct sc_card *card,
		unsigned int type, const void *data, const sc_path_t *path)
{
	struct sc_file *file = sc_file_new();
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
    file->type = SC_FILE_TYPE_WORKING_EF;
    file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->id = path->value[path->len-2] * 0x100 + path->value[path->len-1];
	memcpy(&file->path, path, sizeof(file->path));

	rv = cosm_delete_file(card, profile, file);
	
	sc_file_free(file);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}

static int
cosm_path_to_index (struct sc_pkcs15_object *object, int *index, sc_pkcs15_der_t *out_der)
{
	struct sc_path path;
	sc_pkcs15_der_t der;
	
	if (!object || !index || !out_der)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PRKEY:
		path = ((struct sc_pkcs15_prkey_info *)object->data)->path;
		der = ((struct sc_pkcs15_prkey_info *)object->data)->value;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		path = ((struct sc_pkcs15_pubkey_info *)object->data)->path;
		der = ((struct sc_pkcs15_pubkey_info *)object->data)->value;
		break;
	case SC_PKCS15_TYPE_CERT:
		path = ((struct sc_pkcs15_cert_info *)object->data)->path;
		der = ((struct sc_pkcs15_cert_info *)object->data)->value;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		path = ((struct sc_pkcs15_data_info *)object->data)->path;
		der = ((struct sc_pkcs15_data_info *)object->data)->value;
		break;
	default:
		return SC_ERROR_INTERNAL;
	
	}	

	out_der->value = der.value;
	out_der->len = der.len;
	*index = path.value[path.len-1] & 0xFF;
	
	return SC_SUCCESS;
}


static int
cosm_set_id (struct sc_context *ctx, struct sc_pkcs15_object *object, 
		unsigned char *in, int in_len)
{
	struct sc_pkcs15_id *id;

	SC_FUNC_CALLED(ctx, 1);	
	sc_debug(ctx, "in_len %i, type 0x%X\n", in_len,  object->type);
	if (!object || !in || !in_len || in_len > SC_PKCS15_MAX_ID_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PRKEY:
		id = &((struct sc_pkcs15_prkey_info *)object->data)->id;
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		id = &((struct sc_pkcs15_pubkey_info *)object->data)->id;
		break;
	case SC_PKCS15_TYPE_CERT:
		id = &((struct sc_pkcs15_cert_info *)object->data)->id;
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		id = &((struct sc_pkcs15_data_info *)object->data)->id;
		break;
	default:
		return SC_ERROR_INTERNAL;
	
	}

	memcpy(id->value, in, in_len);
	id->len = in_len;
	
	sc_debug(ctx, "id %s\n", sc_pkcs15_print_id(id));
	SC_FUNC_RETURN(ctx, 1, SC_SUCCESS);
}


static int  
cosm_update_df_delete_object(struct sc_pkcs15_card *p15card, 
		struct sc_profile *profile, 
		struct sc_pkcs15_object *object)
{
	int rv;
	
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	
	rv = cosm_ext_remove_data (profile, p15card->card, object);
	
	SC_FUNC_RETURN(p15card->card->ctx, 1, rv);
}


static int  
cosm_update_df_new_object(struct sc_pkcs15_card *p15card, 
		struct sc_profile *profile, 
		struct sc_pkcs15_object *object)
{
	struct sc_pkcs15_pubkey pubkey;
	struct sc_pkcs15_der der;
	struct sc_pkcs15_tokeninfo tokeninfo;
	struct cosm_key_info ikey;
	struct cosm_cert_info icert;
	struct cosm_data_info idata;			
	struct sc_card *card = p15card->card;
	struct sc_file *info_file=NULL, *obj_file=NULL;
	int index, prvkey_id, rv;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!p15card || !profile)   
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	else  if (!object) 
		SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);

	if (object->type == SC_PKCS15_TYPE_AUTH_PIN)   {
		sc_debug(card->ctx, "P15 Label %s\n", p15card->label);
		p15card->label = realloc(p15card->label, 
				strlen(p15card->label) + strlen(labelPinDomain) + 5);
		if (!p15card->label)
			return SC_ERROR_MEMORY_FAILURE;

		strcat(p15card->label, " (");
		strcat(p15card->label, labelPinDomain);
		strcat(p15card->label, ")");
		
		memset(&tokeninfo, 0, sizeof(tokeninfo));
		
		tokeninfo.label = p15card->label;
		
		sc_debug(card->ctx, "Before cosm_update_tokeninfo()");
		rv = cosm_update_tokeninfo(p15card, profile, &tokeninfo);
		return rv;
	}
	
	sc_debug(p15card->card->ctx, "object %s; type 0x%X; der length %i; data %p\n", 
			object->label, object->type, object->der.len, object->data);
	rv = cosm_path_to_index (object, &index, &der);
	if (rv)   {
		sc_debug(p15card->card->ctx, "return %i", rv);
		return rv;
	}
	sc_debug(p15card->card->ctx, "der.value %p; der.len %i\n", der.value, der.len);
	
	rv = cosm_oberthur_new_file(profile, card, object->type,
			index, &info_file, &obj_file);
	if (rv)   {
		sc_debug(p15card->card->ctx, "return %i", rv);
		return rv;
	}

	switch (object->type)   {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		pubkey.algorithm = SC_ALGORITHM_RSA;

		rv = sc_pkcs15_decode_pubkey(card->ctx, &pubkey, der.value, der.len);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_encode_key_info(card, &pubkey.u.rsa, object->type, &ikey);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_set_key_info(profile, card, info_file, &ikey, NULL);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_update_object_list(profile, card, object->type, index);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		/*
		 * Look for the container that contains corresponding certificate to
		 * include the key object.
		 * Create a new container, if there is no corresponding certificate.
		 */		
		rv = cosm_update_container(profile, card, object->type, &ikey.id, index, NULL);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;

		rv = cosm_set_id (card->ctx, object, ikey.id.value, ikey.id.len);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;

		cosm_free_key_info(&ikey);
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		rv = cosm_encode_cert_info(card, &der, &icert);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_set_certificate_info(profile, card, info_file, &icert);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_update_object_list(profile, card, object->type, index);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		/*
		 * Look for the container that contains corresponding key to
		 * include this certificate object.
		 * Create a new container, if there is no corresponding key.
		 */
		rv = cosm_update_container(profile, card, object->type, &icert.key.id, index, 
				&prvkey_id);
		if (rv)
			break;

		sc_debug(card->ctx, "rv %i;  friend 0x%X\n", rv, prvkey_id);
		if (prvkey_id)  
			rv = cosm_update_key_info(profile, card, prvkey_id, &icert);
		
		rv = cosm_set_id (card->ctx, object, icert.key.id.value, icert.key.id.len);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;

		cosm_free_cert_info(&icert);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = cosm_encode_data_info(card, &der, 
					(sc_pkcs15_data_info_t *)object->data, &idata);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)   
			break;
		
		rv = cosm_set_data_info(profile, card, info_file, &idata);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;
		
		rv = cosm_update_object_list(profile, card, object->type, index);
		sc_debug(card->ctx, "rv %i\n", rv);
		if (rv)
			break;

		cosm_free_data_info(&idata);						
		break;
	default:
		sc_error(card->ctx, "Unsupported type %i\n", object->type);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_debug(card->ctx, "rv %i\n",rv);

	if (rv > 0)
		rv = 0;
	
	if (info_file)
		sc_file_free(info_file);
	if (obj_file)
		sc_file_free(obj_file);
		
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int
cosm_update_df(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		int op,
		struct sc_pkcs15_object *object)
{
	switch(op)   {
	case SC_AC_OP_ERASE:
		return cosm_update_df_delete_object(p15card, profile, object);
	case SC_AC_OP_CREATE:
		return cosm_update_df_new_object(p15card, profile, object);
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}
}


static int 
cosm_update_dir (struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_app_info *info)
{
	sc_debug(p15card->card->ctx, "return 0");
	return 0;
}


static int 
cosm_update_tokeninfo (struct sc_pkcs15_card *p15card,
		struct sc_profile *profile, struct sc_pkcs15_tokeninfo *info)
{
	int rv, sz;
	char *buffer = NULL;
	struct sc_file *file = NULL;

	if (!p15card || !profile || !info)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	
	if (sc_profile_get_file(profile, COSM_TITLE"-token-info", &file))   {
		sc_error(p15card->card->ctx, 
				"Inconsistent profile: cannot find "COSM_TITLE"-token-info");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}
	
	buffer = malloc(file->size + 1);
	if (!buffer)
		SC_FUNC_RETURN(p15card->card->ctx, 1, SC_ERROR_MEMORY_FAILURE);
		
	if (info->label)   {
		strncpy(buffer, info->label, file->size);
	}
	else   {
		snprintf(buffer, file->size, "IDX-SCM");
	}

	sc_debug(p15card->card->ctx, "buffer: '%s'", info->label);
	*(buffer + file->size) = '\0';
		
	sc_debug(p15card->card->ctx, "buffer '%s'\n", buffer);
	sz = strlen(buffer);	
	if (sz < file->size)
		memset(buffer + sz, ' ', file->size - sz);

	memcpy(buffer + file->size - 4, "\0\0\x4\xD", 4);
	rv = sc_pkcs15init_update_file(profile, p15card->card, file, buffer, file->size);
	
	free(buffer);

	SC_FUNC_RETURN(p15card->card->ctx, 1, rv);
}


int cosm_write_info (struct sc_card *card,
		struct sc_profile *profile, struct sc_pkcs15_object *object)
{
	return SC_SUCCESS;
}


int
cosm_change_label(struct sc_pkcs15_card *p15card, struct sc_profile *profile,	
		struct sc_pkcs15_object *object, 
		void *value, int len)
{
	struct sc_card	*card = p15card->card;
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "len %i\n", len);
	if (len >= SC_PKCS15_MAX_LABEL_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	memcpy(object->label, value, len);
	object->label[len] = '\0';
#if 0
	/* TODO  */
#else
	rv = 0;
#endif
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


int
cosm_change_id(struct sc_pkcs15_card *p15card, struct sc_profile *profile,	
		struct sc_pkcs15_object *object, struct sc_pkcs15_id *in_id)
{
	struct sc_card	*card = p15card->card;
	struct sc_pkcs15_id *id;
	
	SC_FUNC_CALLED(card->ctx, 1);
	if (!object || !in_id)
		return SC_ERROR_INVALID_ARGUMENTS;

	switch(object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		id = &(((sc_pkcs15_prkey_info_t *) object->data)->id);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		id = &(((sc_pkcs15_pubkey_info_t *) object->data)->id);
		break;
	case SC_PKCS15_TYPE_CERT:
		id = &(((sc_pkcs15_cert_info_t *) object->data)->id);
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (id->len != in_id->len || memcmp(id->value, in_id->value, id->len))   {
		sc_debug(card->ctx, "obj.id %s; in.id %s\n", 
				sc_pkcs15_print_id(id), sc_pkcs15_print_id(in_id));
		return SC_ERROR_NOT_SUPPORTED;
	}
	
	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


int
cosm_change_attrib(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,	struct sc_pkcs15_object *object,
		int new_attrib_type, void *new_value, int new_len)
{
	struct sc_card	*card = p15card->card;
	int		rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "attribute type 0x%X; len %i\n", new_attrib_type, new_len);
	if (!p15card || !object || !new_value || new_len < 1)
		return SC_ERROR_OBJECT_NOT_FOUND;

	switch(new_attrib_type)   {
	case P15_ATTR_TYPE_LABEL:
		rv = cosm_change_label(p15card, profile, object, new_value, new_len);
		break;
	case P15_ATTR_TYPE_ID:
		if (new_len != sizeof(struct sc_pkcs15_id))
			return SC_ERROR_INVALID_ARGUMENTS;
		
		rv = cosm_change_id(p15card, profile, object, (struct sc_pkcs15_id *)new_value);
		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
		break;
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


int
cosm_select_id (struct sc_pkcs15_card *p15card, int type, 
		sc_pkcs15_id_t *id, void *data)
{
	SC_FUNC_CALLED(p15card->card->ctx, 1);
#ifdef ENABLE_OPENSSL
	if (!data || !id)
		SC_FUNC_RETURN(p15card->card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	if (type == SC_PKCS15_TYPE_PRKEY)   {
		struct sc_pkcs15_prkey *key = (struct sc_pkcs15_prkey *)data;
		if (key->algorithm == SC_ALGORITHM_RSA)   {
			struct sc_pkcs15_prkey_rsa *rsa = &key->u.rsa;

			SHA1(rsa->modulus.data, rsa->modulus.len, id->value);
			id->len = SHA_DIGEST_LENGTH;
			sc_debug(p15card->card->ctx, "private key ID %s\n", sc_pkcs15_print_id(id));
		}
	}
	else if (type == SC_PKCS15_TYPE_CERT)   {		
		struct sc_pkcs15_der *der = (struct sc_pkcs15_der *)data;
	    EVP_PKEY *pkey = NULL;
		X509 *x = NULL;
	    BIO *mem = NULL;
	    BIGNUM *bn = NULL;
		unsigned char *buff = NULL;
		int rv, bn_size;
			
		rv = SC_ERROR_INTERNAL;
		id->len = 0;	
		do   {
			mem = BIO_new_mem_buf(der->value, der->len);
			if (!mem)
				break;
			x = d2i_X509_bio(mem, NULL);
			if (!x)
				break;
			pkey=X509_get_pubkey(x);
			if (!pkey || pkey->type != EVP_PKEY_RSA)
				break;
			bn = pkey->pkey.rsa->n;
			bn_size = BN_num_bytes(pkey->pkey.rsa->n);
			
			buff = OPENSSL_malloc(bn_size);
			if (!buff)
				break;
			if (BN_bn2bin(bn, buff) != bn_size) 
				break;
			if (!SHA1(buff, bn_size, id->value)) 
				break;
			id->len = SHA_DIGEST_LENGTH;

			sc_debug(p15card->card->ctx, "cert ID %s\n", sc_pkcs15_print_id(id));
			rv = SC_SUCCESS;
		} while (0);
	
		if (x)
			X509_free(x);
	    if (mem)    
			BIO_free(mem);
		if (buff)   
			OPENSSL_free(buff);
		
		SC_FUNC_RETURN(p15card->card->ctx, 1, rv);
	}
	else if (type == SC_PKCS15_TYPE_PUBKEY)   {
		struct sc_pkcs15_pubkey *key = (struct sc_pkcs15_pubkey *)data;
		
		if (key->algorithm == SC_ALGORITHM_RSA)   {
			 struct sc_pkcs15_pubkey_rsa *rsa = &key->u.rsa;

			SHA1(rsa->modulus.data, rsa->modulus.len, id->value);
			id->len = SHA_DIGEST_LENGTH;
			sc_debug(p15card->card->ctx, "public key ID %s\n", sc_pkcs15_print_id(id));
		}
	}
#endif
	SC_FUNC_RETURN(p15card->card->ctx, 1, 0);
}
#endif /* COSM_EXTENDED */

static struct sc_pkcs15init_operations 
sc_pkcs15init_oberthur_operations = {
	cosm_erase_card,
	NULL,						/* init_card  */
	NULL,						/* create_dir */
	NULL,						/* create_domain */
	cosm_select_pin_reference,
	cosm_create_pin,
	NULL,						/* select_key_reference */
	NULL,						/* create_key */
	NULL,						/* store_key */
	NULL,						/* generate_key */
	NULL, 
	NULL,						/* encode private/public key */
	NULL,						/* finalize_card */
	cosm_init_app,				/* old */
	NULL,						/* new_pin */
	cosm_new_key,
	cosm_new_file,
	cosm_old_generate_key,
	
#ifdef COSM_EXTENDED	
	cosm_delete_object,			/* delete_object */
	NULL, 						/* ext_store_data */
	NULL, 						/* ext_remove_data */
	cosm_update_df,				/* ext_update_df */
	cosm_update_dir,			/* ext_update_dir */
	cosm_update_tokeninfo,		/* ext_update_tokeninfo */
	cosm_write_info,		/* ext_write_info */
	cosm_change_attrib, /* ext_pkcs15init_change_attrib */	
	cosm_select_id,		/* ext_select_id */
#endif	
	NULL	
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_oberthur_ops(void)
{   
	return &sc_pkcs15init_oberthur_operations;
}
