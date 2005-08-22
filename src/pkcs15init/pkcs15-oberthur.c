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
	
	sc_debug(card->ctx, " id %04X\n", df->id);

	if (df->type==SC_FILE_TYPE_DF)   {
		rv = sc_pkcs15init_authenticate(profile, card, df, SC_AC_OP_DELETE);
		if (rv < 0)
			goto done;
	}
	
	/* Select the parent DF */
	
	path = df->path;
	path.len -= 2;

	rv = sc_select_file(card, &path, &parent);
	if (rv < 0)
		goto done;

	rv = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	if (rv < 0)
		goto done;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(card, &path);
done:	
	sc_debug(card->ctx, "return %i\n", rv);
	return rv;
}


/*
 * Erase the card
 */
static int cosm_erase_card(struct sc_profile *profile, sc_card_t *card)
{
	sc_file_t  *df = profile->df_info->file, *dir;
	int r;

	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete if before the DF because we create
	 * it *after* the DF. 
	 * */
	card->ctx->suppress_errors++;
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		r = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	sc_debug(card->ctx, "erase file ddf %04X\n",df->id);
	r=cosm_delete_file(card, profile, df);

	if (sc_profile_get_file(profile, "private-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		r = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}
	
	if (sc_profile_get_file(profile, "public-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		r = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (r < 0 && r != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	r = sc_profile_get_file(profile, COSM_TITLE"-AppDF", &dir);
	if (!r) {
		sc_debug(card->ctx, "delete %s; r %i\n", COSM_TITLE"-AppDF", r);
		r = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
	}

done:		
	sc_keycache_forget_key(NULL, -1, -1);
	card->ctx->suppress_errors++;

	if (r == SC_ERROR_FILE_NOT_FOUND)
		r=0;
	
	return r;
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
	int r;
	size_t ii;
	sc_file_t *file = NULL;
	static const char *create_dfs[8] = {
		"private-DF",
		"public-DF",
		"PKCS15-ODF",
		"PKCS15-AODF",
		"PKCS15-PrKDF",
		"PKCS15-PuKDF",
		"PKCS15-CDF",
		"PKCS15-DODF"
	};

	sc_debug(card->ctx, "pin_len %i; puk_len %i\n", pin_len, puk_len);
	/* Create the application DF */
	r = sc_pkcs15init_create_file(profile, card, profile->df_info->file);
	if (r)
		return r;
	
	/* Oberthur AWP file system is expected.*/
	/* Create private objects DF */
	for (ii = 0; ii<sizeof(create_dfs)/sizeof(char *); ii++)   {
		if (sc_profile_get_file(profile, create_dfs[ii], &file))   {
			sc_error(card->ctx, "Inconsistent profile: cannot find %s", create_dfs[ii]);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
	
		r = sc_pkcs15init_create_file(profile, card, file);
		sc_file_free(file);
		if (r && r!=SC_ERROR_FILE_ALREADY_EXISTS)
			return r;
	}
	
	/* Create Oberthur AWP application DF (5011),
	 * and populate with Oberthur's xxDF files*/
	r = sc_profile_get_file(profile, COSM_TITLE"-AppDF", &file);
	sc_debug(card->ctx, "name %s; r %i\n", COSM_TITLE"-AppDF", r);
	if (r==SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(card->ctx, "create file dir %04X\n", file->id);
		r = sc_pkcs15init_create_file(profile, card, file);
		sc_file_free(file);
	}
	if (r && r!=SC_ERROR_FILE_ALREADY_EXISTS)
		return(r);

	sc_debug(card->ctx, "return OK\n");
	return 0;
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

	sc_debug(card->ctx, "pin lens %i/%i\n", pin_len,  puk_len);
	if (!pin || pin_len>0x40)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (puk && !puk_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	rv = sc_select_file(card, &pinfo->path, NULL);
	if (rv)
		return rv;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_pin);
	if (profile_pin.max_length > 0x100)
		return SC_ERROR_INCONSISTENT_PROFILE;

	if (puk)   {
		int ii, jj;
		const unsigned char *ptr = puk;
		
		puk_buff = (unsigned char *) malloc(0x100);
		if (!puk_buff)
			goto done;

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &profile_puk);
		if (profile_puk.max_length > 0x100)
			return SC_ERROR_INCONSISTENT_PROFILE;
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
	
    if ((rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_CREATE_PIN, &args)) < 0)
		goto done;

done:
	if (puk_buff)
		free(puk_buff);
	
	sc_debug(card->ctx, "return %i\n", rv);
	return rv;
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
	
	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);

	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
		sc_error(card->ctx,"Pin references should be only in the profile"
				"and in the card-oberthur.\n");
		if (pinfo->reference != 2)
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

	sc_debug(card->ctx, "return %i\n",rv);
	return rv;
}

static int
cosm_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_pin_info_t *pin_info) 
{
	sc_file_t *pinfile;

	sc_debug(card->ctx, "ref %i; flags %X\n", pin_info->reference, pin_info->flags);
    if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_error(card->ctx, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}

	pin_info->path = pinfile->path;
	sc_file_free(pinfile);
		
	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
        pin_info->reference = 2;
	}
	
	if (pin_info->reference < 0 || pin_info->reference > 3)
		return SC_ERROR_INVALID_PIN_REFERENCE;
	
	if (!(pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN))  {
		if (pin_info->reference == 2)
			return SC_ERROR_INVALID_PIN_REFERENCE;
		else if (pin_info->reference == 0)
			pin_info->reference = 1;
	}
	sc_debug(card->ctx, "return %i\n",0);
	return 0;
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
	int r = 0, type;

	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);
    if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_error(card->ctx, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}
		    
	pinfo->path = pinfile->path;
	sc_file_free(pinfile);
	
	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		type = SC_PKCS15INIT_SO_PIN;

		if (pinfo->reference != 2)  
			return SC_ERROR_INVALID_ARGUMENTS;
	} 
	else {
		type = SC_PKCS15INIT_USER_PIN;
		
		if (pinfo->reference !=1)
			return SC_ERROR_INVALID_PIN_REFERENCE;
	}

	if (pin && pin_len)   {
	    r = cosm_update_pin(profile, card, pinfo, pin, pin_len,  puk, puk_len);
	}
	else   {
		sc_debug(card->ctx, "User PIN not updated");		
	}
    sc_debug(card->ctx, "return %i\n",r);
        
	sc_keycache_set_pin_name(&pinfo->path, pinfo->reference, type);
	pinfo->flags &= ~SC_PKCS15_PIN_FLAG_LOCAL;
    return r;
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
	return 0;
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
	sc_path_t path;
	int	 rv;

	sc_debug(card->ctx, "index %i; nn %i\n",idx,keybits);
	if (keybits < 512 || keybits > 2048 || (keybits%0x20))   {
		sc_error(card->ctx, "Unsupported key size %u\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	/* Get private key file from profile. */
	if ((rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx, 
					&prkf)) < 0)
	 	goto failed;
	sc_debug(card->ctx, "prv ef type %i\n",prkf->ef_structure);
	prkf->size = keybits;
	
	/* Access condition of private object DF. */
	path = prkf->path;
	path.len -= 2;
	if ((rv = sc_profile_get_file_by_path(profile, &path, &tmpf))) 
		goto failed;
	else if ((rv = sc_pkcs15init_authenticate(profile, card, tmpf, 
					SC_AC_OP_CRYPTO)) < 0)  
		goto failed;
	else if ((rv = sc_pkcs15init_authenticate(profile, card, tmpf, 
					SC_AC_OP_CREATE)) < 0) 
		goto failed;
	else
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

	if ((rv = sc_pkcs15init_create_file(profile, card, prkf)))  
		goto failed;
	else if ((rv = sc_pkcs15init_create_file(profile, card, tmpf)))
		goto failed;
	
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
	
	sc_debug(card->ctx, "sc_card_ctl %s\n","SC_CARDCTL_OBERTHUR_GENERATE_KEY");
	if ((rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_GENERATE_KEY, &args)) < 0)
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

	info->key_reference = 1;
	info->path = prkf->path;
	
	sc_debug(card->ctx, "delete temporary public key\n");
	if ((rv =  cosm_delete_file(card, profile, tmpf)))
		goto failed;
	
failed:	
	if (tmpf) sc_file_free(tmpf);
	if (prkf) sc_file_free(prkf);
	sc_debug(card->ctx, "return %i\n",rv);
	return rv;
}


/*
 * Store a private key
 */
static int
cosm_new_key(struct sc_profile *profile, sc_card_t *card,
		struct sc_pkcs15_prkey *key, unsigned int idx,
		struct sc_pkcs15_prkey_info *info)
{
	sc_file_t *prvfile = NULL, *pubfile = NULL;
	struct sc_pkcs15_prkey_rsa *rsa = NULL;
	struct sc_pkcs15_bignum bn[6];
	u8 *buff;
	int rv, ii;

	sc_debug(card->ctx, " index %i\n", idx);
	if (key->algorithm != SC_ALGORITHM_RSA) {
		sc_error(card->ctx, "For a while supports only RSA keys.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Create and populate the private part. */
	rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx,
					&prvfile);
	if (rv < 0)
		return SC_ERROR_SYNTAX_ERROR;
	
	sc_debug(card->ctx, " prvfile->id %i;  path=%s\n", 
			prvfile->id, sc_print_path(&prvfile->path));

	rsa = &key->u.rsa;
	
	prvfile->size = rsa->modulus.len << 3;
	buff = (u8 *) malloc(rsa->modulus.len);
	if (!buff)   {
		sc_error(card->ctx, "Memory allocation error.");
		return SC_ERROR_OUT_OF_MEMORY;
	}

	rv = sc_select_file(card, &prvfile->path, NULL);
	if (rv==SC_ERROR_FILE_NOT_FOUND)   
		rv = sc_pkcs15init_create_file(profile, card, prvfile);
	
	if (rv <0)
		goto failed;
	
	if ((rv = sc_pkcs15init_authenticate(profile, card, prvfile, 
					SC_AC_OP_UPDATE)) <0)
		goto failed;
	
	bn[0] = rsa->p;
	bn[1] = rsa->q;
	bn[2] = rsa->iqmp;
	bn[3] = rsa->dmp1;
	bn[4] = rsa->dmq1;
	for (ii=0;ii<5;ii++)   {
		struct sc_cardctl_oberthur_updatekey_info args;
		
		memset(&args, 0, sizeof(args));
		args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
		args.component = ii+1;
		args.data = bn[ii].data;
		args.len = bn[ii].len;
		rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_UPDATE_KEY, &args);
		if (rv)
			goto failed;
	}
	
	info->path = prvfile->path;
	info->modulus_length = rsa->modulus.len << 3;

failed:
	if (pubfile) sc_file_free(pubfile);
	if (prvfile) sc_file_free(prvfile);
	if (buff)	free(buff);

	sc_debug(card->ctx, "return %i\n", rv);
	return rv;
}


static struct sc_pkcs15init_operations sc_pkcs15init_oberthur_operations = {
	cosm_erase_card,
	NULL,				/* init_card  */
	NULL,				/* create_dir */
	NULL,				/* create_domain */
	cosm_select_pin_reference,
	cosm_create_pin,
	NULL,				/* select_key_reference */
	NULL,				/* create_key */
	NULL,				/* store_key */
	NULL,				/* generate_key */
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	cosm_init_app,			/* old */
	NULL,				/* new_pin */
	cosm_new_key,
	cosm_new_file,
	cosm_old_generate_key,
	NULL 				/* delete_object */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_oberthur_ops(void)
{   
	return &sc_pkcs15init_oberthur_operations;
}
