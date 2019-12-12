/*
 * Support for ePass2003 smart cards
 *
 * Copyright (C) 2008, Weitao Sun <weitao@ftsafe.com>
 * Copyright (C) 2011, Xiaoshuo Wu <xiaoshuo@ftsafe.com>
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

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "pkcs15-init.h"
#include "profile.h"
static int epass2003_pkcs15_erase_card(struct sc_profile *profile,
				       struct sc_pkcs15_card *p15card)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (sc_select_file(p15card->card, sc_get_mf_path(), NULL) < 0)
		return SC_SUCCESS;

	return sc_card_ctl(p15card->card, SC_CARDCTL_ERASE_CARD, 0);
}

static int epass2003_pkcs15_init_card(struct sc_profile *profile,
				      struct sc_pkcs15_card *p15card)
{
	struct sc_card *card = p15card->card;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_do_log(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,NULL,0,NULL,
			"ePass2003 doesn't support SO-PIN and SO-PUK. You can unblock key with PUK. \n");
	{			/* MF */
		struct sc_file *mf_file;
		struct sc_file *skey_file;

		ret = sc_profile_get_file(profile, "MF", &mf_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get MF info failed");
		ret = sc_create_file(card, mf_file);
		sc_file_free(mf_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create MF failed");

		ret = sc_profile_get_file(profile, "SKey-MF", &skey_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get SKey info failed");
		ret = sc_create_file(card, skey_file);
		sc_file_free(skey_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create SKey failed");

	}

	{			/* EF(DIR) */
		struct sc_file *dir_file;

		/* get dir profile */
		ret = sc_profile_get_file(profile, "DIR", &dir_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get EF(DIR) info failed");
		ret = sc_create_file(card, dir_file);
		sc_file_free(dir_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create EF(DIR) failed");

		sc_free_apps(card);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int epass2003_pkcs15_create_dir(struct sc_profile *profile,
				       struct sc_pkcs15_card *p15card,
				       struct sc_file *df)
{
	struct sc_card *card = p15card->card;
	int ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	{			/* p15 DF */
		struct sc_file *df_file;
		struct sc_file *skey_file;
		struct sc_file *ef_file;
		u8 max_counter[2] = { 0 };
		int id;
		u8 user_maxtries = 0;
		u8 so_maxtries = 0;

		ret = sc_profile_get_file(profile, "PKCS15-AppDF", &df_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get PKCS15-AppDF info failed");
		ret = sc_create_file(card, df_file);
		sc_file_free(df_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create PKCS15-AppDF failed");

		ret = sc_profile_get_file(profile, "SKey-AppDF", &skey_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get SKey info failed");
		ret = sc_create_file(card, skey_file);
		sc_file_free(skey_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create SKey info failed");

		ret = sc_profile_get_file(profile, "MAXPIN", &ef_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Get MAXPIN info failed");
		ret = sc_create_file(card, ef_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Create MAXPIN failed");
		ret = sc_select_file(card, &(ef_file->path), &ef_file);
		LOG_TEST_RET(card->ctx, ret,
			    "Select MAXPIN failed");

		ret = sc_profile_get_pin_id(profile, 2, &id);
		LOG_TEST_RET(card->ctx, ret,
			    "Get User PIN id error!");
		user_maxtries = (u8) sc_profile_get_pin_retries(profile, id);

		ret = sc_profile_get_pin_id(profile, 1, &id);
		LOG_TEST_RET(card->ctx, ret,
			    "Get User PIN id error!");
		so_maxtries = (u8) sc_profile_get_pin_retries(profile, id);

		max_counter[0] = user_maxtries;
		max_counter[1] = so_maxtries;

		ret = sc_update_binary(card, 0, max_counter, 2, 0);

		LOG_TEST_RET(card->ctx, ret,
			    "Update MAXPIN failed");
		sc_file_free(ef_file);
	}

	{			/* p15 efs */
		char *create_efs[] = {
			"PKCS15-ODF",
			"PKCS15-TokenInfo",
			"PKCS15-UnusedSpace",
			"PKCS15-AODF",
			"PKCS15-PrKDF",
			"PKCS15-PuKDF",
			"PKCS15-CDF",
			"PKCS15-DODF",
			NULL,
		};
		int i;
		struct sc_file *file = 0;

		for (i = 0; create_efs[i]; ++i) {
			if (sc_profile_get_file(profile, create_efs[i], &file)) {
				sc_log(card->ctx, 
					 "Inconsistent profile: cannot find %s",
					 create_efs[i]);
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,
					       SC_ERROR_INCONSISTENT_PROFILE);
			}
			ret = sc_create_file(card, file);
			sc_file_free(file);
			LOG_TEST_RET(card->ctx, ret,
				    "Create pkcs15 file failed");
		}
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int epass2003_pkcs15_pin_reference(struct sc_profile *profile,
					  struct sc_pkcs15_card *p15card,
					  struct sc_pkcs15_auth_info *auth_info)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.reference < ENTERSAFE_USER_PIN_ID
	    || auth_info->attrs.pin.reference > ENTERSAFE_SO_PIN_ID)
		return SC_ERROR_INVALID_PIN_REFERENCE;

	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int epass2003_pkcs15_create_pin(struct sc_profile *profile,
				       struct sc_pkcs15_card *p15card,
				       struct sc_file *df,
				       struct sc_pkcs15_object *pin_obj,
				       const unsigned char *pin, size_t pin_len,
				       const unsigned char *puk, size_t puk_len)
{
	struct sc_card *card = p15card->card;
	int r;
	struct sc_pkcs15_auth_info *auth_info;

	if (NULL == pin_obj)
		return SC_ERROR_INVALID_ARGUMENTS;

	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	{			/*pin */
		sc_epass2003_wkey_data data;
		int id;

		if (!pin || !pin_len || pin_len > 16)
			return SC_ERROR_INVALID_ARGUMENTS;

		data.type = SC_EPASS2003_SECRET_PIN;
		data.key_data.es_secret.kid = auth_info->attrs.pin.reference;
		data.key_data.es_secret.ac[0] =
		    EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_EVERYONE;
		data.key_data.es_secret.ac[1] =
		    EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_USER;

		r = sc_profile_get_pin_id(profile, 2, &id);
		LOG_TEST_RET(card->ctx, r,
			    "Get User PIN id error!");
		data.key_data.es_secret.EC =
		    sc_profile_get_pin_retries(profile, id);

		/* pad pin with 0 */
		memset(data.key_data.es_secret.key_val, 0,
		       sizeof(data.key_data.es_secret.key_val));
		memcpy(data.key_data.es_secret.key_val, pin, pin_len);
		data.key_data.es_secret.key_len = pin_len;

		r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
		if (r < 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
		if (pin_obj) {
			/* Cache new PIN value. */
			sc_pkcs15_pincache_add(p15card, pin_obj, pin, pin_len);
		}
	}

	{			/*puk */
		sc_epass2003_wkey_data data;
		int id;

		if (!puk || !puk_len || puk_len > 16)
			return SC_ERROR_INVALID_ARGUMENTS;

		data.type = SC_EPASS2003_SECRET_PIN;
		data.key_data.es_secret.kid =
		    auth_info->attrs.pin.reference + 1;
		data.key_data.es_secret.ac[0] =
		    EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_EVERYONE;
		data.key_data.es_secret.ac[1] =
		    EPASS2003_AC_MAC_EQUAL | EPASS2003_AC_SO;

		r = sc_profile_get_pin_id(profile, 1, &id);
		LOG_TEST_RET(card->ctx, r,
			    "Get User PIN id error!");
		data.key_data.es_secret.EC =
		    sc_profile_get_pin_retries(profile, id);

		/* pad pin with 0 */
		memset(data.key_data.es_secret.key_val, 0,
		       sizeof(data.key_data.es_secret.key_val));
		memcpy(data.key_data.es_secret.key_val, puk, puk_len);
		data.key_data.es_secret.key_len = puk_len;

		r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int epass2003_pkcs15_key_reference(struct sc_profile *profile,
					  struct sc_pkcs15_card *p15card,
					  struct sc_pkcs15_prkey_info *prkey)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	prkey->key_reference = prkey->path.value[prkey->path.len - 1];
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

/* from pkcs15-oberthur.c, modified */
static int
cosm_new_file(struct sc_profile *profile, struct sc_card *card,
	      unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_file *file;
	const char *_template = NULL, *desc = NULL;
	unsigned int structure = 0xFFFFFFFF;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_log(card->ctx,  "type %X; num %i\n", type,
		 num);
	while (1) {
		switch (type) {
		case SC_PKCS15_TYPE_PRKEY_EC:
			desc = "RSA private key";
			_template = "private-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_EC_CRT;
			break;
		case SC_PKCS15_TYPE_PUBKEY_EC:
			desc = "RSA public key";
			_template = "public-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_EC_PUBLIC;
			break;
		case SC_PKCS15_TYPE_PRKEY_RSA:
			desc = "RSA private key";
			_template = "private-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			desc = "RSA public key";
			_template = "public-key";
			structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
			break;
		case SC_PKCS15_TYPE_PUBKEY_DSA:
			desc = "DSA public key";
			_template = "public-key";
			break;
		case SC_PKCS15_TYPE_PRKEY:
			desc = "extractable private key";
			_template = "extractable-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			desc = "certificate";
			_template = "certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			desc = "data object";
			_template = "data";
			break;
		}
		if (_template)
			break;
		/* If this is a specific type such as
		 * SC_PKCS15_TYPE_CERT_FOOBAR, fall back to
		 * the generic class (SC_PKCS15_TYPE_CERT)
		 */
		if (!(type & ~SC_PKCS15_TYPE_CLASS_MASK)) {
			sc_log(card->ctx, 
				 "File type %X not supported by card driver",
				 type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_log(card->ctx,  "template %s; num %i\n",
		 _template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_log(card->ctx, 
			 "Profile doesn't define %s template '%s'\n", desc,
			 _template);
		return SC_ERROR_NOT_SUPPORTED;
	}

	file->id &= 0xFF00;
	file->id |= (num & 0x00FF);

	file->path.value[file->path.len - 1] = (num & 0xFF);
	file->type = SC_FILE_TYPE_INTERNAL_EF;
	file->ef_structure = structure;

	sc_log(card->ctx, 
		 "file size %"SC_FORMAT_LEN_SIZE_T"u; ef type %i/%i; id %04X, path_len %"SC_FORMAT_LEN_SIZE_T"u\n",
		 file->size, file->type, file->ef_structure, file->id,
		 file->path.len);
	sc_log(card->ctx,  "file path: %s",
		 sc_print_path(&(file->path)));
	*out = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int epass2003_pkcs15_create_key(struct sc_profile *profile,
				       struct sc_pkcs15_card *p15card,
				       struct sc_pkcs15_object *obj)
{
	struct sc_card *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int epass2003_pkcs15_store_key(struct sc_profile *profile,
				      struct sc_pkcs15_card *p15card,
				      struct sc_pkcs15_object *obj,
				      struct sc_pkcs15_prkey *key)
{
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info =
	    (struct sc_pkcs15_prkey_info *)obj->data;
	size_t idx = key_info->key_reference;
	size_t keybits = key_info->modulus_length;
	struct sc_path path;
	struct sc_file *tfile = NULL;
	struct sc_file *file = NULL;
	sc_epass2003_wkey_data data;
	int r;
	int fidl = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(card->ctx, 
		 "index %"SC_FORMAT_LEN_SIZE_T"u; id %s\n", idx,
		 sc_pkcs15_print_id(&key_info->id));
	if (key->algorithm != SC_ALGORITHM_RSA
	    || key->algorithm != SC_ALGORITHM_RSA)
		LOG_TEST_RET(card->ctx,
			    SC_ERROR_NOT_SUPPORTED,
			    "store key: only support RSA");

	sc_log(card->ctx, 
		 "store key: with ID:%s and path:%s",
		 sc_pkcs15_print_id(&key_info->id),
		 sc_print_path(&key_info->path));

	/* allocate key object */
	r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA,
			  key_info->key_reference, &file);
	LOG_TEST_RET(card->ctx, r,
		    "create key: failed to allocate new key object");
	file->size = keybits;
	sc_log(card->ctx,  "private key path: %s",
		 sc_print_path(&(file->path)));
	sc_log(card->ctx,  "private key_info path: %s",
		 sc_print_path(&(key_info->path)));
	sc_delete_file(p15card->card, &file->path);
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	LOG_TEST_RET(card->ctx, r,
		    "create key: failed to create key file");

	sc_log(card->ctx, 
		 "index %"SC_FORMAT_LEN_SIZE_T"u; keybits %"SC_FORMAT_LEN_SIZE_T"u\n",
		 idx, keybits);
	if (keybits < 1024 || keybits > 2048 || (keybits % 0x20)) {
		sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
			 "Unsupported key size %"SC_FORMAT_LEN_SIZE_T"u\n",
			 keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	path = key_info->path;
	path.len -= 2;

	r = sc_select_file(card, &path, &tfile);
	LOG_TEST_RET(card->ctx, r,
		    "generate key: no private object DF");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(card->ctx, r,
		    "No authorisation to store private key");

	sc_file_free(tfile);

	fidl = (file->id & 0xff) * FID_STEP;
	file->id = (file->id & 0xff00) + fidl;
	data.type = SC_EPASS2003_KEY_RSA;
	data.key_data.es_key.fid = file->id;
	data.key_data.es_key.rsa = (void *)&key->u.rsa;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
	LOG_TEST_RET(card->ctx, r,
		    "store key: cannot update private key");

	sc_file_free(file);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int epass2003_pkcs15_generate_key(struct sc_profile *profile,
					 struct sc_pkcs15_card *p15card,
					 struct sc_pkcs15_object *obj,
					 struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	int r;
	sc_epass2003_gen_key_data gendat;
	struct sc_pkcs15_prkey_info *key_info =
	    (struct sc_pkcs15_prkey_info *)obj->data;
	size_t idx = key_info->key_reference;
	size_t keybits = key_info->modulus_length;
	struct sc_file *tfile = NULL, *pukf = NULL;
	struct sc_path path;
	struct sc_file *file = NULL;
	int fidl = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA && obj->type != SC_PKCS15_TYPE_PRKEY_EC)
		return SC_ERROR_NOT_SUPPORTED;

	if(obj->type == SC_PKCS15_TYPE_PRKEY_EC && keybits == 0)
		keybits = 256; 	//EC key length is 256 ...

	/* allocate key object */
	r = cosm_new_file(profile, card, obj->type, idx, &file); //replace SC_PKCS15_TYPE_PRKEY_RSA with obj->type
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "create key: failed to allocate new key object");
	file->size = keybits;
	sc_log(card->ctx,  "private key path: %s",
		 sc_print_path(&file->path));
	sc_log(card->ctx,  "private key_info path: %s",
		 sc_print_path(&(key_info->path)));

	r = sc_pkcs15init_authenticate(profile, p15card, file,
				       SC_AC_OP_DELETE);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key: pkcs15init_authenticate(SC_AC_OP_DELETE) failed");

	sc_delete_file(p15card->card, &file->path);
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "create key: failed to create key file");

	sc_log(card->ctx, 
		 "index %"SC_FORMAT_LEN_SIZE_T"u; keybits %"SC_FORMAT_LEN_SIZE_T"u\n",
		 idx, keybits);
	if (keybits < 1024 || keybits > 2048 || (keybits % 0x20)) {
		if(obj->type == SC_PKCS15_TYPE_PRKEY_EC && keybits == 256)
		{
			sc_log(card->ctx, "current Alg is EC,Only support 256 ..\n");
		}
		else
		{
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE_TOOL,
				 "Unsupported key size %"SC_FORMAT_LEN_SIZE_T"u\n",
				 keybits);
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
		}
	}

	path = key_info->path;
	path.len -= 2;

	r = sc_select_file(card, &path, &tfile);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key: no private object DF");

	r = sc_pkcs15init_authenticate(profile, p15card, tfile,
				       SC_AC_OP_CRYPTO);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key: pkcs15init_authenticate(SC_AC_OP_CRYPTO) failed");

	r = sc_pkcs15init_authenticate(profile, p15card, tfile,
				       SC_AC_OP_CREATE);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key: pkcs15init_authenticate(SC_AC_OP_CREATE) failed");

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA )
	{
	
		r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PUBKEY_EC, idx, &pukf);
	}
	else
	{
		
		r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PUBKEY_RSA, idx, &pukf);
	}

	if (r < 0) {
		sc_log(card->ctx, 
			 "generate key: create temporary pukf failed\n");
		goto err;
	}

	pukf->size = keybits;
	pukf->id = pukf->path.value[pukf->path.len - 2] * 0x100
	    + pukf->path.value[pukf->path.len - 1];

	sc_log(card->ctx, 
		 "public key size %"SC_FORMAT_LEN_SIZE_T"u; ef type %i/%i; id %04X; path: %s",
		 pukf->size, pukf->type, pukf->ef_structure, pukf->id,
		 sc_print_path(&pukf->path));

	r = sc_select_file(p15card->card, &pukf->path, NULL);
	/* if exist, delete */
	if (r == SC_SUCCESS) {
		r = sc_pkcs15init_authenticate(profile, p15card, pukf,
		       SC_AC_OP_DELETE);
		SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key - pubkey: pkcs15init_authenticate(SC_AC_OP_DELETE) failed");

		r = sc_pkcs15init_delete_by_path(profile, p15card, &pukf->path);
		if (r != SC_SUCCESS) {
			sc_log(card->ctx, 
				 "generate key: failed to delete existing key file\n");
			goto err;
		}
	}
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, pukf);
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, 
			 "generate key: pukf create file failed\n");
		goto err;
	}

	r = sc_pkcs15init_authenticate(profile, p15card, pukf,
				       SC_AC_OP_UPDATE);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate key - pubkey: pkcs15init_authenticate(SC_AC_OP_UPDATE) failed");

	/* generate key pair */
	fidl = (file->id & 0xff) * FID_STEP;
	file->id = (file->id & 0xff00) + fidl;
	pukf->id = (pukf->id & 0xff00) + fidl;
	gendat.prkey_id = file->id;
	gendat.pukey_id = pukf->id;
	gendat.key_length = keybits;
	gendat.modulus = NULL;
	r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_GENERATE_KEY, &gendat);
	SC_TEST_GOTO_ERR(card->ctx, SC_LOG_DEBUG_VERBOSE, r,
		    "generate RSA key pair failed");
	
	if (!gendat.modulus) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* get the modulus */
	if (pubkey && (obj->type == SC_PKCS15_TYPE_PRKEY_RSA)) {
		u8 *buf;
		struct sc_pkcs15_pubkey_rsa *rsa = &pubkey->u.rsa;
		/* set the modulus */
		rsa->modulus.data = gendat.modulus;
		rsa->modulus.len = keybits >> 3;
		/* set the exponent (always 0x10001) */
		buf = (u8 *) malloc(3);
		if (!buf) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		buf[0] = 0x01;
		buf[1] = 0x00;
		buf[2] = 0x01;
		rsa->exponent.data = buf;
		rsa->exponent.len = 3;

		pubkey->algorithm = SC_ALGORITHM_RSA;
	}
	else if(pubkey && (obj->type == SC_PKCS15_TYPE_PRKEY_EC)){
		struct sc_ec_parameters *ecparams = (struct	
				sc_ec_parameters *)key_info->params.data;
		pubkey->algorithm = SC_ALGORITHM_EC; 
		pubkey->u.ec.ecpointQ.value = (u8 *) malloc(65);
		if (!pubkey->u.ec.ecpointQ.value) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		pubkey->u.ec.ecpointQ.value[0] = 0x04;
		memcpy(&pubkey->u.ec.ecpointQ.value[1], gendat.modulus, 64);
		pubkey->u.ec.ecpointQ.len = 65;

		free(pubkey->u.ec.params.named_curve);
		pubkey->u.ec.params.named_curve = NULL; 

		free(pubkey->u.ec.params.der.value);
		pubkey->u.ec.params.der.value = NULL;
		pubkey->u.ec.params.der.len = 0;
		pubkey->u.ec.params.named_curve = strdup(ecparams->named_curve); 

		if (!pubkey->u.ec.params.named_curve){
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		r = sc_pkcs15_fix_ec_parameters(card->ctx, &pubkey->u.ec.params);
	}
	else
		/* free public key */
		free(gendat.modulus);

err:
	sc_file_free(pukf);
	sc_file_free(file);
	sc_file_free(tfile);
	
	if(r < 0 && pubkey->u.ec.ecpointQ.value)
	{
		free(pubkey->u.ec.ecpointQ.value);
		pubkey->u.ec.ecpointQ.value = NULL;
		pubkey->u.ec.ecpointQ.len = 0;
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int epass2003_pkcs15_delete_object(struct sc_profile *profile,
					  struct sc_pkcs15_card *p15card,
					  struct sc_pkcs15_object *object,
					  const struct sc_path *path)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	return sc_pkcs15init_delete_by_path(profile, p15card, path);
}

static int epass2003_pkcs15_sanity_check(sc_profile_t * profile,
					 sc_pkcs15_card_t * p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info profile_auth;
	struct sc_pkcs15_object *objs[32];
	int rv, nn, ii, update_df = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(ctx, 
		 "Check and if needed update PinFlags");
	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	LOG_TEST_RET(ctx, rv, "Failed to get PINs");
	nn = rv;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_auth);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN info");

	for (ii = 0; ii < nn; ii++) {
		struct sc_pkcs15_auth_info *ainfo =
		    (struct sc_pkcs15_auth_info *)objs[ii]->data;
		struct sc_pkcs15_pin_attributes *pin_attrs = &ainfo->attrs.pin;

		if (ainfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			continue;

		if (pin_attrs->reference == profile_auth.attrs.pin.reference
		    && pin_attrs->flags != profile_auth.attrs.pin.flags) {
			sc_log(ctx, 
				 "Set flags of '%s'(flags:%X,ref:%i,id:%s) to %X",
				 objs[ii]->label, pin_attrs->flags,
				 pin_attrs->reference,
				 sc_pkcs15_print_id(&ainfo->auth_id),
				 profile_auth.attrs.pin.flags);
			pin_attrs->flags = profile_auth.attrs.pin.flags;
			update_df = 1;
		}
	}
	if (update_df) {
		struct sc_pkcs15_df *df = p15card->df_list;

		while (df != NULL && df->type != SC_PKCS15_AODF)
			df = df->next;
		if (!df)
			LOG_TEST_RET(ctx,
				    SC_ERROR_OBJECT_NOT_FOUND,
				    "Cannot find AODF");
		rv = sc_pkcs15init_update_any_df(p15card, profile, df, 0);
		LOG_TEST_RET(ctx, rv, "Update AODF error");
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}

static struct sc_pkcs15init_operations sc_pkcs15init_epass2003_operations = {
	epass2003_pkcs15_erase_card,
	epass2003_pkcs15_init_card,
	epass2003_pkcs15_create_dir,
	NULL,			/* create_domain */
	epass2003_pkcs15_pin_reference,
	epass2003_pkcs15_create_pin,
	epass2003_pkcs15_key_reference,
	epass2003_pkcs15_create_key,
	epass2003_pkcs15_store_key,
	epass2003_pkcs15_generate_key,
	NULL, NULL,		/* encode private/public key */
	NULL,			/* finalize */
	epass2003_pkcs15_delete_object,
	NULL, NULL, NULL, NULL, NULL,	/* pkcs15init emulation */
	epass2003_pkcs15_sanity_check,
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_epass2003_ops(void)
{
	return &sc_pkcs15init_epass2003_operations;
}
