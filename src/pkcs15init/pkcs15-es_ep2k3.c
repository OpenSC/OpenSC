/*
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
/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008*/

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "pkcs15-init.h"
#include "profile.h"
#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif

static int es_ep2k3_erase_card(struct sc_profile *profile, sc_pkcs15_card_t *p15card)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (sc_select_file(p15card->card, sc_get_mf_path(), NULL) < 0)
		return SC_SUCCESS;

	return sc_card_ctl(p15card->card, SC_CARDCTL_ERASE_CARD, 0);
}

static int es_ep2k3_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_card *card = p15card->card;
	int ret;
	sc_path_t path;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	{/* MF */
		 sc_file_t *mf_file;
		 sc_file_t *skey_file;
		 sc_es_ep2k3_wkey_data session_key;

		 ret = sc_profile_get_file(profile, "MF", &mf_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Get MF info failed");
		 assert(mf_file);
		 ret = sc_create_file(card, mf_file);
		 sc_file_free(mf_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create MF failed");

		 ret = sc_profile_get_file(profile, "SKey-MF", &skey_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Get SKey info failed");
		 assert(skey_file);
		 ret = sc_create_file(card, skey_file);
		 sc_file_free(skey_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create SKey failed");
		 
//		 session_key.type = SC_ES_SECRET_PRE;
//		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &session_key);
//		 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, ret , "Install session keys failed");
	}

	{/* EF(DIR) */
		 sc_file_t *dir_file;

		 /* get dir profile */
		 ret = sc_profile_get_file(profile, "DIR", &dir_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Get EF(DIR) info failed");
		 assert(dir_file);
		 ret = sc_create_file(card, dir_file);
		 sc_file_free(dir_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create EF(DIR) failed");
		 
		 sc_free_apps(card);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

static int es_ep2k3_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								sc_file_t *df)
{
	struct sc_card *card = p15card->card;
	int             ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	{/* p15 DF */
		 sc_file_t *df_file;
		 sc_file_t *skey_file;
		 sc_es_ep2k3_wkey_data session_key;

		 ret = sc_profile_get_file(profile, "PKCS15-AppDF", &df_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Get PKCS15-AppDF info failed");
		 assert(df_file);
		 ret = sc_create_file(card, df_file);
		 sc_file_free(df_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create PKCS15-AppDF failed");
			 
		 ret = sc_profile_get_file(profile, "SKey-AppDF", &skey_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Get SKey info failed");
		 assert(skey_file);
		 ret = sc_create_file(card, skey_file);
		 sc_file_free(skey_file);
		 SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create SKey failed");
		 
		 //FIXME:
//		 session_key.type = SC_ES_SECRET_PRE;
//		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &session_key);
//		 SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, ret , "Install session keys failed");
	}

	{/* p15 efs */
		 char* create_efs[]={
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
		 sc_file_t *file=0;
		 
		 for(i = 0; create_efs[i]; ++i)   {
			  if (sc_profile_get_file(profile, create_efs[i], &file))   {
				   sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Inconsistent profile: cannot find %s", create_efs[i]);
				   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INCONSISTENT_PROFILE);
			  }
			  assert(file);
			  ret = sc_create_file(card, file);
			  sc_file_free(file);
			  SC_TEST_RET(card->ctx,SC_LOG_DEBUG_NORMAL, ret,"Create pkcs15 file failed");
		 }
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, ret);
}

static int es_ep2k3_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								   sc_pkcs15_auth_info_t *auth_info)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;	

	if (auth_info->attrs.pin.reference < ENTERSAFE_USER_PIN_ID
			|| auth_info->attrs.pin.reference > ENTERSAFE_SO_PIN_ID)
		 return SC_ERROR_INVALID_PIN_REFERENCE;

	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int es_ep2k3_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								sc_file_t *df, sc_pkcs15_object_t *pin_obj,
								const unsigned char *pin, size_t pin_len,
								const unsigned char *puk, size_t puk_len)
{
	struct sc_card *card = p15card->card;
	int	r;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	{/*pin*/
		 sc_es_ep2k3_wkey_data  data;

		 if (!pin || !pin_len || pin_len > 16)
			  return SC_ERROR_INVALID_ARGUMENTS;

		 data.type = SC_ES_SECRET_PIN;
		 data.key_data.es_secret.kid = auth_info->attrs.pin.reference;
		 data.key_data.es_secret.ac[0] = ES_AC_MAC_NOLESS|ES_AC_EVERYONE;
		 data.key_data.es_secret.ac[1] = ES_AC_MAC_NOLESS|ES_AC_USER;
		 /* pad pin with 0 */
		 memset(data.key_data.es_secret.key_val, 0, sizeof(data.key_data.es_secret.key_val));
		 memcpy(data.key_data.es_secret.key_val, pin, pin_len);
		 data.key_data.es_secret.key_len=pin_len;

		 r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
		 if (pin_obj)   {
			 /* Cache new PIN value. */
			 sc_pkcs15_pincache_add(p15card, pin_obj, pin, pin_len);
		 }
	}

	{/*puk*/
		 sc_es_ep2k3_wkey_data  data;

		 if (!puk || !puk_len || puk_len > 16)
			  return SC_ERROR_INVALID_ARGUMENTS;

		 data.type = SC_ES_SECRET_PIN;
		 data.key_data.es_secret.kid = auth_info->attrs.pin.reference+1;
		 data.key_data.es_secret.ac[0] = ES_AC_MAC_NOLESS|ES_AC_EVERYONE;
		 data.key_data.es_secret.ac[1] = ES_AC_MAC_EQUAL|ES_AC_SO;
		 /* pad pin with 0 */
		 memset(data.key_data.es_secret.key_val, 0, sizeof(data.key_data.es_secret.key_val));
		 memcpy(data.key_data.es_secret.key_val, puk, puk_len);
		 data.key_data.es_secret.key_len = puk_len;

		 r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,r);
}

static int es_ep2k3_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								   sc_pkcs15_prkey_info_t *prkey)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (prkey->key_reference < 0)
		prkey->key_reference = 0;
	if (prkey->key_reference > ENTERSAFE_MAX_KEY_ID)
		return SC_ERROR_TOO_MANY_OBJECTS;
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

//borrowed from pkcs15-oberthur.c, modified
static int
cosm_new_file(struct sc_profile *profile, sc_card_t *card,
		unsigned int type, unsigned int num, sc_file_t **out)
{
	struct sc_file	*file;
	const char *_template = NULL, *desc = NULL;
	unsigned int structure = 0xFFFFFFFF;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "type %X; num %i\n",type, num);
	while (1) {
		switch (type) {
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type %X not supported by card driver", 
				type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "template %s; num %i\n",_template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Profile doesn't define %s template '%s'\n",
				desc, _template);
		return SC_ERROR_NOT_SUPPORTED;
	}
    
	file->id &= 0xFF00;
	file->id |= (num & 0x00FF);

	file->path.value[file->path.len-1] = (num & 0xFF);
	file->type = SC_FILE_TYPE_INTERNAL_EF;
	file->ef_structure = structure;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "file size %i; ef type %i/%i; id %04X, path_len %i\n",file->size, 
			file->type, file->ef_structure, file->id, file->path.len);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "file path: %s", sc_print_path(&(file->path))); 
	*out = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
}

//borrowed from pkcs15-oberthur.c, modified
static int es_ep2k3_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								sc_pkcs15_object_t *obj)
{
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)obj->data;
	struct sc_file *file = NULL;
	int r = 0;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	//FIXME: temporary return
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);

//	if( obj->type != SC_PKCS15_TYPE_PRKEY_RSA )
//	{
//		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "Only support RSA key");
//	}
//	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key ID:%s" , sc_pkcs15_print_id(&key_info->id)); 
//	/* allocate key object */
//	r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to allocate new key object");
//	file->size = key_info->modulus_length;
//	memcpy(&file->path, &key_info->path, sizeof(file->path));
//	file->id = file->path.value[file->path.len - 2] * 0x100
//		+ file->path.value[file->path.len - 1];
//	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key path: %s", sc_print_path(&file->path)); 
//	r = sc_select_file(p15card->card, &file->path, NULL);
//	/* exists? */
//	if( r == SC_SUCCESS )
//	{
//		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: key file exists");
//	}
//	/* create */
//	r = sc_pkcs15init_create_file(profile, p15card, file);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to create key file");
///* 	key_info->key_reference = file->path.value[file->path.len - 1];
// */
//
//	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int es_ep2k3_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
							   sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) obj->data;
	size_t idx = key_info->key_reference;
	size_t keybits = key_info->modulus_length;
	struct sc_path path;
	struct sc_file *tfile = NULL;
	struct sc_file *file = NULL;
	sc_es_ep2k3_wkey_data data;
	int r;
	int fidl = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "index %i; id %s\n", idx, sc_pkcs15_print_id(&key_info->id));
	if (key->algorithm != SC_ALGORITHM_RSA || key->algorithm != SC_ALGORITHM_RSA)
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "store key: only support RSA");

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "store key: with ID:%s and path:%s", sc_pkcs15_print_id(&key_info->id),
		       	sc_print_path(&key_info->path));

	/* allocate key object */
	r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to allocate new key object");
	file->size = keybits;
//	memcpy(&key_info->path, &file->path, sizeof(file->path));
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key path: %s", sc_print_path(&(file->path))); 
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key_info path: %s", sc_print_path(&(key_info->path))); 
	r = sc_delete_file(p15card->card, &file->path);
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to create key file");


	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "index %i; keybits %i\n", idx, keybits);
	if (keybits < 512 || keybits > 2048 || (keybits%0x20))   {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unsupported key size %u\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	path = key_info->path;
	path.len -= 2;

	r = sc_select_file(card, &path, &tfile);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key: no private object DF");


//	r = sc_select_file(card, &key_info->path, &file);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "store key: select key file failed");
	
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "No authorisation to store private key");

	sc_file_free(tfile);

	if (key_info->id.len > sizeof(data.key_data.es_key.fid))
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	
	fidl = (file->id & 0xff)*FID_STEP;
	file->id = (file->id & 0xff00) + fidl;
	printf("file->id:%02x\n", file->id);
	data.type = SC_ES_KEY_RSA;
	data.key_data.es_key.fid = file->id;
	data.key_data.es_key.rsa = (void *)&key->u.rsa;
		
	r = sc_card_ctl(p15card->card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "store key: cannot update private key");
	
	if (file) 
		sc_file_free(file);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int es_ep2k3_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								  sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_card *card = p15card->card;
	int r;
	sc_es_ep2k3_gen_key_data gendat;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) obj->data;
	size_t idx = key_info->key_reference;
	size_t keybits = key_info->modulus_length;
	struct sc_file *tfile = NULL, *prkf = NULL, *pukf = NULL;
	struct sc_path path;
	struct sc_file *file = NULL;
	int fidl = 0;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		return SC_ERROR_NOT_SUPPORTED;

	/* allocate key object */
	r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx, &file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to allocate new key object");
	file->size = keybits;
//	memcpy(&key_info->path, &file->path, sizeof(file->path));
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key path: %s", sc_print_path(&file->path)); 
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "private key_info path: %s", sc_print_path(&(key_info->path))); 
	r = sc_delete_file(p15card->card, &file->path);
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "create key: failed to create key file");


	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "index %i; keybits %i\n", idx, keybits);
	if (keybits < 512 || keybits > 2048 || (keybits%0x20))   {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Unsupported key size %u\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	path = key_info->path;
	path.len -= 2;

	r = sc_select_file(card, &path, &tfile);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key: no private object DF");

	r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_CRYPTO); 
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key: pkcs15init_authenticate(SC_AC_OP_CRYPTO) failed");
	
	r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_CREATE);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key: pkcs15init_authenticate(SC_AC_OP_CREATE) failed");
	
	sc_file_free(tfile);

//	r = sc_select_file(p15card->card, &key_info->path, &prkf);
//	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate key: select prkf failed");

	if ((r = cosm_new_file(profile, card, SC_PKCS15_TYPE_PUBKEY_RSA, idx, 
					&pukf)) < 0)
	{
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "generate key: create temporary pukf failed\n");
	 	goto failed;
	}
	pukf->size = keybits;
	pukf->id = pukf->path.value[pukf->path.len - 2] * 0x100
		+ pukf->path.value[pukf->path.len - 1];

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "public key size %i; ef type %i/%i; id %04X; path: %s", pukf->size, 
			pukf->type, pukf->ef_structure, pukf->id, sc_print_path(&pukf->path)); 

	r = sc_select_file(p15card->card, &pukf->path, NULL);
	/* if exist, delete */
	if( r == SC_SUCCESS )
	{
		r = sc_pkcs15init_delete_by_path(profile, p15card, &pukf->path);
		if( r != SC_SUCCESS )
		{
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "generate key: failed to delete existing key file\n");
			goto failed;
		}
	}
	/* create */
	r = sc_pkcs15init_create_file(profile, p15card, pukf);
	if( r != SC_SUCCESS )
	{
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "generate key: pukf create file failed\n");
		goto failed;
	}

	/* generate key pair */
	fidl = (file->id & 0xff)*FID_STEP;
	file->id = (file->id & 0xff00) + fidl;
	pukf->id = (pukf->id & 0xff00) + fidl;
//	printf("file->id:%02x\n", file->id);
//	printf("pukf->id:%02x\n", pukf->id);
	gendat.prkey_id = file->id;
//	gendat.prkey_id = prkf->id;
	gendat.pukey_id = pukf->id;
	gendat.key_length = keybits;
	gendat.modulus = NULL;
	r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_GENERATE_KEY, &gendat);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "generate RSA key pair failed");

	/* get the modulus via READ PUBLIC KEY */
	if (pubkey) {
		u8 *buf;
		struct sc_pkcs15_pubkey_rsa *rsa = &pubkey->u.rsa;
		/* set the modulus */
		rsa->modulus.data = gendat.modulus;
		rsa->modulus.len  = keybits >> 3;
		/* set the exponent (always 0x10001) */
		buf = (u8 *) malloc(3);
		if (!buf)
		{
			r = SC_ERROR_OUT_OF_MEMORY;
			goto failed;
		}
		buf[0] = 0x01;
		buf[1] = 0x00;
		buf[2] = 0x01;
		rsa->exponent.data = buf;
		rsa->exponent.len  = 3;

		pubkey->algorithm = SC_ALGORITHM_RSA;
	} else
		/* free public key */
		free(gendat.modulus);

//	key_info->key_reference = prkf->path.value[prkf->path.len - 1] & 0xff;
//	key_info->path = prkf->path;
//	key_info->key_reference = file->path.value[file->path.len - 1] & 0xff;
//	key_info->path = file->path;

failed:	
	if (pukf) sc_file_free(pukf);
	if (prkf) sc_file_free(prkf);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}
static int es_ep2k3_delete_object(struct sc_profile *profile, 
		struct sc_pkcs15_card *p15card, unsigned int type, 
		const void *data, const sc_path_t *path)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	return sc_pkcs15init_delete_by_path(profile, p15card, path);
}
static struct sc_pkcs15init_operations sc_pkcs15init_es_ep2k3_operations = {
	es_ep2k3_erase_card,
	es_ep2k3_init_card,
	es_ep2k3_create_dir,
	NULL,				/* create_domain */
	es_ep2k3_pin_reference,
	es_ep2k3_create_pin,
	es_ep2k3_key_reference,
	es_ep2k3_create_key,
	es_ep2k3_store_key,
	es_ep2k3_generate_key,
	NULL, NULL,			/* encode private/public key */
	NULL,	  			/* finalize */
	es_ep2k3_delete_object
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_es_ep2k3_ops(void)
{
	return &sc_pkcs15init_es_ep2k3_operations;
}
