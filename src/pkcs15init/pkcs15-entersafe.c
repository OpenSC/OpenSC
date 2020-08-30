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
/* Disable RSA:512bits by Shengchao Niu (shengchao@ftsafe.com) 2012 */

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "pkcs15-init.h"
#include "profile.h"

static u8 process_acl_entry(sc_file_t *in, unsigned int method, unsigned int in_def)
{
	u8 def = (u8)in_def;
	const sc_acl_entry_t *entry = sc_file_get_acl_entry(in, method);
	if (!entry)
	{
		return def;
	}
	else if (entry->method == SC_AC_CHV)
	{
		unsigned int key_ref = entry->key_ref;
		if (key_ref == SC_AC_KEY_REF_NONE)
			return def;
		else
			return ENTERSAFE_AC_ALWAYS&0x04;
	}
	else if (entry->method == SC_AC_SYMBOLIC)
	{
		 return ENTERSAFE_AC_ALWAYS&0x04;
	}
	else if (entry->method == SC_AC_NEVER)
	{
		return ENTERSAFE_AC_NEVER;
	}
	else
	{
		return def;
	}
}

static int entersafe_erase_card(struct sc_profile *profile, sc_pkcs15_card_t *p15card)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (sc_select_file(p15card->card, sc_get_mf_path(), NULL) < 0)
		return SC_SUCCESS;

	return sc_card_ctl(p15card->card,SC_CARDCTL_ERASE_CARD,0);
}

static int entersafe_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_card *card = p15card->card;
	int ret;

	{/* MF */
		 sc_file_t *mf_file;
		 sc_entersafe_create_data mf_data;

		 SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

		 ret = sc_profile_get_file(profile, "MF", &mf_file);
		 LOG_TEST_RET(card->ctx,ret,"Get MF info failed");

		 mf_data.type = SC_ENTERSAFE_MF_DATA;
		 mf_data.data.df.file_id[0]=0x3F;
		 mf_data.data.df.file_id[1]=0x00;
		 mf_data.data.df.file_count=0x04;
		 mf_data.data.df.flag=0x11;
		 mf_data.data.df.ikf_size[0]=(mf_file->size>>8)&0xFF;
		 mf_data.data.df.ikf_size[1]=mf_file->size&0xFF;
		 mf_data.data.df.create_ac=0x10;
		 mf_data.data.df.append_ac=0xC0;
		 mf_data.data.df.lock_ac=0x10;
		 memcpy(mf_data.data.df.aid,mf_file->name,mf_file->namelen);
		 sc_file_free(mf_file);

		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_CREATE_FILE, &mf_data);
		 LOG_TEST_RET(card->ctx,ret,"Create MF failed");
	}

	{/* EF(DIR) */
		 sc_file_t *dir_file;
		 size_t fid,size;
		 sc_entersafe_create_data ef_data;
		 u8 *buff=0;

		 /* get dir profile */
		 ret = sc_profile_get_file(profile, "dir", &dir_file);
		 LOG_TEST_RET(card->ctx,ret,"Get EF(DIR) info failed");
		 fid=dir_file->id;
		 size=dir_file->size;
		 sc_file_free(dir_file);

		 ef_data.type=SC_ENTERSAFE_EF_DATA;
		 ef_data.data.ef.file_id[0]=(fid>>8)&0xFF;
		 ef_data.data.ef.file_id[1]=fid&0xFF;
		 ef_data.data.ef.size[0]=(size>>8)&0xFF;
		 ef_data.data.ef.size[1]=size&0xFF;
		 ef_data.data.ef.attr[0]=0x00;
		 ef_data.data.ef.attr[1]=0x00;
		 ef_data.data.ef.name=0x00;
		 memset(ef_data.data.ef.ac,0x10,sizeof(ef_data.data.ef.ac));
		 memset(ef_data.data.ef.sm,0x00,sizeof(ef_data.data.ef.sm));

		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_CREATE_FILE, &ef_data);
		 LOG_TEST_RET(card->ctx,ret,"Create EF(DIR) failed");


		 /* fill file by 0 */
		 buff = calloc(1,size);
		 if(!buff)
			  SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
		 memset(buff,0,size);

		 ret = sc_update_binary(card,0,buff,size,0);
		 free(buff);
		 LOG_TEST_RET(card->ctx,ret,"Initialize EF(DIR) failed");
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);

}

static int entersafe_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								sc_file_t *df)
{
	struct sc_card *card = p15card->card;
	int             ret;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	{/* df */
		 sc_entersafe_create_data df_data;

		 df_data.type = SC_ENTERSAFE_DF_DATA;
		 df_data.data.df.file_id[0]=(df->id >> 8) & 0xFF;
		 df_data.data.df.file_id[1]=df->id & 0xFF;
		 df_data.data.df.file_count=0x30;
		 df_data.data.df.flag=0x01;
		 df_data.data.df.ikf_size[0]=(df->size>>8)&0xFF;
		 df_data.data.df.ikf_size[1]=df->size&0xFF;
		 df_data.data.df.create_ac=0x10;
		 df_data.data.df.append_ac=0xC0;
		 df_data.data.df.lock_ac=0x10;
		 memcpy(df_data.data.df.aid,df->name,df->namelen);

		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_CREATE_FILE, &df_data);
		 LOG_TEST_RET(card->ctx,ret,"Crate DF failed");
	}

	{/* GPKF */
		 sc_file_t *gpkf_file;
		 sc_entersafe_create_data ef_data;

		 /* get p15_gpkf profile */
		 ret = sc_profile_get_file(profile, "p15_gpkf", &gpkf_file);
		 LOG_TEST_RET(card->ctx,ret,"Get GPKF info failed");

		 ef_data.type=SC_ENTERSAFE_EF_DATA;
		 ef_data.data.ef.file_id[0]=(gpkf_file->id>>8)&0xFF;
		 ef_data.data.ef.file_id[1]=gpkf_file->id&0xFF;
		 ef_data.data.ef.size[0]=(gpkf_file->size>>8)&0xFF;
		 ef_data.data.ef.size[1]=gpkf_file->size&0xFF;
		 ef_data.data.ef.attr[0]=0x15;
		 ef_data.data.ef.attr[1]=0x80;
		 ef_data.data.ef.name=0x00;
		 memset(ef_data.data.ef.ac,0x10,sizeof(ef_data.data.ef.ac));
		 memset(ef_data.data.ef.sm,0x00,sizeof(ef_data.data.ef.sm));

		 sc_file_free(gpkf_file);

		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_CREATE_FILE, &ef_data);
		 LOG_TEST_RET(card->ctx,ret,"Create GPKF failed");
	}

	{/* p15 efs */
		 const char * create_efs[]={
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
		 sc_entersafe_create_data tmp;

		 for(i = 0; create_efs[i]; ++i)   {
			  if (sc_profile_get_file(profile, create_efs[i], &file))   {
				   sc_log(card->ctx,  "Inconsistent profile: cannot find %s", create_efs[i]);
				   SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INCONSISTENT_PROFILE);
			  }

			  tmp.type=SC_ENTERSAFE_EF_DATA;
			  tmp.data.ef.file_id[0]=(file->id>>8)&0xFF;
			  tmp.data.ef.file_id[1]=file->id&0xFF;
			  tmp.data.ef.size[0]=(file->size>>8)&0xFF;
			  tmp.data.ef.size[1]=file->size&0xFF;
			  tmp.data.ef.attr[0]=0x00;
			  tmp.data.ef.attr[1]=0x00;
			  tmp.data.ef.name=0x00;
			  memset(tmp.data.ef.ac,ENTERSAFE_AC_ALWAYS,sizeof(tmp.data.ef.ac));
			  tmp.data.ef.ac[0]=process_acl_entry(file,SC_AC_OP_READ,ENTERSAFE_AC_ALWAYS); /* read */
			  tmp.data.ef.ac[1]=process_acl_entry(file,SC_AC_OP_UPDATE,ENTERSAFE_AC_ALWAYS); /* update */
			  memset(tmp.data.ef.sm,0x00,sizeof(tmp.data.ef.sm));

			  sc_file_free(file);

			  ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_CREATE_FILE, &tmp);
			  LOG_TEST_RET(card->ctx,ret,"Create pkcs15 file failed");
		 }
	}

	{/* Preinstall keys */
		 ret = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_PREINSTALL_KEYS, 0);
		 LOG_TEST_RET(card->ctx,ret,"Preinstall keys failed");
	}

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,ret);
}

static int entersafe_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								   sc_pkcs15_auth_info_t *auth_info)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.reference < ENTERSAFE_USER_PIN_ID)
		 auth_info->attrs.pin.reference = ENTERSAFE_USER_PIN_ID;
	if (auth_info->attrs.pin.reference > ENTERSAFE_USER_PIN_ID)
		 return SC_ERROR_TOO_MANY_OBJECTS;

	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int entersafe_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
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
		 sc_entersafe_wkey_data  data;

		 if (!pin || !pin_len || pin_len > 16)
			  return SC_ERROR_INVALID_ARGUMENTS;

		 data.key_id = auth_info->attrs.pin.reference;
		 data.usage=0x0B;
		 data.key_data.symmetric.EC=0x33;
		 data.key_data.symmetric.ver=0x00;
		 /* pad pin with 0 */
		 memset(data.key_data.symmetric.key_val, 0, sizeof(data.key_data.symmetric.key_val));
		 memcpy(data.key_data.symmetric.key_val, pin, pin_len);
		 data.key_data.symmetric.key_len=16;

		 r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
		 if (r < 0)
			 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

		 /* Cache new PIN value. */
		 sc_pkcs15_pincache_add(p15card, pin_obj, pin, pin_len);
	}

	{/*puk*/
		 sc_entersafe_wkey_data  data;

		 if (!puk || !puk_len || puk_len > 16)
			  return SC_ERROR_INVALID_ARGUMENTS;

		 data.key_id = auth_info->attrs.pin.reference+1;
		 data.usage=0x0B;
		 data.key_data.symmetric.EC=0x33;
		 data.key_data.symmetric.ver=0x00;
		 /* pad pin with 0 */
		 memset(data.key_data.symmetric.key_val, 0, sizeof(data.key_data.symmetric.key_val));
		 memcpy(data.key_data.symmetric.key_val, puk, puk_len);
		 data.key_data.symmetric.key_len=16;

		 r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
	}


	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
}

static int entersafe_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								   sc_pkcs15_prkey_info_t *prkey)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (prkey->key_reference < ENTERSAFE_MIN_KEY_ID)
		prkey->key_reference = ENTERSAFE_MIN_KEY_ID;
	if (prkey->key_reference > ENTERSAFE_MAX_KEY_ID)
		return SC_ERROR_TOO_MANY_OBJECTS;
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int entersafe_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								sc_pkcs15_object_t *obj)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);
	SC_FUNC_RETURN(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}

static int entersafe_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
							   sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_card_t *card = p15card->card;
	sc_entersafe_wkey_data data;
	sc_file_t              *tfile;
	const sc_acl_entry_t   *acl_entry;
	int r;

	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)obj->data;
	size_t keybits = key_info->modulus_length;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if ( key->algorithm != SC_ALGORITHM_RSA )
	{
		 /* ignore DSA keys */
		 SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_ERROR_INVALID_ARGUMENTS);
	}

	/* Disable RSA:512bits */
	if ( ( keybits < 1024 ) ||
		 ( keybits > 2048 ) ||
		 ( keybits % 0x20 ) )
	{
		sc_debug(card->ctx,
			 SC_LOG_DEBUG_NORMAL,
			 "Unsupported key size %"SC_FORMAT_LEN_SIZE_T"u\n",
			 keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_profile_get_file(profile, "PKCS15-AODF", &tfile);
	if (r < 0)
		 return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_UPDATE);
	if (acl_entry->method  != SC_AC_NONE) {
		 r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_UPDATE);
		 if(r<0)
			  r = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}
	sc_file_free(tfile);
	LOG_TEST_RET(card->ctx, r, "can't verify pin");

	data.key_id = (u8) kinfo->key_reference;
	data.usage=0x22;
	data.key_data.rsa=&key->u.rsa;
	return sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_WRITE_KEY, &data);
}

static int entersafe_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
								  sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	int r;
	sc_entersafe_gen_key_data	gendat;
	sc_pkcs15_prkey_info_t *kinfo = (sc_pkcs15_prkey_info_t *) obj->data;
	sc_card_t *card = p15card->card;
	sc_file_t              *tfile;
	const sc_acl_entry_t   *acl_entry;

	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)obj->data;
	size_t keybits = key_info->modulus_length;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if ( obj->type != SC_PKCS15_TYPE_PRKEY_RSA )
	{
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Disable RSA:512bits */
	if ( ( keybits < 1024 ) ||
		 ( keybits > 2048 ) ||
		 ( keybits % 0x20 ) )
	{
		sc_debug(card->ctx,
			 SC_LOG_DEBUG_NORMAL,
			 "Unsupported key size %"SC_FORMAT_LEN_SIZE_T"u\n",
			 keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_profile_get_file(profile, "PKCS15-AODF", &tfile);
	if (r < 0)
		 return r;
	acl_entry = sc_file_get_acl_entry(tfile, SC_AC_OP_UPDATE);
	if (acl_entry->method  != SC_AC_NONE) {
		 r = sc_pkcs15init_authenticate(profile, p15card, tfile, SC_AC_OP_UPDATE);
		 if(r<0)
			  r = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}
	sc_file_free(tfile);
	LOG_TEST_RET(card->ctx, r, "can't verify pin");

	/* generate key pair */
	gendat.key_id     = (u8) kinfo->key_reference;
	gendat.key_length = (size_t) kinfo->modulus_length;
	gendat.modulus    = NULL;
	r = sc_card_ctl(card, SC_CARDCTL_ENTERSAFE_GENERATE_KEY, &gendat);
	LOG_TEST_RET(card->ctx, r, "EnterSafe generate RSA key pair failed");

	/* get the modulus via READ PUBLIC KEY */
	if (pubkey) {
		u8 *buf;
		struct sc_pkcs15_pubkey_rsa *rsa = &pubkey->u.rsa;
		/* set the modulus */
		rsa->modulus.data = gendat.modulus;
		rsa->modulus.len  = kinfo->modulus_length >> 3;
		/* set the exponent (always 0x10001) */
		buf = malloc(3);
		if (!buf)
			return SC_ERROR_OUT_OF_MEMORY;
		buf[0] = 0x01;
		buf[1] = 0x00;
		buf[2] = 0x01;
		rsa->exponent.data = buf;
		rsa->exponent.len  = 3;

		pubkey->algorithm = SC_ALGORITHM_RSA;
	} else
		/* free public key */
		free(gendat.modulus);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,SC_SUCCESS);
}


static int entersafe_sanity_check(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info profile_auth;
	struct sc_pkcs15_object *objs[32];
	int rv, nn, ii, update_df = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	sc_log(ctx,  "Check and if needed update PinFlags");
	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	LOG_TEST_RET(ctx, rv, "Failed to get PINs");
	nn = rv;

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_auth);
	LOG_TEST_RET(ctx, rv, "Failed to get PIN info");

	for (ii=0; ii<nn; ii++) {
		struct sc_pkcs15_auth_info *ainfo = (struct sc_pkcs15_auth_info *) objs[ii]->data;
		struct sc_pkcs15_pin_attributes *pin_attrs = &ainfo->attrs.pin;

		if (ainfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			continue;

		if (pin_attrs->reference == profile_auth.attrs.pin.reference
				&& pin_attrs->flags != profile_auth.attrs.pin.flags)   {
			sc_log(ctx,  "Set flags of '%s'(flags:%X,ref:%i,id:%s) to %X", objs[ii]->label,
					pin_attrs->flags, pin_attrs->reference, sc_pkcs15_print_id(&ainfo->auth_id),
					profile_auth.attrs.pin.flags);
			pin_attrs->flags = profile_auth.attrs.pin.flags;
			update_df = 1;
		}
	}
	if (update_df)   {
		struct sc_pkcs15_df *df = p15card->df_list;

		while (df != NULL && df->type != SC_PKCS15_AODF)
			df = df->next;
		if (!df)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "Cannot find AODF");
		rv = sc_pkcs15init_update_any_df(p15card, profile, df, 0);
		LOG_TEST_RET(ctx, rv, "Update AODF error");
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}

static struct sc_pkcs15init_operations sc_pkcs15init_entersafe_operations = {
	entersafe_erase_card,
	entersafe_init_card,
	entersafe_create_dir,
	NULL,				/* create_domain */
	entersafe_pin_reference,
	entersafe_create_pin,
	entersafe_key_reference,
	entersafe_create_key,
	entersafe_store_key,
	entersafe_generate_key,
	NULL, NULL,			/* encode private/public key */
	NULL,	  			/* finalize */
	NULL, 				/* delete_object */
	NULL, NULL, NULL, NULL, NULL, 	/* pkcs15init emulation */
	entersafe_sanity_check,
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_entersafe_ops(void)
{
	return &sc_pkcs15init_entersafe_operations;
}
