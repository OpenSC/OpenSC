/*
 * MyEID specific operations for PKCS15 initialization
 *
 * Copyright (C) 2008-2009 Aventra Ltd.
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define KEEP_AC_NONE_FOR_INIT_APPLET

#define MYEID_MAX_PINS   14

unsigned char MYEID_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define MYEID_DEFAULT_PUBKEY_LEN       sizeof(MYEID_DEFAULT_PUBKEY)

/* For Myeid, all objects are files that can be deleted in any order */
static int 
myeid_delete_object(struct sc_profile *profile, 
		struct sc_pkcs15_card *p15card, unsigned int type, 
		const void *data, const sc_path_t *path)
{
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	return sc_pkcs15init_delete_by_path(profile, p15card, path);
}


/*
 * Get 'Initialize Applet' data
 * 	using the ACLs defined in card profile.
 */
static int
myeid_get_init_applet_data(struct sc_profile *profile, struct sc_pkcs15_card *p15card, 
		unsigned char *data, size_t data_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *tmp_file = NULL;
	const struct sc_acl_entry *entry = NULL;
	int r;
	
	SC_FUNC_CALLED(ctx, 1);

	if (data_len < 8)
		SC_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Cannot get init applet data");
				        
	*(data + 0) = 0xFF;
	*(data + 1) = 0xFF;

	/* MF acls */
	sc_file_dup(&tmp_file, profile->mf_info->file);
	if (tmp_file == NULL)
		SC_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate MF file");
	r = sc_pkcs15init_fixup_file(profile, p15card, tmp_file);
	SC_TEST_RET(ctx, r, "MF fixup failed");

	/* AC 'Create DF' and 'Create EF' */
	*(data + 2) = 0x00;	/* 'NONE' */
        entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_CREATE);
	if (entry->method == SC_AC_CHV)
		*(data + 2) = entry->key_ref | (entry->key_ref << 4);	/* 'CHVx'. */
	else if (entry->method == SC_AC_NEVER)
		*(data + 2) = 0xFF;	/* 'NEVER'. */

	/* AC 'INITIALISE APPLET'. */
	*(data + 3) = 0x0F;	/* 'NONE' */
#ifndef KEEP_AC_NONE_FOR_INIT_APPLET
        entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_DELETE);
	if (entry->method == SC_AC_CHV)
		*(data + 3) = (entry->key_ref << 4) | 0xF;
	else if (entry->method == SC_AC_NEVER)
		*(data + 3) = 0xFF;
#endif
	*(data + 4) = 0xFF;

	sc_file_free(tmp_file);
	tmp_file = NULL;

	/* Application DF (5015) acls */
	sc_file_dup(&tmp_file, profile->df_info->file);
	if (tmp_file == NULL)
		SC_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate Application DF file");
	r = sc_pkcs15init_fixup_file(profile, p15card, tmp_file);
	SC_TEST_RET(ctx, r, "Application DF fixup failed");

	/* AC 'Create DF' and 'Create EF' */
	*(data + 5) = 0x00;	/* 'NONE' */
        entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_CREATE);
	if (entry->method == SC_AC_CHV)
		*(data + 5) = entry->key_ref | (entry->key_ref << 4);	/* 'CHVx' */
	else if (entry->method == SC_AC_NEVER)
		*(data + 5) = 0xFF;	/* 'NEVER'. */

	/* AC 'Self delete' */
	*(data + 6) = 0x0F;	/* 'NONE' */
        entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_DELETE);
	if (entry->method == SC_AC_CHV)
		*(data + 6) = (entry->key_ref << 4) | 0xF;  /* 'CHVx' */
	else if (entry->method == SC_AC_NEVER)
		*(data + 6) = 0xFF;	/* 'NEVER'. */
	*(data + 7)= 0xFF;
	sc_file_free(tmp_file);

	SC_FUNC_RETURN(p15card->card->ctx, 1, SC_SUCCESS);
}


/*
 * Erase the card.
 */
static int 
myeid_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_cardctl_myeid_data_obj data_obj;
	struct sc_file *mf = NULL;
	unsigned char data[8];
	int r;
	
	SC_FUNC_CALLED(ctx, 1);

	r = myeid_get_init_applet_data(profile, p15card, data, sizeof(data));
	SC_TEST_RET(ctx, r, "Get init applet date error");

	/* Select parent DF and verify PINs/key as necessary */
	r = sc_select_file(p15card->card, sc_get_mf_path(), &mf);
	SC_TEST_RET(ctx, r, "Cannot select MF");

	/* ACLs are not actives if file is not in the operational state */
	if (mf->status == SC_FILE_STATUS_ACTIVATED)
		r = sc_pkcs15init_authenticate(profile, p15card, mf, SC_AC_OP_DELETE);
	SC_TEST_RET(ctx, r, "'DELETE' authentication failed on MF");
	
	data_obj.P1      = 0x01;
	data_obj.P2      = 0xE0;
	data_obj.Data    = data;
	data_obj.DataLen = sizeof(data);

	r = sc_card_ctl(p15card->card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);

	SC_FUNC_RETURN(p15card->card->ctx, 1, r);
}

static int 
myeid_init_card(sc_profile_t *profile, 
			   sc_pkcs15_card_t *p15card)
{
	struct	sc_path path;
	int r;

	SC_FUNC_CALLED(p15card->card->ctx, 1);

	sc_format_path("3F00", &path);
	r = sc_select_file(p15card->card, &path, NULL);
		
        SC_FUNC_RETURN(p15card->card->ctx, 1, r);	
}


/*
 * Create a DF
 */
static int 
myeid_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	int	r=0;

	if (!profile || !p15card || !df)
		return SC_ERROR_INVALID_ARGUMENTS;
	SC_FUNC_CALLED(p15card->card->ctx, 1);

	sc_debug(p15card->card->ctx, "id (%x)\n",df->id);

	if(df->id == 0x5015)
	{
	  sc_debug(p15card->card->ctx, "only Select (%x)\n",df->id);
	   r = sc_select_file(p15card->card, &df->path, NULL);
	}

	SC_FUNC_RETURN(p15card->card->ctx, 1, r);
}


/*
 * Select the PIN reference
 */
static int 
myeid_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_pin_info_t *pin_info)
{
	int type;

	SC_FUNC_CALLED(p15card->card->ctx, 1);
	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
	{
	  type = SC_PKCS15INIT_SO_PIN;
	  sc_debug(p15card->card->ctx, "PIN_FLAG_SO_PIN, ref (%d), tries_left (%d)\n",
                            pin_info->reference,pin_info->tries_left);	
	}
	else	
	{
	  type = SC_PKCS15INIT_USER_PIN;
	  sc_debug(p15card->card->ctx, "PIN_FLAG_PIN, ref (%d), tries_left (%d)\n",
                            pin_info->reference, pin_info->tries_left);

	}

	if (pin_info->reference <= 0 || pin_info->reference > MYEID_MAX_PINS)
		pin_info->reference = 1;
		
	SC_FUNC_RETURN(p15card->card->ctx, 1, 0);
}

/*
 * Create a new PIN
 */
static int 
myeid_create_pin(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df, struct sc_pkcs15_object *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char  data[20];
	struct sc_cardctl_myeid_data_obj data_obj;
	struct sc_pkcs15_pin_info *pin_info = (struct sc_pkcs15_pin_info *)pin_obj->data;
        struct sc_pkcs15_pin_info puk_info;
	int	r;

	SC_FUNC_CALLED(ctx, 1);
	sc_debug(ctx, "PIN('%s',ref:%i,flags:0x%X,pin_len:%d,puk_len:%d)\n",
                            pin_obj->label, pin_info->reference, pin_info->flags, pin_len, puk_len);

	if (pin_info->reference >= MYEID_MAX_PINS)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (pin == NULL || puk == NULL || pin_len < 4 || puk_len < 4)
		return SC_ERROR_INVALID_PIN_LENGTH;

	sc_profile_get_pin_info(profile, (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) 
			? SC_PKCS15INIT_SO_PUK : SC_PKCS15INIT_USER_PUK, 
			&puk_info);

	memset(data, 0, sizeof(data));
	/* Make command to add a pin-record */
	data_obj.P1 = 0x01;
	data_obj.P2 = pin_info->reference;	/* myeid pin number */
	
	memset(data, pin_info->pad_char, 8);
	memcpy(&data[0], (u8 *)pin, pin_len);   /* copy pin */

	memset(&data[8], puk_info.pad_char, 8);
	memcpy(&data[8], (u8 *)puk, puk_len);   /* copy puk */

	if(pin_info->tries_left > 0 && pin_info->tries_left < 15)
		data[16] = pin_info->tries_left;
	else
		data[16] = 5;	/* default value */

	if(puk_info.tries_left > 0 && puk_info.tries_left < 15)
		data[17] = puk_info.tries_left;
	else
		data[17] = 5;	/* default value */

	data[18] = 0x00;

	data_obj.Data    = data;
	data_obj.DataLen = 19;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);
	SC_TEST_RET(ctx, r, "Initialize PIN failed");

	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		/* Finalize DIR */
		/* TODO: add to pkcs15init API finalize_dir() method. */
		r = sc_card_ctl(p15card->card, SC_CARDCTL_MYEID_ACTIVATE_CARD, NULL);
	SC_TEST_RET(ctx, r, "Activate applet failed");

	SC_FUNC_RETURN(ctx, 1, r);
}


/*
 * Setup file struct & path: get correct template from the profile, construct full path
 * num = number of objects of this type already on the card
 */
static int 
myeid_new_file(sc_profile_t *profile, sc_card_t *card,
		unsigned int type, unsigned int num, 
		sc_file_t **out)
{
	sc_file_t *file;
	sc_path_t *p;
	char name[64], *tag;
	int r;

	SC_FUNC_CALLED(card->ctx, 1);
	if (type == SC_PKCS15_TYPE_PRKEY_RSA)
		tag = "private-key";
	else if (type  == SC_PKCS15_TYPE_PUBKEY_RSA)
		tag = "public-key";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT)
		tag = "certificate";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_DATA_OBJECT)
		tag = "data";
	else 
	{
		sc_debug(card->ctx, "Unsupported file type");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get template from profile  */
	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) 
	{
		sc_debug(card->ctx, "Profile doesn't define %s", name);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Auto-increment FID for next object */
	file->id += num;
	p = &file->path;
	*p = profile->df_info->file->path;
	p->value[p->len++] = (u8) (file->id / 256);
	p->value[p->len++] = (u8) (file->id % 256);

	/* Increment FID until there's no file with such path */
	r = sc_select_file(card, p, NULL);
	while(r == 0) 
	{
		file->id++;
		p->value[p->len - 2] = (u8) (file->id / 256);
		p->value[p->len - 1] = (u8) (file->id % 256);
		r = sc_select_file(card, p, NULL);
	}

	*out = file;
	SC_FUNC_RETURN(card->ctx, 1, 0);
}


static int 
myeid_encode_private_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key, 
		size_t *keysize, int key_ref)
{
	SC_FUNC_CALLED(card->ctx, 1);
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

static int 
myeid_encode_public_key(sc_profile_t *profile, sc_card_t *card, 
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key, 
		size_t *keysize, int key_ref)
{
	SC_FUNC_CALLED(card->ctx, 1);
	SC_FUNC_RETURN(card->ctx, 1, 0);
}


#if 0
/*
 * Generate RSA key
 */
static int myeid_generate_key(sc_profile_t *profile, sc_card_t *card,
		unsigned int index, /* keyref: 0 for 1st key, ... */
		unsigned int keybits,
		sc_pkcs15_pubkey_t *pubkey,
		struct sc_pkcs15_prkey_info *info)
{
	return myeid_generate_store_key(profile, card, index, keybits, 
		pubkey, NULL, info);
}

/*
 * Store RSA key
 */
static int myeid_new_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey *key, unsigned int index,
		struct sc_pkcs15_prkey_info *info)
{
	return myeid_generate_store_key(profile, card, index, 
		key->u.rsa.modulus.len * 8, NULL, key, info);
}

/*
 * Common code for generating or storing a private key.
 * If pubkey == NULL and prkey != NULL, we have to store a private key
 * In the oposite case, we have to generate a private key
 */
static int myeid_generate_store_key(sc_profile_t *profile, sc_card_t *card,
		unsigned int index,  /* keynumber: 0 for 1st priv key, ...  */
		unsigned int keybits,
		sc_pkcs15_pubkey_t *pubkey,
		sc_pkcs15_prkey_t *prkey,
		sc_pkcs15_prkey_info_t *info)
{
	struct sc_cardctl_myeid_gen_store_key_info args;
	int           r;
	sc_file_t    *prkf = NULL;

	SC_FUNC_CALLED(card->ctx, 1);
	/* Parameter check */
	if ( (keybits < 1024) || (keybits > 2048) || (keybits & 0X7)) {
		sc_debug(card->ctx, 
			"Unsupported key size [%u]: 1024-2048 bit + 8-multiple\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get the private key file */
	r = myeid_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, index, &prkf);	
	if (r < 0)
		goto done;

	/* Take enough room for a 1024 bit key */
	if (prkf->size < 1024)
		prkf->size = 1024;

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, card, prkf);
	if (r < 0)
		goto done;

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	if (prkey == NULL) 
	{
		args.op_type    = OP_TYPE_GENERATE;
		args.pubexp_len = MYEID_DEFAULT_PUBKEY_LEN;
		args.pubexp     = MYEID_DEFAULT_PUBKEY;
	}
	else 
	{
		args.op_type    = OP_TYPE_STORE;
		args.pubexp_len = prkey->u.rsa.exponent.len;
		args.pubexp     = prkey->u.rsa.exponent.data;
		args.primep_len = prkey->u.rsa.p.len;
		args.primep     = prkey->u.rsa.p.data;
		args.primeq_len = prkey->u.rsa.q.len;
		args.primeq     = prkey->u.rsa.q.data;

		args.dp1_len    = prkey->u.rsa.dmp1.len;
		args.dp1        = prkey->u.rsa.dmp1.data;
		args.dq1_len    = prkey->u.rsa.dmq1.len;
		args.dq1        = prkey->u.rsa.dmq1.data;
		args.invq_len   = prkey->u.rsa.iqmp.len;
		args.invq       = prkey->u.rsa.iqmp.data;

		args.mod_len    = prkey->u.rsa.modulus.len;
		args.mod        = prkey->u.rsa.modulus.data;		
	}

	/* Authenticate */
	r = sc_pkcs15init_authenticate(profile, card, prkf, SC_AC_OP_UPDATE);
	if (r < 0) 
	 	goto done;
	
	/* Generate/store rsa key  */
	r = sc_card_ctl(card, SC_CARDCTL_MYEID_GENERATE_KEY, &args);
	if (r < 0)
		goto done;

	info->key_reference = 0;
	info->path = prkf->path;

done:
	if (prkf)
		sc_file_free(prkf);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

#endif

/*
 * Store a private key
 */
static int
myeid_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	int keybits = key_info->modulus_length, r;

	SC_FUNC_CALLED(card->ctx, 1);
	/* Parameter check */
	if ( (keybits < 1024) || (keybits > 2048) || (keybits & 0x7))
		SC_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");

        sc_debug(ctx, "create MyEID private key ID:%s\n",  sc_pkcs15_print_id(&key_info->id));

	/* Get the private key file */
	r = myeid_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);	
	SC_TEST_RET(ctx, r, "Cannot get new MyEID private key file");

	/* Take enough room for a 1024 bit key */
	if (file->size < 1024)
		file->size = 1024;

	/* Replace the path of instantiated key template by the path from the object data. */
        memcpy(&file->path, &key_info->path, sizeof(file->path));
        file->id = file->path.value[file->path.len - 2] * 0x100
		+ file->path.value[file->path.len - 1];
	
	key_info->key_reference = file->path.value[file->path.len - 1] & 0xFF;

        sc_debug(ctx, "Path of MyEID private key file to create %s\n", sc_print_path(&file->path));

        r = sc_select_file(card, &file->path, NULL);
        if (!r)   {
		r = myeid_delete_object(profile, p15card, object->type, NULL, &file->path);
		SC_TEST_RET(ctx, r, "Failed to delete MyEID private key file");
	}
        else if (r != SC_ERROR_FILE_NOT_FOUND)    {
		SC_TEST_RET(ctx, r, "Select MyEID private key file error");
	}

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	sc_file_free(file);
	SC_TEST_RET(ctx, r, "Cannot create MyEID private key file");

	SC_FUNC_RETURN(ctx, 1, r);
}


/*
 * Store a private key
 */
static int
myeid_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, 
		struct sc_pkcs15_prkey *prkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_cardctl_myeid_gen_store_key_info args;
	struct sc_file *file = NULL;
	int r, keybits = key_info->modulus_length;

	SC_FUNC_CALLED(ctx, 1);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		SC_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Store key failed: RSA only supported");

	/* Parameter check */
	if ( (keybits < 1024) || (keybits > 2048) || (keybits & 0x7))
		SC_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");

	sc_debug(ctx, "store MyEID key with ID:%s and path:%s\n", sc_pkcs15_print_id(&key_info->id),
		       	sc_print_path(&key_info->path));

	r = sc_select_file(card, &key_info->path, &file);
	SC_TEST_RET(ctx, r, "Cannot store MyEID key: select key file failed");
	
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	SC_TEST_RET(ctx, r, "No authorisation to store MyEID private key");

	if (file) 
		sc_file_free(file);

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	args.op_type    = OP_TYPE_STORE;
	args.pubexp_len = prkey->u.rsa.exponent.len;
	args.pubexp     = prkey->u.rsa.exponent.data;
	args.primep_len = prkey->u.rsa.p.len;
	args.primep     = prkey->u.rsa.p.data;
	args.primeq_len = prkey->u.rsa.q.len;
	args.primeq     = prkey->u.rsa.q.data;

	args.dp1_len    = prkey->u.rsa.dmp1.len;
	args.dp1        = prkey->u.rsa.dmp1.data;
	args.dq1_len    = prkey->u.rsa.dmq1.len;
	args.dq1        = prkey->u.rsa.dmq1.data;
	args.invq_len   = prkey->u.rsa.iqmp.len;
	args.invq       = prkey->u.rsa.iqmp.data;

	args.mod_len    = prkey->u.rsa.modulus.len;
	args.mod        = prkey->u.rsa.modulus.data;		

	/* Store RSA key  */
	r = sc_card_ctl(card, SC_CARDCTL_MYEID_GENERATE_STORE_KEY, &args);
	SC_TEST_RET(ctx, r, "Card control 'MYEID_GENERATE_STORE_KEY' failed");

	SC_FUNC_RETURN(ctx, 1, r);
}


static int
myeid_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, 
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_cardctl_myeid_gen_store_key_info args;
	struct sc_file *file = NULL;
	int r, keybits = key_info->modulus_length;
	unsigned char raw_pubkey[256];

	SC_FUNC_CALLED(ctx, 1);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		SC_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Store key failed: RSA only supported");

	/* Parameter check */
	if ( (keybits < 1024) || (keybits > 2048) || (keybits & 0x7))
		SC_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");

	sc_debug(ctx, "store MyEID key with ID:%s and path:%s\n", sc_pkcs15_print_id(&key_info->id),
		       	sc_print_path(&key_info->path));

	r = sc_select_file(card, &key_info->path, &file);
	SC_TEST_RET(ctx, r, "Cannot store MyEID key: select key file failed");
	
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	SC_TEST_RET(ctx, r, "No authorisation to store MyEID private key");

	if (file) 
		sc_file_free(file);

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	args.op_type    = OP_TYPE_GENERATE;
	args.pubexp_len = MYEID_DEFAULT_PUBKEY_LEN;
	args.pubexp     = MYEID_DEFAULT_PUBKEY;

	/* Generate RSA key  */
	r = sc_card_ctl(card, SC_CARDCTL_MYEID_GENERATE_STORE_KEY, &args);
	SC_TEST_RET(ctx, r, "Card control 'MYEID_GENERATE_STORE_KEY' failed");

	/* Keypair generation -> collect public key info */
	/* FIXME: was not preset in original Aventra version. Need to be tested. (VT) */
	if (pubkey != NULL)   {
		struct sc_cardctl_myeid_data_obj data_obj;

		pubkey->algorithm		= SC_ALGORITHM_RSA;
		pubkey->u.rsa.modulus.len	= (keybits + 7) / 8;
		pubkey->u.rsa.modulus.data	= (u8 *) malloc(pubkey->u.rsa.modulus.len);
		pubkey->u.rsa.exponent.len	= MYEID_DEFAULT_PUBKEY_LEN;
		pubkey->u.rsa.exponent.data	= (u8 *) malloc(MYEID_DEFAULT_PUBKEY_LEN);
		memcpy(pubkey->u.rsa.exponent.data, MYEID_DEFAULT_PUBKEY, MYEID_DEFAULT_PUBKEY_LEN);

		/* Get public key modulus */
		r = sc_select_file(card, &file->path, NULL);
		SC_TEST_RET(ctx, r, "Cannot get key modulus: select key file failed");

		data_obj.P1 = 0x01;
		data_obj.P2 = 0x01;
		data_obj.Data = raw_pubkey;
		data_obj.DataLen = sizeof(raw_pubkey);

		r = sc_card_ctl(card, SC_CARDCTL_MYEID_GETDATA, &data_obj);
		SC_TEST_RET(ctx, r, "Cannot get key modulus: 'MYEID_GETDATA' failed");

		keybits = ((raw_pubkey[0] * 256) + raw_pubkey[1]);  /* modulus bit length */
		if (keybits != key_info->modulus_length)
			SC_TEST_RET(ctx, SC_ERROR_PKCS15INIT, "Cannot get key modulus: invalid key-size");

		memcpy (pubkey->u.rsa.modulus.data, &raw_pubkey[2], pubkey->u.rsa.modulus.len);
	}

	SC_FUNC_RETURN(ctx, 1, r);
}


/*
 * Create a new PIN
 */
static struct sc_pkcs15init_operations sc_pkcs15init_myeid_operations = {
	myeid_erase_card,
	myeid_init_card,       		/* init_card */
	myeid_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	myeid_select_pin_reference,
	myeid_create_pin,
	NULL,				/* select_key_reference */
	myeid_create_key,
	myeid_store_key,
	myeid_generate_key,
	myeid_encode_private_key,
	myeid_encode_public_key,
	NULL,				/* finalize_card */
	myeid_delete_object		/* delete_object */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_myeid_ops(void)
{
	return &sc_pkcs15init_myeid_operations;
}
