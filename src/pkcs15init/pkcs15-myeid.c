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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "keycache.h"
#include "profile.h"

#define MYEID_MAX_PINS   14

unsigned char MYEID_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define MYEID_DEFAULT_PUBKEY_LEN       sizeof(MYEID_DEFAULT_PUBKEY)

static int myeid_generate_store_key( sc_profile_t *, sc_card_t *,
		unsigned int, unsigned int, sc_pkcs15_pubkey_t *,
		sc_pkcs15_prkey_t *, sc_pkcs15_prkey_info_t *);

static int myeid_create_pin_internal(sc_profile_t *, sc_card_t *,
		int, sc_pkcs15_pin_info_t *, const u8 *, size_t, 
		const u8 *, size_t);

static int myeid_puk_retries(sc_profile_t *profile, sc_pkcs15_pin_info_t *pin_info);

static int acl_to_byte(const struct sc_acl_entry *e)
{
	switch (e->method) {
	case SC_AC_NONE:
		return 0x00;
	case SC_AC_CHV:
	case SC_AC_TERM:
	case SC_AC_AUT:
		if (e->key_ref == SC_AC_KEY_REF_NONE)
			return 0x00;
		if (e->key_ref < 1 || e->key_ref > MYEID_MAX_PINS)
			return 0x00;
		return e->key_ref;
	case SC_AC_NEVER:
		return 0x0F;
	}
	return 0x00;
}

/*
 * Erase the card.
 */
static int myeid_erase_card(sc_profile_t *profile, sc_card_t *card)
{
	struct sc_cardctl_myeid_data_obj data_obj;
	sc_pkcs15_pin_info_t sopin_info, pin_info;

	u8  data[8];
	int r;
	
	SC_FUNC_CALLED(card->ctx, 1);

	/* The SO pin has pin reference 1 -- not that it matters much
	 * because pkcs15-init will ask to enter all pins, even if we
	 * did a --so-pin on the command line. */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &sopin_info);

	/* Select parent DF and verify PINs/key as necessary */
	r = sc_pkcs15init_authenticate(profile, card, profile->mf_info->file, SC_AC_OP_DELETE);
	if (r < 0)
		return r == SC_ERROR_FILE_NOT_FOUND ? 0 : r;

	data[0]= 0xFF;
	data[1]= 0xFF;
	data[2]= 0x11; 
	data[3]= 0x3F;
	data[4]= 0xFF;
	data[5]= 0x11; 
	data[6]= 0xFF; 
	data[7]= 0xFF;
	
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &pin_info);	
	if(pin_info.reference > 0 && pin_info.reference <= MYEID_MAX_PINS && 
           sopin_info.reference > 0 && sopin_info.reference <= MYEID_MAX_PINS)
	{
	  data[2] = (pin_info.reference << 4)| pin_info.reference;
	  data[3] = (sopin_info.reference << 4) | 0x0F;
	  data[5] = data[2];
	}
		
	data_obj.P1      = 0x01;
	data_obj.P2      = 0xE0;
	data_obj.Data    = data;
	data_obj.DataLen = 0x08;

	sc_debug(card->ctx, "so_pin(%d), user pin (%d)\n",
                             sopin_info.reference, pin_info.reference);

	r = sc_card_ctl(card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int myeid_init_card(sc_profile_t *profile, 
			   sc_card_t *card)
{
	struct	sc_path path;
	sc_file_t *file;
	int r;

	SC_FUNC_CALLED(card->ctx, 1);

	sc_format_path("3F00", &path);
	r = sc_select_file(card, &path, NULL);
		
        SC_FUNC_RETURN(card->ctx, 1, r);	
}

/*
 * Create a DF
 */
static int myeid_create_dir(sc_profile_t *profile, sc_card_t *card, sc_file_t *df)
{
	int	r=0;
	struct sc_file *file;

	SC_FUNC_CALLED(card->ctx, 1);
	if (!profile || !card || !df)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_debug(card->ctx, "id (%x)\n",df->id);

	if(df->id == 0x5015)
	{
	  sc_debug(card->ctx, "only Select (%x)\n",df->id);
	   r = sc_select_file(card, &df->path, NULL);
	}

	SC_FUNC_RETURN(card->ctx, 1, r);
}
/*
 * Select the PIN reference
 */
static int myeid_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
		sc_pkcs15_pin_info_t *pin_info)
{
	sc_pkcs15_pin_info_t pin_info_prof;
	int type;

	SC_FUNC_CALLED(card->ctx, 1);
	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
	{
	  type = SC_PKCS15INIT_SO_PIN;
	  sc_debug(card->ctx, "PIN_FLAG_SO_PIN, ref (%d), tries_left (%d)\n",
                            pin_info->reference,pin_info->tries_left);	
	}
	else	
	{
	  type = SC_PKCS15INIT_USER_PIN;
	  sc_debug(card->ctx, "PIN_FLAG_PIN, ref (%d), tries_left (%d)\n",
                            pin_info->reference, pin_info->tries_left);

	}

	if (pin_info->reference <= 0 || pin_info->reference > MYEID_MAX_PINS)
		pin_info->reference = 1;
		
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

/*
 * Create a new PIN
 */
static int myeid_create_pin(sc_profile_t *profile, sc_card_t *card,
		sc_file_t *df, sc_pkcs15_object_t *pin_obj,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	return myeid_create_pin_internal(profile, card, 
		0, (sc_pkcs15_pin_info_t *) pin_obj->data,
		pin, pin_len, 
		puk, puk_len);
}

/*
 * Setup file struct & path: get correct template from the profile, construct full path
 * num = number of objects of this type already on the card
 */
static int myeid_new_file(sc_profile_t *profile, sc_card_t *card,
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
		sc_error(card->ctx, "Unsupported file type");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get template from profile  */
	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) 
	{
		sc_error(card->ctx, "Profile doesn't define %s", name);
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

static int myeid_encode_private_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key, 
		size_t *keysize, int key_ref)
{
	SC_FUNC_CALLED(card->ctx, 1);
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

static int myeid_encode_public_key(sc_profile_t *profile, sc_card_t *card, 
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key, 
		size_t *keysize, int key_ref)
{
	SC_FUNC_CALLED(card->ctx, 1);
	SC_FUNC_RETURN(card->ctx, 1, 0);
}

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
	struct sc_cardctl_myeid_data_obj data_obj;
	unsigned char raw_pubkey[256];
	int           r;
	unsigned int  mod_len;
	sc_file_t    *prkf = NULL;

	SC_FUNC_CALLED(card->ctx, 1);
	/* Parameter check */
	if ( (keybits < 1024) || (keybits > 2048) || (keybits & 0X7)) {
		sc_error(card->ctx, 
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

/*
 * Create a new PIN
 */
static int myeid_create_pin_internal(sc_profile_t *profile, sc_card_t *card,
		int ignore_ac, sc_pkcs15_pin_info_t *pin_info,
		const u8 *pin, size_t pin_len,
		const u8 *puk, size_t puk_len)
{
	u8  data[20];
	int so_pin_ref;
	int	r,type, puk_tries;
	struct sc_cardctl_myeid_data_obj data_obj;
	sc_file_t *pinfile = NULL;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "pin (%d), pin_len (%d), puk_len(%d) \n",
                            pin_info->reference, pin_len, puk_len);

	if (pin_info->reference >= MYEID_MAX_PINS)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (pin == NULL || puk == NULL || pin_len < 4 || puk_len < 4)
		return SC_ERROR_INVALID_PIN_LENGTH;

	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
	  type = SC_PKCS15INIT_SO_PIN;
	else
	  type = SC_PKCS15INIT_USER_PIN;

	sc_debug(card->ctx, "pin type (%s)\n",
                             (type == SC_PKCS15INIT_SO_PIN) ? "SO_PIN": "USER_PIN");

	memset(data, 0xFF, sizeof(data));
	/* Make command to add a pin-record */
	data_obj.P1 = 01;
	data_obj.P2 = pin_info->reference;	/* myeid pin number */
	
	memcpy(&data[0], (u8 *)pin, pin_len);   /* copy pin*/
	memcpy(&data[8], (u8 *)puk, puk_len);   /* copy puk */

        data[16] = 0x00;
	data[17] = 0x00;
	data[18] = 0x00;

	data_obj.Data    = data;
	data_obj.DataLen = 16;

	puk_tries = myeid_puk_retries(profile, pin_info);
	if(pin_info->tries_left > 0 && pin_info->tries_left < 15 &&
           puk_tries > 0 && puk_tries < 15)
	{
	    /* Optional PIN locking */
	    data[16] = (pin_info->tries_left & 0x0F);
	    data[17] = (puk_tries & 0x0F);
	    data_obj.DataLen = 19;
	}

	r = sc_card_ctl(card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);

	SC_FUNC_RETURN(card->ctx, 1, r);
}

static int myeid_puk_retries(sc_profile_t *profile, sc_pkcs15_pin_info_t *pin_info)
{
	sc_pkcs15_pin_info_t puk_info;

	sc_profile_get_pin_info(profile, 
		(pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) ? 
			SC_PKCS15INIT_SO_PUK : SC_PKCS15INIT_USER_PUK,
		&puk_info);
	
	if ((puk_info.tries_left < 0) || (puk_info.tries_left >= 15))
		return -1;
	return puk_info.tries_left;
}

/* For Myeid, all objects are files that can be deleted in any order */
static int myeid_delete_object(struct sc_profile *profile, 
		struct sc_card *card, unsigned int type, 
		const void *data, const sc_path_t *path)
{
	SC_FUNC_CALLED(card->ctx, 1);
	return sc_pkcs15init_delete_by_path(profile, card, path);
}

static struct sc_pkcs15init_operations sc_pkcs15init_myeid_operations = {
	myeid_erase_card,
	myeid_init_card,       		/* init_card */
	myeid_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	myeid_select_pin_reference,
	myeid_create_pin,
	NULL,				/* select_key_reference */
	NULL,				/* create_key */
	NULL,				/* store_key  */
	NULL,				/* generate_key */
	myeid_encode_private_key,
	myeid_encode_public_key,
	NULL,				/* finalize_card */
	NULL,
	NULL,				/* style api */
	myeid_new_key,
	myeid_new_file,
	myeid_generate_key,
	myeid_delete_object
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_myeid_ops(void)
{
	return &sc_pkcs15init_myeid_operations;
}
