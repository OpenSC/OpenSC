/*
 * SetOCS 4.4 specific operations for PKCS15 initialization
 *
 * Copyright (C) 2003, 2005 Zetes
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
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "keycache.h"
#include "profile.h"

#define SETCOS_MAX_PINS   7

static unsigned char SETCOS_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define SETCOS_DEFAULT_PUBKEY_LEN       sizeof(SETCOS_DEFAULT_PUBKEY)

static int setcos_generate_store_key( sc_profile_t *, sc_card_t *,
	unsigned int, unsigned int, sc_pkcs15_pubkey_t *, sc_pkcs15_prkey_t *,
	sc_pkcs15_prkey_info_t *);

static int setcos_create_pin_internal(sc_profile_t *, sc_card_t *,
	int, sc_pkcs15_pin_info_t *, const u8 *, size_t, const u8 *, size_t);

static int setcos_puk_retries(sc_profile_t *, int);

/*
 * Erase the card.
 */
static int setcos_erase_card(sc_profile_t *profile, sc_card_t *card)
{
	sc_pkcs15_pin_info_t pin_info;
	sc_path_t path;
	int r;

	/* Just delete the entire MF */

	/* The SO pin has pin reference 1 -- not that it matters much
	 * because pkcs15-init will ask to enter all pins, even if we
	 * did a --so-pin on the command line. */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info);
	sc_keycache_set_pin_name(NULL, pin_info.reference, SC_PKCS15INIT_SO_PIN);

	/* Select parent DF and verify PINs/key as necessary */
	r = sc_pkcs15init_authenticate(profile, card,
		profile->mf_info->file, SC_AC_OP_DELETE);
	if (r < 0)
		return r == SC_ERROR_FILE_NOT_FOUND ? 0 : r;

	/* Empty path -> we have to to delete the current DF (= the MF) */
	memset(&path, 0, sizeof(sc_path_t));
	r = sc_delete_file(card, &path) ;

	return r;
}

#if 0 /* New API, turned out to be more work wrt setting the
         life cycle state to SC_FILE_STATUS_ACTIVATED. */
/*
 * Create the MF and global pin file if they don't exist.
 */
static int
setcos_init_card(sc_profile_t *profile, sc_card_t *card)
{
	sc_file_t *mf = profile->mf_info->file;
	sc_file_t *pinfile;
	int pin_ref;
	int r;

	/* The SO pin in the keycache is only linked to the pkcs15 DF,
	 * we'll re-ink it to the MF. */
	pin_ref = sc_keycache_find_named_pin(&profile->df_info->file->path,
		SC_PKCS15INIT_SO_PIN);
	if (pin_ref >= 0)
		sc_keycache_set_pin_name(&profile->mf_info->file->path,
			pin_ref, SC_PKCS15INIT_SO_PIN);

	/* Create the MF if it doesn't exist yet */
	card->ctx->suppress_errors++;
	r = sc_select_file(card, &mf->path, NULL);
	card->ctx->suppress_errors--;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(card->ctx, "MF doesn't exist, creating now");

		/* Fix up the file's ACLs */
		r = sc_pkcs15init_fixup_file(profile, mf);
		if (r >= 0)
			r = sc_create_file(card, mf);
	}
	if (r < 0)
		return r;

	/* Create the global pin file if it doesn't exist yet */
	r = sc_profile_get_file(profile, "pinfile", &pinfile);
	if (r < 0)
		return r;
	card->ctx->suppress_errors++;
	r = sc_select_file(card, &pinfile->path, NULL);
	card->ctx->suppress_errors--;
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(card->ctx, "Global pin file doesn't exist, creating now");

		/* Fix up the file's ACLs */
		r = sc_pkcs15init_fixup_file(profile, pinfile);
		/* Set life cycle state to SC_FILE_STATUS_CREATION,
		 * which means that all ACs are ignored. */
		if (r >= 0)
			r = sc_create_file(card, pinfile);
	}
	sc_file_free(pinfile);

	/* Re-link the SO-PIN back to the original DF (= the pkcs15 DF) */
	sc_keycache_set_pin_name(&profile->df_info->file->path,
		pin_ref, SC_PKCS15INIT_SO_PIN);

	return r;
}

/*
 * Create a DF
 */
static int
setcos_create_dir(sc_profile_t *profile, sc_card_t *card, sc_file_t *df)
{
	return sc_pkcs15init_create_file(profile, card, df);
}
#endif

/*
 * Create the MF and global pin file if they don't exist.
 */
static int setcos_init_app(sc_profile_t *profile, sc_card_t *card,
	sc_pkcs15_pin_info_t *pin_info,
	const u8 *pin, size_t pin_len,
	const u8 *puk, size_t puk_len)
{
	sc_file_t *mf = profile->mf_info->file;
	sc_file_t *pinfile = NULL;
	int pin_ref;
	int r;

	/* The SO pin in the keycache is only linked to the pkcs15 DF,
	 * we'll re-link it to the MF. */
	pin_ref = sc_keycache_find_named_pin(&profile->df_info->file->path,
		SC_PKCS15INIT_SO_PIN);
	if (pin_ref >= 0)
		sc_keycache_set_pin_name(&profile->mf_info->file->path,
			pin_ref, SC_PKCS15INIT_SO_PIN);

	/* Create the MF if it doesn't exist yet */
	sc_ctx_suppress_errors_on(card->ctx);
	r = sc_select_file(card, &mf->path, NULL);
	sc_ctx_suppress_errors_off(card->ctx);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(card->ctx, "MF doesn't exist, creating now");
		/* Fix up the file's ACLs */
		if ((r = sc_pkcs15init_fixup_file(profile, mf)) >= 0) {
			/* Set life cycle state to SC_FILE_STATUS_CREATION,
			 * which means that all ACs are ignored. */
			mf->status = SC_FILE_STATUS_CREATION;
			r = sc_create_file(card, mf);
		}
	}
	if (r < 0)
		return r;

	/* Create the global pin file if it doesn't exist yet */
	if ((r = sc_profile_get_file(profile, "pinfile", &pinfile)) < 0)
		goto done;
	sc_ctx_suppress_errors_on(card->ctx);
	r = sc_select_file(card, &pinfile->path, NULL);
	sc_ctx_suppress_errors_off(card->ctx);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_debug(card->ctx, "Global pin file doesn't exist, creating now");
		/* Fix up the file's ACLs */
		if ((r = sc_pkcs15init_fixup_file(profile, pinfile)) >= 0) {
			/* Set life cycle state to SC_FILE_STATUS_CREATION */
			pinfile->status = SC_FILE_STATUS_CREATION;
			r = sc_create_file(card, pinfile);
		}
	}
	if (r < 0)
		goto done;

	/* Set the SO pin/puk values into the pin file */
	r = setcos_create_pin_internal(profile, card, 1, pin_info,
		pin, pin_len, puk, puk_len);
	if (r < 0)
		goto done;

	/* OK, now we can change the life cycle state to SC_FILE_STATUS_ACTIVATED
	 * so the normal ACs on the pinfile and MF apply. */
	if ((r = sc_select_file(card, &pinfile->path, NULL)) >= 0) /* pinfile */
		r = sc_card_ctl(card, SC_CARDCTL_SETCOS_ACTIVATE_FILE, NULL);
	if (r < 0)
		goto done;
	if ((r = sc_select_file(card, &mf->path, NULL)) >= 0)      /* MF */
		r = sc_card_ctl(card, SC_CARDCTL_SETCOS_ACTIVATE_FILE, NULL);
	if (r < 0)
		goto done;

    /* Before we relink th SO_PIN back to the pkcs15 DF, we have to fill in
     * its value for the MF in the keycache. Otherwise, we will be asked to
     * enter the value for the "pin with ref. 1" if we want to create a
     * DF or EF in the MF. */
    sc_pkcs15init_authenticate(profile, card, profile->mf_info->file, SC_AC_OP_CREATE);

	/* Re-link the SO-PIN back to the original DF (= the pkcs15 DF) */
	sc_keycache_set_pin_name(&profile->df_info->file->path,
		pin_ref, SC_PKCS15INIT_SO_PIN);

done:
	if (pinfile)
		free(pinfile);

	return r;
}

/*
 * Select the PIN reference
 */
static int
setcos_select_pin_reference(sc_profile_t *profile, sc_card_t *card,
	sc_pkcs15_pin_info_t *pin_info)
{
	sc_pkcs15_pin_info_t pin_info_prof;

	pin_info_prof.reference = 1; /* Default SO PIN ref. */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info_prof);

	/* For the SO pin, we take the first available pin reference = 1 */
	if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		pin_info->reference = pin_info_prof.reference;
	/* sc_pkcs15init_create_pin() starts checking if 0 is an acceptable
	 * pin reference, which isn't for the SetCOS cards. And since the
	 * value 1 has been assigned to the SO pin, we'll jump to 2. */
	else if (pin_info->reference == 0)
		pin_info->reference = pin_info_prof.reference + 1;

	return 0;
}

/*
 * Create a new PIN
 */
static int
setcos_create_pin(sc_profile_t *profile, sc_card_t *card,
	sc_file_t *df,
	sc_pkcs15_object_t *pin_obj,
	const u8 *pin, size_t pin_len,
	const u8 *puk, size_t puk_len)
{
	return setcos_create_pin_internal(profile, card, 0,
		(sc_pkcs15_pin_info_t *) pin_obj->data,
		pin, pin_len, puk, puk_len);
}

/*
 * Setup file struct & path: get correct template from the profile, construct full path
 */
static int
setcos_new_file(sc_profile_t *profile, sc_card_t *card,
	unsigned int type, 
	unsigned int num, /* number of objects of this type already on the card */
	sc_file_t **out)
{
	sc_file_t *file;
	sc_path_t *p;
	char name[64], *tag;
	int r;

	if (type == SC_PKCS15_TYPE_PRKEY_RSA)
		tag = "private-key";
	else if (type  == SC_PKCS15_TYPE_PUBKEY_RSA)
		tag = "public-key";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT)
		tag = "certificate";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_DATA_OBJECT)
		tag = "data";
	else {
		sc_error(card->ctx, "Unsupported file type");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get template from profile  */
	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
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
	while(r == 0) {
		file->id++;
		p->value[p->len - 2] = (u8) (file->id / 256);
		p->value[p->len - 1] = (u8) (file->id % 256);
		r = sc_select_file(card, p, NULL);
	}

	*out = file;
	return 0;
}

static int
setcos_encode_private_key(sc_profile_t *profile, sc_card_t *card,
	struct sc_pkcs15_prkey_rsa *rsa,
	u8 *key, size_t *keysize, int key_ref)
{
	return 0;
}

static int
setcos_encode_public_key(sc_profile_t *profile, sc_card_t *card,
	struct sc_pkcs15_prkey_rsa *rsa,
	u8 *key, size_t *keysize, int key_ref)
{
	return 0;
}

/*
 * Generate RSA key
 */
static int
setcos_old_generate_key(sc_profile_t *profile, sc_card_t *card,
	unsigned int idx, /* keyref: 0 for 1st key, ... */
	unsigned int keybits,
	sc_pkcs15_pubkey_t *pubkey,
	struct sc_pkcs15_prkey_info *info)
{
	return setcos_generate_store_key(profile, card, idx,
		keybits, pubkey,
		NULL, info);
}

/*
 * Store RSA key
 */
static int
setcos_new_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey *key, unsigned int idx,
		struct sc_pkcs15_prkey_info *info)
{
	return setcos_generate_store_key(profile, card, idx,
		key->u.rsa.modulus.len * 8, NULL,
		key, info);
}

/*
 * Common code for generating or storing a private key.
 * If pubkey == NULL and prkey != NULL, we have to store a private key
 * In the oposite case, we have to generate a private key
 */
static int
setcos_generate_store_key(sc_profile_t *profile, sc_card_t *card,
	unsigned int idx,  /* keynumber: 0 for 1st priv key, ...  */
	unsigned int keybits,
	sc_pkcs15_pubkey_t *pubkey,
	sc_pkcs15_prkey_t *prkey,
	sc_pkcs15_prkey_info_t *info)
{
	struct sc_cardctl_setcos_gen_store_key_info args;
	struct sc_cardctl_setcos_data_obj data_obj;
	unsigned char raw_pubkey[256];
	int           r;
	unsigned int  mod_len;
	sc_file_t    *prkf = NULL;

	/* Parameter check */
	if ( (keybits < 512) || (keybits > 1024) || (keybits & 0X7)) {
		sc_error(card->ctx, "Unsupported key size [%u]: 512-1024 bit + 8-multiple\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get the private key file */
	r = setcos_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx, &prkf);
	if (r < 0)
		goto done;

	/* Take enough room for a 1024 bit key */
	if (prkf->size < 512)
		prkf->size = 512;

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, card, prkf);
	if (r < 0)
		goto done;

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	if (prkey == NULL) {
		args.op_type = OP_TYPE_GENERATE;
		args.pubexp_len = SETCOS_DEFAULT_PUBKEY_LEN * 8;
		args.pubexp = SETCOS_DEFAULT_PUBKEY;
	}
	else {
		args.op_type = OP_TYPE_STORE;
		args.pubexp_len = prkey->u.rsa.exponent.len * 8;
		args.pubexp = prkey->u.rsa.exponent.data;
		args.primep_len = prkey->u.rsa.p.len * 8;
		args.primep = prkey->u.rsa.p.data;
		args.primeq_len = prkey->u.rsa.q.len * 8;
		args.primeq = prkey->u.rsa.q.data;
	}

	/* Authenticate */
	r = sc_pkcs15init_authenticate(profile, card, prkf, SC_AC_OP_UPDATE);
	if (r < 0) 
	 	goto done;

	/* Generate/store rsa key  */
	r = sc_card_ctl(card, SC_CARDCTL_SETCOS_GENERATE_STORE_KEY, &args);
	if (r < 0)
		goto done;

	/* Keypair generation -> collect public key info */
	if (pubkey != NULL) {
		pubkey->algorithm		= SC_ALGORITHM_RSA;
		pubkey->u.rsa.modulus.len	= (keybits + 7) / 8;
		pubkey->u.rsa.modulus.data	= (u8 *) malloc(pubkey->u.rsa.modulus.len);
		pubkey->u.rsa.exponent.len	= SETCOS_DEFAULT_PUBKEY_LEN;
		pubkey->u.rsa.exponent.data	= (u8 *) malloc(SETCOS_DEFAULT_PUBKEY_LEN);
		memcpy(pubkey->u.rsa.exponent.data, SETCOS_DEFAULT_PUBKEY, SETCOS_DEFAULT_PUBKEY_LEN);

		/* Get public key modulus */
		if ( (r = sc_select_file(card, &prkf->path, NULL)) < 0)
			goto done;

		data_obj.P1 = 01;
		data_obj.P2 = 01;
		data_obj.Data = raw_pubkey;
		data_obj.DataLen = sizeof(raw_pubkey);

		if ((r = sc_card_ctl(card, SC_CARDCTL_SETCOS_GETDATA, &data_obj)) < 0)
			goto done;

		mod_len = ((raw_pubkey[0] * 256) + raw_pubkey[1]);  /* modulus bit length */
		if (mod_len != keybits){
			sc_error(card->ctx, "key-size from card[%i] does not match[%i]\n", mod_len, keybits);
			r = SC_ERROR_PKCS15INIT;
			goto done;
		}
		memcpy (pubkey->u.rsa.modulus.data, &raw_pubkey[2], pubkey->u.rsa.modulus.len);
	}

	info->key_reference = 0;
	info->path = prkf->path;

done:
	if (prkf)
		sc_file_free(prkf);

	return r;
}

/*
 * Create a new PIN
 */
static int
setcos_create_pin_internal(sc_profile_t *profile, sc_card_t *card,
	int ignore_ac, sc_pkcs15_pin_info_t *pin_info,
	const u8 *pin, size_t pin_len,
	const u8 *puk, size_t puk_len)
{
	u8  data[32];
	int so_pin_ref;
	int	r;
	struct sc_cardctl_setcos_data_obj data_obj;
	sc_file_t *pinfile = NULL;

	if (pin_info->reference >= SETCOS_MAX_PINS)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (pin == NULL || puk == NULL || pin_len < 4 || puk_len < 4)
		return SC_ERROR_INVALID_PIN_LENGTH;

	/* Verify required access rights if needed (i.e. if the
	 * pin file isn't in the CREATE life cycle state). */
	if (!ignore_ac) {
		/* Re-ink the SO pin to the MF because there is the pin file */
		so_pin_ref = sc_keycache_find_named_pin(&profile->df_info->file->path,
			SC_PKCS15INIT_SO_PIN);
		if (so_pin_ref >= 0)
			sc_keycache_set_pin_name(&profile->mf_info->file->path,
				so_pin_ref, SC_PKCS15INIT_SO_PIN);

		r = sc_profile_get_file(profile, "pinfile", &pinfile);
		if (r >= 0)
			r = sc_pkcs15init_authenticate(profile, card, pinfile, SC_AC_OP_UPDATE);
		sc_file_free(pinfile);
		if (r < 0)
			return r;
	}

	/* Make command to add a pin-record */

	data_obj.P1 = 01;
	data_obj.P2 = 01;

	/* setcos pin number */
	data[0] = pin_info->reference;

	memset(&data[1], pin_info->pad_char, 16); /* padding */		
	memcpy(&data[1], (u8 *)pin, pin_len);     /* copy pin*/
	memcpy(&data[9], (u8 *)puk, puk_len);     /* copy puk */

	data[17] = pin_info->tries_left & 0x0F;
	data[18] = pin_info->tries_left & 0x0F;
	/* 0xF0: unlimited unblock tries */
	data[19] = 0xF0 | setcos_puk_retries(profile, pin_info->reference);

	/* Allow an unlimited number of signatures after a pin verification.
	 * If set to 1 or so, we would have a UserConsent PIN. */
	data[20] = 0x00;

	if (pin_info->type == 0)
		data[21] = 0x01; /* BCD */
	else
		data[21] = 0x00; /* ASCII */
	if ((pin_info->flags & 0x010) == 0) /* test for initial pin */
		data[21] |= 0x80;

	data[22]        = 0x00;			/* not used */
	data[23]        = 0x00;			/* not used */

	data_obj.Data    = data;
	data_obj.DataLen = 24;

	r = sc_card_ctl(card, SC_CARDCTL_SETCOS_PUTDATA, &data_obj);

	return r;
}

static int setcos_puk_retries(sc_profile_t *profile, int pin_ref)
{
	sc_pkcs15_pin_info_t pin_info;

	pin_info.reference = 1; /* Default SO PIN ref. */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &pin_info);

	/* If pin_ref is the SO PIN, get the SO PUK info, otherwise the User PUK info */
	sc_profile_get_pin_info(profile,
		pin_ref == pin_info.reference ? SC_PKCS15INIT_SO_PUK : SC_PKCS15INIT_USER_PUK,
		&pin_info);
	
	if ((pin_info.tries_left < 0) || (pin_info.tries_left > 15))
		return 3; /* Little extra safety */
	return pin_info.tries_left;
}

static int setcos_delete_object(struct sc_profile *profile, struct sc_card *card,
	unsigned int type, const void *data, const sc_path_t *path)
{
	/* For Setcos, all objects are files that can be deleted in any order */
	return sc_pkcs15init_delete_by_path(profile, card, path);
}

static struct sc_pkcs15init_operations sc_pkcs15init_setcos_operations = {
	setcos_erase_card,
	NULL,				/* init_card     */
	NULL,				/* create_dir    */
	NULL,				/* create_domain */
	setcos_select_pin_reference,
	setcos_create_pin,
	NULL,				/* select_key_reference */
	NULL,				/* create_key */
	NULL,				/* store_key  */
	NULL,				/* generate_key */
	setcos_encode_private_key,
	setcos_encode_public_key,
	NULL,				/* finalize_card */
	setcos_init_app,		/* old */
	NULL,				/* old style api */
	setcos_new_key,
	setcos_new_file,
	setcos_old_generate_key,
	setcos_delete_object
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_setcos_ops(void)
{
	return &sc_pkcs15init_setcos_operations;
}
