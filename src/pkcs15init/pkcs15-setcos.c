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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define SETCOS_MAX_PINS   7

static unsigned char SETCOS_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define SETCOS_DEFAULT_PUBKEY_LEN       sizeof(SETCOS_DEFAULT_PUBKEY)

static int setcos_create_pin_internal(sc_profile_t *, sc_pkcs15_card_t *,
	int, sc_pkcs15_auth_info_t *, const u8 *, size_t, const u8 *, size_t);


static int
setcos_puk_retries(sc_profile_t *profile, int pin_ref)
{
	sc_pkcs15_auth_info_t auth_info;

	auth_info.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	auth_info.attrs.pin.reference = 1; /* Default SO PIN ref. */
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &auth_info);

	/* If pin_ref is the SO PIN, get the SO PUK info, otherwise the User PUK info */
	sc_profile_get_pin_info(profile,
		pin_ref == auth_info.attrs.pin.reference ? SC_PKCS15INIT_SO_PUK : SC_PKCS15INIT_USER_PUK,
		&auth_info);

	if ((auth_info.tries_left < 0) || (auth_info.tries_left > 15))
		return 3; /* Little extra safety */
	return auth_info.tries_left;
}


/*
 * Erase the card.
 */
static int setcos_erase_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	sc_path_t path;
	int r;

	/* Just delete the entire MF */

	/* Select parent DF and verify PINs/key as necessary */
	r = sc_pkcs15init_authenticate(profile, p15card, profile->mf_info->file, SC_AC_OP_DELETE);
	if (r < 0)
		return r == SC_ERROR_FILE_NOT_FOUND ? 0 : r;

	/* Empty path -> we have to to delete the current DF (= the MF) */
	memset(&path, 0, sizeof(sc_path_t));
	r = sc_delete_file(p15card->card, &path) ;
	if (r)
		return r;

	sc_free_apps(p15card->card);
	return 0;
}


/*
 * Create the MF and global pin file if they don't exist.
 */
static int
setcos_init_card(sc_profile_t *profile, sc_pkcs15_card_t *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_file_t *mf = profile->mf_info->file;
	sc_file_t *pinfile;
	int r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* Create the MF if it doesn't exist yet */
	r = sc_select_file(p15card->card, &mf->path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_log(ctx,  "MF doesn't exist, creating now");

		/* Fix up the file's ACLs */
		r = sc_pkcs15init_fixup_file(profile, p15card, mf);
		LOG_TEST_RET(ctx, r, "MF fixup failed");

		mf->status = SC_FILE_STATUS_CREATION;
		r = sc_create_file(p15card->card, mf);
		LOG_TEST_RET(ctx, r, "MF creation failed");
	}
	LOG_TEST_RET(ctx, r, "Cannot select MF");

	/* Create the global pin file if it doesn't exist yet */
	r = sc_profile_get_file(profile, "pinfile", &pinfile);
	LOG_TEST_RET(ctx, r, "Cannot get 'pinfile' from profile");

	r = sc_select_file(p15card->card, &pinfile->path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND) {
		sc_log(ctx,  "Global pin file doesn't exist, creating now");

		/* Fix up the file's ACLs */
		r = sc_pkcs15init_fixup_file(profile, p15card, pinfile);
		if (r < 0)
			sc_file_free(pinfile);
		LOG_TEST_RET(ctx, r, "Pinfile fixup failed");

		/* Set life cycle state to SC_FILE_STATUS_CREATION,
		 * which means that all ACs are ignored. */
		pinfile->status = SC_FILE_STATUS_CREATION;
		r = sc_create_file(p15card->card, pinfile);
		if (r < 0)
			sc_file_free(pinfile);
		LOG_TEST_RET(ctx, r, "Pinfile creation failed");
	}
	sc_file_free(pinfile);
	LOG_TEST_RET(ctx, r, "Select pinfile failed");

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Create a DF
 */
static int
setcos_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	int r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

        r = sc_pkcs15init_fixup_file(profile, p15card, df);
	LOG_TEST_RET(ctx, r, "SetCOS file ACL fixup failed");

	r = sc_create_file(p15card->card, df);
	LOG_TEST_RET(ctx, r, "SetCOS create file failed");

	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Select the PIN reference
 */
static int
setcos_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_pkcs15_auth_info_t *auth_info)
{
	sc_pkcs15_auth_info_t auth_info_prof;

	auth_info_prof.attrs.pin.reference = 1; /* Default SO PIN ref. */
	auth_info_prof.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &auth_info_prof);

	/* For the SO pin, we take the first available pin reference = 1 */
	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		auth_info->attrs.pin.reference = auth_info_prof.attrs.pin.reference;
	/* sc_pkcs15init_create_pin() starts checking if -1 is an acceptable
	 * pin reference, which isn't for the SetCOS cards. And since the
	 * value 1 has been assigned to the SO pin, we'll jump to 2. */
	else if (auth_info->attrs.pin.reference <= 0)
		auth_info->attrs.pin.reference = auth_info_prof.attrs.pin.reference + 1;

	return 0;
}

/*
 * Create a new PIN
 */
static int
setcos_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	sc_file_t *df,
	sc_pkcs15_object_t *pin_obj,
	const u8 *pin, size_t pin_len,
	const u8 *puk, size_t puk_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	sc_file_t *pinfile = NULL;
	int r, ignore_ac = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

        /* Create the global pin file if it doesn't exist yet */
	r = sc_profile_get_file(profile, "pinfile", &pinfile);
	LOG_TEST_RET(ctx, r, "No 'pinfile' template in profile");

	r = sc_select_file(p15card->card, &pinfile->path, &pinfile);
	LOG_TEST_RET(ctx, r, "Cannot select 'pinfile'");

	sc_log(ctx,  "pinfile->status:%X", pinfile->status);
	sc_log(ctx,  "create PIN with reference:%X, flags:%X, path:%s",
			auth_info->attrs.pin.reference, auth_info->attrs.pin.flags, sc_print_path(&auth_info->path));

	if (pinfile->status == SC_FILE_STATUS_CREATION)
		ignore_ac = 1;

	r = setcos_create_pin_internal(profile, p15card, ignore_ac, auth_info,
			pin, pin_len, puk, puk_len);

	/* If pinfile is in 'Creation' state and SOPIN has been created,
	 * change status of MF and 'pinfile' to 'Operational:Activated'
	 */
	if (ignore_ac && (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))   {
		sc_file_t *mf = profile->mf_info->file;

		r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_ACTIVATE_FILE, NULL);
		LOG_TEST_RET(ctx, r, "Cannot set 'pinfile' into the activated state");

		r = sc_select_file(p15card->card, &mf->path, NULL);
		LOG_TEST_RET(ctx, r, "Cannot select MF");

		r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_ACTIVATE_FILE, NULL);
		LOG_TEST_RET(ctx, r, "Cannot set MF into the activated state");
	}

	sc_file_free(pinfile);

	LOG_FUNC_RETURN(ctx, r);
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
	char name[64];
	const char *tag;
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
		sc_log(card->ctx,  "Unsupported file type");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get template from profile  */
	snprintf(name, sizeof(name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		sc_log(card->ctx,  "Profile doesn't define %s", name);
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


static int
setcos_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	int keybits = key_info->modulus_length, r;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Create key failed: RSA only supported");

	/* Parameter check */
	if ( (keybits < 512) || (keybits > 1024) || (keybits & 0x7))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key length");

        sc_log(ctx,  "create private key ID:%s\n",  sc_pkcs15_print_id(&key_info->id));

	/* Get the private key file */
	r = setcos_new_file(profile, p15card->card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
	LOG_TEST_RET(ctx, r, "Cannot get new private key file");

	/* Take enough room for a 1024 bit key */
	if (file->size < 512)
		file->size = 512;

	/* Replace the path of instantiated key template by the path from the object data. */
        memcpy(&file->path, &key_info->path, sizeof(file->path));
        file->id = file->path.value[file->path.len - 2] * 0x100
		+ file->path.value[file->path.len - 1];

	key_info->key_reference = file->path.value[file->path.len - 1] & 0xFF;

        sc_log(ctx,  "Path of private key file to create %s\n", sc_print_path(&file->path));

        r = sc_select_file(p15card->card, &file->path, NULL);
        if (!r)   {
		r = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
		LOG_TEST_RET(ctx, r, "Failed to delete private key file");
	}
        else if (r != SC_ERROR_FILE_NOT_FOUND)    {
		LOG_TEST_RET(ctx, r, "Select private key file error");
	}

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	LOG_TEST_RET(ctx, r, "Cannot create private key file");

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
}


/*
 * Store a private key
 */
static int
setcos_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *prkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_cardctl_setcos_gen_store_key_info args;
	struct sc_file *file = NULL;
	int r, keybits = key_info->modulus_length;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Store key failed: RSA only supported");

	/* Parameter check */
	if ( (keybits < 512) || (keybits > 1024) || (keybits & 0x7))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key length");

	sc_log(ctx,  "store key with ID:%s and path:%s\n", sc_pkcs15_print_id(&key_info->id),
		       	sc_print_path(&key_info->path));

	r = sc_select_file(p15card->card, &key_info->path, &file);
	LOG_TEST_RET(ctx, r, "Cannot store key: select key file failed");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, r, "No authorisation to store private key");

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	args.op_type = OP_TYPE_STORE;
	args.pubexp_len = prkey->u.rsa.exponent.len * 8;
	args.pubexp = prkey->u.rsa.exponent.data;
	args.primep_len = prkey->u.rsa.p.len * 8;
	args.primep = prkey->u.rsa.p.data;
	args.primeq_len = prkey->u.rsa.q.len * 8;
	args.primeq = prkey->u.rsa.q.data;

	/* Generate/store rsa key  */
	r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_GENERATE_STORE_KEY, &args);
	LOG_TEST_RET(ctx, r, "Card control 'GENERATE_STORE_KEY' failed");

	sc_file_free(file);

	LOG_FUNC_RETURN(ctx, r);
}


static int
setcos_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_cardctl_setcos_gen_store_key_info args;
	struct sc_cardctl_setcos_data_obj data_obj;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	int r;
	size_t keybits = key_info->modulus_length;
	unsigned char raw_pubkey[256];
	struct sc_file *file = NULL;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Generate key failed: RSA only supported");

	/* Parameter check */
	if ( (keybits < 512) || (keybits > 1024) || (keybits & 0x7))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key length");

	r = sc_select_file(p15card->card, &key_info->path, &file);
	LOG_TEST_RET(ctx, r, "Cannot store key: select key file failed");

	/* Authenticate */
	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, r, "No authorisation to store private key");

	/* Fill in data structure */
	memset(&args, 0, sizeof(args));
	args.mod_len = keybits;
	args.op_type = OP_TYPE_GENERATE;
	args.pubexp_len = SETCOS_DEFAULT_PUBKEY_LEN * 8;
	args.pubexp = SETCOS_DEFAULT_PUBKEY;

	/* Generate/store rsa key  */
	r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_GENERATE_STORE_KEY, &args);
	LOG_TEST_RET(ctx, r, "Card control 'GENERATE_STORE_KEY' failed");

	/* Key pair generation -> collect public key info */
	if (pubkey != NULL) {
		pubkey->algorithm		= SC_ALGORITHM_RSA;
		pubkey->u.rsa.modulus.len	= (keybits + 7) / 8;
		pubkey->u.rsa.modulus.data	= malloc(pubkey->u.rsa.modulus.len);
		pubkey->u.rsa.exponent.len	= SETCOS_DEFAULT_PUBKEY_LEN;
		pubkey->u.rsa.exponent.data	= malloc(SETCOS_DEFAULT_PUBKEY_LEN);
		memcpy(pubkey->u.rsa.exponent.data, SETCOS_DEFAULT_PUBKEY, SETCOS_DEFAULT_PUBKEY_LEN);

		/* Get public key modulus */
		r = sc_select_file(p15card->card, &file->path, NULL);
		LOG_TEST_RET(ctx, r, "Cannot get key modulus: select key file failed");

		data_obj.P1 = 0x01;
		data_obj.P2 = 0x01;
		data_obj.Data = raw_pubkey;
		data_obj.DataLen = sizeof(raw_pubkey);

		r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_GETDATA, &data_obj);
		LOG_TEST_RET(ctx, r, "Cannot get key modulus: 'SETCOS_GETDATA' failed");

		keybits = ((raw_pubkey[0] * 256) + raw_pubkey[1]);  /* modulus bit length */
		if (keybits != key_info->modulus_length)  {
			sc_log(ctx, 
				 "key-size from card[%"SC_FORMAT_LEN_SIZE_T"u] does not match[%"SC_FORMAT_LEN_SIZE_T"u]\n",
				 keybits, key_info->modulus_length);
			LOG_TEST_RET(ctx, SC_ERROR_PKCS15INIT, "Failed to generate key");
		}
		memcpy (pubkey->u.rsa.modulus.data, &raw_pubkey[2], pubkey->u.rsa.modulus.len);
	}

	sc_file_free(file);
	return r;
}


/*
 * Create a new PIN
 */
static int
setcos_create_pin_internal(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
	int ignore_ac, sc_pkcs15_auth_info_t *auth_info,
	const u8 *pin, size_t pin_len,
	const u8 *puk, size_t puk_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	u8  data[32];
	int	r;
	struct sc_cardctl_setcos_data_obj data_obj;
	sc_file_t *pinfile = NULL;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.reference >= SETCOS_MAX_PINS)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (pin == NULL || puk == NULL || pin_len < 4 || puk_len < 4)
		return SC_ERROR_INVALID_PIN_LENGTH;

	/* Verify required access rights if needed (i.e. if the
	 * pin file isn't in the CREATE life cycle state). */
	if (!ignore_ac) {
		r = sc_profile_get_file(profile, "pinfile", &pinfile);
		if (r >= 0)
			r = sc_pkcs15init_authenticate(profile, p15card, pinfile, SC_AC_OP_UPDATE);
		sc_file_free(pinfile);
		if (r < 0)
			return r;
	}

	/* Make command to add a pin-record */

	data_obj.P1 = 01;
	data_obj.P2 = 01;

	/* setcos pin number */
	data[0] = auth_info->attrs.pin.reference;

	memset(&data[1], auth_info->attrs.pin.pad_char, 16); /* padding */
	memcpy(&data[1], (u8 *)pin, pin_len);     /* copy pin*/
	memcpy(&data[9], (u8 *)puk, puk_len);     /* copy puk */

	data[17] = auth_info->tries_left & 0x0F;
	data[18] = auth_info->tries_left & 0x0F;
	/* 0xF0: unlimited unblock tries */
	data[19] = 0xF0 | setcos_puk_retries(profile, auth_info->attrs.pin.reference);

	/* Allow an unlimited number of signatures after a pin verification.
	 * If set to 1 or so, we would have a UserConsent PIN. */
	data[20] = 0x00;

	if (auth_info->attrs.pin.type == 0)
		data[21] = 0x01; /* BCD */
	else
		data[21] = 0x00; /* ASCII */
	if ((auth_info->attrs.pin.flags & 0x010) == 0) /* test for initial pin */
		data[21] |= 0x80;

	data[22]        = 0x00;			/* not used */
	data[23]        = 0x00;			/* not used */

	data_obj.Data    = data;
	data_obj.DataLen = 24;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_SETCOS_PUTDATA, &data_obj);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, r);
}


static struct sc_pkcs15init_operations sc_pkcs15init_setcos_operations = {
	setcos_erase_card,		/* erase_card */
	setcos_init_card,		/* init_card     */
	setcos_create_dir,		/* create_dir    */
	NULL,				/* create_domain */
	setcos_select_pin_reference,	/* select_pin_reference */
	setcos_create_pin,		/* create_pin */
	NULL, 				/* select_key_reference */
	setcos_create_key,		/* create_key */
	setcos_store_key,		/* store_key  */
	setcos_generate_key,		/* generate_key */
	setcos_encode_private_key, 	/* encode_private_key  */
	setcos_encode_public_key, 	/* encode_public_key */
	NULL,				/* finalize_card */
	NULL, 				/* delete_object */
	NULL,				/* emu_update_dir */
	NULL, 				/* emu_update_any_df */
	NULL, 				/* emu_update_tokeninfo */
	NULL, 				/* emu_write_info */
	NULL, 				/* emu_store_data */
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_setcos_ops(void)
{
	return &sc_pkcs15init_setcos_operations;
}
