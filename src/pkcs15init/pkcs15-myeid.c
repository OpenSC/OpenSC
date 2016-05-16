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
#include "libopensc/asn1.h"

#undef KEEP_AC_NONE_FOR_INIT_APPLET

#define MYEID_MAX_PINS   14
#define MYEID_MAX_RSA_KEY_LEN 2048

unsigned char MYEID_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define MYEID_DEFAULT_PUBKEY_LEN       sizeof(MYEID_DEFAULT_PUBKEY)

/* For Myeid, all objects are files that can be deleted in any order */
static int
myeid_delete_object(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path) {
	LOG_FUNC_CALLED(p15card->card->ctx);
	return sc_pkcs15init_delete_by_path(profile, p15card, path);
}

/*
 * Get 'Initialize Applet' data
 * using the ACLs defined in card profile.
 */
static int
myeid_get_init_applet_data(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned char *data, size_t data_len) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *tmp_file = NULL;
	const struct sc_acl_entry *entry = NULL;
	int r;

	LOG_FUNC_CALLED(ctx);

	if (data_len < 8)
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Cannot get init applet data");

	*(data + 0) = 0xFF;
	*(data + 1) = 0xFF;

	/* MF acls */
	sc_file_dup(&tmp_file, profile->mf_info->file);
	if (tmp_file == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate MF file");

	r = sc_pkcs15init_fixup_file(profile, p15card, tmp_file);
	if (r < 0)
		sc_file_free(tmp_file);
	LOG_TEST_RET(ctx, r, "MF fixup failed");

	/* AC 'Create DF' and 'Create EF' */
	*(data + 2) = 0x00; /* 'NONE' */
	entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_CREATE);
	if (entry->method == SC_AC_CHV)
		*(data + 2) = entry->key_ref | (entry->key_ref << 4); /* 'CHVx'. */
	else if (entry->method == SC_AC_NEVER)
		*(data + 2) = 0xFF; /* 'NEVER'. */

	/* AC 'INITIALISE APPLET'. */
	*(data + 3) = 0x0F; /* 'NONE' */
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
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate Application DF file");
	r = sc_pkcs15init_fixup_file(profile, p15card, tmp_file);
	if (r < 0)
		sc_file_free(tmp_file);
	LOG_TEST_RET(ctx, r, "Application DF fixup failed");

	/* AC 'Create DF' and 'Create EF' */
	*(data + 5) = 0x00; /* 'NONE' */
	entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_CREATE);
	if (entry->method == SC_AC_CHV)
		*(data + 5) = entry->key_ref | (entry->key_ref << 4); /* 'CHVx' */
	else if (entry->method == SC_AC_NEVER)
		*(data + 5) = 0xFF; /* 'NEVER'. */

	/* AC 'Self delete' */
	*(data + 6) = 0x0F; /* 'NONE' */
	entry = sc_file_get_acl_entry(tmp_file, SC_AC_OP_DELETE);
	if (entry->method == SC_AC_CHV)
		*(data + 6) = (entry->key_ref << 4) | 0xF; /* 'CHVx' */
	else if (entry->method == SC_AC_NEVER)
		*(data + 6) = 0xFF; /* 'NEVER'. */
	*(data + 7) = 0xFF;

	sc_file_free(tmp_file);
	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

/*
 * Erase the card.
 */
static int
myeid_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_cardctl_myeid_data_obj data_obj;
	struct sc_file *mf = NULL;
	unsigned char data[8];
	int r;

	LOG_FUNC_CALLED(ctx);

	r = myeid_get_init_applet_data(profile, p15card, data, sizeof (data));
	LOG_TEST_RET(ctx, r, "Get init applet date error");

	/* Select parent DF and verify PINs/key as necessary */
	r = sc_select_file(p15card->card, sc_get_mf_path(), &mf);
	LOG_TEST_RET(ctx, r, "Cannot select MF");

	/* ACLs are not actives if file is not in the operational state */
	if (mf->status == SC_FILE_STATUS_ACTIVATED)
		r = sc_pkcs15init_authenticate(profile, p15card, mf, SC_AC_OP_DELETE);
	LOG_TEST_RET(ctx, r, "'DELETE' authentication failed on MF");

	data_obj.P1 = 0x01;
	data_obj.P2 = 0xE0;
	data_obj.Data = data;
	data_obj.DataLen = sizeof (data);

	r = sc_card_ctl(p15card->card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);

	LOG_FUNC_RETURN(p15card->card->ctx, r);
}



static int
myeid_init_card(sc_profile_t *profile,
		sc_pkcs15_card_t *p15card) {
	struct sc_path path;
	struct sc_file *file = NULL;
        u8 rbuf[256];
	int r;

	LOG_FUNC_CALLED(p15card->card->ctx);

	p15card->tokeninfo->flags = SC_PKCS15_TOKEN_PRN_GENERATION | SC_PKCS15_TOKEN_EID_COMPLIANT;

        r = sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &rbuf);
	LOG_TEST_RET(p15card->card->ctx, r,  "Get applet info failed");

        sc_format_path("3F00", &path);
	r = sc_select_file(p15card->card, &path, &file);

	if (file)
		sc_file_free(file);

	LOG_FUNC_RETURN(p15card->card->ctx, r);
}

/*
 * Create a DF
 */
static int
myeid_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df) {
	struct sc_context *ctx = NULL;
	struct sc_file *file = NULL;
	int r = 0, ii;
	static const char *create_dfs[] = {
		"PKCS15-PrKDF",
		"PKCS15-PuKDF",
		"PKCS15-CDF",
		"PKCS15-CDF-TRUSTED",
		"PKCS15-DODF",
		NULL
	};

	static const int create_dfs_val[] = {
		SC_PKCS15_PRKDF,
		SC_PKCS15_PUKDF,
		SC_PKCS15_CDF,
		SC_PKCS15_CDF_TRUSTED,
		SC_PKCS15_DODF
	};

	if (!profile || !p15card || !p15card->card || !df)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "id (%x)", df->id);

	if (df->id == 0x5015) {
		sc_log(ctx, "Select (%x)", df->id);
		r = sc_select_file(p15card->card, &df->path, NULL);

		for (ii = 0; create_dfs[ii]; ii++) {
			sc_log(ctx, "Create '%s'", create_dfs[ii]);

			r = sc_profile_get_file(profile, create_dfs[ii], &file);
			if (file)
				sc_file_free(file);
			if (r) {
				sc_log(ctx, "Inconsistent profile: cannot find %s", create_dfs[ii]);
				LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
			}

			r = sc_pkcs15init_add_object(p15card, profile, create_dfs_val[ii], NULL);

			if (r != SC_ERROR_FILE_ALREADY_EXISTS)
				LOG_TEST_RET(ctx, r, "Failed to create MyEID xDF file");
		}
	}

	LOG_FUNC_RETURN(p15card->card->ctx, r);
}

/*
 * Select the PIN reference
 */
static int
myeid_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_auth_info_t *auth_info) {
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		sc_log(p15card->card->ctx,
				"PIN_FLAG_SO_PIN, ref (%d), tries_left (%d)",
				auth_info->attrs.pin.reference, auth_info->tries_left);
	} else {
		sc_log(p15card->card->ctx,
				"PIN_FLAG_PIN, ref (%d), tries_left (%d)",
				auth_info->attrs.pin.reference, auth_info->tries_left);

	}

	if (auth_info->attrs.pin.reference <= 0 || auth_info->attrs.pin.reference > MYEID_MAX_PINS)
		auth_info->attrs.pin.reference = 1;

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}

/*
 * Create a new PIN
 */
static int
myeid_create_pin(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df, struct sc_pkcs15_object *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len) {
	struct sc_context *ctx = p15card->card->ctx;
	unsigned char data[20];
	struct sc_cardctl_myeid_data_obj data_obj;
	struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	struct sc_pkcs15_auth_info puk_ainfo;
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "PIN('%s',ref:%i,flags:0x%X,pin_len:%d,puk_len:%d)\n",
			pin_obj->label, auth_info->attrs.pin.reference, auth_info->attrs.pin.flags, pin_len, puk_len);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;
	if (auth_info->attrs.pin.reference >= MYEID_MAX_PINS)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (pin == NULL || puk == NULL || pin_len < 4 || puk_len < 4)
		return SC_ERROR_INVALID_PIN_LENGTH;

	sc_profile_get_pin_info(profile, (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			? SC_PKCS15INIT_SO_PUK : SC_PKCS15INIT_USER_PUK,
			&puk_ainfo);

	memset(data, 0, sizeof (data));
	/* Make command to add a pin-record */
	data_obj.P1 = 0x01;
	data_obj.P2 = auth_info->attrs.pin.reference; /* myeid pin number */

	memset(data, auth_info->attrs.pin.pad_char, 8);
	memcpy(&data[0], (u8 *) pin, pin_len); /* copy pin */

	memset(&data[8], puk_ainfo.attrs.pin.pad_char, 8);
	memcpy(&data[8], (u8 *) puk, puk_len); /* copy puk */

	if (auth_info->tries_left > 0 && auth_info->tries_left < 15)
		data[16] = auth_info->tries_left;
	else
		data[16] = 5; /* default value */

	if (puk_ainfo.tries_left > 0 && puk_ainfo.tries_left < 15)
		data[17] = puk_ainfo.tries_left;
	else
		data[17] = 5; /* default value */

	data[18] = 0x00;

	data_obj.Data = data;
	data_obj.DataLen = 19;

	r = sc_card_ctl(p15card->card, SC_CARDCTL_MYEID_PUTDATA, &data_obj);
	LOG_TEST_RET(ctx, r, "Initialize PIN failed");

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Setup file struct & path: get correct template from the profile, construct full path
 * num = number of objects of this type already on the card
 */
static int
myeid_new_file(sc_profile_t *profile, sc_card_t *card,
		unsigned int type, unsigned int num,
		sc_file_t **out) {
	sc_file_t *file;
	sc_path_t *p;
	char name[64];
	const char *tag;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	if (type == SC_PKCS15_TYPE_PRKEY_RSA || type == SC_PKCS15_TYPE_PRKEY_EC)
		tag = "private-key";
	else if (type == SC_PKCS15_TYPE_PUBKEY_RSA || type == SC_PKCS15_TYPE_PUBKEY_EC)
		tag = "public-key";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT)
		tag = "certificate";
	else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_DATA_OBJECT)
		tag = "data";
	else {
		sc_log(card->ctx, "Unsupported file type");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Get template from profile  */
	snprintf(name, sizeof (name), "template-%s", tag);
	if (sc_profile_get_file(profile, name, &file) < 0) {
		sc_log(card->ctx, "Profile doesn't define %s", name);
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
	while (r == 0) {
		file->id++;
		p->value[p->len - 2] = (u8) (file->id / 256);
		p->value[p->len - 1] = (u8) (file->id % 256);
		r = sc_select_file(card, p, NULL);
	}

	*out = file;
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int
myeid_encode_private_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key,
		size_t *keysize, int key_ref) {
	LOG_FUNC_CALLED(card->ctx);
	LOG_FUNC_RETURN(card->ctx, 0);
}

static int
myeid_encode_public_key(sc_profile_t *profile, sc_card_t *card,
		struct sc_pkcs15_prkey_rsa *rsa, u8 *key,
		size_t *keysize, int key_ref) {
	LOG_FUNC_CALLED(card->ctx);
	LOG_FUNC_RETURN(card->ctx, 0);
}


/*
 * Store a private key
 */
static int
myeid_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_file *file = NULL;
	int keybits = key_info->modulus_length, r;

	LOG_FUNC_CALLED(card->ctx);

	/* Check that the card supports the requested modulus length */
	switch (object->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			if (sc_card_find_rsa_alg(p15card->card, keybits) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS,
					"Unsupported RSA key size");
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			/* 
			   Here the information about curve is not available, that's why algorithm is checked
			   without curve OID. 	  			   
                         */
                    
			if (key_info->field_length != 0)
				keybits = key_info->field_length;
			else 
				key_info->field_length = keybits;
			
			if (sc_card_find_ec_alg(p15card->card, keybits, NULL) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported EC key size");
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS,
					"Unsupported key type");
			break;
	}

	sc_log(ctx, "create MyEID private key ID:%s", sc_pkcs15_print_id(&key_info->id));

	/* Get the private key file */
	r = myeid_new_file(profile, card, object->type, key_info->key_reference, &file);
	LOG_TEST_RET(ctx, r, "Cannot get new MyEID private key file");

	if (!file || !file->path.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot determine private key file");

	sc_log(ctx, "Key file size %d", keybits);
	file->size = keybits;

	if (object->type == SC_PKCS15_TYPE_PRKEY_RSA)
		file->ef_structure = SC_CARDCTL_MYEID_KEY_RSA;
	else if (object->type == SC_PKCS15_TYPE_PRKEY_EC)
		file->ef_structure = SC_CARDCTL_MYEID_KEY_EC;

	memcpy(&key_info->path.value, &file->path.value, file->path.len);
	key_info->key_reference = file->path.value[file->path.len - 1] & 0xFF;

	sc_log(ctx, "Path of MyEID private key file to create %s",
			sc_print_path(&file->path));

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	sc_file_free(file);
	LOG_TEST_RET(ctx, r, "Cannot create MyEID private key file");

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Store a private key
 */
static int
myeid_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *prkey) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_cardctl_myeid_gen_store_key_info args;
	struct sc_file *file = NULL;
	int r, keybits = key_info->modulus_length;

	LOG_FUNC_CALLED(ctx);

	switch (object->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			if (sc_card_find_rsa_alg(p15card->card, keybits) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported RSA key size");
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			if (!sc_valid_oid(&prkey->u.ec.params.id))
                                if (sc_pkcs15_fix_ec_parameters(ctx, &prkey->u.ec.params))
                                        LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_VALID);
						
			if(key_info->field_length != 0)
				keybits = key_info->field_length;
			else
				key_info->field_length = keybits;
			break;
			
			if (sc_card_find_ec_alg(p15card->card, keybits, &prkey->u.ec.params.id) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported algorithm or key size");			
		default:
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Store key failed: Unsupported key type");
			break;
	}

	sc_log(ctx, "store MyEID key with ID:%s and path:%s",
			sc_pkcs15_print_id(&key_info->id), sc_print_path(&key_info->path));

	r = sc_select_file(card, &key_info->path, &file);
	LOG_TEST_RET(ctx, r, "Cannot store MyEID key: select key file failed");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, r, "No authorisation to store MyEID private key");

	if (file)
		sc_file_free(file);

	/* Fill in data structure */
	memset(&args, 0, sizeof (args));

	args.op_type = OP_TYPE_STORE;
	if(object->type == SC_PKCS15_TYPE_PRKEY_RSA) {
		//args.key_len_bits = keybits;
		args.key_type = SC_CARDCTL_MYEID_KEY_RSA;
		args.pubexp_len = prkey->u.rsa.exponent.len;
		args.pubexp = prkey->u.rsa.exponent.data;
		args.primep_len = prkey->u.rsa.p.len;
		args.primep = prkey->u.rsa.p.data;
		args.primeq_len = prkey->u.rsa.q.len;
		args.primeq = prkey->u.rsa.q.data;

		args.dp1_len = prkey->u.rsa.dmp1.len;
		args.dp1 = prkey->u.rsa.dmp1.data;
		args.dq1_len = prkey->u.rsa.dmq1.len;
		args.dq1 = prkey->u.rsa.dmq1.data;
		args.invq_len = prkey->u.rsa.iqmp.len;
		args.invq = prkey->u.rsa.iqmp.data;

		args.key_len_bits = prkey->u.rsa.modulus.len;
		args.mod = prkey->u.rsa.modulus.data;
	}
	else {
		args.key_type = SC_CARDCTL_MYEID_KEY_EC;
		args.d = prkey->u.ec.privateD.data;
		args.d_len = prkey->u.ec.privateD.len;
		args.ecpublic_point = prkey->u.ec.ecpointQ.value;
		args.ecpublic_point_len = prkey->u.ec.ecpointQ.len;
		args.key_len_bits = prkey->u.ec.params.field_length;
	}
	/* Store RSA key  */
	r = sc_card_ctl(card, SC_CARDCTL_MYEID_GENERATE_STORE_KEY, &args);
	LOG_TEST_RET(ctx, r, "Card control 'MYEID_GENERATE_STORE_KEY' failed");

	LOG_FUNC_RETURN(ctx, r);
}

static int
myeid_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey *pubkey) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_cardctl_myeid_gen_store_key_info args;
	struct sc_file *file = NULL;
	int r;
	unsigned int cla,tag;
	size_t taglen;
	size_t keybits = key_info->modulus_length;
	u8 raw_pubkey[MYEID_MAX_RSA_KEY_LEN / 8];
	u8* dataptr;

	LOG_FUNC_CALLED(ctx);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA && object->type != SC_PKCS15_TYPE_PRKEY_EC)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Generate key failed: only RSA and EC supported");

	/* Check that the card supports the requested modulus length */
	switch (object->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			if (sc_card_find_rsa_alg(p15card->card, keybits) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported RSA key size");
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			/* EC is supported in MyEID v > 3.5. TODO: set correct return value if older MyEID version. */
			/* Here the information about curve is not available, that's why supported algorithm is checked
			   without curve OID. */						
                    
			if(key_info->field_length != 0)
				keybits = key_info->field_length;
			else
				key_info->field_length = keybits;
			
			if (sc_card_find_ec_alg(p15card->card, keybits, NULL) == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported EC key size");
			
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key type");
			break;
	}

	sc_log(ctx, "Generate key with ID:%s and path:%s",
			sc_pkcs15_print_id(&key_info->id), sc_print_path(&key_info->path));

	r = sc_select_file(card, &key_info->path, &file);
	LOG_TEST_RET(ctx, r, "Cannot generate key: failed to select key file");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_GENERATE);
	LOG_TEST_RET(ctx, r, "No authorisation to generate private key");

	/* Fill in data structure */
	memset(&args, 0, sizeof (args));
	args.key_len_bits = keybits;
	args.op_type = OP_TYPE_GENERATE;
	if (object->type == SC_PKCS15_TYPE_PRKEY_RSA) {
		args.key_type = SC_CARDCTL_MYEID_KEY_RSA;
		args.pubexp_len = MYEID_DEFAULT_PUBKEY_LEN;
		args.pubexp = MYEID_DEFAULT_PUBKEY;
	} else if (object->type == SC_PKCS15_TYPE_PRKEY_EC) {
		args.key_type = SC_CARDCTL_MYEID_KEY_EC;
	}

	/* Generate the key  */
	r = sc_card_ctl(card, SC_CARDCTL_MYEID_GENERATE_STORE_KEY, &args);
	LOG_TEST_RET(ctx, r, "Card control 'MYEID_GENERATE_STORE_KEY' failed");

	/* Keypair generation -> collect public key info */
	if (pubkey != NULL) {
		struct sc_cardctl_myeid_data_obj data_obj;

		if (object->type == SC_PKCS15_TYPE_PRKEY_RSA) {
			pubkey->algorithm = SC_ALGORITHM_RSA;
			pubkey->u.rsa.modulus.len = (keybits + 7) / 8;
			pubkey->u.rsa.modulus.data = malloc(pubkey->u.rsa.modulus.len);
			pubkey->u.rsa.exponent.len = MYEID_DEFAULT_PUBKEY_LEN;
			pubkey->u.rsa.exponent.data = malloc(MYEID_DEFAULT_PUBKEY_LEN);
			memcpy(pubkey->u.rsa.exponent.data, MYEID_DEFAULT_PUBKEY, MYEID_DEFAULT_PUBKEY_LEN);

			/* Get public key modulus */
			r = sc_select_file(card, &file->path, NULL);
			LOG_TEST_RET(ctx, r, "Cannot get key modulus: select key file failed");

			data_obj.P1 = 0x01;
			data_obj.P2 = 0x01;
			data_obj.Data = raw_pubkey;
			data_obj.DataLen = sizeof (raw_pubkey);

			r = sc_card_ctl(card, SC_CARDCTL_MYEID_GETDATA, &data_obj);
			LOG_TEST_RET(ctx, r, "Cannot get RSA key modulus: 'MYEID_GETDATA' failed");

			if ((data_obj.DataLen * 8) != key_info->modulus_length)
				LOG_TEST_RET(ctx, SC_ERROR_PKCS15INIT, "Cannot get RSA key modulus: invalid key-size");

			memcpy(pubkey->u.rsa.modulus.data, raw_pubkey, pubkey->u.rsa.modulus.len);
		}
		else if (object->type == SC_PKCS15_TYPE_PRKEY_EC) {
			struct sc_ec_parameters *ecparams = (struct sc_ec_parameters *)key_info->params.data;

			sc_log(ctx, "curve '%s', len %i, oid '%s'", ecparams->named_curve, ecparams->field_length, sc_dump_oid(&(ecparams->id)));
			pubkey->algorithm = SC_ALGORITHM_EC;

			r = sc_select_file(card, &file->path, NULL);
			LOG_TEST_RET(ctx, r, "Cannot get public key: select key file failed");

			data_obj.P1 = 0x01;
			data_obj.P2 = 0x86; /* Get public EC key (Q) */
			data_obj.Data = raw_pubkey;
			data_obj.DataLen = sizeof (raw_pubkey);

			r = sc_card_ctl(card, SC_CARDCTL_MYEID_GETDATA, &data_obj);
			LOG_TEST_RET(ctx, r, "Cannot get EC public key: 'MYEID_GETDATA' failed");

			dataptr = data_obj.Data;
			r = sc_asn1_read_tag((const u8 **)&dataptr, data_obj.DataLen, &cla, &tag, &taglen);
			LOG_TEST_RET(ctx, r, "Invalid EC public key data. Cannot parse DER structure.");

			if (taglen == 0)
			    LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

			if (pubkey->u.ec.ecpointQ.value)
				free(pubkey->u.ec.ecpointQ.value);

			pubkey->u.ec.ecpointQ.value = malloc(taglen);

			if (pubkey->u.ec.ecpointQ.value == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

			memcpy(pubkey->u.ec.ecpointQ.value, dataptr, taglen);
			pubkey->u.ec.ecpointQ.len = taglen;

			if (pubkey->u.ec.params.named_curve)
				free(pubkey->u.ec.params.named_curve);
			pubkey->u.ec.params.named_curve = NULL;
			if (pubkey->u.ec.params.der.value)
				free(pubkey->u.ec.params.der.value);
			pubkey->u.ec.params.der.value = NULL;
			pubkey->u.ec.params.der.len = 0;

			pubkey->u.ec.params.named_curve = strdup(ecparams->named_curve);
			if (!pubkey->u.ec.params.named_curve)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			r = sc_pkcs15_fix_ec_parameters(ctx, &pubkey->u.ec.params);
			LOG_TEST_RET(ctx, r, "Cannot fix EC parameters");
		}
	}

	if (file)
		sc_file_free(file);

	LOG_FUNC_RETURN(ctx, r);
}

/* Finish initialization. After this ACL is in affect */
static int myeid_finalize_card(sc_card_t *card) {
	LOG_FUNC_CALLED(card->ctx);
	LOG_FUNC_RETURN(card->ctx, sc_card_ctl(card, SC_CARDCTL_MYEID_ACTIVATE_CARD, NULL));
}


/*
 * Create a new PIN
 */
static struct sc_pkcs15init_operations sc_pkcs15init_myeid_operations = {
	myeid_erase_card,
	myeid_init_card, /* init_card */
	myeid_create_dir, /* create_dir */
	NULL, /* create_domain */
	myeid_select_pin_reference,
	myeid_create_pin,
	NULL, /* select_key_reference */
	myeid_create_key,
	myeid_store_key,
	myeid_generate_key,
	myeid_encode_private_key,
	myeid_encode_public_key,
	myeid_finalize_card,
	myeid_delete_object, /* delete_object */
	NULL, NULL, NULL, NULL, NULL, /* pkcs15init emulation */
	NULL /* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_myeid_ops(void) {
	return &sc_pkcs15init_myeid_operations;
}
