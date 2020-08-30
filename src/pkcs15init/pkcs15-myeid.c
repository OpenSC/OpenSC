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
#include "pkcs11/pkcs11.h"

#undef KEEP_AC_NONE_FOR_INIT_APPLET

#define MYEID_MAX_PINS   14
#define MYEID_MAX_RSA_KEY_LEN 4096

unsigned char MYEID_DEFAULT_PUBKEY[] = {0x01, 0x00, 0x01};
#define MYEID_DEFAULT_PUBKEY_LEN       sizeof(MYEID_DEFAULT_PUBKEY)

#define MYEID_PROP_INFO_2_EXCTRACTABLE			0x08;
#define MYEID_PROP_INFO_1_TRUSTED				0x04;
#define MYEID_PROP_INFO_1_WRAP_WITH_TRUSTED		0x08;
#define MYEID_PROP_INFO_2_SESSION_OBJECT		0x01;

static const struct sc_object_id id_aes128_ecb = { { 2, 16, 840, 1, 101, 3, 4, 1, 1, -1 } };
static const struct sc_object_id id_aes128_cbc = { { 2, 16, 840, 1, 101, 3, 4, 1, 2, -1 } };
static const struct sc_object_id id_aes256_ecb = { { 2, 16, 840, 1, 101, 3, 4, 1, 41, -1 } };
static const struct sc_object_id id_aes256_cbc = { { 2, 16, 840, 1, 101, 3, 4, 1, 42, -1 } };

static void
_add_supported_algo(struct sc_profile *profile, struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		    unsigned operations, unsigned mechanism, const struct sc_object_id *oid);

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

	_add_supported_algo(profile, p15card, NULL, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_ECB, &id_aes128_ecb);
	_add_supported_algo(profile, p15card, NULL, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_CBC, &id_aes128_cbc);
	_add_supported_algo(profile, p15card, NULL, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_ECB, &id_aes256_ecb);
	_add_supported_algo(profile, p15card, NULL, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_CBC, &id_aes256_cbc);

	r = sc_card_ctl(p15card->card, SC_CARDCTL_GET_SERIALNR, &rbuf);
	LOG_TEST_RET(p15card->card->ctx, r,  "Get applet info failed");

	sc_format_path("3F00", &path);
	r = sc_select_file(p15card->card, &path, &file);

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
		"PKCS15-SKDF",
		"PKCS15-CDF",
		"PKCS15-CDF-TRUSTED",
		"PKCS15-DODF",
		NULL
	};

	static const int create_dfs_val[] = {
		SC_PKCS15_PRKDF,
		SC_PKCS15_PUKDF,
		SC_PKCS15_SKDF,
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

			file = NULL;
			r = sc_profile_get_file(profile, create_dfs[ii], &file);
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
	sc_log(ctx,
	       "PIN('%s',ref:%i,flags:0x%X,pin_len:%"SC_FORMAT_LEN_SIZE_T"u,puk_len:%"SC_FORMAT_LEN_SIZE_T"u)\n",
	       pin_obj->label, auth_info->attrs.pin.reference,
	       auth_info->attrs.pin.flags, pin_len, puk_len);

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
	const char *tag = NULL;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	switch (type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_EC:
		tag = "private-key";
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
	case SC_PKCS15_TYPE_PUBKEY_EC:
		tag = "public-key";
		break;
	case SC_PKCS15_TYPE_SKEY_GENERIC:
	case SC_PKCS15_TYPE_SKEY_DES:
	case SC_PKCS15_TYPE_SKEY_3DES:
		tag = "secret-key";
		break;
	default:
		if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT)
			tag = "certificate";
		else if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_DATA_OBJECT)
			tag = "data";
		break;
	}

	if (!tag) {
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
 * Add AlgorithmInfo of a supported algorithm to supportedAlgorithms field in tokenInfo. If object != NULL,
 * add reference to the algorithmInfo to the passed object.
 */
static void
_add_supported_algo(struct sc_profile *profile, struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object,
		    unsigned operations, unsigned mechanism, const struct sc_object_id *oid)
{
	struct sc_supported_algo_info *algo;
	struct sc_context *ctx = p15card->card->ctx;
	if (oid == NULL) {
		sc_log(ctx, "Failed to add algorithms refs - invalid arguments.");
		return;
	}
	algo = sc_pkcs15_get_specific_supported_algo(p15card, operations, mechanism, oid);
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (!algo) {
		unsigned ref = 1, ii;

		for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && p15card->tokeninfo->supported_algos[ii].reference; ii++)
			if (p15card->tokeninfo->supported_algos[ii].reference >= ref)
				ref = p15card->tokeninfo->supported_algos[ii].reference + 1;
		if (ii < SC_MAX_SUPPORTED_ALGORITHMS) {
			algo = &p15card->tokeninfo->supported_algos[ii];
			algo->reference = ref;
			algo->mechanism = mechanism;
			algo->operations = operations;
			algo->algo_id = *oid;
			profile->dirty = 1;
			profile->pkcs15.do_last_update = 1;
		}

	}
	if (object != NULL)
		rv = sc_pkcs15_add_supported_algo_ref(object, algo);
	else
		rv = SC_SUCCESS;

	if (rv != SC_SUCCESS) {
		sc_log(ctx, "Failed to add algorithms refs");
	}
}

static void
myeid_fixup_supported_algos(struct sc_profile *profile, struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_skey_info *skey_info = (struct sc_pkcs15_skey_info *) object->data;

	LOG_FUNC_CALLED(ctx);
	switch (object->type) {
	case SC_PKCS15_TYPE_SKEY_GENERIC:
		switch (skey_info->key_type | (skey_info->value_len << 16)) {
		case CKK_AES | (128 << 16):
			_add_supported_algo(profile, p15card, object, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_ECB, &id_aes128_ecb);
			_add_supported_algo(profile, p15card, object, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_CBC, &id_aes128_cbc);
			break;
		case CKK_AES | (256 << 16):
			_add_supported_algo(profile, p15card, object, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_ECB, &id_aes256_ecb);
			_add_supported_algo(profile, p15card, object, SC_PKCS15_ALGO_OP_DECIPHER|SC_PKCS15_ALGO_OP_ENCIPHER, CKM_AES_CBC, &id_aes256_cbc);
			break;
		}
		break;
	}
}


/*
 * Create a private key file
 */
static int
myeid_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object) {
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_pkcs15_skey_info *skey_info = (struct sc_pkcs15_skey_info *) object->data;
	struct sc_pkcs15_id *id;
	struct sc_path *path;
	int *key_reference;
	struct sc_file *file = NULL;
	struct sc_pkcs15_object *pin_object = NULL;
	struct sc_pkcs15_auth_info *pkcs15_auth_info = NULL;
	unsigned char sec_attrs[] = {0xFF, 0xFF, 0xFF};
	int r, ef_structure = 0, keybits = 0, pin_reference = -1;
	unsigned char prop_info[] = {0x00, 0x00};
	int extractable = FALSE;

	LOG_FUNC_CALLED(card->ctx);

	switch (object->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			ef_structure = SC_CARDCTL_MYEID_KEY_RSA;
			keybits = prkey_info->modulus_length;
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			ef_structure = SC_CARDCTL_MYEID_KEY_EC;
			keybits = prkey_info->field_length;
			break;
		case SC_PKCS15_TYPE_SKEY_DES:
		case SC_PKCS15_TYPE_SKEY_3DES:
			ef_structure = SC_CARDCTL_MYEID_KEY_DES;
			keybits = skey_info->value_len;
			if ((skey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE) == SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE)
				extractable = TRUE;
			break;
		case SC_PKCS15_TYPE_SKEY_GENERIC:
			keybits = skey_info->value_len;
			if ((skey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE) == SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE)
				extractable = TRUE;
			switch (skey_info->key_type) {
			case CKK_AES:
				ef_structure = SC_CARDCTL_MYEID_KEY_AES;
				break;
			case CKK_DES:
				ef_structure = SC_CARDCTL_MYEID_KEY_DES;
				break;
			default:
				if (object->type == SC_PKCS15_TYPE_SKEY_GENERIC)
					ef_structure = SC_CARDCTL_MYEID_KEY_GENERIC_SECRET;
				break;
			}
			break;
	}
	if (!ef_structure) {
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS,
				"Unsupported key type");
	}

	myeid_fixup_supported_algos(profile, p15card, object);

	if ((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY) {
		id = &prkey_info->id;
		path = &prkey_info->path;
		key_reference = &prkey_info->key_reference;
	} else {
		id = &skey_info->id;
		path = &skey_info->path;
		key_reference = &skey_info->key_reference;
	}

	sc_log(ctx, "create MyEID key ID:%s", sc_pkcs15_print_id(id));

	/* Get the private key file */
	r = myeid_new_file(profile, card, object->type, *key_reference, &file);
	LOG_TEST_RET(ctx, r, "Cannot get new MyEID key file");

	if (!file || !file->path.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot determine key file");

	sc_log(ctx, "Key file size %d", keybits);
	file->size = keybits;
	file->ef_structure = ef_structure;

	memcpy(path->value, &file->path.value, file->path.len);
	*key_reference = file->path.value[file->path.len - 1] & 0xFF;

	sc_log(ctx, "Path of MyEID key file to create %s",
			sc_print_path(&file->path));

	if (object->auth_id.len >= 1) {
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &object->auth_id, &pin_object);

		if (r != SC_SUCCESS)
			sc_file_free(file);
		LOG_TEST_RET(ctx, r, "Failed to get pin object by auth_id");

		if (pin_object->type != SC_PKCS15_TYPE_AUTH_PIN) {
			sc_file_free(file);
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_VALID, "Invalid object returned when locating pin object.");
		}

		pkcs15_auth_info =  (struct sc_pkcs15_auth_info*) pin_object->data;

		if (pkcs15_auth_info == NULL || pkcs15_auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN) {
			sc_file_free(file);
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_VALID, "NULL or invalid sc_pkcs15_auth_info in pin object");
		}

		pin_reference = pkcs15_auth_info->attrs.pin.reference;

		if (pin_reference >= 1 && pin_reference < MYEID_MAX_PINS) {
			sec_attrs[0] = (pin_reference << 4 | (pin_reference & 0x0F));
			sec_attrs[1] = (pin_reference << 4 | (pin_reference & 0x0F));
			sc_file_set_sec_attr(file, sec_attrs, sizeof(sec_attrs));
		}
	}
	else {
		sc_file_free(file);
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid AuthID value for a private key.");
	}

	/* TODO: fill all proprietary attributes here based on the object */

	if (object->user_consent != 0 && pin_reference >= 1)
	    prop_info[0] |= (pin_reference << 4);

	if (extractable)
	    prop_info[1] |= MYEID_PROP_INFO_2_EXCTRACTABLE;

	if (object->session_object != 0) /* Object will be removed during next reset. */
		prop_info[1] |= MYEID_PROP_INFO_2_SESSION_OBJECT;

	/* TODO: add other flags, like CKA_TRUSTED and CKA_WRAP_WITH_TRUSTED */

	r = sc_file_set_prop_attr(file, prop_info, 2);
	LOG_TEST_RET(ctx, r, "Cannot create MyEID key file");

	/* Now create the key file */
	r = sc_pkcs15init_create_file(profile, p15card, file);
	sc_file_free(file);
	LOG_TEST_RET(ctx, r, "Cannot create MyEID key file");

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
	struct sc_cardctl_myeid_gen_store_key_info args;
	struct sc_file *file = NULL;
	struct sc_pkcs15_id *id;
	struct sc_path *path;
	int r;

	LOG_FUNC_CALLED(ctx);

	if ((object->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY) {
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) object->data;
		id = &prkey_info->id;
		path = &prkey_info->path;
	} else {
		struct sc_pkcs15_skey_info *skey_info = (struct sc_pkcs15_skey_info *) object->data;
		id = &skey_info->id;
		path = &skey_info->path;
	}

	sc_log(ctx, "store MyEID key with ID:%s and path:%s",
			sc_pkcs15_print_id(id), sc_print_path(path));

	r = sc_select_file(card, path, &file);
	LOG_TEST_RET(ctx, r, "Cannot store MyEID key: select key file failed");

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, r, "No authorisation to store MyEID private key");

	sc_file_free(file);

	/* Fill in data structure */
	memset(&args, 0, sizeof (args));

	args.op_type = OP_TYPE_STORE;

	switch (object->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
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

		//args.key_len_bits = keybits;
		args.key_len_bits = prkey->u.rsa.modulus.len;
		args.mod = prkey->u.rsa.modulus.data;
		break;
	case SC_PKCS15_TYPE_PRKEY_EC:
		args.key_type = SC_CARDCTL_MYEID_KEY_EC;
		args.d = prkey->u.ec.privateD.data;
		args.d_len = prkey->u.ec.privateD.len;
		args.ecpublic_point = prkey->u.ec.ecpointQ.value;
		args.ecpublic_point_len = prkey->u.ec.ecpointQ.len;
		args.key_len_bits = prkey->u.ec.params.field_length;
		break;
	case SC_PKCS15_TYPE_SKEY_GENERIC:
	case SC_PKCS15_TYPE_SKEY_DES:
	case SC_PKCS15_TYPE_SKEY_2DES:
	case SC_PKCS15_TYPE_SKEY_3DES:
		switch (prkey->algorithm) {
		case SC_ALGORITHM_AES:
			args.key_type = SC_CARDCTL_MYEID_KEY_AES;
			break;
		case SC_ALGORITHM_DES:
			args.key_type = SC_CARDCTL_MYEID_KEY_DES;
			break;
		}
		args.d = prkey->u.secret.data;
		args.d_len = prkey->u.secret.data_len;
		break;
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

	/* Key pair generation -> collect public key info */
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

			sc_log(ctx,
			       "curve '%s', len %"SC_FORMAT_LEN_SIZE_T"u, oid '%s'",
			       ecparams->named_curve, ecparams->field_length,
			       sc_dump_oid(&(ecparams->id)));
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
			if (dataptr == NULL)
				r = SC_ERROR_ASN1_OBJECT_NOT_FOUND;
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
