/*
 * Oberthur specific operation for PKCS #15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2009  Viktor Tarasov <viktor.tarasov@opentrust.com>,
 *                     OpenTrust <www.opentrust.com>
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

#include "pkcs15-oberthur.h"
#include <sys/types.h>
#include <ctype.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "profile.h"
#include "pkcs15-init.h"

#define COSM_TITLE "OberthurAWP"

#define TLV_TYPE_V	0
#define TLV_TYPE_LV	1
#define TLV_TYPE_TLV	2

/* Should be greater then SC_PKCS15_TYPE_CLASS_MASK */
#define SC_DEVICE_SPECIFIC_TYPE	 0x1000

#define COSM_TYPE_PRKEY_RSA (SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PRKEY_RSA)
#define COSM_TYPE_PUBKEY_RSA (SC_DEVICE_SPECIFIC_TYPE | SC_PKCS15_TYPE_PUBKEY_RSA)

#define COSM_TOKEN_FLAG_PRN_GENERATION		0x01
#define COSM_TOKEN_FLAG_LOGIN_REQUIRED		0x04
#define COSM_TOKEN_FLAG_USER_PIN_INITIALIZED	0x08
#define COSM_TOKEN_FLAG_TOKEN_INITIALIZED	0x0400

static int cosm_create_reference_data(struct sc_profile *, struct sc_pkcs15_card *,
		struct sc_pkcs15_auth_info *, const unsigned char *, size_t,
		const unsigned char *, size_t);
static int cosm_update_pin(struct sc_profile *, struct sc_pkcs15_card *,
		struct sc_pkcs15_auth_info *, const unsigned char *, size_t,
		const unsigned char *, size_t);

static int
cosm_write_tokeninfo (struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		char *label, unsigned flags)
{
	struct sc_context *ctx;
	struct sc_file *file = NULL;
	int rv;
	size_t sz;
	char *buffer = NULL;

	if (!p15card || !p15card->card || !profile)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = p15card->card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "cosm_write_tokeninfo() label '%s'; flags 0x%X", label, flags);
	if (sc_profile_get_file(profile, COSM_TITLE"-token-info", &file)) {
		rv = SC_ERROR_INCONSISTENT_PROFILE;
		SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot find "COSM_TITLE"-token-info");
	}

	if (file->size < 16) {
		rv = SC_ERROR_INCONSISTENT_PROFILE;
		SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Insufficient size of the "COSM_TITLE"-token-info file");
	}

	buffer = calloc(1, file->size);
	if (!buffer) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Allocation error in cosm_write_tokeninfo()");
	}

	if (label)
		strncpy(buffer, label, file->size - 4);
	else if (p15card->tokeninfo->label)
		snprintf(buffer, file->size - 4, "%s", p15card->tokeninfo->label);
	else if (profile->p15_spec && profile->p15_spec->tokeninfo->label)
		snprintf(buffer, file->size - 4, "%s", profile->p15_spec->tokeninfo->label);
	else
		snprintf(buffer, file->size - 4, "OpenSC-Token");

	sz = strlen(buffer);
	if (sz < file->size - 4)
		memset(buffer + sz, ' ', file->size - sz);

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "cosm_write_tokeninfo() token label '%s'; oberthur flags 0x%X", buffer, flags);

	memset(buffer + file->size - 4, 0, 4);
	*(buffer + file->size - 1) = flags & 0xFF;
	*(buffer + file->size - 2) = (flags >> 8) & 0xFF;

	rv = sc_pkcs15init_update_file(profile, p15card, file, buffer, file->size);
	if (rv > 0)
		rv = 0;

err:
	sc_file_free(file);
	free(buffer);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


int
cosm_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path  path;
	struct sc_file  *parent;
	int rv = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "id %04X", df->id);
	if (df->type==SC_FILE_TYPE_DF)   {
		rv = sc_pkcs15init_authenticate(profile, p15card, df, SC_AC_OP_DELETE);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot authenticate SC_AC_OP_DELETE");
	}

	/* Select the parent DF */
	path = df->path;
	path.len -= 2;

	rv = sc_select_file(p15card->card, &path, &parent);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot select parent");

	rv = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot authenticate SC_AC_OP_DELETE");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(p15card->card, &path);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


/*
 * Erase the card
 */
static int
cosm_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file  *df = profile->df_info->file, *dir;
	int rv;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete if before the DF because we create
	 * it *after* the DF.
	 * */
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "erase file dir %04X",dir->id);
		rv = cosm_delete_file(p15card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "erase file ddf %04X",df->id);
	cosm_delete_file(p15card, profile, df);

	if (sc_profile_get_file(profile, "private-DF", &dir) >= 0) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "erase file dir %04X",dir->id);
		rv = cosm_delete_file(p15card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	if (sc_profile_get_file(profile, "public-DF", &dir) >= 0) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "erase file dir %04X",dir->id);
		rv = cosm_delete_file(p15card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	rv = sc_profile_get_file(profile, COSM_TITLE"-AppDF", &dir);
	if (!rv) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "delete %s; r %i", COSM_TITLE"-AppDF", rv);
		rv = cosm_delete_file(p15card, profile, dir);
		sc_file_free(dir);
	}

	sc_free_apps(p15card->card);
done:
	if (rv == SC_ERROR_FILE_NOT_FOUND)
		rv = 0;

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


static int
cosm_create_dir(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	size_t ii;
	int rv;
	static const char *create_dfs[] = {
		COSM_TITLE"-AppDF",
		"private-DF",
		"public-DF",
		COSM_TITLE"-token-info",
		COSM_TITLE"-puk-file",
		COSM_TITLE"-container-list",
		COSM_TITLE"-public-list",
		COSM_TITLE"-private-list",
		NULL
	};

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	/* Oberthur AWP file system is expected.*/
	/* Create private objects DF */
	for (ii = 0; create_dfs[ii]; ii++)   {
		if (sc_profile_get_file(profile, create_dfs[ii], &file))   {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Inconsistent profile: cannot find %s", create_dfs[ii]);
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INCONSISTENT_PROFILE, "Profile do not contains Oberthur AWP file");
		}

		rv = sc_pkcs15init_create_file(profile, p15card, file);
		sc_file_free(file);
		if (rv != SC_ERROR_FILE_ALREADY_EXISTS)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to create Oberthur AWP file");
	}

	rv = cosm_write_tokeninfo(p15card, profile, NULL,
		COSM_TOKEN_FLAG_TOKEN_INITIALIZED | COSM_TOKEN_FLAG_PRN_GENERATION);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


static int
cosm_create_reference_data(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_auth_info *ainfo,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len )
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_auth_info profile_auth_pin, profile_auth_puk;
	struct sc_cardctl_oberthur_createpin_info args;
	int rv;
	unsigned char oberthur_puk[16] = {
		0x6F, 0x47, 0xD9, 0x88, 0x4B, 0x6F, 0x9D, 0xC5,
		0x78, 0x33, 0x79, 0x8F, 0x5B, 0x7D, 0xE1, 0xA5
	};

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL,
		 "pin lens %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u",
		 pin_len, puk_len);
	if (!pin || pin_len>0x40)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (puk && !puk_len)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (ainfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	rv = sc_select_file(card, &ainfo->path, NULL);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot select file");

	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_auth_pin);
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &profile_auth_puk);

	memset(&args, 0, sizeof(args));
	args.type = SC_AC_CHV;
	args.ref = ainfo->attrs.pin.reference;
	args.pin = pin;
	args.pin_len = pin_len;

	if (!(ainfo->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))   {
		args.pin_tries = profile_auth_pin.tries_left;
		if (profile_auth_puk.tries_left > 0)   {
			args.puk = oberthur_puk;
			args.puk_len = sizeof(oberthur_puk);
			args.puk_tries = 5;
		}
	}
	else   {
		args.pin_tries = profile_auth_puk.tries_left;
	}

	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_CREATE_PIN, &args);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "'CREATE_PIN' card specific command failed");

	if (!(ainfo->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
			&& (profile_auth_puk.tries_left > 0))   {
	        struct sc_file *file = NULL;

		if (sc_profile_get_file(profile, COSM_TITLE"-puk-file", &file))
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INCONSISTENT_PROFILE, "Cannot find PUKFILE");

		rv = sc_pkcs15init_update_file(profile, p15card, file, oberthur_puk, sizeof(oberthur_puk));
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to update pukfile");

		sc_file_free(file);
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


/*
 * Update PIN
 */
static int
cosm_update_pin(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_auth_info *ainfo, const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len )
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (ainfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ref %i; flags 0x%X", ainfo->attrs.pin.reference, ainfo->attrs.pin.flags);

	if (ainfo->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
		if (ainfo->attrs.pin.reference != 4)
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_PIN_REFERENCE, "cosm_update_pin() invalid SOPIN reference");
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update SOPIN ignored");
		rv = SC_SUCCESS;
	}
	else   {
		rv = cosm_create_reference_data(profile, p15card, ainfo, pin, pin_len, puk, puk_len);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "cosm_update_pin() failed to change PIN");

		rv = cosm_write_tokeninfo(p15card, profile, NULL,
			COSM_TOKEN_FLAG_TOKEN_INITIALIZED
			| COSM_TOKEN_FLAG_PRN_GENERATION
			| COSM_TOKEN_FLAG_LOGIN_REQUIRED
			| COSM_TOKEN_FLAG_USER_PIN_INITIALIZED);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "cosm_update_pin() failed to update tokeninfo");
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


static int
cosm_select_pin_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_auth_info *auth_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pin_attributes *pin_attrs;
	struct sc_file *pinfile;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	pin_attrs = &auth_info->attrs.pin;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ref %i; flags %X", pin_attrs->reference, pin_attrs->flags);
	if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}

	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_LOCAL)
		auth_info->path = pinfile->path;

	sc_file_free(pinfile);

	if (pin_attrs->reference <= 0)   {
		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			pin_attrs->reference = 4;
		else if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
			pin_attrs->reference = 4;
		else
			pin_attrs->reference = 1;

		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_LOCAL)
			pin_attrs->reference |= 0x80;
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}


/*
 * Store a PIN
 */
static int
cosm_create_pin(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_file *df, struct sc_pkcs15_object *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs;
	struct sc_file *pin_file;
	int rv = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	pin_attrs = &auth_info->attrs.pin;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "create '%.*s'; ref 0x%X; flags %X", (int) sizeof pin_obj->label, pin_obj->label, pin_attrs->reference, pin_attrs->flags);
	if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pin_file) < 0)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INCONSISTENT_PROFILE, "\""COSM_TITLE"-AppDF\" not defined");

	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_LOCAL)
		auth_info->path = pin_file->path;

	sc_file_free(pin_file);

	if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)   {
			SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "SOPIN unblocking is not supported");
		}
		else   {
			if (pin_attrs->reference != 4)
				SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid SOPIN reference");
		}
	}
	else {
		if (pin_attrs->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)   {
			if (pin_attrs->reference != 0x84)
				SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid User PUK reference");
		}
		else   {
			if (pin_attrs->reference != 0x81)
				SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid User PIN reference");
		}
	}

	if (pin && pin_len)   {
		rv = cosm_update_pin(profile, p15card, auth_info, pin, pin_len,  puk, puk_len);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Update PIN failed");
	}

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


/*
 * Allocate a file
 */
static int
cosm_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_file	*file;
	const char *_template = NULL, *desc = NULL;
	unsigned int structure = 0xFFFFFFFF;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "cosm_new_file() type %X; num %i",type, num);
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
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "File type %X not supported by card driver",
				type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "cosm_new_file() template %s; num %i",_template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Profile doesn't define %s template '%s'",
				desc, _template);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED);
	}

	file->id |= (num & 0xFF);
	file->path.value[file->path.len-1] |= (num & 0xFF);
	if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
		file->ef_structure = structure;
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		 "cosm_new_file() file size %"SC_FORMAT_LEN_SIZE_T"u; ef type %i/%i; id %04X",
		 file->size, file->type, file->ef_structure, file->id);
	*out = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}


static int
cosm_get_temporary_public_key_file(struct sc_card *card,
		struct sc_file *prvkey_file, struct sc_file **pubkey_file)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	struct sc_file *file = NULL;
	int rv;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (!pubkey_file || !prvkey_file)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);

	file = sc_file_new();
	if (!file)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);

	file->status = SC_FILE_STATUS_ACTIVATED;
        file->type = SC_FILE_TYPE_INTERNAL_EF;
	file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	file->id = 0x1012;
	memcpy(&file->path, &prvkey_file->path, sizeof(file->path));
        file->path.value[file->path.len - 2] = 0x10;
	file->path.value[file->path.len - 1] = 0x12;
	file->size = prvkey_file->size;

	entry = sc_file_get_acl_entry(prvkey_file, SC_AC_OP_UPDATE);
	rv = sc_file_add_acl_entry(file, SC_AC_OP_UPDATE, entry->method, entry->key_ref);
	if (!rv)
		rv = sc_file_add_acl_entry(file, SC_AC_OP_PSO_ENCRYPT, SC_AC_NONE, 0);
	if (!rv)
		rv = sc_file_add_acl_entry(file, SC_AC_OP_PSO_VERIFY_SIGNATURE, SC_AC_NONE, 0);
	if (!rv)
		rv = sc_file_add_acl_entry(file, SC_AC_OP_EXTERNAL_AUTHENTICATE, SC_AC_NONE, 0);
	if (rv < 0)
		sc_file_free(file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to add ACL entry to the temporary public key file");

	*pubkey_file = file;

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, rv);
}


static int
cosm_generate_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_cardctl_oberthur_genkey_info args;
	struct sc_file *prkf = NULL, *tmpf = NULL;
	struct sc_path path;
	int rv = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "Generate key failed: RSA only supported");

	path = key_info->path;
	path.len -= 2;

	rv = sc_select_file(p15card->card, &path, &tmpf);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot generate key: failed to select private object DF");

	rv = sc_pkcs15init_authenticate(profile, p15card, tmpf, SC_AC_OP_CRYPTO);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot generate key: 'CRYPTO' authentication failed");

	rv = sc_pkcs15init_authenticate(profile, p15card, tmpf, SC_AC_OP_CREATE);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot generate key: 'CREATE' authentication failed");

	sc_file_free(tmpf);

	rv = sc_select_file(p15card->card, &key_info->path, &prkf);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to generate key: cannot select private key file");

	/* In the private key DF create the temporary public RSA file. */
	rv = cosm_get_temporary_public_key_file(p15card->card, prkf, &tmpf);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Error while getting temporary public key file");

	rv = sc_pkcs15init_create_file(profile, p15card, tmpf);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "cosm_generate_key() failed to create temporary public key EF");

	memset(&args, 0, sizeof(args));
	args.id_prv = prkf->id;
	args.id_pub = tmpf->id;
	args.exponent = 0x10001;
	args.key_bits = key_info->modulus_length;
	args.pubkey_len = key_info->modulus_length / 8;
	args.pubkey = malloc(key_info->modulus_length / 8);
	if (!args.pubkey)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate pubkey");

	rv = sc_card_ctl(p15card->card, SC_CARDCTL_OBERTHUR_GENERATE_KEY, &args);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "cosm_generate_key() CARDCTL_OBERTHUR_GENERATE_KEY failed");

	/* extract public key */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = key_info->modulus_length / 8;
	pubkey->u.rsa.modulus.data  = malloc(key_info->modulus_length / 8);
	if (!pubkey->u.rsa.modulus.data)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate modulus buf");

	/* FIXME and if the exponent length is not 3? */
	pubkey->u.rsa.exponent.len  = 3;
	pubkey->u.rsa.exponent.data = malloc(3);
	if (!pubkey->u.rsa.exponent.data)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate exponent buf");
	memcpy(pubkey->u.rsa.exponent.data, "\x01\x00\x01", 3);
	memcpy(pubkey->u.rsa.modulus.data, args.pubkey, args.pubkey_len);

	key_info->key_reference = prkf->path.value[prkf->path.len - 1] & 0xFF;
	key_info->path = prkf->path;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "cosm_generate_key() now delete temporary public key");
	rv =  cosm_delete_file(p15card, profile, tmpf);

	sc_file_free(tmpf);
	sc_file_free(prkf);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


/*
 * Create private key file
 */
static int
cosm_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	int rv = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "Create key failed: RSA only supported");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "create private key ID:%s",  sc_pkcs15_print_id(&key_info->id));
	/* Here, the path of private key file should be defined.
	 * Nevertheless, we need to instantiate private key to get the ACLs. */
	rv = cosm_new_file(profile, p15card->card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot create key: failed to allocate new key object");

	file->size = key_info->modulus_length;
	memcpy(&file->path, &key_info->path, sizeof(file->path));
	file->id = file->path.value[file->path.len - 2] * 0x100
				+ file->path.value[file->path.len - 1];

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Path of private key file to create %s", sc_print_path(&file->path));

	rv = sc_select_file(p15card->card, &file->path, NULL);
	if (rv == 0)   {
		rv = cosm_delete_file(p15card, profile, file);
		SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to delete private key file");
	}
	else if (rv != SC_ERROR_FILE_NOT_FOUND)    {
		SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Select private key file error");
	}

	rv = sc_pkcs15init_create_file(profile, p15card, file);
	SC_TEST_GOTO_ERR(ctx, SC_LOG_DEBUG_NORMAL, rv, "Failed to create private key file");

	key_info->key_reference = file->path.value[file->path.len - 1];

err:
	sc_file_free(file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


/*
 * Store a private key
 */
static int
cosm_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_prkey *prkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)object->data;
	struct sc_file *file = NULL;
	struct sc_cardctl_oberthur_updatekey_info update_info;
	int rv = 0;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA || prkey->algorithm != SC_ALGORITHM_RSA)
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_NOT_SUPPORTED, "Store key failed: RSA only supported");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "store key with ID:%s and path:%s", sc_pkcs15_print_id(&key_info->id),
		       	sc_print_path(&key_info->path));

	rv = sc_select_file(p15card->card, &key_info->path, &file);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot store key: select key file failed");

	rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "No authorisation to store private key");

	if (key_info->id.len > sizeof(update_info.id))
		 SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);

	memset(&update_info, 0, sizeof(update_info));
	update_info.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
	update_info.data = (void *)&prkey->u.rsa;
	update_info.data_len = sizeof(void *);
	update_info.id_len = key_info->id.len;
	memcpy(update_info.id, key_info->id.value, update_info.id_len);

	rv = sc_card_ctl(p15card->card, SC_CARDCTL_OBERTHUR_UPDATE_KEY, &update_info);
	SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot update private key");

	sc_file_free(file);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, rv);
}


#ifdef ENABLE_OPENSSL
static int
cosm_emu_update_dir (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_app_info *info)
{
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	/* No DIR file in the native Oberthur card */
	SC_FUNC_RETURN(p15card->card->ctx, 1, SC_SUCCESS);
}


static int
cosm_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;

	SC_FUNC_CALLED(ctx, 1);
	switch(op)   {
	case SC_AC_OP_ERASE:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; erase object('%.*s',type:%X)", (int) sizeof object->label, object->label, object->type);
		rv = awp_update_df_delete(p15card, profile, object);
		break;
	case SC_AC_OP_CREATE:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update DF; create object('%.*s',type:%X)", (int) sizeof object->label, object->label, object->type);
		rv = awp_update_df_create(p15card, profile, object);
		break;
	}
	SC_FUNC_RETURN(ctx, 1, rv);
}


static int
cosm_emu_update_tokeninfo(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_tokeninfo *tinfo)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	int rv, flags = 0, label_len;
	unsigned char *buf = NULL;

	SC_FUNC_CALLED(ctx, 1);

	if (sc_profile_get_file(profile, COSM_TITLE"-token-info", &file))
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INCONSISTENT_PROFILE, "cannot find "COSM_TITLE"-token-info");

	buf = calloc(1, file->size);
	if (!buf) {
		sc_file_free(file);
		SC_FUNC_RETURN(ctx, 1, SC_ERROR_OUT_OF_MEMORY);
	}

	label_len = strlen(tinfo->label) > (file->size - 4) ? (file->size - 4) : strlen(tinfo->label);
	memcpy(buf, tinfo->label, label_len);
	memset(buf  + label_len, ' ', file->size - 4 - label_len);

	/*  current PKCS#11 flags should be read from the token,
	 *  but for simplicity assume that user-pin is already initialised -- Andre 2010-10-05
	 */
	flags = COSM_TOKEN_FLAG_TOKEN_INITIALIZED
		| COSM_TOKEN_FLAG_USER_PIN_INITIALIZED
		| COSM_TOKEN_FLAG_LOGIN_REQUIRED
		| COSM_TOKEN_FLAG_PRN_GENERATION;

	memset(buf + file->size - 4, 0, 4);
	*(buf + file->size - 1) = flags % 0x100;
	*(buf + file->size - 2) = (flags % 0x10000) / 0x100;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Update token info (label:'%s',flags:%X,p15card->flags:%X)", buf, flags, p15card->flags);
	rv = sc_pkcs15init_update_file(profile, p15card, file, buf, file->size);
	free(buf);
	sc_file_free(file);

	if (rv > 0)
		rv = 0;

	SC_FUNC_RETURN(ctx, 1, rv);
}


static int
cosm_emu_write_info(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *pin_obj)
{
	SC_FUNC_CALLED(p15card->card->ctx, 1);
	/* No OpenSC Info file in the native Oberthur card */
	SC_FUNC_RETURN(p15card->card->ctx, 1, SC_SUCCESS);
}
#endif


static struct sc_pkcs15init_operations
sc_pkcs15init_oberthur_operations = {
	cosm_erase_card,
	NULL,				/* init_card  */
	cosm_create_dir,		/* create_dir */
	NULL,				/* create_domain */
	cosm_select_pin_reference,
	cosm_create_pin,
	NULL,				/* select_key_reference */
	cosm_create_key,		/* create_key */
	cosm_store_key,			/* store_key */
	cosm_generate_key,		/* generate_key */
	NULL,
	NULL,				/* encode private/public key */
	NULL,				/* finalize_card */
	NULL,				/* delete_object */
#ifdef ENABLE_OPENSSL
	cosm_emu_update_dir,
	cosm_emu_update_any_df,
	cosm_emu_update_tokeninfo,
	cosm_emu_write_info,
	NULL,
	NULL
#else
	NULL, NULL, NULL, NULL, NULL,
	NULL
#endif
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_oberthur_ops(void)
{
	return &sc_pkcs15init_oberthur_operations;
}
