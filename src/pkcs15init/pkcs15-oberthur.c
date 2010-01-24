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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#ifdef ENABLE_OPENSSL
#include <openssl/sha.h>
#endif

#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include <opensc/log.h>
#include "pkcs15-init.h"
#include "profile.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static int cosm_create_reference_data(struct sc_profile *, struct sc_card *,
		struct sc_pkcs15_pin_info *, 
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len);
static int cosm_update_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *info, const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len);

int cosm_delete_file(struct sc_card *card, struct sc_profile *profile,
		struct sc_file *df);


static int 
cosm_write_tokeninfo (struct sc_card *card, struct sc_profile *profile, 
		char *label, unsigned p15_flags)
{
	struct sc_file *file = NULL;
	unsigned mask = SC_PKCS15_CARD_FLAG_PRN_GENERATION 
		| SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED 
		| SC_PKCS15_CARD_FLAG_USER_PIN_INITIALIZED 
		| SC_PKCS15_CARD_FLAG_TOKEN_INITIALIZED;
	int rv, sz, flags = 0;
	char *buffer = NULL;

	if (!card || !profile)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "cosm_write_tokeninfo() label '%s'; flags 0x%X\n", label, p15_flags);
	if (sc_profile_get_file(profile, COSM_TITLE"-token-info", &file))
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "Cannot find "COSM_TITLE"-token-info");

	if (file->size < 16)
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "Unsufficient size of the "COSM_TITLE"-token-info file");
	
	buffer = calloc(1, file->size);
	if (!buffer)
		SC_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "Allocation error in cosm_write_tokeninfo()");

	if (label)   
		strncpy(buffer, label, file->size - 4);
	else if (profile->p15_data && profile->p15_data->label)
		snprintf(buffer, file->size - 4, profile->p15_data->label);
	else if (profile->p15_spec && profile->p15_spec->label)
		snprintf(buffer, file->size - 4, profile->p15_spec->label);
	else
		snprintf(buffer, file->size - 4, "OpenSC-Token");

	sz = strlen(buffer);	
	if (sz < file->size - 4)
		memset(buffer + sz, ' ', file->size - sz);

	if (p15_flags & SC_PKCS15_CARD_FLAG_PRN_GENERATION)
		flags |= COSM_TOKEN_FLAG_PRN_GENERATION;
	
	if (p15_flags & SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED)
		flags |= COSM_TOKEN_FLAG_LOGIN_REQUIRED;
	
	if (p15_flags & SC_PKCS15_CARD_FLAG_USER_PIN_INITIALIZED)
		flags |= COSM_TOKEN_FLAG_USER_PIN_INITIALIZED;
	
	if (p15_flags & SC_PKCS15_CARD_FLAG_TOKEN_INITIALIZED)
		flags |= COSM_TOKEN_FLAG_TOKEN_INITIALIZED;

	sc_debug(card->ctx, "cosm_write_tokeninfo() token label '%s'; oberthur flags 0x%X\n", buffer, flags);

	memset(buffer + file->size - 4, 0, 4);
	*(buffer + file->size - 1) = flags & 0xFF;
	*(buffer + file->size - 2) = (flags >> 8) & 0xFF;

	rv = sc_pkcs15init_update_file(profile, card, file, buffer, file->size);
	if (rv > 0)
		rv = 0;

	if (profile->p15_data)
		profile->p15_data->flags = (profile->p15_data->flags & ~mask) | p15_flags;

	if (profile->p15_spec)
		profile->p15_spec->flags = (profile->p15_spec->flags & ~mask) | p15_flags;

	free(buffer);
	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
cosm_update_pukfile (struct sc_card *card, struct sc_profile *profile, 
		unsigned char *data, size_t data_len)
{
	struct sc_pkcs15_pin_info profile_puk;
	struct sc_file *file = NULL;
	int rv;
	unsigned char buffer[16];

	SC_FUNC_CALLED(card->ctx, 1);
	if (!data || data_len > 16)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &profile_puk);
	if (profile_puk.max_length > 16)
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "Invalid PUK settings");

	if (sc_profile_get_file(profile, COSM_TITLE"-puk-file", &file))
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "Cannot find PUKFILE");

	memset(buffer, profile_puk.pad_char, 16);
	memcpy(buffer, data, data_len);

	rv = sc_pkcs15init_update_file(profile, card, file, buffer, sizeof(buffer));
	if (rv > 0)
		rv = 0;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


int 
cosm_delete_file(struct sc_card *card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_path  path;
	struct sc_file  *parent;
	int rv = 0;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "id %04X\n", df->id);
	if (df->type==SC_FILE_TYPE_DF)   {
		rv = sc_pkcs15init_authenticate(profile, card, df, SC_AC_OP_DELETE);
		SC_TEST_RET(card->ctx, rv, "Cannot authenticate SC_AC_OP_DELETE");
	}
	
	/* Select the parent DF */
	path = df->path;
	path.len -= 2;

	rv = sc_select_file(card, &path, &parent);
	SC_TEST_RET(card->ctx, rv, "Cannnot select parent");

	rv = sc_pkcs15init_authenticate(profile, card, parent, SC_AC_OP_DELETE);
	sc_file_free(parent);
	SC_TEST_RET(card->ctx, rv, "Cannnot authenticate SC_AC_OP_DELETE");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(card, &path);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Erase the card
 */
static int 
cosm_erase_card(struct sc_profile *profile, struct sc_card *card)
{
	struct sc_file  *df = profile->df_info->file, *dir;
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	/* Delete EF(DIR). This may not be very nice
	 * against other applications that use this file, but
	 * extremely useful for testing :)
	 * Note we need to delete if before the DF because we create
	 * it *after* the DF. 
	 * */
	if (sc_profile_get_file(profile, "DIR", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	sc_debug(card->ctx, "erase file ddf %04X\n",df->id);
	rv = cosm_delete_file(card, profile, df);

	if (sc_profile_get_file(profile, "private-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}
	
	if (sc_profile_get_file(profile, "public-DF", &dir) >= 0) {
		sc_debug(card->ctx, "erase file dir %04X\n",dir->id);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
		if (rv < 0 && rv != SC_ERROR_FILE_NOT_FOUND)
			goto done;
	}

	rv = sc_profile_get_file(profile, COSM_TITLE"-AppDF", &dir);
	if (!rv) {
		sc_debug(card->ctx, "delete %s; r %i\n", COSM_TITLE"-AppDF", rv);
		rv = cosm_delete_file(card, profile, dir);
		sc_file_free(dir);
	}

	sc_free_apps(card);
done:		
	sc_keycache_forget_key(NULL, -1, -1);

	if (rv == SC_ERROR_FILE_NOT_FOUND)
		rv = 0;

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Initialize the Application DF
 */
static int 
cosm_init_app(struct sc_profile *profile, struct sc_card *card,	
		struct sc_pkcs15_pin_info *pinfo,
		const unsigned char *pin, size_t pin_len, 
		const unsigned char *puk, size_t puk_len)
{
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
		"PKCS15-AppDF",
		"PKCS15-ODF",
		"PKCS15-AODF",
		"PKCS15-PrKDF",
		"PKCS15-PuKDF",
		"PKCS15-CDF",
		"PKCS15-DODF",
		NULL
	};

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "cosm_init_app() pin_len %i; puk_len %i\n", pin_len, puk_len);
	
	/* Oberthur AWP file system is expected.*/
	/* Create private objects DF */
	for (ii = 0; create_dfs[ii]; ii++)   {
		if (sc_profile_get_file(profile, create_dfs[ii], &file))   {
			sc_debug(card->ctx, "Inconsistent profile: cannot find %s", create_dfs[ii]);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
	
		rv = sc_pkcs15init_create_file(profile, card, file);
		sc_debug(card->ctx, "rv %i\n", rv);
		sc_file_free(file);
		if (rv && rv!=SC_ERROR_FILE_ALREADY_EXISTS)
			SC_TEST_RET(card->ctx, rv, "cosm_init_app() sc_pkcs15init_create_file failed");
	}

	rv = cosm_write_tokeninfo(card, profile, NULL,
		SC_PKCS15_CARD_FLAG_TOKEN_INITIALIZED | SC_PKCS15_CARD_FLAG_PRN_GENERATION);

	if (pin && pin_len)   {
		/* Create local SOPIN */
		struct sc_pkcs15_pin_info pin_info;

		sc_profile_get_file(profile, COSM_TITLE"-AppDF", &file);

		pin_info.flags = SC_PKCS15_PIN_FLAG_SO_PIN;
		pin_info.reference = 4;
		memcpy(&pin_info.path, &file->path, sizeof(pin_info.path));

		sc_file_free(file);

		rv = cosm_create_reference_data(profile, card, &pin_info, pin, pin_len, NULL, 0);
		SC_TEST_RET(card->ctx, rv, "cosm_init_app() cosm_update_pin failed");
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int 
cosm_create_reference_data(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *pinfo, 
		const unsigned char *pin, size_t pin_len,	
		const unsigned char *puk, size_t puk_len )
{
	struct sc_pkcs15_pin_info profile_pin;
	struct sc_pkcs15_pin_info profile_puk;
	struct sc_cardctl_oberthur_createpin_info args;
	unsigned char *puk_buff = NULL;
	int rv, puk_buff_len = 0;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "pin lens %i/%i\n", pin_len,  puk_len);
	if (!pin || pin_len>0x40)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (puk && !puk_len)
		return SC_ERROR_INVALID_ARGUMENTS;

	rv = sc_select_file(card, &pinfo->path, NULL);
	SC_TEST_RET(card->ctx, rv, "Cannot select file");

	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &profile_pin);
	else
		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &profile_pin);

	if (profile_pin.max_length > 0x100)
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "Invalid (SO)PIN profile settings");


	if (puk)   {
		int ii, jj;
		const unsigned char *ptr = puk;
		
		puk_buff = (unsigned char *) malloc(0x100);
		if (!puk_buff)
			SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_OUT_OF_MEMORY);

		sc_profile_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &profile_puk);
		if (profile_puk.max_length > 0x100) {
			free(puk_buff);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
		memset(puk_buff, profile_puk.pad_char, 0x100);
		for (ii=0; ii<8 && (size_t)(ptr-puk) < puk_len && (*ptr); ii++)   {
			jj = 0;
			while (isalnum(*ptr) && jj<16)   {
				*(puk_buff + ii*0x10 + jj++) = *ptr;
				++ptr;
			}
			while(!isalnum(*ptr) && (*ptr))
				++ptr;
		}
		
		puk_buff_len = ii*0x10;
	}

	sc_debug(card->ctx, "pinfo->reference %i; tries %i\n", 
			pinfo->reference, profile_pin.tries_left);

	sc_debug(card->ctx, "sc_card_ctl %s\n","SC_CARDCTL_OBERTHUR_CREATE_PIN");
	args.type = SC_AC_CHV;
	args.ref = pinfo->reference;
	args.pin = pin;
	args.pin_len = pin_len;
	args.pin_tries = profile_pin.tries_left;
	args.puk = puk_buff;
	args.puk_len = puk_buff_len;
	args.puk_tries = profile_puk.tries_left;
	
	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_CREATE_PIN, &args);
	SC_TEST_RET(card->ctx, rv, "'CREATE_PIN' card specific command failed");

	if (puk_buff_len == 16)   {
		rv = cosm_update_pukfile (card, profile, puk_buff, puk_buff_len);
		SC_TEST_RET(card->ctx, rv, "Failed to update pukfile");
	}

	if (puk_buff)
		free(puk_buff);
	
	SC_FUNC_RETURN(card->ctx, 1, rv);
}

/*
 * Update PIN
 */
static int 
cosm_update_pin(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *pinfo, const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len )
{
	int rv, tries_left = -1;
	
	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);

	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   {
		if (pinfo->reference != 4)
			SC_TEST_RET(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE, "cosm_update_pin() invalid SOPIN reference");
		
		rv = sc_change_reference_data(card, SC_AC_CHV, pinfo->reference, puk, puk_len,
				pin, pin_len, &tries_left);
		SC_TEST_RET(card->ctx, rv, "cosm_update_pin() failed to change SOPIN");

		if (tries_left != -1)
			SC_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "cosm_update_pin() failed to change SOPIN");
	}
	else   {
		rv = cosm_create_reference_data(profile, card, pinfo, 
				pin, pin_len, puk, puk_len);
		SC_TEST_RET(card->ctx, rv, "cosm_update_pin() failed to change PIN");

		rv = cosm_write_tokeninfo(card, profile, NULL,
			SC_PKCS15_CARD_FLAG_TOKEN_INITIALIZED 
			| SC_PKCS15_CARD_FLAG_PRN_GENERATION
			| SC_PKCS15_CARD_FLAG_LOGIN_REQUIRED
			| SC_PKCS15_CARD_FLAG_USER_PIN_INITIALIZED);
		SC_TEST_RET(card->ctx, rv, "cosm_update_pin() failed to update tokeninfo");
	}

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static int
cosm_select_pin_reference(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_pin_info *pin_info) 
{
	struct sc_file *pinfile;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pin_info->reference, pin_info->flags);
	if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0) {
		sc_debug(card->ctx, "Profile doesn't define \"%s\"", COSM_TITLE "-AppDF");
		return SC_ERROR_INCONSISTENT_PROFILE;
	}

	pin_info->path = pinfile->path;
	sc_file_free(pinfile);
	
	if (!pin_info->reference)   {
		if (pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)   
			pin_info->reference = 4;
		else  
			pin_info->reference = 1;
	}

	if (pin_info->reference < 0 || pin_info->reference > 4)
		return SC_ERROR_INVALID_PIN_REFERENCE;

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


/*
 * Store a PIN
 */
static int
cosm_create_pin(struct sc_profile *profile, struct sc_card *card, struct sc_file *df,
		struct sc_pkcs15_object *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_pkcs15_pin_info *pinfo = (struct sc_pkcs15_pin_info *) pin_obj->data;
	struct sc_file *pinfile;
	int rv = 0, type;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "ref %i; flags %X\n", pinfo->reference, pinfo->flags);
	if (sc_profile_get_file(profile, COSM_TITLE "-AppDF", &pinfile) < 0)
		SC_TEST_RET(card->ctx, SC_ERROR_INCONSISTENT_PROFILE, "\""COSM_TITLE"-AppDF\" not defined");

	pinfo->path = pinfile->path;
	sc_file_free(pinfile);
	
	if (pinfo->flags & SC_PKCS15_PIN_FLAG_SO_PIN) {
		type = SC_PKCS15INIT_SO_PIN;

		if (pinfo->reference != 4)  
			SC_TEST_RET(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid SOPIN reference");
	} 
	else {
		type = SC_PKCS15INIT_USER_PIN;
		
		if (pinfo->reference !=1  &&  pinfo->reference != 2)
			SC_TEST_RET(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid PIN reference");
	}

	if (pin && pin_len)   {
		rv = cosm_update_pin(profile, card, pinfo, pin, pin_len,  puk, puk_len);
		SC_TEST_RET(card->ctx, rv, "Update PIN failed");
	}

	sc_keycache_set_pin_name(&pinfo->path, pinfo->reference, type);
	pinfo->flags &= ~SC_PKCS15_PIN_FLAG_LOCAL;

	SC_FUNC_RETURN(card->ctx, 1, rv);
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

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "cosm_new_file() type %X; num %i\n",type, num);
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
		case SC_PKCS15_TYPE_PRKEY:
			desc = "extractable private key";
			_template = "template-extractable-key";
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
			sc_debug(card->ctx, "File type %X not supported by card driver", 
				type);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		type &= SC_PKCS15_TYPE_CLASS_MASK;
	}

	sc_debug(card->ctx, "cosm_new_file() template %s; num %i\n",_template, num);
	if (sc_profile_get_file(profile, _template, &file) < 0) {
		sc_debug(card->ctx, "Profile doesn't define %s template '%s'\n",
				desc, _template);
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);
	}
 
	file->id |= (num & 0xFF);
	file->path.value[file->path.len-1] |= (num & 0xFF);
	if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
		file->ef_structure = structure;
	}

	sc_debug(card->ctx, "cosm_new_file() file size %i; ef type %i/%i; id %04X\n",file->size, 
			file->type, file->ef_structure, file->id);
	*out = file;

	SC_FUNC_RETURN(card->ctx, 1, SC_SUCCESS);
}


/*
 * RSA key generation
 */
static int
cosm_old_generate_key(struct sc_profile *profile, struct sc_card *card,
		unsigned int idx, unsigned int keybits,
		struct sc_pkcs15_pubkey *pubkey,
		struct sc_pkcs15_prkey_info *info)
{
	struct sc_cardctl_oberthur_genkey_info args;
	struct sc_file	*prkf = NULL, *tmpf = NULL;
	struct sc_path path;
	int	 rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "cosm_generate_key() index %i; nn %i\n", idx, keybits);
	if (keybits < 512 || keybits > 2048 || (keybits%0x20))   {
		sc_debug(card->ctx, "Unsupported key size %u\n", keybits);
		SC_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");
	}
	
	/* Get private key file from profile. */
	rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx, &prkf);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() cannot allocate new file SC_PKCS15_TYPE_PRKEY_RSA");
	prkf->size = keybits;
	
	/* Access condition of private object DF. */
	path = prkf->path;
	path.len -= 2;

	rv = sc_select_file(card, &path, &tmpf);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() no private object DF");
	
	rv = sc_pkcs15init_authenticate(profile, card, tmpf, SC_AC_OP_CRYPTO); 
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() pkcs15init_authenticate(SC_AC_OP_CRYPTO) failed");
	
	rv = sc_pkcs15init_authenticate(profile, card, tmpf, SC_AC_OP_CREATE);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() pkcs15init_authenticate(SC_AC_OP_CREATE) failed");
	
	sc_file_free(tmpf);
	
	/* In the private key DF create the temporary public RSA file. */
	sc_debug(card->ctx, "cosm_generate_key() ready to create temporary public key\n");
	sc_file_dup(&tmpf, prkf);
	if (!tmpf)
		SC_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot duplicate private key file");
	tmpf->type = SC_FILE_TYPE_INTERNAL_EF;
	tmpf->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	tmpf->id = 0x1012;
	tmpf->path.value[tmpf->path.len - 2] = 0x10;
	tmpf->path.value[tmpf->path.len - 1] = 0x12;

	rv = sc_pkcs15init_create_file(profile, card, prkf);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() failed to create private key EF");
	
	rv = sc_pkcs15init_create_file(profile, card, tmpf);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() failed to create temporary public key EF");
	
	memset(&args, 0, sizeof(args));
	args.id_prv = prkf->id;
	args.id_pub = tmpf->id;
	args.exponent = 0x10001;
	args.key_bits = keybits;
	args.pubkey_len = keybits/8;
	args.pubkey = (unsigned char *) malloc(keybits/8);
	if (!args.pubkey)
		SC_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate pubkey");
	
	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_GENERATE_KEY, &args);
	SC_TEST_RET(card->ctx, rv, "cosm_generate_key() CARDCTL_OBERTHUR_GENERATE_KEY failed");
	
	/* extract public key */
	pubkey->algorithm = SC_ALGORITHM_RSA;
	pubkey->u.rsa.modulus.len   = keybits / 8;
	pubkey->u.rsa.modulus.data  = (unsigned char *) malloc(keybits / 8);
	if (!pubkey->u.rsa.modulus.data)
		SC_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate modulus buf");
	
	/* FIXME and if the exponent length is not 3? */
	pubkey->u.rsa.exponent.len  = 3;
	pubkey->u.rsa.exponent.data = (unsigned char *) malloc(3);
	if (!pubkey->u.rsa.exponent.data) 
		SC_TEST_RET(card->ctx, SC_ERROR_OUT_OF_MEMORY, "cosm_generate_key() cannot allocate exponent buf");
	memcpy(pubkey->u.rsa.exponent.data, "\x01\x00\x01", 3);
	memcpy(pubkey->u.rsa.modulus.data, args.pubkey, args.pubkey_len);

	info->key_reference = 1;
	info->path = prkf->path;
	
	sc_debug(card->ctx, "cosm_generate_key() now delete temporary public key\n");
	rv =  cosm_delete_file(card, profile, tmpf);
	
	if (tmpf) 
		sc_file_free(tmpf);
	if (prkf) 
		sc_file_free(prkf);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


/*
 * Store a private key
 */
static int
cosm_new_key(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_prkey *key, unsigned int idx,
		struct sc_pkcs15_prkey_info *info)
{
	struct sc_file *prvfile = NULL;
	struct sc_pkcs15_prkey_rsa *rsa = NULL;
	struct sc_cardctl_oberthur_updatekey_info update_info;
	char pbuf[SC_MAX_PATH_STRING_SIZE];
	int rv;

	SC_FUNC_CALLED(card->ctx, 1);
	sc_debug(card->ctx, "index %i; id %s\n", idx, sc_pkcs15_print_id(&info->id));
	if (key->algorithm != SC_ALGORITHM_RSA)
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_NOT_SUPPORTED);

	/* Create and populate the private part. */
	rv = cosm_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, idx,
					&prvfile);
	SC_TEST_RET(card->ctx, rv, "Update RSA: cosm_new_file failed");
	
	rv = sc_path_print(pbuf, sizeof(pbuf), &prvfile->path);
	sc_debug(card->ctx, "rv %i\n", rv);
	if (rv != SC_SUCCESS)
		pbuf[0] = '\0';
	sc_debug(card->ctx, " prvfile->id %i;  path=%s\n", prvfile->id, pbuf);

	rsa = &key->u.rsa;
	
	prvfile->size = rsa->modulus.len << 3;

	rv = sc_select_file(card, &prvfile->path, NULL);
	sc_debug(card->ctx, "rv %i", rv);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		sc_debug(card->ctx, "Before create file");
		rv = sc_pkcs15init_create_file(profile, card, prvfile);
	}
	SC_TEST_RET(card->ctx, rv, "Update RSA: select/create key file failed");
	
	rv = sc_pkcs15init_authenticate(profile, card, prvfile, SC_AC_OP_UPDATE);
	SC_TEST_RET(card->ctx, rv, "Update RSA: no authorisation");

#ifdef ENABLE_OPENSSL
	/* Mozilla style ID */
	if (!info->id.len)   {
		SHA1(rsa->modulus.data, rsa->modulus.len, info->id.value);
		info->id.len = SHA_DIGEST_LENGTH;
		sc_debug(card->ctx, "ID: %s\n", sc_pkcs15_print_id(&info->id));		
	}
#endif
	
	if (info->id.len > sizeof(update_info.id))
		 SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	
	memset(&update_info, 0, sizeof(update_info));
	update_info.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
	update_info.data = (void *)rsa;
	update_info.data_len = sizeof(void *);
	update_info.id_len = info->id.len;
	memcpy(update_info.id, info->id.value, update_info.id_len);
		
	rv = sc_card_ctl(card, SC_CARDCTL_OBERTHUR_UPDATE_KEY, &update_info);
	SC_TEST_RET(card->ctx, rv, "Update KEY failed");
	
	info->path = prvfile->path;
	info->modulus_length = rsa->modulus.len << 3;

	if (prvfile) 
		sc_file_free(prvfile);

	SC_FUNC_RETURN(card->ctx, 1, rv);
}


static struct sc_pkcs15init_operations 
sc_pkcs15init_oberthur_operations = {
	cosm_erase_card,
	NULL,						/* init_card  */
	NULL,						/* create_dir */
	NULL,						/* create_domain */
	cosm_select_pin_reference,
	cosm_create_pin,
	NULL,						/* select_key_reference */
	NULL,						/* create_key */
	NULL,						/* store_key */
	NULL,						/* generate_key */
	NULL, 
	NULL,						/* encode private/public key */
	NULL,						/* finalize_card */
	cosm_init_app,				/* old */
	NULL,						/* new_pin */
	cosm_new_key,
	cosm_new_file,
	cosm_old_generate_key,
	NULL	
};

struct sc_pkcs15init_operations *
sc_pkcs15init_get_oberthur_ops(void)
{   
	return &sc_pkcs15init_oberthur_operations;
}
