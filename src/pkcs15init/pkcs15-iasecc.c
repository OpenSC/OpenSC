/*
 * IAS/ECC specific operations for PKCS #15 initialization
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *		      OpenTrust <www.opentrust.com>
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

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include "../libopensc/opensc.h"
#include "../libopensc/cardctl.h"
#include "../libopensc/log.h"
#include "../libopensc/pkcs15.h"
#include "../libopensc/cards.h"
#include "../libopensc/iasecc.h"
#include "../libopensc/iasecc-sdo.h"

#include "pkcs15-init.h"
#include "profile.h"

#define IASECC_TITLE "IASECC"

int iasecc_pkcs15_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_file *df);
static int iasecc_md_gemalto_delete_prvkey(struct sc_pkcs15_card *, struct sc_profile *, struct sc_pkcs15_object *);

static void
iasecc_reference_to_pkcs15_id (unsigned int ref, struct sc_pkcs15_id *id)
{
	int ii, sz;

	for (ii=0, sz = 0; (unsigned)ii < sizeof(unsigned int); ii++)
		if (ref >> 8*ii)
			sz++;

	for (ii=0; ii < sz; ii++)
		id->value[sz - ii - 1] = (ref >> 8*ii) & 0xFF;

	id->len = sz;
}


int
iasecc_pkcs15_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_path  path;
	unsigned long caps = card->caps;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "iasecc_pkcs15_delete_file() id %04X\n", df->id);

	card->caps |= SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, df, SC_AC_OP_DELETE);
	card->caps = caps;

	LOG_TEST_RET(ctx, rv, "Cannnot authenticate SC_AC_OP_DELETE");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(card, &path);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Erase the card
 *
 */
static int
iasecc_pkcs15_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file  *file = NULL;
	struct sc_path  path;
	struct sc_pkcs15_df *df;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (p15card->app->ddo.aid.len)   {
		memset(&path, 0, sizeof(struct sc_path));
		path.type = SC_PATH_TYPE_DF_NAME;
		memcpy(path.value, p15card->app->ddo.aid.value, p15card->app->ddo.aid.len);
		path.len = p15card->app->ddo.aid.len;

		sc_log(ctx, "Select DDO AID: %s", sc_print_path(&path));
		rv = sc_select_file(p15card->card, &path, NULL);
		LOG_TEST_RET(ctx, rv, "Erase application error: cannot select DDO AID");
	}

	for (df = p15card->df_list; df; df = df->next)   {
		struct sc_pkcs15_object *objs[32];
		unsigned obj_type = 0;
		int ii;

		if (df->type == SC_PKCS15_PRKDF)
			obj_type = SC_PKCS15_TYPE_PRKEY;
		else if (df->type == SC_PKCS15_PUKDF)
			obj_type = SC_PKCS15_TYPE_PUBKEY;
		else if (df->type == SC_PKCS15_CDF)
			obj_type = SC_PKCS15_TYPE_CERT;
		else if (df->type == SC_PKCS15_DODF)
			obj_type = SC_PKCS15_TYPE_DATA_OBJECT;
		else
			continue;

		rv = sc_pkcs15_get_objects(p15card, obj_type, objs, 32);
		LOG_TEST_RET(ctx, rv, "Failed to get PKCS#15 objects to remove");

		for (ii=0; ii<rv; ii++)   {
			if (obj_type == SC_PKCS15_TYPE_CERT)   {
				struct sc_path path = ((struct sc_pkcs15_cert_info *)(objs[ii]->data))->path;
				rv = sc_delete_file(p15card->card, &path);
			}
			else if (obj_type == SC_PKCS15_TYPE_DATA_OBJECT)   {
				struct sc_path path = ((struct sc_pkcs15_data_info *)(objs[ii]->data))->path;
				rv = sc_delete_file(p15card->card, &path);
			}

			sc_pkcs15_remove_object(p15card, objs[ii]);
		}

		rv = sc_select_file(p15card->card, &df->path, &file);
		if (rv == SC_ERROR_FILE_NOT_FOUND)
			continue;
		LOG_TEST_RET(ctx, rv, "Cannot select object file");

		profile->dirty = 1;

		rv = sc_erase_binary(p15card->card, 0, file->size, 0);
		if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)   {
			rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
			LOG_TEST_RET(ctx, rv, "SC_AC_OP_UPDATE authentication failed");

			rv = sc_erase_binary(p15card->card, 0, file->size, 0);
		}
		LOG_TEST_RET(ctx, rv, "Binary erase error");

		sc_file_free(file);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Allocate a file
 */
static int
iasecc_pkcs15_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file	*file = NULL;
	const char *_template = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "type %X; num %i\n", type, num);
	switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			_template = "private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			_template = "public-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			_template = "certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			_template = "public-data";
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Profile template not supported");
	}

	sc_log(ctx, "df_info path '%s'\n", sc_print_path(&profile->df_info->file->path));
	rv = sc_profile_get_file(profile, _template, &file);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		struct sc_pkcs15_id     id;

		id.len = 1;
		id.value[0] = num & 0xFF;
		rv = sc_profile_instantiate_template(profile, "key-domain", &profile->df_info->file->path,
				_template, &id, &file);
	}
	LOG_TEST_RET(ctx, rv, "Error when getting file from template");

	sc_log(ctx, "path(type:%X;path:%s)\n", file->path.type, sc_print_path(&file->path));

	file->id = (file->id & 0xFF00) | (num & 0xFF);
	if (file->path.len == 0)   {
		file->path.type = SC_PATH_TYPE_FILE_ID;
		file->path.len = 2;
	}
	file->path.value[file->path.len - 2] = (file->id >> 8) & 0xFF;
	file->path.value[file->path.len - 1] = file->id & 0xFF;
	file->path.count = -1;

	sc_log(ctx, "file size %i; ef type %i/%i; id %04X\n", file->size, file->type, file->ef_structure, file->id);
	sc_log(ctx, "path type %X; path '%s'", file->path.type, sc_print_path(&file->path));

	if (out)
		*out = file;
	else
		sc_file_free(file);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Select a key reference
 */
static int
iasecc_pkcs15_select_key_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file  *file = NULL;
	int rv = 0, idx = key_info->key_reference & ~IASECC_OBJECT_REF_LOCAL;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "'seed' key reference %i; path %s", key_info->key_reference & ~IASECC_OBJECT_REF_LOCAL,
			sc_print_path(&key_info->path));

	rv = sc_select_file(card, &key_info->path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select DF to select key reference in");

	/* 1 <= ObjReference <= 31 */
	if (idx < IASECC_OBJECT_REF_MIN)
		idx = IASECC_OBJECT_REF_MIN;

	/* Look for the suitable slot */
	if (idx <= IASECC_OBJECT_REF_MAX)   {
		struct iasecc_ctl_get_free_reference ctl_data;

		ctl_data.key_size = key_info->modulus_length;
		ctl_data.usage = key_info->usage;
		ctl_data.access = key_info->access_flags;
		ctl_data.index = idx;

		rv = sc_card_ctl(card, SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE, &ctl_data);
		if (!rv)
			sc_log(ctx, "found allocated slot %i", idx);
		else if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND && idx <= IASECC_OBJECT_REF_MAX)
			sc_log(ctx, "found empty slot %i", idx);
		else
			LOG_TEST_RET(ctx, rv, "Cannot select key reference");

		idx = ctl_data.index;
	}

	/* All card objects but PINs are locals */
	key_info->key_reference = idx | IASECC_OBJECT_REF_LOCAL;
	sc_log(ctx, "selected key reference %i", key_info->key_reference);

	if (file)
		sc_file_free(file);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_get_data(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_GET_DATA, sdo);
	LOG_TEST_RET(ctx, rv, "IasEcc: GET DATA error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_file_convert_acls(struct sc_context *ctx, struct sc_profile *profile, struct sc_file *file)
{
	int ii;

	for (ii=0; ii<SC_MAX_AC_OPS;ii++)   {
		/* FIXME the acl object must not be modified, it is only defined in
		 * sc_file_get_acl_entry. Accessing it here means we have a race
		 * condition. */
		struct sc_acl_entry *acl = (struct sc_acl_entry *) sc_file_get_acl_entry(file, ii);

		if (acl)   {
			switch (acl->method)   {
			case SC_AC_IDA:
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "'IDA' not actually supported");
			case SC_AC_SCB:
				if ((acl->key_ref & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_USER_AUTH)   {
					acl->method = SC_AC_SEN;
					acl->key_ref &= IASECC_SCB_METHOD_MASK_REF;
				}
				else if ((acl->key_ref & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_SM)   {
					acl->method = SC_AC_PRO;
					acl->key_ref &= IASECC_SCB_METHOD_MASK_REF;
				}
			}
		}
	}

	return 0;
}

static int
iasecc_sdo_set_key_acls_from_profile(struct sc_profile *profile, struct sc_card *card,
		const char *template, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file  *file = NULL;
	unsigned char ops_prvkey[7] = {
		SC_AC_OP_PSO_COMPUTE_SIGNATURE, SC_AC_OP_INTERNAL_AUTHENTICATE, SC_AC_OP_PSO_DECRYPT,
		SC_AC_OP_GENERATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};
	unsigned char ops_pubkey[7] = {
		0xFF, SC_AC_OP_EXTERNAL_AUTHENTICATE, 0xFF,
		SC_AC_OP_GENERATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};
	unsigned char amb, scb[16], mask;
	int rv, ii, cntr;

	LOG_FUNC_CALLED(ctx);

	/* Get ACLs from profile template */
	rv = sc_profile_get_file(profile, template, &file);
	LOG_TEST_RET(ctx, rv, "IasEcc: cannot instanciate private key file");

	/* Convert PKCS15 ACLs to SE ACLs */
	rv = iasecc_file_convert_acls(ctx, profile, file);
	if (rv < 0 && file)
		sc_file_free(file);
	LOG_TEST_RET(ctx, rv, "Cannot convert profile ACLs");

	memset(scb, 0, sizeof(scb));
	for (ii = 0, mask = 0x80, amb = 0x80, cntr = 0; ii < 7; ii++) {
		const sc_acl_entry_t *acl;
		unsigned char op = sdo->sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE ? ops_prvkey[ii] : ops_pubkey[ii];

		mask >>= 1;

		if (op == 0xFF)
			continue;

		acl = sc_file_get_acl_entry(file, op);
		sc_log(ctx, "ACL: 0x%X:0x%X", acl->method, acl->key_ref);

		if (acl->method == SC_AC_NEVER)   {
		}
		else if (acl->method == SC_AC_NONE)   {
			amb |= mask;
			scb[cntr++] = 0x00;
		}
		else if (acl->method == SC_AC_SEN || acl->method == SC_AC_PRO || acl->method == SC_AC_AUT)   {
			if ((acl->key_ref & 0xF) == 0 || (acl->key_ref & 0xF) == 0xF)   {
				if (file)
					sc_file_free(file);
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SE reference");
			}

			amb |= mask;

			if (acl->method == SC_AC_SEN)
				scb[cntr++] = acl->key_ref | IASECC_SCB_METHOD_USER_AUTH;
			else if (acl->method == SC_AC_PRO)
				scb[cntr++] = acl->key_ref | IASECC_SCB_METHOD_SM;
			else
				scb[cntr++] = acl->key_ref | IASECC_SCB_METHOD_EXT_AUTH;
		}
		else   {
			if (file)
				sc_file_free(file);
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Unknown SCB method");
		}
	}

	if (file)
		sc_file_free(file);

	/* Copy ACLs into the DOCP*/
	sdo->docp.acls_contact.tag = IASECC_DOCP_TAG_ACLS_CONTACT;
	sdo->docp.acls_contact.size = cntr + 1;
	sdo->docp.acls_contact.value = calloc(1, sdo->docp.acls_contact.size);
	if (!sdo->docp.acls_contact.value)
		return SC_ERROR_OUT_OF_MEMORY;
	*(sdo->docp.acls_contact.value + 0) = amb;
	memcpy(sdo->docp.acls_contact.value + 1, scb, cntr);

	sc_log(ctx, "AMB: %X, CNTR %i, %x %x %x %x %x %x",
			amb, cntr, scb[0], scb[1], scb[2], scb[3], scb[4], scb[5], scb[6]);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_allocate_prvkey(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_prkey_info *key_info, struct iasecc_sdo **out)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = NULL;
	size_t sz = key_info->modulus_length / 8;
	int rv;

	LOG_FUNC_CALLED(ctx);

	sdo = calloc(1, sizeof(struct iasecc_sdo));
	if (!sdo)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate 'iasecc_sdo'");

	sdo->magic = SC_CARDCTL_IASECC_SDO_MAGIC;
	sdo->sdo_ref = key_info->key_reference & 0x3F;
	sdo->sdo_class = IASECC_SDO_CLASS_RSA_PRIVATE;
	sdo->usage = key_info->usage;

	sc_log(ctx, "sdo->sdo_class 0x%X; sdo->usage 0x%X", sdo->sdo_class, sdo->usage);

	rv = iasecc_sdo_get_data(card, sdo);
	if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)   {
		sdo->not_on_card = 1;

		rv = iasecc_sdo_set_key_acls_from_profile(profile, card, "private-key", sdo);
		LOG_TEST_RET(ctx, rv, "IasEcc: cannot set ACLs for SDO from the 'private-key'");

		/* FIXME: set here sdo->docp.name and sdo->docp.idata */

		sdo->docp.non_repudiation.value = calloc(1, 1);
		if (!sdo->docp.non_repudiation.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		sdo->docp.non_repudiation.tag = IASECC_DOCP_TAG_NON_REPUDATION;
		sdo->docp.non_repudiation.size = 1;

		sdo->data.prv_key.compulsory.value = calloc(1, 1);
		if (!sdo->data.prv_key.compulsory.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		sdo->data.prv_key.compulsory.tag = IASECC_SDO_PRVKEY_TAG_COMPULSORY;
		sdo->data.prv_key.compulsory.size = 1;

		sdo->docp.size.value = calloc(1, 2);
		if (!sdo->docp.size.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		sdo->docp.size.tag = IASECC_DOCP_TAG_SIZE;
		sdo->docp.size.size = 2;
		*(sdo->docp.size.value + 0) = (sz >> 8) & 0xFF;
		*(sdo->docp.size.value + 1) = sz & 0xFF;
/*
  		FIXME: Manage CRT key types: IASECC_GEN_KEY_TYPE_*: X509_usage
		Optional PRIVATE KEY SDO attribute 'Algorithm to compulsorily use' can have one of the three values:
		0(any usage), B6(Sign), A4(Authentication), B8(Confidentiality).
		If present, this attribute has to be the same in the 'GENERATE KEY' template data.
*/
		if (!(key_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL) && (key_info->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))
			sc_log(ctx, "Non fatal error: NON_REPUDATION can be used only for the localy generated keys");

		if ((key_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL)
				&& (key_info->usage & SC_PKCS15_PRKEY_USAGE_SIGN)
				&& (key_info->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))   {
			*(sdo->docp.non_repudiation.value + 0) = 1;
			*(sdo->data.prv_key.compulsory.value + 0) = IASECC_CRT_TAG_DST;
		}

		sc_log(ctx, "non_repudiation %i", *(sdo->docp.non_repudiation.value + 0));
		sc_log(ctx, "compulsory 0x%X", *(sdo->data.prv_key.compulsory.value + 0));
	}
	else   {
		LOG_TEST_RET(ctx, rv, "IasEcc: error while getting private key SDO data");
	}

	if (out)
		*out = sdo;
	else
		free(sdo);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_allocate_pubkey(struct sc_profile *profile, struct sc_card *card, struct sc_pkcs15_pubkey_info *key_info,
		struct iasecc_sdo **out)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = NULL;
	size_t sz = key_info->modulus_length / 8;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sdo = calloc(1, sizeof(struct iasecc_sdo));
	if (!sdo)
		return SC_ERROR_OUT_OF_MEMORY;

	sdo->magic = SC_CARDCTL_IASECC_SDO_MAGIC;
	sdo->sdo_ref = key_info->key_reference & 0x3F;
	sdo->sdo_class = IASECC_SDO_CLASS_RSA_PUBLIC;

	rv = iasecc_sdo_get_data(card, sdo);
	sc_log(ctx, "get Public Key SDO(class:%X) data returned %i", sdo->sdo_class, rv);
	if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)   {
		sdo->not_on_card = 1;

		rv = iasecc_sdo_set_key_acls_from_profile(profile, card, "public-key", sdo);
		LOG_TEST_RET(ctx, rv, "iasecc_sdo_allocate_pubkey() cannot set ACLs for SDO from the 'public-key'");

		sdo->docp.size.value = calloc(1, 2);
		if (!sdo->docp.size.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		sdo->docp.size.size = 2;
		sdo->docp.size.tag = IASECC_DOCP_TAG_SIZE;
		*(sdo->docp.size.value + 0) = (sz >> 8) & 0xFF;
		*(sdo->docp.size.value + 1) = sz & 0xFF;

		if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)   {
			/* TODO: Disabled for the tests of the Oberthur card */
		}
		else   {
			sdo->data.pub_key.cha.value = calloc(1, 2);
			if (!sdo->data.pub_key.cha.value)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			sdo->data.pub_key.cha.size = 2;
			sdo->data.pub_key.cha.tag = IASECC_SDO_PUBKEY_TAG_CHA;
		}

		sdo->data.pub_key.compulsory.value = calloc(1, 1);
		if (!sdo->data.pub_key.compulsory.value)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		sdo->data.pub_key.compulsory.tag = IASECC_SDO_PUBKEY_TAG_COMPULSORY;
		sdo->data.pub_key.compulsory.size = 1;
	}
	else   {
		LOG_TEST_RET(ctx, rv, "iasecc_sdo_allocate_pubkey() error while getting public key SDO data");
	}

	if (out)
		*out = sdo;
	else
		free(sdo);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_convert_to_file(struct sc_card *card, struct iasecc_sdo *sdo, struct sc_file **out)
{
	struct sc_context *ctx;
	struct sc_file *file;
	unsigned ii;
	int rv;

	if (!card || !sdo)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	file = sc_file_new();
	if (!file)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	sc_log(ctx, "SDO class 0x%X", sdo->sdo_class);

	if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		unsigned char ops[] = {
			SC_AC_OP_PSO_COMPUTE_SIGNATURE, SC_AC_OP_INTERNAL_AUTHENTICATE, SC_AC_OP_PSO_DECRYPT,
			SC_AC_OP_GENERATE, SC_AC_OP_UPDATE, SC_AC_OP_READ
		};

		for (ii=0; ii<sizeof(ops)/sizeof(ops[0]);ii++)   {
			unsigned op_method, op_ref;

			rv = iasecc_sdo_convert_acl(card, sdo, ops[ii], &op_method, &op_ref);
			if (rv < 0)   {
				sc_file_free(file);
				LOG_TEST_RET(ctx, rv, "IasEcc: cannot convert ACL");
			}

			sc_log(ctx, "ii:%i, method:%X, ref:%X", ii, op_method, op_ref);
			sc_file_add_acl_entry(file, ops[ii], op_method, op_ref);
		}
	}

	if (out)
		*out = file;
	else
		sc_file_free(file);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_pkcs15_add_access_rule(struct sc_pkcs15_object *object, unsigned access_mode, struct sc_pkcs15_id *auth_id)
{
	int ii;

	for (ii=0;ii<SC_PKCS15_MAX_ACCESS_RULES;ii++)   {
		if (!object->access_rules[ii].access_mode)   {
			object->access_rules[ii].access_mode = access_mode;
			if (auth_id)
				object->access_rules[ii].auth_id = *auth_id;
			else
				object->access_rules[ii].auth_id.len = 0;
			break;
		}
		else if (!auth_id && !object->access_rules[ii].auth_id.len)   {
			object->access_rules[ii].access_mode |= access_mode;
			break;
		}
		else if (auth_id && sc_pkcs15_compare_id(&object->access_rules[ii].auth_id, auth_id))   {
			object->access_rules[ii].access_mode |= access_mode;
			break;
		}
	}

	if (ii==SC_PKCS15_MAX_ACCESS_RULES)
		return SC_ERROR_TOO_MANY_OBJECTS;

	return SC_SUCCESS;
}


static int
iasecc_pkcs15_get_auth_id_from_se(struct sc_pkcs15_card *p15card, unsigned char scb,
		struct sc_pkcs15_id *auth_id)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pin_objs[32];
	int rv, ii, nn_pins, se_ref, pin_ref;

	LOG_FUNC_CALLED(ctx);
	if (!auth_id)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(auth_id, 0, sizeof(struct sc_pkcs15_id));

	if (!(scb & IASECC_SCB_METHOD_USER_AUTH))
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pin_objs, 32);
	LOG_TEST_RET(ctx, rv, "Error while getting AUTH objects");
	nn_pins = rv;

	se_ref = scb & 0x0F;
	rv = sc_card_ctl(p15card->card, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, (void *)(&se_ref));
	LOG_TEST_RET(ctx, rv, "Card CTL error: cannot get CHV reference from SE");
	pin_ref = rv;
	for (ii=0; ii<nn_pins; ii++)   {
		const struct sc_pkcs15_auth_info *auth_info = (const struct sc_pkcs15_auth_info *) pin_objs[ii]->data;

		if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			continue;

		sc_log(ctx, "PIN refs %i/%i", pin_ref, auth_info->attrs.pin.reference);
		if (pin_ref == ((auth_info->attrs.pin.reference + 0x100) % 0x100))   {
			*auth_id = auth_info->auth_id;
			break;
		}
	}
	if (ii == nn_pins)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "No AUTH object found");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_pkcs15_fix_file_access_rule(struct sc_pkcs15_card *p15card, struct sc_file *file,
		unsigned ac_op, unsigned rule_mode, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	const struct sc_acl_entry *acl = NULL;
	struct sc_pkcs15_id id;
	unsigned ref;
	int rv;

	LOG_FUNC_CALLED(ctx);
	acl = sc_file_get_acl_entry(file, ac_op);
	sc_log(ctx, "Fix file access rule: AC_OP:%i, ACL(method:0x%X,ref:0x%X)", ac_op, acl->method, acl->key_ref);
	if (acl->method == SC_AC_NONE)   {
		sc_log(ctx, "rule-mode:0x%X, auth-ID:NONE", rule_mode);
		rv = iasecc_pkcs15_add_access_rule(object, rule_mode, NULL);
		LOG_TEST_RET(ctx, rv, "Fix file access rule error");
	}
	else   {
		if (acl->method == SC_AC_IDA)   {
			ref = acl->key_ref;
			iasecc_reference_to_pkcs15_id (ref, &id);
		}
		else if (acl->method == SC_AC_SCB)   {
			rv = iasecc_pkcs15_get_auth_id_from_se(p15card, acl->key_ref, &id);
			LOG_TEST_RET(ctx, rv, "Cannot get AUTH.ID from SE");
		}
		else if (acl->method == SC_AC_PRO)   {
			ref = IASECC_SCB_METHOD_SM * 0x100 + acl->key_ref;
			iasecc_reference_to_pkcs15_id (ref, &id);
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Fix file access error");
		}

		sc_log(ctx, "rule-mode:0x%X, auth-ID:%s", rule_mode, sc_pkcs15_print_id(&id));
		rv = iasecc_pkcs15_add_access_rule(object, rule_mode, &id);
		LOG_TEST_RET(ctx, rv, "Fix file access rule error");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_pkcs15_fix_file_access(struct sc_pkcs15_card *p15card, struct sc_file *file,
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "authID %s", sc_pkcs15_print_id(&object->auth_id));

	memset(object->access_rules, 0, sizeof(object->access_rules));

	rv = iasecc_pkcs15_fix_file_access_rule(p15card, file, SC_AC_OP_READ, SC_PKCS15_ACCESS_RULE_MODE_READ, object);
	LOG_TEST_RET(ctx, rv, "Fix file READ access error");

	rv = iasecc_pkcs15_fix_file_access_rule(p15card, file, SC_AC_OP_UPDATE, SC_PKCS15_ACCESS_RULE_MODE_UPDATE, object);
	LOG_TEST_RET(ctx, rv, "Fix file READ access error");

	rv = iasecc_pkcs15_fix_file_access_rule(p15card, file, SC_AC_OP_DELETE, SC_PKCS15_ACCESS_RULE_MODE_DELETE, object);
	LOG_TEST_RET(ctx, rv, "Fix file READ access error");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_pkcs15_encode_supported_algos(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_supported_algo_info *algo;
	int rv = SC_SUCCESS, ii;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "encode supported algos for object(%s,type:%X)", object->label, object->type);
	switch (object->type)   {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		sc_log(ctx, "PrKey Usage:%X,Access:%X", prkey_info->usage, prkey_info->access_flags);
		if (prkey_info->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP))   {
			algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_DECIPHER, CKM_RSA_PKCS);
			rv = sc_pkcs15_add_supported_algo_ref(object, algo);
			LOG_TEST_RET(ctx, rv, "cannot add supported algorithm DECIPHER:CKM_RSA_PKCS");
		}

		if (prkey_info->usage & SC_PKCS15_PRKEY_USAGE_SIGN)   {
			if (prkey_info->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)   {
				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA1_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOG_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_SHA1_RSA_PKCS");

				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA256_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOG_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_SHA256_RSA_PKCS");
			}
			else   {
				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOG_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_RSA_PKCS");
			}
		}

		for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS && prkey_info->algo_refs[ii]; ii++)
			sc_log(ctx, "algoReference %i", prkey_info->algo_refs[ii]);
		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Store SDO key RSA
 */
static int
iasecc_sdo_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct iasecc_sdo *sdo_prvkey, struct iasecc_sdo *sdo_pubkey,
		struct sc_pkcs15_prkey_rsa *rsa)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	unsigned long caps = card->caps;
	struct iasecc_sdo_rsa_update update;
	struct sc_file	*dummy_file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!sdo_prvkey && !sdo_pubkey)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "At least one SDO has to be supplied");

	rv = iasecc_sdo_convert_to_file(card, sdo_prvkey ? sdo_prvkey : sdo_pubkey, &dummy_file);
	LOG_TEST_RET(ctx, rv, "Cannot convert SDO PRIVATE KEY to file");

	card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, dummy_file, SC_AC_OP_UPDATE);
	card->caps = caps;
	if (dummy_file)
		sc_file_free(dummy_file);

	LOG_TEST_RET(ctx, rv, "SDO PRIVATE KEY UPDATE authentication failed");

	memset(&update, 0, sizeof(update));

	update.sdo_prv_key = sdo_prvkey;
	update.sdo_pub_key = sdo_pubkey;
	update.p15_rsa = rsa;
	update.magic = IASECC_SDO_MAGIC_UPDATE_RSA;

	rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA, &update);
	LOG_TEST_RET(ctx, rv, "store IAS SDO PRIVATE KEY failed");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15_add_algorithm_reference(struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info, unsigned algo_ref)
{
	int ii, jj;

	for (jj=0;jj<SC_MAX_SUPPORTED_ALGORITHMS && key_info->algo_refs[jj];jj++)
		;
	if (jj == SC_MAX_SUPPORTED_ALGORITHMS)
		return SC_ERROR_TOO_MANY_OBJECTS;

	for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS;ii++)
		if (p15card->tokeninfo->supported_algos[ii].algo_ref == algo_ref)
			break;
	if (ii == SC_MAX_SUPPORTED_ALGORITHMS)
		return SC_ERROR_OBJECT_NOT_FOUND;

	key_info->algo_refs[jj] = p15card->tokeninfo->supported_algos[ii].reference;
	return SC_SUCCESS;
}


static int
iasecc_pkcs15_fix_private_key_attributes(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
					struct sc_pkcs15_object *object,
					struct iasecc_sdo *sdo_prvkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	int rv = 0, ii;
	unsigned keys_access_modes[IASECC_MAX_SCBS] = {
		SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS, SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH, SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT,
		SC_PKCS15_ACCESS_RULE_MODE_EXECUTE, 0x00, SC_PKCS15_ACCESS_RULE_MODE_UPDATE, SC_PKCS15_ACCESS_RULE_MODE_READ
	};

	LOG_FUNC_CALLED(ctx);
	if (!object->content.value || object->content.len != sizeof(struct iasecc_sdo))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "store IAS SDO PRIVATE KEY failed");

	if (object->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported object type");

	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_SENSITIVE;

	sc_log(ctx, "SDO(class:%X,ref:%X,usage:%X)",
			sdo_prvkey->sdo_class, sdo_prvkey->sdo_ref, sdo_prvkey->usage);
	sc_log(ctx, "SDO ACLs(%i):%s", sdo_prvkey->docp.acls_contact.size,
			sc_dump_hex(sdo_prvkey->docp.acls_contact.value, sdo_prvkey->docp.acls_contact.size));
	sc_log(ctx, "SDO AMB:%X, SCBS:%s", sdo_prvkey->docp.amb,
			sc_dump_hex(sdo_prvkey->docp.scbs, IASECC_MAX_SCBS));

	for (ii=0;ii<IASECC_MAX_SCBS;ii++)   {
		sc_log(ctx, "SBC(%i):%X", ii, sdo_prvkey->docp.scbs[ii]);
		if (sdo_prvkey->docp.scbs[ii] == 0xFF)   {
			continue;
		}
		else if (sdo_prvkey->docp.scbs[ii] == 0x00)   {
			rv = iasecc_pkcs15_add_access_rule(object, keys_access_modes[ii], NULL);
			LOG_TEST_RET(ctx, rv, "Cannot add access rule");
		}
		else if (sdo_prvkey->docp.scbs[ii] & IASECC_SCB_METHOD_USER_AUTH)   {
			struct sc_pkcs15_id auth_id;

			rv = iasecc_pkcs15_get_auth_id_from_se(p15card, sdo_prvkey->docp.scbs[ii], &auth_id);
			LOG_TEST_RET(ctx, rv, "Cannot get AUTH.ID from SE");

			rv = iasecc_pkcs15_add_access_rule(object, keys_access_modes[ii], &auth_id);
			LOG_TEST_RET(ctx, rv, "Cannot add access rule");

			if (ii == IASECC_ACLS_RSAKEY_PSO_SIGN || ii == IASECC_ACLS_RSAKEY_INTERNAL_AUTH
					|| ii == IASECC_ACLS_RSAKEY_PSO_DECIPHER)   {
				if (!sc_pkcs15_compare_id(&object->auth_id, &auth_id))   {
					/* Sorry, this will silently overwrite the profile option.*/
					sc_log(ctx, "Change object's authId for the one that really protects crypto operation.");
					object->auth_id = auth_id;
				}

				rv = iasecc_pkcs15_add_access_rule(object, SC_PKCS15_ACCESS_RULE_MODE_EXECUTE, &auth_id);
				LOG_TEST_RET(ctx, rv, "Cannot add 'EXECUTE' access rule");
			}
		}

		if (ii == IASECC_ACLS_RSAKEY_PSO_SIGN)   {
			rv = iasecc_pkcs15_add_algorithm_reference(p15card, key_info,
					IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1);
			LOG_TEST_RET(ctx, rv, "Cannot add RSA_PKCS SHA1 supported mechanism");

			rv = iasecc_pkcs15_add_algorithm_reference(p15card, key_info,
					IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA2);
			LOG_TEST_RET(ctx, rv, "Cannot add RSA_PKCS SHA2 supported mechanism");

			if (sdo_prvkey->docp.non_repudiation.value && sdo_prvkey->docp.non_repudiation.value[0])   {
				object->user_consent = 1;
			}
		}
		else if (ii == IASECC_ACLS_RSAKEY_INTERNAL_AUTH)   {
			rv = iasecc_pkcs15_add_algorithm_reference(p15card, key_info, IASECC_ALGORITHM_RSA_PKCS);
			LOG_TEST_RET(ctx, rv, "Cannot add RSA_PKCS supported mechanism");

		}
		else if (ii == IASECC_ACLS_RSAKEY_PSO_DECIPHER)   {
			rv = iasecc_pkcs15_add_algorithm_reference(p15card, key_info,
					IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1);
			LOG_TEST_RET(ctx, rv, "Cannot add decipher RSA_PKCS supported mechanism");

		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15_create_key_slot(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct iasecc_sdo *sdo_prvkey, struct iasecc_sdo *sdo_pubkey,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file  *file_p_pubkey = NULL, *file_p_prvkey = NULL, *parent = NULL;
	unsigned long save_card_caps = p15card->card->caps;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = iasecc_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file_p_prvkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot instantiate PRKEY_RSA file");

	rv = iasecc_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_PUBKEY_RSA, key_info->key_reference, &file_p_pubkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot instantiate PUBKEY_RSA file");

	rv = iasecc_file_convert_acls(ctx, profile, file_p_prvkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot convert ACLs of the private key file");

	rv = iasecc_file_convert_acls(ctx, profile, file_p_pubkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot convert ACLs of the public key file");

	rv = sc_profile_get_parent(profile, "private-key", &parent);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot get parent of private key file");

	rv = iasecc_file_convert_acls(ctx, profile, parent);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot convert parent's ACLs");

	/* Oberthur's card do not returns FCP for selected application DF.
	 * That's why for the following authentication use the 'CREATE' ACL defined in the application profile. */
	if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)
		p15card->card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_CREATE);
	p15card->card->caps  = save_card_caps;
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: SC_AC_OP_CREATE authentication failed");

	if (!sdo_prvkey->not_on_card)
		sc_log(ctx, "create key slot: SDO private key already present");
	else
		rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_CREATE, sdo_prvkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot create private key: ctl failed");

	if (!sdo_pubkey->not_on_card)
		sc_log(ctx, "create key slot: SDO public key already present");
	else
		rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_CREATE, sdo_pubkey);
	LOG_TEST_GOTO_ERR(ctx, rv, "create key slot: cannot create public key: ctl failed");

err:
	if (file_p_prvkey)
		sc_file_free(file_p_prvkey);
	if (file_p_pubkey)
		sc_file_free(file_p_pubkey);
	if (parent)
		sc_file_free(parent);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_pkcs15_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
					struct sc_pkcs15_object *object)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct iasecc_sdo *sdo_prvkey = NULL, *sdo_pubkey = NULL;
	size_t keybits = key_info->modulus_length;
	unsigned char zeros[0x200];
	int	 rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "create private key(keybits:%i,usage:%X,access:%X,ref:%X)",
			keybits, key_info->usage, key_info->access_flags, key_info->key_reference);
	if (keybits < 1024 || keybits > 2048 || (keybits % 256))   {
		sc_log(ctx, "Unsupported key size %u", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(zeros, 0, sizeof(zeros));

	rv = iasecc_sdo_allocate_pubkey(profile, card, (struct sc_pkcs15_pubkey_info *)key_info, &sdo_pubkey);
	LOG_TEST_RET(ctx, rv, "IasEcc: allocate SDO public key failed");
	sc_log(ctx, "iasecc_pkcs15_create_key() sdo_pubkey->not_on_card %i", sdo_pubkey->not_on_card);

	rv = iasecc_sdo_allocate_prvkey(profile, card, key_info, &sdo_prvkey);
	LOG_TEST_RET(ctx, rv, "IasEcc: init SDO private key failed");
	sc_log(ctx, "iasecc_pkcs15_create_key() sdo_prvkey->not_on_card %i", sdo_prvkey->not_on_card);

	if (!sdo_prvkey->not_on_card && !sdo_pubkey->not_on_card)   {
		sc_log(ctx, "Key ref %i already allocated", key_info->key_reference);
	}
	else   {
		rv = iasecc_pkcs15_create_key_slot(profile, p15card, sdo_prvkey, sdo_pubkey, key_info);
		LOG_TEST_RET(ctx, rv, "Cannot create key slot");
	}

	rv = sc_pkcs15_allocate_object_content(ctx, object, (unsigned char *)sdo_prvkey, sizeof(struct iasecc_sdo));
	LOG_TEST_RET(ctx, rv, "Failed to allocate PrvKey SDO as object content");

	rv = iasecc_pkcs15_fix_private_key_attributes(profile, p15card, object, (struct iasecc_sdo *)object->content.value);
	LOG_TEST_RET(ctx, rv, "Failed to fix private key PKCS#15 attributes");

	key_info->path.len = 0;

	iasecc_sdo_free(card, sdo_pubkey);

	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * RSA key generation
 */
static int
iasecc_pkcs15_generate_key(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct iasecc_sdo *sdo_prvkey = NULL;
	struct iasecc_sdo *sdo_pubkey = NULL;
	struct sc_file	*file = NULL;
	unsigned char *tmp = NULL;
	size_t tmp_len;
	unsigned long caps;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "generate key(bits:%i,path:%s,AuthID:%s\n", keybits,
			sc_print_path(&key_info->path), sc_pkcs15_print_id(&object->auth_id));

	if (!object->content.value || object->content.len != sizeof(struct iasecc_sdo))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid PrKey SDO data");

	sdo_prvkey = (struct iasecc_sdo *)object->content.value;
	if (sdo_prvkey->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "'Magic' control failed for SDO PrvKey");

	if (keybits < 1024 || keybits > 2048 || (keybits%0x100))   {
		sc_log(ctx, "Unsupported key size %u\n", keybits);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* TODO: Check if native IAS middleware accepts the meaningfull path value. */
	rv = sc_profile_get_parent(profile, "private-key", &file);
	LOG_TEST_RET(ctx, rv, "IasEcc: cannot get private key parent file");

	rv = sc_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "DF for private objects not defined");

	if (file)
		sc_file_free(file);

	rv = iasecc_sdo_convert_to_file(card, sdo_prvkey, &file);
	LOG_TEST_RET(ctx, rv, "Cannot convert SDO PRIVKEY to file");

	caps = card->caps;
	card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_GENERATE);
	card->caps = caps;
	LOG_TEST_RET(ctx, rv, "SC_AC_OP_GENERATE authentication failed");

	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_LOCAL;
	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE;
	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;

	rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_GENERATE, sdo_prvkey);
	LOG_TEST_RET(ctx, rv, "generate key failed");

	/* Quite dangerous -- cast of 'sc_pkcs15_prvkey_info' into 'sc_pkcs15_pubkey_info'. */
	rv = iasecc_sdo_allocate_pubkey(profile, card, (struct sc_pkcs15_pubkey_info *)key_info, &sdo_pubkey);
	LOG_TEST_RET(ctx, rv, "IasEcc: allocate SDO public key failed");

	pubkey->algorithm = SC_ALGORITHM_RSA;

	pubkey->u.rsa.modulus.len = sdo_pubkey->data.pub_key.n.size;
	pubkey->u.rsa.modulus.data  = (unsigned char *) malloc(pubkey->u.rsa.modulus.len);
	if (!pubkey->u.rsa.modulus.data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(pubkey->u.rsa.modulus.data, sdo_pubkey->data.pub_key.n.value, pubkey->u.rsa.modulus.len);

	pubkey->u.rsa.exponent.len = sdo_pubkey->data.pub_key.e.size;
	pubkey->u.rsa.exponent.data = (unsigned char *) malloc(pubkey->u.rsa.exponent.len);
	if (!pubkey->u.rsa.exponent.data)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memcpy(pubkey->u.rsa.exponent.data, sdo_pubkey->data.pub_key.e.value, pubkey->u.rsa.exponent.len);

	rv = sc_pkcs15_encode_pubkey(ctx, pubkey, &tmp, &tmp_len);
	LOG_TEST_RET(ctx, rv, "encode public key failed");

	rv = iasecc_pkcs15_encode_supported_algos(p15card, object);
	LOG_TEST_RET(ctx, rv, "encode private key access rules failed");

	/* SDO PrvKey data replaced by public part of generated key */
	rv = sc_pkcs15_allocate_object_content(ctx, object, tmp, tmp_len);
	LOG_TEST_RET(ctx, rv, "Failed to allocate public key as object content");

	iasecc_sdo_free(card, sdo_pubkey);

	free(tmp);
	LOG_FUNC_RETURN(ctx, rv);
}


/*
 * Store a private key
 */
static int
iasecc_pkcs15_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey *prvkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct iasecc_sdo *sdo_prvkey;
	struct iasecc_sdo *sdo_pubkey = NULL;
	struct sc_pkcs15_prkey_rsa *rsa = &prvkey->u.rsa;
	struct sc_file	*file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Store IAS/ECC key(keybits:%i,AuthID:%s,path:%s)",
			keybits, sc_pkcs15_print_id(&object->auth_id), sc_print_path(&key_info->path));

	if (!object->content.value || object->content.len != sizeof(struct iasecc_sdo))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid PrKey SDO data");
	else if (keybits < 1024 || keybits > 2048 || (keybits%0x100))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unsupported key size");

	sdo_prvkey = (struct iasecc_sdo *)object->content.value;
	if (sdo_prvkey->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "'Magic' control failed for SDO PrvKey");

	sc_log(ctx, "key compulsory attr(size:%i,on_card:%i)",
			sdo_prvkey->data.prv_key.compulsory.size, sdo_prvkey->data.prv_key.compulsory.on_card);

	rv = sc_profile_get_parent(profile, "private-key", &file);
	LOG_TEST_RET(ctx, rv, "cannot instantiate parent DF of the private key");

	rv = sc_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "failed to select parent DF");

	if (file)
		sc_file_free(file);

	key_info->access_flags &= ~SC_PKCS15_PRKEY_ACCESS_LOCAL;

	rv = iasecc_sdo_allocate_pubkey(profile, card, (struct sc_pkcs15_pubkey_info *)key_info, &sdo_pubkey);
	LOG_TEST_RET(ctx, rv, "private key store failed: cannot allocate 'SDO PUBLIC KEY'");

	rv = iasecc_sdo_store_key(profile, p15card, sdo_prvkey, sdo_pubkey, rsa);
	LOG_TEST_RET(ctx, rv, "cannot store SDO PRIVATE/PUBLIC KEYs");

	/* sdo_prvkey is freed while object is freeing */
	iasecc_sdo_free(card, sdo_pubkey);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15_delete_sdo (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		int sdo_class, int ref)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct iasecc_sdo *sdo = NULL;
	struct sc_pkcs15_prkey_rsa rsa;
	struct sc_file  *dummy_file = NULL;
	unsigned long save_card_caps = card->caps;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pkcs15_delete_sdo() class 0x%X; reference %i", sdo_class, ref);

	sdo = calloc(1, sizeof(struct iasecc_sdo));
	if (!sdo)
		return SC_ERROR_OUT_OF_MEMORY;

	sdo->magic = SC_CARDCTL_IASECC_SDO_MAGIC;
	sdo->sdo_class = sdo_class;
	sdo->sdo_ref = ref & 0x3F;

	rv = iasecc_sdo_get_data(card, sdo);
	if (rv < 0)   {
		if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)
			rv = SC_SUCCESS;

		iasecc_sdo_free(card, sdo);
		LOG_FUNC_RETURN(ctx, rv);
	}

	if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PUBLIC)   {
		if (sdo->data.pub_key.cha.value)   {
			free(sdo->data.pub_key.cha.value);
			sdo->data.pub_key.cha.value = NULL;
			sdo->data.pub_key.cha.size = 0;
		}
	}

	sc_log(ctx, "iasecc_pkcs15_delete_sdo() SDO class 0x%X, ref 0x%X", sdo->sdo_class, sdo->sdo_ref);
	rv = iasecc_sdo_convert_to_file(card, sdo, &dummy_file);
	if (rv < 0)   {
		iasecc_sdo_free(card, sdo);
		LOG_TEST_RET(ctx, rv, "iasecc_pkcs15_delete_sdo() Cannot convert SDO to file");
	}

	card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, dummy_file, SC_AC_OP_UPDATE);
	card->caps = save_card_caps;

	if (dummy_file)
		sc_file_free(dummy_file);

	if (rv < 0)   {
		iasecc_sdo_free(card, sdo);
		LOG_TEST_RET(ctx, rv, "iasecc_pkcs15_delete_sdo() UPDATE authentication failed for SDO");
	}

	if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)   {
		/* Oberthur's card supports creation/deletion of the key slots ... */
		rv = sc_card_ctl(card, SC_CARDCTL_IASECC_SDO_DELETE, sdo);
	}
	else  {
		/* ... other cards not.
		 * Set to zero the key components . */
		unsigned char zeros[0x200];
		int size = *(sdo->docp.size.value + 0) * 0x100 + *(sdo->docp.size.value + 1);

		sc_log(ctx, "iasecc_pkcs15_delete_sdo() SDO size %i bytes", size);
		memset(zeros, 0xA5, sizeof(zeros));
		memset(&rsa, 0, sizeof(rsa));

		rsa.modulus.data = rsa.exponent.data = zeros;
		rsa.modulus.len = size;
		rsa.exponent.len = 3;

		rsa.p.data = rsa.q.data = rsa.iqmp.data = rsa.dmp1.data = rsa.dmq1.data = zeros;
		rsa.p.len = rsa.q.len = rsa.iqmp.len = rsa.dmp1.len = rsa.dmq1.len = size/2;

		/* Don't know why, but, clean public key do not working with Gemalto card */
		rv = iasecc_sdo_store_key(profile, p15card, sdo, NULL, &rsa);
	}

	iasecc_sdo_free(card, sdo);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pkcs15_delete_object (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	int rv, key_ref;

	LOG_FUNC_CALLED(ctx);

	switch(object->type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PUBKEY:
		key_ref = ((struct sc_pkcs15_pubkey_info *)object->data)->key_reference;
		sc_log(ctx, "Ignore delete of SDO-PubKey(ref:%X) '%s', path %s", key_ref, object->label, sc_print_path(path));
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	case SC_PKCS15_TYPE_PRKEY:
		sc_log(ctx, "delete PrivKey '%s', path %s", object->label, sc_print_path(path));
		if (path->len || path->aid.len)   {
			rv = sc_select_file(p15card->card, path, NULL);
			LOG_TEST_RET(ctx, rv, "cannot select PrivKey path");
		}

		key_ref = ((struct sc_pkcs15_prkey_info *)object->data)->key_reference;

		/* Delete both parts of the RSA key */
		rv = iasecc_pkcs15_delete_sdo (profile, p15card, IASECC_SDO_CLASS_RSA_PRIVATE, key_ref);
		LOG_TEST_RET(ctx, rv, "Cannot delete RSA_PRIVATE SDO");

		rv = iasecc_pkcs15_delete_sdo (profile, p15card, IASECC_SDO_CLASS_RSA_PUBLIC, key_ref);
		LOG_TEST_RET(ctx, rv, "Cannot delete RSA_PUBLIC SDO");

		if (profile->md_style == SC_PKCS15INIT_MD_STYLE_GEMALTO)   {
			rv = iasecc_md_gemalto_delete_prvkey(p15card, profile, object);
			LOG_TEST_RET(ctx, rv, "MD error: cannot delete private key");
		}

		LOG_FUNC_RETURN(ctx, rv);
	case SC_PKCS15_TYPE_CERT:
		sc_log(ctx, "delete Certificate '%s', path %s", object->label, sc_print_path(path));
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		sc_log(ctx, "delete DataObject '%s', path %s", object->label, sc_print_path(path));
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	file = sc_file_new();
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->id = path->value[path->len-2] * 0x100 + path->value[path->len-1];
	memcpy(&file->path, path, sizeof(file->path));

	rv = iasecc_pkcs15_delete_file(p15card, profile, file);

	sc_file_free(file);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_md_gemalto_set_default(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *key_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *data_obj = NULL;
	struct sc_pkcs15init_dataargs data_args;
	unsigned char guid[40];
	size_t guid_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_find_data_object_by_name(p15card, "CSP", "Default Key Container", &data_obj);
	if (rv != SC_ERROR_OBJECT_NOT_FOUND)
		LOG_TEST_RET(ctx, rv, "Find 'Default Key Container' data object error");

	memset(guid, 0, sizeof(guid));
	guid_len = sizeof(guid);

	rv = sc_pkcs15_get_object_guid(p15card, key_obj, 1, guid, &guid_len);
	LOG_TEST_RET(ctx, rv, "Cannot get private key GUID");

	if (!data_obj)   {
		memset(&data_args, 0, sizeof(data_args));
		sc_init_oid(&data_args.app_oid);
		data_args.label = "Default Key Container";
		data_args.app_label = "CSP";
		data_args.der_encoded.value = guid;
		data_args.der_encoded.len = guid_len;

		rv = sc_pkcs15init_store_data_object(p15card, profile, &data_args, NULL);
		LOG_TEST_RET(ctx, rv, "Failed to store 'CSP'/'Default Key Container' data object");
	}
	else   {
		struct sc_pkcs15_data_info *dinfo = (struct sc_pkcs15_data_info *)data_obj->data;
		struct sc_file *file = NULL;

		sc_log(ctx, "update data object content in '%s'\n", sc_print_path(&dinfo->path));
		rv = sc_select_file(p15card->card, &dinfo->path, &file);
		LOG_TEST_RET(ctx, rv, "Cannot select data object file");

		rv = sc_pkcs15init_update_file(profile, p15card, file, guid, guid_len);
		sc_file_free(file);
		LOG_TEST_RET(ctx, rv, "Failed to update 'CSP'/'Default Key Container' data object");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_md_gemalto_unset_default(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *key_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *data_obj = NULL;
	struct sc_pkcs15_data *dod = NULL;
	struct sc_pkcs15_object *key_objs[32];
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
	unsigned char guid[40];
	size_t guid_len;
	int rv, ii, keys_num;

	LOG_FUNC_CALLED(ctx);

	memset(guid, 0, sizeof(guid));
	guid_len = sizeof(guid);

	rv = sc_pkcs15_get_object_guid(p15card, key_obj, 1, guid, &guid_len);
	LOG_TEST_RET(ctx, rv, "Cannot get private key GUID");

	rv = sc_pkcs15_find_data_object_by_name(p15card, "CSP", "Default Key Container", &data_obj);
	if (rv == SC_ERROR_OBJECT_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_read_data_object(p15card, (struct sc_pkcs15_data_info *)data_obj->data, &dod);
	LOG_TEST_RET(ctx, rv, "Cannot read from 'CSP/'Default Key Container'");

	if (guid_len != dod->data_len || memcmp(guid, dod->data, guid_len))
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, key_objs, 32);
	LOG_TEST_RET(ctx, rv, "Get private key PKCS#15 objects error");
	keys_num = rv;

	if (keys_num)   {
		for (ii=0; ii<keys_num; ii++)   {
			struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_objs[ii]->data;

			if (sc_pkcs15_compare_id(&key_info->id, &prkey_info->id))
				continue;

			/* TODO: keys with inappropriate key usages should also be ignored */
			rv = iasecc_md_gemalto_set_default(p15card, profile, key_objs[ii]);
			LOG_TEST_RET(ctx, rv, "Cannot set default container");
			break;
		}

		if (ii == keys_num)   {
			/* No more default container */
			rv = sc_pkcs15init_delete_object(p15card, profile, data_obj);
			LOG_TEST_RET(ctx, rv, "Cannot delete 'CSP'/'Default Key Container' data object");
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_md_gemalto_new_prvkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *key_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
	struct sc_pkcs15init_dataargs data_args;
	unsigned char data[SC_PKCS15_MAX_ID_SIZE + 6];
	unsigned char guid[40];
	size_t offs, guid_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(guid, 0, sizeof(guid));
	guid_len = sizeof(guid) - 1;

	rv = sc_pkcs15_get_object_guid(p15card, key_obj, 1, guid, &guid_len);
	LOG_TEST_RET(ctx, rv, "Cannot get private key GUID");
	sc_log(ctx, "New key GUID: '%s'", (char *)guid);

	offs = 0;
	data[offs++] = 0x01;
	data[offs++] = prkey_info->id.len;
	memcpy(&data[offs], prkey_info->id.value, prkey_info->id.len);
	offs += prkey_info->id.len;
	data[offs++] = 0x02;
	data[offs++] = 0x01;
	data[offs++] = 0x01;

	memset(&data_args, 0, sizeof(data_args));
	sc_init_oid(&data_args.app_oid);
	data_args.label = (char *)guid;
	data_args.app_label = "CSP";
	data_args.der_encoded.value = data;
	data_args.der_encoded.len = offs;

	rv = sc_pkcs15init_store_data_object(p15card, profile, &data_args, NULL);
	LOG_TEST_RET(ctx, rv, "Failed to store 'CSP' data object");

	/* For a while default container is set for the first key.
	 * TODO: Key usage should be taken into consideration. */
	if (sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0) == 1)   {
		rv = iasecc_md_gemalto_set_default(p15card, profile, key_obj);
		LOG_TEST_RET(ctx, rv, "MD: cannot set default container");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_md_gemalto_delete_prvkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *key_obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *data_obj = NULL;
	unsigned char guid[40];
	size_t guid_len;
	int rv;

	LOG_FUNC_CALLED(ctx);

	memset(guid, 0, sizeof(guid));
	guid_len = sizeof(guid) - 1;

	rv = sc_pkcs15_get_object_guid(p15card, key_obj, 1, guid, &guid_len);
	LOG_TEST_RET(ctx, rv, "Cannot get private key GUID");

	rv = sc_pkcs15_find_data_object_by_name(p15card, "CSP", (char *)guid, &data_obj);
	if (rv == SC_ERROR_OBJECT_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, rv, "Find 'CSP'/<key> data object error");

	rv = sc_pkcs15init_delete_object(p15card, profile, data_obj);
	LOG_TEST_RET(ctx, rv, "Cannot delete 'CSP'/<key> data object");

	/* For a while default container is set for the first key.
	 * TODO: Key usage should be taken into consideration. */
	if (sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, NULL, 0) == 1)   {
		rv = iasecc_md_gemalto_unset_default(p15card, profile, key_obj);
		LOG_TEST_RET(ctx, rv, "MD: cannot set default container");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_store_prvkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)object->data;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Private Key id '%s'", sc_pkcs15_print_id(&prkey_info->id));
	sc_log(ctx, "MD style '0x%X'", profile->md_style);

	if (profile->md_style == SC_PKCS15INIT_MD_STYLE_NONE)   {
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}
	else if (profile->md_style == SC_PKCS15INIT_MD_STYLE_GEMALTO)   {
		int rv = iasecc_md_gemalto_new_prvkey(p15card, profile, object);
		LOG_TEST_RET(ctx, rv, "MD: cannot add new key");
	}
	else   {
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported MD style");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_store_pubkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *pubkey_info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Public Key id '%s'", sc_pkcs15_print_id(&pubkey_info->id));

	rv = sc_pkcs15_find_prkey_by_id(p15card, &pubkey_info->id, &prkey_object);
	LOG_TEST_RET(ctx, rv, "Find related PrKey error");

	prkey_info = (struct sc_pkcs15_prkey_info *)prkey_object->data;

	pubkey_info->key_reference = prkey_info->key_reference;

	pubkey_info->access_flags = prkey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL;
	pubkey_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;

	pubkey_info->native = 0;

	pubkey_info->usage |= prkey_info->usage & SC_PKCS15_PRKEY_USAGE_SIGN ? SC_PKCS15_PRKEY_USAGE_VERIFY : 0;
	pubkey_info->usage |= prkey_info->usage & SC_PKCS15_PRKEY_USAGE_SIGNRECOVER ? SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER : 0;
	pubkey_info->usage |= prkey_info->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION ? SC_PKCS15_PRKEY_USAGE_VERIFY : 0;
	pubkey_info->usage |= prkey_info->usage & SC_PKCS15_PRKEY_USAGE_DECRYPT ? SC_PKCS15_PRKEY_USAGE_ENCRYPT : 0;
	pubkey_info->usage |= prkey_info->usage & SC_PKCS15_PRKEY_USAGE_UNWRAP ? SC_PKCS15_PRKEY_USAGE_WRAP : 0;

	iasecc_pkcs15_add_access_rule(object, SC_PKCS15_ACCESS_RULE_MODE_READ, NULL);

	memcpy(&pubkey_info->algo_refs[0], &prkey_info->algo_refs[0], sizeof(pubkey_info->algo_refs));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_store_cert(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object, struct sc_pkcs15_der *data,
		struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_file *pfile = NULL;
	struct sc_path parent_path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_store_cert() authID '%s'", sc_pkcs15_print_id(&object->auth_id));

	rv = iasecc_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_CERT, 0, &pfile);
	LOG_TEST_RET(ctx, rv, "IasEcc new CERT file error");

	parent_path = pfile->path;
	if (parent_path.len >= 2)
		parent_path.len -= 2;
	if (!parent_path.len && !parent_path.aid.len)
		sc_format_path("3F00", &parent_path);
	rv = sc_select_file(card, &parent_path, NULL);
	LOG_TEST_RET(ctx, rv, "cannot select parent of certificate to store");

	rv = iasecc_pkcs15_fix_file_access(p15card, pfile, object);
	LOG_TEST_RET(ctx, rv, "encode file access rules failed");

	if (pfile)
		sc_file_free(pfile);

	/* NOT_IMPLEMENTED error code indicates to the upper call to execute the default 'store data' procedure */
	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
}


static int
iasecc_store_data_object(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)
{
#define MAX_DATA_OBJS 32
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_object *p15objects[MAX_DATA_OBJS];
	struct sc_file *cfile = NULL, *file = NULL, *parent = NULL;
	int rv, nn_objs, indx, ii;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_store_data_object() authID '%s'", sc_pkcs15_print_id(&object->auth_id));
	nn_objs = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, p15objects, MAX_DATA_OBJS);
	LOG_TEST_RET(ctx, nn_objs, "IasEcc get pkcs15 DATA objects error");

	for(indx = 1; indx < MAX_DATA_OBJS; indx++)   {
		rv = iasecc_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_DATA_OBJECT, indx, &file);
		LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() pkcs15 new DATA file error");

		for (ii=0; ii<nn_objs; ii++)   {
			struct sc_pkcs15_data_info *info = (struct sc_pkcs15_data_info *)p15objects[ii]->data;
			int file_id = info->path.value[info->path.len - 2] * 0x100 + info->path.value[info->path.len - 1];

			sc_log(ctx, "iasecc_store_data_object() %i: file_id 0x%X, pfile->id 0x%X\n", ii, file_id, file->id);
			if (file->id == file_id)
			   break;
		}

		if (ii == nn_objs)
			break;
		sc_file_free(file);
	}

	if (indx == MAX_DATA_OBJS)
		LOG_TEST_RET(ctx, SC_ERROR_TOO_MANY_OBJECTS, "iasecc_store_data_object() too many DATA objects.");

	do  {
		const struct sc_acl_entry *acl;

		memset(object->access_rules, 0, sizeof(object->access_rules));

		object->access_rules[0].access_mode = SC_PKCS15_ACCESS_RULE_MODE_READ;
		acl = sc_file_get_acl_entry(file, SC_AC_OP_READ);
		sc_log(ctx, "iasecc_store_data_object() READ method %i", acl->method);
		if (acl->method == SC_AC_IDA)
			iasecc_reference_to_pkcs15_id (acl->key_ref, &object->access_rules[0].auth_id);

		object->access_rules[1].access_mode = SC_PKCS15_ACCESS_RULE_MODE_UPDATE;
		acl = sc_file_get_acl_entry(file, SC_AC_OP_UPDATE);
		sc_log(ctx, "iasecc_store_data_object() UPDATE method %i", acl->method);
		if (acl->method == SC_AC_IDA)
			iasecc_reference_to_pkcs15_id (acl->key_ref, &object->access_rules[1].auth_id);

		object->access_rules[2].access_mode = SC_PKCS15_ACCESS_RULE_MODE_DELETE;
		acl = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
		sc_log(ctx, "iasecc_store_data_object() UPDATE method %i", acl->method);
		if (acl->method == SC_AC_IDA)
			iasecc_reference_to_pkcs15_id (acl->key_ref, &object->access_rules[2].auth_id);

	} while(0);

	rv = iasecc_file_convert_acls(ctx, profile, file);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() cannot convert profile ACLs");

	rv = sc_profile_get_parent(profile, "public-data", &parent);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() cannot get object parent");
	sc_log(ctx, "iasecc_store_data_object() parent path '%s'\n", sc_print_path(&parent->path));

	rv = sc_select_file(card, &parent->path, NULL);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() cannot select parent");

	rv = sc_select_file(card, &file->path, &cfile);
	if (!rv)   {
		rv = sc_pkcs15init_authenticate(profile, p15card, cfile, SC_AC_OP_DELETE);
		LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() DELETE authentication failed");

		rv = iasecc_pkcs15_delete_file(p15card, profile, cfile);
		LOG_TEST_RET(ctx, rv, "s_pkcs15init_store_data_object() delete pkcs15 file error");
	}
	else if (rv != SC_ERROR_FILE_NOT_FOUND)   {
		LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() select file error");
	}

	rv = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_CREATE);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() parent CREATE authentication failed");

	file->size = data->len;
	rv = sc_create_file(card, file);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() cannot create DATA file");

	rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() data file UPDATE authentication failed");

	rv = sc_update_binary(card, 0, data->value, data->len, 0);
	LOG_TEST_RET(ctx, rv, "iasecc_store_data_object() update DATA file failed");

	if (path)
		*path = file->path;

	if (parent)
		sc_file_free(parent);

	sc_file_free(file);

	if (cfile)
		sc_file_free(cfile);

	LOG_FUNC_RETURN(ctx, rv);
#undef MAX_DATA_OBJS
}


static int
iasecc_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
		struct sc_pkcs15_object *object,
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_IMPLEMENTED;

	LOG_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PRKEY:
		rv = iasecc_store_prvkey(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_PUBKEY:
		rv = iasecc_store_pubkey(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_CERT:
		rv = iasecc_store_cert(p15card, profile, object, data, path);
		break;
	case SC_PKCS15_TYPE_DATA_OBJECT:
		rv = iasecc_store_data_object(p15card, profile, object, data, path);
		break;
	default:
		rv = SC_ERROR_NOT_IMPLEMENTED;
		break;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static struct sc_pkcs15init_operations
sc_pkcs15init_iasecc_operations = {
	iasecc_pkcs15_erase_card,
	NULL,					/* init_card  */
	NULL,					/* create_dir */
	NULL,					/* create_domain */
	NULL,					/* select_pin_reference */
	NULL,					/* create_pin */
	iasecc_pkcs15_select_key_reference,
	iasecc_pkcs15_create_key,
	iasecc_pkcs15_store_key,
	iasecc_pkcs15_generate_key,
	NULL,					/* encode private key */
	NULL,					/* encode public key */
	NULL,					/* finalize_card */
	iasecc_pkcs15_delete_object,
	NULL,					/* pkcs15init emulation update_dir */
	NULL,					/* pkcs15init emulation update_any_df */
	NULL,					/* pkcs15init emulation update_tokeninfo */
	NULL,					/* pkcs15init emulation write_info */
	iasecc_emu_store_data,
	NULL,					/* sanity_check */
};


struct sc_pkcs15init_operations *
sc_pkcs15init_get_iasecc_ops(void)
{
	return &sc_pkcs15init_iasecc_operations;
}

#endif /* ENABLE_OPENSSL */
