/*
 * Specific operations for PKCS #15 initialization of the Oberthur's card
 * 	COSMO v7 with applet AuthentIC v3 .
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
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
#include <errno.h>
#include <stdio.h>

#ifndef ENABLE_OPENSSL
#error "Need OpenSSL"
#endif

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
#include "../libopensc/authentic.h"

#include "pkcs15-init.h"
#include "profile.h"

#define AUTHENTIC_CACHE_TIMESTAMP_PATH "3F0050159999"

unsigned char authentic_v3_rsa_mechs[5] = { 
	AUTHENTIC_MECH_CRYPTO_RSA1024, 
	AUTHENTIC_MECH_CRYPTO_RSA1280, 
	AUTHENTIC_MECH_CRYPTO_RSA1536, 
	AUTHENTIC_MECH_CRYPTO_RSA1792, 
	AUTHENTIC_MECH_CRYPTO_RSA2048
};

unsigned char authentic_v3_rsa_ac_ops[6] = { 
	SC_AC_OP_UPDATE, 
	SC_AC_OP_DELETE, 
	SC_AC_OP_PSO_DECRYPT, 
	SC_AC_OP_PSO_COMPUTE_SIGNATURE, 
	SC_AC_OP_INTERNAL_AUTHENTICATE, 
	SC_AC_OP_GENERATE	
};

struct authentic_ac_access_usage {
	unsigned ac_op;
	unsigned access_rule;
	unsigned usage;
};
struct authentic_ac_access_usage authentic_v3_rsa_map_attributes[7]  = {
	{SC_AC_OP_UPDATE, SC_PKCS15_ACCESS_RULE_MODE_UPDATE, 0},
	{SC_AC_OP_DELETE, SC_PKCS15_ACCESS_RULE_MODE_DELETE, 0},
	{SC_AC_OP_PSO_DECRYPT, SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT, 
			SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP},
	{SC_AC_OP_PSO_COMPUTE_SIGNATURE, SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS, 
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION},
	{SC_AC_OP_INTERNAL_AUTHENTICATE, SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH,
			SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER},
	{SC_AC_OP_GENERATE, SC_PKCS15_ACCESS_RULE_MODE_EXECUTE, 0},
	{0, 0, 0}
};

int authentic_pkcs15_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_file *df);

void
authentic_reference_to_pkcs15_id (unsigned int ref, struct sc_pkcs15_id *id)
{
	int ii, sz;

	for (ii=0, sz = 0; ii<sizeof(unsigned int); ii++)
		if (ref >> 8*ii)
			sz++;

	for (ii=0; ii < sz; ii++)
		id->value[sz - ii - 1] = (ref >> 8*ii) & 0xFF;

	id->len = sz;
}


int 
authentic_pkcs15_delete_file(struct sc_pkcs15_card *p15card, struct sc_profile *profile, 
		struct sc_file *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_card *card = p15card->card;
	struct sc_path  path;
	unsigned long caps = card->caps;
	int rv = 0;

	LOGN_FUNC_CALLED(ctx);

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "authentic_pkcs15_delete_file() id %04X\n", df->id);

	card->caps |= SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, df, SC_AC_OP_DELETE);
	card->caps = caps;

	LOGN_TEST_RET(ctx, rv, "Cannnot authenticate SC_AC_OP_DELETE");

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_FILE_ID;
	path.value[0] = df->id >> 8;
	path.value[1] = df->id & 0xFF;
	path.len = 2;

	rv = sc_delete_file(card, &path);
	LOGN_FUNC_RETURN(ctx, rv);
}


/*
 * Erase the card
 *
 */
static int 
authentic_pkcs15_erase_card(struct sc_profile *profile, struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file  *file = NULL;
	struct sc_pkcs15_df *df;
	int rv;

	LOGN_FUNC_CALLED(ctx);

	if (p15card->file_odf)   {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Select ODF path: %s", sc_print_path(&p15card->file_odf->path));
		rv = sc_select_file(p15card->card, &p15card->file_odf->path, NULL);
		LOGN_TEST_RET(ctx, rv, "Erase application error: cannot select ODF path");
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

		if (df->enumerated)   {
			rv = sc_pkcs15_get_objects(p15card, obj_type, objs, 32);
			LOGN_TEST_RET(ctx, rv, "Failed to get PKCS#15 objects to remove");

			for (ii=0; ii<rv; ii++)
				sc_pkcs15_remove_object(p15card, objs[ii]);
		}

		rv = sc_select_file(p15card->card, &df->path, &file);
		if (rv == SC_ERROR_FILE_NOT_FOUND)
			continue;
		LOGN_TEST_RET(ctx, rv, "Cannot select object file");

		rv = sc_erase_binary(p15card->card, 0, file->size, 0);
		if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)   {
			rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
			LOGN_TEST_RET(ctx, rv, "SC_AC_OP_UPDATE authentication failed");

			rv = sc_erase_binary(p15card->card, 0, file->size, 0);
		}
		LOGN_TEST_RET(ctx, rv, "Binary erase error");

		sc_file_free(file);

		profile->dirty = 1;
	}

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Allocate a file
 */
static int
authentic_pkcs15_new_file(struct sc_profile *profile, struct sc_card *card,
		unsigned int type, unsigned int num, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file	*file = NULL;
	const char *t_name = NULL;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "type %X; num %i", type, num);
	switch (type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			t_name = "template-private-key";
			break;
		case SC_PKCS15_TYPE_PUBKEY_RSA:
			t_name = "template-public-key";
			break;
		case SC_PKCS15_TYPE_CERT:
			t_name = "template-certificate";
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:
			t_name = "template-public-data";
			break;
		default:
			LOGN_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Profile template not supported");
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "df_info path '%s'", sc_print_path(&profile->df_info->file->path));
	rv = sc_profile_get_file(profile, t_name, &file);
	LOGN_TEST_RET(ctx, rv, "Error when getting file from template");

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "file(type:%X), path(type:%X;path:%s)", file->type, file->path.type, sc_print_path(&file->path));

	file->id = (file->id & 0xFF00) | (num & 0xFF);
	if (file->type != SC_FILE_TYPE_BSO)   {
		if (file->path.len == 0)   {
			file->path.type = SC_PATH_TYPE_FILE_ID;
			file->path.len = 2;
		}
		file->path.value[file->path.len - 2] = (file->id >> 8) & 0xFF; 
		file->path.value[file->path.len - 1] = file->id & 0xFF;
		file->path.count = -1;
	}

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "file size %i; ef type %i/%i; id %04X", file->size, file->type, file->ef_structure, file->id);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "path type %X; path '%s'", file->path.type, sc_print_path(&file->path));

	if (out)
		*out = file;

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


/*
 * Select a key reference
 */
static int
authentic_pkcs15_select_key_reference(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;

	LOGN_FUNC_CALLED(ctx);

	/* In authentic PKCS#15 all crypto objects are locals */
	key_info->key_reference |= AUTHENTIC_OBJECT_REF_FLAG_LOCAL;

	if (key_info->key_reference > AUTHENTIC_V3_CRYPTO_OBJECT_REF_MAX)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (key_info->key_reference < AUTHENTIC_V3_CRYPTO_OBJECT_REF_MIN)
		key_info->key_reference = AUTHENTIC_V3_CRYPTO_OBJECT_REF_MIN;

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "returns key reference %i", key_info->key_reference);
	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
authentic_docp_set_acls(struct sc_card *card, struct sc_file *file, 
		unsigned char *ops, size_t ops_len,
		struct sc_authentic_sdo_docp *docp)
{
	struct sc_context *ctx = card->ctx;
	int ii, offs;

	LOGN_FUNC_CALLED(ctx);
	if (ops_len > sizeof(docp->acl_data) / 2)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	for (ii=0, offs=0; ii<ops_len; ii++)   {
		const struct sc_acl_entry *entry;

		entry = sc_file_get_acl_entry(file, *(ops + ii));
		if (entry->method == SC_AC_NEVER)   {
			docp->acl_data[offs++] = 0x00;
			docp->acl_data[offs++] = 0x00;
		}
		else if (entry->method == SC_AC_NONE)   {
			docp->acl_data[offs++] = 0x00;
			docp->acl_data[offs++] = 0x00;
		}
		else if (entry->method == SC_AC_CHV)   {
			if (!(entry->key_ref & AUTHENTIC_V3_CREDENTIAL_ID_MASK)
					|| (entry->key_ref & ~AUTHENTIC_V3_CREDENTIAL_ID_MASK))
				LOGN_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported Credential Reference");
						                        
			docp->acl_data[offs++] = 0x00;
			docp->acl_data[offs++] = 0x01 << (entry->key_ref - 1);
		}
	}

	docp->acl_data_len = offs;
	LOGN_FUNC_RETURN(ctx, offs);
}


static int 
authentic_sdo_allocate_prvkey(struct sc_profile *profile, struct sc_card *card,
		struct sc_pkcs15_prkey_info *key_info, struct sc_authentic_sdo **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_authentic_sdo *sdo = NULL;
	struct sc_file *file = NULL;
	int rv;

	LOGN_FUNC_CALLED(ctx);

	if (!out)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if ((key_info->modulus_length % 256) || key_info->modulus_length < 1024 || key_info->modulus_length > 2048)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = authentic_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "authentic_pkcs15_create_key() new_file(TYPE_PRKEY_RSA) rv %i", rv);
	LOGN_TEST_RET(ctx, rv, "IasEcc pkcs15 new PRKEY_RSA file error");

	sdo = calloc(1, sizeof(struct sc_authentic_sdo));
	if (!sdo)
		LOGN_TEST_RET(ctx, SC_ERROR_MEMORY_FAILURE, "Cannot allocate 'sc_authentic_sdo'");

	sdo->magic = AUTHENTIC_SDO_MAGIC;
	sdo->docp.id = key_info->key_reference &  ~AUTHENTIC_OBJECT_REF_FLAG_LOCAL;
	sdo->docp.mech = authentic_v3_rsa_mechs[(key_info->modulus_length - 1024) / 256];

	rv = authentic_docp_set_acls(card, file, authentic_v3_rsa_ac_ops, 
			sizeof(authentic_v3_rsa_ac_ops)/sizeof(authentic_v3_rsa_ac_ops[0]), &sdo->docp);
	LOGN_TEST_RET(ctx, rv, "Cannot set key ACLs from file");

	sc_file_free(file);

	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "sdo(mech:%X,id:%X,acls:%s)", sdo->docp.mech, sdo->docp.id, 
			sc_dump_hex(sdo->docp.acl_data, sdo->docp.acl_data_len));
	if (out)
		*out = sdo;
	else
		free(sdo);

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}

#if 0
static int 
authentic_sdo_convert_to_file(struct sc_card *card, struct sc_authentic_sdo *sdo, struct sc_file **out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = sc_file_new();
	int rv, ii;

	LOGN_FUNC_CALLED(ctx);
	if (file == NULL)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	else if (!card || !sdo)
		LOGN_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_debug_normal(card->ctx, "sdo->sdo_class %X", sdo->sdo_class);

	if (sdo->sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		unsigned char ops[] = { 
			SC_AC_OP_PSO_COMPUTE_SIGNATURE, SC_AC_OP_INTERNAL_AUTHENTICATE, SC_AC_OP_PSO_DECRYPT, 
			SC_AC_OP_GENERATE, SC_AC_OP_UPDATE, SC_AC_OP_READ
		};

		for (ii=0; ii<sizeof(ops)/sizeof(ops[0]);ii++)   {
			unsigned op_method, op_ref; 
			
			rv = authentic_sdo_convert_acl(card, sdo, ops[ii], &op_method, &op_ref);
			LOGN_TEST_RET(ctx, rv, "IasEcc: cannot convert ACL");
			sc_debug_normal(card->ctx, "ii:%i, method:%X, ref:%X", ii, op_method, op_ref);

			sc_file_add_acl_entry(file, ops[ii], op_method, op_ref);
		}
	}

	if (out)
		*out = file;
	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif


static int
authentic_pkcs15_add_access_rule(struct sc_pkcs15_object *object, unsigned access_mode, struct sc_pkcs15_id *auth_id)
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

#if 0
static int
authentic_pkcs15_get_auth_id_from_se(struct sc_pkcs15_card *p15card, unsigned char scb,
		struct sc_pkcs15_id *auth_id)
{
	struct sc_context *ctx = p15card->card->ctx;
        struct sc_pkcs15_object *pin_objs[32];
	int rv, ii, nn_pins, se_ref, pin_ref;

	LOGN_FUNC_CALLED(ctx);
	if (auth_id)
		memset(auth_id, 0, sizeof(struct sc_pkcs15_id));

	if (!(scb & IASECC_SCB_METHOD_USER_AUTH))
		LOGN_FUNC_RETURN(ctx, SC_SUCCESS);

        rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, pin_objs, 32);
	LOGN_TEST_RET(ctx, rv, "Error while getting AUTH objects");
	nn_pins = rv;

	se_ref = scb & 0x0F;
	rv = sc_card_ctl(p15card->card, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, (void *)(&se_ref));
	LOGN_TEST_RET(ctx, rv, "Card CTL error: cannot get CHV reference from SE");
	pin_ref = rv;
	for (ii=0; ii<nn_pins; ii++)   {
		const struct sc_pkcs15_pin_info *pin_info = (const struct sc_pkcs15_pin_info *) pin_objs[ii]->data;

		if (pin_ref == pin_info->reference)   {
			*auth_id = pin_info->auth_id;
			break;
		}
	}
	if (ii == nn_pins)
		LOGN_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "No AUTH object found");

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif

static int
authentic_pkcs15_fix_file_access_rule(struct sc_pkcs15_card *p15card, struct sc_file *file,
		unsigned ac_op, unsigned rule_mode, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	const struct sc_acl_entry *acl = NULL;
	struct sc_pkcs15_id id;
	unsigned ref;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	acl = sc_file_get_acl_entry(file, ac_op);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Fix access rule(op:%i;mode:%i) with ACL(method:%X,ref:%X)", 
			ac_op, rule_mode, acl->method, acl->key_ref);
	if (acl->method == SC_AC_NEVER)   {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ignore access rule(op:%i,mode:%i)", ac_op, rule_mode);
	}
	else if (acl->method == SC_AC_NONE)   {
		rv = authentic_pkcs15_add_access_rule(object, rule_mode, NULL);
		LOGN_TEST_RET(ctx, rv, "Fix file access rule error");
	}
	else   {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ACL(method:%X,ref:%X)", acl->method, acl->key_ref);
		if (acl->method == SC_AC_CHV)   {
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ACL(method:%X,ref:%X)", acl->method, acl->key_ref);
			ref = acl->key_ref;
			authentic_reference_to_pkcs15_id (ref, &id);
		}
		else   {
			LOGN_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "Fix file access error");
		}

		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ACL(method:%X,ref:%X)", acl->method, acl->key_ref);
		rv = authentic_pkcs15_add_access_rule(object, rule_mode, &id);
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "rv %i", rv);
		LOGN_TEST_RET(ctx, rv, "Fix file access rule error");
	}

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
authentic_pkcs15_fix_access(struct sc_pkcs15_card *p15card, struct sc_file *file, 
		struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv, ii;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "authID %s", sc_pkcs15_print_id(&object->auth_id));

	memset(object->access_rules, 0, sizeof(object->access_rules));

	for (ii=0; authentic_v3_rsa_map_attributes[ii].access_rule; ii++)   {
		rv = authentic_pkcs15_fix_file_access_rule(p15card, file, 
				authentic_v3_rsa_map_attributes[ii].ac_op, 
				authentic_v3_rsa_map_attributes[ii].access_rule, 
				object);
		LOGN_TEST_RET(ctx, rv, "Fix file READ access error");
	}

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
authentic_pkcs15_fix_usage(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	int ii, jj;

	LOGN_FUNC_CALLED(ctx);
	if (object->type == SC_PKCS15_TYPE_PRKEY_RSA)   {
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) object->data;

		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "fix private key usage 0x%X", prkey_info->usage);
        	for (ii=0;ii<SC_PKCS15_MAX_ACCESS_RULES;ii++)   {
			if (!object->access_rules[ii].access_mode)
				break;

			for (jj=0; authentic_v3_rsa_map_attributes[jj].access_rule; jj++)
				if (authentic_v3_rsa_map_attributes[jj].access_rule & object->access_rules[ii].access_mode)
					prkey_info->usage |= authentic_v3_rsa_map_attributes[jj].usage;
		}
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "fixed private key usage 0x%X", prkey_info->usage);
	}
	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int 
authentic_pkcs15_fix_supported_algos(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_supported_algo_info *algo;
	int rv = SC_SUCCESS, ii;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "encode supported algos for object(%s,type:%X)", object->label, object->type);
#if 0
	switch (object->type)   {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "PrKey Usage:%X,Access:%X", prkey_info->usage, prkey_info->access_flags);
		if (prkey_info->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP))   {
			algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_DECIPHER, CKM_RSA_PKCS);
			rv = sc_pkcs15_add_supported_algo_ref(object, algo);
			LOGN_TEST_RET(ctx, rv, "cannot add supported algorithm DECIPHER:CKM_RSA_PKCS");
		}

		if (prkey_info->usage & SC_PKCS15_PRKEY_USAGE_SIGN)   {
			if (prkey_info->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)   {
				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA1_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOGN_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_SHA1_RSA_PKCS");

				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA256_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOGN_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_SHA256_RSA_PKCS");
			}
			else   {
				algo = sc_pkcs15_get_supported_algo(p15card, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_RSA_PKCS);
				rv = sc_pkcs15_add_supported_algo_ref(object, algo);
				LOGN_TEST_RET(ctx, rv, "cannot add supported algorithm SIGN:CKM_RSA_PKCS");
			}
		}

		for (ii=0; ii<SC_MAX_SUPPORTED_ALGORITHMS && prkey_info->algo_refs[ii]; ii++)
			sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "algoReference %i", prkey_info->algo_refs[ii]);

		break;
	default:
		rv = SC_ERROR_NOT_SUPPORTED;
		break;
	}
#else
	printf("%s +%i: FIXME\n", __FILE__, __LINE__);
#endif
	LOGN_FUNC_RETURN(ctx, rv);
}


static void
authentic_free_sdo_data(struct sc_authentic_sdo *sdo)
{
	int rsa_mechs_num = sizeof(authentic_v3_rsa_mechs)/sizeof(authentic_v3_rsa_mechs[0]);
	int ii;

	if (!sdo)
		return;

	if (sdo->file)
		sc_file_free(sdo->file);

	for (ii=0; ii<rsa_mechs_num; ii++)
		if (sdo->sdo_class == authentic_v3_rsa_mechs[ii])
			break;
	if (ii<rsa_mechs_num)
		sc_pkcs15_free_prkey(sdo->data.prvkey);
}


static int
authentic_pkcs15_create_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
					struct sc_pkcs15_object *object)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_authentic_sdo *sdo = NULL;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	struct sc_file	*file_p_prvkey = NULL, *parent = NULL;
	size_t keybits = key_info->modulus_length;
	int	 rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "create private key(keybits:%i,usage:%X,access:%X,ref:%X)", keybits, 
			key_info->usage, key_info->access_flags, key_info->key_reference);
	if (keybits < 1024 || keybits > 2048 || (keybits % 256))
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid RSA key size");

	rv = authentic_pkcs15_new_file(profile, card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file_p_prvkey);
	LOGN_TEST_RET(ctx, rv, "IasEcc pkcs15 new PRKEY_RSA file error");

	key_info->key_reference |= AUTHENTIC_OBJECT_REF_FLAG_LOCAL;

	rv = sc_select_file(card, &file_p_prvkey->path, &parent);
	LOGN_TEST_RET(ctx, rv, "DF for the private objects not defined");

	rv = sc_pkcs15init_authenticate(profile, p15card, parent, SC_AC_OP_CRYPTO);
	LOGN_TEST_RET(ctx, rv, "SC_AC_OP_CRYPTO authentication failed for parent DF");

	sc_file_free(parent);

	key_info->access_flags = SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
		| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
		| SC_PKCS15_PRKEY_ACCESS_SENSITIVE;

        rv = authentic_sdo_allocate_prvkey(profile, card, key_info, &sdo);
        LOGN_TEST_RET(ctx, rv, "IasEcc: init SDO private key failed");

	rv = sc_card_ctl(card, SC_CARDCTL_AUTHENTIC_SDO_CREATE, sdo);
	if (rv == SC_ERROR_FILE_ALREADY_EXISTS)   {
		unsigned long caps = p15card->card->caps;

		p15card->card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
		rv = sc_pkcs15init_authenticate(profile, p15card, file_p_prvkey, SC_AC_OP_DELETE);
		p15card->card->caps = caps;
		LOGN_TEST_RET(ctx, rv, "SC_AC_OP_CRYPTO authentication failed for parent DF");

		rv = sc_card_ctl(card, SC_CARDCTL_AUTHENTIC_SDO_DELETE, sdo);
		LOGN_TEST_RET(ctx, rv, "SC_CARDCTL_AUTHENTIC_SDO_DELETE failed for private key");
	
		rv = sc_card_ctl(card, SC_CARDCTL_AUTHENTIC_SDO_CREATE, sdo);
	}
	LOGN_TEST_RET(ctx, rv, "SC_CARDCTL_AUTHENTIC_SDO_CREATE failed");

	rv = authentic_pkcs15_fix_access(p15card, file_p_prvkey, object);
	LOGN_TEST_RET(ctx, rv, "cannot fix access rules for private key");

	rv = authentic_pkcs15_fix_usage(p15card, object);
	LOGN_TEST_RET(ctx, rv, "cannot fix access rules for private key");

	rv = authentic_pkcs15_fix_supported_algos(p15card, object);
	LOGN_TEST_RET(ctx, rv, "encode private key access rules failed");

	sdo->file = file_p_prvkey;
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "sdo->file:%p", sdo->file);

	rv = sc_pkcs15_allocate_object_content(object, (unsigned char *)sdo, sizeof(struct sc_authentic_sdo));
	LOGN_TEST_RET(ctx, rv, "Failed to allocate PrvKey SDO as object content");

	LOGN_FUNC_RETURN(ctx, rv);
}


/*
 * RSA key generation
 */
static int
authentic_pkcs15_generate_key(struct sc_profile *profile, sc_pkcs15_card_t *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_pubkey *pubkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	struct sc_authentic_sdo *sdo = NULL;
	unsigned long caps;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "generate key(bits:%i,path:%s,AuthID:%s\n", keybits, 
			sc_print_path(&key_info->path), sc_pkcs15_print_id(&object->auth_id));

	if (!object->content.value || object->content.len != sizeof(struct sc_authentic_sdo))
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid PrKey SDO data");
	else if (keybits < 1024 || keybits > 2048 || (keybits % 256))
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid RSA key size");

	sdo = (struct sc_authentic_sdo *)object->content.value;
	if (sdo->magic != AUTHENTIC_SDO_MAGIC)
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "'Magic' control failed for SDO PrvKey");

	rv = sc_select_file(card, &key_info->path, NULL);
	LOGN_TEST_RET(ctx, rv, "failed to select parent DF");

	caps = card->caps;
	card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, sdo->file, SC_AC_OP_GENERATE);
	card->caps = caps;
	LOGN_TEST_RET(ctx, rv, "SC_AC_OP_GENERATE authentication failed");

	key_info->access_flags |= SC_PKCS15_PRKEY_ACCESS_LOCAL;

	rv = sc_card_ctl(card, SC_CARDCTL_AUTHENTIC_SDO_GENERATE, sdo);
	LOGN_TEST_RET(ctx, rv, "generate key failed");

	pubkey->algorithm = SC_ALGORITHM_RSA;
	//FIXME: allocate/copy/free to reduce memory likage
	pubkey->u.rsa.modulus = sdo->data.prvkey->u.rsa.modulus;
	pubkey->u.rsa.exponent = sdo->data.prvkey->u.rsa.exponent;
	sdo->data.prvkey = NULL;

	rv = sc_pkcs15_encode_pubkey(ctx, pubkey, &pubkey->data.value, &pubkey->data.len);
	LOGN_TEST_RET(ctx, rv, "encode public key failed");

	rv = authentic_pkcs15_fix_supported_algos(p15card, object);
	LOGN_TEST_RET(ctx, rv, "encode private key access rules failed");

	authentic_free_sdo_data(sdo);

	rv = sc_pkcs15_allocate_object_content(object, pubkey->data.value, pubkey->data.len);
	LOGN_TEST_RET(ctx, rv, "Failed to allocate public key as object content");

	LOGN_FUNC_RETURN(ctx, rv);
}


/*
 * Store a private key
 */
static int
authentic_pkcs15_store_key(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_object *object, struct sc_pkcs15_prkey *prvkey)
{
	struct sc_card *card = p15card->card;
	struct sc_context *ctx = card->ctx;
	struct sc_pkcs15_prkey_info *key_info = (struct sc_pkcs15_prkey_info *) object->data;
	size_t keybits = key_info->modulus_length;
	unsigned long caps;
	struct sc_authentic_sdo *sdo;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Store IAS/ECC key(keybits:%i,AuthID:%s,path:%s)", 
			keybits, sc_pkcs15_print_id(&object->auth_id), sc_print_path(&key_info->path));

	if (!object->content.value || object->content.len != sizeof(struct sc_authentic_sdo))
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid PrKey SDO data");
	else if (keybits < 1024 || keybits > 2048 || (keybits % 256))
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid RSA key size");

	key_info->access_flags &= ~SC_PKCS15_PRKEY_ACCESS_LOCAL;

	sdo = (struct sc_authentic_sdo *)object->content.value;
	if (sdo->magic != AUTHENTIC_SDO_MAGIC)
		LOGN_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "'Magic' control failed for SDO PrvKey");

	rv = sc_select_file(card, &key_info->path, NULL);
	LOGN_TEST_RET(ctx, rv, "failed to select parent DF");

	sdo->data.prvkey = prvkey;
	        
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "sdo(mech:%X,id:%X,acls:%s)", sdo->docp.mech, sdo->docp.id,
			sc_dump_hex(sdo->docp.acl_data, sdo->docp.acl_data_len));

	caps = card->caps;
	card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, sdo->file, SC_AC_OP_UPDATE);
	LOGN_TEST_RET(ctx, rv, "SC_AC_OP_GENERATE authentication failed");

	rv = sc_card_ctl(card, SC_CARDCTL_AUTHENTIC_SDO_STORE, sdo);
	LOGN_TEST_RET(ctx, rv, "store IAS SDO PRIVATE KEY failed");

	authentic_free_sdo_data(sdo);
	sc_pkcs15_free_object_content(object);

	LOGN_FUNC_RETURN(ctx, rv);
}


static int 
authentic_pkcs15_delete_rsa_sdo (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_prkey_info *key_info)
{
	struct sc_context *ctx = p15card->card->ctx;
	unsigned long caps = p15card->card->caps;
	struct sc_authentic_sdo sdo;
	struct sc_file  *file = NULL;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "delete SDO RSA key (ref:%i,size:%i)", key_info->key_reference, key_info->modulus_length);

	rv = authentic_pkcs15_new_file(profile, p15card->card, SC_PKCS15_TYPE_PRKEY_RSA, key_info->key_reference, &file);
	LOGN_TEST_RET(ctx, rv, "PRKEY_RSA instantiation file error");

	p15card->card->caps &= ~SC_CARD_CAP_USE_FCI_AC;
	rv = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE);
	p15card->card->caps = caps;
	LOGN_TEST_RET(ctx, rv, "'DELETE' authentication failed for parent RSA key");

	sdo.magic = AUTHENTIC_SDO_MAGIC;
	sdo.docp.id = key_info->key_reference & ~AUTHENTIC_OBJECT_REF_FLAG_LOCAL;
	sdo.docp.mech = authentic_v3_rsa_mechs[(key_info->modulus_length - 1024) / 256];

	rv = sc_card_ctl(p15card->card, SC_CARDCTL_AUTHENTIC_SDO_DELETE, &sdo);
	if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)
		rv = SC_SUCCESS;
	LOGN_TEST_RET(ctx, rv, "SC_CARDCTL_AUTHENTIC_SDO_DELETE failed for private key");

	LOGN_FUNC_RETURN(ctx, rv);
}


static int 
authentic_pkcs15_delete_object (struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned int type, const void *data, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "delete PKCS15 object: type %X; path %s\n", type, sc_print_path(path));

	switch(type & SC_PKCS15_TYPE_CLASS_MASK)   {
	case SC_PKCS15_TYPE_PRKEY:
		rv = authentic_pkcs15_delete_rsa_sdo (profile, p15card, (struct sc_pkcs15_prkey_info *)data);
		LOGN_FUNC_RETURN(ctx, rv);
	case SC_PKCS15_TYPE_PUBKEY:
		LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
	default:
		LOGN_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int 
authentic_store_pubkey(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15_object *object,  
		struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_pubkey_info *pubkey_info = (struct sc_pkcs15_pubkey_info *)object->data;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_object = NULL;
	int rv;

	LOGN_FUNC_CALLED(ctx);
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "Public Key id '%s'", sc_pkcs15_print_id(&pubkey_info->id));

	rv = sc_pkcs15_find_prkey_by_id(p15card, &pubkey_info->id, &prkey_object);
	LOGN_TEST_RET(ctx, rv, "Find related PrKey error");

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

	authentic_pkcs15_add_access_rule(object, SC_PKCS15_ACCESS_RULE_MODE_READ, NULL);

#if 0
	memcpy(&pubkey_info->algo_refs[0], &prkey_info->algo_refs[0], sizeof(pubkey_info->algo_refs));
#else
	printf("%s +%i: FiXME\n", __FILE__, __LINE__);
#endif

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int 
authentic_emu_store_data(struct sc_pkcs15_card *p15card, struct sc_profile *profile, 
		struct sc_pkcs15_object *object,  
		struct sc_pkcs15_der *data, struct sc_path *path)

{
	struct sc_context *ctx = p15card->card->ctx;
	int rv = SC_ERROR_NOT_IMPLEMENTED;

	LOGN_FUNC_CALLED(ctx);

	switch (object->type & SC_PKCS15_TYPE_CLASS_MASK) {
	case SC_PKCS15_TYPE_PUBKEY:
		rv = authentic_store_pubkey(p15card, profile, object, data, path);
		break;
	}
		
	LOGN_FUNC_RETURN(ctx, rv);
}


static int
authentic_emu_update_tokeninfo(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_pkcs15_tokeninfo *tinfo)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_file *file = NULL;
	struct sc_path path;
	unsigned char buffer[8];
	int rv,len;

        sc_format_path(AUTHENTIC_CACHE_TIMESTAMP_PATH, &path);
        rv = sc_select_file(p15card->card, &path, &file);
        if (!rv)   {
		rv = sc_get_challenge(p15card->card, buffer, sizeof(buffer));
		LOGN_TEST_RET(ctx, rv, "Get challenge error");

		len = file->size > sizeof(buffer) ? sizeof(buffer) : file->size;
	        rv = sc_update_binary(p15card->card, 0, buffer, len, 0);
		LOGN_TEST_RET(ctx, rv, "Get challenge error");

		sc_file_free(file);
	}

	LOGN_FUNC_RETURN(ctx, SC_SUCCESS);
}


static struct sc_pkcs15init_operations 
sc_pkcs15init_authentic_operations = {
	authentic_pkcs15_erase_card,
	NULL,					/* init_card  */
	NULL,					/* create_dir */
	NULL,					/* create_domain */
	NULL,					/* select_pin_reference */
	NULL,					/* create_pin */
	authentic_pkcs15_select_key_reference,
	authentic_pkcs15_create_key,
	authentic_pkcs15_store_key,
	authentic_pkcs15_generate_key,
	NULL,					/* encode private key */
	NULL,					/* encode public key */
	NULL,					/* finalize_card */
	authentic_pkcs15_delete_object,

	/* pkcs15init emulation */
	NULL, 
	NULL, 
	authentic_emu_update_tokeninfo,
	NULL,
	authentic_emu_store_data,
	
	NULL,					/* sanity_check */
};


struct sc_pkcs15init_operations *
sc_pkcs15init_get_authentic_ops(void)
{   
	return &sc_pkcs15init_authentic_operations;
}
