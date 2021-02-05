/*
 * card-oberthur.c: Support for Oberthur smart cards
 *		CosmopolIC  v5;
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
 *
 * best view with tabstop=4
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef ENABLE_OPENSSL	/* empty file without openssl */
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

#include "internal.h"
#include "cardctl.h"
#include "pkcs15.h"
#include "gp.h"

#define OBERTHUR_PIN_LOCAL	0x80
#define OBERTHUR_PIN_REFERENCE_USER	0x81
#define OBERTHUR_PIN_REFERENCE_ONETIME	0x82
#define OBERTHUR_PIN_REFERENCE_SO	0x04
#define OBERTHUR_PIN_REFERENCE_PUK	0x84

static const struct sc_atr_table oberthur_atrs[] = {
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL,
			"Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:18:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL,
			"Oberthur 64k v4/2.1.1", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:01:00:82:90:00", NULL,
			"Oberthur 64k v5", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7D:11:00:00:00:31:80:71:8E:64:77:E3:02:00:82:90:00", NULL,
			"Oberthur 64k v5/2.2.0", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:7B:18:00:00:00:31:C0:64:77:E3:03:00:82:90:00", NULL,
			"Oberthur 64k CosmopolIC v5.2/2.2", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ "3B:FB:11:00:00:81:31:FE:45:00:31:C0:64:77:E9:10:00:00:90:00:6A", NULL,
			"OCS ID-One Cosmo Card", SC_CARD_TYPE_OBERTHUR_64K, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

struct auth_senv {
	unsigned int algorithm;
	int key_file_id;
	size_t key_size;
};

struct auth_private_data {
	unsigned char aid[SC_MAX_AID_SIZE];
	int aid_len;

	struct sc_pin_cmd_pin pin_info;
	struct auth_senv senv;

	long int sn;
};

struct auth_update_component_info {
	enum SC_CARDCTL_OBERTHUR_KEY_TYPE  type;
	unsigned int    component;
	unsigned char   *data;
	unsigned int    len;
};


static const unsigned char *aidAuthentIC_V5 =
		(const unsigned char *)"\xA0\x00\x00\x00\x77\x01\x03\x03\x00\x00\x00\xF1\x00\x00\x00\x02";
static const int lenAidAuthentIC_V5 = 16;
static const char *nameAidAuthentIC_V5 = "AuthentIC v5";

#define OBERTHUR_AUTH_TYPE_PIN		1
#define OBERTHUR_AUTH_TYPE_PUK		2

#define OBERTHUR_AUTH_MAX_LENGTH_PIN	64
#define OBERTHUR_AUTH_MAX_LENGTH_PUK	16

#define SC_OBERTHUR_MAX_ATTR_SIZE	8

#define PUBKEY_512_ASN1_SIZE	0x4A
#define PUBKEY_1024_ASN1_SIZE	0x8C
#define PUBKEY_2048_ASN1_SIZE	0x10E

static unsigned char rsa_der[PUBKEY_2048_ASN1_SIZE];
static int rsa_der_len = 0;

static struct sc_file *auth_current_ef = NULL,  *auth_current_df = NULL;
static struct sc_card_operations auth_ops;
static struct sc_card_operations *iso_ops;
static struct sc_card_driver auth_drv = {
	"Oberthur AuthentIC.v2/CosmopolIC.v4",
	"oberthur",
	&auth_ops,
	NULL, 0, NULL
};

static int auth_get_pin_reference (struct sc_card *card,
		int type, int reference, int cmd, int *out_ref);
static int auth_read_component(struct sc_card *card,
		enum SC_CARDCTL_OBERTHUR_KEY_TYPE type, int num,
		unsigned char *out, size_t outlen);
static int auth_pin_is_verified(struct sc_card *card, int pin_reference,
		int *tries_left);
static int auth_pin_verify(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left);
static int auth_pin_reset(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left);
static int auth_create_reference_data (struct sc_card *card,
		struct sc_cardctl_oberthur_createpin_info *args);
static int auth_get_serialnr(struct sc_card *card, struct sc_serial_number *serial);
static int auth_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file_out);
static int acl_to_ac_byte(struct sc_card *card, const struct sc_acl_entry *e);

static int
auth_finish(struct sc_card *card)
{
	free(card->drv_data);
	return SC_SUCCESS;
}


static int
auth_select_aid(struct sc_card *card)
{
	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	struct auth_private_data *data =  (struct auth_private_data *) card->drv_data;
	int rv, ii;
	struct sc_path tmp_path;

	/* Select Card Manager (to deselect previously selected application) */
	rv = gp_select_card_manager(card);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	/* Get smart card serial number */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x9F, 0x7F);
	apdu.cla = 0x80;
	apdu.le = 0x2D;
	apdu.resplen = 0x30;
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	card->serialnr.len = 4;
	memcpy(card->serialnr.value, apdu.resp+15, 4);

	for (ii=0, data->sn = 0; ii < 4; ii++)
		data->sn += (long int)(*(apdu.resp + 15 + ii)) << (3-ii)*8;

	sc_log(card->ctx, "serial number %li/0x%lX", data->sn, data->sn);

	memset(&tmp_path, 0, sizeof(struct sc_path));
	tmp_path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(tmp_path.value, aidAuthentIC_V5, lenAidAuthentIC_V5);
	tmp_path.len = lenAidAuthentIC_V5;

	rv = iso_ops->select_file(card, &tmp_path, NULL);
	LOG_TEST_RET(card->ctx, rv, "select parent failed");

	sc_format_path("3F00", &tmp_path);
	sc_file_free(auth_current_df);
	auth_current_df = NULL;
	rv = iso_ops->select_file(card, &tmp_path, &auth_current_df);
	LOG_TEST_RET(card->ctx, rv, "select parent failed");

	sc_format_path("3F00", &card->cache.current_path);
	sc_file_free(auth_current_ef);
	auth_current_ef = NULL;
	sc_file_dup(&auth_current_ef, auth_current_df);

	memcpy(data->aid, aidAuthentIC_V5, lenAidAuthentIC_V5);
	data->aid_len = lenAidAuthentIC_V5;
	card->name = nameAidAuthentIC_V5;

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_match_card(struct sc_card *card)
{
	if (_sc_match_atr(card, oberthur_atrs, &card->type) < 0)
		return 0;
	else
		return 1;
}


static int
auth_init(struct sc_card *card)
{
	struct auth_private_data *data;
	struct sc_path path;
	unsigned long flags;
	int rv = 0;

	data = calloc(1, sizeof(struct auth_private_data));
	if (!data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	card->cla = 0x00;
	card->drv_data = data;

	card->caps |= SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	if (auth_select_aid(card))   {
		sc_log(card->ctx, "Failed to initialize %s", card->name);
		rv = SC_ERROR_INVALID_CARD;
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_CARD, "Failed to initialize");
	}

	sc_format_path("3F00", &path);
	rv = auth_select_file(card, &path, NULL);

err:
	if (rv == SC_SUCCESS) {
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ISO9796;
		flags |= SC_ALGORITHM_RSA_HASH_NONE;
		flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;

		_sc_card_add_rsa_alg(card, 512, flags, 0);
		_sc_card_add_rsa_alg(card, 1024, flags, 0);
		_sc_card_add_rsa_alg(card, 2048, flags, 0);
	} else {
		free(card->drv_data);
		card->drv_data = NULL;
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static void
add_acl_entry(struct sc_card *card, struct sc_file *file, unsigned int op,
		unsigned char acl_byte)
{
	if ((acl_byte & 0xE0) == 0x60)   {
		sc_log(card->ctx, "called; op 0x%X; SC_AC_PRO; ref 0x%X", op, acl_byte);
		sc_file_add_acl_entry(file, op, SC_AC_PRO, acl_byte);
		return;
	}

	switch (acl_byte) {
	case 0x00:
		sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE);
		break;
	/* User and OneTime PINs are locals */
	case 0x21:
	case 0x22:
		sc_file_add_acl_entry(file, op, SC_AC_CHV, (acl_byte & 0x0F) | OBERTHUR_PIN_LOCAL);
		break;
	/* Local SOPIN is only for the unblocking. */
	case 0x24:
	case 0x25:
		if (op == SC_AC_OP_PIN_RESET)
			sc_file_add_acl_entry(file, op, SC_AC_CHV, 0x84);
		else
			sc_file_add_acl_entry(file, op, SC_AC_CHV, 0x04);
		break;
	case 0xFF:
		sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		break;
	default:
		sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
		break;
	}
}


static int
auth_process_fci(struct sc_card *card, struct sc_file *file,
            const unsigned char *buf, size_t buflen)
{
	unsigned char type;
	const unsigned char *attr;
	size_t attr_len = 0;

	LOG_FUNC_CALLED(card->ctx);
	attr = sc_asn1_find_tag(card->ctx, buf, buflen, 0x82, &attr_len);
	if (!attr || attr_len < 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	type = attr[0];

	attr = sc_asn1_find_tag(card->ctx, buf, buflen, 0x83, &attr_len);
	if (!attr || attr_len < 2)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	file->id = attr[0]*0x100 + attr[1];

	attr = sc_asn1_find_tag(card->ctx, buf, buflen, type==0x01 ? 0x80 : 0x85, &attr_len);
	switch (type) {
	case 0x01:
		if (!attr || attr_len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		file->size = attr[0]*0x100 + attr[1];
		break;
	case 0x04:
		if (!attr || attr_len < 1)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_VARIABLE;
		file->size = attr[0];
		attr = sc_asn1_find_tag(card->ctx, buf, buflen, 0x82, &attr_len);
		if (!attr || attr_len < 5)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->record_length = attr[2]*0x100+attr[3];
		file->record_count = attr[4];
		break;
	case 0x11:
		if (!attr || attr_len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_DES;
		file->size = attr[0]*0x100 + attr[1];
		file->size /= 8;
		break;
	case 0x12:
		if (!attr || attr_len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;

		file->size = attr[0]*0x100 + attr[1];
		if (file->size==512)
			file->size = PUBKEY_512_ASN1_SIZE;
		else if (file->size==1024)
			file->size = PUBKEY_1024_ASN1_SIZE;
		else if (file->size==2048)
			file->size = PUBKEY_2048_ASN1_SIZE;
		else   {
			sc_log(card->ctx,
			       "Not supported public key size: %"SC_FORMAT_LEN_SIZE_T"u",
			       file->size);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
		break;
	case 0x14:
		if (!attr || attr_len < 2)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_INTERNAL_EF;
		file->ef_structure = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
		file->size = attr[0]*0x100 + attr[1];
		break;
	case 0x38:
		if (!attr || attr_len < 1)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		file->type = SC_FILE_TYPE_DF;
		file->size = attr[0];
		if (SC_SUCCESS != sc_file_set_type_attr(file,attr,attr_len))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	attr = sc_asn1_find_tag(card->ctx, buf, buflen, 0x86, &attr_len);
	if (!attr || attr_len < 8)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);

	if (file->type == SC_FILE_TYPE_DF) {
		add_acl_entry(card, file, SC_AC_OP_CREATE, attr[0]);
		add_acl_entry(card, file, SC_AC_OP_CRYPTO, attr[1]);
		add_acl_entry(card, file, SC_AC_OP_LIST_FILES, attr[2]);
		add_acl_entry(card, file, SC_AC_OP_DELETE, attr[3]);
		add_acl_entry(card, file, SC_AC_OP_PIN_DEFINE, attr[4]);
		add_acl_entry(card, file, SC_AC_OP_PIN_CHANGE, attr[5]);
		add_acl_entry(card, file, SC_AC_OP_PIN_RESET, attr[6]);
		sc_log(card->ctx, "SC_FILE_TYPE_DF:CRYPTO %X", attr[1]);
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)  { /* EF */
		switch (file->ef_structure) {
		case SC_CARDCTL_OBERTHUR_KEY_DES:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_PSO_DECRYPT, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_PSO_ENCRYPT, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_PSO_COMPUTE_CHECKSUM, attr[3]);
			add_acl_entry(card, file, SC_AC_OP_PSO_VERIFY_CHECKSUM, attr[4]);
			add_acl_entry(card, file, SC_AC_OP_INTERNAL_AUTHENTICATE, attr[5]);
			add_acl_entry(card, file, SC_AC_OP_EXTERNAL_AUTHENTICATE, attr[6]);
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_PSO_ENCRYPT, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_PSO_VERIFY_SIGNATURE, attr[4]);
			add_acl_entry(card, file, SC_AC_OP_EXTERNAL_AUTHENTICATE, attr[6]);
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_CRT:
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_PSO_DECRYPT, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_PSO_COMPUTE_SIGNATURE, attr[3]);
			add_acl_entry(card, file, SC_AC_OP_INTERNAL_AUTHENTICATE, attr[5]);
			break;
		}
	}
	else   {
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			add_acl_entry(card, file, SC_AC_OP_WRITE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_READ, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_ERASE, attr[3]);
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			add_acl_entry(card, file, SC_AC_OP_WRITE, attr[0]);
			add_acl_entry(card, file, SC_AC_OP_UPDATE, attr[1]);
			add_acl_entry(card, file, SC_AC_OP_READ, attr[2]);
			add_acl_entry(card, file, SC_AC_OP_ERASE, attr[3]);
			break;
		}
	}

	file->status = SC_FILE_STATUS_ACTIVATED;
	file->magic = SC_FILE_MAGIC;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
auth_select_file(struct sc_card *card, const struct sc_path *in_path,
				 struct sc_file **file_out)
{
	struct sc_path path;
	struct sc_file *tmp_file = NULL;
	size_t offs, ii;
	int rv;

	LOG_FUNC_CALLED(card->ctx);
	assert(card != NULL && in_path != NULL);

	memcpy(&path, in_path, sizeof(struct sc_path));

	if (!auth_current_df)
		return SC_ERROR_OBJECT_NOT_FOUND;

	sc_log(card->ctx, "in_path; type=%d, path=%s, out %p",
			in_path->type, sc_print_path(in_path), file_out);
	sc_log(card->ctx, "current path; type=%d, path=%s",
			auth_current_df->path.type, sc_print_path(&auth_current_df->path));
	if (auth_current_ef)
		sc_log(card->ctx, "current file; type=%d, path=%s",
				auth_current_ef->path.type, sc_print_path(&auth_current_ef->path));

	if (path.type == SC_PATH_TYPE_PARENT || path.type == SC_PATH_TYPE_FILE_ID)   {
		sc_file_free(auth_current_ef);
		auth_current_ef = NULL;

		rv = iso_ops->select_file(card, &path, &tmp_file);
		LOG_TEST_RET(card->ctx, rv, "select file failed");
		if (!tmp_file)
			return SC_ERROR_OBJECT_NOT_FOUND;

		if (path.type == SC_PATH_TYPE_PARENT)   {
			memcpy(&tmp_file->path, &auth_current_df->path, sizeof(struct sc_path));
			if (tmp_file->path.len > 2)
				tmp_file->path.len -= 2;

			sc_file_free(auth_current_df);
			auth_current_df = NULL;
			sc_file_dup(&auth_current_df, tmp_file);
		}
		else   {
			if (tmp_file->type == SC_FILE_TYPE_DF)   {
				sc_concatenate_path(&tmp_file->path, &auth_current_df->path, &path);

				sc_file_free(auth_current_df);
				auth_current_df = NULL;
				sc_file_dup(&auth_current_df, tmp_file);
			}
			else   {
				sc_file_free(auth_current_ef);
				auth_current_ef = NULL;

				sc_file_dup(&auth_current_ef, tmp_file);
				sc_concatenate_path(&auth_current_ef->path, &auth_current_df->path, &path);
			}
		}
		if (file_out) {
			sc_file_free(*file_out);
			sc_file_dup(file_out, tmp_file);
		}

		sc_file_free(tmp_file);
	}
	else if (path.type == SC_PATH_TYPE_DF_NAME)   {
		rv = iso_ops->select_file(card, &path, NULL);
		if (rv)   {
			sc_file_free(auth_current_ef);
			auth_current_ef = NULL;
		}
		LOG_TEST_RET(card->ctx, rv, "select file failed");
	}
	else   {
		for (offs = 0; offs < path.len && offs < auth_current_df->path.len; offs += 2)
			if (path.value[offs] != auth_current_df->path.value[offs] ||
					path.value[offs + 1] != auth_current_df->path.value[offs + 1])
				break;

		sc_log(card->ctx, "offs %"SC_FORMAT_LEN_SIZE_T"u", offs);
		if (offs && offs < auth_current_df->path.len)   {
			size_t deep = auth_current_df->path.len - offs;

			sc_log(card->ctx, "deep %"SC_FORMAT_LEN_SIZE_T"u",
			       deep);
			for (ii=0; ii<deep; ii+=2)   {
				struct sc_path tmp_path;

				memcpy(&tmp_path, &auth_current_df->path,  sizeof(struct sc_path));
				tmp_path.type = SC_PATH_TYPE_PARENT;

				rv = auth_select_file (card, &tmp_path, file_out);
				LOG_TEST_RET(card->ctx, rv, "select file failed");
			}
		}

		if (path.len > offs)   {
			struct sc_path tmp_path;

			memset(&tmp_path, 0, sizeof(struct sc_path));
			tmp_path.type = SC_PATH_TYPE_FILE_ID;
			tmp_path.len = 2;

			for (ii=0; ii < path.len - offs; ii+=2)   {
				memcpy(tmp_path.value, path.value + offs + ii, 2);

				rv = auth_select_file(card, &tmp_path, file_out);
				LOG_TEST_RET(card->ctx, rv, "select file failed");
			}
		}
		else if (path.len - offs == 0 && file_out)  {
			if (sc_compare_path(&path, &auth_current_df->path))
				sc_file_dup(file_out, auth_current_df);
			else  if (auth_current_ef)
				sc_file_dup(file_out, auth_current_ef);
			else
				LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "No current EF");
		}
	}

	LOG_FUNC_RETURN(card->ctx, 0);
}


static int
auth_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x34, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 0x40;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	if (apdu.resplen == 0x100 && rbuf[0]==0 && rbuf[1]==0)
		LOG_FUNC_RETURN(card->ctx, 0);

	buflen = buflen < apdu.resplen ? buflen : apdu.resplen;
	memcpy(buf, rbuf, buflen);

	LOG_FUNC_RETURN(card->ctx, buflen);
}


static int
auth_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_apdu apdu;
	unsigned char sbuf[2];
	int rv;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	rv = sc_path_print(pbuf, sizeof(pbuf), path);
	if (rv != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "path; type=%d, path=%s", path->type, pbuf);

	if (path->len < 2)   {
		sc_log(card->ctx, "Invalid path length");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (path->len > 2)   {
		struct sc_path parent = *path;

		parent.len -= 2;
		parent.type = SC_PATH_TYPE_PATH;
		rv = auth_select_file(card, &parent, NULL);
		LOG_TEST_RET(card->ctx, rv, "select parent failed ");
	}

	sbuf[0] = path->value[path->len - 2];
	sbuf[1] = path->value[path->len - 1];

	if (memcmp(sbuf,"\x00\x00",2)==0 || (memcmp(sbuf,"\xFF\xFF",2)==0) ||
			memcmp(sbuf,"\x3F\xFF",2)==0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x02, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.sw1==0x6A && apdu.sw2==0x82)   {
		/* Clean up tDF contents.*/
		struct sc_path tmp_path;
		int ii, len;
		unsigned char lbuf[SC_MAX_APDU_BUFFER_SIZE];

		memset(&tmp_path, 0, sizeof(struct sc_path));
		tmp_path.type = SC_PATH_TYPE_FILE_ID;
		memcpy(tmp_path.value, sbuf, 2);
		tmp_path.len = 2;
		rv = auth_select_file(card, &tmp_path, NULL);
		LOG_TEST_RET(card->ctx, rv, "select DF failed");

		len = auth_list_files(card, lbuf, sizeof(lbuf));
		LOG_TEST_RET(card->ctx, len, "list DF failed");

		for (ii=0; ii<len/2; ii++)   {
			struct sc_path tmp_path_x;

			memset(&tmp_path_x, 0, sizeof(struct sc_path));
			tmp_path_x.type = SC_PATH_TYPE_FILE_ID;
			tmp_path_x.value[0] = *(lbuf + ii*2);
			tmp_path_x.value[1] = *(lbuf + ii*2 + 1);
			tmp_path_x.len = 2;

			rv = auth_delete_file(card, &tmp_path_x);
			LOG_TEST_RET(card->ctx, rv, "delete failed");
		}

		tmp_path.type = SC_PATH_TYPE_PARENT;
		rv = auth_select_file(card, &tmp_path, NULL);
		LOG_TEST_RET(card->ctx, rv, "select parent failed");

		apdu.p1 = 1;
		rv = sc_transmit_apdu(card, &apdu);
	}

	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
acl_to_ac_byte(struct sc_card *card, const struct sc_acl_entry *e)
{
	unsigned key_ref;

	if (e == NULL)
		return SC_ERROR_OBJECT_NOT_FOUND;

	key_ref = e->key_ref & ~OBERTHUR_PIN_LOCAL;

	switch (e->method) {
	case SC_AC_NONE:
		LOG_FUNC_RETURN(card->ctx, 0);

	case SC_AC_CHV:
		if (key_ref > 0 && key_ref < 6)
			LOG_FUNC_RETURN(card->ctx, (0x20 | key_ref));
		else
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	case SC_AC_PRO:
		if (((key_ref & 0xE0) != 0x60) || ((key_ref & 0x18) == 0))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
		else
			LOG_FUNC_RETURN(card->ctx, key_ref);

	case SC_AC_NEVER:
		return 0xff;
	}

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
}


static int
encode_file_structure_V5(struct sc_card *card, const struct sc_file *file,
				 unsigned char *buf, size_t *buflen)
{
	size_t ii;
	int rv=0, size;
	unsigned char *p = buf;
	unsigned char  ops[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "id %04X; size %"SC_FORMAT_LEN_SIZE_T"u; type 0x%X/0x%X",
	       file->id, file->size, file->type, file->ef_structure);

	if (*buflen < 0x18)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	p[0] = 0x62, p[1] = 0x16;
	p[2] = 0x82, p[3] = 0x02;

	rv = 0;
	if (file->type == SC_FILE_TYPE_DF)  {
		p[4] = 0x38;
		p[5] = 0x00;
	}
	else  if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		switch (file->ef_structure) {
		case SC_FILE_EF_TRANSPARENT:
			p[4] = 0x01;
			p[5] = 0x01;
			break;
		case SC_FILE_EF_LINEAR_VARIABLE:
			p[4] = 0x04;
			p[5] = 0x01;
			break;
		default:
			rv = SC_ERROR_INVALID_ARGUMENTS;
			break;
		}
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)  {
		switch (file->ef_structure) {
		case SC_CARDCTL_OBERTHUR_KEY_DES:
			p[4] = 0x11;
			p[5] = 0x00;
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC:
			p[4] = 0x12;
			p[5] = 0x00;
			break;
		case SC_CARDCTL_OBERTHUR_KEY_RSA_CRT:
			p[4] = 0x14;
			p[5] = 0x00;
			break;
		default:
			rv = -1;
			break;
		}
	}
	else
		rv = SC_ERROR_INVALID_ARGUMENTS;

	if (rv)   {
		sc_log(card->ctx, "Invalid EF structure 0x%X/0x%X", file->type, file->ef_structure);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
	}

	p[6] = 0x83;
	p[7] = 0x02;
	p[8] = file->id >> 8;
	p[9] = file->id & 0xFF;

	p[10] = 0x85;
	p[11] = 0x02;

	size = file->size;

	if (file->type == SC_FILE_TYPE_DF)   {
		size &= 0xFF;
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF &&
			file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)   {
		sc_log(card->ctx, "ef %s","SC_FILE_EF_RSA_PUBLIC");
		if (file->size == PUBKEY_512_ASN1_SIZE || file->size == 512)
			size = 512;
		else if (file->size == PUBKEY_1024_ASN1_SIZE || file->size == 1024)
			size = 1024;
		else if (file->size == PUBKEY_2048_ASN1_SIZE || file->size == 2048)
			size = 2048;
		else   {
			sc_log(card->ctx,
			       "incorrect RSA size %"SC_FORMAT_LEN_SIZE_T"X",
			       file->size);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
		}
	}
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF &&
			file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		if (file->size == 8 || file->size == 64)
			size = 64;
		else if (file->size == 16 || file->size == 128)
			size = 128;
		else if (file->size == 24 || file->size == 192)
			size = 192;
		else   {
			sc_log(card->ctx,
			       "incorrect DES size %"SC_FORMAT_LEN_SIZE_T"u",
			       file->size);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);
		}
	}

	p[12] = (size >> 8) & 0xFF;
	p[13] = size & 0xFF;

	p[14] = 0x86;
	p[15] = 0x08;

	if (file->type == SC_FILE_TYPE_DF) {
		ops[0] = SC_AC_OP_CREATE;
		ops[1] = SC_AC_OP_CRYPTO;
		ops[2] = SC_AC_OP_LIST_FILES;
		ops[3] = SC_AC_OP_DELETE;
		ops[4] = SC_AC_OP_PIN_DEFINE;
		ops[5] = SC_AC_OP_PIN_CHANGE;
		ops[6] = SC_AC_OP_PIN_RESET;
	}
	else if (file->type == SC_FILE_TYPE_WORKING_EF)   {
		if (file->ef_structure == SC_FILE_EF_TRANSPARENT)   {
			sc_log(card->ctx, "SC_FILE_EF_TRANSPARENT");
			ops[0] = SC_AC_OP_WRITE;
			ops[1] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_READ;
			ops[3] = SC_AC_OP_ERASE;
		}
		else if (file->ef_structure == SC_FILE_EF_LINEAR_VARIABLE)  {
			sc_log(card->ctx, "SC_FILE_EF_LINEAR_VARIABLE");
			ops[0] = SC_AC_OP_WRITE;
			ops[1] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_READ;
			ops[3] = SC_AC_OP_ERASE;
		}
	}
	else   if (file->type == SC_FILE_TYPE_INTERNAL_EF)   {
		if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)  {
			sc_log(card->ctx, "EF_DES");
			ops[0] = SC_AC_OP_UPDATE;
			ops[1] = SC_AC_OP_PSO_DECRYPT;
			ops[2] = SC_AC_OP_PSO_ENCRYPT;
			ops[3] = SC_AC_OP_PSO_COMPUTE_CHECKSUM;
			ops[4] = SC_AC_OP_PSO_VERIFY_CHECKSUM;
			ops[5] = SC_AC_OP_INTERNAL_AUTHENTICATE;
			ops[6] = SC_AC_OP_EXTERNAL_AUTHENTICATE;
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  {
			sc_log(card->ctx, "EF_RSA_PUBLIC");
			ops[0] = SC_AC_OP_UPDATE;
			ops[2] = SC_AC_OP_PSO_ENCRYPT;
			ops[4] = SC_AC_OP_PSO_VERIFY_SIGNATURE;
			ops[6] = SC_AC_OP_EXTERNAL_AUTHENTICATE;
		}
		else if (file->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)  {
			sc_log(card->ctx, "EF_RSA_PRIVATE");
			ops[0] = SC_AC_OP_UPDATE;
			ops[1] = SC_AC_OP_PSO_DECRYPT;
			ops[3] = SC_AC_OP_PSO_COMPUTE_SIGNATURE;
			ops[5] = SC_AC_OP_INTERNAL_AUTHENTICATE;
		}
	}

	for (ii = 0; ii < sizeof(ops); ii++) {
		const struct sc_acl_entry *entry;

		p[16+ii] = 0xFF;
		if (ops[ii]==0xFF)
			continue;
		entry = sc_file_get_acl_entry(file, ops[ii]);
		rv = acl_to_ac_byte(card,entry);
		LOG_TEST_RET(card->ctx, rv, "Invalid ACL");
		p[16+ii] = rv;
	}

	*buflen = 0x18;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
auth_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_apdu apdu;
	struct sc_path path;
	int rv, rec_nr;
	unsigned char sbuf[0x18];
	size_t sendlen = sizeof(sbuf);
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	rv = sc_path_print(pbuf, sizeof(pbuf), &file->path);
	if (rv != SC_SUCCESS)
		pbuf[0] = '\0';
	sc_log(card->ctx, " create path=%s", pbuf);

	sc_log(card->ctx,
	       "id %04X; size %"SC_FORMAT_LEN_SIZE_T"u; type 0x%X; ef 0x%X",
	       file->id, file->size, file->type, file->ef_structure);

	if (file->id==0x0000 || file->id==0xFFFF || file->id==0x3FFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = sc_path_print(pbuf, sizeof(pbuf), &card->cache.current_path);
	if (rv != SC_SUCCESS)
		pbuf[0] = '\0';

	if (file->path.len)   {
		memcpy(&path, &file->path, sizeof(path));
		if (path.len>2)
			path.len -= 2;

		if (auth_select_file(card, &path, NULL))   {
			sc_log(card->ctx, "Cannot select parent DF.");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}
	}

	rv = encode_file_structure_V5(card, file, sbuf, &sendlen);
	LOG_TEST_RET(card->ctx, rv, "File structure encoding failed");

	if (file->type != SC_FILE_TYPE_DF && file->ef_structure != SC_FILE_EF_TRANSPARENT)
		rec_nr = file->record_count;
	else
		rec_nr = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, rec_nr);
	apdu.data = sbuf;
	apdu.datalen = sendlen;
	apdu.lc = sendlen;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	/* select created DF. */
	if (file->type == SC_FILE_TYPE_DF)   {
		struct sc_path tmp_path;
		struct sc_file *df_file = NULL;

		memset(&tmp_path, 0, sizeof(struct sc_path));
		tmp_path.type = SC_PATH_TYPE_FILE_ID;
		tmp_path.value[0] = file->id >> 8;
		tmp_path.value[1] = file->id & 0xFF;
		tmp_path.len = 2;
		rv = auth_select_file(card, &tmp_path, &df_file);
		sc_log(card->ctx, "rv %i", rv);
	}

	sc_file_free(auth_current_ef);
	auth_current_ef = NULL;
	sc_file_dup(&auth_current_ef, file);

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct auth_senv *auth_senv = &((struct auth_private_data *) card->drv_data)->senv;
	struct sc_apdu apdu;
	long unsigned pads = env->algorithm_flags & SC_ALGORITHM_RSA_PADS;
	long unsigned supported_pads = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_PAD_ISO9796;
	int rv;
	unsigned char rsa_sbuf[3] = {
		0x80, 0x01, 0xFF
	};
	unsigned char des_sbuf[13] = {
		0x80, 0x01, 0x01,
		0x87, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "op %i; path %s; key_ref 0x%X; algos 0x%X; flags 0x%lX",
	       env->operation, sc_print_path(&env->file_ref), env->key_ref[0],
	       env->algorithm_flags, env->flags);

	memset(auth_senv, 0, sizeof(struct auth_senv));

	if (!(env->flags & SC_SEC_ENV_FILE_REF_PRESENT))
		LOG_TEST_RET(card->ctx, SC_ERROR_INTERNAL, "Key file is not selected.");

	switch (env->algorithm)   {
	case SC_ALGORITHM_DES:
	case SC_ALGORITHM_3DES:
		sc_log(card->ctx,
		       "algo SC_ALGORITHM_xDES: ref %X, flags %lX",
		       env->algorithm_ref, env->flags);

		if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = 3;
			apdu.data = des_sbuf;
			apdu.datalen = 3;
		}
		else {
			sc_log(card->ctx, "Invalid crypto operation: %X", env->operation);
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Invalid crypto operation");
		}

		break;
	case SC_ALGORITHM_RSA:
		sc_log(card->ctx, "algo SC_ALGORITHM_RSA");
		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) {
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "No support for hashes.");
		}

		if (pads & (~supported_pads))   {
			sc_log(card->ctx, "No support for PAD %lX", pads);
			LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "No padding support.");
		}

		if (env->operation == SC_SEC_OPERATION_SIGN)   {
			rsa_sbuf[2] = 0x11;

			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB6);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else if (env->operation == SC_SEC_OPERATION_DECIPHER)   {
			rsa_sbuf[2] = 0x11;

			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0xB8);
			apdu.lc = sizeof(rsa_sbuf);
			apdu.datalen = sizeof(rsa_sbuf);
			apdu.data = rsa_sbuf;
		}
		else {
			sc_log(card->ctx, "Invalid crypto operation: %X", env->operation);
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
		}

		break;
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Invalid crypto algorithm supplied");
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	auth_senv->algorithm = env->algorithm;

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_restore_security_env(struct sc_card *card, int se_num)
{
	return SC_SUCCESS;
}


static int
auth_compute_signature(struct sc_card *card, const unsigned char *in, size_t ilen,
		unsigned char * out, size_t olen)
{
	struct sc_apdu apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	if (!card || !in || !out)   {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	else if (ilen > 96)   {
		sc_log(card->ctx,
		       "Illegal input length %"SC_FORMAT_LEN_SIZE_T"u",
		       ilen);
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Illegal input length");
	}

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "inlen %"SC_FORMAT_LEN_SIZE_T"u, outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       ilen, olen);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.datalen = ilen;
	apdu.data = in;
	apdu.lc = ilen;
	apdu.le = olen > 256 ? 256 : olen;
	apdu.resp = resp;
	apdu.resplen = olen;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Compute signature failed");

	if (apdu.resplen > olen)   {
		sc_log(card->ctx,
		       "Compute signature failed: invalid response length %"SC_FORMAT_LEN_SIZE_T"u",
		       apdu.resplen);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_CARD_CMD_FAILED);
	}

	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


static int
auth_decipher(struct sc_card *card, const unsigned char *in, size_t inlen,
				unsigned char *out, size_t outlen)
{
	struct sc_apdu apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv, _inlen = inlen;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "crgram_len %"SC_FORMAT_LEN_SIZE_T"u;  outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       inlen, outlen);
	if (!out || !outlen || inlen > SC_MAX_APDU_BUFFER_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);

	sc_log(card->ctx, "algorithm SC_ALGORITHM_RSA");
	if (inlen % 64)   {
		rv = SC_ERROR_INVALID_ARGUMENTS;
		goto done;
	}

	_inlen = inlen;
	if (_inlen == 256)   {
		apdu.cla |= 0x10;
		apdu.data = in;
		apdu.datalen = 8;
		apdu.resp = resp;
		apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
		apdu.lc = 8;
		apdu.le = 256;

		rv = sc_transmit_apdu(card, &apdu);
		sc_log(card->ctx, "rv %i", rv);
		LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, rv, "Card returned error");

		_inlen -= 8;
		in += 8;

		apdu.cla &= ~0x10;
	}

	apdu.data = in;
	apdu.datalen = _inlen;
	apdu.resp = resp;
	apdu.resplen = SC_MAX_APDU_BUFFER_SIZE;
	apdu.lc = _inlen;
	apdu.le = _inlen;

	rv = sc_transmit_apdu(card, &apdu);
	sc_log(card->ctx, "rv %i", rv);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	sc_log(card->ctx, "rv %i", rv);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	if (outlen > apdu.resplen)
		outlen = apdu.resplen;

	memcpy(out, apdu.resp, outlen);
	rv = outlen;

done:
	LOG_FUNC_RETURN(card->ctx, rv);
}


/* Return the default AAK for this type of card */
static int
auth_get_default_key(struct sc_card *card, struct sc_cardctl_default_key *data)
{
	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NO_DEFAULT_KEY);
}


static int
auth_encode_exponent(unsigned long exponent, unsigned char *buff, size_t buff_len)
{
	int    shift;
	size_t ii;

	for (shift=0; exponent >> (shift+8); shift += 8)
		;

	for (ii = 0; ii<buff_len && shift>=0 ; ii++, shift-=8)
		*(buff + ii) = (exponent >> shift) & 0xFF;

	if (ii==buff_len)
		return 0;
	else
		return ii;
}


/* Generate key on-card */
static int
auth_generate_key(struct sc_card *card, int use_sm,
		struct sc_cardctl_oberthur_genkey_info *data)
{
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_path tmp_path;
	int rv = 0;

	LOG_FUNC_CALLED(card->ctx);
	if (data->key_bits < 512 || data->key_bits > 2048 ||
			(data->key_bits%0x20)!=0)   {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Illegal key length");
	}

	sbuf[0] = (data->id_pub >> 8) & 0xFF;
	sbuf[1] = data->id_pub & 0xFF;
	sbuf[2] = (data->id_prv >> 8) & 0xFF;
	sbuf[3] = data->id_prv & 0xFF;
	if (data->exponent != 0x10001)   {
		rv = auth_encode_exponent(data->exponent, &sbuf[5],SC_MAX_APDU_BUFFER_SIZE-6);
		LOG_TEST_RET(card->ctx, rv, "Cannot encode exponent");

		sbuf[4] = rv;
		rv++;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x46, 0x00, 0x00);
	apdu.resp = calloc(1, data->key_bits/8+8);
	if (!apdu.resp)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	apdu.resplen = data->key_bits/8+8;
	apdu.lc = rv + 4;
	apdu.le = data->key_bits/8;
	apdu.data = sbuf;
	apdu.datalen = rv + 4;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	memset(&tmp_path, 0, sizeof(struct sc_path));
	tmp_path.type = SC_PATH_TYPE_FILE_ID;
	tmp_path.len = 2;
	memcpy(tmp_path.value, sbuf, 2);

	rv = auth_select_file(card, &tmp_path, NULL);
	LOG_TEST_RET(card->ctx, rv, "cannot select public key");

	rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC,
			1, apdu.resp, data->key_bits/8);
	LOG_TEST_RET(card->ctx, rv, "auth_read_component() returned error");

	apdu.resplen = rv;

	if (data->pubkey)   {
		if (data->pubkey_len < apdu.resplen)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		memcpy(data->pubkey,apdu.resp,apdu.resplen);
	}

	data->pubkey_len = apdu.resplen;
	free(apdu.resp);

	sc_log(card->ctx, "resulted public key len %"SC_FORMAT_LEN_SIZE_T"u",
	       apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
auth_update_component(struct sc_card *card, struct auth_update_component_info *args)
{
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE + 0x10];
	unsigned char ins, p1, p2;
	int rv, len;

	LOG_FUNC_CALLED(card->ctx);
	if (args->len > sizeof(sbuf) || args->len > 0x100)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(card->ctx, "nn %i; len %i", args->component, args->len);
	ins = 0xD8;
	p1 = args->component;
	p2 = 0x04;
	len = 0;

	sbuf[len++] = args->type;
	sbuf[len++] = args->len;
	memcpy(sbuf + len, args->data, args->len);
	len += args->len;

	if (args->type == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		int outl;
		const unsigned char in[8] = {0,0,0,0,0,0,0,0};
		unsigned char out[8];
		EVP_CIPHER_CTX  * ctx = NULL;

		if (args->len!=8 && args->len!=24)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		ctx = EVP_CIPHER_CTX_new();
		if (ctx == NULL) 
		    LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

		p2 = 0;
		if (args->len == 24)
			EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, args->data, NULL);
		else
			EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, args->data, NULL);
		rv = EVP_EncryptUpdate(ctx, out, &outl, in, 8);
		EVP_CIPHER_CTX_free(ctx);
		if (rv == 0) {
			sc_log(card->ctx, "OpenSSL encryption error.");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
		}

		sbuf[len++] = 0x03;
		memcpy(sbuf + len, out, 3);
		len += 3;
	}
	else   {
		sbuf[len++] = 0;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, ins,	p1, p2);
	apdu.cla |= 0x80;
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;
	if (args->len == 0x100)   {
		sbuf[0] = args->type;
		sbuf[1] = 0x20;
		memcpy(sbuf + 2, args->data, 0x20);
		sbuf[0x22] = 0;
		apdu.cla |= 0x10;
		apdu.data = sbuf;
		apdu.datalen = 0x23;
		apdu.lc = 0x23;
		rv = sc_transmit_apdu(card, &apdu);
		apdu.cla &= ~0x10;
		LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

		sbuf[0] = args->type;
		sbuf[1] = 0xE0;
		memcpy(sbuf + 2, args->data + 0x20, 0xE0);
		sbuf[0xE2] = 0;
		apdu.data = sbuf;
		apdu.datalen = 0xE3;
		apdu.lc = 0xE3;
	}

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_update_key(struct sc_card *card, struct sc_cardctl_oberthur_updatekey_info *info)
{
	int rv, ii;

	LOG_FUNC_CALLED(card->ctx);

	if (info->data_len != sizeof(void *) || !info->data)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (info->type == SC_CARDCTL_OBERTHUR_KEY_RSA_CRT)   {
		struct sc_pkcs15_prkey_rsa  *rsa = (struct sc_pkcs15_prkey_rsa *)info->data;
		struct sc_pkcs15_bignum bn[5];

		sc_log(card->ctx, "Import RSA CRT");
		bn[0] = rsa->p;
		bn[1] = rsa->q;
		bn[2] = rsa->iqmp;
		bn[3] = rsa->dmp1;
		bn[4] = rsa->dmq1;
		for (ii=0;ii<5;ii++)   {
			struct auth_update_component_info args;

			memset(&args, 0, sizeof(args));
			args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_CRT;
			args.component = ii+1;
			args.data = bn[ii].data;
			args.len = bn[ii].len;

			rv = auth_update_component(card, &args);
			LOG_TEST_RET(card->ctx, rv, "Update RSA component failed");
		}
	}
	else if (info->type == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		rv = SC_ERROR_NOT_SUPPORTED;
	}
	else   {
		rv = SC_ERROR_INVALID_DATA;
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return auth_get_default_key(card,
				(struct sc_cardctl_default_key *) ptr);
	case SC_CARDCTL_OBERTHUR_GENERATE_KEY:
		return auth_generate_key(card, 0,
				(struct sc_cardctl_oberthur_genkey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_UPDATE_KEY:
		return auth_update_key(card,
				(struct sc_cardctl_oberthur_updatekey_info *) ptr);
	case SC_CARDCTL_OBERTHUR_CREATE_PIN:
		return auth_create_reference_data(card,
				(struct sc_cardctl_oberthur_createpin_info *) ptr);
	case SC_CARDCTL_GET_SERIALNR:
		return auth_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_LIFECYCLE_GET:
	case SC_CARDCTL_LIFECYCLE_SET:
		return SC_ERROR_NOT_SUPPORTED;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
}


static int
auth_read_component(struct sc_card *card, enum SC_CARDCTL_OBERTHUR_KEY_TYPE type,
		int num, unsigned char *out, size_t outlen)
{
	struct sc_apdu apdu;
	int rv;
	unsigned char resp[256];

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "num %i, outlen %"SC_FORMAT_LEN_SIZE_T"u, type %i",
	       num, outlen, type);

	if (!outlen || type!=SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INCORRECT_PARAMETERS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB4,	num, 0x00);
	apdu.cla |= 0x80;
	apdu.le = outlen;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	if (outlen < apdu.resplen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_WRONG_LENGTH);

	memcpy(out, apdu.resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


static int
auth_get_pin_reference (struct sc_card *card, int type, int reference, int cmd, int *out_ref)
{
	if (!out_ref)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	switch (type) {
	case SC_AC_CHV:
		if (reference != 1 && reference != 2 && reference != 4)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE);

		*out_ref = reference;
		if (reference == 1 || reference == 4)
			if (cmd == SC_PIN_CMD_VERIFY)
				*out_ref |= 0x80;
		break;

	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static void
auth_init_pin_info(struct sc_card *card, struct sc_pin_cmd_pin *pin,
		unsigned int type)
{
	pin->offset = 0;
	pin->pad_char   = 0xFF;
	pin->encoding   = SC_PIN_ENCODING_ASCII;

	if (type == OBERTHUR_AUTH_TYPE_PIN)   {
		pin->max_length = OBERTHUR_AUTH_MAX_LENGTH_PIN;
		pin->pad_length = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	}
	else    {
		pin->max_length = OBERTHUR_AUTH_MAX_LENGTH_PUK;
		pin->pad_length = OBERTHUR_AUTH_MAX_LENGTH_PUK;
	}
}


static int
auth_pin_verify_pinpad(struct sc_card *card, int pin_reference, int *tries_left)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	struct sc_pin_cmd_data pin_cmd;
	struct sc_apdu apdu;
	unsigned char ffs1[0x100];
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	memset(ffs1, 0xFF, sizeof(ffs1));
	memset(&pin_cmd, 0, sizeof(pin_cmd));

        rv = auth_pin_is_verified(card, pin_reference, tries_left);
    	sc_log(card->ctx, "auth_pin_is_verified returned rv %i", rv);

	/* Return SUCCESS without verifying if
	 * PIN has been already verified and PIN pad has to be used. */
	if (!rv)
		LOG_FUNC_RETURN(card->ctx, rv);

	pin_cmd.flags |= SC_PIN_CMD_NEED_PADDING;

	/* For Oberthur card, PIN command data length has to be 0x40.
	 * In PCSC10 v2.06 the upper limit of pin.max_length is 8.
	 *
	 * The standard sc_build_pin() throws an error when 'pin.len > pin.max_length' .
	 * So, let's build our own APDU.
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, pin_reference);
	apdu.lc = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	apdu.datalen = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	apdu.data = ffs1;

	pin_cmd.apdu = &apdu;
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;
	pin_cmd.flags |= SC_PIN_CMD_USE_PINPAD;
	pin_cmd.pin_reference = pin_reference;
	if (pin_cmd.pin1.min_length < 4)
		pin_cmd.pin1.min_length = 4;
	pin_cmd.pin1.max_length = 8;
	pin_cmd.pin1.encoding = SC_PIN_ENCODING_ASCII;
	pin_cmd.pin1.offset = 5;
	pin_cmd.pin1.data = ffs1;
	pin_cmd.pin1.len = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	pin_cmd.pin1.pad_length = OBERTHUR_AUTH_MAX_LENGTH_PIN;

	rv = iso_drv->ops->pin_cmd(card, &pin_cmd, tries_left);
	LOG_TEST_RET(card->ctx, rv, "PIN CMD 'VERIFY' with pinpad failed");

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_pin_verify(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	if (type != SC_AC_CHV)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "PIN type other then SC_AC_CHV is not supported");

	data->flags |= SC_PIN_CMD_NEED_PADDING;

	auth_init_pin_info(card, &data->pin1, OBERTHUR_AUTH_TYPE_PIN);

	/* User PIN is always local. */
	if (data->pin_reference == OBERTHUR_PIN_REFERENCE_USER
			|| data->pin_reference == OBERTHUR_PIN_REFERENCE_ONETIME)
		data->pin_reference  |= OBERTHUR_PIN_LOCAL;

        rv = auth_pin_is_verified(card, data->pin_reference, tries_left);
    	sc_log(card->ctx, "auth_pin_is_verified returned rv %i", rv);

	/* Return if only PIN status has been asked. */
	if (data->pin1.data && !data->pin1.len)
		LOG_FUNC_RETURN(card->ctx, rv);

	/* Return SUCCESS without verifying if
	 * PIN has been already verified and PIN pad has to be used. */
	if (!rv && !data->pin1.data && !data->pin1.len)
		LOG_FUNC_RETURN(card->ctx, rv);

	if (!data->pin1.data && !data->pin1.len)
		rv = auth_pin_verify_pinpad(card, data->pin_reference, tries_left);
	else
		rv = iso_drv->ops->pin_cmd(card, data, tries_left);

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_pin_is_verified(struct sc_card *card, int pin_reference, int *tries_left)
{
	struct sc_apdu apdu;
	int rv;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, pin_reference);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;

	/* Replace 'no tries left' with 'auth method blocked' */
	if (apdu.sw1 == 0x63 && apdu.sw2 == 0xC0)    {
		apdu.sw1 = 0x69;
		apdu.sw2 = 0x83;
	}

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	return rv;
}


static int
auth_pin_change_pinpad(struct sc_card *card, struct sc_pin_cmd_data *data,
		int *tries_left)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	struct sc_pin_cmd_data pin_cmd;
	struct sc_apdu apdu;
	unsigned char ffs1[0x100];
	unsigned char ffs2[0x100];
	int rv, pin_reference;

	LOG_FUNC_CALLED(card->ctx);

	pin_reference = data->pin_reference & ~OBERTHUR_PIN_LOCAL;

	memset(ffs1, 0xFF, sizeof(ffs1));
	memset(ffs2, 0xFF, sizeof(ffs2));
	memset(&pin_cmd, 0, sizeof(pin_cmd));

	if (data->pin1.len > OBERTHUR_AUTH_MAX_LENGTH_PIN)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "'PIN CHANGE' failed");

	if (data->pin1.data && data->pin1.len)
		memcpy(ffs1, data->pin1.data, data->pin1.len);

	pin_cmd.flags |= SC_PIN_CMD_NEED_PADDING;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, pin_reference);
	apdu.lc = OBERTHUR_AUTH_MAX_LENGTH_PIN * 2;
	apdu.datalen = OBERTHUR_AUTH_MAX_LENGTH_PIN * 2;
	apdu.data = ffs1;

	pin_cmd.apdu = &apdu;
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.cmd = SC_PIN_CMD_CHANGE;
	pin_cmd.flags |= SC_PIN_CMD_USE_PINPAD;
	pin_cmd.pin_reference = pin_reference;
	if (pin_cmd.pin1.min_length < 4)
		pin_cmd.pin1.min_length = 4;
	pin_cmd.pin1.max_length = 8;
	pin_cmd.pin1.encoding = SC_PIN_ENCODING_ASCII;
	pin_cmd.pin1.offset = 5 + OBERTHUR_AUTH_MAX_LENGTH_PIN;
	pin_cmd.pin1.data = ffs1;
	pin_cmd.pin1.len = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	pin_cmd.pin1.pad_length = 0;

	memcpy(&pin_cmd.pin2, &pin_cmd.pin1, sizeof(pin_cmd.pin2));
	pin_cmd.pin1.offset = 5;
	pin_cmd.pin2.data = ffs2;

	rv = iso_drv->ops->pin_cmd(card, &pin_cmd, tries_left);
	LOG_TEST_RET(card->ctx, rv, "PIN CMD 'VERIFY' with pinpad failed");

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_pin_change(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(card->ctx);

	if (data->pin1.len && data->pin2.len)   {
		/* Direct unblock style */
		data->flags |= SC_PIN_CMD_NEED_PADDING;
		data->flags &= ~SC_PIN_CMD_USE_PINPAD;
		data->apdu = NULL;

		data->pin_reference &= ~OBERTHUR_PIN_LOCAL;

		auth_init_pin_info(card, &data->pin1, OBERTHUR_AUTH_TYPE_PIN);
		auth_init_pin_info(card, &data->pin2, OBERTHUR_AUTH_TYPE_PIN);

		rv = iso_drv->ops->pin_cmd(card, data, tries_left);
		LOG_TEST_RET(card->ctx, rv, "CMD 'PIN CHANGE' failed");
	}
	else if (!data->pin1.len && !data->pin2.len)   {
		/* Oberthur unblock style with PIN pad. */
		rv = auth_pin_change_pinpad(card, data, tries_left);
		LOG_TEST_RET(card->ctx, rv, "'PIN CHANGE' failed: SOPIN verify with pinpad failed");
	}
	else   {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "'PIN CHANGE' failed");
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_pin_reset_oberthur_style(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	struct sc_pin_cmd_data pin_cmd;
	struct sc_path tmp_path;
	struct sc_file *tmp_file = NULL;
	struct sc_apdu apdu;
	unsigned char puk[OBERTHUR_AUTH_MAX_LENGTH_PUK];
	unsigned char ffs1[0x100];
	int rv, rvv, local_pin_reference;

	LOG_FUNC_CALLED(card->ctx);

	local_pin_reference = data->pin_reference & ~OBERTHUR_PIN_LOCAL;

	if (data->pin_reference !=  OBERTHUR_PIN_REFERENCE_USER)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Oberthur style 'PIN RESET' failed: invalid PIN reference");

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	memset(&tmp_path, 0, sizeof(struct sc_path));

	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;
	pin_cmd.pin_reference = OBERTHUR_PIN_REFERENCE_PUK;
	memcpy(&pin_cmd.pin1, &data->pin1, sizeof(pin_cmd.pin1));

	rv = auth_pin_verify(card, SC_AC_CHV, &pin_cmd, tries_left);
	LOG_TEST_RET(card->ctx, rv, "Oberthur style 'PIN RESET' failed: SOPIN verify error");

	sc_format_path("2000", &tmp_path);
	tmp_path.type = SC_PATH_TYPE_FILE_ID;
	rv = iso_ops->select_file(card, &tmp_path, &tmp_file);
	LOG_TEST_RET(card->ctx, rv, "select PUK file");

	if (!tmp_file || tmp_file->size < OBERTHUR_AUTH_MAX_LENGTH_PUK)
		LOG_TEST_RET(card->ctx, SC_ERROR_FILE_TOO_SMALL, "Oberthur style 'PIN RESET' failed");

	rv = iso_ops->read_binary(card, 0, puk, OBERTHUR_AUTH_MAX_LENGTH_PUK, 0);
	LOG_TEST_RET(card->ctx, rv, "read PUK file error");
	if (rv != OBERTHUR_AUTH_MAX_LENGTH_PUK)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_DATA, "Oberthur style 'PIN RESET' failed");

	memset(ffs1, 0xFF, sizeof(ffs1));
	memcpy(ffs1, puk, rv);

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
        pin_cmd.cmd = SC_PIN_CMD_UNBLOCK;
	pin_cmd.pin_reference = local_pin_reference;
	auth_init_pin_info(card, &pin_cmd.pin1, OBERTHUR_AUTH_TYPE_PUK);
	pin_cmd.pin1.data = ffs1;
	pin_cmd.pin1.len = OBERTHUR_AUTH_MAX_LENGTH_PUK;

	if (data->pin2.data)   {
		memcpy(&pin_cmd.pin2, &data->pin2, sizeof(pin_cmd.pin2));
		rv = auth_pin_reset(card, SC_AC_CHV, &pin_cmd, tries_left);
		LOG_FUNC_RETURN(card->ctx, rv);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, 0x00, local_pin_reference);
	apdu.lc = OBERTHUR_AUTH_MAX_LENGTH_PIN  + OBERTHUR_AUTH_MAX_LENGTH_PUK;
	apdu.datalen = OBERTHUR_AUTH_MAX_LENGTH_PIN  + OBERTHUR_AUTH_MAX_LENGTH_PUK;
	apdu.data = ffs1;

	pin_cmd.apdu = &apdu;
	pin_cmd.flags |= SC_PIN_CMD_USE_PINPAD | SC_PIN_CMD_IMPLICIT_CHANGE;

	pin_cmd.pin1.min_length = 4;
	pin_cmd.pin1.max_length = 8;
	pin_cmd.pin1.encoding = SC_PIN_ENCODING_ASCII;
	pin_cmd.pin1.offset = 5;

	pin_cmd.pin2.data = &ffs1[OBERTHUR_AUTH_MAX_LENGTH_PUK];
	pin_cmd.pin2.len = OBERTHUR_AUTH_MAX_LENGTH_PIN;
	pin_cmd.pin2.offset = 5 + OBERTHUR_AUTH_MAX_LENGTH_PUK;
	pin_cmd.pin2.min_length = 4;
	pin_cmd.pin2.max_length = 8;
	pin_cmd.pin2.encoding = SC_PIN_ENCODING_ASCII;

	rvv = iso_drv->ops->pin_cmd(card, &pin_cmd, tries_left);
	if (rvv)
		sc_log(card->ctx,
				"%s: PIN CMD 'VERIFY' with pinpad failed",
				sc_strerror(rvv));

	if (auth_current_ef) {
		struct sc_file *ef = NULL;
		rv = iso_ops->select_file(card, &auth_current_ef->path, &ef);
		if (rv == SC_SUCCESS) {
			sc_file_free(auth_current_ef);
			auth_current_ef = ef;
		} else
			sc_file_free(ef);
	}

	if (rv > 0)
		rv = 0;

	LOG_FUNC_RETURN(card->ctx, rv ? rv: rvv);
}


static int
auth_pin_reset(struct sc_card *card, unsigned int type,
		struct sc_pin_cmd_data *data, int *tries_left)
{
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	/* Oberthur unblock style: PUK value is a SOPIN */
	rv = auth_pin_reset_oberthur_style(card, SC_AC_CHV, data, tries_left);
	LOG_TEST_RET(card->ctx, rv, "Oberthur style 'PIN RESET' failed");

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int rv = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(card->ctx);
	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "auth_pin_cmd() unsupported PIN type");

	sc_log(card->ctx, "PIN CMD:%i; reference:%i; pin1:%p/%i, pin2:%p/%i", data->cmd,
			data->pin_reference, data->pin1.data, data->pin1.len,
			data->pin2.data, data->pin2.len);
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		rv = auth_pin_verify(card, SC_AC_CHV, data, tries_left);
		LOG_TEST_RET(card->ctx, rv, "CMD 'PIN VERIFY' failed");
		break;
	case SC_PIN_CMD_CHANGE:
		rv = auth_pin_change(card, SC_AC_CHV, data, tries_left);
		LOG_TEST_RET(card->ctx, rv, "CMD 'PIN VERIFY' failed");
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = auth_pin_reset(card, SC_AC_CHV, data, tries_left);
		LOG_TEST_RET(card->ctx, rv, "CMD 'PIN VERIFY' failed");
		break;
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported PIN operation");
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_create_reference_data (struct sc_card *card,
		struct sc_cardctl_oberthur_createpin_info *args)
{
	struct sc_apdu apdu;
	struct sc_pin_cmd_pin pin_info, puk_info;
	int rv, len;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE];

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "PIN reference %i", args->ref);

	if (args->type != SC_AC_CHV)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported PIN type");

	if (args->pin_tries < 1 || !args->pin || !args->pin_len)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN options");

	if (args->ref != OBERTHUR_PIN_REFERENCE_USER && args->ref != OBERTHUR_PIN_REFERENCE_PUK)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_PIN_REFERENCE, "Invalid PIN reference");

	auth_init_pin_info(card, &puk_info, OBERTHUR_AUTH_TYPE_PUK);
	auth_init_pin_info(card, &pin_info, OBERTHUR_AUTH_TYPE_PIN);

	if (args->puk && args->puk_len && (args->puk_len%puk_info.pad_length))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PUK options");

	len = 0;
	sc_log(card->ctx, "len %i", len);
	sbuf[len++] = args->pin_tries;
	sbuf[len++] = pin_info.pad_length;
	sc_log(card->ctx, "len %i", len);
	memset(sbuf + len, pin_info.pad_char, pin_info.pad_length);
	memcpy(sbuf + len, args->pin, args->pin_len);
	len += pin_info.pad_length;
	sc_log(card->ctx, "len %i", len);

	if (args->puk && args->puk_len)   {
		sbuf[len++] = args->puk_tries;
		sbuf[len++] = args->puk_len / puk_info.pad_length;
		sc_log(card->ctx, "len %i", len);
		memcpy(sbuf + len, args->puk, args->puk_len);
		len += args->puk_len;
	}

	sc_log(card->ctx, "len %i", len);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 1, args->ref & ~OBERTHUR_PIN_LOCAL);
	apdu.data = sbuf;
	apdu.datalen = len;
	apdu.lc = len;

	rv = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, sizeof(sbuf));
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_logout(struct sc_card *card)
{
	struct sc_apdu apdu;
	int ii, rv = 0, pin_ref;
	int reset_flag = 0x20;

	for (ii=0; ii < 4; ii++)   {
		rv = auth_get_pin_reference (card, SC_AC_CHV, ii+1, SC_PIN_CMD_UNBLOCK, &pin_ref);
		LOG_TEST_RET(card->ctx, rv, "Cannot get PIN reference");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x00);
		apdu.cla = 0x80;
		apdu.p2 = pin_ref | reset_flag;
		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
write_publickey (struct sc_card *card, unsigned int offset,
				const unsigned char *buf, size_t count)
{
	struct auth_update_component_info args;
	struct sc_pkcs15_pubkey_rsa key;
	int ii, rv;
	size_t len = 0, der_size = 0;

	LOG_FUNC_CALLED(card->ctx);

	sc_log_hex(card->ctx, "write_publickey", buf, count);

	if (1+offset > sizeof(rsa_der))
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid offset value");

	len = offset+count > sizeof(rsa_der) ? sizeof(rsa_der) - offset : count;

	memcpy(rsa_der + offset, buf, len);
	rsa_der_len = offset + len;

	if (rsa_der[0]==0x30)   {
		if (rsa_der[1] & 0x80)
			for (ii=0; ii < (rsa_der[1]&0x0F); ii++)
				der_size = der_size*0x100 + rsa_der[2+ii];
		else
			der_size = rsa_der[1];
	}

	sc_log(card->ctx, "der_size %"SC_FORMAT_LEN_SIZE_T"u", der_size);
	if (offset + len < der_size + 2)
		LOG_FUNC_RETURN(card->ctx, len);

	rv = sc_pkcs15_decode_pubkey_rsa(card->ctx, &key, rsa_der, rsa_der_len);
	rsa_der_len = 0;
	memset(rsa_der, 0, sizeof(rsa_der));
	LOG_TEST_RET(card->ctx, rv, "cannot decode public key");

	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 1;
	args.data = key.modulus.data;
	args.len = key.modulus.len;
	rv = auth_update_component(card, &args);
	LOG_TEST_RET(card->ctx, rv, "Update component failed");

	memset(&args, 0, sizeof(args));
	args.type = SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC;
	args.component = 2;
	args.data = key.exponent.data;
	args.len = key.exponent.len;
	rv = auth_update_component(card, &args);
	LOG_TEST_RET(card->ctx, rv, "Update component failed");

	LOG_FUNC_RETURN(card->ctx, len);
}


static int
auth_update_binary(struct sc_card *card, unsigned int offset,
		const unsigned char *buf, size_t count, unsigned long flags)
{
	int rv = 0;

	LOG_FUNC_CALLED(card->ctx);

	if (!auth_current_ef)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid auth_current_ef");

	sc_log(card->ctx, "offset %i; count %"SC_FORMAT_LEN_SIZE_T"u", offset,
	       count);
	sc_log(card->ctx, "last selected : magic %X; ef %X",
			auth_current_ef->magic, auth_current_ef->ef_structure);

	if (offset & ~0x7FFF)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid file offset");

	if (auth_current_ef->magic==SC_FILE_MAGIC &&
			 auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)  {
		rv = write_publickey(card, offset, buf, count);
	}
	else if (auth_current_ef->magic==SC_FILE_MAGIC &&
			auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_DES)   {
		struct auth_update_component_info args;

		memset(&args, 0, sizeof(args));
		args.type = SC_CARDCTL_OBERTHUR_KEY_DES;
		args.data = (unsigned char *)buf;
		args.len = count;
		rv = auth_update_component(card, &args);
	}
	else   {
		rv = iso_ops->update_binary(card, offset, buf, count, 0);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_read_binary(struct sc_card *card, unsigned int offset,
		unsigned char *buf, size_t count, unsigned long flags)
{
	int rv;
	struct sc_pkcs15_bignum bn[2];
	unsigned char *out = NULL;
	bn[0].data = NULL;
	bn[1].data = NULL;

	LOG_FUNC_CALLED(card->ctx);

	if (!auth_current_ef)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid auth_current_ef");

	sc_log(card->ctx,
	       "offset %i; size %"SC_FORMAT_LEN_SIZE_T"u; flags 0x%lX",
	       offset, count, flags);
	sc_log(card->ctx,"last selected : magic %X; ef %X",
			auth_current_ef->magic, auth_current_ef->ef_structure);

	if (offset & ~0x7FFF)
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid file offset");

	if (auth_current_ef->magic==SC_FILE_MAGIC &&
			auth_current_ef->ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC)   {
		int jj;
		unsigned char resp[256];
		size_t resp_len, out_len;
		struct sc_pkcs15_pubkey_rsa key;

		resp_len = sizeof(resp);
		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC,
				2, resp, resp_len);
		LOG_TEST_RET(card->ctx, rv, "read component failed");

		for (jj=0; jj<rv && *(resp+jj)==0; jj++)
			;

		if (rv - jj == 0)
			return SC_ERROR_INVALID_DATA;
		bn[0].data = calloc(1, rv - jj);
		if (!bn[0].data) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		bn[0].len = rv - jj;
		memcpy(bn[0].data, resp + jj, rv - jj);

		rv = auth_read_component(card, SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC,
				1, resp, resp_len);
		LOG_TEST_GOTO_ERR(card->ctx, rv, "Cannot read RSA public key component");

		bn[1].data = calloc(1, rv);
		if (!bn[1].data) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		bn[1].len = rv;
		memcpy(bn[1].data, resp, rv);

		key.exponent = bn[0];
		key.modulus = bn[1];

		if (sc_pkcs15_encode_pubkey_rsa(card->ctx, &key, &out, &out_len) != SC_SUCCESS) {
			rv = SC_ERROR_INVALID_ASN1_OBJECT;
			LOG_TEST_GOTO_ERR(card->ctx, rv, "cannot encode RSA public key");
		}
		else {
			if (out_len < offset) {
				rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
				goto err;
			}
			rv = ((out_len - offset) > count) ? count : (out_len - offset);
			memcpy(buf, out + offset, rv);

			sc_log_hex(card->ctx, "write_publickey", buf, rv);
		}
	}
	else {
		rv = iso_ops->read_binary(card, offset, buf, count, 0);
	}

err:
	free(bn[0].data);
	free(bn[1].data);
	free(out);

	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_read_record(struct sc_card *card, unsigned int nr_rec,
		unsigned char *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int rv = 0;
	unsigned char recvbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_log(card->ctx,
	       "auth_read_record(): nr_rec %i; count %"SC_FORMAT_LEN_SIZE_T"u",
	       nr_rec, count);

	if (nr_rec > 0xFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2, nr_rec, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.resplen == 0)
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


static int
auth_delete_record(struct sc_card *card, unsigned int nr_rec)
{
	struct sc_apdu apdu;
	int rv = 0;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "auth_delete_record(): nr_rec %i", nr_rec);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x32, nr_rec, 0x04);
	apdu.cla = 0x80;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, rv);
}


static int
auth_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	if (!serial)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (card->serialnr.len==0)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	memcpy(serial, &card->serialnr, sizeof(*serial));

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static const struct sc_card_error
auth_warnings[] = {
	{ 0x6282, SC_SUCCESS,
		"ignore warning 'End of file or record reached before reading Ne bytes'" },
	{0, 0, NULL},
};


static int
auth_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	int ii;

	for (ii=0; auth_warnings[ii].SWs; ii++)   {
		if (auth_warnings[ii].SWs == ((sw1 << 8) | sw2))   {
			sc_log(card->ctx, "%s", auth_warnings[ii].errorstr);
			return auth_warnings[ii].errorno;
		}
	}

	return iso_ops->check_sw(card, sw1, sw2);
}


static struct sc_card_driver *
sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	auth_ops = *iso_ops;
	auth_ops.match_card = auth_match_card;
	auth_ops.init = auth_init;
	auth_ops.finish = auth_finish;
	auth_ops.select_file = auth_select_file;
	auth_ops.list_files = auth_list_files;
	auth_ops.delete_file = auth_delete_file;
	auth_ops.create_file = auth_create_file;
	auth_ops.read_binary = auth_read_binary;
	auth_ops.update_binary = auth_update_binary;
	auth_ops.read_record = auth_read_record;
	auth_ops.delete_record = auth_delete_record;
	auth_ops.card_ctl = auth_card_ctl;
	auth_ops.set_security_env = auth_set_security_env;
	auth_ops.restore_security_env = auth_restore_security_env;
	auth_ops.compute_signature = auth_compute_signature;
	auth_ops.decipher = auth_decipher;
	auth_ops.process_fci = auth_process_fci;
	auth_ops.pin_cmd = auth_pin_cmd;
	auth_ops.logout = auth_logout;
	auth_ops.check_sw = auth_check_sw;
	return &auth_drv;
}


struct sc_card_driver *
sc_get_oberthur_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
