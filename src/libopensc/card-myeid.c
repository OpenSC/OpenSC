/*
 * card-myeid.c
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "types.h"

#define LOAD_KEY_MODULUS		0x80
#define LOAD_KEY_PUBLIC_EXPONENT	0x81
#define LOAD_KEY_PRIME_P		0x83
#define LOAD_KEY_PRIME_Q		0x84
#define LOAD_KEY_DP1			0x85
#define LOAD_KEY_DQ1			0x86
#define LOAD_KEY_INVQ			0x87
#define LOAD_KEY_MODE_EC_PRIV		0x87
#define LOAD_KEY_MODE_EC_PUB		0x86

#define LOAD_KEY_EC_PRIVATE	0x97
#define LOAD_KEY_EC_PUBLIC	0x96

#define MYEID_STATE_CREATION	0x01
#define MYEID_STATE_ACTIVATED	0x07

#define MYEID_INFINEON_CHIP_ATR		0x04
#define MYEID_CARD_NAME_MAX_LEN		100

static const char *myeid_card_name = "MyEID";
static char card_name_buf[MYEID_CARD_NAME_MAX_LEN];

static struct sc_card_operations myeid_ops;
static struct sc_card_driver myeid_drv = {
	"MyEID cards with PKCS#15 applet",
	"myeid",
	&myeid_ops,
	NULL,
	0,
	NULL
};

static const char *myeid_atrs[] = {
	"3B:F5:18:00:FF:81:31:FE:45:4D:79:45:49:44:65",
	"3B:F5:18:00:00:81:31:FE:45:4D:79:45:49:44:9A",
	"3B:85:80:01:4D:79:45:49:44:78",
	"3B:89:80:01:09:38:33:B1:4D:79:45:49:44:4C",
	"3B:F5:96:00:00:80:31:FE:45:4D:79:45:49:44:15", /* Infineon's chip */
	"3B:F5:96:00:00:81:31:FE:45:4D:79:45:49:44:14",
	NULL
};

typedef struct myeid_private_data {
	int card_state;

	unsigned short change_counter;
	/* the driver sets sec_env pointer in myeid_set_security_env and
	 it is used immediately in myeid_decipher to differentiate between RSA decryption and
	 ECDH key agreement. Note that this pointer is usually not valid
	 after this pair of calls and must not be used elsewhere. */
	const struct sc_security_env* sec_env;
} myeid_private_data_t;

static struct myeid_supported_ec_curves {
	char *curve_name;
	struct sc_object_id curve_oid;
	size_t size;
} ec_curves[] = {
	{"secp192r1", {{1, 2, 840, 10045, 3, 1, 1, -1}},192},
	/* {"secp224r1", {{1, 3, 132, 0, 33, -1}},		224}, */
	{"secp256r1", {{1, 2, 840, 10045, 3, 1, 7, -1}},256},
	{"secp384r1", {{1, 3, 132, 0, 34, -1}},		384},
	{"secp521r1", {{1, 3, 132, 0, 35, -1}},		521},
	{NULL, {{-1}}, 0},
};

static int myeid_get_info(struct sc_card *card, u8 *rbuf, size_t buflen);

static int myeid_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; myeid_atrs[i] != NULL; i++)
	{
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = myeid_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr.len)
			continue;
		if (memcmp(card->atr.value, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int myeid_init(struct sc_card *card)
{
	unsigned long flags = 0, ext_flags = 0;
	myeid_private_data_t *priv;
	u8 appletInfo[20];
	size_t appletInfoLen;
	int r;
	int largeEccKeys = 0;
	u8 defatr[SC_MAX_ATR_SIZE];
	size_t len = sizeof(defatr);
	const char *atrp = myeid_atrs[MYEID_INFINEON_CHIP_ATR];

	LOG_FUNC_CALLED(card->ctx);

	card->name = myeid_card_name;

	priv = calloc(1, sizeof(myeid_private_data_t));

	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	priv->card_state = SC_FILE_STATUS_CREATION;
	card->drv_data = priv;

	/* find out MyEID version */

	appletInfoLen = 20;

	r = myeid_get_info(card, appletInfo, appletInfoLen);

	LOG_TEST_RET(card->ctx, r, "Failed to get MyEID applet information.");

	priv->change_counter = appletInfo[19] | appletInfo[18] << 8;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_ONBOARD_KEY_GEN;
	flags |= SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1;

	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	if (sc_hex_to_bin(atrp, defatr, &len) == 0
		&& (len == card->atr.len) &&
		memcmp(card->atr.value, defatr, len) == 0) {
	    largeEccKeys = 1;
	}

	/* show ECC algorithms if the applet version of the inserted card supports them */
	if ((card->version.fw_major == 3 && card->version.fw_minor > 5) ||
			card->version.fw_major >= 4)   {
		int i;

		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;
		flags |= SC_ALGORITHM_ECDSA_HASH_NONE | SC_ALGORITHM_ECDSA_HASH_SHA1;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

		for (i=0; ec_curves[i].curve_name != NULL; i++) {
		    if (i >= 2 && !largeEccKeys)
			continue;
		    else
			_sc_card_add_ec_alg(card,  ec_curves[i].size, flags, ext_flags, &ec_curves[i].curve_oid);
		}
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG | SC_CARD_CAP_ISO7816_PIN_INFO;

	card->max_recv_size = 255;
	card->max_send_size = 255;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static const struct sc_card_operations *iso_ops = NULL;

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
		if (e->key_ref < 1 || e->key_ref > 14)
			return 0x00;
		return e->key_ref;
	case SC_AC_NEVER:
		return 0x0F;
	}
	return 0x00;
}

static void add_acl_entry(struct sc_file *file, int op, u8 byte)
{
	unsigned int method, key_ref = SC_AC_KEY_REF_NONE;

	switch (byte)
	{
	case 0:
		method = SC_AC_NONE;
		break;
	case 15:
		method = SC_AC_NEVER;
		break;
	default:
		method = SC_AC_CHV;
		key_ref = byte;
		break;
	}
	sc_file_add_acl_entry(file, op, method, key_ref);
}

static void parse_sec_attr(struct sc_file *file, const u8 *buf, size_t len)
{
	int i;
	const int df_ops[4] =
		{ SC_AC_OP_CREATE, SC_AC_OP_CREATE, SC_AC_OP_DELETE, -1 };
	const int ef_ops[4] =
		{ SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_DELETE, -1 };
	const int key_ops[4] =
		{ SC_AC_OP_CRYPTO, SC_AC_OP_UPDATE, SC_AC_OP_DELETE, SC_AC_OP_GENERATE };

	const int *ops;

	if (len < 2)
		return;

	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		ops = ef_ops;
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		ops = key_ops;
		break;
	case SC_FILE_TYPE_DF:
		ops = df_ops;
		break;
	default:
		ops = key_ops;
		break;
	}

	for (i = 0; i < 4; i++)
	{
		if (ops[i] == -1)
			continue;
		if ((i & 1) == 0)
			add_acl_entry(file, ops[i], (u8)(buf[i / 2] >> 4));
		else
			add_acl_entry(file, ops[i], (u8)(buf[i / 2] & 0x0F));
	}
}

static int myeid_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file)
{
	int r;

	LOG_FUNC_CALLED(card->ctx);
	r = iso_ops->select_file(card, in_path, file);

	if (r == 0 && file != NULL && *file != NULL)
		parse_sec_attr(*file, (*file)->sec_attr, (*file)->sec_attr_len);

	LOG_FUNC_RETURN(card->ctx, r);
}


static int myeid_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, 0xA1);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = buflen > 256 ? 256 : buflen;

	r = sc_transmit_apdu(card, &apdu);

	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		return sc_check_sw(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static int myeid_process_fci(struct sc_card *card, struct sc_file *file,
		const u8 *buf, size_t buflen)
{
	myeid_private_data_t *priv = (myeid_private_data_t *) card->drv_data;
	size_t taglen = 0;
	const u8 *tag = NULL;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	r = iso_ops->process_fci(card, file, buf, buflen);
	if (r < 0)
	 LOG_FUNC_RETURN(card->ctx, r);

	if(file->type == SC_FILE_EF_UNKNOWN)
	{
		tag = sc_asn1_find_tag(NULL, buf, buflen, 0x82, &taglen);
		if (tag != NULL && taglen > 0 && *tag == 17)
		{
			file->type = SC_FILE_TYPE_INTERNAL_EF;
		}
	}
	if(file->sec_attr_len >= 3)
	{
		sc_log(card->ctx, "id (%X) sec_attr (%X %X %X)", file->id,
			file->sec_attr[0],file->sec_attr[1],file->sec_attr[2]);
	}
	tag = sc_asn1_find_tag(NULL, buf, buflen, 0x8A, &taglen);
	if (tag != NULL && taglen > 0)
	{
		if(tag[0] == MYEID_STATE_CREATION) {
			file->status = SC_FILE_STATUS_CREATION;
			sc_log(card->ctx, "File id (%X) status SC_FILE_STATUS_CREATION (0x%X)",
					file->id, tag[0]);
		}
		else if(tag[0] == MYEID_STATE_ACTIVATED) {
			file->status = SC_FILE_STATUS_ACTIVATED;
			sc_log(card->ctx, "File id (%X) status SC_FILE_STATUS_ACTIVATED (0x%X)",
					file->id, tag[0]);
		}
		priv->card_state = file->status;
	}

	LOG_FUNC_RETURN(card->ctx, 0);
}

static int encode_file_structure(sc_card_t *card, const sc_file_t *file,
		u8 *buf, size_t *outlen)
{
	const sc_acl_entry_t *read, *update, *delete, *generate;
	size_t i;

	LOG_FUNC_CALLED(card->ctx);

	if (!buf || !outlen || *outlen < 45)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	/* PrivateKey
	 * 0E0000019 6217 81020400 820111 83024B01 8603000000 85028000 8A0100 RESULT 6984
	 *	   6217 81020400 820111 83024B01 8603000000 85021000 8A0100 */
	memset(buf, 0x0, *outlen);

	buf[0] = 0x62;
	buf[1] = 0x17;
	/* File size */
	buf[2] = (SC_FILE_TYPE_WORKING_EF == file->type ? 0x80 : 0x81);
	buf[3] = 0x02;
	buf[4] = (file->size >> 8) & 0xFF;
	buf[5] = file->size & 0xFF;

	/* File Description tag */
	buf[6] = 0x82;
	buf[7] = 0x01;
	buf[8] = 0x01;

	/* File Identifier tag */
	buf[9]  = 0x83;
	buf[10] = 0x02;
	buf[11] = (file->id >> 8) & 0xFF;
	buf[12] = file->id & 0xFF;

	/* Security Attributes Tag */
	buf[13] = 0x86;
	buf[14] = 0x03;
	buf[15] = 0xFF;
	buf[16] = 0xFF;
	buf[17] = 0xFF;

	if (file->sec_attr_len == 3 && file->sec_attr)   {
		buf[15] = file->sec_attr[0];
		buf[16] = file->sec_attr[1];
		buf[17] = file->sec_attr[2];

		sc_log(card->ctx, "id (%X), sec_attr %X %X %X", file->id,
				file->sec_attr[0],file->sec_attr[1],file->sec_attr[2]);
	}
	else   {
		delete = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);

		switch (file->type) {
		case SC_FILE_TYPE_WORKING_EF:

			read = sc_file_get_acl_entry(file, SC_AC_OP_READ);
			update = sc_file_get_acl_entry(file, SC_AC_OP_UPDATE);

			buf[15] = (acl_to_byte(read) << 4) | acl_to_byte(update);
			buf[16] = (acl_to_byte(delete)<< 4) | 0x0F;
			break;
		case SC_FILE_TYPE_INTERNAL_EF:

			read = sc_file_get_acl_entry(file, SC_AC_OP_CRYPTO);
			update = sc_file_get_acl_entry(file, SC_AC_OP_UPDATE);
			generate = sc_file_get_acl_entry(file, SC_AC_OP_GENERATE);

			buf[15] = (acl_to_byte(read) << 4) | acl_to_byte(update);
			buf[16] = (acl_to_byte(delete)<< 4) | acl_to_byte(generate);
			break;
		case SC_FILE_TYPE_DF:

			update = sc_file_get_acl_entry(file, SC_AC_OP_CREATE);

			buf[15] = (acl_to_byte(update) << 4) | acl_to_byte(update);
			buf[16] = (acl_to_byte(delete) << 4) | 0x0F;
			break;
		default:
			break;
		}
	}

	/* Proprietary Information */
	buf[18] = 0x85;
	buf[19] = 0x02;
	/* AC right to clear default 0 */
	/* TODO: Implement this */
	buf[20] = 0x00; /*(SC_FILE_TYPE_INTERNAL_EF == file->type ? 0x00 : 0x80);*/
	buf[21] = 0x00;

	/* Life Cycle Status tag */
	buf[22] = 0x8A;
	buf[23] = 0x01;
	buf[24] = 0x0; /* RFU */

	switch (file->type)
	{
	case SC_FILE_TYPE_WORKING_EF:
		break;

	case SC_FILE_TYPE_INTERNAL_EF:
		buf[8] = file->ef_structure; /* RSA or EC */
		break;

	case SC_FILE_TYPE_DF:
		buf[8] = 0x38;
		if(file->namelen > 0 && file->namelen <= 16)
		{
			buf[25] = 0x84;
			buf[26] = (u8)file->namelen;

			for(i=0;i < file->namelen;i++)
				buf[i + 27] = file->name[i];

			buf[1] = 27 + file->namelen;
		}
		break;
	default:
		sc_log(card->ctx, "Unknown file type\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	*outlen = buf[1]+2;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int myeid_create_file(struct sc_card *card, struct sc_file *file)
{
	sc_apdu_t apdu;
	u8 sbuf[45];
	size_t buflen = sizeof sbuf;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = encode_file_structure(card, file, sbuf, &buflen);
	if (r)
	  LOG_FUNC_RETURN(card->ctx, r);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.data = sbuf;
	apdu.datalen = buflen;
	apdu.lc = buflen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x6A && apdu.sw2 == 0x89)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_ALREADY_EXISTS);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_delete_file(struct sc_card *card, const struct sc_path *path)
{
	int r;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2)
	{
		sc_log(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	r = sc_select_file(card, path, NULL);
	LOG_TEST_RET(card->ctx, r, "Unable to select file to be deleted");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	apdu.cla = 0xA0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int myeid_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
			 int *tries_left)
{
	myeid_private_data_t *priv = (myeid_private_data_t *) card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	sc_log(card->ctx, "ref (%d), pin1 len(%d), pin2 len (%d)\n",
			data->pin_reference, data->pin1.len, data->pin2.len);

	if(data->pin1.len > 8 || data->pin2.len > 8)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_PIN_LENGTH);

	data->pin1.pad_length = data->pin2.pad_length = 8;
	data->pin1.pad_char = data->pin2.pad_char = 0xFF;

	if (data->cmd == SC_PIN_CMD_VERIFY && priv->card_state == SC_FILE_STATUS_CREATION) {
		sc_log(card->ctx, "Card in creation state, no need to verify");
		return SC_SUCCESS;
	}

	LOG_FUNC_RETURN(card->ctx, iso_ops->pin_cmd(card, data, tries_left));
}

static int myeid_set_security_env_rsa(sc_card_t *card, const sc_security_env_t *env,
		int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r;

	assert(card != NULL && env != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
	{
		sc_log(card->ctx, "asymmetric keyref not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (se_num > 0)
	{
		sc_log(card->ctx, "restore security environment not supported.\n");
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation)
	{
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT)
	{
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
	{
		*p++ = 0x81;
		*p++ = 2;
		memcpy(p, env->file_ref.value, 2);
		p += 2;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	{
		*p++ = 0x84;
		*p++ = 1;
		*p++ = 0;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (apdu.datalen != 0)
	{
		r = sc_transmit_apdu(card, &apdu);
		if (r)
		{
			sc_log(card->ctx,
				"%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
		{
			sc_log(card->ctx,
				"%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
err:
	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_set_security_env_ec(sc_card_t *card, const sc_security_env_t *env,
		int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r;

	assert(card != NULL && env != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
	{
		sc_log(card->ctx, "asymmetric keyref not supported.");
		return SC_ERROR_NOT_SUPPORTED;
	}
	if (se_num > 0)
	{
		sc_log(card->ctx, "restore security environment not supported.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation)
	{
	case SC_SEC_OPERATION_DECIPHER:
		sc_log(card->ctx, "Decipher operation is not supported with EC keys.");
		return SC_ERROR_NOT_SUPPORTED;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		break;
	case SC_SEC_OPERATION_DERIVE:
		apdu.p1 = 0x41;
		apdu.p2 = 0xA4;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT)
	{
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT)
	{
		*p++ = 0x81;
		*p++ = 0x02;
		memcpy(p, env->file_ref.value, 2);
		p += 2;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT)
	{
		*p++ = 0x84;
		*p++ = 1;
		*p++ = 0;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (apdu.datalen != 0)
	{
		r = sc_transmit_apdu(card, &apdu);
		if (r)
		{
			sc_log(card->ctx,
				"%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r)
		{
			sc_log(card->ctx,
				"%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
err:
	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_context *ctx = card->ctx;
	myeid_private_data_t* priv;

	LOG_FUNC_CALLED(ctx);

	priv = (myeid_private_data_t*) card->drv_data;
	/* store security environment to differentiate between ECDH and RSA in decipher - Hannu*/
	priv->sec_env = env;

	if (env->flags & SC_SEC_ENV_ALG_PRESENT)
	{
		sc_security_env_t tmp;

		tmp = *env;
		tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
		tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;

		if (tmp.algorithm == SC_ALGORITHM_RSA)
		{
			tmp.algorithm_ref = 0x00;
			/* potential FIXME: return an error, if an unsupported
			* pad or hash was requested, although this shouldn't happen */
			if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
				tmp.algorithm_ref = 0x02;
			if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
				tmp.algorithm_ref |= 0x10;

			return myeid_set_security_env_rsa(card, &tmp, se_num);
		}
		else if (tmp.algorithm == SC_ALGORITHM_EC)
		{
			tmp.algorithm_ref = 0x04;
			tmp.algorithm_flags = 0;
			return myeid_set_security_env_ec(card, &tmp, se_num);
		}
		else
		{

			sc_log(ctx, "Unsupported algorithm.");
			return SC_ERROR_NOT_SUPPORTED;
		}
	}
	return myeid_set_security_env_rsa(card, env, se_num);
}


static int
myeid_convert_ec_signature(struct sc_context *ctx, size_t s_len, unsigned char *data, size_t datalen)
{
	unsigned char *buf;
	size_t buflen;
	int r;
	size_t len_size = 1;
	size_t sig_len = 0;

	assert(data && datalen && datalen > 3);

	/*
	 *	When validating the signature data, we have to consider that length of the signature
	 *	can be encoded in either one or two bytes depending on key size. With 521 bit keys
	 *	length of the structure takes two bytes.
	 */

	if (*data != 0x30)
		return SC_ERROR_INVALID_DATA;

	if ((*(data + 1) & 0x80) == 0x80)
		len_size += *(data + 1) & 0x7F;

	if (len_size == 1)
	    sig_len = *(data + 1);
	else if (len_size == 2)
	    sig_len = *(data + 2);
	else if (len_size == 3)
	{
	    sig_len = *(data + 2) | (*data + 3) << 8;
	}
	else
	    return SC_ERROR_INVALID_DATA;

	if (*(data + 1 + len_size) != 0x02)		/* Verify that it is an INTEGER */

	if (sig_len != (datalen - len_size - 1))	/* validate size of the DER structure */
	    return SC_ERROR_INVALID_DATA;

	buf = calloc(1, (s_len + 7)/8*2);
	if (!buf)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	buflen = (s_len + 7)/8*2;

	r = sc_asn1_sig_value_sequence_to_rs(ctx, data, datalen, buf, buflen);
	if (r < 0)
		free(buf);
	LOG_TEST_RET(ctx, r, "Failed to cenvert Sig-Value to the raw RS format");

	if (buflen > datalen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	memmove(data, buf, buflen);
	return buflen;
}


static int
myeid_compute_signature(struct sc_card *card, const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct myeid_private_data* priv;
	int r;
	size_t field_length = 0;
	size_t pad_chars = 0;


	assert(card != NULL && data != NULL && out != NULL);
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	priv = (myeid_private_data_t*) card->drv_data;
	sc_log(ctx, "key type %i, key length %i", priv->sec_env->algorithm, priv->sec_env->algorithm_ref);

	if (priv->sec_env->algorithm == SC_ALGORITHM_EC ) {

	    field_length = priv->sec_env->algorithm_ref;

	    /* pad with zeros if needed */
		if (datalen < (field_length + 7) / 8 ) {
			pad_chars = ((field_length + 7) / 8) - datalen;

			memset(sbuf, 0, pad_chars);
		}
	}

	if ((datalen + pad_chars) > 256)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
		* P1:  0x9E  Resp: Digital Signature
		* P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;
	if (datalen == 256)   {
		apdu.p2 = data[0];
		memcpy(sbuf, data+1, datalen-1);
		apdu.lc = datalen - 1;
		apdu.datalen = datalen - 1;
	}
	else   {
		memcpy(sbuf + pad_chars, data, datalen);
		apdu.lc = datalen + pad_chars;
		apdu.datalen = datalen + pad_chars;
	}

	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "compute_signature failed");

	if (priv->sec_env->algorithm == SC_ALGORITHM_EC)   {
		r = myeid_convert_ec_signature(ctx, priv->sec_env->algorithm_ref, apdu.resp, apdu.resplen);
		LOG_TEST_RET(ctx, r, "compute_signature convert signature failed");
		apdu.resplen = r;
	}

	if (apdu.resplen > outlen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memcpy(out, apdu.resp, apdu.resplen);
	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


/* takes other party's public key as input, performs ECDH key derivation and returns the shared secret in [out]. */
int myeid_ecdh_derive(struct sc_card *card, const u8* pubkey, size_t pubkey_len, u8* out, size_t outlen)
{

	/* MyEID uses GENERAL AUTHENTICATE ISO command for ECDH */

	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];

	int r;
	size_t ext_len_bytes;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x86, 0x00, 0x00);

	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	/* Fill in "Data objects in dynamic authentication template" (tag 0x7C) structure
	*
	* TODO: encode the structure using OpenSC's ASN1-functions.
	*
	*  Size of the structure depends on key length. With 521 bit keys two bytes are needed for defining length of a point.
	*/

	sbuf[0] = 0x7C;
	ext_len_bytes = 0;

	if (pubkey_len > 127)
	{
		sbuf[1] = 0x81;
		sbuf[2] = (u8) (pubkey_len + 3);
		sbuf[3] = 0x85;
		sbuf[4] = 0x81;
		sbuf[5] = (u8) (pubkey_len);
		ext_len_bytes = 2;
	}
	else
	{
		sbuf[1] = pubkey_len + 2;
		sbuf[2] = 0x85;
		sbuf[3] = pubkey_len;
	}

	memcpy(&sbuf[4 + ext_len_bytes], pubkey, pubkey_len);

	apdu.lc = pubkey_len + 4 + ext_len_bytes;
	apdu.le = 0;
	apdu.datalen = apdu.lc;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);

	LOG_TEST_RET(card->ctx, r, "APDU transmit failed.");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "ECDH operation failed - GENERAL AUTHENTICATE returned error.");

	if (outlen < apdu.resplen)
	{
		r = SC_ERROR_BUFFER_TOO_SMALL;
		LOG_TEST_RET(card->ctx, r, "Buffer too small to hold shared secret.");
	}

	memcpy(out, rbuf, apdu.resplen);

	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}


static int myeid_decipher(struct sc_card *card, const u8 * crgram,
		size_t crgram_len, u8 * out, size_t outlen)
{
	int r;
	myeid_private_data_t* priv;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	LOG_FUNC_CALLED(card->ctx);
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);

	assert(card != NULL && crgram != NULL && out != NULL);

	priv = (myeid_private_data_t*) card->drv_data;

	if (priv->sec_env && priv->sec_env->algorithm == SC_ALGORITHM_EC
		&& priv->sec_env->operation == SC_SEC_OPERATION_DERIVE
		&& priv->sec_env->algorithm_flags & SC_ALGORITHM_ECDSA_RAW)
	{
		r = myeid_ecdh_derive(card, crgram, crgram_len, out, outlen);
		priv->sec_env = NULL; /* clear after operation */
		LOG_FUNC_RETURN(card->ctx, r);
	}

	if (crgram_len > 256)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	    * P1:  0x80  Resp: Plain value
	    * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu,
		(crgram_len < 256) ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT,
		0x2A, 0x80, 0x86);

	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = crgram_len;

	if (crgram_len == 256)
	{
		apdu.le = 0;
		/* padding indicator byte, 0x81 = first half of 2048 bit cryptogram */
		sbuf[0] = 0x81;
		memcpy(sbuf + 1, crgram, crgram_len / 2);
		apdu.lc = crgram_len / 2 + 1;
	}
	else
	{
		sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
		memcpy(sbuf + 1, crgram, crgram_len);
		apdu.lc = crgram_len + 1;
	}

	apdu.datalen = apdu.lc;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		if (crgram_len == 256)
		{
			sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT,
				0x2A, 0x80, 0x86);
			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			apdu.le = crgram_len;
			/* padding indicator byte,
			    * 0x82 = Second half of 2048 bit cryptogram */
			sbuf[0] = 0x82;
			memcpy(sbuf + 1, crgram + crgram_len / 2, crgram_len / 2);
			apdu.lc = crgram_len / 2 + 1;
			apdu.datalen = apdu.lc;
			apdu.data = sbuf;

			r = sc_transmit_apdu(card, &apdu);

			LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

			if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
			{
				int len = apdu.resplen > outlen ? outlen : apdu.resplen;
				memcpy(out, apdu.resp, len);
				LOG_FUNC_RETURN(card->ctx, len);
			}
		}
		else
		{
			int len = apdu.resplen > outlen ? outlen : apdu.resplen;

			memcpy(out, apdu.resp, len);
			LOG_FUNC_RETURN(card->ctx, len);
		}
	}
	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


/* Write internal data, e.g. add default pin-records to pin */
static int myeid_putdata(struct sc_card *card, struct sc_cardctl_myeid_data_obj* data_obj)
{
	int r;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse     = SC_APDU_CASE_3_SHORT;
	apdu.cla     = 0x00;
	apdu.ins     = 0xDA;
	apdu.p1      = data_obj->P1;
	apdu.p2      = data_obj->P2;
	apdu.lc      = data_obj->DataLen;
	apdu.datalen = data_obj->DataLen;
	apdu.data    = data_obj->Data;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "PUT_DATA returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

/* Read internal data, e.g. get RSA public key */
static int myeid_getdata(struct sc_card *card, struct sc_cardctl_myeid_data_obj* data_obj)
{
	int r;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse     = SC_APDU_CASE_2_SHORT;
	apdu.cla     = 0x00;
	apdu.ins     = 0xCA;		/* GET DATA */
	apdu.p1      = data_obj->P1;
	apdu.p2      = data_obj->P2;
	apdu.lc      = 0;
	apdu.datalen = 0;
	apdu.data    = data_obj->Data;

	apdu.le      = card->max_recv_size;
	apdu.resp    = data_obj->Data;
	apdu.resplen = data_obj->DataLen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "GET_DATA returned error");

	if (apdu.resplen > data_obj->DataLen)
		r = SC_ERROR_WRONG_LENGTH;
	else
		data_obj->DataLen = apdu.resplen;

	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_loadkey(sc_card_t *card, int mode, u8* value, int value_len)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, len;

	LOG_FUNC_CALLED(card->ctx);
	len = 0;
	if(value_len == 0 || value == NULL)
		return 0;

	if(value    != NULL &&
	   value[0] != 0x0 &&
	   mode     != LOAD_KEY_PUBLIC_EXPONENT)
		sbuf[len++] = 0x0;

	if(mode == LOAD_KEY_MODULUS && value_len >= 256)
	{
		r=0;
		if((value_len % 2) > 0 && value[0] == 0x00)
		{
			value_len--;
			memmove(value, value + 1, value_len);
		}
		mode   = 0x88;
		len    = 128;
		memcpy(sbuf,value, 128);

		memset(&apdu, 0, sizeof(apdu));
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, mode);

		apdu.cla     = 0x00;
		apdu.data    = sbuf;
		apdu.datalen = len;
		apdu.lc	     = len;

		r = sc_transmit_apdu(card, &apdu);
		if(r < 0)
			return r;
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if(r < 0)
			return r;

		mode = 0x89;
		len  = value_len - 128;
		memset(&sbuf, 0, SC_MAX_APDU_BUFFER_SIZE);
		memcpy(sbuf,value + 128, value_len - 128);
	}
	else  if(mode == LOAD_KEY_EC_PRIVATE) {
		memcpy(sbuf, value, value_len);
		len = value_len;
		mode = LOAD_KEY_MODE_EC_PRIV;
	}
	else if(mode == LOAD_KEY_EC_PUBLIC) {
		memcpy(sbuf, value, value_len);
		len = value_len;
		mode = LOAD_KEY_MODE_EC_PUB;
	}
	else
	{
		memcpy(sbuf + len, value, value_len);
		len += value_len;
	}

	memset(&apdu, 0, sizeof(apdu));
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, mode);

	apdu.cla     = 0x00;
	apdu.data    = sbuf;
	apdu.datalen = len;
	apdu.lc	     = len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(card->ctx, r);
}

/* Generate or store a key */
static int myeid_generate_store_key(struct sc_card *card,
	struct sc_cardctl_myeid_gen_store_key_info *data)
{
	struct	sc_apdu apdu;
	u8	sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int	r=0,len;

	LOG_FUNC_CALLED(card->ctx);
	/* Setup key-generation parameters */
	if (data->op_type == OP_TYPE_GENERATE)
	{
		len = 0;
		memset(&apdu, 0, sizeof(apdu));

		if(data->key_type == SC_CARDCTL_MYEID_KEY_RSA)
		{
		    sbuf[len++] = 0x30;
		    sbuf[len++] = 0x05;
		    sbuf[len++] = 0x81;
		    sbuf[len++] = data->pubexp_len;

		    memcpy(sbuf + len, data->pubexp, data->pubexp_len);
		    len += data->pubexp_len;
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0x00, 0x00);
			apdu.data    = sbuf;
		}
		else if(data->key_type == SC_CARDCTL_MYEID_KEY_EC) {

			sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x46, 0x00, 0x00);

			apdu.data    = NULL;
			apdu.resp	 = sbuf;
			apdu.resplen = 0x00;
			apdu.le		 = 0x00;
		}

		apdu.cla     = 0x00;
		apdu.datalen = len;
		apdu.lc	     = len;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "GENERATE_KEY returned error");
	}
	else
	{
		if(data->key_type == SC_CARDCTL_MYEID_KEY_RSA)
		{
			if((r=myeid_loadkey(card, LOAD_KEY_PRIME_P,
				data->primep, data->primep_len)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_PRIME_Q,
				data->primeq, data->primeq_len)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_DP1,
				data->dp1, data->dp1_len)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_DQ1,
				data->dq1, data->dq1_len)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_INVQ,
				data->invq, data->invq_len)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_MODULUS,
				data->mod, data->key_len_bits)) >= 0 &&
			(r=myeid_loadkey(card, LOAD_KEY_PUBLIC_EXPONENT,
				data->pubexp, data->pubexp_len)) >= 0)
				LOG_FUNC_RETURN(card->ctx, r);
		}
		else if(data->key_type == SC_CARDCTL_MYEID_KEY_EC) {
			if((r = myeid_loadkey(card, LOAD_KEY_EC_PRIVATE, data->d,
					data->d_len)) >= 0 &&
				(r = myeid_loadkey(card, LOAD_KEY_EC_PUBLIC, data->ecpublic_point,
					data->ecpublic_point_len)) >= 0)
			LOG_FUNC_RETURN(card->ctx, r);
		}
	}

	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_activate_card(struct sc_card *card)
{
	int r;
	u8 sbuf[] ="\xA0\x00\x00\x00\x63\x50\x4B\x43\x53\x2D\x31\x35";
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x44, 0x04, 0x00);
	apdu.cla     = 0x00;
	apdu.data    = sbuf;
	apdu.datalen = 0x0C;
	apdu.lc	     = 0x0C;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "ACTIVATE_APPLET returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_get_info(struct sc_card *card, u8 *rbuf, size_t buflen)
{
	sc_apdu_t apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0xA0);
	apdu.resp    = rbuf;
	apdu.resplen = buflen;
	apdu.le      = buflen;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r,  "APDU transmit failed");

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;

	if (apdu.resplen != 20)
	{
		sc_log(card->ctx, "Unexpected response to GET DATA (applet info)");
		return SC_ERROR_INTERNAL;
	}

	/* store the applet version */
	card->version.fw_major = rbuf[5] * 10 + rbuf[6];
	card->version.fw_minor = rbuf[7];
	/* add version to name */
	snprintf(card_name_buf, sizeof(card_name_buf),
			"%s %d.%d.%d", card->name, rbuf[5], rbuf[6], rbuf[7]);
	card->name = card_name_buf;

	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	u8  rbuf[256];

	LOG_FUNC_CALLED(card->ctx);

	/* if number cached, get it
	if(card->serialnr.value) {
		memcpy(serial, &card->serialnr, sizeof(*serial));
		LOG_FUNC_RETURN(card->ctx, r);
	}*/

	/* get number from card */
	r = myeid_get_info(card, rbuf, sizeof(rbuf));
	LOG_TEST_RET(card->ctx, r,  "Get applet info failed");

	/* cache serial number */
	memcpy(card->serialnr.value, &rbuf[8], 10);
	card->serialnr.len = 10;

	/* copy and return serial number */
	memcpy(serial, &card->serialnr, sizeof(*serial));

	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	int r = SC_ERROR_NOT_SUPPORTED;
	LOG_FUNC_CALLED(card->ctx);

	switch(cmd) {
	case SC_CARDCTL_MYEID_PUTDATA:
		r = myeid_putdata(card,
			(struct sc_cardctl_myeid_data_obj*) ptr);
		break;
	case SC_CARDCTL_MYEID_GETDATA:
		r = myeid_getdata(card,
			(struct sc_cardctl_myeid_data_obj*) ptr);
		break;
	case SC_CARDCTL_MYEID_GENERATE_STORE_KEY:
		r = myeid_generate_store_key(card,
			(struct sc_cardctl_myeid_gen_store_key_info *) ptr);
		break;
	case SC_CARDCTL_MYEID_ACTIVATE_CARD:
		r = myeid_activate_card(card);
		break;
	case SC_CARDCTL_GET_SERIALNR:
		r = myeid_get_serialnr(card, (sc_serial_number_t *)ptr);
		break;
	case SC_CARDCTL_GET_DEFAULT_KEY:
	case SC_CARDCTL_LIFECYCLE_SET:
	case SC_CARDCTL_LIFECYCLE_GET:
		break;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_finish(sc_card_t * card)
{
	struct myeid_private_data *priv = (struct myeid_private_data *) card->drv_data;
	free(priv);
	return SC_SUCCESS;
}


static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	myeid_ops			= *iso_drv->ops;
	myeid_ops.match_card		= myeid_match_card;
	myeid_ops.init			= myeid_init;
	myeid_ops.finish		= myeid_finish;
	/* no record oriented file services */
	myeid_ops.read_record		= NULL;
	myeid_ops.write_record		= NULL;
	myeid_ops.append_record		= NULL;
	myeid_ops.update_record		= NULL;
	myeid_ops.select_file		= myeid_select_file;
	myeid_ops.create_file		= myeid_create_file;
	myeid_ops.delete_file		= myeid_delete_file;
	myeid_ops.list_files		= myeid_list_files;
	myeid_ops.set_security_env	= myeid_set_security_env;
	myeid_ops.compute_signature	= myeid_compute_signature;
	myeid_ops.decipher		= myeid_decipher;
	myeid_ops.process_fci		= myeid_process_fci;
	myeid_ops.card_ctl		= myeid_card_ctl;
	myeid_ops.pin_cmd		= myeid_pin_cmd;
	return &myeid_drv;
}

struct sc_card_driver * sc_get_myeid_driver(void)
{
	return sc_get_driver();
}

