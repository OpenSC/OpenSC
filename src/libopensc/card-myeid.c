/*
 * card-myeid.c
 *
 * Copyright (C) 2008-2019 Aventra Ltd.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "types.h"

/* Low byte is the MyEID card's key type specific component ID. High byte is used
 * internally for key type, so myeid_loadkey() is aware of the exact component. */
#define LOAD_KEY_MODULUS		0x0080
#define LOAD_KEY_PUBLIC_EXPONENT	0x0081
#define LOAD_KEY_PRIME_P		0x0083
#define LOAD_KEY_PRIME_Q		0x0084
#define LOAD_KEY_DP1			0x0085
#define LOAD_KEY_DQ1			0x0086
#define LOAD_KEY_INVQ			0x0087
#define LOAD_KEY_EC_PUBLIC		0x1086
#define LOAD_KEY_EC_PRIVATE		0x1087
#define LOAD_KEY_SYMMETRIC		0x20a0

#define MYEID_CARD_NAME_MAX_LEN		100

/* The following flags define the features supported by the card currently in use.
  They are used in 'card_supported_features' field in myeid_card_caps struct */
#define MYEID_CARD_CAP_RSA		0x01
#define MYEID_CARD_CAP_3DES		0x02
#define MYEID_CARD_CAP_AES		0x04
#define MYEID_CARD_CAP_ECC		0x08
#define MYEID_CARD_CAP_GRIDPIN		0x10
#define MYEID_CARD_CAP_PIV_EMU		0x20

#define MYEID_MAX_APDU_DATA_LEN		0xFF
#define MYEID_MAX_RSA_KEY_LEN		4096

#define MYEID_MAX_EXT_APDU_BUFFER_SIZE	(MYEID_MAX_RSA_KEY_LEN/8+16)

static const char *myeid_card_name = "MyEID";
static const char *oseid_card_name = "OsEID";
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

typedef struct myeid_private_data {
	int card_state;

	unsigned short change_counter;
	unsigned char cap_chaining;
	/* the driver sets sec_env pointer in myeid_set_security_env and
	 it is used immediately in myeid_decipher to differentiate between RSA decryption and
	 ECDH key agreement. Note that this pointer is usually not valid
	 after this pair of calls and must not be used elsewhere. */
	const struct sc_security_env* sec_env;
	int disable_hw_pkcs1_padding;
	/* buffers for AES(DES) block cipher */
	uint8_t sym_crypt_buffer[16];
	uint8_t sym_plain_buffer[16];
	uint8_t sym_crypt_buffer_len;
	uint8_t sym_plain_buffer_len;
	/* PSO for AES/DES need algo+flags from sec env */
	unsigned long algorithm, algorithm_flags;
} myeid_private_data_t;

typedef struct myeid_card_caps {
	unsigned char card_caps_ver;
	unsigned short card_supported_features;
	unsigned short max_rsa_key_length;
	unsigned short max_des_key_length;
	unsigned short max_aes_key_length;
	unsigned short max_ecc_key_length;
} myeid_card_caps_t;

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
static int myeid_get_card_caps(struct sc_card *card, myeid_card_caps_t* card_caps);

static int myeid_match_card(struct sc_card *card)
{
	size_t len = card->reader->atr_info.hist_bytes_len;
	/* Normally the historical bytes are exactly "MyEID", but there might
	 * be some historic units which have a small prefix byte sequence. */
	if (len >= 5) {
		if (!memcmp(&card->reader->atr_info.hist_bytes[len - 5], "MyEID", 5)) {
			sc_log(card->ctx, "Matched MyEID card");
			card->type = SC_CARD_TYPE_MYEID_GENERIC;
			return 1;
		}
		/* The software implementation of MyEID is identified by OsEID bytes */
		if (!memcmp(&card->reader->atr_info.hist_bytes[len - 5], "OsEID", 5)) {
			sc_log(card->ctx, "Matched OsEID card");
			card->type = SC_CARD_TYPE_MYEID_OSEID;
			return 1;
		}
	}
	return 0;
}

static int
myeid_select_aid(struct sc_card *card, struct sc_aid *aid, unsigned char *out, size_t *out_len)
{
	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	/* Select application (deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aid->len;
	apdu.data = aid->value;
	apdu.datalen = aid->len;
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Cannot select AID");

	if (*out_len > 0) {
		if (*out_len < apdu.resplen)
			LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL, "Cannot select AID - response buffer too small.");
		if (out == NULL)
			LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Cannot select AID - invalid arguments.");
		memcpy(out, apdu.resp, apdu.resplen);
		*out_len = apdu.resplen;
	}

	return SC_SUCCESS;
}

static int myeid_load_options(sc_context_t *ctx, myeid_private_data_t *priv)
{
	int r;
	size_t i, j;
	scconf_block **found_blocks, *block;

	if (!ctx || !priv) {
		r = SC_ERROR_INTERNAL;
		goto err;
	}
	priv->disable_hw_pkcs1_padding = 0;
	for (i = 0; ctx->conf_blocks[i]; i++) {
		found_blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
				"card_driver", "myeid");
		if (!found_blocks)
			continue;
		for (j = 0, block = found_blocks[j]; block; j++, block = found_blocks[j]) {
			priv->disable_hw_pkcs1_padding = scconf_get_int(block, "disable_hw_pkcs1_padding", 0);
			sc_log(ctx,"Found config option: disable_hw_pkcs1_padding = %d\n", priv->disable_hw_pkcs1_padding);
		}
		free(found_blocks);
	}
	r = SC_SUCCESS;

err:
	return r;
}

static int myeid_init(struct sc_card *card)
{
	unsigned long flags = 0, ext_flags = 0;
	myeid_private_data_t *priv;
	u8 appletInfo[20];
	size_t appletInfoLen;
	myeid_card_caps_t card_caps;
	size_t resp_len = 0;
	static struct sc_aid myeid_aid = { "\xA0\x00\x00\x00\x63\x50\x4B\x43\x53\x2D\x31\x35", 0x0C };
	int rv = 0;
	void *old_drv_data = card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	switch (card->type) {
	case SC_CARD_TYPE_MYEID_OSEID:
		card->name = oseid_card_name;
		break;
	case SC_CARD_TYPE_MYEID_GENERIC:
		card->name = myeid_card_name;
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_CARD);
	}

	priv = calloc(1, sizeof(myeid_private_data_t));

	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	rv = myeid_load_options (card->ctx, priv);
	LOG_TEST_GOTO_ERR(card->ctx, rv, "Unable to read options from opensc.conf");

	priv->card_state = SC_FILE_STATUS_CREATION;
	card->drv_data = priv;

	/* Ensure that the MyEID applet is selected. */
	rv = myeid_select_aid(card, &myeid_aid, NULL, &resp_len);
	LOG_TEST_GOTO_ERR(card->ctx, rv, "Failed to select MyEID applet.");

	/* find out MyEID version */

	appletInfoLen = 20;

	if (0 > myeid_get_info(card, appletInfo, appletInfoLen))
		LOG_TEST_GOTO_ERR(card->ctx, SC_ERROR_INVALID_CARD, "Failed to get MyEID applet information.");

	priv->change_counter = appletInfo[19] | appletInfo[18] << 8;

	memset(&card_caps, 0, sizeof(myeid_card_caps_t));
	card_caps.max_ecc_key_length = 256;
	card_caps.max_rsa_key_length = 2048;

	if (card->version.fw_major >= 40) {
	    /* Since 4.0, we can query available algorithms and key sizes.
	     * Since 3.5.0 RSA up to 2048 and ECC up to 256 are always supported, so we check only max ECC key length. */
	    if (myeid_get_card_caps(card, &card_caps) != SC_SUCCESS) {
			sc_log(card->ctx, "Failed to get card capabilities. Using default max ECC key length 256.");
	    }
	}

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;
	if (priv->disable_hw_pkcs1_padding == 0)
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
	flags |= SC_ALGORITHM_RSA_HASH_NONE;

	_sc_card_add_rsa_alg(card,  512, flags, 0);
	_sc_card_add_rsa_alg(card,  768, flags, 0);
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 1536, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	if (card_caps.card_supported_features & MYEID_CARD_CAP_RSA) {
		if (card_caps.max_rsa_key_length >= 3072)
			_sc_card_add_rsa_alg(card, 3072, flags, 0);
		if (card_caps.max_rsa_key_length >= 4096)
			_sc_card_add_rsa_alg(card, 4096, flags, 0);
	}

	/* show ECC algorithms if the applet version of the inserted card supports them */
	if (card->version.fw_major >= 35) {
		int i;

		flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ONBOARD_KEY_GEN;
		flags |= SC_ALGORITHM_ECDSA_HASH_NONE;
		ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

		for (i=0; ec_curves[i].curve_name != NULL; i++) {
			if (card_caps.max_ecc_key_length >= ec_curves[i].size)
				_sc_card_add_ec_alg(card, ec_curves[i].size, flags, ext_flags, &ec_curves[i].curve_oid);
		}
	}

	/* show supported symmetric algorithms */
	flags = 0;
	if (card_caps.card_supported_features & MYEID_CARD_CAP_3DES) {
		if (card_caps.max_des_key_length >= 64)
			_sc_card_add_symmetric_alg(card, SC_ALGORITHM_DES, 64, flags);
		if (card_caps.max_des_key_length >= 128)
			_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 128, flags);
		if (card_caps.max_des_key_length >= 192)
			_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 192, flags);
	}
	if (card_caps.card_supported_features & MYEID_CARD_CAP_AES) {
		if (card_caps.max_aes_key_length >= 128)
			_sc_card_add_symmetric_alg(card, SC_ALGORITHM_AES, 128, flags);
		if (card_caps.max_aes_key_length >= 256)
			_sc_card_add_symmetric_alg(card, SC_ALGORITHM_AES, 256, flags);
	}

	/* State that we have an RNG */
	card->caps |= SC_CARD_CAP_RNG | SC_CARD_CAP_ISO7816_PIN_INFO;

	if ((card->version.fw_major == 40 && card->version.fw_minor >= 10 )
		|| card->version.fw_major >= 41)
		card->caps |= SC_CARD_CAP_WRAP_KEY | SC_CARD_CAP_UNWRAP_KEY
			   | SC_CARD_CAP_ONCARD_SESSION_OBJECTS;

	if (card->version.fw_major >= 45)
		priv->cap_chaining = 1;
	if (card->version.fw_major >= 40)
		card->max_recv_size = 256;
	else
		card->max_recv_size = 255;
	card->max_send_size = 255;

	rv = SC_SUCCESS;

err:
	if (rv < 0) {
		free(priv);
		card->drv_data = old_drv_data;
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static const struct sc_card_operations *iso_ops = NULL;

static int acl_to_byte(const struct sc_acl_entry *e)
{
	if (NULL == e)
		return 0x00;
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

static int myeid_logout(struct sc_card *card)
{
	sc_apdu_t apdu;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x00 /*pin ref: 0x01-0x0E, 0=ALL*/);
	apdu.cla = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
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
	return (int)apdu.resplen;
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

	priv->card_state = file->status;
	switch (file->status) {
		case SC_FILE_STATUS_CREATION:
			file->acl_inactive = 1;
			sc_log(card->ctx, "File id (%X) status SC_FILE_STATUS_CREATION", file->id);
			break;
		case SC_FILE_STATUS_ACTIVATED:
			sc_log(card->ctx, "File id (%X) status SC_FILE_STATUS_ACTIVATED", file->id);
			break;
		default:
			sc_log(card->ctx, "File id (%X) unusual status (0x%X)", file->id, file->status);
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

		sc_log(card->ctx, "id (%X), type (%X)", file->id, file->type);

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
	if (file->prop_attr_len == 2 && file->prop_attr != NULL)
	    memcpy(&buf[20], file->prop_attr, 2);
	else
	{
		buf[20] = 0x00;
		buf[21] = 0x00;
	}

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

	sc_log(card->ctx, "ref (%d), pin1 len(%zu), pin2 len (%zu)\n",
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

#define IS_SYMETRIC_CRYPT(x) ((x) == SC_SEC_OPERATION_ENCRYPT_SYM || (x) == SC_SEC_OPERATION_DECRYPT_SYM)

static int myeid_set_security_env_rsa(sc_card_t *card, const sc_security_env_t *env,
		int se_num)
{
	sc_apdu_t apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r;
	size_t i, sz;
	sc_path_t *target_file;

	assert(card != NULL && env != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
	{
		sc_log(card->ctx, "symmetric keyref not supported.\n");
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
	case SC_SEC_OPERATION_UNWRAP:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_WRAP:
		apdu.p1 = 0x81;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_ENCRYPT_SYM:
		apdu.p1 = 0x81;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_DECRYPT_SYM:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
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
	/* symmetric operations: we need to set the key reference */
	if (IS_SYMETRIC_CRYPT(env->operation)) {
		*p++ = 0x83;
		*p++ = 1;
		*p++ = 0;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT && env->operation != SC_SEC_OPERATION_UNWRAP &&
			env->operation != SC_SEC_OPERATION_WRAP &&
			env->operation != SC_SEC_OPERATION_ENCRYPT_SYM &&
			env->operation != SC_SEC_OPERATION_DECRYPT_SYM) {
		*p++ = 0x84;
		*p++ = 1;
		*p++ = 0;
	}
	for (i = 0; i < SC_SEC_ENV_MAX_PARAMS; i++)
	    if (env->params[i].param_type == SC_SEC_ENV_PARAM_TARGET_FILE) {
			target_file = (sc_path_t*) env->params[i].value;
			if (env->params[i].value_len < sizeof(sc_path_t) || target_file->len != 2) {
				sc_log(card->ctx, "wrong length of target file reference.\n");
				return SC_ERROR_WRONG_LENGTH;
			}
			*p++ = 0x83;
			*p++ = 2;
			memcpy(p, target_file->value, 2);
			p+= 2;
			break;
	    }

	r = 0;
	if (env->operation == SC_SEC_OPERATION_UNWRAP || env->operation == SC_SEC_OPERATION_WRAP ||
			IS_SYMETRIC_CRYPT(env->operation)) {
		/* add IV if present */
		for (i = 0; i < SC_SEC_ENV_MAX_PARAMS; i++)
			if (env->params[i].param_type == SC_SEC_ENV_PARAM_IV) {
				r = 1;
				*p++ = 0x87;
				*p++ = (unsigned char) env->params[i].value_len;
				if (p + env->params[i].value_len >= sbuf + SC_MAX_APDU_BUFFER_SIZE) {
					sc_log(card->ctx, "IV too long.\n");
					return SC_ERROR_WRONG_LENGTH;
				}
				memcpy(p, env->params[i].value, env->params[i].value_len);
				p+=(unsigned char) env->params[i].value_len;
				break;
			}
	}
	/* for AES_ECB we need to reset the IV but we respect if the IV is already present */
	if (IS_SYMETRIC_CRYPT(env->operation) && env->algorithm == SC_ALGORITHM_AES &&
			env->algorithm_flags == SC_ALGORITHM_AES_ECB && r == 0) {
		*p++ = 0x87;
		*p++ = 16;
		memset(p, 0, 16);
		p += 16;
	}

	sz = p - sbuf;
	apdu.lc = sz;
	apdu.datalen = sz;
	apdu.data = sbuf;
	apdu.resplen = 0;
	r = (int)sz;
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
	size_t sz;
	int r;

	assert(card != NULL && env != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
	{
		sc_log(card->ctx, "symmetric keyref not supported.");
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
	sz = p - sbuf;
	apdu.lc = sz;
	apdu.datalen = sz;
	apdu.data = sbuf;
	apdu.resplen = 0;
	r = (int)sz;
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

	/* for symmetric operation save algo and algo flags */
	priv->algorithm_flags = env->algorithm_flags;
	priv->algorithm = env->algorithm;

	if (env->flags & SC_SEC_ENV_ALG_PRESENT)
	{
		sc_security_env_t tmp;

		tmp = *env;
		tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
		tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;

		if (tmp.algorithm == SC_ALGORITHM_RSA)
		{
			if (tmp.operation == SC_SEC_OPERATION_UNWRAP || tmp.operation == SC_SEC_OPERATION_WRAP)
			{
			    tmp.algorithm_ref = 0x0A;
			}
			else
			{
				tmp.algorithm_ref = 0x00;
				/* potential FIXME: return an error, if an unsupported
				* pad or hash was requested, although this shouldn't happen */
				if ((env->operation == SC_SEC_OPERATION_SIGN && env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01)
					|| (env->operation == SC_SEC_OPERATION_DECIPHER && env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02))
					tmp.algorithm_ref = 0x02;
				if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
					tmp.algorithm_ref |= 0x10;
			}

			return myeid_set_security_env_rsa(card, &tmp, se_num);
		}
		else if (tmp.algorithm == SC_ALGORITHM_EC)
		{
			tmp.algorithm_ref = 0x04;
			tmp.algorithm_flags = 0;
			return myeid_set_security_env_ec(card, &tmp, se_num);
		}
		else if (tmp.algorithm == SC_ALGORITHM_AES)
		{
			if (tmp.operation == SC_SEC_OPERATION_UNWRAP || tmp.operation == SC_SEC_OPERATION_WRAP)
			{
				tmp.algorithm_ref = 0x0A;
			}
			else
			{
				tmp.algorithm_ref = 0x00;
			}

			if ((tmp.algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) == SC_ALGORITHM_AES_CBC_PAD)
				tmp.algorithm_ref |= 0x80;		/* set PKCS#7 padding */
			/* Tag 0x80 algorithm_ref - value 0x80 or 0x8A is working only for UNWRAP/WRAP
			 * AES is supported from version 4.0 but without pkcs#7 padding.
			 * For SC_SEC_OPERATION_ENCRYPT_SYM and SC_SEC_OPERATION_DECRYPT_SYM we running
			 * PKCS#7 in software, here we fix the algorithm_ref variable.
			 */
			if (IS_SYMETRIC_CRYPT(env->operation))
				tmp.algorithm_ref &= ~0x80; /* do not handle padding in card */

			/* from this point, there's no difference to RSA SE */
			return myeid_set_security_env_rsa(card, &tmp, se_num);
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

	/* test&fail early */
	buflen = BYTES4BITS(s_len) * 2;
	if (buflen > datalen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

	buf = calloc(1, buflen);
	if (!buf)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	r = sc_asn1_sig_value_sequence_to_rs(ctx, data, datalen, buf, buflen);
	if (r < 0) {
		free(buf);
		sc_log(ctx, "Failed to convert Sig-Value to the raw RS format");
		return r;
	}

	memmove(data, buf, buflen);
	free(buf);
	return (int)buflen;
}
/* MyEID cards before version 4.5 do not support RAW RSA signature for 2048 bit RSA keys.
 * (Source: MyEID reference manual 2.1.4)
 *
 * This function uses decipher operation for calculating RAW 2048 bit signature. */
static int
myeid_compute_raw_2048_signature(struct sc_card *card, const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	int r;
	struct sc_context *ctx;
	struct myeid_private_data *priv;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_security_env_t env;

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	priv = (myeid_private_data_t *) card->drv_data;

/* security env change - use DECIPHER operation */
	memcpy(&env, priv->sec_env, sizeof(sc_security_env_t));
	env.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
	env.flags |= SC_SEC_ENV_FILE_REF_PRESENT;
	env.flags |= SC_SEC_ENV_KEY_REF_PRESENT;
	env.operation = SC_SEC_OPERATION_DECIPHER;
	myeid_set_security_env_rsa(card, &env, 0);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0;	/* there is no response to 1st part of data */

/* prepare 1st part of data */
	sbuf[0] = 0x81;
	memcpy(sbuf + 1, data, datalen / 2);
	apdu.lc = datalen / 2 + 1;
	apdu.datalen = apdu.lc;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
/* prepare 2nd part of data */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = datalen;
		sbuf[0] = 0x82;
		memcpy(sbuf + 1, data + datalen / 2, datalen / 2);
		apdu.lc = datalen / 2 + 1;
		apdu.datalen = apdu.lc;
		apdu.data = sbuf;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;
			memcpy(out, apdu.resp, len);
			LOG_FUNC_RETURN(card->ctx, (int)len);
		}
	}
	LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int
myeid_compute_signature(struct sc_card *card, const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	u8 rbuf[MYEID_MAX_EXT_APDU_BUFFER_SIZE];
	u8 sbuf[MYEID_MAX_EXT_APDU_BUFFER_SIZE];
	struct myeid_private_data* priv;
	int r;
	size_t field_length = 0;
	size_t pad_chars = 0;


	assert(card != NULL && data != NULL && out != NULL);
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	priv = (myeid_private_data_t*) card->drv_data;
	sc_log(ctx, "key type %lu, key length %lu", priv->sec_env->algorithm, priv->sec_env->algorithm_ref);

	if (priv->sec_env->algorithm == SC_ALGORITHM_EC ) {

	    field_length = priv->sec_env->algorithm_ref;

	    /* pad with zeros if needed */
		if (datalen < BYTES4BITS(field_length)) {
			pad_chars = BYTES4BITS(field_length) - datalen;

			memset(sbuf, 0, pad_chars);
		}
	}

	if ((datalen + pad_chars) > sizeof(sbuf))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (priv->sec_env->algorithm == SC_ALGORITHM_RSA && datalen == 256 && !priv->cap_chaining)
		return myeid_compute_raw_2048_signature(card, data, datalen, out, outlen);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
		* P1:  0x9E  Resp: Digital Signature
		* P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;
	memcpy(sbuf + pad_chars, data, datalen);
	apdu.lc = datalen + pad_chars;
	apdu.datalen = datalen + pad_chars;

	apdu.data = sbuf;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "compute_signature failed");

	if (priv->sec_env->algorithm == SC_ALGORITHM_EC) {
		r = myeid_convert_ec_signature(ctx, priv->sec_env->algorithm_ref, apdu.resp, apdu.resplen);
		LOG_TEST_RET(ctx, r, "compute_signature convert signature failed");
		apdu.resplen = r;
	}

	if (apdu.resplen > outlen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memcpy(out, apdu.resp, apdu.resplen);
	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
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
	apdu.le = pubkey_len / 2;
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

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

static int myeid_transmit_decipher_pi_split(struct sc_card *card, struct sc_apdu *apdu, u8 *sbuf)
{
	/* MyEID before 4.5.x does not support APDU chaining. The payload
	 * is split to two regular APDUs and Padding Indicator field is used to
	 * describe which slice it is. */
	size_t crgram_len = apdu->lc - 1;
	size_t crgram_half = crgram_len / 2;
	size_t resplen = apdu->resplen;
	unsigned char *resp = apdu->resp;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* Send 1st part, no response */
	apdu->cse = SC_APDU_CASE_3_SHORT;
	apdu->data = &sbuf[0];
	apdu->datalen = apdu->lc = crgram_half + 1;
	apdu->resp = 0;
	apdu->resplen = 0;
	apdu->le = 0;
	sbuf[0] = 0x81;			/* Padding Indicator, 0x81 = First half */

	r = sc_transmit_apdu(card, apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu->sw1 != 0x90 || apdu->sw2 != 0x00)
		return 0;

	/* Send 2nd part, expect response */
	apdu->cse = resplen ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT;
	apdu->data = &sbuf[crgram_half];
	apdu->datalen = apdu->lc = crgram_len - crgram_half + 1;
	apdu->resp = resp;
	apdu->resplen = resplen;
	apdu->le = resplen ? MIN(card->max_recv_size, crgram_len) : 0;
	sbuf[crgram_half] = 0x82;	/* Padding Indicator, 0x82 = Second half */

	r = sc_transmit_apdu(card, apdu);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int myeid_transmit_decipher(struct sc_card *card, u8 p1, u8 p2,
		const u8 * crgram, size_t crgram_len, u8 * out, size_t outlen)
{
	myeid_private_data_t *priv = card->drv_data;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x00  Resp: No response (unwrapping)
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x84  Cmd: Cryptogram (no padding byte)
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, p1 ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT, 0x2A, p1, p2);
	if (p2 == 0x86) {
		if (crgram_len+1 > sizeof(sbuf))
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		sbuf[0] = 0; /* Padding indicator: 0x00 = No further indication */
		memcpy(sbuf + 1, crgram, crgram_len);
		apdu.data = sbuf;
		apdu.datalen = apdu.lc = crgram_len + 1;
	} else {
		apdu.data = crgram;
		apdu.datalen = apdu.lc = crgram_len;
	}
	if (p1 != 0x00) {
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = MIN(card->max_recv_size, crgram_len);
	}

	/* In MyEID 4.5.x, unwrapping with 2K RSA using APDU chaining doesn't work properly. Split the APDU in the old way in this case. */
	if (p2 == 0x86 && crgram_len == 256 && priv && (!priv->cap_chaining || (card->version.fw_major == 45 && priv->sec_env != NULL && priv->sec_env->operation == SC_SEC_OPERATION_UNWRAP))) {
		r = myeid_transmit_decipher_pi_split(card, &apdu, sbuf);
	} else {
		apdu.flags |= SC_APDU_FLAGS_CHAINING;
		r = sc_transmit_apdu(card, &apdu);
	}
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "DECIPHER returned error");

	if (out && outlen) {
		outlen = MIN(apdu.resplen, outlen);
		memcpy(out, apdu.resp, outlen);
	} else {
		outlen = 0;
	}
	LOG_FUNC_RETURN(card->ctx, (int)outlen);
}

static int myeid_decipher(struct sc_card *card, const u8 * crgram,
		size_t crgram_len, u8 * out, size_t outlen)
{
	int r;
	myeid_private_data_t* priv;

	LOG_FUNC_CALLED(card->ctx);

	assert(card != NULL && crgram != NULL && out != NULL);

	priv = (myeid_private_data_t*) card->drv_data;

	if (priv->sec_env && priv->sec_env->algorithm == SC_ALGORITHM_EC
		&& priv->sec_env->operation == SC_SEC_OPERATION_DERIVE
		&& priv->sec_env->algorithm_flags & SC_ALGORITHM_ECDH_CDH_RAW)
	{
		r = myeid_ecdh_derive(card, crgram, crgram_len, out, outlen);
		priv->sec_env = NULL; /* clear after operation */
		LOG_FUNC_RETURN(card->ctx, r);
	}

	r = myeid_transmit_decipher(card, 0x80, 0x86, crgram, crgram_len, out, outlen);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int myeid_wrap_key(struct sc_card *card, u8 *out, size_t outlen)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	assert(card != NULL);
	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	   P1:  0x84  Resp: Return a cryptogram
	 * P2:  0x00  The data field is absent */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A, 0x84, 0x00);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf) <= 256 ? sizeof(rbuf) : 256;
	apdu.lc = 0;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, r, "wrap key failed");

	if (apdu.resplen <= outlen && out != NULL)
		memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
}

static int myeid_unwrap_key(struct sc_card *card, const u8 *crgram, size_t crgram_len)
{
	myeid_private_data_t* priv;
	u8 p2 = 0x86; /* init P2 for asymmetric crypto by default.*/
	int r;

	if (card == NULL || crgram == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	priv = card->drv_data;

	LOG_FUNC_CALLED(card->ctx);

	if (crgram_len > MYEID_MAX_RSA_KEY_LEN / 8)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (priv && priv->sec_env)
	{
		if (priv->sec_env->algorithm == SC_ALGORITHM_AES ||
			priv->sec_env->algorithm == SC_ALGORITHM_3DES ||
			priv->sec_env->algorithm == SC_ALGORITHM_DES)
				p2 = 0x84;
	}

	if (p2 == 0x84 && crgram_len > MYEID_MAX_APDU_DATA_LEN)
		LOG_TEST_RET(card->ctx, SC_ERROR_WRONG_LENGTH, "Unwrapping symmetric data longer that 255 bytes is not supported\n");

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x00  Do not expect response - the deciphered data will be placed into the target key EF.
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram
	 * P2:  0x84  Cmd: AES/3DES Cryptogram (plain value encoded in BER-TLV DO, but not including SM DOs) */
	r = myeid_transmit_decipher(card, 0x00, p2, crgram, crgram_len, 0, 0);
	LOG_FUNC_RETURN(card->ctx, r);
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

static int myeid_loadkey(sc_card_t *card, unsigned mode, u8 *value, size_t value_len)
{
	myeid_private_data_t *priv = (myeid_private_data_t *) card->drv_data;
	sc_apdu_t apdu;
	u8 sbuf[MYEID_MAX_EXT_APDU_BUFFER_SIZE];
	int r;

	LOG_FUNC_CALLED(card->ctx);
	if (value_len == 0 || value == NULL)
		return 0;

	if (mode == LOAD_KEY_MODULUS && value_len == 256 && !priv->cap_chaining)
	{
		mode = 0x88;
		memset(&apdu, 0, sizeof(apdu));
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, mode);

		apdu.cla     = 0x00;
		apdu.data    = value;
		apdu.datalen = 128;
		apdu.lc	     = 128;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, r, "LOAD KEY returned error");

		mode = 0x89;
		value += 128;
		value_len -= 128;
	}
	else if ((mode & 0xff00) == 0 && mode != LOAD_KEY_PUBLIC_EXPONENT &&
		 value[0] != 0x00)
	{
		/* RSA components needing leading zero byte */
		sbuf[0] = 0x0;
		memcpy(&sbuf[1], value, value_len);
		value = sbuf;
		value_len ++;
	}

	memset(&apdu, 0, sizeof(apdu));
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDA, 0x01, mode & 0xFF);
	apdu.flags   = SC_APDU_FLAGS_CHAINING;
	apdu.cla     = 0x00;
	apdu.data    = value;
	apdu.datalen = value_len;
	apdu.lc	     = value_len;

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
		else if(data->key_type == SC_CARDCTL_MYEID_KEY_AES ||
			data->key_type == SC_CARDCTL_MYEID_KEY_DES) {
			if((r = myeid_loadkey(card, LOAD_KEY_SYMMETRIC, data->d,
					data->d_len)) >= 0)
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

static int
myeid_get_change_counter(sc_card_t *card, size_t *change_counter)
{
	int r;
	u8 rbuf[256];

	LOG_FUNC_CALLED(card->ctx);

	/* get change counter from card */
	r = myeid_get_info(card, rbuf, sizeof(rbuf));
	LOG_TEST_RET(card->ctx, r, "Get applet info failed");

	*change_counter = rbuf[18] * 256 + rbuf[19];

	LOG_FUNC_RETURN(card->ctx, r);
}

/*
 Get information of features that the card supports. MyEID 4.x cards are available on different
 hardware and maximum key sizes cannot be determined simply from the version number anymore.
 */
static int myeid_get_card_caps(struct sc_card *card, myeid_card_caps_t* card_caps)
{
	sc_apdu_t apdu;
	int r;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xca, 0x01, 0xAA);
	apdu.resp    = rbuf;
	apdu.resplen = sizeof(myeid_card_caps_t);
	apdu.le      = sizeof(myeid_card_caps_t);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r,  "APDU transmit failed");

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;

	if (apdu.resplen < 11) {
		sc_log(card->ctx, "Unexpected response to GET DATA (MyEIC card capabilities)");
		return SC_ERROR_INTERNAL;
	}

	card_caps->card_caps_ver = rbuf[0];
	/* the card returns big endian values */
	card_caps->card_supported_features = (unsigned short) rbuf[1] << 8 | rbuf[2];
	card_caps->max_rsa_key_length = (unsigned short) rbuf[3] << 8 | rbuf[4];
	card_caps->max_des_key_length = (unsigned short) rbuf[5] << 8 | rbuf[6];
	card_caps->max_aes_key_length = (unsigned short) rbuf[7] << 8 | rbuf[8];
	card_caps->max_ecc_key_length = (unsigned short) rbuf[9] << 8 | rbuf[10];

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
	case SC_CARDCTL_GET_CHANGE_COUNTER:
		r = myeid_get_change_counter(card, (size_t *)ptr);
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

static int
myeid_enc_dec_sym(struct sc_card *card, const u8 *data, size_t datalen,
		u8 *out, size_t *outlen, int decipher)
{

	struct sc_context *ctx;

	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *sdata;
	int r, padding = 0, cbc = 0;

	size_t block_size;
	size_t len, rest_len;
	size_t return_len = 0;

	size_t max_apdu_datalen;
	size_t apdu_datalen;

	assert(card != NULL);

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	myeid_private_data_t *priv;
	priv = (myeid_private_data_t *)card->drv_data;

	/* How many cipher blocks will fit in the APDU. We do not use the APDU chaining
	 * mechanism from OpenSC, because we need the size of the APDU data block
	 * to match a multiple of the cipher block size */

	max_apdu_datalen = sc_get_max_send_size(card);
	if (max_apdu_datalen > sc_get_max_recv_size(card))
		max_apdu_datalen = sc_get_max_recv_size(card);

	if (max_apdu_datalen > SC_MAX_APDU_BUFFER_SIZE)
		max_apdu_datalen = SC_MAX_APDU_BUFFER_SIZE;

	sc_log(ctx, "algorithm %lu algorithm_flags %lx", priv->algorithm, priv->algorithm_flags);

	/* for C_Encrypt/C_EncryptUpdate/C_EncryptFinalize/C_Decrypt/C_DecryptUpdate/C_DecryptFinalize
	 * the 'outlen' is always not NULL (src/pkcs11/framework-pkcs15.c).
	 * For C_EncryptInit and C_DecrytpInit the 'outlen' is set to NULL
	 */
	if (outlen == NULL) {
		/* C_EncryptInit/C_DecryptInit - clear buffers */
		sc_log(ctx, "%s (symmetric key) initialized", decipher ? "C_DecryptInit" : "C_EncryptInit");
		priv->sym_crypt_buffer_len = 0;
		priv->sym_plain_buffer_len = 0;
		return SC_SUCCESS;
	}

	switch (priv->algorithm) {
	case SC_ALGORITHM_AES:
		block_size = 16;
		if (priv->algorithm_flags & SC_ALGORITHM_AES_ECB) {
			padding = 0;
			cbc = 0;
		} else if (priv->algorithm_flags & SC_ALGORITHM_AES_CBC) {
			padding = 0;
			cbc = 1;
		} else if (priv->algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) {
			padding = 1;
			cbc = 1;
		}
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	/* MyEID: ECB APDU must match exact cipher block size in CBC
	 * mode up to 240 bytes can be handled in one APDU
	 * round max_apdu_datalen to multiple of block_size (CBC mode) */

	if (cbc)
		max_apdu_datalen -= max_apdu_datalen % block_size;
	else
		max_apdu_datalen = block_size;

	/* Maybe we have more input data (from previous PSO operation). */
	rest_len = priv->sym_crypt_buffer_len;

	/* no input data from application (this is C_EncryptFinalize/C_DecryptFinalize */
	if (data == NULL) {
		if (datalen != 0)
			LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
		if (decipher) {
			/* C_DecryptFinalize */
			/* decrypted buffer size must match the block size */
			if (priv->sym_plain_buffer_len != block_size)
				LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
			/* do we have any encrypted data left? */
			if (rest_len)
				LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);

			return_len = block_size;
			if (padding) {
				/* check padding */
				uint8_t i, pad_byte = *(priv->sym_plain_buffer + block_size - 1);

				sc_log(ctx, "Found padding byte %02x", pad_byte);
				if (pad_byte == 0 || pad_byte > block_size)
					LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
				sdata = priv->sym_plain_buffer + block_size;
				for (i = 0; i < pad_byte; i++)
					if (*(--sdata) != pad_byte)
						LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_PADDING);
				return_len = block_size - pad_byte;
			}
			/* application can request buffer size or actual buffer size is too small */
			if (out == NULL) {
				*outlen = return_len;
				LOG_FUNC_RETURN(ctx, SC_SUCCESS);
			}
			if (return_len > *outlen)
				LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
			*outlen = return_len;
			memcpy(out, priv->sym_plain_buffer, return_len);
			sc_log(ctx, "C_DecryptFinal %zu bytes", *outlen);
			return SC_SUCCESS;
		} else {
			/* C_EncryptFinalize */
			if (padding) {
				uint8_t pad_byte = block_size - rest_len;
				sc_log(ctx, "Generating padding, padding byte: %d", pad_byte);
				sdata = priv->sym_crypt_buffer + rest_len;
				memset(sdata, pad_byte, pad_byte);
				rest_len = block_size;

			} else if (rest_len) {
				LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
			}
			/* fall through - encipher last block */
		}
	}
	/* check output buffer size */
	len = datalen + rest_len;

	sc_log(ctx, "datalen=%zu rest_len=%zu len=%zu outlen=%zu", datalen, rest_len, len, *outlen);
	/* there is block_size bytes space that can be saved to next run */
	len -= (len % block_size);

	/* application can request buffer size or actual buffer size is too small */
	*outlen = len;
	if (out == NULL)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	/* application buffer is too small */
	if (*outlen < len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	/* main loop */
	while (len >= block_size) {
		if (!decipher)
			sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x84, 0x80);
		else
			sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x84);
		apdu.cla = 0;

		if (len > max_apdu_datalen)
			apdu_datalen = max_apdu_datalen;
		else
			apdu_datalen = len;

		if (cbc)
			apdu.cla = 0x10;

		len -= apdu_datalen;
		sdata = sbuf;

		apdu.le = apdu_datalen;
		apdu.lc = apdu_datalen;
		apdu.datalen = apdu_datalen;
		apdu.data = sbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;

		/* do we have any data from the previous step ? */
		if (rest_len) {
			memcpy(sbuf, priv->sym_crypt_buffer, rest_len);
			sdata += rest_len;
			apdu_datalen -= rest_len;
			priv->sym_crypt_buffer_len = 0;
			rest_len = 0;
		}
		if (data) {
			memcpy(sdata, data, apdu_datalen);
			data += apdu_datalen;
			datalen -= apdu_datalen;
		}
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, r, "decrypt_sym/encrypt_sym failed");
		if (apdu.resplen != apdu.datalen)
			LOG_FUNC_RETURN(ctx, SC_ERROR_WRONG_LENGTH);
		memcpy(out, apdu.resp, apdu.resplen);
		out += apdu.resplen;
		return_len += apdu.resplen;
	}
	/* last block is stored in buffer and is returned to application
	 * in next call to C_DecryptUpdate or C_DecryptFinal. This allow us
	 * to compute how many bytes is to be returned after padding removal.
	 * Whole handling of this is here, because "data" and "out" buffer
	 * can be in the same place.
	 */
	if (decipher) {
		uint8_t tmp_buf[16];
		if (return_len >= block_size) {
			/* save last block to temp buffer */
			memcpy(tmp_buf, out - block_size, block_size);
			if (priv->sym_plain_buffer_len) {
				/* insert previous last block to output buffer */
				sc_log(ctx, "inserting block from previous decrypt");
				memmove(out - return_len + block_size, out - return_len, return_len - block_size);
				memcpy(out - return_len, priv->sym_plain_buffer, block_size);
			} else
				return_len -= block_size;
			/* save last (decrypted) block */
			memcpy(priv->sym_plain_buffer, tmp_buf, block_size);
			priv->sym_plain_buffer_len = block_size;

		} else
			priv->sym_plain_buffer_len = 0;
	}
	/* save rest of data for next run */
	priv->sym_crypt_buffer_len = datalen;
	sc_log(ctx, "rest data len = %zu", datalen);
	if (data)
		memcpy(priv->sym_crypt_buffer, data, datalen);
	sc_log(ctx, "return data len = %zu", return_len);
	*outlen = return_len;
	return SC_SUCCESS;
}

static int
myeid_encrypt_sym(struct sc_card *card, const u8 *data, size_t datalen, u8 *out, size_t *outlen)
{
	return myeid_enc_dec_sym(card, data, datalen, out, outlen, 0);
}

static int
myeid_decrypt_sym(struct sc_card *card, const u8 *data, size_t datalen, u8 *out, size_t *outlen)
{
	return myeid_enc_dec_sym(card, data, datalen, out, outlen, 1);
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
	myeid_ops.get_response		= iso_ops->get_response;
	myeid_ops.logout		= myeid_logout;
	myeid_ops.create_file		= myeid_create_file;
	myeid_ops.delete_file		= myeid_delete_file;
	myeid_ops.list_files		= myeid_list_files;
	myeid_ops.set_security_env	= myeid_set_security_env;
	myeid_ops.compute_signature	= myeid_compute_signature;
	myeid_ops.decipher		= myeid_decipher;
	myeid_ops.process_fci		= myeid_process_fci;
	myeid_ops.card_ctl		= myeid_card_ctl;
	myeid_ops.pin_cmd		= myeid_pin_cmd;
	myeid_ops.wrap			= myeid_wrap_key;
	myeid_ops.unwrap		= myeid_unwrap_key;
	myeid_ops.encrypt_sym		= myeid_encrypt_sym;
	myeid_ops.decrypt_sym		= myeid_decrypt_sym;
	return &myeid_drv;
}

struct sc_card_driver * sc_get_myeid_driver(void)
{
	return sc_get_driver();
}

