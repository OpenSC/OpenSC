/*
 * card-jacartapki.c: Support for JaCarta PKI applet
 *
 * Copyright (C) 2025  Andrey Khodunov <a.khodunov@aladdin.ru>
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
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL /* empty file without openssl */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "iso7816.h"
#include "opensc.h"
#include "pkcs15.h"
#include "sm/sm-jacartapki.h"

#include "jacartapki.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#define JACARTAPKI_CARD_DEFAULT_FLAGS (SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_ISO9796 | SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations jacartapki_ops;

static struct sc_card_driver jacartapki_drv = {
		"JaCarta PKI driver",
		"jacartapki",
		&jacartapki_ops,
		NULL, 0, NULL};

static struct sc_atr_table jacartapki_known_atrs[] = {
		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:06:11:59:00:01:28",
			"JaCarta PKI",								   SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:0B:03:52:00:05:38",
			"JaCarta PKI",								   SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:8C:80:01:80:73:C8:21:13:66:01:06:11:59:00:01:2C",
			"JaCarta PKI/BIO",							       SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:6C:00:FF:80:73:C8:21:13:66:01:06:11:59:00:01",
			"JaCarta PKI/BIO",							       SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
			"3B:9F:11:81:11:3D:00:11:00:00:00:00:00:00:00:00:00:00:00:00:00:32",
			"JaCarta-2 PKI",								 SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{"FF:FF:FF:00:00:00:FF:FF:FF:FF:FF:0F:0F:FF:FF:00:0F:FF",
			"3B:FC:16:00:00:00:73:C8:21:13:66:01:06:11:59:00:01:2C",
			"JaCarta-2 PKI",								 SC_CARD_TYPE_JACARTA_PKI, 0, NULL},

		{NULL,								NULL, NULL, 0,			      0, NULL}
};

static struct sc_aid jacartapki_aid = {
		{0xA0, 0x00, 0x00, 0x01, 0x64, 0x4C, 0x41, 0x53, 0x45, 0x52, 0x00, 0x01},
		12
};

unsigned char jacartapki_ops_df[6] = {
		SC_AC_OP_CREATE, SC_AC_OP_CREATE_DF, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE};
unsigned char jacartapki_ops_ef[4] = {
		SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF};
unsigned char jacartapki_ops_do[3] = {
		SC_AC_OP_READ, SC_AC_OP_WRITE, SC_AC_OP_ADMIN};
unsigned char jacartapki_ops_ko[7] = {
		SC_AC_OP_READ, SC_AC_OP_UPDATE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO};
unsigned char jacartapki_ops_pin[7] = {
		SC_AC_OP_READ, SC_AC_OP_PIN_CHANGE, SC_AC_OP_ADMIN, SC_AC_OP_DELETE_SELF, SC_AC_OP_GENERATE, SC_AC_OP_PIN_RESET, SC_AC_OP_CRYPTO};

static const u8 jacartapki_root_fid[] = {
		0x3F, 0x00};

static int jacartapki_get_serialnr(struct sc_card *, struct sc_serial_number *);
static int jacartapki_get_default_key(struct sc_card *, struct sc_cardctl_default_key *);
static int jacartapki_parse_sec_attrs(struct sc_card *, struct sc_file *);
static int jacartapki_process_fci(struct sc_card *, struct sc_file *, const unsigned char *, size_t);

static int
jacartapki_get_capability(struct sc_card *card, unsigned tag,
		unsigned char *out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[0x100];
	unsigned char p1 = (unsigned char)((tag >> 8) & 0xFF);
	unsigned char p2 = (unsigned char)(tag & 0xFF);
	int rv;
	int ins;

	LOG_FUNC_CALLED(ctx);

	if (out == NULL || out_len == NULL)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	/* INS translation CB -> CC for 'even mode' capsulation, tag 0x87 */
	ins = (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT ? 0xCC : 0xCB);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, ins, p1, p2);
	apdu.cla = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "get SE data  error");

	if (apdu.resplen > *out_len)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, apdu.resp, apdu.resplen);
	*out_len = apdu.resplen;

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_get_caps(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *prv_data = (struct jacartapki_private_data *)card->drv_data;
	unsigned char buf[8];
	size_t buf_len;
	int rv;

	buf_len = sizeof(buf);
	rv = jacartapki_get_capability(card, 0x0180, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'CRYPTO' card capability");
	if (buf_len != sizeof(prv_data->caps.crypto))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'CRYPTO' capability data");
	memcpy(prv_data->caps.crypto, buf, buf_len);

	buf_len = sizeof(buf);
	rv = jacartapki_get_capability(card, 0x0188, buf, &buf_len);
	LOG_TEST_RET(ctx, rv, "cannot get 'KEY LENGTHS' card capability");
	if (buf_len != sizeof(prv_data->caps.supported_keys))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'KEY LENGTHS' capability data");
	memcpy(prv_data->caps.supported_keys, buf, buf_len);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_match_card(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i;

	i = _sc_match_atr(card, jacartapki_known_atrs, &card->type);
	if (i < 0) {
		return 0;
	}

	sc_debug(ctx, SC_LOG_DEBUG_MATCH, "'%s' card matched", jacartapki_known_atrs[i].name);
	return 1;
}

static int
jacartapki_load_options(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i, j;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	const int undefinedSecureVerify = -1;
	const int defaultSecureVerify = 1;
	int secure_verify;

	for (i = 0, secure_verify = undefinedSecureVerify; card->ctx->conf_blocks[i] != NULL && secure_verify == undefinedSecureVerify; i++) {
		scconf_block **found_blocks, *block;

		found_blocks = scconf_find_blocks(card->ctx->conf, card->ctx->conf_blocks[i],
				"card_driver", "jacartapki");
		if (found_blocks == NULL)
			continue;

		for (j = 0, block = found_blocks[j]; block != NULL && secure_verify == undefinedSecureVerify; j++, block = found_blocks[j])
			secure_verify = scconf_get_bool(block, "secure_verify", undefinedSecureVerify);

		free(found_blocks);
	}
	private_data->secure_verify = (secure_verify != undefinedSecureVerify ? secure_verify : defaultSecureVerify);

	sc_log(ctx, "Secure-verify %i", private_data->secure_verify);

	return SC_SUCCESS;
}

static int
jacartapki_init(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = NULL;
	struct sc_path path;
	unsigned int flags;
	int rv = SC_ERROR_NO_CARD_SUPPORT;

	LOG_FUNC_CALLED(ctx);

	private_data = (struct jacartapki_private_data *)calloc(1, sizeof(struct jacartapki_private_data));
	if (private_data == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Failed to allocate private blob for card driver.");

	private_data->auth_state[0].pin_reference = JACARTAPKI_USER_PIN_REFERENCE;
	private_data->auth_state[1].pin_reference = JACARTAPKI_SO_PIN_REFERENCE;

	card->cla = 0x00;
	card->drv_data = private_data;

	sc_path_set(&path, SC_PATH_TYPE_DF_NAME, jacartapki_aid.value, jacartapki_aid.len, 0, 0);
	rv = sc_select_file(card, &path, NULL);
	if (rv < 0) {
		free(card->drv_data);
		card->drv_data = NULL;
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_CARD, "Failed to select JaCarta PKI AID.");
	}

	rv = jacartapki_get_serialnr(card, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get card serial");

	rv = jacartapki_get_caps(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get card capabilities");

	flags = JACARTAPKI_CARD_DEFAULT_FLAGS;
	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 4096, flags, 0x10001);

	card->caps |= SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT;

	rv = jacartapki_load_options(card);
	LOG_TEST_GOTO_ERR(ctx, rv, "Failed to read card driver configuration");

#if defined(ENABLE_SM)
	card->sm_ctx.ops.open = jacartapki_iso_sm_open;
	card->sm_ctx.ops.get_sm_apdu = jacartapki_iso_sm_get_apdu;
	card->sm_ctx.ops.free_sm_apdu = jacartapki_iso_sm_free_apdu;

#endif
	rv = SC_SUCCESS;
err:
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_read_binary(struct sc_card *card, unsigned int offs,
		u8 *buf, size_t count, unsigned long *flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;
	const size_t leMax = 0x100U;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_read_binary(card:%p) offs %i; count %" SC_FORMAT_LEN_SIZE_T "u", card, offs, count);
	if (offs > 0x7fff) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", offs);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, (offs >> 8) & 0x7F, offs & 0xFF);
	apdu.le = MIN(count, leMax);
	apdu.resplen = count;
	apdu.resp = buf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "jacartapki_read_binary() failed");
	sc_log(ctx, "jacartapki_read_binary() apdu.resplen %" SC_FORMAT_LEN_SIZE_T "u", apdu.resplen);

	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
}

static int
jacartapki_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_erase_binary(card:%p) count %" SC_FORMAT_LEN_SIZE_T "u", card, count);
	if (count == 0)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "'ERASE BINARY' failed: invalid size to erase");

	tmp = malloc(count);
	if (tmp == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate temporary buffer");
	memset(tmp, 0xFF, count);

	rv = jacartapki_ops.update_binary(card, offs, tmp, count, flags);
	free(tmp);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	size_t pathlen;
	int rv;
	int reopen_sm_session = 0;

	LOG_FUNC_CALLED(ctx);

	if (in_path->len > SC_MAX_PATH_SIZE)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid path length");

	sc_log(ctx, "jacartapki_select_file(card:%p) path(type:%i):%s, out:%p", card, in_path->type, sc_print_path(in_path), file_out);

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;
	if (file_out)
		*file_out = NULL;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	apdu.cla = 0x80;

	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			LOG_ERROR_GOTO(ctx, rv = SC_ERROR_INVALID_ARGUMENTS, "Invalid path");
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		if (jacartapki_aid.len == in_path->len && memcmp(jacartapki_aid.value, in_path->value, in_path->len) == 0) {
			/* JaCarta PKI application has to be selected by the standand ISO7816 command */
			apdu.cla = 0x00;
		}
		break;
	case SC_PATH_TYPE_PATH:
		if (in_path->len < 2) {
			apdu.p1 = 0;
		} else {
			apdu.p1 = 8;
			if (memcmp(in_path->value, jacartapki_root_fid, sizeof(jacartapki_root_fid)) != 0) {
				if (in_path->len + sizeof(jacartapki_root_fid) > SC_MAX_PATH_SIZE)
					LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid non root starting path length");
				/* In a difference to ISO7816-4 specification (tab. 39)
				 * leading 3F00 has to be included into 'path-from-MF'. */
				memcpy(path, jacartapki_root_fid, sizeof(jacartapki_root_fid));
				memcpy(path + sizeof(jacartapki_root_fid), in_path->value, in_path->len);
				pathlen = in_path->len + sizeof(jacartapki_root_fid);
			}
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		rv = SC_ERROR_INVALID_ARGUMENTS;
		LOG_ERROR_GOTO(ctx, rv, "Invalid path type");
	}

	/* reopening SM for select application */
	if (card->sm_ctx.sm_mode != SM_MODE_NONE && in_path->type == SC_PATH_TYPE_DF_NAME && jacartapki_aid.len == pathlen && memcmp(jacartapki_aid.value, path, pathlen) == 0) {
		jacartapki_iso_sm_close(card);
		reopen_sm_session = 1;
	}

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	/* Return FCI data */
	apdu.p2 = 0x0C; /* not ISO 7816-4 */
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	apdu.le = 256; /* card->max_recv_size > 0 ? card->max_recv_size : 256; */

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "Select file error");

	if (apdu.resplen < 2) {
		if (file_out != NULL) {
			rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
			LOG_ERROR_GOTO(ctx, rv, "Incorrect apdu resp.");
		} else
			goto err;
	}

	switch (apdu.resp[0]) {
	case ISO7816_TAG_FCI:
	case ISO7816_TAG_FCP:
		if (card->ops->process_fci == NULL) {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_ERROR_GOTO(ctx, rv, "FCI processing not supported");
		}

		file = sc_file_new();
		if (file == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			LOG_ERROR_GOTO(ctx, rv, "Failed to allocate sc_file");
		}

		file->path = *in_path;
		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen) {
			rv = jacartapki_process_fci(card, file, apdu.resp + 2, apdu.resp[1]);
			LOG_TEST_GOTO_ERR(ctx, rv, "Process FCI error");

			rv = jacartapki_parse_sec_attrs(card, file);
			LOG_TEST_GOTO_ERR(ctx, rv, "Security attributes parse error");

			if (file->type == SC_FILE_TYPE_INTERNAL_EF) {
				struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;

				sc_file_free(private_data->last_ko);
				sc_file_dup(&private_data->last_ko, file);
			}
		}

		if (file_out) {
			*file_out = file;
			file = NULL;
		}
		break;
	case 0x00: /* proprietary coding */
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		LOG_ERROR_GOTO(ctx, rv, "Proprietary encoding in 'SELECT' APDU response not supported");
		break;
	default:
		rv = SC_ERROR_UNKNOWN_DATA_RECEIVED;
		LOG_ERROR_GOTO(ctx, rv, "Unknown 'SELECT' APDU response tag");
	}
err:
	sc_file_free(file);
	if (reopen_sm_session != 0)
		jacartapki_iso_sm_open(card);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_process_fci(struct sc_card *card, struct sc_file *file, const u8 *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen, len = buflen;
	const unsigned char *tag = NULL, *p = buf;

	LOG_FUNC_CALLED(ctx);
	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_FID, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		sc_log(ctx, "  file identifier: 0x%02X%02X", tag[0], tag[1]);
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE, &taglen);
	if (tag != NULL && taglen > 0 && taglen < 3) {
		file->size = tag[0];
		if (taglen == 2)
			file->size = (file->size << 8) + tag[1];
		sc_log(ctx, "  bytes in file: %" SC_FORMAT_LEN_SIZE_T "d", file->size);
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_SIZE_FULL, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];

			sc_log(ctx, "  bytes in file: %d", bytes);
			file->size = bytes;
		}
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x87, &taglen);
	if (tag != NULL && taglen > 0) {
		unsigned char byte = tag[0];
		const char *type;

		file->shareable = byte & 0x40 ? 1 : 0;
		sc_log(ctx, "  shareable: %s", (byte & 0x40) ? "yes" : "no");
		file->ef_structure = byte & 0x07;
		switch ((byte >> 3) & 7) {
		case 0:
			type = "working EF";
			file->type = SC_FILE_TYPE_WORKING_EF;
			break;
		case 1:
			type = "internal EF";
			file->type = SC_FILE_TYPE_INTERNAL_EF;
			break;
		case 7:
			type = "DF";
			file->type = SC_FILE_TYPE_DF;
			break;
		default:
			type = "unknown";
			break;
		}
		sc_log(ctx, "  type: %s", type);
		sc_log(ctx, "  EF structure: %d", byte & 0x07);
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_DF_NAME, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= sizeof(file->name)) {
		char tbuf[128];

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		sc_hex_dump(file->name, file->namelen, tbuf, sizeof(tbuf));
		sc_log(ctx, "  File name: %s", tbuf);
		if (file->type == 0)
			file->type = SC_FILE_TYPE_DF;
	}

	tag = sc_asn1_find_tag(ctx, p, len, ISO7816_TAG_FCP_PROP_INFO, &taglen);
	if (tag != NULL && taglen > 0)
		sc_file_set_prop_attr(file, tag, taglen);
	else
		file->prop_attr_len = 0;

	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen > 0) {
		sc_file_set_prop_attr(file, tag, taglen);
	} else {
		tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
		if (tag != NULL && taglen)
			sc_file_set_prop_attr(file, tag, taglen);
	}

	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen > 0)
		sc_file_set_sec_attr(file, tag, taglen);

	tag = sc_asn1_find_tag(ctx, p, len, 0x8A, &taglen);
	if (tag != NULL && taglen == 1) {
		if (tag[0] == 0x01)
			file->status = SC_FILE_STATUS_CREATION;
		else if (tag[0] == 0x07 || tag[0] == 0x05)
			file->status = SC_FILE_STATUS_ACTIVATED;
		else if (tag[0] == 0x06 || tag[0] == 0x04)
			file->status = SC_FILE_STATUS_INVALIDATED;
	}

	file->magic = SC_FILE_MAGIC;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_parse_sec_attrs(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	unsigned type = file->type;
	unsigned char *attrs = file->sec_attr;
	size_t len = file->sec_attr_len;
	unsigned char *ops = NULL;
	size_t ii, ops_len = 0;

	LOG_FUNC_CALLED(ctx);
	if (type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(jacartapki_ops_ko) * 2) {
		if (file->prop_attr_len > 2) {
			if (*(file->prop_attr + 2) == JACARTAPKI_KO_ALGORITHM_PIN) {
				sc_log(ctx, "KO-PIN");
				ops = &jacartapki_ops_pin[0];
				ops_len = sizeof(jacartapki_ops_pin) / sizeof(jacartapki_ops_pin[0]);
			} else {
				sc_log(ctx, "KO algo:%X", *(file->prop_attr + 2));
				ops = &jacartapki_ops_ko[0];
				ops_len = sizeof(jacartapki_ops_ko) / sizeof(jacartapki_ops_ko[0]);
			}
		} else {
			sc_log(ctx, "KO");
			ops = &jacartapki_ops_ko[0];
			ops_len = sizeof(jacartapki_ops_ko) / sizeof(jacartapki_ops_ko[0]);
		}
	} else if (type == SC_FILE_TYPE_INTERNAL_EF && len == sizeof(jacartapki_ops_do) * 2) {
		sc_log(ctx, "DO");
		ops = &jacartapki_ops_do[0];
		ops_len = sizeof(jacartapki_ops_do) / sizeof(jacartapki_ops_do[0]);
	} else if (type == SC_FILE_TYPE_WORKING_EF) {
		sc_log(ctx, "EF");
		ops = &jacartapki_ops_ef[0];
		ops_len = sizeof(jacartapki_ops_ef) / sizeof(jacartapki_ops_ef[0]);
	} else if (type == SC_FILE_TYPE_DF) {
		sc_log(ctx, "DF");
		ops = &jacartapki_ops_df[0];
		ops_len = sizeof(jacartapki_ops_df) / sizeof(jacartapki_ops_df[0]);
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported file type");
	}

	sc_log(ctx, "sec.attrs(%" SC_FORMAT_LEN_SIZE_T "u) %s, ops_len %" SC_FORMAT_LEN_SIZE_T "u", len, sc_dump_hex(attrs, len), ops_len);
	if (ops_len * 2 > len)
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Incorrect security attributes");

	for (ii = 0; ii < ops_len; ii++) {
		unsigned val = attrs[ii * 2] * 0x100 + attrs[ii * 2 + 1];

		sc_log(ctx, "access rule 0x%04X, op 0x%X(%i)", val, ops[ii], ops[ii]);
		if (attrs[ii * 2] != 0) {
			sc_log(ctx, "op:%X SC_AC_SCB, val:%X", ops[ii], val);
			sc_file_add_acl_entry(file, ops[ii], SC_AC_SCB, val);
		} else if (attrs[ii * 2 + 1] == 0xFF) {
			sc_log(ctx, "op:%X SC_AC_NEVER", ops[ii]);
			sc_file_add_acl_entry(file, ops[ii], SC_AC_NEVER, SC_AC_KEY_REF_NONE);
		} else if (attrs[ii * 2 + 1] != 0) {
			unsigned char ref = attrs[ii * 2 + 1];
			unsigned method = (ref == JACARTAPKI_TRANSPORT_PIN1_REFERENCE) ? SC_AC_AUT : SC_AC_CHV;
			/* KO ref supported: Transportation PIN 0x01, Admin PIN 0x10, User PIN 0x20, (Admin OR User) Logical EXP 0x30 -> 0x20 CHV
			 */
			if (ref == 0x30) {
				sc_log(ctx, "(Admin OR User) Logical EXP transitioned to (User PIN) ref-20");
				ref = 0x20;
			}

			sc_file_add_acl_entry(file, ops[ii], method, ref);
		} else {
			sc_log(ctx, "op:%X SC_AC_NONE", ops[ii]);
			sc_file_add_acl_entry(file, ops[ii], SC_AC_NONE, SC_AC_KEY_REF_NONE);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_fcp_encode(struct sc_card *card, const struct sc_file *file, unsigned char **out)
{
	struct sc_context *ctx = card->ctx;
	size_t buf_size;
	unsigned char *buf = NULL;
	size_t offs = 0;
	unsigned char *ops = NULL;
	size_t ii, ops_len = 0, file_size = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (out == NULL) {
		rv = SC_ERROR_INVALID_DATA;
		LOG_ERROR_GOTO(ctx, rv, "Invalid buffer parameter");
	}

	if (file->type == SC_FILE_TYPE_DF) {
		ops = &jacartapki_ops_df[0];
		ops_len = sizeof(jacartapki_ops_df);
	} else if (file->type == SC_FILE_TYPE_WORKING_EF) {
		ops = &jacartapki_ops_ef[0];
		ops_len = sizeof(jacartapki_ops_ef);
		file_size = file->size;
	} else if (file->type == SC_FILE_TYPE_INTERNAL_EF && file->ef_structure == JACARTAPKI_FILE_DESCRIPTOR_KO) {
		ops = &jacartapki_ops_ko[0];
		ops_len = sizeof(jacartapki_ops_ko);
		file_size = file->size;
	} else {
		rv = SC_ERROR_NOT_SUPPORTED;
		LOG_ERROR_GOTO(ctx, rv, "Unsupported type of the file to be created");
	}

	buf_size = 13;
	buf_size += (file->namelen > 0 ? file->namelen + 2 : 0);
	buf_size += (file->prop_attr != NULL && file->prop_attr_len > 0 ? file->prop_attr_len + 2 : 0);
	buf_size += ops_len * 2;
	buf_size += (file->encoded_content != NULL ? file->encoded_content_len : 0);

	buf = calloc(1, buf_size);
	if (buf == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to allocate FCP buffer");
	}
	offs = 0;

	buf[offs++] = ISO7816_TAG_FCP_LCS;
	buf[offs++] = 1;
	buf[offs++] = 0x04; /* offs: +3 */

	buf[offs++] = ISO7816_TAG_FCP_FID;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF; /* offs: +4 */

	buf[offs++] = ISO7816_TAG_FCP_SIZE;
	buf[offs++] = 2;
	buf[offs++] = (file_size >> 8) & 0xFF;
	buf[offs++] = file_size & 0xFF; /* offs: +4 */

	if (file->namelen > 0) {
		buf[offs++] = ISO7816_TAG_FCP_DF_NAME;
		buf[offs++] = file->namelen;
		memcpy(buf + offs, file->name, file->namelen);
		offs += file->namelen;
	}

	if (file->prop_attr != NULL && file->prop_attr_len > 0) {
		buf[offs++] = ISO7816_TAG_FCP_PROP_INFO;
		buf[offs++] = file->prop_attr_len;
		memcpy(buf + offs, file->prop_attr, file->prop_attr_len);
		offs += file->prop_attr_len;
	}

	buf[offs++] = ISO7816_TAG_FCP_ACLS;
	buf[offs++] = ops_len * 2; /* offs: +2 */

	for (ii = 0; ii < ops_len; ii++) {
		const struct sc_acl_entry *entry = sc_file_get_acl_entry(file, ops[ii]);

		if (entry != NULL)
			sc_log(ctx, "ops %i: method %X, reference %X", ops[ii], entry->method, entry->key_ref);
		else
			sc_log(ctx, "ops %i: no ACL entry", ops[ii]);

		if (entry == NULL || entry->method == SC_AC_NEVER) {
			buf[offs++] = 0x00;
			buf[offs++] = 0xFF;
		} else if (entry->method == SC_AC_NONE) {
			buf[offs++] = 0x00;
			buf[offs++] = 0x00;
		} else if (entry->method == SC_AC_CHV) {
			buf[offs++] = 0x00;
			buf[offs++] = entry->key_ref & 0xFF;
		} else if (entry->method == SC_AC_SCB) {
			buf[offs++] = (entry->key_ref >> 8) & 0xFF;
			buf[offs++] = entry->key_ref & 0xFF;
		} else {
			rv = SC_ERROR_NOT_SUPPORTED;
			LOG_ERROR_GOTO(ctx, rv, "Non supported AC method");
		}
	}

	if (file->encoded_content != NULL && file->encoded_content_len > 0) {
		memcpy(buf + offs, file->encoded_content, file->encoded_content_len);
		offs += file->encoded_content_len;
	}

	*out = buf;
	rv = (int)offs;
err:
	if (rv < 0)
		free(buf);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char *fcp = NULL, *tmp;
	unsigned char p1 = (unsigned char)0;
	int fcp_len;
	size_t fcp_hdr_len, offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "create file (type:%i, ID:0x%X, path:%s)", file->type, file->id, sc_print_path(&file->path));

	/* Select parent */
	if (file->path.len > 2) {
		struct sc_path parent_path = file->path;

		parent_path.len -= 2;
		rv = jacartapki_select_file(card, &parent_path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select parent DF");
	}

	rv = jacartapki_fcp_encode(card, file, &fcp);
	LOG_TEST_GOTO_ERR(ctx, rv, "FCP encode error");
	fcp_len = rv;

	if (fcp_len < 0x80)
		fcp_hdr_len = 2;
	else if (fcp_len <= 0xFF)
		fcp_hdr_len = 3;
	else if (fcp_len <= 0xFFFF)
		fcp_hdr_len = 4;
	else {
		rv = SC_ERROR_NOT_SUPPORTED;
		LOG_ERROR_GOTO(ctx, rv, "Unsupported FCP size");
	}

	if (file->type == SC_FILE_TYPE_WORKING_EF)
		p1 = 0x01;
	else if (file->type == SC_FILE_TYPE_DF)
		p1 = 0x38;
	else if (file->type == SC_FILE_TYPE_INTERNAL_EF)
		p1 = file->ef_structure;
	else
		LOG_ERROR_GOTO(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported type of the file to create");

	tmp = realloc(fcp, fcp_hdr_len + fcp_len);
	if (tmp == NULL) {
		rv = SC_ERROR_OUT_OF_MEMORY;
		LOG_ERROR_GOTO(ctx, rv, "Failed to reallocate FCP buffer");
	}
	fcp = tmp;
	memmove(fcp + fcp_hdr_len, fcp, fcp_len);

	offs = 0;
	fcp[offs++] = ISO7816_TAG_FCP;
	if (fcp_len < 0x80) {
		fcp[offs++] = fcp_len & 0xFF;
	} else if (fcp_len <= 0xFF) {
		fcp[offs++] = 0x81;
		fcp[offs++] = fcp_len & 0xFF;
	} else if (fcp_len <= 0xFFFF) {
		fcp[offs++] = 0x82;
		fcp[offs++] = (fcp_len >> 8) & 0xFF;
		fcp[offs++] = fcp_len & 0xFF;
	}
	offs += fcp_len;

	sc_log(ctx, "FCP data '%s'", sc_dump_hex(fcp, offs));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.p1 = p1;
	apdu.data = fcp;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "jacartapki_create_file() create file error");

	if (file->path.len == 0) {
		sc_append_file_id(&file->path, file->id);
		file->path.type = SC_PATH_TYPE_FILE_ID;
	}

	rv = jacartapki_select_file(card, &file->path, NULL);
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot select newly created file");
err:
	free(fcp);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_apdu apdu;
	u8 pin_data[ARRAY_SIZE(private_data->auth_state) * 4];
	int offs;
	int rv;
	size_t i;

	LOG_FUNC_CALLED(ctx);

	offs = 0;
	for (i = 0; i < ARRAY_SIZE(private_data->auth_state); ++i) {
		if (private_data->auth_state[i].logged_in != SC_PIN_STATE_LOGGED_OUT) {
			pin_data[offs++] = 0; /* XX = 0 */
			pin_data[offs++] = 0; /* level */
			pin_data[offs++] = (private_data->auth_state[i].pin_reference >> 8) & 0xFF;
			pin_data[offs++] = private_data->auth_state[i].pin_reference & 0xFF;

			private_data->auth_state[i].logged_in = SC_PIN_STATE_LOGGED_OUT;
		}
	}
	if (offs == 0)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x28, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.data = pin_data;
	apdu.datalen = offs;
	apdu.lc = offs;

	rv = sc_transmit_apdu(card, &apdu);
	if (rv == SC_SUCCESS)
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;

	LOG_FUNC_CALLED(ctx);

#ifdef ENABLE_SM
	if (card->sm_ctx.sm_mode != SM_MODE_NONE && card->sm_ctx.ops.close)
		card->sm_ctx.ops.close(card);
#endif
	if (private_data != NULL) {
		sc_file_free(private_data->last_ko);
		free(private_data);
		card->drv_data = NULL;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_apdu apdu;
	int rv, p1 = 0;

	LOG_FUNC_CALLED(ctx);

	rv = jacartapki_select_file(card, path, &file);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	if (file->type == SC_FILE_TYPE_DF)
		p1 = 1;
	sc_file_free(file);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, p1, 0x00);

	sc_log(ctx, "delete %s file '%s'", (p1 ? "DF" : "EF"), sc_print_path(path));
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Failed to delete file");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_list_files(struct sc_card *card, unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char p1s[] = {0x01, 0x38, 0x08}; /* 0x01 list all EF, 0x38 list all subdirectories, 0x08 list all KO (keys/PIN) */
	unsigned ii;
	size_t offs;

	LOG_FUNC_CALLED(ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x30, 0, 0);
	apdu.cla = 0x80;

	for (ii = 0, offs = 0; ii < sizeof(p1s); ii++) {
		size_t oo;
		int jj;
		int rv;
		int fileTLVs;

		apdu.p1 = p1s[ii];
		apdu.resplen = sizeof(rbuf);
		apdu.resp = rbuf;
		apdu.le = MIN(apdu.resplen, 0x100);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "list files error");

		if (apdu.resplen < 4)
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);

		/* APDU response
		 *		TLV1		TLV2				TLVN
		 *      ┌────┬────┬───────┬────┬───┬─────┬──────┬────┬────┬───┬─────┬──────┐
		 *      │0xD1│0x02│DF size│0xD2│ L │ FID │ Name │... │0xD2│ L │ FID │ Name │
		 *      └────┴────┴───────┴────┴───┴─────┴──────┴────┴────┴───┴─────┴──────┘
		 */

		/* number of the file TLVs in this chunk: rbuf[2] * 0x100 + rbuf[3]
		 * for le <= 0x100 we can have no more than 0x3F file TLVs in chunk
		 * which falls in rbuf[3]
		 */
		fileTLVs = rbuf[3];
		if (fileTLVs * 2 + offs > buflen) /* offs: length of data already put to output buf */
			LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

		/* oo points to the file TLV being processed
		 * file TLV size >= 4, name optional
		 */
		for (oo = 4, jj = 0; jj < fileTLVs && oo + 4 <= apdu.resplen; jj++) {
			if (rbuf[oo] != 0xD2)
				LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
			memcpy(buf + offs, rbuf + oo + 2, 2);
			oo += 2 + rbuf[oo + 1]; /* rbuf[oo + 1]: (file_ID || file_name) length */
			offs += 2;
		}
	}

	LOG_FUNC_RETURN(ctx, (int)offs);
}

static int
jacartapki_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	if (sw1 == 0x62 && sw2 == 0x82)
		return SC_SUCCESS;

	return iso_ops->check_sw(card, sw1, sw2);
}

static int
jacartapki_set_security_env(struct sc_card *card,
		const struct sc_security_env *senv, int se_num)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &private_data->security_env;

	LOG_FUNC_CALLED(ctx);
	if (senv == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "jacartapki_set_security_env() op:%X,flags:%lX,algo:(%lX,ref:%lX,flags:%lX)",
			senv->operation, senv->flags, senv->algorithm, senv->algorithm_ref, senv->algorithm_flags);
	*env = *senv;
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_chv_secure_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char plain_text[16], sha1[SHA_DIGEST_LENGTH];
	unsigned char *encrypted = NULL;
	size_t encrypted_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%" SC_FORMAT_LEN_SIZE_T "u)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (pin_cmd->pin1.data == NULL || pin_cmd->pin1.len == 0) {
		rv = SC_ERROR_INVALID_ARGUMENTS;
		LOG_ERROR_GOTO(ctx, rv, "null value not allowed for secure PIN verify");
	}

	RAND_bytes(plain_text, 8);

	rv = iso_ops->get_challenge(card, plain_text + 8, 8);
	LOG_TEST_RET(ctx, rv, "Get card challenge failed");

	SHA1(pin_cmd->pin1.data, pin_cmd->pin1.len, sha1);

	rv = jacartapki_sm_encrypt_des_cbc3(ctx, sha1, plain_text, 16, &encrypted, &encrypted_len, 1);
	LOG_TEST_GOTO_ERR(ctx, rv, "_encrypt_des_cbc3() failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.data = encrypted;
	apdu.datalen = encrypted_len;
	apdu.lc = encrypted_len;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	free(encrypted);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, int secure_verify,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%" SC_FORMAT_LEN_SIZE_T "u)", pin_cmd->pin_reference, pin_cmd->pin1.len);

	if (pin_cmd->pin1.data != NULL && pin_cmd->pin1.len == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, pin_cmd->pin_reference);
	} else if (pin_cmd->pin1.data != NULL && pin_cmd->pin1.len > 0) {
		if (secure_verify) {
			rv = jacartapki_chv_secure_verify(card, pin_cmd, tries_left);
			LOG_FUNC_RETURN(ctx, rv);
		} else {
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, 0x00);
			apdu.data = pin_cmd->pin1.data;
			apdu.datalen = pin_cmd->pin1.len;
			apdu.lc = pin_cmd->pin1.len;
		}
	} else {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_is_verified(struct sc_card *card, const struct sc_pin_cmd_data *pin_cmd_data,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	int rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

	LOG_FUNC_CALLED(ctx);
	if (pin_cmd_data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (pin_cmd_data->pin_type != SC_AC_CHV)
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non CHV PIN type is not supported for verification");

	pin_cmd = *pin_cmd_data;
	pin_cmd.pin1.data = (unsigned char *)"";
	pin_cmd.pin1.len = 0;
	rv = jacartapki_chv_verify(card, &pin_cmd, 0, tries_left);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_from_ko_le(struct sc_context *ctx, unsigned reference, unsigned *out)
{
	if (out == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (reference == 0x30) {
		*out = 0x20;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

static int
jacartapki_select_global_pin(struct sc_card *card, unsigned reference, struct sc_file **out_file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *file = NULL;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Select global PIN file %X", reference);

	sc_format_path("3F0000FF", &path);
	path.value[path.len - 1] = reference;

	rv = jacartapki_select_file(card, &path, &file);
	LOG_TEST_RET(ctx, rv, "Failed to select PIN file");

	if (file->prop_attr != NULL && file->prop_attr_len >= 3 && *(file->prop_attr + 2) == JACARTAPKI_KO_ALGORITHM_LOGIC) {
		unsigned ref;

		rv = jacartapki_pin_from_ko_le(ctx, reference, &ref);
		LOG_TEST_GOTO_ERR(ctx, rv, "Unknown LogicalExpression KO");
		path.value[path.len - 1] = ref;

		sc_file_free(file);
		file = NULL;
		rv = jacartapki_select_file(card, &path, &file);
		LOG_TEST_GOTO_ERR(ctx, rv, "Failed to select PIN file");
	}

	if (out_file != NULL) {
		*out_file = file;
		file = NULL;
	}
err:
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_verify(struct sc_card *card, unsigned type, unsigned reference,
		const unsigned char *data, size_t data_len, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	int rv;
	unsigned int chv_ref = reference;
	int secure_verify;
	size_t i;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify PIN(type:%X,ref:%i,data(len:%" SC_FORMAT_LEN_SIZE_T "u,%p)", type, reference, data_len, data);

	if (type == SC_AC_AUT && reference == JACARTAPKI_TRANSPORT_PIN1_REFERENCE)
		type = SC_AC_CHV;

	if (type == SC_AC_AUT) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	} else if (type == SC_AC_SCB) {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	} else if (type == SC_AC_CHV) {
		if ((reference & 0x80) == 0) {
			rv = jacartapki_select_global_pin(card, reference, NULL);
			LOG_TEST_RET(ctx, rv, "Select PIN file error");
			chv_ref = 0;
		}
	} else {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = chv_ref;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;
	pin_cmd.pin1.data = data;
	pin_cmd.pin1.len = data_len;

	if (data && !data_len) {
		rv = jacartapki_pin_is_verified(card, &pin_cmd, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}
	/* plain VERIFY for Transport PIN #1,#2 */
	secure_verify = (reference != 0x01 && reference != 0x02 ? private_data->secure_verify : 0);

	rv = jacartapki_chv_verify(card, &pin_cmd, secure_verify, tries_left);
	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	/* TEMP P15 DF RELOAD PRIVATE */
	for (i = 0; i < ARRAY_SIZE(private_data->auth_state); ++i) {
		if (private_data->auth_state[i].pin_reference == reference) {
			private_data->auth_state[i].logged_in = SC_PIN_STATE_LOGGED_IN;
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned chv_ref = data->pin_reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(type:%i,ref:%i,lengths:%" SC_FORMAT_LEN_SIZE_T "u/%" SC_FORMAT_LEN_SIZE_T "u)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (data->pin1.len > 0) {
		rv = jacartapki_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_TEST_RET(ctx, rv, "Cannot verify old PIN");
	}

	if (data->pin2.len == 0)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Missing new PIN value");

	if ((data->pin_reference & 0x80) != 0) {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "TODO: local PINs");
	}

	struct sc_file *pin_file = NULL;
	const struct sc_acl_entry *entry;

	rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
	LOG_TEST_RET(ctx, rv, "Select PIN file error");

	chv_ref = 0;
	entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_CHANGE);
	if (entry != NULL) {
#if defined(ENABLE_SM)
		rv = jacartapki_sm_chv_change(card, data, chv_ref, tries_left, entry->key_ref);
		LOG_FUNC_RETURN(ctx, rv);
#else
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "UPDATE CHV/SCB present. PIN change is not supported w/o SM");
#endif
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "PIN change is not supported for KO object w/o UPDATE CHV/SCB");
	}
}

static int
jacartapki_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	struct sc_file *pin_file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(type:%i,ref:%i,lengths:%" SC_FORMAT_LEN_SIZE_T "u/%" SC_FORMAT_LEN_SIZE_T "u)", data->pin_type, data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (!(data->pin_reference & 0x80)) {
		const struct sc_acl_entry *entry;

		rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
		LOG_TEST_GOTO_ERR(ctx, rv, "Select PIN file error");

		if (data->pin1.len) {
			entry = sc_file_get_acl_entry(pin_file, SC_AC_OP_PIN_RESET);
			if (entry != NULL) {
				sc_log(ctx, "Acl(PIN_RESET): %04X", entry->key_ref);
				if ((entry->key_ref & 0x00FF) == 0xFF) {
					LOG_TEST_GOTO_ERR(ctx, SC_ERROR_NOT_ALLOWED, "Reset PIN not allowed");
				} else if ((entry->key_ref & 0xC000) != 0) {
					LOG_TEST_GOTO_ERR(ctx, SC_ERROR_NOT_SUPPORTED, "Reset PIN protected by SM: not supported (TODO)");
				} else if ((entry->key_ref & 0x00FF) != 0) {
					rv = jacartapki_pin_verify(card, SC_AC_CHV, entry->key_ref & 0x00FF, data->pin1.data, data->pin1.len, tries_left);
					LOG_TEST_GOTO_ERR(ctx, rv, "Verify PUK failed");

					sc_file_free(pin_file);
					pin_file = NULL;

					rv = jacartapki_select_global_pin(card, data->pin_reference, &pin_file);
					LOG_TEST_GOTO_ERR(ctx, rv, "Select PIN file error");
				}
			}
		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 0, 0);
	apdu.cla = 0x80;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(ctx, rv, "PIN change failed");

	if (data->pin2.len > 0) {
		size_t save_len = data->pin1.len;

		data->pin1.len = 0;
		rv = jacartapki_pin_change(card, data, tries_left);
		data->pin1.len = save_len;
		LOG_TEST_GOTO_ERR(ctx, rv, "Cannot set new PIN value");
	}
	rv = SC_SUCCESS;
err:
	sc_file_free(pin_file);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_pin_getinfo(struct sc_card *card, struct sc_pin_cmd_data *data)
{
	size_t i;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	for (i = 0; i < ARRAY_SIZE(private_data->auth_state); ++i) {
		if (private_data->auth_state[i].pin_reference == (unsigned int)data->pin_reference) {
			data->pin1.logged_in = private_data->auth_state[i].logged_in;
			break;
		}
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jacartapki_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "jacartapki_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%" SC_FORMAT_LEN_SIZE_T "u, PIN-2 %p:%" SC_FORMAT_LEN_SIZE_T "u",
			data->cmd, data->pin_type, data->pin_reference,
			data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		rv = jacartapki_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_CHANGE:
		rv = jacartapki_pin_change(card, data, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_UNBLOCK:
		rv = jacartapki_pin_reset(card, data, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	case SC_PIN_CMD_GET_INFO:
		rv = jacartapki_pin_getinfo(card, data);
		LOG_FUNC_RETURN(ctx, rv);
	default:
		sc_log(ctx, "PIN command 0x%X do not yet supported.", data->cmd);
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non-supported PIN command");
	}
}

static int
jacartapki_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_serial_number sn;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->serialnr.len) {
		if (serial)
			*serial = card->serialnr;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	sn.len = sizeof(sn.value);
	rv = jacartapki_get_capability(card, 0x0114, sn.value, &sn.len);
	LOG_TEST_RET(ctx, rv, "cannot get 'serial number' card capability");

	if (sizeof(private_data->caps.serial) != sn.len)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid 'SERIAL NUMBER' data");
	memcpy(&private_data->caps.serial, sn.value, sn.len);

	card->serialnr = sn;
	if (serial)
		*serial = sn;
	sc_log(ctx, "jacartapki serial '%s'", sc_dump_hex(sn.value, sn.len));
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_get_default_key(struct sc_card *card, struct sc_cardctl_default_key *data)
{
	struct sc_context *ctx = card->ctx;
	scconf_block *atrblock = NULL;

	LOG_FUNC_CALLED(ctx);

	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (atrblock == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);

	if (data->method == SC_AC_AUT && data->key_ref == 1) {
		const char *default_key = scconf_get_str(atrblock, "default_transport_pin1", JACARTAPKI_TRANSPORT_PIN1_VALUE);
		int rv;

		rv = sc_hex_to_bin(default_key, data->key_data, &data->len);
		LOG_TEST_RET(ctx, rv, "Cannot get transport PIN01 default value: HEX to BIN conversion error");

		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	LOG_FUNC_RETURN(ctx, SC_ERROR_NO_DEFAULT_KEY);
}

static int
jacartapki_generate_key(struct sc_card *card, struct sc_cardctl_jacartapki_genkey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	const unsigned char *ptr = NULL;
	size_t offs, taglen = 0;
	int rv;
	int ins;

	LOG_FUNC_CALLED(ctx);

	offs = 0;
	sbuf[offs++] = 0xAC;
	sbuf[offs++] = args->exponent_len + 6;
	sbuf[offs++] = 0x80;
	sbuf[offs++] = 0x01;
	sbuf[offs++] = args->algorithm;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = 0x81;
	sbuf[offs++] = args->exponent_len;
	memcpy(sbuf + offs, args->exponent, args->exponent_len);
	offs += args->exponent_len;

	/* INS translation 47 -> 48 for 'even mode' capsulation, tag 0x87 */
	ins = (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT ? 0x48 : 0x47);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, ins, 0x00, 0x00);
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = SC_MAX_APDU_RESP_SIZE;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	/* get modulus */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr != NULL)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x81, &taglen);
	if (ptr == NULL || (taglen != args->modulus_len))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid modulus data length");
	memcpy(args->modulus, ptr, taglen);

	/* get exponent */
	ptr = sc_asn1_find_tag(ctx, apdu.resp, apdu.resplen, 0x7F49, &taglen);
	if (ptr != NULL)
		ptr = sc_asn1_find_tag(ctx, ptr, taglen, 0x82, &taglen);
	if (ptr == NULL || taglen != args->exponent_len || memcmp(ptr, args->exponent, taglen) != 0)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid exponent data");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
jacartapki_update_key(struct sc_card *card, const struct sc_cardctl_jacartapki_updatekey *args)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	LOG_FUNC_CALLED(ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x00, 0x00);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.cla = 0x80;
	apdu.datalen = args->len;
	apdu.data = args->data;
	apdu.lc = args->len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
jacartapki_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return jacartapki_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_GET_DEFAULT_KEY:
		return jacartapki_get_default_key(card, (struct sc_cardctl_default_key *)ptr);
	case SC_CARDCTL_JACARTAPKI_GENERATE_KEY:
		sc_log(ctx, "CMD SC_CARDCTL_JACARTAPKI_GENERATE_KEY");
		return jacartapki_generate_key(card, (struct sc_cardctl_jacartapki_genkey *)ptr);
	case SC_CARDCTL_JACARTAPKI_UPDATE_KEY:
		sc_log(ctx, "CMD SC_CARDCTL_JACARTAPKI_UPDATE_KEY");
		return jacartapki_update_key(card, (struct sc_cardctl_jacartapki_updatekey *)ptr);
	case SC_CARDCTL_PKCS11_INIT_TOKEN:
		sc_log(ctx, "CMD SC_CARDCTL_PKCS11_INIT_TOKEN");
		return SC_ERROR_NOT_SUPPORTED;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int
jacartapki_decipher(struct sc_card *card, const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &private_data->security_env;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	struct sc_tlv_data tlv;
	int rv;
	size_t offs;
	u8 *tagPtr;
	u8 *responseTagPtr;
	unsigned int tagClass;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "in-length:%" SC_FORMAT_LEN_SIZE_T "u, key-size:%" SC_FORMAT_LEN_SIZE_T "u, out-length:%" SC_FORMAT_LEN_SIZE_T "u", in_len, (private_data->last_ko ? private_data->last_ko->size : 0), out_len);
	if (env->operation != SC_SEC_OPERATION_DECIPHER)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "has to be SC_SEC_OPERATION_DECIPHER");
	else if (in_len > (sizeof(sbuf) - 4))
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "invalid data length");

	rv = sc_asn1_put_tag(0x82, in, in_len, sbuf, sizeof(sbuf), &tagPtr);
	LOG_TEST_RET(ctx, rv, "ASN.1 tagging failed"); // should never fail

	offs = tagPtr - sbuf;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80,
			(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) ? 0x0A : 0x0C);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = SC_MAX_APDU_RESP_SIZE;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	responseTagPtr = rbuf;
	rv = sc_asn1_read_tag((const u8 **)&responseTagPtr, apdu.resplen, &tagClass, &tlv.tag, &tlv.len);
	LOG_TEST_RET(ctx, rv, "Invalid response from PSO DST");
	tlv.value = responseTagPtr;

	if (tagClass != 0x80 || tlv.tag != 0x00) {
		sc_log(ctx, "invalid decrypted data tag. response(%" SC_FORMAT_LEN_SIZE_T "u) %s ...", apdu.resplen, sc_dump_hex(apdu.resp, 12));
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
	}

	if (tlv.len > out_len) {
		sc_log(ctx, "PSO Decipher failed: response data too long: %" SC_FORMAT_LEN_SIZE_T "u\n", tlv.len);
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);
	} else if (tlv.len == 0) {
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_DATA, "PSO Decipher failed: response data missing.");
	}

	memcpy(out, tlv.value, tlv.len);
	LOG_FUNC_RETURN(ctx, (int)tlv.len);
}

static int
jacartapki_compute_signature_dst(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	struct sc_security_env *env = &private_data->security_env;
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	unsigned char dataTag;
	unsigned char pso;
	unsigned char algo;
	unsigned char tailReserved;
	int rv;
	size_t offs = 0;
	size_t keySize;
	unsigned long digestEncodeFlags;
	size_t digestLength;
	size_t sigValueLength;
	u8 *tagPtr;
	const u8 *sigValuePtr;

	LOG_FUNC_CALLED(ctx);

	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");

	keySize = private_data->last_ko != NULL ? private_data->last_ko->size : 0;
	sc_log(ctx, "SC_SEC_OPERATION: %04X, in-length:%" SC_FORMAT_LEN_SIZE_T "u, key-size:%" SC_FORMAT_LEN_SIZE_T "u", env->operation, in_len, keySize);

	if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) != 0 ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224) != 0 ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) != 0 ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) != 0 ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) != 0 ||
			(env->algorithm_flags & SC_ALGORITHM_RSA_HASH_NONE) != 0) {

		digestEncodeFlags = (env->algorithm_flags & SC_ALGORITHM_RSA_HASHES) | SC_ALGORITHM_RSA_PAD_NONE;

	} else if ((env->algorithm_flags & SC_ALGORITHM_RSA_RAW) != 0) {

		digestEncodeFlags = SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_PAD_NONE;
	} else {
		LOG_ERROR_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported digest type");
	}

	digestLength = sizeof(rbuf); /* rbuf reuse */
	rv = sc_pkcs1_encode(ctx, digestEncodeFlags, in, in_len, rbuf, &digestLength, keySize, NULL);
	LOG_TEST_RET(ctx, rv, "Failed to encode digest");

	if ((env->algorithm_flags & SC_ALGORITHM_RSA_RAW) != 0) {
		dataTag = 0x82; /* tag 82H ciphertext */
		pso = 0x80;	/* PSO_Decrypt */
		algo = 0x0C;	/* ALG_RSA_NOPAD */
		tailReserved = 0;
	} else {
		dataTag = 0x80;
		pso = 0x9E;  /* PSO_Sign */
		algo = 0x8A; /* ALG_RSA_PKCS */
		tailReserved = 11;
	}

	if ((keySize > 0 && digestLength > (keySize - tailReserved)) || digestLength > SC_MAX_EXT_APDU_DATA_SIZE)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "too much of the input data");

	rv = sc_asn1_put_tag(dataTag, rbuf, digestLength, sbuf, sizeof(sbuf), &tagPtr);
	LOG_TEST_RET(ctx, rv, "ASN.1 tagging failed");
	offs = tagPtr - sbuf;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, pso, algo);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.datalen = offs;
	apdu.data = sbuf;
	apdu.lc = offs;
	apdu.le = SC_MAX_APDU_RESP_SIZE;
	apdu.resp = rbuf;
	apdu.resplen = SC_MAX_EXT_APDU_RESP_SIZE;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PSO DST failed");

	sigValuePtr = (u8 *)apdu.resp;
	if ((env->algorithm_flags & SC_ALGORITHM_RSA_RAW) != 0) {
		unsigned int valueClass;
		unsigned int tagOut;
		rv = sc_asn1_read_tag(&sigValuePtr, apdu.resplen, &valueClass, &tagOut, &sigValueLength);
		LOG_TEST_RET(ctx, rv, "Incorrect ASN1 in PSO Decrypt response");

		if (0x00 != tagOut || 0x80 != valueClass || 5 > apdu.resplen)
			LOG_ERROR_RET(ctx, SC_ERROR_INTERNAL, "APDU response incorrect");
	} else {
		sigValueLength = apdu.resplen;
	}

	if (sigValueLength > out_len) {
		sc_log(ctx, "Compute signature failed: invalid response length %" SC_FORMAT_LEN_SIZE_T "u\n", sigValueLength);
		LOG_FUNC_RETURN(ctx, SC_ERROR_CARD_CMD_FAILED);
	}

	memcpy(out, sigValuePtr, sigValueLength);
	LOG_FUNC_RETURN(ctx, (int)sigValueLength);
}

static int
jacartapki_compute_signature_at(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct jacartapki_private_data *private_data = (struct jacartapki_private_data *)card->drv_data;
	const struct sc_security_env *env = &private_data->security_env;

	LOG_FUNC_CALLED(ctx);
	if (env->operation != SC_SEC_OPERATION_AUTHENTICATE)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_AUTHENTICATE");

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

static int
jacartapki_compute_signature(struct sc_card *card,
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx;
	struct jacartapki_private_data *private_data;
	struct sc_security_env *env;

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = card->ctx;
	if (in == NULL || out == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid compute signature arguments");

	LOG_FUNC_CALLED(ctx);

	private_data = (struct jacartapki_private_data *)card->drv_data;
	if (private_data == NULL)
		LOG_ERROR_RET(ctx, SC_ERROR_INTERNAL, "Invalid card drv_data");

	env = &private_data->security_env;

	sc_log(ctx, "op:%x, inlen %" SC_FORMAT_LEN_SIZE_T "u, outlen %" SC_FORMAT_LEN_SIZE_T "u", env->operation, in_len, out_len);

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return jacartapki_compute_signature_dst(card, in, in_len, out, out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return jacartapki_compute_signature_at(card, in, in_len, out, out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}

/* card reader lock obtained - re-select card applet if necessary. */
static int
jacartapki_card_reader_lock_obtained(sc_card_t *card, int was_reset)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv = SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);

	if (was_reset > 0) {
		sc_path_set(&path, SC_PATH_TYPE_DF_NAME, jacartapki_aid.value, jacartapki_aid.len, 0, 0);
		rv = sc_select_file(card, &path, NULL);
		LOG_TEST_RET(ctx, rv, "Cannot select JaCarta PKI AID");
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static struct sc_card_driver *
sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (!iso_ops)
		iso_ops = iso_drv->ops;

	jacartapki_ops = *iso_ops;

	jacartapki_ops.match_card = jacartapki_match_card;
	jacartapki_ops.init = jacartapki_init;
	jacartapki_ops.finish = jacartapki_finish;
	jacartapki_ops.read_binary = jacartapki_read_binary;
	/*	write_binary: ISO7816 implementation works	*/
	/*	update_binary: ISO7816 implementation works	*/
	jacartapki_ops.erase_binary = jacartapki_erase_binary;
	/*	resize_binary	*/
	/*	read_record: Untested	*/
	/*	write_record: Untested	*/
	/*	append_record: Untested	*/
	/*	update_record: Untested	*/
	jacartapki_ops.select_file = jacartapki_select_file;
	/*	get_response: Untested	*/
	/*	get_challenge: ISO7816 implementation works	*/
	jacartapki_ops.logout = jacartapki_logout;
	/*	restore_security_env	*/
	jacartapki_ops.set_security_env = jacartapki_set_security_env;
	jacartapki_ops.decipher = jacartapki_decipher;
	jacartapki_ops.compute_signature = jacartapki_compute_signature;
	jacartapki_ops.create_file = jacartapki_create_file;
	jacartapki_ops.delete_file = jacartapki_delete_file;
	jacartapki_ops.list_files = jacartapki_list_files;
	jacartapki_ops.check_sw = jacartapki_check_sw;
	jacartapki_ops.card_ctl = jacartapki_card_ctl;
	jacartapki_ops.process_fci = jacartapki_process_fci;
	/*	construct_fci: Not needed	*/
	jacartapki_ops.pin_cmd = jacartapki_pin_cmd;
	/*	get_data: Not implemented	*/
	/*	put_data: Not implemented	*/
	/*	delete_record: Not implemented	*/

	/* jacartapki_ops.read_public_key = jacartapki_read_public_key	*/

	jacartapki_ops.card_reader_lock_obtained = jacartapki_card_reader_lock_obtained;

	return &jacartapki_drv;
}

struct sc_card_driver *
sc_get_jacartapki_driver(void)
{
	return sc_get_driver();
}

#endif /* ENABLE_OPENSSL */
