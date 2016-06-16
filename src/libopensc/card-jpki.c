/*
 * card-jpki.c: Support for JPKI(Japanese Individual Number Cards).
 *
 * Copyright (C) 2016, HAMANO Tsukasa <hamano@osstech.co.jp>
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
#include "jpki.h"

static struct sc_atr_table jpki_atrs[] = {
	{"3b:e0:00:ff:81:31:fe:45:14", NULL, NULL,
	 SC_CARD_TYPE_JPKI_BASE, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations jpki_ops;
static struct sc_card_driver jpki_drv = {
	"JPKI(Japanese Individual Number Cards)",
	"jpki",
	&jpki_ops,
	NULL, 0, NULL
};

int jpki_select_ap(struct sc_card *card)
{
	int rc;
	sc_path_t path;

	LOG_FUNC_CALLED(card->ctx);

	/* Select JPKI application */
	sc_format_path(AID_JPKI, &path);
	path.type = SC_PATH_TYPE_DF_NAME;
	rc = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, rc, "select JPKI AP failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_match_card(struct sc_card *card)
{
	int i, rc;

	i = _sc_match_atr(card, jpki_atrs, &card->type);
	if (i >= 0) {
		return 1;
	}

	rc = jpki_select_ap(card);
	if (rc == SC_SUCCESS) {
		card->type = SC_CARD_TYPE_JPKI_BASE;
		return 1;
	}
	return 0;
}

static int
jpki_finish(sc_card_t * card)
{
	struct jpki_private_data *drvdata = JPKI_DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);

	if (drvdata) {
		free(drvdata);
		card->drv_data = NULL;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_init(struct sc_card *card)
{
	struct jpki_private_data *drvdata;
	sc_file_t *mf;
	int flags;

	LOG_FUNC_CALLED(card->ctx);

	drvdata = malloc(sizeof (struct jpki_private_data));
	if (!drvdata)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	memset(drvdata, 0, sizeof (struct jpki_private_data));

	/* create virtual MF */
	mf = sc_file_new();
	if (!mf) {
		free(drvdata);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	sc_format_path("3f00", &mf->path);
	mf->type = SC_FILE_TYPE_DF;
	mf->shareable = 0;
	mf->ef_structure = SC_FILE_EF_UNKNOWN;
	mf->size = 0;
	mf->id = 0x3f00;
	mf->status = SC_FILE_STATUS_ACTIVATED;
	sc_file_add_acl_entry(mf, SC_AC_OP_SELECT, SC_AC_NONE, 0);
	sc_file_add_acl_entry(mf, SC_AC_OP_LIST_FILES, SC_AC_NONE, 0);
	sc_file_add_acl_entry(mf, SC_AC_OP_LOCK, SC_AC_NEVER, 0);
	sc_file_add_acl_entry(mf, SC_AC_OP_DELETE, SC_AC_NEVER, 0);
	sc_file_add_acl_entry(mf, SC_AC_OP_CREATE, SC_AC_NEVER, 0);
	drvdata->mf = mf;
	drvdata->selected = SELECT_MF;

	card->name = "jpki";
	card->drv_data = drvdata;

	flags = SC_ALGORITHM_RSA_HASH_NONE | SC_ALGORITHM_RSA_PAD_PKCS1;
	_sc_card_add_rsa_alg(card, 2048, flags, 0);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_select_file(struct sc_card *card,
		 const struct sc_path *path, struct sc_file **file_out)
{
	struct jpki_private_data *drvdata = JPKI_DRVDATA(card);
	int rc;
	sc_apdu_t apdu;
	struct sc_file *file = NULL;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "jpki_select_file: path=%s, len=%d",
			sc_print_path(path), path->len);
	if (path->len == 2 && memcmp(path->value, "\x3F\x00", 2) == 0) {
		drvdata->selected = SELECT_MF;
		if (file_out) {
			sc_file_dup(file_out, drvdata->mf);
			if (*file_out == NULL) {
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			}
		}
		return 0;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
	switch (path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 2;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0x0C;
	apdu.data = path->value;
	apdu.datalen = path->len;
	apdu.lc = path->len;

	rc = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rc, "APDU transmit failed");
	rc = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rc, "SW Check failed");
	if (!file_out) {
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}

	/* read size of auth certificate file */
	if (path->len == 2 && memcmp(path->value, "\x00\x0a", 2) == 0) {
		u8 buf[4];
		rc = sc_read_binary(card, 0, buf, 4, 0);
		LOG_TEST_RET(card->ctx, rc, "SW Check failed");
		file = sc_file_new();
		if (!file) {
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
		}
		file->path = *path;
		file->size = (buf[2] << 8 | buf[3]) + 4;
		*file_out = file;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_read_binary(sc_card_t * card, unsigned int idx,
		 u8 * buf, size_t count, unsigned long flags)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	const struct sc_card_operations *iso_ops = iso_drv->ops;
	int rc;

	LOG_FUNC_CALLED(card->ctx);

	rc = iso_ops->read_binary(card, idx, buf, count, flags);
	LOG_FUNC_RETURN(card->ctx, rc);
}

static int
jpki_pin_cmd(sc_card_t * card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int rc;
	sc_path_t path;
	sc_apdu_t apdu;

	LOG_FUNC_CALLED(card->ctx);

	if (tries_left) {
		*tries_left = -1;
	}

	switch (data->pin_reference) {
	case 1:
		sc_format_path(JPKI_AUTH_PIN, &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rc = sc_select_file(card, &path, NULL);
		break;
	case 2:
		sc_format_path(JPKI_SIGN_PIN, &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rc = sc_select_file(card, &path, NULL);
		break;
	default:
		sc_log(card->ctx, "Unknown PIN reference: %d", data->pin_reference);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	LOG_TEST_RET(card->ctx, rc, "SELECT_FILE error");

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0x20, 0x00, 0x80);
		apdu.data = data->pin1.data;
		apdu.datalen = data->pin1.len;
		apdu.lc = data->pin1.len;
		rc = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, rc, "APDU transmit failed");
		rc = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, rc, "VERIFY failed");
		break;
	case SC_PIN_CMD_GET_INFO:
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, 0x80);
		rc = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, rc, "APDU transmit failed");
		if (apdu.sw1 != 0x63) {
			sc_log(card->ctx, "VERIFY GET_INFO error");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_CARD_CMD_FAILED);
		}
		if (tries_left) {
			*tries_left = apdu.sw2 - 0xC0;
		}
		break;
	default:
		sc_log(card->ctx, "Card does not support PIN command: %d", data->cmd);
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_set_security_env(sc_card_t * card,
		const sc_security_env_t * env, int se_num)
{
	int rc;
	sc_path_t path;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
		"flags=%08x op=%d alg=%d algf=%08x algr=%08x kr0=%02x, krfl=%d",
		env->flags, env->operation, env->algorithm,
		env->algorithm_flags, env->algorithm_ref, env->key_ref[0],
		env->key_ref_len);

	switch (env->operation) {
	case SC_SEC_OPERATION_SIGN:
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}

	switch (env->key_ref[0]) {
	case 1:
		sc_format_path(JPKI_AUTH_KEY, &path);
		break;
	case 2:
		sc_format_path(JPKI_SIGN_KEY, &path);
		break;
	default:
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	path.type = SC_PATH_TYPE_FILE_ID;
	rc = sc_select_file(card, &path, NULL);
	LOG_TEST_RET(card->ctx, rc, "select key failed");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int
jpki_compute_signature(sc_card_t * card,
		const u8 * data, size_t datalen, u8 * out, size_t outlen)
{
	int rc;
	sc_apdu_t apdu;
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x00, 0x80);
	apdu.cla = 0x80;
	apdu.data = data;
	apdu.datalen = datalen;
	apdu.lc = datalen;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = 0;
	rc = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rc, "APDU transmit failed");
	rc = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rc, "SW Check failed");
	if (apdu.resplen > outlen) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(out, resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}

static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	jpki_ops = *iso_drv->ops;
	jpki_ops.match_card = jpki_match_card;
	jpki_ops.init = jpki_init;
	jpki_ops.finish = jpki_finish;
	jpki_ops.select_file = jpki_select_file;
	jpki_ops.read_binary = jpki_read_binary;
	jpki_ops.pin_cmd = jpki_pin_cmd;
	jpki_ops.set_security_env = jpki_set_security_env;
	jpki_ops.compute_signature = jpki_compute_signature;

	return &jpki_drv;
}

struct sc_card_driver *
sc_get_jpki_driver(void)
{
	return sc_get_driver();
}
