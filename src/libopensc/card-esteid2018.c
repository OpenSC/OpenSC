/*
 * Driver for EstEID card issued from December 2018.
 *
 * Copyright (C) 2019, Martin Paljak <martin@martinpaljak.net>
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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "asn1.h"
#include "gp.h"
#include "internal.h"

/* Helping defines */
#define SIGNATURE_PAYLOAD_SIZE 0x30
#define PIN1_REF 0x01
#define PIN2_REF 0x85
#define PUK_REF 0x02

static const struct sc_atr_table esteid_atrs[] = {
    {"3b:db:96:00:80:b1:fe:45:1f:83:00:12:23:3f:53:65:49:44:0f:90:00:f1", NULL, "EstEID 2018", SC_CARD_TYPE_ESTEID_2018, 0, NULL},
    {NULL, NULL, NULL, 0, 0, NULL}};

static const struct sc_aid IASECC_AID = {{0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
                                         16};

static const struct sc_path adf2 = {{0x3f, 0x00, 0xAD, 0xF2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 4, 0, 0, SC_PATH_TYPE_PATH, {{0}, 0}};

static const struct sc_card_operations *iso_ops = NULL;
static struct sc_card_operations esteid_ops;

static struct sc_card_driver esteid2018_driver = {"EstEID 2018", "esteid2018", &esteid_ops, NULL, 0, NULL};

struct esteid_priv_data {
	sc_security_env_t sec_env; /* current security environment */
};

#define DRVDATA(card) ((struct esteid_priv_data *)((card)->drv_data))

#define SC_TRANSMIT_TEST_RET(card, apdu, text)                                                                                                      \
	do {                                                                                                                               \
		LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");                                            \
		LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), text);                                                      \
	} while (0)

static int esteid_match_card(sc_card_t *card) {
	int i = _sc_match_atr(card, esteid_atrs, &card->type);

	if (i >= 0 && gp_select_aid(card, &IASECC_AID) == SC_SUCCESS) {
		card->name = esteid_atrs[i].name;
		return 1;
	}
	return 0;
}

static int esteid_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2) {
	if (sw1 == 0x6B && sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_FILE_END_REACHED);
	return iso_ops->check_sw(card, sw1, sw2);
}

static int esteid_select(struct sc_card *card, unsigned char p1, unsigned char id1, unsigned char id2) {
	struct sc_apdu apdu;
	unsigned char sbuf[2];

	LOG_FUNC_CALLED(card->ctx);

	// Select EF/DF
	sbuf[0] = id1;
	sbuf[1] = id2;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xA4, p1, 0x0C);
	if (id1 != 0x3F && id2 != 0x00) {
		apdu.cse = SC_APDU_CASE_3_SHORT;
		apdu.lc = 2;
		apdu.data = sbuf;
		apdu.datalen = 2;
	}
	apdu.le = 0;
	apdu.resplen = 0;

	SC_TRANSMIT_TEST_RET(card, apdu, "SELECT failed");
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int esteid_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out) {
	unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	size_t pathlen;
	struct sc_file *file = NULL;

	LOG_FUNC_CALLED(card->ctx);

	// Only support full paths
	if (in_path->type != SC_PATH_TYPE_PATH) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	while (pathlen >= 2) {
		if (memcmp(path, "\x3F\x00", 2) == 0) {
			LOG_TEST_RET(card->ctx, esteid_select(card, 0x00, 0x3F, 0x00), "MF select failed");
		} else if (path[0] == 0xAD) {
			LOG_TEST_RET(card->ctx, esteid_select(card, 0x01, path[0], path[1]), "DF select failed");
		} else if (pathlen == 2) {
			LOG_TEST_RET(card->ctx, esteid_select(card, 0x02, path[0], path[1]), "EF select failed");

			if (file_out != NULL) // Just make a dummy file
			{
				file = sc_file_new();
				if (file == NULL)
					LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
				file->path = *in_path;
				file->size = 1536; // Dummy size, to be above 1024

				*file_out = file;
			}
		}
		path += 2;
		pathlen -= 2;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

// temporary hack, overload 6B00 SW processing
static int esteid_read_binary(struct sc_card *card, unsigned int idx, u8 *buf, size_t count, unsigned long flags) {
	int r;
	int (*saved)(struct sc_card *, unsigned int, unsigned int) = card->ops->check_sw;
	LOG_FUNC_CALLED(card->ctx);
	card->ops->check_sw = esteid_check_sw;
	r = iso_ops->read_binary(card, idx, buf, count, flags);
	card->ops->check_sw = saved;
	LOG_FUNC_RETURN(card->ctx, r);
}

static int esteid_set_security_env(sc_card_t *card, const sc_security_env_t *env, int se_num) {
	struct esteid_priv_data *priv;
	struct sc_apdu apdu;

	// XXX: could be const
	unsigned char cse_crt_aut[] = {0x80, 0x04, 0xFF, 0x20, 0x08, 0x00, 0x84, 0x01, 0x81};
	unsigned char cse_crt_sig[] = {0x80, 0x04, 0xFF, 0x15, 0x08, 0x00, 0x84, 0x01, 0x9F};
	unsigned char cse_crt_dec[] = {0x80, 0x04, 0xFF, 0x30, 0x04, 0x00, 0x84, 0x01, 0x81};

	LOG_FUNC_CALLED(card->ctx);

	if (card == NULL || env == NULL || env->key_ref_len != 1)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);

	sc_log(card->ctx, "algo: %d operation: %d keyref: %d", env->algorithm, env->operation, env->key_ref[0]);

	if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_SIGN && env->key_ref[0] == 1) {
		sc_format_apdu_ex(card, &apdu, 0x22, 0x41, 0xA4, cse_crt_aut, sizeof(cse_crt_aut), NULL, 0);
	} else if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_SIGN && env->key_ref[0] == 2) {
		sc_format_apdu_ex(card, &apdu, 0x22, 0x41, 0xB6, cse_crt_sig, sizeof(cse_crt_sig), NULL, 0);
	} else if (env->algorithm == SC_ALGORITHM_EC && env->operation == SC_SEC_OPERATION_DERIVE && env->key_ref[0] == 1) {
		sc_format_apdu_ex(card, &apdu, 0x22, 0x41, 0xB8, cse_crt_dec, sizeof(cse_crt_dec), NULL, 0);
	} else {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	}
	SC_TRANSMIT_TEST_RET(card, apdu, "SET SECURITY ENV failed");

	priv = DRVDATA(card);
	priv->sec_env = *env;
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int esteid_compute_signature(sc_card_t *card, const u8 *data, size_t datalen, u8 *out, size_t outlen) {
	struct esteid_priv_data *priv = DRVDATA(card);
	struct sc_security_env *env = NULL;
	struct sc_apdu apdu;
	u8 sbuf[SIGNATURE_PAYLOAD_SIZE];
	int le = MIN(SC_MAX_APDU_RESP_SIZE, MIN(SIGNATURE_PAYLOAD_SIZE * 2, outlen));

	LOG_FUNC_CALLED(card->ctx);
	if (data == NULL || out == NULL || datalen > SIGNATURE_PAYLOAD_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	env = &priv->sec_env;
	// left-pad if necessary
	memcpy(&sbuf[SIGNATURE_PAYLOAD_SIZE - datalen], data, MIN(datalen, SIGNATURE_PAYLOAD_SIZE));
	memset(sbuf, 0x00, SIGNATURE_PAYLOAD_SIZE - datalen);
	datalen = SIGNATURE_PAYLOAD_SIZE;

	switch (env->key_ref[0]) {
	case 1: /* authentication key */
		sc_format_apdu_ex(card, &apdu, 0x88, 0, 0, sbuf, datalen, out, le);
		break;
	default:
		sc_format_apdu_ex(card, &apdu, 0x2A, 0x9E, 0x9A, sbuf, datalen, out, le);
	}

	SC_TRANSMIT_TEST_RET(card, apdu, "PSO CDS/INTERNAL AUTHENTICATE failed");

	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

static int esteid_get_pin_remaining_tries(sc_card_t *card, int pin_reference) {
	unsigned char get_pin_info[] = {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, 0xFF, 0x02, 0xA0, 0x80};

	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_RESP_SIZE];
	LOG_FUNC_CALLED(card->ctx);

	// We don't get the file information here, so we need to be ugly
	if (pin_reference == PIN1_REF || pin_reference == PUK_REF) {
		LOG_TEST_RET(card->ctx, esteid_select(card, 0x00, 0x3F, 0x00), "Cannot select MF");
	} else if (pin_reference == PIN2_REF) {
		LOG_TEST_RET(card->ctx, esteid_select_file(card, &adf2, NULL), "Cannot select QSCD AID");
	} else {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	get_pin_info[6] = pin_reference & 0x0F; // mask out local/global
	sc_format_apdu_ex(card, &apdu, 0xCB, 0x3F, 0xFF, get_pin_info, sizeof(get_pin_info), apdu_resp, sizeof(apdu_resp));
	SC_TRANSMIT_TEST_RET(card, apdu, "GET DATA(pin info) failed");
	if (apdu.resplen < 32) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INTERNAL);
	}

	// XXX: sc_asn1_find_tag with the following payload (to get to tag 0x9B):
	// https://lapo.it/asn1js/#cB6_gQEaoBiaAQObAQOhEIwG8wAAc0MAnAbzAABzQwA
	return (int)apdu_resp[13];
}

static int esteid_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left) {
	int r;
	struct sc_pin_cmd_data tmp;
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "PIN CMD is %d", data->cmd);
	if (data->cmd == SC_PIN_CMD_GET_INFO) {
		sc_log(card->ctx, "SC_PIN_CMD_GET_INFO for %d", data->pin_reference);
		r = esteid_get_pin_remaining_tries(card, data->pin_reference);
		LOG_TEST_RET(card->ctx, r, "GET DATA(pin info) failed");

		data->pin1.tries_left = r;
		data->pin1.max_tries = -1; // "no support, which means the one set in PKCS#15 emulation sticks
		data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	} else if (data->cmd == SC_PIN_CMD_UNBLOCK) {
		// Verify PUK, then issue UNBLOCK
		// VERIFY
		memcpy(&tmp, data, sizeof(struct sc_pin_cmd_data));
		tmp.cmd = SC_PIN_CMD_VERIFY;
		tmp.pin_reference = PUK_REF;
		tmp.pin2.len = 0;
		r = iso_ops->pin_cmd(card, &tmp, tries_left);
		LOG_TEST_RET(card->ctx, r, "VERIFY during unblock failed");

		if (data->pin_reference == 0x85) {
			LOG_TEST_RET(card->ctx, esteid_select_file(card, &adf2, NULL), "Cannot select QSCD AID");
		}
		// UNBLOCK
		tmp = *data;
		tmp.cmd = SC_PIN_CMD_UNBLOCK;
		tmp.pin1.len = 0;
		r = iso_ops->pin_cmd(card, &tmp, tries_left);
		sc_mem_clear(&tmp, sizeof(tmp));
		LOG_FUNC_RETURN(card->ctx, r);
	}

	LOG_FUNC_RETURN(card->ctx, iso_ops->pin_cmd(card, data, tries_left));
}

static int esteid_init(sc_card_t *card) {
	unsigned long flags, ext_flags;
	struct esteid_priv_data *priv;

	priv = calloc(1, sizeof *priv);
	if (!priv)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	card->drv_data = priv;
	card->max_recv_size = 233; // XXX: empirical, not documented

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE;
	ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_UNCOMPRESES;

	_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int esteid_finish(sc_card_t *card) {
	if (card != NULL)
		free(DRVDATA(card));
	return 0;
}

struct sc_card_driver *sc_get_esteid2018_driver(void) {
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

	esteid_ops = *iso_drv->ops;
	esteid_ops.match_card = esteid_match_card;
	esteid_ops.init = esteid_init;
	esteid_ops.finish = esteid_finish;

	esteid_ops.select_file = esteid_select_file;
	esteid_ops.read_binary = esteid_read_binary;

	esteid_ops.set_security_env = esteid_set_security_env;
	esteid_ops.compute_signature = esteid_compute_signature;
	esteid_ops.pin_cmd = esteid_pin_cmd;

	return &esteid2018_driver;
}