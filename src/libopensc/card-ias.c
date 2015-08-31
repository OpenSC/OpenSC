/*
 * Driver for IAS based cards, e.g. Portugal's eID card.
 *
 * Copyright (C) 2009, Joao Poupino <joao.poupino@ist.utl.pt>
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
 * Partially based on the ISO7816 driver.
 *
 * Thanks to Andre Cruz, Jorge Ferreira and Paulo F. Andrade
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"

#define DRVDATA(card)	((struct ias_priv_data *) ((card)->drv_data))

static struct sc_card_operations ias_ops;
static struct sc_card_operations *iso_ops = NULL;

static struct sc_card_driver ias_drv = {
		"IAS",
		"ias",
		&ias_ops,
		NULL, 0, NULL
};

/* Known ATRs */
static struct sc_atr_table ias_atrs[] = {
	/* Portugal eID cards */
	{"3B:65:00:00:D0:00:54:01:31", NULL, NULL, SC_CARD_TYPE_IAS_PTEID, 0, NULL},
	{"3B:65:00:00:D0:00:54:01:32", NULL, NULL, SC_CARD_TYPE_IAS_PTEID, 0, NULL},
	{"3B:95:95:40:FF:D0:00:54:01:31", NULL, NULL, SC_CARD_TYPE_IAS_PTEID, 0, NULL},
	{"3B:95:95:40:FF:D0:00:54:01:32", NULL, NULL, SC_CARD_TYPE_IAS_PTEID, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

/* Known AIDs */
static const u8 ias_aid_pteid[] = {0x60, 0x46, 0x32, 0xFF, 0x00, 0x01, 0x02};

static int ias_select_applet(sc_card_t *card, const u8 *aid, size_t aid_len)
{
	int 		r;
	sc_path_t 	tpath;

	memset(&tpath, 0, sizeof(sc_path_t));

	tpath.type = SC_PATH_TYPE_DF_NAME;
	tpath.len = aid_len;
	memcpy(tpath.value, aid, aid_len);
	r = iso_ops->select_file(card, &tpath, NULL);
	if (r != SC_SUCCESS) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "unable to select applet");
		return r;
	}

	return SC_SUCCESS;
}

static int ias_init(sc_card_t *card)
{
	unsigned long flags;

	assert(card != NULL);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	card->name = "IAS";
	card->cla = 0x00;

	/* Card version detection */
	if (card->type == SC_CARD_TYPE_IAS_PTEID) {
		int r = ias_select_applet(card, ias_aid_pteid, sizeof(ias_aid_pteid));
		if (r != SC_SUCCESS)
			return r;
	/* Add other cards if necessary */
	} else {
		return SC_ERROR_INTERNAL;
	}

	/* Set card capabilities */
	card->caps |= SC_CARD_CAP_RNG;

	/* Set the supported algorithms */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 |
			SC_ALGORITHM_RSA_HASH_NONE;

    /* Only 1024 bit key sizes were tested */
     _sc_card_add_rsa_alg(card, 1024, flags, 0);

	return SC_SUCCESS;
}

static int ias_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, ias_atrs, &card->type);
	if (i < 0)
		return 0;

	return 1;
}

static int ias_build_pin_apdu(sc_card_t *card,
		sc_apdu_t *apdu,
		struct sc_pin_cmd_data *data)
{
	static u8 	sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int 		r, len, pad, use_pin_pad, ins, p1;

	len = pad = use_pin_pad = p1 = 0;
	assert(card != NULL);

	switch (data->pin_type) {
	case SC_AC_CHV:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (data->flags & SC_PIN_CMD_USE_PINPAD)
		use_pin_pad = 1;
	/* "needs-padding" necessary for the PTEID card,
	 * but not defined in the pin structure
	 */
	if ((data->flags & SC_PIN_CMD_NEED_PADDING) ||
		 card->type == SC_CARD_TYPE_IAS_PTEID)
		pad = 1;

	data->pin1.offset = 5;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		ins = 0x20;
		if ( (r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
			return r;
		len = r;
		break;
	case SC_PIN_CMD_CHANGE:
		ins = 0x24;
		if ((data->flags & SC_PIN_CMD_IMPLICIT_CHANGE) == 0 &&
			(data->pin1.len != 0 || use_pin_pad)) {
			if ( (r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			/* implicit test */
			p1 = 1;
		}
		data->pin2.offset = data->pin1.offset + len;
		if ( (r = sc_build_pin(sbuf+len, sizeof(sbuf)-len, &data->pin2, pad)) < 0)
			return r;
		len += r;
		break;
	case SC_PIN_CMD_UNBLOCK:
		ins = 0x2C;
		if (data->pin1.len != 0 || use_pin_pad) {
			if ( (r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x02;
		}
		if (data->pin2.len != 0 || use_pin_pad) {
			data->pin2.offset = data->pin1.offset + len;
			if ( (r = sc_build_pin(sbuf+len, sizeof(sbuf)-len, &data->pin2, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x01;
		}
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, ins, p1, data->pin_reference);
	apdu->lc = len;
	apdu->datalen = len;
	apdu->data = sbuf;
	apdu->resplen = 0;

	return SC_SUCCESS;
}

static int ias_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data,
		int *tries_left)
{
	int 		r;
	sc_apdu_t 	local_apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* Check if a PIN change operation is being requested,
	 * as it requires sending two separate APDUs
	 */
	if (data->cmd == SC_PIN_CMD_CHANGE) {
		/* Build a SC_PIN_CMD_VERIFY APDU */
		data->cmd = SC_PIN_CMD_VERIFY;
		r = ias_build_pin_apdu(card, &local_apdu, data);
		if (r < 0)
			return r;
		data->apdu = &local_apdu;
		r = iso_ops->pin_cmd(card, data, tries_left);
		if (r < 0)
			return r;
		/* Continue processing */
		data->cmd = SC_PIN_CMD_CHANGE;
		/* The IAS spec mandates an implicit change PIN operation */
		data->flags |= SC_PIN_CMD_IMPLICIT_CHANGE;
	}

	r = ias_build_pin_apdu(card, &local_apdu, data);
	if (r < 0)
		return r;
	data->apdu = &local_apdu;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int ias_set_security_env(sc_card_t *card,
		const sc_security_env_t *env, int se_num)
{
	int 		r;
	sc_apdu_t 	apdu;
	u8 			sbuf[SC_MAX_APDU_BUFFER_SIZE];

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "ias_set_security_env, keyRef = 0x%0x, algo = 0x%0x\n",
			*env->key_ref, env->algorithm_flags);

	assert(card != NULL && env != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8; /* confidentiality template */
		sbuf[0] = 0x95;	/* tag for usage qualifier byte */
		sbuf[1] = 0x01;	/* tag length */
		sbuf[2] = 0x40; /* data decryption */
		sbuf[3] = 0x84; /* tag for private key reference */
		sbuf[4] = 0x01; /* tag length */
		sbuf[5] = *env->key_ref;	/* key reference */
		sbuf[6] = 0x80; /* tag for algorithm reference */
		sbuf[7] = 0x01; /* tag length */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			sbuf[8] = 0x1A; /* RSA PKCS#1 with no data formatting */
		else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Set Sec Env: unsupported algo 0X%0X\n",
					env->algorithm_flags);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		apdu.lc = 9;
		apdu.datalen = 9;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xA4; /* authentication template */
		sbuf[0] = 0x95;	/* tag for usage qualifier byte */
		sbuf[1] = 0x01;	/* tag length */
		sbuf[2] = 0x40; /* internal authentication */
		sbuf[3] = 0x84; /* tag for private key reference */
		sbuf[4] = 0x01; /* tag length */
		sbuf[5] = *env->key_ref;	/* key reference */
		sbuf[6] = 0x80; /* tag for algorithm reference */
		sbuf[7] = 0x01; /* tag length */
		if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			sbuf[8] = 0x02; /* RSA PKCS#1 with no data formatting */
		else {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Set Sec Env: unsupported algo 0X%0X\n",
					env->algorithm_flags);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		apdu.lc = 9;
		apdu.datalen = 9;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	apdu.data = sbuf;
	apdu.resplen = 0;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Set Security Env APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Card's Set Security Env command returned error");

	return r;
}
 
static int ias_compute_signature(sc_card_t *card, const u8 *data,
		size_t data_len, u8 *out, size_t outlen)
{
	sc_apdu_t	apdu;
	size_t		len;
	/*
	** XXX: Ensure sufficient space exists for the card's response
	** as the caller's buffer size may not be sufficient
	*/
	u8		rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_context_t	*ctx = card->ctx;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	if (data_len > 64) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "error: input data too long: %lu bytes\n", data_len);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x02, 0x00);
	apdu.data = (u8 *) data;
	apdu.lc = data_len;
	apdu.datalen = data_len;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 256;

	LOG_TEST_RET(card->ctx, sc_transmit_apdu(card, &apdu), "APDU transmit failed");
	LOG_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2), "INTERNAL AUTHENTICATE failed");

	len = apdu.resplen > outlen ? outlen : apdu.resplen;
	memcpy(out, apdu.resp, len);
	
	LOG_FUNC_RETURN(card->ctx, apdu.resplen);
}

static int ias_select_file(sc_card_t *card, const sc_path_t *in_path,
		sc_file_t **file_out)
{
	int 			r, pathlen, stripped_len;
	u8 				buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 				pathbuf[SC_MAX_PATH_SIZE], *path;
	sc_apdu_t 		apdu;
	sc_file_t 		*file;

	stripped_len = 0;
	path = pathbuf;
	file = NULL;

	assert(card != NULL && in_path != NULL);

	if (in_path->len > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	apdu.p2 = 0; /* First record, return FCI */

	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 2;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
		apdu.p1 = 9;
		/* Strip the MF */
		if (pathlen >= 2 && memcmp(path, "\x3f\x00", 2) == 0) {
			if (pathlen == 2) { /* Only 3f00 provided */
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		/* Optimization based on the normal Portuguese eID usage pattern:
		 * paths with len >= 4 shall be stripped - this avoids unnecessary
		 * "file not found" errors. Other cards may benefit from this also.
		 *
		 * This works perfectly for the Portuguese eID card, but if you
		 * are adapting this driver to another card, "false positives" may
		 * occur depending, of course, on the file structure of the card.
		 *
		 * Please have this in mind if adapting this driver to another card.
		 */
		if (pathlen >= 4) {
			stripped_len = pathlen - 2;
			path += stripped_len;
			pathlen = 2;
		} else if (pathlen == 2) {
			apdu.p1 = 0;
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		apdu.p2 = 0x0C;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}

	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
	} else {
		apdu.p2 = 0x0C;
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, 0);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	/* A "file not found" error was received, this can mean two things:
	 * 1) the file does not exist
	 * 2) the current DF may be incorrect due to the optimization applied
	 *    earlier. If the path was previously stripped, select the first DF
	 *    and try to re-select the path with the full value.
	 */
	if (stripped_len > 0 && apdu.sw1 == 0x6A && apdu.sw2 == 0x82) {
		sc_path_t tpath;

		/* Restore original path value */
		path -= stripped_len;
		pathlen += stripped_len;

		memset(&tpath, 0, sizeof(sc_path_t));
		tpath.type = SC_PATH_TYPE_PATH;
		tpath.len = 2;
		tpath.value[0] = path[0];
		tpath.value[1] = path[1];

		/* Go up in the hierarchy to the correct DF */
		r = ias_select_file(card, &tpath, NULL);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Error selecting parent.");

		/* We're now in the right place, reconstruct the APDU and retry */
		path += 2;
		pathlen -= 2;
		apdu.lc = pathlen;
		apdu.data = path;
		apdu.datalen = pathlen;

		if (file_out != NULL)
			apdu.resplen = sizeof(buf);

		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
		if (file_out == NULL) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
		}
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);

	if (apdu.resplen < 2)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	switch (apdu.resp[0]) {
	case 0x6F:
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_SUPPORTED);
		}
		if ((size_t)apdu.resp[1] + 2 <= apdu.resplen)
			card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
		*file_out = file;
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	default:
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	return SC_SUCCESS;
}

static struct sc_card_driver *sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (iso_ops == NULL)
		iso_ops = iso_drv->ops;
	/* Use the standard iso operations as default */
	ias_ops = *iso_drv->ops;
	/* IAS specific functions */
	ias_ops.select_file = ias_select_file;
	ias_ops.match_card = ias_match_card;
	ias_ops.init = ias_init;
	ias_ops.set_security_env = ias_set_security_env;
	ias_ops.compute_signature = ias_compute_signature;
	ias_ops.pin_cmd = ias_pin_cmd;

	return &ias_drv;
}

struct sc_card_driver *sc_get_ias_driver(void)
{
	return sc_get_driver();
}
