/*
 * Support for the JCOP4 Cards with NQ-Applet
 *
 * Copyright (C) 2021 jozsefd <jozsef.dojcsak@gmail.com>
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

#include <stdlib.h>
#include <string.h>

#include "opensc.h"
#include "asn1.h"
#include "cardctl.h"
#include "internal.h"
#include "log.h"

#define APPLET_VERSION_LEN  2
#define APPLET_MEMTYPE_LEN  1
#define APPLET_SERIALNR_LEN 8

/* card constants */
static const struct sc_atr_table nqapplet_atrs[] = {
	{"3b:d5:18:ff:81:91:fe:1f:c3:80:73:c8:21:10:0a", NULL, NULL, SC_CARD_TYPE_NQ_APPLET, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}};

static const u8 nqapplet_aid[] = {0xd2, 0x76, 0x00, 0x01, 0x80, 0xBA, 0x01, 0x44, 0x02, 0x01, 0x00};

static struct sc_card_operations nqapplet_operations;
static struct sc_card_operations *iso_operations = NULL;

#define KEY_REFERENCE_NO_KEY   0x00
#define KEY_REFERENCE_AUTH_KEY 0x01
#define KEY_REFERENCE_ENCR_KEY 0x02

struct nqapplet_driver_data {
	u8 version_minor;
	u8 version_major;
	u8 key_reference;
};
typedef struct nqapplet_driver_data *nqapplet_driver_data_ptr;

static struct sc_card_driver nqapplet_driver = {
	"NQ-Applet",          // name
	"nqapplet",           // short name
	&nqapplet_operations, // operations
	NULL,                 // atr table
	0,                    // nr of atr
	NULL                  // dll?
};

static const struct sc_card_error nqapplet_errors[] = {
	{0x6700, SC_ERROR_WRONG_LENGTH, "Invalid LC or LE"},
	{0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied"}, // TODO MK/DK??
	{0x6985, SC_ERROR_NOT_ALLOWED, "Invalid PIN or key"},
	{0x6986, SC_ERROR_NOT_ALLOWED, "Conditions of use not satisfied"},
	{0x6A80, SC_ERROR_INVALID_ARGUMENTS, "Invalid parameters"},
	{0x6A82, SC_ERROR_OBJECT_NOT_FOUND, "Data object not found"},
	{0x6A84, SC_ERROR_NOT_ENOUGH_MEMORY, "Not enough memory"},
	{0x6A86, SC_ERROR_INCORRECT_PARAMETERS, "Invalid P1 or P2"},
	{0x6A88, SC_ERROR_INVALID_ARGUMENTS, "Wrong key ID"},
	{0x6D00, SC_ERROR_FILE_NOT_FOUND, "Applet not found"}};

/* convenience functions */

static int init_driver_data(sc_card_t *card, u8 version_major, u8 version_minor)
{
	nqapplet_driver_data_ptr data = calloc(1, sizeof(struct nqapplet_driver_data));
	if (data == NULL) {
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
	}

	data->version_major = version_major;
	data->version_minor = version_minor;
	data->key_reference = KEY_REFERENCE_NO_KEY;
	card->drv_data = (void *)data;
	return SC_SUCCESS;
}

/**
 * SELECT NQ-Applet, on success it returns the applet version and card serial nr.
 *
 * @param[in]     	card
 * @param[out,opt]  version_major	Version major of the applet
 * @param[out,opt]  version_minor	Version minor of the applet
 * @param[out,opt]  serial_nr		Buffer to receive serial number octets
 * @param[in]  		cb_serial_nr	Size of buffer in octets
 * @param[out,opt]	serial_nr_len	The actual number of octet copied into serial_nr buffer
 *
 * @return SC_SUCCESS: The applet is present and selected.
 *
 */
static int select_nqapplet(sc_card_t *card, u8 *version_major, u8 *version_minor, u8 *serial_nr,
                           size_t cb_serial_nr, size_t *serial_nr_len)
{
	int rv;
	sc_context_t *ctx = card->ctx;
	sc_apdu_t apdu;
	u8 buffer[APPLET_VERSION_LEN + APPLET_MEMTYPE_LEN + APPLET_SERIALNR_LEN + 2];
	size_t cb_buffer = sizeof(buffer);
	size_t cb_aid = sizeof(nqapplet_aid);

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu_ex(&apdu, 0x00, 0xA4, 0x04, 0x00, nqapplet_aid, cb_aid, buffer, cb_buffer);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failure.");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Card returned error");

	if (apdu.resplen < APPLET_VERSION_LEN + APPLET_MEMTYPE_LEN + APPLET_SERIALNR_LEN) {
		SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_WRONG_LENGTH);
	}

	if (version_major != NULL) {
		*version_major = buffer[0];
	}
	if (version_minor != NULL) {
		*version_minor = buffer[1];
	}
	if (serial_nr != NULL && cb_serial_nr > 0 && serial_nr_len != NULL) {
		size_t cb = MIN(APPLET_SERIALNR_LEN, cb_serial_nr);
		memcpy(serial_nr, buffer + 3, cb);
		*serial_nr_len = cb;
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/* driver operations API */
static int nqapplet_match_card(struct sc_card *card)
{
	int rv = _sc_match_atr(card, nqapplet_atrs, &card->type);
	return (rv >= 0);
}

static int nqapplet_init(struct sc_card *card)
{
	u8 version_major;
	u8 version_minor;
	u8 serial_nr[APPLET_SERIALNR_LEN];
	size_t cb_serial_nr = sizeof(serial_nr);
	unsigned long rsa_flags = 0;

	LOG_FUNC_CALLED(card->ctx);
	int rv =
		select_nqapplet(card, &version_major, &version_minor, serial_nr, cb_serial_nr, &cb_serial_nr);
	if (rv != SC_SUCCESS) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_CARD, "Cannot select NQ-Applet.");
	}

	rv = init_driver_data(card, version_major, version_minor);
	LOG_TEST_RET(card->ctx, rv, "Failed to initialize driver data.");

	card->max_send_size = 255;
	card->max_recv_size = 256;
	card->caps |= SC_CARD_CAP_RNG | SC_CARD_CAP_ISO7816_PIN_INFO;
	rsa_flags |= SC_ALGORITHM_RSA_RAW;
	_sc_card_add_rsa_alg(card, 3072, rsa_flags, 0);

	card->serialnr.len = MIN(sizeof(card->serialnr.value), cb_serial_nr);
	memcpy(card->serialnr.value, serial_nr, card->serialnr.len);

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int nqapplet_finish(struct sc_card *card)
{
	nqapplet_driver_data_ptr data = (nqapplet_driver_data_ptr)card->drv_data;

	LOG_FUNC_CALLED(card->ctx);
	if (data != NULL) {
		free(data);
		card->drv_data = NULL;
	}
	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int nqapplet_get_response(struct sc_card *card, size_t *cb_resp, u8 *resp)
{
	struct sc_apdu apdu;
	int rv;
	size_t resplen;

	LOG_FUNC_CALLED(card->ctx);
	resplen = MIN(sc_get_max_recv_size(card), *cb_resp);

	sc_format_apdu_ex(&apdu, 0x80, 0xC0, 0x00, 0x00, NULL, 0, resp, resplen);
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	if (apdu.resplen == 0) {
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	*cb_resp = apdu.resplen;

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		rv = SC_SUCCESS;
	} else if (apdu.sw1 == 0x61) {
		rv = apdu.sw2 == 0 ? 256 : apdu.sw2;
	} else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82) {
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int nqapplet_get_challenge(struct sc_card *card, u8 *buf, size_t count)
{
	int r;
	struct sc_apdu apdu;

	LOG_FUNC_CALLED(card->ctx);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x84, 0x00, 0x00);
	apdu.le = count;
	apdu.resp = buf;
	apdu.resplen = count;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE failed");

	if (count < apdu.resplen) {
		return (int)count;
	}

	return (int)apdu.resplen;
}

static int nqapplet_logout(struct sc_card *card)
{
	LOG_FUNC_CALLED(card->ctx);
	/* selecting NQ-Applet again will reset the applet status and unauthorize PINs */
	int rv = select_nqapplet(card, NULL, NULL, NULL, 0, NULL);
	if (rv != SC_SUCCESS) {
		LOG_TEST_RET(card->ctx, rv, "Failed to logout");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

int nqapplet_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num)
{
	/* Note: the NQ-Applet does not have APDU for SET SECURITY ENV,
	this function checks the intended parameters and sets card_data.key_reference */
	nqapplet_driver_data_ptr data;
	u8 key_reference = KEY_REFERENCE_NO_KEY;

	LOG_FUNC_CALLED(card->ctx);

	data = (nqapplet_driver_data_ptr)card->drv_data;
	data->key_reference = KEY_REFERENCE_NO_KEY;

	if (se_num != 0) {
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED,
		             "Storing of security environment is not supported");
	}
	if (env->key_ref_len == 1) {
		key_reference = env->key_ref[0];
	}

	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		if (key_reference != KEY_REFERENCE_AUTH_KEY && key_reference != KEY_REFERENCE_ENCR_KEY) {
			LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
			             "Decipher operation is only supported with AUTH and ENCR keys.");
		}
		data->key_reference = key_reference;
		break;
	case SC_SEC_OPERATION_SIGN:
		if (key_reference != KEY_REFERENCE_AUTH_KEY) {
			LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
			             "Sign operation is only supported with AUTH key.");
		}
		data->key_reference = key_reference;
		break;
	default:
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported sec. operation.");
	}

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int nqapplet_decipher(struct sc_card *card, const u8 *data, size_t cb_data, u8 *out, size_t outlen)
{
	int rv;
	struct sc_apdu apdu;
	u8 p1 = 0x80;
	u8 p2 = 0x86;
	nqapplet_driver_data_ptr drv_data;

	LOG_FUNC_CALLED(card->ctx);

	drv_data = (nqapplet_driver_data_ptr)card->drv_data;

	if (drv_data->key_reference == KEY_REFERENCE_AUTH_KEY) {
		p1 = 0x9E;
		p2 = 0x9A;
	} else if (drv_data->key_reference != KEY_REFERENCE_ENCR_KEY) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
		             "Decipher operation is only supported with AUTH and ENCR keys.");
	}

	/* the applet supports only 3072 RAW RSA, input buffer size must be 384 octets,
	output buffer size must be at least 384 octets */
	sc_format_apdu_ex(&apdu, 0x80, 0x2A, p1, p2, data, cb_data, out, outlen);
	apdu.le = 256;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		rv = (int)apdu.resplen;
	} else if (apdu.sw1 == 0x61) {
		rv = apdu.sw2 == 0 ? 256 : apdu.sw2;
	} else {
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int nqapplet_compute_signature(struct sc_card *card, const u8 *data, size_t cb_data, u8 *out,
                                      size_t outlen)
{
	int rv;
	struct sc_apdu apdu;
	nqapplet_driver_data_ptr drv_data;

	LOG_FUNC_CALLED(card->ctx);
	drv_data = (nqapplet_driver_data_ptr)card->drv_data;

	if (drv_data->key_reference != KEY_REFERENCE_AUTH_KEY) {
		LOG_TEST_RET(card->ctx, SC_ERROR_INCOMPATIBLE_KEY,
		             "Sign operation is only supported with AUTH key.");
	}

	/* the applet supports only 3072 RAW RSA, input buffer size must be 384 octets,
	output buffer size must be at least 384 octets */
	sc_format_apdu_ex(&apdu, 0x80, 0x2A, 0x9E, 0x9A, data, cb_data, out, outlen);
	apdu.le = 256;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		rv = (int)apdu.resplen;
	} else if (apdu.sw1 == 0x61) {
		rv = apdu.sw2 == 0 ? 256 : apdu.sw2;
	} else {
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int nqapplet_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	const int nqapplet_error_count = sizeof(nqapplet_errors) / sizeof(struct sc_card_error);
	int i;

	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx, "Checking sw1 = 0x%02x, sw2 = 0x%02x\n", sw1, sw2);

	for (i = 0; i < nqapplet_error_count; i++) {
		if (nqapplet_errors[i].SWs == ((sw1 << 8) | sw2)) {
			LOG_TEST_RET(card->ctx, nqapplet_errors[i].errorno, nqapplet_errors[i].errorstr);
		}
	}

	return iso_operations->check_sw(card, sw1, sw2);
}

static int nqapplet_get_data(struct sc_card *card, unsigned int id, u8 *resp, size_t cb_resp)
{
	struct sc_apdu apdu;
	int rv;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu_ex(&apdu, 0x80, 0xB0, 0x00, (u8)id, NULL, 0, resp, cb_resp);
	apdu.le = 256;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		rv = (int)apdu.resplen;
	} else if (apdu.sw1 == 0x61) {
		rv = apdu.sw2 == 0 ? 256 : apdu.sw2;
	} else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82) {
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	}

	LOG_FUNC_RETURN(card->ctx, rv);
}

static int nqapplet_select_file(struct sc_card *card, const struct sc_path *in_path,
                                struct sc_file **file_out)
{
	LOG_FUNC_CALLED(card->ctx);

	/* the applet does not support SELECT EF/DF except for SELECT APPLET.
	In order to enable opensc-explorer add support for virtually selecting MF only */
	if (in_path->type == SC_PATH_TYPE_PATH && in_path->len == 2 &&
	    memcmp(in_path->value, "\x3F\x00", 2) == 0) {
		if (file_out != NULL) {
			struct sc_file *file = sc_file_new();
			if (file == NULL) {
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);
			}
			file->path = *in_path;
			*file_out = file;
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		}
	}
	// TODO allow selecting Applet AID

	LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
}

static int nqapplet_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		if (card->serialnr.len) {
			sc_serial_number_t *serial = (sc_serial_number_t *)ptr;
			memcpy(serial->value, card->serialnr.value, card->serialnr.len);
			serial->len = card->serialnr.len;
			return SC_SUCCESS;
		}
		break;
	}
	return SC_ERROR_NOT_SUPPORTED;
}

struct sc_card_driver *sc_get_nqApplet_driver(void)
{
	sc_card_driver_t *iso_driver = sc_get_iso7816_driver();

	if (iso_operations == NULL) {
		iso_operations = iso_driver->ops;
	}

	nqapplet_operations = *iso_driver->ops;

	/* supported operations */
	nqapplet_operations.match_card = nqapplet_match_card;
	nqapplet_operations.init = nqapplet_init;
	nqapplet_operations.finish = nqapplet_finish;
	nqapplet_operations.get_response = nqapplet_get_response;
	nqapplet_operations.get_challenge = nqapplet_get_challenge;
	nqapplet_operations.logout = nqapplet_logout;
	nqapplet_operations.set_security_env = nqapplet_set_security_env;
	nqapplet_operations.decipher = nqapplet_decipher;
	nqapplet_operations.compute_signature = nqapplet_compute_signature;
	nqapplet_operations.check_sw = nqapplet_check_sw;
	nqapplet_operations.get_data = nqapplet_get_data;
	nqapplet_operations.select_file = nqapplet_select_file;
	nqapplet_operations.card_ctl = nqapplet_card_ctl;

	/* unsupported operations */
	nqapplet_operations.read_binary = NULL;
	nqapplet_operations.write_binary = NULL;
	nqapplet_operations.update_binary = NULL;
	nqapplet_operations.erase_binary = NULL;
	nqapplet_operations.read_record = NULL;
	nqapplet_operations.write_record = NULL;
	nqapplet_operations.append_record = NULL;
	nqapplet_operations.update_record = NULL;

	nqapplet_operations.verify = NULL;
	nqapplet_operations.restore_security_env = NULL;
	nqapplet_operations.change_reference_data = NULL;
	nqapplet_operations.reset_retry_counter = NULL;
	nqapplet_operations.create_file = NULL;
	nqapplet_operations.delete_file = NULL;
	nqapplet_operations.list_files = NULL;
	nqapplet_operations.process_fci = NULL;
	nqapplet_operations.construct_fci = NULL;
	nqapplet_operations.put_data = NULL;
	nqapplet_operations.delete_record = NULL;
	nqapplet_operations.read_public_key = NULL;

	/* let iso driver handle these operations
	nqapplet_operations.pin_cmd;
	nqapplet_operations.card_reader_lock_obtained;
	nqapplet_operations.wrap;
	nqapplet_operations.unwrap;
	*/

	return &nqapplet_driver;
}
