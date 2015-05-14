/*
 * card-masktech.c: Support for Masktech smart cards using the MTCOS operating system.
 *
 * Copyright (C) 2011-2015 MaskTech GmbH Fischerstrasse 19, 87435 Kempten, Germany
 * Copyright (C) 2011 Andrey Uvarov (X-Infotech) <andrejs.uvarovs@x-infotech.com>
 * Copyright (C) 2015 Vincent Le Toux (My Smart Logon) <vincent.letoux@mysmartlogon.com>
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

#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "cardctl.h"
#include "iso7816.h"

static struct sc_atr_table masktech_atrs[] = {
	{"3B:89:80:01:4D:54:43:4F:53:70:02:02:05:3B", NULL, NULL,
	 SC_CARD_TYPE_MASKTECH_GENERIC, 0, NULL},
	{"3B:88:80:01:00:00:00:00:77:81:81:00:7E", NULL, NULL,
	 SC_CARD_TYPE_MASKTECH_GENERIC, 0, NULL},
	{"3B:9D:13:81:31:60:37:80:31:C0:69:4D:54:43:4F:53:73:02:02:05:41", NULL, NULL,
	 SC_CARD_TYPE_MASKTECH_GENERIC, 0, NULL},
	{"3B:9D:13:81:31:60:37:80:31:C0:69:4D:54:43:4F:53:73:02:01:02:45", NULL, NULL,
	 SC_CARD_TYPE_MASKTECH_GENERIC, 0, NULL},
	{NULL, NULL, NULL, 0, 0, NULL}
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations masktech_ops;
static struct sc_card_driver masktech_drv = {
	"MaskTech Smart Card",
	"MaskTech",
	&masktech_ops,
	masktech_atrs, 0, NULL
};

struct masktech_private_data {
	/* save the key reference set at set_masktech_set_security_env to recover it as the signature step */
	int	rsa_key_ref;

};

static int masktech_match_card(sc_card_t * card)
{
	/* check if the ATR is in the known ATR */
	if (_sc_match_atr(card, masktech_atrs, &card->type) < 0)
		return 0;

	return 1;
}

static int masktech_init(sc_card_t * card)
{
	unsigned long flags;
	struct masktech_private_data *data;

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "masktech_init()\n");

	/* private data kept during the live of the driver */
	if (!(data = (struct masktech_private_data *) malloc(sizeof(*data))))
		return SC_ERROR_OUT_OF_MEMORY;
	card->drv_data = data;

	/* supported RSA keys and how padding is done */
	flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
	_sc_card_add_rsa_alg(card, 1024, flags, 0);
	_sc_card_add_rsa_alg(card, 2048, flags, 0);
	_sc_card_add_rsa_alg(card, 3072, flags, 0);
	card->caps |= SC_CARD_CAP_APDU_EXT;
	return SC_SUCCESS;
}


static int masktech_finish(sc_card_t *card)
{
	/* free the private data */
	if (card->drv_data) {
		free(card->drv_data);
		card->drv_data = NULL;
	}
	return 0;
}

static int masktech_set_security_env(sc_card_t *card,
                                     const sc_security_env_t *env,
                                     int se_num)
{
	struct masktech_private_data *private_data;
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "masktech_set_security_env(), keyRef = 0x%0x, algo = 0x%0x\n",
		 *env->key_ref, env->algorithm_flags);

	private_data = (struct masktech_private_data *) card->drv_data;
	if (!private_data)
		return SC_ERROR_INTERNAL;

	/* save the key reference */
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->key_ref_len != 1) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Invalid key reference supplied.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		private_data->rsa_key_ref = env->key_ref[0];
	}

	return iso_ops->set_security_env(card, env, se_num);
}

static int masktech_compute_signature(sc_card_t *card,
                                      const u8 * data,
                                      size_t datalen,
                                      u8 * out,
                                      size_t outlen)
{

	struct masktech_private_data *private_data;
	u8 sha256hash[32];
	static const u8 hdr_sha256[] = {
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
		0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
	};
	assert(card != NULL && data != NULL && out != NULL);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "masktech_compute_signature()\n");

	/* retrieve the key reference */
	private_data = (struct masktech_private_data *) card->drv_data;
	if (!private_data)
		return SC_ERROR_INTERNAL;

	if (private_data->rsa_key_ref == 0x88)
	{
		/* for this key reference, the card supports only SHA256 hash and the hash is computed using a digest info */
		/* check that it is a SHA256 with digest info*/
		if ((datalen != sizeof(hdr_sha256) + 32) || (memcmp(hdr_sha256, data, sizeof(hdr_sha256)) != 0))
		{
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "It is not a SHA256 with digestinfo\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
		/* extract the SHA-256 hash */
		memcpy(sha256hash, (u8 *)(data+(datalen-32)), 32);//only last 32 byte => sha256
		/* default ISO 7816 functions */
		return iso_ops->compute_signature(card, sha256hash, 32, out, outlen);
	}
	else
	{
		/* default ISO 7816 functions */
		return iso_ops->compute_signature(card, data, datalen, out, outlen);
	}
}

static int masktech_decipher(sc_card_t *card,
                             const u8 * crgram,
                             size_t crgram_len,
                             u8 * out,
                             size_t outlen)
{
	int r;
	sc_apdu_t apdu;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];

	assert(card != NULL && crgram != NULL && out != NULL);
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "masktech_decipher()\n");

	if (crgram_len > SC_MAX_EXT_APDU_BUFFER_SIZE) SC_ERROR_INVALID_ARGUMENTS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_EXT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	/* the card doesn't support anything else here (+1 / -1 is not working) */
	apdu.le = 65536;

	apdu.data = crgram;
	apdu.lc = crgram_len;
	apdu.datalen = crgram_len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		size_t len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, len);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

/* unblock pin cmd */
static int masktech_pin_unblock(sc_card_t *card,
                            struct sc_pin_cmd_data *data,
                            int *tries_left)
{
	int rv = 0;
	struct sc_pin_cmd_data verify_data;
	struct sc_pin_cmd_data reset_data;

	/* Build a SC_PIN_CMD_VERIFY APDU on PUK */
	memset(&verify_data, 0, sizeof(verify_data));
	verify_data.cmd = SC_PIN_CMD_VERIFY;
	verify_data.pin_type = 1;
	verify_data.pin_reference = 0x83;
	verify_data.pin1 = data->pin1;
	verify_data.flags = data->flags;
	verify_data.pin1.prompt = data->pin1.prompt;

	rv = iso_ops->pin_cmd(card, &verify_data, tries_left);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed - verify unblock PIN");

	/* Build a SC_PIN_CMD_UNBLOCK APDU */
	memset(&reset_data, 0, sizeof(reset_data));
	reset_data.cmd = SC_PIN_CMD_UNBLOCK;
	reset_data.pin_type = 1;
	reset_data.pin_reference = 0x91;
	/* pin1 is set to null on purpose and flag set to implicit change
	 => if there is a pinpad reader, do not ask for pin1 */
	reset_data.pin2 = data->pin2;
	reset_data.flags = data->flags | SC_PIN_CMD_IMPLICIT_CHANGE;
	reset_data.pin2.prompt = data->pin2.prompt;

	rv = iso_ops->pin_cmd(card, &reset_data, tries_left);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed - reset unblock PIN");

	return 0;
}

static int masktech_pin_change(sc_card_t *card,
                            struct sc_pin_cmd_data *data,
                            int *tries_left)
{
	int rv = 0;
	struct sc_pin_cmd_data verify_data;
	struct sc_pin_cmd_data change_data;

	/* Build a SC_PIN_CMD_VERIFY APDU */
	memset(&verify_data, 0, sizeof(verify_data));
	verify_data.cmd = SC_PIN_CMD_VERIFY;
	verify_data.pin_type = 1;
	verify_data.pin_reference = data->pin_reference;
	verify_data.pin1 = data->pin1;
	verify_data.flags = data->flags;
	verify_data.pin1.prompt = data->pin1.prompt;

	rv = iso_ops->pin_cmd(card, &verify_data, tries_left);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed - verify change PIN");

	/* Build a SC_PIN_CMD_CHANGE APDU */
	memset(&change_data, 0, sizeof(change_data));
	change_data.cmd = SC_PIN_CMD_CHANGE;
	change_data.pin_type = 1;
	change_data.pin_reference = data->pin_reference;
	/* pin1 is set to null on purpose and flag set to implicit change
	 => if there is a pinpad reader, do not ask for pin1 */
	change_data.pin2 = data->pin2;
	change_data.flags = data->flags | SC_PIN_CMD_IMPLICIT_CHANGE;
	change_data.pin2.prompt = data->pin2.prompt;

	rv = iso_ops->pin_cmd(card, &change_data, tries_left);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed - chnage PIN");

	return 0;
}

static int masktech_pin_cmd(sc_card_t *card,
                            struct sc_pin_cmd_data *data,
                            int *tries_left)
{
	int       rv;
	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	switch(data->cmd)
	{
	case SC_PIN_CMD_UNBLOCK:
		rv = masktech_pin_unblock(card, data, tries_left);
		break;
	case SC_PIN_CMD_CHANGE:
		rv = masktech_pin_change(card, data, tries_left);
		break;
	default:
		rv = iso_ops->pin_cmd(card, data, tries_left);
		break;
	}
	return rv;


}

static int masktech_get_serialnr(sc_card_t * card, sc_serial_number_t * serial)
{
	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE-2];
	int rv;

	if (!serial)
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INVALID_ARGUMENTS);

	/* Get smart card serial number */
	card->cla = 0x80;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x08, 0x00, 0x00);
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	card->cla = 0x00;

	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, rv, "APDU transmit failed");

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return SC_ERROR_INTERNAL;

	if (SC_MAX_SERIALNR < apdu.resplen)
	{
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_INTERNAL);
	}
	/* cache serial number */
	card->serialnr.len = apdu.resplen;
	memcpy(card->serialnr.value, apdu.resp, card->serialnr.len);

	/* copy and return serial number */
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}


static int masktech_card_ctl(sc_card_t * card, unsigned long cmd, void *ptr)
{
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "masktech_card_ctl()\n");
	switch (cmd) {
		case SC_CARDCTL_GET_SERIALNR:
			return masktech_get_serialnr(card, (sc_serial_number_t *) ptr);
		default:
			return SC_ERROR_NOT_SUPPORTED;
	}
}

static struct sc_card_driver *sc_get_driver(void)
{

	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	masktech_ops = *iso_ops;

	masktech_ops.match_card = masktech_match_card;
	masktech_ops.init = masktech_init;
	masktech_ops.finish = masktech_finish;
	masktech_ops.set_security_env = masktech_set_security_env;
	masktech_ops.compute_signature = masktech_compute_signature;
	masktech_ops.decipher = masktech_decipher;
	masktech_ops.pin_cmd = masktech_pin_cmd;
	masktech_ops.card_ctl = masktech_card_ctl;
	return &masktech_drv;
}

struct sc_card_driver *sc_get_masktech_driver(void)
{
	return sc_get_driver();
}
