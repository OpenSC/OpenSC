/*
 * card-akis.c: Support for AKIS smart cards
 *
 * Copyright (C) 2007 TUBITAK / UEKAE
 * contact: bilgi@pardus.org.tr
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

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations akis_ops;

static struct sc_card_driver akis_drv = {
	"TUBITAK UEKAE AKIS",
	"akis",
	&akis_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table akis_atrs[] = {
	{ "3b:ba:11:00:81:31:fe:4d:55:45:4b:41:45:20:56:31:2e:30:ae", NULL, NULL, SC_CARD_TYPE_AKIS_GENERIC, 0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};

static int
akis_match_card(sc_card_t *card)
{
	int i;

	i = _sc_match_atr(card, akis_atrs, &card->type);
	if (i < 0)
		return 0;
	return 1;
}

static int
akis_init(sc_card_t *card)
{
	unsigned long flags;

	card->name = "AKIS";
	card->cla = 0x00;
	card->max_pin_len = 16;
	card->max_recv_size = 244;
	card->max_send_size = 244;

	flags = SC_ALGORITHM_RSA_RAW | SC_ALGORITHM_RSA_PAD_PKCS1;
        _sc_card_add_rsa_alg(card, 2048, flags, 0);

	return 0;
}

static int
select_file(sc_card_t *card, sc_apdu_t *apdu, const sc_path_t *path,
	    int mode, sc_file_t **file_out)
{
	int r;
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
        sc_file_t *file;

	sc_format_apdu(card, apdu, SC_APDU_CASE_4_SHORT, 0xA4, mode, 0);
	apdu->resp = rbuf;
	apdu->resplen = sizeof(rbuf);
	apdu->datalen = path->len;
	apdu->data = path->value;
	apdu->lc = path->len;
	apdu->le = 256;

	r = sc_transmit_apdu(card, apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu->sw1, apdu->sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	if (file_out == NULL)
		return 0;

	file = sc_file_new();
	if (file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OUT_OF_MEMORY);

	r = card->ops->process_fci(card, file, apdu->resp + 2, apdu->resp[1]);
	if (r) {
		sc_file_free(file);
		return r;
	}

	*file_out = file;
	return 0;
}

static int
akis_select_file(sc_card_t *card, const sc_path_t *path,
		 sc_file_t **file_out)
{
	int r;
	sc_apdu_t apdu;

	if (path->type == SC_PATH_TYPE_PATH) {
		/* FIXME: iso implementation seems already do that
		*/
		r = select_file(card, &apdu, path, path->len == 2 ? 0 : 8, file_out);

		LOG_TEST_RET(card->ctx, r, "Unable to select DF");
		return 0;
	} else if (path->type == SC_PATH_TYPE_FILE_ID) {
		/* AKIS differentiates between EF and DF files
		 * when selecting with ID, this workaround tries both
		 */
		r = select_file(card, &apdu, path, 2, file_out);
		if (r)
			r = select_file(card, &apdu, path, 0, file_out);

		LOG_TEST_RET(card->ctx, r, "Unable to select DF");
		return 0;
	} else {
		return iso_ops->select_file(card, path, file_out);
	}
}

static int
akis_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	/* This AKIS specific command is not provided by generic ISO driver
	 */
	sc_apdu_t apdu;
	u8 rbuf[256];
	size_t left, fids = 0;
	u8 *p;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x18, 0, 0);
	apdu.cla = 0x80;
	apdu.le = 256;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "DIRECTORY command returned error");

	left = apdu.resplen;
	p = rbuf;

	while (left > 19) {
		if (p[0] != 0x2f && p[0] != 0x3d) {
			sc_log(card->ctx,  "Malformatted list reply %02x", p[0]);
			return SC_ERROR_INTERNAL;
		}
		if (buflen >= 2) {
			buf[fids++] = p[1];
			buf[fids++] = p[2];
			buflen -= 2;
		} else {
			break;
		}
		p += 20;
		left -= 20;
	}

	r = fids;
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
akis_process_fci(sc_card_t *card, sc_file_t *file,
		 const u8 *buf, size_t buflen)
{
	int r;
	size_t len;
	const u8 *p;
	u8 perms;

	r = iso_ops->process_fci(card, file, buf, buflen);
	if (r < 0) return r;

	/* AKIS uses a different security model than ISO implementation
	 */
	p = sc_asn1_find_tag(card->ctx, buf, buflen, 0x90, &len);
	if (p == NULL) {
		sc_log(card->ctx,  "Security tag missing");
		return SC_ERROR_INTERNAL;
	}
	perms = p[0];
	/* Bit definitions:
	 * 0x01 Encrypted
	 * 0x02 Valid
	 * 0x04 PIN needed
	 * 0x08 New PIN
	 * 0x10 Read
	 * 0x20 Write
	 * 0x40 Wrong PIN entered once
	 * 0x80 Last try for PIN
	 */

	if (file->type == SC_FILE_TYPE_DF) {
		if (perms & 0x04)
			sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_CHV, 0x80);
	} else {
		if (!(perms & 0x04))
			sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_CHV, 0x80);
	}

	return 0;
}

static int
akis_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	u8 type;
	u8 acl;
	u8 fid[4];
        u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;

	/* AKIS uses different create commands for EF and DF.
	 * Parameters are not passed as ASN.1 structs but in
	 * a custom format.
	 */

	/* FIXME: hardcoded for now, better get it from file acl params */
	acl = 0xb0;

	fid[0] = (file->id >> 8) & 0xFF;
	fid[1] = file->id & 0xFF;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x15, 0, acl);
	apdu.cla = 0x80;
	apdu.data = fid;
	apdu.datalen = 2;
	apdu.lc = 2;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	if (file->type == SC_FILE_TYPE_WORKING_EF) {
		switch (file->ef_structure) {
			case SC_FILE_EF_TRANSPARENT:
				type = 0x80;
				break;
			case SC_FILE_EF_LINEAR_FIXED:
				type = 0x41;
				break;
			case SC_FILE_EF_CYCLIC:
				type = 0x43;
				break;
			case SC_FILE_EF_LINEAR_VARIABLE_TLV:
				type = 0x45;
				break;
			default:
				sc_log(card->ctx,  "This EF structure is not supported yet");
				return SC_ERROR_NOT_SUPPORTED;
		}
		apdu.p1 = type;
		if (type == 0x41 || type == 0x43) {
			fid[2] = file->record_length;
			apdu.datalen++;
			apdu.lc++;
		}
	} else if (file->type == SC_FILE_TYPE_DF) {
		apdu.ins = 0x10;
	} else {
		sc_log(card->ctx,  "Unknown file type");
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int
akis_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	u8 sbuf[2];
	const u8 *buf;
	size_t buflen;
	int type;
	sc_apdu_t apdu;

	switch (path->type) {
		case SC_PATH_TYPE_FILE_ID:
			sbuf[0] = path->value[0];
			sbuf[1] = path->value[1];
			buf = sbuf;
			buflen = 2;
			type = 0x02;
			break;
		case SC_PATH_TYPE_PATH:
			buf = path->value;
			buflen = path->len;
			type = 0x08;
			break;
		default:
			sc_log(card->ctx,  "File type has to be FID or PATH");
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x16, type, 0x00);
        apdu.cla = 0x80;
	apdu.lc = buflen;
	apdu.datalen = buflen;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int
akis_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	if (data->cmd == SC_PIN_CMD_VERIFY) {
		/* ISO7816 implementation works */
		return iso_ops->pin_cmd(card, data, tries_left);
	}

	if (data->cmd == SC_PIN_CMD_CHANGE) {
		/* This is AKIS specific */
		int r;
		sc_apdu_t apdu;
		u8 buf[64];
		int p1, p2;

		p2 = data->pin_reference;
		if (p2 & 0x80) {
			p1 = 2;
			p2 &= 0x7f;
		} else {
			p1 = 1;
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, p1, p2);

		buf[0] = data->pin1.len;
		memcpy(buf+1, data->pin1.data, data->pin1.len);

		buf[data->pin1.len+1] = data->pin2.len;
		memcpy(buf+data->pin1.len+2, data->pin2.data, data->pin2.len);

		apdu.data = buf;
		apdu.datalen = data->pin1.len + data->pin2.len + 2;
		apdu.lc = apdu.datalen;

		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		return r;
	}

	sc_log(card->ctx,  "Other pin cmds not supported yet");
	return SC_ERROR_NOT_SUPPORTED;
}

static int
akis_get_data(sc_card_t *card, unsigned int dataid, u8 *buf, size_t len)
{
	int r;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x01, dataid);
	apdu.resp = buf;
	apdu.resplen = len;
	apdu.le = len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static int
akis_get_serialnr(sc_card_t *card, sc_serial_number_t *serial)
{
	int r;
	u8 system_buffer[128];

	if (!serial)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* see if we have cached serial number */
	if (card->serialnr.len) goto end;

	/* read serial number */
	r = akis_get_data(card, 6, system_buffer, 0x4D);
	LOG_TEST_RET(card->ctx, r, "GET_DATA failed");

	card->serialnr.len = 12;
	memcpy(card->serialnr.value, system_buffer+55, 12);

end:
	memcpy(serial, &card->serialnr, sizeof(*serial));
	return SC_SUCCESS;
}

static int
akis_lifecycle_get(sc_card_t *card, int *mode)
{
	int r;
	u8 memory[10];

	r = akis_get_data(card, 4, memory, 10);
	LOG_TEST_RET(card->ctx, r, "GET_DATA failed");

	switch(memory[6]) {
		case 0xA0:
			*mode = SC_CARDCTRL_LIFECYCLE_ADMIN;
			break;
		case 0xA5:
			*mode = SC_CARDCTRL_LIFECYCLE_USER;
			break;
		default:
			*mode = SC_CARDCTRL_LIFECYCLE_OTHER;
			break;
	}
	return SC_SUCCESS;
}

static int
akis_lifecycle_set(sc_card_t *card, int *mode)
{
	int r;
	u8 stage;
	sc_apdu_t apdu;

	switch(*mode) {
		case SC_CARDCTRL_LIFECYCLE_ADMIN:
			stage = 0x02;
			break;
		case SC_CARDCTRL_LIFECYCLE_USER:
			stage = 0x01;
			break;
		default:
			return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x09, 0x00, stage);
	apdu.cla = 0x80;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static int
akis_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return akis_get_serialnr(card, (sc_serial_number_t *)ptr);
	case SC_CARDCTL_LIFECYCLE_GET:
		return akis_lifecycle_get(card, (int *) ptr);
	case SC_CARDCTL_LIFECYCLE_SET:
		return akis_lifecycle_set(card, (int *) ptr);
	}
	return SC_ERROR_NOT_SUPPORTED;
}

static int
akis_set_security_env(sc_card_t *card,
                      const sc_security_env_t *env,
                      int se_num)
{
	int r;
	u8 ref;
	sc_apdu_t apdu;

	/* AKIS uses key references for accessing keys
	 */
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		ref = env->key_ref[0];
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0xC3, ref);
		r = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		return r;
	}
	return SC_SUCCESS;
}

static int
akis_logout(sc_card_t *card)
{
	int r;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x1A, 0, 0);
	apdu.cla = 0x80;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	return r;
}

static struct sc_card_driver *
sc_get_driver(void)
{
	if (iso_ops == NULL)
		iso_ops = sc_get_iso7816_driver()->ops;

	akis_ops = *iso_ops;

	akis_ops.match_card = akis_match_card;
	akis_ops.init = akis_init;
	/* read_binary: ISO7816 implementation works */
	/* write_binary: ISO7816 implementation works */
	/* update_binary: ISO7816 implementation works */
	/* erase_binary: Untested */
	/* read_record: Untested */
	/* write_record: Untested */
	/* append_record: Untested */
	/* update_record: Untested */
	akis_ops.select_file = akis_select_file;
	/* get_response: ISO7816 implementation works */
	/* get_challenge: ISO7816 implementation works */
	akis_ops.logout = akis_logout;
	/* restore_security_env: Untested */
	akis_ops.set_security_env = akis_set_security_env;
	/* decipher: Untested */
	/* compute_signature: ISO7816 implementation works */
	akis_ops.create_file = akis_create_file;
	akis_ops.delete_file = akis_delete_file;
	akis_ops.list_files = akis_list_files;
	/* check_sw: ISO7816 implementation works */
	akis_ops.card_ctl = akis_card_ctl;
	akis_ops.process_fci = akis_process_fci;
	/* construct_fci: Not needed */
	akis_ops.pin_cmd = akis_pin_cmd;
	akis_ops.get_data = akis_get_data;
	/* put_data: Not implemented */
	/* delete_record: Not implemented */

	return &akis_drv;
}

#if 1
struct sc_card_driver *
sc_get_akis_driver(void)
{
	return sc_get_driver();
}
#endif
