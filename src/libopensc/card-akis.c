/*
 * card-akis.c: Support for AKIS smart cards
 *
 * Copyright (C) 2007 TUBITAK / UEKAE
 * contact: bilgi@pardus.org.tr
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

#include <string.h>
#include <stdlib.h>

#include "internal.h"
#include "asn1.h"

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

static struct sc_atr_table akis_atrs[] = {
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
	sc_app_info_t *app = NULL;

	card->name = "AKIS";
	card->cla = 0x00;

	/* FIXME: set an application ID & path
	 * When AKIS comes with EF(DIR) this will be unnecessary
	 */
	app = (sc_app_info_t *) malloc(sizeof(sc_app_info_t));
	if (app == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	memcpy(app->aid, "\xA0\x00\x00\x00\x63PKCS-15", 12);
	app->aid_len = 12;
	app->label = strdup("PKCS-15");
	memcpy(app->path.value, "\x3F\x00\x3D\x00", 4);
	app->path.len = 4;	
	app->path.type = SC_PATH_TYPE_PATH;
	app->ddo = NULL;
	app->ddo_len = 0;

	app->desc = NULL;
	card->app[0] = app;
	card->app_count = 1;

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
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu->sw1, apdu->sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	if (file_out == NULL)
		return 0;

	file = sc_file_new();
	if (file == NULL)
		SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);

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

		SC_TEST_RET(card->ctx, r, "Unable to select DF");
		return 0;
	} else if (path->type == SC_PATH_TYPE_FILE_ID) {
		/* AKIS differentiates between EF and DF files
		 * when selecting with ID, this workaround tries both
		 */
		r = select_file(card, &apdu, path, 2, file_out);
		if (r)
			r = select_file(card, &apdu, path, 0, file_out);

		SC_TEST_RET(card->ctx, r, "Unable to select DF");
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
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "DIRECTORY command returned error");

	left = apdu.resplen;
	p = rbuf;

	while (left > 19) {
		if (p[0] != 0x2f && p[0] != 0x3d) {
			sc_error(card->ctx, "Malformatted list reply %02x", p[0]);
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
	SC_FUNC_RETURN(card->ctx, 1, r);
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
		sc_error(card->ctx, "Security tag missing");
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
			sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_CHV, 0);
	} else {
		if (!(perms & 0x04))
			sc_file_add_acl_entry(file, SC_AC_OP_READ, SC_AC_CHV, 0);
	}

	return 0;
}

static int
akis_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	int r;
	sc_apdu_t apdu;

	if (data->cmd != SC_PIN_CMD_VERIFY) {
		sc_error(card->ctx, "Other pin cmds not supported yet");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* AKIS VERIFY command uses P2 0x80 while ISO uses 0x00
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, 0x80);
	apdu.data = data->pin1.data;
	apdu.datalen = data->pin1.len;
	apdu.lc = apdu.datalen;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
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
	akis_ops.select_file = akis_select_file;
	akis_ops.list_files = akis_list_files;
	akis_ops.process_fci = akis_process_fci;
	akis_ops.pin_cmd = akis_pin_cmd;

	return &akis_drv;
}

#if 1
struct sc_card_driver *
sc_get_akis_driver(void)
{
	return sc_get_driver();
}
#endif
