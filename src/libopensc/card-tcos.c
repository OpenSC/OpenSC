/*
 * card-tcos.c: Support for TCOS 2.0 cards
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "sc-internal.h"
#include "sc-log.h"

static const char *tcos_atrs[] = {
	"3B:BA:96:00:81:31:86:5D:00:64:05:60:02:03:31:80:90:00:66",
	NULL
};

static struct sc_card_operations tcos_ops;
static const struct sc_card_driver tcos_drv = {
	"TCOS 2.0 cards",
	"tcos",
	&tcos_ops
};

static int tcos_finish(struct sc_card *card)
{
	return 0;
}

static int tcos_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; tcos_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = tcos_atrs[i];

		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != card->atr_len)
			continue;
		if (memcmp(card->atr, defatr, len) != 0)
			continue;
		match = i;
		break;
	}
	if (match == -1)
		return 0;

	return 1;
}

static int tcos_init(struct sc_card *card)
{
	card->drv_data = NULL;
	card->cla = 0x00;

	return 0;
}

static const struct sc_card_operations *iso_ops = NULL;

static int tcos_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_file tmp;
	
	tmp = *file;
	memcpy(tmp.prop_attr, "\x03\x00\x00", 3);
	tmp.prop_attr_len = 3;
	return iso_ops->create_file(card, &tmp);
}

static int tcos_set_security_env(struct sc_card *card,
				  const struct sc_security_env *env,
				  int se_num)
{
	if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
		struct sc_security_env tmp;

		tmp = *env;
                tmp.flags &= ~SC_SEC_ENV_ALG_PRESENT;
		tmp.flags |= SC_SEC_ENV_ALG_REF_PRESENT;
		if (tmp.algorithm != SC_ALGORITHM_RSA) {
			error(card->ctx, "Only RSA algorithm supported.\n");
			return SC_ERROR_NOT_SUPPORTED;
		}
                tmp.algorithm_ref = 0x00;
		if (tmp.algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1)
			tmp.algorithm_ref = 0x02;
#if 0
		if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
                        tmp.algorithm_ref |= 0x10;
#endif
                return iso_ops->set_security_env(card, &tmp, se_num);

	}
        return iso_ops->set_security_env(card, env, se_num);
}

static void parse_sec_attr(struct sc_file *file, const u8 *buf, size_t len)
{
	return;
}

static int tcos_select_file(struct sc_card *card,
			    const struct sc_path *in_path,
			    struct sc_file **file)
{
	int r;
	
	r = iso_ops->select_file(card, in_path, file);
	if (r)
		return r;
	if (file != NULL)
		parse_sec_attr((*file), (*file)->sec_attr, (*file)->sec_attr_len);
	return 0;
}

static int tcos_list_files(struct sc_card *card, u8 *buf, size_t buflen)
{
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 p1s[2] = { 0x01, 0x02 };
	int r, i, count = 0;

	for (i = 0; i < 2; i++) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, p1s[i], 0);
		apdu.cla = 0x80;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = 256;
		r = sc_transmit_apdu(card, &apdu);
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r == SC_ERROR_FILE_NOT_FOUND)
			continue;
		SC_TEST_RET(card->ctx, r, "Card returned error");
		if (apdu.resplen > buflen)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(buf, apdu.resp, apdu.resplen);
		buf += apdu.resplen;
		buflen -= apdu.resplen;
		count += apdu.resplen;
	}
	return count;
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	tcos_ops = *iso_drv->ops;
	tcos_ops.match_card = tcos_match_card;
	tcos_ops.init = tcos_init;
        tcos_ops.finish = tcos_finish;
	if (iso_ops == NULL)
                iso_ops = iso_drv->ops;
	tcos_ops.create_file = tcos_create_file;
	tcos_ops.set_security_env = tcos_set_security_env;
	tcos_ops.select_file = tcos_select_file;
	tcos_ops.list_files = tcos_list_files;
	
        return &tcos_drv;
}

#if 1
const struct sc_card_driver * sc_get_tcos_driver(void)
{
	return sc_get_driver();
}
#endif
