/*
 * sc-card-multiflex.c: Support for Multiflex cards by Schlumberger
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

static const char *mflex_atrs[] = {
	"3B:19:14:55:90:01:02:02:00:05:04:B0",
	NULL
};

static struct sc_card_operations mflex_ops;
static const struct sc_card_driver mflex_drv = {
	NULL,
	"Multiflex/Schlumberger",
	&mflex_ops
};

static int mflex_finish(struct sc_card *card)
{
	return 0;
}

static int mflex_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; mflex_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		int len = sizeof(defatr);
		const char *atrp = mflex_atrs[i];

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

static int mflex_init(struct sc_card *card)
{
	card->ops_data = NULL;
	card->cla = 0xC0;

	return 0;
}

static int parse_flex_sf_reply(struct sc_context *ctx, const u8 *buf, int buflen,
			       struct sc_file *file)
{
	const u8 *p = buf + 2;
        int left;

	file->size = (*p++ << 8) + *p++;
	file->id = (*p++ << 8) + *p++;
	switch (*p) {
	case 0x01:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
		break;
	case 0x02:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_FIXED;
		break;
	case 0x04:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_LINEAR_VARIABLE;
		break;
	case 0x06:
		file->type = SC_FILE_TYPE_WORKING_EF;
		file->ef_structure = SC_FILE_EF_CYCLIC;
		break;
	case 0x38:
		file->type = SC_FILE_TYPE_DF;
		break;
	default:
		error(ctx, "invalid file type: 0x%02X\n", *p);
                return SC_ERROR_UNKNOWN_REPLY;
	}
        p++;
	p += 3; /* skip ACs */
	if (*p++)
		file->status = SC_FILE_STATUS_ACTIVATED;
	else
                file->status = SC_FILE_STATUS_INVALIDATED;
        left = *p++;

	return 0;
}

static int mflex_select_file(struct sc_card *card, const struct sc_path *path,
			     struct sc_file *file)
{
	int r;
	struct sc_apdu apdu;
        u8 rbuf[MAX_BUFFER_SIZE];
	u8 *pathptr = path->value;
	size_t pathlen = path->len;

	SC_FUNC_CALLED(card->ctx, 3);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
	apdu.resp = rbuf;
        apdu.resplen = sizeof(rbuf);
        apdu.p1 = apdu.p2 = 0;

	switch (path->type) {
	case SC_PATH_TYPE_PATH:
		if ((pathlen & 1) != 0) /* not divisible by 2 */
			return SC_ERROR_INVALID_ARGUMENTS;
		if (pathlen != 2 || memcmp(pathptr, "\x3F\x00", 2) != 0) {
			struct sc_path tmppath;

			if (memcmp(pathptr, "\x3F\x00", 2) != 0) {
				sc_format_path("I3F00", &tmppath);
				r = mflex_select_file(card, &tmppath, NULL);
				SC_TEST_RET(card->ctx, r, "Unable to select Master File (MF)");
				pathptr += 2;
				pathlen -= 2;
			}
			while (pathlen > 2) {
				memcpy(tmppath.value, pathptr, 2);
				tmppath.len = 2;
				r = mflex_select_file(card, &tmppath, NULL);
				SC_TEST_RET(card->ctx, r, "Unable to select DF");
				pathptr += 2;
				pathlen -= 2;
			}
		}
                break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 0x04;
		break;
	case SC_PATH_TYPE_FILE_ID:
		if ((pathlen & 1) != 0)
			return SC_ERROR_INVALID_ARGUMENTS;
                break;
	}
	apdu.datalen = pathlen;
        apdu.data = pathptr;
        apdu.lc = pathlen;

	/* No need to get file information, if file is NULL or already
         * valid. */
	if (file == NULL || sc_file_valid(file))
                apdu.no_response = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");
	if (apdu.no_response)
                return 0;

	if (apdu.resplen < 14)
		return SC_ERROR_UNKNOWN_REPLY;

	if (apdu.resp[0] == 0x6F) {
		error(card->ctx, "unsupported: Multiflex returned FCI\n");
                return SC_ERROR_UNKNOWN_REPLY; /* FIXME */
	}

	return parse_flex_sf_reply(card->ctx, apdu.resp, apdu.resplen, file);
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	mflex_ops = *iso_drv->ops;
	mflex_ops.match_card = mflex_match_card;
	mflex_ops.init = mflex_init;
        mflex_ops.finish = mflex_finish;
	mflex_ops.select_file = mflex_select_file;

        return &mflex_drv;
}

#if 1
const struct sc_card_driver * sc_get_mflex_driver(void)
{
	return sc_get_driver();
}
#endif
