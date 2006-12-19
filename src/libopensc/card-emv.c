/*
 * card-emv.c: Functions specified by the EMV standard
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include <string.h>

static struct sc_card_operations emv_ops;
static struct sc_card_driver emv_drv = {
	"EMV compatible cards",
	"emv",
	&emv_ops,
	NULL, 0, NULL
};

static int emv_finish(sc_card_t *card)
{
	return 0;
}

static int parse_atr(const u8 *atr, size_t atr_len, int *t0_out, int *tx1, int *tx2,
		     u8 *hist_bytes, int *hbcount)
{
	const u8 *p = atr;
	int len = atr_len;
	int nr_hist_bytes, tx, i;
	
	if (len < 2)
		return -1;
	p++;
	len--;
	*t0_out = *p;
	nr_hist_bytes = *p & 0x0F;
	tx = *p >> 4;
	p++;
	for (i = 0; i < 4; i++)
		tx1[i] = tx2[i] = -1;
	for (i = 0; i < 4; i++)
		if (tx & (1 << i)) {
			if (len <= 0)
				return -1;
			tx1[i] = *p++;
			len--;
		}
	if (tx1[3] != -1) {
		tx = tx1[3] >> 4;
		for (i = 0; i < 4; i++)
			if (tx & (1 << i)) {
				if (len <= 0)
					return -1;
				tx2[i] = *p++;
				len--;
			}
	}
	/* FIXME: possibly check TD2 */
	if (hist_bytes == NULL || nr_hist_bytes == 0)
		return 0;
	if (len < nr_hist_bytes)
		return -1;
	memcpy(hist_bytes, p, nr_hist_bytes);
	*hbcount = nr_hist_bytes;
	
	return 0;
}

static int emv_match_card(sc_card_t *card)
{
	int i, r, hbcount = 0, match = 1;
	int tx1[4], tx2[4], t0;
	char line[200], *linep = line;
	u8 hist_bytes[32];

	r = parse_atr(card->atr, card->atr_len, &t0, tx1, tx2, hist_bytes, &hbcount);
	if (r)
		return 0;
	for (i = 0; i < 4; i++)
		if (tx1[i] != -1)
			linep += sprintf(linep, "T%c1 = 0x%02X ", 'A' + i, tx1[i]);
	for (i = 0; i < 4; i++)
		if (tx2[i] != -1)
			linep += sprintf(linep, "T%c2 = 0x%02X ", 'A' + i, tx2[i]);
	if (card->ctx->debug >= 4) {
		sc_debug(card->ctx, "ATR parse: %s\n", line);
		if (hbcount) {
			sc_hex_dump(card->ctx, hist_bytes, hbcount, line, sizeof(line));
			sc_debug(card->ctx, "historic bytes:\n%s", line);
		}
	}
	if ((t0 & 0xF0) != 0x60)
		match = 0;
	if (match && tx1[1] != 0x00)
		match = 0;
	if (match && tx1[2] == -1)
		match = 0;
	if (match)
		for (i = 0; i < 4; i++)
			if (tx2[i] != -1)
				match = 0;
	return match;
}

static int emv_init(sc_card_t *card)
{
	card->drv_data = NULL;
	card->cla = 0x00;

	return 0;
}

static int emv_select_file(sc_card_t *card, const sc_path_t *path,
			   sc_file_t **file)
{
	int r;
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
	const struct sc_card_operations *ops = iso_drv->ops;

	r = ops->select_file(card, path, file);
	if (r)
		return r;
	if (file != NULL && path->len == 2 && memcmp(path->value, "\x3F\x00", 2) == 0)
		(*file)->type = SC_FILE_TYPE_DF;
	if (file != NULL && (*file)->namelen)
		(*file)->type = SC_FILE_TYPE_DF;
	return 0;
}

static struct sc_card_driver * sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	emv_ops = *iso_drv->ops;
	emv_ops.match_card = emv_match_card;
	emv_ops.init = emv_init;
        emv_ops.finish = emv_finish;
	emv_ops.select_file = emv_select_file;

	return &emv_drv;
}

#if 1
struct sc_card_driver * sc_get_emv_driver(void)
{
	return sc_get_driver();
}
#endif
