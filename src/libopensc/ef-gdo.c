/*
 * ef-atr.c: Stuff for handling EF(GDO)
 *
 * Copyright (C) 2017  Frank Morgner <frankmorgner@gmail.com>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "asn1.h"
#include "internal.h"
#include <stdlib.h>
#include <string.h>

static int
sc_parse_ef_gdo_content(const unsigned char *gdo, size_t gdo_len,
		unsigned char *iccsn, size_t *iccsn_len,
		unsigned char *chn, size_t *chn_len)
{
	int r = SC_SUCCESS, iccsn_found = 0, chn_found = 0;
	const unsigned char *p = gdo;
	size_t left = gdo_len;

	while (left >= 2) {
		unsigned int cla, tag;
		size_t tag_len;

		r = sc_asn1_read_tag(&p, left, &cla, &tag, &tag_len);
		if (r != SC_SUCCESS) {
			if (r == SC_ERROR_ASN1_END_OF_CONTENTS) {
				/* not enough data */
				r = SC_SUCCESS;
			}
			break;
		}
		if (p == NULL) {
			/* done parsing */
			break;
		}

		if (cla == SC_ASN1_TAG_APPLICATION) {
			switch (tag) {
				case 0x1A:
					iccsn_found = 1;
					if (iccsn && iccsn_len) {
						memcpy(iccsn, p, MIN(tag_len, *iccsn_len));
						*iccsn_len = MIN(tag_len, *iccsn_len);
					}
					break;
				case 0x1F20:
					chn_found = 1;
					if (chn && chn_len) {
						memcpy(chn, p, MIN(tag_len, *chn_len));
						*chn_len = MIN(tag_len, *chn_len);
					}
					break;
			}
		}

		p += tag_len;
		left = gdo_len - (p - gdo);
	}

	if (!iccsn_found && iccsn_len)
		*iccsn_len = 0;
	if (!chn_found && chn_len)
		*chn_len = 0;

	return r;
}



int
sc_parse_ef_gdo(struct sc_card *card,
		unsigned char *iccsn, size_t *iccsn_len,
		unsigned char *chn, size_t *chn_len)
{
	struct sc_context *ctx;
	struct sc_path path;
	struct sc_file *file;
	unsigned char *gdo = NULL;
	size_t gdo_len = 0;
	int r;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;

	LOG_FUNC_CALLED(ctx);

	sc_format_path("3F002F02", &path);
	r = sc_select_file(card, &path, &file);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot select EF(GDO) file");

	if (file->size) {
		gdo_len = file->size;
	} else {
		gdo_len = 64;
	}
	gdo = malloc(gdo_len);
	if (!gdo) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	r = sc_read_binary(card, 0, gdo, gdo_len, 0);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot read EF(GDO) file");

	r = sc_parse_ef_gdo_content(gdo, r, iccsn, iccsn_len, chn, chn_len);

err:
	sc_file_free(file);
	free(gdo);

	LOG_FUNC_RETURN(ctx, r);
}
