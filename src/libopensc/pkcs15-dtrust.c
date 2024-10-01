/*
 * PKCS15 emulation layer for D-Trust card.
 *
 * Copyright (C) 2024, Mario Haustein <mario.haustein@hrz.tu-chemnitz.de>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include "pkcs15.h"

static int
_dtrust_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pkobjs[32];
	struct sc_pkcs15_prkey_info *prkey_info;
	int rv, i, count;

	LOG_FUNC_CALLED(ctx);

	if (!df)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_parse_df(p15card, df);
	LOG_TEST_RET(ctx, rv, "DF parse error");

	if (df->type != SC_PKCS15_PRKDF)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	switch (p15card->card->type) {
	/* Cards with EC keys, don't encode the curve size in the
	 * private key directory file. We need to set the field_length
	 * element after parsing the private key directory file. */
	case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
	case SC_CARD_TYPE_DTRUST_V4_1_M100:
	case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
		rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, pkobjs, sizeof(pkobjs) / sizeof(pkobjs[0]));
		LOG_TEST_RET(ctx, rv, "Cannot get PRKEY objects list");

		count = rv;
		for (i = 0; i < count; i++) {
			prkey_info = (struct sc_pkcs15_prkey_info *)pkobjs[i]->data;
			prkey_info->field_length = 256;
		}
		break;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
dtrust_pkcs15emu_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type < SC_CARD_TYPE_DTRUST_V4_1_STD)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type > SC_CARD_TYPE_DTRUST_V4_4_MULTI)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

static int
sc_pkcs15emu_dtrust_init(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_bind_internal(p15card, aid);

	p15card->ops.parse_df = _dtrust_parse_df;

	LOG_FUNC_RETURN(ctx, rv);
}

int
sc_pkcs15emu_dtrust_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	if (dtrust_pkcs15emu_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_dtrust_init(p15card, aid);
}
