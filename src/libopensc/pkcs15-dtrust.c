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

#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include "pkcs15.h"

static int
_dtrust_parse_prkdf(struct sc_pkcs15_card *p15card)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_pkcs15_object *pkobjs[32];
	struct sc_pkcs15_prkey_info *prkey_info;
	int rv, i, count;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, pkobjs, sizeof(pkobjs) / sizeof(pkobjs[0]));
	LOG_TEST_RET(ctx, rv, "Cannot get PRKEY objects list");

	count = rv;
	for (i = 0; i < count; i++) {
		prkey_info = (struct sc_pkcs15_prkey_info *)pkobjs[i]->data;

		switch (p15card->card->type) {
		/* Cards with EC keys, don't encode the curve size in the
		 * private key directory file. We need to set the field_length
		 * element after parsing the private key directory file. */
		case SC_CARD_TYPE_DTRUST_V4_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V4_1_M100:
		case SC_CARD_TYPE_DTRUST_V4_4_MULTI:
			prkey_info->field_length = 256;
			break;

		case SC_CARD_TYPE_DTRUST_V5_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V5_1_M100:
		case SC_CARD_TYPE_DTRUST_V5_4_MULTI:
			prkey_info->field_length = 384;
			break;
		}

		switch (p15card->card->type) {
		case SC_CARD_TYPE_DTRUST_V6_1_STD:
		case SC_CARD_TYPE_DTRUST_V6_4_STD:
		case SC_CARD_TYPE_DTRUST_V6_1_MULTI:
		case SC_CARD_TYPE_DTRUST_V6_1_M100:
		case SC_CARD_TYPE_DTRUST_V6_4_MULTI:
			/* Key reference `ref` is encoded as `0x80 ref 0x00` in
			 * the ASN.1 data structure. This is an invalid
			 * negative number. We fix it to return `ref`.
			 */
			if (prkey_info->key_reference < 0) {
				/* Revert the hack from src/libopensc/pkcs15-prkey.c */
				prkey_info->key_reference -= 256;

				/* Extract the key reference */
				prkey_info->key_reference >>= 8;
				prkey_info->key_reference &= 0xff;
			}

			/* OpenSC (re)selects the application between verifying
			 * the PIN and performing the security operation.
			 * STARCOS cannot select whole paths. Instead it
			 * selects files by sequentially navigating through the
			 * directory tree. This would destroy our security
			 * status by first selecting the master file.
			 *
			 * Thus we strip the path from the PKCS#15 data
			 * structure and set the proper AID according to the
			 * specs. Selecting a file with its AID, doesn't
			 * destroy the security status. */
			prkey_info->path.len = 0;

			if (prkey_info->key_reference == 0x11) {
				memcpy(prkey_info->path.aid.value, "\xD2\x76\x00\x00\x66\x01", 6);
				prkey_info->path.aid.len = 6;
			} else if (prkey_info->key_reference == 0x17) {
				memcpy(prkey_info->path.aid.value, "\xA0\x00\x00\x01\x67\x45\x53\x49\x47\x4E", 10);
				prkey_info->path.aid.len = 10;
			}
			break;
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
_dtrust_parse_df(struct sc_pkcs15_card *p15card, struct sc_pkcs15_df *df)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!df)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (df->enumerated)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	rv = sc_pkcs15_parse_df(p15card, df);
	LOG_TEST_RET(ctx, rv, "DF parse error");

	if (df->type == SC_PKCS15_PRKDF) {
		rv = _dtrust_parse_prkdf(p15card);
	} else {
		rv = SC_SUCCESS;
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
dtrust_pkcs15emu_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type < SC_CARD_TYPE_DTRUST_V4_1_STD)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type > SC_CARD_TYPE_DTRUST_V6_4_MULTI)
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

#if defined(ENABLE_SM) && defined(ENABLE_OPENPACE)
	struct sc_pkcs15_search_key sk;
	struct sc_pkcs15_object *objs[8];
	int i, len;

	memset(&sk, 0, sizeof(sk));
	sk.class_mask = SC_PKCS15_SEARCH_CLASS_AUTH;
	len = sc_pkcs15_search_objects(p15card, &sk, (struct sc_pkcs15_object **)&objs, sizeof(objs) / sizeof(struct sc_pkcs15_object *));
	for (i = 0; i < len; i++) {
		if (!strcmp(objs[i]->label, "CAN")) {
			/* Mark "Card CAN" as NOT a PIN object, so that it doesn't get it's own PKCS#11 slot */
			objs[i]->type &= ~SC_PKCS15_TYPE_AUTH_PIN;
		}
	}
#endif

	LOG_FUNC_RETURN(ctx, rv);
}

int
sc_pkcs15emu_dtrust_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	if (dtrust_pkcs15emu_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_dtrust_init(p15card, aid);
}
