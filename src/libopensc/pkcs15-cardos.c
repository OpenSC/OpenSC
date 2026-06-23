/*
 * PKCS15 emulation layer for CardOS cards
 * Adapted from PKCS15 emulation layer for IAS/ECC card.
 *
 * Copyright (C) 2020, Douglas E. Engert <DEEngert@gmail.com>
 * Copyright (C) 2016, Viktor Tarasov <viktor.tarasov@gmail.com>
 * Copyright (C) 2004, Bud P. Bruegger <bud@comune.grosseto.it>
 * Copyright (C) 2004, Antonino Iacono <ant_iacono@tin.it>
 * Copyright (C) 2003, Olaf Kirch <okir@suse.de>
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"


/*
 * Called after sc_pkcs15_bind_internal
 * Create new flags based on supported_algos.
 */
static int cardos_fix_token_info(sc_pkcs15_card_t *p15card)
{
	sc_card_t *card;
	struct sc_supported_algo_info (*saa)[SC_MAX_SUPPORTED_ALGORITHMS];
	struct sc_supported_algo_info *sa;
	struct sc_cardctl_cardos_pass_algo_flags *passed = NULL;
	int r = 0;
	int i;

	card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	passed = calloc(1, sizeof(struct sc_cardctl_cardos_pass_algo_flags));
	if (!passed)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_ENOUGH_MEMORY);

	passed->pass = 1; /* get used_flags and card_flags from card */
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_PASS_ALGO_FLAGS, passed);
	if (r < 0) {
		free(passed);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	saa = &(p15card->tokeninfo->supported_algos);

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "Original Flags: 0x%8.8lx card->flags:0x%8.8lx", passed->used_flags, passed->card_flags);

	if (passed->card_flags) { /* user forced the flags, use them */
		passed->new_flags = passed->card_flags; /* from card_atr flags */
	} else {

		for (i = 0, sa = saa[0]; i < SC_MAX_SUPPORTED_ALGORITHMS; i++, sa++) {

			if (sa->reference == 0 && sa->mechanism == 0
					&& sa->operations == 0 && sa->algo_ref == 0)
				break;

			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "supported_algos[%d] mechanism:0x%8.8x", i, sa->mechanism);
			switch(sa->mechanism) {
			case 0x01 :
				/*
				 * Card appears to use lower 4 bits of reference as key, and upper
				 * 4 bits as mech for card.
				 * Also has a bug if mechanism = 1 (CKM_RSA_PKCS1) and reference 0x10 
				 * bit is set mechanism should be 3 (CKM_RSA_X_509) 
				 * correct the mechanism in tokenInfo
				 */
				if (sa->reference & 0x10) {
					sc_log(card->ctx, "Changing mechanism to CKM_RSA_X_509 based on reference");
					passed->new_flags |= SC_ALGORITHM_RSA_RAW
						| SC_ALGORITHM_RSA_PAD_NONE;
					sa->mechanism = 0x03;
				} else
				passed->new_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
				break;
			case 0x03 :
				passed->new_flags |= SC_ALGORITHM_RSA_RAW
					| SC_ALGORITHM_RSA_PAD_NONE;
				break;
			case 0x06 :
				passed->new_flags |= SC_ALGORITHM_RSA_HASH_SHA1;
				break;
			case 0x1041:
				passed->ec_flags |= SC_ALGORITHM_ECDSA_RAW;
				/* no old_ec_flags */
				/* TODO turn on sizes from  ec curves OIDS */
				break;
			default:
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "UNKNOWN MECH: 0x%8.8x", sa->mechanism);
			}

			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "New_flags 0x%8.8lx New_ec_flags: 0x%8.8lx",
				passed->new_flags, passed->ec_flags);
		}

		if (passed->new_flags == 0) {
			if (p15card->tokeninfo && p15card->tokeninfo->flags & SC_PKCS15_TOKEN_EID_COMPLIANT) {
				sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "EID_COMPLIANT flag found");
				passed->new_flags = (passed->used_flags & ~SC_ALGORITHM_SPECIFIC_FLAGS) | SC_ALGORITHM_RSA_PAD_PKCS1;
			} else
				passed->new_flags = passed->used_flags; /* from default cardos_init */
		}
	}

	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,"Final New_flags 0x%8.8lx New_ec_flags: 0x%8.8lx", passed->new_flags, passed->ec_flags);

	passed->pass = 2; /* tell card driver to use the new flags */
	r = sc_card_ctl(p15card->card, SC_CARDCTL_CARDOS_PASS_ALGO_FLAGS, passed);

	free(passed);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
cardos_pkcs15emu_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type <  SC_CARD_TYPE_CARDOS_BASE)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type >= SC_CARD_TYPE_CARDOS_BASE + 1000)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}

/*
 * CardOS V5.x cards often omit SupportedAlgorithms on private key objects
 * (Algo_refs: 0). OpenSC's pkcs15_prkey_can_do() then returns
 * CKR_FUNCTION_NOT_SUPPORTED and signing fails in browsers.
 */
static int
cardos_fixup_prkey_algo_refs(struct sc_pkcs15_card *p15card)
{
	struct sc_supported_algo_info *token_algos;
	struct sc_pkcs15_object *objs[32];
	int i, j, count;

	LOG_FUNC_CALLED(p15card->card->ctx);

	token_algos = p15card->tokeninfo->supported_algos;
	count = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, objs,
			sizeof(objs) / sizeof(objs[0]));
	if (count < 0)
		LOG_FUNC_RETURN(p15card->card->ctx, count);

	for (i = 0; i < count; i++) {
		struct sc_pkcs15_prkey_info *pkinfo = (struct sc_pkcs15_prkey_info *) objs[i]->data;
		unsigned int sign_usage = SC_PKCS15_PRKEY_USAGE_SIGN
			| SC_PKCS15_PRKEY_USAGE_NONREPUDIATION
			| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
		unsigned int decipher_usage = SC_PKCS15_PRKEY_USAGE_DECRYPT
			| SC_PKCS15_PRKEY_USAGE_UNWRAP;

		if (pkinfo->algo_refs[0] != 0)
			continue;

		for (j = 0; j < SC_MAX_SUPPORTED_ALGORITHMS && token_algos[j].reference; j++) {
			if ((pkinfo->usage & sign_usage)
					&& (token_algos[j].operations & SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE)) {
				pkinfo->algo_refs[0] = token_algos[j].reference;
				sc_log(p15card->card->ctx,
					"cardos: set algo_ref %u for signing key '%s'",
					token_algos[j].reference, objs[i]->label);
				break;
			}
			if ((pkinfo->usage & decipher_usage)
					&& (token_algos[j].operations & SC_PKCS15_ALGO_OP_DECIPHER)) {
				pkinfo->algo_refs[0] = token_algos[j].reference;
				sc_log(p15card->card->ctx,
					"cardos: set algo_ref %u for decipher key '%s'",
					token_algos[j].reference, objs[i]->label);
				break;
			}
		}
	}

	LOG_FUNC_RETURN(p15card->card->ctx, SC_SUCCESS);
}


static int
sc_pkcs15emu_cardos_init(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	sc_card_t *card = p15card->card;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = sc_pkcs15_bind_internal(p15card, aid);
	LOG_TEST_RET(card->ctx, r, "sc_pkcs15_bind_internal failed");

	/* CardOS V5.x defers algorithm setup until tokenInfo is available */
	sc_log(card->ctx, " card->algorithms:%p card->algorithm_count:%d", card->algorithms, card->algorithm_count);
	if (!card->algorithms && card->algorithm_count == 0) {
		r = cardos_fix_token_info(p15card);
		LOG_TEST_RET(card->ctx, r, "cardos_fix_token_info failed");
	}

	r = cardos_fixup_prkey_algo_refs(p15card);
	LOG_TEST_RET(card->ctx, r, "cardos_fixup_prkey_algo_refs failed");

	LOG_FUNC_RETURN(card->ctx, r);
}


int
sc_pkcs15emu_cardos_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	if (cardos_pkcs15emu_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_cardos_init(p15card, aid);
}
