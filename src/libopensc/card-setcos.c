/*
 * card-setec.c: Support for PKI cards by Setec
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

static const char *setec_atrs[] = {
	/* the current FINEID card has this ATR: */
	"3B:9F:94:40:1E:00:67:11:43:46:49:53:45:10:52:66:FF:81:90:00",
	/* this is from a Nokia branded SC */
	"3B:1F:11:00:67:80:42:46:49:53:45:10:52:66:FF:81:90:00",
	NULL
};

static struct sc_card_operations setec_ops;
static const struct sc_card_driver setec_drv = {
	NULL,
	"Setec smartcards",
	"setec",
	&setec_ops
};

static int setec_finish(struct sc_card *card)
{
	return 0;
}

static int setec_match_card(struct sc_card *card)
{
	int i, match = -1;

	for (i = 0; setec_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = setec_atrs[i];

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

static int setec_init(struct sc_card *card)
{
	card->ops_data = NULL;
	card->cla = 0x00;

	return 0;
}

static const struct sc_card_operations *iso_ops = NULL;

static int setec_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_file tmp;
	
	tmp = *file;
	memcpy(tmp.prop_attr, "\x03\x00\x00", 3);
	tmp.prop_attr_len = 3;
	return iso_ops->create_file(card, &tmp);
}

static int setec_set_security_env(struct sc_card *card,
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
		if (tmp.algorithm_flags & SC_ALGORITHM_RSA_PKCS1_PAD)
			tmp.algorithm_ref = 0x02;
		if (tmp.algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
                        tmp.algorithm_ref |= 0x10;
                return iso_ops->set_security_env(card, &tmp, se_num);

	}
        return iso_ops->set_security_env(card, env, se_num);
}

static const struct sc_card_driver * sc_get_driver(void)
{
	const struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	setec_ops = *iso_drv->ops;
	setec_ops.match_card = setec_match_card;
	setec_ops.init = setec_init;
        setec_ops.finish = setec_finish;
	if (iso_ops == NULL)
                iso_ops = iso_drv->ops;
	setec_ops.create_file = setec_create_file;
	setec_ops.set_security_env = setec_set_security_env;
	
        return &setec_drv;
}

#if 1
const struct sc_card_driver * sc_get_setec_driver(void)
{
	return sc_get_driver();
}
#endif
