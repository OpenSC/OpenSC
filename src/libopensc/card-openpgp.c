/*
 * card-pgp.c: Support for OpenPGP card
 *
 * Copyright (C) 2003  Olaf Kirch <okir@suse.de>
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
#include "asn1.h"
#include "cardctl.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *pgp_atrs[] = {
	"3b:fa:13:00:ff:81:31:80:45:00:31:c1:73:c0:01:00:00:90:00:b1",
	NULL
};

static struct sc_card_operations *iso_ops;
static struct sc_card_operations pgp_ops;
static struct sc_card_driver pgp_drv = {
	"OpenPGP Card",
	"openpgp",
	&pgp_ops
};

#define DRVDATA(card)        ((struct pgp_priv_data *) ((card)->drv_data))
struct pgp_priv_data {
	int dummy;
};

static int
pgp_match_card(sc_card_t *card)
{
	int i, match = -1;

	for (i = 0; pgp_atrs[i] != NULL; i++) {
		u8 defatr[SC_MAX_ATR_SIZE];
		size_t len = sizeof(defatr);
		const char *atrp = pgp_atrs[i];

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

static int
pgp_init(sc_card_t *card)
{
        unsigned long flags;
        struct pgp_priv_data *priv;

	priv = (struct pgp_priv_data *) calloc (1, sizeof *priv);
	if (!priv)
		return SC_ERROR_OUT_OF_MEMORY;
	card->name = "OpenPGP";
	card->drv_data = priv;
	card->cla = 0x00;

        flags = SC_ALGORITHM_RSA_RAW;
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
        flags |= SC_ALGORITHM_RSA_HASH_NONE;

        _sc_card_add_rsa_alg(card, 512, flags, 0);
        _sc_card_add_rsa_alg(card, 768, flags, 0);
        _sc_card_add_rsa_alg(card, 1024, flags, 0);

	return 0;
}

static int
pgp_finish(sc_card_t *card)
{
        struct pgp_priv_data *priv;

        if (card == NULL)
                return 0;
	priv = DRVDATA (card);

	free(priv);
	return 0;
}

/*
 * The OpenPGP card doesn't have a file system; we use GET/PUT DATA
 * instead.
 */
static int
pgp_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t buf_len)
{
	sc_apdu_t	apdu;
	int		r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
				0xCA, tag >> 8, tag);
	apdu.le = (buf_len <= 255)? buf_len : 256;
	apdu.resp = buf;
	apdu.resplen = buf_len;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	SC_TEST_RET(card->ctx, r, "Card returned error");

	return apdu.resplen;
}

static int
pgp_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t buf_len)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_pin_cmd(sc_card_t *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	if (data->pin_type != SC_AC_CHV)
		return SC_ERROR_INVALID_ARGUMENTS;

	data->pin_reference |= 0x80;

	return iso_ops->pin_cmd(card, data, tries_left);
}

static int
pgp_set_security_env(sc_card_t *card,
		const struct sc_security_env *env, int se_num)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_compute_signature(sc_card_t *card, const u8 *data,
                size_t data_len, u8 * out, size_t outlen)
{
	return SC_ERROR_NOT_SUPPORTED;
}

static int
pgp_logout(sc_card_t *card)
{
	sc_error(card->ctx, "OpenPGP card: logout not supported\n");
	return SC_ERROR_NOT_SUPPORTED;
}

/* Driver binding stuff */
static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	iso_ops = iso_drv->ops;

	pgp_ops = *iso_ops;
	pgp_ops.match_card = pgp_match_card;
	pgp_ops.init	   = pgp_init;
        pgp_ops.finish	   = pgp_finish;
	pgp_ops.pin_cmd	   = pgp_pin_cmd;
	pgp_ops.get_data   = pgp_get_data;
	pgp_ops.put_data   = pgp_put_data;
        pgp_ops.set_security_env = pgp_set_security_env;
        pgp_ops.compute_signature = pgp_compute_signature;
	pgp_ops.logout	   = pgp_logout;

        return &pgp_drv;
}

struct sc_card_driver *
sc_get_openpgp_driver(void)
{
	return sc_get_driver();
}
