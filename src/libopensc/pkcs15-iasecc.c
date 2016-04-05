/*
 * PKCS15 emulation layer for IAS/ECC card.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef ENABLE_OPENSSL
#include <openssl/x509v3.h>
#endif

#include "internal.h"
#include "pkcs15.h"

int sc_pkcs15emu_iasecc_init_ex(sc_pkcs15_card_t *, struct sc_aid *, sc_pkcs15emu_opt_t *);


static int
sc_pkcs15emu_iasecc_init (struct sc_pkcs15_card *p15card, struct sc_aid *aid)
{
	struct sc_context *ctx = p15card->card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);

	rv = sc_pkcs15_bind_internal(p15card, aid);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_detect_card(sc_pkcs15_card_t *p15card)
{
	if (p15card->card->type < SC_CARD_TYPE_IASECC_BASE)
		return SC_ERROR_WRONG_CARD;

	if (p15card->card->type > SC_CARD_TYPE_IASECC_BASE + 10)
		return SC_ERROR_WRONG_CARD;

	return SC_SUCCESS;
}


int
sc_pkcs15emu_iasecc_init_ex(struct sc_pkcs15_card *p15card, struct sc_aid *aid, struct sc_pkcs15emu_opt *opts)
{
	if (opts && opts->flags & SC_PKCS15EMU_FLAGS_NO_CHECK)
		return sc_pkcs15emu_iasecc_init(p15card, aid);

	if (iasecc_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;

	return sc_pkcs15emu_iasecc_init(p15card, aid);
}
