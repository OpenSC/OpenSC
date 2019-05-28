/*
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
/* Initially written by Weitao Sun (weitao@ftsafe.com) 2008*/

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15.h"
#include "cardctl.h"

#define MANU_ID		"entersafe"

static int entersafe_detect_card( sc_pkcs15_card_t *p15card)
{
	sc_card_t *card = p15card->card;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* check if we have the correct card OS */
	if (strcmp(card->name, "entersafe"))
		return SC_ERROR_WRONG_CARD;

    return SC_SUCCESS;
}

static int sc_pkcs15emu_entersafe_init( sc_pkcs15_card_t *p15card)
{
	int    r;
	char   buf[256];
	sc_card_t *card = p15card->card;
	sc_serial_number_t serial;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	/* get serial number */
	r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	r = sc_bin_to_hex(serial.value, serial.len, buf, sizeof(buf), 0);
	if (r != SC_SUCCESS)
		return SC_ERROR_INTERNAL;
	if (p15card->tokeninfo->serial_number)
		free(p15card->tokeninfo->serial_number);
	p15card->tokeninfo->serial_number = strdup(buf);
	if (!p15card->tokeninfo->serial_number)
		return SC_ERROR_INTERNAL;

	/* the manufacturer ID, in this case Giesecke & Devrient GmbH */
	if (p15card->tokeninfo->manufacturer_id)
		free(p15card->tokeninfo->manufacturer_id);
	p15card->tokeninfo->manufacturer_id = strdup(MANU_ID);
	if (!p15card->tokeninfo->manufacturer_id)
		return SC_ERROR_INTERNAL;

	return SC_SUCCESS;
}

int sc_pkcs15emu_entersafe_init_ex(sc_pkcs15_card_t *p15card,
				   struct sc_aid *aid)
{
	SC_FUNC_CALLED(p15card->card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (entersafe_detect_card(p15card))
		return SC_ERROR_WRONG_CARD;
	return sc_pkcs15emu_entersafe_init(p15card);
}
