/*
 * reader-quirks.c: Reader quirks
 *
 * Copyright (C) 2014  Javier Serrano Polo <javier@jasp.net>
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

#include "config.h"

#include <string.h>

#include "log.h"
#include "opensc.h"
#include "pkcs15.h"
#include "reader-quirks.h"

static int _vendor_specific_problem(struct sc_reader *reader,
                                    struct sc_pkcs15_auth_info *pkcs15_pin_info)
{
	int id_vendor;
	int id_product;

	if (!reader->ops || !reader->ops->get_vendor_product)
		return 0;

	if (reader->ops->get_vendor_product(reader, &id_vendor, &id_product) != SC_SUCCESS)
		return 0;

	/* Dell Smart Card Reader Keyboard */
	if (id_vendor == 0x413c && id_product == 0x2101
	    && !(pkcs15_pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_NEEDS_PADDING))
		return 1;

	return 0;
}

int sc_reader_can_handle_pin(struct sc_reader *reader,
                             struct sc_pkcs15_auth_info *pkcs15_pin_info)
{
	struct sc_context *ctx = reader->ctx;

	if (!(reader->capabilities & SC_READER_CAP_PIN_PAD))
		return 0;

	if (!(reader->flags & SC_READER_AUTO_PIN_PAD))
		return 1;

	if (!pkcs15_pin_info)
		return 1;

	if (pkcs15_pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;

	if (_vendor_specific_problem(reader, pkcs15_pin_info)) {
		sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "reader cannot handle this PIN");
		return 0;
	}

	return 1;
}
