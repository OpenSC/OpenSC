/*
 * module.c: Dynamic linking loader
 *
 * Copyright (C) 2002  Antti Tapaninen <aet@cc.hut.fi>
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <opensc/scdl.h>

int sc_module_open(struct sc_context *ctx, void **mod_handle, const char *filename)
{
	void *handle;

	assert(ctx != NULL);

	if (!filename)
		return SC_ERROR_UNKNOWN;

	handle = scdl_open(filename);

	if (handle == NULL) {
		if (ctx->debug)
			/* TODO: scdl_error */
			sc_debug(ctx, "sc_module_open: unknown error");
		return SC_ERROR_UNKNOWN;
	}
	*mod_handle = handle;
	return SC_SUCCESS;
}

int sc_module_close(struct sc_context *ctx, void *mod_handle)
{
	assert(ctx != NULL);

	if (!mod_handle)
		return SC_ERROR_UNKNOWN;

	scdl_close(mod_handle);
	return SC_SUCCESS;
}

int sc_module_get_address(struct sc_context *ctx, void *mod_handle, void **sym_address, const char *sym_name)
{
	void *address;

	assert(ctx != NULL);

	if (!mod_handle || !sym_name)
		return SC_ERROR_UNKNOWN;

	address = scdl_get_address(mod_handle, sym_name);

	if (address == NULL) {
		if (ctx->debug)
			/* TODO: scdl_error */
			sc_debug(ctx, "sc_module_get_address: unknown error");
		return SC_ERROR_UNKNOWN;
	}
	*sym_address = address;
	return SC_SUCCESS;
}
