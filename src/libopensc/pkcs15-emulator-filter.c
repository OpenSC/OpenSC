/*
 * pkcs15-emulator-filter.c: PKCS #15 emulator filter
 *
 * Copyright (C) 2021 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"
#include "pkcs15-syn.h"
#include "pkcs15-emulator-filter.h"

static int add_emul(struct _sc_pkcs15_emulators* filtered_emulators,
					struct sc_pkcs15_emulator_handler* emul_handler)
{
	struct sc_pkcs15_emulator_handler** lst;
	int *cp, max, i;

	if (!filtered_emulators || !emul_handler || !emul_handler->name || !emul_handler->handler)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	lst = filtered_emulators->list_of_handlers;
	cp = &filtered_emulators->ccount;
	max = SC_MAX_PKCS15_EMULATORS;

	if (*cp > max)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (*cp == max)
		return SC_ERROR_TOO_MANY_OBJECTS;

	for (i = 0; i < *cp; i++) {
		if (!lst[i])
			return SC_ERROR_OBJECT_NOT_VALID;
		if (!strcmp(lst[i]->name, emul_handler->name))
			return SC_SUCCESS;
	}

	lst[*cp] = emul_handler;
	(*cp)++;
	return SC_SUCCESS;
}

static int add_emul_list(struct _sc_pkcs15_emulators* filtered_emulators,
						 struct sc_pkcs15_emulator_handler* emulators)
{
	struct sc_pkcs15_emulator_handler* lst;
	int i, r;

	if (!filtered_emulators || !emulators)
		return SC_ERROR_INVALID_ARGUMENTS;

	lst = emulators;
	for(i = 0; lst[i].name; i++) {
		if ((r = add_emul(filtered_emulators, &lst[i])))
			return r;
	}
	return SC_SUCCESS;
}

int set_emulators(sc_context_t *ctx, struct _sc_pkcs15_emulators* filtered_emulators, const scconf_list *list,
				  struct sc_pkcs15_emulator_handler* internal, struct sc_pkcs15_emulator_handler* old)
{
	const scconf_list *item;
	int *cp, i, r, count;
	
	LOG_FUNC_CALLED(ctx);

	if (!filtered_emulators || !list || !internal || !old)
		return SC_ERROR_INVALID_ARGUMENTS;

	cp = &filtered_emulators->ccount;
	r = SC_SUCCESS;

	for (item = list; item; item = item->next) {
		if (!item->data)
			continue;

		if (!strcmp(item->data, "internal")) {
			if ((r = add_emul_list(filtered_emulators, internal)))
				goto out;
		} else if (!strcmp(item->data, "old")) {
			if ((r = add_emul_list(filtered_emulators, old)))
				goto out;
		} else {
			count = *cp;
			for (i = 0; internal[i].name; i++) {
				if (!strcmp(internal[i].name, item->data)) {
					if ((r = add_emul(filtered_emulators, &internal[i])))
						goto out;
					break;
				}
			}
			for (i = 0; old[i].name && count == *cp; i++) {
				if (!strcmp(old[i].name, item->data)) {
					if ((r = add_emul(filtered_emulators, &old[i])))
						goto out;
					break;
				}
			}
			if (count == *cp)
				sc_log(ctx, "Warning: Trying to add non-existing emulator '%s'.", item->data);
		}
	}
out:
	if (r == SC_SUCCESS || r == SC_ERROR_TOO_MANY_OBJECTS) {
		filtered_emulators->list_of_handlers[*cp] = NULL;
		if (r == SC_ERROR_TOO_MANY_OBJECTS)
			sc_log(ctx, "Warning: Number of filtered emulators exceeded %d.", SC_MAX_PKCS15_EMULATORS);
	}
	LOG_FUNC_RETURN(ctx, r);
}
