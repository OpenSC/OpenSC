/*
 * pkcs15-emulator-filter.h: PKCS #15 emulator filter
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

struct _sc_pkcs15_emulators {
	struct sc_pkcs15_emulator_handler *list_of_handlers[SC_MAX_PKCS15_EMULATORS + 1];
	int ccount;
};

int set_emulators(sc_context_t *ctx, struct _sc_pkcs15_emulators* filtered_emulators, const scconf_list *list,
					struct sc_pkcs15_emulator_handler* builtin, struct sc_pkcs15_emulator_handler* old);
