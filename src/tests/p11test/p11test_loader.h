/*
 * p11test_loader.h: Library loader for PKCS#11 test suite
 *
 * Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>
 * Copyright (C) 2016, 2017 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#ifndef P11TEST_LOADER_H
#define P11TEST_LOADER_H

#include <dlfcn.h>
#include "p11test_helpers.h"

int load_pkcs11_module(token_info_t * info, const char* path_to_pkcs11_library);
int get_slot_with_card(token_info_t * info);
void close_pkcs11_module();


#endif //P11TEST_LOADER_H
