/*
 * p11test_helpers.h: Test suite for PKCS#11 API: Supporting functions
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

#ifndef P11TEST_HELPERS_H
#define P11TEST_HELPERS_H
#include "p11test_common.h"

int group_setup(void **state);
int group_teardown(void **state);

int user_login_setup(void **state);
int after_test_cleanup(void **state);

int token_setup(void **state);
int token_cleanup(void **state);

int token_initialize(void **state);
#endif //P11TEST_HELPERS_H
