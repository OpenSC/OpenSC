/*
 * p11test_common.h: Test suite shared declarations for PKCS#11 API
 *
 * Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>
 * Copyright (C) 2016 Red Hat, Inc.
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

#ifndef P11TEST_COMMON_H
#define P11TEST_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "pkcs11/pkcs11.h"

#define MAX_MECHS 30

#ifdef NDEBUG
	#define debug_print(fmt, ...) \
		{ fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
	#define debug_print(fmt, ...)
#endif

#define FLAGS_VERIFY_SIGN		0x02
#define FLAGS_VERIFY_DECRYPT	0x04

typedef struct {
	CK_MECHANISM_TYPE mech;
	int flags;
} test_mech_t;

typedef struct {
	CK_FUNCTION_LIST_PTR function_pointer;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session_handle;
	CK_UTF8CHAR* pin;
	size_t pin_length;
	char* library_path;
	unsigned int interactive;

	test_mech_t rsa_mechs[MAX_MECHS];
	size_t  num_rsa_mechs;
	test_mech_t	ec_mechs[MAX_MECHS];
	size_t  num_ec_mechs;
	test_mech_t	keygen_mechs[MAX_MECHS];
	size_t  num_keygen_mechs;
} token_info_t;

token_info_t token;

#endif /* P11TEST_COMMON_H */

