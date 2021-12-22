/*
 * p11test_common.h: Test suite shared declarations for PKCS#11 API
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

#ifndef P11TEST_COMMON_H
#define P11TEST_COMMON_H
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "pkcs11/pkcs11.h"
#include "libopensc/sc-ossl-compat.h"

#define MAX_MECHS 200

#define debug_print(fmt, ...) \
	do { \
		if (debug_flag) { \
			fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
		} \
	} while (0)

#define FLAGS_SIGN		0x001
#define FLAGS_SIGN_OPENSSL	0x002
#define FLAGS_SIGN_ANY		( FLAGS_SIGN | FLAGS_SIGN_OPENSSL )
#define FLAGS_DECRYPT		0x004
#define FLAGS_DECRYPT_OPENSSL	0x008
#define FLAGS_DECRYPT_ANY	( FLAGS_DECRYPT | FLAGS_DECRYPT_OPENSSL )
#define FLAGS_DERIVE		0x010
#define FLAGS_WRAP		0x020
#define FLAGS_WRAP_SYM		0x040
#define FLAGS_UNWRAP		0x080
#define FLAGS_UNWRAP_SYM	0x100

typedef struct {
	char *outfile;
	FILE *fd;
	int in_test;
	int first;
	int in_data;
	int first_data;
} log_context_t;

typedef struct {
	CK_MECHANISM_TYPE mech;
	/* RSA-PSS parameters */
	CK_MECHANISM_TYPE hash;
	CK_RSA_PKCS_MGF_TYPE mgf;
	int salt;
	/* generic parameters used for example for secret keys */
	void *params;
	unsigned long params_len;
	int usage_flags;
	int result_flags;
} test_mech_t;

typedef struct {
	CK_FUNCTION_LIST_PTR function_pointer;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session_handle;
	CK_UTF8CHAR* pin;
	size_t pin_length;
	char *library_path;
	unsigned int interactive;
	log_context_t log;

	int verify_support;
	int encrypt_support;

	test_mech_t rsa_mechs[MAX_MECHS];
	size_t  num_rsa_mechs;
	test_mech_t	ec_mechs[MAX_MECHS];
	size_t  num_ec_mechs;
	test_mech_t	ed_mechs[MAX_MECHS];
	size_t  num_ed_mechs;
	test_mech_t	montgomery_mechs[MAX_MECHS];
	size_t  num_montgomery_mechs;
	test_mech_t	aes_mechs[MAX_MECHS];
	size_t  num_aes_mechs;
	test_mech_t	keygen_mechs[MAX_MECHS];
	size_t  num_keygen_mechs;
} token_info_t;

extern token_info_t token;
extern int debug_flag;

#endif /* P11TEST_COMMON_H */

