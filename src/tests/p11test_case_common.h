/*
 * p11test_case_common.h: Functions shared between test caess.
 *
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

#ifndef P11TEST_CASE_COMMON_H
#define P11TEST_CASE_COMMON_H

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "p11test_common.h"

typedef struct {
	char	*key_id;
	CK_ULONG key_id_size;
	char	*id_str;
	X509	*x509;
	int		 type;
	union {
		RSA		*rsa;
		EC_KEY	*ec;
	} key;
	CK_OBJECT_HANDLE private_handle;
	CK_OBJECT_HANDLE public_handle;
	CK_BBOOL	sign;
	CK_BBOOL	decrypt;
	CK_BBOOL	verify;
	CK_BBOOL	encrypt;
	CK_KEY_TYPE	key_type;
	CK_BBOOL	always_auth;
	char		*label;
	CK_ULONG 	 bits;
	int			verify_public;
	test_mech_t	mechs[MAX_MECHS];
	int			num_mechs;
} test_cert_t;

typedef struct {
	unsigned int count;
	test_cert_t *data;
} test_certs_t;

int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned int, CK_OBJECT_HANDLE));
void search_for_all_objects(test_certs_t *objects, token_info_t *info);
void clean_all_objects(test_certs_t *objects);

const char *get_mechanism_name(int mech_id);
const char *get_mechanism_flag_name(int flag_id);
char *convert_byte_string(char *id, unsigned long length);

#endif /* P11TEST_CASE_COMMON_H */
