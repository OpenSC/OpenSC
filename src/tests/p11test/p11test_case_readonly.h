/*
 * p11test_case_readonly.h: Sign & Verify tests
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

#include "p11test_case_common.h"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>

#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying.\n"
#define BUFFER_SIZE		4096

void readonly_tests(void **state);
int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech);
int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech, CK_ULONG message_length);

