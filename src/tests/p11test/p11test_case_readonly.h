/*
 * p11test_case_readonly.h: Sign & Verify tests
 *
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

#include "p11test_case_common.h"

void readonly_tests(void **state);
int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
    CK_ULONG message_length, int multipart);
int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech,
    CK_ULONG message_length, int multipart);

int verify_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char *sign,
    CK_ULONG sign_length, int multipart);
int sign_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **sign,
    int multipart);
int encrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *message,
    CK_ULONG message_length, test_mech_t *mech, unsigned char **enc_message);
int decrypt_message(test_cert_t *o, token_info_t *info, CK_BYTE *enc_message,
    CK_ULONG enc_message_length, test_mech_t *mech, unsigned char **dec_message);

unsigned char *rsa_x_509_pad_message(const unsigned char *message, unsigned long *message_length,
		test_cert_t *o, int encrypt);
