/*
 * base64.c: Unit tests for Base64 encoding and decoding
 *
 * Copyright (C) 2024 Red Hat, Inc.
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

#include "common/compat_strlcpy.c"
#include "libopensc/log.c"
#include "libopensc/padding.c"
#include "torture.h"
#include <cmocka.h>

static void
torture_encode_short_length(void **state)
{
	u8 data[] = "ew";
	size_t data_len = 2;
	u8 buf[6] = {0};
	size_t buf_len = 6;
	u8 expected[] = "ZXc=\n";
	size_t expected_size = 6;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	assert_int_equal(r, SC_SUCCESS);
	assert_memory_equal(buf, expected, expected_size);
}

static void
torture_encode_data(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[18] = {0};
	size_t buf_len = 18;
	u8 expected[] = "SGVsbG8gV29ybGQ=\n";
	size_t expected_size = 18;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	assert_int_equal(r, SC_SUCCESS);
	assert_memory_equal(buf, expected, expected_size);
}

static void
torture_encode_more_lines(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[21] = {0};
	size_t buf_len = 21;
	u8 expected[] = "SGVs\nbG8g\nV29y\nbGQ=\n";
	size_t expected_size = 21;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 4);
	assert_int_equal(r, SC_SUCCESS);
	assert_memory_equal(buf, expected, expected_size);
}

static void
torture_encode_small_out_length_for_lines(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[18] = {0};
	size_t buf_len = 18;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 4);
	assert_int_equal(r, SC_ERROR_BUFFER_TOO_SMALL);
}

static void
torture_encode_small_out_length_for_last_foursome(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[15] = {0};
	size_t buf_len = 15;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	assert_int_equal(r, SC_ERROR_BUFFER_TOO_SMALL);
}

static void
torture_encode_small_out_length_for_last_newline(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[16] = {0};
	size_t buf_len = 16;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	assert_int_equal(r, SC_ERROR_BUFFER_TOO_SMALL);
}

static void
torture_encode_small_out_length_for_last_0(void **state)
{
	u8 data[] = "Hello World";
	size_t data_len = 11;
	u8 buf[17] = {0};
	size_t buf_len = 17;
	int r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	assert_int_equal(r, SC_ERROR_BUFFER_TOO_SMALL);
}

static void
torture_decode_short_data(void **state)
{
	char data[] = "SGVsbG8gV29ybGQ=";
	u8 buf[11] = {0};
	size_t buf_len = 11;
	u8 expected[] = "Hello World";
	size_t expected_size = 11;
	int actual_size = sc_base64_decode(data, buf, buf_len);
	assert_int_equal(actual_size, expected_size);
	assert_memory_equal(buf, expected, expected_size);
}

static void
torture_decode_skip_newline_inside(void **state)
{
	char data[] = "SG\nVsbG8gV29ybGQ=";
	u8 buf[11] = {0};
	size_t buf_len = 11;
	u8 expected[] = "Hello World";
	size_t expected_size = 11;
	int actual_size = sc_base64_decode(data, buf, buf_len);
	assert_int_equal(actual_size, expected_size);
	assert_memory_equal(buf, expected, expected_size);
}

static void
torture_decode_zero_byte_early_finish(void **state)
{
	char data[] = "\0GVsbG8gV29ybGQ=";
	u8 buf[11] = {0};
	size_t buf_len = 11;
	int error = sc_base64_decode(data, buf, buf_len);
	assert_int_equal(error, 0);
}

static void
torture_decode_non_ascii_character(void **state)
{
	char data[] = "SG\x11sbG8gV29ybGQ=";
	u8 buf[11] = {0};
	size_t buf_len = 11;
	int error = sc_base64_decode(data, buf, buf_len);
	assert_int_equal(error, SC_ERROR_INVALID_ARGUMENTS);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(torture_encode_short_length),
			cmocka_unit_test(torture_encode_data),
			cmocka_unit_test(torture_encode_more_lines),
			cmocka_unit_test(torture_encode_small_out_length_for_lines),
			cmocka_unit_test(torture_encode_small_out_length_for_last_foursome),
			cmocka_unit_test(torture_encode_small_out_length_for_last_newline),
			cmocka_unit_test(torture_encode_small_out_length_for_last_0),
			cmocka_unit_test(torture_decode_short_data),
			cmocka_unit_test(torture_decode_skip_newline_inside),
			cmocka_unit_test(torture_decode_zero_byte_early_finish),
			cmocka_unit_test(torture_decode_non_ascii_character)};
	return cmocka_run_group_tests(tests, NULL, NULL);
}