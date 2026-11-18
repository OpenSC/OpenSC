/*
 * decode_ecdsa_signature.c: Unit tests for decode ASN.1 ECDSA signature
 *
 * Copyright (C) 2022 Red Hat, Inc.
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

#include "torture.h"
#include "libopensc/log.c"
#include "libopensc/asn1.c"
#include <cmocka.h>

static int setup(void **state)
{
	struct sc_context *ctx = NULL;

	sc_establish_context(&ctx, "test");
	*state = ctx;
	return 0;
}

static int teardown(void **state)
{
	struct sc_context *ctx = *state;

	sc_release_context(ctx);

	return 0;
}

static void torture_empty_rs(void **state)
{
	int r = 0;
	size_t fieldsize = 24;
	struct sc_context *ctx = *state;
	u8 *out = malloc(48);
	u8 data[] = {0x30, 0x04, 0x02, 0x00, 0x02, 0x00};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 48);
	free(out);
	assert_int_equal(r, SC_ERROR_INVALID_DATA);
}

static void torture_valid_format(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 result[] = {0x03, 0x04};
	u8 data[] = {0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, 2 * fieldsize);
	assert_memory_equal(result, out, sizeof(result));
	free(out);
}

static void torture_valid_format_leading00(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 result[] = {0x03, 0x04};
	u8 data[] = {0x30, 0x07, 0x02, 0x02, 0x00, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, 2 * fieldsize);
	assert_memory_equal(result, out, sizeof(result));
	free(out);
}

static void torture_valid_format_long_fieldsize(void **state)
{
	int r = 0;
	size_t fieldsize = 3;
	struct sc_context *ctx = *state;
	u8 *out = malloc(6);
	u8 result[] = {0x00, 0x00, 0x03, 0x00, 0x00, 0x04};
	u8 data[] = {0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 6);

	assert_int_equal(r, 2 * fieldsize);
	assert_memory_equal(result, out, sizeof(result));
	free(out);
}

static void torture_wrong_tag_len(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 data[] = {0x30, 0x05, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}

static void torture_wrong_integer_tag_len(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 data[] = {0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x02, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}

static void torture_small_fieldsize(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(3);
	u8 data[] = {0x30, 0x07, 0x02, 0x01, 0x03, 0x02, 0x02, 0x04, 0x05};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 3);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}

static void torture_long_leading00(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(3);
	u8 data[] = {0x30, 0x08, 0x02, 0x03, 0x00, 0x00, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 3);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}

static void torture_missing_tag(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 data[] = {0x20, 0x07, 0x02, 0x01, 0x03, 0x02, 0x02, 0x04, 0x05};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}


static void torture_missing_integer_tag(void **state)
{
	int r = 0;
	size_t fieldsize = 1;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 data[] = {0x30, 0x07, 0x01, 0x01, 0x03, 0x02, 0x02, 0x04, 0x05};

	if (!out)
		return;

	r = sc_asn1_decode_ecdsa_signature(ctx, data, sizeof(data), fieldsize, &out, 2);

	assert_int_equal(r, SC_ERROR_INVALID_DATA);
	free(out);
}

static void
torture_sequence_to_rs(void **state)
{
	int r = 0;
	struct sc_context *ctx = *state;
	u8 *out = malloc(2);
	u8 result[] = {0x03, 0x04};
	const u8 data[] = {0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x04};

	if (!out)
		return;

	r = sc_asn1_sig_value_sequence_to_rs(ctx, data, sizeof(data), out, 2);

	assert_int_equal(r, sizeof(result));
	assert_memory_equal(result, out, sizeof(result));
	free(out);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test_setup_teardown(torture_empty_rs, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_valid_format, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_valid_format_leading00, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_valid_format_long_fieldsize, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_wrong_tag_len, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_wrong_integer_tag_len, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_small_fieldsize, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_long_leading00, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_missing_tag, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_missing_integer_tag, setup, teardown),
			cmocka_unit_test_setup_teardown(torture_sequence_to_rs, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

