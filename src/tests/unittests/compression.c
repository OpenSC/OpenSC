/*
 * compression.c: Unit tests for compression API
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "torture.h"
#include "libopensc/log.c"
#include "libopensc/compression.c"

/* The data from fuzzer has valid header (0x1f, 0x8b), but anything
 * after that is just garbage. The first call to inflate()
 * returns Z_STREAM_END, calculated number of processed bytes 0, while
 * keeping the allocated buffers.
 */
u8 invalid_data[] = {
	0x1f, 0x8b, 0x08, 0x10, 0x08, 0x78, 0x10, 0x1f,
	0x8b, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x8b, 0x08,
	0x10, 0x08, 0x78, 0x10, 0x1f, 0x8b, 0x08, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1f, 0x8b, 0x08, 0x10, 0x08, 0x78,
	0x10, 0x1f, 0x8b, 0x08, 0x61, 0x61, 0x61, 0x61,
	0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
	0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
	0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x08, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1f, 0x8b, 0x08, 0x10, 0x08, 0x78,
	0x10, 0x1f, 0x8b};

/* Generated using
 * $ echo "test" > /tmp/test
 * $ gzip -c /tmp/test  > /tmp/test.gz
 * $ hexdump -C /tmp/test.gz
 */
u8 valid_data[] = {
	0x1f, 0x8b, 0x08, 0x08, 0x5d, 0xd8, 0xcb, 0x5d,
	0x00, 0x03, 0x74, 0x65, 0x73, 0x74, 0x00, 0x2b,
	0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00, 0xc6, 0x35,
	0xb9, 0x3b, 0x05, 0x00, 0x00, 0x00};

/* Generated as in the previous test case with some added mess on the end
 */
u8 invalid_suffix_data[] = {
	0x1f, 0x8b, 0x08, 0x08, 0x5d, 0xd8, 0xcb, 0x5d,
	0x00, 0x03, 0x74, 0x65, 0x73, 0x74, 0x00, 0x2b,
	0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00, 0xc6, 0x35,
	0xb9, 0x3b, 0x05, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff};

/* https://github.com/madler/zlib/blob/master/test/infcover.c
 */
u8 zlib_good[] = {0x78, 0x9c, 0x63, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1};

/* Generated using
 * $ echo "test" > /tmp/test
 * $ pigz --zlib /tmp/test  > /tmp/test.zz
 * $ hexdump -C /tmp/test.zz
 */
u8 valid_zlib_data[] = {0x78, 0x5e, 0x2b, 0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00, 0x06, 0x28, 0x01, 0xcb};

/* Generated as in the previous test case with some added mess on the end
 */
u8 invalid_zlib_suffix_data[] = {0x78, 0x5e, 0x2b, 0x49, 0x2d, 0x2e, 0xe1, 0x02, 0x00, 0x06, 0x28, 0x01, 0xcb,
	0xff, 0xff, 0xff, 0xff};

static void torture_compression_decompress_alloc_empty(void **state)
{
	u8 *buf = NULL;
	u8 *data = NULL;
	size_t buflen = 0;
	size_t datalen = 0;
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_gzip_empty(void **state)
{
	u8 *buf = NULL;
	u8 *data = NULL;
	size_t buflen = 0;
	size_t datalen = 0;
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, data, datalen, COMPRESSION_GZIP);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_zlib_empty(void **state)
{
	u8 *buf = NULL;
	u8 *data = NULL;
	size_t buflen = 0;
	size_t datalen = 0;
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, data, datalen, COMPRESSION_ZLIB);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_header(void **state)
{
	u8 *buf = NULL;
	u8 data[] = {0x1f, 0x8b};
	size_t buflen = 0;
	size_t datalen = sizeof(data);
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_header_invalid(void **state)
{
	u8 *buf = NULL;
	u8 data[] = {0x1e, 0x8a};
	size_t buflen = 0;
	size_t datalen = sizeof(data);
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_invalid(void **state)
{
	u8 *buf = NULL;
	size_t buflen = 0;
	size_t datalen = sizeof(invalid_data);
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, invalid_data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
	assert_null(buf);
}

static void torture_compression_decompress_alloc_valid(void **state)
{
	u8 *buf = NULL;
	size_t buflen = 0;
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, valid_data, sizeof(valid_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);

	rv = sc_decompress_alloc(&buf, &buflen, valid_zlib_data, sizeof(valid_zlib_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);
}

static void torture_compression_decompress_alloc_invalid_suffix(void **state)
{
	u8 *buf = NULL;
	size_t buflen = 0;
	int rv;

	rv = sc_decompress_alloc(&buf, &buflen, invalid_suffix_data, sizeof(invalid_suffix_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS); /* TODO Is this fine? */
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);

	rv = sc_decompress_alloc(&buf, &buflen, invalid_zlib_suffix_data, sizeof(invalid_zlib_suffix_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS); /* TODO Is this fine? */
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);
}



/* Decompress without allocation */
static void torture_compression_decompress_empty(void **state)
{
	u8 buf[1024];
	u8 *data = NULL;
	size_t buflen = sizeof(buf);
	size_t datalen = 0;
	int rv;

	rv = sc_decompress(buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, sizeof(buf)); /* not touched */
}

static void torture_compression_decompress_gzip_empty(void **state)
{
	u8 buf[1024];
	u8 *data = NULL;
	size_t buflen = sizeof(buf);
	size_t datalen = 0;
	int rv;

	rv = sc_decompress(buf, &buflen, data, datalen, COMPRESSION_GZIP);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, sizeof(buf)); /* not touched */
}

static void torture_compression_decompress_zlib_empty(void **state)
{
	u8 buf[1024];
	u8 *data = NULL;
	size_t buflen = sizeof(buf);
	size_t datalen = 0;
	int rv;

	rv = sc_decompress(buf, &buflen, data, datalen, COMPRESSION_ZLIB);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, sizeof(buf)); /* not touched */
}

static void torture_compression_decompress_header(void **state)
{
	u8 buf[1024];
	u8 data[] = {0x1f, 0x8b};
	size_t buflen = sizeof(buf);
	size_t datalen = sizeof(data);
	int rv;

	rv = sc_decompress(buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
}

static void torture_compression_decompress_header_invalid(void **state)
{
	u8 buf[1024];
	u8 data[] = {0x1e, 0x8a};
	size_t buflen = sizeof(buf);
	size_t datalen = sizeof(data);
	int rv;

	rv = sc_decompress(buf, &buflen, data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
}

static void torture_compression_decompress_invalid(void **state)
{
	u8 buf[1024];
	size_t buflen = sizeof(buf);
	size_t datalen = sizeof(invalid_data);
	int rv;

	rv = sc_decompress(buf, &buflen, invalid_data, datalen, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	assert_int_equal(buflen, 0);
}

static void torture_compression_decompress_valid(void **state)
{
	u8 buf[1024];
	size_t buflen = sizeof(buf);
	int rv;

	rv = sc_decompress(buf, &buflen, valid_data, sizeof(valid_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);

	rv = sc_decompress(buf, &buflen, valid_zlib_data, sizeof(valid_zlib_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);
}

static void torture_compression_decompress_invalid_suffix(void **state)
{
	u8 buf[1024];
	size_t buflen = sizeof(buf);
	int rv;

	rv = sc_decompress(buf, &buflen, invalid_suffix_data, sizeof(invalid_suffix_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS); /* TODO Is this fine? */
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);

	rv = sc_decompress(buf, &buflen, invalid_zlib_suffix_data, sizeof(invalid_zlib_suffix_data), COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS); /* TODO Is this fine? */
	assert_int_equal(buflen, 5);
	assert_memory_equal(buf, "test\x0a", 5);
}

static void torture_compression_decompress_zlib_good(void **state)
{
	u8 buf[1024];
	size_t buflen;
	int rv;

	buflen = sizeof(buf);
	rv = sc_decompress(buf, &buflen, zlib_good, sizeof zlib_good, COMPRESSION_AUTO);
	assert_int_equal(rv, SC_SUCCESS);
}



int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		/* Decompress alloc */
		cmocka_unit_test(torture_compression_decompress_alloc_empty),
		cmocka_unit_test(torture_compression_decompress_alloc_gzip_empty),
		cmocka_unit_test(torture_compression_decompress_alloc_zlib_empty),
		cmocka_unit_test(torture_compression_decompress_alloc_header),
		cmocka_unit_test(torture_compression_decompress_alloc_header_invalid),
		cmocka_unit_test(torture_compression_decompress_alloc_invalid),
		cmocka_unit_test(torture_compression_decompress_alloc_invalid_suffix),
		cmocka_unit_test(torture_compression_decompress_alloc_valid),
		/* Decompress */
		cmocka_unit_test(torture_compression_decompress_empty),
		cmocka_unit_test(torture_compression_decompress_gzip_empty),
		cmocka_unit_test(torture_compression_decompress_zlib_empty),
		cmocka_unit_test(torture_compression_decompress_header),
		cmocka_unit_test(torture_compression_decompress_header_invalid),
		cmocka_unit_test(torture_compression_decompress_invalid),
		cmocka_unit_test(torture_compression_decompress_invalid_suffix),
		cmocka_unit_test(torture_compression_decompress_valid),
		cmocka_unit_test(torture_compression_decompress_zlib_good),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
