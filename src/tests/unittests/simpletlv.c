/*
 * asn1.c: Unit tests for SimpleTLV parser and encoder
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
#include "libopensc/sc.c"
#include "libopensc/simpletlv.c"

static void torture_simpletlv_read_tag_null(void **state)
{
	const u8 *data = NULL;
	size_t datalen = 0;
	u8 tag = 0;
	size_t taglen = 0;
	int rv;

	rv = sc_simpletlv_read_tag(&data, datalen, &tag, &taglen, SC_SIMPLETLV_LITTLE_ENDIAN);
	assert_int_equal(rv, SC_ERROR_INVALID_TLV_OBJECT);
	assert_int_equal(tag, 0);
	assert_int_equal(taglen, 0);
}

#define TORTURE_READ_TAG(name, data, tag_value, len_value, error) \
	static void torture_simpletlv_read_tag_##name(void **state) \
	{ \
		u8 buf[] = data; \
		const u8 *bufptr = buf; \
		size_t buflen = sizeof(buf) - 1; \
		u8 tag = 0; \
		size_t taglen = 0; \
		int rv; \
\
		rv = sc_simpletlv_read_tag(&bufptr, buflen, &tag, &taglen, SC_SIMPLETLV_LITTLE_ENDIAN); \
		assert_int_equal(rv, error); \
		assert_int_equal(tag, tag_value); \
		assert_int_equal(taglen, len_value); \
	}
#define TORTURE_READ_TAG_SUCCESS(name, data, tag_value, len_value) \
	TORTURE_READ_TAG(name, data, tag_value, len_value, SC_SUCCESS)
#define TORTURE_READ_TAG_ERROR(name, data, error) \
	TORTURE_READ_TAG(name, data, 0, 0, error)

TORTURE_READ_TAG_ERROR(short, "\x42", SC_ERROR_INVALID_TLV_OBJECT)
TORTURE_READ_TAG_SUCCESS(minimal,
	"\x42\x00", 0x42, 0)
TORTURE_READ_TAG_SUCCESS(minimal2,
	"\x42\x00", 0x42, 0)
TORTURE_READ_TAG_SUCCESS(valid_short,
	"\x42\x02\x01\x02", 0x42, 2)
TORTURE_READ_TAG_ERROR(incomplete_length,
	"\x42\xff", SC_ERROR_INVALID_TLV_OBJECT)
TORTURE_READ_TAG_SUCCESS(long_length,
	"\x42\xff\x00\x00", 0x42, 0)
TORTURE_READ_TAG(missing_data,
	"\x42\xff\x02\x00", 0x42, 2, SC_ERROR_TLV_END_OF_CONTENTS)
TORTURE_READ_TAG_SUCCESS(valid_long,
	"\x42\xff\x02\x00\x01\x02", 0x42, 2)

static void torture_simpletlv_put_tag_null(void **state)
{
	u8 *data = NULL;
	size_t datalen = 0;
	u8 *outptr = NULL;
	int rv;

	rv = sc_simpletlv_put_tag(0x42, 2, data, datalen, &outptr, SC_SIMPLETLV_LITTLE_ENDIAN);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	assert_null(outptr);
}

#define TORTURE_PUT_TAG(name, tag, taglen, data_len, exp_data, error) \
	static void torture_simpletlv_put_tag_##name(void **state) \
	{ \
		u8 data[data_len] = {}; \
		size_t datalen = sizeof(data); \
		u8 *outptr = NULL; \
		int rv; \
\
		rv = sc_simpletlv_put_tag(tag, taglen, data, datalen, &outptr, SC_SIMPLETLV_LITTLE_ENDIAN); \
		assert_int_equal(rv, error); \
		assert_memory_equal(data, exp_data, MIN(sizeof(data), sizeof(exp_data))); \
		if (rv == SC_SUCCESS) { \
			assert_non_null(outptr); \
		} else { \
			assert_null(outptr); \
		} \
	}
#define TORTURE_PUT_TAG_ERROR(name, tag, taglen, data_len, error) \
	TORTURE_PUT_TAG(name, tag, taglen, data_len, "", error)
#define TORTURE_PUT_TAG_SUCCESS(name, tag, taglen, data_len, exp_data) \
	TORTURE_PUT_TAG(name, tag, taglen, data_len, exp_data, SC_SUCCESS)

TORTURE_PUT_TAG_ERROR(too_small, 0x42, 2, 1, SC_ERROR_INVALID_ARGUMENTS)
TORTURE_PUT_TAG_SUCCESS(valid_short, 0x42, 2, 2, "\x42\x02")
TORTURE_PUT_TAG_ERROR(invalid_tag, 0x00, 2, 2, SC_ERROR_INVALID_ARGUMENTS)
TORTURE_PUT_TAG_ERROR(invalid_tag2, 0xff, 2, 2, SC_ERROR_INVALID_ARGUMENTS)
TORTURE_PUT_TAG_SUCCESS(max_short, 0x42, 0xfe, 2, "\x42\xfe")
TORTURE_PUT_TAG_ERROR(too_long_length, 0x42, 512, 3, SC_ERROR_INVALID_ARGUMENTS)
TORTURE_PUT_TAG_SUCCESS(valid_long, 0x42, 512, 4, "\x42\xff\x00\x02")
TORTURE_PUT_TAG_SUCCESS(first_long, 0x42, 0xff, 4, "\x42\xff\xff\x00")
TORTURE_PUT_TAG_SUCCESS(last_long, 0x42, 0xffff, 4, "\x42\xff\xff\xff")
TORTURE_PUT_TAG_ERROR(too_large_length, 0x42, 0x10000, 4, SC_ERROR_WRONG_LENGTH)

static void
torture_simpletlv_read_extended_byte_order(void **state)
{
	static const struct {
		u8 header[4];
		enum sc_simpletlv_byte_order byte_order;
		size_t length;
	} cases[] = {
			{{0x42, 0xff, 0xff, 0x00}, SC_SIMPLETLV_LITTLE_ENDIAN, 255  },
			{{0x42, 0xff, 0x00, 0xff}, SC_SIMPLETLV_BIG_ENDIAN,    255  },
			{{0x42, 0xff, 0x58, 0x02}, SC_SIMPLETLV_LITTLE_ENDIAN, 600  },
			{{0x42, 0xff, 0x02, 0x58}, SC_SIMPLETLV_BIG_ENDIAN,    600  },
			{{0x42, 0xff, 0xff, 0xff}, SC_SIMPLETLV_LITTLE_ENDIAN, 65535},
			{{0x42, 0xff, 0xff, 0xff}, SC_SIMPLETLV_BIG_ENDIAN,    65535},
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const u8 *ptr = cases[i].header;
		u8 tag = 0;
		size_t length = 0;
		int rv;

		/* A complete header still returns its length when the value is absent. */
		rv = sc_simpletlv_read_tag(&ptr, sizeof(cases[i].header), &tag, &length, cases[i].byte_order);
		assert_int_equal(rv, SC_ERROR_TLV_END_OF_CONTENTS);
		assert_int_equal(tag, 0x42);
		assert_int_equal(length, cases[i].length);
		assert_ptr_equal(ptr, cases[i].header + sizeof(cases[i].header));

		ptr = cases[i].header;
		rv = sc_simpletlv_read_tag(&ptr, sizeof(cases[i].header) - 1, &tag, &length, cases[i].byte_order);
		assert_int_equal(rv, SC_ERROR_INVALID_TLV_OBJECT);
		assert_null(ptr);
	}
}

static void
torture_simpletlv_put_byte_order(void **state)
{
	static const struct {
		enum sc_simpletlv_byte_order byte_order;
		size_t length;
		u8 header[4];
		size_t header_length;
	} cases[] = {
			{SC_SIMPLETLV_BIG_ENDIAN,	  2,     {0x42, 0x02},		   2},
			{SC_SIMPLETLV_BIG_ENDIAN,	  254,   {0x42, 0xfe},	     2},
			{SC_SIMPLETLV_LITTLE_ENDIAN, 600,	  {0x42, 0xff, 0x58, 0x02}, 4},
			{SC_SIMPLETLV_BIG_ENDIAN,	  600,   {0x42, 0xff, 0x02, 0x58}, 4},
			{SC_SIMPLETLV_BIG_ENDIAN,	  255,   {0x42, 0xff, 0x00, 0xff}, 4},
			{SC_SIMPLETLV_BIG_ENDIAN,	  65535, {0x42, 0xff, 0xff, 0xff}, 4},
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		u8 output[5] = {0};
		u8 *ptr = NULL;
		int rv;

		output[cases[i].header_length] = 0xa5;
		rv = sc_simpletlv_put_tag(0x42, cases[i].length, output, cases[i].header_length, &ptr, cases[i].byte_order);
		assert_int_equal(rv, SC_SUCCESS);
		assert_memory_equal(output, cases[i].header, cases[i].header_length);
		assert_ptr_equal(ptr, output + cases[i].header_length);
		assert_int_equal(output[cases[i].header_length], 0xa5);
	}
}

static void
torture_simpletlv_invalid_byte_order(void **state)
{
	const u8 header[] = {0x42, 0x00};
	const u8 *ptr = header;
	u8 tag = 0xa5;
	size_t length = 7;
	u8 output[] = {0xa5, 0xa5, 0xa5, 0xa5};
	u8 *outptr = output;
	int rv;

	rv = sc_simpletlv_read_tag(&ptr, sizeof(header), &tag, &length, (enum sc_simpletlv_byte_order) - 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	assert_ptr_equal(ptr, header);
	assert_int_equal(tag, 0xa5);
	assert_int_equal(length, 7);

	rv = sc_simpletlv_put_tag(0x42, 600, output, sizeof(output), &outptr, (enum sc_simpletlv_byte_order) - 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	assert_memory_equal(output, "\xa5\xa5\xa5\xa5", sizeof(output));
	assert_ptr_equal(outptr, output);
}

int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
			cmocka_unit_test(torture_simpletlv_read_extended_byte_order),
			cmocka_unit_test(torture_simpletlv_put_byte_order),
			cmocka_unit_test(torture_simpletlv_invalid_byte_order),
			/* simpletlv_read_tag() */
			cmocka_unit_test(torture_simpletlv_read_tag_null),
			cmocka_unit_test(torture_simpletlv_read_tag_short),
			cmocka_unit_test(torture_simpletlv_read_tag_minimal),
			cmocka_unit_test(torture_simpletlv_read_tag_minimal2),
			cmocka_unit_test(torture_simpletlv_read_tag_valid_short),
			cmocka_unit_test(torture_simpletlv_read_tag_incomplete_length),
			cmocka_unit_test(torture_simpletlv_read_tag_long_length),
			cmocka_unit_test(torture_simpletlv_read_tag_missing_data),
			cmocka_unit_test(torture_simpletlv_read_tag_valid_long),
			/* simpletlv_put_tag() */
			cmocka_unit_test(torture_simpletlv_put_tag_null),
			cmocka_unit_test(torture_simpletlv_put_tag_too_small),
			cmocka_unit_test(torture_simpletlv_put_tag_valid_short),
			cmocka_unit_test(torture_simpletlv_put_tag_invalid_tag),
			cmocka_unit_test(torture_simpletlv_put_tag_invalid_tag2),
			cmocka_unit_test(torture_simpletlv_put_tag_max_short),
			cmocka_unit_test(torture_simpletlv_put_tag_too_long_length),
			cmocka_unit_test(torture_simpletlv_put_tag_valid_long),
			cmocka_unit_test(torture_simpletlv_put_tag_first_long),
			cmocka_unit_test(torture_simpletlv_put_tag_last_long),
			cmocka_unit_test(torture_simpletlv_put_tag_too_large_length),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
