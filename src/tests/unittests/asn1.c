/*
 * asn1.c: Unit tests for ASN1 parsers
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
#include "libopensc/asn1.c"

/*
 * Test undefined behavior of too large parts of OID encoding
 *
 * The specification does not place any limits to these values, but they
 * are internally in opensc stored as ints so it makes sense to reject
 * the too-large onese for now, rather than causing undefined overflow.
 *
 * https://oss-fuzz.com/testcase-detail/5673497895895040
 */
static void torture_large_oid(void **state)
{
	/* 2.5.4.18446744073709551616 (The last part is 64 bit overflow) */
	u8 data1[] = {0x55, 0x04, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00};
	/* 2.18446744073709551616.4.3 (The second part is 64 bit overflow) */
	u8 data2[] = {0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x50, 0x04, 0x03};
	/* 2.5.4.2147483647 (The last part is largest 32 bit integer) */
	u8 data3[] = {0x55, 0x04, 0x87, 0xFF, 0xFF, 0xFF, 0x7F};
	/* 2.2147483647.4.3 (The second part is largest 32 bit integer) */
	u8 data4[] = {0x88, 0x80, 0x80, 0x80, 0x4F, 0x04, 0x03};
	/* 2.5.4.2147483648 (The last part is 32 bit integer overflow) */
	u8 data5[] = {0x55, 0x04, 0x88, 0x80, 0x80, 0x80, 0x00};
	/* 2.2147483648.4.3 (The second part is 32 bit integer overflow) */
	u8 data6[] = {0x88, 0x80, 0x80, 0x80, 0x50, 0x04, 0x03};
	struct sc_object_id oid;
	u8 *buf = NULL;
	size_t buflen = 0;
	int rv = 0;

	rv = sc_asn1_decode_object_id(data1, sizeof(data1), &oid);
	assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

	rv = sc_asn1_decode_object_id(data2, sizeof(data2), &oid);
	assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

	if (sizeof(int) == 4) {
		/* For 64 bit builds */
		struct sc_object_id oid_3 = {{2, 5, 4, 2147483647, -1}};
		struct sc_object_id oid_4 = {{2, 2147483647, 4, 3, -1}};

		rv = sc_asn1_decode_object_id(data3, sizeof(data3), &oid);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(sc_compare_oid(&oid_3, &oid), 1);
		rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(buflen, sizeof(data3));
		assert_memory_equal(buf, data3, buflen);
		free(buf);

		rv = sc_asn1_decode_object_id(data4, sizeof(data4), &oid);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(sc_compare_oid(&oid_4, &oid), 1);
		rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(buflen, sizeof(data4));
		assert_memory_equal(buf, data4, buflen);
		free(buf);

		rv = sc_asn1_decode_object_id(data5, sizeof(data5), &oid);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

		rv = sc_asn1_decode_object_id(data6, sizeof(data6), &oid);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);
	} else {
		rv = sc_asn1_decode_object_id(data3, sizeof(data3), &oid);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

		rv = sc_asn1_decode_object_id(data4, sizeof(data4), &oid);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);
	}
}

static void torture_oid(void **state)
{
	/* (without the tag and length {0x06, 0x06}) */
	/* Small OIDs */
	struct sc_object_id small_oid = {{0, 1, 2, 3, 4, 5, 6, -1}};
	u8 small[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	/* Limit what we can fit into the first byte */
	struct sc_object_id limit_oid = {{2, 47, -1}};
	u8 limit[] = {0x7F};
	/* The second octet already oveflows to the second byte */
	struct sc_object_id two_byte_oid = {{2, 48, -1}};
	u8 two_byte[] = {0x81, 0x00};
	/* Existing OID ec publickey */
	struct sc_object_id ecpubkey_oid = {{1, 2, 840, 10045, 2, 1, -1}};
	u8 ecpubkey[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
	/* Missing second byte, even though indicated with the first bit */
	u8 missing[] = {0x81};
	/* Missing second byte in later identifiers */
	u8 missing_second[] = {0x2A, 0x48, 0x81};
	struct sc_object_id oid;
	u8 *buf = NULL;
	size_t buflen = 0;
	int rv = 0;

	rv = sc_asn1_decode_object_id(small, sizeof(small), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(sc_compare_oid(&small_oid, &oid), 1);
	rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(small));
	assert_memory_equal(buf, small, buflen);
	free(buf);

	rv = sc_asn1_decode_object_id(limit, sizeof(limit), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(sc_compare_oid(&limit_oid, &oid), 1);
	rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(limit));
	assert_memory_equal(buf, limit, buflen);
	free(buf);

	rv = sc_asn1_decode_object_id(two_byte, sizeof(two_byte), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(sc_compare_oid(&two_byte_oid, &oid), 1);
	rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(two_byte));
	assert_memory_equal(buf, two_byte, buflen);
	free(buf);

	rv = sc_asn1_decode_object_id(ecpubkey, sizeof(ecpubkey), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(oid.value[0], 1);
	assert_int_equal(oid.value[1], 2);
	assert_int_equal(oid.value[2], 840);
	assert_int_equal(oid.value[3], 10045);
	assert_int_equal(oid.value[4], 2);
	assert_int_equal(oid.value[5], 1);
	assert_int_equal(oid.value[6], -1);
	assert_int_equal(sc_compare_oid(&ecpubkey_oid, &oid), 1);
	rv = sc_asn1_encode_object_id(&buf, &buflen, &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(ecpubkey));
	assert_memory_equal(buf, ecpubkey, buflen);
	free(buf);

	rv = sc_asn1_decode_object_id(missing, sizeof(missing), &oid);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	rv = sc_asn1_decode_object_id(missing_second, sizeof(missing_second), &oid);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	/* TODO SC_MAX_OBJECT_ID_OCTETS */
}

static void torture_integer(void **state)
{
	/* Without the Tag and Length {0x02, 0x01} */
	u8 null[] = {};
	u8 padded_zero[] = {0x00, 0x00};
	u8 zero[] = {0x00};
	u8 one[] = {0x01};
	u8 minus_one[] = {0xFF};
	u8 padded_one[] = {0x00, 0x01};
	u8 padded_minus_one[] = {0xFF, 0xFF};
	u8 padded_127[] = {0x00, 0x7F};
	u8 padded_128[] = {0x00, 0x80};
	u8 max2[] = {0x7F, 0xFF};
	u8 min2[] = {0x80, 0x00};
	u8 max4[] = {0x7F, 0xFF, 0xFF, 0xFF};
	u8 min4[] = {0x80, 0x00, 0x00, 0x00};
	u8 over[] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF};
	int value;
	u8 *buf = NULL;
	size_t buflen = 0;
	int rv = 0;

	rv = sc_asn1_decode_integer(null, sizeof(null), &value, 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	rv = sc_asn1_decode_integer(padded_zero, sizeof(padded_zero), &value, 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	rv = sc_asn1_decode_integer(padded_one, sizeof(padded_one), &value, 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
	/* but we can parse them without the strict checking */
	rv = sc_asn1_decode_integer(padded_one, sizeof(padded_one), &value, 0);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 1);

	rv = sc_asn1_decode_integer(padded_minus_one, sizeof(padded_minus_one), &value, 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
	/* but we can parse them without the strict checking */
	rv = sc_asn1_decode_integer(padded_minus_one, sizeof(padded_minus_one), &value, 0);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -1);

	rv = sc_asn1_decode_integer(padded_127, sizeof(padded_127), &value, 1);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
	/* but we can parse them without the strict checking */
	rv = sc_asn1_decode_integer(padded_127, sizeof(padded_127), &value, 0);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 127);

	rv = sc_asn1_decode_integer(padded_128, sizeof(padded_128), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 128);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(padded_128));
	assert_memory_equal(buf, padded_128, buflen);
	free(buf);

	rv = sc_asn1_decode_integer(zero, sizeof(zero), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 0);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(zero));
	assert_memory_equal(buf, zero, buflen);
	free(buf);

	rv = sc_asn1_decode_integer(one, sizeof(one), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 1);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(one));
	assert_memory_equal(buf, one, buflen);
	free(buf);

	rv = sc_asn1_decode_integer(minus_one, sizeof(minus_one), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -1);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(minus_one));
	assert_memory_equal(buf, minus_one, buflen);
	free(buf);

	rv = sc_asn1_decode_integer(max2, sizeof(max2), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 32767);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(max2));
	assert_memory_equal(buf, max2, buflen);
	free(buf);

	rv = sc_asn1_decode_integer(min2, sizeof(min2), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -32768);
	rv = asn1_encode_integer(value, &buf, &buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(buflen, sizeof(min2));
	assert_memory_equal(buf, min2, buflen);
	free(buf);

	if (sizeof(int) == 4) {
		rv = sc_asn1_decode_integer(max4, sizeof(max4), &value, 1);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(value, 2147483647);
		rv = asn1_encode_integer(value, &buf, &buflen);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(buflen, sizeof(max4));
		assert_memory_equal(buf, max4, buflen);
		free(buf);

		rv = sc_asn1_decode_integer(min4, sizeof(min4), &value, 1);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(value, -2147483648);
		rv = asn1_encode_integer(value, &buf, &buflen);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(buflen, sizeof(min4));
		assert_memory_equal(buf, min4, buflen);
		free(buf);

		rv = sc_asn1_decode_integer(over, sizeof(over), &value, 1);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);
	} else {
		/* On more esoteric architectures, we can have different size of int */
		rv = sc_asn1_decode_integer(max4, sizeof(max4), &value, 1);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

		rv = sc_asn1_decode_integer(min4, sizeof(min4), &value, 1);
		assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);
	}
}

/*
 * Test undefined behavior of negative INTEGERS handling.
 * https://oss-fuzz.com/testcase-detail/5125815506829312
 *
 * The issue was not actually the size of the integers, but that first
 * negative value wrote ones to the whole integer and it was not possible
 * to shift values afterward.
 */
static void torture_negative_int(void **state)
{
	/* Without the Tag and Length {0x80, 0x04} */
	/* u8 data1[] = {0xff, 0x20, 0x20, 0x20}; original data */
	u8 data1[] = {0xff, 0x20}; /* Shortened also for 32 bit builds */
	int value;
	int rv = 0;

	rv = sc_asn1_decode_integer(data1, sizeof(data1), &value, 1);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -224);
}

/*
 * Test undefined behavior of too-large bit field (BIT STRING as an integer)
 * https://oss-fuzz.com/testcase-detail/5764460018401280
 *
 * In this example, invalid "unused bytes" value was used
 */
static void torture_bit_field(void **state)
{
	/* Without the Tag and Length {0x03, 0x02} */
	u8 data0[] = {0x07, 0x80};
	/* Without the Tag and Length {0x03, 0x05} */
	/* u8 data1[] = {0x20, 0x20, 0xff, 0xff, 0xff}; original data */
	u8 data1[] = {0x20, 0xff, 0xff, 0xff, 0xff};
	u8 data2[] = {0x00, 0xff, 0xff, 0xff, 0xff};
	/* Without the Tag and Length {0x03, 0x06} */
	u8 data3[] = {0x00, 0xff, 0xff, 0xff, 0xff, 0xff};
	/* Without the Tag and Length {0x03, 0x02} */
	u8 padding[] = {0x01, 0xfe};
	u8 invalid_padding[] = {0x01, 0xff};
	unsigned int value;
	size_t value_len = sizeof(value);
	int rv = 0;

	/* Simple value 1 */
	rv = decode_bit_field(data0, sizeof(data0), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 1);

	/* Too large unused bits field */
	rv = decode_bit_field(data1, sizeof(data1), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	/* This is the last value that can be represented in the unsigned int */
	rv = decode_bit_field(data2, sizeof(data2), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, UINT_MAX);

	/* Too large to represent in the unsigned int type */
	rv = decode_bit_field(data3, sizeof(data3), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_ERROR_BUFFER_TOO_SMALL);

	/* Valid padding */
	rv = decode_bit_field(padding, sizeof(padding), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 127);

	/* Invalid (non-zero bits) padding */
	rv = decode_bit_field(invalid_padding, sizeof(invalid_padding), (unsigned int *)&value, value_len);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
}
int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_large_oid),
		cmocka_unit_test(torture_integer),
		cmocka_unit_test(torture_negative_int),
		cmocka_unit_test(torture_oid),
		cmocka_unit_test(torture_bit_field),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
