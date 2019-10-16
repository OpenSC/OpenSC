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
#include "libopensc/asn1.h"

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
	/* 2.5.4.18446744073709551619 (The last part is 64 bit overflow) */
	u8 data1[] = {0x55, 0x04, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x03};
	/* 2.18446744073709551621.4.3 (The second part is 64 bit overflow) */
	u8 data2[] = {0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x55, 0x04, 0x03};
	struct sc_object_id oid;
	int rv = 0;

	rv = sc_asn1_decode_object_id(data1, sizeof(data1), &oid);
	assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);

	rv = sc_asn1_decode_object_id(data2, sizeof(data2), &oid);
	assert_int_equal(rv, SC_ERROR_NOT_SUPPORTED);
}

static void torture_oid(void **state)
{
	/* (without the tag and length {0x06, 0x06}) */
	/* Small OIDs */
	u8 small[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	/* Limit what we can fit into the first byte */
	u8 limit[] = {0x7F};
	/* The second octet already oveflows to the second byte */
	u8 two_byte[] = {0x81, 0x00};
	/* Missing second byte, even though indicated with the first bit */
	u8 missing[] = {0x81};
	/* Missing second byte, even though indicated with the first bit */
	u8 ecpubkey[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
	struct sc_object_id oid;
	int rv = 0;

	rv = sc_asn1_decode_object_id(small, sizeof(small), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(oid.value[0], 0);
	assert_int_equal(oid.value[1], 1);
	assert_int_equal(oid.value[2], 2);
	assert_int_equal(oid.value[3], 3);
	assert_int_equal(oid.value[4], 4);
	assert_int_equal(oid.value[5], 5);
	assert_int_equal(oid.value[6], 6);
	assert_int_equal(oid.value[7], -1);

	rv = sc_asn1_decode_object_id(limit, sizeof(limit), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(oid.value[0], 2);
	assert_int_equal(oid.value[1], 47);
	assert_int_equal(oid.value[2], -1);

	rv = sc_asn1_decode_object_id(two_byte, sizeof(two_byte), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(oid.value[0], 2);
	assert_int_equal(oid.value[1], 48);
	assert_int_equal(oid.value[2], -1);

	rv = sc_asn1_decode_object_id(missing, sizeof(missing), &oid);
	assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

	rv = sc_asn1_decode_object_id(ecpubkey, sizeof(ecpubkey), &oid);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(oid.value[0], 1);
	assert_int_equal(oid.value[1], 2);
	assert_int_equal(oid.value[2], 840);
	assert_int_equal(oid.value[3], 10045);
	assert_int_equal(oid.value[4], 2);
	assert_int_equal(oid.value[5], 1);
	assert_int_equal(oid.value[6], -1);

	/* TODO SC_MAX_OBJECT_ID_OCTETS */
}

static void torture_integer(void **state)
{
	/* Without the Tag and Length {0x02, 0x01} */
	u8 zero[] = {0x00};
	u8 one[] = {0x01};
	u8 minus_one[] = {0xFF};
	u8 max2[] = {0x7F, 0xFF};
	u8 min2[] = {0x80, 0x00};
	u8 max4[] = {0x7F, 0xFF, 0xFF, 0xFF};
	u8 min4[] = {0x80, 0x00, 0x00, 0x00};
	u8 over[] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF};
	int value;
	int rv = 0;

	rv = sc_asn1_decode_integer(zero, sizeof(zero), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 0);

	rv = sc_asn1_decode_integer(one, sizeof(one), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 1);

	rv = sc_asn1_decode_integer(minus_one, sizeof(minus_one), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, (int)-1);

	rv = sc_asn1_decode_integer(max2, sizeof(max2), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, 32767);

	rv = sc_asn1_decode_integer(min2, sizeof(min2), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -32768);

	if (sizeof(int*) == 8) {
		/* For 64 bit builds */
		rv = sc_asn1_decode_integer(max4, sizeof(max4), &value);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(value, 2147483647);

		rv = sc_asn1_decode_integer(min4, sizeof(min4), &value);
		assert_int_equal(rv, SC_SUCCESS);
		assert_int_equal(value, -2147483648);

		rv = sc_asn1_decode_integer(over, sizeof(over), &value);
		assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
	} else {
		/* On 32 bit builds, this will fail */
		rv = sc_asn1_decode_integer(max4, sizeof(max4), &value);
		assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);

		rv = sc_asn1_decode_integer(min4, sizeof(min4), &value);
		assert_int_equal(rv, SC_ERROR_INVALID_ASN1_OBJECT);
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
	u8 data1[] = {0xff, 0x20}; /* Shortened also for 32 builds */
	int value;
	int rv = 0;

	rv = sc_asn1_decode_integer(data1, sizeof(data1), &value);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(value, -224);
}


int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_large_oid),
		cmocka_unit_test(torture_integer),
		cmocka_unit_test(torture_negative_int),
		cmocka_unit_test(torture_oid),
		/* TODO Test and adjust the ANS1 generators */
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
