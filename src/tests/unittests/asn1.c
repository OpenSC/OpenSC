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


int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_large_oid),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
