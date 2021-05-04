/*
 * sm.c: Unit tests for Secure Messaging
 *
 * Copyright (C) 2021 Red Hat, Inc.
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
#include "sm/sm-common.h"

static void torture_sm_incr_ssc(void **state)
{
	unsigned char in[] = {0x00, 0x00};

	(void)state;

	/* just make sure it does not crash */
	sm_incr_ssc(NULL, 0);

	/* zero-length input should not underflow the buffer */
	sm_incr_ssc(in, 0);

	/* shortest possible input */
	in[0] = 0x42;
	sm_incr_ssc(in, 1);
	assert_int_equal(in[0], 0x43);

	/* overflow to the second byte */
	in[0] = 0x00;
	in[1] = 0xff;
	sm_incr_ssc(in, 2);
	assert_int_equal(in[0], 0x01);
	assert_int_equal(in[1], 0x00);

	/* overflow */
	in[0] = 0xff;
	in[1] = 0xff;
	sm_incr_ssc(in, 2);
	assert_int_equal(in[0], 0x00);
	assert_int_equal(in[1], 0x00);
}


int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		/* sm_incr_ssc */
		cmocka_unit_test(torture_sm_incr_ssc),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
