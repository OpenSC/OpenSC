/*
 * check_macro_reference_loop.c: Unit tests checking macro reference loop
 *
 * Copyright (C) 2023 Red Hat, Inc.
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

#define SC_PKCS15_PROFILE_DIRECTORY ""

#include "torture.h"
#include "libopensc/log.c"
#include "pkcs15init/profile.c"
#include "common/compat_strlcpy.c"
#include <cmocka.h>

static void
torture_no_loop(void **state)
{
	scconf_list value = {.data = "value"};
	sc_macro_t macro = {.name = "name", .value = &value};
	sc_profile_t profile = {.macro_list = &macro};

	int r = check_macro_reference_loop("name", &macro, &profile, 10);
	assert_int_equal(r, 0);
}

static void
torture_one_macro_no_loop(void **state)
{
	scconf_list value = {.data = "value"};
	sc_macro_t macro = {.name = "name", .value = &value};
	sc_profile_t profile = {.macro_list = &macro};

	int r = check_macro_reference_loop("name", &macro, &profile, 10);
	assert_int_equal(r, 0);
}

static void
torture_one_macro_loop(void **state)
{
	scconf_list value = {.data = "$name"};
	sc_macro_t macro = {.name = "name", .value = &value};
	sc_profile_t profile = {.macro_list = &macro};

	int r = check_macro_reference_loop("name", &macro, &profile, 10);
	assert_int_equal(r, 1);
}

static void
torture_long_macro_loop(void **state)
{
	scconf_list value1 = {.data = "$second"};
	scconf_list value2 = {.data = "$third"};
	scconf_list value3 = {.data = "$first"};
	sc_macro_t macro3 = {.name = "third", .value = &value3};
	sc_macro_t macro2 = {.name = "second", .value = &value2, .next = &macro3};
	sc_macro_t macro1 = {.name = "first", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("first", &macro1, &profile, 10);
	assert_int_equal(r, 1);
}

static void
torture_long_macro_loop_too_deep(void **state)
{
	scconf_list value1 = {.data = "$second"};
	scconf_list value2 = {.data = "$third"};
	scconf_list value3 = {.data = "value"};
	sc_macro_t macro3 = {.name = "third", .value = &value3};
	sc_macro_t macro2 = {.name = "second", .value = &value2, .next = &macro3};
	sc_macro_t macro1 = {.name = "first", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("first", &macro1, &profile, 14);
	assert_int_equal(r, 1);
}

static void
torture_macro_loop_inner_string(void **state)
{
	scconf_list value1 = {.data = "xx$second"};
	scconf_list value2 = {.data = "$third"};
	scconf_list value3 = {.data = "$first\0"};
	sc_macro_t macro3 = {.name = "third", .value = &value3};
	sc_macro_t macro2 = {.name = "second", .value = &value2, .next = &macro3};
	sc_macro_t macro1 = {.name = "first", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("first", &macro1, &profile, 10);
	assert_int_equal(r, 1);
}

static void
torture_macro_loop_indirect(void **state)
{
	scconf_list value1 = {.data = "$x"};
	scconf_list value2 = {.data = "-$x"};
	sc_macro_t macro2 = {.name = "o", .value = &value2};
	sc_macro_t macro1 = {.name = "x", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("o", &macro2, &profile, 10);
	assert_int_equal(r, 1);
}

static void
torture_macro_loop_indirect_multivalue(void **state)
{
	scconf_list value3 = {.data = "-$x"};
	scconf_list value2 = {.data = "1", .next = &value3};
	scconf_list value1 = {.data = "$x"};
	sc_macro_t macro2 = {.name = "o", .value = &value2};
	sc_macro_t macro1 = {.name = "x", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("o", &macro2, &profile, 10);
	assert_int_equal(r, 1);
}

#if 0
/* A reproducer for https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=64549
 * This can no longer happen as the non-printable macro names are now ignored while they are defined
 */
static void torture_macro_loop_indirect_nonprintable(void **state)
{
	scconf_list value3 = {.data = "$\270\270x\001"};
	scconf_list value2 = {.data = "$e"};
	scconf_list value1 = {.data = "$e"};
	sc_macro_t macro3 = {.name = "e", .value = &value3};
	sc_macro_t macro2 = {.name = "osi", .value = &value2, .next = &macro3};
	sc_macro_t macro1 = {.name = "\270\270x\001", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("osi", &macro2, &profile, 10);
	assert_int_equal(r, 1);
}
#endif /* 0 */

/*
 *A reproducer for https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=68061
 */
static void
torture_macro_loop_long_name(void **state)
{
	scconf_list value1 = {.data = "$second"};
	scconf_list value2 = {.data = "$dtBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCBBBBe"};
	scconf_list value3 = {.data = "$second"};
	sc_macro_t macro3 = {.name = "dtBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCBBBBe", .value = &value3};
	sc_macro_t macro2 = {.name = "second", .value = &value2, .next = &macro3};
	sc_macro_t macro1 = {.name = "first", .value = &value1, .next = &macro2};
	sc_profile_t profile = {.macro_list = &macro1};

	int r = check_macro_reference_loop("first", &macro1, &profile, 10);
	assert_int_equal(r, 1);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(torture_no_loop),
			cmocka_unit_test(torture_one_macro_no_loop),
			cmocka_unit_test(torture_one_macro_loop),
			cmocka_unit_test(torture_long_macro_loop),
			cmocka_unit_test(torture_long_macro_loop_too_deep),
			cmocka_unit_test(torture_macro_loop_inner_string),
			cmocka_unit_test(torture_macro_loop_indirect),
			cmocka_unit_test(torture_macro_loop_indirect_multivalue),
			cmocka_unit_test(torture_macro_loop_long_name),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
