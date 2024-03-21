/*
 * pkcs15-emulator-filter.c: Unit tests for PKCS15 emulator filter
 *
 * Copyright (C) 2021 Red Hat, Inc.
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
#include "libopensc/pkcs15-emulator-filter.c"

int func(sc_pkcs15_card_t *card, struct sc_aid *aid) {
	(void) card;
	(void) aid;
	return SC_SUCCESS;
}

// clang-format off
struct sc_pkcs15_emulator_handler builtin[] = {
	{ "openpgp",	&func },
	{ "starcert",	&func },
	{ NULL,	NULL }
};
struct sc_pkcs15_emulator_handler old[] = {
	{ "cardos",		&func },
	{ "jcop",		&func },
	{ NULL, NULL }
};
// clang-format on

/* add_emul */
static void torture_null_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &builtin[0] }, 1 };
	int rv;

	rv = add_emul(NULL, &builtin[0]);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	rv = add_emul(&filtered_emulators, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
}

static void torture_name_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int rv;
	filtered_emulators.ccount = 0;

	rv = add_emul(&filtered_emulators, &builtin[0]);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(filtered_emulators.ccount, 1);
}

static void torture_name_already_in_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &builtin[0] }, 1 };
	int rv;

	rv = add_emul(&filtered_emulators, &builtin[0]);
	assert_int_equal(rv, SC_SUCCESS);
	assert_int_equal(filtered_emulators.ccount, 1);
}

static void torture_full_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS;
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = add_emul(&filtered_emulators, &old[0]);
	assert_int_equal(rv, SC_ERROR_TOO_MANY_OBJECTS);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
	assert_ptr_equal(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1], &builtin[0]);
}

static void torture_overfilled_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS + 1;
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS + 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = add_emul(&filtered_emulators, &old[0]);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS + 1);
}

static void torture_invalid_handler_name_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	struct sc_pkcs15_emulator_handler handler = { NULL, &func };
	int rv;
	filtered_emulators.ccount = 0;

	rv = add_emul(&filtered_emulators, &handler);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
}

static void torture_invalid_handler_func_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	struct sc_pkcs15_emulator_handler handler = { "name", NULL };
	int rv;
	filtered_emulators.ccount = 0;

	rv = add_emul(&filtered_emulators, &handler);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
}

static void torture_invalid_emulator_list_add_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { NULL }, 1 };
	struct sc_pkcs15_emulator_handler handler = { "name", &func };
	int rv;

	rv = add_emul(&filtered_emulators, &handler);
	assert_int_equal(rv, SC_ERROR_OBJECT_NOT_VALID);
}

/* add_emul_list */
static void torture_null_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &builtin[0] }, 1 };
	int rv;

	rv = add_emul_list(NULL, builtin);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	rv = add_emul_list(&filtered_emulators, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
}

static void torture_internal_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = 0;

	rv = add_emul_list(&filtered_emulators, builtin);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_int_equal(filtered_emulators.ccount, i);
}

static void torture_internal_already_name_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &builtin[0] }, 1 };
	int i, rv;

	rv = add_emul_list(&filtered_emulators, builtin);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_int_equal(filtered_emulators.ccount, i);
}

static void torture_internal_already_name2_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &old[0] }, 1 };
	int i, rv;

	rv = add_emul_list(&filtered_emulators, builtin);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i + 1]);
	}
	assert_int_equal(filtered_emulators.ccount, i + 1);
}

static void torture_full_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS;
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[1];
	}

	rv = add_emul_list(&filtered_emulators, builtin);
	assert_int_equal(rv, SC_ERROR_TOO_MANY_OBJECTS);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
}

static void torture_one_to_full_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS - 1;
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS - 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = add_emul_list(&filtered_emulators, old);
	assert_int_equal(rv, SC_ERROR_TOO_MANY_OBJECTS);
	assert_ptr_equal(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1], &old[0]);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
}

static void torture_overfilled_add_emul_list(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS + 1;
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS + 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = add_emul_list(&filtered_emulators, old);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	assert_ptr_equal(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1], &builtin[0]);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS + 1);
}

/* set_emulators */
static void torture_non_existing(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int rv;
	scconf_list list =  { NULL, "non" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	assert_null(filtered_emulators.list_of_handlers[0]);
}

static void torture_internal_only(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	scconf_list list =  { NULL, "internal" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_int_equal(filtered_emulators.ccount, 2);
	assert_null(filtered_emulators.list_of_handlers[2]);
	assert_null(builtin[i].name);
}

static void torture_old_only(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	scconf_list list =  { NULL, "old" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; old[i].name; i++) {
		assert_ptr_equal(&old[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_null(filtered_emulators.list_of_handlers[i]);
	assert_null(old[i].name);
}

static void torture_internal_name(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int rv;
	scconf_list list =  { NULL, strdup(builtin[0].name) };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	assert_ptr_equal(&builtin[0], filtered_emulators.list_of_handlers[0]);
	assert_null(filtered_emulators.list_of_handlers[1]);
	free(list.data);
}

static void torture_old_name(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int rv;
	scconf_list list =  { NULL, strdup(old[0].name) };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	assert_ptr_equal(&old[0], filtered_emulators.list_of_handlers[0]);
	assert_null(filtered_emulators.list_of_handlers[1]);
	free(list.data);
}

static void torture_internal_and_name(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	scconf_list list2 =  { NULL, "cardos" };
	scconf_list list1 =  { &list2, "internal" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_ptr_equal(&old[0], filtered_emulators.list_of_handlers[i]);
	assert_null(filtered_emulators.list_of_handlers[i + 1]);
}

static void torture_name_and_internal(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int rv;
	scconf_list list2 =  { NULL, "internal" };
	scconf_list list1 =  { &list2, "starcert" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	assert_ptr_equal(&builtin[1], filtered_emulators.list_of_handlers[0]);
	assert_ptr_equal(&builtin[0], filtered_emulators.list_of_handlers[1]);
	assert_null(filtered_emulators.list_of_handlers[2]);
}

static void torture_internal_and_nonexisting(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;;
	scconf_list list2 =  { NULL, "non" };
	scconf_list list1 =  { &list2, "internal" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_null(filtered_emulators.list_of_handlers[i]);
	assert_null(builtin[i].name);
}

static void torture_nonexisting_and_internal(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	scconf_list list2 =  { NULL, "internal" };
	scconf_list list1 =  { &list2, "non" };
	filtered_emulators.ccount = 0;

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	for (i = 0; builtin[i].name; i++) {
		assert_ptr_equal(&builtin[i], filtered_emulators.list_of_handlers[i]);
	}
	assert_null(filtered_emulators.list_of_handlers[i]);
	assert_null(builtin[i].name);
}

static void torture_null_set_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators = { { &builtin[0] }, 1 };
	int rv;
	scconf_list list1 = { NULL, "internal" };

	rv = set_emulators(NULL, NULL, &list1, builtin, old);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	rv = set_emulators(NULL, &filtered_emulators, NULL, builtin, old);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	rv = set_emulators(NULL, &filtered_emulators, &list1, NULL, old);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, NULL);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
}

static void torture_full_set_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS;
	scconf_list list1 = { NULL, "old" };
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_ERROR_TOO_MANY_OBJECTS);
	assert_non_null(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1]);
	assert_null(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS]);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
}

static void torture_one_to_full_set_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS - 1;
	scconf_list list1 = { NULL, "old" };
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS - 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_ERROR_TOO_MANY_OBJECTS);
	assert_ptr_equal(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1], &old[0]);
	assert_null(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS]);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
}

static void torture_one_to_full2_set_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS - 1;
	scconf_list list1 = { NULL, strdup(old[1].name) };
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS - 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_SUCCESS);
	assert_ptr_equal(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS - 1], &old[1]);
	assert_null(filtered_emulators.list_of_handlers[SC_MAX_PKCS15_EMULATORS]);
	assert_int_equal(filtered_emulators.ccount, SC_MAX_PKCS15_EMULATORS);
	free(list1.data);
}

static void torture_overfilled_set_emul(void **state)
{
	struct _sc_pkcs15_emulators filtered_emulators;
	int i, rv;
	filtered_emulators.ccount = SC_MAX_PKCS15_EMULATORS + 1;
	scconf_list list1 = { NULL, strdup(old[1].name) };
	for (i = 0; i < SC_MAX_PKCS15_EMULATORS + 1; i++) {
		filtered_emulators.list_of_handlers[i] = &builtin[0];
	}

	rv = set_emulators(NULL, &filtered_emulators, &list1, builtin, old);
	assert_int_equal(rv, SC_ERROR_INVALID_ARGUMENTS);
	free(list1.data);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		/* add_emul */
		cmocka_unit_test(torture_null_add_emul),
		cmocka_unit_test(torture_name_add_emul),
		cmocka_unit_test(torture_name_already_in_add_emul),
		cmocka_unit_test(torture_full_add_emul),
		cmocka_unit_test(torture_overfilled_add_emul),
		cmocka_unit_test(torture_invalid_handler_name_add_emul),
		cmocka_unit_test(torture_invalid_handler_func_add_emul),
		cmocka_unit_test(torture_invalid_emulator_list_add_emul),
		/* add_emul_list */
		cmocka_unit_test(torture_null_add_emul_list),
		cmocka_unit_test(torture_internal_add_emul_list),
		cmocka_unit_test(torture_internal_already_name_add_emul_list),
		cmocka_unit_test(torture_internal_already_name2_add_emul_list),
		cmocka_unit_test(torture_full_add_emul_list),
		cmocka_unit_test(torture_one_to_full_add_emul_list),
		cmocka_unit_test(torture_overfilled_add_emul_list),
		/* set_emulators */
		cmocka_unit_test(torture_non_existing),
		cmocka_unit_test(torture_internal_only),
		cmocka_unit_test(torture_old_only),
		cmocka_unit_test(torture_internal_name),
		cmocka_unit_test(torture_old_name),
		cmocka_unit_test(torture_internal_and_name),
		cmocka_unit_test(torture_name_and_internal),
		cmocka_unit_test(torture_internal_and_nonexisting),
		cmocka_unit_test(torture_nonexisting_and_internal),
		cmocka_unit_test(torture_null_set_emul),
		cmocka_unit_test(torture_full_set_emul),
		cmocka_unit_test(torture_one_to_full_set_emul),
		cmocka_unit_test(torture_one_to_full2_set_emul),
		cmocka_unit_test(torture_overfilled_set_emul),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
