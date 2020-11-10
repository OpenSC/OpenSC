/*
 * cachedir.c: Test various options how cache dir is evaluated
 *
 * Copyright (C) 2020 Red Hat, Inc.
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

#include <limits.h>

#include "torture.h"
#include "libopensc/opensc.h"

static void torture_cachedir_default_empty_home(void **state)
{
	sc_context_t *ctx = NULL;
	char buf[PATH_MAX] = {0};
	size_t buflen = sizeof(buf);
	int rv;

	rv = sc_establish_context(&ctx, "cachedir");
	assert_int_equal(rv, SC_SUCCESS);
	assert_non_null(ctx);

	/* Keep configuration empty */
	setenv("OPENSC_CONF", "/nonexistent", 1);
	setenv("XDG_CACHE_HOME", "", 1);
	setenv("HOME", "", 1);

	rv = sc_get_cache_dir(ctx, buf, buflen);
	assert_int_equal(rv, SC_ERROR_INTERNAL);

	sc_release_context(ctx);
}

static void torture_cachedir_default_empty(void **state)
{
	sc_context_t *ctx = NULL;
	char buf[PATH_MAX] = {0};
	size_t buflen = sizeof(buf);
	int rv;

	rv = sc_establish_context(&ctx, "cachedir");
	assert_int_equal(rv, SC_SUCCESS);
	assert_non_null(ctx);

	/* Keep configuration empty */
	setenv("OPENSC_CONF", "/nonexistent", 1);
	setenv("XDG_CACHE_HOME", "", 1);
	setenv("HOME", "/home/test", 1);

	rv = sc_get_cache_dir(ctx, buf, buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_string_equal(buf, "/home/test/.cache/opensc");

	sc_release_context(ctx);
}

static void torture_cachedir_default_cache_home(void **state)
{
	sc_context_t *ctx = NULL;
	char buf[PATH_MAX] = {0};
	size_t buflen = sizeof(buf);
	int rv;

	rv = sc_establish_context(&ctx, "cachedir");
	assert_int_equal(rv, SC_SUCCESS);
	assert_non_null(ctx);

	/* Keep configuration empty */
	setenv("OPENSC_CONF", "/nonexistent", 1);
	setenv("XDG_CACHE_HOME", "/home/test2/.cache", 1);
	setenv("HOME", "/home/test", 1);

	rv = sc_get_cache_dir(ctx, buf, buflen);
	assert_int_equal(rv, SC_SUCCESS);
	assert_string_equal(buf, "/home/test2/.cache/opensc");

	sc_release_context(ctx);
}


int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_cachedir_default_empty_home),
		cmocka_unit_test(torture_cachedir_default_empty),
		cmocka_unit_test(torture_cachedir_default_cache_home),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
