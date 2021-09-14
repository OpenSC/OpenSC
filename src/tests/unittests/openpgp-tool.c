/*
 * openpgp-tool.c: Test various functions of openpgp-tool
 *
 * Copyright (C) 2021  Vincent Pelletier <plr.vincent@gmail.com>
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

#include "tools/openpgp-tool-helpers.h"

struct expectation {
    const char *data;
    size_t length;
    const char *output;
};

static void torture_prettify(void **state, const struct expectation *cur, char *(prettify_func)(const u8 *data, size_t length))
{
	char *output;

	while (cur->data != NULL) {
		output = prettify_func((u8 *) cur->data, cur->length);
		if (cur->output == NULL)
			assert_null(output);
		else {
			assert_non_null(output);
			assert_string_equal(output, cur->output);
		}
		cur++;
	}
}

const struct expectation expectations_algorithm[] = {
    { "", 0, NULL },
    { "\x12\x2b\x06\x01\x04\x01\x97\x55\x01\x05\x01", 11, "ECDH" },
    { "\x01\x08\x00\x00\x20\x00", 6, "RSA2048" },
    { NULL, 0, NULL }
};

static void torture_prettify_algorithm(void **state)
{
	torture_prettify(state, expectations_algorithm, prettify_algorithm);
}

const struct expectation expectations_date[] = {
    { "\x01\x02\x03", 3, NULL },
    { "\x12\x34\x56\x78", 4, "1979-09-05 22:51:36" },
    { "\x7f\xff\xff\xff", 4, "2038-01-19 03:14:07" },
    /* XXX: probably not a feature */
    { "\x80\x00\x00\x00", 4, "1901-12-13 20:45:52" },
    { NULL, 0, NULL }
};

static void torture_prettify_date(void **state)
{
	torture_prettify(state, expectations_date, prettify_date);
}

const struct expectation expectations_version[] = {
    { "\x01", 1, NULL },
    { "\x03\x41", 2, "3.41" },
    { NULL, 0, NULL }
};

static void torture_prettify_version(void **state)
{
	torture_prettify(state, expectations_version, prettify_version);
}

const struct expectation expectations_manufacturer[] = {
    { "\x01", 1, NULL },
    { "\xf5\x17", 2, "FSIJ" },
    { "\xff\x00", 2, "unmanaged S/N range" },
    { "\xff\x7f", 2, "unmanaged S/N range" },
    { "\xff\xfe", 2, "unmanaged S/N range" },
    { "\xff\xff", 2, "test card" },
    /* Number picked by a fair dice roll among unregistered numbers */
    { "\x81\x88", 2, "unknown" },
    { NULL, 0, NULL }
};

static void torture_prettify_manufacturer(void **state)
{
	torture_prettify(state, expectations_manufacturer, prettify_manufacturer);
}

const struct expectation expectations_serialnumber[] = {
    { "\x00\x00\x00", 3, NULL },
    { "\x12\x34\x56\x78", 4, "12345678" },
    { "\x80\x00\x00\x00", 4, "80000000" },
    { NULL, 0, NULL }
};

static void torture_prettify_serialnumber(void **state)
{
	torture_prettify(state, expectations_serialnumber, prettify_serialnumber);
}

const struct expectation expectations_name[] = {
    { "", 0, NULL },
    { "John Doe", 8, "John Doe" },
    { "John<Doe", 8, "John Doe" },
    { "John<<Doe", 9, "John Doe" },
    { NULL, 0, NULL }
};

static void torture_prettify_name(void **state)
{
	torture_prettify(state, expectations_name, prettify_name);
}

const struct expectation expectations_language[] = {
    { "", 0, NULL },
    { "en", 2, "en" },
    { "end", 3, "en" },
    { "deen", 4, "de,en" },
    { NULL, 0, NULL }
};

static void torture_prettify_language(void **state)
{
	torture_prettify(state, expectations_language, prettify_language);
}

const struct expectation expectations_gender[] = {
    { "", 0, NULL },
    { "\x30", 1, "unknown" },
    { "\x31", 1, "male" },
    { "\x32", 1, "female" },
    { "\x39", 1, "not announced" },
    { NULL, 0, NULL }
};

static void torture_prettify_gender(void **state)
{
	torture_prettify(state, expectations_gender, prettify_gender);
}

int main(void)
{
	int rc;
	struct CMUnitTest tests[] = {
		cmocka_unit_test(torture_prettify_algorithm),
		cmocka_unit_test(torture_prettify_date),
		cmocka_unit_test(torture_prettify_version),
		cmocka_unit_test(torture_prettify_manufacturer),
		cmocka_unit_test(torture_prettify_serialnumber),
		cmocka_unit_test(torture_prettify_name),
		cmocka_unit_test(torture_prettify_language),
		cmocka_unit_test(torture_prettify_gender),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);
	return rc;
}
