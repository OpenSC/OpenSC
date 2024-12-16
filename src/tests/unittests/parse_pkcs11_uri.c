/*
 * parse_pkcs11_uri.c: Unit tests for PKCS#11 URI parser
 *
 * Copyright (C) 2024 Red Hat, Inc.
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

#include "tools/pkcs11_uri.c"
#include "torture.h"

static void
torture_id_non_percent(void **state)
{
	char *uri = "pkcs11:id=123456;";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("123456", result->id);
	assert_int_equal(strlen("123456"), result->id_len);
	pkcs11_uri_free(result);
}

static void
torture_id_percent(void **state)
{
	char *uri = "pkcs11:id=%30%31%32";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("012", result->id);
	assert_int_equal(3, result->id_len);
	pkcs11_uri_free(result);
}

static void
torture_id_percent_incorrect(void **state)
{
	char *uri = "pkcs11:id=%30%31%3";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 1);
	assert_ptr_equal(NULL, result->id);
	assert_int_equal(0, result->id_len);
	pkcs11_uri_free(result);
}

static void
torture_manufacturer(void **state)
{
	char *uri = "pkcs11:manufacturer=Snake%20Oil,%20Inc.";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("Snake Oil, Inc.", result->token_manufacturer);
	pkcs11_uri_free(result);
}

static void
torture_object(void **state)
{
	char *uri = "pkcs11:object=my-certificate;";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("my-certificate", result->object);
	pkcs11_uri_free(result);
}

static void
torture_empty_serial(void **state)
{
	char *uri = "pkcs11:serial=;";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("", result->serial);
	pkcs11_uri_free(result);
}

static void
torture_serial(void **state)
{
	char *uri = "pkcs11:serial=123456;";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("123456", result->serial);
	pkcs11_uri_free(result);
}

static void
torture_invalid_token(void **state)
{
	char *uri = "pkcs11:invalid=123456";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 1);
	pkcs11_uri_free(result);
}

static void
torture_half_invalid_token(void **state)
{
	char *uri = "pkcs11:serial-number=123456;";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 1);
	pkcs11_uri_free(result);
}

static void
torture_spec_only_scheme(void **state)
{
	char *uri = "pkcs11:";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	pkcs11_uri_free(result);
}

static void
torture_spec_object_label(void **state)
{
	char *uri = "pkcs11:object=my-pubkey;type=public";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("my-pubkey", result->object);
	assert_string_equal("public", result->type);
	pkcs11_uri_free(result);
}

static void
torture_spec_type_pin(void **state)
{
	char *uri = "pkcs11:object=my-key;type=private?pin-source=file:/etc/token";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("my-key", result->object);
	assert_string_equal("private", result->type);
	assert_string_equal("file:/etc/token", result->pin_source);
	pkcs11_uri_free(result);
}

static void
torture_spec_token_object_serial_pin(void **state)
{
	char *uri = "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;"
		    "manufacturer=Snake%20Oil,%20Inc.;"
		    "model=1.0;"
		    "object=my-certificate;"
		    "type=cert;"
		    "id=%69%95%3E%5C%F4%BD%EC%91;"
		    "serial="
		    "?pin-source=file:/etc/token_pin";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("The Software PKCS#11 Softtoken", result->token_label);
	assert_string_equal("Snake Oil, Inc.", result->token_manufacturer);
	assert_string_equal("my-certificate", result->object);
	assert_string_equal("cert", result->type);
	assert_string_equal("\x69\x95\x3E\x5C\xF4\xBD\xEC\x91", result->id);
	assert_int_equal(8, result->id_len);
	assert_string_equal("", result->serial);
	assert_string_equal("file:/etc/token_pin", result->pin_source);
	pkcs11_uri_free(result);
}

static void
torture_spec_unsupported_module_name(void **state)
{
	char *uri = "pkcs11:object=my-sign-key;"
		    "type=private"
		    "?module-name=mypkcs11";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 1);
	pkcs11_uri_free(result);
}

static void
torture_module_path(void **state)
{
	char *uri = "pkcs11:object=my-sign-key;"
		    "type=private"
		    "?module-path=/mnt/libmypkcs11.so.1";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("my-sign-key", result->object);
	assert_string_equal("private", result->type);
	assert_string_equal("/mnt/libmypkcs11.so.1", result->module_path);
	pkcs11_uri_free(result);
}

static void
torture_pin_value(void **state)
{
	char *uri = "pkcs11:token=Software%20PKCS%2311%20softtoken;"
		    "manufacturer=Snake%20Oil,%20Inc."
		    "?pin-value=the-pin";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("Software PKCS#11 softtoken", result->token_label);
	assert_string_equal("Snake Oil, Inc.", result->token_manufacturer);
	assert_string_equal("the-pin", result->pin);
	pkcs11_uri_free(result);
}

static void
torture_encoded_semicolon(void **state)
{
	char *uri = "pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;"
		    "object=my-certificate;"
		    "type=cert";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 0);
	assert_string_equal("A name with a substring %;", result->token_label);
	assert_string_equal("my-certificate", result->object);
	assert_string_equal("cert", result->type);
	pkcs11_uri_free(result);
}

static void
torture_pin_pin_source(void **state)
{
	char *uri = "pkcs11:?pin-value=the-pin;pin-source=file:/path/to/pin";
	struct pkcs11_uri *result = pkcs11_uri_new();
	int rv = parse_pkcs11_uri(uri, result);
	assert_int_equal(rv, 1);
	pkcs11_uri_free(result);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
			cmocka_unit_test(torture_id_non_percent),
			cmocka_unit_test(torture_id_percent),
			cmocka_unit_test(torture_id_percent_incorrect),
			cmocka_unit_test(torture_manufacturer),
			cmocka_unit_test(torture_invalid_token),
			cmocka_unit_test(torture_half_invalid_token),
			cmocka_unit_test(torture_object),
			cmocka_unit_test(torture_empty_serial),
			cmocka_unit_test(torture_serial),
			cmocka_unit_test(torture_spec_only_scheme),
			cmocka_unit_test(torture_spec_object_label),
			cmocka_unit_test(torture_spec_type_pin),
			cmocka_unit_test(torture_spec_token_object_serial_pin),
			cmocka_unit_test(torture_spec_unsupported_module_name),
			cmocka_unit_test(torture_module_path),
			cmocka_unit_test(torture_pin_value),
			cmocka_unit_test(torture_encoded_semicolon),
			cmocka_unit_test(torture_pin_pin_source)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
