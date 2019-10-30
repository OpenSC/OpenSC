/*
 * p11test.c: Test suite for PKCS#11 API
 *
 * Copyright (C) 2016 Martin Strhársky <strharsky.martin@gmail.com>
 * Copyright (C) 2016, 2017 Red Hat, Inc.
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

#include <getopt.h>
#include "p11test_helpers.h"

#include "p11test_case_readonly.h"
#include "p11test_case_multipart.h"
#include "p11test_case_ec_sign.h"
#include "p11test_case_ec_derive.h"
#include "p11test_case_usage.h"
#include "p11test_case_mechs.h"
#include "p11test_case_wait.h"
#include "p11test_case_pss_oaep.h"

#define DEFAULT_P11LIB	"../../pkcs11/.libs/opensc-pkcs11.so"

void display_usage() {
	fprintf(stdout,
		" Usage:\n"
		"	./p11test [-m module_path] [-s slot_id] [-p pin]\n"
		"		-m module_path	Path to tested module (e.g. /usr/lib64/opensc-pkcs11.so)\n"
		"						Default is "DEFAULT_P11LIB"\n"
		"		-p pin			Application PIN\n"
		"		-s slot_id		Slot ID with the card\n"
		"		-i				Wait for the card before running the test (interactive)\n"
		"		-o				File to write a log in JSON\n"
		"		-h				This help\n"
		"\n");
}

int main(int argc, char** argv) {
	signed char command;
	const struct CMUnitTest readonly_tests_without_initialization[] = {
		/* Test card events on slot */
		cmocka_unit_test_setup_teardown(wait_test,
			token_initialize, token_cleanup),

		/* Check all the mechanisms provided by the token */
		cmocka_unit_test_setup_teardown(supported_mechanisms_test,
			token_setup, token_cleanup),

		/* Complex readonly test of all objects on the card */
		cmocka_unit_test_setup_teardown(readonly_tests,
			user_login_setup, after_test_cleanup),

		/* Multipart signatures and encryption */
		cmocka_unit_test_setup_teardown(multipart_tests,
			user_login_setup, after_test_cleanup),

		/* Regression test Sign&Verify with various data lengths */
		cmocka_unit_test_setup_teardown(ec_sign_size_test,
			user_login_setup, after_test_cleanup),

		/* Verify that the Usage flags on the objects are sane */
		cmocka_unit_test_setup_teardown(usage_test,
			user_login_setup, after_test_cleanup),

		/* Verify that RSA-PSS and RSA-OAEP functions if supported */
		cmocka_unit_test_setup_teardown(pss_oaep_test,
			user_login_setup, after_test_cleanup),

		/* Verify that ECDH key derivation works */
		cmocka_unit_test_setup_teardown(derive_tests,
			user_login_setup, after_test_cleanup),
	};

	token.library_path = NULL;
	token.pin = NULL;
	token.pin_length = 0;
	token.interactive = 0;
	token.slot_id = (unsigned long) -1;
	token.log.outfile = NULL;

	while ((command = getopt(argc, argv, "?hm:s:p:io:")) != -1) {
		switch (command) {
			case 'o':
				token.log.outfile = strdup(optarg);
				break;
			case 'm':
				token.library_path = strdup(optarg);
				break;
			case 's':
				token.slot_id = atol(optarg);
				break;
			case 'p':
				token.pin = (CK_UTF8CHAR*) strdup(optarg);
				token.pin_length = strlen(optarg);
				break;
			case 'i':
				token.interactive = 1;
				break;
			case 'h':
			case '?':
				display_usage();
				return 0;
			default:
				break;
		}
	}

	if (token.library_path == NULL) {
		debug_print("Falling back to the default library " DEFAULT_P11LIB);
		token.library_path = strdup(DEFAULT_P11LIB);
	}

	if (token.pin == NULL || token.pin_length == 0) {
		printf("No PIN specified. Please, specify it on command-line using -p switch\n");
		return -1;
	}

	debug_print("Card info:\n\tPIN %s\n\tPIN LENGTH %lu\n\t",
		token.pin, token.pin_length);

	return cmocka_run_group_tests(readonly_tests_without_initialization,
		group_setup, group_teardown);
}

