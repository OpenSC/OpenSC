#include <getopt.h>
#include "p11test_helpers.h"

#include "p11test_case_readonly.h"
#include "p11test_case_ec_sign.h"
#include "p11test_case_mechs.h"

#define DEFAULT_P11LIB	"../pkcs11/.libs/opensc-pkcs11.so"

void display_usage() {
	fprintf(stdout,
		" usage:\n"
		"	./p11test [-m module_path] [-p pin]\n"
		"		-m module_path	Path to tested module (e.g. /usr/lib64/opensc-pkcs11.so)\n"
		"						Default is "DEFAULT_P11LIB"\n"
		"		-p pin:			Application PIN\n"
		"		-h				This help\n"
		"\n");
}

int main(int argc, char** argv) {

	char command;
	const struct CMUnitTest readonly_tests_without_initialization[] = {
		/* Check all the mechanisms provided by the token */
		cmocka_unit_test_setup_teardown(supported_mechanisms_test,
			token_setup, token_cleanup),

		/* Regression test Sign&Verify with various data lengths */
		cmocka_unit_test_setup_teardown(ec_sign_size_test,
			user_login_setup, after_test_cleanup),

		/* Complex readonly test of all objects on the card */
		cmocka_unit_test_setup_teardown(readonly_tests,
			user_login_setup, after_test_cleanup),
	};

	token.library_path = NULL;
	token.pin = NULL;
	token.pin_length = 0;

	while ((command = getopt(argc, argv, "?hm:p:")) != -1) {
		switch (command) {
			case 'm':
				token.library_path = strdup(optarg);
				break;
			case 'p':
				token.pin = (CK_UTF8CHAR*) strdup(optarg);
				token.pin_length = strlen(optarg);
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
		debug_print("Falling back to the default PIN " DEFAULT_PIN);
		token.pin = (CK_UTF8CHAR*) strdup(DEFAULT_PIN);
		token.pin_length = strlen(DEFAULT_PIN);
	}

	debug_print("Card info:\n\tPIN %s\n\tPIN LENGTH %lu\n\t",
		token.pin, token.pin_length);

	return cmocka_run_group_tests(readonly_tests_without_initialization,
		group_setup, group_teardown);
}

