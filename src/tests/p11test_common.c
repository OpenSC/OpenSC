#include "p11test_common.h"

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

void init_card_info() {
	card_info.pin = NULL;
	card_info.pin_length = 0;
}

int set_card_info() {

	if (card_info.pin == NULL) {
		card_info.pin = (unsigned char *) strdup(DEFAULT_PIN);
		card_info.pin_length = strlen(DEFAULT_PIN);
	}

	return 0;
}

void clear_card_info() {
	if(card_info.pin)
		free(card_info.pin);
}
