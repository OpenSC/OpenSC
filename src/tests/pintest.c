
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 PIN code test
 */

#include "sc-test.h"
#include "opensc.h"
#include "opensc-pkcs15.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct sc_pkcs15_card *p15card;

int enum_pins()
{
	int i, c;

	c = sc_pkcs15_enum_pins(p15card);
	if (c < 0) {
		fprintf(stderr, "Error enumerating PIN codes: %s\n",
			sc_strerror(i));
		return 1;
	}
	if (c == 0)
		fprintf(stderr, "No PIN codes found!\n");
	for (i = 0; i < c; i++) {
		sc_pkcs15_print_pin_info(&p15card->pin_info[i]);
	}
	return 0;
}


int ask_and_verify_pin(struct sc_pkcs15_pin_info *pin)
{
	int i = 0;
        char prompt[80];
        char *pass;

	while (1) {
		sprintf(prompt, "Please enter PIN code [%s]: ", pin->com_attr.label);
                pass = getpass(prompt);

		if (strlen(pass) == 0) {
			printf("Not verifying PIN code.\n");
			return -1;
		}
		if (strlen(pass) < pin->min_length)
			break;
		if (strlen(pass) > pin->stored_length)
			break;
		break;
	}

       	sc_lock(card);
       	i = sc_pkcs15_verify_pin(p15card, pin, pass, strlen(pass));
       	sc_unlock(card);
       	if (i) {
       		if (i == SC_ERROR_PIN_CODE_INCORRECT)
       			fprintf(stderr,
       				"Incorrect PIN code (%d tries left)\n",
       				pin->tries_left);
       		else
       			fprintf(stderr,
       				"PIN verifying failed: %s\n",
       				sc_strerror(i));
       		return 1;
       	} else
		printf("PIN code correct.\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int i, c;

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	printf("Looking for a PKCS#15 compatible Smart Card... ");
	fflush(stdout);
	sc_lock(card);
	i = sc_pkcs15_init(card, &p15card);
	sc_unlock(card);
	if (i) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		return 1;
	}
	printf("found.\n");
	printf("Enumerating PIN codes...\n");
	sc_lock(card);
	i = enum_pins();
	sc_unlock(card);
	if (i)
		return 1;
	for (c = 0; c < p15card->pin_count; c++) {
		ask_and_verify_pin(&p15card->pin_info[c]);
	}
	sc_test_cleanup();
	return 0;
}
