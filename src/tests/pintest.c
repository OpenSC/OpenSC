/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 PIN code test
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "sc-test.h"

struct sc_pkcs15_card *p15card;

int enum_pins(struct sc_pkcs15_object ***ret)
{
	struct sc_pkcs15_object **objs;
	int i, n;

	n = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, NULL, 0);
	if (n < 0) {
		fprintf(stderr, "Error enumerating PIN codes: %s\n",
			sc_strerror(n));
		return 1;
	}
	if (n == 0) {
		fprintf(stderr, "No PIN codes found!\n");
		return 0;
	}
	objs = (struct sc_pkcs15_object **) calloc(n, sizeof(*objs));
	sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, n);
	for (i = 0; i < n; i++) {
		sc_test_print_object(objs[i]);
	}
	*ret = objs;
	return n;
}

int ask_and_verify_pin(struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_pin_info *pin;
	int i = 0;
	char prompt[80];
	u8 *pass;

	pin = (struct sc_pkcs15_pin_info *) obj->data;
	while (1) {
		sprintf(prompt, "Please enter PIN code [%s]: ", obj->label);
		pass = (u8 *) getpass(prompt);

		if (strlen((char *) pass) == 0) {
			printf("Not verifying PIN code.\n");
			return -1;
		}
		if (strlen((char *) pass) < pin->min_length)
			break;
		if (strlen((char *) pass) > pin->max_length)
			break;
		break;
	}

	sc_lock(card);
	i = sc_pkcs15_verify_pin(p15card, pin, pass, strlen((char *) pass));
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
	struct sc_pkcs15_object **objs;
	int i, count;

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	printf("Looking for a PKCS#15 compatible Smart Card... ");
	fflush(stdout);
	sc_lock(card);
	i = sc_pkcs15_bind(card, &p15card);
	sc_unlock(card);
	if (i) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		sc_test_cleanup();
		return 1;
	}
	printf("found.\n");
	printf("Enumerating PIN codes...\n");
	sc_lock(card);
	count = enum_pins(&objs);
	sc_unlock(card);
	if (count < 0) {
		sc_pkcs15_unbind(p15card);
		sc_test_cleanup();
		return 1;
	}
	for (i = 0; i < count; i++) {
		ask_and_verify_pin(objs[i]);
	}
	sc_pkcs15_unbind(p15card);
	sc_test_cleanup();
	return 0;
}
