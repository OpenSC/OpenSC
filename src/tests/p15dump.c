/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 objects test
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "sc-test.h"

struct sc_pkcs15_card *p15card;

static int dump_objects(const char *what, int type)
{
	struct sc_pkcs15_object **objs;
	int count, i;

	printf("\nEnumerating %s... ", what);
	fflush(stdout);

	sc_lock(card);
	count = sc_pkcs15_get_objects(p15card, type, NULL, 0);
	if (count < 0) {
		printf("failed.\n");
		fprintf(stderr, "Error enumerating %s: %s\n",
			what, sc_strerror(count));
		sc_unlock(card);
		return 1;
	}
	if (count == 0) {
		printf("none found.\n");
		sc_unlock(card);
		return 0;
	}
	printf("%u found.\n", count);

	objs = (struct sc_pkcs15_object **) calloc(count, sizeof(*objs));
	if ((count = sc_pkcs15_get_objects(p15card, type, objs, count)) < 0) {
		fprintf(stderr, "Error enumerating %s: %s\n",
			what, sc_strerror(count));
	} else {
		for (i = 0; i < count; i++)
			sc_test_print_object(objs[i]);
	}
	free(objs);
	sc_unlock(card);
	return (count < 0) ? 1 : 0;
}

int main(int argc, char *argv[])
{
	int i;

	i = sc_test_init(&argc, argv);
	if (i < 0)
		return 1;
	printf("Looking for a PKCS#15 compatible Smart Card... ");
	fflush(stdout);
	sc_lock(card);
	i = sc_pkcs15_bind(card, &p15card);
	/* Keep card locked to prevent useless calls to sc_logout */
	if (i) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		return 1;
	}
	printf("found.\n");
	sc_test_print_card(p15card);

	dump_objects("PIN codes", SC_PKCS15_TYPE_AUTH_PIN);
	dump_objects("Private keys", SC_PKCS15_TYPE_PRKEY);
	dump_objects("Public keys", SC_PKCS15_TYPE_PUBKEY);
	dump_objects("X.509 certificates", SC_PKCS15_TYPE_CERT_X509);
	dump_objects("data objects", SC_PKCS15_TYPE_DATA_OBJECT);

	sc_pkcs15_unbind(p15card);
	sc_unlock(card);
	sc_test_cleanup();
	return 0;
}
