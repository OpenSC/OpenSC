
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * PKCS#15 PIN code test
 */

#include "sc-test.h"
#include "sc.h"
#include "sc-pkcs15.h"
#include "sc-asn1.h"
#include <stdio.h>
#include <stdlib.h>

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
	sc_pkcs15_print_card(p15card);

	printf("Enumerating PIN codes...\n");
	sc_lock(card);
	i = enum_pins();
	sc_unlock(card);
	if (i)
		return 1;

	printf("Enumerating private keys... ");
	fflush(stdout);
	sc_lock(card);
	i = sc_pkcs15_enum_private_keys(p15card);
	sc_unlock(card);
	if (i < 0) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		return 1;
	}
	printf("done.\n");
	for (c = 0; c < p15card->prkey_count; c++) {
		sc_pkcs15_print_prkey_info(&p15card->prkey_info[c]);
	}

	printf("Enumerating certificates... ");
	fflush(stdout);
	sc_lock(card);
	i = sc_pkcs15_enum_certificates(p15card);
	sc_unlock(card);
	if (i < 0) {
		fprintf(stderr, "failed: %s\n", sc_strerror(i));
		return 1;
	}
	printf("done.\n");
	for (c = 0; c < p15card->cert_count; c++) {
		sc_pkcs15_print_cert_info(&p15card->cert_info[c]);
	}

	for (c = 0; c < p15card->cert_count; c++) {
		struct sc_pkcs15_cert *cert;
		
		printf("Reading %s... ", p15card->cert_info[c].com_attr.label);
		fflush(stdout);
		i = sc_pkcs15_read_certificate(p15card, &p15card->cert_info[c], &cert);
		if (i) {
			fprintf(stderr, "failed: %s\n", sc_strerror(i));
			return 1;
		}
		printf("\n");
		sc_asn1_print_tags(cert->data, cert->data_len);
	}
	sc_test_cleanup();
	return 0;
}
