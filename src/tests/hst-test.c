
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opensc.h>
#include <opensc-pkcs15.h>
#include "sc-test.h"

struct sc_pkcs15_card *p15card;

int test()
{
	struct sc_file file;
	struct sc_path path;
	struct sc_apdu apdu;
	u8 rbuf[MAX_BUFFER_SIZE], sbuf[MAX_BUFFER_SIZE];
	
	int r;
	
	sc_lock(card);
	
#if 1
	r = sc_pkcs15_init(card, &p15card);
	if (r < 0) {
		fprintf(stderr, "PKCS#15 init failed: %s\n", sc_strerror(r));
		goto err;
	}
	r = sc_pkcs15_enum_pins(p15card);
	if (r < 0) {
		fprintf(stderr, "PIN code enum failed: %s\n", sc_strerror(r));
		goto err;
	}
	memcpy(path.value, "\x51\x10", 2);
	path.len = 2;
	sc_debug = 3;
	r = sc_select_file(card, &file, &path, SC_SELECT_FILE_BY_PATH);
	sc_debug = 0;
	if (r) {
		fprintf(stderr, "sc_select_file failed: %s\n", sc_strerror(r));
		goto err;
	}
	r = sc_pkcs15_verify_pin(p15card, &p15card->pin_info[0], "\x31\x32\x33\x34", 4);
	if (r) {
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(r));
		goto err;
	}
#endif
	sc_debug = 3;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, 1);
	apdu.lc = 8;
	apdu.data = sbuf;
	apdu.datalen = 8;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	memcpy(sbuf, "\x31\x32\x33\x34\x00\x00\x00\x00", 8);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "transmit failed: %s\n", sc_strerror(r));
		goto err;
	}
	r = sc_delete_file(card, 0x5110);
	if (r) {
		fprintf(stderr, "fail: %s\n", sc_strerror(r));
		goto err;
	}

	return 0;

	memset(&file, 0, sizeof(file));
	file.id = 0x5110;
	file.sec_attr_len = 6;
	memcpy(file.sec_attr, "\x00\x00\x00\x00\x00\x00", 6);
	file.prop_attr_len = 3;
	memcpy(file.prop_attr, "\x23\x00\x00", 3);
	file.size = 32;
	file.type = SC_FILE_TYPE_WORKING_EF;
	file.ef_structure = SC_FILE_EF_TRANSPARENT;

	sc_debug = 1;
	r = sc_create_file(card, &file);

err:
	sc_unlock(card);
	return r;
}

int test2()
{
	int r;
	struct sc_path path;
	struct sc_file file;
	
	memcpy(path.value, "\x3F\x00", 2);
	path.len = 2;
	
	sc_debug = 3;
	r = sc_select_file(card, &file, &path, SC_SELECT_FILE_BY_PATH);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return r;
	}
	return 0;
}

int test3()
{
	FILE *inf;
	u8 buf[256], txt[256];
	int len, r;
	struct sc_pkcs15_pin_info *pin;
	struct sc_pkcs15_prkey_info *key;
	
	r = sc_pkcs15_init(card, &p15card);
	if (r) {
		fprintf(stderr, "pkcs15 init failed: %s\n", sc_strerror(r));
		return -1;
	}
	r = sc_pkcs15_enum_private_keys(p15card);
	if (r < 0) {
		fprintf(stderr, "pkcs15 enum prk: %s\n", sc_strerror(r));
		return -1;
	}
	key = &p15card->prkey_info[0];
	r = sc_pkcs15_enum_pins(p15card);
	if (r < 0) {
		fprintf(stderr, "pkcs15 enum pins: %s\n", sc_strerror(r));
		return -1;
	}
	pin = &p15card->pin_info[0];
	inf = fopen("crypt.dat", "r");
	if (inf == NULL)
		return -1;
	len = fread(buf, 1, sizeof(buf), inf);

	r = sc_pkcs15_verify_pin(p15card, pin, "\x31\x32\x33\x34", 4);
	if (r) {
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(r));
		return -1;
	}
	r = sc_pkcs15_decipher(p15card, key, buf, len, txt, sizeof(txt));
	if (r < 0) {
		fprintf(stderr, "decipher failed: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int i;

	i = sc_test_init(&argc, argv);
	if (i != 0)
		return 1;
	
	sc_debug = 3;
	if (test3())
		return 1;

	sc_test_cleanup();

	return 0;
}
