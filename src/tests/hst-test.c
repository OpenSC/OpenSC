
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sc.h>
#include <sc-pkcs15.h>
#include <sc-asn1.h>
#include "sc-test.h"

#define DO_PRKEY_ENUM		0
#define	DO_PIN_ENUM		0
#define DO_PIN_VERIFY		0
#define DO_DECIPHER		0
#define DO_SIGN			0
#define DO_TEST			0

struct sc_pkcs15_card *p15card;

int enum_private_keys()
{
	int i;
	i = sc_pkcs15_enum_private_keys(p15card);
	if (i < 0) {
		fprintf(stderr, "Private key enumeration failed with %s\n",
			sc_strerror(i));
		return 1;
	}

	printf("%d private keys found!\n", i);
	for (i = 0; i < p15card->prkey_count; i++) {
		sc_pkcs15_print_prkey_info(&p15card->prkey_info[i]);
	}
	return 0;
}

int test()
{
	struct sc_file file;
	struct sc_path path;
	
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
	r = sc_pkcs15_verify_pin(p15card, &p15card->pin_info[0], "\x31\x32\x33\x34", 4);
	if (r) {
		fprintf(stderr, "PIN code verification failed: %s\n", sc_strerror(r));
		goto err;
	}
#endif
	memcpy(path.value, "\x3f\x00", 2);
	path.len = 2;
	sc_debug = 1;
	r = sc_select_file(card, &file, &path, SC_SELECT_FILE_BY_PATH);
	if (r) {
		fprintf(stderr, "sc_select_file failed: %s\n", sc_strerror(r));
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

int main(int argc, char **argv)
{
	int i;

	i = sc_test_init(&argc, argv);
	if (i != 0)
		return 1;

	if (test())
		return 1;

	return 0;
		
	i = sc_pkcs15_init(card, &p15card);
	if (i != 0) {
		fprintf(stderr, "PKCS#15 card init failed: %s\n",
			sc_strerror(i));
		return 1;
	}
	sc_pkcs15_print_card(p15card);

#if DO_PRKEY_ENUM
	if (enum_private_keys())
		return 1;
#endif
#if DO_DECIPHER
	senv.signature = 0;
	senv.algorithm_ref = 0x02;
	senv.key_ref = 0;
	senv.key_file_id = p15card->prkey_info[0].file_id;
	senv.app_df_path = p15card->file_app.path;
	i = sc_set_security_env(p15card->card, &senv);
	if (i) {
		fprintf(stderr, "Security environment set failed: %s\n",
			sc_strerror(i));
		return 1;
	}
	file = fopen("cryptogram", "r");
	if (file != NULL) {
		i = fread(buf, 1, sizeof(buf), file);
		c = sc_decipher(card, buf, i, buf2, sizeof(buf2));
		if (c < 0) {
			fprintf(stderr, "Decipher failed: (%d) %s\n", c,
				sc_strerror(c));
		} else {
			printf("Decrypted payload: ");
			for (i = 0; i < c; i++) {
				printf("%02X ", buf2[i]);
			}
			printf("\n");
			fclose(file);
			file = fopen("decrypted.dat", "w");
			fwrite(buf2, c, 1, file);
			fclose(file);
		}
	} else {
		printf("File 'cryptogram' not found, not decrypting.\n");
	}
#endif
#if DO_SIGN
	senv.signature = 1;
	senv.algorithm_ref = 0x02;
	senv.key_ref = 0;
	senv.key_file_id = p15card->prkey_info[0].file_id;
	senv.app_df_path = p15card->file_app.path;
	i = sc_set_security_env(p15card->card, &senv);
	if (i) {
		fprintf(stderr, "Security environment set failed: %s\n",
			sc_strerror(i));
		return 1;
	}
	file = fopen("input", "r");
	if (file != NULL) {
		i = fread(buf, 1, sizeof(buf), file);
		SCardSetTimeout(ctx->pcsc_ctx, 15000);
		c = sc_compute_signature(card, buf, i, buf2, sizeof(buf2));
		if (c < 0) {
			fprintf(stderr, "Signing failed: (%d) %s\n", c,
				sc_strerror(c));
		} else {
			printf("Signed payload: ");
			for (i = 0; i < c; i++) {
				printf("%02X ", buf2[i]);
			}
			printf("\n");
			fclose(file);
			file = fopen("signed.dat", "w");
			fwrite(buf2, c, 1, file);
			fclose(file);
		}
	} else {
		printf("File 'input' not found, not signing.\n");
	}
#endif
	printf("Cleaning up...\n");
	sc_test_cleanup();

	return 0;
}
