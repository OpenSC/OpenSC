
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc.h"
#include "sc-pkcs15.h"
#include "sc-test.h"

#define DO_PRKEY_ENUM		0
#define	DO_PIN_ENUM		0
#define DO_PIN_VERIFY		0
#define DO_DECIPHER		0
#define DO_SIGN			0
#define DO_CERT_ENUM		1
#define DO_CERT_READ		1
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

int main(int argc, char **argv)
{
	u8 buf[256], buf2[256];
	struct sc_security_env senv;
	FILE *file;
	struct sc_object_id oid;
	struct timeval tv1, tv2;

	int i, c;

	i = sc_test_init(&argc, argv);
	if (i != 0)
		return 1;

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
#if DO_CERT_ENUM
	i = sc_pkcs15_enum_certificates(p15card);
	if (i < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n",
			sc_strerror(i));
		return 1;
	}
	printf("%d certificates found.\n", i);
#endif
#if DO_CERT_READ
	for (i = 0; i < p15card->cert_count; i++) {
		char fname[16];
		struct sc_pkcs15_cert *cert;

		sc_pkcs15_print_cert_info(&p15card->cert_info[i]);

		strcpy(fname, "cert-");
		sprintf(fname + 5, "%02X",
			p15card->cert_info[i].id.value[0]);
		file = fopen(fname, "w");
		if (file != NULL) {
			c = sc_pkcs15_read_certificate(p15card,
						       &p15card->cert_info[i],
						       &cert);
			if (c) {
				fprintf(stderr,
					"Certificate read failed.\n ");
				return 1;
			}
			printf("Dumping certificate to file '%s' (%d bytes)\n",
			       fname, cert->data_len);
			fwrite(cert->data, cert->data_len, 1, file);
			sc_pkcs15_free_certificate(cert);
			fclose(file);
		}
	}
#endif
	printf("Cleaning up...\n");
	sc_test_cleanup();

	return 0;
}
