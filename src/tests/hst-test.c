
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc.h"
#include "sc-pkcs15.h"

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15_card = NULL;

#define DO_PRKEY_ENUM		1
#define	DO_PIN_ENUM		1
#define DO_PIN_VERIFY		1
#define DO_DECIPHER		0
#define DO_SIGN			1
#define DO_CERT_ENUM		0
#define DO_CERT_READ		0

int enum_private_keys()
{
	int i;
	i = sc_pkcs15_enum_private_keys(p15_card);
	if (i < 0) {
		fprintf(stderr, "Private key enumeration failed with %s\n", sc_strerror(i));
		return 1;
	}

	printf("%d private keys found!\n", i);
	for (i = 0; i < p15_card->prkey_count; i++) {
		sc_pkcs15_print_prkey_info(&p15_card->prkey_info[i]);
	}
	return 0;
}

int enum_pins()
{
	int i, c;

	c = sc_pkcs15_enum_pins(p15_card);
	if (c < 0) {
  		fprintf(stderr, "Error enumerating PIN codes: %s\n", sc_strerror(i));
		return 1;
	}
	if (c == 0)
		fprintf(stderr, "No PIN codes found!\n");
	for (i = 0; i < c; i++) {
		sc_pkcs15_print_pin_info(&p15_card->pin_info[i]);
	}
	return 0;
}

int ask_and_verify_pin(struct sc_pkcs15_pin_info *pin)
{
	int i;
	char buf[32];
	
	i = sc_sec_ask_pin_code(pin, buf, sizeof(buf), "Please enter PIN code");
	if (i == 0) {
		i = sc_pkcs15_verify_pin(p15_card, pin, buf, strlen(buf));
		if (i) {
			if (i == SC_ERROR_PIN_CODE_INCORRECT)
				fprintf(stderr, "Incorrect PIN code (%d tries left)\n", pin->tries_left);
			else
				fprintf(stderr, "PIN verifying failed: %s\n", sc_strerror(i));
			return 1;
		}
		printf("PIN code correct.\n");
	} else {
		printf("\nNot verifying PIN code.\n");
	}
	return 0;
}

int main(int argc, char **argv) {
  u8 buf[256], buf2[256];
  u8 *certbuf;
  struct sc_security_env senv;
  FILE *file;
  
  int i,c ;

  i = sc_establish_context(&ctx);
  if (i < 0) {
  	printf("sc_establish_context() failed (%d)\n", i);
  	return 1;
  }
  i = sc_detect_card(ctx, 0);
  printf("Card %s.\n", i == 1 ? "present" : "absent");
  if (i < 0) {
    return 1;
  }
  if (i == 0) {
    printf("Please insert a smart card.");
    fflush(stdout);
    i = sc_wait_for_card(ctx, 0, -1);
    if (i != 1)
    	return 1;
    printf("\n");
  }
  printf("Connecting... ");
  fflush(stdout);
  i = sc_connect_card(ctx, 0, &card);
  if (i != 0) {
    printf("Connecting to card failed\n");
    return 1;
  }
  printf("done.\n");
  fflush(stdout);

  i = sc_pkcs15_init(card, &p15_card);
  if (i != 0) {
    fprintf(stderr, "PKCS#15 card init failed: %s\n", sc_strerror(i));
    return 1;
  }
  sc_pkcs15_print_card(p15_card);

#if DO_PRKEY_ENUM
	if (enum_private_keys())
		return 1;
#endif
#if DO_PIN_ENUM
	if (enum_pins())
		return 1;
#endif
#if DO_PIN_VERIFY
	if (ask_and_verify_pin(&p15_card->pin_info[0]))
		return 1;
#endif
#if DO_DECIPHER
  senv.signature = 0;
  senv.algorithm_ref = 0x02;
  senv.key_ref = 0;
  senv.key_file_id = p15_card->prkey_info[0].file_id;
  senv.app_df_path = p15_card->file_app.path;
  i = sc_set_security_env(p15_card->card, &senv);
  if (i) {
    fprintf(stderr, "Security environment set failed: %s\n", sc_strerror(i));
    return 1;
  }
  file = fopen("cryptogram", "r");
  if (file != NULL) {
	i = fread(buf, 1, sizeof(buf), file);
	c = sc_decipher(card, buf, i, buf2, sizeof(buf2));
	if (c < 0) {
		fprintf(stderr, "Decipher failed: (%d) %s\n", c, sc_strerror(c));
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
  senv.key_file_id = p15_card->prkey_info[0].file_id;
  senv.app_df_path = p15_card->file_app.path;
  i = sc_set_security_env(p15_card->card, &senv);
  if (i) {
    fprintf(stderr, "Security environment set failed: %s\n", sc_strerror(i));
    return 1;
  }
  file = fopen("input", "r");
  if (file != NULL) {
	i = fread(buf, 1, sizeof(buf), file);
	SCardSetTimeout(ctx->pcsc_ctx, 15000);
	c = sc_compute_signature(card, buf, i, buf2, sizeof(buf2));
	if (c < 0) {
		fprintf(stderr, "Signing failed: (%d) %s\n", c, sc_strerror(c));
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
  i = sc_pkcs15_enum_certificates(p15_card);
  if (i < 0) {
    fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(i));
    return 1;
  }
  printf("%d certificates found.\n", i);
#endif
#if DO_CERT_READ
  for (i = 0; i < p15_card->cert_count; i++) {
	char fname[16];

  	sc_pkcs15_print_cert_info(&p15_card->cert_info[i]);

	strcpy(fname, "cert-");
	sprintf(fname+5, "%02X", p15_card->cert_info[i].id.value[0]);
	file = fopen(fname, "r");
	if (file == NULL) {
		file = fopen(fname, "w");
		c = sc_pkcs15_read_certificate(p15_card, &p15_card->cert_info[i],
					       &certbuf);
		if (c < 0) {
			fprintf(stderr, "Certificate read failed.\n");
			return 1;
		}
		printf("Dumping certificate to file '%s' (%d bytes)\n", fname, c);
		fwrite(certbuf, c, 1, file);
		free(certbuf);
	}
	fclose(file);
  }  
#endif
  printf("Cleaning up...\n");
  i = sc_pkcs15_destroy(p15_card);
  sc_disconnect_card(card);
  sc_destroy_context(ctx);
  
  return 0;
}
