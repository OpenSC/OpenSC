
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc.h"
#include "sc-pkcs15.h"

int main(int argc, char **argv) {
  struct sc_context *ctx = NULL;
  struct sc_card *card = NULL;
  struct sc_pkcs15_card *p15_card = NULL;
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

#if 1
  i = sc_pkcs15_enum_private_keys(p15_card);
  if (i < 0) {
    fprintf(stderr, "Private key enumeration failed with %s\n", sc_strerror(i));
    return 1;
  }
  printf("%d private keys found!\n", i);
  for (i = 0; i < p15_card->prkey_count; i++) {
    sc_pkcs15_print_prkey_info(&p15_card->prkey_info[i]);
  }
#endif
#if 1
  printf("Searching for PIN codes...\n");

  i = sc_pkcs15_enum_pins(p15_card);
  if (i < 0) {
  	fprintf(stderr, "Error enumerating PIN codes: %s\n", sc_strerror(i));
  	return 1;
  }
  if (i == 0)
  	fprintf(stderr, "No PIN codes found!\n");
  for (c = 0; c < i; c++) {
	sc_pkcs15_print_pin_info(&p15_card->pin_info[c]);
  }
#endif
#if 1
  i = sc_sec_ask_pin_code(&p15_card->pin_info[0], buf, sizeof(buf), "Please enter PIN code");
  if (i == 0) {
    i = sc_pkcs15_verify_pin(p15_card, &p15_card->pin_info[0], buf, strlen(buf));
    if (i) {
      if (i == SC_ERROR_PIN_CODE_INCORRECT)
    	fprintf(stderr, "Incorrect PIN code (%d tries left)\n", p15_card->pin_info[0].tries_left);
      else
	fprintf(stderr, "PIN verifying failed: %s\n", sc_strerror(i));
      return 1;
    }
    printf("PIN code correct.\n");
  } else {
    printf("\nNot verifying PIN code.\n");
  }
#endif
#if 1
  senv.signature = 0;
  senv.algorithm_ref = 0x02;
  senv.key_ref = 0;
  senv.key_file_id = p15_card->prkey_info[0].file_id;
  senv.app_df_path = p15_card->file_app.path;
  i = sc_set_security_env(p15_card->card, 1, &senv);
  if (i) {
    fprintf(stderr, "Security environment set failed: %s\n", sc_strerror(i));
    return 1;
  }
  file = fopen("cryptogram", "r");
  if (file != NULL) {
	i = fread(buf, 1, sizeof(buf), file);
	SCardSetTimeout(ctx->pcsc_ctx, 15000);
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
#if 1
  i = sc_pkcs15_enum_certificates(p15_card);
  if (i < 0) {
    fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(i));
    return 1;
  }
  printf("%d certificates found.\n", i);
#endif
#if 1
  for (i = 0; i < p15_card->cert_count; i++) {
  	sc_pkcs15_print_cert_info(&p15_card->cert_info[i]);
	c = sc_pkcs15_read_certificate(p15_card, &p15_card->cert_info[i],
				       &certbuf);
	if (c < 0) {
		fprintf(stderr, "Certificate read failed.\n");
		return 1;
	}
	printf("Certificate size is %d bytes\n", c);
//	sc_asn1_print_tags(certbuf, c);
	free(certbuf);
  }  
#endif
  printf("Cleaning up...\n");
  i = sc_pkcs15_destroy(p15_card);
  sc_disconnect_card(card);
  sc_destroy_context(ctx);
  
  return 0;
}
