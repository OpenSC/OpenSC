
/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc.h"

int main(int argc, char **argv) {
  struct sc_context *ctx = NULL;
  struct sc_card *card = NULL;
  struct sc_pkcs15_card *p15_card = NULL;
  struct sc_pkcs15_pin_info pin;
  char buf[16], buf2[16];
  char certbuf[2048];
  
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
  i = sc_pkcs15_enum_certificates(p15_card);
  if (i < 0) {
    fprintf(stderr, "Certificate enumeration failed with %s\n", sc_strerror(i));
    return 1;
  }
  printf("%d certificates found.\n", i);
  for (i = 0; i < p15_card->cert_count; i++) {
  	sc_pkcs15_print_cert_info(&p15_card->cert_info[i]);
	c = sc_pkcs15_read_certificate(p15_card, &p15_card->cert_info[i],
				       (u8 *) certbuf, 2048);
	if (c < 0) {
		fprintf(stderr, "Certificate read failed.\n");
		return 1;
	}
	printf("Certificate size is %d bytes\n", c);
  }  
  return 0;

  printf("Searching for PIN codes...\n");

  c = 0;
  while (sc_pkcs15_read_pin_info(p15_card, ++c, &pin) == 0) {
  	sc_pkcs15_print_pin_info(&pin);
  }
  c--;
  if (c == 0) {
  	printf("No PIN codes found!\n");
  	return 1;
  }

  i = sc_sec_ask_pin_code(&p15_card->pins[0], buf, sizeof(buf), "Please enter PIN code");
  if (i) {
    fprintf(stderr, "\nFailed to ask PIN code from user\n");
    return 1;
  }
  i = sc_sec_ask_pin_code(&p15_card->pins[0], buf2, sizeof(buf2), "Please enter _new_ PIN code");
  if (i) {
    fprintf(stderr, "\nFailed to ask PIN code from user\n");
    return 1;
  }
  i = sc_pkcs15_change_pin(p15_card, &p15_card->pins[0], buf, strlen(buf), buf2, strlen(buf2));
//  i = sc_pkcs15_verify_pin(p15_card, &p15_card->pins[0], buf, strlen(buf));
  if (i) {
    if (i == SC_ERROR_PIN_CODE_INCORRECT)
    	fprintf(stderr, "Incorrect PIN code (%d tries left)\n", p15_card->pins[0].tries_left);
    else
	fprintf(stderr, "PIN verifying failed: %s\n", sc_strerror(i));
    return 1;
  }
  printf("PIN code correct.\n");
  
  printf("Cleaning up...\n");
  i = sc_pkcs15_destroy(p15_card);
  sc_disconnect_card(card);
  sc_destroy_context(ctx);

  return 0;
  
  return 0;
}
