
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
  struct sc_pkcs15_card p15_card;
  int i;

  i = sc_establish_context(&ctx);
  if (i < 0) {
  	printf("sc_establish_context() failed (%d)\n", i);
  	return 1;
  }
  i = sc_detect_card(ctx, 0);
  fprintf(stderr, "Card %s.\n", i == 1 ? "present" : "absent");
  if (i != 1) {
    return 1;
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
    fprintf(stderr, "PKCS#15 card init failed with %d\n", i);
    return 1;
  }
  
  i = sc_pkcs15_read_certificate(&p15_card, 0);
  if (i) {
    fprintf(stderr, "Certificate read failed with %d\n", i);
    return 1;
  }
  i = sc_pkcs15_read_pin_object(&p15_card, 1, NULL);
  if (i) {
    fprintf(stderr, "PIN object read failed with %d\n", i);
    return 1;
  }
  printf("Cleaning up...\n");
  sc_disconnect_card(card);
  sc_destroy_context(ctx);
  
  return 0;
}
