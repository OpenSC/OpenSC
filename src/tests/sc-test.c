/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * Common functions for test programs
 */

#include <stdio.h>
#include <stdlib.h>
#include "opensc.h"

struct sc_context *ctx;
struct sc_card *card;

int sc_test_init(int *argc, char *argv[])
{
	int i, c;

	printf("Using libopensc version %s.\n", sc_version);
	i = sc_establish_context(&ctx);
	if (i < 0) {
		printf("sc_establish_context() failed (%d)\n", i);
		return i;
	}
	ctx->error_file = stderr;
	ctx->debug_file = stdout;
	i = sc_detect_card_presence(ctx->reader[0], 0);
	printf("Card %s.\n", i == 1 ? "present" : "absent");
	if (i < 0) {
		return i;
	}
	if (i == 0) {
		printf("Please insert a smart card.\n");
		fflush(stdout);
#if 0
		i = sc_wait_for_card(ctx, -1, -1);
		if (i < 0)
			return i;
		if (i != 1)
			return -1;
#endif
		c = -1;
		for (i = 0; i < ctx->reader_count; i++) {
			if (sc_detect_card_presence(ctx->reader[i], 0) == 1) {
				printf("Card detected in reader '%s'\n", ctx->reader[i]->name);
				c = i;
				break;
			}
		}
	} else
		c = 0;
	printf("Connecting... ");
	fflush(stdout);
	i = sc_connect_card(ctx->reader[c], 0, &card);
	if (i != 0) {
		printf("Connecting to card failed\n");
		return i;
	}
	printf("connected. ATR = ");
	for (i = 0; i < card->atr_len; i++) {
		if (i)
			printf(":");
		printf("%02X", (u8) card->atr[i]);
	}
	printf("\n");
	fflush(stdout);

	return 0;
}

void sc_test_cleanup(void)
{
	sc_disconnect_card(card, 0);
	sc_destroy_context(ctx);
}
