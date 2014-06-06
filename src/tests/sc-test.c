/* Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi> 
 * All rights reserved.
 *
 * Common functions for test programs
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"
#include "sc-test.h"

sc_context_t *ctx;
sc_card_t *card;

static const struct option	options[] = {
	{ "reader",             1, NULL,           'r' },
	{ "driver",		1, NULL,           'c' },
	{ "debug",              0, NULL,           'd' },
	{ NULL, 0, NULL, 0 }
};

int sc_test_init(int *argc, char *argv[])
{
	char	*opt_driver = NULL, *app_name;
	int	opt_debug = 0, opt_reader = -1;
	int	i, c, rc;
	sc_context_param_t ctx_param;

	if  ((app_name = strrchr(argv[0], '/')) != NULL)
		app_name++;
	else
		app_name = argv[0];

	while ((c = getopt_long(*argc, argv, "r:c:d", options, NULL)) != -1) {
		switch (c) {
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'd':
			opt_debug++;
			break;
		default:
			fprintf(stderr,
				"usage: %s [-r reader] [-c driver] [-d]\n",
				app_name);
			exit(1);
		}
	}
	*argc = optind;

	printf("Using libopensc version %s.\n", sc_get_version());

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	i = sc_context_create(&ctx, &ctx_param);
	if (i != SC_SUCCESS) {
		printf("Failed to establish context: %s\n", sc_strerror(i));
		return i;
	}
	ctx->debug = opt_debug;

	if (opt_reader >= (int) sc_ctx_get_reader_count(ctx)) {
		fprintf(stderr, "Illegal reader number.\n"
				"Only %d reader(s) configured.\n",
				sc_ctx_get_reader_count(ctx));
		exit(1);
	}

	while (1) {
		if (opt_reader >= 0) {
			rc = sc_detect_card_presence(sc_ctx_get_reader(ctx, opt_reader));
			printf("Card %s.\n", rc == 1 ? "present" : "absent");
			if (rc < 0)
				return rc;
		} else {
			for (i = rc = 0; rc != 1 && i < (int) sc_ctx_get_reader_count(ctx); i++)
				rc = sc_detect_card_presence(sc_ctx_get_reader(ctx, opt_reader));
			if (rc == 1)
				opt_reader = i - 1;
		}

		if (rc > 0) {
			printf("Card detected in reader '%s'\n",sc_ctx_get_reader(ctx, opt_reader)->name);
			break;
		}
		if (rc < 0)
			return rc;

		printf("Please insert a smart card. Press return to continue");
		fflush(stdout);
		while (getc(stdin) != '\n')
			;
	}

	printf("Connecting... ");
	fflush(stdout);
	i = sc_connect_card(sc_ctx_get_reader(ctx, opt_reader), &card);
	if (i != SC_SUCCESS) {
		printf("Connecting to card failed: %s\n", sc_strerror(i));
		return i;
	}
	printf("connected.\n");
	{
		char tmp[SC_MAX_ATR_SIZE*3];
		sc_bin_to_hex(card->atr.value, card->atr.len, tmp, sizeof(tmp) - 1, ':');
		printf("ATR = %s\n",tmp);
	}

	if (opt_driver != NULL) {
		rc = sc_set_card_driver(ctx, opt_driver);
		if (rc != 0) {
			fprintf(stderr,
				"Driver '%s' not found!\n", opt_driver);
			return rc;
		}
	}

	return 0;
}

void sc_test_cleanup(void)
{
	sc_disconnect_card(card);
	sc_release_context(ctx);
}
