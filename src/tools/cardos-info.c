/*
 * cardos-info.c: Info about Card OS based tokens
 *
 * Copyright (C) 2003  Andreas Jellinghaus <aj@dungeon.inka.de>
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <opensc/opensc.h>
#include "util.h"

const char *app_name = "cardos-info";

int opt_reader = -1, opt_debug = 0, opt_wait = 0;
int quiet = 0;

const struct option options[] = {
	{"reader",	1, 0, 'r'},
	{"card-driver", 1, 0, 'c'},
	{"quiet",	0, 0, 'q'},
	{"wait",	0, 0, 'w'},
	{"debug",	0, 0, 'd'},
	{0, 0, 0, 0}
};

const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect]",
	"Quiet operation",
	"Wait for a card to be inserted",
	"Debug output -- may be supplied several times",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;

int cardos_info(void)
{
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cla = 0x00;
	apdu.ins = 0xca;
	apdu.p1 = 0x01;
	apdu.p2 = 0x80;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.lc = 0;
	apdu.le = 256;
	apdu.cse = SC_APDU_CASE_2_SHORT;
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}
	printf("Info : %s\n", apdu.resp);

	apdu.p2 = 0x81;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Chip type: %d\n", apdu.resp[8]);
	printf("Serial number: %02x %02x %02x %02x %02x %02x\n",
	       apdu.resp[10], apdu.resp[11], apdu.resp[12],
	       apdu.resp[13], apdu.resp[14], apdu.resp[15]);
	printf("Full prom dump:\n");
	if (apdu.resplen)
		hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	apdu.p2 = 0x82;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("OS Version: %d.%d", apdu.resp[0], apdu.resp[1]);
	if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 02) {
		printf(" (that's CardOS M4.0)\n");
	} else if (apdu.resp[0] == 0xc8 && apdu.resp[1] == 03) {
		printf(" (that's CardOS M4.01)\n");
	} else {
		printf(" (unknown Version)\n");
	}

	apdu.p2 = 0x83;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}


	printf("Current life cycle: ");
	if (rbuf[0] == 0x34) {
		printf("%d (manufacturing)\n", rbuf[0]);
	} else if (rbuf[0] == 0x26) {
		printf("%d (initialization)\n", rbuf[0]);
	} else if (rbuf[0] == 0x24) {
		printf("%d (personalization)\n", rbuf[0]);
	} else if (rbuf[0] == 0x20) {
		printf("%d (administration)\n", rbuf[0]);
	} else if (rbuf[0] == 0x10) {
		printf("%d (operational)\n", rbuf[0]);
	} else {
		printf("%d (unknown)\n", rbuf[0]);
	}

	apdu.p2 = 0x84;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Security Status of current DF:\n");
	hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	apdu.p2 = 0x85;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Free memory : %d\n", rbuf[0]<<8|rbuf[1]);

	apdu.p2 = 0x86;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	if (rbuf[0] == 0x00) {
		printf("ATR Status: 0x%d ROM-ATR\n",rbuf[0]);
	} else if (rbuf[0] == 0x90) {
		printf("ATR Status: 0x%d EEPROM-ATR\n",rbuf[0]);
	} else {
		printf("ATR Status: 0x%d unknown\n",rbuf[0]);
	}
	
	apdu.p2 = 0x88;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Packages installed:\n");
	hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	apdu.p2 = 0x89;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Ram size: %d, Eeprom size: %d, cpu type: %x, chip config: %d\n",
			rbuf[0]<<8|rbuf[1], rbuf[2]<<8|rbuf[3], rbuf[4], rbuf[5]);

	apdu.p2 = 0x8a;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Free eeprom memory: %d\n", rbuf[0]<<8|rbuf[1]);

	apdu.p2 = 0x96;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("System keys: PackageLoadKey (version %d, retries %d)\n",
			rbuf[0], rbuf[1]);
	printf("System keys: StartKey (version %d, retries %d)\n",
			rbuf[2], rbuf[3]);

	apdu.p2 = 0x87;
	apdu.resplen = sizeof(rbuf);
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 00 || opt_debug) {
		fprintf(stderr, "Received (SW1=0x%02X, SW2=0x%02X)%s\n",
			apdu.sw1, apdu.sw2, apdu.resplen ? ":" : "");
		if (apdu.resplen)
			hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);
		return 1;
	}

	printf("Path to current DF:\n");
	hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	return 0;
}


int main(int argc, char *const argv[])
{
	int err = 0, r, c, long_optind = 0;
	const char *opt_driver = NULL;

	while (1) {
		c = getopt_long(argc, argv, "r:qdc:w", options,
				&long_optind);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
		case '?':
			print_usage_and_die();
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'q':
			quiet++;
			break;
		case 'd':
			opt_debug++;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		}
	}
	r = sc_establish_context(&ctx, app_name);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n",
			sc_strerror(r));
		return 1;
	}
	if (opt_debug)
		ctx->debug = opt_debug;
	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n",
				opt_driver);
			err = 1;
			goto end;
		}
	}

	err = connect_card(ctx, &card, opt_reader, 0, opt_wait, quiet);
	if (err)
		goto end;

	printf("Using card driver: %s\n", card->driver->name);
	r = sc_lock(card);
	if (r) {
		fprintf(stderr, "Unable to lock card: %s\n",
			sc_strerror(r));
		err = 1;
		goto end;
	}
	if ((err = cardos_info())) {
		goto end;
	}
      end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
