/*
 * dnie-tool.c: DNIe tool
 *
 * Copyright (C) 2011  Juan Antonio Martinez <jonsito@terra.es>
 *
 * Based on file rutoken-tool.c from  Pavel Mironchik <rutoken@rutoken.ru>
 * and Eugene Hermann <rutoken@rutoken.ru>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include "libopensc/opensc.h"
#include "libopensc/errors.h"
#include "libopensc/cardctl.h"
#include "libopensc/pkcs15.h"
#include "util.h"

/* win32 needs this in open(2) */
#ifndef O_BINARY
#define O_BINARY 0
#endif

static const char *app_name = "dnie-tool";

#define OP_NONE 	0 /* no operation requested */
#define	OP_GET_DATA	1 /* retrieve DNIe number, apellidos, nombre */
#define OP_GET_IDESP	2 /* retrieve IDESP */
#define	OP_GET_VERSION	4 /* retrieve DNIe version number */
#define	OP_GET_SERIALNR	8 /* Get SerialNumber */

static const struct option options[] = {
	{"reader",      1, NULL, 'r'},
	{"driver",      1, NULL, 'c'},
	{"wait",	0, NULL, 'w'},
	{"pin",		1, NULL, 'p'},
	{"idesp",       0, NULL, 'i'},
	{"version",     0, NULL, 'V'},
	{"data",	0, NULL, 'd'},
	{"serial",      0, NULL, 's'},
	{"all",	 	0, NULL, 'a'},
	{"verbose",     0, NULL, 'v'},
	{NULL,	  	0, NULL,  0 }
};

static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Uses card driver <arg> [auto-detect]",
	"Wait for a card to be inserted",
	"Specify PIN",
	"Retrieve IDESP",
	"Gets DNIe software version",
	"Show DNIe number, Name, and SurName",
	"Show DNIe serial number",
	"Display all the information available",
	"Verbose operation. Use several times to enable debug output."
};

/*  Get DNIe device extra information  */

int main(int argc, char* argv[])
{
	int	     opt_wait = 0;
	const char  *opt_pin = NULL;
	const char  *opt_reader = NULL;
	const char  *opt_driver = NULL;
	int	     opt_operation = OP_NONE;
	int	     verbose = 0;
	
	int err = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int c, long_optind, r, tries_left;
	
	char *data[] = { NULL, NULL, NULL, NULL, NULL };
	sc_serial_number_t serial;

	while (1) {
		c = getopt_long(argc, argv, "r:c:wp:iVdsav",
				options, &long_optind);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			util_print_usage_and_die(app_name, options, option_help, NULL);
		case 'r':
			opt_reader = optarg;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'p':
			util_get_pin(optarg, &opt_pin);
			break;
		case 'i':
			opt_operation |= OP_GET_IDESP;
			break;
		case 'V':
			opt_operation |= OP_GET_VERSION;
			break;
		case 'd':
			opt_operation |= OP_GET_DATA;
			break;
		case 's':
			opt_operation |= OP_GET_SERIALNR;
			break;
		case 'a':
			opt_operation = OP_GET_IDESP | OP_GET_VERSION | OP_GET_DATA | OP_GET_SERIALNR;
			break;
		case 'v':
			verbose++;
			break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.app_name = app_name;
	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Error: Failed to establish context: %s\n",
			sc_strerror(r));
		goto dnie_tool_end;
	}

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n",
				opt_driver);
			err = -1;
			goto dnie_tool_end;
		}
	}
	
	if (util_connect_card(ctx, &card, opt_reader, opt_wait, verbose) ) {
		fprintf(stderr, "Error: Cannot connect with card\n");
		err = -1;
		goto dnie_tool_end;
	}

	if ( strcmp(card->name,"dnie") ) {
		fprintf(stderr, "Error: Card seems not to be a DNIe\n");
		err=-1;
		goto dnie_tool_end;
	}

	if ( opt_pin ) {
		/*  verify  */
		r = sc_verify(card, SC_AC_CHV, 0,
				(u8*)opt_pin, strlen(opt_pin), &tries_left);
		if (r) {
			fprintf(stderr, "Error: PIN verification failed: %s",
					sc_strerror(r));
			if (r == SC_ERROR_PIN_CODE_INCORRECT)
				fprintf(stderr, " (tries left %d)", tries_left);
			putc('\n', stderr);
			err=-1;
			goto dnie_tool_end;
		}
	}

	if (opt_operation==0) {
		fprintf(stderr,"Error: No operation specified");
		err = -1;
		goto dnie_tool_end;
	}
	if (opt_operation & 0x0f) {
		r = sc_card_ctl(card, SC_CARDCTL_DNIE_GET_INFO, data);
		if ( r != SC_SUCCESS ) {
			fprintf(stderr, "Error: Get info failed: %s\n", sc_strerror(r));
			err = -1;
			goto dnie_tool_end;
		}
	}
	if (opt_operation & OP_GET_DATA) {
		printf("DNIe Number:   %s\n",data[0]);
		printf("SurName:       %s\n",data[1]);
		printf("Name:	  %s\n",data[2]);
	}
	if (opt_operation & OP_GET_IDESP) {
		if (data[3]==NULL) 
			printf("IDESP:	 (Not available)\n");
		else 	printf("IDESP:	 %s\n",data[3]);
	}
	if (opt_operation & OP_GET_VERSION) {
		if (data[4]==NULL)
			printf("DNIe Version:  (Not available)\n");
		else 	printf("DNIe Version:  %s\n",data[4]);
	}
	if (opt_operation & OP_GET_SERIALNR) {
		r = sc_card_ctl(card, SC_CARDCTL_GET_SERIALNR, &serial);
		if ( r != SC_SUCCESS ) {
			fprintf(stderr,"Error: Get serial failed: %s\n",sc_strerror(r));
			err = -1;
			goto dnie_tool_end;
		}
		printf("Serial number: ");
		util_hex_dump(stdout, serial.value, serial.len, NULL);
		putchar('\n');
	}

dnie_tool_end:
	if (card) {
		/*  sc_lock  and  sc_connect_card  in  util_connect_card  */
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}

