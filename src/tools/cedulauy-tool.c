/*
 * cedulauy-tool.c: Set up the Uruguayan eID card (cédula de identidad) for contactless use
 *
 * Copyright (C) 2026 Nicolás Gutiérrez <ngutierreztassano@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "libopensc/card-cedulauy-cache.h"
#include "libopensc/cards.h"
#include "libopensc/opensc.h"
#include "util.h"

static const char *app_name = "cedulauy-tool";

static const struct option options[] = {
		{"reader",   1, NULL, 'r'},
		{"wait",	 0, NULL, 'w'},
		{"read-mrz", 0, NULL, 'c'},
		{"delete",   0, NULL, 'd'},
		{"verbose",  0, NULL, 'v'},
		{"help",	 0, NULL, 'h'},
		{NULL,       0, NULL, 0	 }
};

static const char *option_help[] = {
		"Uses reader number <arg> [0]",
		"Wait for a card to be inserted",
		"Read the MRZ from the card in a contact reader",
		"Delete the stored MRZ",
		"Verbose operation, may be used several times",
		"Display tool options",
};

/* TD1 MRZ, readable over the contact interface without a PIN */
#define CEDULAUY_MRZ_PATH "3F007000700B"

static int
read_mrz(sc_context_t *ctx, const char *reader, int wait, unsigned char *mrz)
{
	sc_card_t *card = NULL;
	unsigned char buf[3 + CEDULAUY_MRZ_LEN];
	sc_path_t path;
	int r;

	if (util_connect_card(ctx, &card, reader, wait)) {
		fprintf(stderr, "Cannot connect with the card\n");
		return SC_ERROR_CARD_NOT_PRESENT;
	}

	if (card->type != SC_CARD_TYPE_CEDULAUY) {
		fprintf(stderr, "The card is not a cedulauy in a contact reader\n");
		r = SC_ERROR_NOT_SUPPORTED;
	} else {
		sc_format_path(CEDULAUY_MRZ_PATH, &path);
		r = sc_select_file(card, &path, NULL);
		if (r >= 0)
			r = sc_read_binary(card, 0, buf, sizeof buf, NULL);
		if (r >= 0 && (r < (int)sizeof buf || buf[0] != 0x7F || buf[1] != 0x01 || buf[2] != CEDULAUY_MRZ_LEN))
			r = SC_ERROR_INVALID_DATA;
		if (r < 0) {
			fprintf(stderr, "Cannot read the MRZ from the card: %s\n", sc_strerror(r));
		} else {
			memcpy(mrz, buf + 3, CEDULAUY_MRZ_LEN);
			r = SC_SUCCESS;
		}
		sc_mem_clear(buf, sizeof buf);
	}

	sc_unlock(card);
	sc_disconnect_card(card);
	return r;
}

int
main(int argc, char *argv[])
{
	const char *opt_reader = NULL;
	int opt_wait = 0, opt_read = 0, opt_delete = 0;
	int verbose = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param = {0};
	unsigned char mrz[CEDULAUY_MRZ_LEN];
	int c, r;

	while ((c = getopt_long(argc, argv, "r:wcdvh", options, NULL)) != -1) {
		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'c':
			opt_read = 1;
			break;
		case 'd':
			opt_delete = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	if (optind < argc || opt_read + opt_delete != 1)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	ctx_param.app_name = app_name;
	ctx_param.debug = verbose;
	if (verbose)
		ctx_param.debug_file = stderr;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	if (opt_delete) {
		r = cedulauy_delete_mrz_cache(ctx);
		if (r == SC_ERROR_FILE_NOT_FOUND) {
			printf("No MRZ is stored.\n");
			r = SC_SUCCESS;
		} else if (r < 0) {
			fprintf(stderr, "Cannot delete the stored MRZ: %s\n", sc_strerror(r));
		} else {
			printf("MRZ removed.\n");
		}
	} else {
		r = read_mrz(ctx, opt_reader, opt_wait, mrz);
		if (r == SC_SUCCESS) {
			r = cedulauy_write_mrz_cache(ctx, mrz);
			if (r < 0)
				fprintf(stderr, "Cannot store the MRZ: %s\n", sc_strerror(r));
			else
				printf("MRZ stored, the card can now be used over the contactless interface.\n");
		}
	}

	sc_mem_clear(mrz, sizeof mrz);
	sc_release_context(ctx);
	return r == SC_SUCCESS ? 0 : 1;
}
