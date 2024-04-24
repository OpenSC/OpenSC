/*
 * fuzz_pkcs15_tool.c: Fuzz target for pkcs15-tool
 *
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __APPLE__
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "libopensc/internal.h"
#include "fuzzer_reader.h"
#include "fuzzer_tool.h"
#undef stderr
#define stderr stdout

/* Rename main to call it in fuzz target */
#define main _main
#define util_connect_card_ex(ctx, card, id, do_wait, do_lock) fuzz_util_connect_card(ctx, card)
# include "tools/pkcs15-tool.c"
#undef main

static const uint8_t *reader_data = NULL;
static size_t reader_data_size = 0;

/* Use instead of util_connect_card() */
int fuzz_util_connect_card(sc_context_t *ctx, sc_card_t **card)
{
	return fuzz_connect_card(ctx, card, NULL, reader_data, reader_data_size);
}

void initialize_global()
{
	/* Global variables need to be reser between runs,
	   fuzz target is called repetitively in one execution */
	ctx = NULL;
	card = NULL;
	p15card = NULL;
	opt_auth_id = NULL;
	opt_reader = NULL;
	opt_cert = NULL;
	opt_data = NULL;
	opt_pubkey = NULL;
	opt_outfile = NULL;
	opt_bind_to_aid = NULL;
	opt_newpin = NULL;
	opt_pin = NULL;
	opt_puk = NULL;

	optind = 0;
	opterr = 0; /* do not print out error messages */
	optopt = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char **argv = NULL;
	int argc = 0;

	if (size < 10)
		return 0;

#ifdef FUZZING_ENABLED
	fclose(stdout);
#endif
	initialize_global();

	if (get_fuzzed_argv("./fuzz_pkcs15", data, size, &argv, &argc, &reader_data, &reader_data_size) != 0)
		return 0;
	_main(argc, argv);
	free_arguments(argc, argv);

	return 0;
}
