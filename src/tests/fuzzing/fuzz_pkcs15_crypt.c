/*
 * fuzz_pkcs15_crypt.c: Fuzz target for pkcs15-crypt
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

#include "libopensc/internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "fuzzer_reader.h"
#include "fuzzer_tool.h"
#undef stderr
#define stderr stdout

/* Rename main to call it in fuzz target */
#define main _main
#define util_connect_card_ex(ctx, card, id, do_wait, do_lock) fuzz_util_connect_card(ctx, card)
# include "tools/pkcs15-crypt.c"
#undef main

static const uint8_t *reader_data = NULL;
static size_t reader_data_size = 0;

/* Use instead of util_connect_card() */
int fuzz_util_connect_card(sc_context_t *ctx, sc_card_t **card)
{
	opt_output = NULL; /* Do not create new outputfile */
	return fuzz_connect_card(ctx, card, NULL, reader_data, reader_data_size);
}

void initialize_global()
{
	/* Global variables need to be reser between runs,
	   fuzz target is called repetitively in one execution */
	verbose = 0, opt_wait = 0, opt_raw = 0;
	opt_reader = NULL;
	opt_pincode = NULL, opt_key_id = NULL;
	opt_input = NULL, opt_output = NULL;
	opt_bind_to_aid = NULL;
	opt_sig_format = NULL;
	opt_crypt_flags = 0;
	ctx = NULL;
	card = NULL;
	p15card = NULL;

	optind = 0;
	opterr = 0;
	optopt = 0;
}

void test_operation(char *op, char *pin, const uint8_t *data, size_t size, char *filename,
					char *hash, char *format, char *aid, char *id, uint8_t pad)
{
	char *argv[] = {"./fuzz_pkcs15_crypt", op, "-p", pin, "-i", filename,
					hash, "-f", format, NULL, NULL, NULL, NULL, NULL, NULL};
	int argc = 9;

	if (aid) {
		argv[argc++] = "--aid";
		argv[argc++] = aid;
	}
	if (id) {
		argv[argc++] = "-k";
		argv[argc++] = id;
	}
	if (pad)
		argv[argc++] = "--pkcs1";

	reader_data = data;
	reader_data_size = size;
	_main(argc, argv);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t operation = 0;
	uint8_t hash = 0;
	char *hash_options[] = {"--md5", "--sha-1", "--sha-224", "--sha-256", "--sha-384", "--sha-512"};
	uint8_t pad = 0;
	uint8_t format = 0;
	char *formats[] = {"rs", "sequence", "openssl"};
	uint8_t aid = 0;
	char *opt_aid = NULL;
	uint8_t id = 0;
	char *opt_id = NULL;
	char *pin = NULL;
	char *filename = NULL;

	if (size < 15)
		return 0;

#ifdef FUZZING_ENABLED
	fclose(stdout);
#endif

	initialize_global();

	operation = data[0] % 3;
	data++; size--;

	if (!(pin = extract_word(&data, &size)))
		return 0;

	if (operation == 0) { /* test random arguments */
		char **argv = NULL;
		int argc = 0;

		/* setup pin and input file otherwise fuzz target waits for input from stdin */
		opt_pincode = pin;
		opt_input = "invalid_filename";

		if (get_fuzzed_argv("./fuzz_pkcs15_crypt", data, size, &argv, &argc, &reader_data, &reader_data_size) != 0)
			goto err;
		_main(argc, argv);
		free_arguments(argc, argv);
	} else {
		/* Set options */
		if (size < 5)
			goto err;
		hash = data[0] % 6; data++; size--;
		pad = data[0] % 2; data++; size--;
		format = data[0] % 3; data++; size--;

		aid = data[0] % 2; data++; size--;
		if (aid) {
			if (!(opt_aid = extract_word(&data, &size)))
				goto err;
		}
		if (size < 3)
			goto err;

		id = data[0] % 2; data++; size--;
		if (id) {
			if (!(opt_id = extract_word(&data, &size)))
				goto err;
		}

		if (create_input_file(&filename, &data, &size) != 0)
			goto err;
		test_operation(operation == 1 ? "-c" : "-s", pin, data, size, filename, hash_options[hash], formats[format], opt_aid, opt_id, pad);

		remove_file(filename);
	}

err:
	free(pin);
	free(opt_aid);
	free(opt_id);
	return 0;
}
