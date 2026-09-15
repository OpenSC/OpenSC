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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "common/compat_strlcat.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "libopensc/opensc.h"
#include "util.h"

/* TD1 MRZ, readable over the contact interface without a PIN */
#define CEDULAUY_MRZ_PATH "3F007000700B"

static const char *app_name = "cedulauy-tool";

static const struct option options[] = {
		{"reader",   1, NULL, 'r'},
		{"wait",	 0, NULL, 'w'},
		{"read-mrz", 0, NULL, 'c'},
		{"mrz",	1, NULL, 'm'},
		{"delete",   0, NULL, 'd'},
		{"verbose",  0, NULL, 'v'},
		{"help",	 0, NULL, 'h'},
		{NULL,       0, NULL, 0	 }
};

static const char *option_help[] = {
		"Uses reader number <arg> [0]",
		"Wait for a card to be inserted",
		"Read the MRZ from the card in a contact reader",
		"Use the MRZ <arg> (the three lines without separators)",
		"Delete the stored MRZ",
		"Verbose operation, may be used several times",
		"Display tool options",
};

static int
mrz_cache_path(sc_context_t *ctx, char *buf, size_t buflen)
{
	int r = sc_get_cache_dir(ctx, buf, buflen);
	if (r < 0)
		return r;

#ifdef _WIN32
	strlcat(buf, "\\", buflen);
#else
	strlcat(buf, "/", buflen);
#endif

	if (strlcat(buf, CEDULAUY_MRZ_CACHE_FILE, buflen) >= buflen)
		return SC_ERROR_BUFFER_TOO_SMALL;

	return SC_SUCCESS;
}

static FILE *
open_mrz_cache(const char *path)
{
#ifdef _WIN32
	/* the profile directory ACL already restricts access to the user */
	return fopen(path, "wb");
#else
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	FILE *f;

	if (fd < 0)
		return NULL;

	/* O_CREAT does not change the mode of an existing file */
	if (fchmod(fd, S_IRUSR | S_IWUSR) < 0)
		fprintf(stderr, "Warning: Cannot restrict the permissions of %s\n", path);

	f = fdopen(fd, "wb");
	if (f == NULL)
		close(fd);

	return f;
#endif
}

static int
store_mrz(sc_context_t *ctx, const unsigned char *mrz)
{
	char path[PATH_MAX];
	FILE *f;
	int r;

	r = mrz_cache_path(ctx, path, sizeof path);
	if (r < 0) {
		fprintf(stderr, "Cannot determine the cache directory: %s\n", sc_strerror(r));
		return r;
	}

	f = open_mrz_cache(path);
	if (f == NULL && errno == ENOENT) {
		r = sc_make_cache_dir(ctx);
		if (r < 0) {
			fprintf(stderr, "Cannot create the cache directory: %s\n", sc_strerror(r));
			return r;
		}
		f = open_mrz_cache(path);
	}
	if (f == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return SC_ERROR_INTERNAL;
	}

	if (fwrite(mrz, 1, CEDULAUY_MRZ_LEN, f) != CEDULAUY_MRZ_LEN) {
		fclose(f);
		fprintf(stderr, "Cannot write %s\n", path);
		return SC_ERROR_INTERNAL;
	}
	if (fclose(f) != 0) {
		fprintf(stderr, "Cannot write %s: %s\n", path, strerror(errno));
		return SC_ERROR_INTERNAL;
	}

	printf("MRZ stored in %s\n", path);
	printf("The card can now be used over the contactless interface.\n");

	return SC_SUCCESS;
}

static int
delete_mrz(sc_context_t *ctx)
{
	char path[PATH_MAX];
	int r;

	r = mrz_cache_path(ctx, path, sizeof path);
	if (r < 0) {
		fprintf(stderr, "Cannot determine the cache directory: %s\n", sc_strerror(r));
		return r;
	}

	if (remove(path) != 0) {
		if (errno == ENOENT) {
			printf("No MRZ is stored.\n");
			return SC_SUCCESS;
		}
		fprintf(stderr, "Cannot remove %s: %s\n", path, strerror(errno));
		return SC_ERROR_INTERNAL;
	}

	printf("MRZ removed from %s\n", path);

	return SC_SUCCESS;
}

static int
read_mrz(sc_context_t *ctx, const char *reader, int wait, unsigned char *mrz)
{
	sc_card_t *card = NULL;
	struct sc_path path;
	unsigned char buf[3 + CEDULAUY_MRZ_LEN];
	int r;

	if (util_connect_card(ctx, &card, reader, wait)) {
		fprintf(stderr, "Cannot connect with the card\n");
		return SC_ERROR_CARD_NOT_PRESENT;
	}

	if (card->type != SC_CARD_TYPE_CEDULAUY) {
		fprintf(stderr, "The card is not a cedula in a contact reader\n");
		r = SC_ERROR_INVALID_CARD;
		goto out;
	}

	sc_format_path(CEDULAUY_MRZ_PATH, &path);
	r = sc_select_file(card, &path, NULL);
	if (r < 0) {
		fprintf(stderr, "Cannot select the MRZ file: %s\n", sc_strerror(r));
		goto out;
	}

	r = sc_read_binary(card, 0, buf, sizeof buf, NULL);
	if (r < 0) {
		fprintf(stderr, "Cannot read the MRZ file: %s\n", sc_strerror(r));
		goto out;
	}

	if (r < (int)sizeof buf || buf[0] != 0x7F || buf[1] != 0x01 || buf[2] != CEDULAUY_MRZ_LEN) {
		fprintf(stderr, "Unexpected contents of the MRZ file\n");
		r = SC_ERROR_INVALID_DATA;
		goto out;
	}

	memcpy(mrz, buf + 3, CEDULAUY_MRZ_LEN);
	r = SC_SUCCESS;

out:
	sc_mem_clear(buf, sizeof buf);
	sc_unlock(card);
	sc_disconnect_card(card);
	return r;
}

/* appends the characters of in to the MRZ, ignoring whitespace */
static int
append_mrz(const char *in, unsigned char *mrz, size_t *len)
{
	for (; *in != '\0'; in++) {
		if (isspace((unsigned char)*in))
			continue;
		if (*len == CEDULAUY_MRZ_LEN)
			return SC_ERROR_WRONG_LENGTH;
		mrz[(*len)++] = (unsigned char)toupper((unsigned char)*in);
	}

	return SC_SUCCESS;
}

static int
prompt_mrz(unsigned char *mrz, size_t *len)
{
	char line[128];
	int i, r = SC_SUCCESS;

	printf("Enter the three lines of the MRZ printed on the back of the card.\n");
	for (i = 1; i <= 3 && r == SC_SUCCESS; i++) {
		printf("Line %d: ", i);
		fflush(stdout);
		if (fgets(line, sizeof line, stdin) == NULL) {
			fprintf(stderr, "Cannot read the MRZ\n");
			r = SC_ERROR_INTERNAL;
			break;
		}
		r = append_mrz(line, mrz, len);
	}
	sc_mem_clear(line, sizeof line);

	return r;
}

int
main(int argc, char *argv[])
{
	const char *opt_reader = NULL;
	const char *opt_mrz = NULL;
	int opt_wait = 0, opt_read = 0, opt_delete = 0, opt_mrz_given = 0;
	int verbose = 0;
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param = {0};
	unsigned char mrz[CEDULAUY_MRZ_LEN];
	size_t mrz_len = 0;
	int c, r;

	while ((c = getopt_long(argc, argv, "r:wcm:dvh", options, NULL)) != -1) {
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
		case 'm':
			util_get_pin(optarg, &opt_mrz);
			opt_mrz_given = 1;
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

	if (optind < argc || opt_read + opt_delete + opt_mrz_given > 1)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	if (opt_mrz_given && opt_mrz == NULL) {
		fprintf(stderr, "No MRZ given\n");
		return 1;
	}

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
		r = delete_mrz(ctx);
		goto out;
	}

	if (opt_read) {
		r = read_mrz(ctx, opt_reader, opt_wait, mrz);
		if (r == SC_SUCCESS)
			mrz_len = CEDULAUY_MRZ_LEN;
	} else if (opt_mrz != NULL) {
		r = append_mrz(opt_mrz, mrz, &mrz_len);
	} else {
		r = prompt_mrz(mrz, &mrz_len);
	}

	if ((r == SC_SUCCESS && mrz_len != CEDULAUY_MRZ_LEN) || r == SC_ERROR_WRONG_LENGTH) {
		fprintf(stderr, "The MRZ has to be %d characters long\n", CEDULAUY_MRZ_LEN);
		r = SC_ERROR_WRONG_LENGTH;
	}

	if (r == SC_SUCCESS)
		r = store_mrz(ctx, mrz);

out:
	sc_mem_clear(mrz, sizeof mrz);
	sc_release_context(ctx);
	return r == SC_SUCCESS ? 0 : 1;
}
