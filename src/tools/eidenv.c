/*
 * eidenv.c: EstEID utility
 *
 * Copyright (C) 2004 Martin Paljak <martin@paljak.pri.ee>
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
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <opensc/opensc.h>

#include "../libopensc/cards.h"
#include "../libopensc/esteid.h"

static int reader_num = 0;
static int stats = 0;
static char *exec_program = NULL;
static int exit_status = EXIT_FAILURE;

static struct option const long_options[] = {
	{"reader", required_argument, 0, 'r'},
	{"print", no_argument, 0, 'n'},
	{"exec", required_argument, 0, 'x'},
	{"stats", no_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{NULL, 0, NULL, 0}
};


static struct {
	const char *name;
	const char *env_name;
	int recno;
} esteid_data[] = {
	{"Surname", "ESTEID_SURNAME", 1},
	{"Given names 1", "ESTEID_GIVEN_NAMES1", 2},
	{"Given names 2", "ESTEID_GIVEN_NAMES2", 3},
	{"Sex", "ESTEID_SEX", 4},
	{"Citizenship", "ESTEID_CITIZENSHIP", 5},
	{"Date of birth", "ESTEID_DATE_OF_BIRTH", 6},
	{"Personal ID code", "ESTEID_PERSONAL_ID", 7},
	{"Document number", "ESTEID_DOCUMENT_NR", 8},
	{"Expiry date", "ESTEID_EXPIRY_DATE", 9},
	{"Place of birth", "ESTEID_PLACE_OF_BIRTH", 10},
	{"Issuing date", "ESTEID_ISSUING_DATE", 11},
	{"Permit type", "ESTEID_PERMIT_TYPE", 12},
	{"Remark 1", "ESTEID_REMARK1", 13},
	{"Remark 2", "ESTEID_REMARK2", 14},
	{"Remark 3", "ESTEID_REMARK3", 15},
	{"Remark 4", "ESTEID_REMARK4", 16},
	{NULL, NULL, 0}
};

static void show_version(void)
{
	fprintf(stderr,
		"eidenv - EstEID utility version " VERSION "\n"
		"\n"
		"Copyright (c) 2004 Martin Paljak <martin@paljak.pri.ee>\n"
		"Licensed under GPL v2\n");
}

static void show_help(void)
{
	show_version();
	fprintf(stderr,
		"-h --help      -  show this text and exit\n"
		"-v --version   -  show version and exit\n"
		"-r --reader    -  the reader to use\n"
		"-n --print     -  print the datafile\n"
		"-t --stats     -  show usage counts of keys\n"
		"-x --exec      -  execute a program with data in env vars.\n");
}

static void decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"ptr:x:hV", long_options, (int *) 0)) != EOF) {

		switch (c) {
		case 'r':
			reader_num = atoi(optarg);
			break;
		case 't':
			stats = !stats;
			break;
		case 'x':
			if (exec_program)
				free(exec_program);
			exec_program = strdup(optarg);
			break;
		case 'h':
			show_help();
			exit(EXIT_SUCCESS);
			break;
		case 'n':
			break;
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
			break;
		default:
			show_help();
			exit(EXIT_FAILURE);
		}
	}
}


int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_reader_t *reader = NULL;
	sc_card_t *card = NULL;
	sc_path_t path;
	int r, i;
	char buff[512];

	/* get options */
	decode_options(argc, argv);

	/* connect to the card */
	r = sc_establish_context(&ctx, "eidenv");
	if (r) {
	fprintf(stderr, "Failed to establish context: %s\n",
		sc_strerror(r));
		return 1;
	}
	if (reader_num > ctx->reader_count) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		return 1;
	}
	reader = ctx->reader[reader_num];

	r = sc_connect_card(reader, 0, &card);
	if (r) {
	fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
	return 1;
	}

	r = sc_lock(card);
	if (r) {
	fprintf(stderr, "Failed to lock card: %s\n", sc_strerror(r));
	return 1;
	}

	/* Make sure it is an EstEID card  */
	if (card->type != SC_CARD_TYPE_MCRD_ESTEID) {
		fprintf(stderr, "Not an EstEID card!\n");
		goto out;
	}

	if (stats) {
		int key_used[4];
		sc_format_path("3f00eeee0013", &path);
		r = sc_select_file(card, &path, NULL);
		if (r) {
			fprintf(stderr, "Failed to select key counters: %s\n", sc_strerror(r));
			goto out;
		}
	
		/* print the counters */
		for (i = 1; i <= 4; i++) {
			r = sc_read_record(card, i, buff, 128, SC_RECORD_BY_REC_NR);
			key_used[i - 1] = 0xffffff - ((unsigned char) buff[0xc] * 65536
									+ (unsigned char) buff[0xd] * 256
									+ (unsigned char) buff[0xe]);
		}
		for (i = 0; i < 2; i++) {
			printf("Key generation #%d usage:\n\tsign: %d\n\tauth: %d\n",
					 i, key_used[i], key_used[i + 2]);
		}
		exit_status = EXIT_SUCCESS;
		goto out;
	}
	
	/* Or just read the datafile */
	sc_format_path("3f00eeee5044", &path);
	r = sc_select_file(card, &path, NULL);
	if (r) {
		fprintf(stderr, "Failed to select DF: %s\n", sc_strerror(r));
		goto out;
	}

	for (i = 0; esteid_data[i].recno != 0; i++) {
		r = sc_read_record(card, esteid_data[i].recno, buff, 50, SC_RECORD_BY_REC_NR);
		if (r < 0) {
			fprintf (stderr, "Failed to read record %d from card: %s\n",
						esteid_data[i].recno, sc_strerror (r));
			goto out;
		} 
		buff[r] = '\0';
		if (exec_program) {
			char * cp;
			cp = malloc(strlen(esteid_data[i].env_name) + 
			strlen(buff) + 2);
			if (cp) { 
				strcpy(cp,esteid_data[i].env_name);
				strcat(cp,"=");
				strcat(cp,buff);
				putenv(cp);
			}
		} else {
			printf("%s: %s\n", esteid_data[i].name, buff);
		}
	}
	
	exit_status = EXIT_SUCCESS;
	
	if (exec_program) {
		char *largv[2];
		sc_unlock(card);
		sc_disconnect_card(card, 0);
		sc_release_context(ctx);
		largv[0] = exec_program;
		largv[1] = NULL;
		execv(exec_program, largv);
		/* we should not get here */
		perror("execv()");
	}
	
out:
	sc_unlock(card);
	sc_disconnect_card(card, 0);
	sc_release_context(ctx);
	exit(exit_status);
}
