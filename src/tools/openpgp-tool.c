/*
 * openpgp-tool.c: OpenPGP card utility
 *
 * Copyright (C) 2012 Peter Marschall <peter@adpm.de>
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
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cards.h"
#include "libopensc/cardctl.h"
#include "util.h"

#define	OPT_RAW		256
#define	OPT_PRETTY	257

/* define structures */
struct ef_name_map {
	const char *name;
	const char *env_name;
	const char *ef;
	char *(*prettify_value)(char *);
};

/* declare functions */
static void show_version(void);
static char *prettify_name(char *str);
static char *prettify_language(char *str);
static char *prettify_gender(char *str);
static void display_data(const struct ef_name_map *mapping, char *value);
static int decode_options(int argc, char **argv);
static int do_userinfo(sc_card_t *card);
static int read_transp(sc_card_t *card, const char *pathstring, unsigned char *buf, int buflen);
static void bintohex(char *buf, int len);

/* define global variables */
static int actions = 0;
static char *opt_reader = NULL;
static int opt_wait = 0;
static int opt_raw = 0;
static int verbose = 0;
static int opt_userinfo = 0;
static int opt_cardinfo = 0;
static char *exec_program = NULL;
static int opt_genkey = 0;
static int opt_keylen = 0;
static u8 key_id = 0;
static unsigned int key_len = 2048;

static const char *app_name = "openpgp-tool";

static const struct option options[] = {
	{ "reader",    required_argument, NULL, 'r'        },
	{ "wait",      no_argument,       NULL, 'w'        },
	{ "exec",      required_argument, NULL, 'x'        },
	{ "raw",       no_argument,       NULL, OPT_RAW    },
	{ "pretty",    no_argument,       NULL, OPT_PRETTY },
	{ "card-info", no_argument,       NULL, 'C'        },
	{ "user-info", no_argument,       NULL, 'U'        },
	{ "gen-key",   required_argument, NULL, 'G'        },
	{ "key-length",required_argument, NULL, 'L'        },
	{ "help",      no_argument,       NULL, 'h'        },
	{ "verbose",   no_argument,       NULL, 'v'        },
	{ "version",   no_argument,       NULL, 'V'        },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
/* r */	"Use reader number <arg> [0]",
/* w */	"Wait for card insertion",
/* x */	"Execute program <arg> with data in env vars",
	"Print values in raw format",
	"Print values in pretty format",
/* C */	NULL,
/* U */	"Show card holder information",
/* G */ "Generate key",
/* L */ "Key length (default 2048)",
/* h */	"Print this help message",
/* v */	"Verbose operation. Use several times to enable debug output.",
/* V */	"Show version number"
};

static const struct ef_name_map openpgp_data[] = {
	{ "Account",  "OPENGPG_ACCOUNT", "3F00:005E",      NULL              },
	{ "URL",      "OPENPGP_URL",     "3F00:5F50",      NULL              },
	{ "Name",     "OPENPGP_NAME",    "3F00:0065:005B", prettify_name     },
	{ "Language", "OPENPGP_LANG",    "3F00:0065:5F2D", prettify_language },
	{ "Gender",   "OPENPGP_GENDER",  "3F00:0065:5F35", prettify_gender   },
	{ "DO 0101",  "OPENPGP_DO0101",  "3F00:0101",      NULL              },
	{ "DO 0102",  "OPENPGP_DO0102",  "3F00:0102",      NULL              },
//	{ "DO 0103",  "OPENPGP_DO0103",  "3F00:0103",      NULL              },
//	{ "DO 0104",  "OPENPGP_DO0104",  "3F00:0104",      NULL              },
	{ NULL, NULL, NULL, NULL }
};


static void show_version(void)
{
	fprintf(stderr,
		"openpgp-tool - OpenPGP card utility version " PACKAGE_VERSION "\n"
		"\n"
		"Copyright (c) 2012 Peter Marschall <peter@adpm.de>\n"
		"Licensed under LGPL v2\n");
}


/* prettify card holder's name */
static char *prettify_name(char *str)
{
	if (str != NULL) {
		char *src = str;
		char *dst = str;

		while (*src != '\0') {
			*dst = *src++;
			if (*dst == '<') {
				if (*src == '<')
					src++;
				*dst = ' ';
			}
			dst++;
		}
		*dst = '\0';
	}
	return str;
}


/* prettify language */
static char *prettify_language(char *str)
{
	if (str != NULL) {
		switch (strlen(str)) {
			case 8:	memmove(str+7, str+6, 1+strlen(str+6));
				str[6] = ',';
				/* fall through */
			case 6:	memmove(str+5, str+4, 1+strlen(str+4));
				str[4] = ',';
				/* fall through */
			case 4:	memmove(str+3, str+2, 1+strlen(str+2));
				str[2] = ',';
				/* fall through */
			case 2:  return str;
		}
	}
	return NULL;
}


/* convert the raw ISO-5218 SEX value to an english word */
static char *prettify_gender(char *str)
{
	if (str != NULL) {
		switch (*str) {
			case '0':  return "unknown";
			case '1':  return "male";
			case '2':  return "female";
			case '9':  return "not applicable";
		}
	}
	return NULL;
}


static void display_data(const struct ef_name_map *mapping, char *value)
{
	if (mapping != NULL && value != NULL) {
		if (mapping->prettify_value != NULL && !opt_raw)
			value = mapping->prettify_value(value);

		if (value != NULL) {
			if (exec_program) {
				char *envvar;

				envvar = malloc(strlen(mapping->env_name) +
						strlen(value) + 2);
				if (envvar != NULL) {
					strcpy(envvar, mapping->env_name);
					strcat(envvar, "=");
					strcat(envvar, value);
					putenv(envvar);
				}
			} else {
				const char *label = mapping->name;

				printf("%s:%*s%s\n", label, 10-strlen(label), "", value);
			}
		}
	}
}


static int decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"r:x:CUGLhwvV", options, (int *) 0)) != EOF) {
		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'x':
			if (exec_program)
				free(exec_program);
			exec_program = strdup(optarg);
			break;
		case OPT_RAW:
			opt_raw = 1;
			break;
		case OPT_PRETTY:
			opt_raw = 0;
			break;
		case 'C':
			opt_cardinfo++;
			actions++;;
			break;
		case 'U':
			opt_userinfo++;
			actions++;;
			break;
		case 'G':
			opt_genkey++;
			key_id = optarg[0] - '0';
			actions++;
			break;
		case 'L':
			opt_keylen++;
			key_len = atoi(optarg);
			actions++;
			break;
		case 'h':
			util_print_usage_and_die(app_name, options, option_help, NULL);
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			show_version();
			exit(EXIT_SUCCESS);
			break;
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	return optind;
}


static int do_userinfo(sc_card_t *card)
{
	int i;
	unsigned char buf[2048];

	for (i = 0; openpgp_data[i].ef != NULL; i++) {
		sc_path_t path;
		sc_file_t *file;
		size_t count;
		size_t offset = 0;
		int r;

		sc_format_path(openpgp_data[i].ef, &path);
		r = sc_select_file(card, &path, &file);

		if (r) {
			fprintf(stderr, "Failed to select EF %s: %s\n",
				openpgp_data[i].ef, sc_strerror(r));
			return EXIT_FAILURE;
		}

		count = file->size;
		while (count > 0) {
	                int c = count > sizeof(buf) ? sizeof(buf) : count;

        	        r = sc_read_binary(card, offset, buf+offset, c, 0);
                	if (r < 0) {
				fprintf(stderr, "%s: read failed - %s\n",
					openpgp_data[i].ef, sc_strerror(r));
	                        return EXIT_FAILURE;
        	        }
                	if (r != c) {
                        	fprintf(stderr, "%s: expecting %d, got only %d bytes\n",
					openpgp_data[i].ef, c, r);
	                        return EXIT_FAILURE;
        	        }

        	        offset += r;
                	count -= r;
	        }

		buf[file->size] = '\0';

		if (file->size > 0) {
			display_data(openpgp_data + i, buf);
		}
	}

	return EXIT_SUCCESS;
}


/* Select and read a transparent EF */
static int read_transp(sc_card_t *card, const char *pathstring, unsigned char *buf, int buflen)
{
	sc_path_t path;
	int r;

	sc_format_path(pathstring, &path);
	r = sc_select_file(card, &path, NULL);
	if (r < 0)
		fprintf(stderr, "\nFailed to select file %s: %s\n", pathstring, sc_strerror(r));
	else {
		r = sc_read_binary(card, 0, buf, buflen, 0);
		if (r < 0)
			fprintf(stderr, "\nFailed to read %s: %s\n", pathstring, sc_strerror(r));
	}

	return r;
}


/* Hex-encode the buf, 2*len+1 bytes must be reserved. E.g. {'1','2'} -> {'3','1','3','2','\0'} */
static void bintohex(char *buf, int len)
{
	static const char hextable[] = "0123456789ABCDEF";
	int i;

	for (i = len - 1; i >= 0; i--) {
		unsigned char c = (unsigned char) buf[i];

		buf[2 * i + 1] = hextable[c % 16];
		buf[2 * i] = hextable[c / 16];
	}
}

int do_genkey(sc_card_t *card, u8 key_id, unsigned int key_len)
{
	int r;
	sc_cardctl_openpgp_keygen_info_t key_info;
	u8 fingerprints[60];
	sc_path_t path;
	sc_file_t *file;

	if (key_id < 1 || key_id > 3) {
		printf("Unknown key ID %d.\n", key_id);
		return 1;
	}
	memset(&key_info, 0, sizeof(sc_cardctl_openpgp_keygen_info_t));
	key_info.keytype = key_id;
	key_info.modulus_len = key_len;
	key_info.modulus = malloc(key_len/8);
	r = sc_card_ctl(card, SC_CARDCTL_OPENPGP_GENERATE_KEY, &key_info);
	free(key_info.modulus);
	if (r < 0) {
		printf("Failed to generate key. Error %s.\n", sc_strerror(r));
		return 1;
	}
	sc_format_path("006E007300C5", &path);
	r = sc_select_file(card, &path, &file);
	r = sc_read_binary(card, 0, fingerprints, 60, 0);
	if (r < 0) {
		printf("Failed to retrieve fingerprints. Error %s.\n", sc_strerror(r));
		return 1;
	}
	printf("Fingerprint:\n%s\n", sc_dump_hex(fingerprints + 20*(key_id - 1), 20));
	return 0;
}

int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int r;
	int argind = 0;
	int exit_status = EXIT_FAILURE;

	/* decode options */
	argind = decode_options(argc, argv);

	/* connect to the card */
	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		util_fatal("failed to establish context: %s\n",
			sc_strerror(r));
		return EXIT_FAILURE;
	}

	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	r = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
	if (r) {
		util_fatal("failed to connect to card: %s\n",
			sc_strerror(r));
		return EXIT_FAILURE;
	}

	/* check card type */
	if ((card->type != SC_CARD_TYPE_OPENPGP_V1) &&
	    (card->type != SC_CARD_TYPE_OPENPGP_V2)) {
		util_error("not an OpenPGP card");
		exit_status = EXIT_FAILURE;
		goto out;
	}

	/* fail on too many arguments */
	if (argind > argc)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	/* set default action */
	if (!actions)
		opt_userinfo = 1;

	if (opt_userinfo)
		exit_status |= do_userinfo(card);

	if (opt_genkey)
		exit_status |= do_genkey(card, key_id, key_len);

	if (exec_program) {
		char *const largv[] = {exec_program, NULL};
		sc_unlock(card);
		sc_disconnect_card(card);
		sc_release_context(ctx);
		execv(exec_program, largv);
		/* we should not get here */
		perror("execv()");
		exit(EXIT_FAILURE);
	}

out:
	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	exit(exit_status);
}
