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
/* For dup() and dup2() functions */
#ifndef _WIN32
#include <unistd.h>
#else
/*
 * Windows:
 * https://msdn.microsoft.com/en-us/library/8syseb29.aspx
 * https://msdn.microsoft.com/en-us/library/886kc0as.aspx
 */
#include <io.h>
#include <process.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "common/compat_getopt.h"
#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cards.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "libopensc/errors.h"
#include "util.h"
#include "libopensc/log.h"

#define OPT_RAW     256
#define OPT_PRETTY  257
#define OPT_VERIFY  258
#define OPT_PIN     259
#define OPT_DELKEY  260

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
static int opt_verify = 0;
static char *verifytype = NULL;
static int opt_pin = 0;
static const char *pin = NULL;
static int opt_erase = 0;
static int opt_delkey = 0;
static int opt_dump_do = 0;
static u8 do_dump_idx;

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
	{ "erase",     no_argument,       NULL, 'E'        },
	{ "verify",    required_argument, NULL, OPT_VERIFY },
	{ "pin",       required_argument, NULL, OPT_PIN },
	{ "del-key",   required_argument, NULL, OPT_DELKEY },
	{ "do",        required_argument, NULL, 'd' },
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
/* V */	"Show version number",
/* E */	"Erase (reset) the card",
	"Verify PIN (CHV1, CHV2, CHV3...)",
	"PIN string",
	"Delete key (1, 2, 3 or all)",
/* d */ "Dump private data object number <arg> (i.e. PRIVATE-DO-<arg>)",
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
			case 8: memmove(str+7, str+6, 1+strlen(str+6));
				str[6] = ',';
				/* fall through */
			case 6: memmove(str+5, str+4, 1+strlen(str+4));
				str[4] = ',';
				/* fall through */
			case 4: memmove(str+3, str+2, 1+strlen(str+2));
				str[2] = ',';
				/* fall through */
			case 2: return str;
		}
	}
	return NULL;
}


/* convert the raw ISO-5218 SEX value to an english word */
static char *prettify_gender(char *str)
{
	if (str != NULL) {
		switch (*str) {
			case '0': return "unknown";
			case '1': return "male";
			case '2': return "female";
			case '9': return "not announced";
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

				printf("%s:%*s%s\n", label, (int)(10-strlen(label)), "", value);
			}
		}
	}
}


static int decode_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv,"r:x:CUG:L:EhwvVd:", options, (int *) 0)) != EOF) {
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
		case OPT_VERIFY:
			opt_verify++;
			if (verifytype)
				free(verifytype);
			verifytype = strdup(optarg);
			actions++;
			break;
		case OPT_PIN:
			opt_pin++;
			util_get_pin(optarg, &pin);
			break;
		case 'C':
			opt_cardinfo++;
			actions++;
			break;
		case 'U':
			opt_userinfo++;
			actions++;
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
		case 'E':
			opt_erase++;
			actions++;
			break;
		case OPT_DELKEY:
			opt_delkey++;
			if (strcmp(optarg, "all") != 0)   /* Arg string is not 'all' */
				key_id = optarg[0] - '0';
			else                              /* Arg string is 'all' */
				key_id = 'a';
			break;
		case 'd':
			do_dump_idx = optarg[0] - '0';
			opt_dump_do++;
			actions++;
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
	/* FIXME there are no length checks on buf. */
	unsigned char buf[2048];

	for (i = 0; openpgp_data[i].ef != NULL; i++) {
		sc_path_t path;
		sc_file_t *file;
		size_t count;
		int r;

		sc_format_path(openpgp_data[i].ef, &path);
		r = sc_select_file(card, &path, &file);
		if (r) {
			fprintf(stderr, "Failed to select EF %s: %s\n", openpgp_data[i].ef, sc_strerror(r));
			return EXIT_FAILURE;
		}

		count = file->size;
		if (!count)
			continue;

		if (count > sizeof(buf) - 1) {
			fprintf(stderr, "Too small buffer to read the OpenPGP data\n");
			return EXIT_FAILURE;
		}

		r = sc_read_binary(card, 0, buf, count, 0);
		if (r < 0) {
			fprintf(stderr, "%s: read failed - %s\n", openpgp_data[i].ef, sc_strerror(r));
			return EXIT_FAILURE;
		}
		if (r != (signed)count) {
			fprintf(stderr, "%s: expecting %"SC_FORMAT_LEN_SIZE_T"d, got only %d bytes\n",
				openpgp_data[i].ef, count, r);
			return EXIT_FAILURE;
		}

		buf[count] = '\0';

		display_data(openpgp_data + i, (char *) buf);
	}

	return EXIT_SUCCESS;
}

static int do_dump_do(sc_card_t *card, unsigned int tag)
{
	int r, tmp;
	FILE *fp;

	// Private DO are specified up to 254 bytes
	unsigned char buffer[254];
	memset(buffer, '\0', sizeof(buffer));

	r = sc_get_data(card, tag, buffer, sizeof(buffer));
	if (r < 0) {
		printf("Failed to get data object: %s\n", sc_strerror(r));
		if(SC_ERROR_SECURITY_STATUS_NOT_SATISFIED == r) {
			printf("Make sure the 'verify' and 'pin' parameters are correct.\n");
		}
		return r;
	}

	if(opt_raw) {
		r = 0;
		#ifndef _WIN32
		tmp = dup(fileno(stdout));
		#else
		tmp = _dup(_fileno(stdout));
		#endif
		if (tmp < 0)
			return EXIT_FAILURE;
		fp = freopen(NULL, "wb", stdout);
		if (fp) {
			r = (int)fwrite(buffer, sizeof(char), sizeof(buffer), fp);
		}
		#ifndef _WIN32
		dup2(tmp, fileno(stdout));
		#else
		_dup2(tmp, _fileno(stdout));
		#endif
		clearerr(stdout);
		close(tmp);
		if (sizeof(buffer) != r)
			return EXIT_FAILURE;
	} else {
		util_hex_dump_asc(stdout, buffer, sizeof(buffer), -1);
	}

	return EXIT_SUCCESS;
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
	if (r < 0) {
		printf("Failed to retrieve fingerprints. Error %s.\n", sc_strerror(r));
		return 1;
	}
	r = sc_read_binary(card, 0, fingerprints, 60, 0);
	if (r < 0) {
		printf("Failed to retrieve fingerprints. Error %s.\n", sc_strerror(r));
		return 1;
	}
	printf("Fingerprint:\n%s\n", (char *)sc_dump_hex(fingerprints + 20*(key_id - 1), 20));
	return 0;
}

int do_verify(sc_card_t *card, char *type, const char *pin)
{
	struct sc_pin_cmd_data data;
	int tries_left;
	int r;
	if (!type || !pin)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (strncasecmp("CHV", type, 3) != 0) {
		printf("Invalid PIN type. Please use CHV1, CHV2 or CHV3.\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (type[3] < '1' || type[3] > '3' || type[4] != '\0') {
		printf("Invalid PIN reference. Please use CHV1, CHV2 or CHV3.\n");
		return SC_ERROR_INVALID_PIN_REFERENCE;
	}

	memset(&data, 0, sizeof(struct sc_pin_cmd_data));
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = type[3] - '0';
	data.pin1.data = (unsigned char *) pin;
	data.pin1.len = (int)strlen(pin);
	r = sc_pin_cmd(card, &data, &tries_left);
	return r;
}

/**
 * Delete key, for OpenPGP card.
 * This function is not complete and is reserved for future version (> 2) of OpenPGP card.
 **/
int delete_key_openpgp(sc_card_t *card, u8 key_id)
{
	char *del_fingerprint = "00:DA:00:C6:14:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
	char *del_creationtime = "00:DA:00:CD:04:00:00:00:00";
	/* We need to replace the 4th byte later */
	char *apdustring = NULL;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	sc_apdu_t apdu;
	size_t len0;
	int i;
	int r = SC_SUCCESS;

	for (i = 0; i < 2; i++) {
		if (i == 0)    /* Reset fingerprint */
			apdustring = del_fingerprint;
		else           /* Reset creation time */
			apdustring = del_creationtime;
		/* Convert the string to binary array */
		len0 = sizeof(buf);
		sc_hex_to_bin(apdustring, buf, &len0);

		/* Replace DO tag, subject to key ID */
		buf[3] = buf[3] + key_id;

		/* Build APDU from binary array */
		r = sc_bytes2apdu(card->ctx, buf, len0, &apdu);
		if (r) {
			fprintf(stderr, "Failed to build APDU: %s\n", sc_strerror(r));
			return r;
		}
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		/* Send APDU to card */
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			fprintf(stderr, "Transmitting APDU failed: %s\n", sc_strerror(r));
			return r;
		}
	}
	/* TODO: Rewrite Extended Header List.
	 * Not support by OpenGPG v2 yet */
	return r;
}

int do_delete_key(sc_card_t *card, u8 key_id)
{
	sc_path_t path;
	int r = SC_SUCCESS;

	/* Currently, only Gnuk supports deleting keys */
	if (card->type != SC_CARD_TYPE_OPENPGP_GNUK) {
		printf("Only Gnuk supports deleting keys. General OpenPGP doesn't.");
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (key_id < 1 || (key_id > 3 && key_id != 'a')) {
		printf("Error: Invalid key id %d", key_id);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (key_id == 1 || key_id == 'a') {
		sc_format_path("B601", &path);
		r |= sc_delete_file(card, &path);
	}
	if (key_id == 2 || key_id == 'a') {
		sc_format_path("B801", &path);
		r |= sc_delete_file(card, &path);
	}
	if (key_id == 3 || key_id == 'a') {
		sc_format_path("A401", &path);
		r |= sc_delete_file(card, &path);
	}
	return r;
}

int do_erase(sc_card_t *card)
{
	printf("Erase card\n");
	return sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL);
}

int main(int argc, char **argv)
{
	sc_context_t *ctx = NULL;
	sc_context_param_t ctx_param;
	sc_card_t *card = NULL;
	int r;
	int argind = 0;
	int exit_status = EXIT_SUCCESS;

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
	if ((card->type != SC_CARD_TYPE_OPENPGP_BASE) &&
			(card->type != SC_CARD_TYPE_OPENPGP_V1) &&
			(card->type != SC_CARD_TYPE_OPENPGP_V2) &&
			(card->type != SC_CARD_TYPE_OPENPGP_V3) &&
			(card->type != SC_CARD_TYPE_OPENPGP_GNUK)) {
		util_error("not an OpenPGP card");
		fprintf(stderr, "Card type %X\n", card->type);
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

	if (opt_verify && opt_pin) {
		exit_status |= do_verify(card, verifytype, pin);
	}

	if (opt_dump_do) {
		exit_status |= do_dump_do(card, 0x0100 + do_dump_idx);
	}

	if (opt_genkey)
		exit_status |= do_genkey(card, key_id, key_len);

	if (exec_program) {
		char *const largv[] = {exec_program, NULL};
		sc_unlock(card);
		sc_disconnect_card(card);
		sc_release_context(ctx);
		#ifndef _WIN32
		execv(exec_program, largv);
		#else
		_execv(exec_program, (const char * const*)largv);
		#endif
		/* we should not get here */
		perror("execv()");
		exit(EXIT_FAILURE);
	}

	if (opt_delkey)
		exit_status |= do_delete_key(card, key_id);

	if (opt_erase)
		exit_status |= do_erase(card);

out:
	sc_unlock(card);
	sc_disconnect_card(card);
	sc_release_context(ctx);

	exit(exit_status);
}
