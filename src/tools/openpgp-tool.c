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
#include <ctype.h>

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

enum code_types {
	TYPE_NULL,
	TYPE_HEX,
	TYPE_STRING
};

/* define structures */
struct ef_name_map {
	const char *name;
	const char *env_name;
	const char *ef;
	enum code_types type;
	size_t offset;
	size_t length;	/* 0 <=> potentially infinite */
	char *(*prettify_value)(void *);
};

/* declare functions */
static void show_version(void);
static char *prettify_version(void *ptr);
static char *prettify_manufacturer(void *ptr);
static char *prettify_serialnumber(void *ptr);
static char *prettify_name(void *ptr);
static char *prettify_language(void *ptr);
static char *prettify_gender(void *ptr);
static void display_data(const struct ef_name_map *mapping, void *value);
static int decode_options(int argc, char **argv);
static int do_info(sc_card_t *card, const struct ef_name_map *map);

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
static size_t opt_dump_do = 0;
static unsigned int do_dump_idx[200];	/* large enough and checked on input */

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
/* C */	"Show card information",
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
/* d */ "Dump private data object number <arg> (i.e. DO <arg>)",
};


static const struct ef_name_map card_data[] = {
	{ "AID",           "OPENPGP_AID",          "3F00:004F", TYPE_HEX,  0, 16, NULL                  },
	{ "Version",       "OPENPGP_VERSION",      "3F00:004F", TYPE_HEX,  6,  2, prettify_version      },
	{ "Manufacturer",  "OPENPGP_MANUFACTURER", "3F00:004F", TYPE_HEX,  8,  2, prettify_manufacturer },
	{ "Serial number", "OPENPGP_SERIALNO",     "3F00:004F", TYPE_HEX, 10,  4, prettify_serialnumber },
	{ NULL, NULL, NULL, TYPE_NULL, 0, 0, NULL }
};

static const struct ef_name_map user_data[] = {
	{ "Account",  "OPENGPG_ACCOUNT", "3F00:005E",      TYPE_STRING, 0, 0, NULL              },
	{ "URL",      "OPENPGP_URL",     "3F00:5F50",      TYPE_STRING, 0, 0, NULL              },
	{ "Name",     "OPENPGP_NAME",    "3F00:0065:005B", TYPE_STRING, 0, 0, prettify_name     },
	{ "Language", "OPENPGP_LANG",    "3F00:0065:5F2D", TYPE_STRING, 0, 0, prettify_language },
	{ "Gender",   "OPENPGP_GENDER",  "3F00:0065:5F35", TYPE_STRING, 0, 0, prettify_gender   },
	{ "DO 0101",  "OPENPGP_DO0101",  "3F00:0101",      TYPE_STRING, 0, 0, NULL              },
	{ "DO 0102",  "OPENPGP_DO0102",  "3F00:0102",      TYPE_STRING, 0, 0, NULL              },
//	{ "DO 0103",  "OPENPGP_DO0103",  "3F00:0103",      TYPE_STRING, 0, 0, NULL              },
//	{ "DO 0104",  "OPENPGP_DO0104",  "3F00:0104",      TYPE_STRING, 0, 0, NULL              },
	{ NULL, NULL, NULL, TYPE_NULL, 0, 0, NULL }
};


static void show_version(void)
{
	fprintf(stderr,
		"openpgp-tool - OpenPGP card utility version " PACKAGE_VERSION "\n"
		"\n"
		"Copyright (c) 2012 Peter Marschall <peter@adpm.de>\n"
		"Licensed under LGPL v2\n");
}


#define BCD2CHAR(x) (((((x) & 0xF0) >> 4) * 10) + ((x) & 0x0F))

static char *prettify_version(void *ptr)
{
	if (ptr != NULL) {
		static char result[10];	/* large enough for even 2*3 digits + separator */
		u8 *str = (u8 *) ptr;
		int major = BCD2CHAR(str[0]);
		int minor = BCD2CHAR(str[1]);

		sprintf(result, "%d.%d", major, minor);

		return result;
	}
	return ptr;
}


static char *prettify_manufacturer(void *ptr)
{
	if (ptr != NULL) {
		u8 *str = (u8 *) ptr;
		unsigned int manuf = (str[0] << 8) + str[1];

		switch (manuf) {
			case 0x0001: return "PPC Card Systems";
			case 0x0002: return "Prism";
			case 0x0003: return "OpenFortress";
			case 0x0004: return "Wewid";
			case 0x0005: return "ZeitControl";
			case 0x0006: return "Yubico";
			case 0x0007: return "OpenKMS";
			case 0x0008: return "LogoEmail";
			case 0x0009: return "Fidesmo";
			case 0x000A: return "Dangerous Things";

			case 0x002A: return "Magrathea";
			case 0x0042: return "GnuPG e.V.";

			case 0x1337: return "Warsaw Hackerspace";
			case 0x2342: return "warpzone"; /* hackerspace Muenster.  */
			case 0x63AF: return "Trustica";
			case 0xBD0E: return "Paranoidlabs";
			case 0xF517: return "FSIJ";

			/* 0x0000 and 0xFFFF are defined as test cards per spec,
			   0xFF00 to 0xFFFE are assigned for use with randomly created
			   serial numbers.  */
			case 0x0000:
			case 0xffff: return "test card";
			default: return (manuf & 0xff00) == 0xff00 ? "unmanaged S/N range" : "unknown";
		}
	}
	return ptr;
}


static char *prettify_serialnumber(void *ptr)
{
	if (ptr != NULL) {
		u8 *str = (u8 *) ptr;
		static char result[15];	/* large enough for even 2*3 digits + separator */
		unsigned int serial = (str[0] << 24) + (str[1] << 16) + (str[2] << 8) + str[3];

		sprintf(result, "%08X", serial);
		return result;
	}
	return ptr;
}


/* prettify card holder's name */
static char *prettify_name(void *ptr)
{
	if (ptr != NULL) {
		char *src = (char *) ptr;
		char *dst = (char *) ptr;

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
	return ptr;
}


/* prettify language */
static char *prettify_language(void *ptr)
{
	if (ptr != NULL) {
		char *str = (char *) ptr;

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
static char *prettify_gender(void *ptr)
{
	if (ptr != NULL) {
		u8 *str = (u8 *) ptr;
		switch (*str) {
			case '0': return "unknown";
			case '1': return "male";
			case '2': return "female";
			case '9': return "not announced";
		}
	}
	return NULL;
}


static char *bin_to_hex(char *str, const u8 *data, size_t count, int indent)
{
	if (str != NULL) {
		int lines = 0;
		char *ptr = str;

		while (count > 0) {
			char ascbuf[17];
			int printed;
			int i;

			for (i = 0; i < 16 && (size_t) i < count; i++) {
				if ((printed = sprintf(ptr, "%02X ", *data)) < 0)
					return NULL;
				if (indent < 0 && i < 15 && (size_t) i+1 < count)
					ptr[2] = ':';
				ptr += printed;
				ascbuf[i] = (isprint(*data)) ? *data : '.';
				data++;
			}
			count -= i;
			ascbuf[i] = '\0';
			if (indent >= 0) {
				if (lines) {
					if ((printed = sprintf(ptr, "%*s", 3*(16-i), "")) < 0)
						return NULL;
					ptr += printed;
				}
				if ((printed = sprintf(ptr, " %s", ascbuf)) < 0)
					return NULL;
				ptr += printed;

				if (count > 0) {
					if ((printed = sprintf(ptr, "\n%*s", indent, "")) < 0)
						return NULL;
					ptr += printed;
					lines++;
				}
			}
        	}
        }
	return str;
}


#define INDENT	16

static void display_data(const struct ef_name_map *map, void *data)
{
	if (map != NULL && data != NULL) {
		/* FIXME: no length checks on buffer */
		char buffer[8192];
		char *value;
		
		if (map->prettify_value != NULL && !opt_raw) {
			value = map->prettify_value(data);
		}
		else {
			value = (map->type == TYPE_HEX)
				? bin_to_hex(buffer, data, map->length, (exec_program) ? -1 : INDENT)
				: (char *) data;
		}

		if (value != NULL) {
			if (exec_program) {
				char *envvar= malloc(strlen(map->env_name) +
							strlen(value) + 2);

				if (envvar != NULL) {
					strcpy(envvar, map->env_name);
					strcat(envvar, "=");
					strcat(envvar, value);
					putenv(envvar);
					/* envvar deliberately kept: see putenv(3) */
				}
			}
			else {
				const char *label = map->name;
				int fill = (int) (INDENT - strlen(label));

				printf("%s:%*s%s\n", label, fill, "", value);
			}
		}
	}
}


static int decode_options(int argc, char **argv)
{
	int c;
	char *endptr;
	unsigned long val;

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
			actions++;
			break;
		case 'd':
			endptr = NULL;
			val = strtoul(optarg, &endptr, 16);
			if (endptr == NULL || endptr == optarg || *endptr != '\0') {
				printf("Unable to parse DO identifier\n");
				return 1;
			}
			if (opt_dump_do < sizeof(do_dump_idx) / sizeof(*do_dump_idx)) {
				do_dump_idx[opt_dump_do] = (unsigned int) (val | 0x100);
				opt_dump_do++;
			}
			actions++;
			break;
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	return optind;
}


static int do_info(sc_card_t *card, const struct ef_name_map *map)
{
	int i;
	u8 buf[2048];

	for (i = 0; map[i].ef != NULL; i++) {
		sc_path_t path;
		sc_file_t *file;
		size_t count;
		int r;

		sc_format_path(map[i].ef, &path);
		r = sc_select_file(card, &path, &file);
		if (r) {
			fprintf(stderr, "Failed to select EF %s: %s\n", map[i].ef, sc_strerror(r));
			return EXIT_FAILURE;
		}

		count = file->size;
		if (!count)
			continue;

		if (count > sizeof(buf) - 1) {
			fprintf(stderr, "Too small buffer to read the OpenPGP map\n");
			return EXIT_FAILURE;
		}

		r = sc_read_binary(card, 0, buf, count, 0);
		if (r < 0) {
			fprintf(stderr, "%s: read failed - %s\n", map[i].ef, sc_strerror(r));
			return EXIT_FAILURE;
		}
		if (r != (signed) count || (size_t) r < map[i].offset + map[i].length) {
			fprintf(stderr, "%s: expecting %"SC_FORMAT_LEN_SIZE_T"d, got only %d bytes\n",
				map[i].ef, count, r);
			return EXIT_FAILURE;
		}
		if (map[i].offset) {
			memmove(buf, buf + map[i].offset, map[i].length);
			count -= map[i].offset;
		}
		if (map[i].type == TYPE_STRING)
			buf[count] = '\0';

		display_data(&map[i], (void *) buf);
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

	if (tag < 0x101 || tag > 0x104) {
		printf("Illegal DO identifier\n");
		return 1;
	}

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

	if (opt_cardinfo)
		exit_status |= do_info(card, card_data);

	if (opt_userinfo)
		exit_status |= do_info(card, user_data);

	if (opt_verify && opt_pin) {
		exit_status |= do_verify(card, verifytype, pin);
	}

	if (opt_dump_do) {
		size_t n;

		for (n = 0; n < opt_dump_do; n++) {
			exit_status |= do_dump_do(card, do_dump_idx[n]);
		}
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
