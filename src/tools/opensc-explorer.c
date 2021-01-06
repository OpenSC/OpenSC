/*
 * opensc-explorer.c: A shell for accessing smart cards with libopensc
 *
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

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#ifdef ENABLE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#if !defined(_WIN32)
#include <arpa/inet.h>  /* for htons() */
#endif

#ifdef _WIN32
#include <io.h>		/* for_setmode() */
#include <fcntl.h>	/* for _O_TEXT and _O_BINARY */
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "libopensc/cards.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "common/compat_strlcpy.h"
#include <getopt.h>
#include "util.h"

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

/* type for associations of IDs to names */
typedef struct _id2str {
	unsigned int id;
	const char *str;
} id2str_t;

static const char *app_name = "opensc-explorer";

static int opt_wait = 0, verbose = 0;
static const char *opt_driver = NULL;
static const char *opt_reader = NULL;
static const char *opt_startfile = NULL;

static sc_file_t *current_file = NULL;
static sc_path_t current_path;
static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static int interactive = 1;

static const struct option options[] = {
	{ "reader",		1, NULL, 'r' },
	{ "card-driver",	1, NULL, 'c' },
	{ "mf",			1, NULL, 'm' },
	{ "wait",		0, NULL, 'w' },
	{ "verbose",		0, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};
static const char *option_help[] = {
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect; '?' for list]",
	"Selects path <arg> on start-up, or none if empty [3F00]",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
};


/* declare functions called by user commands */
static int do_echo(int argc, char **argv);
static int do_ls(int argc, char **argv);
static int do_find(int argc, char **argv);
static int do_find_tags(int argc, char **argv);
static int do_cd(int argc, char **argv);
static int do_cat(int argc, char **argv);
static int do_info(int argc, char **argv);
static int do_create(int argc, char **argv);
static int do_mkdir(int argc, char **argv);
static int do_delete(int argc, char **argv);
static int do_pininfo(int argc, char **argv);
static int do_verify(int argc, char **argv);
static int do_change(int argc, char **argv);
static int do_unblock(int argc, char **argv);
static int do_get(int argc, char **argv);
static int do_get_record(int argc, char **argv);
static int do_update_binary(int argc, char **argv);
static int do_update_record(int argc, char **argv);
static int do_put(int argc, char **argv);
static int do_debug(int argc, char **argv);
static int do_erase(int argc, char **argv);
static int do_random(int argc, char **argv);
static int do_get_data(int argc, char **argv);
static int do_put_data(int argc, char **argv);
static int do_apdu(int argc, char **argv);
static int do_sm(int argc, char **argv);
static int do_asn1(int argc, char **argv);
static int do_help(int argc, char **argv);
static int do_quit(int argc, char **argv);


struct command {
	int		(*func)(int, char **);
	const char *	name;
	const char *	args;
	const char *	help;
};

static struct command	cmds[] = {
	{ do_echo,
		"echo",	"[<string> ...]",
		"display arguments"			},
	{ do_ls,
		"ls",	"[<pattern> ...]",
		"list files in the current DF"		},
	{ do_find,
		"find",	"[<start-id> [<end-id>]]",
		"find all files in the current DF"	},
	{ do_find_tags,
		"find_tags",	"[<start-tag> [<end-tag>]]",
		"find all tags of data objects in the current context"	},
	{ do_cd,
		"cd",	"{.. | <file-id> | aid:<DF-name>}",
		"change to another DF"			},
	{ do_cat,
		"cat",	"[{<file-id> | sfi:<sfi-id>} [<rec-no>]]"
	,	"print the contents of [a record in] an EF"		},
	{ do_info,
		"info",	"[<file-id>]",
		"display attributes of card file"	},
	{ do_create,
		"create",	"<file-id> <size>",
		"create a new EF"			},
	{ do_mkdir,
		"mkdir",	"<file-id> <size>",
		"create a new DF"			},
	{ do_delete,
		"delete",	"<file-id>",
		"remove an EF/DF"			},
	{ do_delete,
		"rm",	"<file-id>",
		"remove an EF/DF"			},
	{ do_pininfo,
		"pin_info",	"{CHV|KEY|AUT|PRO}<key-ref>",
		"get information on PIN or key from the card"	},
	{ do_verify,
		"verify",	"{CHV|KEY|AUT|PRO}<key-ref> [<pin>]",
		"present a PIN or key to the card"	},
	{ do_change,
		"change",	"CHV<pin-ref> [[<old-pin>] <new-pin>]",
		"change a PIN"                          },
	{ do_unblock,
		"unblock",	"CHV<pin-ref> [<puk> [<new-pin>]]",
		"unblock a PIN"                         },
	{ do_put,
		"put",	"<file-id> [<input-file>]",
		"copy a local file to the card"		},
	{ do_get,
		"get",	"<file-id> [<output-file>]",
		"copy an EF to a local file"		},
	{ do_get_record,
		"get_record",	"<file-id> <rec-no> [<output-file>]",
		"copy a record of an EF to a local file"	},
	{ do_get_data,
		"do_get",	"<hex-tag> [<output-file>]",
		"get a data object"			},
	{ do_put_data,
		"do_put",	"<hex-tag> <data>",
		"put a data object"			},
	{ do_erase,
		"erase",	"",
		"erase card"				},
	{ do_random,
		"random",	"<count> [<output-file>]",
		"obtain <count> random bytes from card"	},
	{ do_update_record,
		"update_record", "<file-id> <rec-no> <rec-offs> <data>",
		"update record"				},
	{ do_update_binary,
		"update_binary", "<file-id> <offs> <data>",
		"update binary"				},
	{ do_apdu,
		"apdu",	"<data> ...",
		"send a custom apdu command"		},
	{ do_asn1,
		"asn1",	"[<file-id> [<rec-no>] [<offs>]]",
		"decode an ASN.1 file or record"	},
	{ do_sm,
		"sm",	"{open|close}",
		"call SM 'open' or 'close' handlers, if available"},
	{ do_debug,
		"debug",	"[<value>]",
		"get/set the debug level"		},
	{ do_quit,
		"quit",	"",
		"quit this program"			},
	{ do_quit,
		"exit",	"",
		"quit this program"			},
	{ do_help,
		"help",	"",
		"show this help"			},
	{ NULL, NULL, NULL, NULL }
};


static char *path_to_filename(const sc_path_t *path, const char sep, size_t rec)
{
	static char buf[2*SC_MAX_PATH_STRING_SIZE+10];
	size_t i, j;

	/* build file name from path elements */
	for (i = 0, j = 0; path != NULL && i < path->len; i++) {
		if (sep != '\0' && i > 0 && (i & 1) == 0)
			j += sprintf(buf+j, "%c", sep);
		j += sprintf(buf+j, "%02X", path->value[i]);
	}
	/* single record: append record-number */
	if (rec > 0)
		j += sprintf(buf+j, "%c%"SC_FORMAT_LEN_SIZE_T"u",
				(sep == '-') ? '_' : '-', rec);
	buf[j] = '\0';

	return buf;
}

static int parse_string_or_hexdata(const char *in, u8 *out, size_t *outlen)
{
	if (in == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (*in == '"') {
		u8 quote = *in++;
		size_t count = 0;

		while (*in != quote && *in != '\0' && count < *outlen)
			out[count++] = *in++;
		if (*in == '\0')
			return SC_ERROR_INVALID_ARGUMENTS;
		if (count >= *outlen)
			return SC_ERROR_BUFFER_TOO_SMALL;

		*outlen = count;
		return 0;
	}
	else
		return sc_hex_to_bin(in, out, outlen);
}

static int usage(int (*func)(int, char **))
{
	struct command	*cmd;

	for (cmd = cmds; cmd->func; cmd++)
		if (cmd->func == func)
			printf("Usage: %s %s\n", cmd->name, cmd->args);
	return -1;
}

static void die(int ret)
{
	sc_file_free(current_file);
	if (card) {
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	exit(ret);
}

static void select_current_path_or_die(void)
{
	if (current_path.type || current_path.len) {
		int r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &current_path, NULL);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "unable to select parent DF: %s\n", sc_strerror(r));
			die(1);
		}
	}
}

static struct command *
ambiguous_match(struct command *table, const char *cmd, int *ambiguous)
{
	struct command *last_match = NULL;

	if (table != NULL && cmd != NULL) {
		for (; table->name; table++) {
			size_t cmdlen = strlen(cmd);

			/* compare cmd with prefix of known command */
			if (strncasecmp(table->name, cmd, cmdlen) == 0) {
				/* succeed immediately if lengths match too, i.e. exact match */
				if (cmdlen == strlen(table->name))
					return table;
				/* fail on multiple prefix-only matches */
				if (last_match != NULL) {
					if (ambiguous != NULL)
						*ambiguous = 1;
					return NULL;
				}
				/* remember latest prefix-only match */
				last_match = table;
			}
		}
	}
	/* indicate as non-ambiguous if there was no match */
	if (ambiguous != NULL && last_match == NULL)
		*ambiguous = 0;
	return last_match;
}


static void
check_ret(int r, int op, const char *err, const sc_file_t *file)
{
	fprintf(stderr, "%s: %s\n", err, sc_strerror(r));
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		fprintf(stderr, "ACL for operation: %s\n", util_acl_to_str(sc_file_get_acl_entry(file, op)));
}


static int
arg_to_fid(const char *arg, u8 *fid)
{
	unsigned int fid0, fid1;

	if (strlen(arg) != 4) {
		fprintf(stderr, "Wrong ID length.\n");
		return -1;
	}

	if (sscanf(arg, "%02X%02X", &fid0, &fid1) != 2) {
		fprintf(stderr, "Invalid ID.\n");
		return -1;
	}

	fid[0] = (unsigned char)fid0;
	fid[1] = (unsigned char)fid1;

	return 0;
}


static int
arg_to_path(const char *arg, sc_path_t *path, int is_id)
{
	memset(path, 0, sizeof(sc_path_t));

	if (strncasecmp(arg, "aid:", strlen("aid:")) == 0) {
		/* DF aid */
		const char *p = arg + strlen("aid:");
		int r;

		path->type = SC_PATH_TYPE_DF_NAME;
		path->len  = sizeof(path->value);
		if ((r = sc_hex_to_bin(p, path->value, &path->len)) < 0) {
			fprintf(stderr, "Error parsing AID: %s\n", p);
			return r;
		}
	} else {
		/* file id */
		u8 cbuf[2];

		if (arg_to_fid(arg, cbuf) < 0)
			return -1;

		if ((cbuf[0] == 0x3F && cbuf[1] == 0x00) || is_id) {
			path->len = 2;
			memcpy(path->value, cbuf, 2);
			path->type = (is_id) ? SC_PATH_TYPE_FILE_ID : SC_PATH_TYPE_PATH;
		} else {
			*path = current_path;
			if (path->type == SC_PATH_TYPE_DF_NAME) {
				if (path->len > sizeof(path->aid.value)) {
					fprintf(stderr, "Invalid length of DF_NAME path\n");
					return -1;
				}

				memcpy(path->aid.value, path->value, path->len);
				path->aid.len = path->len;

				path->type = SC_PATH_TYPE_FILE_ID;
				path->len = 0;
			}
			sc_append_path_id(path, cbuf, 2);
		}
	}

	return 0;
}

static void print_file(const sc_file_t *file)
{
	const char *format = " %02X%02X ";
	const char *st = NULL;

	if(!file->type_attr_len)
		st = "???";

	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		st = "wEF";
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		st = "iEF";
		break;
	case SC_FILE_TYPE_DF:
		format = "[%02X%02X]";
		st = "DF";
		break;
	}
	printf(format, file->id >> 8, file->id & 0xFF);
	if (st == NULL)
		printf("\t0x%02X", *file->type_attr);
	else
		printf("\t%4s", st);
	printf(" %5lu", (unsigned long)file->size);
	if (file->namelen) {
		printf("\tName: ");
		util_print_binary(stdout, file->name, file->namelen);
	}
	printf("\n");
	return;
}

static int do_echo(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++) {
		printf("%s%s", argv[i], (i < argc) ? " " : "");
	}
	printf("\n");
	return 0;
}

static int pattern_match(const char *pattern, const char *string)
{
	if (pattern == NULL || string == NULL)
		return 0;

	while (*pattern != '\0' && *string != '\0') {
		/* wildcard matching multiple characters */
		if (*pattern == '*') {
			for (pattern++; *string != '\0' ; string++)
				if (pattern_match(pattern, string))
					return 1;
			return 0;
		}
		/* simple character class matching a single character */
		else if (*pattern == '[') {
			char *end = strchr(pattern, ']');
			int match = 0;

			for (pattern++; end != NULL && pattern != end; pattern++) {
				if (tolower((unsigned char) *pattern) == tolower((unsigned char) *string))
					match++;
			}
			if (!match)
				return 0;
			pattern++;
			string++;
		}
		/* single character comparison / wildcard matching a single character */
		else if (tolower((unsigned char) *pattern) == tolower((unsigned char) *string) || *pattern == '?') {
			pattern++;
			string++;
		}
		else
			return 0;

		if (*string == '\0' || *pattern == '\0')
			break;
	}
	return (*pattern != '\0' || *string != '\0' || tolower((unsigned char) *pattern) != tolower((unsigned char) *string)) ? 0 : 1;
}

static int do_ls(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_RESP_SIZE], *cur = buf;
	int r, count;

	memset(buf, 0, sizeof(buf));
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_list_files(card, buf, sizeof(buf));
	sc_unlock(card);
	if (r < 0) {
		check_ret(r, SC_AC_OP_LIST_FILES, "Unable to receive file listing", current_file);
		return -1;
	}
	count = r;
	printf("FileID\tType  Size\n");
	while (count >= 2) {
		char filename[SC_MAX_PATH_STRING_SIZE];
		int i = 0;
		int matches = 0;

		/* construct file name */
		sprintf(filename, "%02X%02X", cur[0], cur[1]);

		 /* compare file name against patterns */
		for (i = 0; i < argc; i++) {
			if (pattern_match(argv[i], filename)) {
				matches = 1;
				break;
			}
		}

		/* if any filename pattern were given, filter only matching file names */
		if (argc == 0 || matches) {
			sc_path_t path;
			sc_file_t *file = NULL;

			if (current_path.type != SC_PATH_TYPE_DF_NAME) {
				path = current_path;
				sc_append_path_id(&path, cur, 2);
			} else {
				if (sc_path_set(&path, SC_PATH_TYPE_FILE_ID, cur, 2, 0, 0) != SC_SUCCESS) {
					fprintf(stderr, "Unable to set path.\n");
					die(1);
				}
			}

			r = sc_lock(card);
			if (r == SC_SUCCESS)
				r = sc_select_file(card, &path, &file);
			sc_unlock(card);
			if (r) {
				fprintf(stderr, "Unable to select file %02X%02X: %s\n",
					 cur[0], cur[1], sc_strerror(r));
			} else {
				file->id = (cur[0] << 8) | cur[1];
				print_file(file);
				sc_file_free(file);
			}
		}
		cur += 2;
		count -= 2;
		select_current_path_or_die();
	}
	return 0;
}

static int do_find(int argc, char **argv)
{
	u8 fid[2] = { 0x00, 0x00 };
	u8 end[2] = { 0xFF, 0xFF };
	sc_path_t path;
	int r;

	switch (argc) {
	case 2:
		if (arg_to_fid(argv[1], end) != 0)
			return usage(do_find);
		/* fall through */
	case 1:
		if (arg_to_fid(argv[0], fid) != 0)
			return usage(do_find);
		/* fall through */
	case 0:
		break;
	default:
		return usage(do_find);
	}

	printf("FileID\tType  Size\n");
	while (1) {
		sc_file_t *file = NULL;

		printf("(%02X%02X)\r", fid[0], fid[1]);
		fflush(stdout);

		if (current_path.type != SC_PATH_TYPE_DF_NAME) {
			path = current_path;
			sc_append_path_id(&path, fid, sizeof(fid));
		} else {
			if (sc_path_set(&path, SC_PATH_TYPE_FILE_ID, fid, sizeof(fid), 0, 0) != SC_SUCCESS) {
				fprintf(stderr, "Unable to set path.\n");
				die(1);
			}
		}

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &path, &file);
		sc_unlock(card);
		switch (r) {
		case SC_SUCCESS:
			file->id = (fid[0] << 8) | fid[1];
			print_file(file);
			sc_file_free(file);
			select_current_path_or_die();
			break;
		case SC_ERROR_NOT_ALLOWED:
		case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
			printf("(%02X%02X)\t%s\n", fid[0], fid[1], sc_strerror(r));
			break;
		}

		if (fid[0] == end[0] && fid[1] == end[1])
			break;
		fid[1] = fid[1] + 1;
		if (fid[1] == 0)
			fid[0] = fid[0] + 1;
	}
	return 0;
}

static int do_find_tags(int argc, char **argv)
{
	u8 start[2] = { 0x00, 0x00 };
	u8 end[2]   = { 0xFF, 0xFF };
	u8 rbuf[SC_MAX_EXT_APDU_RESP_SIZE];
	int r;
	unsigned int tag, tag_end;

	switch (argc) {
	case 2:
		if (arg_to_fid(argv[1], end) != 0)
			return usage(do_find_tags);
		/* fall through */
	case 1:
		if (arg_to_fid(argv[0], start) != 0)
			return usage(do_find_tags);
		/* fall through */
	case 0:
		break;
	default:
		return usage(do_find_tags);
	}
	tag = (start[0] << 8) | start[1];
	tag_end = (end[0] << 8) | end[1];

	printf("Tag\tType\n");
	while (1) {
		printf("(%04X)\r", tag);
		fflush(stdout);

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_get_data(card, tag, rbuf, sizeof(rbuf));
		else
			r = SC_ERROR_READER_LOCKED;
		sc_unlock(card);
		if (r >= 0) {
			printf(" %04X ", tag);
			if (tag == 0)
				printf("\tdump file");
			if ((0x0001 <= tag && tag <= 0x00FE)
					|| (0x1F1F <= tag && tag <= 0xFFFF))
				printf("\tBER-TLV");
			if (tag == 0x00FF || tag == 0x02FF)
				printf("\tspecial function");
			if (0x0100 <= tag && tag <= 0x01FF)
				printf("\tproprietary");
			if (tag == 0x0200)
				printf("\tRFU");
			if (0x0201 <= tag && tag <= 0x02FE)
				printf("\tSIMPLE-TLV");
			printf("\n");
			if (r > 0)
				util_hex_dump_asc(stdout, rbuf, r, -1);
		} else {
			switch (r) {
				case SC_ERROR_NOT_ALLOWED:
				case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
					printf("(%04X)\t%s\n", tag, sc_strerror(r));
					break;
			}
		}

		if (tag >= tag_end)
			break;
		tag++;
	}
	return 0;
}

static int do_cd(int argc, char **argv)
{
	sc_path_t path;
	sc_file_t *file;
	int r;

	if (argc != 1)
		return usage(do_cd);

	if (strcmp(argv[0], "..") == 0) {
		path = current_path;
		if (path.len < 4) {
			fprintf(stderr, "unable to go up, already in MF.\n");
			return -1;
		}

		if (path.type == SC_PATH_TYPE_DF_NAME) {
			sc_format_path("3F00", &path);
		}
		else {
			path.len -= 2;
		}

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &path, &file);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "unable to go up: %s\n", sc_strerror(r));
			return -1;
		}
		sc_file_free(current_file);
		current_file = file;
		current_path = path;
		return 0;
	}
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_cd);

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select DF", current_file);
		return -1;
	}
	if ((file->type != SC_FILE_TYPE_DF) && (file->type != SC_FILE_TYPE_UNKNOWN) &&
			(card->type != SC_CARD_TYPE_BELPIC_EID)) {
		fprintf(stderr, "Error: file is not a DF.\n");
		sc_file_free(file);
		select_current_path_or_die();
		return -1;
	}
	current_path = path;
	sc_file_free(current_file);
	current_file = file;

	return 0;
}

static int read_and_print_binary_file(sc_file_t *file)
{
	u8 *buf;
	size_t size = (file->size > 0) ? file->size : SC_MAX_EXT_APDU_RESP_SIZE;
	int r, ret = -1;

	buf = calloc(size, 1);
	if (buf == NULL)
		return -1;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_read_binary(card, 0, buf, size, 0);
	sc_unlock(card);
	if (r < 0) {
		check_ret(r, SC_AC_OP_READ, "Read failed", file);
		goto err;
	}

	util_hex_dump_asc(stdout, buf, r, 0);

	ret = 0;

err:
	free(buf);
	return ret;
}

static int read_and_print_record_file(sc_file_t *file, unsigned char sfi, unsigned int wanted)
{
	u8 buf[SC_MAX_EXT_APDU_RESP_SIZE];
	int r;
	unsigned int rec;

	for (rec = (wanted > 0) ? wanted : 1; wanted == 0 || wanted == rec; rec++) {
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_read_record(card, rec, buf, sizeof(buf),
					SC_RECORD_BY_REC_NR | sfi);
		else
			r = SC_ERROR_READER_LOCKED;
		sc_unlock(card);
		if (r == SC_ERROR_RECORD_NOT_FOUND && wanted == 0)
			return 0;
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "Read failed", file);
			return -1;
		}
		printf("Record %d:\n", rec);
		util_hex_dump_asc(stdout, buf, r, 0);
	}

	return 0;
}

static int do_cat(int argc, char **argv)
{
	int r, err = 1;
	unsigned int rec = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	int not_current = 1;
	int sfi = 0;

	if (argc > 2)
		return usage(do_cat);

	if (argc > 1)
		rec = (unsigned int) strtoul(argv[1], NULL, 10);

	if (!argc) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else {
		const char sfi_prefix[] = "sfi:";

		if (strncasecmp(argv[0], sfi_prefix, strlen(sfi_prefix)) == 0) {
			const char *sfi_n = argv[0] + strlen(sfi_prefix);

			if(!current_file) {
				fprintf(stderr, "A DF must be selected to read by SFI\n");
				goto err;
			}
			path = current_path;
			file = current_file;
			not_current = 0;
			sfi = atoi(sfi_n);
			if ((sfi < 1) || (sfi > 30)) {
				fprintf(stderr, "Invalid SFI: %s\n", sfi_n);
				return usage(do_cat);
			}
		} else {
			if (arg_to_path(argv[0], &path, 0) != 0)
				return usage(do_cat);

			r = sc_lock(card);
			if (r == SC_SUCCESS)
				r = sc_select_file(card, &path, &file);
			sc_unlock(card);
			if (r) {
				check_ret(r, SC_AC_OP_SELECT, "unable to select file",
					current_file);
				goto err;
			}
		}
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF &&
		!(file->type == SC_FILE_TYPE_DF && sfi)) {
		fprintf(stderr, "only working EFs may be read\n");
		goto err;
	}
	if (file->ef_structure == SC_FILE_EF_TRANSPARENT && !sfi) {
		if (argc > 1) {
			fprintf(stderr, "Transparent files do not have records\n");
			goto err;
		}
		read_and_print_binary_file(file);
	}
	else
		read_and_print_record_file(file, sfi, rec);

	err = 0;
err:
	if (not_current) {
		sc_file_free(file);
		select_current_path_or_die();
	}

	return -err;
}

static int do_info(int argc, char **argv)
{
	sc_file_t *file;
	sc_path_t path;
	size_t i;
	const char *st = NULL;
	int r, not_current = 1;
	const id2str_t *ac_ops = NULL;

	const char *lifecycle = "unknown value";

	static const id2str_t lc[] = {
		{ SC_FILE_STATUS_NO_INFO,		"No information given"		},
		{ SC_FILE_STATUS_CREATION,		"Creation state"		},
		{ SC_FILE_STATUS_RFU_2,			"RFU (2)"			},
		{ SC_FILE_STATUS_INITIALISATION,	"Initialisation state"		},
		{ SC_FILE_STATUS_INVALIDATED,		"Operational, deactivated"	},
		{ SC_FILE_STATUS_ACTIVATED,		"Operational, activated"	},
		{ SC_FILE_STATUS_RFU_8,			"RFU (8)"			},
		{ SC_FILE_STATUS_RFU_9,			"RFU (9)"			},
		{ SC_FILE_STATUS_RFU_10,		"RFU (10)"			},
		{ SC_FILE_STATUS_RFU_11,		"RFU (11)"			},
		{ SC_FILE_STATUS_TERMINATION,		"Termination state"		},
		{ SC_FILE_STATUS_PROPRIETARY,		"Proprietary state"		},
		{ SC_FILE_STATUS_UNKNOWN,		"LCSB is not present"		},
		{  0, NULL }
	};

	if (!argc) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else if (argc == 1) {
		if (arg_to_path(argv[0], &path, 0) != 0)
			return usage(do_info);

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &path, &file);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "unable to select file: %s\n", sc_strerror(r));
			return -1;
		}
	} else
		return usage(do_info);

	if (!file->type_attr_len)
		st = "Unknown File";

	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		st = "Working Elementary File";
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		st = "Internal Elementary File";
		break;
	case SC_FILE_TYPE_DF:
		st = "Dedicated File";
		break;
	}
	if (st == NULL)
		printf("\nFile type [%02x] ID %04X", *file->type_attr, file->id);
	else
		printf("\n%s  ID %04X", st, file->id);
	if (file->sid)
		printf(", SFI %02X", file->sid);
	printf("\n\n%-25s%s\n", "File path:", path_to_filename(&path, '/', 0));
	printf("%-25s%"SC_FORMAT_LEN_SIZE_T"u bytes\n", "File size:", file->size);

	if (file->type == SC_FILE_TYPE_DF) {
		static const id2str_t ac_ops_df[] = {
			{ SC_AC_OP_SELECT,       "SELECT"       },
			{ SC_AC_OP_LOCK,         "LOCK"         },
			{ SC_AC_OP_DELETE,       "DELETE"       },
			{ SC_AC_OP_CREATE,       "CREATE"       },
			{ SC_AC_OP_REHABILITATE, "REHABILITATE" },
			{ SC_AC_OP_INVALIDATE,   "INVALIDATE"   },
			{ SC_AC_OP_LIST_FILES,   "LIST FILES"   },
			{ SC_AC_OP_CRYPTO,       "CRYPTO"       },
			{ SC_AC_OP_DELETE_SELF,  "DELETE SELF"  },
			{ 0, NULL }
		};

		if (file->namelen) {
			printf("%-25s", "DF name:");
			util_print_binary(stdout, file->name, file->namelen);
			printf("\n");
		}

		ac_ops = ac_ops_df;
	} else {
		static const id2str_t ac_ops_ef[] = {
			{ SC_AC_OP_READ,         "READ"         },
			{ SC_AC_OP_UPDATE,       "UPDATE"       },
			{ SC_AC_OP_DELETE,       "DELETE"       },
			{ SC_AC_OP_WRITE,        "WRITE"        },
			{ SC_AC_OP_REHABILITATE, "REHABILITATE" },
			{ SC_AC_OP_INVALIDATE,   "INVALIDATE"   },
			{ SC_AC_OP_LIST_FILES,   "LIST FILES"   },
			{ SC_AC_OP_CRYPTO,       "CRYPTO"       },
			{ 0, NULL }
		};
		const id2str_t ef_type_name[] = {
			{ SC_FILE_EF_TRANSPARENT,         "Transparent"                 },
			{ SC_FILE_EF_LINEAR_FIXED,        "Linear fixed"                },
			{ SC_FILE_EF_LINEAR_FIXED_TLV,    "Linear fixed, SIMPLE-TLV"    },
			{ SC_FILE_EF_LINEAR_VARIABLE,     "Linear variable"             },
			{ SC_FILE_EF_LINEAR_VARIABLE_TLV, "Linear variable, SIMPLE-TLV" },
			{ SC_FILE_EF_CYCLIC,              "Cyclic"                      },
			{ SC_FILE_EF_CYCLIC_TLV,          "Cyclic, SIMPLE-TLV"          },
			{ 0, NULL }
		};
		const char *ef_type = "Unknown";

		for (i = 0; ef_type_name[i].str != NULL; i++)
			if (file->ef_structure == ef_type_name[i].id)
				ef_type = ef_type_name[i].str;
		printf("%-25s%s\n", "EF structure:", ef_type);

		if (file->record_count > 0)
			printf("%-25s%"SC_FORMAT_LEN_SIZE_T"u\n",
				"Number of records:", file->record_count);

		if (file->record_length > 0)
			printf("%-25s%"SC_FORMAT_LEN_SIZE_T"u bytes\n",
				"Max. record size:", file->record_length);

		ac_ops = ac_ops_ef;
	}

	for (i = 0; ac_ops != NULL && ac_ops[i].str != NULL; i++) {
		int len = strlen(ac_ops[i].str);

		printf("ACL for %s:%*s %s\n",
			ac_ops[i].str,
			(15 > len) ? (15 - len) : 0, "",
			util_acl_to_str(sc_file_get_acl_entry(file, ac_ops[i].id)));
	}

	if (file->type_attr_len > 0) {
		printf("%-25s", "Type attributes:");
		util_hex_dump(stdout, file->type_attr, file->type_attr_len, " ");
		printf("\n");
	}
	if (file->prop_attr_len > 0) {
		printf("%-25s", "Proprietary attributes:");
		util_hex_dump(stdout, file->prop_attr, file->prop_attr_len, " ");
		printf("\n");
	}
	if (file->sec_attr_len > 0) {
		printf("%-25s", "Security attributes:");
		util_hex_dump(stdout, file->sec_attr, file->sec_attr_len, " ");
		printf("\n");
	}
	for (i = 0; lc[i].str != NULL; i++)
		if (file->status == lc[i].id)
			lifecycle = lc[i].str;
	printf("%-25s%s\n", "Life cycle: ", lifecycle);
	printf("\n");
	if (not_current) {
		sc_file_free(file);
		select_current_path_or_die();
	}
	return 0;
}

static int create_file(sc_file_t *file)
{
	int r;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_create_file(card, file);
	sc_unlock(card);
	if (r) {
		check_ret(r, SC_AC_OP_CREATE, "CREATE FILE failed", current_file);
		return -1;
	}
	/* Make sure we're back in the parent directory, because on some cards
	 * CREATE FILE also selects the newly created file. */
	select_current_path_or_die();
	return 0;
}

static int do_create(int argc, char **argv)
{
	sc_path_t path;
	sc_file_t *file;
	unsigned int size;
	int r, op;

	if (argc < 2)
		return usage(do_create);
	if (arg_to_path(argv[0], &path, 1) != 0)
		return usage(do_create);
	/* %z isn't supported everywhere */
	if (sscanf(argv[1], "%u", &size) != 1)
		return usage(do_create);

	file = sc_file_new();
	file->id = (path.value[0] << 8) | path.value[1];
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->size = (size_t) size;
	file->status = SC_FILE_STATUS_ACTIVATED;
	for (op = 0; op < SC_MAX_AC_OPS; op++)
		sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);

	if (argc > 2)   {
		snprintf((char *)file->name, sizeof(file->name), "%s", argv[2]);
		file->namelen = strlen((char *)file->name);
	}

	r = create_file(file);
	sc_file_free(file);
	return r;
}

static int do_mkdir(int argc, char **argv)
{
	sc_path_t path;
	sc_file_t *file;
	unsigned int size;
	int r, op;

	if (argc != 2)
		return usage(do_mkdir);
	if (arg_to_path(argv[0], &path, 1) != 0)
		return usage(do_mkdir);
	if (sscanf(argv[1], "%u", &size) != 1)
		return usage(do_mkdir);
	file = sc_file_new();
	file->id = (path.value[0] << 8) | path.value[1];
	file->type = SC_FILE_TYPE_DF;
	file->size = size;
	file->status = SC_FILE_STATUS_ACTIVATED;
	for (op = 0; op < SC_MAX_AC_OPS; op++)
		sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);

	r = create_file(file);
	sc_file_free(file);
	return r;
}

static int do_delete(int argc, char **argv)
{
	sc_path_t path;
	int r;

	if (argc != 1)
		return usage(do_delete);
	if (arg_to_path(argv[0], &path, 1) != 0)
		return usage(do_delete);
	if (path.len != 2)
		return usage(do_delete);
	path.type = SC_PATH_TYPE_FILE_ID;
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_delete_file(card, &path);
	sc_unlock(card);
	if (r) {
		check_ret(r, SC_AC_OP_DELETE, "DELETE FILE failed", current_file);
		return -1;
	}
	return 0;
}

static int do_pininfo(int argc, char **argv)
{
	const id2str_t typeNames[] = {
		{ SC_AC_CHV,	"CHV"	},
		{ SC_AC_AUT,	"KEY"	},
		{ SC_AC_AUT,	"AUT"	},
		{ SC_AC_PRO,	"PRO"	},
		{ SC_AC_NONE,	NULL, 	}
	};
	int r, tries_left = -1;
	size_t i;
	struct sc_pin_cmd_data data;
	int prefix_len = 0;

	if (argc != 1)
		return usage(do_pininfo);

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_GET_INFO;

	data.pin_type = SC_AC_NONE;
	for (i = 0; typeNames[i].str; i++) {
		prefix_len = strlen(typeNames[i].str);
		if (strncasecmp(argv[0], typeNames[i].str, prefix_len) == 0) {
			data.pin_type = typeNames[i].id;
			break;
		}
	}
	if (data.pin_type == SC_AC_NONE) {
		fprintf(stderr, "Invalid type.\n");
		return usage(do_pininfo);
	}
	if (sscanf(argv[0] + prefix_len, "%d", &data.pin_reference) != 1) {
		fprintf(stderr, "Invalid key reference.\n");
		return usage(do_pininfo);
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_pin_cmd(card, &data, &tries_left);
	sc_unlock(card);

	if (r) {
		fprintf(stderr, "Unable to get PIN info: %s\n", sc_strerror(r));
		return -1;
	}
	switch (data.pin1.logged_in) {
		case SC_PIN_STATE_LOGGED_IN:
			printf("Logged in.\n");
			break;
		case SC_PIN_STATE_LOGGED_OUT:
			printf("Logged out.\n");
			break;
		case SC_PIN_STATE_UNKNOWN:
		default:
			printf("Login status unknown.\n");
	}
	if (tries_left >= 0)
		printf("%d tries left.\n", tries_left);
	return 0;
}

static int do_verify(int argc, char **argv)
{
	const id2str_t typeNames[] = {
		{ SC_AC_CHV,	"CHV"	},
		{ SC_AC_AUT,	"KEY"	},
		{ SC_AC_AUT,	"AUT"	},
		{ SC_AC_PRO,	"PRO"	},
		{ SC_AC_NONE,	NULL, 	}
	};
	int r, tries_left = -1;
	u8 buf[SC_MAX_PIN_SIZE];
	size_t buflen = sizeof(buf), i;
	struct sc_pin_cmd_data data;
	int prefix_len = 0;

	if (argc < 1 || argc > 2)
		return usage(do_verify);

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;

	data.pin_type = SC_AC_NONE;
	for (i = 0; typeNames[i].str; i++) {
		prefix_len = strlen(typeNames[i].str);
		if (strncasecmp(argv[0], typeNames[i].str, prefix_len) == 0) {
			data.pin_type = typeNames[i].id;
			break;
		}
	}
	if (data.pin_type == SC_AC_NONE) {
		fprintf(stderr, "Invalid type.\n");
		return usage(do_verify);
	}
	if (sscanf(argv[0] + prefix_len, "%d", &data.pin_reference) != 1) {
		fprintf(stderr, "Invalid key reference.\n");
		return usage(do_verify);
	}

	if (argc < 2) {
		if (card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
			printf("Please enter PIN on the reader's pin pad.\n");
			data.pin1.prompt = "Please enter PIN";
			data.flags |= SC_PIN_CMD_USE_PINPAD;
		}
		else {
			char *pin = NULL;
			size_t len = 0;

			printf("Please enter PIN: ");
			r = util_getpass(&pin, &len, stdin);
			if (r < 0) {
				fprintf(stderr, "util_getpass error.\n");
				return -1;
			}

			if (strlcpy((char *)buf, pin, sizeof(buf)) >= sizeof(buf)) {
				free(pin);
				fprintf(stderr, "PIN too long - aborting VERIFY.\n");
				return -1;
			}
			free(pin);
			data.pin1.data = buf;
			data.pin1.len = strlen((char *)buf);
		}
	} else {
		r = parse_string_or_hexdata(argv[1], buf, &buflen);
		if (0 != r) {
			fprintf(stderr, "Invalid key value.\n");
			return usage(do_verify);
		}
		data.pin1.data = buf;
		data.pin1.len = buflen;
	}
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_pin_cmd(card, &data, &tries_left);
	sc_unlock(card);

	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT) {
			if (tries_left >= 0)
				printf("Incorrect code, %d tries left.\n", tries_left);
			else
				printf("Incorrect code.\n");
		} else
			fprintf(stderr, "Unable to verify PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Code correct.\n");
	return 0;
}

static int do_change(int argc, char **argv)
{
	int ref, r, tries_left = -1;
	u8 oldpin[SC_MAX_PIN_SIZE];
	u8 newpin[SC_MAX_PIN_SIZE];
	size_t oldpinlen = 0;
	size_t newpinlen = 0;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_CHANGE;

	if (argc < 1 || argc > 3)
		return usage(do_change);
	if (strncasecmp(argv[0], "CHV", 3)) {
		fprintf(stderr, "Invalid type.\n");
		return usage(do_change);
	}
	if (sscanf(argv[0] + 3, "%d", &ref) != 1) {
		fprintf(stderr, "Invalid key reference.\n");
		return usage(do_change);
	}

	if (argc == 3) {
		oldpinlen = sizeof(oldpin);
		if (parse_string_or_hexdata(argv[1], oldpin, &oldpinlen) != 0) {
			fprintf(stderr, "Invalid key value.\n");
			return usage(do_change);
		}
	}

	if (argc >= 2) {
		newpinlen = sizeof(newpin);
		if (parse_string_or_hexdata(argv[argc-1], newpin, &newpinlen) != 0) {
			fprintf(stderr, "Invalid key value.\n");
			return usage(do_change);
		}
	}

	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref;
	data.pin1.data = oldpinlen ? oldpin : NULL;
	data.pin1.len = oldpinlen;
	data.pin2.data = newpinlen ? newpin : NULL;
	data.pin2.len = newpinlen;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_pin_cmd(card, &data, &tries_left);
	sc_unlock(card);
	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT) {
			if (tries_left >= 0)
				printf("Incorrect code, %d tries left.\n", tries_left);
			else
				printf("Incorrect code.\n");
		}
		fprintf(stderr, "Unable to change PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("PIN changed.\n");
	return 0;
}


static int do_unblock(int argc, char **argv)
{
	int ref, r;
	u8 puk[SC_MAX_PIN_SIZE];
	u8 newpin[SC_MAX_PIN_SIZE];
	size_t puklen = 0;
	size_t newpinlen = 0;
	struct sc_pin_cmd_data data;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_UNBLOCK;

	if (argc < 1 || argc > 3)
		return usage(do_unblock);
	if (strncasecmp(argv[0], "CHV", 3)) {
		fprintf(stderr, "Invalid type.\n");
		return usage(do_unblock);
	}
	if (sscanf(argv[0] + 3, "%d", &ref) != 1) {
		printf("Invalid key reference.\n");
		return usage(do_unblock);
	}

	if (argc > 1) {
		puklen = sizeof(puk);
		if (parse_string_or_hexdata(argv[1], puk, &puklen) != 0) {
			fprintf(stderr, "Invalid key value.\n");
			return usage(do_unblock);
		}
	}

	if (argc > 2)   {
		newpinlen = sizeof(newpin);
		if (parse_string_or_hexdata(argv[2], newpin, &newpinlen) != 0) {
			fprintf(stderr, "Invalid key value.\n");
			return usage(do_unblock);
		}
	}

	data.pin_type = SC_AC_CHV;
	data.pin_reference = ref;
	data.pin1.data = puklen ? puk : NULL;
	data.pin1.len = puklen;
	data.pin2.data = newpinlen ? newpin : NULL;
	data.pin2.len = newpinlen;

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_pin_cmd(card, &data, NULL);
	sc_unlock(card);
	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
			fprintf(stderr, "Incorrect code.\n");
		fprintf(stderr, "Unable to unblock PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("PIN unblocked.\n");
	return 0;
}

static int do_get(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_RESP_SIZE];
	int r, err = 1;
	size_t count = 0;
	unsigned int idx = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	char *filename;
	FILE *outf = NULL;

	if (argc < 1 || argc > 2)
		return usage(do_get);
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_get);

	filename = (argc == 2) ? argv[1] : path_to_filename(&path, '_', 0);
	outf = (strcmp(filename, "-") == 0)
		? stdout
		: fopen(filename, "wb");
	if (outf == NULL) {
		perror(filename);
		goto err;
	}
#ifdef _WIN32
	if (outf == stdout)
	        _setmode(fileno(stdout), _O_BINARY);
#endif

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r || file == NULL) {
		check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
		goto err;
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF || file->ef_structure != SC_FILE_EF_TRANSPARENT) {
		fprintf(stderr, "Only transparent working EFs may be read\n");
		goto err;
	}
	count = file->size;
	while (count) {
		/* FIXME sc_read_binary does this kind of fetching in a loop already */
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = sc_read_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "Read failed", file);
			goto err;
		}
		if ((r != c) && (card->type != SC_CARD_TYPE_BELPIC_EID)) {
			fprintf(stderr, "Expecting %d, got only %d bytes.\n", c, r);
			goto err;
		}
		if ((r == 0) && (card->type == SC_CARD_TYPE_BELPIC_EID))
			break;
		fwrite(buf, r, 1, outf);
		idx += r;
		count -= r;
	}
	if (outf == stdout) {
		fwrite("\n", 1, 1, outf);
	}
	else {
		printf("Total of %d bytes read from %s and saved to %s.\n",
		       idx, argv[0], filename);
	}

	err = 0;
err:
	sc_file_free(file);
#ifdef _WIN32
	if (outf == stdout)
	        _setmode(fileno(stdout), _O_TEXT);
#endif
	if (outf != NULL && outf != stdout)
		fclose(outf);
	select_current_path_or_die();
	return -err;
}

static int do_get_record(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_RESP_SIZE];
	int r, err = 1;
	size_t rec, count = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	char *filename;
	FILE *outf = NULL;

	if (argc < 2 || argc > 3)
		return usage(do_get);
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_get);
	rec = strtoul(argv[1], NULL, 10);

	filename = (argc == 3) ? argv[2] : path_to_filename(&path, '_', rec);
	outf = (strcmp(filename, "-") == 0)
		? stdout
		: fopen(filename, "wb");
	if (outf == NULL) {
		perror(filename);
		goto err;
	}
#ifdef _WIN32
	if (outf == stdout)
	        _setmode(fileno(stdout), _O_BINARY);
#endif

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r || file == NULL) {
		check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
		goto err;
	}

	/* fail on wrong file type */
	if (file->type != SC_FILE_TYPE_WORKING_EF ||
		(file->ef_structure != SC_FILE_EF_LINEAR_FIXED &&
		file->ef_structure != SC_FILE_EF_LINEAR_FIXED_TLV &&
		file->ef_structure != SC_FILE_EF_LINEAR_VARIABLE &&
		file->ef_structure != SC_FILE_EF_LINEAR_VARIABLE_TLV)) {
		fprintf(stderr, "Only record-oriented working EFs may be read\n");
		goto err;
	}

	/* fail on out of bound record index:
	 * must be > 0 and if record_count is set <= record_count */
	if (rec < 1 || (file->record_count > 0 && rec > file->record_count)) {
		fprintf(stderr, "Invalid record number %"SC_FORMAT_LEN_SIZE_T"u\n", rec);
		goto err;
	}

	r = sc_read_record(card, rec, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
	if (r < 0)   {
		fprintf(stderr, "Cannot read record %"SC_FORMAT_LEN_SIZE_T"u; return %i\n", rec, r);
		goto err;
	}

	count = r;

	if (count > 0) {
		size_t written = fwrite(buf, 1, (size_t) r, outf);

		if (written != count) {
			fprintf(stderr, "Cannot write to file %s (only %"SC_FORMAT_LEN_SIZE_T"u of %"SC_FORMAT_LEN_SIZE_T"u bytes written)",
				filename, written, count);
			goto err;
		}
	}

	if (outf == stdout) {
		fwrite("\n", 1, 1, outf);
	}
	else {
		printf("Total of %"SC_FORMAT_LEN_SIZE_T"u bytes read from %s and saved to %s.\n",
		       count, argv[0], filename);
	}

	err = 0;
err:
	sc_file_free(file);
#ifdef _WIN32
	if (outf == stdout)
	        _setmode(fileno(stdout), _O_TEXT);
#endif
	if (outf != NULL && outf != stdout)
		fclose(outf);
	select_current_path_or_die();
	return -err;
}

static int do_update_binary(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_DATA_SIZE];
	size_t buflen = sizeof(buf);
	int r, err = 1;
	int offs;
	sc_path_t path;
	sc_file_t *file;

	if (argc != 3)
		return usage(do_update_binary);
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_update_binary);
	offs = strtol(argv[1], NULL, 10);

	r = parse_string_or_hexdata(argv[2], buf, &buflen);
	if (r < 0) {
		fprintf(stderr, "Unable to parse input data: %s\n", sc_strerror(r));
		return -1;
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
		return -1;
	}

	if (file->ef_structure != SC_FILE_EF_TRANSPARENT) {
		fprintf(stderr, "EF structure should be SC_FILE_EF_TRANSPARENT\n");
		goto err;
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_update_binary(card, offs, buf, buflen, 0);
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "Cannot update %04X: %s\n", file->id, sc_strerror(r));
		goto err;
	}

	printf("Total of %d bytes written to %04X at offset %d.\n",
	       r, file->id, offs);

	err = 0;
err:
	sc_file_free(file);
	select_current_path_or_die();
	return -err;
}

static int do_update_record(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_DATA_SIZE];
	size_t buflen;
	int r, err = 1;
	size_t rec, offs;
	sc_path_t path;
	sc_file_t *file;

	if (argc != 4)
		return usage(do_update_record);
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_update_record);
	rec  = strtol(argv[1], NULL, 10);
	offs = strtol(argv[2], NULL, 10);

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
		return -1;
	}

	if (file->ef_structure != SC_FILE_EF_LINEAR_VARIABLE) {
		fprintf(stderr, "EF structure should be SC_FILE_EF_LINEAR_VARIABLE\n");
		goto err;
	}

	if (rec < 1 || rec > file->record_count) {
		fprintf(stderr, "Invalid record number %"SC_FORMAT_LEN_SIZE_T"u\n", rec);
		goto err;
	}

	r = sc_read_record(card, rec, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
	if (r < 0) {
		fprintf(stderr, "Cannot read record %"SC_FORMAT_LEN_SIZE_T"u of %04X: %s\n",
			rec, file->id, sc_strerror(r));
		goto err;
	}

	/* do not allow gaps between data read and added */
	if (offs >= (size_t) r) {
		fprintf(stderr, "Offset too large.\n");
		goto err;
	}

	buflen = sizeof(buf) - offs;
	r = parse_string_or_hexdata(argv[3], buf + offs, &buflen);
	if (r < 0) {
		fprintf(stderr, "Unable to parse input data: %s.\n", sc_strerror(r));
		goto err;
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_update_record(card, rec, buf, buflen, SC_RECORD_BY_REC_NR);
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "Cannot update record %"SC_FORMAT_LEN_SIZE_T"u of %04X: %s\n.",
			rec, file->id, sc_strerror(r));
		goto err;
	}

	printf("Total of %d bytes written to %04X's record %"SC_FORMAT_LEN_SIZE_T"u "
		"at offset %"SC_FORMAT_LEN_SIZE_T"u.\n",
		r, file->id, rec, offs);

	err = 0;
err:
	sc_file_free(file);
	select_current_path_or_die();
	return -err;
}


static int do_put(int argc, char **argv)
{
	u8 buf[SC_MAX_EXT_APDU_DATA_SIZE];
	int r, err = 1;
	size_t count = 0;
	unsigned int idx = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	const char *filename;
	FILE *inf = NULL;

	if (argc < 1 || argc > 2)
		return usage(do_put);
	if (arg_to_path(argv[0], &path, 0) != 0)
		return usage(do_put);

	filename = (argc == 2) ? argv[1] : path_to_filename(&path, '_', 0);
	inf = fopen(filename, "rb");
	if (inf == NULL) {
		perror(filename);
		goto err;
	}
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_select_file(card, &path, &file);
	sc_unlock(card);
	if (r || file == NULL) {
		check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
		goto err;
	}
	count = file->size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = fread(buf, 1, c, inf);
		if (r < 0) {
			perror("fread");
			goto err;
		}
		if (r != c)
			count = c = r;
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_update_binary(card, idx, buf, c, 0);
		sc_unlock(card);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "Update failed", file);
			goto err;
		}
		if (r != c) {
			fprintf(stderr, "Expecting %d, wrote only %d bytes.\n", c, r);
			goto err;
		}
		idx += c;
		count -= c;
	}
	printf("Total of %d bytes written to %04X.\n", idx, file->id);

	err = 0;
err:
	sc_file_free(file);
	if (inf)
		fclose(inf);
	select_current_path_or_die();
	return -err;
}

static int do_debug(int argc, char **argv)
{
	int i;

	if (!argc)
		printf("Current debug level is %d\n", ctx->debug);
	else {
		if (sscanf(argv[0], "%d", &i) != 1)
			return -1;
		printf("Debug level set to %d\n", i);
		ctx->debug = i;
		if (i > 1) {
			sc_ctx_log_to_file(ctx, "stderr");
		}
	}
	return 0;
}


static int do_erase(int argc, char **argv)
{
	int	r;

	if (argc != 0)
		return usage(do_erase);

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL);
	sc_unlock(card);
	if (r) {
		fprintf(stderr, "Failed to erase card: %s\n", sc_strerror(r));
		return -1;
	}
	return 0;
}

static int do_random(int argc, char **argv)
{
	unsigned char buffer[SC_MAX_EXT_APDU_BUFFER_SIZE];
	int r, count;
	const char *filename = NULL;
	FILE *outf = NULL;

	if (argc < 1 || argc > 2)
		return usage(do_random);
	count = atoi(argv[0]);

	if (count < 0 || (size_t) count > sizeof(buffer)) {
		fprintf(stderr, "Number must be in range 0..%"SC_FORMAT_LEN_SIZE_T"u\n",
			sizeof(buffer));
		return -1;
	}

	if (argc == 2) {
		filename = argv[1];

		if (interactive && strcmp(filename, "-") == 0) {
			fprintf(stderr, "Binary writing to stdout not supported in interactive mode\n");
			return -1;
		}

		outf = (strcmp(filename, "-") == 0)
			? stdout
			: fopen(filename, "wb");
		if (outf == NULL) {
			perror(filename);
			return -1;
		}
#ifdef _WIN32
		if (outf == stdout)
		        _setmode(fileno(stdout), _O_BINARY);
#endif
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_get_challenge(card, buffer, count);
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "Failed to get random bytes: %s\n", sc_strerror(r));
		if (argc == 2) {
			fclose(outf);
		}
		return -1;
	}

	if (argc == 2) {
		/* outf is guaranteed to be non-NULL */
		size_t written = fwrite(buffer, 1, count, outf);

		if (written < (size_t) count)
			perror(filename);

		if (outf == stdout) {
#ifdef _WIN32
			_setmode(fileno(stdout), _O_TEXT);
#endif
			printf("\nTotal of %"SC_FORMAT_LEN_SIZE_T"u random bytes written\n", written);
		}
		else
			printf("Total of %"SC_FORMAT_LEN_SIZE_T"u random bytes written to %s\n",
				written, filename);

		fclose(outf);

		if (written < (size_t) count)
			return -1;
	}
	else {
		util_hex_dump_asc(stdout, buffer, count, 0);
	}
	return 0;
}

static int do_get_data(int argc, char **argv)
{
	u8 id[2] = { 0x00, 0x00 };
	unsigned int tag;
	u8 buffer[SC_MAX_EXT_APDU_RESP_SIZE];
	FILE *fp;
	int r;

	if (argc != 1 && argc != 2)
		return usage(do_get_data);
	if (arg_to_fid(argv[0], id) != 0)
		return usage(do_get_data);
	tag = id[0] << 8 | id[1];

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_get_data(card, tag, buffer, sizeof(buffer));
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "Failed to get DO %04X: %s\n", tag, sc_strerror(r));
		return -1;
	}

	if (argc == 2) {
		const char *filename = argv[1];

		fp = (strcmp(filename, "-") == 0)
			? stdout
			: fopen(filename, "wb");
		if (fp == NULL) {
			perror(filename);
			return -1;
		}
#ifdef _WIN32
		if (fp == stdout)
			_setmode(fileno(stdout), _O_BINARY);
#endif
		fwrite(buffer, r, 1, fp);
#ifdef _WIN32
		if (fp == stdout)
			_setmode(fileno(stdout), _O_TEXT);
#endif
		if (fp != stdout)
			fclose(fp);
	} else {
		printf("Data Object %04X:\n", tag & 0xFFFF);
		util_hex_dump_asc(stdout, buffer, r, 0);
	}

	return 0;
}

/**
 * Use PUT DATA command to write to Data Object.
 **/
static int do_put_data(int argc, char **argv)
{
	u8 id[2] = { 0x00, 0x00 };
	unsigned int tag;
	u8 buf[SC_MAX_EXT_APDU_DATA_SIZE];
	size_t buflen = sizeof(buf);
	int r;

	if (argc != 2)
		return usage(do_put_data);

	if (arg_to_fid(argv[0], id) != 0)
		return usage(do_get_data);
	tag = id[0] << 8 | id[1];

	/* Extract the new content */
	/* buflen is the max length of reception buffer */
	r = parse_string_or_hexdata(argv[1], buf, &buflen);
	if (r < 0) {
		fprintf(stderr, "Error parsing %s: %s\n", argv[1], sc_strerror(r));
		return r;
	}

	/* Call OpenSC to do put data */
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_put_data(card, tag, buf, buflen);
	sc_unlock(card);
	if (r < 0) {
		fprintf(stderr, "Failed to put data to DO %04X: %s\n", tag, sc_strerror(r));
		return -1;
	}

	printf("Total of %d bytes written.\n", r);

	return 0;
}

static int do_apdu(int argc, char **argv)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t len, i;
	int r;

	if (argc < 1)
		return usage(do_apdu);

	/* loop over the args and parse them, making sure the result fits into buf[] */
	for (i = 0, len = 0; i < (unsigned) argc && len < sizeof(buf); i++)   {
		size_t len0 = sizeof(buf) - len;

		if ((r = parse_string_or_hexdata(argv[i], buf + len, &len0)) < 0) {
			fprintf(stderr, "error parsing %s: %s\n", argv[i], sc_strerror(r));
			return r;
		};
		len += len0;
	}

	r = sc_bytes2apdu(card->ctx, buf, len, &apdu);
	if (r) {
		fprintf(stderr, "Invalid APDU: %s\n", sc_strerror(r));
		return 2;
	}

	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	printf("Sending: ");
	util_hex_dump(stdout, buf, len, " ");
	printf("\n");
	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
		return 1;
	}
	printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
	       apdu.resplen ? ":" : "");
	if (apdu.resplen)
		util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		fprintf(stderr, "Failure: %s\n", sc_strerror(r));
	else
		printf("Success!\n");
	return 0;
}

static int do_asn1(int argc, char **argv)
{
	int r, err = 1;
	unsigned int offs = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	int not_current = 1;
	u8 buf[SC_MAX_EXT_APDU_DATA_SIZE];

	if (argc > 3)
		return usage(do_asn1);

	/* select file */
	if (argc) {
		if (arg_to_path(argv[0], &path, 0) != 0) {
			fprintf(stderr, "Invalid file path\n");
			return -1;
		}
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &path, &file);
		sc_unlock(card);
		if (r) {
			check_ret(r, SC_AC_OP_SELECT, "Unable to select file", current_file);
			goto err;
		}
	} else {
		path = current_path;
		file = current_file;
		not_current = 0;
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF) {
		fprintf(stderr, "Only working EFs may be read\n");
		goto err;
	}

	/* read */
	if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
		size_t size = (file->size > 0) ? file->size : sizeof(buf);

		if (argc > 2) {
			fprintf(stderr, "Transparent EFs do not have records\n");
			goto err;
		}

		if (argc > 1)
			offs = (unsigned int) strtoul(argv[1], NULL, 10);

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_read_binary(card, 0, buf, MIN(size, sizeof(buf)), 0);
		sc_unlock(card);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "read failed", file);
			goto err;
		}
		if ((size_t) r != file->size) {
			fprintf(stderr, "WARNING: expecting %"SC_FORMAT_LEN_SIZE_T"u, got %d bytes.\n",
				 file->size, r);
			/* some cards return a bogus value for file length.
			 * As long as the actual length is not higher
			 * than the expected length, continue */
			if ((size_t) r > file->size)
				goto err;
		}
	}
	else {	/* record-oriented file */
		unsigned int rec = 0;

		if (argc < 2) {
			fprintf(stderr, "Record-oriented EFs require parameter record number.\n");
			goto err;
		}

		rec = (unsigned int) strtoul(argv[1], NULL, 10);
		if (argc > 2)
			offs = (unsigned int) strtoul(argv[2], NULL, 10);

		if (rec < 1 || rec > file->record_count) {
			fprintf(stderr, "Invalid record number %u.\n", rec);
			goto err;
		}

		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_read_record(card, rec, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
		else
			r = SC_ERROR_READER_LOCKED;
		sc_unlock(card);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "Read failed", file);
			goto err;
		}
	}

	/* if offset does not exceed the length read from file/record, ... */
	if (offs <= (unsigned int) r) {
		/* ... perform the ASN.1 dump */
		sc_asn1_print_tags(buf + offs, (unsigned int) r - offs);

		err = 0;
	}

err:
	if (not_current) {
		sc_file_free(file);
		select_current_path_or_die();
	}
	return -err;
}

static int do_sm(int argc, char **argv)
{
	int r = SC_ERROR_NOT_SUPPORTED, ret = -1;

	if (argc != 1)
		return usage(do_sm);

#ifdef ENABLE_SM
	if (!strcmp(argv[0],"open"))   {
		if (!card->sm_ctx.ops.open)   {
			fprintf(stderr, "Not supported\n");
			return -1;
		}
		r = card->sm_ctx.ops.open(card);
	}
	else if (!strcmp(argv[0],"close"))   {
		if (!card->sm_ctx.ops.close)   {
			fprintf(stderr, "Not supported\n");
			return -1;
		}
		r = card->sm_ctx.ops.close(card);
	}
#endif
	if (r == SC_SUCCESS)   {
		ret = 0;
		printf("Success!\n");
	}
	else   {
		fprintf(stderr, "Failure: %s\n", sc_strerror(r));
	}

	return ret;
}

static int do_help(int argc, char **argv)
{
	struct command	*cmd;

	printf("%s commands:\n", (argc) ? "Matching" : "Supported");

	for (cmd = cmds; cmd->name; cmd++) {
		int i;
		int match = 0;

		for (i = 0; i < argc; i++) {
			if (strncmp(cmd->name, argv[i], strlen(argv[i])) == 0)
				match++;
		}
		if (match || !argc) {
			int len = strlen(cmd->name) + strlen(cmd->args);

			printf("  %s %s%*s  %s\n",
				cmd->name, cmd->args,
				(len > 40) ? 0 : (40 - len), "",
				cmd->help);
		}
	}

	return 0;
}

static int do_quit(int argc, char **argv)
{
	die(0);
	return 0;
}

static int parse_cmdline(char *in, char **argv, int argvsize)
{
	int	argc;

	for (argc = 0; argc < argvsize-1; argc++) {
		in += strspn(in, " \t\n");

		if (*in == '\0') {		/* end of input reached */
			argv[argc] = NULL;
			return argc;
		}
		if (*in == '"') {		/* double-quoted string */
			argv[argc] = in++;
			in += strcspn(in, "\"");
			if (*in++ != '"') {	/* error: unbalanced quote */
				argv[0] = NULL;
				return 0;
			}
		}
		else {				/* white-space delimited word */
			argv[argc] = in;
			in += strcspn(in, " \t\n");
		}
		if (*in != '\0')
			*in++ = '\0';
	}

	/* error: too many arguments - argv[] exhausted */
	argv[0] = NULL;
	return 0;
}

static char *read_cmdline(FILE *script, char *prompt)
{
	static char buf[SC_MAX_EXT_APDU_BUFFER_SIZE];

	if (interactive) {
#ifdef ENABLE_READLINE
		static int initialized;

		if (!initialized) {
			initialized = 1;
			using_history();
		}

		char *line = readline(prompt);

		/* add line to history if longer than 2 characters */
		if (line != NULL && strlen(line) > 2)
			add_history(line);

		/* return in interactive case with readline */
		return line;
#else
		sc_color_fprintf(SC_COLOR_FG_BLUE|SC_COLOR_BOLD, NULL, stdout, "%s", prompt);
#endif
	}

	/* either we don't have readline or we are not running interactively */
	fflush(stdout);
	if (fgets(buf, sizeof(buf), script) == NULL) {
		fputc('\n', stdout);
		return NULL;
	}
	if (strlen(buf) == 0)
		return NULL;
	if (buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = '\0';
	return buf;
}

int main(int argc, char *argv[])
{
	int r, c, long_optind = 0, err = 0;
	sc_context_param_t ctx_param;
	int lcycle = SC_CARDCTRL_LIFECYCLE_ADMIN;
	FILE *script;

	printf("OpenSC Explorer version %s\n", sc_get_version());

	while (1) {
		c = getopt_long(argc, argv, "r:c:vwm:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, "[SCRIPT]");
		switch (c) {
		case 'r':
			opt_reader = optarg;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'm':
			opt_startfile = optarg;
			break;
		}
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}

	ctx->flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;

	if (verbose > 1) {
		ctx->debug = verbose;
		ctx->debug_file = stderr;
        }

	if (opt_driver != NULL) {
		/* special card driver value "?" means: list available drivers */
		if (strncmp("?", opt_driver, sizeof("?")) == 0) {
			err = util_list_card_drivers(ctx);
			goto end;
		}

		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n", opt_driver);
			err = 1;
			goto end;
		}
	}

	err = util_connect_card_ex(ctx, &card, opt_reader, opt_wait, 0, 0);
	if (err)
		goto end;

	if (opt_startfile) {
		if(*opt_startfile) {
			char startpath[SC_MAX_PATH_STRING_SIZE * 2];
			char *args[] = { startpath };

			if (strlcpy(startpath, opt_startfile, sizeof(startpath)) >= sizeof(startpath)) {
				fprintf(stderr, "unable to select file %s: name too long\n",
					opt_startfile);
				die(1);
			}
			r = do_cd(1, args);
			if (r) {
				fprintf(stderr, "unable to select file %s: %s\n",
					opt_startfile, sc_strerror(r));
				die(1);
			}
		}
	} else {
		sc_format_path("3F00", &current_path);
		r = sc_lock(card);
		if (r == SC_SUCCESS)
			r = sc_select_file(card, &current_path, &current_file);
		sc_unlock(card);
		if (r) {
			fprintf(stderr, "unable to select MF: %s\n", sc_strerror(r));
			die(1);
		}
	}

	r = sc_lock(card);
	if (r == SC_SUCCESS)
		r = sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &lcycle);
	sc_unlock(card);
	if (r && r != SC_ERROR_NOT_SUPPORTED)
		printf("unable to change lifecycle: %s\n", sc_strerror(r));

	switch (argc - optind) {
	default:
		util_print_usage_and_die(app_name, options, option_help, "[SCRIPT]");
		break;
	case 0:
		interactive = 1;
		script = stdin;
		break;
	case 1:
		interactive = 0;
		if (strcmp(argv[optind], "-") == 0) {
			script = stdin;
		}
		else if ((script = fopen(argv[optind], "r")) == NULL) {
			util_print_usage_and_die(app_name, options, option_help, "[SCRIPT]");
		}
		break;
	}

	while (!feof(script)) {
		char *line;
		int cargc;
		char *cargv[260];
		int multiple;
		struct command *cmd;
		char prompt[3*SC_MAX_PATH_STRING_SIZE];

		sprintf(prompt, "OpenSC [%s]> ", path_to_filename(&current_path, '/', 0));
		line = read_cmdline(script, prompt);
		if (line == NULL)
			break;

		cargc = parse_cmdline(line, cargv, DIM(cargv));
		if ((cargc < 1) || (*cargv[0] == '#'))
			continue;

		cmd = ambiguous_match(cmds, cargv[0], &multiple);
		if (cmd == NULL) {
			fprintf(stderr, "%s command: %s\n",
				(multiple) ? "Ambiguous" : "Unknown", cargv[0]);
			if (interactive)
				do_help((multiple) ? 1 : 0, cargv);
			err = -1;
		} else {
			err = cmd->func(cargc-1, cargv+1);
		}
	}
end:
	die(err);

	return 0; /* not reached */
}
