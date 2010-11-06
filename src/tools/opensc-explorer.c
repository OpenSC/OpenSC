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
#ifdef ENABLE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "libopensc/opensc.h"
#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "util.h"

#define DIM(v) (sizeof(v)/sizeof((v)[0]))

static const char *app_name = "opensc-explorer";

static int opt_wait = 0, verbose = 0;
static const char *opt_driver = NULL;
static const char *opt_reader = NULL;
static const char *opt_startfile = NULL;

static sc_file_t *current_file = NULL;
static sc_path_t current_path;
static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

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
	"Forces the use of driver <arg> [auto-detect]",
	"Selects path <arg> on start-up, or none if empty [3F00]",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
};

static size_t hex2binary(u8 *out, size_t outlen, const char *in);

struct command {
	const char *	name;
	int		(*func)(int, char **);
	const char *	help;
};

static void die(int ret)
{
	if (current_file != NULL)
		sc_file_free(current_file);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_release_context(ctx);
	exit(ret);
}

static void select_current_path_or_die(void)
{
	if (current_path.type || current_path.len) {
		int r = sc_select_file(card, &current_path, NULL);
		if (r) {
			printf("unable to select parent DF: %s\n", sc_strerror(r));
			die(1);
		}
	}
}

static struct command *
ambiguous_match(struct command *table, const char *cmd)
{
	struct command *last_match = NULL;
	int matches = 0;

	for (; table->name; table++) {
		if (strncasecmp(cmd, table->name, strlen(cmd)) == 0) {
			last_match = table;
			matches++;
		}
	}
	if (matches > 1) {
		printf("Ambiguous command: %s\n", cmd);
		return NULL;
	}
	return last_match;
}

static void check_ret(int r, int op, const char *err, const sc_file_t *file)
{
	fprintf(stderr, "%s: %s\n", err, sc_strerror(r));
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		fprintf(stderr, "ACL for operation: %s\n", util_acl_to_str(sc_file_get_acl_entry(file, op)));
}

static int arg_to_path(const char *arg, sc_path_t *path, int is_id)
{
	if (strncasecmp(arg, "aid:", strlen("aid:")) == 0) {
		/* DF aid */
		const char *p = arg + strlen("aid:");
		path->len  = hex2binary(path->value, sizeof(path->value), p);
		path->type = SC_PATH_TYPE_DF_NAME;
	} else {
		/* file id */
		unsigned int buf[2];
		u8 cbuf[2];
	
		if (strlen(arg) != 4) {
			printf("Wrong ID length.\n");
			return -1;
		}
		if (sscanf(arg, "%02X%02X", &buf[0], &buf[1]) != 2) {
			printf("Invalid ID.\n");
			return -1;
		}
		cbuf[0] = buf[0];
		cbuf[1] = buf[1];
		if ((cbuf[0] == 0x3F && cbuf[1] == 0x00) || is_id) {
			path->len = 2;
			memcpy(path->value, cbuf, 2);
			if (is_id)
				path->type = SC_PATH_TYPE_FILE_ID;
			else
				path->type = SC_PATH_TYPE_PATH;
		} else {
			*path = current_path;
			sc_append_path_id(path, cbuf, 2);
		}
	}

	return 0;	
}

static void print_file(const sc_file_t *file)
{
	const char *st;

	if (file->type == SC_FILE_TYPE_DF)
		printf("[");
	else
		printf(" ");
	printf("%02X%02X", file->id >> 8, file->id & 0xFF);
	if (file->type == SC_FILE_TYPE_DF)
		printf("]");
	else
		printf(" ");
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		st = "wEF";
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		st = "iEF";
		break;
	case SC_FILE_TYPE_DF:
		st = "DF";
		break;
	default:
		st = "???";
		break;
	}
	printf("\t%4s", st);
	printf(" %5lu", (unsigned long)file->size);
	if (file->namelen) {
		printf("\tName: ");
		util_print_binary(stdout, file->name, file->namelen);
	}
	printf("\n");
	return;
}

static int do_ls(int argc, char **argv)
{
	u8 buf[256], *cur = buf;
	int r, count;

	if (argc)
		goto usage;
	r = sc_list_files(card, buf, sizeof(buf));
	if (r < 0) {
		check_ret(r, SC_AC_OP_LIST_FILES, "unable to receive file listing", current_file);
		return -1;
	}
	count = r;
	printf("FileID\tType  Size\n");
	while (count >= 2) {
		sc_path_t path;
		sc_file_t *file = NULL;

		if (current_path.type != SC_PATH_TYPE_DF_NAME) {
			path = current_path;
			sc_append_path_id(&path, cur, 2);
		} else {
			if (sc_path_set(&path, SC_PATH_TYPE_FILE_ID, cur, 2, 0, 0) != SC_SUCCESS) {
				printf("unable to set path.\n");
				die(1);
			}
		}
			
		r = sc_select_file(card, &path, &file);
		if (r) {
			printf(" %02X%02X unable to select file, %s\n", cur[0], cur[1], sc_strerror(r));
		} else {
			file->id = (cur[0] << 8) | cur[1];
			print_file(file);
			sc_file_free(file);
		}
		cur += 2;
		count -= 2;
		select_current_path_or_die();
	}
	return 0;
usage:
	puts("Usage: ls");
	return -1;
}

static int do_cd(int argc, char **argv)
{
	sc_path_t path;
	sc_file_t *file;
	int r;

	if (argc != 1)
		goto usage;
	if (strcmp(argv[0], "..") == 0) {
		if (current_path.len < 4) {
			printf("unable to go up, already in MF.\n");
			return -1;
		}
		path = current_path;
		path.len -= 2;
		r = sc_select_file(card, &path, &file);
		if (r) {
			printf("unable to go up: %s\n", sc_strerror(r));
			return -1;
		}
		if (current_file)
			sc_file_free(current_file);
		current_file = file;
		current_path = path;
		return 0;
	}
	if (arg_to_path(argv[0], &path, 0) != 0) 
		goto usage;

	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select DF", current_file);
		return -1;
	}
	if ((file->type != SC_FILE_TYPE_DF) && !(card->caps & SC_CARD_CAP_NO_FCI)) {
		printf("Error: file is not a DF.\n");
		sc_file_free(file);
		select_current_path_or_die();
		return -1;
	}
	current_path = path;
	if (current_file)
		sc_file_free(current_file);
	current_file = file;

	return 0;
usage:
	puts("Usage: cd <file_id>|aid:<DF name>");
	return -1;
}

static int read_and_util_print_binary_file(sc_file_t *file)
{
	unsigned int idx = 0;
	u8 buf[128];
	size_t count;
	int r;
	
	count = file->size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = sc_read_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "read failed", file);
			return -1;
		}
		if ((r != c) && !(card->caps & SC_CARD_CAP_NO_FCI)) {
			printf("expecting %d, got only %d bytes.\n", c, r);
			return -1;
		}
		if ((r == 0) && (card->caps & SC_CARD_CAP_NO_FCI))
			break;
		util_hex_dump_asc(stdout, buf, r, idx);
		idx += r;
		count -= r;
	}
	return 0;
}

static int read_and_print_record_file(sc_file_t *file, unsigned char sfi)
{
	u8 buf[256];
	int rec, r;

	for (rec = 1; ; rec++) {
		r = sc_read_record(card, rec, buf, sizeof(buf),
			SC_RECORD_BY_REC_NR | sfi);
		if (r == SC_ERROR_RECORD_NOT_FOUND)
			return 0;
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "read failed", file);
			return -1;
		}
		printf("Record %d:\n", rec);
		util_hex_dump_asc(stdout, buf, r, 0);
	}
}

static int do_cat(int argc, char **argv)
{
	int r, err = 1;
	sc_path_t path;
	sc_file_t *file = NULL;
	int not_current = 1;
	int sfi = 0;
	const char sfi_prefix[] = "sfi:";

	if (argc > 1)
		goto usage;
	if (!argc) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else {
		if (strncmp(argv[0], sfi_prefix, sizeof(sfi_prefix)-1)) {
			if (arg_to_path(argv[0], &path, 1) != 0)
				goto usage;
			r = sc_select_file(card, &path, &file);
			if (r) {
				check_ret(r, SC_AC_OP_SELECT, "unable to select file",
					current_file);
				goto err;
			}
		} else {
			const char *sfi_n = &argv[0][sizeof(sfi_prefix)-1];

			if(!current_file) {
				printf("A DF must be selected to read by SFI\n");
				goto err;
			}
			path = current_path;
			file = current_file;
			not_current = 0;
			sfi = atoi(sfi_n);
			if ((sfi < 1) || (sfi > 30)) {
				printf("Invalid SFI: %s\n", sfi_n);
				goto usage;
			}
		}
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF &&
		!(file->type == SC_FILE_TYPE_DF && sfi)) {
		printf("only working EFs may be read\n");
		goto err;
	}
	if (file->ef_structure == SC_FILE_EF_TRANSPARENT && !sfi)
		read_and_util_print_binary_file(file);
	else
		read_and_print_record_file(file, sfi);
	
	err = 0;

err:
	if (not_current) {
		if (file != NULL) {
			sc_file_free(file);
		}
		select_current_path_or_die();
	}

	return -err;
usage:
	puts("Usage: cat [file_id] or");
	puts("       cat sfi:<sfi_id>");
	return -1;
}

static int do_info(int argc, char **argv)
{
	sc_file_t *file;
	sc_path_t path;
	size_t i;
	const char *st;
	int r, not_current = 1;

	if (!argc) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else if (argc == 1) {
		if (arg_to_path(argv[0], &path, 0) != 0) 
			goto usage;
		r = sc_select_file(card, &path, &file);
		if (r) {
			printf("unable to select file: %s\n", sc_strerror(r));
			return -1;
		}
	} else 
		goto usage;

	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
	case SC_FILE_TYPE_INTERNAL_EF:
		st = "Elementary File";
		break;
	case SC_FILE_TYPE_DF:
		st = "Dedicated File";
		break;
	default:
		st = "Unknown File";
		break;
	}
	printf("\n%s  ID %04X\n\n", st, file->id);
	printf("%-15s", "File path:");
	for (i = 0; i < path.len; i++) {
		for (i = 0; i < path.len; i++) {
			if ((i & 1) == 0 && i)
				printf("/");
			printf("%02X", path.value[i]);
		}
	}
	printf("\n%-15s%lu bytes\n", "File size:", (unsigned long) file->size);

	if (file->type == SC_FILE_TYPE_DF) {
		const char *ops[] = {
			"SELECT", "LOCK", "DELETE", "CREATE", "REHABILITATE",
			"INVALIDATE", "LIST FILES", "CRYPTO", "DELETE SELF"
		};
		if (file->namelen) {
			printf("%-15s", "DF name:");
			util_print_binary(stdout, file->name, file->namelen);
			printf("\n");
		}
		for (i = 0; i < sizeof(ops)/sizeof(ops[0]); i++) {
			char buf[80];
			
			sprintf(buf, "ACL for %s:", ops[i]);
			printf("%-25s%s\n", buf, util_acl_to_str(sc_file_get_acl_entry(file, i)));
		}
	} else {
		const char *structs[] = {
			"Unknown", "Transparent", "Linear fixed",
			"Linear fixed, SIMPLE-TLV", "Linear variable",
			"Linear variable TLV", "Cyclic, SIMPLE-TLV",
		};
		const struct {
			const char * label;
			int op;
		} ops[] = {
			{ "READ", SC_AC_OP_READ },
			{ "UPDATE", SC_AC_OP_UPDATE },
			{ "DELETE", SC_AC_OP_DELETE },
			{ "WRITE", SC_AC_OP_WRITE },
			{ "REHABILITATE", SC_AC_OP_REHABILITATE },
			{ "INVALIDATE", SC_AC_OP_INVALIDATE },
			{ "LIST_FILES", SC_AC_OP_LIST_FILES },
			{ "CRYPTO", SC_AC_OP_CRYPTO },
		};
		printf("%-15s%s\n", "EF structure:", structs[file->ef_structure]);
		for (i = 0; i < sizeof(ops)/sizeof(ops[0]); i++) {
			char buf[80];
			
			sprintf(buf, "ACL for %s:", ops[i].label);
			printf("%-25s%s\n", buf, util_acl_to_str(sc_file_get_acl_entry(file, ops[i].op)));
		}
	}	
	if (file->prop_attr_len) {
		printf("%-25s", "Proprietary attributes:");
		for (i = 0; i < file->prop_attr_len; i++)
			printf("%02X ", file->prop_attr[i]);
		printf("\n");
	}
	if (file->sec_attr_len) {
		printf("%-25s", "Security attributes:");
		for (i = 0; i < file->sec_attr_len; i++)
			printf("%02X ", file->sec_attr[i]);
		printf("\n");
	}
	printf("\n");
	if (not_current) {
		sc_file_free(file);
		select_current_path_or_die();
	}
	return 0;

usage:
	puts("Usage: info [file_id]");
	return -1;
}

static int create_file(sc_file_t *file)
{
	int r;
	
	r = sc_create_file(card, file);
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

	if (argc != 2)
		goto usage;
	if (arg_to_path(argv[0], &path, 1) != 0)
		goto usage;
	/* %z isn't supported everywhere */
	if (sscanf(argv[1], "%u", &size) != 1)
		goto usage;
	file = sc_file_new();
	file->id = (path.value[0] << 8) | path.value[1];
	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->size = (size_t) size;
	file->status = SC_FILE_STATUS_ACTIVATED;
	for (op = 0; op < SC_MAX_AC_OPS; op++)
		sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
	
	r = create_file(file);
	sc_file_free(file);
	return r;
 usage:
	printf("Usage: create <file_id> <file_size>\n");
	return -1;
}

static int do_mkdir(int argc, char **argv)
{
	sc_path_t path;
	sc_file_t *file;
	unsigned int size;
	int r, op;

	if (argc != 2)
		goto usage;
	if (arg_to_path(argv[0], &path, 1) != 0)
		goto usage;
	if (sscanf(argv[1], "%u", &size) != 1)
		goto usage;
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
 usage:
	printf("Usage: mkdir <file_id> <df_size>\n");
	return -1;
}

static int do_delete(int argc, char **argv)
{
	sc_path_t path;
	int r;

	if (argc != 1)
		goto usage;
	if (arg_to_path(argv[0], &path, 1) != 0)
		goto usage;
	if (path.len != 2)
		goto usage;
	path.type = SC_PATH_TYPE_FILE_ID;
	r = sc_delete_file(card, &path);
	if (r) {
		check_ret(r, SC_AC_OP_DELETE, "DELETE FILE failed", current_file);
		return -1;
	}
	return 0;
usage:
	printf("Usage: delete <file_id>\n");
	return -1;
}

static int do_verify(int argc, char **argv)
{
	struct {
		const char *	name;
		int		type;
	} typeNames[] = {
		{ "CHV",	SC_AC_CHV	},
		{ "KEY",	SC_AC_AUT	},
		{ "AUT",	SC_AC_AUT	},
		{ "PRO",	SC_AC_PRO	},
		{ NULL, 	SC_AC_NONE	}
	};
	int r, tries_left = -1;
	u8 buf[64];
	const char *s;
	size_t buflen = sizeof(buf), i;
	struct sc_pin_cmd_data data;

	if (argc < 1 || argc > 2)
		goto usage;

	memset(&data, 0, sizeof(data));
	data.cmd = SC_PIN_CMD_VERIFY;

	data.pin_type = SC_AC_NONE;
	for (i = 0; typeNames[i].name; i++) {
		if (strncasecmp(argv[0], typeNames[i].name, 3) == 0) {
			data.pin_type = typeNames[i].type;
			break;
		}
	}
	if (data.pin_type == SC_AC_NONE) {
		printf("Invalid type.\n");
		goto usage;
	}
	if (sscanf(argv[0] + 3, "%d", &data.pin_reference) != 1) {
		printf("Invalid key reference.\n");
		goto usage;
	}

	if (argc < 2) {
		if (!(card->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
			printf("Card reader or driver doesn't support PIN PAD\n");
			return -1;
		}
		printf("Please enter PIN on the reader's pin pad.\n");
		data.pin1.prompt = "Please enter PIN";
		data.flags |= SC_PIN_CMD_USE_PINPAD;
	} else if (argv[1][0] == '"') {
		for (s=argv[1]+1, i=0; i < sizeof(buf) && *s && *s != '"';i++) 
			buf[i] = *s++;
		data.pin1.data = buf;
		data.pin1.len = i;
	} else {
		r = sc_hex_to_bin(argv[1], buf, &buflen); 
		if (0 != r) {
			printf("Invalid key value.\n");
			goto usage;
		}
		data.pin1.data = buf;
		data.pin1.len = buflen;
	}
	r = sc_pin_cmd(card, &data, &tries_left);

	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT) {
			if (tries_left >= 0) 
				printf("Incorrect code, %d tries left.\n", tries_left);
			else
				printf("Incorrect code.\n");
		} else
			printf("Unable to verify PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Code correct.\n");
	return 0;
usage:
	printf("Usage: verify <key type><key ref> [<key in hex>]\n");
	printf("Possible values of <key type>:\n");
	for (i = 0; typeNames[i].name; i++)
		printf("\t%s\n", typeNames[i].name);
	printf("Example: verify CHV2 31:32:33:34:00:00:00:00\n");
	printf("If key is omitted, card reader's keypad will be used to collect PIN.\n");
	return -1;
}


static int do_change(int argc, char **argv)
{
	int ref, r, tries_left = -1;
	u8 oldpin[30];
	u8 newpin[30];
	const char *s;
	size_t oldpinlen = sizeof(oldpin), i;
	size_t newpinlen = sizeof(newpin);
	
	if (argc < 1 || argc > 3)
		goto usage;
	if (strncasecmp(argv[0], "CHV", 3)) {
		printf("Invalid type.\n");
		goto usage;
	}
	if (sscanf(argv[0] + 3, "%d", &ref) != 1) {
		printf("Invalid key reference.\n");
		goto usage;
	}
	argc--;
	argv++;

	if (argc == 0) {
		/* set without verification */
		oldpinlen = 0;
		newpinlen = 0;
	} else if (argc == 1) {
		/* set without verification */
		oldpinlen = 0;
	} else {
		if (argv[0][0] == '"') {
			for (s = argv[0] + 1, i = 0;
			     i < sizeof(oldpin) && *s && *s != '"'; i++) 
				oldpin[i] = *s++;
			oldpinlen = i;
		} else if (sc_hex_to_bin(argv[0], oldpin, &oldpinlen) != 0) {
			printf("Invalid key value.\n");
			goto usage;
		}
		argc--;
		argv++;
	}

	if (argc)   {
		if (argv[0][0] == '"') {
			for (s = argv[0] + 1, i = 0;
			     i < sizeof(newpin) && *s && *s != '"'; i++) 
				newpin[i] = *s++;
			newpinlen = i;
		} else if (sc_hex_to_bin(argv[0], newpin, &newpinlen) != 0) {
			printf("Invalid key value.\n");
			goto usage;
		}
	}

	r = sc_change_reference_data (card, SC_AC_CHV, ref,
                                      oldpinlen ? oldpin : NULL, oldpinlen,
                                      newpinlen ? newpin : NULL, newpinlen,
                                      &tries_left);
	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT) {
			if (tries_left >= 0) 
				printf("Incorrect code, %d tries left.\n", tries_left);
			else
				printf("Incorrect code.\n");
		}
		printf("Unable to change PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("PIN changed.\n");
	return 0;
usage:
	printf("Usage: change CHV<pin ref> [[<old pin>] <new pin>]\n");
	printf("Examples: \n");
	printf("\tChange PIN: change CHV2 00:00:00:00:00:00 \"foobar\"\n");
	printf("\tSet PIN: change CHV2 \"foobar\"\n");
	printf("\tChange PIN with pinpad': change CHV2\n");
	return -1;
}


static int do_unblock(int argc, char **argv)
{
	int ref, r;
	u8 puk_buf[30], *puk = NULL;
	u8 newpin_buf[30], *newpin = NULL;
	const char *s;
	size_t puklen = sizeof(puk_buf), i;
	size_t newpinlen = sizeof(newpin_buf);
	
	if (argc < 1 || argc > 3)
		goto usage;
	if (strncasecmp(argv[0], "CHV", 3)) {
		printf("Invalid type.\n");
		goto usage;
	}
	if (sscanf(argv[0] + 3, "%d", &ref) != 1) {
		printf("Invalid key reference.\n");
		goto usage;
	}
	argc--;
	argv++;

	if (argc == 0) {
		puklen = 0;
		puk = NULL;
	} else {
		if (argv[0][0] == '"') {
			for (s = argv[0] + 1, i = 0;
			     i < sizeof(puk_buf) && *s && *s != '"'; i++) 
				puk_buf[i] = *s++;
			puklen = i;
		} else if (sc_hex_to_bin(argv[0], puk_buf, &puklen) != 0) {
			printf("Invalid key value.\n");
			goto usage;
		}
		puk = &puk_buf[0];

		argc--;
		argv++;
	}

	if (argc)   {
		if (argv[0][0] == '"') {
			for (s = argv[0] + 1, i = 0;
			     i < sizeof(newpin_buf) && *s && *s != '"'; i++) 
				newpin_buf[i] = *s++;
			newpinlen = i;
		} else if (sc_hex_to_bin(argv[0], newpin_buf, &newpinlen) != 0) {
			printf("Invalid key value.\n");
			goto usage;
		}

		newpin = &newpin_buf[0];
	}
	else   {
		newpinlen = 0;
		newpin = NULL;
	}

	r = sc_reset_retry_counter (card, SC_AC_CHV, ref,
                                      puk, puklen,
                                      newpin, newpinlen);
	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT)
			printf("Incorrect code.\n");
		printf("Unable to unblock PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("PIN unblocked.\n");
	return 0;
usage:
	printf("Usage: unblock CHV<pin ref> [<puk>] [<new pin>]\n");
	printf("PUK and PIN values can be hexadecimal, ASCII, empty (\"\") or absent\n");
	printf("Examples:\n");
	printf("\tUnblock PIN and set a new value:   unblock CHV2 00:00:00:00:00:00 \"foobar\"\n");
	printf("\tUnblock PIN keeping the old value: unblock CHV2 00:00:00:00:00:00 \"\"\n");
	printf("\tSet new PIN value:                 unblock CHV2 \"\" \"foobar\"\n");
	printf("Examples with pinpad:\n");
	printf("\tUnblock PIN: new PIN value is prompted by pinpad:                   unblock CHV2 00:00:00:00:00:00\n");
	printf("\tSet PIN: new PIN value is prompted by pinpad:                       unblock CHV2 \"\"\n");
	printf("\tUnblock PIN: unblock code and new PIN value are prompted by pinpad: unblock CHV2\n");
	return -1;
}

static int do_get(int argc, char **argv)
{
	u8 buf[256];
	int r, err = 1;
	size_t count = 0;
	unsigned int idx = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	char fbuf[256], *filename;
	FILE *outf = NULL;
	
	if (argc < 1 || argc > 2)
		goto usage;
	if (arg_to_path(argv[0], &path, 0) != 0)
		goto usage;
	if (argc == 2)
		filename = argv[1];
	else {
		size_t i = 0;

		while (2*i < path.len) {
			sprintf(&fbuf[5*i], "%02X%02X_", path.value[2*i], path.value[2*i+1]);
			i++;
		}
		fbuf[5*i-1] = 0;
		filename = fbuf;
	}
	outf = fopen(filename, "wb");
	if (outf == NULL) {
		perror(filename);
		goto err;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", current_file);
		goto err;
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF) {
		printf("only working EFs may be read\n");
		goto err;
	}
	count = file->size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = sc_read_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "read failed", file);
			goto err;
		}
		if ((r != c) && !(card->caps & SC_CARD_CAP_NO_FCI)) {
			printf("expecting %d, got only %d bytes.\n", c, r);
			goto err;
		}
		if ((r == 0) && (card->caps & SC_CARD_CAP_NO_FCI))
			break;
		fwrite(buf, r, 1, outf);
		idx += r;
		count -= r;
	}
	printf("Total of %d bytes read from %s and saved to %s.\n",
	       idx, argv[0], filename);
	
	err = 0;
err:
	if (file)
		sc_file_free(file);
	if (outf)
		fclose(outf);
	select_current_path_or_die();
	return -err;
usage:
	printf("Usage: get <file id> [output file]\n");
	return -1;
}

static size_t hex2binary(u8 *out, size_t outlen, const char *in)
{
	size_t      inlen = strlen(in), len = outlen;
	const char *p = in;
	int	    s = 0;

	out--;
	while (inlen && (len || s)) {
		char c = *p++;
		inlen--;
		if (!isxdigit(c))
			continue;
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a' && c <= 'f')
			c -= 'a' - 10;
		else /* (c >= 'A' && c <= 'F') */
			c -= 'A' - 10;
		if (s)
			*out <<= 4;
		else {
			len--;
			*(++out) = 0;
		}
		s = !s;
		*out |= (u8)c;
	} 
	if (s) {
		printf("Error: the number of hex digits must be even.\n");
		return 0;
	}

	return outlen - len;
}

static int do_update_binary(int argc, char **argv)
{
	u8 buf[240];
	int r, err = 1, in_len;
	int offs;
	sc_path_t path;
	sc_file_t *file;
	char *in_str;
	
	if (argc < 2 || argc > 3)
		goto usage;
	if (arg_to_path(argv[0], &path, 0) != 0)
		goto usage;
	offs = strtol(argv[1],NULL,10);

	in_str = argv[2];
	printf("in: %i; %s\n", offs, in_str);
	if (*in_str=='\"')   {
		in_len = strlen(in_str)-2 >= sizeof(buf) ? sizeof(buf)-1 : strlen(in_str)-2;
		strncpy((char *) buf, in_str+1, in_len);
	} else {
		in_len = hex2binary(buf, sizeof(buf), in_str);
		if (!in_len) {
			printf("unable to parse hex value\n");
			return -1;
		}
	}
	
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", current_file);
		return -1;
	}

	if (file->ef_structure != SC_FILE_EF_TRANSPARENT)   {
		printf("EF structure should be SC_FILE_EF_TRANSPARENT\n");
		goto err;
	}
	
	r = sc_update_binary(card, offs, buf, in_len, 0);
	if (r < 0) {
		printf("Cannot update %04X; return %i\n", file->id, r);
		goto err;
	}

	printf("Total of %d bytes written to %04X at %i offset.\n", 
	       r, file->id, offs);

	err = 0;

err:
	sc_file_free(file);
	select_current_path_or_die();
	return -err;
usage:
	printf("Usage: update <file id> offs <hex value> | <'\"' enclosed string>\n");
	return -1;
}

static int do_update_record(int argc, char **argv)
{
	u8 buf[240];
	int r, i, err = 1;
	int rec, offs;
	sc_path_t path;
	sc_file_t *file;
	char *in_str;
	
	if (argc < 3 || argc > 4)
		goto usage;
	if (arg_to_path(argv[0], &path, 0) != 0)
		goto usage;
	rec  = strtol(argv[1],NULL,10);
	offs = strtol(argv[2],NULL,10);

	in_str = argv[3];
	printf("in: %i; %i; %s\n", rec, offs, in_str);

	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", current_file);
		return -1;
	}

	if (file->ef_structure != SC_FILE_EF_LINEAR_VARIABLE)   {
		printf("EF structure should be SC_FILE_EF_LINEAR_VARIABLE\n");
		goto err;
	} else if (rec < 1 || rec > file->record_count)   {
		printf("Invalid record number %i\n", rec);
		goto err;
	}
	
	r = sc_read_record(card, rec, buf, sizeof(buf), SC_RECORD_BY_REC_NR);
	if (r<0)   {
		printf("Cannot read record %i; return %i\n", rec, r);
		goto err;;
	}

	i = hex2binary(buf + offs, sizeof(buf) - offs, in_str);
	if (!i) {
		printf("unable to parse hex value\n");
		goto err;
	}

	r = sc_update_record(card, rec, buf, r, SC_RECORD_BY_REC_NR);
	if (r<0)   {
		printf("Cannot update record %i; return %i\n", rec, r);
		goto err;
	}

	printf("Total of %d bytes written to record %i at %i offset.\n", 
	       i, rec, offs);
	err = 0;

err:
	sc_file_free(file);
	select_current_path_or_die();
	return -err;
usage:
	printf("Usage: update_record <file id> rec_nr rec_offs <hex value>\n");
	return -1;
}


static int do_put(int argc, char **argv)
{
	u8 buf[256];
	int r, err = 1;
	size_t count = 0;
	unsigned int idx = 0;
	sc_path_t path;
	sc_file_t *file = NULL;
	const char *filename;
	FILE *outf = NULL;

	if (argc < 1 || argc > 2)
		goto usage;
	if (arg_to_path(argv[0], &path, 0) != 0)
		goto usage;
	if (argc == 2)
		filename = argv[1];
	else {
		sprintf((char *) buf, "%02X%02X", path.value[0], path.value[1]);
		filename = (char *) buf;
	}
	outf = fopen(filename, "rb");
	if (outf == NULL) {
		perror(filename);
		goto err;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", current_file);
		goto err;
	}
	count = file->size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = fread(buf, 1, c, outf);
		if (r < 0) {
			perror("fread");
			goto err;
		}
		if (r != c)
			count = c = r;
		r = sc_update_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "update failed", file);
			goto err;
		}
		if (r != c) {
			printf("expecting %d, wrote only %d bytes.\n", c, r);
			goto err;
		}
		idx += c;
		count -= c;
	}
	printf("Total of %d bytes written.\n", idx);

	err = 0;

err:

	if (file)
		sc_file_free(file);
	if (outf)
		fclose(outf);
	select_current_path_or_die();
	return -err;
usage:
	printf("Usage: put <file id> [input file]\n");
	return -1;
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
		if (i) {
			ctx->debug_file = stderr;
		} else {
			ctx->debug_file = NULL;
		}
	}
	return 0;
}


static int
do_erase(int argc, char **argv)
{
	int	r;

	if (argc != 0)
		goto usage;

	r = sc_card_ctl(card, SC_CARDCTL_ERASE_CARD, NULL);
	if (r) {
		printf("Failed to erase card: %s\n", sc_strerror (r));
		return -1;
	}
	return 0;

usage:
	printf("Usage: erase\n");
	return -1;
}

static int
do_random(int argc, char **argv)
{
	unsigned char buffer[128];
	int r, count;

	if (argc != 1)
		goto usage;

	count = atoi(argv[0]);
	if (count < 0 || count > 128) {
		printf("Number must be in range 0..128\n");
		return -1;
	}

	r = sc_get_challenge(card, buffer, count);
	if (r < 0) {
		printf("Failed to get random bytes: %s\n", sc_strerror(r));
		return -1;
	}

	util_hex_dump_asc(stdout, buffer, count, 0);
	return 0;

usage:
	printf("Usage: random count\n");
	return -1;
}

static int do_get_data(int argc, char **argv)
{
	unsigned char buffer[256];
	unsigned int tag;
	FILE *fp;
	int r;

	if (argc != 1 && argc != 2)
		goto usage;

	tag = strtoul(argv[0], NULL, 16);
	r = sc_get_data(card, tag, buffer, sizeof(buffer));
	if (r < 0) {
		printf("Failed to get data object: %s\n", sc_strerror(r));
		return -1;
	}

	if (argc == 2) {
		const char	*filename = argv[1];

		if (!(fp = fopen(filename, "w"))) {
			perror(filename);
			return -1;
		}
		fwrite(buffer, r, 1, fp);
		fclose(fp);
	} else {
		printf("Object %04x:\n", tag & 0xFFFF);
		util_hex_dump_asc(stdout, buffer, r, 0);
	}

	return 0;

usage:	printf("Usage: do_get hex_tag [dest_file]\n");
	return -1;
}

static int do_put_data(int argc, char **argv)
{
	printf("Usage: do_put hex_tag source_file\n"
	       "or:    do_put hex_tag aa:bb:cc\n"
	       "or:    do_put hex_tag \"foobar...\"\n");
	return -1;
}

static int do_apdu(int argc, char **argv)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	size_t len, len0, r, ii;

	if (argc < 1) {
		puts("Usage: apdu [apdu:hex:codes:...]");
		return -1;
	}

	for (ii = 0, len = 0; ii < argc; ii++)   {
		len0 = strlen(argv[ii]);
		sc_hex_to_bin(argv[ii], buf + len, &len0);
		len += len0;
	}

	if (len < 4) {
		puts("APDU too short (must be at least 4 bytes)");
		return 1;
	}
	len0 = len;

	memset(&apdu, 0, sizeof(apdu));
	p = buf;
	apdu.cla = *p++;
	apdu.ins = *p++;
	apdu.p1 = *p++;
	apdu.p2 = *p++;
	len -= 4;
	if (len > 1) {
		apdu.lc = *p++;
		len--;
		memcpy(sbuf, p, apdu.lc);
		apdu.data = sbuf;
		apdu.datalen = apdu.lc;
		if (len < apdu.lc) {
			printf("APDU too short (need %lu bytes)\n",
				(unsigned long) apdu.lc - len);
			return 1;
		}
		len -= apdu.lc;
		p += apdu.lc;
		if (len) {
			apdu.le = *p++;
			if (apdu.le == 0)
				apdu.le = 256;
			len--;
			apdu.cse = SC_APDU_CASE_4_SHORT;
		} else {
			apdu.cse = SC_APDU_CASE_3_SHORT;
		}
		if (len) {
			printf("APDU too long (%lu bytes extra)\n",
				(unsigned long) len);
			return 1;
		}
	} else if (len == 1) {
		apdu.le = *p++;
		if (apdu.le == 0)
			apdu.le = 256;
		len--;
		apdu.cse = SC_APDU_CASE_2_SHORT;
	} else {
		apdu.cse = SC_APDU_CASE_1;
	}
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	printf("Sending: ");
	for (r = 0; r < len0; r++)
		printf("%02X ", buf[r]);
	printf("\n");
	r = sc_transmit_apdu(card, &apdu);
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
		return 1;
	}
	printf("Received (SW1=0x%02X, SW2=0x%02X)%s\n", apdu.sw1, apdu.sw2,
	       apdu.resplen ? ":" : "");
	if (apdu.resplen)
		util_hex_dump_asc(stdout, apdu.resp, apdu.resplen, -1);

	return 0;
}

static int do_asn1(int argc, char **argv)
{
	int r, err = 1;
	sc_path_t path;
	sc_file_t *file = NULL;
	int not_current = 1;
	size_t len;
	unsigned char *buf = NULL;

	if (argc > 1) {
		puts("Usage: asn1 [file_id]");
		return -1;
	}

	/* select file */
	if (argc) {
		if (arg_to_path(argv[0], &path, 1) != 0) {
			puts("Invalid file path");
			return -1;
		}
		r = sc_select_file(card, &path, &file);
		if (r) {
			check_ret(r, SC_AC_OP_SELECT, "unable to select file", current_file);
			goto err;
		}
	} else {
		path = current_path;
		file = current_file;
		not_current = 0;
	}
	if (file->type != SC_FILE_TYPE_WORKING_EF) {
		printf("only working EFs may be read\n");
		goto err;
	}

	/* read */
	if (file->ef_structure != SC_FILE_EF_TRANSPARENT) {
		printf("only transparent file type is supported at the moment\n");
		goto err;
	}
	len = file->size;
	buf = calloc(1, len);
	if (!buf) {
		goto err;
	}
	r = sc_read_binary(card, 0, buf, len, 0);
	if (r < 0) {
		check_ret(r, SC_AC_OP_READ, "read failed", file);
		goto err;
	}
	if ((size_t)r != len) {
		printf("expecting %ld, got only %d bytes.\n", len, r);
		goto err;
	}

	/* asn1 dump */
	sc_asn1_print_tags(buf, len);

	err = 0;
err:
	if (buf)
		free(buf);
	if (not_current) {
		if (file)
			sc_file_free(file);
		select_current_path_or_die();
	}
	return -err;
}

static int do_quit(int argc, char **argv)
{
	die(0);
	return 0;
}

static struct command	cmds[] = {
 { "ls",	do_ls,		"list all files in the current DF"	},
 { "cd",	do_cd,		"change to another DF"			},
 { "cat",	do_cat,		"print the contents of an EF"		},
 { "info",	do_info,	"display attributes of card file"	},
 { "create",	do_create,	"create a new EF"			},
 { "delete",	do_delete,	"remove an EF/DF"			},
 { "rm",	do_delete,	"remove an EF/DF"			},
 { "verify",	do_verify,	"present a PIN or key to the card"	},
 { "change",	do_change,	"change a PIN"                          },
 { "unblock",	do_unblock,	"unblock a PIN"                         },
 { "put",	do_put,		"copy a local file to the card"		},
 { "get",	do_get,		"copy an EF to a local file"		},
 { "do_get",	do_get_data,	"get a data object"			},
 { "do_put",	do_put_data,	"put a data object"			},
 { "mkdir",	do_mkdir,	"create a DF"				},
 { "erase",	do_erase,	"erase card"				},
 { "random",	do_random,	"obtain N random bytes from card"	},
 { "quit",	do_quit,	"quit this program"			},
 { "exit",	do_quit,	"quit this program"			},
 { "update_record", do_update_record, "update record"			},
 { "update_binary", do_update_binary, "update binary"			},
 { "debug",	do_debug,	"set the debug level"			},
 { "apdu",	do_apdu,	"send a custom apdu command"		},
 { "asn1",	do_asn1,	"decode an asn1 file"			},
 { NULL, NULL, NULL }
};

static void usage(void)
{
	struct command	*cmd;

	printf("Supported commands:\n");
	for (cmd = cmds; cmd->name; cmd++)
		printf("  %-10s %s\n", cmd->name, cmd->help);
}

static int parse_line(char *in, char **argv, int maxargc)
{
	int	argc;

	for (argc = 0; argc < maxargc; argc++) {
		in += strspn(in, " \t\n");
		if (*in == '\0')
			return argc;
 		if (*in == '"') {
			/* Parse quoted string */
			argv[argc] = in++;
			in += strcspn(in, "\"");
			if (*in++ != '"')
				return 0;
		} else {
			/* White space delimited word */
 			argv[argc] = in;
			in += strcspn(in, " \t\n");
		}
		if (*in != '\0')
			*in++ = '\0';
 	}
	return argc;
}

static char * my_readline(char *prompt)
{
	static char buf[256];
	static int initialized;
	static int interactive;

	if (!initialized) {
		initialized = 1;
		interactive = isatty(fileno(stdin));
#ifdef ENABLE_READLINE
		if (interactive)
			using_history ();
#endif
	}
#ifdef ENABLE_READLINE
	if (interactive) {
		char *line = readline(prompt);
		if (line && strlen(line) > 2 )
			add_history(line);
		return line;
	}
#endif
	/* Either we don't have readline or we are not running
	   interactively */
#ifndef ENABLE_READLINE
	printf("%s", prompt);
#endif
	fflush(stdout);
	if (fgets(buf, sizeof(buf), stdin) == NULL)
		return NULL;
	if (strlen(buf) == 0)
		return NULL;
	if (buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = '\0';
	return buf;
}

int main(int argc, char * const argv[])
{
	int r, c, long_optind = 0, err = 0;
	char *line;
	int cargc;
	char *cargv[260];
	sc_context_param_t ctx_param;
	int lcycle = SC_CARDCTRL_LIFECYCLE_ADMIN;

	printf("OpenSC Explorer version %s\n", sc_get_version());

	while (1) {
		c = getopt_long(argc, argv, "r:c:vwm:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help);
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

	if (verbose > 1) {
		ctx->debug = verbose;
		ctx->debug_file = stderr;
        }

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n", opt_driver);
			err = 1;
			goto end;
		}
	}

	err = util_connect_card(ctx, &card, opt_reader, opt_wait, 0);
	if (err)
		goto end;

	if (opt_startfile) {
		if(*opt_startfile) {
			char startpath[1024];
			char *argv[] = { startpath };

			strncpy(startpath, opt_startfile, sizeof(startpath)-1);
			r = do_cd(1, argv);
			if (r) {
				printf("unable to select file %s: %s\n",
					opt_startfile, sc_strerror(r));
				return -1;
			}
		}
	} else {
		sc_format_path("3F00", &current_path);
		r = sc_select_file(card, &current_path, &current_file);
		if (r) {
			printf("unable to select MF: %s\n", sc_strerror(r));
			return 1;
		}
	}
	
	r = sc_card_ctl(card, SC_CARDCTL_LIFECYCLE_SET, &lcycle);
	if (r && r != SC_ERROR_NOT_SUPPORTED)
		printf("unable to change lifecycle: %s\n", sc_strerror(r));

	while (1) {
		struct command *cmd;
		size_t i;
		char prompt[40];

		sprintf(prompt, "OpenSC [");
		for (i = 0; i < current_path.len; i++) {
			if ((i & 1) == 0 && i && current_path.type != SC_PATH_TYPE_DF_NAME)
				sprintf(prompt+strlen(prompt), "/");
			sprintf(prompt+strlen(prompt), "%02X",
			        current_path.value[i]);
		}
		sprintf(prompt+strlen(prompt), "]> ");
		line = my_readline(prompt);
		if (line == NULL)
			break;
		cargc = parse_line(line, cargv, DIM(cargv));
		if (cargc < 1)
			continue;
		for (r=cargc; r < (int)DIM(cargv); r++)
			cargv[r] = "";
		cmd = ambiguous_match(cmds, cargv[0]);
		if (cmd == NULL) {
			usage();
		} else {
			cmd->func(cargc-1, cargv+1);
		}
	}
end:
	die(err);
	
	return 0; /* not reached */
}
