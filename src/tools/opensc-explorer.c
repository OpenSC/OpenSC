/*
 * opensc-explorer.c: A shell for accessing SmartCards with libopensc
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

#include <opensc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "util.h"

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_file current_file;
struct sc_path current_path;

const struct option options[] = { { NULL } };
const char *option_help[] = { NULL };

const char *cmds[] = {
	"ls", "cd", "debug", "cat", "info"
};
const int nr_cmds = sizeof(cmds)/sizeof(cmds[0]);

int die(int ret)
{
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_destroy_context(ctx);
	exit(ret);
}

static int ambiguous_match(const char **table, int nr_entries, const char *cmd)
{
	int matches = 0;
	int last_match = 0;
	int i;

	for (i = 0; i < nr_entries; i++) {
                if (strncasecmp(cmd, table[i], strlen(cmd)) == 0) {
			matches++;
			last_match = i;
		}
	}
	if (matches > 1)
		return -1;
	if (matches == 0)
		return -2;
	return last_match;
}

void check_ret(int r, int op, const char *err, const struct sc_file *file)
{
	fprintf(stderr, "%s: %s\n", err, sc_strerror(r));
	if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
		fprintf(stderr, "ACL for operation: %s\n", acl_to_str(file->acl[op]));
}

void print_file(const struct sc_file *file)
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
        printf(" %5d", file->size);
	if (file->namelen) {
		printf("\tName: ");
		print_binary(stdout, file->name, file->namelen);
	}
        printf("\n");
	return;
}

int do_ls()
{
	u8 buf[256], *cur = buf;
	int r, count;

	r = sc_list_files(card, buf, sizeof(buf));
	if (r < 0) {
		check_ret(r, SC_AC_OP_LIST_FILES, "unable to receive file listing", &current_file);
		return -1;
	}
	count = r;
        printf("FileID\tType  Size\n");
	while (count >= 2) {
		struct sc_path path;
		struct sc_file file;

		memcpy(path.value, cur, 2);
		path.len = 2;
                path.type = SC_PATH_TYPE_FILE_ID;
		r = sc_select_file(card, &path, &file);
		if (r) {
			check_ret(r, SC_AC_OP_SELECT, "unable to select file", &current_file);
			return -1;
		}
                cur += 2;
		count -= 2;
                print_file(&file);
		r = sc_select_file(card, &current_path, NULL);
		if (r) {
			printf("unable to select parent DF: %s\n", sc_strerror(r));
			die(1);
		}
	}
        return 0;
}

int do_cd(const char *arg)
{
	struct sc_path path;
        struct sc_file file;
	char buf[6];
	int r;

	if (strcmp(arg, "..") == 0) {
		if (current_path.len < 4) {
			printf("unable to go up, already in MF.\n");
			return -1;
		}
                path = current_path;
		path.len -= 2;
		r = sc_select_file(card, &path, &current_file);
		if (r) {
			printf("unable to go up: %s\n", sc_strerror(r));
			return -1;
		}
		current_path = path;
		return 0;
	}

	if (strlen(arg) != 4) {
		printf("Usage: cd <file_id>\n");
		return -1;
	}
	strcpy(buf, "I");
        strcat(buf, arg);
	sc_format_path(buf, &path);
	if (path.len != 2) {
		printf("Usage: cd <file_id>\n");
		return -1;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select DF", &current_file);
		return -1;
	}
	memcpy(current_path.value + current_path.len, path.value, path.len);
        current_path.len += path.len;
        current_file = file;

	return 0;
}


int do_cat(const char *arg)
{
	u8 buf[256];
	int r, error = 0;
	size_t count = 0;
        unsigned int idx = 0;
	struct sc_path path;
        struct sc_file file;
	int not_current = 1;

	if (strlen(arg) == 0) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else {
		if (strlen(arg) != 4) {
			printf("Usage: cat [file_id]\n");
			return -1;
		}
		strcpy(buf, "I");
	        strcat(buf, arg);
		sc_format_path(buf, &path);
		if (path.len != 2) {
			printf("Usage: cat [file_id]\n");
			return -1;
		}
		r = sc_select_file(card, &path, &file);
		if (r) {
			check_ret(r, SC_AC_OP_SELECT, "unable to select file", &current_file);
			return -1;
		}
	}
	count = file.size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = sc_read_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "read failed", &file);
			error = 1;
                        goto err;
		}
		if (r != c) {
			printf("expecting %d, got only %d bytes.\n", c, r);
			error = 1;
                        goto err;
		}
		hex_dump_asc(stdout, buf, c, idx);
		idx += c;
		count -= c;
	}
err:
	if (not_current) {
		r = sc_select_file(card, &current_path, NULL);
		if (r) {
			printf("unable to select parent file: %s\n", sc_strerror(r));
			die(1);
		}
	}
        return -error;
}

int do_info(const char *arg)
{
	struct sc_file file;
	struct sc_path path;
	int r, i;
	const char *st;
	int not_current = 1;
	
	if (strlen(arg) == 0) {
		path = current_path;
		file = current_file;
		not_current = 0;
	} else {
		char buf[6];
		struct sc_path tmppath;
		
		if (strlen(arg) != 4) {
			printf("Usage: info [file_id]\n");
			return -1;
		}
		strcpy(buf, "I");
	        strcat(buf, arg);
		sc_format_path(buf, &tmppath);
		if (tmppath.len != 2) {
			printf("Usage: info [file_id]\n");
			return -1;
		}
		r = sc_select_file(card, &tmppath, &file);
		if (r) {
			printf("unable to select file: %s\n", sc_strerror(r));
			return -1;
		}
		path = current_path;
		memcpy(path.value + path.len, tmppath.value, 2);
		path.len += 2;
	}
	switch (file.type) {
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
	printf("\n%s  ID %04X\n\n", st, file.id);
	printf("%-15s", "File path:");
	for (i = 0; i < path.len; i++) {
		for (i = 0; i < path.len; i++) {
                        if ((i & 1) == 0 && i)
				printf("/");
			printf("%02X", path.value[i]);
		}
	}
	printf("\n%-15s%d bytes\n", "File size:", file.size);

	if (file.type == SC_FILE_TYPE_DF) {
		const char *ops[] = {
			"SELECT", "LOCK", "DELETE", "CREATE", "REHABILITATE",
			"INVALIDATE", "LIST FILES"
		};
		if (file.namelen) {
			printf("%-15s", "DF name:");
			print_binary(stdout, file.name, file.namelen);
			printf("\n");
		}
		for (i = 0; i < sizeof(ops)/sizeof(ops[0]); i++) {
			char buf[80];
			
			sprintf(buf, "ACL for %s:", ops[i]);
			printf("%-25s%s\n", buf, acl_to_str(file.acl[i]));
		}
	} else {
                const char *structs[] = {
                        "Unknown", "Transparent", "Linear fixed",
			"Linear fixed, SIMPLE-TLV", "Linear variable",
			"Cyclic", "Cyclic, SIMPLE-TLV",
                };
		printf("%-15s%s\n", "EF structure:", structs[file.ef_structure]);
	}	
	printf("\n");
	if (not_current) {
		r = sc_select_file(card, &current_path, NULL);
		if (r) {
			printf("unable to select parent file: %s\n", sc_strerror(r));
			die(1);
		}
	}
	return 0;
}

int handle_cmd(int cmd, const char *arg)
{
        int i;

	switch (cmd) {
	case 0:
		return do_ls();
	case 1:
		return do_cd(arg);
	case 2:
		if (sscanf(arg, "%d", &i) != 1)
			return -1;
		printf("Debug level set to %d\n", i);
		ctx->debug = i;
		if (i) {
			ctx->use_std_output = 1;
		} else
			ctx->use_std_output = 0;
		return 0;
	case 3:
                return do_cat(arg);
        case 4:
        	return do_info(arg);
	}
        return -1;
}

void usage()
{
	int i;
	
	printf("Supported commands:\n");
	for (i = 0; i < nr_cmds; i++)
		printf("  %s\n", cmds[i]);
}

int main(int argc, const char *argv[])
{
	int r;
	char line[80], cmd[80], arg[80];

	printf("OpenSC Explorer version %s\n", sc_version);

	r = sc_establish_context(&ctx);
	if (r) {
		printf("est ctx failed: %s\n", sc_strerror(r));
		return 1;
	}
	r = sc_connect_card(ctx, 0, &card);
	if (r) {
		printf("connect card failed: %s\n", sc_strerror(r));
		return 1;
	}
        sc_lock(card);

        sc_format_path("3F00", &current_path);
        r = sc_select_file(card, &current_path, &current_file);
	if (r) {
		printf("unable to select MF: %s\n", sc_strerror(r));
		return 1;
	}
	while (1) {
		int i;

		printf("OpenSC [");
		for (i = 0; i < current_path.len; i++) {
                        if ((i & 1) == 0 && i)
				printf("/");
			printf("%02X", current_path.value[i]);
		}
                printf("]> ");
		fflush(stdout);
                fflush(stdin);
		if (fgets(line, sizeof(line), stdin) == NULL)
			break;
		if (strlen(line) == 0)
			break;
		r = sscanf(line, "%s %s", cmd, arg);
		if (r < 1)
			continue;
		if (r == 1)
			arg[0] = 0;
		r = ambiguous_match(cmds, nr_cmds, cmd);
		if (r < 0) {
			usage();
                        continue;
		}
                handle_cmd(r, arg);
	}
	die(0);
	
	return 0; /* not reached */
}
