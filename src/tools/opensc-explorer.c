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

#define CMD_LS		0
#define CMD_CD		1
#define CMD_DEBUG	2
#define CMD_CAT		3
#define CMD_INFO	4
#define CMD_DELETE	5
#define CMD_VERIFY	6

const char *cmds[] = {
	"ls", "cd", "debug", "cat", "info", "create", "delete",
	"verify", "put", "get"
};

const int nr_cmds = sizeof(cmds)/sizeof(cmds[0]);

void die(int ret)
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

int arg_to_path(const char *arg, struct sc_path *path)
{
	char buf[6];
	
	if (strlen(arg) != 4) {
		printf("Wrong ID length.\n");
		return -1;
	}
	strcpy(buf, "I");
        strcat(buf, arg);
	sc_format_path(buf, path);
	if (path->len != 2)
		return -1;
	return 0;	
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
	if (arg_to_path(arg, &path) != 0) {
		printf("Usage: cd <file_id>\n");
		return -1;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select DF", &current_file);
		return -1;
	}
	if (file.type != SC_FILE_TYPE_DF) {
		printf("Error: file is not a DF.\n");
		r = sc_select_file(card, &current_path, NULL);
		if (r) {
			printf("unable to select parent file: %s\n", sc_strerror(r));
			die(1);
		}
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
		if (arg_to_path(arg, &path) != 0) {
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
		struct sc_path tmppath;
		
		if (arg_to_path(arg, &tmppath) != 0) {
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
		const char *ops[] = {
			"READ", "UPDATE", "WRITE", "ERASE", "REHABILITATE",
			"INVALIDATE"
		};
		printf("%-15s%s\n", "EF structure:", structs[file.ef_structure]);
		for (i = 0; i < sizeof(ops)/sizeof(ops[0]); i++) {
			char buf[80];
			
			sprintf(buf, "ACL for %s:", ops[i]);
			printf("%-25s%s\n", buf, acl_to_str(file.acl[i]));
		}
	}	
	if (file.prop_attr_len) {
		printf("%-25s", "Proprietary attributes:");
		for (i = 0; i < file.prop_attr_len; i++)
			printf("%02X ", file.prop_attr[i]);
		printf("\n");
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

int do_create(const char *arg, const char *arg2)
{
	struct sc_path path;
	struct sc_file file;
	int size;
	int i, r;

	if (arg_to_path(arg, &path) != 0)
		goto usage;
	/* %z isn't supported everywhere */
	if (sscanf(arg2, "%d", &size) != 1)
		goto usage;
	memset(&file, 0, sizeof(file));
	file.id = (path.value[0] << 8) | path.value[1];
	file.type = SC_FILE_TYPE_WORKING_EF;
	file.ef_structure = SC_FILE_EF_TRANSPARENT;
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		file.acl[i] = SC_AC_NONE;
	file.size = (size_t) size;
	file.status = SC_FILE_STATUS_ACTIVATED;
	
	r = sc_create_file(card, &file);
	if (r) {
		check_ret(r, SC_AC_OP_CREATE, "CREATE FILE failed", &current_file);
		return -1;
	}
	/* Make sure we're back in the parent directory, because on some cards
	 * CREATE FILE also selects the newly created file. */
	r = sc_select_file(card, &current_path, NULL);
	if (r) {
		printf("unable to select parent file: %s\n", sc_strerror(r));
		die(1);
	}
	return 0;
usage:
	printf("Usage: create <file_id> <file_size>\n");
	return -1;
}

int do_delete(const char *arg)
{
	struct sc_path path;
	int r;

	if (arg_to_path(arg, &path) != 0)
		goto usage;
	r = sc_delete_file(card, &path);
	if (r) {
		check_ret(r, SC_AC_OP_DELETE, "DELETE FILE failed", &current_file);
		return -1;
	}
	return 0;
usage:
	printf("Usage: delete <file_id>\n");
	return -1;
}

int do_verify(const char *arg, const char *arg2)
{
	const char *types[] = {
		"CHV", "KEY"
	};
	int i, type = -1, ref, r, tries_left = -1;
	u8 buf[30];
	size_t buflen = sizeof(buf);
	
	if (strlen(arg) == 0 || strlen(arg2) == 0)
		goto usage;
	for (i = 0; i < 2; i++)
		if (strncasecmp(arg, types[i], 3) == 0) {
			type = i;
			break;
		}
	if (type == -1) {
		printf("Invalid type.\n");
		goto usage;
	}
	if (sscanf(arg + 3, "%d", &ref) != 1) {
		printf("Invalid key reference.\n");
		goto usage;
	}
	if (sc_hex_to_bin(arg2, buf, &buflen) != 0) {
		printf("Invalid key value.\n");
		goto usage;
	}
	switch (type) {
	case 0:
		type = SC_AC_CHV1;
		break;
	case 1:
		type = SC_AC_AUT;
		break;
	}
	r = sc_verify(card, type, ref, buf, buflen, &tries_left);
	if (r) {
		if (r == SC_ERROR_PIN_CODE_INCORRECT) {
			if (tries_left >= 0) 
				printf("Incorrect code, %d tries left", tries_left);
			else
				printf("Incorrect code.\n");
		}
		printf("Unable to verify PIN code: %s\n", sc_strerror(r));
		return -1;
	}
	printf("Code correct.\n");
	return 0;
usage:
	printf("Usage: verify <key type><key ref> <key in hex>\n");
	printf("Possible values of <key type>:\n");
	for (i = 0; i < sizeof(types)/sizeof(types[0]); i++)
		printf("\t%s\n", types[i]);
	printf("Example: verify CHV2 31:32:33:34:00:00:00:00\n");
	return -1;
}

int do_get(const char *arg, const char *arg2)
{
	u8 buf[256];
	int r, error = 0;
	size_t count = 0;
        unsigned int idx = 0;
	struct sc_path path;
        struct sc_file file;
	const char *filename;
	FILE *outf = NULL;
	
	if (arg_to_path(arg, &path) != 0)
		goto usage;
	if (strlen(arg2))
		filename = arg2;
	else {
		sprintf((char *) buf, "%02X%02X", path.value[0], path.value[1]);
		filename = (char *) buf;
	}
	outf = fopen(filename, "w");
	if (outf == NULL) {
		perror(filename);
		return -1;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", &current_file);
		return -1;
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
		fwrite(buf, c, 1, outf);
		idx += c;
		count -= c;
	}
	printf("Total of %d bytes read.\n", idx);
err:
	r = sc_select_file(card, &current_path, NULL);
	if (r) {
		printf("unable to select parent file: %s\n", sc_strerror(r));
		die(1);
	}
	if (outf)
		fclose(outf);
        return -error;
usage:
	printf("Usage: get <file id> [output file]\n");
	return -1;
}

int do_put(const char *arg, const char *arg2)
{
	u8 buf[256];
	int r, error = 0;
	size_t count = 0;
        unsigned int idx = 0;
	struct sc_path path;
        struct sc_file file;
	const char *filename;
	FILE *outf = NULL;
	
	if (arg_to_path(arg, &path) != 0)
		goto usage;
	if (strlen(arg2))
		filename = arg2;
	else {
		sprintf((char *) buf, "%02X%02X", path.value[0], path.value[1]);
		filename = (char *) buf;
	}
	outf = fopen(filename, "r");
	if (outf == NULL) {
		perror(filename);
		return -1;
	}
	r = sc_select_file(card, &path, &file);
	if (r) {
		check_ret(r, SC_AC_OP_SELECT, "unable to select file", &current_file);
		return -1;
	}
	count = file.size;
	while (count) {
		int c = count > sizeof(buf) ? sizeof(buf) : count;

		r = fread(buf, 1, c, outf);
		if (r < 0) {
			perror("fread");
			error = 1;
			goto err;
		}
		if (r != c)
			count = c = r;
		r = sc_update_binary(card, idx, buf, c, 0);
		if (r < 0) {
			check_ret(r, SC_AC_OP_READ, "update failed", &file);
			error = 1;
                        goto err;
		}
		if (r != c) {
			printf("expecting %d, wrote only %d bytes.\n", c, r);
			error = 1;
                        goto err;
		}
		idx += c;
		count -= c;
	}
	printf("Total of %d bytes written.\n", idx);
err:
	r = sc_select_file(card, &current_path, NULL);
	if (r) {
		printf("unable to select parent file: %s\n", sc_strerror(r));
		die(1);
	}
	if (outf)
		fclose(outf);
        return -error;
usage:
	printf("Usage: put <file id> [output file]\n");
	return -1;
}

int handle_cmd(int cmd, const char *arg, const char *arg2)
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
        case 5:
        	return do_create(arg, arg2);
        case 6:
        	return do_delete(arg);
        case 7:
        	return do_verify(arg, arg2);
        case 8:
        	return do_put(arg, arg2);
        case 9:
        	return do_get(arg, arg2);
        default:
        	printf("Don't know how to handle command.\n");
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
	char line[80], cmd[80], arg[80], arg2[80];

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
		r = sscanf(line, "%s %s %s", cmd, arg, arg2);
		if (r < 1)
			continue;
		if (r < 3)
			arg2[0] = 0;
		if (r < 2)
			arg[0] = 0;
		r = ambiguous_match(cmds, nr_cmds, cmd);
		if (r < 0) {
			usage();
                        continue;
		}
                handle_cmd(r, arg, arg2);
	}
	die(0);
	
	return 0; /* not reached */
}
