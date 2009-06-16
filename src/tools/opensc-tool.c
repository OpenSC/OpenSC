/*
 * opensc-tool.c: Tool for accessing smart cards with libopensc
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <opensc/opensc.h>
#include <opensc/cardctl.h>
#include "util.h"

static const char *app_name = "opensc-tool";

static int	opt_reader = -1,
		opt_wait = 0;
static char **	opt_apdus;
static int	opt_apdu_count = 0;
static int	verbose = 0;

enum {
	OPT_SERIAL = 0x100,
};

static const struct option options[] = {
	{ "info",		0, NULL,		'i' },
	{ "atr",		0, NULL,		'a' },
	{ "serial",		0, NULL,	OPT_SERIAL  },
	{ "name",		0, NULL,		'n' },
	{ "get-conf-entry",	1, NULL,		'G' },
	{ "set-conf-entry",	1, NULL,		'S' },
	{ "list-readers",	0, NULL, 		'l' },
	{ "list-drivers",	0, NULL,		'D' },
	{ "list-rdrivers",	0, NULL,		'R' },
	{ "list-files",		0, NULL,		'f' },
	{ "send-apdu",		1, NULL,		's' },
	{ "reader",		1, NULL,		'r' },
	{ "card-driver",	1, NULL,		'c' },
	{ "wait",		0, NULL,		'w' },
	{ "verbose",		0, NULL,		'v' },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Prints information about OpenSC",
	"Prints the ATR bytes of the card",
	"Prints the card serial number",
	"Identify the card and print its name",
	"Get configuration key, format: section:name:key",
	"Set configuration key, format: section:name:key:value",
	"Lists all configured readers",
	"Lists all installed card drivers",
	"Lists all installed reader drivers",
	"Recursively lists files stored on card",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
	"Uses reader number <arg> [0]",
	"Forces the use of driver <arg> [auto-detect]",
	"Wait for a card to be inserted",
	"Verbose operation. Use several times to enable debug output.",
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;

static int opensc_info(void)
{
	printf (
		"%s %s ",
		PACKAGE_NAME,
		PACKAGE_VERSION
	);

#if defined(__VERSION__)
	printf (
		"[%s %s]\n",
#if defined(__GNUC__)
		"gcc ",
#else
		"unknown ",
#endif
		__VERSION__
	);
#elif defined(_MSC_VER)
	printf ("[Microsoft %d]\n", _MSC_VER);
#else
	printf ("[Unknown compiler, please report]");
#endif
	printf ("Enabled features:%s\n", OPENSC_FEATURES);
	return 0;
}

static int opensc_get_conf_entry(const char *config)
{
	scconf_block *conf_block = NULL, **blocks;
	char *buffer = NULL;
	char *section = NULL;
	char *name = NULL;
	char *key = NULL;
	int r = 0;

	if (ctx->conf == NULL) {
		r = ENOENT;
		goto cleanup;
	}

	if ((buffer = strdup(config)) == NULL) {
		r = ENOMEM;
		goto cleanup;
	}

	section = buffer;
	name = section == NULL ? NULL : strchr(section+1, ':');
	key = name == NULL ? NULL : strchr(name+1, ':');
	if (key == NULL) {
		r = EINVAL;
		goto cleanup;
	}
	*name = '\0';
	name++;
	*key = '\0';
	key++;

	blocks = scconf_find_blocks(ctx->conf, NULL, section, name);
	if (blocks[0])
		conf_block = blocks[0];
	free(blocks);
	if (conf_block != NULL) {
		const char *value = scconf_get_str(conf_block, key, NULL);

		if (value != NULL) {
			printf ("%s\n", value);
		}
	}

	r = 0;

cleanup:

	if (buffer != NULL)
		free(buffer);

	return r;
}

static int opensc_set_conf_entry(const char *config)
{
	scconf_block *conf_block = NULL, **blocks;
	char *buffer = NULL;
	char *section = NULL;
	char *name = NULL;
	char *key = NULL;
	char *value = NULL;
	int r = 0;

	if (ctx->conf == NULL) {
		r = ENOENT;
		goto cleanup;
	}

	if ((buffer = strdup(config)) == NULL) {
		r = ENOMEM;
		goto cleanup;
	}

	section = buffer;
	name = section == NULL ? NULL : strchr(section+1, ':');
	key = name == NULL ? NULL : strchr(name+1, ':');
	value = key == NULL ? NULL : strchr(key+1, ':');
	if (value == NULL) {
		r = EINVAL;
		goto cleanup;
	}
	*name = '\0';
	name++;
	*key = '\0';
	key++;
	*value = '\0';
	value++;

	blocks = scconf_find_blocks(ctx->conf, NULL, section, name);
	if (blocks[0])
		conf_block = blocks[0];
	free(blocks);
	if (conf_block != NULL) {
		scconf_item *item;

		for (item = conf_block->items; item != NULL; item = item->next) {
			scconf_list *list;

			if ((item->type != SCCONF_ITEM_TYPE_VALUE)
			    || (strcmp(item->key, key) != 0))
				continue;
			list = item->value.list;
			scconf_list_destroy(list);
			list = NULL;
			scconf_list_add(&list, value);
			item->value.list = list;
			break;
		}
		if (item == NULL)
			scconf_put_str(conf_block, key, value);
	}

	/* Write */
	if ((r = scconf_write(ctx->conf, ctx->conf->filename)) != 0) {
		fprintf(stderr, "scconf_write(): %s\n", strerror(r));
		goto cleanup;
	}

	r = 0;

cleanup:

	if (buffer != NULL)
		free(buffer);

	return r;
}

static int list_readers(void)
{
	unsigned int i, rcount = sc_ctx_get_reader_count(ctx);
	
	if (rcount == 0) {
		printf("No smart card readers found.\n");
		return 0;
	}
	printf("Readers known about:\n");
	printf("Nr.    Driver     Name\n");
	for (i = 0; i < rcount; i++) {
		sc_reader_t *screader = sc_ctx_get_reader(ctx, i);
		printf("%-7d%-11s%s\n", i, screader->driver->short_name,
		       screader->name);
	}
	return 0;
}

static int list_reader_drivers(void)
{
	int i;
	
	if (ctx->reader_drivers[0] == NULL) {
		printf("No reader drivers installed!\n");
		return 0;
	}
	printf("Configured reader drivers:\n");
	for (i = 0; ctx->reader_drivers[i] != NULL; i++) {
		printf("  %-16s %s\n", ctx->reader_drivers[i]->short_name,
		       ctx->reader_drivers[i]->name);
	}
	return 0;
}

static int list_drivers(void)
{
	int i;
	
	if (ctx->card_drivers[0] == NULL) {
		printf("No card drivers installed!\n");
		return 0;
	}
	printf("Configured card drivers:\n");
	for (i = 0; ctx->card_drivers[i] != NULL; i++) {
		printf("  %-16s %s\n", ctx->card_drivers[i]->short_name,
		       ctx->card_drivers[i]->name);
	}
	return 0;
}

static int print_file(sc_card_t *in_card, const sc_file_t *file,
	const sc_path_t *path, int depth)
{
	int r;
	const char *tmps;
	const char *ac_ops_df[] = {
		"select", "lock", "delete", "create", "rehab", "inval",
		"list"
	};
	const char *ac_ops_ef[] = {
		"read", "update", "erase", "write", "rehab", "inval"
	};
	
	for (r = 0; r < depth; r++)
		printf("  ");
	printf("%s ", sc_print_path(path));
	if (file->namelen) {
		printf("[");
		util_print_binary(stdout, file->name, file->namelen);
		printf("] ");
	}
	switch (file->type) {
	case SC_FILE_TYPE_WORKING_EF:
		tmps = "wEF";
		break;
	case SC_FILE_TYPE_INTERNAL_EF:
		tmps = "iEF";
		break;
	case SC_FILE_TYPE_DF:
		tmps = " DF";
		break;
	default:
		tmps = "unknown";
		break;
	}
	printf("type: %-3s, ", tmps);
	if (file->type != SC_FILE_TYPE_DF) {
		const char *structs[] = {
			"unknown", "transpnt", "linrfix", "linrfix(TLV)",
			"linvar", "linvar(TLV)", "lincyc", "lincyc(TLV)"
		};
		int ef_type = file->ef_structure;
		if (ef_type < 0 || ef_type > 7)
			ef_type = 0;	/* invalid or unknow ef type */
		printf("ef structure: %s, ", structs[ef_type]);
	}
	printf("size: %lu\n", (unsigned long) file->size);
	for (r = 0; r < depth; r++)
		printf("  ");
	if (file->type == SC_FILE_TYPE_DF)
		for (r = 0; r < (int) (sizeof(ac_ops_df)/sizeof(ac_ops_df[0])); r++)
			printf("%s[%s] ", ac_ops_df[r], util_acl_to_str(sc_file_get_acl_entry(file, r)));
	else
		for (r = 0; r < (int) (sizeof(ac_ops_ef)/sizeof(ac_ops_ef[0])); r++)
			printf("%s[%s] ", ac_ops_ef[r], util_acl_to_str(sc_file_get_acl_entry(file, r)));

	if (file->sec_attr_len) {
		printf("sec: ");
		/* Octets are as follows:
		 *   DF: select, lock, delete, create, rehab, inval
		 *   EF: read, update, write, erase, rehab, inval
		 * 4 MSB's of the octet mean:			 
		 *  0 = ALW, 1 = PIN1, 2 = PIN2, 4 = SYS,
		 * 15 = NEV */
		util_hex_dump(stdout, file->sec_attr, file->sec_attr_len, ":");
	}
	if (file->prop_attr_len) {
		printf("\n");
		for (r = 0; r < depth; r++)
			printf("  ");
		printf("prop: ");
		util_hex_dump(stdout, file->prop_attr, file->prop_attr_len, ":");
	}
	printf("\n\n");

	if (file->type == SC_FILE_TYPE_DF)
		return 0;

	if (file->ef_structure == SC_FILE_EF_TRANSPARENT) {
		unsigned char *buf;
		
		if (!(buf = (unsigned char *) malloc(file->size))) {
			fprintf(stderr, "out of memory");
			return 1;
		}

		r = sc_read_binary(in_card, 0, buf, file->size, 0);
		if (r > 0)
			util_hex_dump_asc(stdout, buf, r, 0);
		free(buf);
	} else {
		unsigned char buf[256];
		int i;

		for (i=0; i < file->record_count; i++) {
			printf("Record %d\n", i);
			r = sc_read_record(in_card, i, buf, 256, 0);
			if (r > 0)
				util_hex_dump_asc(stdout, buf, r, 0);
		}
	}
	return 0;
}

static int enum_dir(sc_path_t path, int depth)
{
	sc_file_t *file;
	int r, file_type;
	u8 files[SC_MAX_APDU_BUFFER_SIZE];

	r = sc_select_file(card, &path, &file);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return 1;
	}
	print_file(card, file, &path, depth);
	file_type = file->type;
	sc_file_free(file);
	if (file_type == SC_FILE_TYPE_DF) {
		int i;

		r = sc_list_files(card, files, sizeof(files));
		if (r < 0) {
			fprintf(stderr, "sc_list_files() failed: %s\n", sc_strerror(r));
			return 1;
		}
		if (r == 0) {
			printf("Empty directory\n");
		} else
		for (i = 0; i < r/2; i++) {
			sc_path_t tmppath;

			memcpy(&tmppath, &path, sizeof(path));
			memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
			tmppath.len += 2;
			enum_dir(tmppath, depth + 1);
		}
	}
	return 0;
}	

static int list_files(void)
{
	sc_path_t path;
	int r;
	
	sc_format_path("3F00", &path);
	r = enum_dir(path, 0);
	return r;
}

static int send_apdu(void)
{
	sc_apdu_t apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE], sbuf[SC_MAX_APDU_BUFFER_SIZE],
	   rbuf[SC_MAX_APDU_BUFFER_SIZE], *p;
	size_t len, len0, r;
	int c;

	for (c = 0; c < opt_apdu_count; c++) {
		len0 = sizeof(buf);
		sc_hex_to_bin(opt_apdus[c], buf, &len0);
		if (len0 < 4) {
			fprintf(stderr, "APDU too short (must be at least 4 bytes).\n");
			return 2;
		}
		len = len0;
		p = buf;
		memset(&apdu, 0, sizeof(apdu));
		apdu.cla = *p++;
		apdu.ins = *p++;
		apdu.p1 = *p++;
		apdu.p2 = *p++;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		len -= 4;
		if (len > 1) {
			apdu.lc = *p++;
			len--;
			memcpy(sbuf, p, apdu.lc);
			apdu.data = sbuf;
			apdu.datalen = apdu.lc;
			if (len < apdu.lc) {
				fprintf(stderr, "APDU too short (need %lu bytes).\n",
					(unsigned long) apdu.lc-len);
				return 2;
			}
			len -= apdu.lc;
			p   += apdu.lc;
			if (len) {
				apdu.le = *p++;
				if (apdu.le == 0)
					apdu.le = 256;
				len--;
				apdu.cse = SC_APDU_CASE_4_SHORT;
			} else
				apdu.cse = SC_APDU_CASE_3_SHORT;
			if (len) {
				fprintf(stderr, "APDU too long (%lu bytes extra).\n",
					(unsigned long) len);
				return 2;
			}
		} else if (len == 1) {
			apdu.le = *p++;
			if (apdu.le == 0)
				apdu.le = 256;
			len--;
			apdu.cse = SC_APDU_CASE_2_SHORT;
		} else
			apdu.cse = SC_APDU_CASE_1;
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
	}
	return 0;
}

static void print_serial(sc_card_t *in_card)
{
	int r;
	sc_serial_number_t serial;

	r = sc_card_ctl(in_card, SC_CARDCTL_GET_SERIALNR, &serial);
	if (r)
		fprintf(stderr, "sc_card_ctl(*, SC_CARDCTL_GET_SERIALNR, *) failed\n");
	else
		util_hex_dump_asc(stdout, serial.value, serial.len, -1);
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_info = 0;
	int do_get_conf_entry = 0;
	int do_set_conf_entry = 0;
	int do_list_readers = 0;
	int do_list_drivers = 0;
	int do_list_rdrivers = 0;
	int do_list_files = 0;
	int do_send_apdu = 0;
	int do_print_atr = 0;
	int do_print_serial = 0;
	int do_print_name = 0;
	int action_count = 0;
	const char *opt_driver = NULL;
	const char *opt_conf_entry = NULL;
	sc_context_param_t ctx_param;
		
	setbuf(stderr, NULL);
	setbuf(stdout, NULL);

	while (1) {
		c = getopt_long(argc, argv, "inlG:S:fr:vs:DRc:aw", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help);
		switch (c) {
		case 'i':
			do_info = 1;
			action_count++;
			break;
		case 'G':
			do_get_conf_entry = 1;
			opt_conf_entry = optarg;
			action_count++;
			break;
		case 'S':
			do_set_conf_entry = 1;
			opt_conf_entry = optarg;
			action_count++;
			break;
		case 'l':
			do_list_readers = 1;
			action_count++;
			break;
		case 'D':
			do_list_drivers = 1;
			action_count++;
			break;
		case 'R':
			do_list_rdrivers = 1;
			action_count++;
			break;
		case 'f':
			do_list_files = 1;
			action_count++;
			break;
		case 's':
			opt_apdus = (char **) realloc(opt_apdus,
					(opt_apdu_count + 1) * sizeof(char *));
			opt_apdus[opt_apdu_count] = optarg;
			do_send_apdu++;
			if (opt_apdu_count == 0)
				action_count++;
			opt_apdu_count++;
			break;
		case 'a':
			do_print_atr = 1;
			action_count++;
			break;
		case 'n':
			do_print_name = 1;
			action_count++;
			break;
		case 'r':
			opt_reader = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		case 'c':
			opt_driver = optarg;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_SERIAL:
			do_print_serial = 1;
			action_count++;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help);

	if (do_info) {
		opensc_info();
		action_count--;
	}

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose > 1)
		ctx->debug = verbose-1;
	if (do_get_conf_entry) {
		if ((err = opensc_get_conf_entry (opt_conf_entry)))
			goto end;
		action_count--;
	}
	if (do_set_conf_entry) {
		if ((err = opensc_set_conf_entry (opt_conf_entry)))
			goto end;
		action_count--;
	}
	if (do_list_rdrivers) {
		if ((err = list_reader_drivers()))
			goto end;
		action_count--;
	}
	if (do_list_readers) {
		if ((err = list_readers()))
			goto end;
		action_count--;
	}
	if (do_list_drivers) {
		if ((err = list_drivers()))
			goto end;
		action_count--;
	}
	if (action_count <= 0)
		goto end;

	if (opt_driver != NULL) {
		err = sc_set_card_driver(ctx, opt_driver);
		if (err) {
			fprintf(stderr, "Driver '%s' not found!\n", opt_driver);
			err = 1;
			goto end;
		}
	}

	err = util_connect_card(ctx, &card, opt_reader, 0, opt_wait, verbose);
	if (err)
		goto end;

	if (do_print_atr) {
		if (verbose) {
			printf("Card ATR:\n");
			util_hex_dump_asc(stdout, card->atr, card->atr_len, -1);		
		} else {
			char tmp[SC_MAX_ATR_SIZE*3];
			sc_bin_to_hex(card->atr, card->atr_len, tmp, sizeof(tmp) - 1, ':');
			fprintf(stdout,"%s\n",tmp);
		}
		action_count--;
	}
	if (do_print_serial) {
		if (verbose)
			printf("Card serial number:");
		print_serial(card);
		action_count--;
	}
	if (do_print_name) {
		if (verbose)
			printf("Card name: ");
		printf("%s\n", card->name);
		action_count--;
	}
	if (do_send_apdu) {
		if ((err = send_apdu()))
			goto end;
		action_count--;
	}
	
	if (do_list_files) {
		if ((err = list_files()))
			goto end;
		action_count--;
	}
end:
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
