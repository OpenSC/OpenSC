/*
 * sc-tool.c: Tool for accessing SmartCards with libsc
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

#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <opensc.h>
#include <opensc-pkcs15.h>
#include <sys/stat.h>

#define OPT_CHANGE_PIN	0x100
#define OPT_LIST_PINS	0x101
#define OPT_READER	0x102
#define OPT_PIN_ID	0x103

int opt_reader = 0;
char * opt_pin_id;
char * opt_cert = NULL;
char * opt_outfile = NULL;
char * opt_newpin = NULL;
char * opt_apdu = NULL;
int quiet = 0;

const struct option options[] = {
	{ "list-readers",	0, 0, 		'l' },
	{ "list-files",		0, 0,		'f' },
	{ "learn-card",		0, 0, 		'L' },
	{ "send-apdu",		1, 0,		's' },
	{ "read-certificate",	1, 0, 		'r' },
	{ "list-certificates",	0, 0,		'c' },
	{ "list-pins",		0, 0,		OPT_LIST_PINS },
	{ "change-pin",		0, 0,		OPT_CHANGE_PIN },
	{ "list-private-keys",	0, 0,		'k' },
	{ "reader",		1, 0,		OPT_READER },
	{ "output",		1, 0,		'o' },
	{ "quiet",		0, 0,		'q' },
	{ "debug",		0, 0,		'd' },
	{ "pin-id",		1, 0,		'p' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Lists all configured readers",
	"Recursively lists files stored on card",
	"Stores card info to cache [P15]",
	"Sends an APDU in format AA:BB:CC:DD:EE:FF...",
	"Reads certificate with ID <arg> [P15]",
	"Lists certificates [P15]",
	"Lists PIN codes [P15]",
	"Changes the PIN code [P15]",
	"Lists private keys [P15]",
	"Uses reader number <arg>",
	"Outputs to file <arg>",
	"Quiet operation",
	"Debug output -- may be supplied several times",
	"The auth ID of the PIN to use [P15]",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

void print_usage_and_die()
{
	int i = 0;
	printf("Usage: sc-tool [OPTIONS]\nOptions:\n");

	while (options[i].name) {
		char buf[40], tmp[5];
		const char *arg_str;
		
		if (options[i].val > 0 && options[i].val < 128)
			sprintf(tmp, ", -%c", options[i].val);
		else
			tmp[0] = 0;
		switch (options[i].has_arg) {
		case 1:
			arg_str = " <arg>";
			break;
		case 2:
			arg_str = " [arg]";
			break;
		default:
			arg_str = "";
			break;
		}
		sprintf(buf, "--%s%s%s", options[i].name, tmp, arg_str);
		printf("  %-30s%s\n", buf, option_help[i]);
		i++;
	}
	exit(2);
}

int list_readers()
{
	int i;
	
	printf("Configured readers:\n");
	for (i = 0; i < ctx->reader_count; i++) {
		printf("\t%d - %s\n", i, ctx->readers[i]);
	}
	return 0;
}

int list_certificates()
{
	int r, i;
	
	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d certificate(s).\n\n", p15card->cert_count);
	for (i = 0; i < p15card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[i];
		sc_pkcs15_print_cert_info(cinfo);
		printf("\n");
	}
	return 0;
}

int print_pem_certificate(struct sc_pkcs15_cert *cert)
{
	int r;
	u8 buf[2048];
	FILE *outf;
	
	r = sc_base64_encode(cert->data, cert->data_len, buf,
			     sizeof(buf), 64);
	if (r) {
		fprintf(stderr, "Base64 encoding failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (opt_outfile != NULL) {
		outf = fopen(opt_outfile, "w");
		if (outf == NULL) {
			fprintf(stderr, "Error opening file '%s': %s\n",
				opt_outfile, strerror(errno));
			return 2;
		}
	} else
		outf = stdout;
	fprintf(outf, "-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n",
		buf);
	if (outf != stdout)
		fclose(outf);
	return 0;
}

int read_certificate()
{
	int r, i;
	struct sc_pkcs15_id id;

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_cert, &id);

	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	
	for (i = 0; i < p15card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[i];
		struct sc_pkcs15_cert *cert;

		if (sc_pkcs15_compare_id(&id, &cinfo->id) != 1)
			continue;
			
		if (!quiet)
			printf("Reading certificate with ID '%s'\n", opt_cert);
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r) {
			fprintf(stderr, "Certificate read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = print_pem_certificate(cert);
		sc_pkcs15_free_certificate(cert);
		return r;
	}
	fprintf(stderr, "Certificate with ID '%s' not found.\n", opt_cert);
	return 2;
}

int list_private_keys()
{
	int r, i;
	
	r = sc_pkcs15_enum_private_keys(p15card);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d private key(s).\n\n", p15card->prkey_count);
	for (i = 0; i < p15card->prkey_count; i++) {
		struct sc_pkcs15_prkey_info *pinfo = &p15card->prkey_info[i];
		sc_pkcs15_print_prkey_info(pinfo);
		printf("\n");
	}
	return 0;
}

char * get_pin(const char *prompt, struct sc_pkcs15_pin_info **pin_out)
{
	int r;
	char buf[80];
	char *pincode;
	struct sc_pkcs15_pin_info *pinfo;
	
	if (pin_out != NULL)
		pinfo = *pin_out;
		
	if (pinfo == NULL && opt_pin_id == NULL) {
		r = sc_pkcs15_enum_pins(p15card);
		if (r < 0) {
			fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
			return NULL;
		}
		if (r == 0) {
			fprintf(stderr, "No PIN codes found.\n");
			return NULL;
		}
		pinfo = &p15card->pin_info[0];
	} else if (pinfo == NULL) {
		struct sc_pkcs15_id pin_id;
		
		sc_pkcs15_hex_string_to_id(opt_pin_id, &pin_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &pin_id, &pinfo);
		if (r) {
			fprintf(stderr, "Unable to find PIN code: %s\n", sc_strerror(r));
			return NULL;
		}
	}
	
	if (pin_out != NULL)
		*pin_out = pinfo;
		
	sprintf(buf, "%s [%s]: ", prompt, pinfo->com_attr.label);
	while (1) {
		pincode = getpass(buf);
		if (strlen(pincode) == 0)
			return NULL;
		if (strlen(pincode) < pinfo->min_length) {
			printf("PIN code too short, try again.\n");
			continue;
		}
		if (strlen(pincode) > pinfo->stored_length) {
			printf("PIN code too long, try again.\n");
			continue;
		}
		return strdup(pincode);
	}
}

int list_pins()
{
	int r, i;

	r = sc_pkcs15_enum_pins(p15card);
	if (r < 0) {
		fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d PIN code(s).\n\n", p15card->pin_count);
	for (i = 0; i < p15card->pin_count; i++) {
		struct sc_pkcs15_pin_info *pinfo = &p15card->pin_info[i];
		sc_pkcs15_print_pin_info(pinfo);
		printf("\n");
	}
	return 0;
}

int change_pin()
{
	char *pincode;
	char *newpin;
	struct sc_pkcs15_pin_info *pinfo = NULL;
	int r;
	
	pincode = get_pin("Enter old PIN", &pinfo);
	if (pincode == NULL)
		return 2;
	if (strlen(pincode) == 0) {
		fprintf(stderr, "No PIN code supplied.\n");
		return 2;
	}
	while (1) {
		char *newpin2;
		
		newpin = get_pin("Enter new PIN", &pinfo);
		if (newpin == NULL || strlen(newpin) == 0)
			return 2;
		newpin2 = get_pin("Enter new PIN again", &pinfo);
		if (newpin2 == NULL || strlen(newpin2) == 0)
			return 2;
		if (strcmp(newpin, newpin2) == 0) {
			free(newpin2);
			break;
		}
		printf("PIN codes do not match, try again.\n");
		free(newpin);
		free(newpin2);
	}
	r = sc_pkcs15_change_pin(p15card, pinfo, pincode, strlen(pincode),
				 newpin, strlen(newpin));
	if (r == SC_ERROR_PIN_CODE_INCORRECT) {
		fprintf(stderr, "PIN code incorrect; tries left: %d\n", pinfo->tries_left);
		return 3;
	} else if (r) {
		fprintf(stderr, "PIN code change failed: %s\n", sc_strerror(r));
		return 2;
	}
	if (!quiet)
		printf("PIN code changed successfully.\n");
	return 0;
}

int enum_dir(struct sc_path path, int depth)
{
	struct sc_file file;
	int r;
	u8 files[MAX_BUFFER_SIZE];
	u8 buf[2048];
	const char *tmps;

	r = sc_select_file(card, &file, &path, SC_SELECT_FILE_BY_PATH);
	if (r) {
		fprintf(stderr, "SELECT FILE failed: %s\n", sc_strerror(r));
		return 1;
	}
	for (r = 0; r < depth; r++) {
		printf("  ");
	}
	for (r = 0; r < path.len; r++) {
		printf("%02X", path.value[r]);
		if (r && (r & 1) == 1)
			printf(" ");
	}
	if (sc_file_valid(&file)) {
		if (file.namelen) {
			printf("[");
			sc_print_binary(stdout, file.name, file.namelen);
			printf("] ");
		}
		switch (file.type) {
		case 0:
			tmps = "wEF";
			break;
		case 1:
			tmps = "iEF";
			break;
		case 7:
			tmps = "DF";
			break;
		default:
			tmps = "unknown";
			break;
		}	
		printf("type: %-3s ", tmps);
		if (file.type != 7)
			printf("ef structure: %d ", file.ef_structure);
		printf("size: %d ", file.size);
		if (file.type == 0 && 0) {
			r = sc_read_binary(card, 0, buf, file.size);
			if (r > 0)
				sc_hex_dump(buf, r);
		}
		if (file.sec_attr_len) {
			printf("sec: ");
			/* Octets are as follows:
			 *   DF: select, lock, delete, create, rehab, inval
			 *   EF: read, update, write, erase, rehab, inval
			 * 4 MSB's of the octet mean:			 
			 *  0 = ALW, 1 = PIN1, 2 = PIN2, 4 = SYS,
			 * 15 = NEV */
			sc_hex_dump(file.sec_attr, file.sec_attr_len);
		} else {
			printf("\n");
		}
	} else {
		printf("\n");
	}
	if (!sc_file_valid(&file) || file.type == 7) {
		int i;

		r = sc_list_files(card, files, sizeof(files));
		if (r <= 0) {
			fprintf(stderr, "sc_list_files() failed: %s\n", sc_strerror(r));
			return 1;
		}
		for (i = 0; i < r/2; i++) {
			struct sc_path tmppath;

			memcpy(&tmppath, &path, sizeof(path));
			memcpy(tmppath.value + tmppath.len, files + 2*i, 2);
			tmppath.len += 2;
			enum_dir(tmppath, depth + 1);
		}
	}
	return 0;
}	

int list_files()
{
	struct sc_path path;
	int r;
	
	memcpy(path.value, "\x3F\x00", 2);
	path.len = 2;
	r = enum_dir(path, 0);
	return r;
}

static int generate_cert_filename(struct sc_pkcs15_card *p15card,
				  const struct sc_pkcs15_cert_info *info,
				  char *fname, int len)
{
	char *homedir;
	u8 cert_id[SC_PKCS15_MAX_ID_SIZE*2+1];
	int i, r;

	homedir = getenv("HOME");
	if (homedir == NULL)
		return -1;
	cert_id[0] = 0;
	for (i = 0; i < info->id.len; i++) {
		char tmp[3];

		sprintf(tmp, "%02X", info->id.value[i]);
		strcat(cert_id, tmp);
	}
	r = snprintf(fname, len, "%s/%s/%s_%s_%s.crt", homedir,
		     SC_PKCS15_CACHE_DIR, p15card->label,
		     p15card->serial_number, cert_id);
	if (r < 0)
		return -1;
	return 0;
}

int learn_card()
{
	struct stat stbuf;
	char fname[512], *home;
	int r, i;
	
	home = getenv("HOME");
	if (home == NULL) {
		fprintf(stderr, "No $HOME environment variable set.\n");
		return 1;
	}
	sprintf(fname, "%s/%s", home, SC_PKCS15_CACHE_DIR);
	r = stat(fname, &stbuf);
	if (r) {
		printf("No '%s' directory found, creating...\n", fname);
		r = mkdir(fname, 0700);
		if (r) {
			perror("Directory creation failed");
			return 1;
		}
	}
	printf("Using cache directory '%s'.\n", fname);
	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	printf("Caching %d certificate(s)...\n", r);
	for (i = 0; i < p15card->cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[i];
		struct sc_pkcs15_cert *cert;
		FILE *crtf;
		
		printf("Reading certificate: %s...\n", cinfo->com_attr.label);
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r) {
			fprintf(stderr, "Certificate read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = generate_cert_filename(p15card, cinfo, fname, sizeof(fname));
		if (r)
			return 1;
		crtf = fopen(fname, "w");
		if (crtf == NULL) {
			perror(fname);
			return 1;
		}
		fwrite(cert->data, cert->data_len, 1, crtf);
		fclose(crtf);

		sc_pkcs15_free_certificate(cert);
	}

	return 0;
}

int send_apdu()
{
	struct sc_apdu apdu;
	u8 buf[MAX_BUFFER_SIZE], sbuf[MAX_BUFFER_SIZE],
	   rbuf[MAX_BUFFER_SIZE], *p = buf;
	int len = sizeof(buf), r;
	
	sc_hex_to_bin(opt_apdu, buf, &len);
	if (len < 5) {
		fprintf(stderr, "APDU too short (must be at least 5 bytes).\n");
		return 2;
	}
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
		len -= apdu.lc;
		if (len) {
			apdu.le = *p++;
			len--;
			apdu.cse = SC_APDU_CASE_4_SHORT;
		} else
			apdu.cse = SC_APDU_CASE_3_SHORT;
		if (len) {
			fprintf(stderr, "APDU too long (%d bytes extra).\n", len);
			return 2;
		}
	} else if (len == 1) {
		apdu.le = *p++;
		len--;
		apdu.cse = SC_APDU_CASE_2_SHORT;
	} else
		apdu.cse = SC_APDU_CASE_1;
	
	sc_debug = 3;
	r = sc_transmit_apdu(card, &apdu);
	sc_debug = 0;
	if (r) {
		fprintf(stderr, "APDU transmit failed: %s\n", sc_strerror(r));
		return 1;
	}
	
	return 0;
}

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_list_readers = 0;
	int do_read_cert = 0;
	int do_list_certs = 0;
	int do_list_pins = 0;
	int do_list_files = 0;
	int do_list_prkeys = 0;
	int do_change_pin = 0;
	int do_send_apdu = 0;
	int do_learn_card = 0;
	int action_count = 0;
		
	while (1) {
		c = getopt_long(argc, argv, "lfr:kco:qdp:s:L", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			print_usage_and_die();
		switch (c) {
		case 'r':
			opt_cert = optarg;
			do_read_cert = 1;
			action_count++;
			break;
		case 'l':
			do_list_readers = 1;
			action_count++;
			break;
		case 'f':
			do_list_files = 1;
			action_count++;
			break;
		case 'c':
			do_list_certs = 1;
			action_count++;
			break;
		case 's':
			opt_apdu = optarg;
			do_send_apdu++;
			action_count++;
			break;
		case OPT_CHANGE_PIN:
			do_change_pin = 1;
			action_count++;
			break;
		case OPT_LIST_PINS:
			do_list_pins = 1;
			action_count++;
			break;
		case 'k':
			do_list_prkeys = 1;
			action_count++;
			break;
		case 'L':
			do_learn_card = 1;
			action_count++;
			break;
		case OPT_READER:
			opt_reader = atoi(optarg);
			break;
		case 'o':
			opt_outfile = optarg;
			break;
		case 'q':
			quiet++;
			break;
		case 'd':
			sc_debug++;
			break;
		case 'p':
			opt_pin_id = optarg;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die();
	r = sc_establish_context(&ctx);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (do_list_readers) {
		if ((err = list_readers()))
			goto end;
		action_count--;
	}
	if (action_count <= 0)
		goto end;
	if (opt_reader >= ctx->reader_count || opt_reader < 0) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		err = 1;
		goto end;
	}
	if (sc_detect_card(ctx, opt_reader) != 1) {
		fprintf(stderr, "Card not present.\n");
		return 3;
	}
	if (!quiet)
		fprintf(stderr, "Connecting to card in reader %s...\n", ctx->readers[opt_reader]);
	r = sc_connect_card(ctx, opt_reader, &card);
	if (r) {
		fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}

	sc_lock(card);
	
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
	
	if (action_count <= 0)
		goto end;
	if (!quiet)
		fprintf(stderr, "Trying to find a PKCS#15 compatible card...\n");
	r = sc_pkcs15_init(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS#15 initialization failed: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Found %s!\n", p15card->label);
	if (do_learn_card) {
		if ((err = learn_card()))
			goto end;
		action_count--;
	}
	if (do_list_certs) {
		if ((err = list_certificates()))
			goto end;
		action_count--;
	}
	if (do_read_cert) {
		if ((err = read_certificate()))
			goto end;
		action_count--;
	}
	if (do_list_prkeys) {
		if ((err = list_private_keys()))
			goto end;
		action_count--;
	}
	if (do_list_pins) {
		if ((err = list_pins()))
			goto end;
		action_count--;
	}
	if (do_change_pin) {
		if ((err = change_pin()))
			goto end;
		action_count--;
	}
end:
	if (p15card)
		sc_pkcs15_destroy(p15card);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_destroy_context(ctx);
	return err;
}
