/*
 * pkcs15-tool.c: Tool for poking with PKCS #15 smartcards
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

#include "util.h"
#include <opensc-pkcs15.h>

int opt_reader = 0, opt_debug = 0;
int opt_no_cache = 0;
char * opt_pin_id;
char * opt_cert = NULL;
char * opt_outfile = NULL;
char * opt_newpin = NULL;

int quiet = 0;

#define OPT_CHANGE_PIN	0x100
#define OPT_LIST_PINS	0x101
#define OPT_READER	0x102
#define OPT_PIN_ID	0x103
#define OPT_NO_CACHE	0x104

const struct option options[] = {
	{ "learn-card",		0, 0, 		'L' },
	{ "read-certificate",	1, 0, 		'r' },
	{ "list-certificates",	0, 0,		'c' },
	{ "list-pins",		0, 0,		OPT_LIST_PINS },
	{ "change-pin",		0, 0,		OPT_CHANGE_PIN },
	{ "list-keys",          0, 0,           'k' },
	{ "reader",		1, 0,		OPT_READER },
	{ "output",		1, 0,		'o' },
	{ "quiet",		0, 0,		'q' },
	{ "debug",		0, 0,		'd' },
	{ "no-cache",		0, 0,		OPT_NO_CACHE },
	{ "pin-id",		1, 0,		'p' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Stores card info to cache",
	"Reads certificate with ID <arg>",
	"Lists certificates",
	"Lists PIN codes",
	"Changes the PIN code",
	"Lists private keys",
	"Uses reader number <arg>",
	"Outputs to file <arg>",
	"Quiet operation",
	"Debug output -- may be supplied several times",
	"Disable card caching",
	"The auth ID of the PIN to use",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

int list_certificates(void)
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

int read_certificate(void)
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

int list_private_keys(void)
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

u8 * get_pin(const char *prompt, struct sc_pkcs15_pin_info **pin_out)
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
		return (u8 *) strdup(pincode);
	}
}

int list_pins(void)
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

int change_pin(void)
{
	struct sc_pkcs15_pin_info *pinfo = NULL;
	u8 *pincode, *newpin;
	int r;
	
	pincode = get_pin("Enter old PIN", &pinfo);
	if (pincode == NULL)
		return 2;
	if (strlen((char *) pincode) == 0) {
		fprintf(stderr, "No PIN code supplied.\n");
		return 2;
	}
	while (1) {
		u8 *newpin2;

		newpin = get_pin("Enter new PIN", &pinfo);
		if (newpin == NULL || strlen((char *) newpin) == 0)
			return 2;
		newpin2 = get_pin("Enter new PIN again", &pinfo);
		if (newpin2 == NULL || strlen((char *) newpin2) == 0)
			return 2;
		if (strcmp((char *) newpin, (char *) newpin2) == 0) {
			free(newpin2);
			break;
		}
		printf("PIN codes do not match, try again.\n");
		free(newpin);
		free(newpin2);
	}
	r = sc_pkcs15_change_pin(p15card, pinfo, pincode, strlen((char *) pincode),
				 newpin, strlen((char *) newpin));
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

static int generate_cert_filename(struct sc_pkcs15_card *p15card,
				  const struct sc_pkcs15_cert_info *info,
				  char *fname, int len)
{
	char *homedir;
	char cert_id[SC_PKCS15_MAX_ID_SIZE*2+1];
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

int learn_card(void)
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
	p15card->use_cache = 0;
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

int main(int argc, char * const argv[])
{
	int err = 0, r, c, long_optind = 0;
	int do_read_cert = 0;
	int do_list_certs = 0;
	int do_list_pins = 0;
	int do_list_prkeys = 0;
	int do_change_pin = 0;
	int do_learn_card = 0;
	int action_count = 0;

	while (1) {
		c = getopt_long(argc, argv, "r:cko:qdp:L", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			print_usage_and_die("pkcs15-tool");
		switch (c) {
		case 'r':
			opt_cert = optarg;
			do_read_cert = 1;
			action_count++;
			break;
		case 'c':
			do_list_certs = 1;
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
			opt_debug++;
			break;
		case 'p':
			opt_pin_id = optarg;
			break;
		case OPT_NO_CACHE:
			opt_no_cache++;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die("pkcs15-tool");
	r = sc_establish_context(&ctx);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	ctx->use_std_output = 1;
	ctx->debug = opt_debug;
	if (opt_no_cache)
		ctx->use_cache = 0;
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
	printf("Using card driver: %s\n", card->driver->name);
	r = sc_lock(card);
	if (r) {
		fprintf(stderr, "Unable to lock card: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Trying to find a PKCS#15 compatible card...\n");
	r = sc_pkcs15_bind(card, &p15card);
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
		sc_pkcs15_unbind(p15card);
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	if (ctx)
		sc_destroy_context(ctx);
	return err;
}
