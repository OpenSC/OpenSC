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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "util.h"
#include <opensc-pkcs15.h>

const char *app_name = "pkcs15-tool";

int opt_reader = 0, opt_debug = 0;
int opt_no_cache = 0;
char * opt_pin_id;
char * opt_cert = NULL;
char * opt_pubkey = NULL;
char * opt_outfile = NULL;
char * opt_newpin = NULL;

int quiet = 0;

#define OPT_CHANGE_PIN	0x100
#define OPT_LIST_PINS	0x101
#define OPT_READER	0x102
#define OPT_PIN_ID	0x103
#define OPT_NO_CACHE	0x104
#define OPT_LIST_PUB	0x105
#define OPT_READ_PUB	0x106

#define PEM_RSA_KEY_PREFIX \
	"\x30\x12\x30\x0D\x06\x09" \
	"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" \
	"\x05\x00\x03\x00\x00"
#define PEM_RSA_KEY_PREFIX_SIZE 20

const struct option options[] = {
	{ "learn-card",		0, 0, 		'L' },
	{ "read-certificate",	1, 0, 		'r' },
	{ "list-certificates",	0, 0,		'c' },
	{ "list-pins",		0, 0,		OPT_LIST_PINS },
	{ "change-pin",		0, 0,		OPT_CHANGE_PIN },
	{ "list-keys",          0, 0,           'k' },
	{ "list-public-keys",	0, 0,		OPT_LIST_PUB },
	{ "read-public-key",	1, 0,		OPT_READ_PUB },
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
	"Lists public keys",
	"Reads public key with ID <arg>",
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

void print_cert_info(const struct sc_pkcs15_object *obj)
{
	int i;
        struct sc_pkcs15_cert_info *cert = (struct sc_pkcs15_cert_info *) obj->data;

	printf("X.509 Certificate [%s]\n", obj->label);
	printf("\tFlags    : %d\n", obj->flags);
	printf("\tAuthority: %s\n", cert->authority ? "yes" : "no");
	printf("\tPath     : ");
	for (i = 0; i < cert->path.len; i++)
		printf("%02X", cert->path.value[i]);
	printf("\n");
	printf("\tID       : ");
	sc_pkcs15_print_id(&cert->id);
	printf("\n");
}


int list_certificates(void)
{
	int r, i;
        struct sc_pkcs15_object *objs[32];
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d certificate(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_cert_info(objs[i]);
		printf("\n");
	}
	return 0;
}

int
print_pem_object(const char *kind, const u8*data, size_t data_len)
{
	int r;
	u8 buf[2048];
	FILE *outf;
	
	r = sc_base64_encode(data, data_len, buf, sizeof(buf), 64);
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
	fprintf(outf,
		"-----BEGIN %s-----\n"
		"%s"
		"-----END %s-----\n",
		kind, buf, kind);
	if (outf != stdout)
		fclose(outf);
	return 0;
}

int read_certificate(void)
{
	int r, i, count;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *objs[32];

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_cert, &id);
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_cert_info *cinfo = objs[i]->data;
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
		r = print_pem_object("CERTIFICATE", cert->data, cert->data_len);
		sc_pkcs15_free_certificate(cert);
		return r;
	}
	fprintf(stderr, "Certificate with ID '%s' not found.\n", opt_cert);
	return 2;
}

void print_prkey_info(const struct sc_pkcs15_object *obj)
{
	int i;
        struct sc_pkcs15_prkey_info *prkey = (struct sc_pkcs15_prkey_info *) obj->data;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages)/sizeof(usages[0]);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags)/sizeof(access_flags[0]);

	printf("Private RSA Key [%s]\n", obj->label);
	printf("\tCom. Flags  : %X\n", obj->flags);
	printf("\tUsage       : [0x%X]", prkey->usage);
        for (i = 0; i < usage_count; i++)
                if (prkey->usage & (1 << i)) {
                        printf(", %s", usages[i]);
                }
	printf("\n");
	printf("\tAccess Flags: [0x%X]", prkey->access_flags);
        for (i = 0; i < af_count; i++)
                if (prkey->access_flags & (1 << i)) {
                        printf(", %s", access_flags[i]);   
                }
        printf("\n");
	printf("\tModLength   : %d\n", prkey->modulus_length);
	printf("\tKey ref     : %d\n", prkey->key_reference);
	printf("\tNative      : %s\n", prkey->native ? "yes" : "no");
	printf("\tPath        : ");
	for (i = 0; i < prkey->path.len; i++)
		printf("%02X", prkey->path.value[i]);
	printf("\n");
	printf("\tAuth ID     : ");
	sc_pkcs15_print_id(&obj->auth_id);
	printf("\n");
	printf("\tID          : ");
	sc_pkcs15_print_id(&prkey->id);
	printf("\n");
}


int list_private_keys(void)
{
	int r, i;
        struct sc_pkcs15_object *objs[32];
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d private key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_prkey_info(objs[i]);
		printf("\n");
	}
	return 0;
}

void print_pubkey_info(const struct sc_pkcs15_object *obj)
{
	int i;
        const struct sc_pkcs15_pubkey_info *pubkey = (const struct sc_pkcs15_pubkey_info *) obj->data;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const int usage_count = sizeof(usages)/sizeof(usages[0]);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const int af_count = sizeof(access_flags)/sizeof(access_flags[0]);

	printf("Public RSA Key [%s]\n", obj->label);
	printf("\tCom. Flags  : %X\n", obj->flags);
	printf("\tUsage       : [0x%X]", pubkey->usage);
        for (i = 0; i < usage_count; i++)
                if (pubkey->usage & (1 << i)) {
                        printf(", %s", usages[i]);
                }
	printf("\n");
	printf("\tAccess Flags: [0x%X]", pubkey->access_flags);
        for (i = 0; i < af_count; i++)
                if (pubkey->access_flags & (1 << i)) {
                        printf(", %s", access_flags[i]);   
                }
        printf("\n");
	printf("\tModLength   : %d\n", pubkey->modulus_length);
	printf("\tKey ref     : %d\n", pubkey->key_reference);
	printf("\tNative      : %s\n", pubkey->native ? "yes" : "no");
	printf("\tPath        : ");
	for (i = 0; i < pubkey->path.len; i++)
		printf("%02X", pubkey->path.value[i]);
	printf("\n");
	printf("\tAuth ID     : ");
	sc_pkcs15_print_id(&obj->auth_id);
	printf("\n");
	printf("\tID          : ");
	sc_pkcs15_print_id(&pubkey->id);
	printf("\n");
}

int list_public_keys(void)
{
	int r, i;
        struct sc_pkcs15_object *objs[32];
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY_RSA, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d public key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_pubkey_info(objs[i]);
		printf("\n");
	}
	return 0;
}

int read_public_key(void)
{
	int r, i, count;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *objs[32];

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_pubkey, &id);

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY_RSA, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_pubkey_info *info = objs[i]->data;
		struct sc_pkcs15_pubkey_rsa *key;
		u8 buffer[512];

		if (sc_pkcs15_compare_id(&id, &info->id) != 1)
			continue;
			
		if (!quiet)
			printf("Reading public key with ID '%s'\n", opt_pubkey);
		r = sc_pkcs15_read_pubkey(p15card, info, &key);
		if (r) {
			fprintf(stderr, "Public key read failed: %s\n", sc_strerror(r));
			return 1;
		}
		memcpy(buffer, PEM_RSA_KEY_PREFIX, PEM_RSA_KEY_PREFIX_SIZE);
		buffer[1] += key->data_len;
		buffer[PEM_RSA_KEY_PREFIX_SIZE-2] = key->data_len + 1;
		memcpy(buffer + PEM_RSA_KEY_PREFIX_SIZE,
				key->data, key->data_len);
		r = print_pem_object("PUBLIC KEY", buffer,
				PEM_RSA_KEY_PREFIX_SIZE + key->data_len);
		sc_pkcs15_free_pubkey(key);
		return r;
	}
	fprintf(stderr, "Public key with ID '%s' not found.\n", opt_pubkey);
	return 2;
}



u8 * get_pin(const char *prompt, struct sc_pkcs15_pin_info **pin_out)
{
	int r;
	char buf[80];
	char *pincode;
        struct sc_pkcs15_object *objs[32], *obj;
	struct sc_pkcs15_pin_info *pinfo = NULL;
	
	if (pin_out != NULL)
		pinfo = *pin_out;

	if (pinfo == NULL && opt_pin_id == NULL) {
                r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
		if (r < 0) {
			fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
			return NULL;
		}
		if (r == 0) {
			fprintf(stderr, "No PIN codes found.\n");
			return NULL;
		}
                obj = objs[0];
		pinfo = obj->data;
	} else if (pinfo == NULL) {
		struct sc_pkcs15_id pin_id;
		
		sc_pkcs15_hex_string_to_id(opt_pin_id, &pin_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &pin_id, &obj);
		if (r) {
			fprintf(stderr, "Unable to find PIN code: %s\n", sc_strerror(r));
			return NULL;
		}
		pinfo = obj->data;
	}
	
	if (pin_out != NULL)
		*pin_out = pinfo;

	sprintf(buf, "%s [%s]: ", prompt, obj->label);
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

void print_pin_info(const struct sc_pkcs15_object *obj)
{
	const char *pin_flags[] = {
		"case-sensitive", "local", "change-disabled",
		"unblock-disabled", "initialized", "needs-padding",
		"unblockingPin", "soPin", "disable_allowed",
		"integrity-protected", "confidentiality-protected",
		"exchangeRefData"
	};
        const struct sc_pkcs15_pin_info *pin = (const struct sc_pkcs15_pin_info *) obj->data;
	const int pf_count = sizeof(pin_flags)/sizeof(pin_flags[0]);
	char path[SC_MAX_PATH_SIZE * 2 + 1];
	int i;
	char *p;

	p = path;
	*p = 0;
	for (i = 0; i < pin->path.len; i++) {
		sprintf(p, "%02X", pin->path.value[i]);
		p += 2;
	}
	printf("PIN [%s]\n", obj->label);
	printf("\tCom. Flags: 0x%X\n", obj->flags);
	printf("\tAuth ID   : ");
	sc_pkcs15_print_id(&pin->auth_id);
	printf("\n");
	printf("\tFlags     : [0x%02X]", pin->flags);
	for (i = 0; i < pf_count; i++)
		if (pin->flags & (1 << i)) {
			printf(", %s", pin_flags[i]);
		}
	printf("\n");
	printf("\tLength    : %d..%d\n", pin->min_length, pin->stored_length);
	printf("\tPad char  : 0x%02X\n", pin->pad_char);
	printf("\tReference : %d\n", pin->reference);
	printf("\tType      : %d\n", pin->type);
	printf("\tPath      : %s\n", path);
}

int list_pins(void)
{
	int r, i;
        struct sc_pkcs15_object *objs[32];
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!quiet)
		printf("Card has %d PIN code(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_pin_info(objs[i]);
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

int read_and_cache_file(const struct sc_path *path)
{
	struct sc_file *tmpfile;
	const struct sc_acl_entry *e;
	u8 buf[16384];
	int r;

	if (!quiet) {
		printf("Reading file ");
		hex_dump(stdout, path->value, path->len, "");
		printf("...\n");
	}
	r = sc_select_file(card, path, &tmpfile);
	if (r != 0) {
		fprintf(stderr, "sc_select_file() failed: %s\n", sc_strerror(r));
		return -1;
	}
	e = sc_file_get_acl_entry(tmpfile, SC_AC_OP_READ);
	if (e != NULL && e->method != SC_AC_NONE) {
		if (!quiet)
			printf("Skipping; ACL for read operation is not NONE.\n");
		return -1;
	}
	r = sc_read_binary(card, 0, buf, tmpfile->size, 0);
	if (r < 0) {
		fprintf(stderr, "sc_read_binary() failed: %s\n", sc_strerror(r));
		return -1;
	}
	r = sc_pkcs15_cache_file(p15card, path, buf, tmpfile->size);
	if (r) {
		fprintf(stderr, "Unable to cache file: %s\n", sc_strerror(r));
		return -1;
	}
	sc_file_free(tmpfile);
	return 0;
}

int learn_card(void)
{
	struct stat stbuf;
	char dir[120];
	int r, i, cert_count;
        struct sc_pkcs15_object *certs[32];

	r = sc_get_cache_dir(ctx, dir, sizeof(dir)); 
	if (r) {
		fprintf(stderr, "Unable to find cache directory: %s\n", sc_strerror(r));
		return 1;
	}
	r = stat(dir, &stbuf);
	if (r) {
		printf("No '%s' directory found, creating...\n", dir);
		r = mkdir(dir, 0700);
		if (r) {
			perror("Directory creation failed");
			return 1;
		}
	}
	printf("Using cache directory '%s'.\n", dir);
        r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, certs, 32);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
        cert_count = r;
        r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY_RSA, NULL, 0);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
        r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, NULL, 0);
	if (r < 0) {
		fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	for (i = 0; i < SC_PKCS15_DF_TYPE_COUNT; i++) {
		int file_nr;
		struct sc_pkcs15_df *df = &p15card->df[i];
		
		for (file_nr = 0; file_nr < df->count; file_nr++) {
			struct sc_file *file = df->file[file_nr];
			
			read_and_cache_file(&file->path);
		}
	}
	printf("Caching %d certificate(s)...\n", r);
	for (i = 0; i < cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = certs[i]->data;
		
		printf("[%s]\n", certs[i]->label);
		read_and_cache_file(&cinfo->path);
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
	int do_list_pubkeys = 0;
	int do_read_pubkey = 0;
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
		case OPT_LIST_PUB:
			do_list_pubkeys = 1;
			action_count++;
			break;
		case OPT_READ_PUB:
			opt_pubkey = optarg;
			do_read_pubkey = 1;
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
	r = sc_establish_context(&ctx, app_name);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	ctx->error_file = stderr;
	ctx->debug_file = stdout;
	ctx->debug = opt_debug;
	if (ctx->reader_count == 0) {
		fprintf(stderr, "No readers configured.\n");
		err = 1;
		goto end;
	}
	if (opt_reader >= ctx->reader_count || opt_reader < 0) {
		fprintf(stderr, "Illegal reader number. Only %d reader(s) configured.\n", ctx->reader_count);
		err = 1;
		goto end;
	}
	if (sc_detect_card_presence(ctx->reader[opt_reader], 0) != 1) {
		fprintf(stderr, "Card not present.\n");
		err = 3;
		goto end;
	}
	if (!quiet)
		fprintf(stderr, "Connecting to card in reader %s...\n", ctx->reader[opt_reader]->name);
	r = sc_connect_card(ctx->reader[opt_reader], 0, &card);
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
	if (opt_no_cache)
		p15card->use_cache = 0;
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
	if (do_list_pubkeys) {
		if ((err = list_public_keys()))
			goto end;
		action_count--;
	}
	if (do_read_pubkey) {
		if ((err = read_public_key()))
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
		sc_disconnect_card(card, 0);
	}
	if (ctx)
		sc_release_context(ctx);
	return err;
}
