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
#include <limits.h>
#include <opensc/pkcs15.h>
#include "util.h"

const char *app_name = "pkcs15-tool";

int opt_reader = -1, opt_debug = 0, opt_wait = 0;
int opt_no_cache = 0;
char * opt_auth_id;
char * opt_cert = NULL;
char * opt_pubkey = NULL;
char * opt_outfile = NULL;
char * opt_newpin = NULL;
char * opt_pin = NULL;

int quiet = 0;

enum {
	OPT_CHANGE_PIN = 0x100,
	OPT_LIST_PINS,
	OPT_READER,
	OPT_PIN_ID,
	OPT_NO_CACHE,
	OPT_LIST_PUB,
	OPT_READ_PUB,
	OPT_PIN,
};

#define NELEMENTS(x)	(sizeof(x)/sizeof((x)[0]))

static int pem_encode(struct sc_context *, int,
		sc_pkcs15_der_t *, sc_pkcs15_der_t *);

const struct option options[] = {
	{ "learn-card",		no_argument, 0, 	'L' },
	{ "read-certificate",	required_argument, 0, 	'r' },
	{ "list-certificates",	no_argument, 0,		'c' },
	{ "read-data-object",	required_argument, 0, 	'R' },
	{ "list-data-objects",	no_argument, 0,		'C' },
	{ "list-pins",		no_argument, 0,		OPT_LIST_PINS },
	{ "unblock-pin",	no_argument, 0,		'u' },
	{ "change-pin",		no_argument, 0,		OPT_CHANGE_PIN },
	{ "list-keys",          no_argument, 0,         'k' },
	{ "list-public-keys",	no_argument, 0,		OPT_LIST_PUB },
	{ "read-public-key",	required_argument, 0,	OPT_READ_PUB },
	{ "reader",		required_argument, 0,	OPT_READER },
	{ "pin",                required_argument, 0,   OPT_PIN },
	{ "output",		required_argument, 0,	'o' },
	{ "quiet",		no_argument, 0,		'q' },
	{ "debug",		no_argument, 0,		'd' },
	{ "no-cache",		no_argument, 0,		OPT_NO_CACHE },
	{ "auth-id",		required_argument, 0,	'a' },
	{ "wait",		no_argument, 0,		'w' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Stores card info to cache",
	"Reads certificate with ID <arg>",
	"Lists certificates",
	"Reads data object with ID <arg>",
	"Lists data objects",
	"Lists PIN codes",
	"Unblock PIN code",
	"Changes the PIN code",
	"Lists private keys",
	"Lists public keys",
	"Reads public key with ID <arg>",
	"Uses reader number <arg>",
        "Specify PIN",
	"Outputs to file <arg>",
	"Quiet operation",
	"Debug output -- may be supplied several times",
	"Disable card caching",
	"The auth ID of the PIN to use",
	"Wait for card insertion",
};

struct sc_context *ctx = NULL;
struct sc_card *card = NULL;
struct sc_pkcs15_card *p15card = NULL;

void print_cert_info(const struct sc_pkcs15_object *obj)
{
	unsigned int i;
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

int
list_data_object(const char *kind, const u8*data, size_t data_len)
{
	int i;
	
	printf("%s (%i bytes): <", kind, data_len);
	for (i = 0; i < data_len; i++)
		printf(" %02X", data[i]);
	printf(" >\n");

	return 0;
}

int
print_data_object(const char *kind, const u8*data, size_t data_len)
{
	int i;
	
	if (opt_outfile != NULL) {
		FILE *outf;
		outf = fopen(opt_outfile, "w");
		if (outf == NULL) {
			fprintf(stderr, "Error opening file '%s': %s\n",
				opt_outfile, strerror(errno));
			return 2;
			}
		for (i=0; i < data_len; i++)
			fprintf(outf, "%c", data[i]);
		printf("Dumping (%i bytes) to file <%s>: <", data_len, opt_outfile);
		for (i=0; i < data_len; i++)
			printf(" %02X", data[i]);
		printf(" >\n");
		fclose(outf);
	} else {
		printf("%s (%i bytes): <", kind, data_len);
		for (i=0; i < data_len; i++)
			printf(" %02X", data[i]);
		printf(" >\n");
	}
	printf(" >\n");
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
		struct sc_pkcs15_cert_info *cinfo = (struct sc_pkcs15_cert_info *) objs[i]->data;
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

int read_data_object(void)
{
	int r, i, count;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *objs[32];

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_cert, &id);
	
	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Data object enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
		struct sc_pkcs15_data *data_object;

		if (sc_pkcs15_compare_id(&id, &cinfo->id) != 1)
			continue;
			
		if (!quiet)
			printf("Reading data object with ID '%s'\n", opt_cert);
		r = sc_pkcs15_read_data_object(p15card, cinfo, &data_object);
		if (r) {
			fprintf(stderr, "Data object read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = print_data_object("Data Object", data_object->data, data_object->data_len);
		sc_pkcs15_free_data_object(data_object);
		return r;
	}
	fprintf(stderr, "Data object with ID '%s' not found.\n", opt_cert);
	return 2;
}

int list_data_objects(void)
{
	int r, i, count;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *objs[32];
	id.len = SC_PKCS15_MAX_ID_SIZE;

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Data object enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	for (i = 0; i < count; i++) {
		struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
		struct sc_pkcs15_data *data_object;

		printf("Reading data object <%i> ---------------------------\n", i);
		r = sc_pkcs15_read_data_object(p15card, cinfo, &data_object);
		if (r) {
			fprintf(stderr, "Data object read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = list_data_object("Data Object", data_object->data, data_object->data_len);
		sc_pkcs15_free_data_object(data_object);
	}
	return 0;
}

void print_prkey_info(const struct sc_pkcs15_object *obj)
{
	unsigned int i;
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
	const unsigned int af_count = NELEMENTS(access_flags);

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
	unsigned int i;
        const struct sc_pkcs15_pubkey_info *pubkey = (const struct sc_pkcs15_pubkey_info *) obj->data;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const unsigned int usage_count = NELEMENTS(usages);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const unsigned int af_count = NELEMENTS(access_flags);

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
	int r;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *obj;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	sc_pkcs15_cert_t *cert = NULL;
	sc_pkcs15_der_t pem_key;

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_pubkey, &id);

	r = sc_pkcs15_find_pubkey_by_id(p15card, &id, &obj);
	if (r >= 0) {
		if (!quiet)
			printf("Reading public key with ID '%s'\n", opt_pubkey);
		r = sc_pkcs15_read_pubkey(p15card, obj, &pubkey);
	} else if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		/* No pubkey - try if there's a certificate */
		r = sc_pkcs15_find_cert_by_id(p15card, &id, &obj);
		if (r >= 0) {
			if (!quiet)
				printf("Reading certificate with ID '%s'\n", opt_pubkey);
			r = sc_pkcs15_read_certificate(p15card,
				(sc_pkcs15_cert_info_t *) obj->data,
				&cert);
		}
		if (r >= 0)
			pubkey = &cert->key;
	}

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		fprintf(stderr, "Public key with ID '%s' not found.\n", opt_pubkey);
		return 2;
	}
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}

	r = pem_encode(ctx, pubkey->algorithm, &pubkey->data, &pem_key);
	if (r < 0) {
		fprintf(stderr, "Error encoding PEM key: %s\n",
				sc_strerror(r));
		r = 1;
	} else {
		r = print_pem_object("PUBLIC KEY", pem_key.value, pem_key.len);
	}

	free(pem_key.value);
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);

	return r;
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

	if (pinfo == NULL && opt_auth_id == NULL) {
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
		pinfo = (struct sc_pkcs15_pin_info *) obj->data;
	} else if (pinfo == NULL) {
		struct sc_pkcs15_id auth_id;
		
		sc_pkcs15_hex_string_to_id(opt_auth_id, &auth_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &auth_id, &obj);
		if (r) {
			fprintf(stderr, "Unable to find PIN code: %s\n", sc_strerror(r));
			return NULL;
		}
		pinfo = (struct sc_pkcs15_pin_info *) obj->data;
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
		if (strlen(pincode) > pinfo->max_length) {
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
	printf("\tLength    : min_len:%d, max_len:%d, stored_len:%d\n",
				pin->min_length, pin->max_length, pin->stored_length);
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

int unblock_pin(void)
{
	struct sc_pkcs15_pin_info *pinfo = NULL;
	u8 *pin, *puk;
	int r;
	
	puk = get_pin("Enter PUK", &pinfo);
	if (puk == NULL)
		return 2;

	if (opt_pin)
		pin = (u8 *) opt_pin;
	else 
		while (1) {
		u8 *pin2;
	
		pin = get_pin("Enter new PIN", &pinfo);
		if (pin == NULL || strlen((char *) pin) == 0)
			return 2;
		pin2 = get_pin("Enter new PIN again", &pinfo);
		if (pin2 == NULL || strlen((char *) pin2) == 0)
			return 2;
		if (strcmp((char *) pin, (char *) pin2) == 0) {
			free(pin2);
			break;
		}
		printf("PIN codes do not match, try again.\n");
		free(pin);
		free(pin2);
	}
	r = sc_pkcs15_unblock_pin(p15card, pinfo, puk, strlen((char *) puk),
				 pin, strlen((char *) pin));
	if (r == SC_ERROR_PIN_CODE_INCORRECT) {
		fprintf(stderr, "PUK code incorrect; tries left: %d\n", pinfo->tries_left);
		return 3;
	} else if (r) {
		fprintf(stderr, "PIN unblocking failed: %s\n", sc_strerror(r));
		return 2;
	}
	if (!quiet)
		printf("PIN successfully unblocked.\n");
	return 0;
}

int change_pin(void)
{
	struct sc_pkcs15_pin_info *pinfo = NULL;
	u8 *pincode, *newpin;
	int r;
	
	if (opt_pin) 
		pincode = (u8 *) opt_pin;
	else 
		pincode = get_pin("Enter old PIN", &pinfo);
	if (pincode == NULL)
		return 2;
	if (strlen((char *) pincode) == 0) {
		fprintf(stderr, "No PIN code supplied.\n");
		return 2;
	}
	if (opt_newpin)
		newpin = (u8 *) opt_newpin;
	else 
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
	r = sc_pkcs15_cache_file(p15card, path, buf, r);
	if (r) {
		fprintf(stderr, "Unable to cache file: %s\n", sc_strerror(r));
		return -1;
	}
	sc_file_free(tmpfile);
	return 0;
}

int learn_card(void)
{
	char dir[PATH_MAX];
	int r, i, cert_count;
        struct sc_pkcs15_object *certs[32];
	struct sc_pkcs15_df *df;

	r = sc_get_cache_dir(ctx, dir, sizeof(dir)); 
	if (r) {
		fprintf(stderr, "Unable to find cache directory: %s\n", sc_strerror(r));
		return 1;
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

	/* Cache all relevant DF files. The cache
	 * directory is created automatically. */
	for (df = p15card->df_list; df != NULL; df = df->next)
		read_and_cache_file(&df->path);
	printf("Caching %d certificate(s)...\n", cert_count);
	for (i = 0; i < cert_count; i++) {
		struct sc_pkcs15_cert_info *cinfo = (struct sc_pkcs15_cert_info *) certs[i]->data;
		
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
	int do_read_data_object = 0;
	int do_list_data_objects = 0;
	int do_list_pins = 0;
	int do_list_prkeys = 0;
	int do_list_pubkeys = 0;
	int do_read_pubkey = 0;
	int do_change_pin = 0;
	int do_unblock_pin = 0;
	int do_learn_card = 0;
	int action_count = 0;

	while (1) {
		c = getopt_long(argc, argv, "r:cuko:qda:LR:Cw", options, &long_optind);
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
		case 'c':
			do_list_certs = 1;
			action_count++;
			break;
		case 'R':
			opt_cert = optarg;
			do_read_data_object = 1;
			action_count++;
			break;
		case 'C':
			do_list_data_objects = 1;
			action_count++;
			break;
		case OPT_CHANGE_PIN:
			do_change_pin = 1;
			action_count++;
			break;
		case 'u':
			do_unblock_pin = 1;
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
		case OPT_PIN:
			opt_pin = optarg;
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
		case 'a':
			opt_auth_id = optarg;
			break;
		case OPT_NO_CACHE:
			opt_no_cache++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		}
	}
	if (action_count == 0)
		print_usage_and_die();
	r = sc_establish_context(&ctx, app_name);
	if (r) {
		fprintf(stderr, "Failed to establish context: %s\n", sc_strerror(r));
		return 1;
	}
	if (opt_debug)
		ctx->debug = opt_debug;

	err = connect_card(ctx, &card, opt_reader, 0, opt_wait, quiet);
	if (err)
		goto end;

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
		p15card->opts.use_cache = 0;
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
	if (do_list_data_objects) {
		if ((err = list_data_objects()))
			goto end;
		action_count--;
	}
	if (do_read_data_object) {
		if ((err = read_data_object()))
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
	if (do_unblock_pin) {
		if ((err = unblock_pin()))
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

/*
 * Helper function for PEM encoding public key
 */
#include "opensc/asn1.h"
static const struct sc_asn1_entry	c_asn1_pem_key_items[] = {
	{ "algorithm",	SC_ASN1_ALGORITHM_ID, SC_ASN1_CONS|ASN1_SEQUENCE, },
	{ "key",	SC_ASN1_BIT_STRING_NI, ASN1_BIT_STRING },
	{ NULL }
};
static const struct sc_asn1_entry	c_asn1_pem_key[] = {
	{ "publicKey",	SC_ASN1_STRUCT, SC_ASN1_CONS|ASN1_SEQUENCE, },
	{ NULL }
};

static int
pem_encode(struct sc_context *ctx,
		int alg_id, sc_pkcs15_der_t *key, sc_pkcs15_der_t *out)
{
	struct sc_asn1_entry	asn1_pem_key[2],
				asn1_pem_key_items[3];
	struct sc_algorithm_id algorithm;
	int key_len;

	memset(&algorithm, 0, sizeof(algorithm));
	algorithm.algorithm = alg_id;

	sc_copy_asn1_entry(c_asn1_pem_key, asn1_pem_key);
	sc_copy_asn1_entry(c_asn1_pem_key_items, asn1_pem_key_items);
	sc_format_asn1_entry(asn1_pem_key + 0, asn1_pem_key_items, NULL, 1);
	sc_format_asn1_entry(asn1_pem_key_items + 0,
			&algorithm, NULL, 1);
	key_len = 8 * key->len;
	sc_format_asn1_entry(asn1_pem_key_items + 1,
			key->value, &key_len, 1);

	return sc_asn1_encode(ctx, asn1_pem_key, &out->value, &out->len);
}
