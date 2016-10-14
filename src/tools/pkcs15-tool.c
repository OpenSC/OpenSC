/*
 * pkcs15-tool.c: Tool for poking with PKCS #15 smart cards
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2008  Andreas Jellinghaus <aj@dungeon.inka.de>
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

#define _XOPEN_SOURCE 500
#include <assert.h>
#include <ctype.h>
#ifdef _WIN32
#ifdef __MINGW32__
// work around for https://sourceforge.net/p/mingw-w64/bugs/476/
#include <windows.h>
#endif
#include <shellapi.h>
#include <tchar.h>
#else
#include <ftw.h>
#endif
#include <stdio.h>

#ifdef ENABLE_OPENSSL
#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
#else
#warning no uint32_t type available, please contact opensc-devel@opensc-project.org
#endif
#include <openssl/bn.h>
#include <openssl/crypto.h>
#endif
#include <limits.h>

#include "libopensc/pkcs15.h"
#include "libopensc/asn1.h"
#include "util.h"

static const char *app_name = "pkcs15-tool";

static int opt_wait = 0;
static int opt_no_cache = 0;
static int opt_clear_cache = 0;
static char * opt_auth_id = NULL;
static char * opt_reader = NULL;
static char * opt_cert = NULL;
static char * opt_data = NULL;
static int opt_raw = 0;
static char * opt_pubkey = NULL;
static char * opt_outfile = NULL;
static char * opt_bind_to_aid = NULL;
static const char * opt_newpin = NULL;
static const char * opt_pin = NULL;
static const char * opt_puk = NULL;
static int	verbose = 0;
static int opt_no_prompt = 0;
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
static int opt_rfc4716 = 0;
#endif

enum {
	OPT_CHANGE_PIN = 0x100,
	OPT_LIST_PINS,
	OPT_READER,
	OPT_PIN_ID,
	OPT_NO_CACHE,
	OPT_CLEAR_CACHE,
	OPT_LIST_PUB,
	OPT_READ_PUB,
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
	OPT_READ_SSH,
	OPT_RFC4716,
#endif
	OPT_PIN,
	OPT_NEWPIN,
	OPT_PUK,
	OPT_VERIFY_PIN,
	OPT_BIND_TO_AID,
	OPT_LIST_APPLICATIONS,
	OPT_LIST_SKEYS,
	OPT_NO_PROMPT,
	OPT_RAW,
	OPT_PRINT_VERSION
};

#define NELEMENTS(x)	(sizeof(x)/sizeof((x)[0]))

static int	authenticate(sc_pkcs15_object_t *obj);

static const struct option options[] = {
	{ "version",		0, NULL,			OPT_PRINT_VERSION },
	{ "list-applications",	no_argument, NULL,		OPT_LIST_APPLICATIONS },
	{ "read-certificate",	required_argument, NULL,	'r' },
	{ "list-certificates",	no_argument, NULL,		'c' },
	{ "read-data-object",	required_argument, NULL,	'R' },
	{ "raw",		no_argument, NULL,		OPT_RAW },
	{ "list-data-objects",	no_argument, NULL,		'C' },
	{ "list-pins",		no_argument, NULL,		OPT_LIST_PINS },
	{ "list-secret-keys",	no_argument, NULL,		OPT_LIST_SKEYS },
	{ "dump",		no_argument, NULL,		'D' },
	{ "unblock-pin",	no_argument, NULL,		'u' },
	{ "change-pin",		no_argument, NULL,		OPT_CHANGE_PIN },
	{ "list-keys",		no_argument, NULL,		'k' },
	{ "list-public-keys",	no_argument, NULL,		OPT_LIST_PUB },
	{ "read-public-key",	required_argument, NULL,	OPT_READ_PUB },
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
	{ "read-ssh-key",	required_argument, NULL,	OPT_READ_SSH },
	{ "rfc4716",		no_argument, NULL,		OPT_RFC4716 },
#endif
	{ "test-update",	no_argument, NULL,		'T' },
	{ "update",		no_argument, NULL,		'U' },
	{ "reader",		required_argument, NULL,	OPT_READER },
	{ "pin",		required_argument, NULL,	OPT_PIN },
	{ "new-pin",		required_argument, NULL,	OPT_NEWPIN },
	{ "puk",		required_argument, NULL,	OPT_PUK },
	{ "verify-pin",		no_argument, NULL,		OPT_VERIFY_PIN },
	{ "output",		required_argument, NULL,	'o' },
	{ "no-cache",		no_argument, NULL,		OPT_NO_CACHE },
	{ "clear-cache",	no_argument, NULL,		OPT_CLEAR_CACHE },
	{ "auth-id",		required_argument, NULL,	'a' },
	{ "aid",		required_argument, NULL,	OPT_BIND_TO_AID },
	{ "wait",		no_argument, NULL,		'w' },
	{ "verbose",		no_argument, NULL,		'v' },
	{ "no-prompt",		no_argument, NULL,		OPT_NO_PROMPT },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Print OpenSC package version",
	"List the on-card PKCS#15 applications",
	"Reads certificate with ID <arg>",
	"Lists certificates",
	"Reads data object with OID, applicationName or label <arg>",
	"Outputs raw 8 bit data to stdout. File output will not be affected by this, it always uses raw mode.",
	"Lists data objects",
	"Lists PIN codes",
	"Lists secret keys",
	"Dump card objects",
	"Unblock PIN code",
	"Change PIN or PUK code",
	"Lists private keys",
	"Lists public keys",
	"Reads public key with ID <arg>",
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
	"Reads public key with ID <arg>, outputs ssh format",
	"Outputs the public key in RFC 4716 format (requires --read-ssh-key)",
#endif
	"Test if the card needs a security update",
	"Update the card with a security update",
	"Uses reader number <arg>",
	"Specify PIN",
	"Specify New PIN (when changing or unblocking)",
	"Specify Unblock PIN",
	"Verify PIN after card binding (without 'auth-id' the first non-SO, non-Unblock PIN will be verified)",
	"Outputs to file <arg>",
	"Disable card caching",
	"Clear card caching",
	"The auth ID of the PIN to use",
	"Specify AID of the on-card PKCS#15 application to bind to (in hexadecimal form)",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
	"Do not prompt the user; if no PINs supplied, pinpad will be used.",
	NULL
};

static sc_context_t *ctx = NULL;
static sc_card_t *card = NULL;
static struct sc_pkcs15_card *p15card = NULL;

struct _access_rule_text {
	unsigned flag;
	const char *label;
} _access_rules_text[] = {
	{SC_PKCS15_ACCESS_RULE_MODE_READ, "read"},
	{SC_PKCS15_ACCESS_RULE_MODE_UPDATE, "update"},
	{SC_PKCS15_ACCESS_RULE_MODE_EXECUTE, "execute"},
	{SC_PKCS15_ACCESS_RULE_MODE_DELETE, "delete"},
	{SC_PKCS15_ACCESS_RULE_MODE_ATTRIBUTE, "attribute"},
	{SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS, "pso_cds"},
	{SC_PKCS15_ACCESS_RULE_MODE_PSO_VERIFY, "pso_verify"},
	{SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT, "pso_decrypt"},
	{SC_PKCS15_ACCESS_RULE_MODE_PSO_ENCRYPT, "pso_encrypt"},
	{SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH, "int_auth"},
	{SC_PKCS15_ACCESS_RULE_MODE_EXT_AUTH, "ext_auth"},
	{0, NULL},
};

static void
print_access_rules(const struct sc_pkcs15_accessrule *rules, int num)
{
	int i, j;

	if (!rules->access_mode)
		return;

	printf("\tAccess Rules   :");
	for (i = 0; i < num; i++)   {
		int next_coma = 0;

		if (!(rules + i)->access_mode)
			break;
		printf(" ");

		for (j = 0; _access_rules_text[j].label;j++)   {
			if ((rules + i)->access_mode & (_access_rules_text[j].flag))   {
				printf("%s%s", next_coma ? "," : "", _access_rules_text[j].label);
				next_coma = 1;
			}
		}

		printf(":%s;", (rules + i)->auth_id.len ? sc_pkcs15_print_id(&(rules + i)->auth_id) : "<always>");
	}
	printf("\n");
}

static void print_common_flags(const struct sc_pkcs15_object *obj)
{
	const char *common_flags[] = {"private", "modifiable"};
	unsigned int i;
	printf("\tObject Flags   : [0x%X]", obj->flags);
	for (i = 0; i < NELEMENTS(common_flags); i++) {
		if (obj->flags & (1 << i)) {
			printf(", %s", common_flags[i]);
		}
	}
	printf("\n");
}

static void print_cert_info(const struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) obj->data;
	struct sc_pkcs15_cert *cert_parsed = NULL;
	int rv;

	printf("X.509 Certificate [%.*s]\n", (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tAuthority      : %s\n", cert_info->authority ? "yes" : "no");
	printf("\tPath           : %s\n", sc_print_path(&cert_info->path));
	printf("\tID             : %s\n", sc_pkcs15_print_id(&cert_info->id));

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	rv = sc_pkcs15_read_certificate(p15card, cert_info, &cert_parsed);
	if (rv >= 0 && cert_parsed)   {
		printf("\tEncoded serial : %02X %02X ", *(cert_parsed->serial), *(cert_parsed->serial + 1));
		util_hex_dump(stdout, cert_parsed->serial + 2, cert_parsed->serial_len - 2, "");
		printf("\n");
		sc_pkcs15_free_certificate(cert_parsed);
	}
}


static int list_certificates(void)
{
	int r, i;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Certificate enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Card has %d certificate(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_cert_info(objs[i]);
		printf("\n");
	}

	return 0;
}

static int
print_pem_object(const char *kind, const u8*data, size_t data_len)
{
	FILE		*outf;
	unsigned char	*buf = NULL;
	size_t		buf_len = 1024;
	int		r;

	/* With base64, every 3 bytes yield 4 characters, and with
	 * 64 chars per line we know almost exactly how large a buffer we
	 * will need. */
	buf_len = (data_len + 2) / 3 * 4;
	buf_len += 2 * (buf_len / 64 + 2); /* certain platforms use CRLF */
	buf_len += 64;			   /* slack for checksum etc */

	if (!(buf = malloc(buf_len))) {
		perror("print_pem_object");
		return 1;
	}

	r = sc_base64_encode(data, data_len, buf, buf_len, 64);
	if (r < 0) {
		fprintf(stderr, "Base64 encoding failed: %s\n", sc_strerror(r));
		free(buf);
		return 1;
	}

	if (opt_outfile != NULL) {
		outf = fopen(opt_outfile, "w");
		if (outf == NULL) {
			fprintf(stderr, "Error opening file '%s': %s\n",
				opt_outfile, strerror(errno));
			free(buf);
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
	free(buf);
	return 0;
}

static void
list_data_object(const char *kind, const unsigned char *data, size_t data_len)
{
	char title[0x100];
	size_t i;

	snprintf(title, sizeof(title), "%s (%lu bytes): ", kind, (unsigned long) data_len);
	printf("%s", title);
	memset(title, ' ', strlen(title));
	for (i = 0; i < data_len; i++)   {
		if (i && !(i%48))
			printf("\n%s", title);
		printf("%02X", data[i]);
	}
	printf("\n");
}

static int
print_data_object(const char *kind, const u8*data, size_t data_len)
{
	size_t i;

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
		if (opt_raw) {
			for (i=0; i < data_len; i++)
				printf("%c", data[i]);
		} else {
			printf("Dumping (%lu bytes) to file <%s>: <",
				(unsigned long) data_len, opt_outfile);
			for (i=0; i < data_len; i++)
				printf(" %02X", data[i]);
			printf(" >\n");
		}
		fclose(outf);
	} else {
		if (opt_raw) {
			for (i=0; i < data_len; i++)
				printf("%c", data[i]);
		} else {
			printf("%s (%lu bytes): <",
				kind, (unsigned long) data_len);
			for (i=0; i < data_len; i++)
				printf(" %02X", data[i]);
			printf(" >\n");
		}
	}
	return 0;
}

static int read_certificate(void)
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

		if (verbose)
			printf("Reading certificate with ID '%s'\n", opt_cert);
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r) {
			fprintf(stderr, "Certificate read failed: %s\n", sc_strerror(r));
			return 1;
		}
		r = print_pem_object("CERTIFICATE", cert->data.value, cert->data.len);
		sc_pkcs15_free_certificate(cert);
		return r;
	}
	fprintf(stderr, "Certificate with ID '%s' not found.\n", opt_cert);
	return 2;
}

static int read_data_object(void)
{
	int r, i, count;
	struct sc_pkcs15_object *objs[32];
	struct sc_object_id oid;

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Data object enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;

	for (i = 0; i < count; i++) {
		struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;
		struct sc_pkcs15_data *data_object = NULL;

		if (!sc_format_oid(&oid, opt_data))   {
			if (!sc_compare_oid(&oid, &cinfo->app_oid))
				continue;
		}
		else   {
			if (strcmp(opt_data, cinfo->app_label) && strncmp(opt_data, objs[i]->label, sizeof objs[i]->label))
				continue;
		}

		if (verbose)
			printf("Reading data object with label '%s'\n", opt_data);
		r = authenticate(objs[i]);
		if (r >= 0) {
			r = sc_pkcs15_read_data_object(p15card, cinfo, &data_object);
			if (r) {
				fprintf(stderr, "Data object read failed: %s\n", sc_strerror(r));
				if (r == SC_ERROR_FILE_NOT_FOUND)
					continue; /* DEE emulation may say there is a file */
				return 1;
			}
			r = print_data_object("Data Object", data_object->data, data_object->data_len);
			sc_pkcs15_free_data_object(data_object);
			return r;
		} else {
			fprintf(stderr, "Authentication error: %s\n", sc_strerror(r));
			return 1;
		}
	}
	fprintf(stderr, "Data object with label '%s' not found.\n", opt_data);
	return 2;
}

static int list_data_objects(void)
{
	int r, i, count;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_DATA_OBJECT, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Data object enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	count = r;
	for (i = 0; i < count; i++) {
		int idx;
		struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;

		if (objs[i]->label[0] != '\0')
			printf("Data object '%.*s'\n",(int) sizeof objs[i]->label, objs[i]->label);
		else
			printf("Data object <%i>\n", i);
		printf("\tapplicationName: %s\n", cinfo->app_label);
		if (sc_valid_oid(&cinfo->app_oid)) {
			printf("\tapplicationOID:  %i", cinfo->app_oid.value[0]);
			for (idx = 1; idx < SC_MAX_OBJECT_ID_OCTETS && cinfo->app_oid.value[idx] != -1 ; idx++)
				printf(".%i", cinfo->app_oid.value[idx]);
			printf("\n");
		}
		printf("\tPath:            %s\n", sc_print_path(&cinfo->path));
		if (objs[i]->auth_id.len == 0) {
			struct sc_pkcs15_data *data_object;
			r = sc_pkcs15_read_data_object(p15card, cinfo, &data_object);
			if (r) {
				fprintf(stderr, "Data object read failed: %s\n", sc_strerror(r));
				if (r == SC_ERROR_FILE_NOT_FOUND)
					 continue; /* DEE emulation may say there is a file */
				return 1;
			}
			list_data_object("\tData", data_object->data, data_object->data_len);
			sc_pkcs15_free_data_object(data_object);
		}
		else {
			printf("\tAuth ID:         %s\n", sc_pkcs15_print_id(&objs[i]->auth_id));
		}
	}
	return 0;
}

static void print_prkey_info(const struct sc_pkcs15_object *obj)
{
	unsigned int i;
	struct sc_pkcs15_prkey_info *prkey = (struct sc_pkcs15_prkey_info *) obj->data;
	const char *types[] = { "", "RSA", "DSA", "GOSTR3410", "EC", "", "", "" };
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive", "nonRepudiation"
	};
	const size_t usage_count = NELEMENTS(usages);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const unsigned int af_count = NELEMENTS(access_flags);
	unsigned char guid[40];
	size_t guid_len;

	printf("Private %s Key [%.*s]\n", types[7 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%X]", prkey->usage);
	for (i = 0; i < usage_count; i++)
		if (prkey->usage & (1 << i)) {
			printf(", %s", usages[i]);
		}
	printf("\n");

	printf("\tAccess Flags   : [0x%X]", prkey->access_flags);
	for (i = 0; i < af_count; i++)
		if (prkey->access_flags & (1 << i))
			printf(", %s", access_flags[i]);
	printf("\n");

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	if (prkey->modulus_length)
		printf("\tModLength      : %lu\n", (unsigned long)prkey->modulus_length);
	else
		printf("\tFieldLength    : %lu\n", (unsigned long)prkey->field_length);
	printf("\tKey ref        : %d (0x%X)\n", prkey->key_reference, prkey->key_reference);
	printf("\tNative         : %s\n", prkey->native ? "yes" : "no");
	if (prkey->path.len || prkey->path.aid.len)
		printf("\tPath           : %s\n", sc_print_path(&prkey->path));
	if (obj->auth_id.len != 0)
		printf("\tAuth ID        : %s\n", sc_pkcs15_print_id(&obj->auth_id));
	printf("\tID             : %s\n", sc_pkcs15_print_id(&prkey->id));

	guid_len = sizeof(guid);
	if (!sc_pkcs15_get_object_guid(p15card, obj, 1, guid, &guid_len))   {
		printf("\tMD:guid        : ");
		if (strlen((char *)guid) == guid_len)   {
			printf("%s\n", (char *)guid);
		}
		else  {
			printf("0x'");
			util_hex_dump(stdout, guid, guid_len, "");
			printf("'\n");
		}
	}
}


static int list_private_keys(void)
{
	int r, i;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PRKEY, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Card has %d private key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_prkey_info(objs[i]);
		printf("\n");
	}
	return 0;
}

static void print_pubkey_info(const struct sc_pkcs15_object *obj)
{
	unsigned int i;
	const struct sc_pkcs15_pubkey_info *pubkey = (const struct sc_pkcs15_pubkey_info *) obj->data;
	const char *types[] = { "", "RSA", "DSA", "GOSTR3410", "EC", "", "", "" };
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
	int have_path = (pubkey->path.len != 0) || (pubkey->path.aid.len != 0);

	printf("Public %s Key [%.*s]\n", types[7 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%X]", pubkey->usage);
	for (i = 0; i < usage_count; i++)
		if (pubkey->usage & (1 << i)) {
			printf(", %s", usages[i]);
	}
	printf("\n");

	printf("\tAccess Flags   : [0x%X]", pubkey->access_flags);
	for (i = 0; i < af_count; i++)
		if (pubkey->access_flags & (1 << i))
			printf(", %s", access_flags[i]);
	printf("\n");

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	if (pubkey->modulus_length)   {
		printf("\tModLength      : %lu\n", (unsigned long)pubkey->modulus_length);
	}
	else if (pubkey->field_length)   {
		printf("\tFieldLength    : %lu\n", (unsigned long)pubkey->field_length);
	}
	else if (obj->type == SC_PKCS15_TYPE_PUBKEY_EC && have_path)   {
		sc_pkcs15_pubkey_t *pkey = NULL;
		if (!sc_pkcs15_read_pubkey(p15card, obj, &pkey))   {
			printf("\tFieldLength    : %lu\n", (unsigned long)pkey->u.ec.params.field_length);
			sc_pkcs15_free_pubkey(pkey);
		}
	}

	printf("\tKey ref        : %d (0x%X)\n", pubkey->key_reference,  pubkey->key_reference);
	printf("\tNative         : %s\n", pubkey->native ? "yes" : "no");
	if (have_path)
		printf("\tPath           : %s\n", sc_print_path(&pubkey->path));
	if (obj->auth_id.len != 0)
		printf("\tAuth ID        : %s\n", sc_pkcs15_print_id(&obj->auth_id));
	printf("\tID             : %s\n", sc_pkcs15_print_id(&pubkey->id));
	if (!have_path || obj->content.len)
		printf("\tDirectValue    : <%s>\n", obj->content.len ? "present" : "absent");
}

static int list_public_keys(void)
{
	int r, i;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_PUBKEY, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Card has %d public key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_pubkey_info(objs[i]);
		printf("\n");
	}
	return 0;
}

static int read_public_key(void)
{
	int r;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *obj;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	sc_pkcs15_cert_t *cert = NULL;
	sc_pkcs15_der_t pem_key;

	pem_key.value = NULL;
	pem_key.len = 0;

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_pubkey, &id);

	r = sc_pkcs15_find_pubkey_by_id(p15card, &id, &obj);
	if (r >= 0) {
		if (verbose)
			printf("Reading public key with ID '%s'\n", opt_pubkey);
		r = sc_pkcs15_read_pubkey(p15card, obj, &pubkey);
	} else if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		/* No pubkey - try if there's a certificate */
		r = sc_pkcs15_find_cert_by_id(p15card, &id, &obj);
		if (r >= 0) {
			if (verbose)
				printf("Reading certificate with ID '%s'\n", opt_pubkey);
			r = sc_pkcs15_read_certificate(p15card, (sc_pkcs15_cert_info_t *) obj->data, &cert);
		}
		if (r >= 0)
			pubkey = cert->key;
	}

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		fprintf(stderr, "Public key with ID '%s' not found.\n", opt_pubkey);
		return 2;
	}
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (!pubkey) {
		fprintf(stderr, "Public key not available\n");
		return 1;
	}

	r = sc_pkcs15_encode_pubkey_as_spki(ctx, pubkey, &pem_key.value, &pem_key.len);
	if (r < 0) {
		fprintf(stderr, "Error encoding PEM key: %s\n", sc_strerror(r));
		r = 1;
	} else {
		r = print_pem_object("PUBLIC KEY", pem_key.value, pem_key.len);
		free(pem_key.value);
	}

	if (cert)
		sc_pkcs15_free_certificate(cert);
	else if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);

	return r;
}

static void print_skey_info(const struct sc_pkcs15_object *obj)
{
	unsigned int i;
	struct sc_pkcs15_skey_info *skey = (struct sc_pkcs15_skey_info *) obj->data;
	const char *types[] = { "generic", "DES", "2DES", "3DES"};
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover",
		"wrap", "unwrap", "verify", "verifyRecover",
		"derive"
	};
	const size_t usage_count = NELEMENTS(usages);
	const char *access_flags[] = {
		"sensitive", "extract", "alwaysSensitive",
		"neverExtract", "local"
	};
	const unsigned int af_count = NELEMENTS(access_flags);
	unsigned char guid[40];
	size_t guid_len;

	printf("Secret %s Key [%.*s]\n", types[3 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%X]", skey->usage);
	for (i = 0; i < usage_count; i++)
		if (skey->usage & (1 << i))
			printf(", %s", usages[i]);
	printf("\n");

	printf("\tAccess Flags   : [0x%X]", skey->access_flags);
	for (i = 0; i < af_count; i++)
		if (skey->access_flags & (1 << i))
			printf(", %s", access_flags[i]);
	printf("\n");

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	printf("\tSize           : %lu bits\n", (unsigned long)skey->value_len);
	printf("\tID             : %s\n", sc_pkcs15_print_id(&skey->id));
	printf("\tNative         : %s\n", skey->native ? "yes" : "no");
	printf("\tKey ref        : %d (0x%X)\n", skey->key_reference, skey->key_reference);

	if (skey->path.len || skey->path.aid.len)
		printf("\tPath           : %s\n", sc_print_path(&skey->path));

	guid_len = sizeof(guid);
	if (!sc_pkcs15_get_object_guid(p15card, obj, 1, guid, &guid_len))   {
		printf("\tGUID           : %s\n", (char *)guid);
	}

}

static int list_skeys(void)
{
	int r, i;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_SKEY, objs, 32);
	if (r < 0) {
		fprintf(stderr, "Secret key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Card has %d secret key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_skey_info(objs[i]);
		printf("\n");
	}

	return 0;
}


#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))

static void print_ssh_key(FILE *outf, const char * alg, struct sc_pkcs15_object *obj, unsigned char * buf, uint32_t len) {
	unsigned char *uu;
	int r;

	uu = malloc(len*2); // Way over - even if we have extra LFs; as each 6 bits take one byte.

	if (opt_rfc4716) {
		r = sc_base64_encode(buf, len, uu, 2*len, 64);
		if (r < 0) {
			free(uu);
			return;
		}

		fprintf(outf,"---- BEGIN SSH2 PUBLIC KEY ----\n");

		if (obj->label[0] != '\0')
			fprintf(outf,"Comment: \"%.*s\"\n", (int) sizeof obj->label, obj->label);

		fprintf(outf,"%s", uu);
		fprintf(outf,"---- END SSH2 PUBLIC KEY ----\n");
	} else {
		// Old style openssh - [<quote protected options> <whitespace> <keytype> <whitespace> <key> [<whitespace> anything else]
		//
		r = sc_base64_encode(buf, len, uu, 2*len, 0);
		if (r < 0) {
			free(uu);
			return;
		}

		if (obj->label[0] != '\0')
			fprintf(outf,"ssh-%s %s %.*s\n", alg, uu, (int) sizeof obj->label, obj->label);
		else
			fprintf(outf,"ssh-%s %s\n", alg, uu);
	}
	free(uu);
	return;
}

static int read_ssh_key(void)
{
	int r;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_object *obj = NULL;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	sc_pkcs15_cert_t *cert = NULL;
	FILE *outf = NULL;

	if (opt_outfile != NULL) {
		outf = fopen(opt_outfile, "w");
		if (outf == NULL) {
			fprintf(stderr, "Error opening file '%s': %s\n", opt_outfile, strerror(errno));
			goto fail2;
		}
	}
	else   {
		outf = stdout;
	}

	id.len = SC_PKCS15_MAX_ID_SIZE;
	sc_pkcs15_hex_string_to_id(opt_pubkey, &id);

	r = sc_pkcs15_find_pubkey_by_id(p15card, &id, &obj);
	if (r >= 0) {
		if (verbose)
			fprintf(stderr,"Reading ssh key with ID '%s'\n", opt_pubkey);
		r = authenticate(obj);
		if (r >= 0)
			r = sc_pkcs15_read_pubkey(p15card, obj, &pubkey);
	}
	else if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		/* No pubkey - try if there's a certificate */
		r = sc_pkcs15_find_cert_by_id(p15card, &id, &obj);
		if (r >= 0) {
			if (verbose)
				fprintf(stderr,"Reading certificate with ID '%s'\n", opt_pubkey);
			r = sc_pkcs15_read_certificate(p15card, (sc_pkcs15_cert_info_t *) obj->data, &cert);
		}
		if (r >= 0)
			pubkey = cert->key;
	}

	if (r == SC_ERROR_OBJECT_NOT_FOUND) {
		if (outf != stdout)
			fclose(outf);
		fprintf(stderr, "Public key with ID '%s' not found.\n", opt_pubkey);
		return 2;
	}
	if (r < 0) {
		if (outf != stdout)
			fclose(outf);
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}

	if (pubkey->algorithm == SC_ALGORITHM_RSA) {
		unsigned char buf[2048];
		uint32_t len, n;

		if (!pubkey->u.rsa.modulus.data || !pubkey->u.rsa.modulus.len ||
				!pubkey->u.rsa.exponent.data || !pubkey->u.rsa.exponent.len)  {
			fprintf(stderr, "Failed to decode public RSA key.\n");
			goto fail2;
		}

		buf[0]=0;
		buf[1]=0;
		buf[2]=0;
		buf[3]=7;

		len = sprintf((char *) buf+4,"ssh-rsa");
		len+=4;

		if (sizeof(buf)-len < 4+pubkey->u.rsa.exponent.len)
			goto fail;

		n = pubkey->u.rsa.exponent.len;
		if (pubkey->u.rsa.exponent.data[0] & 0x80)
			n++;

		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;
		if (pubkey->u.rsa.exponent.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.rsa.exponent.data, pubkey->u.rsa.exponent.len);
		len += pubkey->u.rsa.exponent.len;

		if (sizeof(buf)-len < 5+pubkey->u.rsa.modulus.len)
			goto fail;

		n = pubkey->u.rsa.modulus.len;
		if (pubkey->u.rsa.modulus.data[0] & 0x80)
			n++;
		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;

		if (pubkey->u.rsa.modulus.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.rsa.modulus.data, pubkey->u.rsa.modulus.len);
		len += pubkey->u.rsa.modulus.len;

		print_ssh_key(outf, "rsa", obj, buf, len);
	}

	if (pubkey->algorithm == SC_ALGORITHM_DSA) {
		unsigned char buf[2048];
		uint32_t len;
		uint32_t n;

		if (!pubkey->u.dsa.p.data || !pubkey->u.dsa.p.len ||
				!pubkey->u.dsa.q.data || !pubkey->u.dsa.q.len ||
				!pubkey->u.dsa.g.data || !pubkey->u.dsa.g.len ||
				!pubkey->u.dsa.pub.data || !pubkey->u.dsa.pub.len)   {
			fprintf(stderr, "Failed to decode DSA key.\n");
			goto fail2;
		}

		buf[0]=0;
		buf[1]=0;
		buf[2]=0;
		buf[3]=7;

		len = sprintf((char *) buf+4,"ssh-dss");
		len+=4;

		if (sizeof(buf)-len < 5+pubkey->u.dsa.p.len)
			goto fail;

		n = pubkey->u.dsa.p.len;
		if (pubkey->u.dsa.p.data[0] & 0x80)
			n++;

		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;
		if (pubkey->u.dsa.p.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.dsa.p.data, pubkey->u.dsa.p.len);
		len += pubkey->u.dsa.p.len;

		if (sizeof(buf)-len < 5+pubkey->u.dsa.q.len)
			goto fail;

		n = pubkey->u.dsa.q.len;
		if (pubkey->u.dsa.q.data[0] & 0x80)
			n++;

		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;
		if (pubkey->u.dsa.q.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.dsa.q.data, pubkey->u.dsa.q.len);
		len += pubkey->u.dsa.q.len;

		if (sizeof(buf)-len < 5+pubkey->u.dsa.g.len)
			goto fail;
		n = pubkey->u.dsa.g.len;
		if (pubkey->u.dsa.g.data[0] & 0x80)
			n++;

		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;
		if (pubkey->u.dsa.g.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.dsa.g.data, pubkey->u.dsa.g.len);
		len += pubkey->u.dsa.g.len;

		if (sizeof(buf)-len < 5+pubkey->u.dsa.pub.len)
			goto fail;

		n = pubkey->u.dsa.pub.len;
		if (pubkey->u.dsa.pub.data[0] & 0x80)
			n++;

		buf[len++]=(n >>24) & 0xff;
		buf[len++]=(n >>16) & 0xff;
		buf[len++]=(n >>8) & 0xff;
		buf[len++]=(n) & 0xff;
		if (pubkey->u.dsa.pub.data[0] & 0x80)
			buf[len++]= 0;

		memcpy(buf+len,pubkey->u.dsa.pub.data, pubkey->u.dsa.pub.len);
		len += pubkey->u.dsa.pub.len;

		print_ssh_key(outf, "dss", obj, buf, len);
	}

	if (outf != stdout)
		fclose(outf);
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);
	return 0;
fail:
	printf("can't convert key: buffer too small\n");
fail2:
	if (outf && outf != stdout)
		fclose(outf);
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else if (pubkey)
		sc_pkcs15_free_pubkey(pubkey);
	return SC_ERROR_OUT_OF_MEMORY;
}

#endif

static sc_pkcs15_object_t *
get_pin_info(void)
{
	sc_pkcs15_object_t *objs[32], *obj;
	int r;

	if (opt_auth_id == NULL) {
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
	} else {
		struct sc_pkcs15_id auth_id;

		sc_pkcs15_hex_string_to_id(opt_auth_id, &auth_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &auth_id, &obj);
		if (r) {
			fprintf(stderr, "Unable to find PIN code: %s\n", sc_strerror(r));
			return NULL;
		}
	}

	return obj;
}

static u8 * get_pin(const char *prompt, sc_pkcs15_object_t *pin_obj)
{
	sc_pkcs15_auth_info_t *pinfo = (sc_pkcs15_auth_info_t *) pin_obj->data;
	char *pincode = NULL;
	size_t len = 0;
	int r;

	if (opt_no_prompt) {
		// defer entry of the PIN to the readers pinpad.
		if (verbose)
			printf("%s [%.*s]: entry deferred to the reader keypad\n", prompt, (int) sizeof pin_obj->label, pin_obj->label);
		return NULL;
	}

	printf("%s [%.*s]: ", prompt, (int) sizeof pin_obj->label, pin_obj->label);
	if (pinfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return NULL;

	while (1) {
		r = util_getpass(&pincode, &len, stdin);
		if (r < 0)
			return NULL;
		if (!pincode || strlen(pincode) == 0) {
			free(pincode);
			return NULL;
		}
		if (strlen(pincode) < pinfo->attrs.pin.min_length) {
			printf("PIN code too short, try again.\n");
			continue;
		}
		if (strlen(pincode) > pinfo->attrs.pin.max_length) {
			printf("PIN code too long, try again.\n");
			continue;
		}
		return (u8 *) pincode;
	}
}

#ifdef _WIN32
static int clear_cache(void)
{
	TCHAR dirname[PATH_MAX];
	SHFILEOPSTRUCT fileop;
	int r;

	fileop.hwnd   = NULL;      // no status display
	fileop.wFunc  = FO_DELETE; // delete operation
	fileop.pFrom  = dirname;   // source file name as double null terminated string
	fileop.pTo    = NULL;      // no destination needed
	fileop.fFlags = FOF_NOCONFIRMATION|FOF_SILENT;  // do not prompt the user

	fileop.fAnyOperationsAborted = FALSE;
	fileop.lpszProgressTitle     = NULL;
	fileop.hNameMappings         = NULL;

	/* remove the user's cache directory */
	if ((r = sc_get_cache_dir(ctx, dirname, sizeof(dirname))) < 0)
		return r;
	dirname[_tcslen(dirname)+1] = 0;

	printf("Deleting %s...", dirname);
	r = SHFileOperation(&fileop);
	if (r == 0) {
		printf(" OK\n");
	} else {
		printf(" Error\n");
	}

	_tcscpy(dirname, _T("C:\\Windows\\System32\\config\\systemprofile\\eid-cache"));
	dirname[_tcslen(dirname)+1] = 0;

	printf("Deleting %s...", dirname);
	r = SHFileOperation(&fileop);
	if (r == 0) {
		printf(" OK\n");
	} else {
		printf(" Error\n");
	}

	return r;
}

#else

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	int r = remove(fpath);
	if (r)
		perror(fpath);
	return r;
}
static int clear_cache(void)
{
	char dirname[PATH_MAX];
	int r = 0;

	/* remove the user's cache directory */
	if ((r = sc_get_cache_dir(ctx, dirname, sizeof(dirname))) < 0)
		return r;
	r = nftw(dirname, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
	return r;
}
#endif


static int verify_pin(void)
{
	struct sc_pkcs15_object	*pin_obj = NULL;
	unsigned char		*pin;
	int r;

	if (!opt_auth_id)   {
		struct sc_pkcs15_object *objs[32];
		int ii;

		r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
		if (r < 0) {
			fprintf(stderr, "PIN code enumeration failed: %s\n", sc_strerror(r));
			return -1;
		}

		for (ii=0;ii<r;ii++)   {
			struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info *) objs[ii]->data;

			if (pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
				continue;
			if (pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
				continue;
			if (pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
				continue;

			pin_obj = objs[ii];
			break;
		}
	}
	else   {
		pin_obj = get_pin_info();
	}

	if (!pin_obj)   {
		fprintf(stderr, "PIN object '%s' not found\n", opt_auth_id);
		return -1;
	}

	if (opt_pin != NULL)
		pin = (unsigned char *) opt_pin;
	else
		pin = get_pin("Please enter PIN", pin_obj);


	r = sc_pkcs15_verify_pin(p15card, pin_obj, pin, pin ? strlen((char *) pin) : 0);
	if (r < 0)   {
		fprintf(stderr, "Operation failed: %s\n", sc_strerror(r));
		return -1;
	}

	if (opt_pin == NULL)
		free(pin);

	return 0;
}

static int authenticate(sc_pkcs15_object_t *obj)
{
	sc_pkcs15_object_t	*pin_obj;
	u8			*pin = NULL;
	int			r;

	if (obj->auth_id.len == 0)
		return 0;
	r = sc_pkcs15_find_pin_by_auth_id(p15card, &obj->auth_id, &pin_obj);
	if (r)
		return r;

	if (opt_pin != NULL)
		pin = (u8 *) opt_pin;
	else
		pin = get_pin("Please enter PIN", pin_obj);

	r = sc_pkcs15_verify_pin(p15card, pin_obj, pin, pin? strlen((char *) pin) : 0);

	if (opt_pin == NULL)
		free(pin);

	return r;
}

static void print_pin_info(const struct sc_pkcs15_object *obj)
{
	const char *pin_flags[] = {
		"case-sensitive", "local", "change-disabled",
		"unblock-disabled", "initialized", "needs-padding",
		"unblockingPin", "soPin", "disable_allowed",
		"integrity-protected", "confidentiality-protected",
		"exchangeRefData"
	};
	const char *pin_types[] = {"bcd", "ascii-numeric", "UTF-8", "halfnibble bcd", "iso 9664-1"};
	const struct sc_pkcs15_auth_info *auth_info = (const struct sc_pkcs15_auth_info *) obj->data;
	const size_t pf_count = NELEMENTS(pin_flags);
	size_t i;

	if (obj->type == SC_PKCS15_TYPE_AUTH_PIN)
		printf("PIN [%.*s]\n", (int) sizeof obj->label, obj->label);
	else if (obj->type == SC_PKCS15_TYPE_AUTH_AUTHKEY)
		printf("AuthKey [%.*s]\n", (int) sizeof obj->label, obj->label);

	print_common_flags(obj);
	if (obj->auth_id.len)
		printf("\tAuth ID        : %s\n", sc_pkcs15_print_id(&obj->auth_id));

	printf("\tID             : %s\n", sc_pkcs15_print_id(&auth_info->auth_id));
	if (auth_info->auth_type == SC_PKCS15_PIN_AUTH_TYPE_PIN)   {
		const struct sc_pkcs15_pin_attributes *pin_attrs = &(auth_info->attrs.pin);

		printf("\tFlags          : [0x%02X]", pin_attrs->flags);
		for (i = 0; i < pf_count; i++)
			if (pin_attrs->flags & (1 << i))
				printf(", %s", pin_flags[i]);
		printf("\n");

		printf("\tLength         : min_len:%lu, max_len:%lu, stored_len:%lu\n",
			(unsigned long)pin_attrs->min_length, (unsigned long)pin_attrs->max_length,
			(unsigned long)pin_attrs->stored_length);
		printf("\tPad char       : 0x%02X\n", pin_attrs->pad_char);
		printf("\tReference      : %d (0x%02X)\n", pin_attrs->reference, pin_attrs->reference);
		if (pin_attrs->type < NELEMENTS(pin_types))
			printf("\tType           : %s\n", pin_types[pin_attrs->type]);
		else
			printf("\tType           : [encoding %d]\n", pin_attrs->type);
	}
	else if (auth_info->auth_type == SC_PKCS15_PIN_AUTH_TYPE_AUTH_KEY)   {
		const struct sc_pkcs15_authkey_attributes *attrs = &auth_info->attrs.authkey;
		printf("\tDerived        : %i\n", attrs->derived);
		printf("\tSecretKeyID    : %s\n", sc_pkcs15_print_id(&attrs->skey_id));
	}

	if (auth_info->path.len || auth_info->path.aid.len)
		printf("\tPath           : %s\n", sc_print_path(&auth_info->path));
	if (auth_info->tries_left >= 0)
		printf("\tTries left     : %d\n", auth_info->tries_left);
}

static int list_pins(void)
{
	int r, i;
	struct sc_pkcs15_object *objs[32];

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH, objs, 32);
	if (r < 0) {
		fprintf(stderr, "AUTH objects enumeration failed: %s\n", sc_strerror(r));
		return 1;
	}
	if (verbose)
		printf("Card has %d Authentication objects.\n", r);
	for (i = 0; i < r; i++) {
		print_pin_info(objs[i]);
		printf("\n");
	}
	return 0;
}

static int list_apps(FILE *fout)
{
	unsigned j;
	int i;

	for (i=0; i<p15card->card->app_count; i++)   {
		struct sc_app_info *info = p15card->card->app[i];

		fprintf(fout, "Application '%s':\n", info->label);
		fprintf(fout, "\tAID: ");
		for(j=0;j<info->aid.len;j++)
			fprintf(fout, "%02X", info->aid.value[j]);
		fprintf(fout, "\n");

		if (info->ddo.value && info->ddo.len)   {
			fprintf(fout, "\tDDO: ");
			for(j=0;j<info->ddo.len;j++)
				fprintf(fout, "%02X", info->ddo.value[j]);
			fprintf(fout, "\n");
		}

		fprintf(fout, "\n");
	}
	return 0;
}

static int dump(void)
{
	const char *flags[] = {
		"Read-only",
		"Login required",
		"PRN generation",
		"EID compliant"
	};
	char *last_update = sc_pkcs15_get_lastupdate(p15card);
	int i, count = 0;

	printf("PKCS#15 Card [%s]:\n", p15card->tokeninfo->label);
	printf("\tVersion        : %d\n", p15card->tokeninfo->version);
	printf("\tSerial number  : %s\n", p15card->tokeninfo->serial_number);
	printf("\tManufacturer ID: %s\n", p15card->tokeninfo->manufacturer_id);
	if (last_update)
		printf("\tLast update    : %s\n", last_update);
	if (p15card->tokeninfo->preferred_language)
		printf("\tLanguage       : %s\n", p15card->tokeninfo->preferred_language);
	if (p15card->tokeninfo->profile_indication.name)
		printf("\tProfile        : %s\n", p15card->tokeninfo->profile_indication.name);
	printf("\tFlags          : ");
	for (i = 0; i < 4; i++) {
		if ((p15card->tokeninfo->flags >> i) & 1) {
			if (count)
				printf(", ");
			printf("%s", flags[i]);
			count++;
		}
	}
	printf("\n\n");

	list_pins();
	list_private_keys();
	list_public_keys();
	list_certificates();
	list_data_objects();

	return 0;
}

static int unblock_pin(void)
{
	struct sc_pkcs15_auth_info *pinfo = NULL;
	sc_pkcs15_object_t *pin_obj;
	u8 *pin, *puk;
	int r, pinpad_present = 0;

	pinpad_present = p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD;

	if (!(pin_obj = get_pin_info()))
		return 2;
	pinfo = (sc_pkcs15_auth_info_t *) pin_obj->data;

	if (pinfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;

	puk = (u8 *) opt_puk;
	if (puk == NULL) {
		sc_pkcs15_object_t *puk_obj = NULL;

		if (pin_obj->auth_id.len)   {
			r = sc_pkcs15_find_pin_by_auth_id(p15card, &pin_obj->auth_id, &puk_obj);
			if (r)
				return 2;
		}

		if (puk_obj)   {
			struct sc_pkcs15_auth_info *puk_info = (sc_pkcs15_auth_info_t *) puk_obj->data;

			if (puk_info->auth_type == SC_PKCS15_PIN_AUTH_TYPE_PIN)    {
				/* TODO: Print PUK's label */
				puk = get_pin("Enter PUK", puk_obj);
				if (!pinpad_present && puk == NULL)
					return 2;
			}
		}
		else   {
			puk = get_pin("Enter PUK", pin_obj);
			if (!pinpad_present && puk == NULL)
				return 2;
		}
	}

	if (puk == NULL && verbose)
		printf("PUK value will be prompted with pinpad.\n");

	/* FIXME should OPENSSL_cleanse on pin/puk data */
	pin = opt_pin ? (u8 *) opt_pin : (u8 *) opt_newpin;
	while (pin == NULL) {
		u8 *pin2;

		pin = get_pin("Enter new PIN", pin_obj);
		if (pinpad_present && pin == NULL)   {
			if (verbose)
				printf("New PIN value will be prompted with pinpad.\n");
			break;
		}
		if (pin == NULL || strlen((char *) pin) == 0) {
			free(pin);
			return 2;
		}

		pin2 = get_pin("Enter new PIN again", pin_obj);
		if (pin2 == NULL || strlen((char *) pin2) == 0) {
			free(pin);
			free(pin2);
			return 2;
		}
		if (strcmp((char *) pin, (char *) pin2) != 0) {
			printf("PIN codes do not match, try again.\n");
			free(pin);
			pin = NULL;
		}
		free(pin2);
	}

	r = sc_pkcs15_unblock_pin(p15card, pin_obj,
			puk, puk ? strlen((char *) puk) : 0,
			pin, pin ? strlen((char *) pin) : 0);

	if (NULL == opt_puk)
		free(puk);
	if (NULL == opt_pin && NULL == opt_newpin)
		free(pin);

	if (r == SC_ERROR_PIN_CODE_INCORRECT) {
		fprintf(stderr, "PUK code incorrect; tries left: %d\n", pinfo->tries_left);
		return 3;
	} else if (r) {
		fprintf(stderr, "PIN unblocking failed: %s\n", sc_strerror(r));
		return 2;
	}
	if (verbose)
		printf("PIN successfully unblocked.\n");
	return 0;
}

static int change_pin(void)
{
	sc_pkcs15_object_t *pin_obj;
	sc_pkcs15_auth_info_t *pinfo = NULL;
	u8 *pincode, *newpin;
	int r, pinpad_present = 0;

	pinpad_present = p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD;

	if (!(pin_obj = get_pin_info()))
		return 2;

	pinfo = (sc_pkcs15_auth_info_t *) pin_obj->data;
	if (pinfo->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;

	if (pinfo->tries_left != -1) {
		if (pinfo->tries_left != pinfo->max_tries) {
			if (pinfo->tries_left == 0) {
				fprintf(stderr, "PIN code blocked!\n");
				return 2;
			} else {
				fprintf(stderr, "%d PIN tries left.\n", pinfo->tries_left);
			}
		}
	}

	pincode = (u8 *) opt_pin;
	if (pincode == NULL) {
		pincode = get_pin("Enter old PIN", pin_obj);
		if (!pinpad_present && pincode == NULL)
			return 2;
	}

	if (pincode && strlen((char *) pincode) == 0) {
		fprintf(stderr, "No PIN code supplied.\n");
		free(pincode);
		return 2;
	}

	if (pincode == NULL && verbose)
		printf("Old PIN value will be prompted with pinpad.\n");

	newpin = (u8 *) opt_newpin;
	while (newpin == NULL) {
		u8 *newpin2;

		newpin = get_pin("Enter new PIN", pin_obj);
		if (pinpad_present && newpin == NULL)   {
			if (verbose)
				printf("New PIN value will be prompted with pinpad.\n");
			break;
		}
		if (newpin == NULL || strlen((char *) newpin) == 0)   {
			fprintf(stderr, "No new PIN value supplied.\n");
			free(newpin);
			free(pincode);
			return 2;
		}

		newpin2 = get_pin("Enter new PIN again", pin_obj);
		if (newpin2 && strlen((char *) newpin2) &&
				strcmp((char *) newpin, (char *) newpin2) == 0) {
			free(newpin2);
			break;
		}
		printf("PIN codes do not match, try again.\n");
		free(newpin);
		free(newpin2);
		newpin=NULL;
	}

	r = sc_pkcs15_change_pin(p15card, pin_obj,
			pincode, pincode ? strlen((char *) pincode) : 0,
			newpin, newpin ? strlen((char *) newpin) : 0);
	if (r == SC_ERROR_PIN_CODE_INCORRECT) {
		fprintf(stderr, "PIN code incorrect; tries left: %d\n", pinfo->tries_left);
		return 3;
	} else if (r) {
		fprintf(stderr, "PIN code change failed: %s\n", sc_strerror(r));
		return 2;
	}
	if (verbose)
		printf("PIN code changed successfully.\n");

	if (opt_pin == NULL)
		free(pincode);
	if (opt_newpin == NULL)
		free(newpin);

	return 0;
}

static int test_update(sc_card_t *in_card)
{
	sc_apdu_t apdu;
	static u8 cmd1[2] = { 0x50, 0x15};
	u8 rbuf[258];
	int rc;
	int r;
	static u8 fci_bad[] = { 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static u8 fci_good[] = { 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00 };

	r = sc_lock(card);
	if (r < 0)
		return r;

	if (strcmp("cardos",in_card->driver->short_name) != 0) {
		printf("not using the cardos driver, card is fine.\n");
		rc = 0;
		goto end;
	}

	/* first select file on 5015 and get fci */
	sc_format_apdu(in_card, &apdu, SC_APDU_CASE_4_SHORT, 0xa4, 0x08, 0x00);
	apdu.lc = sizeof(cmd1);
	apdu.datalen = sizeof(cmd1);
	apdu.data = cmd1;
	apdu.le = 256;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("selecting folder failed: %s\n", sc_strerror(r));
		rc = 2;
		goto end;
	}

	if (apdu.sw1 != 0x90) {
		printf("apdu command select file failed: card returned %02X %02X\n",
			apdu.sw1, apdu.sw2);
		rc = 2;
		goto end;

	}

	if (apdu.resplen < 6) {
		printf("select file did not return enough data (length %d)\n",
			(int) apdu.resplen);
		goto bad_fci;
	}

	if (rbuf[0] != 0x6f) {
		printf("select file did not return the information we need\n");
		goto bad_fci;
	}

	if (rbuf[1] != apdu.resplen -2) {
		printf("select file returned inconsistent information\n");
		goto bad_fci;
	}

	{
		size_t i=0;
		while(i < rbuf[1]) {
			if (rbuf[2+i] == 0x86) { /* found our buffer */
				break;
			}
			/* other tag */
			i += 2 + rbuf[2+i+1]; /* length of this tag*/
		}
		if (rbuf[2+i+1] < 9 || 2+i+2+9 > apdu.resplen) {
			printf("select file returned short fci\n");
			goto bad_fci;
		}

		if (memcmp(&rbuf[2+i+2],fci_good,sizeof(fci_good)) == 0) {
			printf("fci is up-to-date, card is fine\n");
			rc = 0;
			goto end;
		}

		if (memcmp(&rbuf[2+i+2],fci_bad,sizeof(fci_bad)) == 0) {
			printf("fci is out-of-date, card is vulnerable\n");
			rc = 1;
			goto end;
		}

		printf("select file returned fci with unknown data\n");
		goto bad_fci;
	}
end:
	sc_unlock(card);
	/* 0 = card ok, 1 = card vulnerable, 2 = problem! */
	return rc;

bad_fci:
	sc_unlock(card);
	util_hex_dump(stdout,rbuf,apdu.resplen," ");
	printf("\n");
	return 2;
}

static int update(sc_card_t *in_card)
{
	sc_apdu_t apdu;
	u8 rbuf[258];
	static u8 cmd1[2] = { 0x50, 0x15};
	static u8 cmd3[11] = { 0x86, 0x09, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
				0xff, 0x00, 0x00};
	int r;

	/* first select file on 5015 */
	sc_format_apdu(in_card, &apdu, SC_APDU_CASE_3_SHORT, 0xa4, 0x08, 0x00);
	apdu.lc = sizeof(cmd1);
	apdu.datalen = sizeof(cmd1);
	apdu.data = cmd1;

	r = sc_lock(card);
	if (r < 0)
		return r;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("selecting folder failed: %s\n", sc_strerror(r));
		goto end;
	}

	if (apdu.sw1 != 0x90) {
		printf("apdu command select file: card returned %02X %02X\n",
			apdu.sw1, apdu.sw2);
		goto end;

	}

	/* next get lifecycle */
	memset(&apdu, 0, sizeof(apdu));
	sc_format_apdu(in_card, &apdu, SC_APDU_CASE_2, 0xca, 0x01, 0x83);
	apdu.cla = 0x00;
	apdu.le = 256;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("get lifecycle failed: %s\n", sc_strerror(r));
		goto end;
	}

	if (apdu.sw1 != 0x90) {
		printf("get lifecycle failed: card returned %02X %02X\n",
			apdu.sw1, apdu.sw2);
		goto end;

	}

	if (apdu.resplen < 1) {
		printf("get lifecycle failed: lifecycle byte not in response\n");
		goto end;
	}

	if (rbuf[0] != 0x10 && rbuf[0] != 0x20) {
		printf("lifecycle neither user nor admin, can't proceed\n");
		goto end;
	}

	if (rbuf[0] == 0x20)
		goto skip_change_lifecycle;

	/* next phase control / change lifecycle to operational */
	memset(&apdu, 0, sizeof(apdu));
	sc_format_apdu(in_card, &apdu, SC_APDU_CASE_1, 0x10, 0x00, 0x00);
	apdu.cla = 0x80;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("change lifecycle failed: %s\n", sc_strerror(r));
		goto end;
	}

	if (apdu.sw1 != 0x90) {
		printf("apdu command change lifecycle failed: card returned %02X %02X\n",
			apdu.sw1, apdu.sw2);
		goto end;

	}

skip_change_lifecycle:
	/* last update AC */
	memset(&apdu, 0, sizeof(apdu));
	sc_format_apdu(in_card, &apdu, SC_APDU_CASE_3_SHORT, 0xda, 0x01, 0x6f);
	apdu.lc = sizeof(cmd3);
	apdu.datalen = sizeof(cmd3);
	apdu.data = cmd3;
	apdu.le = 0;
	apdu.resplen = 0;
	apdu.resp = NULL;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0) {
		printf("update fci failed: %s\n", sc_strerror(r));
		goto end;
	}

	if (apdu.sw1 != 0x90) {
		printf("apdu command update fci failed: card returned %02X %02X\n",
			apdu.sw1, apdu.sw2);
		goto end;

	}

	printf("security update applied successfully.\n");
end:
	sc_unlock(card);
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
	int do_list_skeys = 0;
	int do_list_apps = 0;
	int do_dump = 0;
	int do_list_prkeys = 0;
	int do_list_pubkeys = 0;
	int do_read_pubkey = 0;
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
	int do_read_sshkey = 0;
#endif
	int do_verify_pin = 0;
	int do_change_pin = 0;
	int do_unblock_pin = 0;
	int do_test_update = 0;
	int do_update = 0;
	int do_print_version = 0;
	int action_count = 0;
	sc_context_param_t ctx_param;

	assert(sizeof(option_help)/sizeof(char *)==sizeof(options)/sizeof(struct option));

	c = OPT_PUK;

	while (1) {
		c = getopt_long(argc, argv, "r:cuko:va:LR:CwDTU", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case OPT_PRINT_VERSION:
			do_print_version = 1;
			action_count++;
			break;
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
			opt_data = optarg;
			do_read_data_object = 1;
			action_count++;
			break;
		case OPT_RAW:
			opt_raw = 1;
			break;
		case 'C':
			do_list_data_objects = 1;
			action_count++;
			break;
		case OPT_VERIFY_PIN:
			do_verify_pin = 1;
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
		case OPT_LIST_SKEYS:
			do_list_skeys = 1;
			action_count++;
			break;
		case 'D':
			do_dump = 1;
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
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
		case OPT_READ_SSH:
			opt_pubkey = optarg;
			do_read_sshkey = 1;
			action_count++;
			break;
		case OPT_RFC4716:
			opt_rfc4716 = 1;
			break;
#endif
		case 'T':
			do_test_update = 1;
			action_count++;
			break;
		case 'U':
			do_update = 1;
			action_count++;
			break;
		case OPT_READER:
			opt_reader = optarg;
			break;
		case OPT_PIN:
			util_get_pin(optarg, &opt_pin);
			break;
		case OPT_NEWPIN:
			util_get_pin(optarg, &opt_newpin);
			break;
		case OPT_PUK:
			util_get_pin(optarg, &opt_puk);
			break;
		case 'o':
			opt_outfile = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'a':
			opt_auth_id = optarg;
			break;
		case OPT_BIND_TO_AID:
			opt_bind_to_aid = optarg;
			break;
		case OPT_LIST_APPLICATIONS:
			do_list_apps = 1;
			action_count++;
			break;
		case OPT_NO_CACHE:
			opt_no_cache++;
			break;
		case OPT_CLEAR_CACHE:
			opt_clear_cache = 1;
			action_count++;
			break;
		case 'w':
			opt_wait = 1;
			break;
		case OPT_NO_PROMPT:
			opt_no_prompt = 1;
			break;
		}
	}
	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	if (do_print_version)   {
		printf("%s\n", OPENSC_SCM_REVISION);
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

	if (opt_clear_cache) {
		if ((err = clear_cache()))
			goto end;
		action_count--;
	}

	if (verbose > 1) {
		ctx->debug = verbose;
		sc_ctx_log_to_file(ctx, "stderr");
	}

	err = util_connect_card_ex(ctx, &card, opt_reader, opt_wait, 0, verbose);
	if (err)
		goto end;

	if (verbose)
		fprintf(stderr, "Trying to find a PKCS#15 compatible card...\n");

	if (opt_bind_to_aid)   {
		struct sc_aid aid;

		aid.len = sizeof(aid.value);
		if (sc_hex_to_bin(opt_bind_to_aid, aid.value, &aid.len))   {
			fprintf(stderr, "Invalid AID value: '%s'\n", opt_bind_to_aid);
			return 1;
		}

		r = sc_pkcs15_bind(card, &aid, &p15card);
	}
	else   {
		r = sc_pkcs15_bind(card, NULL, &p15card);
	}

	if (r) {
		fprintf(stderr, "PKCS#15 binding failed: %s\n", sc_strerror(r));
		err = 1;
		goto end;
	}
	if (opt_no_cache)
		p15card->opts.use_file_cache = 0;
	if (verbose)
		fprintf(stderr, "Found %s!\n", p15card->tokeninfo->label);

	if (do_verify_pin)
		if ((err = verify_pin()))
			goto end;

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
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
	if (do_read_sshkey) {
		if ((err = read_ssh_key()))
			goto end;
		action_count--;
	}
#endif
	if (do_list_pins) {
		if ((err = list_pins()))
			goto end;
		action_count--;
	}
	if (do_list_skeys) {
		if ((err = list_skeys()))
			goto end;
		action_count--;
	}
	if (do_list_apps) {
		if ((err = list_apps(stdout)))
			goto end;
		action_count--;
	}
	if (do_dump) {
		if ((err = dump()))
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
	if (do_test_update || do_update) {
		err = test_update(card);
		action_count--;
		if (err == 2) { /* problem */
			err = 1;
			goto end;
		}
		if (do_update && err == 1) { /* card vulnerable */
			if ((err = update(card)))
				goto end;
		}
	}
end:
	if (p15card)
		sc_pkcs15_unbind(p15card);
	if (card)
		sc_disconnect_card(card);
	if (ctx)
		sc_release_context(ctx);
	return err;
}
