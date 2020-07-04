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

#ifdef __APPLE__
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif
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
#include "pkcs11/pkcs11-display.h"

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
static int	compact = 0;
static int	verbose = 0;
static int opt_use_pinpad = 0;
#if defined(ENABLE_OPENSSL) && (defined(_WIN32) || defined(HAVE_INTTYPES_H))
static int opt_rfc4716 = 0;
#endif

enum {
	OPT_CHANGE_PIN = 0x100,
	OPT_LIST_PINS,
	OPT_READER,
	OPT_TEST_SESSION_PIN,
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
	OPT_USE_PINPAD,
	OPT_USE_PINPAD_DEPRECATED,
	OPT_RAW,
	OPT_PRINT_VERSION,
	OPT_LIST_INFO,
	OPT_READ_CERT,
};

#define NELEMENTS(x)	(sizeof(x)/sizeof((x)[0]))

static int	authenticate(sc_pkcs15_object_t *obj);

static const struct option options[] = {
	{ "version",		0, NULL,			OPT_PRINT_VERSION },
	{ "list-info",	no_argument, NULL,		OPT_LIST_INFO },
	{ "list-applications",	no_argument, NULL,		OPT_LIST_APPLICATIONS },
	{ "read-certificate",	required_argument, NULL,	OPT_READ_CERT },
	{ "list-certificates",	no_argument, NULL,		'c' },
	{ "read-data-object",	required_argument, NULL,	'R' },
	{ "raw",		no_argument, NULL,		OPT_RAW },
	{ "list-data-objects",	no_argument, NULL,		'C' },
	{ "list-pins",		no_argument, NULL,		OPT_LIST_PINS },
	{ "list-secret-keys",	no_argument, NULL,		OPT_LIST_SKEYS },
	{ "short",			no_argument, NULL,		's' },
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
	{ "test-session-pin",	no_argument, NULL,		OPT_TEST_SESSION_PIN },
	{ "output",		required_argument, NULL,	'o' },
	{ "no-cache",		no_argument, NULL,		OPT_NO_CACHE },
	{ "clear-cache",	no_argument, NULL,		OPT_CLEAR_CACHE },
	{ "auth-id",		required_argument, NULL,	'a' },
	{ "aid",		required_argument, NULL,	OPT_BIND_TO_AID },
	{ "wait",		no_argument, NULL,		'w' },
	{ "verbose",		no_argument, NULL,		'v' },
	{ "use-pinpad",		no_argument, NULL,		OPT_USE_PINPAD },
	{ "no-prompt",		no_argument, NULL,		OPT_USE_PINPAD_DEPRECATED },
	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Print OpenSC package version",
	"List card information",
	"List the on-card PKCS#15 applications",
	"Read certificate with ID <arg>",
	"List certificates",
	"Reads data object with OID, applicationName or label <arg>",
	"Outputs raw 8 bit data to stdout. File output will not be affected by this, it always uses raw mode.",
	"List data objects",
	"List PIN codes",
	"List secret keys",
	"Output lists in compact format",
	"List all card objects",
	"Unblock PIN code",
	"Change PIN or PUK code",
	"List private keys",
	"List public keys",
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
	"Equivalent to --verify-pin with additional session PIN generation",
	"Outputs to file <arg>",
	"Disable card caching",
	"Clear card caching",
	"The auth ID of the PIN to use",
	"Specify AID of the on-card PKCS#15 application to bind to (in hexadecimal form)",
	"Wait for card insertion",
	"Verbose operation. Use several times to enable debug output.",
	"Do not prompt the user; if no PINs supplied, pinpad will be used.",
	NULL,
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

static const char *key_types[] = { "", "RSA", "DSA", "GOSTR3410", "EC", "", "", "" };

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
	printf("\tObject Flags   : [0x%02X]", obj->flags);
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

	if (compact) {
		printf("\tPath:%s  ID:%s", sc_print_path(&cert_info->path),
			sc_pkcs15_print_id(&cert_info->id));
		if (cert_info->authority)
			printf("  Authority");
		return;
	}

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
	if (compact)
		printf("Card has %d Certificate(s).\n", r);
	else if (verbose)
		printf("Card has %d Certificate(s).\n\n", r);
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
	if (compact)
		printf("Card has %d Data object(s).\n", count);
	else if (verbose)
		printf("Card has %d Data object(s).\n\n", count);
	for (i = 0; i < count; i++) {
		int idx;
		struct sc_pkcs15_data_info *cinfo = (struct sc_pkcs15_data_info *) objs[i]->data;

		if (compact) {
			printf("\tPath:%-12s", sc_print_path(&cinfo->path));
			if (sc_valid_oid(&cinfo->app_oid)) {
				printf("  %i", cinfo->app_oid.value[0]);
				for (idx = 1; idx < SC_MAX_OBJECT_ID_OCTETS && cinfo->app_oid.value[idx] != -1 ; idx++)
					printf(".%i", cinfo->app_oid.value[idx]);
			}
			if (objs[i]->auth_id.len == 0) {
				struct sc_pkcs15_data *data_object;
				r = sc_pkcs15_read_data_object(p15card, cinfo, &data_object);
				if (r) {
					fprintf(stderr, "Data object read failed: %s\n", sc_strerror(r));
					if (r == SC_ERROR_FILE_NOT_FOUND)
						continue; /* DEE emulation may say there is a file */
					return 1;
				}
				sc_pkcs15_free_data_object(data_object);
				printf("  Size:%5"SC_FORMAT_LEN_SIZE_T"u",
				       cinfo->data.len);
			} else {
				printf("  AuthID:%-3s", sc_pkcs15_print_id(&objs[i]->auth_id));
			}
			printf("  %-20s", cinfo->app_label);
			printf("\n");
			continue;
		}

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

		printf("\n");
	}
	return 0;
}

static void print_key_usages(int usage)
{
	size_t i;
	const char *usages[] = {
		"encrypt", "decrypt", "sign", "signRecover", "wrap", "unwrap",
		"verify", "verifyRecover", "derive", "nonRepudiation"
	};
	const size_t usage_count = NELEMENTS(usages);
	for (i = 0; i < usage_count; i++)
		if (usage & (1 << i))
			printf(", %s", usages[i]);
}

static void print_key_access_flags(int flags)
{
	size_t i;
	const char *key_access_flags[] = {
		"sensitive", "extract", "alwaysSensitive","neverExtract", "local"
	};
	const size_t af_count = NELEMENTS(key_access_flags);
	for (i = 0; i < af_count; i++)
		if (flags & (1 << i))
			printf(", %s", key_access_flags[i]);
}

static void print_prkey_info(const struct sc_pkcs15_object *obj)
{
	struct sc_pkcs15_prkey_info *prkey = (struct sc_pkcs15_prkey_info *) obj->data;
	unsigned char guid[40];
	size_t guid_len;
	int i;
	int last_algo_refs = 0;

	if (compact) {
		printf("\t%-3s", key_types[7 & obj->type]);

		if (prkey->modulus_length)
			printf("[%lu]", (unsigned long)prkey->modulus_length);
		else {
			if (prkey->field_length)
				printf("[%lu]", (unsigned long)prkey->field_length);
		}
		printf("  ID:%s", sc_pkcs15_print_id(&prkey->id));
		printf("  Ref:0x%02X", prkey->key_reference);
		if (obj->auth_id.len != 0)
			printf("  AuthID:%s", sc_pkcs15_print_id(&obj->auth_id));
		printf("\n\t     %-18.*s [0x%02X", (int) sizeof obj->label, obj->label, prkey->usage);
		print_key_usages(prkey->usage);
		printf("]");
		return;
	}

	printf("Private %s Key [%.*s]\n", key_types[7 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%02X]", prkey->usage);
	print_key_usages(prkey->usage);
	printf("\n");
	printf("\tAccess Flags   : [0x%02X]", prkey->access_flags);
	print_key_access_flags(prkey->access_flags);
	printf("\n");
	printf("\tAlgo_refs      : ");
	/* zero may be valid and don't know how many were read  print at least 1*/
	for (i = 0; i< SC_MAX_SUPPORTED_ALGORITHMS; i++) {
		if (prkey->algo_refs[i] != 0)
			last_algo_refs = i;
	}
	for (i = 0; i< last_algo_refs + 1; i++) {
		printf("%s%u", (i == 0) ? "" : ", ", prkey->algo_refs[i]);
	}
	printf("\n");

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	if (prkey->modulus_length)
		printf("\tModLength      : %lu\n", (unsigned long)prkey->modulus_length);
	else
		printf("\tFieldLength    : %lu\n", (unsigned long)prkey->field_length);
	printf("\tKey ref        : %d (0x%02X)\n", prkey->key_reference, prkey->key_reference);
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
	if (compact)
		printf("Card has %d Private key(s).\n", r);
	else if (verbose)
		printf("Card has %d Private key(s).\n\n", r);
	for (i = 0; i < r; i++) {
		print_prkey_info(objs[i]);
		printf("\n");
	}
	return 0;
}

static void print_pubkey_info(const struct sc_pkcs15_object *obj)
{
	const struct sc_pkcs15_pubkey_info *pubkey = (const struct sc_pkcs15_pubkey_info *) obj->data;
	int have_path = (pubkey->path.len != 0) || (pubkey->path.aid.len != 0);

	if (compact) {
		printf("\t%-3s", key_types[7 & obj->type]);

		if (pubkey->modulus_length)
			printf("[%lu]", (unsigned long)pubkey->modulus_length);
		else
			printf("[FieldLength:%lu]", (unsigned long)pubkey->field_length);
		printf("  %s", sc_pkcs15_print_id(&pubkey->id));
		printf("  Ref:0x%02X", pubkey->key_reference);
		if (obj->auth_id.len != 0)
			printf("  AuthID:%s", sc_pkcs15_print_id(&obj->auth_id));
		printf("  %-18.*s [0x%02X", (int) sizeof obj->label, obj->label, pubkey->usage);
		print_key_usages(pubkey->usage);
		printf("]");
		return;
	}

	printf("Public %s Key [%.*s]\n", key_types[7 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%02X]", pubkey->usage);
	print_key_usages(pubkey->usage);
	printf("\n");

	printf("\tAccess Flags   : [0x%02X]", pubkey->access_flags);
	print_key_access_flags(pubkey->access_flags);
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

	printf("\tKey ref        : %d (0x%02X)\n", pubkey->key_reference,  pubkey->key_reference);
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
	if (compact)
		printf("Card has %d Public key(s).\n", r);
	else if (verbose)
		printf("Card has %d Public key(s).\n\n", r);
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
		r = 2;
		goto out;
	}
	if (r < 0) {
		fprintf(stderr, "Public key enumeration failed: %s\n", sc_strerror(r));
		r = 1;
		goto out;
	}
	if (!pubkey) {
		fprintf(stderr, "Public key not available\n");
		r = 1;
		goto out;
	}

	r = sc_pkcs15_encode_pubkey_as_spki(ctx, pubkey, &pem_key.value, &pem_key.len);
	if (r < 0) {
		fprintf(stderr, "Error encoding PEM key: %s\n", sc_strerror(r));
		r = 1;
	} else {
		r = print_pem_object("PUBLIC KEY", pem_key.value, pem_key.len);
		free(pem_key.value);
	}

out:
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else
		sc_pkcs15_free_pubkey(pubkey);

	return r;
}

static void print_skey_info(const struct sc_pkcs15_object *obj)
{
	static const char *skey_types[] = { "", "Generic", "DES", "2DES", "3DES", "", "", "" };
	struct sc_pkcs15_skey_info *skey = (struct sc_pkcs15_skey_info *) obj->data;
	unsigned char guid[40];
	size_t guid_len;

	printf("Secret %s Key [%.*s]\n", skey_types[7 & obj->type], (int) sizeof obj->label, obj->label);
	print_common_flags(obj);
	printf("\tUsage          : [0x%02X]", skey->usage);
	print_key_usages(skey->usage);
	printf("\n");

	printf("\tAccess Flags   : [0x%02X]", skey->access_flags);
	print_key_access_flags(skey->access_flags);
	printf("\n");

	print_access_rules(obj->access_rules, SC_PKCS15_MAX_ACCESS_RULES);

	printf("\tSize           : %lu bits\n", (unsigned long)skey->value_len);
	printf("\tID             : %s\n", sc_pkcs15_print_id(&skey->id));
	printf("\tNative         : %s\n", skey->native ? "yes" : "no");
	printf("\tKey ref        : %d (0x%02X)\n", skey->key_reference, skey->key_reference);

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
		printf("Card has %d Secret key(s).\n\n", r);
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
	if (!uu)
		return;

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
			fprintf(outf,"%s %s %.*s\n", alg, uu, (int) sizeof obj->label, obj->label);
		else
			fprintf(outf,"%s %s\n", alg, uu);
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

	if (pubkey->algorithm == SC_ALGORITHM_EC) {
		// support only for NIST
		// 'ssh-keygen -t ecdsa' allow only field lengths 256/384/521

		static struct supported_ec_curves {
			char *curve_name;
			struct sc_object_id curve_oid;
			size_t size;
		} ec_curves[] = {
			{"secp256r1", {{1, 2, 840, 10045, 3, 1, 7, -1}},256},
			{"secp384r1", {{1, 3, 132, 0, 34, -1}},         384},
			{"secp521r1", {{1, 3, 132, 0, 35, -1}},         521},
		        {NULL, {{-1}}, 0},
		};
		char alg[20];
		/* Large enough to fit the following:
		 * 3 x 4B item length headers
		 * max 20B algorithm name, 9B curve name, max 256B key data */
		unsigned char buf[300];
		unsigned int i, len, tmp, n;

		for (n = 0,i = 0; ec_curves[i].curve_name != NULL; i++) {
			if(sc_compare_oid (&ec_curves[i].curve_oid,&pubkey->u.ec.params.id))
				n = ec_curves[i].size;
		}
		if (!n) {
			fprintf(stderr, "Unsupported curve\n");
			goto fail2;
		}
		if (n != pubkey->u.ec.params.field_length) {
			fprintf(stderr, "Wrong field length\n");
			goto fail2;
		}

		buf[0] = 0;
		buf[1] = 0;
		buf[2] = 0;
		len = snprintf((char *) buf+4, 20, "ecdsa-sha2-nistp%d", n);
		memcpy(alg, buf+4, 20);
		buf[3] = len;

		len += 4;
		buf[len++] = 0;
		buf[len++] = 0;
		buf[len++] = 0;
		tmp = snprintf((char *) buf+len+1, 9, "nistp%d", n);
		buf[len++] = tmp;
		len += tmp;

		n = pubkey->u.ec.ecpointQ.len;
		if(n > 255) {
			fprintf(stderr, "Wrong public key length\n");
			goto fail2;
		}
		buf[len++] = 0;
		buf[len++] = 0;
		buf[len++] = 0;
		buf[len++] = n & 0xff;
		memcpy(buf+len,pubkey->u.ec.ecpointQ.value,n);
		len += n;

		print_ssh_key(outf, alg, obj, buf, len);
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

		print_ssh_key(outf, "ssh-rsa", obj, buf, len);
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

		print_ssh_key(outf, "ssh-dss", obj, buf, len);
	}

	if (outf != stdout)
		fclose(outf);
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else
		sc_pkcs15_free_pubkey(pubkey);
	return 0;
fail:
	printf("can't convert key: buffer too small\n");
fail2:
	if (outf && outf != stdout)
		fclose(outf);
	if (cert)
		sc_pkcs15_free_certificate(cert);
	else
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

	if (opt_use_pinpad) {
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
	if (opt_pin == NULL)
		free(pin);
	if (r < 0)   {
		fprintf(stderr, "Operation failed: %s\n", sc_strerror(r));
		return -1;
	}

	return 0;
}

static int test_session_pin(void)
{
	struct sc_pkcs15_object	*pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	unsigned int  auth_method;
	unsigned char		*pin;
	int r;
	unsigned char sessionpin[SC_MAX_PIN_SIZE];
	size_t sessionpinlen = sizeof sessionpin;

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

	if (!(card->caps & SC_CARD_CAP_SESSION_PIN)) {
		fprintf(stderr, "Card does not support session PIN. Will try anyway.\n");
	}

	if (!pin_obj)   {
		fprintf(stderr, "PIN object '%s' not found\n", opt_auth_id);
		return -1;
	}

	if (opt_pin != NULL)
		pin = (unsigned char *) opt_pin;
	else
		pin = get_pin("Please enter PIN", pin_obj);

	r = sc_pkcs15_verify_pin_with_session_pin(p15card, pin_obj, pin, pin ? strlen((char *) pin) : 0,
			sessionpin, &sessionpinlen);
	if (opt_pin == NULL)
		free(pin);
	if (r < 0)   {
		fprintf(stderr, "Operation failed: %s\n", sc_strerror(r));
		return -1;
	}

	if (!sessionpinlen)   {
		fprintf(stderr, "Could not generate session PIN\n");
		return -1;
	}

	printf("Generated session PIN (in hexadecimal form): ");
	util_hex_dump(stdout, sessionpin, sessionpinlen, "");
	puts("");

	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
	/* save the pin type */
	auth_method = auth_info->auth_method;
	auth_info->auth_method = SC_AC_SESSION;
	r = sc_pkcs15_verify_pin(p15card, pin_obj, sessionpin, sessionpinlen);
	/* restore the pin type */
	auth_info->auth_method = auth_method;
	if (r < 0)   {
		fprintf(stderr, "Could not verify session PIN: %s\n", sc_strerror(r));
		return -1;
	}

	puts("Verified session PIN");

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

	assert(obj->type == SC_PKCS15_TYPE_AUTH_PIN || obj->type == SC_PKCS15_TYPE_AUTH_AUTHKEY);

	if (compact) {
		printf("\t%-3s  ID:%s", obj->type == SC_PKCS15_TYPE_AUTH_PIN ? "PIN" : "Key",
			sc_pkcs15_print_id(&auth_info->auth_id));
		if (auth_info->auth_type == SC_PKCS15_PIN_AUTH_TYPE_PIN) {
			const struct sc_pkcs15_pin_attributes *pin_attrs = &(auth_info->attrs.pin);
			printf("  Ref:0x%02X", pin_attrs->reference);
		}
		else {
			const struct sc_pkcs15_authkey_attributes *attrs = &auth_info->attrs.authkey;
			printf("  Derived:%i", attrs->derived);
			printf("  SecretKeyID:%s", sc_pkcs15_print_id(&attrs->skey_id));
		}
		if (obj->auth_id.len)
			printf("  AuthID:%s", sc_pkcs15_print_id(&obj->auth_id));
		if (auth_info->path.len || auth_info->path.aid.len)
			printf("  Path:%s", sc_print_path(&auth_info->path));
		if (auth_info->tries_left >= 0)
			printf("  Tries:%d", auth_info->tries_left);
		printf("  %.*s", (int) sizeof obj->label, obj->label);
		return;
	}

	printf("%s [%.*s]\n", obj->type == SC_PKCS15_TYPE_AUTH_PIN ? "PIN" : "AuthKey",
		(int) sizeof obj->label, obj->label);

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
	if (compact)
		printf("Card has %d Authentication object(s).\n", r);
	else if (verbose)
		printf("Card has %d Authentication object(s).\n\n", r);

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


static void print_supported_algo_info_operations(unsigned int operation)

{
	size_t i;
	const char *operations[] = {
		"compute_checksum", "compute_signature", "verify_checksum", "verify_signature",
		"encipher", "decipher", "hash", "generate/derive_key"
	};
	const size_t operations_count = NELEMENTS(operations);
	for (i = 0; i < operations_count; i++)
		if (operation & (1 << i))
			printf(", %s", operations[i]);
}

static void list_info(void)
{
	const char *flags[] = {
		"Read-only",
		"Login required",
		"PRN generation",
		"EID compliant"
	};
	char *last_update = sc_pkcs15_get_lastupdate(p15card);
	int i, count = 0;
	int idx;

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
	printf("\n");
	for (i = 0; i < SC_MAX_SUPPORTED_ALGORITHMS; i++) {
		struct sc_supported_algo_info * sa = &p15card->tokeninfo->supported_algos[i];

		if (sa->reference == 0 && sa->mechanism == 0
				&& sa->operations == 0 && sa->algo_ref == 0)
					break;
		printf("\t\t sc_supported_algo_info[%d]:\n", i);
		printf("\t\t\t reference  : %u (0x%02x)\n", sa->reference, sa->reference);
		printf("\t\t\t mechanism  : [0x%02x] %s\n", sa->mechanism, lookup_enum(MEC_T, sa->mechanism));
		if (sc_valid_oid(&sa->parameters)) {
			printf("\t\t\t parameters:  %i", sa->parameters.value[0]);
			for (idx = 1; idx < SC_MAX_OBJECT_ID_OCTETS && sa->parameters.value[idx] != -1 ; idx++)
				printf(".%i", sa->parameters.value[idx]);
			printf("\n");
		}
		printf("\t\t\t operations : [0x%2.2x]",sa->operations);
		print_supported_algo_info_operations(sa->operations);
		printf("\n");
		if (sc_valid_oid((const struct sc_object_id*)&sa->algo_id)) {
			printf("\t\t\t algo_id    : %i", sa->algo_id.value[0]);
			for (idx = 1; idx < SC_MAX_OBJECT_ID_OCTETS && sa->algo_id.value[idx] != -1 ; idx++)
				printf(".%i", sa->algo_id.value[idx]);
			printf("\n");
		}
		printf("\t\t\t algo_ref   : [0x%02x]\n",sa->algo_ref);
	}

	printf((compact) ? "\n" : "\n\n");
}

static int dump(void)
{
	list_info();
	list_pins();
	list_private_keys();
	list_public_keys();
	list_skeys();
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

	pinpad_present = p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD
	   	|| p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH;

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
			if (r < 0)   {
				fprintf(stderr, "Failed to find PUK object for PIN: %s\n", sc_strerror(r));
				return 2;
			}
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

	pinpad_present = p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD
	   	|| p15card->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH;

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

int main(int argc, char *argv[])
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
	int do_test_session_pin = 0;
	int do_update = 0;
	int do_print_version = 0;
	int do_list_info = 0;
	int action_count = 0;
	sc_context_param_t ctx_param;

	assert(sizeof(option_help)/sizeof(char *)==sizeof(options)/sizeof(struct option));

	while (1) {
		c = getopt_long(argc, argv, "r:cuko:sva:LR:CwDTU", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?')
			util_print_usage_and_die(app_name, options, option_help, NULL);
		switch (c) {
		case 'r':

#if OPENSC_MAJOR == 0 &&  OPENSC_VERSION_MINOR == 19
			fprintf(stderr, "\nWarning, option -r is reserved to specify card reader in future versions\n");
			fprintf (stderr, "Using -r option for read-certificate operation\n\n");
			opt_cert = optarg;
			do_read_cert = 1;
			action_count++;
			break;
#elif OPENSC_MAJOR == 0 &&  OPENSC_VERSION_MINOR == 20

			memset(&ctx_param, 0, sizeof(ctx_param));
			ctx_param.ver      = 0;
			ctx_param.app_name = app_name;

			if (SC_SUCCESS == sc_context_create(&ctx, &ctx_param)) {
				/* attempt to connect reader, on error, -r is used for read-certificate operation */
				struct sc_reader *reader = NULL;

				err = util_connect_reader(ctx, &reader, optarg, 0, 0);
				sc_release_context(ctx);
				ctx = NULL;

				if (err != SC_SUCCESS ) {
#if 1
					fprintf (stderr,
						"Error, option -r is reserved to specify card reader, no reader \"%s\" found\n", optarg);
					exit (1);
#else
					fprintf (stderr,
						"\nWarning, option -r is reserved to specify card reader, no reader \"%s\" found\n", optarg);
					fprintf (stderr, "Using -r option for read-certificate operation\n\n");
					opt_cert = optarg;
					do_read_cert = 1;
					action_count++;
					break;
#endif
				}
			}
			opt_reader = optarg;
			break;
#elif (OPENSC_MAJOR > 0) || (OPENSC_MAJOR == 0 && OPENSC_VERSION_MINOR > 20)

			opt_reader = optarg;
			break;
#endif

		case OPT_PRINT_VERSION:
			do_print_version = 1;
			action_count++;
			break;
		case OPT_LIST_INFO:
			do_list_info = 1;
			action_count++;
			break;
		case OPT_READ_CERT:
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
		case OPT_TEST_SESSION_PIN:
			do_test_session_pin = 1;
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
		case 's':
			compact++;
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
		case OPT_USE_PINPAD_DEPRECATED:
			fprintf(stderr, "'--no-prompt' is deprecated , use '--use-pinpad' instead.\n");
			/* fallthrough */
		case OPT_USE_PINPAD:
			opt_use_pinpad = 1;
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

	if (do_list_info) {
		if (!do_dump)
			list_info();
		action_count--;
	}

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
	if (do_test_session_pin) {
		if ((err = test_session_pin()))
			goto end;
		action_count--;
	}
end:
	sc_pkcs15_unbind(p15card);
	sc_disconnect_card(card);
	sc_release_context(ctx);
	return err;
}
