/*
 * pkcs11-tool.c: Tool for poking around pkcs11 modules/tokens
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
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

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/opensslconf.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#include <openssl/conf.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/err.h>
#endif

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11-opensc.h"
#include "libopensc/asn1.h"
#include "common/compat_strlcat.h"
#include "common/compat_strlcpy.h"
#include "util.h"

extern void *C_LoadModule(const char *name, CK_FUNCTION_LIST_PTR_PTR);
extern CK_RV C_UnloadModule(void *module);

#define NEED_SESSION_RO	0x01
#define NEED_SESSION_RW	0x02

static struct ec_curve_info {
	const char *name;
	const char *oid;
	const char *oid_encoded;
	size_t size;
} ec_curve_infos[] = {
	{"secp192r1",    "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"prime192v1",   "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"nistp192",     "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"ansiX9p192r1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},

	{"secp224r1", "1.3.132.0.33", "06052b81040021", 224},
	{"nistp224",  "1.3.132.0.33", "06052b81040021", 224},

	{"prime256v1",   "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"secp256r1",    "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"ansiX9p256r1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},

	{"secp384r1",		"1.3.132.0.34", "06052B81040022", 384},
	{"prime384v1",		"1.3.132.0.34", "06052B81040022", 384},
	{"ansiX9p384r1",	"1.3.132.0.34", "06052B81040022", 384},

	{"secp521r1", "1.3.132.0.35", "06052B81040023", 521},
	{"nistp521",  "1.3.132.0.35", "06052B81040023", 521},

	{"brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", "06092B2403030208010103", 192},
	{"brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", "06092B2403030208010105", 224},
	{"brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", "06092B2403030208010107", 256},
	{"brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", "06092B2403030208010109", 320},

	{"secp192k1",		"1.3.132.0.31", "06052B8104001F", 192},
	{"secp256k1",		"1.3.132.0.10", "06052B8104000A", 256},
	{NULL, NULL, NULL, 0},
};

enum {
	OPT_MODULE = 0x100,
	OPT_SLOT,
	OPT_SLOT_DESCRIPTION,
	OPT_SLOT_INDEX,
	OPT_TOKEN_LABEL,
	OPT_APPLICATION_LABEL,
	OPT_APPLICATION_ID,
	OPT_ISSUER,
	OPT_SUBJECT,
	OPT_SO_PIN,
	OPT_INIT_TOKEN,
	OPT_INIT_PIN,
	OPT_ATTR_FROM,
	OPT_KEY_TYPE,
	OPT_KEY_USAGE_SIGN,
	OPT_KEY_USAGE_DECRYPT,
	OPT_KEY_USAGE_DERIVE,
	OPT_PRIVATE,
	OPT_TEST_HOTPLUG,
	OPT_UNLOCK_PIN,
	OPT_PUK,
	OPT_NEW_PIN,
	OPT_LOGIN_TYPE,
	OPT_TEST_EC,
	OPT_DERIVE,
	OPT_DECRYPT,
	OPT_TEST_FORK,
};

static const struct option options[] = {
	{ "module",		1, NULL,		OPT_MODULE },
	{ "show-info",		0, NULL,		'I' },
	{ "list-slots",		0, NULL,		'L' },
	{ "list-token-slots",	0, NULL,		'T' },
	{ "list-mechanisms",	0, NULL,		'M' },
	{ "list-objects",	0, NULL,		'O' },

	{ "sign",		0, NULL,		's' },
	{ "decrypt",		0, NULL,		OPT_DECRYPT },
	{ "hash",		0, NULL,		'h' },
	{ "derive",		0, NULL,		OPT_DERIVE },
	{ "mechanism",		1, NULL,		'm' },

	{ "login",		0, NULL,		'l' },
	{ "login-type",         1, NULL,                OPT_LOGIN_TYPE },
	{ "pin",		1, NULL,		'p' },
	{ "puk",		1, NULL,		OPT_PUK },
	{ "new-pin",		1, NULL,		OPT_NEW_PIN },
	{ "so-pin",		1, NULL,		OPT_SO_PIN },
	{ "init-token",		0, NULL,		OPT_INIT_TOKEN },
	{ "init-pin",		0, NULL,		OPT_INIT_PIN },
	{ "change-pin",		0, NULL,		'c' },
	{ "unlock-pin",		0, NULL,		OPT_UNLOCK_PIN },
	{ "keypairgen",		0, NULL,		'k' },
	{ "key-type",		1, NULL,		OPT_KEY_TYPE },
	{ "usage-sign",		0, NULL,		OPT_KEY_USAGE_SIGN },
	{ "usage-decrypt",	0, NULL,		OPT_KEY_USAGE_DECRYPT },
	{ "usage-derive",	0, NULL,		OPT_KEY_USAGE_DERIVE },
	{ "write-object",	1, NULL,		'w' },
	{ "read-object",	0, NULL,		'r' },
	{ "delete-object",	0, NULL,		'b' },
	{ "application-label",	1, NULL,		OPT_APPLICATION_LABEL },
	{ "application-id",	1, NULL,		OPT_APPLICATION_ID },
	{ "issuer",		1, NULL,		OPT_ISSUER },
	{ "subject",		1, NULL,		OPT_SUBJECT },
	{ "type",		1, NULL,		'y' },
	{ "id",			1, NULL,		'd' },
	{ "label",		1, NULL,		'a' },
	{ "slot",		1, NULL,		OPT_SLOT },
	{ "slot-description",	1, NULL,		OPT_SLOT_DESCRIPTION },
	{ "slot-index",		1, NULL,		OPT_SLOT_INDEX },
	{ "token-label",	1, NULL,		OPT_TOKEN_LABEL },
	{ "set-id",		1, NULL,		'e' },
	{ "attr-from",		1, NULL,		OPT_ATTR_FROM },
	{ "input-file",		1, NULL,		'i' },
	{ "output-file",	1, NULL,		'o' },
	{ "signature-format",	1, NULL,		'f' },

	{ "test",		0, NULL,		't' },
	{ "test-hotplug",	0, NULL,		OPT_TEST_HOTPLUG },
	{ "moz-cert",		1, NULL,		'z' },
	{ "verbose",		0, NULL,		'v' },
	{ "private",		0, NULL,		OPT_PRIVATE },
	{ "test-ec",		0, NULL,		OPT_TEST_EC },
#ifndef _WIN32
	{ "test-fork",		0, NULL,		OPT_TEST_FORK },
#endif

	{ NULL, 0, NULL, 0 }
};

static const char *option_help[] = {
	"Specify the module to load (default:" DEFAULT_PKCS11_PROVIDER ")",
	"Show global token information",
	"List available slots",
	"List slots with tokens",
	"List mechanisms supported by the token",
	"Show objects on token",

	"Sign some data",
	"Decrypt some data",
	"Hash some data",
	"Derive a secret key using another key and some data",
	"Specify mechanism (use -M for a list of supported mechanisms)",

	"Log into the token first",
	"Specify login type ('so', 'user', 'context-specific'; default:'user')",
	"Supply User PIN on the command line (if used in scripts: careful!)",
	"Supply User PUK on the command line",
	"Supply new User PIN on the command line",
	"Supply SO PIN on the command line (if used in scripts: careful!)",
	"Initialize the token, its label and its SO PIN (use with --label and --so-pin)",
	"Initialize the User PIN (use with --pin and --login)",
	"Change User PIN",
	"Unlock User PIN (without '--login' unlock in logged in session; otherwise '--login-type' has to be 'context-specific')",
	"Key pair generation",
	"Specify the type and length of the key to create, for example rsa:1024 or EC:prime256v1",
	"Specify 'sign' key usage flag (sets SIGN in privkey, sets VERIFY in pubkey)",
	"Specify 'decrypt' key usage flag (RSA only, set DECRYPT privkey, ENCRYPT in pubkey)",
	"Specify 'derive' key usage flag (EC only)",
	"Write an object (key, cert, data) to the card",
	"Get object's CKA_VALUE attribute (use with --type)",
	"Delete an object",
	"Specify the application label of the data object (use with --type data)",
	"Specify the application ID of the data object (use with --type data)",
	"Specify the issuer in hexadecimal format (use with --type cert)",
	"Specify the subject in hexadecimal format (use with --type cert/privkey/pubkey)",
	"Specify the type of object (e.g. cert, privkey, pubkey, data)",
	"Specify the ID of the object",
	"Specify the label of the object",
	"Specify the ID of the slot to use",
	"Specify the description of the slot to use",
	"Specify the index of the slot to use",
	"Specify the token label of the slot to use",
	"Set the CKA_ID of an object, <args>= the (new) CKA_ID",
	"Use <arg> to create some attributes when writing an object",
	"Specify the input file",
	"Specify the output file",
	"Format for ECDSA signature <arg>: 'rs' (default), 'sequence', 'openssl'",

	"Test (best used with the --login or --pin option)",
	"Test hotplug capabilities (C_GetSlotList + C_WaitForSlotEvent)",
	"Test Mozilla-like keypair gen and cert req, <arg>=certfile",
	"Verbose operation. (Set OPENSC_DEBUG to enable OpenSC specific debugging)",
	"Set the CKA_PRIVATE attribute (object is only viewable after a login)",
	"Test EC (best used with the --login or --pin option)",
#ifndef _WIN32
	"Test forking and calling C_Initialize() in the child",
#endif
};

static const char *	app_name = "pkcs11-tool"; /* for utils.c */

static int		verbose = 0;
static const char *	opt_input = NULL;
static const char *	opt_output = NULL;
static const char *	opt_module = DEFAULT_PKCS11_PROVIDER;
static int		opt_slot_set = 0;
static CK_SLOT_ID	opt_slot = 0;
static const char *	opt_slot_description = NULL;
static const char *	opt_token_label = NULL;
static CK_ULONG		opt_slot_index = 0;
static int		opt_slot_index_set = 0;
static CK_MECHANISM_TYPE opt_mechanism = 0;
static int		opt_mechanism_used = 0;
static const char *	opt_file_to_write = NULL;
static const char *	opt_object_class_str = NULL;
static CK_OBJECT_CLASS	opt_object_class = -1;
static CK_BYTE		opt_object_id[100], new_object_id[100];
static const char *	opt_attr_from_file = NULL;
static size_t		opt_object_id_len = 0, new_object_id_len = 0;
static char *		opt_object_label = NULL;
static const char *	opt_pin = NULL;
static const char *	opt_so_pin = NULL;
static const char *	opt_puk = NULL;
static const char *	opt_new_pin = NULL;
static char *		opt_application_label = NULL;
static char *		opt_application_id = NULL;
static char *		opt_issuer = NULL;
static char *		opt_subject = NULL;
static char *		opt_key_type = NULL;
static char *		opt_sig_format = NULL;
static int		opt_is_private = 0;
static int		opt_test_hotplug = 0;
static int		opt_login_type = -1;
static int		opt_key_usage_sign = 0;
static int		opt_key_usage_decrypt = 0;
static int		opt_key_usage_derive = 0;
static int		opt_key_usage_default = 1; /* uses defaults if no opt_key_usage options */

static void *module = NULL;
static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_SLOT_ID_PTR p11_slots = NULL;
static CK_ULONG p11_num_slots = 0;
static int suppress_warn = 0;

struct flag_info {
	CK_FLAGS	value;
	const char *	name;
};
struct mech_info {
	CK_MECHANISM_TYPE mech;
	const char *	name;
	const char *	short_name;
};
struct x509cert_info {
	unsigned char	subject[256];
	int		subject_len;
	unsigned char	issuer[256];
	int		issuer_len;
	unsigned char	serialnum[128];
	int		serialnum_len;
};
struct rsakey_info {
	unsigned char	*modulus;
	int		modulus_len;
	unsigned char	*public_exponent;
	int		public_exponent_len;
	unsigned char	*private_exponent;
	int		private_exponent_len;
	unsigned char	*prime_1;
	int		prime_1_len;
	unsigned char	*prime_2;
	int		prime_2_len;
	unsigned char	*exponent_1;
	int		exponent_1_len;
	unsigned char	*exponent_2;
	int		exponent_2_len;
	unsigned char	*coefficient;
	int		coefficient_len;
};
struct gostkey_info {
	struct sc_lv_data param_oid;
	struct sc_lv_data public;
	struct sc_lv_data private;
};

static void		show_cryptoki_info(void);
static void		list_slots(int, int, int);
static void		show_token(CK_SLOT_ID);
static void		list_mechs(CK_SLOT_ID);
static void		list_objects(CK_SESSION_HANDLE, CK_OBJECT_CLASS);
static int		login(CK_SESSION_HANDLE, int);
static void		init_token(CK_SLOT_ID);
static void		init_pin(CK_SLOT_ID, CK_SESSION_HANDLE);
static int		change_pin(CK_SLOT_ID, CK_SESSION_HANDLE);
static int		unlock_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess, int login_type);
static void		show_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_key(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_cert(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_dobj(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
static void		sign_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		decrypt_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		hash_data(CK_SLOT_ID, CK_SESSION_HANDLE);
static void		derive_key(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static int		gen_keypair(CK_SESSION_HANDLE,
				CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *, const char *);
static int		write_object(CK_SESSION_HANDLE session);
static int		read_object(CK_SESSION_HANDLE session);
static int		delete_object(CK_SESSION_HANDLE session);
static void		set_id_attr(CK_SESSION_HANDLE session);
static int		find_object(CK_SESSION_HANDLE, CK_OBJECT_CLASS,
				CK_OBJECT_HANDLE_PTR,
				const unsigned char *, size_t id_len, int obj_index);
static int		find_mechanism(CK_SLOT_ID, CK_FLAGS, CK_MECHANISM_TYPE_PTR, size_t, CK_MECHANISM_TYPE_PTR);
static int		find_slot_by_description(const char *, CK_SLOT_ID_PTR);
static int		find_slot_by_token_label(const char *, CK_SLOT_ID_PTR);
static void		get_token_info(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
static CK_ULONG		get_mechanisms(CK_SLOT_ID,
				CK_MECHANISM_TYPE_PTR *, CK_FLAGS);
static void		p11_fatal(const char *, CK_RV);
static void		p11_warn(const char *, CK_RV);
static const char *	p11_slot_info_flags(CK_FLAGS);
static const char *	p11_token_info_flags(CK_FLAGS);
static const char *	p11_utf8_to_local(CK_UTF8CHAR *, size_t);
static const char *	p11_flag_names(struct flag_info *, CK_FLAGS);
static const char *	p11_mechanism_to_name(CK_MECHANISM_TYPE);
static CK_MECHANISM_TYPE p11_name_to_mechanism(const char *);
static void		p11_perror(const char *, CK_RV);
static const char *	CKR2Str(CK_ULONG res);
static int		p11_test(CK_SESSION_HANDLE session);
static int test_card_detection(int);
static int		hex_to_bin(const char *in, CK_BYTE *out, size_t *outlen);
static void		test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static void		test_ec(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
#ifndef _WIN32
static void		test_fork(void);
#endif
static CK_RV		find_object_with_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *out,
				CK_ATTRIBUTE *attrs, CK_ULONG attrsLen, CK_ULONG obj_index);
static CK_ULONG		get_private_key_length(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE prkey);

/* win32 needs this in open(2) */
#ifndef O_BINARY
# define O_BINARY 0
#endif

int main(int argc, char * argv[])
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	int err = 0, c, long_optind = 0;
	int do_show_info = 0;
	int do_list_slots = 0;
	int list_token_slots = 0;
	int do_list_mechs = 0;
	int do_list_objects = 0;
	int do_sign = 0;
	int do_decrypt = 0;
	int do_hash = 0;
	int do_derive = 0;
	int do_gen_keypair = 0;
	int do_write_object = 0;
	int do_read_object = 0;
	int do_delete_object = 0;
	int do_set_id = 0;
	int do_test = 0;
	int do_test_kpgen_certwrite = 0;
	int do_test_ec = 0;
#ifndef _WIN32
	int do_test_fork = 0;
#endif
	int need_session = 0;
	int opt_login = 0;
	int do_init_token = 0;
	int do_init_pin = 0;
	int do_change_pin = 0;
	int do_unlock_pin = 0;
	int action_count = 0;
	CK_RV rv;

#ifdef _WIN32
	if(_setmode(_fileno(stdout), _O_BINARY ) == -1)
		util_fatal("Cannot set FMODE to O_BINARY");
	if(_setmode(_fileno(stdin), _O_BINARY ) == -1)
		util_fatal("Cannot set FMODE to O_BINARY");
#endif

#ifdef ENABLE_OPENSSL
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
	OPENSSL_config(NULL);
#endif
	/* OpenSSL magic */
	SSLeay_add_all_algorithms();
	CRYPTO_malloc_init();
#endif
	while (1) {
		c = getopt_long(argc, argv, "ILMOTa:bd:e:hi:klm:o:p:scvf:ty:w:z:r",
		                options, &long_optind);
		if (c == -1)
			break;
		switch (c) {
		case 'I':
			do_show_info = 1;
			action_count++;
			break;
		case 'L':
			do_list_slots = 1;
			action_count++;
			break;
		case 'T':
			do_list_slots = 1;
			list_token_slots = 1;
			action_count++;
			break;
		case 'M':
			do_list_mechs = 1;
			action_count++;
			break;
		case 'O':
			need_session |= NEED_SESSION_RO;
			do_list_objects = 1;
			action_count++;
			break;
		case 'h':
			need_session |= NEED_SESSION_RO;
			do_hash = 1;
			action_count++;
			break;
		case 'k':
			need_session |= NEED_SESSION_RW;
			do_gen_keypair = 1;
			action_count++;
			break;
		case 'w':
			need_session |= NEED_SESSION_RW;
			do_write_object = 1;
			opt_file_to_write = optarg;
			action_count++;
			break;
		case 'r':
			need_session |= NEED_SESSION_RO;
			do_read_object = 1;
			action_count++;
			break;
		case 'b':
			need_session |= NEED_SESSION_RW;
			do_delete_object = 1;
			action_count++;
			break;
		case 'e':
			need_session |= NEED_SESSION_RW;
			do_set_id = 1;
			new_object_id_len = sizeof(new_object_id);
			if (!hex_to_bin(optarg, new_object_id, &new_object_id_len)) {
				printf("Invalid ID \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			action_count++;
			break;
		case OPT_ATTR_FROM:
			opt_attr_from_file = optarg;
			break;
		case 'y':
			opt_object_class_str = optarg;
			if (strcmp(optarg, "cert") == 0)
				opt_object_class = CKO_CERTIFICATE;
			else if (strcmp(optarg, "privkey") == 0)
				opt_object_class = CKO_PRIVATE_KEY;
			else if (strcmp(optarg, "pubkey") == 0)
				opt_object_class = CKO_PUBLIC_KEY;
			else if (strcmp(optarg, "data") == 0)
				opt_object_class = CKO_DATA;
			else {
				printf("Unsupported object type \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			break;
		case 'd':
			opt_object_id_len = sizeof(opt_object_id);
			if (!hex_to_bin(optarg, opt_object_id, &opt_object_id_len)) {
				printf("Invalid ID \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			break;
		case 'a':
			opt_object_label = optarg;
			break;
		case 'i':
			opt_input = optarg;
			break;
		case 'l':
			need_session |= NEED_SESSION_RW;
			opt_login = 1;
			break;
		case 'm':
			opt_mechanism_used = 1;
			opt_mechanism = p11_name_to_mechanism(optarg);
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 'p':
			util_get_pin(optarg, &opt_pin);
			break;
		case 'c':
			do_change_pin = 1;
			need_session |= NEED_SESSION_RW;
			action_count++;
			break;
		case OPT_UNLOCK_PIN:
			do_unlock_pin = 1;
			need_session |= NEED_SESSION_RW;
			action_count++;
			break;
		case 's':
			need_session |= NEED_SESSION_RW;
			do_sign = 1;
			action_count++;
			break;
		case OPT_DECRYPT:
			need_session |= NEED_SESSION_RW;
			do_decrypt = 1;
			action_count++;
			break;
		case 'f':
			opt_sig_format = optarg;
			break;
		case 't':
			need_session |= NEED_SESSION_RO;
			do_test = 1;
			action_count++;
			break;
		case 'z':
			do_test_kpgen_certwrite = 1;
			opt_file_to_write = optarg;
			action_count++;
			break;
		case 'v':
			verbose++;
			break;
		case OPT_SLOT:
			opt_slot = (CK_SLOT_ID) strtoul(optarg, NULL, 0);
			opt_slot_set = 1;
			if (verbose)
				fprintf(stderr, "Using slot with ID 0x%lx\n", opt_slot);
			break;
		case OPT_SLOT_DESCRIPTION:
			if (opt_slot_set) {
				fprintf(stderr, "Error: Only one of --slot, --slot-label, --slot-index or --token-label can be used\n");
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			opt_slot_description = optarg;
			break;
		case OPT_SLOT_INDEX:
			if (opt_slot_set || opt_slot_description) {
				fprintf(stderr, "Error: Only one of --slot, --slot-label, --slot-index or --token-label can be used\n");
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			opt_slot_index = (CK_ULONG) strtoul(optarg, NULL, 0);
			opt_slot_index_set = 1;
			break;
		case OPT_TOKEN_LABEL:
			if (opt_slot_set || opt_slot_description || opt_slot_index_set) {
				fprintf(stderr, "Error: Only one of --slot, --slot-label, --slot-index or --token-label can be used\n");
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			opt_token_label = optarg;
			break;
		case OPT_MODULE:
			opt_module = optarg;
			break;
		case OPT_APPLICATION_LABEL:
			opt_application_label = optarg;
			break;
		case OPT_APPLICATION_ID:
			opt_application_id = optarg;
			break;
		case OPT_ISSUER:
			opt_issuer = optarg;
			break;
		case OPT_SUBJECT:
			opt_subject = optarg;
			break;
		case OPT_NEW_PIN:
			util_get_pin(optarg, &opt_new_pin);
			break;
		case OPT_PUK:
			util_get_pin(optarg, &opt_puk);
			break;
		case OPT_LOGIN_TYPE:
			if (!strcmp(optarg, "so"))
				opt_login_type = CKU_SO;
			else if (!strcmp(optarg, "user"))
				opt_login_type = CKU_USER;
			else if (!strcmp(optarg, "context-specific"))
				opt_login_type = CKU_CONTEXT_SPECIFIC;
			else {
				printf("Unsupported login type \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			break;
		case OPT_SO_PIN:
			util_get_pin(optarg, &opt_so_pin);
			break;
		case OPT_INIT_TOKEN:
			do_init_token = 1;
			action_count++;
			break ;
		case OPT_INIT_PIN:
			need_session |= NEED_SESSION_RW;
			do_init_pin = 1;
			action_count++;
			break ;
		case OPT_KEY_TYPE:
			opt_key_type = optarg;
			break;
		case OPT_KEY_USAGE_SIGN:
			opt_key_usage_sign = 1;
			opt_key_usage_default = 0;
			break;
		case OPT_KEY_USAGE_DECRYPT:
			opt_key_usage_decrypt = 1;
			opt_key_usage_default = 0;
			break;
		case OPT_KEY_USAGE_DERIVE:
			opt_key_usage_derive = 1;
			opt_key_usage_default = 0;
			break;
		case OPT_PRIVATE:
			opt_is_private = 1;
			break;
		case OPT_TEST_HOTPLUG:
			opt_test_hotplug = 1;
			action_count++;
			break;
		case OPT_TEST_EC:
			do_test_ec = 1;
			action_count++;
			break;
		case OPT_DERIVE:
			need_session |= NEED_SESSION_RW;
			do_derive = 1;
			action_count++;
			break;
#ifndef _WIN32
		case OPT_TEST_FORK:
			do_test_fork = 1;
			action_count++;
			break;
#endif
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}

	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

	module = C_LoadModule(opt_module, &p11);
	if (module == NULL)
		util_fatal("Failed to load pkcs11 module");

	rv = p11->C_Initialize(NULL);
	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
		printf("\n*** Cryptoki library has already been initialized ***\n");
	else if (rv != CKR_OK)
		p11_fatal("C_Initialize", rv);

#ifndef _WIN32
	if (do_test_fork)
		test_fork();
#endif

	if (do_show_info)
		show_cryptoki_info();

	list_slots(list_token_slots, 1, do_list_slots);

	if (opt_test_hotplug) {
		test_card_detection(0);
		test_card_detection(1);
	}

	if (p11_num_slots == 0) {
		fprintf(stderr, "No slots.\n");
		err = 1;
		goto end;
	}

	if (!opt_slot_set && (action_count > do_list_slots)) {
		if (opt_slot_description) {
			if (!find_slot_by_description(opt_slot_description, &opt_slot)) {
				fprintf(stderr, "No slot named \"%s\" found\n", opt_slot_description);
				err = 1;
				goto end;
			}
			if (verbose)
				fprintf(stderr, "Using slot with label \"%s\" (0x%lx)\n", opt_slot_description, opt_slot);
		} else if (opt_token_label) {
			if (!find_slot_by_token_label(opt_token_label, &opt_slot)) {
				fprintf(stderr, "No slot with token named \"%s\" found\n", opt_token_label);
				err = 1;
				goto end;
			}
			if (verbose)
				fprintf(stderr, "Using slot with label \"%s\" (0x%lx)\n", opt_slot_description, opt_slot);
		} else if (opt_slot_index_set) {
			if (opt_slot_index < p11_num_slots) {
				opt_slot = p11_slots[opt_slot_index];
				fprintf(stderr, "Using slot with index %lu (0x%lx)\n", opt_slot_index, opt_slot);
			} else {
				fprintf(stderr, "Slot with index %lu (counting from 0) is not available.\n", opt_slot_index);
				fprintf(stderr, "You must specify a valid slot with either --slot, --slot-index or --slot-label.\n");
				err = 1;
				goto end;
			}
		} else {
			/* use first slot with token present (or default slot on error) */
			unsigned int i, found = 0;
			for (i = 0; i < p11_num_slots; i++) {
				CK_SLOT_INFO info;
				rv = p11->C_GetSlotInfo(p11_slots[i], &info);
				if (rv != CKR_OK)
					p11_fatal("C_GetSlotInfo", rv);
				if (info.flags & CKF_TOKEN_PRESENT) {
					opt_slot = p11_slots[i];
					fprintf(stderr, "Using slot %u with a present token (0x%lx)\n", i, opt_slot);
					found = 1;
					break;
				}
			}
			if (!found) {
				fprintf(stderr, "No slot with a token was found.\n");
				err = 1;
				goto end;
			}

		}
	}

	if (do_list_mechs)
		list_mechs(opt_slot);

	if (do_sign || do_decrypt) {
		CK_TOKEN_INFO	info;

		get_token_info(opt_slot, &info);
		if (!(info.flags & CKF_TOKEN_INITIALIZED))
			util_fatal("Token not initialized\n");
		if (info.flags & CKF_LOGIN_REQUIRED)
			opt_login++;
	}

	if (do_init_token)
		init_token(opt_slot);

	if (need_session) {
		int flags = CKF_SERIAL_SESSION;

		if (need_session & NEED_SESSION_RW)
			flags |= CKF_RW_SESSION;
		rv = p11->C_OpenSession(opt_slot, flags,
				NULL, NULL, &session);
		if (rv != CKR_OK)
			p11_fatal("C_OpenSession", rv);
	}

	if (opt_login) {
		int r;

		if (opt_login_type == -1)
			opt_login_type = do_init_pin ? CKU_SO : CKU_USER;

		r = login(session, opt_login_type);
		if (r != 0)
			return r;
	}

	if (do_change_pin)
		/* To be sure we won't mix things up with the -l or -p options,
		 * we safely stop here. */
		return change_pin(opt_slot, session);

	if (do_unlock_pin)   {
		if (opt_login_type != -1
				&& opt_login_type != CKU_CONTEXT_SPECIFIC)   {
			printf("Invalid login type for 'Unlock User PIN' operation\n");
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}

		return unlock_pin(opt_slot, session, opt_login_type);
	}

	if (do_init_pin) {
		init_pin(opt_slot, session);
		/* We logged in as a CKU_SO user just to initialize
		* the User PIN, we now have to exit. */
		goto end;
	}

	if (do_sign || do_derive || do_decrypt) {
		if (!find_object(session, CKO_PRIVATE_KEY, &object,
					opt_object_id_len ? opt_object_id : NULL,
					opt_object_id_len, 0))
			util_fatal("Private key not found");
	}

	/* before list objects, so we can see a derived key */
	if (do_derive)
		derive_key(opt_slot, session, object);

	if (do_list_objects)
		list_objects(session, opt_object_class);

	if (do_sign)
		sign_data(opt_slot, session, object);

	if (do_decrypt)
		decrypt_data(opt_slot, session, object);

	if (do_hash)
		hash_data(opt_slot, session);

	if (do_gen_keypair) {
		CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
		gen_keypair(session, &hPublicKey, &hPrivateKey, opt_key_type);
	}

	if (do_write_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify the object type with the -y option\n");
		write_object(session);
	}

	if (do_read_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify type of the object to read");
		if (opt_object_id_len == 0 && opt_object_label == NULL &&
				opt_application_label == NULL && opt_application_id == NULL &&
				opt_issuer == NULL && opt_subject == NULL)
			 util_fatal("You should specify at least one of the "
					 "object ID, object label, application label or application ID\n");
		read_object(session);
	}

	if (do_delete_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify type of the object to delete");
		if (opt_object_id_len == 0 && opt_object_label == NULL &&
				opt_application_label == NULL && opt_application_id == NULL)
			 util_fatal("You should specify at least one of the "
					 "object ID, object label, application label or application ID\n");
		delete_object(session);
	}

	if (do_set_id) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify the object type with the -y option\n");
		if (opt_object_id_len == 0)
			util_fatal("You should specify the current ID with the -d option\n");
		set_id_attr(session);
	}

	if (do_test)
		p11_test(session);

	if (do_test_kpgen_certwrite)
		test_kpgen_certwrite(opt_slot, session);

	if (do_test_ec)
		test_ec(opt_slot, session);
end:
	if (session != CK_INVALID_HANDLE) {
		rv = p11->C_CloseSession(session);
		if (rv != CKR_OK)
			p11_fatal("C_CloseSession", rv);
	}

	if (p11)
		p11->C_Finalize(NULL_PTR);
	if (module)
		C_UnloadModule(module);

	return err;
}

static void show_cryptoki_info(void)
{
	CK_INFO	info;
	CK_RV	rv;

	rv = p11->C_GetInfo(&info);
	if (rv != CKR_OK)
		p11_fatal("C_GetInfo", rv);

	printf("Cryptoki version %u.%u\n",
			info.cryptokiVersion.major,
			info.cryptokiVersion.minor);
	printf("Manufacturer     %s\n",
			p11_utf8_to_local(info.manufacturerID,
				sizeof(info.manufacturerID)));
	printf("Library          %s (ver %u.%u)\n",
			p11_utf8_to_local(info.libraryDescription,
				sizeof(info.libraryDescription)),
			info.libraryVersion.major,
			info.libraryVersion.minor);
}

static void list_slots(int tokens, int refresh, int print)
{
	CK_SLOT_INFO info;
	CK_ULONG n;
	CK_RV rv;

	/* Get the list of slots */
	if (refresh) {
		rv = p11->C_GetSlotList(tokens, NULL, &p11_num_slots);
		if (rv != CKR_OK)
			p11_fatal("C_GetSlotList(NULL)", rv);
		p11_slots = calloc(p11_num_slots, sizeof(CK_SLOT_ID));
		if (p11_slots == NULL) {
			perror("calloc failed");
			return;
		}

		rv = p11->C_GetSlotList(tokens, p11_slots, &p11_num_slots);
		if (rv != CKR_OK)
			p11_fatal("C_GetSlotList()", rv);
	}

	if (!print)
		return;

	printf("Available slots:\n");
	for (n = 0; n < p11_num_slots; n++) {
		printf("Slot %lu (0x%lx): ", n, p11_slots[n]);
		rv = p11->C_GetSlotInfo(p11_slots[n], &info);
		if (rv != CKR_OK) {
			printf("(GetSlotInfo failed, %s)\n", CKR2Str(rv));
			continue;
		}
		printf("%s\n", p11_utf8_to_local(info.slotDescription,
					sizeof(info.slotDescription)));
		if ((!verbose) && !(info.flags & CKF_TOKEN_PRESENT)) {
			printf("  (empty)\n");
			continue;
		}

		if (verbose) {
			printf("  manufacturer:  %s\n", p11_utf8_to_local(info.manufacturerID,
						sizeof(info.manufacturerID)));
			printf("  hardware ver:  %u.%u\n",
						info.hardwareVersion.major,
						info.hardwareVersion.minor);
			printf("  firmware ver:  %u.%u\n",
						info.firmwareVersion.major,
						info.firmwareVersion.minor);
			printf("  flags:         %s\n", p11_slot_info_flags(info.flags));
		}
		if (info.flags & CKF_TOKEN_PRESENT)
			show_token(p11_slots[n]);
	}
}

static void show_token(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO	info;
	CK_RV rv;

	rv = p11->C_GetTokenInfo(slot, &info);
	if (rv == CKR_TOKEN_NOT_RECOGNIZED) {
		printf("  (token not recognized)\n");
		return;
	}
	if (!(info.flags & CKF_TOKEN_INITIALIZED) && (!verbose)) {
		printf("  token state:   uninitialized\n");
		return;
	}

	printf("  token label        : %s\n",
			p11_utf8_to_local(info.label,
				sizeof(info.label)));
	printf("  token manufacturer : %s\n",
			p11_utf8_to_local(info.manufacturerID,
				sizeof(info.manufacturerID)));
	printf("  token model        : %s\n",
			p11_utf8_to_local(info.model,
				sizeof(info.model)));
	printf("  token flags        : %s\n",
			p11_token_info_flags(info.flags));
	printf("  hardware version   : %d.%d\n", info.hardwareVersion.major, info.hardwareVersion.minor);
	printf("  firmware version   : %d.%d\n", info.firmwareVersion.major, info.firmwareVersion.minor);
	printf("  serial num         : %s\n", p11_utf8_to_local(info.serialNumber,
			sizeof(info.serialNumber)));
}

static void list_mechs(CK_SLOT_ID slot)
{
	CK_MECHANISM_TYPE	*mechs = NULL;
	CK_ULONG		n, num_mechs = 0;
	CK_RV			rv;

	num_mechs = get_mechanisms(slot, &mechs, -1);

	printf("Supported mechanisms:\n");
	for (n = 0; n < num_mechs; n++) {
		CK_MECHANISM_INFO info;

		printf("  %s", p11_mechanism_to_name(mechs[n]));
		rv = p11->C_GetMechanismInfo(slot, mechs[n], &info);
		if (rv == CKR_OK) {
			if (info.ulMinKeySize || info.ulMaxKeySize)   {
				printf(", keySize={");
				if (info.ulMinKeySize)
					printf("%li", info.ulMinKeySize);
				printf(",");
				if (info.ulMaxKeySize)
					printf("%li", info.ulMaxKeySize);
				printf("}");
			}
			if (info.flags & CKF_HW) {
				printf(", hw");
				info.flags &= ~CKF_HW;
			}
			if (info.flags & CKF_ENCRYPT) {
				printf(", encrypt");
				info.flags &= ~CKF_ENCRYPT;
			}
			if (info.flags & CKF_DECRYPT) {
				printf(", decrypt");
				info.flags &= ~CKF_DECRYPT;
			}
			if (info.flags & CKF_DIGEST) {
				printf(", digest");
				info.flags &= ~CKF_DIGEST;
			}
			if (info.flags & CKF_SIGN) {
				printf(", sign");
				info.flags &= ~CKF_SIGN;
			}
			if (info.flags & CKF_SIGN_RECOVER) {
				printf(", sign_recover");
				info.flags &= ~CKF_SIGN_RECOVER;
			}
			if (info.flags & CKF_VERIFY) {
				printf(", verify");
				info.flags &= ~CKF_VERIFY;
			}
			if (info.flags & CKF_VERIFY_RECOVER) {
				printf(", verify_recover");
				info.flags &= ~CKF_VERIFY_RECOVER;
			}
			if (info.flags & CKF_GENERATE) {
				printf(", generate");
				info.flags &= ~CKF_GENERATE;
			}
			if (info.flags & CKF_GENERATE_KEY_PAIR) {
				printf(", generate_key_pair");
				info.flags &= ~CKF_GENERATE_KEY_PAIR;
			}
			if (info.flags & CKF_WRAP) {
				printf(", wrap");
				info.flags &= ~CKF_WRAP;
			}
			if (info.flags & CKF_UNWRAP) {
				printf(", unwrap");
				info.flags &= ~CKF_UNWRAP;
			}
			if (info.flags & CKF_DERIVE) {
				printf(", derive");
				info.flags &= ~CKF_DERIVE;
			}
			if (info.flags)
				printf(", other flags=0x%x", (unsigned int) info.flags);
		}
		printf("\n");
	}

	if (mechs)
		free(mechs);
}

static int login(CK_SESSION_HANDLE session, int login_type)
{
	char		*pin = NULL;
	size_t		len = 0;
	int		pin_allocated = 0, r;
	CK_TOKEN_INFO	info;
	CK_RV		rv;

	get_token_info(opt_slot, &info);

	/* Identify which pin to enter */

	if (login_type == CKU_SO)
		pin = (char *) opt_so_pin;
	else if (login_type == CKU_USER)
		pin = (char *) opt_pin;
	else if (login_type == CKU_CONTEXT_SPECIFIC)
		pin = opt_pin ? (char *) opt_pin : (char *) opt_puk;

	if (!pin && !(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
			printf("Logging in to \"%s\".\n", p11_utf8_to_local(info.label, sizeof(info.label)));
		if (login_type == CKU_SO)
			printf("Please enter SO PIN: ");
		else if (login_type == CKU_USER)
			printf("Please enter User PIN: ");
		else if (login_type == CKU_CONTEXT_SPECIFIC)
			printf("Please enter context specific PIN: ");
		r = util_getpass(&pin, &len, stdin);
		if (r < 0)
			util_fatal("No PIN entered, exiting!\n");
		pin_allocated = 1;
	}

	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
			&& (!pin || !*pin)
			&& login_type != CKU_CONTEXT_SPECIFIC)
		return 1;

	rv = p11->C_Login(session, login_type,
			(CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin));
	if (rv != CKR_OK)
		p11_fatal("C_Login", rv);
	if (pin_allocated)
		free(pin);

	return 0;
}

static void init_token(CK_SLOT_ID slot)
{
	unsigned char token_label[33];
	char new_buf[21], *new_pin = NULL;
	size_t len = 0;
	int pin_allocated = 0, r;
	CK_TOKEN_INFO	info;
	CK_RV rv;

	if (!opt_object_label)
		util_fatal("The token label must be specified using --label\n");
	snprintf((char *) token_label, sizeof (token_label), "%-32.32s",
			opt_object_label);

	get_token_info(slot, &info);
	if (opt_so_pin != NULL) {
		new_pin = (char *) opt_so_pin;
	} else {
		if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
			printf("Please enter the new SO PIN: ");
			r = util_getpass(&new_pin, &len, stdin);
			if (r < 0)
				util_fatal("No PIN entered, exiting\n");
			if (!new_pin || !*new_pin || strlen(new_pin) > 20)
				util_fatal("Invalid SO PIN\n");
			strlcpy(new_buf, new_pin, sizeof new_buf);
			free(new_pin); new_pin = NULL;
			printf("Please enter the new SO PIN (again): ");
			r = util_getpass(&new_pin, &len, stdin);
			if (r < 0)
				util_fatal("No PIN entered, exiting\n");
			if (!new_pin || !*new_pin ||
					strcmp(new_buf, new_pin) != 0)
				util_fatal("Different new SO PINs, exiting\n");
			pin_allocated = 1;
		}
	}

	rv = p11->C_InitToken(slot, (CK_UTF8CHAR *) new_pin,
			new_pin == NULL ? 0 : strlen(new_pin), token_label);
	if (rv != CKR_OK)
		p11_fatal("C_InitToken", rv);
	printf("Token successfully initialized\n");

	if (pin_allocated)
		free(new_pin);
}

static void init_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess)
{
	char *pin;
	char *new_pin1 = NULL, *new_pin2 = NULL;
	size_t len1 = 0, len2 = 0;
	int r;
	CK_TOKEN_INFO	info;
	CK_RV rv;

	get_token_info(slot, &info);

	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		if (! opt_pin && !opt_new_pin) {
			printf("Please enter the new PIN: ");
			r = util_getpass(&new_pin1,&len1,stdin);
			if (r < 0)
				util_fatal("No PIN entered, aborting.\n");
			if (!new_pin1 || !*new_pin1 || strlen(new_pin1) > 20)
				util_fatal("Invalid User PIN\n");
			printf("Please enter the new PIN again: ");
			r = util_getpass(&new_pin2, &len2, stdin);
			if (r < 0)
				util_fatal("No PIN entered, aborting.\n");
			if (!new_pin2 || !*new_pin2 ||
					strcmp(new_pin1, new_pin2) != 0)
				util_fatal("Different new User PINs, exiting\n");
		}
	}

	pin = (char *) opt_pin;
	if (!pin) pin = (char *) opt_new_pin;
	if (!pin) pin = new_pin1;

	rv = p11->C_InitPIN(sess, (CK_UTF8CHAR *) pin, pin == NULL ? 0 : strlen(pin));

	if (new_pin1) {
		memset(new_pin1, 0, len1);
		free(new_pin1);
	}
	if (new_pin2) {
		memset(new_pin2,0, len2);
		free(new_pin2);
	}

	if (rv != CKR_OK)
		p11_fatal("C_InitPIN", rv);
	printf("User PIN successfully initialized\n");
}

static int change_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess)
{
	char old_buf[21], *old_pin = NULL;
	char new_buf[21], *new_pin = NULL;
	CK_TOKEN_INFO	info;
	CK_RV rv;
	int r;
	size_t		len = 0;

	get_token_info(slot, &info);

	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		if (!opt_pin && !opt_so_pin) {
			printf("Please enter the current PIN: ");
			r = util_getpass(&old_pin, &len, stdin);
			if (r < 0)
				return 1;
			if (!old_pin || !*old_pin || strlen(old_pin) > 20)
				return 1;
			strcpy(old_buf, old_pin);
			old_pin = old_buf;
		}
		else   {
			if (opt_so_pin)
				old_pin = (char *) opt_so_pin;
			else
				old_pin = (char *) opt_pin;
		}

		if (!opt_new_pin) {
			printf("Please enter the new PIN: ");
			r = util_getpass(&new_pin, &len, stdin);
			if (r < 0)
				return 1;
			if (!new_pin || !*new_pin || strlen(new_pin) > 20)
				return 1;
			strcpy(new_buf, new_pin);

			printf("Please enter the new PIN again: ");
			r = util_getpass(&new_pin, &len, stdin);
			if (r < 0)
				return 1;
			if (!new_pin || !*new_pin || strcmp(new_buf, new_pin) != 0)
				return 1;
		}
		else   {
			new_pin = (char *) opt_new_pin;
		}
	}

	rv = p11->C_SetPIN(sess,
		(CK_UTF8CHAR *) old_pin, old_pin == NULL ? 0 : strlen(old_pin),
		(CK_UTF8CHAR *) new_pin, new_pin == NULL ? 0 : strlen(new_pin));
	if (rv != CKR_OK)
		p11_fatal("C_SetPIN", rv);
	printf("PIN successfully changed\n");

	return 0;
}


static int unlock_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess, int login_type)
{
	char unlock_buf[21], *unlock_code = NULL;
	char new_buf[21], *new_pin = NULL;
	CK_TOKEN_INFO info;
	CK_RV rv;
	int r;
	size_t len = 0;

	get_token_info(slot, &info);

	if (login_type == CKU_CONTEXT_SPECIFIC)
		unlock_code = opt_pin ? (char *) opt_pin : (char *) opt_puk;
	else if (login_type == -1)
		unlock_code = (char *) opt_puk;
	else
		return 1;

	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) && !unlock_code)   {
		if (login_type == CKU_CONTEXT_SPECIFIC)
			printf("Please enter the 'Change PIN' context secret code: ");
		else if (login_type == -1)
			printf("Please enter unblock code for User PIN: ");

		r = util_getpass(&unlock_code, &len, stdin);
		if (r < 0)
			return 1;
		if (!unlock_code || !*unlock_code || strlen(unlock_code) > 20)
			return 1;

		strcpy(unlock_buf, unlock_code);
		unlock_code = unlock_buf;
	}

	new_pin = (char *) opt_new_pin;
	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) && !new_pin)   {
		printf("Please enter the new PIN: ");
		r = util_getpass(&new_pin, &len, stdin);
		if (r < 0)
			return 1;
		strlcpy(new_buf, new_pin, sizeof new_buf);

		printf("Please enter the new PIN again: ");
		r = util_getpass(&new_pin, &len, stdin);
		if (r < 0)
			return 1;
		if (!new_pin || !*new_pin || strcmp(new_buf, new_pin) != 0) {
			if (new_pin != opt_new_pin)
				free(new_pin);
			printf("  different new PINs, exiting\n");
			return -1;
		}

		if (!new_pin || !*new_pin || strlen(new_pin) > 20) {
			if (new_pin != opt_new_pin)
				free(new_pin);
			return 1;
		}
	}

	rv = p11->C_SetPIN(sess,
		(CK_UTF8CHAR *) unlock_code, unlock_code == NULL ? 0 : strlen(unlock_code),
		(CK_UTF8CHAR *) new_pin, new_pin == NULL ? 0 : strlen(new_pin));
	if (rv != CKR_OK)
		p11_fatal("C_SetPIN", rv);
	printf("PIN successfully changed\n");

	return 0;
}

static void sign_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1025], sig_buffer[512];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, r;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_SIGN|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Sign mechanism not supported\n");

	printf("Using signature algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	r = read(fd, in_buffer, sizeof(in_buffer));
	if (r < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	rv = CKR_CANCEL;
	if (r < (int) sizeof(in_buffer))   {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);

		sig_len = sizeof(sig_buffer);
		rv =  p11->C_Sign(session, in_buffer, r, sig_buffer, &sig_len);
	}

	if (rv != CKR_OK)   {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);

		do   {
			rv = p11->C_SignUpdate(session, in_buffer, r);
			if (rv != CKR_OK)
				p11_fatal("C_SignUpdate", rv);

			r = read(fd, in_buffer, sizeof(in_buffer));
		} while (r > 0);

		sig_len = sizeof(sig_buffer);
		rv = p11->C_SignFinal(session, sig_buffer, &sig_len);
		if (rv != CKR_OK)
			p11_fatal("C_SignFinal", rv);
	}

	if (fd != 0)
		close(fd);

	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
		util_fatal("failed to open %s: %m", opt_output);
	}

	if (opt_mechanism == CKM_ECDSA || opt_mechanism == CKM_ECDSA_SHA1) {
		if (opt_sig_format &&  (!strcmp(opt_sig_format, "openssl") || !strcmp(opt_sig_format, "sequence"))) {
			unsigned char *seq;
			size_t seqlen;

			if (sc_asn1_sig_value_rs_to_sequence(NULL, sig_buffer, sig_len, &seq, &seqlen)) {
				util_fatal("Failed to convert signature to ASN.1 sequence format.");
			}

			memcpy(sig_buffer, seq, seqlen);
			sig_len = seqlen;

			free(seq);
		}
	}
	r = write(fd, sig_buffer, sig_len);

	if (r < 0)
		util_fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}


static void decrypt_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1024], out_buffer[1024];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	in_len, out_len;
	int		fd, r;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DECRYPT|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Decrypt mechanism not supported\n");

	printf("Using decrypt algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	r = read(fd, in_buffer, sizeof(in_buffer));
	if (r < 0)
		util_fatal("Cannot read from %s: %m", opt_input);
	in_len = r;

	rv = p11->C_DecryptInit(session, &mech, key);
	if (rv != CKR_OK)
		p11_fatal("C_DecryptInit", rv);

	out_len = sizeof(out_buffer);
	rv = p11->C_Decrypt(session, in_buffer, in_len, out_buffer, &out_len);
	if (rv != CKR_OK)
		p11_fatal("C_Decrypt", rv);

	if (fd != 0)
		close(fd);

	if (opt_output == NULL)   {
		fd = 1;
	}
	else  {
		fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, S_IRUSR|S_IWUSR);
		if (fd < 0)
			util_fatal("failed to open %s: %m", opt_output);
	}

	r = write(fd, out_buffer, out_len);
	if (r < 0)
		util_fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}


static void hash_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	unsigned char	buffer[64];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	hash_len;
	int		fd, r;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DIGEST, NULL, 0, &opt_mechanism))
			util_fatal("Digest mechanism is not supported\n");

	printf("Using digest algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	rv = p11->C_DigestInit(session, &mech);
	if (rv != CKR_OK)
		p11_fatal("C_DigestInit", rv);

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	while ((r = read(fd, buffer, sizeof(buffer))) > 0) {
		rv = p11->C_DigestUpdate(session, buffer, r);
		if (rv != CKR_OK)
			p11_fatal("C_DigestUpdate", rv);
	}

	if (fd != 0)
		close(fd);

	hash_len = sizeof(buffer);
	rv = p11->C_DigestFinal(session, buffer, &hash_len);
	if (rv != CKR_OK)
		p11_fatal("C_DigestFinal", rv);

	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, S_IRUSR|S_IWUSR)) < 0)
		util_fatal("failed to open %s: %m", opt_output);

	r = write(fd, buffer, hash_len);
	if (r < 0)
		util_fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}

#define FILL_ATTR(attr, typ, val, len) {(attr).type=(typ); (attr).pValue=(val); (attr).ulValueLen=len;}

static int gen_keypair(CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE *hPublicKey, CK_OBJECT_HANDLE *hPrivateKey, const char *type)
{
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG modulusBits = 1024;
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 }; /* 65537 in bytes */
	CK_BBOOL _true = TRUE;
	CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE publicKeyTemplate[20] = {
		{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
		{CKA_TOKEN, &_true, sizeof(_true)},
	};
	int n_pubkey_attr = 2;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
		{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
		{CKA_TOKEN, &_true, sizeof(_true)},
		{CKA_PRIVATE, &_true, sizeof(_true)},
		{CKA_SENSITIVE, &_true, sizeof(_true)},
	};
	int n_privkey_attr = 4;
	unsigned char *ecparams = NULL;
	size_t ecparams_size;
	CK_RV rv;

	if (type != NULL) {
		if (strncmp(type, "RSA:", strlen("RSA:")) == 0 ||
		    strncmp(type, "rsa:", strlen("rsa:")) == 0) {
			CK_ULONG    key_length;
			const char *size = type + strlen("RSA:");

			if (size == NULL)
				util_fatal("Unknown key type %s", type);
			key_length = (unsigned long)atol(size);
			if (key_length != 0)
				modulusBits = key_length;

			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits));
			n_pubkey_attr++;
			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent));
			n_pubkey_attr++;

			if (opt_key_usage_default || opt_key_usage_sign) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN, &_true, sizeof(_true));
				n_privkey_attr++;
			}

			if (opt_key_usage_default || opt_key_usage_decrypt) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ENCRYPT, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_DECRYPT, &_true, sizeof(_true));
				n_privkey_attr++;
			}

			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_WRAP, &_true, sizeof(_true));
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_UNWRAP, &_true, sizeof(_true));
			n_privkey_attr++;


			mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
		}
		else if (!strncmp(type, "EC:", 3))   {
			int ii;

			for (ii=0; ec_curve_infos[ii].name; ii++)   {
				if (!strcmp(ec_curve_infos[ii].name, type + 3))
					break;
				if (!strcmp(ec_curve_infos[ii].oid, type + 3))
					break;
			}
			if (!ec_curve_infos[ii].name)
				util_fatal("Unknown EC key params '%s'", type + 3);

			ecparams_size = strlen(ec_curve_infos[ii].oid_encoded) / 2;
			ecparams = malloc(ecparams_size);
			if (!ecparams)
				util_fatal("Allocation error", 0);
			if (!hex_to_bin(ec_curve_infos[ii].oid_encoded, ecparams, &ecparams_size)) {
				printf("Cannot convert \"%s\"\n", ec_curve_infos[ii].oid_encoded);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}

			if (opt_key_usage_default || opt_key_usage_sign) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN, &_true, sizeof(_true));
				n_privkey_attr++;
			}

			if (opt_key_usage_default || opt_key_usage_derive) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_DERIVE, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_DERIVE, &_true, sizeof(_true));
				n_privkey_attr++;
			}


			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_EC_PARAMS, ecparams, ecparams_size);
			n_pubkey_attr++;

			mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
		}
		else {
			util_fatal("Unknown key type %s", type);
		}
	}

	if (opt_object_label != NULL) {
		FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_LABEL,
			opt_object_label, strlen(opt_object_label));
		FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_LABEL,
			opt_object_label, strlen(opt_object_label));
		n_pubkey_attr++;
		n_privkey_attr++;

	}
	if (opt_object_id_len != 0) {
		FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_ID,
			opt_object_id, opt_object_id_len);
		FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_ID,
			opt_object_id, opt_object_id_len);
		n_pubkey_attr++;
		n_privkey_attr++;
	}

	rv = p11->C_GenerateKeyPair(session, &mechanism,
		publicKeyTemplate, n_pubkey_attr,
		privateKeyTemplate, n_privkey_attr,
		hPublicKey, hPrivateKey);
	if (rv != CKR_OK)
		p11_fatal("C_GenerateKeyPair", rv);

	if (ecparams)
		free(ecparams);

	printf("Key pair generated:\n");
	show_object(session, *hPrivateKey);
	show_object(session, *hPublicKey);

	return 1;
}

#ifdef ENABLE_OPENSSL
static void	parse_certificate(struct x509cert_info *cert,
		unsigned char *data, int len)
{
	X509 *x;
	unsigned char *p;
	const unsigned char *pp;
	int n;

	pp = data;
	x = d2i_X509(NULL, &pp, len);
	if (!x) {
		util_fatal("OpenSSL error during X509 certificate parsing");
	}
	/* check length first */
	n = i2d_X509_NAME(x->cert_info->subject, NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding subject name");
	if (n > (int)sizeof (cert->subject))
		util_fatal("subject name too long");
	/* green light, actually do it */
	p = cert->subject;
	n = i2d_X509_NAME(x->cert_info->subject, &p);
	cert->subject_len = n;

	/* check length first */
	n = i2d_X509_NAME(x->cert_info->issuer, NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding issuer name");
	if (n > (int)sizeof (cert->issuer))
		util_fatal("issuer name too long");
	/* green light, actually do it */
	p = cert->issuer;
	n = i2d_X509_NAME(x->cert_info->issuer, &p);
	cert->issuer_len = n;

	/* check length first */
	n = i2d_ASN1_INTEGER(x->cert_info->serialNumber, NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding serial number");
	if (n > (int)sizeof (cert->serialnum))
		util_fatal("serial number too long");
	/* green light, actually do it */
	p = cert->serialnum;
	n = i2d_ASN1_INTEGER(x->cert_info->serialNumber, &p);
	cert->serialnum_len = n;
}

static int
do_read_private_key(unsigned char *data, size_t data_len, EVP_PKEY **key)
{
	BIO	*mem;
	BUF_MEM buf_mem;

	if (!key)
		return -1;
	buf_mem.data = malloc(data_len);
        if (!buf_mem.data)
		return -1;

        memcpy(buf_mem.data, data, data_len);
        buf_mem.max = buf_mem.length = data_len;

	mem = BIO_new(BIO_s_mem());
	BIO_set_mem_buf(mem, &buf_mem, BIO_NOCLOSE);
	if (!strstr((char *)data, "-----BEGIN PRIVATE KEY-----") && !strstr((char *)data, "-----BEGIN EC PRIVATE KEY-----"))
		*key = d2i_PrivateKey_bio(mem, NULL);
	else
		*key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
	BIO_free(mem);
	if (*key == NULL)
		return -1;

	return 0;
}

#define RSA_GET_BN(LOCALNAME, BNVALUE) \
	do { \
		rsa->LOCALNAME = malloc(BN_num_bytes(BNVALUE)); \
		if (!rsa->LOCALNAME) \
			util_fatal("malloc() failure\n"); \
		rsa->LOCALNAME##_len = BN_bn2bin(BNVALUE, rsa->LOCALNAME); \
	} while (0)

static int
parse_rsa_private_key(struct rsakey_info *rsa, unsigned char *data, int len)
{
	RSA *r = NULL;
	const unsigned char *p;

	p = data;
	r = d2i_RSAPrivateKey(NULL, &p, len);
	if (!r) {
		util_fatal("OpenSSL error during RSA private key parsing");
	}
	RSA_GET_BN(modulus, r->n);
	RSA_GET_BN(public_exponent, r->e);
	RSA_GET_BN(private_exponent, r->d);
	RSA_GET_BN(prime_1, r->p);
	RSA_GET_BN(prime_2, r->q);
	RSA_GET_BN(exponent_1, r->dmp1);
	RSA_GET_BN(exponent_2, r->dmq1);
	RSA_GET_BN(coefficient, r->iqmp);

	return 0;
}

static void parse_rsa_public_key(struct rsakey_info *rsa,
		unsigned char *data, int len)
{
	RSA *r = NULL;
	const unsigned char *p;

	p = data;
	r = d2i_RSA_PUBKEY(NULL, &p, len);

	if (!r) {
		r = d2i_RSAPublicKey(NULL, &p, len);
	}

	if (!r) {
		util_fatal("OpenSSL error during RSA public key parsing");
	}
	RSA_GET_BN(modulus, r->n);
	RSA_GET_BN(public_exponent, r->e);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
static int parse_gost_private_key(EVP_PKEY *evp_key, struct gostkey_info *gost)
{
	EC_KEY *src = EVP_PKEY_get0(evp_key);
	unsigned char *pder;
	const BIGNUM *bignum;
	int nid, rv;

	if (!src)
		return -1;

	nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0(evp_key)));
	rv = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), NULL);
	if (rv < 0)
		return -1;

	gost->param_oid.value = malloc(rv);
	if (!gost->param_oid.value)
		return -1;

	pder =  gost->param_oid.value;
	rv = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &pder);
	gost->param_oid.len = rv;

	bignum = EC_KEY_get0_private_key(EVP_PKEY_get0(evp_key));

	gost->private.len = BN_num_bytes(bignum);
	gost->private.value = malloc(gost->private.len);
	if (!gost->private.value)
		return -1;
	BN_bn2bin(bignum, gost->private.value);

	return 0;
}
#endif
#endif

#define MAX_OBJECT_SIZE	5000

/* Currently for certificates (-type cert), private keys (-type privkey),
   public keys (-type pubkey) and data objects (-type data).
   Note: only RSA private keys are supported. */
static int write_object(CK_SESSION_HANDLE session)
{
	CK_BBOOL _true = TRUE;
	unsigned char contents[MAX_OBJECT_SIZE + 1];
	int contents_len = 0;
	unsigned char certdata[MAX_OBJECT_SIZE];
	int certdata_len = 0;
	FILE *f;
	CK_OBJECT_HANDLE cert_obj, privkey_obj, pubkey_obj, data_obj;
	CK_ATTRIBUTE cert_templ[20], privkey_templ[20], pubkey_templ[20], data_templ[20];
	int n_cert_attr = 0, n_privkey_attr = 0, n_pubkey_attr = 0, n_data_attr = 0;
	struct sc_object_id oid;
	CK_RV rv;
	int need_to_parse_certdata = 0;
	unsigned char *oid_buf = NULL;
	CK_OBJECT_CLASS clazz;
	CK_CERTIFICATE_TYPE cert_type;
	CK_KEY_TYPE type = CKK_RSA;
#ifdef ENABLE_OPENSSL
	struct x509cert_info cert;
	struct rsakey_info rsa;
	struct gostkey_info gost;
	EVP_PKEY *evp_key = NULL;

	memset(&cert, 0, sizeof(cert));
	memset(&rsa,  0, sizeof(rsa));
	memset(&gost,  0, sizeof(gost));
#endif

	memset(contents, 0, sizeof(contents));
	memset(certdata, 0, sizeof(certdata));

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		util_fatal("Couldn't open file \"%s\"\n", opt_file_to_write);
	contents_len = fread(contents, 1, sizeof(contents) - 1, f);
	if (contents_len < 0)
		util_fatal("Couldn't read from file \"%s\"\n", opt_file_to_write);
	fclose(f);
	contents[contents_len] = '\0';

	if (opt_attr_from_file) {
		if (!(f = fopen(opt_attr_from_file, "rb")))
			util_fatal("Couldn't open file \"%s\"\n", opt_attr_from_file);
		certdata_len = fread(certdata, 1, sizeof(certdata), f);
		if (certdata_len < 0)
			util_fatal("Couldn't read from file \"%s\"\n", opt_attr_from_file);
		fclose(f);
		need_to_parse_certdata = 1;
	}
	if (opt_object_class == CKO_CERTIFICATE && !opt_attr_from_file) {
		memcpy(certdata, contents, MAX_OBJECT_SIZE);
		certdata_len = contents_len;
		need_to_parse_certdata = 1;
	}

	if (need_to_parse_certdata) {
#ifdef ENABLE_OPENSSL
		parse_certificate(&cert, certdata, certdata_len);
#else
		util_fatal("No OpenSSL support, cannot parse certificate\n");
#endif
	}
	if (opt_object_class == CKO_PRIVATE_KEY) {
#ifdef ENABLE_OPENSSL
		int rv;

		rv = do_read_private_key(contents, contents_len, &evp_key);
		if (rv)
			util_fatal("Cannot read private key\n");

		if (evp_key->type == EVP_PKEY_RSA)   {
			rv = parse_rsa_private_key(&rsa, contents, contents_len);
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		else if (evp_key->type == NID_id_GostR3410_2001 || evp_key->type == EVP_PKEY_EC)   {
			/* parsing ECDSA is identical to GOST */
			rv = parse_gost_private_key(evp_key, &gost);
		}
#endif
		else   {
			util_fatal("Unsupported key type: 0x%X\n", evp_key->type);
		}

		if (rv)
			util_fatal("Cannot parse private key\n");
#else
		util_fatal("No OpenSSL support, cannot parse private key\n");
#endif
	}
	if (opt_object_class == CKO_PUBLIC_KEY) {
#ifdef ENABLE_OPENSSL
		parse_rsa_public_key(&rsa, contents, contents_len);
#else
		util_fatal("No OpenSSL support, cannot parse RSA public key\n");
#endif
	}

	if (opt_object_class == CKO_CERTIFICATE) {
		clazz = CKO_CERTIFICATE;
		cert_type = CKC_X_509;

		FILL_ATTR(cert_templ[0], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(cert_templ[1], CKA_VALUE, contents, contents_len);
		FILL_ATTR(cert_templ[2], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(cert_templ[3], CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type));
		n_cert_attr = 4;

		if (opt_object_label != NULL) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_LABEL,
				opt_object_label, strlen(opt_object_label));
			n_cert_attr++;
		}
		if (opt_object_id_len != 0) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_ID,
				opt_object_id, opt_object_id_len);
			n_cert_attr++;
		}
#ifdef ENABLE_OPENSSL
		/* according to PKCS #11 CKA_SUBJECT MUST be specified */
		FILL_ATTR(cert_templ[n_cert_attr], CKA_SUBJECT,
			cert.subject, cert.subject_len);
		n_cert_attr++;
		FILL_ATTR(cert_templ[n_cert_attr], CKA_ISSUER,
			cert.issuer, cert.issuer_len);
		n_cert_attr++;
		FILL_ATTR(cert_templ[n_cert_attr], CKA_SERIAL_NUMBER,
			cert.serialnum, cert.serialnum_len);
		n_cert_attr++;
#endif
	}
	else
	if (opt_object_class == CKO_PRIVATE_KEY) {
		clazz = CKO_PRIVATE_KEY;

		n_privkey_attr = 0;
		FILL_ATTR(privkey_templ[n_privkey_attr], CKA_CLASS, &clazz, sizeof(clazz));
		n_privkey_attr++;
		FILL_ATTR(privkey_templ[n_privkey_attr], CKA_TOKEN, &_true, sizeof(_true));
		n_privkey_attr++;
		FILL_ATTR(privkey_templ[n_privkey_attr], CKA_PRIVATE, &_true, sizeof(_true));
		n_privkey_attr++;
		FILL_ATTR(privkey_templ[n_privkey_attr], CKA_SENSITIVE, &_true, sizeof(_true));
		n_privkey_attr++;

		if (opt_object_label != NULL) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
			n_privkey_attr++;
		}
		if (opt_object_id_len != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_ID, opt_object_id, opt_object_id_len);
			n_privkey_attr++;
		}
		if (opt_key_usage_sign != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_SIGN, &_true, sizeof(_true));
			n_privkey_attr++;
		}
		if (opt_key_usage_decrypt != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_DECRYPT, &_true, sizeof(_true));
			n_privkey_attr++;
		}
		if (opt_key_usage_derive != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_DERIVE, &_true, sizeof(_true));
			n_privkey_attr++;
		}

#ifdef ENABLE_OPENSSL
		if (cert.subject_len != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_SUBJECT, cert.subject, cert.subject_len);
			n_privkey_attr++;
		}
		if (evp_key->type == EVP_PKEY_RSA)   {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_MODULUS, rsa.modulus, rsa.modulus_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_PUBLIC_EXPONENT, rsa.public_exponent, rsa.public_exponent_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_PRIVATE_EXPONENT, rsa.private_exponent, rsa.private_exponent_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_PRIME_1, rsa.prime_1, rsa.prime_1_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_PRIME_2, rsa.prime_2, rsa.prime_2_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_EXPONENT_1, rsa.exponent_1, rsa.exponent_1_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_EXPONENT_2, rsa.exponent_2, rsa.exponent_2_len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_COEFFICIENT, rsa.coefficient, rsa.coefficient_len);
			n_privkey_attr++;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		else if (evp_key->type == EVP_PKEY_EC)   {
			type = CKK_EC;

			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_EC_PARAMS, gost.param_oid.value, gost.param_oid.len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_VALUE, gost.private.value, gost.private.len);
			n_privkey_attr++;
		}
		else if (evp_key->type == NID_id_GostR3410_2001)   {
			type = CKK_GOSTR3410;

			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_GOSTR3410_PARAMS, gost.param_oid.value, gost.param_oid.len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_VALUE, gost.private.value, gost.private.len);
			/* CKA_VALUE of the GOST key has to be in the little endian order */
			rv = sc_mem_reverse(privkey_templ[n_privkey_attr].pValue, privkey_templ[n_privkey_attr].ulValueLen);
			if (rv)
				return rv;
			n_privkey_attr++;
		}
#endif
#endif
	}
	else
	if (opt_object_class == CKO_PUBLIC_KEY) {
		clazz = CKO_PUBLIC_KEY;
		type = CKK_RSA;

		FILL_ATTR(pubkey_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(pubkey_templ[1], CKA_KEY_TYPE, &type, sizeof(type));
		FILL_ATTR(pubkey_templ[2], CKA_TOKEN, &_true, sizeof(_true));
		n_pubkey_attr = 3;

		if (opt_is_private != 0) {
			FILL_ATTR(data_templ[n_data_attr], CKA_PRIVATE,
				&_true, sizeof(_true));
			n_data_attr++;
		}

		if (opt_object_label != NULL) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_LABEL,
				opt_object_label, strlen(opt_object_label));
			n_pubkey_attr++;
		}
		if (opt_object_id_len != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_ID,
				opt_object_id, opt_object_id_len);
			n_pubkey_attr++;
		}
		if (opt_key_usage_sign != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_VERIFY, &_true, sizeof(_true));
			n_pubkey_attr++;
		}
		if (opt_key_usage_decrypt != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_ENCRYPT, &_true, sizeof(_true));
			n_pubkey_attr++;
		}
		if (opt_key_usage_derive != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_DERIVE, &_true, sizeof(_true));
			n_pubkey_attr++;
		}

#ifdef ENABLE_OPENSSL
		if (cert.subject_len != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_SUBJECT,
				cert.subject, cert.subject_len);
			n_pubkey_attr++;
		}
		FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_MODULUS,
			rsa.modulus, rsa.modulus_len);
		n_pubkey_attr++;
		FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_PUBLIC_EXPONENT,
			rsa.public_exponent, rsa.public_exponent_len);
		n_pubkey_attr++;
#endif
	}
	else
	if (opt_object_class == CKO_DATA) {
		clazz = CKO_DATA;
		FILL_ATTR(data_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(data_templ[1], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(data_templ[2], CKA_VALUE, &contents, contents_len);

		n_data_attr = 3;

		if (opt_is_private != 0) {
			FILL_ATTR(data_templ[n_data_attr], CKA_PRIVATE,
				&_true, sizeof(_true));
			n_data_attr++;
		}

		if (opt_application_label != NULL) {
			FILL_ATTR(data_templ[n_data_attr], CKA_APPLICATION,
				opt_application_label, strlen(opt_application_label));
			n_data_attr++;
		}

		if (opt_application_id != NULL) {
			size_t len;

			if (sc_format_oid(&oid, opt_application_id))
				util_fatal("Invalid OID \"%s\"\n", opt_application_id);

			if (sc_asn1_encode_object_id(&oid_buf, &len, &oid))
				util_fatal("Cannot encode OID \"%s\"\n", opt_application_id);

			FILL_ATTR(data_templ[n_data_attr], CKA_OBJECT_ID, oid_buf, len);
			n_data_attr++;
		}

		if (opt_object_label != NULL) {
			FILL_ATTR(data_templ[n_data_attr], CKA_LABEL,
				opt_object_label, strlen(opt_object_label));
			n_data_attr++;
		}

	}
	else
		util_fatal("Writing of a \"%s\" type not (yet) supported\n", opt_object_class_str);

	if (n_data_attr) {
		rv = p11->C_CreateObject(session, data_templ, n_data_attr, &data_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);

		printf("Created Data Object:\n");
		show_dobj(session, data_obj);
	}
	if (n_cert_attr) {
		rv = p11->C_CreateObject(session, cert_templ, n_cert_attr, &cert_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);

		printf("Created certificate:\n");
		show_object(session, cert_obj);
	}

	if (n_pubkey_attr) {
		rv = p11->C_CreateObject(session, pubkey_templ, n_pubkey_attr, &pubkey_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);

		printf("Created public key:\n");
		show_object(session, pubkey_obj);
	}

	if (n_privkey_attr) {
		rv = p11->C_CreateObject(session, privkey_templ, n_privkey_attr, &privkey_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);

		printf("Created private key:\n");
		show_object(session, privkey_obj);
	}

	if (oid_buf)
		free(oid_buf);
	return 1;
}

static void set_id_attr(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ATTRIBUTE templ[] = {{CKA_ID, new_object_id, new_object_id_len}};
	CK_RV rv;

	if (!find_object(session, opt_object_class, &obj, opt_object_id, opt_object_id_len, 0)) {
		printf("set_id(): coudn't find the object\n");
		return;
	}

	rv = p11->C_SetAttributeValue(session, obj, templ, 1);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue", rv);

	printf("Result:");
	show_object(session, obj);
}

static int find_slot_by_description(const char *label, CK_SLOT_ID_PTR result)
{
	CK_SLOT_INFO	info;
	CK_ULONG	n, len;
	CK_RV		rv;

	if (!p11_num_slots)
		return 0;

	len = strlen(label);
	for (n = 0; n < p11_num_slots; n++) {
		const char	*slot_label;

		rv = p11->C_GetSlotInfo(p11_slots[n], &info);
		if (rv != CKR_OK)
			continue;
		slot_label = p11_utf8_to_local(info.slotDescription, sizeof(info.slotDescription));
		if (!strncmp(label, slot_label, len)) {
			*result = p11_slots[n];
			return 1;
		}
	}
	return 0;
}

static int find_slot_by_token_label(const char *label, CK_SLOT_ID_PTR result)
{
	CK_TOKEN_INFO	info;
	CK_ULONG	n, len;
	CK_RV		rv;

	if (!p11_num_slots)
		return 0;

	len = strlen(label);
	for (n = 0; n < p11_num_slots; n++) {
		const char	*token_label;

		rv = p11->C_GetTokenInfo(p11_slots[n], &info);
		if (rv != CKR_OK)
			continue;
		token_label = p11_utf8_to_local(info.label, sizeof(info.label));
		if (!strncmp(label, token_label, len)) {
			*result = p11_slots[n];
			return 1;
		}
	}
	return 0;
}


static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len, int obj_index)
{
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;
	int i;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id) {
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void *) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}

	rv = p11->C_FindObjectsInit(sess, attrs, nattrs);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjectsInit", rv);

	for (i = 0; i < obj_index; i++) {
		rv = p11->C_FindObjects(sess, ret, 1, &count);
		if (rv != CKR_OK)
			p11_fatal("C_FindObjects", rv);
		if (count == 0)
			goto done;
	}
	rv = p11->C_FindObjects(sess, ret, 1, &count);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjects", rv);

done:	if (count == 0)
		*ret = CK_INVALID_HANDLE;
	p11->C_FindObjectsFinal(sess);

	return count;
}

static CK_RV find_object_with_attributes(CK_SESSION_HANDLE session,
			CK_OBJECT_HANDLE *out,
			CK_ATTRIBUTE *attrs, CK_ULONG attrsLen,
			CK_ULONG obj_index)
{
	CK_ULONG count, ii;
	CK_OBJECT_HANDLE ret;
	CK_RV rv;

	if (!out || !attrs || !attrsLen)
		return CKR_ARGUMENTS_BAD;
	else
		*out = CK_INVALID_HANDLE;

	rv = p11->C_FindObjectsInit(session, attrs, attrsLen);
	if (rv != CKR_OK)
		return rv;

	for (ii = 0; ii < obj_index; ii++) {
		rv = p11->C_FindObjects(session, &ret, 1, &count);
		if (rv != CKR_OK)
			return rv;
		else if (!count)
			goto done;
	}

	rv = p11->C_FindObjects(session, &ret, 1, &count);
	if (rv != CKR_OK)
		return rv;
	else if (count)
		*out = ret;

done:
	p11->C_FindObjectsFinal(session);
	return CKR_OK;
}


static int
find_mechanism(CK_SLOT_ID slot, CK_FLAGS flags,
		CK_MECHANISM_TYPE_PTR list, size_t list_len,
		CK_MECHANISM_TYPE_PTR result)
{
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_ULONG	count = 0;

	count = get_mechanisms(slot, &mechs, flags);
	if (count)   {
		if (list && list_len)   {
			unsigned ii, jj;

			for (jj=0; jj<count; jj++)   {
				for (ii=0; ii<list_len; ii++)
					if (*(mechs + jj) == *(list + ii))
						break;
				if (ii<list_len)
					break;
			}

			if (jj < count && ii < list_len)
				*result = mechs[jj];
			else
				count = 0;
		}
		else   {
			*result = mechs[0];
		}
	}
	free(mechs);

	return count;
}


#define ATTR_METHOD(ATTR, TYPE) \
static TYPE \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj) \
{ \
	TYPE		type = 0; \
	CK_ATTRIBUTE	attr = { CKA_##ATTR, &type, sizeof(type) }; \
	CK_RV		rv; \
 \
	rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
	if (rv != CKR_OK) \
		p11_warn("C_GetAttributeValue(" #ATTR ")", rv); \
	return type; \
}

#define VARATTR_METHOD(ATTR, TYPE) \
static TYPE * \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) \
{ \
	CK_ATTRIBUTE	attr = { CKA_##ATTR, NULL, 0 }; \
	CK_RV		rv; \
 \
	rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
	if (rv == CKR_OK) { \
		if (!(attr.pValue = calloc(1, attr.ulValueLen + 1))) \
			util_fatal("out of memory in get" #ATTR ": %m"); \
		rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
		if (pulCount) \
			*pulCount = attr.ulValueLen / sizeof(TYPE); \
	} else {\
		p11_warn("C_GetAttributeValue(" #ATTR ")", rv); \
	} \
	return (TYPE *) attr.pValue; \
}

/*
 * Define attribute accessors
 */
ATTR_METHOD(CLASS, CK_OBJECT_CLASS);
ATTR_METHOD(ALWAYS_AUTHENTICATE, CK_BBOOL);
ATTR_METHOD(PRIVATE, CK_BBOOL);
ATTR_METHOD(MODIFIABLE, CK_BBOOL);
ATTR_METHOD(ENCRYPT, CK_BBOOL);
ATTR_METHOD(DECRYPT, CK_BBOOL);
ATTR_METHOD(SIGN, CK_BBOOL);
ATTR_METHOD(VERIFY, CK_BBOOL);
ATTR_METHOD(WRAP, CK_BBOOL);
ATTR_METHOD(UNWRAP, CK_BBOOL);
ATTR_METHOD(DERIVE, CK_BBOOL);
ATTR_METHOD(OPENSC_NON_REPUDIATION, CK_BBOOL);
ATTR_METHOD(KEY_TYPE, CK_KEY_TYPE);
ATTR_METHOD(CERTIFICATE_TYPE, CK_CERTIFICATE_TYPE);
ATTR_METHOD(MODULUS_BITS, CK_ULONG);
VARATTR_METHOD(LABEL, char);
VARATTR_METHOD(APPLICATION, char);
VARATTR_METHOD(ID, unsigned char);
VARATTR_METHOD(OBJECT_ID, unsigned char);
VARATTR_METHOD(MODULUS, CK_BYTE);
#ifdef ENABLE_OPENSSL
VARATTR_METHOD(PUBLIC_EXPONENT, CK_BYTE);
#endif
VARATTR_METHOD(VALUE, unsigned char);
VARATTR_METHOD(GOSTR3410_PARAMS, unsigned char);
VARATTR_METHOD(EC_POINT, unsigned char);
VARATTR_METHOD(EC_PARAMS, unsigned char);

static void list_objects(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS  object_class)
{
	CK_OBJECT_HANDLE object;
	CK_ULONG count;
	CK_RV rv;

	rv = p11->C_FindObjectsInit(sess, NULL, 0);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjectsInit", rv);

	while (1) {
		rv = p11->C_FindObjects(sess, &object, 1, &count);
		if (rv != CKR_OK)
			p11_fatal("C_FindObjects", rv);
		if (count == 0)
			break;
		if ((int) object_class == -1 || object_class == getCLASS(sess, object))
			show_object(sess, object);
	}
	p11->C_FindObjectsFinal(sess);
}

static void show_object(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_OBJECT_CLASS	cls = getCLASS(sess, obj);

	switch (cls) {
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		show_key(sess, obj);
		break;
	case CKO_CERTIFICATE:
		show_cert(sess, obj);
		break;
	case CKO_DATA:
		show_dobj(sess, obj);
		break;
	default:
		printf("Object %u, type %u\n",
				(unsigned int) obj,
				(unsigned int) cls);
	}
}


static void
derive_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	unsigned char *value = NULL;
	CK_ULONG value_len = 0;
	CK_MECHANISM mech;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = 0;
	CK_ECDH1_DERIVE_PARAMS ecdh_parms;
	CK_RV rv;
	int fd, r;
	CK_ATTRIBUTE newkey_template[] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)}
	};

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DERIVE|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Derive mechanism not supported\n");

	printf("Using derive algorithm 0x%8.8lx %s\n", opt_mechanism, p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	switch(opt_mechanism) {
#if defined(ENABLE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x00908000L && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
	case CKM_ECDH1_COFACTOR_DERIVE:
	case CKM_ECDH1_DERIVE:
		/*  Use OpenSSL to read the other public key, and get the raw verion */
		{
		unsigned char buf[512];
		int len;
		BIO     *bio_in = NULL;
		const EC_KEY  *eckey = NULL;
		const EC_GROUP *ecgroup = NULL;
		const EC_POINT * ecpoint = NULL;

		bio_in = BIO_new(BIO_s_file());
		if (BIO_read_filename(bio_in, opt_input) <= 0)
			util_fatal("Cannot open %s: %m", opt_input);

		eckey = d2i_EC_PUBKEY_bio(bio_in, NULL);
		if (!eckey)
			util_fatal("Cannot read EC key from %s", opt_input);

		ecpoint = EC_KEY_get0_public_key(eckey);
		ecgroup = EC_KEY_get0_group(eckey);
		if (!ecpoint || !ecgroup)
			util_fatal("Failed to parse other EC kry from %s", opt_input);

		len = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf),NULL);

		memset(&ecdh_parms, 0, sizeof(ecdh_parms));
		ecdh_parms.kdf = CKD_NULL;
		ecdh_parms.ulSharedDataLen = 0;
		ecdh_parms.pSharedData = NULL;
		ecdh_parms.ulPublicDataLen = len;	/* TODO drop header */
		ecdh_parms.pPublicData = buf;		/* Cheat to test */
		mech.pParameter = &ecdh_parms;
		mech.ulParameterLen = sizeof(ecdh_parms);
		}
		break;
#endif /* ENABLE_OPENSSL  && !OPENSSL_NO_EC && !OPENSSL_NO_ECDSA */
	/* TODO add RSA  but do not have card to test */
	default:
		util_fatal("mechanisum not supported for derive\n");
		break;
	}

	rv = p11->C_DeriveKey(session, &mech, key, newkey_template, 5, &newkey);
	if (rv != CKR_OK)
	    p11_fatal("C_DeriveKey", rv);

	/*TODO get the key value and write to stdout or file */
	value = getVALUE(session, newkey, &value_len);
	if (value && value_len > 0) {
		if (opt_output == NULL)   {
			fd = 1;
		}
		else  {
			fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, S_IRUSR|S_IWUSR);
			if (fd < 0)
				util_fatal("failed to open %s: %m", opt_output);
		}

		r = write(fd, value, value_len);
		if (r < 0)
			util_fatal("Failed to write to %s: %m", opt_output);
		if (fd != 1)
			close(fd);
	}
}


static void
show_key(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_KEY_TYPE	key_type = getKEY_TYPE(sess, obj);
	CK_ULONG	size = 0;
	unsigned char	*id, *oid, *value;
	const char      *sepa;
	char		*label;
	int		pub = 1;
	int             sec = 0;

	switch(getCLASS(sess, obj)) {
		case CKO_PRIVATE_KEY:
			printf("Private Key Object");
			pub = 0;
			break;
		case CKO_PUBLIC_KEY:
			printf("Public Key Object");
			pub = 1;
			break;
		case CKO_SECRET_KEY:
			printf("Secret Key Object");
			sec = 1;
			break;
		default:
			return;
	}

	switch (key_type) {
	case CKK_RSA:
		if (pub)
			printf("; RSA %lu bits\n",
				(unsigned long) getMODULUS_BITS(sess, obj));
		else
			printf("; RSA \n");
		break;
	case CKK_GOSTR3410:
		printf("; GOSTR3410 \n");
		oid = getGOSTR3410_PARAMS(sess, obj, &size);
		if (oid) {
			unsigned int	n;

			printf("  PARAMS OID: ");
			for (n = 0; n < size; n++)
				printf("%02x", oid[n]);
			printf("\n");
			free(oid);
		}

		if (pub)   {
			value = getVALUE(sess, obj, &size);
			if (value) {
				unsigned int	n;

				printf("  VALUE:      ");
				for (n = 0; n < size; n++)   {
					if (n && (n%32)==0)
						printf("\n              ");
					printf("%02x", value[n]);
				}
				printf("\n");
				free(value);
			}
		}
		break;
		break;
	case CKK_EC:
		printf("; EC");
		if (pub) {
			unsigned char *bytes = NULL;
			unsigned int n;
			int ksize;

			bytes = getEC_POINT(sess, obj, &size);
			/*
			 * (We only support uncompressed for now)
			 * Uncompresed EC_POINT is DER OCTET STRING of "04||x||y"
			 * So a "256" bit key has x and y of 32 bytes each
			 * something like: "04 41 04||x||y"
			 * Do simple size calculation based on DER encoding
			 */
			if ((size - 2) <= 127)
				ksize = (size - 3) * 4;
			else if ((size - 3) <= 255)
				ksize = (size - 4) * 4;
			else
				ksize = (size - 5) * 4;

			printf("  EC_POINT %d bits\n", ksize);
			if (bytes) {
				if ((CK_LONG)size > 0) { /* Will print the point here */
					printf("  EC_POINT:   ");
					for (n = 0; n < size; n++)
						printf("%02x", bytes[n]);
					printf("\n");
				}
				free(bytes);
			}
			bytes = NULL;
			bytes = getEC_PARAMS(sess, obj, &size);
			if (bytes){
				if ((CK_LONG)size > 0) {
					printf("  EC_PARAMS:  ");
					for (n = 0; n < size; n++)
						printf("%02x", bytes[n]);
					printf("\n");
				}
				free(bytes);
			}
		} else
			 printf("\n");
		break;
	case CKK_GENERIC_SECRET:
		value = getVALUE(sess, obj, &size);
		if (value) {
			unsigned int    n;

			printf("  VALUE:      ");
			for (n = 0; n < size; n++)   {
				if (n && (n%32)==0)
					printf("\n              ");
				printf("%02x", value[n]);
			}
			printf("\n");
			free(value);
		}
		break;
	default:
		printf("; unknown key algorithm %lu\n",
				(unsigned long) key_type);
		break;
	}

	if ((label = getLABEL(sess, obj, NULL)) != NULL) {
		printf("  label:      %s\n", label);
		free(label);
	}

	if ((id = getID(sess, obj, &size)) != NULL && size) {
		unsigned int	n;

		printf("  ID:         ");
		for (n = 0; n < size; n++)
			printf("%02x", id[n]);
		printf("\n");
		free(id);
	}

	printf("  Usage:      ");
	sepa = "";
	if ((pub || sec) && getENCRYPT(sess, obj)) {
		printf("%sencrypt", sepa);
		sepa = ", ";
	}
	if ((!pub || sec) && getDECRYPT(sess, obj)) {
		printf("%sdecrypt", sepa);
		sepa = ", ";
	}
	if (!pub && getSIGN(sess, obj)) {
		printf("%ssign", sepa);
		sepa = ", ";
	}

	suppress_warn = 1;
	if (!pub && getOPENSC_NON_REPUDIATION(sess, obj)) {
		printf("%snon-repudiation", sepa);
		sepa = ", ";
	}
	suppress_warn = 0;

	if (pub && getVERIFY(sess, obj)) {
		printf("%sverify", sepa);
		sepa = ", ";
	}
	if ((pub || sec) && getWRAP(sess, obj)) {
		printf("%swrap", sepa);
		sepa = ", ";
	}
	if ((!pub || sec) && getUNWRAP(sess, obj)) {
		printf("%sunwrap", sepa);
		sepa = ", ";
	}
	if ((!pub || sec) && getDERIVE(sess, obj)) {
		printf("%sderive", sepa);
		sepa = ", ";
	}
	if (!*sepa)
		printf("none");
	printf("\n");

	if (!pub && getALWAYS_AUTHENTICATE(sess, obj))
		printf("  Access:     always authenticate\n");
	suppress_warn = 0;
}

static void show_cert(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_CERTIFICATE_TYPE	cert_type = getCERTIFICATE_TYPE(sess, obj);
	CK_ULONG	size;
	unsigned char	*id;
	char		*label;

	printf("Certificate Object, type = ");
	switch (cert_type) {
	case CKC_X_509:
		printf("X.509 cert\n");
		break;
	case CKC_X_509_ATTR_CERT:
		printf("X.509 attribute cert\n");
		break;
	case CKC_VENDOR_DEFINED:
		printf("vendor defined");
		break;
	default:
		printf("; unknown cert type\n");
		break;
	}

	if ((label = getLABEL(sess, obj, NULL)) != NULL) {
		printf("  label:      %s\n", label);
		free(label);
	}

	if ((id = getID(sess, obj, &size)) != NULL && size) {
		unsigned int	n;

		printf("  ID:         ");
		for (n = 0; n < size; n++)
			printf("%02x", id[n]);
		printf("\n");
		free(id);
	}
}

static void show_dobj(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	unsigned char *oid_buf;
	char *label;
	CK_ULONG    size = 0;

	suppress_warn = 1;
	printf("Data object %u\n", (unsigned int) obj);
	printf("  label:          ");
	if ((label = getLABEL(sess, obj, NULL)) != NULL) {
		printf("'%s'\n", label);
		free(label);
	}
	else   {
		printf("<empty>\n");
	}

	printf("  application:    ");
	if ((label = getAPPLICATION(sess, obj, NULL)) != NULL) {
		printf("'%s'\n", label);
		free(label);
	}
	else   {
		printf("<empty>\n");
	}

	printf("  app_id:         ");
	oid_buf = getOBJECT_ID(sess, obj, &size);
	if (oid_buf != NULL && size) {
		unsigned int	n;
		struct sc_object_id oid;

		sc_init_oid(&oid);
		sc_asn1_decode_object_id(oid_buf, size, &oid);
		printf("%i", oid.value[0]);
		if (oid.value[0] >= 0)
			for (n = 1; (n < SC_MAX_OBJECT_ID_OCTETS) && (oid.value[n] >= 0); n++)
				printf(".%i", oid.value[n]);
		printf("\n");

		free(oid_buf);
	}
	else   {
		printf("<empty>\n");
	}

	printf("  flags:          ");
	if (getMODIFIABLE(sess, obj))
		printf(" modifiable");
	if (getPRIVATE(sess, obj))
		printf(" private");
	if (!getMODIFIABLE(sess, obj) && !getPRIVATE(sess, obj))
		printf("<empty>\n");

	printf ("\n");
	suppress_warn = 0;
}


static void
get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV		rv;

	rv = p11->C_GetTokenInfo(slot, info);
	if (rv != CKR_OK)
		p11_fatal("C_GetTokenInfo", rv);
}


static CK_ULONG
get_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR *pList, CK_FLAGS flags)
{
	CK_ULONG	m, n, ulCount = 0;
	CK_RV		rv;

	rv = p11->C_GetMechanismList(slot, *pList, &ulCount);
	*pList = calloc(ulCount, sizeof(**pList));
	if (*pList == NULL)
		util_fatal("calloc failed: %m");

	rv = p11->C_GetMechanismList(slot, *pList, &ulCount);
	if (rv != CKR_OK)
		p11_fatal("C_GetMechanismList", rv);

	if (flags != (CK_FLAGS)-1) {
		CK_MECHANISM_TYPE *mechs = *pList;
		CK_MECHANISM_INFO info;

		for (m = n = 0; n < ulCount; n++) {
			rv = p11->C_GetMechanismInfo(slot, mechs[n], &info);
			if (rv != CKR_OK)
				continue;
			if ((info.flags & flags) == flags)
				mechs[m++] = mechs[n];
		}
		ulCount = m;
	}

	return ulCount;
}

/*
 * Read object CKA_VALUE attribute's value.
 */
static int read_object(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_ATTRIBUTE attrs[20];
	CK_OBJECT_CLASS clazz = opt_object_class;
	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	int nn_attrs = 0;
	unsigned char *value = NULL, *oid_buf = NULL;
	CK_ULONG len = 0;
	FILE *out;
	struct sc_object_id oid;
	unsigned char subject[0x400], issuer[0x400];

	if (opt_object_class_str != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_CLASS,
				 &clazz, sizeof(clazz));
		nn_attrs++;
	}

	if (opt_object_id_len != 0)  {
		FILL_ATTR(attrs[nn_attrs], CKA_ID,
				opt_object_id, opt_object_id_len);
		nn_attrs++;
	}

	if (opt_object_label != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_LABEL,
				opt_object_label, strlen(opt_object_label));
		nn_attrs++;
	}

	if (opt_application_label != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_APPLICATION,
				opt_application_label, strlen(opt_application_label));
		nn_attrs++;
	}

	if (opt_application_id != NULL)   {
		size_t oid_buf_len;

		if (sc_format_oid(&oid, opt_application_id))
			util_fatal("Invalid OID \"%s\"\n", opt_application_id);

		if (sc_asn1_encode_object_id(&oid_buf, &oid_buf_len, &oid))
			util_fatal("Cannot encode OID \"%s\"\n", opt_application_id);

		FILL_ATTR(attrs[nn_attrs], CKA_OBJECT_ID, oid_buf, oid_buf_len);
		nn_attrs++;
	}

	if (opt_issuer != NULL)   {
		size_t sz = sizeof(issuer);

		if (sc_hex_to_bin(opt_issuer, issuer, &sz))
			util_fatal("Invalid 'issuer' hexadecimal value");
		FILL_ATTR(attrs[nn_attrs], CKA_ISSUER, issuer,  sz);
		nn_attrs++;
	}

	if (opt_subject != NULL)   {
		size_t sz = sizeof(subject);

		if (sc_hex_to_bin(opt_subject, subject, &sz))
			util_fatal("Invalid 'subject' hexadecimal value");
		FILL_ATTR(attrs[nn_attrs], CKA_SUBJECT, subject,  sz);
		nn_attrs++;
	}

	rv = find_object_with_attributes(session, &obj, attrs, nn_attrs, 0);
	if (rv != CKR_OK)
		p11_fatal("find_object_with_attributes()", rv);
	else if (obj==CK_INVALID_HANDLE)
		util_fatal("object not found\n");

/* TODO: -DEE should look at object class, and get appropriate values
 * based on the object, and other attributes. For example EC keys do
 * not have a VALUE But have a EC_POINT.
 */
	value = getVALUE(session, obj, &len);
	if (value == NULL)
		util_fatal("get CKA_VALUE failed\n");

	if (opt_output)   {
		out = fopen(opt_output, "wb");
		if (out==NULL)
			util_fatal("cannot open '%s'\n", opt_output);
	}
	else
		out = stdout;

	if (fwrite(value, 1, len, out) != len)
		util_fatal("cannot write to '%s'\n", opt_output);
	if (opt_output)
		fclose(out);

	if (oid_buf)
		free(oid_buf);
	return 1;
}

/*
 * Delete object.
 */
static int delete_object(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_ATTRIBUTE attrs[20];
	CK_OBJECT_CLASS clazz = opt_object_class;
	CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
	int nn_attrs = 0;
	struct sc_object_id oid;
	unsigned char *oid_buf = NULL;

	if (opt_object_class_str != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_CLASS,
				 &clazz, sizeof(clazz));
		nn_attrs++;
	}

	if (opt_object_id_len != 0)  {
		FILL_ATTR(attrs[nn_attrs], CKA_ID,
				opt_object_id, opt_object_id_len);
		nn_attrs++;
	}

	if (opt_object_label != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_LABEL,
				opt_object_label, strlen(opt_object_label));
		nn_attrs++;
	}

	if (opt_application_label != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_APPLICATION,
				opt_application_label, strlen(opt_application_label));
		nn_attrs++;
	}

	if (opt_application_id != NULL)   {
		size_t oid_buf_len;

		if (sc_format_oid(&oid, opt_application_id))
			util_fatal("Invalid OID '%s'\n", opt_application_id);

		if (sc_asn1_encode_object_id(&oid_buf, &oid_buf_len, &oid))
			util_fatal("Cannot encode OID \"%s\"\n", opt_application_id);

		FILL_ATTR(attrs[nn_attrs], CKA_OBJECT_ID, oid_buf, oid_buf_len);
		nn_attrs++;
	}

	rv = find_object_with_attributes(session, &obj, attrs, nn_attrs, 0);
	if (rv != CKR_OK)
		p11_fatal("find_object_with_attributes()", rv);
	else if (obj==CK_INVALID_HANDLE)
		util_fatal("object not found\n");
	rv = p11->C_DestroyObject(session, obj);
	if (rv != CKR_OK)
		p11_fatal("C_DestroyObject()", rv);

	if (oid_buf)
		free(oid_buf);

	return 1;
}

static CK_ULONG	get_private_key_length(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE prkey)
{
	unsigned char  *id;
	CK_ULONG        idLen;
	CK_OBJECT_HANDLE pubkey;

	id = NULL;
	id = getID(sess, prkey, &idLen);
	if (id == NULL) {
		printf("private key has no ID, can't lookup the corresponding pubkey\n");
		return 0;
	}

	if (!find_object(sess, CKO_PUBLIC_KEY, &pubkey, id, idLen, 0)) {
		free(id);
		printf("coudn't find the corresponding pubkey\n");
		return 0;
	}
	free(id);

	return getMODULUS_BITS(sess, pubkey);
}

static int test_digest(CK_SESSION_HANDLE session)
{
	int             errors = 0;
	CK_RV           rv;
	CK_MECHANISM    ck_mech = { CKM_MD5, NULL, 0 };
	CK_ULONG        i, j;
	unsigned char   data[100];
	unsigned char   hash1[64], hash2[64];
	CK_ULONG        hashLen1, hashLen2;
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;

	CK_MECHANISM_TYPE mechTypes[] = {
		CKM_MD5,
		CKM_SHA_1,
		CKM_RIPEMD160,
		0xffffff
	};
	unsigned char  *digests[] = {
		(unsigned char *) "\x7a\x08\xb0\x7e\x84\x64\x17\x03\xe5\xf2\xc8\x36\xaa\x59\xa1\x70",
		(unsigned char *) "\x29\xb0\xe7\x87\x82\x71\x64\x5f\xff\xb7\xee\xc7\xdb\x4a\x74\x73\xa1\xc0\x0b\xc1",
		(unsigned char *) "\xda\x79\xa5\x8f\xb8\x83\x3d\x61\xf6\x32\x16\x17\xe3\xfd\xf0\x56\x26\x5f\xb7\xcd"
	};
	CK_ULONG        digestLens[] = {
		16,
		20,
		20
	};

	rv = p11->C_GetSessionInfo(session, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	if (!find_mechanism(sessionInfo.slotID, CKF_DIGEST, NULL, 0, &firstMechType)) {
		printf("Digests: not implemented\n");
		return errors;
	}
	else    {
		printf("Digests:\n");
	}

	/* 1st test */

	ck_mech.mechanism = firstMechType;
	rv = p11->C_DigestInit(session, &ck_mech);
	if (rv != CKR_OK)
		p11_fatal("C_DigestInit", rv);

	rv = p11->C_DigestUpdate(session, data, 5);
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		printf("  Note: C_DigestUpdate(), DigestFinal() not supported\n");
		/* finish the digest operation */
		hashLen2 = sizeof(hash2);
		rv = p11->C_Digest(session, data, sizeof(data), hash2,
			&hashLen2);
		if (rv != CKR_OK)
			p11_fatal("C_Digest", rv);
	} else {
		if (rv != CKR_OK)
			p11_fatal("C_DigestUpdate", rv);

		rv = p11->C_DigestUpdate(session, data + 5, 50);
		if (rv != CKR_OK)
			p11_fatal("C_DigestUpdate", rv);

		rv = p11->C_DigestUpdate(session, data + 55,
			sizeof(data) - 55);
		if (rv != CKR_OK)
			p11_fatal("C_DigestUpdate", rv);

		hashLen1 = sizeof(hash1);
		rv = p11->C_DigestFinal(session, hash1, &hashLen1);
		if (rv != CKR_OK)
			p11_fatal("C_DigestFinal", rv);

		rv = p11->C_DigestInit(session, &ck_mech);
		if (rv != CKR_OK)
			p11_fatal("C_DigestInit", rv);

		hashLen2 = sizeof(hash2);
		rv = p11->C_Digest(session, data, sizeof(data), hash2,
			&hashLen2);
		if (rv != CKR_OK)
			p11_fatal("C_Digest", rv);

		if (hashLen1 != hashLen2) {
			errors++;
			printf("  ERR: digest lengths returned by C_DigestFinal() different from C_Digest()\n");
		} else if (memcmp(hash1, hash2, hashLen1) != 0) {
			errors++;
			printf("  ERR: digests returned by C_DigestFinal() different from C_Digest()\n");
		} else
			printf("  all 4 digest functions seem to work\n");
	}

	/* 2nd test */

	/* input = "01234567890123456...456789" */
	for (i = 0; i < 10; i++)
		for (j = 0; j < 10; j++)
			data[10 * i + j] = (unsigned char) (0x30 + j);


	for (i = 0; mechTypes[i] != 0xffffff; i++) {
		ck_mech.mechanism = mechTypes[i];

		rv = p11->C_DigestInit(session, &ck_mech);
		if (rv == CKR_MECHANISM_INVALID)
			continue;	/* mechanism not implemented, don't test */
		if (rv != CKR_OK)
			p11_fatal("C_DigestInit", rv);

		printf("  %s: ", p11_mechanism_to_name(mechTypes[i]));

		hashLen1 = sizeof(hash1);
		rv = p11->C_Digest(session, data, sizeof(data), hash1,
			&hashLen1);
		if (rv != CKR_OK)
			p11_fatal("C_Digest", rv);

		if (hashLen1 != digestLens[i]) {
			errors++;
			printf("ERR: wrong digest length: %ld instead of %ld\n",
					hashLen1, digestLens[i]);
		} else if (memcmp(hash1, digests[i], hashLen1) != 0) {
			errors++;
			printf("ERR: wrong digest value\n");
		} else
			printf("OK\n");
	}

	/* 3rd test */

	ck_mech.mechanism = firstMechType;
	rv = p11->C_DigestInit(session, &ck_mech);
	if (rv != CKR_OK)
		p11_fatal("C_DigestInit", rv);

	hashLen2 = 1;		/* too short */
	rv = p11->C_Digest(session, data, sizeof(data), hash2, &hashLen2);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		errors++;
		printf("  ERR: C_Digest() didn't return CKR_BUFFER_TOO_SMALL but %s (0x%0x)\n", CKR2Str(rv), (int) rv);
	}
	/* output buffer = NULL */
	rv = p11->C_Digest(session, data, sizeof(data), NULL, &hashLen2);
	if (rv != CKR_OK) {
		errors++;
		printf("  ERR: C_Digest() didn't return CKR_OK for a NULL output buffer, but %s (0x%0x)\n", CKR2Str(rv), (int) rv);
	}

	rv = p11->C_Digest(session, data, sizeof(data), hash2, &hashLen2);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		printf("  ERR: digest operation ended prematurely\n");
		errors++;
	} else if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	return errors;
}

#ifdef ENABLE_OPENSSL
static EVP_PKEY *get_public_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKeyObject)
{
	CK_BYTE         *id, *mod, *exp;
	CK_ULONG         idLen = 0, modLen = 0, expLen = 0;
	CK_OBJECT_HANDLE pubkeyObject;
	unsigned char  *pubkey;
	const unsigned char *pubkey_c;
	CK_ULONG        pubkeyLen;
	EVP_PKEY       *pkey;
	RSA            *rsa;

	id = NULL;
	id = getID(session, privKeyObject, &idLen);
	if (id == NULL) {
		printf("private key has no ID, can't lookup the corresponding pubkey for verification\n");
		return NULL;
	}

	if (!find_object(session, CKO_PUBLIC_KEY, &pubkeyObject, id, idLen, 0)) {
		free(id);
		printf("coudn't find the corresponding pubkey for validation\n");
		return NULL;
	}
	free(id);

	switch(getKEY_TYPE(session, pubkeyObject)) {
		case CKK_RSA:
			pkey = EVP_PKEY_new();
			rsa = RSA_new();
			mod = getMODULUS(session, pubkeyObject, &modLen);
			exp = getPUBLIC_EXPONENT(session, pubkeyObject, &expLen);
			if ( !pkey || !rsa || !mod || !exp) {
				printf("public key not extractable\n");
				if (pkey)
					EVP_PKEY_free(pkey);
				if (rsa)
					RSA_free(rsa);
				if (mod)
					free(mod);
				if (exp)
					free(exp);
				return NULL;
			}
			rsa->n = BN_bin2bn(mod, modLen, NULL);
			rsa->e = BN_bin2bn(exp, expLen, NULL);
			EVP_PKEY_assign_RSA(pkey, rsa);
			free(mod);
			free(exp);
			return pkey;
		case CKK_DSA:
		case CKK_ECDSA:
		case CKK_GOSTR3410:
			break;
		default:
			printf("public key of unsupported type\n");
			return NULL;
	}

	pubkey = getVALUE(session, pubkeyObject, &pubkeyLen);
	if (pubkey == NULL) {
		printf("couldn't get the pubkey VALUE attribute, no validation done\n");
		return NULL;
	}

	pubkey_c = pubkey;
	pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &pubkey_c, pubkeyLen);
	free(pubkey);

	if (pkey == NULL) {
		printf(" couldn't parse pubkey, no verification done\n");
		return NULL;
	}

	return pkey;
}
#endif

static int sign_verify_openssl(CK_SESSION_HANDLE session,
		CK_MECHANISM *ck_mech, CK_OBJECT_HANDLE privKeyObject,
		unsigned char *data, CK_ULONG dataLen,
		unsigned char *verifyData, CK_ULONG verifyDataLen,
		CK_ULONG modLenBytes, int evp_md_index)
{
	int 		errors = 0;
	CK_RV           rv;
	unsigned char   sig1[1024];
	CK_ULONG        sigLen1;

#ifdef ENABLE_OPENSSL
	int             err;
	EVP_PKEY       *pkey;
	EVP_MD_CTX      *md_ctx;

	const EVP_MD         *evp_mds[] = {
		EVP_sha1(),
		EVP_sha1(),
		EVP_sha1(),
		EVP_md5(),
		EVP_ripemd160(),
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
		EVP_sha256(),
#endif
	};
#endif

	rv = p11->C_SignInit(session, ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

	if (getALWAYS_AUTHENTICATE(session, privKeyObject))
		login(session,CKU_CONTEXT_SPECIFIC);
	printf("    %s: ", p11_mechanism_to_name(ck_mech->mechanism));

	sigLen1 = sizeof(sig1);
	rv = p11->C_Sign(session, data, dataLen, sig1,
		&sigLen1);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	if (sigLen1 != modLenBytes) {
		errors++;
		printf("  ERR: wrong signature length: %u instead of %u\n",
				(unsigned int) sigLen1,
				(unsigned int) modLenBytes);
	}
#ifndef ENABLE_OPENSSL
	printf("unable to verify signature (compile with ENABLE_OPENSSL)\n");
#else

	if (!(pkey = get_public_key(session, privKeyObject)))
		return errors;

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx)
		err = -1;
	else {
		EVP_VerifyInit(md_ctx, evp_mds[evp_md_index]);
		EVP_VerifyUpdate(md_ctx, verifyData, verifyDataLen);
		err = EVP_VerifyFinal(md_ctx, sig1, sigLen1, pkey);
		EVP_MD_CTX_destroy(md_ctx);
		EVP_PKEY_free(pkey);
	}
	if (err == 0) {
		printf("ERR: verification failed\n");
		errors++;
	} else if (err != 1) {
		printf("openssl error during verification: 0x%0x (%d)\n", err, err);
	} else
		printf("OK\n");

	/* free(cert); */
#endif

	return errors;
}

/*
 * Test signature functions
 */
static int test_signature(CK_SESSION_HANDLE sess)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_MECHANISM    ck_mech = { CKM_MD5, NULL, 0 };
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        i, j;
	unsigned char   data[256];
	CK_ULONG        modLenBytes = 0;
	CK_ULONG        dataLen;
	unsigned char   sig1[1024], sig2[1024];
	CK_ULONG        sigLen1, sigLen2;
	unsigned char   verifyData[100];
	char 		*label;

	CK_MECHANISM_TYPE mechTypes[] = {
		CKM_RSA_X_509,
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_MD5_RSA_PKCS,
		CKM_RIPEMD160_RSA_PKCS,
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
		CKM_SHA256_RSA_PKCS,
#endif
		0xffffff
	};
	size_t mechTypes_num = sizeof(mechTypes)/sizeof(CK_MECHANISM_TYPE);
	unsigned char  *datas[] = {
		/* PCKS1_wrap(SHA1_encode(SHA-1(verifyData))),
		 * is done further on
		 */
		NULL,

		/* SHA1_encode(SHA-1(verifyData)) */
		(unsigned char *) "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x29\xb0\xe7\x87\x82\x71\x64\x5f\xff\xb7\xee\xc7\xdb\x4a\x74\x73\xa1\xc0\x0b\xc1",

		verifyData,
		verifyData,
		verifyData,
		verifyData,
	};
	CK_ULONG        dataLens[] = {
		0,		/* should be modulus length, is done further on */
		35,
		sizeof(verifyData),
		sizeof(verifyData),
		sizeof(verifyData),
		sizeof(verifyData),
	};

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Signatures: not logged in, skipping signature tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_SIGN | CKF_HW, mechTypes, mechTypes_num, &firstMechType)) {
		printf("Signatures: not implemented\n");
		return errors;
	}

	printf("Signatures (currently only RSA signatures)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}

		if (!getSIGN(sess, privKeyObject)) {
			printf(" -- can't be used for signature, skipping\n");
			continue;
		}

		modLenBytes = (get_private_key_length(sess, privKeyObject) + 7) / 8;
		if(!modLenBytes) {
			printf(" -- can't be used for signature, skipping: can't obtain modulus\n");
			continue;
		}
		printf("\n");
		break;
	}
	if (privKeyObject == CK_INVALID_HANDLE) {
		printf("Signatures: no private key found in this slot\n");
		return 0;
	}

	data[0] = 0;
	data[1] = 1;

	/* 1st test */

	/* assume --login has already authenticated the key */
	switch (firstMechType) {
	case CKM_RSA_PKCS:
		dataLen = 35;
		memcpy(data, datas[1], dataLen);
		break;
	case CKM_RSA_X_509:
		dataLen = modLenBytes;
		break;
	default:
		dataLen = sizeof(data);	/* let's hope it's OK */
		break;
	}

	ck_mech.mechanism = firstMechType;
	rv = p11->C_SignInit(sess, &ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

	rv = p11->C_SignUpdate(sess, data, 5);
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		p11_warn("C_SignUpdate", rv);
	} else if (rv != CKR_OK) {
		p11_perror("C_SignUpdate", rv);
		errors++;
	} else {
		if (rv != CKR_OK)
			p11_fatal("C_SignUpdate", rv);

		rv = p11->C_SignUpdate(sess, data + 5, 10);
		if (rv != CKR_OK)
			p11_fatal("C_SignUpdate", rv);

		rv = p11->C_SignUpdate(sess, data + 15, dataLen - 15);
		if (rv != CKR_OK)
			p11_fatal("C_SignUpdate", rv);

		sigLen1 = sizeof(sig1);
		rv = p11->C_SignFinal(sess, sig1, &sigLen1);
		if (rv != CKR_OK)
			p11_fatal("C_SignFinal", rv);

		rv = p11->C_SignInit(sess, &ck_mech, privKeyObject);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);
		if (getALWAYS_AUTHENTICATE(sess, privKeyObject))
			login(sess,CKU_CONTEXT_SPECIFIC);

		sigLen2 = sizeof(sig2);
		rv = p11->C_Sign(sess, data, dataLen, sig2, &sigLen2);
		if (rv != CKR_OK)
			p11_fatal("C_Sign", rv);

		if (sigLen1 != sigLen2) {
			errors++;
			printf("  ERR: signature lengths returned by C_SignFinal() different from C_Sign()\n");
		} else if (memcmp(sig1, sig2, sigLen1) != 0) {
			errors++;
			printf("  ERR: signatures returned by C_SignFinal() different from C_Sign()\n");
		} else
			printf("  all 4 signature functions seem to work\n");
	}

	/* 2nd test */

	ck_mech.mechanism = firstMechType;
	rv = p11->C_SignInit(sess, &ck_mech, privKeyObject);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

	sigLen2 = 1;		/* too short */
	rv = p11->C_Sign(sess, data, dataLen, sig2, &sigLen2);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		errors++;
		printf("  ERR: C_Sign() didn't return CKR_BUFFER_TOO_SMALL but %s (0x%0x)\n", CKR2Str(rv), (int) rv);
	}

	/* output buf = NULL */
	rv = p11->C_Sign(sess, data, dataLen, NULL, &sigLen2);
	if (rv != CKR_OK) {
	   errors++;
	   printf("  ERR: C_Sign() didn't return CKR_OK for a NULL output buf, but %s (0x%0x)\n",
	   CKR2Str(rv), (int) rv);
	}
	if (getALWAYS_AUTHENTICATE(sess, privKeyObject))
		login(sess,CKU_CONTEXT_SPECIFIC);

	rv = p11->C_Sign(sess, data, dataLen, sig2, &sigLen2);
	if (rv == CKR_OPERATION_NOT_INITIALIZED) {
		printf("  ERR: signature operation ended prematurely\n");
		errors++;
	} else if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	/* 3rd test */

	/* input = "01234567890123456...456789" */
	for (i = 0; i < 10; i++)
		for (j = 0; j < 10; j++)
			verifyData[10 * i + j] = (unsigned char) (0x30 + j);

	/* Fill in data[0] and dataLens[0] */
	dataLen = modLenBytes;
	data[1] = 0x01;
	memset(data + 2, 0xFF, dataLen - 3 - dataLens[1]);
	data[dataLen - 36] = 0x00;
	memcpy(data + (dataLen - dataLens[1]), datas[1], dataLens[1]);
	datas[0] = data;
	dataLens[0] = dataLen;

	printf("  testing signature mechanisms:\n");
	for (i = 0; mechTypes[i] != 0xffffff; i++) {
		ck_mech.mechanism = mechTypes[i];
		errors += sign_verify_openssl(sess, &ck_mech, privKeyObject,
			datas[i], dataLens[i], verifyData, sizeof(verifyData),
			modLenBytes, i);
	}

	/* 4rd test: the other signature keys */

	for (i = 0; mechTypes[i] != 0xffffff; i++)
		if (i == firstMechType)
			break;
	ck_mech.mechanism = mechTypes[i];
	j = 1;  /* j-th signature key */
	while (find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j++) != 0) {
		CK_ULONG	modLenBits;

		label = getLABEL(sess, privKeyObject, NULL);
		modLenBits = get_private_key_length(sess, privKeyObject);
		modLenBytes = (modLenBits + 7) / 8;

		printf("  testing key %d (%u bits%s%s) with 1 signature mechanism",
				(int) (j-1),
				(int) modLenBits,
				label? ", label=" : "",
				label? label : "");
		if (label)
			free(label);

		if (!getSIGN(sess, privKeyObject)) {
			printf(" -- can't be used to sign/verify, skipping\n");
			continue;
		}
		else if (!modLenBytes)   {
			printf(" -- can't be used to sign/verify, skipping: can't obtain modulus\n");
			continue;
		}
		else   {
			printf("\n");
		}

		errors += sign_verify_openssl(sess, &ck_mech, privKeyObject,
			datas[i], dataLens[i], verifyData, sizeof(verifyData),
			modLenBytes, i);
	}

	return errors;
}

static int sign_verify(CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE priv_key, int key_len,
	CK_OBJECT_HANDLE pub_key, int one_test)
{
	CK_RV rv;
	CK_MECHANISM_TYPE mech_types[] = {
		CKM_RSA_X_509,
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_MD5_RSA_PKCS,
		CKM_RIPEMD160_RSA_PKCS,
		0xffffff
	};
	CK_MECHANISM_TYPE *mech_type;
	unsigned char buf[512] = {0};
	unsigned char *datas[] = {
		buf,
		(unsigned char *) "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x29\xb0\xe7\x87\x82\x71\x64\x5f\xff\xb7\xee\xc7\xdb\x4a\x74\x73\xa1\xc0\x0b\xc1",
		buf,
		buf,
		buf
	};
	int data_lens[] = {
		key_len,
		35,
		234,
		345,
		456
	};
	unsigned char signat[512];
	CK_ULONG signat_len;
	int j, errors = 0;

	memcpy(buf, "\x00\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00", 11);

	for (j = 0, mech_type = mech_types; *mech_type != 0xffffff; mech_type++, j++) {
		CK_MECHANISM mech = {*mech_type, NULL, 0};

		rv = p11->C_SignInit(session, &mech, priv_key);
		if (rv == CKR_MECHANISM_INVALID)
			continue;
		if (rv != CKR_OK) {
			printf("  ERR: C_SignInit() returned %s (0x%0x)\n", CKR2Str(rv), (int) rv);
			return ++errors;
		}

		printf("    %s: ", p11_mechanism_to_name(*mech_type));
		if (getALWAYS_AUTHENTICATE(session, priv_key))
			login(session,CKU_CONTEXT_SPECIFIC);

		signat_len = sizeof(signat);
		rv = p11->C_Sign(session, datas[j], data_lens[j], signat, &signat_len);
		if (rv != CKR_OK) {
			printf("  ERR: C_Sign() returned %s (0x%0x)\n", CKR2Str(rv), (int) rv);
			return ++errors;
		}

		rv = p11->C_VerifyInit(session, &mech, pub_key);
		if (rv != CKR_OK) {
			printf("  ERR: C_VerifyInit() returned %s (0x%0x)\n", CKR2Str(rv), (int) rv);
			return ++errors;
		}
		rv = p11->C_Verify(session, datas[j], data_lens[j], signat, signat_len);
		if (rv == CKR_SIGNATURE_INVALID) {
			printf("  ERR: verification failed");
			errors++;
		}
		if (rv != CKR_OK) {
			printf("  ERR: C_Verify() returned %s (0x%0x)\n", CKR2Str(rv), (int) rv);
			return ++errors;
		}
		else
			printf("OK\n");

		if (one_test)
			return errors;
	}

	return errors;
}

static int test_verify(CK_SESSION_HANDLE sess)
{
	int key_len, i, errors = 0;
	CK_OBJECT_HANDLE priv_key, pub_key;
	CK_MECHANISM_TYPE first_mech_type;
	CK_SESSION_INFO sessionInfo;
	CK_RV rv;

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Verify: not logged in, skipping verify tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_VERIFY, NULL, 0, &first_mech_type)) {
		printf("Verify: not implemented\n");
		return errors;
	}

	printf("Verify (currently only for RSA):\n");

	for (i = 0; find_object(sess, CKO_PRIVATE_KEY, &priv_key, NULL, 0, i); i++) {
		char *label;
		unsigned char *id;
		CK_ULONG id_len;

		printf("  testing key %d", i);
		if ((label = getLABEL(sess, priv_key, NULL)) != NULL) {
			printf(" (%s)", label);
			free(label);
		}
		if (i != 0)
			printf(" with 1 mechanism");
		printf("\n");

		if (!getSIGN(sess, priv_key)) {
			printf(" -- can't be used to sign/verify, skipping\n");
			continue;
		}
		if ((id = getID(sess, priv_key, &id_len)) != NULL) {
			int r;

			r = find_object(sess, CKO_PUBLIC_KEY, &pub_key, id, id_len, 0);
			free(id);
			if (r == 0) {
				printf(" -- can't find corresponding public key, skipping\n");
				continue;
			}
		}
		else {
			printf(" -- can't get the ID for looking up the public key, skipping\n");
			continue;
		}

		key_len = (get_private_key_length(sess, priv_key) + 7) / 8;
		if(!key_len) {
			printf(" -- can't get the modulus length, skipping\n");
			continue;
		}

		errors += sign_verify(sess, priv_key, key_len, pub_key, i != 0);
	}

	if (i == 0)
		printf("  No private key found for testing\n");

	return errors;
}

#ifdef ENABLE_OPENSSL
static int wrap_unwrap(CK_SESSION_HANDLE session,
	    const EVP_CIPHER *algo, CK_OBJECT_HANDLE privKeyObject)
{
	CK_OBJECT_HANDLE cipherKeyObject;
	CK_RV           rv;
	EVP_PKEY       *pkey;
	EVP_CIPHER_CTX	seal_ctx;
	unsigned char	keybuf[512], *key = keybuf;
	int		key_len;
	unsigned char	iv[32], ciphered[1024], cleartext[1024];
	int		ciphered_len, cleartext_len, len;
	CK_MECHANISM	mech;
	CK_ULONG	key_type = CKM_DES_CBC;
	CK_ULONG key_len_ul;
	CK_ATTRIBUTE	key_template = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };

	pkey = get_public_key(session, privKeyObject);
	if (pkey == NULL)
		return 0;

	printf("    %s: ", OBJ_nid2sn(EVP_CIPHER_nid(algo)));

	if (!EVP_SealInit(&seal_ctx, algo,
			&key, &key_len,
			iv, &pkey, 1)) {
		printf("Internal error.\n");
		return 1;
	}

	/* Encrypt something */
	len = sizeof(ciphered);
	if (!EVP_SealUpdate(&seal_ctx, ciphered, &len, (const unsigned char *) "hello world", 11)) {
		printf("Internal error.\n");
		return 1;
	}
	ciphered_len = len;

	len = sizeof(ciphered) - ciphered_len;
	if (!EVP_SealFinal(&seal_ctx, ciphered + ciphered_len, &len)) {
		printf("Internal error.\n");
		return 1;
	}
	ciphered_len += len;

	EVP_PKEY_free(pkey);

	mech.mechanism = CKM_RSA_PKCS;
	rv = p11->C_UnwrapKey(session, &mech, privKeyObject,
			key, key_len,
			&key_template, 1,
			&cipherKeyObject);

	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID) {
		printf("Wrap mechanism not supported, skipped\n");
		return 0;
	}
	if (rv != CKR_OK) {
		p11_perror("C_UnwrapKey", rv);
		return 1;
	}

	/* Try to decrypt */
	key = getVALUE(session, cipherKeyObject, &key_len_ul);
	key_len = key_len_ul;
	if (key == NULL) {
		printf("Could not get unwrapped key\n");
		return 1;
	}
	if (key_len != EVP_CIPHER_key_length(algo)) {
		printf("Key length mismatch (%d != %d)\n",
				key_len, EVP_CIPHER_key_length(algo));
		return 1;
	}

	if (!EVP_DecryptInit(&seal_ctx, algo, key, iv)) {
		printf("Internal error.\n");
		return 1;
	}

	len = sizeof(cleartext);
	if (!EVP_DecryptUpdate(&seal_ctx, cleartext, &len, ciphered, ciphered_len)) {
		printf("Internal error.\n");
		return 1;
	}

	cleartext_len = len;
	len = sizeof(cleartext) - len;
	if (!EVP_DecryptFinal(&seal_ctx, cleartext + cleartext_len, &len)) {
		printf("Internal error.\n");
		return 1;
	}
	cleartext_len += len;

	if (cleartext_len != 11
	 || memcmp(cleartext, "hello world", 11)) {
		printf("resulting cleartext doesn't match input\n");
		return 1;
	}

	printf("OK\n");
	return 0;
}
#endif


/*
 * Test unwrap functions
 */
static int test_unwrap(CK_SESSION_HANDLE sess)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        j;
	char 		*label;

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if (!(sessionInfo.state & CKS_RW_USER_FUNCTIONS)) {
		printf("Key unwrap: not a R/W session, skipping key unwrap tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_UNWRAP | CKF_HW, NULL, 0, &firstMechType)) {
		printf("Unwrap: not implemented\n");
		return errors;
	}

	printf("Key unwrap (RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}
		if (!getUNWRAP(sess, privKeyObject)) {
			printf(" -- can't be used to unwrap, skipping\n");
			continue;
		}
		printf("\n");

#ifndef ENABLE_OPENSSL
		printf("No OpenSSL support, unable to validate C_Unwrap\n");
#else
		errors += wrap_unwrap(sess, EVP_des_cbc(), privKeyObject);
		errors += wrap_unwrap(sess, EVP_des_ede3_cbc(), privKeyObject);
		errors += wrap_unwrap(sess, EVP_bf_cbc(), privKeyObject);
		errors += wrap_unwrap(sess, EVP_cast5_cfb(), privKeyObject);
#endif
	}

	return errors;
}

#ifdef ENABLE_OPENSSL
static int encrypt_decrypt(CK_SESSION_HANDLE session,
		CK_MECHANISM_TYPE mech_type,
		CK_OBJECT_HANDLE privKeyObject)
{
	EVP_PKEY       *pkey;
	unsigned char	orig_data[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '\0'};
	unsigned char	encrypted[512], data[512];
	CK_MECHANISM	mech;
	CK_ULONG	encrypted_len, data_len;
	int             failed;
	CK_RV           rv;

	printf("    %s: ", p11_mechanism_to_name(mech_type));

	pkey = get_public_key(session, privKeyObject);
	if (pkey == NULL)
		return 0;

	if (EVP_PKEY_size(pkey) > (int)sizeof(encrypted)) {
		printf("Ciphertext buffer too small\n");
		EVP_PKEY_free(pkey);
		return 0;
	}
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
	encrypted_len = EVP_PKEY_encrypt_old(encrypted, orig_data, sizeof(orig_data), pkey);
#else
	encrypted_len = EVP_PKEY_encrypt(encrypted, orig_data, sizeof(orig_data), pkey);
#endif
	EVP_PKEY_free(pkey);
	if (encrypted_len <= 0) {
		printf("Encryption failed, returning\n");
		return 0;
	}

	mech.mechanism = mech_type;
	rv = p11->C_DecryptInit(session, &mech, privKeyObject);
	if (rv == CKR_MECHANISM_INVALID) {
		printf("Mechanism not supported\n");
		return 0;
	}
	if (rv != CKR_OK)
		p11_fatal("C_DecryptInit", rv);

	data_len = encrypted_len;
	rv = p11->C_Decrypt(session, encrypted, encrypted_len, data, &data_len);
	if (rv != CKR_OK)
		p11_fatal("C_Decrypt", rv);

	if (mech_type == CKM_RSA_X_509)
		failed = (data[0] != 0) || (data[1] != 2) || (data_len <= sizeof(orig_data) - 2) ||
		    memcmp(orig_data, data + data_len - sizeof(orig_data), sizeof(orig_data));
	else
		failed = data_len != sizeof(orig_data) || memcmp(orig_data, data, data_len);

	if (failed) {
		CK_ULONG n;

		printf("resulting cleartext doesn't match input\n");
		printf("    Original:");
		for (n = 0; n < sizeof(orig_data); n++)
			printf(" %02x", orig_data[n]);
		printf("\n");
		printf("    Decrypted:");
		for (n = 0; n < data_len; n++)
			printf(" %02x", data[n]);
		printf("\n");
		return 1;
	}

	printf("OK\n");
	return 0;
}
#endif


/*
 * Test decryption functions
 */
static int test_decrypt(CK_SESSION_HANDLE sess)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        j, n, num_mechs = 0;
	char 		*label;

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Decryption: not logged in, skipping decryption tests\n");
		return errors;
	}

	num_mechs = get_mechanisms(sessionInfo.slotID, &mechs, CKF_DECRYPT);
	if (num_mechs == 0) {
		printf("Decrypt: not implemented\n");
		return errors;
	}

	printf("Decryption (RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}
		if (!getDECRYPT(sess, privKeyObject)) {
			printf(" -- can't be used to decrypt, skipping\n");
			continue;
		}
		printf("\n");

#ifndef ENABLE_OPENSSL
		printf("No OpenSSL support, unable to validate decryption\n");
		n = 0;
#else
		for (n = 0; n < num_mechs; n++) {
			errors += encrypt_decrypt(sess, mechs[n], privKeyObject);
		}
#endif
	}

	free(mechs);
	return errors;
}

static int test_random(CK_SESSION_HANDLE session)
{
	CK_BYTE buf1[100], buf2[100];
	CK_BYTE seed1[100];
	CK_RV rv;
	int errors = 0;

	printf("C_SeedRandom() and C_GenerateRandom():\n");

	rv = p11->C_SeedRandom(session, seed1, 100);
	if (rv == CKR_RANDOM_NO_RNG) {
		printf("  RNG not available\n");
		return 0;
	}

	if (rv == CKR_RANDOM_SEED_NOT_SUPPORTED || rv == CKR_FUNCTION_NOT_SUPPORTED)
		printf("  seeding (C_SeedRandom) not supported\n");
	else if (rv != CKR_OK) {
		p11_perror("C_SeedRandom", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, buf1, 10);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, buf1, 100);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf1,100)", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, buf1, 0);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf1,0)", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, buf2, 100);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf2,100)", rv);
		return 1;
	}

	if (memcmp(buf1, buf2, 100) == 0) {
		printf("  ERR: C_GenerateRandom returned twice the same value!!!\n");
		errors++;
	}

	printf("  seems to be OK\n");

	return 0;
}

static int test_card_detection(int wait_for_event)
{
	char buffer[256];
	CK_SLOT_ID slot_id;
	CK_RV rv;

	printf("Testing card detection using %s\n",
		wait_for_event? "C_WaitForSlotEvent()" : "C_GetSlotList()");

	while (1) {
		printf("Please press return to continue, x to exit: ");
		fflush(stdout);
		if (fgets(buffer, sizeof(buffer), stdin) == NULL
		|| buffer[0] == 'x')
			break;

		if (wait_for_event) {
			printf("Calling C_WaitForSlotEvent: ");
			fflush(stdout);
			rv = p11->C_WaitForSlotEvent(0, &slot_id, NULL);
			if (rv != CKR_OK) {
				printf("failed.\n");
				p11_perror("C_WaitForSlotEvent", rv);
				return 1;
			}
			printf("event on slot 0x%lx\n", slot_id);
		}
		list_slots(0, 1, 1);
	}

	return 0;
}

static int p11_test(CK_SESSION_HANDLE session)
{
	int errors = 0;

	errors += test_random(session);

	errors += test_digest(session);

	errors += test_signature(session);

	errors += test_verify(session);

	errors += test_unwrap(session);

	errors += test_decrypt(session);

	if (errors == 0)
		printf("No errors\n");
	else
		printf("%d errors\n", errors);

	return errors;
}

/* Does about the same as Mozilla does when you go to an on-line CA
 * for obtaining a certificate: key pair generation, signing the
 * cert request + some other tests, writing certs and changing
 * some attributes.
 */
static void test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	CK_MECHANISM		mech = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM_TYPE	*mech_type = NULL;
	CK_OBJECT_HANDLE	pub_key, priv_key;
	CK_ULONG		i, num_mechs = 0;
	CK_RV			rv;
	CK_BYTE			buf[20], *tmp;
	CK_BYTE			md5_and_digestinfo[34] = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10";
	CK_BYTE			*data, sig[512];
	CK_ULONG		data_len, sig_len;
	CK_BYTE 		id[] = "abcdefghijklmnopqrst";
	CK_ULONG		id_len = 20, mod_len = 0;
	CK_BYTE			*label = (CK_BYTE *) "Just a label";
	CK_ULONG		label_len = 12;
	CK_ATTRIBUTE		attribs[3] = {
		{CKA_ID, id, id_len},
		{CKA_LABEL, label, label_len},
		{CKA_SUBJECT, (void *) "This won't be used in our lib", 29}
	};
	FILE                    *f;

	printf("\n*** We already opened a session and logged in ***\n");

	num_mechs = get_mechanisms(slot, &mech_type, -1);
	for (i = 0; i < num_mechs; i++) {
		if (mech_type[i] == CKM_RSA_PKCS_KEY_PAIR_GEN)
			break;
	}
	if (i == num_mechs) {
		printf("ERR: no \"CKM_RSA_PKCS_KEY_PAIR_GEN\" found in the mechanism list\n");
		return;
	}

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		util_fatal("Couldn't open file \"%s\"\n", opt_file_to_write);
	fclose(f);

	/* Get for a not-yet-existing ID */
	while(find_object(session, CKO_PRIVATE_KEY, &priv_key, id, id_len, 0))
		id[0]++;

	printf("\n*** Generating a %s key pair ***\n", opt_key_type);

	if (!gen_keypair(session, &pub_key, &priv_key, opt_key_type))
		return;

	tmp = getID(session, priv_key, (CK_ULONG *) &opt_object_id_len);
	if (opt_object_id_len == 0) {
		printf("ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return;
	}
	memcpy(opt_object_id, tmp, opt_object_id_len);

	/* This is done in NSS */
	getMODULUS(session, priv_key, &mod_len);
	if (mod_len < 5 || mod_len > 10000) { /* should be resonable limits */
		printf("ERR: GetAttribute(privkey, CKA_MODULUS) doesn't seem to work\n");
		return;
	}

	printf("\n*** Changing the CKA_ID of private and public key into one of 20 bytes ***\n");

	rv = p11->C_SetAttributeValue(session, priv_key, attribs, 1);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue(priv_key)", rv);

	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 1);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue(pub_key)", rv);

	printf("\n*** Do a signature and verify it (presumably to test the keys) ***\n");

	data = buf;
	data_len = 20;
	rv = p11->C_SignInit(session, &mech, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	rv = p11->C_Sign(session, data, data_len, NULL, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);
	sig_len = 20;
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		printf("ERR: C_Sign() didn't return CKR_BUFFER_TO_SMALL but %s\n", CKR2Str(rv));
		return;
	}
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	rv = p11->C_VerifyInit(session, &mech, pub_key);
	if (rv != CKR_OK)
		p11_fatal("C_VerifyInit", rv);
	rv = p11->C_Verify(session, data, data_len, sig, sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Verify", rv);

	/* Sign the certificate request */

	printf("\n*** Signing the certificate request ***\n");

	data = md5_and_digestinfo;
	data_len = 20;
	rv = p11->C_SignInit(session, &mech, priv_key);
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	printf("\n*** Changing the CKA_LABEL, CKA_ID and CKA_SUBJECT of the public key ***\n");

	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 3);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue", rv);

	printf("\n*** Logging off and releasing pkcs11 lib ***\n");

	rv = p11->C_CloseAllSessions(slot);
	if (rv != CKR_OK)
		p11_fatal("CloseAllSessions", rv);

	rv = p11->C_Finalize(NULL);
	if (rv != CKR_OK)
		p11_fatal("Finalize", rv);

	C_UnloadModule(module);

	/* Now we assume the user turns of her PC and comes back tomorrow to see
	 * if here cert is allready made and to install it (as is done next) */

	printf("\n*** In real life, the cert req should now be sent to the CA ***\n");

	printf("\n*** Loading the pkcs11 lib, opening a session and logging in ***\n");

	module = C_LoadModule(opt_module, &p11);
	if (module == NULL)
		util_fatal("Failed to load pkcs11 module");

	rv = p11->C_Initialize(NULL);
	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
		printf("\n*** Cryptoki library has already been initialized ***\n");
	else if (rv != CKR_OK)
		p11_fatal("C_Initialize", rv);

	rv = p11->C_OpenSession(opt_slot, CKF_SERIAL_SESSION| CKF_RW_SESSION,
			NULL, NULL, &session);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	login(session, CKU_USER);

	printf("\n*** Put a cert on the card (NOTE: doesn't correspond with the key!) ***\n");

	opt_object_class = CKO_CERTIFICATE;
	memcpy(opt_object_id, id, id_len);
	opt_object_id_len = id_len;
	opt_object_label = (char *) label;
	if (!write_object(session))
		return;

	printf("\n==> OK, successfull! Should work with Mozilla\n");
}


static void test_ec(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	CK_MECHANISM		mech = {CKM_ECDSA_SHA1, NULL_PTR, 0};
	CK_MECHANISM_TYPE	*mech_type = NULL;
	CK_OBJECT_HANDLE	pub_key, priv_key;
	CK_ULONG		i, num_mechs = 0;
	CK_RV			rv;
	CK_BYTE			*tmp;
	CK_BYTE			*data_to_sign = (CK_BYTE *)"My Heart's in the Highland";
	CK_BYTE			*data, sig[512];
	CK_ULONG		data_len, sig_len;
	CK_BYTE			*id = (CK_BYTE *) "abcdefghijklmnopqrst";
	CK_ULONG		id_len = strlen((char *)id), ec_params_len, ec_point_len;
	CK_BYTE			*label = (CK_BYTE *) "Just a label";
	CK_ULONG		label_len = 12;
	CK_ATTRIBUTE		attribs[3] = {
		{CKA_ID, id, id_len},
		{CKA_LABEL, label, label_len},
		{CKA_SUBJECT, (void *) "This won't be used in our lib", 29}
	};

	printf("\n*** We already opened a session and logged in ***\n");

	num_mechs = get_mechanisms(slot, &mech_type, -1);
	for (i = 0; i < num_mechs; i++)
		if (mech_type[i] == CKM_EC_KEY_PAIR_GEN)
			break;
	if (i == num_mechs) {
		printf("ERR: no 'CKM_EC_KEY_PAIR_GEN' found in the mechanism list\n");
		return;
	}

	printf("*** Generating EC key pair ***\n");
	if (!gen_keypair(session, &pub_key, &priv_key, opt_key_type))
		return;

	tmp = getID(session, priv_key, (CK_ULONG *) &opt_object_id_len);
	if (opt_object_id_len == 0) {
		printf("ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return;
	}
	memcpy(opt_object_id, tmp, opt_object_id_len);

	/* This is done in NSS */
	getEC_PARAMS(session, priv_key, &ec_params_len);
	if (ec_params_len < 5 || ec_params_len > 10000) {
		printf("ERR: GetAttribute(privkey, CKA_EC_PARAMS) doesn't seem to work\n");
		return;
	}
	getEC_POINT(session, pub_key, &ec_point_len);
	if (ec_point_len < 5 || ec_point_len > 10000) {
		printf("ERR: GetAttribute(pubkey, CKA_EC_POINT) doesn't seem to work\n");
		return;
	}

	printf("*** Changing the CKA_ID of private and public key into one of 20 bytes ***\n");
	rv = p11->C_SetAttributeValue(session, priv_key, attribs, 1);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue(priv_key)", rv);

	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 1);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue(pub_key)", rv);


	printf("*** Do a signature ***\n");
	data = data_to_sign;
	data_len = sizeof(data_to_sign);
	rv = p11->C_SignInit(session, &mech, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	rv = p11->C_Sign(session, data, data_len, NULL, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);
	sig_len = 20;
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		printf("ERR: C_Sign() didn't return CKR_BUFFER_TO_SMALL but %s\n", CKR2Str(rv));
		return;
	}
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	printf("*** Changing the CKA_LABEL, CKA_ID and CKA_SUBJECT of the public key ***\n");
	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 3);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue", rv);

	printf("==> OK\n");
}

#ifndef _WIN32
static void test_fork(void)
{
	CK_RV rv;
	pid_t pid = fork();

	if (!pid) {
		printf("*** Calling C_Initialize in forked child process ***\n");
		rv = p11->C_Initialize(NULL);
		if (rv != CKR_OK)
			p11_fatal("C_Initialize in child\n", rv);
		exit(0);
	} else if (pid < 0) {
		util_fatal("Failed to fork for test: %s", strerror(errno));
	} else {
		int st;
		waitpid(pid, &st, 0);
		if (!WIFEXITED(st) || WEXITSTATUS(st))
			util_fatal("Child process exited with status %d", st);
	}

}
#endif

static const char *p11_flag_names(struct flag_info *list, CK_FLAGS value)
{
	static char	buffer[1024];
	const char	*sepa = "";

	buffer[0] = '\0';
	while (list->value) {
		if (list->value & value) {
			strlcat(buffer, sepa, sizeof buffer);
			strlcat(buffer, list->name, sizeof buffer);
			value &= ~list->value;
			sepa = ", ";
		}
		list++;
	}
	if (value) {
		sprintf(buffer+strlen(buffer),
			"%sother flags=0x%x", sepa,
			(unsigned int) value);
	}
	return buffer;
}

static const char *p11_slot_info_flags(CK_FLAGS value)
{
	static struct flag_info	slot_flags[] = {
		{ CKF_TOKEN_PRESENT, "token present" },
		{ CKF_REMOVABLE_DEVICE, "removable device" },
		{ CKF_HW_SLOT, "hardware slot" },
		{ 0, NULL }
	};

	return p11_flag_names(slot_flags, value);
}

static const char *p11_token_info_flags(CK_FLAGS value)
{
	static struct flag_info	slot_flags[] = {
		{ CKF_RNG, "rng" },
		{ CKF_WRITE_PROTECTED, "readonly" },
		{ CKF_LOGIN_REQUIRED, "login required" },
		{ CKF_USER_PIN_INITIALIZED, "PIN initialized" },
		{ CKF_PROTECTED_AUTHENTICATION_PATH, "PIN pad present" },
		{ CKF_TOKEN_INITIALIZED, "token initialized" },
		{ CKF_USER_PIN_COUNT_LOW, "user PIN count low" },
		{ CKF_USER_PIN_FINAL_TRY, "final user PIN try" },
		{ CKF_USER_PIN_LOCKED, "user PIN locked" },
		{ CKF_USER_PIN_TO_BE_CHANGED, "user PIN to be changed"},
		{ CKF_SO_PIN_TO_BE_CHANGED, "SO PIN to be changed"},
		{ 0, NULL }
	};

	return p11_flag_names(slot_flags, value);
}

static const char *p11_utf8_to_local(CK_UTF8CHAR *string, size_t len)
{
	static char	buffer[512];
	size_t		n, m;

	while (len && string[len-1] == ' ')
		len--;

	/* For now, simply copy this thing */
	for (n = m = 0; n < sizeof(buffer) - 1; n++) {
		if (m >= len)
			break;
		buffer[n] = string[m++];
	}
	buffer[n] = '\0';
	return buffer;
}

static void p11_fatal(const char *func, CK_RV rv)
{
	if (p11)
		p11->C_Finalize(NULL_PTR);
	if (module)
		C_UnloadModule(module);

	util_fatal("PKCS11 function %s failed: rv = %s (0x%0x)\n", func, CKR2Str(rv), (unsigned int) rv);
}

static void p11_warn(const char *func, CK_RV rv)
{
	if (!suppress_warn)
		util_warn("PKCS11 function %s failed: rv = %s (0x%0x)\n", func, CKR2Str(rv), (unsigned int) rv);
}

static void p11_perror(const char *msg, CK_RV rv)
{
	fprintf(stderr, "  ERR: %s failed: %s (0x%0x)\n", msg, CKR2Str(rv), (unsigned int) rv);
}

static int hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;

		while (nybbles-- && *in && *in != ':') {
			char c;
			byte <<= 4;
			c = *in++;
			if ('0' <= c && c <= '9')
				c -= '0';
			else
			if ('a' <= c && c <= 'f')
				c = c - 'a' + 10;
			else
			if ('A' <= c && c <= 'F')
				c = c - 'A' + 10;
			else {
				printf("hex_to_bin(): invalid char '%c' in hex string\n", c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
			printf("hex_to_bin(): hex string too long");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char) byte;
		left--;
	}

	*outlen = count;
	return 1;
}

static struct mech_info	p11_mechanisms[] = {
      { CKM_RSA_PKCS_KEY_PAIR_GEN,	"RSA-PKCS-KEY-PAIR-GEN", NULL },
      { CKM_RSA_PKCS,		"RSA-PKCS",	NULL },
      { CKM_RSA_9796,		"RSA-9796",	NULL },
      { CKM_RSA_X_509,		"RSA-X-509",	NULL },
      { CKM_MD2_RSA_PKCS,	"MD2-RSA-PKCS", 	NULL },
      { CKM_MD5_RSA_PKCS,	"MD5-RSA-PKCS", 	"rsa-md5" },
      { CKM_SHA1_RSA_PKCS,	"SHA1-RSA-PKCS",	"rsa-sha1" },
      { CKM_SHA256_RSA_PKCS,	"SHA256-RSA-PKCS",	"rsa-sha256" },
      { CKM_SHA384_RSA_PKCS,	"SHA384-RSA-PKCS",	"rsa-sha384" },
      { CKM_SHA512_RSA_PKCS,	"SHA512-RSA-PKCS",	"rsa-sha512" },
      { CKM_RIPEMD128_RSA_PKCS,	"RIPEMD128-RSA-PKCS",	NULL },
      { CKM_RIPEMD160_RSA_PKCS,	"RIPEMD160-RSA-PKCS",	"rsa-ripemd160" },
      { CKM_RSA_PKCS_OAEP,	"RSA-PKCS-OAEP",	NULL },
      { CKM_RSA_X9_31_KEY_PAIR_GEN,"RSA-X9-31-KEY-PAIR-GEN", NULL },
      { CKM_RSA_X9_31,		"RSA-X9-31",	NULL },
      { CKM_SHA1_RSA_X9_31,	"SHA1-RSA-X9-31",	NULL },
      { CKM_RSA_PKCS_PSS,	"RSA-PKCS-PSS",	NULL },
      { CKM_SHA1_RSA_PKCS_PSS,	"SHA1-RSA-PKCS-PSS",	NULL },
      { CKM_SHA256_RSA_PKCS,	"SHA256-RSA-PKCS-PSS",	NULL },
      { CKM_SHA384_RSA_PKCS,	"SHA384-RSA-PKCS-PSS",	NULL },
      { CKM_SHA512_RSA_PKCS,	"SHA512-RSA-PKCS-PSS",	NULL },
      { CKM_DSA_KEY_PAIR_GEN,	"DSA-KEY-PAIR-GEN",	NULL },
      { CKM_DSA,		"DSA",	NULL },
      { CKM_DSA_SHA1,		"DSA-SHA1", NULL },
      { CKM_DH_PKCS_KEY_PAIR_GEN,"DH-PKCS-KEY-PAIR-GEN", NULL },
      { CKM_DH_PKCS_DERIVE,	"DH-PKCS-DERIVE", NULL },
      { CKM_X9_42_DH_KEY_PAIR_GEN,"X9-42-DH-KEY-PAIR-GEN", NULL },
      { CKM_X9_42_DH_DERIVE,	"X9-42-DH-DERIVE", NULL },
      { CKM_X9_42_DH_HYBRID_DERIVE,"X9-42-DH-HYBRID-DERIVE", NULL },
      { CKM_X9_42_MQV_DERIVE,	"X9-42-MQV-DERIVE", NULL },
      { CKM_RC2_KEY_GEN,	"RC2-KEY-GEN", NULL },
      { CKM_RC2_ECB,		"RC2-ECB", NULL },
      { CKM_RC2_CBC,		"RC2-CBC", NULL },
      { CKM_RC2_MAC,		"RC2-MAC", NULL },
      { CKM_RC2_MAC_GENERAL,	"RC2-MAC-GENERAL", NULL },
      { CKM_RC2_CBC_PAD,	"RC2-CBC-PAD", NULL },
      { CKM_RC4_KEY_GEN,	"RC4-KEY-GEN", NULL },
      { CKM_RC4,		"RC4", NULL },
      { CKM_DES_KEY_GEN,	"DES-KEY-GEN", NULL },
      { CKM_DES_ECB,		"DES-ECB", NULL },
      { CKM_DES_CBC,		"DES-CBC", NULL },
      { CKM_DES_MAC,		"DES-MAC", NULL },
      { CKM_DES_MAC_GENERAL,	"DES-MAC-GENERAL", NULL },
      { CKM_DES_CBC_PAD,	"DES-CBC-PAD", NULL },
      { CKM_DES2_KEY_GEN,	"DES2-KEY-GEN", NULL },
      { CKM_DES3_KEY_GEN,	"DES3-KEY-GEN", NULL },
      { CKM_DES3_ECB,		"DES3-ECB", NULL },
      { CKM_DES3_CBC,		"DES3-CBC", NULL },
      { CKM_DES3_MAC,		"DES3-MAC", NULL },
      { CKM_DES3_MAC_GENERAL,	"DES3-MAC-GENERAL", NULL },
      { CKM_DES3_CBC_PAD,	"DES3-CBC-PAD", NULL },
      { CKM_CDMF_KEY_GEN,	"CDMF-KEY-GEN", NULL },
      { CKM_CDMF_ECB,		"CDMF-ECB", NULL },
      { CKM_CDMF_CBC,		"CDMF-CBC", NULL },
      { CKM_CDMF_MAC,		"CDMF-MAC", NULL },
      { CKM_CDMF_MAC_GENERAL,	"CDMF-MAC-GENERAL", NULL },
      { CKM_CDMF_CBC_PAD,	"CDMF-CBC-PAD", NULL },
      { CKM_MD2,		"MD2", NULL },
      { CKM_MD2_HMAC,		"MD2-HMAC", NULL },
      { CKM_MD2_HMAC_GENERAL,	"MD2-HMAC-GENERAL", NULL },
      { CKM_MD5,		"MD5", NULL },
      { CKM_MD5_HMAC,		"MD5-HMAC", NULL },
      { CKM_MD5_HMAC_GENERAL,	"MD5-HMAC-GENERAL", NULL },
      { CKM_SHA_1,		"SHA-1", NULL },
      { CKM_SHA_1_HMAC,		"SHA-1-HMAC", NULL },
      { CKM_SHA_1_HMAC_GENERAL,	"SHA-1-HMAC-GENERAL", NULL },
      { CKM_SHA256,		"SHA256", NULL },
      { CKM_SHA384,		"SHA384", NULL },
      { CKM_SHA512,		"SHA512", NULL },
      { CKM_RIPEMD128,		"RIPEMD128", NULL },
      { CKM_RIPEMD128_HMAC,	"RIPEMD128-HMAC", NULL },
      { CKM_RIPEMD128_HMAC_GENERAL,"RIPEMD128-HMAC-GENERAL", NULL },
      { CKM_RIPEMD160,		"RIPEMD160", NULL },
      { CKM_RIPEMD160_HMAC,	"RIPEMD160-HMAC", NULL },
      { CKM_RIPEMD160_HMAC_GENERAL,"RIPEMD160-HMAC-GENERAL", NULL },
      { CKM_CAST_KEY_GEN,	"CAST-KEY-GEN", NULL },
      { CKM_CAST_ECB,		"CAST-ECB", NULL },
      { CKM_CAST_CBC,		"CAST-CBC", NULL },
      { CKM_CAST_MAC,		"CAST-MAC", NULL },
      { CKM_CAST_MAC_GENERAL,	"CAST-MAC-GENERAL", NULL },
      { CKM_CAST_CBC_PAD,	"CAST-CBC-PAD", NULL },
      { CKM_CAST3_KEY_GEN,	"CAST3-KEY-GEN", NULL },
      { CKM_CAST3_ECB,		"CAST3-ECB", NULL },
      { CKM_CAST3_CBC,		"CAST3-CBC", NULL },
      { CKM_CAST3_MAC,		"CAST3-MAC", NULL },
      { CKM_CAST3_MAC_GENERAL,	"CAST3-MAC-GENERAL", NULL },
      { CKM_CAST3_CBC_PAD,	"CAST3-CBC-PAD", NULL },
      { CKM_CAST5_KEY_GEN,	"CAST5-KEY-GEN", NULL },
      { CKM_CAST5_ECB,		"CAST5-ECB", NULL },
      { CKM_CAST5_CBC,		"CAST5-CBC", NULL },
      { CKM_CAST5_MAC,		"CAST5-MAC", NULL },
      { CKM_CAST5_MAC_GENERAL,	"CAST5-MAC-GENERAL", NULL },
      { CKM_CAST5_CBC_PAD,	"CAST5-CBC-PAD", NULL },
      { CKM_RC5_KEY_GEN,	"RC5-KEY-GEN", NULL },
      { CKM_RC5_ECB,		"RC5-ECB", NULL },
      { CKM_RC5_CBC,		"RC5-CBC", NULL },
      { CKM_RC5_MAC,		"RC5-MAC", NULL },
      { CKM_RC5_MAC_GENERAL,	"RC5-MAC-GENERAL", NULL },
      { CKM_RC5_CBC_PAD,	"RC5-CBC-PAD", NULL },
      { CKM_IDEA_KEY_GEN,	"IDEA-KEY-GEN", NULL },
      { CKM_IDEA_ECB,		"IDEA-ECB", NULL },
      { CKM_IDEA_CBC,		"IDEA-CBC", NULL },
      { CKM_IDEA_MAC,		"IDEA-MAC", NULL },
      { CKM_IDEA_MAC_GENERAL,	"IDEA-MAC-GENERAL", NULL },
      { CKM_IDEA_CBC_PAD,	"IDEA-CBC-PAD", NULL },
      { CKM_GENERIC_SECRET_KEY_GEN,"GENERIC-SECRET-KEY-GEN", NULL },
      { CKM_CONCATENATE_BASE_AND_KEY,"CONCATENATE-BASE-AND-KEY", NULL },
      { CKM_CONCATENATE_BASE_AND_DATA,"CONCATENATE-BASE-AND-DATA", NULL },
      { CKM_CONCATENATE_DATA_AND_BASE,"CONCATENATE-DATA-AND-BASE", NULL },
      { CKM_XOR_BASE_AND_DATA,	"XOR-BASE-AND-DATA", NULL },
      { CKM_EXTRACT_KEY_FROM_KEY,"EXTRACT-KEY-FROM-KEY", NULL },
      { CKM_SSL3_PRE_MASTER_KEY_GEN,"SSL3-PRE-MASTER-KEY-GEN", NULL },
      { CKM_SSL3_MASTER_KEY_DERIVE,"SSL3-MASTER-KEY-DERIVE", NULL },
      { CKM_SSL3_KEY_AND_MAC_DERIVE,"SSL3-KEY-AND-MAC-DERIVE", NULL },
      { CKM_SSL3_MASTER_KEY_DERIVE_DH,"SSL3-MASTER-KEY-DERIVE-DH", NULL },
      { CKM_TLS_PRE_MASTER_KEY_GEN,"TLS-PRE-MASTER-KEY-GEN", NULL },
      { CKM_TLS_MASTER_KEY_DERIVE,"TLS-MASTER-KEY-DERIVE", NULL },
      { CKM_TLS_KEY_AND_MAC_DERIVE,"TLS-KEY-AND-MAC-DERIVE", NULL },
      { CKM_TLS_MASTER_KEY_DERIVE_DH,"TLS-MASTER-KEY-DERIVE-DH", NULL },
      { CKM_SSL3_MD5_MAC,	"SSL3-MD5-MAC", NULL },
      { CKM_SSL3_SHA1_MAC,	"SSL3-SHA1-MAC", NULL },
      { CKM_MD5_KEY_DERIVATION,	"MD5-KEY-DERIVATION", NULL },
      { CKM_MD2_KEY_DERIVATION,	"MD2-KEY-DERIVATION", NULL },
      { CKM_SHA1_KEY_DERIVATION,"SHA1-KEY-DERIVATION", NULL },
      { CKM_PBE_MD2_DES_CBC,	"PBE-MD2-DES-CBC", NULL },
      { CKM_PBE_MD5_DES_CBC,	"PBE-MD5-DES-CBC", NULL },
      { CKM_PBE_MD5_CAST_CBC,	"PBE-MD5-CAST-CBC", NULL },
      { CKM_PBE_MD5_CAST3_CBC,	"PBE-MD5-CAST3-CBC", NULL },
      { CKM_PBE_MD5_CAST5_CBC,	"PBE-MD5-CAST5-CBC", NULL },
      { CKM_PBE_SHA1_CAST5_CBC,	"PBE-SHA1-CAST5-CBC", NULL },
      { CKM_PBE_SHA1_RC4_128,	"PBE-SHA1-RC4-128", NULL },
      { CKM_PBE_SHA1_RC4_40,	"PBE-SHA1-RC4-40", NULL },
      { CKM_PBE_SHA1_DES3_EDE_CBC,"PBE-SHA1-DES3-EDE-CBC", NULL },
      { CKM_PBE_SHA1_DES2_EDE_CBC,"PBE-SHA1-DES2-EDE-CBC", NULL },
      { CKM_PBE_SHA1_RC2_128_CBC,"PBE-SHA1-RC2-128-CBC", NULL },
      { CKM_PBE_SHA1_RC2_40_CBC,"PBE-SHA1-RC2-40-CBC", NULL },
      { CKM_PKCS5_PBKD2,	"PKCS5-PBKD2", NULL },
      { CKM_PBA_SHA1_WITH_SHA1_HMAC,"PBA-SHA1-WITH-SHA1-HMAC", NULL },
      { CKM_KEY_WRAP_LYNKS,	"KEY-WRAP-LYNKS", NULL },
      { CKM_KEY_WRAP_SET_OAEP,	"KEY-WRAP-SET-OAEP", NULL },
      { CKM_SKIPJACK_KEY_GEN,	"SKIPJACK-KEY-GEN", NULL },
      { CKM_SKIPJACK_ECB64,	"SKIPJACK-ECB64", NULL },
      { CKM_SKIPJACK_CBC64,	"SKIPJACK-CBC64", NULL },
      { CKM_SKIPJACK_OFB64,	"SKIPJACK-OFB64", NULL },
      { CKM_SKIPJACK_CFB64,	"SKIPJACK-CFB64", NULL },
      { CKM_SKIPJACK_CFB32,	"SKIPJACK-CFB32", NULL },
      { CKM_SKIPJACK_CFB16,	"SKIPJACK-CFB16", NULL },
      { CKM_SKIPJACK_CFB8,	"SKIPJACK-CFB8", NULL },
      { CKM_SKIPJACK_WRAP,	"SKIPJACK-WRAP", NULL },
      { CKM_SKIPJACK_PRIVATE_WRAP,"SKIPJACK-PRIVATE-WRAP", NULL },
      { CKM_SKIPJACK_RELAYX,	"SKIPJACK-RELAYX", NULL },
      { CKM_KEA_KEY_PAIR_GEN,	"KEA-KEY-PAIR-GEN", NULL },
      { CKM_KEA_KEY_DERIVE,	"KEA-KEY-DERIVE", NULL },
      { CKM_FORTEZZA_TIMESTAMP,	"FORTEZZA-TIMESTAMP", NULL },
      { CKM_BATON_KEY_GEN,	"BATON-KEY-GEN", NULL },
      { CKM_BATON_ECB128,	"BATON-ECB128", NULL },
      { CKM_BATON_ECB96,	"BATON-ECB96", NULL },
      { CKM_BATON_CBC128,	"BATON-CBC128", NULL },
      { CKM_BATON_COUNTER,	"BATON-COUNTER", NULL },
      { CKM_BATON_SHUFFLE,	"BATON-SHUFFLE", NULL },
      { CKM_BATON_WRAP,		"BATON-WRAP", NULL },
      { CKM_ECDSA_KEY_PAIR_GEN,	"ECDSA-KEY-PAIR-GEN", NULL },
      { CKM_ECDSA,		"ECDSA", NULL },
      { CKM_ECDSA_SHA1,		"ECDSA-SHA1", NULL },
      { CKM_ECDH1_DERIVE,	"ECDH1-DERIVE", NULL },
      { CKM_ECDH1_COFACTOR_DERIVE,"ECDH1-COFACTOR-DERIVE", NULL },
      { CKM_ECMQV_DERIVE,	"ECMQV-DERIVE", NULL },
      { CKM_JUNIPER_KEY_GEN,	"JUNIPER-KEY-GEN", NULL },
      { CKM_JUNIPER_ECB128,	"JUNIPER-ECB128", NULL },
      { CKM_JUNIPER_CBC128,	"JUNIPER-CBC128", NULL },
      { CKM_JUNIPER_COUNTER,	"JUNIPER-COUNTER", NULL },
      { CKM_JUNIPER_SHUFFLE,	"JUNIPER-SHUFFLE", NULL },
      { CKM_JUNIPER_WRAP,	"JUNIPER-WRAP", NULL },
      { CKM_FASTHASH,		"FASTHASH", NULL },
      { CKM_AES_KEY_GEN,	"AES-KEY-GEN", NULL },
      { CKM_AES_ECB,		"AES-ECB", NULL },
      { CKM_AES_CBC,		"AES-CBC", NULL },
      { CKM_AES_MAC,		"AES-MAC", NULL },
      { CKM_AES_MAC_GENERAL,	"AES-MAC-GENERAL", NULL },
      { CKM_AES_CBC_PAD,	"AES-CBC-PAD", NULL },
      { CKM_GOSTR3410_KEY_PAIR_GEN,"GOSTR3410-KEY-PAIR-GEN", NULL },
      { CKM_GOSTR3410,		"GOSTR3410", NULL },
      { CKM_GOSTR3410_WITH_GOSTR3411,"GOSTR3410-WITH-GOSTR3411", NULL },
      { CKM_GOSTR3411,		"GOSTR3411", NULL },
      { CKM_DSA_PARAMETER_GEN,	"DSA-PARAMETER-GEN", NULL },
      { CKM_DH_PKCS_PARAMETER_GEN,"DH-PKCS-PARAMETER-GEN", NULL },
      { CKM_X9_42_DH_PARAMETER_GEN,"X9-42-DH-PARAMETER-GEN", NULL },
      { 0, NULL, NULL }
};

static const char *p11_mechanism_to_name(CK_MECHANISM_TYPE mech)
{
	static char temp[64];
	struct mech_info *mi;

	for (mi = p11_mechanisms; mi->name; mi++) {
		if (mi->mech == mech)
			return mi->name;
	}
	snprintf(temp, sizeof(temp), "mechtype-%lu", (unsigned long) mech);
	return temp;
}

static CK_MECHANISM_TYPE p11_name_to_mechanism(const char *name)
{
	struct mech_info *mi;

	for (mi = p11_mechanisms; mi->name; mi++) {
		if (!strcasecmp(mi->name, name)
		 || (mi->short_name && !strcasecmp(mi->short_name, name)))
			return mi->mech;
	}
	util_fatal("Unknown PKCS11 mechanism \"%s\"\n", name);
	return 0; /* gcc food */
}

static const char * CKR2Str(CK_ULONG res)
{
	switch (res) {
	case CKR_OK:
		return "CKR_OK";
	case CKR_CANCEL:
		return "CKR_CANCEL";
	case CKR_HOST_MEMORY:
		return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID:
		return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR:
		return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED:
		return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD:
		return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT:
		return "CKR_NO_EVENT";
	case CKR_NEED_TO_CREATE_THREADS:
		return "CKR_NEED_TO_CREATE_THREADS";
	case CKR_CANT_LOCK:
		return "CKR_CANT_LOCK";
	case CKR_ATTRIBUTE_READ_ONLY:
		return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE:
		return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID:
		return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID:
		return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID:
		return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE:
		return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR:
		return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY:
		return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED:
		return "CKR_DEVICE_REMOVED";
	case CKR_ENCRYPTED_DATA_INVALID:
		return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_FUNCTION_CANCELED:
		return "CKR_FUNCTION_CANCELED";
	case CKR_FUNCTION_NOT_PARALLEL:
		return "CKR_FUNCTION_NOT_PARALLEL";
	case CKR_FUNCTION_NOT_SUPPORTED:
		return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID:
		return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE:
		return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT:
		return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_NOT_NEEDED:
		return "CKR_KEY_NOT_NEEDED";
	case CKR_KEY_CHANGED:
		return "CKR_KEY_CHANGED";
	case CKR_KEY_NEEDED:
		return "CKR_KEY_NEEDED";
	case CKR_KEY_INDIGESTIBLE:
		return "CKR_KEY_INDIGESTIBLE";
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE:
		return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_KEY_UNEXTRACTABLE:
		return "CKR_KEY_UNEXTRACTABLE";
	case CKR_MECHANISM_INVALID:
		return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID:
		return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID:
		return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE:
		return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED:
		return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT:
		return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID:
		return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE:
		return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED:
		return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED:
		return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED:
		return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT:
		return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID:
		return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	case CKR_SESSION_READ_ONLY:
		return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS:
		return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS:
		return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID:
		return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE:
		return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE:
		return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT:
		return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT:
		return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED:
		return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED:
		return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_USER_ALREADY_LOGGED_IN:
		return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN:
		return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED:
		return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID:
		return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES:
		return "CKR_USER_TOO_MANY_TYPES";
	case CKR_WRAPPED_KEY_INVALID:
		return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE:
		return "CKR_WRAPPED_KEY_LEN_RANGE";
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		return "CKR_WRAPPING_KEY_HANDLE_INVALID";
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		return "CKR_WRAPPING_KEY_SIZE_RANGE";
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		return "CKR_RANDOM_SEED_NOT_SUPPORTED";
	case CKR_RANDOM_NO_RNG:
		return "CKR_RANDOM_NO_RNG";
	case CKR_DOMAIN_PARAMS_INVALID:
		return "CKR_DOMAIN_PARAMS_INVALID";
	case CKR_BUFFER_TOO_SMALL:
		return "CKR_BUFFER_TOO_SMALL";
	case CKR_SAVED_STATE_INVALID:
		return "CKR_SAVED_STATE_INVALID";
	case CKR_INFORMATION_SENSITIVE:
		return "CKR_INFORMATION_SENSITIVE";
	case CKR_STATE_UNSAVEABLE:
		return "CKR_STATE_UNSAVEABLE";
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_MUTEX_BAD:
		return "CKR_MUTEX_BAD";
	case CKR_MUTEX_NOT_LOCKED:
		return "CKR_MUTEX_NOT_LOCKED";
	case CKR_VENDOR_DEFINED:
		return "CKR_VENDOR_DEFINED";
	}
	return "unknown PKCS11 error";
}
