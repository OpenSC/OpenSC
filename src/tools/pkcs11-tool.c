/*
 * pkcs11-tool.c: Tool for poking around pkcs11 modules/tokens
 *
 * Copyright (C) 2002  Olaf Kirch <okir@suse.de>
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include <windows.h>
#include <io.h>
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#endif
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#if !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
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
#include "common/libpkcs11.h"
#include "util.h"
#include "libopensc/sc-ossl-compat.h"

#ifdef _WIN32
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#endif

#ifndef ENABLE_SHARED
extern CK_FUNCTION_LIST pkcs11_function_list;
#endif

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
	{"prime192v2",   "1.2.840.10045.3.1.2", "06082A8648CE3D030102", 192},
	{"prime192v3",   "1.2.840.10045.3.1.3", "06082A8648CE3D030103", 192},
	{"nistp192",     "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},
	{"ansiX9p192r1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192},

	{"secp224r1", "1.3.132.0.33", "06052b81040021", 224},
	{"nistp224",  "1.3.132.0.33", "06052b81040021", 224},

	{"prime256v1",   "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"secp256r1",    "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"ansiX9p256r1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256},
	{"frp256v1",	 "1.2.250.1.223.101.256.1", "060a2a817a01815f65820001", 256},

	{"secp384r1",		"1.3.132.0.34", "06052B81040022", 384},
	{"prime384v1",		"1.3.132.0.34", "06052B81040022", 384},
	{"ansiX9p384r1",	"1.3.132.0.34", "06052B81040022", 384},

	{"secp521r1", "1.3.132.0.35", "06052B81040023", 521},
	{"nistp521",  "1.3.132.0.35", "06052B81040023", 521},

	{"brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", "06092B2403030208010103", 192},
	{"brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", "06092B2403030208010105", 224},
	{"brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", "06092B2403030208010107", 256},
	{"brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", "06092B2403030208010109", 320},
	{"brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", "06092B240303020801010B", 384},
	{"brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", "06092B240303020801010D", 512},

	{"secp192k1",		"1.3.132.0.31", "06052B8104001F", 192},
	{"secp256k1",		"1.3.132.0.10", "06052B8104000A", 256},
	{NULL, NULL, NULL, 0},
};

static const struct sc_aid GOST_HASH2001_PARAMSET_OID = { { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 }, 9 };
static const struct sc_aid GOST_HASH2012_256_PARAMSET_OID = { { 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02 }, 10 };
static const struct sc_aid GOST_HASH2012_512_PARAMSET_OID = { { 0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03 }, 10 };

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
	OPT_SENSITIVE,
	OPT_TEST_HOTPLUG,
	OPT_UNLOCK_PIN,
	OPT_PUK,
	OPT_NEW_PIN,
	OPT_LOGIN_TYPE,
	OPT_TEST_EC,
	OPT_DERIVE,
	OPT_DERIVE_PASS_DER,
	OPT_DECRYPT,
	OPT_TEST_FORK,
	OPT_GENERATE_KEY,
	OPT_GENERATE_RANDOM,
	OPT_HASH_ALGORITHM,
	OPT_MGF,
	OPT_SALT,
	OPT_VERIFY,
	OPT_SIGNATURE_FILE,
	OPT_ALWAYS_AUTH,
	OPT_ALLOWED_MECHANISMS,
	OPT_OBJECT_INDEX
};

static const struct option options[] = {
	{ "module",		1, NULL,		OPT_MODULE },
	{ "show-info",		0, NULL,		'I' },
	{ "list-slots",		0, NULL,		'L' },
	{ "list-token-slots",	0, NULL,		'T' },
	{ "list-mechanisms",	0, NULL,		'M' },
	{ "list-objects",	0, NULL,		'O' },

	{ "sign",		0, NULL,		's' },
	{ "verify",		0, NULL,		OPT_VERIFY },
	{ "decrypt",		0, NULL,		OPT_DECRYPT },
	{ "hash",		0, NULL,		'h' },
	{ "derive",		0, NULL,		OPT_DERIVE },
	{ "derive-pass-der",	0, NULL,		OPT_DERIVE_PASS_DER },
	{ "mechanism",		1, NULL,		'm' },
	{ "hash-algorithm",	1, NULL,		OPT_HASH_ALGORITHM },
	{ "mgf",		1, NULL,		OPT_MGF },
	{ "salt-len",		1, NULL,		OPT_SALT },

	{ "login",		0, NULL,		'l' },
	{ "login-type",		1, NULL,		OPT_LOGIN_TYPE },
	{ "pin",		1, NULL,		'p' },
	{ "puk",		1, NULL,		OPT_PUK },
	{ "new-pin",		1, NULL,		OPT_NEW_PIN },
	{ "so-pin",		1, NULL,		OPT_SO_PIN },
	{ "init-token",		0, NULL,		OPT_INIT_TOKEN },
	{ "init-pin",		0, NULL,		OPT_INIT_PIN },
	{ "change-pin",		0, NULL,		'c' },
	{ "unlock-pin",		0, NULL,		OPT_UNLOCK_PIN },
	{ "keypairgen",		0, NULL,		'k' },
	{ "keygen",		0, NULL,		OPT_GENERATE_KEY },
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
	{ "object-index",		1, NULL,		OPT_OBJECT_INDEX },
	{ "token-label",	1, NULL,		OPT_TOKEN_LABEL },
	{ "set-id",		1, NULL,		'e' },
	{ "attr-from",		1, NULL,		OPT_ATTR_FROM },
	{ "input-file",		1, NULL,		'i' },
	{ "signature-file",	1, NULL,		OPT_SIGNATURE_FILE },
	{ "output-file",	1, NULL,		'o' },
	{ "signature-format",	1, NULL,		'f' },
	{ "allowed-mechanisms",	1, NULL,		OPT_ALLOWED_MECHANISMS },

	{ "test",		0, NULL,		't' },
	{ "test-hotplug",	0, NULL,		OPT_TEST_HOTPLUG },
	{ "moz-cert",		1, NULL,		'z' },
	{ "verbose",		0, NULL,		'v' },
	{ "private",		0, NULL,		OPT_PRIVATE },
	{ "sensitive",		0, NULL,		OPT_SENSITIVE },
	{ "always-auth",	0, NULL,		OPT_ALWAYS_AUTH },
	{ "test-ec",		0, NULL,		OPT_TEST_EC },
#ifndef _WIN32
	{ "test-fork",		0, NULL,		OPT_TEST_FORK },
#endif
	{ "generate-random",	1, NULL,		OPT_GENERATE_RANDOM },

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
	"Verify a signature of some data",
	"Decrypt some data",
	"Hash some data",
	"Derive a secret key using another key and some data",
	"Derive ECDHpass DER encoded pubkey for compatibility with some PKCS#11 implementations",
	"Specify mechanism (use -M for a list of supported mechanisms), or by hexadecimal, e.g., 0x80001234",
	"Specify hash algorithm used with RSA-PKCS-PSS signature and RSA-PKCS-OAEP decryption",
	"Specify MGF (Message Generation Function) used for RSA-PSS signature and RSA-OAEP decryption (possible values are MGF1-SHA1 to MGF1-SHA512)",
	"Specify how many bytes should be used for salt in RSA-PSS signatures (default is digest size)",

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
	"Key generation",
	"Specify the type and length of the key to create, for example rsa:1024 or EC:prime256v1 or GOSTR3410-2012-256:B",
	"Specify 'sign' key usage flag (sets SIGN in privkey, sets VERIFY in pubkey)",
	"Specify 'decrypt' key usage flag (RSA only, set DECRYPT privkey, ENCRYPT in pubkey)",
	"Specify 'derive' key usage flag (EC only)",
	"Write an object (key, cert, data) to the card",
	"Get object's CKA_VALUE attribute (use with --type)",
	"Delete an object (use with --type cert/data/privkey/pubkey/secrkey)",
	"Specify the application label of the data object (use with --type data)",
	"Specify the application ID of the data object (use with --type data)",
	"Specify the issuer in hexadecimal format (use with --type cert)",
	"Specify the subject in hexadecimal format (use with --type cert/privkey/pubkey)",
	"Specify the type of object (e.g. cert, privkey, pubkey, secrkey, data)",
	"Specify the ID of the object",
	"Specify the label of the object",
	"Specify the ID of the slot to use",
	"Specify the description of the slot to use",
	"Specify the index of the slot to use",
	"Specify the index of the object to use",
	"Specify the token label of the slot to use",
	"Set the CKA_ID of an object, <args>= the (new) CKA_ID",
	"Use <arg> to create some attributes when writing an object",
	"Specify the input file",
	"Specify the file with signature for verification",
	"Specify the output file",
	"Format for ECDSA signature <arg>: 'rs' (default), 'sequence', 'openssl'",
	"Specify the comma-separated list of allowed mechanisms when creating an object.",

	"Test (best used with the --login or --pin option)",
	"Test hotplug capabilities (C_GetSlotList + C_WaitForSlotEvent)",
	"Test Mozilla-like keypair gen and cert req, <arg>=certfile",
	"Verbose operation. (Set OPENSC_DEBUG to enable OpenSC specific debugging)",
	"Set the CKA_PRIVATE attribute (object is only viewable after a login)",
	"Set the CKA_SENSITIVE attribute (object cannot be revealed in plaintext)",
	"Set the CKA_ALWAYS_AUTHENTICATE attribute to a key object (require PIN verification for each use)",
	"Test EC (best used with the --login or --pin option)",
#ifndef _WIN32
	"Test forking and calling C_Initialize() in the child",
#endif
	"Generate given amount of random data"
};

static const char *	app_name = "pkcs11-tool"; /* for utils.c */

static int		verbose = 0;
static const char *	opt_input = NULL;
static const char *	opt_output = NULL;
static const char *	opt_signature_file = NULL;
static const char *	opt_module = DEFAULT_PKCS11_PROVIDER;
static int		opt_slot_set = 0;
static CK_SLOT_ID	opt_slot = 0;
static const char *	opt_slot_description = NULL;
static const char *	opt_token_label = NULL;
static CK_ULONG		opt_slot_index = 0;
static int		opt_slot_index_set = 0;
static CK_ULONG		opt_object_index = 0;
static int		opt_object_index_set = 0;
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
#define MAX_ALLOWED_MECHANISMS 20
static CK_MECHANISM_TYPE opt_allowed_mechanisms[MAX_ALLOWED_MECHANISMS];
static size_t		opt_allowed_mechanisms_len = 0;
static int		opt_is_private = 0;
static int		opt_is_sensitive = 0;
static int		opt_test_hotplug = 0;
static int		opt_login_type = -1;
static int		opt_key_usage_sign = 0;
static int		opt_key_usage_decrypt = 0;
static int		opt_key_usage_derive = 0;
static int		opt_key_usage_default = 1; /* uses defaults if no opt_key_usage options */
static int		opt_derive_pass_der = 0;
static unsigned long	opt_random_bytes = 0;
static CK_MECHANISM_TYPE opt_hash_alg = 0;
static unsigned long	opt_mgf = 0;
static long	        opt_salt_len = 0;
static int		opt_salt_len_given = 0; /* 0 - not given, 1 - given with input parameters */
static int		opt_always_auth = 0;

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
	unsigned char	subject[512];
	int		subject_len;
	unsigned char	issuer[512];
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
static void		verify_signature(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		decrypt_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		hash_data(CK_SLOT_ID, CK_SESSION_HANDLE);
static void		derive_key(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static int		gen_keypair(CK_SLOT_ID slot, CK_SESSION_HANDLE,
				CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *, const char *);
static int		gen_key(CK_SLOT_ID slot, CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, const char *, char *);
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
static const char *	p11_mgf_to_name(CK_RSA_PKCS_MGF_TYPE);
static CK_MECHANISM_TYPE p11_name_to_mgf(const char *);
static void		p11_perror(const char *, CK_RV);
static const char *	CKR2Str(CK_ULONG res);
static int		p11_test(CK_SESSION_HANDLE session);
static int test_card_detection(int);
static int		hex_to_bin(const char *in, CK_BYTE *out, size_t *outlen);
static void		pseudo_randomize(unsigned char *data, size_t dataLen);
static CK_SESSION_HANDLE test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static void		test_ec(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
#ifndef _WIN32
static void		test_fork(void);
#endif
static void		generate_random(CK_SESSION_HANDLE session);
static CK_RV		find_object_with_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *out,
				CK_ATTRIBUTE *attrs, CK_ULONG attrsLen, CK_ULONG obj_index);
static CK_ULONG		get_private_key_length(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE prkey);

/* win32 needs this in open(2) */
#ifndef O_BINARY
# define O_BINARY 0
#endif

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
	CK_ATTRIBUTE	attr = { CKA_##ATTR, NULL, 0 };		\
	CK_RV		rv;					\
	if (pulCount)						\
		*pulCount = 0;					\
	rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);	\
	if (rv == CKR_OK) {					\
		if (attr.ulValueLen == (CK_ULONG)(-1))		\
			return NULL;				\
		if (!(attr.pValue = calloc(1, attr.ulValueLen + 1)))		\
			util_fatal("out of memory in get" #ATTR ": %m");	\
		rv = p11->C_GetAttributeValue(sess, obj, &attr, 1);		\
		if (attr.ulValueLen == (CK_ULONG)(-1)) {	\
			free(attr.pValue);			\
			return NULL;				\
		}						\
		if (pulCount)					\
			*pulCount = attr.ulValueLen / sizeof(TYPE);	\
	} else if (rv != CKR_ATTRIBUTE_TYPE_INVALID) {		\
		p11_warn("C_GetAttributeValue(" #ATTR ")", rv);	\
	}							\
	return (TYPE *) attr.pValue;				\
}

/*
 * Define attribute accessors
 */
ATTR_METHOD(CLASS, CK_OBJECT_CLASS);			/* getCLASS */
ATTR_METHOD(ALWAYS_AUTHENTICATE, CK_BBOOL); 		/* getALWAYS_AUTHENTICATE */
ATTR_METHOD(PRIVATE, CK_BBOOL); 			/* getPRIVATE */
ATTR_METHOD(MODIFIABLE, CK_BBOOL);			/* getMODIFIABLE */
ATTR_METHOD(ENCRYPT, CK_BBOOL);				/* getENCRYPT */
ATTR_METHOD(DECRYPT, CK_BBOOL);				/* getDECRYPT */
ATTR_METHOD(SIGN, CK_BBOOL);				/* getSIGN */
ATTR_METHOD(VERIFY, CK_BBOOL);				/* getVERIFY */
ATTR_METHOD(WRAP, CK_BBOOL);				/* getWRAP */
ATTR_METHOD(UNWRAP, CK_BBOOL);				/* getUNWRAP */
ATTR_METHOD(DERIVE, CK_BBOOL);				/* getDERIVE */
ATTR_METHOD(SENSITIVE, CK_BBOOL);			/* getSENSITIVE */
ATTR_METHOD(ALWAYS_SENSITIVE, CK_BBOOL);		/* getALWAYS_SENSITIVE */
ATTR_METHOD(EXTRACTABLE, CK_BBOOL);			/* getEXTRACTABLE */
ATTR_METHOD(NEVER_EXTRACTABLE, CK_BBOOL);		/* getNEVER_EXTRACTABLE */
ATTR_METHOD(LOCAL, CK_BBOOL);				/* getLOCAL */
ATTR_METHOD(OPENSC_NON_REPUDIATION, CK_BBOOL);		/* getOPENSC_NON_REPUDIATION */
ATTR_METHOD(KEY_TYPE, CK_KEY_TYPE);			/* getKEY_TYPE */
ATTR_METHOD(CERTIFICATE_TYPE, CK_CERTIFICATE_TYPE);	/* getCERTIFICATE_TYPE */
ATTR_METHOD(MODULUS_BITS, CK_ULONG);			/* getMODULUS_BITS */
ATTR_METHOD(VALUE_LEN, CK_ULONG);			/* getVALUE_LEN */
VARATTR_METHOD(LABEL, char);				/* getLABEL */
VARATTR_METHOD(APPLICATION, char);			/* getAPPLICATION */
VARATTR_METHOD(ID, unsigned char);			/* getID */
VARATTR_METHOD(OBJECT_ID, unsigned char);		/* getOBJECT_ID */
VARATTR_METHOD(MODULUS, CK_BYTE);			/* getMODULUS */
#ifdef ENABLE_OPENSSL
VARATTR_METHOD(SUBJECT, unsigned char);			/* getSUBJECT */
VARATTR_METHOD(PUBLIC_EXPONENT, CK_BYTE);		/* getPUBLIC_EXPONENT */
#endif
VARATTR_METHOD(VALUE, unsigned char);			/* getVALUE */
VARATTR_METHOD(GOSTR3410_PARAMS, unsigned char);	/* getGOSTR3410_PARAMS */
VARATTR_METHOD(GOSTR3411_PARAMS, unsigned char);	/* getGOSTR3411_PARAMS */
VARATTR_METHOD(EC_POINT, unsigned char);		/* getEC_POINT */
VARATTR_METHOD(EC_PARAMS, unsigned char);		/* getEC_PARAMS */
VARATTR_METHOD(ALLOWED_MECHANISMS, CK_MECHANISM_TYPE);	/* getALLOWED_MECHANISMS */


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
	int do_verify = 0;
	int do_decrypt = 0;
	int do_hash = 0;
	int do_derive = 0;
	int do_gen_keypair = 0;
	int do_gen_key = 0;
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
	int do_generate_random = 0;
	char *s = NULL;
	CK_RV rv;

#ifdef _WIN32
	char expanded_val[PATH_MAX];
	DWORD expanded_len;

	if(_setmode(_fileno(stdout), _O_BINARY ) == -1)
		util_fatal("Cannot set FMODE to O_BINARY");
	if(_setmode(_fileno(stdin), _O_BINARY ) == -1)
		util_fatal("Cannot set FMODE to O_BINARY");
#endif

#ifdef ENABLE_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	OPENSSL_config(NULL);
	/* OpenSSL magic */
	OpenSSL_add_all_algorithms();
	OPENSSL_malloc_init();
#endif
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
		case OPT_GENERATE_KEY:
			need_session |= NEED_SESSION_RW;
			do_gen_key = 1;
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
				fprintf(stderr, "Invalid ID \"%s\"\n", optarg);
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
			else if (strcmp(optarg, "secrkey") == 0)
				opt_object_class = CKO_SECRET_KEY;
			else if (strcmp(optarg, "pubkey") == 0)
				opt_object_class = CKO_PUBLIC_KEY;
			else if (strcmp(optarg, "data") == 0)
				opt_object_class = CKO_DATA;
			else {
				fprintf(stderr, "Unsupported object type \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			break;
		case 'd':
			opt_object_id_len = sizeof(opt_object_id);
			if (!hex_to_bin(optarg, opt_object_id, &opt_object_id_len)) {
				fprintf(stderr, "Invalid ID \"%s\"\n", optarg);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			break;
		case 'a':
			opt_object_label = optarg;
			break;
		case 'i':
			opt_input = optarg;
			break;
		case OPT_SIGNATURE_FILE:
			opt_signature_file = optarg;
			break;
		case 'l':
			need_session |= NEED_SESSION_RW;
			opt_login = 1;
			break;
		case 'm':
			opt_mechanism_used = 1;
			opt_mechanism = p11_name_to_mechanism(optarg);
			break;
		case OPT_HASH_ALGORITHM:
			opt_hash_alg = p11_name_to_mechanism(optarg);
			break;
		case OPT_MGF:
			opt_mgf = p11_name_to_mgf(optarg);
			break;
		case OPT_SALT:
			opt_salt_len = (CK_ULONG) strtoul(optarg, NULL, 0);
			opt_salt_len_given = 1;
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 'p':
			need_session |= NEED_SESSION_RW;
			opt_login = 1;
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
		case OPT_VERIFY:
			need_session |= NEED_SESSION_RO;
			do_verify = 1;
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
		case OPT_OBJECT_INDEX:
			opt_object_index = (CK_ULONG) strtoul(optarg, NULL, 0);
			opt_object_index_set = 1;
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
				fprintf(stderr, "Unsupported login type \"%s\"\n", optarg);
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
		case OPT_SENSITIVE:
			opt_is_sensitive = 1;
			break;
		case OPT_TEST_HOTPLUG:
			opt_test_hotplug = 1;
			action_count++;
			break;
		case OPT_TEST_EC:
			do_test_ec = 1;
			action_count++;
			break;
		case OPT_DERIVE_PASS_DER:
			opt_derive_pass_der = 1;
			/* fall through */
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
		case OPT_GENERATE_RANDOM:
			need_session |= NEED_SESSION_RO;
			opt_random_bytes = strtoul(optarg, NULL, 0);
			do_generate_random = 1;
			action_count++;
			break;
		case OPT_ALWAYS_AUTH:
			opt_always_auth = 1;
			break;
		case OPT_ALLOWED_MECHANISMS:
			/* Parse the mechanism list and fail early */
			s = strtok(optarg, ",");
			while (s != NULL) {
				if (opt_allowed_mechanisms_len > MAX_ALLOWED_MECHANISMS) {
					fprintf(stderr, "Too many mechanisms provided"
						" (max %d). Skipping the rest.", MAX_ALLOWED_MECHANISMS);
					break;
				}

				opt_allowed_mechanisms[opt_allowed_mechanisms_len] =
					p11_name_to_mechanism(s);
				opt_allowed_mechanisms_len++;
				s = strtok(NULL, ",");
			}
			break;
		default:
			util_print_usage_and_die(app_name, options, option_help, NULL);
		}
	}
	if (optind < argc) {
		util_fatal("invalid option(s) given");
	}

	if (action_count == 0)
		util_print_usage_and_die(app_name, options, option_help, NULL);

#ifdef _WIN32
	expanded_len = PATH_MAX;
	expanded_len = ExpandEnvironmentStringsA(opt_module, expanded_val, expanded_len);
	if (0 < expanded_len && expanded_len < sizeof expanded_val)
		opt_module = expanded_val;
#endif

#ifndef ENABLE_SHARED
	if (strcmp(opt_module, DEFAULT_PKCS11_PROVIDER) == 0)
		p11 = &pkcs11_function_list;
	else
#endif
	{
		module = C_LoadModule(opt_module, &p11);
		if (module == NULL)
			util_fatal("Failed to load pkcs11 module");
	}

	rv = p11->C_Initialize(NULL);
	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
		fprintf(stderr, "\n*** Cryptoki library has already been initialized ***\n");
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
			util_fatal("Token not initialized");
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
			fprintf(stderr, "Invalid login type for 'Unlock User PIN' operation\n");
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

	if (do_verify) {
		if (!find_object(session, CKO_PUBLIC_KEY, &object,
		        opt_object_id_len ? opt_object_id : NULL,
		        opt_object_id_len, 0) &&
		    !find_object(session, CKO_CERTIFICATE, &object,
		        opt_object_id_len ? opt_object_id : NULL,
		        opt_object_id_len, 0))
			util_fatal("Public key nor certificate not found");
	}

	/* before list objects, so we can see a derived key */
	if (do_derive)
		derive_key(opt_slot, session, object);

	if (do_list_objects)
		list_objects(session, opt_object_class);

	if (do_sign)
		sign_data(opt_slot, session, object);

	if (do_verify)
		verify_signature(opt_slot, session, object);

	if (do_decrypt)
		decrypt_data(opt_slot, session, object);

	if (do_hash)
		hash_data(opt_slot, session);

	if (do_gen_keypair) {
		CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
		gen_keypair(opt_slot, session, &hPublicKey, &hPrivateKey, opt_key_type);
	}

	if (do_gen_key) {
		CK_OBJECT_HANDLE hSecretKey;
		gen_key(opt_slot, session, &hSecretKey, opt_key_type, NULL);
	}

	if (do_write_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify the object type with the -y option");
		write_object(session);
	}

	if (do_read_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify type of the object to read");
		if (opt_object_id_len == 0 && opt_object_label == NULL &&
				opt_application_label == NULL && opt_application_id == NULL &&
				opt_issuer == NULL && opt_subject == NULL)
			 util_fatal("You should specify at least one of the "
					 "object ID, object label, application label or application ID");
		read_object(session);
	}

	if (do_delete_object) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify type of the object to delete");
		if (opt_object_id_len == 0 && opt_object_label == NULL &&
				opt_application_label == NULL && opt_application_id == NULL &&
				opt_object_index_set == 0)
			 util_fatal("You should specify at least one of the "
					 "object ID, object label, application label, application ID or object index");
		delete_object(session);
	}

	if (do_set_id) {
		if (opt_object_class_str == NULL)
			util_fatal("You should specify the object type with the -y option");
		if (opt_object_id_len == 0)
			util_fatal("You should specify the current ID with the -d option");
		set_id_attr(session);
	}

	if (do_test)
		p11_test(session);

	if (do_test_kpgen_certwrite) {
		if (!opt_login)
			fprintf(stderr, "ERR: login required\n");
		else
			session = test_kpgen_certwrite(opt_slot, session);
	}

	if (do_test_ec) {
		if (!opt_login)
			fprintf(stderr, "ERR: login required\n");
		else
			test_ec(opt_slot, session);
	}

	if (do_generate_random) {
		generate_random(session);
	}

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
		free(p11_slots);
		p11_slots = calloc(p11_num_slots, sizeof(CK_SLOT_ID));
		if (p11_slots == NULL) {
			perror("calloc failed");
			exit(1);
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
	} else if (rv != CKR_OK) {
		printf("C_GetTokenInfo() failed: rv = %s\n", CKR2Str(rv));
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
	printf("  pin min/max        : %lu/%lu\n", info.ulMinPinLen, info.ulMaxPinLen);
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
	CK_FLAGS	pin_flags;

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
		if (login_type == CKU_SO)   {
			pin_flags=info.flags & (
				CKF_SO_PIN_COUNT_LOW |
				CKF_SO_PIN_FINAL_TRY |
				CKF_SO_PIN_LOCKED |
				CKF_SO_PIN_TO_BE_CHANGED);
			if(pin_flags)
				printf("WARNING: %s\n",p11_token_info_flags(pin_flags));

			printf("Please enter SO PIN: ");
		}
		else if (login_type == CKU_USER)   {
			pin_flags=info.flags & (
				CKF_USER_PIN_COUNT_LOW |
				CKF_USER_PIN_FINAL_TRY |
				CKF_USER_PIN_LOCKED |
				CKF_USER_PIN_TO_BE_CHANGED);
			if(pin_flags)
				printf("WARNING: %s\n",p11_token_info_flags(pin_flags));

			printf("Please enter User PIN: ");
		}
		else if (login_type == CKU_CONTEXT_SPECIFIC)   {
			printf("Please enter context specific PIN: ");
		}

		r = util_getpass(&pin, &len, stdin);
		if (r < 0)
			util_fatal("util_getpass error");
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
		util_fatal("The token label must be specified using --label");
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
				util_fatal("No PIN entered");
			if (!new_pin || !*new_pin || strlen(new_pin) > 20)
				util_fatal("Invalid SO PIN");
			strlcpy(new_buf, new_pin, sizeof new_buf);
			free(new_pin); new_pin = NULL;
			printf("Please enter the new SO PIN (again): ");
			r = util_getpass(&new_pin, &len, stdin);
			if (r < 0)
				util_fatal("No PIN entered");
			if (!new_pin || !*new_pin ||
					strcmp(new_buf, new_pin) != 0)
				util_fatal("Different new SO PINs");
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
				util_fatal("No PIN entered");
			if (!new_pin1 || !*new_pin1 || strlen(new_pin1) > 20)
				util_fatal("Invalid User PIN");
			printf("Please enter the new PIN again: ");
			r = util_getpass(&new_pin2, &len2, stdin);
			if (r < 0)
				util_fatal("No PIN entered");
			if (!new_pin2 || !*new_pin2 ||
					strcmp(new_pin1, new_pin2) != 0)
				util_fatal("Different new User PINs");
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
			if (!new_pin || !*new_pin || strcmp(new_buf, new_pin) != 0) {
				free(new_pin);
				return 1;
			}
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

/* return digest length in bytes */
static unsigned long hash_length(const int hash) {
	unsigned long sLen = 0;
	switch (hash) {
	case  CKM_SHA_1:
		sLen = 20;
		break;
	case  CKM_SHA224:
		sLen = 28;
		break;
	case  CKM_SHA256:
		sLen = 32;
		break;
	case  CKM_SHA384:
		sLen = 48;
		break;
	case  CKM_SHA512:
		sLen = 64;
		break;
	default:
		util_fatal("Unknown hash algorithm '%s' for RSA-PSS signatures",
			p11_mechanism_to_name(hash));
		break;
	}
	return sLen;
}

static unsigned long
parse_pss_params(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
    CK_MECHANISM *mech, CK_RSA_PKCS_PSS_PARAMS *pss_params)
{
	unsigned long hashlen = 0;

	if (pss_params == NULL)
		return 0;

	pss_params->hashAlg = 0;

	if (opt_hash_alg != 0 && opt_mechanism != CKM_RSA_PKCS_PSS)
		util_fatal("The hash-algorithm is applicable only to "
			"RSA-PKCS-PSS mechanism");

	/* set "default" MGF and hash algorithms. We can overwrite MGF later */
	switch (opt_mechanism) {
	case CKM_RSA_PKCS_PSS:
		pss_params->hashAlg = opt_hash_alg;

		switch (opt_hash_alg) {
		case CKM_SHA224:
			pss_params->mgf = CKG_MGF1_SHA224;
			break;
		case CKM_SHA256:
			pss_params->mgf = CKG_MGF1_SHA256;
			break;
		case CKM_SHA384:
			pss_params->mgf = CKG_MGF1_SHA384;
			break;
		case CKM_SHA512:
			pss_params->mgf = CKG_MGF1_SHA512;
			break;
		default:
			/* the PSS should use SHA-1 if not specified */
			pss_params->hashAlg = CKM_SHA_1;
			/* fallthrough */
		case CKM_SHA_1:
			pss_params->mgf = CKG_MGF1_SHA1;
		}
		break;

	case CKM_SHA1_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA_1;
		pss_params->mgf = CKG_MGF1_SHA1;
		break;

	case CKM_SHA224_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA224;
		pss_params->mgf = CKG_MGF1_SHA224;
		break;

	case CKM_SHA256_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA256;
		pss_params->mgf = CKG_MGF1_SHA256;
		break;

	case CKM_SHA384_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA384;
		pss_params->mgf = CKG_MGF1_SHA384;
		break;

	case CKM_SHA512_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA512;
		pss_params->mgf = CKG_MGF1_SHA512;
		break;

	default: /* The non-RSA-PSS algorithms do not need any parameters */
		return 0;
	}

	/* One of RSA-PSS mechanisms above: They need parameters */
	if (pss_params->hashAlg) {
		if (opt_mgf != 0)
			pss_params->mgf = opt_mgf;

		hashlen = hash_length(pss_params->hashAlg);

		if (opt_salt_len_given == 1) { /* salt size explicitly given */
			unsigned long modlen = 0;
			if (opt_salt_len < 0 && opt_salt_len != -1 && opt_salt_len != -2)
				util_fatal("Salt length must be greater or equal "
				    "to zero, or equal to -1 (meaning: use digest size) "
				    "or to -2 (meaning: use maximum permissible size");

			modlen = (get_private_key_length(session, key) + 7) / 8;
			switch (opt_salt_len) {
			case -1: /* salt size equals to digest size */
				pss_params->sLen = hashlen;
				break;
			case -2: /* maximum permissible salt len */
				pss_params->sLen = modlen - hashlen -2;
				break;
			default: /* use given size but its value must be >= 0 */
				pss_params->sLen = opt_salt_len;
				break;
			} /* end switch (opt_salt_len_given) */
		} else { /* use default: salt len of digest size */
			pss_params->sLen = hashlen;
		}

		mech->pParameter = pss_params;
		mech->ulParameterLen = sizeof(*pss_params);

		fprintf(stderr, "PSS parameters: hashAlg=%s, mgf=%s, salt_len=%lu B\n",
			p11_mechanism_to_name(pss_params->hashAlg),
			p11_mgf_to_name(pss_params->mgf),
			pss_params->sLen);
	}
	return hashlen;
}

static void sign_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1025], sig_buffer[512];
	CK_MECHANISM	mech;
	CK_RSA_PKCS_PSS_PARAMS pss_params;
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, r;
	unsigned long	hashlen;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_SIGN|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Sign mechanism not supported");

	fprintf(stderr, "Using signature algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;
	hashlen = parse_pss_params(session, key, &mech, &pss_params);

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	r = read(fd, in_buffer, sizeof(in_buffer));
	if (r < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	if (opt_mechanism == CKM_RSA_PKCS_PSS && (unsigned long)r != hashlen) {
		util_fatal("For %s mechanism, message size (got %d bytes) "
			"must be equal to specified digest length (%lu)\n",
			p11_mechanism_to_name(opt_mechanism), r, hashlen);
	}

	rv = CKR_CANCEL;
	if (r < (int) sizeof(in_buffer)) {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);
		if (getALWAYS_AUTHENTICATE(session, key))
			login(session,CKU_CONTEXT_SPECIFIC);

		sig_len = sizeof(sig_buffer);
		rv =  p11->C_Sign(session, in_buffer, r, sig_buffer, &sig_len);
	}

	if (rv != CKR_OK)   {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);
		if (getALWAYS_AUTHENTICATE(session, key))
			login(session,CKU_CONTEXT_SPECIFIC);

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

	if (opt_mechanism == CKM_ECDSA || opt_mechanism == CKM_ECDSA_SHA1 ||
	    opt_mechanism == CKM_ECDSA_SHA256 || opt_mechanism == CKM_ECDSA_SHA384 ||
	    opt_mechanism == CKM_ECDSA_SHA512 || opt_mechanism == CKM_ECDSA_SHA224) {
		if (opt_sig_format && (!strcmp(opt_sig_format, "openssl") ||
		                       !strcmp(opt_sig_format, "sequence"))) {
			unsigned char *seq;
			size_t seqlen;

			if (sc_asn1_sig_value_rs_to_sequence(NULL, sig_buffer,
			    sig_len, &seq, &seqlen)) {
				util_fatal("Failed to convert signature to ASN.1 sequence format");
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

static void verify_signature(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1025], sig_buffer[512];
	CK_MECHANISM	mech;
	CK_RSA_PKCS_PSS_PARAMS pss_params;
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, fd2, r, r2;
	unsigned long   hashlen;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_VERIFY|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Mechanism not supported for signature verification");

	fprintf(stderr, "Using signature algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;
	hashlen = parse_pss_params(session, key, &mech, &pss_params);

	/* Open a signature file */
	if (opt_signature_file == NULL)
		util_fatal("No file with signature provided. Use --signature-file");
	else if ((fd2 = open(opt_signature_file, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_signature_file);

	r2 = read(fd2, sig_buffer, sizeof(sig_buffer));
	if (r2 < 0)
		util_fatal("Cannot read from %s: %m", opt_signature_file);

	close(fd2);

	if (opt_mechanism == CKM_ECDSA || opt_mechanism == CKM_ECDSA_SHA1 ||
		opt_mechanism == CKM_ECDSA_SHA256 || opt_mechanism == CKM_ECDSA_SHA384 ||
		opt_mechanism == CKM_ECDSA_SHA512 || opt_mechanism == CKM_ECDSA_SHA224) {
		if (opt_sig_format && (!strcmp(opt_sig_format, "openssl") ||
							   !strcmp(opt_sig_format, "sequence"))) {

			CK_BYTE* bytes;
			CK_ULONG len;
			size_t rs_len = 0;
			unsigned char rs_buffer[512];
			bytes = getEC_POINT(session, key, &len);
			free(bytes);
			/*
			 * (We only support uncompressed for now)
			 * Uncompressed EC_POINT is DER OCTET STRING of "04||x||y"
			 * So a "256" bit key has x and y of 32 bytes each
			 * something like: "04 41 04||x||y"
			 * Do simple size calculation based on DER encoding
			 */
			if ((len - 2) <= 127)
				rs_len = len - 3;
			else if ((len - 3) <= 255)
				rs_len = len - 4;
			else
				util_fatal("Key not supported");

			if (sc_asn1_sig_value_sequence_to_rs(NULL, sig_buffer, r2,
				rs_buffer, rs_len)) {
				util_fatal("Failed to convert ASN.1 signature");
			}

			memcpy(sig_buffer, rs_buffer, rs_len);
			r2 = rs_len;
		}
	}

	/* Open the data file */
	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	r = read(fd, in_buffer, sizeof(in_buffer));
	if (r < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	if (opt_mechanism == CKM_RSA_PKCS_PSS && (unsigned long)r != hashlen) {
		util_fatal("For %s mechanism, message size (got %d bytes)"
			" must be equal to specified digest length (%lu)\n",
			p11_mechanism_to_name(opt_mechanism), r, hashlen);
	}

	rv = CKR_CANCEL;
	if (r < (int) sizeof(in_buffer)) {
		rv = p11->C_VerifyInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_VerifyInit", rv);

		sig_len = r2;
		rv =  p11->C_Verify(session, in_buffer, r, sig_buffer, sig_len);
	}

	if (rv != CKR_OK) {
		rv = p11->C_VerifyInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_VerifyInit", rv);

		do   {
			rv = p11->C_VerifyUpdate(session, in_buffer, r);
			if (rv != CKR_OK)
				p11_fatal("C_VerifyUpdate", rv);

			r = read(fd, in_buffer, sizeof(in_buffer));
		} while (r > 0);

		sig_len = r2;
		rv = p11->C_VerifyFinal(session, sig_buffer, sig_len);
		if (rv != CKR_OK)
			p11_fatal("C_VerifyFinal", rv);
	}

	if (fd != 0)
		close(fd);

	if (rv == CKR_OK)
		printf("Signature is valid\n");
	else if (rv == CKR_SIGNATURE_INVALID)
		printf("Invalid signature\n");
	else
		printf("Cryptoki returned erorr: %s\n", CKR2Str(rv));
}


static void decrypt_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1024], out_buffer[1024];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_ULONG	in_len, out_len;
	int		fd, r;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DECRYPT|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Decrypt mechanism not supported");

	fprintf(stderr, "Using decrypt algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;
	oaep_params.hashAlg = 0;

	if (opt_hash_alg != 0 && opt_mechanism != CKM_RSA_PKCS_OAEP)
		util_fatal("The hash-algorithm is applicable only to "
               "RSA-PKCS-OAEP mechanism");

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	r = read(fd, in_buffer, sizeof(in_buffer));
	if (r < 0)
		util_fatal("Cannot read from %s: %m", opt_input);
	in_len = r;

	/* set "default" MGF and hash algorithms. We can overwrite MGF later */
	switch (opt_mechanism) {
	case CKM_RSA_PKCS_OAEP:
		oaep_params.hashAlg = opt_hash_alg;
		switch (opt_hash_alg) {
		case CKM_SHA224:
			oaep_params.mgf = CKG_MGF1_SHA224;
			break;
		case CKM_SHA256:
			oaep_params.mgf = CKG_MGF1_SHA256;
			break;
		case CKM_SHA384:
			oaep_params.mgf = CKG_MGF1_SHA384;
			break;
		case CKM_SHA512:
			oaep_params.mgf = CKG_MGF1_SHA512;
			break;
		default:
			oaep_params.hashAlg = CKM_SHA_1;
			/* fall through */
		case CKM_SHA_1:
			oaep_params.mgf = CKG_MGF1_SHA1;
			break;
		}
		break;
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;
		break;
	default:
		util_fatal("Mechanism %s illegal or not supported\n", p11_mechanism_to_name(opt_mechanism));
	}


	/* If an RSA-OAEP mechanism, it needs parameters */
	if (oaep_params.hashAlg) {
		if (opt_mgf != 0)
			oaep_params.mgf = opt_mgf;

		/* These settings are compatible with OpenSSL 1.0.2L and 1.1.0+ */
		oaep_params.source = 0UL;  /* empty encoding parameter (label) */
		oaep_params.pSourceData = NULL; /* PKCS#11 standard: this must be NULLPTR */
		oaep_params.ulSourceDataLen = 0; /* PKCS#11 standard: this must be 0 */

		mech.pParameter = &oaep_params;
		mech.ulParameterLen = sizeof(oaep_params);

		fprintf(stderr, "OAEP parameters: hashAlg=%s, mgf=%s, source_type=%lu, source_ptr=%p, source_len=%lu\n",
			p11_mechanism_to_name(oaep_params.hashAlg),
			p11_mgf_to_name(oaep_params.mgf),
			oaep_params.source,
			oaep_params.pSourceData,
			oaep_params.ulSourceDataLen);

	}

	rv = p11->C_DecryptInit(session, &mech, key);
	if (rv != CKR_OK)
		p11_fatal("C_DecryptInit", rv);
	if (getALWAYS_AUTHENTICATE(session, key))
		login(session,CKU_CONTEXT_SPECIFIC);

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
			util_fatal("Digest mechanism is not supported");

	fprintf(stderr, "Using digest algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
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

/* Generate asymmetric key pair */
static int gen_keypair(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE *hPublicKey, CK_OBJECT_HANDLE *hPrivateKey, const char *type)
{
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG modulusBits = 1024;
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 }; /* 65537 in bytes */
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
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
		if (strncmp(type, "RSA:", strlen("RSA:")) == 0 || strncmp(type, "rsa:", strlen("rsa:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_X9_31_KEY_PAIR_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			CK_ULONG    key_length;
			const char *size = type + strlen("RSA:");

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE_KEY_PAIR, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate RSA mechanism not supported");

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
		}
		else if (!strncmp(type, "EC:", 3))   {
			CK_MECHANISM_TYPE mtypes[] = {CKM_EC_KEY_PAIR_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			int ii;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE_KEY_PAIR, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate EC key mechanism not supported\n");

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
				fprintf(stderr, "Cannot convert \"%s\"\n", ec_curve_infos[ii].oid_encoded);
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
		}
		else if (strncmp(type, "GOSTR3410", strlen("GOSTR3410")) == 0 || strncmp(type, "gostr3410", strlen("gostr3410")) == 0) {
			const struct sc_aid GOST2001_PARAMSET_A_OID = { { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 }, 9 };
			const struct sc_aid GOST2001_PARAMSET_B_OID = { { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02 }, 9 };
			const struct sc_aid GOST2001_PARAMSET_C_OID = { { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03 }, 9 };
			const struct sc_aid GOST2012_256_PARAMSET_A_OID = { { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01 }, 11 };
			const struct sc_aid GOST2012_512_PARAMSET_A_OID = { { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01 }, 11 };
			const struct sc_aid GOST2012_512_PARAMSET_B_OID = { { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02 }, 11 };
			const struct sc_aid GOST2012_512_PARAMSET_C_OID = { { 0x06, 0x09, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03 }, 11 };
			struct sc_aid key_paramset_encoded_oid;
			struct sc_aid hash_paramset_encoded_oid;
			unsigned long int gost_key_type = -1;
			CK_MECHANISM_TYPE mtypes[] = {-1};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *p_param_set = type + strlen("GOSTR3410");

			if (p_param_set == NULL)
				util_fatal("Unknown key type %s", type);

			if (!strcmp(":A", p_param_set) || !strcmp("-2001:A", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_A_OID;
				hash_paramset_encoded_oid = GOST_HASH2001_PARAMSET_OID;
			}
			else if (!strcmp(":B", p_param_set) || !strcmp("-2001:B", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_B_OID;
				hash_paramset_encoded_oid = GOST_HASH2001_PARAMSET_OID;
			}
			else if (!strcmp(":C", p_param_set) || !strcmp("-2001:C", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_C_OID;
				hash_paramset_encoded_oid = GOST_HASH2001_PARAMSET_OID;
			} else if (!strcmp("-2012-256:A", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2012_256_PARAMSET_A_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_256_PARAMSET_OID;
			}
			else if (!strcmp("-2012-256:B", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_A_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_256_PARAMSET_OID;
			}
			else if (!strcmp("-2012-256:C", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_B_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_256_PARAMSET_OID;
			}
			else if (!strcmp("-2012-256:D", p_param_set)) {
				gost_key_type = CKK_GOSTR3410;
				mtypes[0] = CKM_GOSTR3410_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2001_PARAMSET_C_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_256_PARAMSET_OID;
			}
			else if (!strcmp("-2012-512:A", p_param_set)) {
				gost_key_type = CKK_GOSTR3410_512;
				mtypes[0] = CKM_GOSTR3410_512_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2012_512_PARAMSET_A_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_512_PARAMSET_OID;
			}
			else if (!strcmp("-2012-512:B", p_param_set)) {
				gost_key_type = CKK_GOSTR3410_512;
				mtypes[0] = CKM_GOSTR3410_512_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2012_512_PARAMSET_B_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_512_PARAMSET_OID;
			}
			else if (!strcmp("-2012-512:C", p_param_set)) {
				gost_key_type = CKK_GOSTR3410_512;
				mtypes[0] = CKM_GOSTR3410_512_KEY_PAIR_GEN;
				key_paramset_encoded_oid = GOST2012_512_PARAMSET_C_OID;
				hash_paramset_encoded_oid = GOST_HASH2012_512_PARAMSET_OID;
			}
			else
				util_fatal("Unknown key type %s, valid key types for mechanism GOSTR3410 are GOSTR3410-2001:{A,B,C},"
					" GOSTR3410-2012-256:{A,B,C,D}, GOSTR3410-2012-512:{A,B,C}", type);

			if (!opt_mechanism_used) {
				if (!find_mechanism(slot, CKF_GENERATE_KEY_PAIR, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate GOSTR3410%s mechanism not supported", gost_key_type == CKK_GOSTR3410_512 ? "-2012-512" : "");
			}

			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_GOSTR3410_PARAMS, key_paramset_encoded_oid.value, key_paramset_encoded_oid.len);
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_GOSTR3410_PARAMS, key_paramset_encoded_oid.value, key_paramset_encoded_oid.len);
			n_privkey_attr++;

			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_GOSTR3411_PARAMS, hash_paramset_encoded_oid.value, hash_paramset_encoded_oid.len);
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_GOSTR3411_PARAMS, hash_paramset_encoded_oid.value, hash_paramset_encoded_oid.len);
			n_privkey_attr++;

			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_KEY_TYPE, &gost_key_type, sizeof(gost_key_type));
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_KEY_TYPE, &gost_key_type, sizeof(gost_key_type));
			n_privkey_attr++;

			if (opt_key_usage_default || opt_key_usage_sign) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_VERIFY, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_SIGN, &_true, sizeof(_true));
				n_privkey_attr++;
			}

			/* do not set 'derive' attribute unless it is specified directly */
			if (opt_key_usage_derive) {
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_DERIVE, &_true, sizeof(_true));
				n_privkey_attr++;
			}
		}
		else {
			util_fatal("Unknown key type %s", type);
		}

		mechanism.mechanism = opt_mechanism;
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

	if (opt_is_private != 0) {
		FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_PRIVATE,
			&_true, sizeof(_true));
		n_pubkey_attr++;
	}
	else {
		FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_PRIVATE,
			&_false, sizeof(_false));
		n_pubkey_attr++;
	}

	if (opt_always_auth != 0) {
		FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_ALWAYS_AUTHENTICATE,
				&_true, sizeof(_true));
		n_privkey_attr++;
	}

	if (opt_allowed_mechanisms_len > 0) {
		FILL_ATTR(privateKeyTemplate[n_privkey_attr],
			CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
			sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
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

/* generate symmetric key */
static int
gen_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *hSecretKey,
	const char *type, char *label)
{
	CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG    key_length;
	CK_ATTRIBUTE keyTemplate[20] = {
		{CKA_CLASS, &secret_key_class, sizeof(secret_key_class)},
		{CKA_TOKEN, &_true, sizeof(_true)},
	};
	int n_attr = 2;
	CK_RV rv;

	if (type != NULL) {
		if (strncasecmp(type, "AES:", strlen("AES:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_AES_KEY_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *size = type + strlen("AES:");

			key_type = CKK_AES;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate Key mechanism not supported\n");

			if (size == NULL)
				util_fatal("Unknown key type %s", type);
			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				key_length = 32;

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		}
		else if (strncasecmp(type, "DES:", strlen("DES:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_DES_KEY_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *size = type + strlen("DES:");

			key_type = CKK_DES;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate Key mechanism not supported\n");

			if (size == NULL)
				util_fatal("Unknown key type %s", type);
			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				key_length = 8;

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		}
		else if (strncasecmp(type, "DES3:", strlen("DES3:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_DES3_KEY_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *size = type + strlen("DES3:");

			key_type = CKK_DES3;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate Key mechanism not supported\n");

			if (size == NULL)
				util_fatal("Unknown key type %s", type);
			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				key_length = 16;

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		}
		else {
			util_fatal("Unknown key type %s", type);
		}

		if (opt_is_sensitive != 0) {
			FILL_ATTR(keyTemplate[n_attr], CKA_SENSITIVE, &_true, sizeof(_true));
			n_attr++;
		}
		else {
			FILL_ATTR(keyTemplate[n_attr], CKA_SENSITIVE, &_false, sizeof(_false));
			n_attr++;
		}

		FILL_ATTR(keyTemplate[n_attr], CKA_ENCRYPT, &_true, sizeof(_true));
		n_attr++;
		FILL_ATTR(keyTemplate[n_attr], CKA_DECRYPT, &_true, sizeof(_true));
		n_attr++;
		FILL_ATTR(keyTemplate[n_attr], CKA_WRAP, &_true, sizeof(_true));
		n_attr++;
		FILL_ATTR(keyTemplate[n_attr], CKA_UNWRAP, &_true, sizeof(_true));
		n_attr++;
		FILL_ATTR(keyTemplate[n_attr], CKA_VALUE_LEN, &key_length, sizeof(key_length));
		n_attr++;

		mechanism.mechanism = opt_mechanism;
	}

	if (label != NULL) {
		FILL_ATTR(keyTemplate[n_attr], CKA_LABEL, label, strlen(label));
		n_attr++;
	}
	else if (opt_object_label != NULL) {
		FILL_ATTR(keyTemplate[n_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
		n_attr++;
	}

	if (opt_object_id_len != 0) {
		FILL_ATTR(keyTemplate[n_attr], CKA_ID, opt_object_id, opt_object_id_len);
		n_attr++;
	}

	if (opt_allowed_mechanisms_len > 0) {
		FILL_ATTR(keyTemplate[n_attr],
			CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
			sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
		n_attr++;
	}

	rv = p11->C_GenerateKey(session, &mechanism, keyTemplate, n_attr, hSecretKey);
	if (rv != CKR_OK)
		p11_fatal("C_GenerateKey", rv);

	printf("Key generated:\n");
	show_object(session, *hSecretKey);
	return 1;
}


#ifdef ENABLE_OPENSSL
static void	parse_certificate(struct x509cert_info *cert,
		unsigned char *data, int len, unsigned char *contents,
		int *contents_len)
{
	X509 *x = NULL;
	unsigned char *p;
	int n;

	if (strstr((char *)data, "-----BEGIN CERTIFICATE-----")) {
		BIO *mem = BIO_new_mem_buf(data, len);
		x = PEM_read_bio_X509(mem, NULL, NULL, NULL);
		/* Update what is written to the card to be DER encoded */
		if (contents != NULL) {
			unsigned char *contents_pointer = contents;
			*contents_len = i2d_X509(x, &contents_pointer);
			if (*contents_len < 0)
				util_fatal("Failed to convert PEM to DER");
		}
		BIO_free(mem);
	} else {
		x = d2i_X509(NULL, (const unsigned char **)&data, len);
	}
	if (!x) {
		util_fatal("OpenSSL error during X509 certificate parsing");
	}
	/* convert only (if needed) */
	if (cert == NULL)
		return;

	/* check length first */
	n = i2d_X509_NAME(X509_get_subject_name(x), NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding subject name");
	if (n > (int)sizeof (cert->subject))
		util_fatal("subject name too long");
	/* green light, actually do it */
	p = cert->subject;
	n = i2d_X509_NAME(X509_get_subject_name(x), &p);
	cert->subject_len = n;

	/* check length first */
	n = i2d_X509_NAME(X509_get_issuer_name(x), NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding issuer name");
	if (n > (int)sizeof (cert->issuer))
		util_fatal("issuer name too long");
	/* green light, actually do it */
	p = cert->issuer;
	n =i2d_X509_NAME(X509_get_issuer_name(x), &p);
	cert->issuer_len = n;

	/* check length first */
	n = i2d_ASN1_INTEGER(X509_get_serialNumber(x), NULL);
	if (n < 0)
		util_fatal("OpenSSL error while encoding serial number");
	if (n > (int)sizeof (cert->serialnum))
		util_fatal("serial number too long");
	/* green light, actually do it */
	p = cert->serialnum;
	n = i2d_ASN1_INTEGER(X509_get_serialNumber(x), &p);
	cert->serialnum_len = n;
}

static int
do_read_key(unsigned char *data, size_t data_len, int private, EVP_PKEY **key)
{
	BIO *mem = BIO_new_mem_buf(data, data_len);;

	if (!key)
		return -1;

	if (private) {
		if (!strstr((char *)data, "-----BEGIN "))
			*key = d2i_PrivateKey_bio(mem, NULL);
		else
			*key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
	}
	else {
		if (!strstr((char *)data, "-----BEGIN "))
			*key = d2i_PUBKEY_bio(mem, NULL);
		else
			*key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
	}

	BIO_free(mem);
	if (*key == NULL)
		return -1;

	return 0;
}

#define RSA_GET_BN(RSA, LOCALNAME, BNVALUE) \
	do { \
		if (BNVALUE) { \
			RSA->LOCALNAME = malloc(BN_num_bytes(BNVALUE)); \
			if (!RSA->LOCALNAME) \
				util_fatal("malloc() failure\n"); \
			RSA->LOCALNAME##_len = BN_bn2bin(BNVALUE, RSA->LOCALNAME); \
		} else { \
			RSA->LOCALNAME##_len = 0; \
			RSA->LOCALNAME = NULL; \
		} \
	} while (0)

static int
parse_rsa_pkey(EVP_PKEY *pkey, int private, struct rsakey_info *rsa)
{
	RSA *r;
	const BIGNUM *r_n, *r_e, *r_d;
	const BIGNUM *r_p, *r_q;
	const BIGNUM *r_dmp1, *r_dmq1, *r_iqmp;

	r = EVP_PKEY_get1_RSA(pkey);
	if (!r) {
		if (private)
			util_fatal("OpenSSL error during RSA private key parsing");
		else
			util_fatal("OpenSSL error during RSA public key parsing");
	}

	RSA_get0_key(r, &r_n, &r_e, NULL);
	RSA_GET_BN(rsa, modulus, r_n);
	RSA_GET_BN(rsa, public_exponent, r_e);

	if (private) {
		RSA_get0_key(r, NULL, NULL, &r_d);
		RSA_GET_BN(rsa, private_exponent, r_d);

		RSA_get0_factors(r, &r_p, &r_q);
		RSA_GET_BN(rsa, prime_1, r_p);
		RSA_GET_BN(rsa, prime_2, r_q);

		RSA_get0_crt_params(r, &r_dmp1, &r_dmq1, &r_iqmp);
		RSA_GET_BN(rsa, exponent_1, r_dmp1);
		RSA_GET_BN(rsa, exponent_2, r_dmq1);
		RSA_GET_BN(rsa, coefficient, r_iqmp);
	}

	RSA_free(r);

	return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
static int
parse_gost_pkey(EVP_PKEY *pkey, int private, struct gostkey_info *gost)
{
	EC_KEY *src = EVP_PKEY_get0(pkey);
	unsigned char *pder;
	const BIGNUM *bignum;
	BIGNUM *X, *Y;
	const EC_POINT *point;
	int nid, rv;

	if (!src)
		return -1;

	nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0(pkey)));
	rv = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), NULL);
	if (rv < 0)
		return -1;

	gost->param_oid.value = malloc(rv);
	if (!gost->param_oid.value)
		return -1;

	pder =  gost->param_oid.value;
	rv = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &pder);
	gost->param_oid.len = rv;

	if (private) {
		bignum = EC_KEY_get0_private_key(EVP_PKEY_get0(pkey));

		gost->private.len = BN_num_bytes(bignum);
		gost->private.value = malloc(gost->private.len);
		if (!gost->private.value)
			return -1;
		BN_bn2bin(bignum, gost->private.value);
	}
	else {
		X = BN_new();
		Y = BN_new();
		point = EC_KEY_get0_public_key(src);
		rv = -1;
		if (X && Y && point && EC_KEY_get0_group(src))
			rv = EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(src),
					point, X, Y, NULL);
		if (rv == 1) {
			gost->public.len = BN_num_bytes(X) + BN_num_bytes(Y);
			gost->public.value = malloc(gost->public.len);
			if (!gost->public.value)
				rv = -1;
			else
			{
				BN_bn2bin(Y, gost->public.value);
				BN_bn2bin(X, gost->public.value + BN_num_bytes(Y));
			}
		}
		BN_free(X);
		BN_free(Y);
		if (rv != 1)
			return -1;
	}

	return 0;
}

static int
parse_ec_pkey(EVP_PKEY *pkey, int private, struct gostkey_info *gost)
{
	EC_KEY *src = EVP_PKEY_get0(pkey);
	const BIGNUM *bignum;

	if (!src)
		return -1;

	gost->param_oid.len = i2d_ECParameters(src, &gost->param_oid.value);
	if (gost->param_oid.len <= 0)
		return -1;

	if (private) {
		bignum = EC_KEY_get0_private_key(EVP_PKEY_get0(pkey));

		gost->private.len = BN_num_bytes(bignum);
		gost->private.value = malloc(gost->private.len);
		if (!gost->private.value)
			return -1;
		BN_bn2bin(bignum, gost->private.value);
	}
	else {
		unsigned char buf[512], *point;
		int point_len, header_len;
		const int MAX_HEADER_LEN = 3;
		const EC_GROUP *ecgroup = EC_KEY_get0_group(src);
		const EC_POINT *ecpoint = EC_KEY_get0_public_key(src);
		if (!ecgroup || !ecpoint)
			return -1;
		point_len = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), NULL);
		gost->public.value = malloc(MAX_HEADER_LEN+point_len);
		if (!gost->public.value)
			return -1;
		point = gost->public.value;
		ASN1_put_object(&point, 0, point_len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
		header_len = point-gost->public.value;
		memcpy(point, buf, point_len);
		gost->public.len = header_len+point_len;
#ifdef EC_POINT_NO_ASN1_OCTET_STRING // workaround for non-compliant cards not expecting DER encoding
		gost->public.len   -= header_len;
		gost->public.value += header_len;
#endif
	}

	return 0;
}
#endif
#endif

#define MAX_OBJECT_SIZE	5000

/* Currently for certificates (-type cert), private keys (-type privkey),
   public keys (-type pubkey) and data objects (-type data). */
static int write_object(CK_SESSION_HANDLE session)
{
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	unsigned char contents[MAX_OBJECT_SIZE + 1];
	int contents_len = 0;
	unsigned char certdata[MAX_OBJECT_SIZE];
	int certdata_len = 0;
	FILE *f;
	CK_OBJECT_HANDLE cert_obj, privkey_obj, pubkey_obj, seckey_obj, data_obj;
	CK_ATTRIBUTE cert_templ[20], privkey_templ[30], pubkey_templ[20], seckey_templ[20], data_templ[20];
	int n_cert_attr = 0, n_privkey_attr = 0, n_pubkey_attr = 0, n_seckey_attr = 0, n_data_attr = 0;
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
	int pk_type;

	memset(&cert, 0, sizeof(cert));
	memset(&rsa,  0, sizeof(rsa));
	memset(&gost,  0, sizeof(gost));
#endif

	memset(contents, 0, sizeof(contents));
	memset(certdata, 0, sizeof(certdata));

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		util_fatal("Couldn't open file \"%s\"", opt_file_to_write);
	contents_len = fread(contents, 1, sizeof(contents) - 1, f);
	if (contents_len < 0)
		util_fatal("Couldn't read from file \"%s\"", opt_file_to_write);
	fclose(f);
	contents[contents_len] = '\0';

	if (opt_attr_from_file) {
		if (!(f = fopen(opt_attr_from_file, "rb")))
			util_fatal("Couldn't open file \"%s\"", opt_attr_from_file);
		certdata_len = fread(certdata, 1, sizeof(certdata), f);
		fclose(f);
		if (certdata_len < 0)
			util_fatal("Couldn't read from file \"%s\"", opt_attr_from_file);
		certdata[certdata_len] = '\0';
		need_to_parse_certdata = 1;
	}
	if (opt_object_class == CKO_CERTIFICATE) {
		if (opt_attr_from_file) {
			/* Convert  contents  from PEM to DER if needed
			 * certdata  already read and will be validated later
			 */
#ifdef ENABLE_OPENSSL
			parse_certificate(NULL, contents, contents_len, contents, &contents_len);
#else
			util_fatal("No OpenSSL support, cannot parse certificate");
#endif
		} else {
			memcpy(certdata, contents, MAX_OBJECT_SIZE);
			certdata_len = contents_len;
			need_to_parse_certdata = 1;
		}
	}

	if (need_to_parse_certdata) {
#ifdef ENABLE_OPENSSL
		/* Validate and get the certificate fields (from certdata)
		 * and convert PEM to DER if needed
		 */
		parse_certificate(&cert, certdata, certdata_len,
			(opt_attr_from_file ? NULL : contents), &contents_len);
#else
		util_fatal("No OpenSSL support, cannot parse certificate");
#endif
	}
	if (opt_object_class == CKO_PRIVATE_KEY || opt_object_class == CKO_PUBLIC_KEY) {
#ifdef ENABLE_OPENSSL
		int is_private = opt_object_class == CKO_PRIVATE_KEY;
		int rv;

		rv = do_read_key(contents, contents_len, is_private, &evp_key);
		if (rv) {
			if (is_private)
				util_fatal("Cannot read private key");
			else
				util_fatal("Cannot read public key");
		}

		pk_type = EVP_PKEY_base_id(evp_key);

		if (pk_type == EVP_PKEY_RSA)   {
			rv = parse_rsa_pkey(evp_key, is_private, &rsa);
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		else if (pk_type == NID_id_GostR3410_2001)   {
			rv = parse_gost_pkey(evp_key, is_private, &gost);
			type = CKK_GOSTR3410;
		} else if (pk_type == EVP_PKEY_EC) {
			rv = parse_ec_pkey(evp_key, is_private, &gost);
			type = CKK_EC;
		}
#endif
		else
			util_fatal("Unsupported key type: 0x%X", pk_type);

		if (rv)
			util_fatal("Cannot parse key");
#else
		util_fatal("No OpenSSL support, cannot parse key");
#endif
	}

	switch(opt_object_class)
	{
	case CKO_CERTIFICATE:
		clazz = CKO_CERTIFICATE;
		cert_type = CKC_X_509;

		FILL_ATTR(cert_templ[0], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(cert_templ[1], CKA_VALUE, contents, contents_len);
		FILL_ATTR(cert_templ[2], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(cert_templ[3], CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type));
		FILL_ATTR(cert_templ[4], CKA_PRIVATE, &_false, sizeof(_false));
		n_cert_attr = 5;

		if (opt_object_label != NULL) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
			n_cert_attr++;
		}
		if (opt_object_id_len != 0) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_ID, opt_object_id, opt_object_id_len);
			n_cert_attr++;
		}
#ifdef ENABLE_OPENSSL
		/* according to PKCS #11 CKA_SUBJECT MUST be specified */
		FILL_ATTR(cert_templ[n_cert_attr], CKA_SUBJECT, cert.subject, cert.subject_len);
		n_cert_attr++;
		FILL_ATTR(cert_templ[n_cert_attr], CKA_ISSUER, cert.issuer, cert.issuer_len);
		n_cert_attr++;
		FILL_ATTR(cert_templ[n_cert_attr], CKA_SERIAL_NUMBER, cert.serialnum, cert.serialnum_len);
		n_cert_attr++;
#endif
		break;
	case CKO_PRIVATE_KEY:
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
		if (opt_always_auth != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_ALWAYS_AUTHENTICATE,
				&_true, sizeof(_true));
			n_privkey_attr++;
		}
		if (opt_allowed_mechanisms_len > 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr],
				CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
				sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
			n_privkey_attr++;
		}


#ifdef ENABLE_OPENSSL
		if (cert.subject_len != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_SUBJECT, cert.subject, cert.subject_len);
			n_privkey_attr++;
		}
		pk_type = EVP_PKEY_base_id(evp_key);

		if (pk_type == EVP_PKEY_RSA)   {
			type = CKK_RSA;
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
		else if (pk_type == EVP_PKEY_EC)   {
			type = CKK_EC;

			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_EC_PARAMS, gost.param_oid.value, gost.param_oid.len);
			n_privkey_attr++;
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_VALUE, gost.private.value, gost.private.len);
			n_privkey_attr++;
		}
		else if (pk_type == NID_id_GostR3410_2001)   {
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
		break;
	case CKO_PUBLIC_KEY:
		clazz = CKO_PUBLIC_KEY;
#ifdef ENABLE_OPENSSL
		pk_type = EVP_PKEY_base_id(evp_key);
		if (pk_type == EVP_PKEY_RSA)
			type = CKK_RSA;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		else if (pk_type == EVP_PKEY_EC)
			type = CKK_EC;
		else if (pk_type == NID_id_GostR3410_2001)
			type = CKK_GOSTR3410;
#endif
		else
			util_fatal("Unsupported public key type: 0x%X", pk_type);
#endif

		n_pubkey_attr = 0;
		FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_CLASS, &clazz, sizeof(clazz));
		n_pubkey_attr++;
		FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_TOKEN, &_true, sizeof(_true));
		n_pubkey_attr++;

		if (opt_is_private != 0) {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_PRIVATE, &_true, sizeof(_true));
			n_pubkey_attr++;
		}
		else {
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_PRIVATE, &_false, sizeof(_false));
			n_pubkey_attr++;
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
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_SUBJECT, cert.subject, cert.subject_len);
			n_pubkey_attr++;
		}
		pk_type = EVP_PKEY_base_id(evp_key);

		if (pk_type == EVP_PKEY_RSA) {
			type = CKK_RSA;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_MODULUS,
				rsa.modulus, rsa.modulus_len);
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_PUBLIC_EXPONENT, rsa.public_exponent, rsa.public_exponent_len);
			n_pubkey_attr++;
		}
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		else if (pk_type == EVP_PKEY_EC)   {
			type = CKK_EC;

			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_EC_PARAMS, gost.param_oid.value, gost.param_oid.len);
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_EC_POINT, gost.public.value, gost.public.len);
			n_pubkey_attr++;
		}
		else if (pk_type == NID_id_GostR3410_2001) {
			type = CKK_GOSTR3410;

			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_KEY_TYPE, &type, sizeof(type));
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_GOSTR3410_PARAMS, gost.param_oid.value, gost.param_oid.len);
			n_pubkey_attr++;
			FILL_ATTR(pubkey_templ[n_pubkey_attr], CKA_VALUE, gost.public.value, gost.public.len);
			/* CKA_VALUE of the GOST key has to be in the little endian order */
			rv = sc_mem_reverse(pubkey_templ[n_pubkey_attr].pValue, pubkey_templ[n_pubkey_attr].ulValueLen);
			if (rv)
				return rv;
			n_pubkey_attr++;
		}
#endif
#endif
		break;
	case CKO_SECRET_KEY:
		clazz = CKO_SECRET_KEY;
		type = CKK_AES;

		if (opt_key_type != 0) {
			if (strncasecmp(opt_key_type, "AES:", strlen("AES:")) == 0)
				type = CKK_AES;
			else if (strncasecmp(opt_key_type, "DES3:", strlen("DES3:")) == 0)
				type = CKK_DES3;
			else
				util_fatal("Unknown key type: 0x%X", type);
		}

		FILL_ATTR(seckey_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(seckey_templ[1], CKA_KEY_TYPE, &type, sizeof(type));
		FILL_ATTR(seckey_templ[2], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(seckey_templ[3], CKA_VALUE, &contents, contents_len);
		n_seckey_attr = 4;

		if (opt_is_private != 0) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_PRIVATE, &_true, sizeof(_true));
			n_seckey_attr++;
		}
		else {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_PRIVATE, &_false, sizeof(_false));
			n_seckey_attr++;
		}

		if (opt_is_sensitive != 0) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_SENSITIVE, &_true, sizeof(_true));
			n_seckey_attr++;
		}
		else {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_SENSITIVE, &_false, sizeof(_false));
			n_seckey_attr++;
		}

		if (opt_object_label != NULL) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
			n_seckey_attr++;
		}
		if (opt_object_id_len != 0)  {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_ID, opt_object_id, opt_object_id_len);
			n_seckey_attr++;
		}
		break;
	case CKO_DATA:
		clazz = CKO_DATA;
		FILL_ATTR(data_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(data_templ[1], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(data_templ[2], CKA_VALUE, &contents, contents_len);

		n_data_attr = 3;

		if (opt_is_private != 0) {
			FILL_ATTR(data_templ[n_data_attr], CKA_PRIVATE, &_true, sizeof(_true));
			n_data_attr++;
		}
		else {
			FILL_ATTR(data_templ[n_data_attr], CKA_PRIVATE, &_false, sizeof(_false));
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
				util_fatal("Invalid OID \"%s\"", opt_application_id);

			if (sc_asn1_encode_object_id(&oid_buf, &len, &oid))
				util_fatal("Cannot encode OID \"%s\"", opt_application_id);

			FILL_ATTR(data_templ[n_data_attr], CKA_OBJECT_ID, oid_buf, len);
			n_data_attr++;
		}

		if (opt_object_label != NULL) {
			FILL_ATTR(data_templ[n_data_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
			n_data_attr++;
		}
		break;
	default:
		util_fatal("Writing of a \"%s\" type not (yet) supported", opt_object_class_str);
		break;
	}

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

	if (n_seckey_attr) {
		rv = p11->C_CreateObject(session, seckey_templ, n_seckey_attr, &seckey_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);

		printf("Created secret key:\n");
		show_object(session, seckey_obj);
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
		fprintf(stderr, "set_id(): couldn't find the object\n");
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
			unsigned ii = list_len, jj;

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


static CK_OBJECT_HANDLE
derive_ec_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE mech_mech)
{
#if defined(ENABLE_OPENSSL) && !defined(OPENSSL_NO_EC) && !defined(OPENSSL_NO_ECDSA)
	CK_MECHANISM mech;
	CK_OBJECT_CLASS newkey_class= CKO_SECRET_KEY;
	CK_KEY_TYPE newkey_type = CKK_GENERIC_SECRET;
	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_OBJECT_HANDLE newkey = 0;
	CK_ATTRIBUTE newkey_template[20] = {
		{CKA_TOKEN, &false, sizeof(false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_SENSITIVE, &false, sizeof(false)},
		{CKA_EXTRACTABLE, &true, sizeof(true)},
		{CKA_ENCRYPT, &true, sizeof(true)},
		{CKA_DECRYPT, &true, sizeof(true)},
		{CKA_WRAP, &true, sizeof(true)},
		{CKA_UNWRAP, &true, sizeof(true)}
	};
	int n_attrs = 9;
	CK_ECDH1_DERIVE_PARAMS ecdh_parms;
	CK_RV rv;
	BIO *bio_in = NULL;
	EC_KEY  *eckey = NULL;
	const EC_GROUP *ecgroup = NULL;
	const EC_POINT *ecpoint = NULL;
	unsigned char *buf = NULL;
	size_t buf_size = 0;
	CK_ULONG key_len = 0;
	ASN1_OCTET_STRING *octet = NULL;
	unsigned char * der = NULL;
	unsigned char * derp = NULL;
	size_t  der_size = 0;

	printf("Using derive algorithm 0x%8.8lx %s\n", opt_mechanism, p11_mechanism_to_name(mech_mech));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = mech_mech;

	/*  Use OpenSSL to read the other public key, and get the raw version */
	bio_in = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio_in, opt_input) <= 0)
		util_fatal("Cannot open %s: %m", opt_input);

	eckey = d2i_EC_PUBKEY_bio(bio_in, NULL);
	if (!eckey)
		util_fatal("Cannot read EC key from %s", opt_input);

	ecpoint = EC_KEY_get0_public_key(eckey);
	ecgroup = EC_KEY_get0_group(eckey);

	if (!ecpoint || !ecgroup)
		util_fatal("Failed to parse other EC key from %s", opt_input);

	/* both eckeys must be same curve */
	key_len = (EC_GROUP_get_degree(ecgroup) + 7) / 8;
	FILL_ATTR(newkey_template[n_attrs], CKA_VALUE_LEN, &key_len, sizeof(key_len));
	n_attrs++;

	if (opt_allowed_mechanisms_len > 0) {
		FILL_ATTR(newkey_template[n_attrs],
			CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
			sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
		n_attrs++;
	}

	buf_size = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, NULL,	    0, NULL);
	buf = (unsigned char *)malloc(buf_size);
	if (buf == NULL)
	    util_fatal("malloc() failure\n");
	buf_size = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, buf_size, NULL);

	if (opt_derive_pass_der) {
		octet = ASN1_OCTET_STRING_new();
		if (octet == NULL)
		    util_fatal("ASN1_OCTET_STRING_new failure\n");
		ASN1_OCTET_STRING_set(octet, buf, buf_size);
		der_size = i2d_ASN1_OCTET_STRING(octet, NULL);
		derp = der = (unsigned char *) malloc(der_size);
		if (der == NULL)
			util_fatal("malloc() failure\n");
		der_size = i2d_ASN1_OCTET_STRING(octet, &derp);
	}

	BIO_free(bio_in);
	EC_KEY_free(eckey);

	memset(&ecdh_parms, 0, sizeof(ecdh_parms));
	ecdh_parms.kdf = CKD_NULL;
	ecdh_parms.ulSharedDataLen = 0;
	ecdh_parms.pSharedData = NULL;
	if (opt_derive_pass_der) {
		ecdh_parms.ulPublicDataLen = der_size;
		ecdh_parms.pPublicData = der;
	} else {
		ecdh_parms.ulPublicDataLen = buf_size;
		ecdh_parms.pPublicData = buf;
	}
	mech.pParameter = &ecdh_parms;
	mech.ulParameterLen = sizeof(ecdh_parms);

	rv = p11->C_DeriveKey(session, &mech, key, newkey_template, n_attrs, &newkey);
	if (rv != CKR_OK)
	    p11_fatal("C_DeriveKey", rv);

	if (der)
	    OPENSSL_free(der);
	if (buf)
	    free(buf);
	if (octet)
	    ASN1_OCTET_STRING_free(octet);

	return newkey;
#else
	util_fatal("Derive EC key not supported");
	return 0;
#endif /* ENABLE_OPENSSL  && !OPENSSL_NO_EC && !OPENSSL_NO_ECDSA */
}


static void
derive_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_BYTE *value = NULL;
	CK_ULONG value_len = 0;
	CK_OBJECT_HANDLE derived_key = 0;
	int rv, fd;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DERIVE|CKF_HW, NULL, 0, &opt_mechanism))
			util_fatal("Derive mechanism not supported");

	switch(opt_mechanism) {
	case CKM_ECDH1_COFACTOR_DERIVE:
	case CKM_ECDH1_DERIVE:
		derived_key= derive_ec_key(session, key, opt_mechanism);
		break;
	default:
		util_fatal("mechanism not supported for derive");
		break;
	}

	value = getVALUE(session, derived_key, &value_len);
	if (value && value_len > 0) {
		fd = STDOUT_FILENO;
		if (opt_output)   {
			fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, S_IRUSR|S_IWUSR);
			if (fd < 0)
				util_fatal("failed to open %s: %m", opt_output);
		}

		rv = write(fd, value, value_len);
		if (rv < 0)
			util_fatal("Failed to write to %s: %m", opt_output);

		if (opt_output)
			close(fd);
	}
}


static void
show_key(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_MECHANISM_TYPE_PTR mechs = NULL;
	CK_KEY_TYPE	key_type = getKEY_TYPE(sess, obj);
	CK_ULONG	size = 0;
	unsigned char	*id, *oid, *value;
	const char      *sepa;
	char		*label;
	int		pub = 1;
	int		sec = 0;

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
	case CKK_GOSTR3410_512:
		oid = getGOSTR3411_PARAMS(sess, obj, &size);
		if (oid) {
			if (size == GOST_HASH2001_PARAMSET_OID.len && !memcmp(oid, GOST_HASH2001_PARAMSET_OID.value, size))
				printf("; GOSTR3410\n");
			else if (size == GOST_HASH2012_256_PARAMSET_OID.len && !memcmp(oid, GOST_HASH2012_256_PARAMSET_OID.value, size))
				printf("; GOSTR3410-2012-256\n");
			else if (size == GOST_HASH2012_512_PARAMSET_OID.len && !memcmp(oid, GOST_HASH2012_512_PARAMSET_OID.value, size))
				printf("; GOSTR3410-2012-512\n");
			else
				printf("; unknown GOSTR3410 algorithm\n");
			free(oid);
		} else {
			printf("; unknown GOSTR3410 algorithm\n");
		}

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
			 * Uncompressed EC_POINT is DER OCTET STRING of "04||x||y"
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
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
		if (key_type == CKK_AES)
			printf("; AES");
		else if (key_type == CKK_DES)
			printf("; DES");
		else if (key_type == CKK_DES3)
			printf("; DES3");
		else
			printf("; Generic secret");
		size = getVALUE_LEN(sess, obj);
		if (size)
			printf(" length %li", size);
		size = 0;
		printf("\n");
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
	if (getDERIVE(sess, obj)) {
		printf("%sderive", sepa);
		sepa = ", ";
	}
	if (!*sepa)
		printf("none");
	printf("\n");

	printf("  Access:     ");
	sepa = "";
	if (!pub && getALWAYS_AUTHENTICATE(sess, obj)) {
		printf("%salways authenticate", sepa);
		sepa = ", ";
	}
	if (!pub || sec) {
		if (getSENSITIVE(sess, obj)) {
			printf("%ssensitive", sepa);
			sepa = ", ";
		}
		if (getALWAYS_SENSITIVE(sess, obj)) {
			printf("%salways sensitive", sepa);
			sepa = ", ";
		}
		if (getEXTRACTABLE(sess, obj)) {
			printf("%sextractable", sepa);
			sepa = ", ";
		}
		if (getNEVER_EXTRACTABLE(sess, obj)) {
			printf("%snever extractable", sepa);
			sepa = ", ";
		}
	}
	if (getLOCAL(sess, obj)) {
		printf("%slocal", sepa);
		sepa = ", ";
	}
	if (!*sepa)
		printf("none");
	printf("\n");

	if (!pub) {
		mechs = getALLOWED_MECHANISMS(sess, obj, &size);
		if (mechs && size) {
			unsigned int n;

			printf("  Allowed mechanisms: ");
			for (n = 0; n < size; n++) {
				printf("%s%s", (n != 0 ? "," : ""),
					p11_mechanism_to_name(mechs[n]));
			}
			printf("\n");
		}
	}

	suppress_warn = 0;
}

static void show_cert(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_CERTIFICATE_TYPE	cert_type = getCERTIFICATE_TYPE(sess, obj);
	CK_ULONG	size;
	unsigned char	*id;
	char		*label;
#if defined(ENABLE_OPENSSL)
	unsigned char	*subject;
#endif /* ENABLE_OPENSSL */

	printf("Certificate Object; type = ");
	switch (cert_type) {
	case CKC_X_509:
		printf("X.509 cert\n");
		break;
	case CKC_X_509_ATTR_CERT:
		printf("X.509 attribute cert\n");
		break;
	case CKC_VENDOR_DEFINED:
		printf("vendor defined\n");
		break;
	default:
		printf("unknown cert type\n");
		break;
	}

	if ((label = getLABEL(sess, obj, NULL)) != NULL) {
		printf("  label:      %s\n", label);
		free(label);
	}

#if defined(ENABLE_OPENSSL)
	if ((subject = getSUBJECT(sess, obj, &size)) != NULL) {
		X509_NAME *name;
		const unsigned char *tmp = subject;

		name = d2i_X509_NAME(NULL, &tmp, size);
		if(name) {
			BIO *bio = BIO_new(BIO_s_file());
			BIO_set_fp(bio, stdout, BIO_NOCLOSE);
			printf("  subject:    DN: ");
			X509_NAME_print(bio, name, XN_FLAG_RFC2253);
			printf("\n");
			BIO_free(bio);
		}
		free(subject);
	}
#endif /* ENABLE_OPENSSL */

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
		printf("<empty>");

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
	if (rv != CKR_OK)
		p11_fatal("C_GetMechanismList", rv);

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

#ifdef ENABLE_OPENSSL
unsigned char *BIO_copy_data(BIO *out, long *data_lenp) {
    unsigned char *data, *tdata;
    long data_len;

    data_len = BIO_get_mem_data(out, &tdata);
    data = malloc(data_len+1);
    if (data) {
        memcpy(data, tdata, data_len);
	data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
	if (data_lenp) {
	    *data_lenp = data_len;
	}
    } else {
        util_fatal("malloc failed");
    }
    return data;
}
#endif

/*
 * Read object CKA_VALUE attribute's value.
 */
static int read_object(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_ATTRIBUTE attrs[20];
	CK_OBJECT_CLASS clazz = opt_object_class;
#ifdef ENABLE_OPENSSL
	CK_KEY_TYPE type = CKK_RSA;
#endif
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
			util_fatal("Invalid OID \"%s\"", opt_application_id);

		if (sc_asn1_encode_object_id(&oid_buf, &oid_buf_len, &oid))
			util_fatal("Cannot encode OID \"%s\"", opt_application_id);

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
		util_fatal("object not found");

/* TODO: -DEE should look at object class, and get appropriate values
 * based on the object, and other attributes. For example EC keys do
 * not have a VALUE But have a EC_POINT. DvO: done for RSA and EC public keys.
 */
	if (clazz == CKO_PRIVATE_KEY) {
		fprintf(stderr, "sorry, reading private keys not (yet) supported\n");
		return 0;
	}
	if (clazz == CKO_PUBLIC_KEY) {
#ifdef ENABLE_OPENSSL
		long derlen;
		BIO *pout = BIO_new(BIO_s_mem());
		if (!pout)
			util_fatal("out of memory");

		type = getKEY_TYPE(session, obj);
		if (type == CKK_RSA) {
			RSA *rsa;
			BIGNUM *rsa_n = NULL;
			BIGNUM *rsa_e = NULL;


			rsa = RSA_new();
			if (rsa == NULL)
				util_fatal("out of memory");

			if ((value = getMODULUS(session, obj, &len))) {
				if (!(rsa_n = BN_bin2bn(value, len, NULL)))
					util_fatal("cannot parse MODULUS");
				free(value);
			} else
				util_fatal("cannot obtain MODULUS");

			if ((value = getPUBLIC_EXPONENT(session, obj, &len))) {
				if (!(rsa_e = BN_bin2bn(value, len, NULL)))
					util_fatal("cannot parse PUBLIC_EXPONENT");
				free(value);
			} else
				util_fatal("cannot obtain PUBLIC_EXPONENT");

			if (RSA_set0_key(rsa, rsa_n, rsa_e, NULL) != 1)
				util_fatal("cannot set RSA values");

			if (!i2d_RSA_PUBKEY_bio(pout, rsa))
				util_fatal("cannot convert RSA public key to DER");
			RSA_free(rsa);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L && !defined(OPENSSL_NO_EC)
		} else if (type == CKK_EC) {
			EC_KEY *ec;
			CK_BYTE *params;
			const unsigned char *a;
			ASN1_OCTET_STRING *os;
			EC_KEY *success = NULL;

			ec = EC_KEY_new();
			if (ec == NULL)
				util_fatal("out of memory");

			if ((params = getEC_PARAMS(session, obj, &len))) {
				const unsigned char *a = params;
				if (!d2i_ECParameters(&ec, &a, (long)len))
					util_fatal("cannot parse EC_PARAMS");
				OPENSSL_free(params);
			} else
				util_fatal("cannot obtain EC_PARAMS");

			value = getEC_POINT(session, obj, &len);
			/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
			a = value;
			os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)len);
			if (os) {
				a = os->data;
				success = o2i_ECPublicKey(&ec, &a, os->length);
				ASN1_STRING_free(os);
			}
			if (!success) { /* Workaround for broken PKCS#11 modules */
				a = value;
				success = o2i_ECPublicKey(&ec, &a, len);
			}
			free(value);
			if (!success)
				util_fatal("cannot obtain and parse EC_POINT");
			if (!i2d_EC_PUBKEY_bio(pout, ec))
				util_fatal("cannot convert EC public key to DER");
			EC_KEY_free(ec);
#endif
		}
		else
			util_fatal("Reading public keys of type 0x%X not (yet) supported", type);
		value = BIO_copy_data(pout, &derlen);
		BIO_free(pout);
		len = derlen;
#else
		util_fatal("No OpenSSL support, cannot read public key");
#endif
	}
	else
		value = getVALUE(session, obj, &len);
	if (value == NULL)
		util_fatal("get CKA_VALUE failed");

	if (opt_output)   {
		out = fopen(opt_output, "wb");
		if (out==NULL)
			util_fatal("cannot open '%s'", opt_output);
	}
	else
		out = stdout;

	if (fwrite(value, 1, len, out) != len)
		util_fatal("cannot write to '%s'", opt_output);
	if (opt_output)
		fclose(out);

	free(value);
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
			util_fatal("Invalid OID '%s'", opt_application_id);

		if (sc_asn1_encode_object_id(&oid_buf, &oid_buf_len, &oid))
			util_fatal("Cannot encode OID \"%s\"", opt_application_id);

		FILL_ATTR(attrs[nn_attrs], CKA_OBJECT_ID, oid_buf, oid_buf_len);
		nn_attrs++;
	}

	rv = find_object_with_attributes(session, &obj, attrs, nn_attrs, opt_object_index);
	if (rv != CKR_OK)
		p11_fatal("find_object_with_attributes()", rv);
	else if (obj==CK_INVALID_HANDLE)
		util_fatal("object not found");
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
		fprintf(stderr, "private key has no ID, can't lookup the corresponding pubkey\n");
		return 0;
	}

	if (!find_object(sess, CKO_PUBLIC_KEY, &pubkey, id, idLen, 0)) {
		free(id);
		fprintf(stderr, "couldn't find the corresponding pubkey\n");
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
		fprintf(stderr, "Digests: not implemented\n");
		return errors;
	}
	else    {
		printf("Digests:\n");
	}

	/* 1st test */
	pseudo_randomize(data, sizeof(data));

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
	BIGNUM *rsa_n, *rsa_e;

	id = NULL;
	id = getID(session, privKeyObject, &idLen);
	if (id == NULL) {
		fprintf(stderr, "private key has no ID, can't lookup the corresponding pubkey for verification\n");
		return NULL;
	}

	if (!find_object(session, CKO_PUBLIC_KEY, &pubkeyObject, id, idLen, 0)) {
		free(id);
		fprintf(stderr, "couldn't find the corresponding pubkey for validation\n");
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
				fprintf(stderr, "public key not extractable\n");
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
			rsa_n = BN_bin2bn(mod, modLen, NULL);
			rsa_e =	BN_bin2bn(exp, expLen, NULL);
			if (RSA_set0_key(rsa, rsa_n, rsa_e, NULL) != 1)
			    return NULL;

			EVP_PKEY_assign_RSA(pkey, rsa);
			free(mod);
			free(exp);
			return pkey;
		case CKK_DSA:
		case CKK_ECDSA:
		case CKK_GOSTR3410:
			break;
		default:
			fprintf(stderr, "public key of unsupported type\n");
			return NULL;
	}

	pubkey = getVALUE(session, pubkeyObject, &pubkeyLen);
	if (pubkey == NULL) {
		fprintf(stderr, "couldn't get the pubkey VALUE attribute, no validation done\n");
		return NULL;
	}

	pubkey_c = pubkey;
	pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &pubkey_c, pubkeyLen);
	free(pubkey);

	if (pkey == NULL) {
		fprintf(stderr, "couldn't parse pubkey, no verification done\n");
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
#ifndef OPENSSL_NO_RIPEMD
		EVP_ripemd160(),
#endif
		EVP_sha256(),
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
	fprintf(stderr, "unable to verify signature (compile with ENABLE_OPENSSL)\n");
#else

	if (!(pkey = get_public_key(session, privKeyObject)))
		return errors;

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx)
		err = -1;
	else {
		if (EVP_VerifyInit(md_ctx, evp_mds[evp_md_index])
				&& EVP_VerifyUpdate(md_ctx, verifyData, verifyDataLen)) {
			err = EVP_VerifyFinal(md_ctx, sig1, sigLen1, pkey);
		} else {
			err = -1;
		}
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
	unsigned char   data[512]; /* FIXME: Will not work for keys above 4096 bits */
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
#ifndef OPENSSL_NO_RIPEMD
		CKM_RIPEMD160_RSA_PKCS,
#endif
		CKM_SHA256_RSA_PKCS,
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
	if (!(sessionInfo.state & CKS_RW_USER_FUNCTIONS)) {
		printf("Signature: not a R/W session, skipping signature tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_SIGN | CKF_HW, mechTypes, mechTypes_num, &firstMechType)) {
		printf("Signatures: not implemented\n");
		return errors;
	}

	printf("Signatures (currently only for RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}
		if (getKEY_TYPE(sess, privKeyObject) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
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
		fprintf(stderr, "Signatures: no private key found in this slot\n");
		return 0;
	}

	/* 1st test */

	/* assume --login has already authenticated the key */
	switch (firstMechType) {
	case CKM_RSA_PKCS:
		dataLen = 35;
		memcpy(data, datas[1], dataLen);
		break;
	case CKM_RSA_X_509:
		dataLen = modLenBytes;
		pseudo_randomize(data, dataLen);
		break;
	default:
		dataLen = sizeof(data);	/* let's hope it's OK */
		pseudo_randomize(data, dataLen);
		break;
	}

	if (firstMechType == CKM_RSA_X_509) {
		/* make sure our data is smaller than the modulus */
		data[0] = 0x00;
	}

	ck_mech.mechanism = firstMechType;
	rv = p11->C_SignInit(sess, &ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if (getALWAYS_AUTHENTICATE(sess, privKeyObject))
		login(sess,CKU_CONTEXT_SPECIFIC);

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
	data[0] = 0x00;
	data[1] = 0x01;
	memset(data + 2, 0xFF, dataLen - 3 - dataLens[1]);
	if (dataLen >= 36)
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

	/* 4th test: the other signature keys */

	for (i = 0; mechTypes[i] != 0xffffff; i++)
		if (mechTypes[i] == firstMechType)
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

		if (getKEY_TYPE(sess, privKeyObject) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
		}
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

		/* Fill in data[0] and dataLens[0] */
		dataLen = modLenBytes;
		data[0] = 0x00;
		data[1] = 0x01;
		memset(data + 2, 0xFF, dataLen - 3 - dataLens[1]);
		data[dataLen - 36] = 0x00;
		memcpy(data + (dataLen - dataLens[1]), datas[1], dataLens[1]);
		datas[0] = data;
		dataLens[0] = dataLen;

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
		if (getALWAYS_AUTHENTICATE(session, priv_key))
			login(session,CKU_CONTEXT_SPECIFIC);
		printf("    %s: ", p11_mechanism_to_name(*mech_type));

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
	if (!(sessionInfo.state & CKS_RW_USER_FUNCTIONS)) {
		printf("Verify: not a R/W session, skipping verify tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_VERIFY, NULL, 0, &first_mech_type)) {
		printf("Verify: not implemented\n");
		return errors;
	}

	printf("Verify (currently only for RSA)\n");

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
		if (getKEY_TYPE(sess, priv_key) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
		}

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
		printf("\n");

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
	EVP_CIPHER_CTX	* seal_ctx;
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

	seal_ctx = EVP_CIPHER_CTX_new();
	if (seal_ctx == NULL) {
		printf("Internal error.\n");
		return 1;
	}

	if (!EVP_SealInit(seal_ctx, algo,
			&key, &key_len,
			iv, &pkey, 1)) {
		fprintf(stderr, "Internal error.\n");
		return 1;
	}

	/* Encrypt something */
	len = sizeof(ciphered);
	if (!EVP_SealUpdate(seal_ctx, ciphered, &len, (const unsigned char *) "hello world", 11)) {
		printf("Internal error.\n");
		return 1;
	}
	ciphered_len = len;

	len = sizeof(ciphered) - ciphered_len;
	if (!EVP_SealFinal(seal_ctx, ciphered + ciphered_len, &len)) {
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
		fprintf(stderr, "Could not get unwrapped key\n");
		return 1;
	}
	if (key_len != EVP_CIPHER_key_length(algo)) {
		fprintf(stderr, "Key length mismatch (%d != %d)\n",
				key_len, EVP_CIPHER_key_length(algo));
		return 1;
	}

	if (!EVP_DecryptInit(seal_ctx, algo, key, iv)) {
		printf("Internal error.\n");
		return 1;
	}

	len = sizeof(cleartext);
	if (!EVP_DecryptUpdate(seal_ctx, cleartext, &len, ciphered, ciphered_len)) {
		printf("Internal error.\n");
		return 1;
	}

	cleartext_len = len;
	len = sizeof(cleartext) - len;
	if (!EVP_DecryptFinal(seal_ctx, cleartext + cleartext_len, &len)) {
		printf("Internal error.\n");
		return 1;
	}
	cleartext_len += len;

	if (cleartext_len != 11
	 || memcmp(cleartext, "hello world", 11)) {
		printf("resulting cleartext doesn't match input\n");
		return 1;
	}

	if (seal_ctx)
	    EVP_CIPHER_CTX_free(seal_ctx);

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

	printf("Key unwrap (currently only for RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}
		if (getKEY_TYPE(sess, privKeyObject) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
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
#ifndef OPENSSL_NO_CAST
		errors += wrap_unwrap(sess, EVP_cast5_cfb(), privKeyObject);
#endif
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
	unsigned char	orig_data[512];
	unsigned char	encrypted[512], data[512];
	CK_MECHANISM	mech;
	CK_ULONG	encrypted_len, data_len;
	int             failed;
	CK_RV           rv;
	int             pad;
	CK_MECHANISM_TYPE hash_alg = CKM_SHA256;
	CK_RSA_PKCS_MGF_TYPE mgf = CKG_MGF1_SHA256;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	printf("    %s: ", p11_mechanism_to_name(mech_type));

	pseudo_randomize(orig_data, sizeof(orig_data));

	pkey = get_public_key(session, privKeyObject);
	if (pkey == NULL)
		return 0;

	if (EVP_PKEY_size(pkey) > (int)sizeof(encrypted)) {
		printf("Ciphertext buffer too small\n");
		EVP_PKEY_free(pkey);
		return 0;
	}
	size_t in_len;
	CK_ULONG mod_len = (get_private_key_length(session, privKeyObject) + 7) / 8;
	switch (mech_type) {
	case CKM_RSA_PKCS:
		pad = RSA_PKCS1_PADDING;
		/* Limit the input length to <= mod_len-11 */
		in_len = mod_len-11;
		break;
	case CKM_RSA_PKCS_OAEP: {
		if (opt_hash_alg != 0) {
			hash_alg = opt_hash_alg;
		}
		switch (hash_alg) {
		case CKM_SHA_1:
			mgf = CKG_MGF1_SHA1;
			break;
		case CKM_SHA224:
			mgf = CKG_MGF1_SHA224;
			break;
		default:
			printf("hash-algorithm %s unknown, defaulting to CKM_SHA256\n", p11_mechanism_to_name(hash_alg));
			/* fall through */
		case CKM_SHA256:
			mgf = CKG_MGF1_SHA256;
			break;
		case CKM_SHA384:
			mgf = CKG_MGF1_SHA384;
			break;
		case CKM_SHA512:
			mgf = CKG_MGF1_SHA512;
			break;
		}
		if (opt_mgf != 0) {
			mgf = opt_mgf;
		} else {
			printf("mgf not set, defaulting to %s\n", p11_mgf_to_name(mgf));
		}

		pad = RSA_PKCS1_OAEP_PADDING;
		/* Limit the input length to <= mod_len-2-2*hlen */
		size_t len = 2+2*hash_length(hash_alg);
		if (len >= mod_len) {
			printf("Incompatible mechanism and key size\n");
			return 0;
		}
		in_len = mod_len-len;
		break;
	}
	case CKM_RSA_X_509:
		pad = RSA_NO_PADDING;
		/* Limit the input length to the modulus length */
		in_len = mod_len;
		break;
	default:
		printf("Unsupported mechanism %s, returning\n", p11_mechanism_to_name(mech_type));
		return 0;
	}

	if (in_len > sizeof(orig_data)) {
		printf("Private key size is too long\n");
		return 0;
	}

	EVP_PKEY_CTX *ctx;
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx) {
		EVP_PKEY_free(pkey);
		printf("EVP_PKEY_CTX_new failed, returning\n");
		return 0;
	}
	if (EVP_PKEY_encrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		printf("EVP_PKEY_encrypt_init failed, returning\n");
		return 0;
	}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		printf("set padding failed, returning\n");
		return 0;
	}
	if (mech_type == CKM_RSA_PKCS_OAEP) {
		const EVP_MD *md;
		switch (hash_alg) {
		case CKM_SHA_1:
			md = EVP_sha1();
			break;
		case CKM_SHA224:
			md = EVP_sha224();
			break;
		default: /* it should not happen, hash_alg is checked earlier */
			/* fall through */
		case CKM_SHA256:
			md = EVP_sha256();
			break;
		case CKM_SHA384:
			md = EVP_sha384();
			break;
		case CKM_SHA512:
			md = EVP_sha512();
			break;
		}
#if defined(EVP_PKEY_CTX_set_rsa_oaep_md)
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(pkey);
			printf("set md failed, returning\n");
			return 0;
		}
#else
		if (hash_alg != CKM_SHA_1) {
			printf("This version of OpenSSL only supports SHA1 for OAEP, returning\n");
			return 0;
		}
#endif
		switch (mgf) {
		case CKG_MGF1_SHA1:
			md = EVP_sha1();
			break;
		case CKG_MGF1_SHA224:
			md = EVP_sha224();
			break;
		default:
			printf("mgf %s unknown, defaulting to CKG_MGF1_SHA256\n", p11_mgf_to_name(mgf));
			mgf = CKG_MGF1_SHA256;
			/* fall through */
		case CKG_MGF1_SHA256:
			md = EVP_sha256();
			break;
		case CKG_MGF1_SHA384:
			md = EVP_sha384();
			break;
		case CKG_MGF1_SHA512:
			md = EVP_sha512();
			break;
		}
		if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(pkey);
			printf("set mgf1 md failed, returning\n");
			return 0;
		}
	}

	size_t out_len = sizeof(encrypted);
	if (EVP_PKEY_encrypt(ctx, encrypted, &out_len, orig_data, in_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		printf("Encryption failed, returning\n");
		return 0;
	}
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	encrypted_len = out_len;

	/* set "default" MGF and hash algorithms. We can overwrite MGF later */
	switch (mech_type) {
	case CKM_RSA_PKCS_OAEP:
		oaep_params.hashAlg = hash_alg;
		oaep_params.mgf = mgf;

		/* These settings are compatible with OpenSSL 1.0.2L and 1.1.0+ */
		oaep_params.source = 0UL;  /* empty encoding parameter (label) */
		oaep_params.pSourceData = NULL; /* PKCS#11 standard: this must be NULLPTR */
		oaep_params.ulSourceDataLen = 0; /* PKCS#11 standard: this must be 0 */

		/* If an RSA-OAEP mechanism, it needs parameters */
		mech.pParameter = &oaep_params;
		mech.ulParameterLen = sizeof(oaep_params);

		fprintf(stderr, "OAEP parameters: hashAlg=%s, mgf=%s, source_type=%lu, source_ptr=%p, source_len=%lu\n",
			p11_mechanism_to_name(oaep_params.hashAlg),
			p11_mgf_to_name(oaep_params.mgf),
			oaep_params.source,
			oaep_params.pSourceData,
			oaep_params.ulSourceDataLen);
		break;
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;
		break;
	default:
		util_fatal("Mechanism %s illegal or not supported\n", p11_mechanism_to_name(mech_type));
	}

	mech.mechanism = mech_type;
	rv = p11->C_DecryptInit(session, &mech, privKeyObject);
	if (rv == CKR_MECHANISM_INVALID || rv == CKR_MECHANISM_PARAM_INVALID) {
		printf("Mechanism not supported\n");
		return 0;
	}
	if (rv != CKR_OK)
		p11_fatal("C_DecryptInit", rv);
	if (getALWAYS_AUTHENTICATE(session, privKeyObject))
		login(session,CKU_CONTEXT_SPECIFIC);

	data_len = encrypted_len;
	rv = p11->C_Decrypt(session, encrypted, encrypted_len, data, &data_len);
	if (rv != CKR_OK)
		p11_fatal("C_Decrypt", rv);

	failed = data_len != in_len || memcmp(orig_data, data, data_len);

	if (failed) {
		CK_ULONG n;

		printf("resulting cleartext doesn't match input\n");
		printf("    Original:");
		for (n = 0; n < in_len; n++)
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
	CK_ULONG        j, num_mechs = 0;
#ifdef ENABLE_OPENSSL
	CK_ULONG        n;
#endif
	char 		*label;

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if (!(sessionInfo.state & CKS_RW_USER_FUNCTIONS)) {
		printf("Decryption: not a R/W session, skipping decryption tests\n");
		return errors;
	}

	num_mechs = get_mechanisms(sessionInfo.slotID, &mechs, CKF_DECRYPT);
	if (num_mechs == 0) {
		printf("Decrypt: not implemented\n");
		return errors;
	}

	printf("Decryption (currently only for RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %ld ", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf("(%s) ", label);
			free(label);
		}
		if (getKEY_TYPE(sess, privKeyObject) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
		}
		if (!getDECRYPT(sess, privKeyObject)) {
			printf(" -- can't be used to decrypt, skipping\n");
			continue;
		}
		printf("\n");

#ifndef ENABLE_OPENSSL
		printf("No OpenSSL support, unable to validate decryption\n");
#else
		for (n = 0; n < num_mechs; n++) {
			switch (mechs[n]) {
			case CKM_RSA_PKCS:
			case CKM_RSA_PKCS_OAEP:
			case CKM_RSA_X_509:
				break;
			default:
				printf(" -- mechanism can't be used to decrypt, skipping\n");
				continue;
			}

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
static CK_SESSION_HANDLE test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
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
	CK_BYTE			id[] = "abcdefghijklmnopqrst";
	CK_ULONG		id_len = 20, mod_len = 0;
	CK_BYTE			*label = (CK_BYTE *) "Just a label";
	CK_ULONG		label_len = 12;
	CK_ATTRIBUTE		attribs[3] = {
		{CKA_ID, id, id_len},
		{CKA_LABEL, label, label_len},
		{CKA_SUBJECT, (void *) "This won't be used in our lib", 29}
	};
	FILE			*f;

	if (!opt_object_id_len) {
		fprintf(stderr, "ERR: must give an ID, e.g.: --id 01\n");
		return session;
	}
	if (!opt_key_type) {
		printf("ERR: must give an RSA key type, e.g.: --key-type RSA:1024\n");
		return session;
	}
	printf("\n*** We already opened a session and logged in ***\n");

	num_mechs = get_mechanisms(slot, &mech_type, -1);
	for (i = 0; i < num_mechs; i++) {
		if (mech_type[i] == CKM_RSA_PKCS_KEY_PAIR_GEN)
			break;
	}
	if (i == num_mechs) {
		fprintf(stderr, "ERR: no \"CKM_RSA_PKCS_KEY_PAIR_GEN\" found in the mechanism list\n");
		return session;
	}

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		util_fatal("Couldn't open file \"%s\"", opt_file_to_write);
	fclose(f);

	/* Get for a not-yet-existing ID */
	while(find_object(session, CKO_PRIVATE_KEY, &priv_key, id, id_len, 0))
		id[0]++;

	printf("\n*** Generating a %s key pair ***\n", opt_key_type);

	if (!gen_keypair(slot, session, &pub_key, &priv_key, opt_key_type)) {
		printf("ERR: cannot generate new key pair\n");
		return session;
	}

	tmp = getID(session, priv_key, (CK_ULONG *) &opt_object_id_len);
	if (opt_object_id_len == 0) {
		fprintf(stderr, "ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return session;
	}
	memcpy(opt_object_id, tmp, opt_object_id_len);

	/* This is done in NSS */
	getMODULUS(session, priv_key, &mod_len);
	if (mod_len < 5 || mod_len > 10000) { /* should be reasonable limits */
		fprintf(stderr, "ERR: GetAttribute(privkey, CKA_MODULUS) doesn't seem to work\n");
		return session;
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
	if (getALWAYS_AUTHENTICATE(session, priv_key))
		login(session,CKU_CONTEXT_SPECIFIC);

	rv = p11->C_Sign(session, data, data_len, NULL, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);
	sig_len = 20;
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		fprintf(stderr, "ERR: C_Sign() didn't return CKR_BUFFER_TO_SMALL but %s\n", CKR2Str(rv));
		return session;
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
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if (getALWAYS_AUTHENTICATE(session, priv_key))
		login(session,CKU_CONTEXT_SPECIFIC);

	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	printf("\n*** Changing the CKA_LABEL, CKA_ID and CKA_SUBJECT of the public key ***\n");

	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 3);
	if (rv != CKR_OK)
		p11_fatal("C_SetAttributeValue", rv);

	printf("*** Deleting the private and the public key again ***\n");

	rv = p11->C_DestroyObject(session, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_DestroyObject()", rv);
	rv = p11->C_DestroyObject(session, pub_key);
	if (rv != CKR_OK)
		p11_fatal("C_DestroyObject()", rv);

	printf("\n*** Logging off and releasing pkcs11 lib ***\n");

	rv = p11->C_CloseAllSessions(slot);
	if (rv != CKR_OK)
		p11_fatal("CloseAllSessions", rv);

	rv = p11->C_Finalize(NULL);
	if (rv != CKR_OK)
		p11_fatal("Finalize", rv);

	C_UnloadModule(module);

	/* Now we assume the user turns of her PC and comes back tomorrow to see
	 * if here cert is already made and to install it (as is done next) */

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
		util_fatal("Failed to write certificate");
	if (!delete_object(session))
		util_fatal("Failed to delete certificate");

	printf("\n==> OK, successful! Should work with Mozilla\n");
	return session;
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

	if (!opt_object_id_len) {
		fprintf(stderr, "ERR: must give an ID, e.g.: --id 01\n");
		return;
	}
	if (!opt_key_type) {
		fprintf(stderr, "ERR: must give an EC key type, e.g.: --key-type EC:secp256r1\n");
		return;
	}

	printf("\n*** We already opened a session and logged in ***\n");

	num_mechs = get_mechanisms(slot, &mech_type, -1);
	for (i = 0; i < num_mechs; i++)
		if (mech_type[i] == CKM_EC_KEY_PAIR_GEN)
			break;
	if (i == num_mechs) {
		printf("warning: no 'CKM_EC_KEY_PAIR_GEN' found in the mechanism list\n");
		//return;
	}

	printf("*** Generating EC key pair ***\n");
	if (!gen_keypair(slot, session, &pub_key, &priv_key, opt_key_type))
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
		p11_warn("C_SetAttributeValue(priv_key)", rv);

	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 1);
	if (rv != CKR_OK)
		p11_warn("C_SetAttributeValue(pub_key)", rv);

	printf("*** Doing a signature ***\n");
	data = data_to_sign;
	data_len = strlen((char *)data_to_sign);
	rv = p11->C_SignInit(session, &mech, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if (getALWAYS_AUTHENTICATE(session, priv_key))
		login(session,CKU_CONTEXT_SPECIFIC);
	rv = p11->C_Sign(session, data, data_len, NULL, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);
	sig_len -= 20;
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_BUFFER_TOO_SMALL) {
		printf("warning: C_Sign() didn't return CKR_BUFFER_TO_SMALL but %s\n", CKR2Str(rv));
		// return;
	}
	sig_len += 20;
	// re-doing C_SignInit after C_SignFinal to avoid CKR_OPERATION_NOT_INITIALIZED for CardOS
	rv = p11->C_SignFinal(session, sig, &sig_len);
	if (rv != CKR_OK) {
		p11_warn("C_SignFinal", rv);
	}
	rv = p11->C_SignInit(session, &mech, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if (getALWAYS_AUTHENTICATE(session, priv_key))
		login(session,CKU_CONTEXT_SPECIFIC);
	rv = p11->C_Sign(session, data, data_len, sig, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_Sign", rv);

	printf("*** Changing the CKA_LABEL, CKA_ID and CKA_SUBJECT of the public key ***\n");
	rv = p11->C_SetAttributeValue(session, pub_key, attribs, 3);
	if (rv != CKR_OK)
		p11_warn("C_SetAttributeValue(pub_key)", rv);

	printf("*** Deleting the private and the public key again ***\n");
	rv = p11->C_DestroyObject(session, priv_key);
	if (rv != CKR_OK)
		p11_fatal("C_DestroyObject()", rv);
	rv = p11->C_DestroyObject(session, pub_key);
	if (rv != CKR_OK)
		p11_fatal("C_DestroyObject()", rv);

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

static void generate_random(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_BYTE *buf;
	FILE *out;

	buf = malloc(opt_random_bytes);
	if (!buf)
		util_fatal("Not enough memory to allocate random data buffer");

	rv = p11->C_GenerateRandom(session, buf, opt_random_bytes);
	if (rv != CKR_OK)
		util_fatal("Could not generate random bytes");

	if (opt_output) {
		out = fopen(opt_output, "wb");
		if (out==NULL)
			util_fatal("Cannot open '%s'", opt_output);
	}
	else
		out = stdout;

	if (fwrite(buf, 1, opt_random_bytes, out) != opt_random_bytes)
		util_fatal("Cannot write to '%s'", opt_output);

	if (opt_output)
		fclose(out);

	free(buf);
}

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
		{ CKF_LOGIN_REQUIRED, "login required" },
		{ CKF_PROTECTED_AUTHENTICATION_PATH, "PIN pad present" },
		{ CKF_RNG, "rng" },
		{ CKF_SO_PIN_COUNT_LOW, "SO PIN count low" },
		{ CKF_SO_PIN_FINAL_TRY, "final SO PIN try" },
		{ CKF_SO_PIN_LOCKED, "SO PIN locked" },
		{ CKF_SO_PIN_TO_BE_CHANGED, "SO PIN to be changed"},
		{ CKF_TOKEN_INITIALIZED, "token initialized" },
		{ CKF_USER_PIN_COUNT_LOW, "user PIN count low" },
		{ CKF_USER_PIN_FINAL_TRY, "final user PIN try" },
		{ CKF_USER_PIN_INITIALIZED, "PIN initialized" },
		{ CKF_USER_PIN_LOCKED, "user PIN locked" },
		{ CKF_USER_PIN_TO_BE_CHANGED, "user PIN to be changed"},
		{ CKF_WRITE_PROTECTED, "readonly" },
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

	util_fatal("PKCS11 function %s failed: rv = %s (0x%0x)", func, CKR2Str(rv), (unsigned int) rv);
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
	int nybbles = 2;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

	left = *outlen;

	if (strlen(in) % 2)
		nybbles = 1; // any leading zero in output should be in most-significant byte, not last one!
	while (*in != '\0') {
		int byte = 0;

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
				fprintf(stderr, "hex_to_bin(): invalid char '%c' in hex string\n", c);
				*outlen = 0;
				return 0;
			}
			byte |= c;
		}
		if (*in == ':')
			in++;
		if (left <= 0) {
			fprintf(stderr, "hex_to_bin(): hex string too long");
			*outlen = 0;
			return 0;
		}
		out[count++] = (unsigned char) byte;
		left--;
		nybbles = 2;
	}

	*outlen = count;
	return 1;
}

static void pseudo_randomize(unsigned char *data, size_t dataLen)
{
	size_t i = 0;
	/* initialization with some data */
	while (i < dataLen) {
		*data = rand() & 0xFF;
		data++;
		i++;
	}
}

static struct mech_info	p11_mechanisms[] = {
      { CKM_RSA_PKCS_KEY_PAIR_GEN,	"RSA-PKCS-KEY-PAIR-GEN", NULL },
      { CKM_RSA_PKCS,		"RSA-PKCS",	NULL },
      { CKM_RSA_9796,		"RSA-9796",	NULL },
      { CKM_RSA_X_509,		"RSA-X-509",	NULL },
      { CKM_MD2_RSA_PKCS,	"MD2-RSA-PKCS",	NULL },
      { CKM_MD5_RSA_PKCS,	"MD5-RSA-PKCS",	"rsa-md5" },
      { CKM_SHA1_RSA_PKCS,	"SHA1-RSA-PKCS",	"rsa-sha1" },
      { CKM_SHA224_RSA_PKCS,	"SHA224-RSA-PKCS",	"rsa-sha224" },
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
      { CKM_SHA1_RSA_PKCS_PSS,	"SHA1-RSA-PKCS-PSS",	"rsa-pss-sha1" },
      { CKM_SHA224_RSA_PKCS_PSS,"SHA224-RSA-PKCS-PSS",	"rsa-pss-sha224" },
      { CKM_SHA256_RSA_PKCS_PSS,"SHA256-RSA-PKCS-PSS",	"rsa-pss-sha256" },
      { CKM_SHA384_RSA_PKCS_PSS,"SHA384-RSA-PKCS-PSS",	"rsa-pss-sha384" },
      { CKM_SHA512_RSA_PKCS_PSS,"SHA512-RSA-PKCS-PSS",	"rsa-pss-sha512" },
      { CKM_DSA_KEY_PAIR_GEN,	"DSA-KEY-PAIR-GEN",	NULL },
      { CKM_DSA,		"DSA",	NULL },
      { CKM_DSA_SHA1,		"DSA-SHA1", NULL },
      { CKM_DSA_SHA224,		"DSA-SHA224", NULL },
      { CKM_DSA_SHA256,		"DSA-SHA256", NULL },
      { CKM_DSA_SHA384,		"DSA-SHA384", NULL },
      { CKM_DSA_SHA512,		"DSA-SHA512", NULL },
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
      { CKM_DES3_CMAC,		"DES3-CMAC", NULL },
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
      { CKM_SHA224,		"SHA224", NULL },
      { CKM_SHA224_HMAC,	"SHA224-HMAC", NULL },
      { CKM_SHA256,		"SHA256", NULL },
      { CKM_SHA256_HMAC,	"SHA256-HMAC", NULL },
      { CKM_SHA384,		"SHA384", NULL },
      { CKM_SHA384_HMAC,	"SHA384-HMAC", NULL },
      { CKM_SHA512,		"SHA512", NULL },
      { CKM_SHA512_HMAC,	"SHA512-HMAC", NULL },
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
      { CKM_ECDSA_SHA224,	"ECDSA-SHA224", NULL },
      { CKM_ECDSA_SHA256,	"ECDSA-SHA256", NULL },
      { CKM_ECDSA_SHA384,	"ECDSA-SHA384", NULL },
      { CKM_ECDSA_SHA512,	"ECDSA-SHA512", NULL },
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
      { CKM_AES_CTR,		"AES-CTR", NULL },
      { CKM_AES_GCM,		"AES-GCM", NULL },
      { CKM_AES_CMAC,		"AES-CMAC", NULL },
      { CKM_DES_ECB_ENCRYPT_DATA, "DES-ECB-ENCRYPT-DATA", NULL },
      { CKM_DES_CBC_ENCRYPT_DATA, "DES-CBC-ENCRYPT-DATA", NULL },
      { CKM_DES3_ECB_ENCRYPT_DATA, "DES3-ECB-ENCRYPT-DATA", NULL },
      { CKM_DES3_CBC_ENCRYPT_DATA, "DES3-CBC-ENCRYPT-DATA", NULL },
      { CKM_AES_ECB_ENCRYPT_DATA, "AES-ECB-ENCRYPT-DATA", NULL },
      { CKM_AES_CBC_ENCRYPT_DATA, "AES-CBC-ENCRYPT-DATA", NULL },
      { CKM_GOST28147_KEY_GEN,	"GOST28147-KEY-GEN", NULL },
      { CKM_GOST28147_ECB,	"GOST28147-ECB", NULL },
      { CKM_GOST28147,	"GOST28147", NULL },
      { CKM_GOST28147_MAC,	"GOST28147-MAC", NULL },
      { CKM_GOST28147_KEY_WRAP,	"GOST28147-KEY-WRAP", NULL },
      { CKM_GOSTR3410_KEY_PAIR_GEN,"GOSTR3410-KEY-PAIR-GEN", NULL },
      { CKM_GOSTR3410,		"GOSTR3410", NULL },
      { CKM_GOSTR3410_DERIVE,	"GOSTR3410-DERIVE", NULL },
      { CKM_GOSTR3410_WITH_GOSTR3411,"GOSTR3410-WITH-GOSTR3411", NULL },
      { CKM_GOSTR3410_512_KEY_PAIR_GEN,	"GOSTR3410-512-KEY-PAIR-GEN", NULL },
      { CKM_GOSTR3410_512,	"GOSTR3410_512", NULL },
      { CKM_GOSTR3410_12_DERIVE,	"GOSTR3410-12-DERIVE", NULL },
      { CKM_GOSTR3410_WITH_GOSTR3411_12_256,	"GOSTR3410-WITH-GOSTR3411-12-256", NULL },
      { CKM_GOSTR3410_WITH_GOSTR3411_12_512,	"GOSTR3410-WITH-GOSTR3411-12-512", NULL },
      { CKM_GOSTR3411,		"GOSTR3411", NULL },
      { CKM_GOSTR3411_HMAC,	"GOSTR3411-HMAC", NULL },
      { CKM_GOSTR3411_12_256,	"GOSTR3411-12-256", NULL },
      { CKM_GOSTR3411_12_512,	"GOSTR3411-12-512", NULL },
      { CKM_GOSTR3411_12_256_HMAC,	"GOSTR3411-12-256-HMAC", NULL },
      { CKM_GOSTR3411_12_512_HMAC,	"GOSTR3411-12-512-HMAC", NULL },
      { CKM_DSA_PARAMETER_GEN,	"DSA-PARAMETER-GEN", NULL },
      { CKM_DH_PKCS_PARAMETER_GEN,"DH-PKCS-PARAMETER-GEN", NULL },
      { CKM_X9_42_DH_PARAMETER_GEN,"X9-42-DH-PARAMETER-GEN", NULL },
      { CKM_AES_KEY_WRAP,	"AES-KEY-WRAP", NULL},
      { 0, NULL, NULL }
};

static struct mech_info	p11_mgf[] = {
      { CKG_MGF1_SHA1,		"MGF1-SHA1", NULL },
      { CKG_MGF1_SHA224,	"MGF1-SHA224", NULL },
      { CKG_MGF1_SHA256,	"MGF1-SHA256", NULL },
      { CKG_MGF1_SHA384,	"MGF1-SHA384", NULL },
      { CKG_MGF1_SHA512,	"MGF1-SHA512", NULL },
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
	snprintf(temp, sizeof(temp), "mechtype-0x%lX", (unsigned long) mech);
	return temp;
}

static CK_MECHANISM_TYPE p11_name_to_mechanism(const char *name)
{
	struct mech_info *mi;

	if (strncasecmp("0x", name, 2) == 0) {
		return strtoul(name, NULL, 0);
	}
	for (mi = p11_mechanisms; mi->name; mi++) {
		if (!strcasecmp(mi->name, name)
		 || (mi->short_name && !strcasecmp(mi->short_name, name)))
			return mi->mech;
	}
	util_fatal("Unknown PKCS11 mechanism \"%s\"", name);
	return 0; /* gcc food */
}

static CK_RSA_PKCS_MGF_TYPE p11_name_to_mgf(const char *name)
{
	struct mech_info *mi;

	for (mi = p11_mgf; mi->name; mi++) {
		if (!strcasecmp(mi->name, name))
			return mi->mech;
	}
	util_fatal("Unknown PKCS11 MGF \"%s\"", name);
}

static const char *p11_mgf_to_name(CK_RSA_PKCS_MGF_TYPE mgf)
{
	static char temp[64];
	struct mech_info *mi;

	for (mi = p11_mgf; mi->name; mi++) {
		if (mi->mech == mgf)
			return mi->name;
	}
	snprintf(temp, sizeof(temp), "mgf-0x%lX", (unsigned long) mgf);
	return temp;
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
