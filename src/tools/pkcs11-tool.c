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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif
#else
#include <windows.h>
#include <io.h>
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
# include <openssl/param_build.h>
#include <openssl/provider.h>
#endif
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
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "common/compat_strlcat.h"
#include "common/compat_strlcpy.h"
#include "common/libpkcs11.h"
#include "util.h"
#include "libopensc/sc-ossl-compat.h"

/* pkcs11-tool uses libopensc routines that do not use an sc_context
 * but does use some OpenSSL routines
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static OSSL_PROVIDER *legacy_provider = NULL;
	static OSSL_PROVIDER *default_provider = NULL;
	static OSSL_LIB_CTX *osslctx = NULL;
#endif

#ifdef _WIN32
#ifndef STDOUT_FILENO
#define STDOUT_FILENO 1
#endif
#endif

#ifndef ENABLE_SHARED
extern CK_FUNCTION_LIST_3_0 pkcs11_function_list_3_0;
#endif

#if defined(_WIN32) || defined(HAVE_PTHREAD)
#define MAX_TEST_THREADS 10
#endif

#ifndef MIN
# define MIN(a, b)	(((a) < (b))? (a) : (b))
#endif

#define NEED_SESSION_RO	0x01
#define NEED_SESSION_RW	0x02

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

// clang-format off
static struct ec_curve_info {
	const char *name;
	const char *oid;
	const char *ec_params;
	size_t size;
	CK_KEY_TYPE mechanism;
} ec_curve_infos[] = {
	{"secp192r1",    "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0},
	{"prime192v1",   "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0},
	{"prime192v2",   "1.2.840.10045.3.1.2", "06082A8648CE3D030102", 192, 0},
	{"prime192v3",   "1.2.840.10045.3.1.3", "06082A8648CE3D030103", 192, 0},
	{"nistp192",     "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0},
	{"ansiX9p192r1", "1.2.840.10045.3.1.1", "06082A8648CE3D030101", 192, 0},

	{"secp224r1", "1.3.132.0.33", "06052b81040021", 224, 0},
	{"nistp224",  "1.3.132.0.33", "06052b81040021", 224, 0},

	{"prime256v1",   "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0},
	{"secp256r1",    "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0},
	{"ansiX9p256r1", "1.2.840.10045.3.1.7", "06082A8648CE3D030107", 256, 0},
	{"frp256v1",	 "1.2.250.1.223.101.256.1", "060a2a817a01815f65820001", 256, 0},

	{"secp384r1",		"1.3.132.0.34", "06052B81040022", 384, 0},
	{"prime384v1",		"1.3.132.0.34", "06052B81040022", 384, 0},
	{"ansiX9p384r1",	"1.3.132.0.34", "06052B81040022", 384, 0},

	{"prime521v1", "1.3.132.0.35", "06052B81040023", 521, 0},
	{"secp521r1", "1.3.132.0.35", "06052B81040023", 521, 0},
	{"nistp521",  "1.3.132.0.35", "06052B81040023", 521, 0},

	{"brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3", "06092B2403030208010103", 192, 0},
	{"brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5", "06092B2403030208010105", 224, 0},
	{"brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7", "06092B2403030208010107", 256, 0},
	{"brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9", "06092B2403030208010109", 320, 0},
	{"brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11", "06092B240303020801010B", 384, 0},
	{"brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13", "06092B240303020801010D", 512, 0},

	{"secp192k1",		"1.3.132.0.31", "06052B8104001F", 192, 0},
	{"secp256k1",		"1.3.132.0.10", "06052B8104000A", 256, 0},
	{"secp521k1",		"1.3.132.0.35", "06052B81040023", 521, 0},

	/* Some of the following may not yet be supported by the OpenSC module, but may be by other modules */
	/* OpenPGP extensions by Yubikey and GNUK are not defined in RFCs, so pass by printable string */
	/* See PKCS#11 3.0 2.3.7 */
	{"edwards25519", "1.3.6.1.4.1.11591.15.1", "130c656477617264733235353139", 255, CKM_EC_EDWARDS_KEY_PAIR_GEN}, /* send by curve name */
	{"curve25519",   "1.3.6.1.4.1.3029.1.5.1", "130a63757276653235353139",     255, CKM_EC_MONTGOMERY_KEY_PAIR_GEN}, /* send by curve name */

	/* RFC8410, EDWARDS and MONTGOMERY curves are used by GnuPG and also by OpenSSL */

	{"X25519",  "1.3.101.110", "06032b656e", 255, CKM_EC_MONTGOMERY_KEY_PAIR_GEN}, /* RFC 4810 send by OID */
	{"X448",    "1.3.101.111", "06032b656f", 448, CKM_EC_MONTGOMERY_KEY_PAIR_GEN}, /* RFC 4810 send by OID */
	{"Ed25519", "1.3.101.112", "06032b6570", 255, CKM_EC_EDWARDS_KEY_PAIR_GEN}, /* RFC 4810 send by OID */
	{"Ed448",   "1.3.101.113", "06032b6571", 448, CKM_EC_EDWARDS_KEY_PAIR_GEN}, /* RFC 4810 send by OID */

	/* GnuPG openpgp curves as used in gnupg-card are equivalent to RFC8410 OIDs */
	{"cv25519", "1.3.101.110", "06032b656e", 255, CKM_EC_MONTGOMERY_KEY_PAIR_GEN},
	{"ed25519", "1.3.101.112", "06032b6570", 255, CKM_EC_EDWARDS_KEY_PAIR_GEN},
	/* OpenSC card-openpgp.c will map these to what is need on the card */

	{NULL, NULL, NULL, 0, 0},
};
// clang-format on

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
	OPT_KEY_USAGE_WRAP,
	OPT_PRIVATE,
	OPT_SENSITIVE,
	OPT_EXTRACTABLE,
	OPT_UNDESTROYABLE,
	OPT_TEST_HOTPLUG,
	OPT_UNLOCK_PIN,
	OPT_PUK,
	OPT_NEW_PIN,
	OPT_SESSION_RW,
	OPT_LOGIN_TYPE,
	OPT_TEST_EC,
	OPT_DERIVE,
	OPT_DERIVE_PASS_DER,
	OPT_DECRYPT,
	OPT_ENCRYPT,
	OPT_UNWRAP,
	OPT_WRAP,
	OPT_TEST_FORK,
#if defined(_WIN32) || defined(HAVE_PTHREAD)
	OPT_TEST_THREADS,
	OPT_USE_LOCKING,
#endif

	OPT_GENERATE_KEY,
	OPT_GENERATE_RANDOM,
	OPT_HASH_ALGORITHM,
	OPT_MGF,
	OPT_SALT,
	OPT_VERIFY,
	OPT_SIGNATURE_FILE,
	OPT_ALWAYS_AUTH,
	OPT_ALLOWED_MECHANISMS,
	OPT_OBJECT_INDEX,
	OPT_ALLOW_SW,
	OPT_LIST_INTERFACES,
	OPT_IV,
	OPT_MAC_GEN_PARAM,
	OPT_AAD,
	OPT_TAG_BITS,
	OPT_SALT_FILE,
	OPT_INFO_FILE
};

// clang-format off
static const struct option options[] = {
	{ "module",		1, NULL,		OPT_MODULE },
	{ "show-info",		0, NULL,		'I' },
	{ "list-slots",		0, NULL,		'L' },
	{ "list-token-slots",	0, NULL,		'T' },
	{ "list-mechanisms",	0, NULL,		'M' },
	{ "list-objects",	0, NULL,		'O' },
	{ "list-interfaces",	0, NULL,		OPT_LIST_INTERFACES },

	{ "sign",		0, NULL,		's' },
	{ "verify",		0, NULL,		OPT_VERIFY },
	{ "decrypt",		0, NULL,		OPT_DECRYPT },
	{ "encrypt",		0, NULL,		OPT_ENCRYPT },
	{ "unwrap",		0, NULL,		OPT_UNWRAP },
	{ "wrap",		0, NULL,		OPT_WRAP },
	{ "hash",		0, NULL,		'h' },
	{ "derive",		0, NULL,		OPT_DERIVE },
	{ "derive-pass-der",	0, NULL,		OPT_DERIVE_PASS_DER },
	{ "mechanism",		1, NULL,		'm' },
	{ "hash-algorithm",	1, NULL,		OPT_HASH_ALGORITHM },
	{ "mgf",		1, NULL,		OPT_MGF },
	{ "salt-len",		1, NULL,		OPT_SALT },

	{ "session-rw",		0, NULL,		OPT_SESSION_RW },
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
	{ "usage-wrap",	0, NULL,		OPT_KEY_USAGE_WRAP },
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
	{ "extractable",	0, NULL,		OPT_EXTRACTABLE },
	{ "undestroyable",	0, NULL,		OPT_UNDESTROYABLE },
	{ "always-auth",	0, NULL,		OPT_ALWAYS_AUTH },
	{ "test-ec",		0, NULL,		OPT_TEST_EC },
#ifndef _WIN32
	{ "test-fork",		0, NULL,		OPT_TEST_FORK },
#endif
#if defined(_WIN32) || defined(HAVE_PTHREAD)
	{ "use-locking",	0, NULL,		OPT_USE_LOCKING },
	{ "test-threads",	1, NULL,		OPT_TEST_THREADS },
#endif
	{ "generate-random",	1, NULL,		OPT_GENERATE_RANDOM },
	{ "allow-sw",		0, NULL,		OPT_ALLOW_SW },
	{ "iv",			1, NULL,		OPT_IV },
	{ "mac-general-param",	1, NULL, 		OPT_MAC_GEN_PARAM},
	{ "aad", 		1, NULL, 		OPT_AAD	},
	{ "tag-bits-len", 	1, NULL, 		OPT_TAG_BITS},
	{ "salt-file", 		1, NULL,		OPT_SALT_FILE},
	{ "info-file",		1, NULL,		OPT_INFO_FILE},

	{ NULL, 0, NULL, 0 }
};
// clang-format on

static const char *option_help[] = {
		"Specify the module to load (default:" DEFAULT_PKCS11_PROVIDER ")",
		"Show global token information",
		"List available slots",
		"List slots with tokens",
		"List mechanisms supported by the token",
		"Show objects on token",
		"List interfaces of PKCS #11 3.0 library",

		"Sign some data",
		"Verify a signature of some data",
		"Decrypt some data",
		"Encrypt some data",
		"Unwrap key",
		"Wrap key",
		"Hash some data",
		"Derive a secret key using another key and some data",
		"Derive ECDHpass DER encoded pubkey for compatibility with some PKCS#11 implementations",
		"Specify mechanism (use -M for a list of supported mechanisms), or by hexadecimal, e.g., 0x80001234",
		"Specify hash algorithm used with RSA-PKCS-PSS signature and RSA-PKCS-OAEP decryption",
		"Specify MGF (Message Generation Function) used for RSA-PSS signature and RSA-OAEP decryption (possible values are MGF1-SHA1 to MGF1-SHA512)",
		"Specify how many bytes should be used for salt in RSA-PSS signatures (default is digest size)",

		"Forces to open the PKCS#11 session with CKF_RW_SESSION",
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
		"Specify the type and (not always compulsory) flavour (byte-wise symmetric key length, bit-wise asymmetric key length, elliptic curve identifier, etc.) of the key to create, for example RSA:2048, EC:prime256v1, GOSTR3410-2012-256:B, DES:8, DES3:24, AES:16, AES: or GENERIC:64",
		"Specify 'sign' key usage flag (sets SIGN in privkey, sets VERIFY in pubkey)",
		"Specify 'decrypt' key usage flag (sets DECRYPT in privkey and ENCRYPT in pubkey for RSA, sets both DECRYPT and ENCRYPT for secret keys)",
		"Specify 'derive' key usage flag (EC only)",
		"Specify 'wrap' key usage flag",
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
		"Specify the ID of the slot to use (accepts HEX format with 0x.. prefix or decimal number)",
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
		"Test Mozilla-like key pair gen and cert req, <arg>=certfile",
		"Verbose operation. (Set OPENSC_DEBUG to enable OpenSC specific debugging)",
		"Set the CKA_PRIVATE attribute (object is only viewable after a login)",
		"Set the CKA_SENSITIVE attribute (object cannot be revealed in plaintext)",
		"Set the CKA_EXTRACTABLE attribute (object can be extracted)",
		"Set the CKA_DESTROYABLE attribute to false (object cannot be destroyed)",
		"Set the CKA_ALWAYS_AUTHENTICATE attribute to a key object (require PIN verification for each use)",
		"Test EC (best used with the --login or --pin option)",
#ifndef _WIN32
		"Test forking and calling C_Initialize() in the child",
#endif
		"Call C_initialize() with CKF_OS_LOCKING_OK.",
#if defined(_WIN32) || defined(HAVE_PTHREAD)
		"Test threads. Multiple times to start additional threads, arg is string or 2 byte commands",
#endif
		"Generate given amount of random data",
		"Allow using software mechanisms (without CKF_HW)",
		"Initialization vector",
		"Specify the value <arg> of the mechanism parameter CK_MAC_GENERAL_PARAMS",
		"Specify additional authenticated data for AEAD ciphers as a hex string",
		"Specify the required length (in bits) for the authentication tag for AEAD ciphers",
		"Specify the file containing the salt for HKDF (optional)",
		"Specify the file containing the info for HKDF (optional)",
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
static int		opt_is_extractable = 0;
static int		opt_is_destroyable = 1;
static int		opt_test_hotplug = 0;
static int		opt_login_type = -1;
static int		opt_key_usage_sign = 0;
static int		opt_key_usage_decrypt = 0;
static int		opt_key_usage_derive = 0;
static int		opt_key_usage_wrap = 0;
static int		opt_key_usage_default = 1; /* uses defaults if no opt_key_usage options */
static int		opt_derive_pass_der = 0;
static unsigned long	opt_random_bytes = 0;
static CK_MECHANISM_TYPE opt_hash_alg = 0;
static unsigned long	opt_mgf = 0;
static long	        opt_salt_len = 0;
static int		opt_salt_len_given = 0; /* 0 - not given, 1 - given with input parameters */
static int		opt_always_auth = 0;
static CK_FLAGS		opt_allow_sw = CKF_HW;
static const char *	opt_iv = NULL;
static unsigned long opt_mac_gen_param = 0;
static const char *opt_aad = NULL;
static unsigned long opt_tag_bits = 0;
static const char *opt_salt_file = NULL;
static const char *opt_info_file = NULL;

static void *module = NULL;
static CK_FUNCTION_LIST_3_0_PTR p11 = NULL;
static CK_SLOT_ID_PTR p11_slots = NULL;
static CK_ULONG p11_num_slots = 0;
static int suppress_warn = 0;
static CK_C_INITIALIZE_ARGS_PTR  c_initialize_args_ptr = NULL;

#if defined(_WIN32) || defined(HAVE_PTHREAD)
static CK_C_INITIALIZE_ARGS  c_initialize_args_OS = {NULL, NULL, NULL, NULL, CKF_OS_LOCKING_OK, NULL};
#ifdef _WIN32
static HANDLE test_threads_handles[MAX_TEST_THREADS];
#else
static pthread_t test_threads_handles[MAX_TEST_THREADS];
#endif
struct test_threads_data {
	int tnum;
	char * tests;
};
static struct test_threads_data test_threads_datas[MAX_TEST_THREADS];
static int test_threads_num = 0;
#endif /* defined(_WIN32) || defined(HAVE_PTHREAD) */

struct flag_info {
	CK_FLAGS	value;
	const char *	name;
};

/*
 * Flags for mech_info. These flags can provide meta-data for
 * pkcs11 mechanisms and are tracked per mechanism. Thus for figuring
 * out if sign is valid for this mechanism, one can query the mechanism
 * table over having to build conditional statements.
 *
 * Note that the tool takes in raw 0x prefixed mechanisms that may not exist in
 * the table, so we just assume MF_UNKOWN for flags.
 *
 * TODO these flags are only the tip of the iceberg, but can be filled out as time progresses.
 */
#define MF_UNKNOWN 0        /* Used to indicate additional information is not available */
#define MF_SIGN    (1 << 0) /* C_Sign interface supported */
#define MF_VERIFY  (1 << 1) /* C_verify interface supported */
#define MF_HMAC    (1 << 2) /* Is an Hashed Message Authentication Code (HMAC) */
#define MF_MGF     (1 << 3) /* Is an Mask Generation Function (MGF) */
#define MF_CKO_SECRET_KEY (1 << 4) /* Uses a CKO_SECRET_KEY class object */

/* Handy initializers */
#define MF_GENERIC_HMAC_FLAGS (MF_SIGN | MF_VERIFY | MF_HMAC | MF_CKO_SECRET_KEY)

struct mech_info {
	CK_MECHANISM_TYPE mech;
	const char *	name;
	const char *	short_name;
	uint16_t mf_flags;
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
static void		list_objects(CK_SESSION_HANDLE);
static void		list_interfaces(void);
static int		login(CK_SESSION_HANDLE, int);
static void		init_token(CK_SLOT_ID);
static void		init_pin(CK_SLOT_ID, CK_SESSION_HANDLE);
static int		change_pin(CK_SLOT_ID, CK_SESSION_HANDLE);
static int		unlock_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess, int login_type);
static void		show_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_key(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_cert(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_dobj(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
static void		show_profile(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj);
static void		sign_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		verify_signature(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		decrypt_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		encrypt_data(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		hash_data(CK_SLOT_ID, CK_SESSION_HANDLE);
static void		derive_key(CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static int		gen_keypair(CK_SLOT_ID slot, CK_SESSION_HANDLE,
				CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *, const char *);
static int		gen_key(CK_SLOT_ID slot, CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, const char *, char *);
static int		unwrap_key(CK_SESSION_HANDLE session);
static int		wrap_key(CK_SESSION_HANDLE session);

static CK_RV		write_object(CK_SESSION_HANDLE session);
static int		read_object(CK_SESSION_HANDLE session);
static int		delete_object(CK_SESSION_HANDLE session);
static void		set_id_attr(CK_SESSION_HANDLE session);
static int		find_object_id_or_label(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
				CK_OBJECT_HANDLE_PTR ret,
				const unsigned char *, size_t id_len,
				const char *,
				int obj_index);
static int		find_object(CK_SESSION_HANDLE, CK_OBJECT_CLASS,
				CK_OBJECT_HANDLE_PTR,
				const unsigned char *, size_t id_len, int obj_index);
static int		find_object_flags(CK_SESSION_HANDLE, uint16_t flags,
				CK_OBJECT_HANDLE_PTR,
				const unsigned char *, size_t id_len, int obj_index);
static CK_ULONG		find_mechanism(CK_SLOT_ID, CK_FLAGS, CK_MECHANISM_TYPE_PTR, size_t, CK_MECHANISM_TYPE_PTR);
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
static uint16_t p11_mechanism_to_flags(CK_MECHANISM_TYPE mech);
static const char *	p11_mgf_to_name(CK_RSA_PKCS_MGF_TYPE);
static CK_MECHANISM_TYPE p11_name_to_mgf(const char *);
static const char *	p11_profile_to_name(CK_ULONG);
static void		p11_perror(const char *, CK_RV);
static const char *	CKR2Str(CK_ULONG res);
static int		p11_test(CK_SESSION_HANDLE session);
static int test_card_detection(int);
static CK_BYTE_PTR hex_string_to_byte_array(const char *iv_input, size_t *iv_size, const char *buffer_name);
static void		pseudo_randomize(unsigned char *data, size_t dataLen);
static CK_SESSION_HANDLE test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static void		test_ec(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
#ifndef _WIN32
static void		test_fork(void);
#endif
#if defined(_WIN32) || defined(HAVE_PTHREAD)
static void		test_threads();
static int		test_threads_start(int tnum);
static int		test_threads_cleanup();
#ifdef _WIN32
static DWORD WINAPI	test_threads_run(_In_ LPVOID pttd);
#else
static void *		test_threads_run(void * pttd);
#endif
#endif /* defined(_WIN32) || defined(HAVE_PTHREAD) */
static void		generate_random(CK_SESSION_HANDLE session);
static CK_RV		find_object_with_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *out,
				CK_ATTRIBUTE *attrs, CK_ULONG attrsLen, CK_ULONG obj_index);
static CK_ULONG		get_private_key_length(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE prkey);
static const char *percent_encode(CK_UTF8CHAR *, size_t);

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
ATTR_METHOD(SIGN_RECOVER, CK_BBOOL);		/* getSIGN_RECOVER */
ATTR_METHOD(VERIFY, CK_BBOOL);				/* getVERIFY */
ATTR_METHOD(VERIFY_RECOVER, CK_BBOOL);		/* getVERIFY_RECOVER */
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
ATTR_METHOD(PROFILE_ID, CK_ULONG);			/* getPROFILE_ID */
VARATTR_METHOD(LABEL, char);				/* getLABEL */
VARATTR_METHOD(UNIQUE_ID, char);			/* getUNIQUE_ID */
VARATTR_METHOD(APPLICATION, char);			/* getAPPLICATION */
VARATTR_METHOD(ID, unsigned char);			/* getID */
VARATTR_METHOD(OBJECT_ID, unsigned char);		/* getOBJECT_ID */
VARATTR_METHOD(MODULUS, CK_BYTE);			/* getMODULUS */
#ifdef ENABLE_OPENSSL
VARATTR_METHOD(SUBJECT, unsigned char);			/* getSUBJECT */
VARATTR_METHOD(SERIAL_NUMBER, unsigned char);	/* getSERIAL_NUMBER */
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
	int do_list_interfaces = 0;
	int do_sign = 0;
	int do_verify = 0;
	int do_decrypt = 0;
	int do_encrypt = 0;
	int do_unwrap = 0;
	int do_wrap = 0;
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
#if defined(_WIN32) || defined(HAVE_PTHREAD)
	int do_test_threads = 0;
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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!(osslctx = OSSL_LIB_CTX_new())) {
		util_fatal("Failed to create OpenSSL OSSL_LIB_CTX\n");
	}
	if (!(default_provider = OSSL_PROVIDER_load(osslctx, "default"))) {
		util_fatal("Failed to load OpenSSL \"default\" provider\n");
	}
	legacy_provider = OSSL_PROVIDER_try_load(NULL, "legacy", 1);
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
			if (sc_hex_to_bin(optarg, new_object_id, &new_object_id_len)) {
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
			if (sc_hex_to_bin(optarg, opt_object_id, &opt_object_id_len)) {
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
		case OPT_SESSION_RW:
			need_session |= NEED_SESSION_RW;
			break;
		case 'l':
			need_session |= NEED_SESSION_RO;
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
			need_session |= NEED_SESSION_RO;
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
			need_session |= NEED_SESSION_RO;
			do_sign = 1;
			action_count++;
			break;
		case OPT_VERIFY:
			need_session |= NEED_SESSION_RO;
			do_verify = 1;
			action_count++;
			break;
		case OPT_DECRYPT:
			need_session |= NEED_SESSION_RO;
			do_decrypt = 1;
			action_count++;
			break;
		case OPT_ENCRYPT:
			need_session |= NEED_SESSION_RO;
			do_encrypt = 1;
			action_count++;
			break;
		case OPT_UNWRAP:
			need_session |= NEED_SESSION_RW;
			do_unwrap = 1;
			action_count++;
			break;
		case OPT_WRAP:
			need_session |= NEED_SESSION_RO;
			do_wrap = 1;
			action_count++;
			break;
		case 'f':
			opt_sig_format = optarg;
			break;
		case 't':
			need_session |= NEED_SESSION_RW;
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
				fprintf(stderr, "Error: Only one of --slot, --slot-description, --slot-index or --token-label can be used\n");
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
			opt_slot_description = optarg;
			break;
		case OPT_SLOT_INDEX:
			if (opt_slot_set || opt_slot_description) {
				fprintf(stderr, "Error: Only one of --slot, --slot-description, --slot-index or --token-label can be used\n");
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
				fprintf(stderr, "Error: Only one of --slot, --slot-description, --slot-index or --token-label can be used\n");
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
		case OPT_KEY_USAGE_WRAP:
			opt_key_usage_wrap = 1;
			opt_key_usage_default = 0;
			break;
		case OPT_PRIVATE:
			opt_is_private = 1;
			break;
		case OPT_SENSITIVE:
			opt_is_sensitive = 1;
			break;
		case OPT_EXTRACTABLE:
			opt_is_extractable = 1;
			break;
		case OPT_UNDESTROYABLE:
			opt_is_destroyable = 0;
			break;
		case OPT_MAC_GEN_PARAM:
			if (optarg != NULL) {
				char *end_ptr;
				opt_mac_gen_param = strtoul(optarg, &end_ptr, 10);
			} else {
				util_fatal("--mac-general-param option needs a decimal value argument");
			}
			break;
		case OPT_AAD:
			opt_aad = optarg;
			break;
		case OPT_TAG_BITS:
			if (optarg != NULL) {
				char *end_ptr;
				opt_tag_bits = strtoul(optarg, &end_ptr, 10);
			} else {
				util_fatal("--tag-bits-len option needs a decimal value argument");
			}
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
#if defined(_WIN32) || defined(HAVE_PTHREAD)
		case OPT_USE_LOCKING:
			c_initialize_args_ptr = &c_initialize_args_OS;
			break;
		case OPT_TEST_THREADS:
			do_test_threads = 1;
			if (test_threads_num < MAX_TEST_THREADS) {
				test_threads_datas[test_threads_num].tnum = test_threads_num;
				test_threads_datas[test_threads_num].tests = optarg;
				test_threads_num++;
			} else {
				fprintf(stderr,"Too many --test_threads options limit is %d\n", MAX_TEST_THREADS);
				util_print_usage_and_die(app_name, options, option_help, NULL);
			}
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
		case OPT_ALLOW_SW:
			opt_allow_sw = 0;
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
		case OPT_LIST_INTERFACES:
			do_list_interfaces = 1;
			action_count++;
			break;
		case OPT_IV:
			opt_iv = optarg;
			break;
		case OPT_SALT_FILE:
			opt_salt_file = optarg;
			break;
		case OPT_INFO_FILE:
			opt_info_file = optarg;
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
		p11 = &pkcs11_function_list_3_0;
	else
#endif
	{
		CK_FUNCTION_LIST_PTR p11_v2 = NULL;

		module = C_LoadModule(opt_module, &p11_v2);
		if (module == NULL)
			util_fatal("Failed to load pkcs11 module");
		p11 = (CK_FUNCTION_LIST_3_0_PTR) p11_v2;
	}

	/* This can be done even before initialization */
	if (do_list_interfaces)
		list_interfaces();

	rv = p11->C_Initialize(c_initialize_args_ptr);

#if defined(_WIN32) || defined(HAVE_PTHREAD)
	if (do_test_threads || rv != CKR_OK)
		fprintf(stderr,"Main C_Initialize(%s) rv:%s\n",
				(c_initialize_args_ptr) ? "CKF_OS_LOCKING_OK" : "NULL",  CKR2Str(rv));
#else
	if (rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
		fprintf(stderr, "\n*** Cryptoki library has already been initialized ***\n");
#endif /* defined(_WIN32) || defined(HAVE_PTHREAD) */

	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
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
				fprintf(stderr, "You must specify a valid slot with either --slot, --slot-description, --slot-index or --token-label.\n");
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

	if (do_sign || do_decrypt || do_encrypt || do_unwrap || do_wrap) {
		CK_TOKEN_INFO info;

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

	uint16_t mf_flags = MF_UNKNOWN;
	if (opt_mechanism_used) {
		mf_flags = p11_mechanism_to_flags(opt_mechanism);
	}

	if (do_sign || do_derive) {

		/*
		 * Newer mechanisms have their details in the mechanism table, however
		 * if it's not known fall back to the old code always assuming it was a
		 * CKO_PRIVATE_KEY.
		 */
		if (mf_flags != MF_UNKNOWN) {
			/* this function dies on error via util_fatal */
			find_object_flags(session, mf_flags, &object,
				opt_object_id_len ? opt_object_id : NULL,
				opt_object_id_len, 0);
		} else if (!find_object(session, CKO_PRIVATE_KEY, &object,
					   opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
			if (!find_object(session, CKO_SECRET_KEY, &object,
					    opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
				util_fatal("Private/secret key not found");
	}

	if (do_decrypt) {
		/*
		 * Newer mechanisms have their details in the mechanism table, however
		 * if it's not known fall back to the old code always assuming it was a
		 * CKO_PUBLIC_KEY then a CKO_CERTIFICATE.
		 */
		if (mf_flags != MF_UNKNOWN) {
			/* this function dies on error via util_fatal */
			find_object_flags(session, mf_flags, &object,
				opt_object_id_len ? opt_object_id : NULL,
				opt_object_id_len, 0);
		} else if (!find_object(session, CKO_PRIVATE_KEY, &object,
				 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
			if (!find_object(session, CKO_SECRET_KEY, &object,
					 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
				util_fatal("Private/secret key not found");
	}

	if (do_encrypt) {
		/*
		 * Newer mechanisms have their details in the mechanism table, however
		 * if it's not known fall back to the old code always assuming it was a
		 * CKO_PUBLIC_KEY then a CKO_CERTIFICATE.
		 */
		if (mf_flags != MF_UNKNOWN) {
			/* this function dies on error via util_fatal */
			find_object_flags(session, mf_flags, &object,
				opt_object_id_len ? opt_object_id : NULL,
				opt_object_id_len, 0);
		} else if (!find_object(session, CKO_PUBLIC_KEY, &object,
					   opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
			if (!find_object(session, CKO_SECRET_KEY, &object,
					    opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
				util_fatal("Public/Secret key not found");
	}

	if (do_verify) {
		/*
		 * Newer mechanisms have their details in the mechanism table, however
		 * if it's not known fall back to the old code always assuming it was a
		 * CKO_PUBLIC_KEY then a CKO_CERTIFICATE.
		 */
		if (mf_flags != MF_UNKNOWN) {
			/* this function dies on error via util_fatal */
			find_object_flags(session, mf_flags, &object,
				opt_object_id_len ? opt_object_id : NULL,
				opt_object_id_len, 0);
		} else if (!find_object(session, CKO_PUBLIC_KEY, &object,
		        opt_object_id_len ? opt_object_id : NULL,
		        opt_object_id_len, 0) &&
		    !find_object(session, CKO_CERTIFICATE, &object,
		        opt_object_id_len ? opt_object_id : NULL,
		        opt_object_id_len, 0))
			util_fatal("Public key nor certificate not found");
	}

	if (do_unwrap)
		unwrap_key(session);

	if (do_wrap)
		wrap_key(session);

	/* before list objects, so we can see a derived key */
	if (do_derive)
		derive_key(opt_slot, session, object);

	if (do_list_objects)
		list_objects(session);

	if (do_sign)
		sign_data(opt_slot, session, object);

	if (do_verify)
		verify_signature(opt_slot, session, object);

	if (do_decrypt)
		decrypt_data(opt_slot, session, object);

	if (do_encrypt)
		encrypt_data(opt_slot, session, object);

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
		if (opt_object_id_len == 0 && opt_object_label == NULL)
			util_fatal("You should specify the current object with the -d or -a option");
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

#if defined(_WIN32) || defined(HAVE_PTHREAD)
	if (do_test_threads) {
		/* running threading tests is deliberately placed after opt_slot was
		 * initialized so that the command line options allow detailed
		 * configuration when running with `--test-threads LT` */
		test_threads();
		test_threads_cleanup();
	}
#endif /* defined(_WIN32) || defined(HAVE_PTHREAD) */

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

static void list_interfaces(void)
{
	CK_ULONG count = 0, i;
	CK_INTERFACE_PTR interfaces = NULL;
	CK_RV rv;

	if (p11->version.major < 3) {
		fprintf(stderr, "Interfaces are supported only in PKCS #11 3.0 and newer\n");
		exit(1);
	}

	rv = p11->C_GetInterfaceList(NULL, &count);
	if (rv != CKR_OK) {
		p11_fatal("C_GetInterfaceList(size inquire)", rv);
	}

	interfaces = malloc(count * sizeof(CK_INTERFACE));
	if (interfaces == NULL) {
			perror("malloc failed");
			exit(1);
	}
	rv = p11->C_GetInterfaceList(interfaces, &count);
	if (rv != CKR_OK) {
		p11_fatal("C_GetInterfaceList", rv);
	}
	for (i = 0; i < count; i++) {
		printf("Interface '%s'\n  version: %d.%d\n  funcs=%p\n  flags=0x%lu\n",
			interfaces[i].pInterfaceName,
			((CK_VERSION *)interfaces[i].pFunctionList)->major,
			((CK_VERSION *)interfaces[i].pFunctionList)->minor,
			interfaces[i].pFunctionList,
			interfaces[i].flags);
	}

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
		p11_slots = NULL;
		if (p11_num_slots > 0) {
			p11_slots = calloc(p11_num_slots, sizeof(CK_SLOT_ID));
			if (p11_slots == NULL) {
				perror("calloc failed");
				exit(1);
			}
			rv = p11->C_GetSlotList(tokens, p11_slots, &p11_num_slots);
			if (rv != CKR_OK)
				p11_fatal("C_GetSlotList()", rv);
		}

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

static const char *
copy_key_value_to_uri(const char *key, const char *value, CK_BBOOL last)
{
	static char URI[1024];
	static size_t shift = 0;
	if (key && (shift + strlen(key) < sizeof(URI))) {
		strcpy(&URI[shift], key);
		shift += strlen(key);
	}
	if (value && (shift + strlen(value) < sizeof(URI))) {
		strcpy(&URI[shift], value);
		shift += strlen(value);
	}
	if (key && value && !last && shift < sizeof(URI)) {
		URI[shift++] = ';';
	}
	if (last && shift < sizeof(URI)) {
		URI[shift] = '\0';
		shift = 0;
	}
	return URI;
}

static const char *
get_uri(CK_TOKEN_INFO_PTR info)
{
	copy_key_value_to_uri("pkcs11:", NULL, CK_FALSE);
	const char *model = percent_encode(info->model, sizeof(info->model));
	copy_key_value_to_uri("model=", model, CK_FALSE);
	const char *manufacturer = percent_encode(info->manufacturerID, sizeof(info->manufacturerID));
	copy_key_value_to_uri("manufacturer=", manufacturer, CK_FALSE);
	const char *serial = percent_encode(info->serialNumber, sizeof(info->serialNumber));
	copy_key_value_to_uri("serial=", serial, CK_FALSE);
	const char *token = percent_encode(info->label, sizeof(info->label));
	return copy_key_value_to_uri("token=", token, CK_TRUE);
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
	printf("  uri                : %s", get_uri(&info));
	printf("\n");
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
			if (info.flags & CKF_EC_F_P) {
				printf(", EC F_P");
				info.flags &= ~CKF_EC_F_P;
			}
			if (info.flags & CKF_EC_F_2M) {
				printf(", EC F_2M");
				info.flags &= ~CKF_EC_F_2M;
			}
			if (info.flags & CKF_EC_ECPARAMETERS) {
				printf(", EC parameters");
				info.flags &= ~CKF_EC_ECPARAMETERS;
			}
			if (info.flags & CKF_EC_OID) {
				printf(", EC OID");
				info.flags &= ~CKF_EC_OID;
			}
			if (info.flags & CKF_EC_UNCOMPRESS) {
				printf(", EC uncompressed");
				info.flags &= ~CKF_EC_UNCOMPRESS;
			}
			if (info.flags & CKF_EC_COMPRESS) {
				printf(", EC compressed");
				info.flags &= ~CKF_EC_COMPRESS;
			}
			if (info.flags & CKF_EC_CURVENAME) {
				printf(", EC curve name");
				info.flags &= ~CKF_EC_CURVENAME;
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
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
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
	char old_buf[21], *old_pin = opt_so_pin ? (char*)opt_so_pin : (char*)opt_pin;
	char new_buf[21], *new_pin = (char *)opt_new_pin;
	CK_TOKEN_INFO	info;
	CK_RV rv;
	int r;
	size_t		len = 0;

	get_token_info(slot, &info);
	const CK_FLAGS hasReaderPinPad = info.flags & CKF_PROTECTED_AUTHENTICATION_PATH;

	if (!hasReaderPinPad && !old_pin) {
		printf("Please enter the current PIN: ");
		r = util_getpass(&old_pin, &len, stdin);
		if (r < 0)
			return 1;
		if (!old_pin || !*old_pin || strlen(old_pin) > 20)
			return 1;
		strcpy(old_buf, old_pin);
		old_pin = old_buf;
	}
	if (!hasReaderPinPad && !new_pin) {
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

/* return matching ec_curve_info or NULL based on ec_params */
static const struct ec_curve_info *
match_ec_curve_by_params(const unsigned char *ec_params, CK_ULONG ec_params_size)
{
	char ecpbuf[64];

	if (ec_params_size > (sizeof(ecpbuf) / 2)) {
		util_fatal("Invalid EC params");
	}

	sc_bin_to_hex(ec_params, ec_params_size, ecpbuf, sizeof(ecpbuf), 0);

	for (size_t i = 0; ec_curve_infos[i].name != NULL; ++i) {
		if (strcmp(ec_curve_infos[i].ec_params, ecpbuf) == 0) {
			return &ec_curve_infos[i];
		}
	}

	return NULL;
}

/* return digest length in bytes */
static unsigned long hash_length(const unsigned long hash) {
	unsigned long sLen = 0;
	switch (hash) {
	case  CKM_SHA_1:
		sLen = 20;
		break;
	case  CKM_SHA224:
	case  CKM_SHA3_224:
		sLen = 28;
		break;
	case  CKM_SHA256:
	case  CKM_SHA3_256:
		sLen = 32;
		break;
	case  CKM_SHA384:
	case  CKM_SHA3_384:
		sLen = 48;
		break;
	case  CKM_SHA512:
	case  CKM_SHA3_512:
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
		case CKM_SHA3_224:
			pss_params->mgf = CKG_MGF1_SHA3_224;
			break;
		case CKM_SHA3_256:
			pss_params->mgf = CKG_MGF1_SHA3_256;
			break;
		case CKM_SHA3_384:
			pss_params->mgf = CKG_MGF1_SHA3_384;
			break;
		case CKM_SHA3_512:
			pss_params->mgf = CKG_MGF1_SHA3_512;
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

	case CKM_SHA3_224_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA3_224;
		pss_params->mgf = CKG_MGF1_SHA3_224;
		break;

	case CKM_SHA3_256_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA3_256;
		pss_params->mgf = CKG_MGF1_SHA3_256;
		break;

	case CKM_SHA3_384_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA3_384;
		pss_params->mgf = CKG_MGF1_SHA3_384;
		break;

	case CKM_SHA3_512_RSA_PKCS_PSS:
		pss_params->hashAlg = CKM_SHA3_512;
		pss_params->mgf = CKG_MGF1_SHA3_512;
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

			modlen = BYTES4BITS(get_private_key_length(session, key));
			if (modlen == 0)
				util_fatal("Incorrect length of private key");
			switch (opt_salt_len) {
			case -1: /* salt size equals to digest size */
				pss_params->sLen = hashlen;
				break;
			case -2: /* maximum permissible salt len */
			case -3:
				pss_params->sLen = modlen - hashlen - 2;
				break;
			default: /* use given size but its value must be >= 0 */
				if (opt_salt_len < 0)
					util_fatal("Salt length must be greater or equal "
						"to zero, or equal to -1 (meaning: use digest size) "
						"or to -2 or -3 (meaning: use maximum permissible size");

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
	CK_MAC_GENERAL_PARAMS mac_gen_param;
	CK_EDDSA_PARAMS eddsa_params = {
			.phFlag = CK_FALSE,
	};
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd;
	ssize_t sz;
	unsigned long	hashlen;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_SIGN|opt_allow_sw, NULL, 0, &opt_mechanism))
			util_fatal("Sign mechanism not supported");

	fprintf(stderr, "Using signature algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;
	hashlen = parse_pss_params(session, key, &mech, &pss_params);

	/* support pure EdDSA only */
	if (opt_mechanism == CKM_EDDSA) {
		const struct ec_curve_info *curve;
		unsigned char *ec_params;
		CK_ULONG ec_params_size = 0;

		ec_params = getEC_PARAMS(session, key, &ec_params_size);
		if (ec_params == NULL) {
			util_fatal("Key has no EC_PARAMS attribute");
		}

		curve = match_ec_curve_by_params(ec_params, ec_params_size);
		if (curve == NULL) {
			util_fatal("Unknown or unsupported EC curve used in key");
		}

		/* Ed448: need the params defined but default to false */
		if (curve->size == 448) {
			mech.pParameter = &eddsa_params;
			mech.ulParameterLen = (CK_ULONG)sizeof(eddsa_params);
		}
	}

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	sz = read(fd, in_buffer, sizeof(in_buffer));
	if (sz < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	if (opt_mechanism == CKM_RSA_PKCS_PSS && (size_t)sz != hashlen) {
		util_fatal("For %s mechanism, message size (got %z bytes) "
			"must be equal to specified digest length (%lu)\n",
			p11_mechanism_to_name(opt_mechanism), sz, hashlen);
	} else if (opt_mechanism == CKM_AES_CMAC_GENERAL) {
		if (opt_mac_gen_param == 0 || opt_mac_gen_param > 16) {
			util_fatal("For %s mechanism, the option --mac-general-param "
				   "is mandatory and its value must be comprised between 1 and "
				   "16 (>=8 recommended).\n",
					p11_mechanism_to_name(opt_mechanism));
		}
		mac_gen_param = opt_mac_gen_param;
		mech.pParameter = &mac_gen_param;
		mech.ulParameterLen = sizeof(CK_MAC_GENERAL_PARAMS);
	}

	rv = CKR_CANCEL;
	if ((size_t)sz < sizeof(in_buffer)) {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session,CKU_CONTEXT_SPECIFIC);

		sig_len = sizeof(sig_buffer);
		rv = p11->C_Sign(session, in_buffer, sz, sig_buffer, &sig_len);
	}

	if (rv != CKR_OK)   {
		rv = p11->C_SignInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_SignInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session,CKU_CONTEXT_SPECIFIC);

		do   {
			rv = p11->C_SignUpdate(session, in_buffer, sz);
			if (rv != CKR_OK)
				p11_fatal("C_SignUpdate", rv);

			sz = read(fd, in_buffer, sizeof(in_buffer));
		} while (sz > 0);

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
		opt_mechanism == CKM_ECDSA_SHA512 || opt_mechanism == CKM_ECDSA_SHA224 ||
		opt_mechanism == CKM_ECDSA_SHA3_224 || opt_mechanism == CKM_ECDSA_SHA3_256 ||
		opt_mechanism == CKM_ECDSA_SHA3_384 || opt_mechanism == CKM_ECDSA_SHA3_512) {
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
	sz = write(fd, sig_buffer, sig_len);

	if (sz < 0)
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
	CK_MAC_GENERAL_PARAMS mac_gen_param;
	CK_EDDSA_PARAMS eddsa_params = {
			.phFlag = CK_FALSE,
	};
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, fd2;
	ssize_t sz, sz2;
	unsigned long   hashlen;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_VERIFY|opt_allow_sw, NULL, 0, &opt_mechanism))
			util_fatal("Mechanism not supported for signature verification");

	fprintf(stderr, "Using signature algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;
	hashlen = parse_pss_params(session, key, &mech, &pss_params);
	if (hashlen && opt_salt_len_given) {
		if (opt_salt_len == -2) {
			/* openssl allow us to set sLen to -2 for autodetecting salt length
			 * here maximal CK_ULONG value is used to pass this special code
			 * to openssl. For non OpenSC PKCS#11 module this is minimal limitation
			 * because there is no need to use extra long salt length.
			 */
			pss_params.sLen = ((CK_ULONG) 1 ) << (sizeof(CK_ULONG) * CHAR_BIT -1);
			fprintf(stderr, "Warning, requesting salt length recovery from signature (supported only in in opensc pkcs11 module).\n");
		}
	}

	/* support pure EdDSA only */
	if (opt_mechanism == CKM_EDDSA) {
		const struct ec_curve_info *curve;
		unsigned char *ec_params;
		CK_ULONG ec_params_size = 0;

		ec_params = getEC_PARAMS(session, key, &ec_params_size);
		if (ec_params == NULL) {
			util_fatal("Key has no EC_PARAMS attribute");
		}

		curve = match_ec_curve_by_params(ec_params, ec_params_size);
		if (curve == NULL) {
			util_fatal("Unknown or unsupported EC curve used in key");
		}

		/* Ed448: need the params defined but default to false */
		if (curve->size == 448) {
			mech.pParameter = &eddsa_params;
			mech.ulParameterLen = (CK_ULONG)sizeof(eddsa_params);
		}
	}

	/* Open a signature file */
	if (opt_signature_file == NULL)
		util_fatal("No file with signature provided. Use --signature-file");
	else if ((fd2 = open(opt_signature_file, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_signature_file);

	sz2 = read(fd2, sig_buffer, sizeof(sig_buffer));
	if (sz2 < 0)
		util_fatal("Cannot read from %s: %m", opt_signature_file);

	close(fd2);

	if (opt_mechanism == CKM_ECDSA || opt_mechanism == CKM_ECDSA_SHA1 ||
		opt_mechanism == CKM_ECDSA_SHA256 || opt_mechanism == CKM_ECDSA_SHA384 ||
		opt_mechanism == CKM_ECDSA_SHA512 || opt_mechanism == CKM_ECDSA_SHA224 ||
		opt_mechanism == CKM_ECDSA_SHA3_224 || opt_mechanism == CKM_ECDSA_SHA3_256 ||
		opt_mechanism == CKM_ECDSA_SHA3_384 || opt_mechanism == CKM_ECDSA_SHA3_512) {
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

			if (sc_asn1_sig_value_sequence_to_rs(NULL, sig_buffer, sz2,
				rs_buffer, rs_len)) {
				util_fatal("Failed to convert ASN.1 signature");
			}

			memcpy(sig_buffer, rs_buffer, rs_len);
			sz2 = rs_len;
		}
	}

	/* Open the data file */
	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	sz = read(fd, in_buffer, sizeof(in_buffer));
	if (sz < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	if (opt_mechanism == CKM_RSA_PKCS_PSS && (size_t)sz != hashlen) {
		util_fatal("For %s mechanism, message size (got %z bytes)"
			" must be equal to specified digest length (%lu)\n",
			p11_mechanism_to_name(opt_mechanism), sz, hashlen);
	} else if (opt_mechanism == CKM_AES_CMAC_GENERAL) {
		if (opt_mac_gen_param == 0 || opt_mac_gen_param > 16) {
			util_fatal("For %s mechanism, the option --mac-general-param "
				   "is mandatory and its value must be comprised between 1 and "
				   "16 (>=8 recommended).\n",
					p11_mechanism_to_name(opt_mechanism));
		}
		mac_gen_param = opt_mac_gen_param;
		mech.pParameter = &mac_gen_param;
		mech.ulParameterLen = sizeof(CK_MAC_GENERAL_PARAMS);
	}

	rv = CKR_CANCEL;
	if ((size_t)sz < sizeof(in_buffer)) {
		rv = p11->C_VerifyInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_VerifyInit", rv);

		sig_len = sz2;
		rv =  p11->C_Verify(session, in_buffer, sz, sig_buffer, sig_len);
	}

	if (rv != CKR_OK && rv != CKR_SIGNATURE_INVALID) {
		rv = p11->C_VerifyInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_VerifyInit", rv);

		do   {
			rv = p11->C_VerifyUpdate(session, in_buffer, sz);
			if (rv != CKR_OK)
				p11_fatal("C_VerifyUpdate", rv);

			sz = read(fd, in_buffer, sizeof(in_buffer));
		} while (sz > 0);

		sig_len = sz2;
		rv = p11->C_VerifyFinal(session, sig_buffer, sig_len);
		if (rv != CKR_OK && rv != CKR_SIGNATURE_INVALID)
			p11_fatal("C_VerifyFinal", rv);
	}

	if (fd != 0)
		close(fd);

	if (rv == CKR_OK)
		printf("Signature is valid\n");
	else if (rv == CKR_SIGNATURE_INVALID)
		util_fatal("Invalid signature");
	else
		util_fatal("Signature verification failed: rv = %s (0x%0x)\n", CKR2Str(rv), (unsigned int)rv);
}

static void
build_rsa_oaep_params(
		CK_RSA_PKCS_OAEP_PARAMS *oaep_params,
		CK_MECHANISM *mech,
		char *param,
		int param_len)
{
	/* An RSA-OAEP mechanism needs parameters */

	/* set "default" MGF and hash algorithms. We can overwrite MGF later */
	oaep_params->hashAlg = opt_hash_alg;
	switch (opt_hash_alg) {
	case CKM_SHA_1:
		oaep_params->mgf = CKG_MGF1_SHA1;
		break;
	case CKM_SHA224:
		oaep_params->mgf = CKG_MGF1_SHA224;
		break;
	case CKM_SHA3_224:
		oaep_params->mgf = CKG_MGF1_SHA3_224;
		break;
	case CKM_SHA3_256:
		oaep_params->mgf = CKG_MGF1_SHA3_256;
		break;
	case CKM_SHA3_384:
		oaep_params->mgf = CKG_MGF1_SHA3_384;
		break;
	case CKM_SHA3_512:
		oaep_params->mgf = CKG_MGF1_SHA3_512;
		break;
	default:
		printf("hash-algorithm %s unknown, defaulting to CKM_SHA256\n", p11_mechanism_to_name(opt_hash_alg));
		oaep_params->hashAlg = CKM_SHA256;
		/* fall through */
	case CKM_SHA256:
		oaep_params->mgf = CKG_MGF1_SHA256;
		break;
	case CKM_SHA384:
		oaep_params->mgf = CKG_MGF1_SHA384;
		break;
	case CKM_SHA512:
		oaep_params->mgf = CKG_MGF1_SHA512;
		break;
	}

	if (opt_mgf != 0) {
		oaep_params->mgf = opt_mgf;
	} else {
		printf("mgf not set, defaulting to %s\n", p11_mgf_to_name(oaep_params->mgf));
	}

	oaep_params->source = CKZ_DATA_SPECIFIED;
	oaep_params->pSourceData = param;
	oaep_params->ulSourceDataLen = param_len;

	mech->pParameter = oaep_params;
	mech->ulParameterLen = sizeof(*oaep_params);

	printf("OAEP parameters: hashAlg=%s, mgf=%s, source_type=%lu, source_ptr=%p, source_len=%lu\n",
			p11_mechanism_to_name(oaep_params->hashAlg),
			p11_mgf_to_name(oaep_params->mgf),
			oaep_params->source,
			oaep_params->pSourceData,
			oaep_params->ulSourceDataLen);
}

static void decrypt_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1024], out_buffer[1024];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_GCM_PARAMS gcm_params = {0};
	CK_ULONG	in_len, out_len;
	int		fd_in, fd_out;
	CK_BYTE_PTR	iv = NULL;
	size_t		iv_size = 0;
	ssize_t sz;
	CK_BYTE_PTR aad = NULL;
	size_t aad_size = 0;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DECRYPT|opt_allow_sw, NULL, 0, &opt_mechanism))
			util_fatal("Decrypt mechanism not supported");

	fprintf(stderr, "Using decrypt algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	if (opt_hash_alg != 0 && opt_mechanism != CKM_RSA_PKCS_OAEP)
		util_fatal("The hash-algorithm is applicable only to "
               "RSA-PKCS-OAEP mechanism");


	/* set "default" MGF and hash algorithms. We can overwrite MGF later */
	switch (opt_mechanism) {
	case CKM_RSA_PKCS_OAEP:
		build_rsa_oaep_params(&oaep_params, &mech, NULL, 0);
		break;
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_AES_ECB:
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;
		break;
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		iv_size = 16;
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		mech.pParameter = iv;
		mech.ulParameterLen = iv_size;
		break;
	case CKM_AES_GCM:
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		gcm_params.pIv = iv;
		gcm_params.ulIvLen = iv_size;
		aad = hex_string_to_byte_array(opt_aad, &aad_size, "AAD");
		gcm_params.pAAD = aad;
		gcm_params.ulAADLen = aad_size;
		gcm_params.ulTagBits = opt_tag_bits;
		mech.pParameter = &gcm_params;
		mech.ulParameterLen = sizeof(gcm_params);
		break;
	default:
		util_fatal("Mechanism %s illegal or not supported\n", p11_mechanism_to_name(opt_mechanism));
	}

	if (opt_input == NULL)
		fd_in = 0;
	else if ((fd_in = open(opt_input, O_RDONLY | O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	if (opt_output == NULL) {
		fd_out = 1;
	} else {
		fd_out = open(opt_output, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
		if (fd_out < 0)
			util_fatal("failed to open %s: %m", opt_output);
	}

	sz = read(fd_in, in_buffer, sizeof(in_buffer));
	in_len = sz;

	if (sz < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	rv = CKR_CANCEL;
	if ((size_t)sz < sizeof(in_buffer)) {
		out_len = sizeof(out_buffer);
		rv = p11->C_DecryptInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_DecryptInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session, CKU_CONTEXT_SPECIFIC);
		rv = p11->C_Decrypt(session, in_buffer, in_len, out_buffer, &out_len);
	}
	if (rv != CKR_OK) {
		rv = p11->C_DecryptInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_DecryptInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session, CKU_CONTEXT_SPECIFIC);
		do {
			out_len = sizeof(out_buffer);
			rv = p11->C_DecryptUpdate(session, in_buffer, in_len, out_buffer, &out_len);
			if (rv != CKR_OK)
				p11_fatal("C_DecryptUpdate", rv);
			sz = write(fd_out, out_buffer, out_len);
			if ((size_t)sz != out_len)
				util_fatal("Cannot write to %s: %m", opt_output);
			sz = read(fd_in, in_buffer, sizeof(in_buffer));
			in_len = sz;
		} while (sz > 0);
		out_len = sizeof(out_buffer);
		rv = p11->C_DecryptFinal(session, out_buffer, &out_len);
		if (rv != CKR_OK)
			p11_fatal("C_DecryptFinal", rv);
	}
	if (out_len) {
		sz = write(fd_out, out_buffer, out_len);
		if ((size_t)sz != out_len)
			util_fatal("Cannot write to %s: %m", opt_output);
	}
	if (fd_in != 0)
		close(fd_in);
	if (fd_out != 1)
		close(fd_out);

	free(iv);
	free(aad);
}

static void encrypt_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_OBJECT_HANDLE key)
{
	unsigned char	in_buffer[1024], out_buffer[1024];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_ULONG	in_len, out_len;
	int		fd_in, fd_out;
	ssize_t sz;
	CK_GCM_PARAMS gcm_params = {0};
	CK_BYTE_PTR	iv = NULL;
	size_t		iv_size = 0;
	CK_BYTE_PTR aad = NULL;
	size_t aad_size = 0;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_ENCRYPT | opt_allow_sw, NULL, 0, &opt_mechanism))
			util_fatal("Encrypt mechanism not supported");

	fprintf(stderr, "Using encrypt algorithm %s\n", p11_mechanism_to_name(opt_mechanism));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	if (opt_hash_alg != 0 && opt_mechanism != CKM_RSA_PKCS_OAEP)
		util_fatal("The hash-algorithm is applicable only to "
			   "RSA-PKCS-OAEP mechanism");

	switch (opt_mechanism) {
	case CKM_RSA_PKCS_OAEP:
		build_rsa_oaep_params(&oaep_params, &mech, NULL, 0);
		break;
	case CKM_AES_ECB:
		mech.pParameter = NULL;
		mech.ulParameterLen = 0;
		break;
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		iv_size = 16;
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		mech.pParameter = iv;
		mech.ulParameterLen = iv_size;
		break;
	case CKM_AES_GCM:
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		gcm_params.pIv = iv;
		gcm_params.ulIvLen = iv_size;
		aad = hex_string_to_byte_array(opt_aad, &aad_size, "AAD");
		gcm_params.pAAD = aad;
		gcm_params.ulAADLen = aad_size;
		gcm_params.ulTagBits = opt_tag_bits;
		mech.pParameter = &gcm_params;
		mech.ulParameterLen = sizeof(gcm_params);
		break;
	default:
		util_fatal("Mechanism %s illegal or not supported\n", p11_mechanism_to_name(opt_mechanism));
	}

	if (opt_input == NULL)
		fd_in = 0;
	else if ((fd_in = open(opt_input, O_RDONLY | O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	if (opt_output == NULL) {
		fd_out = 1;
	} else {
		fd_out = open(opt_output, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR);
		if (fd_out < 0)
			util_fatal("failed to open %s: %m", opt_output);
	}

	sz = read(fd_in, in_buffer, sizeof(in_buffer));
	in_len = sz;

	if (sz < 0)
		util_fatal("Cannot read from %s: %m", opt_input);

	rv = CKR_CANCEL;
	if ((size_t)sz < sizeof(in_buffer)) {
		out_len = sizeof(out_buffer);
		rv = p11->C_EncryptInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_EncryptInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session, CKU_CONTEXT_SPECIFIC);
		out_len = sizeof(out_buffer);
		rv = p11->C_Encrypt(session, in_buffer, in_len, out_buffer, &out_len);
	}
	if (rv != CKR_OK) {
		rv = p11->C_EncryptInit(session, &mech, key);
		if (rv != CKR_OK)
			p11_fatal("C_EncryptInit", rv);
		if ((getCLASS(session, key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, key))
			login(session, CKU_CONTEXT_SPECIFIC);
		do {
			out_len = sizeof(out_buffer);
			rv = p11->C_EncryptUpdate(session, in_buffer, in_len, out_buffer, &out_len);
			if (rv != CKR_OK)
				p11_fatal("C_EncryptUpdate", rv);
			sz = write(fd_out, out_buffer, out_len);
			if ((size_t)sz != out_len)
				util_fatal("Cannot write to %s: %m", opt_output);
			sz = read(fd_in, in_buffer, sizeof(in_buffer));
			in_len = sz;
		} while (sz > 0);
		out_len = sizeof(out_buffer);
		rv = p11->C_EncryptFinal(session, out_buffer, &out_len);
		if (rv != CKR_OK)
			p11_fatal("C_EncryptFinal", rv);
	}
	if (out_len) {
		sz = write(fd_out, out_buffer, out_len);
		if ((size_t)sz != out_len)
			util_fatal("Cannot write to %s: %m", opt_output);
	}
	if (fd_in != 0)
		close(fd_in);
	if (fd_out != 1)
		close(fd_out);

	free(iv);
	free(aad);
}


static void hash_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	unsigned char	buffer[64];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	hash_len;
	int		fd;
	ssize_t sz;

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

	while ((sz = read(fd, buffer, sizeof(buffer))) > 0) {
		rv = p11->C_DigestUpdate(session, buffer, sz);
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

	sz = write(fd, buffer, hash_len);
	if (sz < 0)
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
	unsigned long int gost_key_type = -1;
	int n_privkey_attr = 4;
	unsigned char *ecparams = NULL;
	size_t ecparams_size;
	CK_ULONG key_type = CKK_RSA;
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

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key pair type %s, expecting RSA:<nbytes>", type);
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

			if (opt_key_usage_wrap) {
				FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_WRAP, &_true, sizeof(_true));
				n_pubkey_attr++;
				FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_UNWRAP, &_true, sizeof(_true));
				n_privkey_attr++;
			}
			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_privkey_attr++;
		}
		else if (strncmp(type, "EC:", strlen("EC:")) == 0 || strncmp(type, "ec:", strlen("ec:")) == 0)  {
			CK_MECHANISM_TYPE mtypes[] = {CKM_EC_KEY_PAIR_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			int ii;

			key_type = CKK_EC;

			for (ii=0; ec_curve_infos[ii].name; ii++)   {
				if (!strcmp(ec_curve_infos[ii].name, type + 3))
					break;
				if (!strcmp(ec_curve_infos[ii].oid, type + 3))
					break;
			}
			if (!ec_curve_infos[ii].name) {
				fprintf(stderr, "EC key parameters may be specified by their canonic name or object identifier. Possible values are:\n");
				for (ii = 0; ec_curve_infos[ii].name; ii++) {
					fprintf(stderr, "%s (%s)\n", ec_curve_infos[ii].name, ec_curve_infos[ii].oid);
				}
				util_fatal("Unknown EC key parameter '%s'", type + 3);
			}

			switch (ec_curve_infos[ii].mechanism) {
			case CKM_EC_EDWARDS_KEY_PAIR_GEN:
				/* The Edwards key can not be used for derivation */
				opt_key_usage_derive = 0;
				key_type = CKK_EC_EDWARDS;
				/* This replaces the above default mechanism */
				if (!opt_mechanism_used) {
					mtypes[0] = ec_curve_infos[ii].mechanism;
				}
				break;
			case CKM_EC_MONTGOMERY_KEY_PAIR_GEN:
				key_type = CKK_EC_MONTGOMERY;
				/* This replaces the above default mechanism */
				if (!opt_mechanism_used) {
					mtypes[0] = ec_curve_infos[ii].mechanism;
				}
				break;
			}

			if (!opt_mechanism_used) {
				if (!find_mechanism(slot, CKF_GENERATE_KEY_PAIR, mtypes, mtypes_num,
						&opt_mechanism)) {
					util_fatal("Generate EC key mechanism %lx not supported", mtypes[0]);
				}
			}

			ecparams_size = strlen(ec_curve_infos[ii].ec_params) / 2;
			ecparams = malloc(ecparams_size);
			if (!ecparams)
				util_fatal("Allocation error", 0);
			if (sc_hex_to_bin(ec_curve_infos[ii].ec_params, ecparams, &ecparams_size)) {
				fprintf(stderr, "Cannot convert \"%s\"\n", ec_curve_infos[ii].ec_params);
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
			FILL_ATTR(publicKeyTemplate[n_pubkey_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_pubkey_attr++;
			FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_privkey_attr++;
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
			CK_MECHANISM_TYPE mtypes[] = {-1};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *p_param_set = type + strlen("GOSTR3410");

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
				util_fatal("Unknown key pair type %s, valid key types for mechanism GOSTR3410 are GOSTR3410-2001:{A,B,C},"
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
			util_fatal("Unknown key pair type %s", type);
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

	if (opt_is_extractable != 0) {
		FILL_ATTR(privateKeyTemplate[n_privkey_attr], CKA_EXTRACTABLE,
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

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key type %s, expecting AES:<nbytes>", type);

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

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key type %s, expecting DES:<nbytes>", type);

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

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key type %s, expecting DES3:<nbytes>", type);

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		}
		else if (strncasecmp(type, "GENERIC:", strlen("GENERIC:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_GENERIC_SECRET_KEY_GEN};
			size_t mtypes_num = sizeof(mtypes)/sizeof(mtypes[0]);
			const char *size = type + strlen("GENERIC:");

			key_type = CKK_GENERIC_SECRET;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate Key mechanism not supported\n");

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key type %s, expecting GENERIC:<nbytes>", type);

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		}

		else if (strncasecmp(type, "HKDF:", strlen("HKDF:")) == 0) {
			CK_MECHANISM_TYPE mtypes[] = {CKM_HKDF_KEY_GEN};
			size_t mtypes_num = sizeof(mtypes) / sizeof(mtypes[0]);
			const char *size = type + strlen("HKDF:");

			key_type = CKK_HKDF;

			if (!opt_mechanism_used)
				if (!find_mechanism(slot, CKF_GENERATE, mtypes, mtypes_num, &opt_mechanism))
					util_fatal("Generate Key mechanism not supported\n");

			key_length = (unsigned long)atol(size);
			if (key_length == 0)
				util_fatal("Unknown key type %s, expecting HKDF:<nbytes>", type);

			FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
			n_attr++;
		} else {
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

		if (opt_is_extractable != 0) {
			FILL_ATTR(keyTemplate[n_attr], CKA_EXTRACTABLE, &_true, sizeof(_true));
			n_attr++;
		} else {
			FILL_ATTR(keyTemplate[n_attr], CKA_EXTRACTABLE, &_false, sizeof(_false));
			n_attr++;
		}

		if (opt_is_private != 0) {
			FILL_ATTR(keyTemplate[n_attr], CKA_PRIVATE, &_true, sizeof(_true));
			n_attr++;
		} else {
			FILL_ATTR(keyTemplate[n_attr], CKA_PRIVATE, &_false, sizeof(_false));
			n_attr++;
		}

		if (opt_key_usage_default || opt_key_usage_decrypt) {
			FILL_ATTR(keyTemplate[n_attr], CKA_ENCRYPT, &_true, sizeof(_true));
			n_attr++;
			FILL_ATTR(keyTemplate[n_attr], CKA_DECRYPT, &_true, sizeof(_true));
			n_attr++;
		}

		if (opt_key_usage_wrap) {
			FILL_ATTR(keyTemplate[n_attr], CKA_WRAP, &_true, sizeof(_true));
			n_attr++;
			FILL_ATTR(keyTemplate[n_attr], CKA_UNWRAP, &_true, sizeof(_true));
			n_attr++;
		}

		if (opt_key_usage_sign != 0) {
			FILL_ATTR(keyTemplate[n_attr], CKA_SIGN, &_true, sizeof(_true));
			n_attr++;
			FILL_ATTR(keyTemplate[n_attr], CKA_VERIFY, &_true, sizeof(_true));
			n_attr++;
		}

		if (opt_key_usage_derive != 0) {
			FILL_ATTR(keyTemplate[n_attr], CKA_DERIVE, &_true, sizeof(_true));
			n_attr++;
		} else {
			FILL_ATTR(keyTemplate[n_attr], CKA_DERIVE, &_false, sizeof(_false));
			n_attr++;
		}

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

static int
unwrap_key(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mechanism;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG key_length;
	const char *length;
	CK_ATTRIBUTE keyTemplate[20] = {
			{CKA_CLASS, &class, sizeof(class)},
			{CKA_TOKEN, &_true, sizeof(_true)},
	};
	CK_BYTE object_id[100];
	size_t id_len;
	CK_OBJECT_HANDLE hSecretKey;
	int n_attr = 2;
	CK_RV rv;
	int fd;
	unsigned char in_buffer[2048];
	CK_ULONG wrapped_key_length;
	CK_BYTE_PTR pWrappedKey;
	CK_GCM_PARAMS gcm_params = {0};
	CK_BYTE_PTR iv = NULL;
	size_t iv_size = 0;
	CK_BYTE_PTR aad = NULL;
	size_t aad_size = 0;
	CK_OBJECT_HANDLE hUnwrappingKey;
	ssize_t sz;

	if (!find_object(session, CKO_PRIVATE_KEY, &hUnwrappingKey,
			 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
		if (!find_object(session, CKO_SECRET_KEY, &hUnwrappingKey,
				 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
			util_fatal("Private/secret key not found");

	if (!opt_mechanism_used)
		util_fatal("Unable to unwrap, no mechanism specified\n");

	mechanism.mechanism = opt_mechanism;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY | O_BINARY)) < 0)
		util_fatal("Cannot open %s: %m", opt_input);

	sz = read(fd, in_buffer, sizeof(in_buffer));
	if (sz < 0)
		util_fatal("Cannot read from %s: %m", opt_input);
	wrapped_key_length = sz;
	if (fd != 0)
		close(fd);
	pWrappedKey = in_buffer;

	switch (opt_mechanism) {
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		iv_size = 16;
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		mechanism.pParameter = iv;
		mechanism.ulParameterLen = iv_size;
		break;
	case CKM_AES_GCM:
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		gcm_params.pIv = iv;
		gcm_params.ulIvLen = iv_size;
		aad = hex_string_to_byte_array(opt_aad, &aad_size, "AAD");
		gcm_params.pAAD = aad;
		gcm_params.ulAADLen = aad_size;
		gcm_params.ulTagBits = opt_tag_bits;
		mechanism.pParameter = &gcm_params;
		mechanism.ulParameterLen = sizeof(gcm_params);
		break;
	default:
		// Nothing to do with other mechanisms.
		break;
	}

	if (opt_key_type == NULL) {
		util_fatal("Key type must be specified");
	}

	if (strncasecmp(opt_key_type, "AES:", strlen("AES:")) == 0) {
		length = opt_key_type + strlen("AES:");
	} else if (strncasecmp(opt_key_type, "GENERIC:", strlen("GENERIC:")) == 0) {
		length = opt_key_type + strlen("GENERIC:");
		key_type = CKK_GENERIC_SECRET;
	} else if (strncasecmp(opt_key_type, "HKDF:", strlen("HKDF:")) == 0) {
		length = opt_key_type + strlen("HKDF:");
		key_type = CKK_HKDF;
	} else if (strncasecmp(opt_key_type, "RSA:", strlen("RSA:")) == 0) {
		length = "0"; // No key length for RSA keys
		key_type = CKK_RSA;
		class = CKO_PRIVATE_KEY;
	} else if (strncasecmp(opt_key_type, "EC:", strlen("EC:")) == 0) {
		length = "0"; // No key length for EC keys
		key_type = CKK_EC;
		class = CKO_PRIVATE_KEY;
	} else {
		util_fatal("Unsupported key type %s", opt_key_type);
	}

	FILL_ATTR(keyTemplate[n_attr], CKA_KEY_TYPE, &key_type, sizeof(key_type));
	n_attr++;

	if (opt_is_sensitive != 0) {
		FILL_ATTR(keyTemplate[n_attr], CKA_SENSITIVE, &_true, sizeof(_true));
	} else {
		FILL_ATTR(keyTemplate[n_attr], CKA_SENSITIVE, &_false, sizeof(_false));
	}
	n_attr++;

	if (opt_key_usage_default || opt_key_usage_decrypt) {
		if (class != CKO_PRIVATE_KEY) {
			FILL_ATTR(keyTemplate[n_attr], CKA_ENCRYPT, &_true, sizeof(_true));
			n_attr++;
		}
		FILL_ATTR(keyTemplate[n_attr], CKA_DECRYPT, &_true, sizeof(_true));
		n_attr++;
	}
	if (opt_key_usage_wrap) {
		if (class != CKO_PRIVATE_KEY) {
			FILL_ATTR(keyTemplate[n_attr], CKA_WRAP, &_true, sizeof(_true));
			n_attr++;
		}
		FILL_ATTR(keyTemplate[n_attr], CKA_UNWRAP, &_true, sizeof(_true));
		n_attr++;
	}
	if (opt_key_usage_sign) {
		if (class != CKO_PRIVATE_KEY) {
			FILL_ATTR(keyTemplate[n_attr], CKA_VERIFY, &_true, sizeof(_true));
			n_attr++;
		}
		FILL_ATTR(keyTemplate[n_attr], CKA_SIGN, &_true, sizeof(_true));
		n_attr++;
	}

	if (opt_is_extractable != 0) {
		FILL_ATTR(keyTemplate[n_attr], CKA_EXTRACTABLE, &_true, sizeof(_true));
	} else {
		FILL_ATTR(keyTemplate[n_attr], CKA_EXTRACTABLE, &_false, sizeof(_false));
	}
	n_attr++;

	/* softhsm2 does not allow to attribute CKA_VALUE_LEN, but MyEID card must have this attribute
				specified. We set CKA_VALUE_LEN only if the user sets it in the key specification. */
	key_length = (unsigned long)atol(length);
	if (key_length != 0) {
		FILL_ATTR(keyTemplate[n_attr], CKA_VALUE_LEN, &key_length, sizeof(key_length));
		n_attr++;
	}

	if (opt_application_label != NULL) {
		FILL_ATTR(keyTemplate[n_attr], CKA_LABEL, opt_application_label, strlen(opt_application_label));
		n_attr++;
	}

	if (opt_application_id != NULL) {
		id_len = sizeof(object_id);
		if (!sc_hex_to_bin(opt_application_id, object_id, &id_len)) {
			FILL_ATTR(keyTemplate[n_attr], CKA_ID, object_id, id_len);
			n_attr++;
		}
	}

	if (opt_allowed_mechanisms_len > 0) {
		FILL_ATTR(keyTemplate[n_attr], CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
			  sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
		n_attr++;
	}
	rv = p11->C_UnwrapKey(session, &mechanism, hUnwrappingKey,
			      pWrappedKey, wrapped_key_length, keyTemplate, n_attr, &hSecretKey);
	if (rv != CKR_OK)
		p11_fatal("C_UnwrapKey", rv);

	free(iv);
	free(aad);
	printf("Key unwrapped\n");
	show_object(session, hSecretKey);
	return 1;
}

static int
wrap_key(CK_SESSION_HANDLE session)
{
	CK_BYTE pWrappedKey[4096];
	CK_ULONG pulWrappedKeyLen = sizeof(pWrappedKey);
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE hWrappingKey;	// wrapping key
	CK_OBJECT_HANDLE hkey;	// key to be wrapped
	CK_RV rv;
	CK_BYTE hkey_id[100];
	size_t hkey_id_len;
	int fd;
	ssize_t sz;
	CK_GCM_PARAMS gcm_params = {0};
	CK_BYTE_PTR iv = NULL;
	size_t iv_size = 0;
	CK_BYTE_PTR aad = NULL;
	size_t aad_size = 0;

	if (NULL == opt_application_id)
		util_fatal("Use --application-id to specify secret key (to be wrapped)");
	if (!opt_mechanism_used)
		util_fatal("Unable to wrap, no mechanism specified\n");

	mechanism.mechanism = opt_mechanism;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;

	switch (opt_mechanism) {
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
		iv_size = 16;
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		mechanism.pParameter = iv;
		mechanism.ulParameterLen = iv_size;
		break;
	case CKM_AES_GCM:
		iv = hex_string_to_byte_array(opt_iv, &iv_size, "IV");
		gcm_params.pIv = iv;
		gcm_params.ulIvLen = iv_size;
		aad = hex_string_to_byte_array(opt_aad, &aad_size, "AAD");
		gcm_params.pAAD = aad;
		gcm_params.ulAADLen = aad_size;
		gcm_params.ulTagBits = opt_tag_bits;
		mechanism.pParameter = &gcm_params;
		mechanism.ulParameterLen = sizeof(gcm_params);
		break;
	default:
		// Nothing to do with other mechanisms.
		break;
	}

	hkey_id_len = sizeof(hkey_id);
	if (sc_hex_to_bin(opt_application_id, hkey_id, &hkey_id_len))
		util_fatal("Invalid application-id \"%s\"\n", opt_application_id);

	if (!find_object(session, CKO_SECRET_KEY, &hkey, hkey_id_len ? hkey_id : NULL, hkey_id_len, 0))
		if (!find_object(session, CKO_PRIVATE_KEY, &hkey, hkey_id_len ? hkey_id : NULL, hkey_id_len, 0))
			util_fatal("Key to be wrapped not found");

	if (!find_object(session, CKO_PUBLIC_KEY, &hWrappingKey,
			 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
		if (!find_object(session, CKO_SECRET_KEY, &hWrappingKey,
				 opt_object_id_len ? opt_object_id : NULL, opt_object_id_len, 0))
			util_fatal("Wrapping key not found");

	rv = p11->C_WrapKey(session, &mechanism, hWrappingKey, hkey, pWrappedKey, &pulWrappedKeyLen);
	if (rv != CKR_OK)
		p11_fatal("C_WrapKey", rv);
	printf("Key wrapped\n");

	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT | O_TRUNC | O_WRONLY | O_BINARY, S_IRUSR | S_IWUSR)) < 0)
		util_fatal("failed to open %s: %m", opt_output);

	sz = write(fd, pWrappedKey, pulWrappedKeyLen);

	if (sz < 0)
		util_fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
	free(iv);
	free(aad);
	return 1;
}

#ifdef ENABLE_OPENSSL
static void	parse_certificate(struct x509cert_info *cert,
		unsigned char *data, ssize_t len, unsigned char *contents,
		ssize_t *contents_len)
{
	X509 *x = NULL;
	unsigned char *p;
	int n;

	if (strstr((char *)data, "-----BEGIN CERTIFICATE-----")) {
		BIO *mem = BIO_new_mem_buf(data, (int)len);
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
	n = i2d_X509_NAME(X509_get_issuer_name(x), &p);
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

	X509_free(x);
}

static int
do_read_key(unsigned char *data, size_t data_len, int private, EVP_PKEY **key)
{
	BIO *mem = BIO_new_mem_buf(data, (int)data_len);

	if (!key)
		return -1;

	if (private) {
		if (!strstr((char *)data, "-----BEGIN "))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			*key = d2i_PrivateKey_ex_bio(mem, NULL, osslctx, NULL);
#else
			*key = d2i_PrivateKey_bio(mem, NULL);
#endif
		else
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			*key = PEM_read_bio_PrivateKey_ex(mem, NULL, NULL, NULL, osslctx, NULL);
#else
			*key = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
#endif
	}
	else {
		if (!strstr((char *)data, "-----BEGIN "))
		/*
		 * d2i_PUBKEY_ex_bio is in OpenSSL master of 02/23/2023
		 * committed Dec 26, 2022 expected in 3.2.0
		*/
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
			*key = d2i_PUBKEY_ex_bio(mem, NULL, osslctx, NULL);
#else
			*key = d2i_PUBKEY_bio(mem, NULL);
#endif
		else
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			*key = PEM_read_bio_PUBKEY_ex(mem, NULL, NULL, NULL, osslctx, NULL);
#else
			*key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *r;
	const BIGNUM *r_n, *r_e, *r_d;
	const BIGNUM *r_p, *r_q;
	const BIGNUM *r_dmp1, *r_dmq1, *r_iqmp;
	r = EVP_PKEY_get1_RSA(pkey);
	if (!r) {
		util_fatal("OpenSSL error during RSA %s key parsing: %s", private ? "private" : "public",
			ERR_error_string(ERR_peek_last_error(), NULL));
	}

	RSA_get0_key(r, &r_n, &r_e, NULL);
#else
	BIGNUM *r_n = NULL, *r_e = NULL, *r_d = NULL;
	BIGNUM *r_p = NULL, *r_q = NULL;
	BIGNUM *r_dmp1 = NULL, *r_dmq1 = NULL, *r_iqmp = NULL;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &r_n) != 1 ||
		EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &r_e) != 1) {
		util_fatal("OpenSSL error during RSA %s key parsing: %s", private ? "private" : "public",
			ERR_error_string(ERR_peek_last_error(), NULL));
	 }
#endif
	RSA_GET_BN(rsa, modulus, r_n);
	RSA_GET_BN(rsa, public_exponent, r_e);

	if (private) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		RSA_get0_key(r, NULL, NULL, &r_d);
		RSA_get0_factors(r, &r_p, &r_q);
		RSA_get0_crt_params(r, &r_dmp1, &r_dmq1, &r_iqmp);
#else
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &r_d) != 1 ||
			EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &r_p) != 1 ||
			EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &r_q) != 1 ||
			EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &r_dmp1) != 1 ||
			EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &r_dmq1) != 1 ||
			EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &r_iqmp) != 1) {
			util_fatal("OpenSSL error during RSA private key parsing: %s",
				ERR_error_string(ERR_peek_last_error(), NULL));
		}
#endif
		RSA_GET_BN(rsa, private_exponent, r_d);

		RSA_GET_BN(rsa, prime_1, r_p);
		RSA_GET_BN(rsa, prime_2, r_q);

		RSA_GET_BN(rsa, exponent_1, r_dmp1);
		RSA_GET_BN(rsa, exponent_2, r_dmq1);
		RSA_GET_BN(rsa, coefficient, r_iqmp);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		BN_clear_free(r_d);
		BN_clear_free(r_p);
		BN_clear_free(r_q);
		BN_clear_free(r_dmp1);
		BN_clear_free(r_dmq1);
		BN_clear_free(r_iqmp);
#endif
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA_free(r);
#else
	BN_free(r_n);
	BN_free(r_e);
#endif
	return 0;
}

#if !defined(OPENSSL_NO_EC)
static int
parse_gost_pkey(EVP_PKEY *pkey, int private, struct gostkey_info *gost)
{
	unsigned char *pder;
	BIGNUM *X, *Y;
	int nid, rv;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	const BIGNUM *bignum;
	const EC_GROUP *group;
	const EC_POINT *point;
	EC_KEY *src = EVP_PKEY_get0(pkey);
	if (!src)
		return -1;
	group = EC_KEY_get0_group(src);
	nid = EC_GROUP_get_curve_name(group);
#else
	unsigned char *pubkey = NULL;
	size_t pubkey_len = 0;
	BIGNUM *bignum = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	char name[256]; size_t len = 0;
	if (EVP_PKEY_get_group_name(pkey, name, sizeof(name), &len) != 1)
		return -1;

	nid = OBJ_txt2nid(name);
#endif
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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		bignum = EC_KEY_get0_private_key(src);
#else
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bignum) != 1)
			return -1;
#endif
		gost->private.len = BN_num_bytes(bignum);
		gost->private.value = malloc(gost->private.len);
		if (!gost->private.value) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			BN_free(bignum);
#endif
			return -1;
		}
		BN_bn2bin(bignum, gost->private.value);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		BN_free(bignum);
#endif
	}
	else {
		X = BN_new();
		Y = BN_new();
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		point = EC_KEY_get0_public_key(src);
#else
		group = EC_GROUP_new_by_curve_name_ex(osslctx, NULL, nid);
		EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pubkey_len);
		if (!(pubkey = malloc(pubkey_len)) ||
			EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkey_len, NULL) != 1 ||
			!(point = EC_POINT_new(group)) ||
			EC_POINT_oct2point(group, point, pubkey, pubkey_len, NULL) != 1) {
			EC_GROUP_free(group);
			EC_POINT_free(point);
			return -1;
		}
#endif
		rv = -1;
		if (X && Y && point && group)
			rv = EC_POINT_get_affine_coordinates(group, point, X, Y, NULL);
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EC_GROUP_free(group);
		EC_POINT_free(point);
#endif
		if (rv != 1)
			return -1;
	}
	return 0;
}

static int
parse_ec_pkey(EVP_PKEY *pkey, int private, struct gostkey_info *gost)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	const EC_KEY *src = EVP_PKEY_get0_EC_KEY(pkey);
	const BIGNUM *bignum;
	if (!src)
		return -1;
	gost->param_oid.len = i2d_ECParameters((EC_KEY *)src, &gost->param_oid.value);
#else
	BIGNUM *bignum = NULL;
	gost->param_oid.len = i2d_KeyParams(pkey, &gost->param_oid.value);
#endif
	if (gost->param_oid.len <= 0) {
		return -1;
	}

	if (private) {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		bignum = EC_KEY_get0_private_key(src);
#else
		if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bignum) != 1) {
			return -1;
		}
#endif
		gost->private.len = BN_num_bytes(bignum);
		gost->private.value = malloc(gost->private.len);
		if (!gost->private.value) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			BN_free(bignum);
#endif
			return -1;
		}
		BN_bn2bin(bignum, gost->private.value);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		BN_free(bignum);
#endif
	}
	else {
		unsigned char buf[512], *point;
		size_t point_len, header_len;
		const int MAX_HEADER_LEN = 3;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		const EC_GROUP *ecgroup = EC_KEY_get0_group(src);
		const EC_POINT *ecpoint = EC_KEY_get0_public_key(src);
		if (!ecgroup || !ecpoint)
			return -1;
		point_len = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), NULL);
#else
		EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, sizeof(buf), &point_len);
#endif
		gost->public.value = malloc(MAX_HEADER_LEN+point_len);
		if (!gost->public.value)
			return -1;
		point = gost->public.value;
		ASN1_put_object(&point, 0, (int)point_len, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL);
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
static int
parse_ed_pkey(EVP_PKEY *pkey, int pk_type, int private, struct gostkey_info *gost)
{
	static unsigned char ec_params_ed25519[] = {0x06, 0x03, 0x2b, 0x65, 0x70};
	static unsigned char ec_params_ed448[] = {0x06, 0x03, 0x2b, 0x65, 0x71};
	unsigned char *ec_params = (pk_type == EVP_PKEY_ED25519) ? ec_params_ed25519 : ec_params_ed448;
	size_t ec_params_size = (pk_type == EVP_PKEY_ED25519) ? sizeof(ec_params_ed25519) : sizeof(ec_params_ed448);
	unsigned char *key;
	size_t key_size;

	/* set EC_PARAMS value */
	gost->param_oid.value = OPENSSL_malloc(ec_params_size);
	if (gost->param_oid.value == NULL) {
		return -1;
	}
	gost->param_oid.len = ec_params_size;
	memcpy(gost->param_oid.value, ec_params, ec_params_size);

	if (private) {
		if (EVP_PKEY_get_raw_private_key(pkey, NULL, &key_size) != 1) {
			return -1;
		}
	} else {
		if (EVP_PKEY_get_raw_public_key(pkey, NULL, &key_size) != 1) {
			return -1;
		}
	}

	key = OPENSSL_malloc(key_size);
	if (key == NULL) {
		return -1;
	}

	if (private) {
		if (EVP_PKEY_get_raw_private_key(pkey, key, &key_size) != 1) {
			OPENSSL_free(key);
			return -1;
		}
		gost->private.value = key;
		gost->private.len = key_size;
	} else {
		if (EVP_PKEY_get_raw_public_key(pkey, key, &key_size) != 1) {
			OPENSSL_free(key);
			return -1;
		}
		gost->public.value = key;
		gost->public.len = key_size;
	}

	return 0;
}
#endif
static void gost_info_free(struct gostkey_info gost)
{
	OPENSSL_free(gost.param_oid.value);
	OPENSSL_free(gost.public.value);
	OPENSSL_free(gost.private.value);
}
#endif

/* Currently for certificates (-type cert), private keys (-type privkey),
   public keys (-type pubkey) and data objects (-type data). */
static CK_RV write_object(CK_SESSION_HANDLE session)
{
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	unsigned char *contents = NULL;
	ssize_t contents_len = 0;
	unsigned char *certdata = NULL;
	ssize_t certdata_len = 0;
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
	size_t ret = 0;
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

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		util_fatal("Couldn't open file \"%s\"", opt_file_to_write);
	if (fseek(f, 0L, SEEK_END) != 0)
		util_fatal("Couldn't set file position to the end of the file \"%s\"", opt_file_to_write);
	contents_len = ftell(f);
	if (contents_len < 0)
		util_fatal("Couldn't get file position \"%s\"", opt_file_to_write);
	contents = malloc(contents_len + 1);
	if (contents == NULL)
		util_fatal("malloc() failure\n");
	if (fseek(f, 0L, SEEK_SET) != 0)
		util_fatal("Couldn't set file position to the beginning of the file \"%s\"", opt_file_to_write);
	ret = fread(contents, 1, contents_len, f);
	if (ret != (size_t)contents_len)
		util_fatal("Couldn't read from file \"%s\"", opt_file_to_write);
	fclose(f);
	contents[contents_len] = '\0';

	if (opt_attr_from_file) {
		f = fopen(opt_attr_from_file, "rb");
		if (f == NULL)
			util_fatal("Couldn't open file \"%s\"", opt_attr_from_file);
		if (fseek(f, 0L, SEEK_END) != 0)
			util_fatal("Couldn't set file position to the end of the file \"%s\"", opt_attr_from_file);
		certdata_len = ftell(f);
		if (certdata_len < 0)
			util_fatal("Couldn't get file position \"%s\"", opt_attr_from_file);
		certdata = malloc(certdata_len + 1);
		if (certdata == NULL)
			util_fatal("malloc() failure\n");
		if (fseek(f, 0L, SEEK_SET) != 0)
			util_fatal("Couldn't set file position to the beginning of the file \"%s\"", opt_attr_from_file);
		ret = fread(certdata, 1, certdata_len, f);
		if (ret != (size_t)certdata_len)
			util_fatal("Couldn't read from file \"%s\"", opt_attr_from_file);
		fclose(f);
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
			certdata = malloc(contents_len + 1);
			if (certdata == NULL)
				util_fatal("malloc() failure\n");
			memcpy(certdata, contents, contents_len + 1);
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
#if !defined(OPENSSL_NO_EC)
		else if (pk_type == NID_id_GostR3410_2001)   {
			rv = parse_gost_pkey(evp_key, is_private, &gost);
			type = CKK_GOSTR3410;
		} else if (pk_type == EVP_PKEY_EC) {
			rv = parse_ec_pkey(evp_key, is_private, &gost);
			type = CKK_EC;
#ifdef EVP_PKEY_ED448
		} else if ((pk_type == EVP_PKEY_ED25519) || (pk_type == EVP_PKEY_ED448)) {
#else
		} else if (pk_type == EVP_PKEY_ED25519) {
#endif
			rv = parse_ed_pkey(evp_key, pk_type, is_private, &gost);
			type = CKK_EC_EDWARDS;
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
		if (opt_is_private == 1) {
			FILL_ATTR(cert_templ[4], CKA_PRIVATE, &_true, sizeof(_true));
		} else {
			FILL_ATTR(cert_templ[4], CKA_PRIVATE, &_false, sizeof(_false));
		}
		n_cert_attr = 5;

		if (opt_object_label != NULL) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_LABEL, opt_object_label, strlen(opt_object_label));
			n_cert_attr++;
		}
		if (opt_object_id_len != 0) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_ID, opt_object_id, opt_object_id_len);
			n_cert_attr++;
		}
		if (opt_is_destroyable == 0) {
			FILL_ATTR(cert_templ[n_cert_attr], CKA_DESTROYABLE, &_false, sizeof(_false));
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
		if (opt_is_extractable != 0) {
			FILL_ATTR(privkey_templ[n_privkey_attr], CKA_EXTRACTABLE, &_true, sizeof(_true));
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
#if !defined(OPENSSL_NO_EC)
#ifdef EVP_PKEY_ED448
		else if ((pk_type == EVP_PKEY_EC) || (pk_type == EVP_PKEY_ED25519) || (pk_type == EVP_PKEY_ED448)) {
#else
		else if ((pk_type == EVP_PKEY_EC) || (pk_type == EVP_PKEY_ED25519)) {
#endif
			type = (pk_type == EVP_PKEY_EC) ? CKK_EC : CKK_EC_EDWARDS;

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
#if !defined(OPENSSL_NO_EC)
		else if (pk_type == EVP_PKEY_EC)
			type = CKK_EC;
#ifdef EVP_PKEY_ED448
		else if ((pk_type == EVP_PKEY_ED25519) || (pk_type == EVP_PKEY_ED448))
#else
		else if (pk_type == EVP_PKEY_ED25519)
#endif
			type = CKK_EC_EDWARDS;
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
#if !defined(OPENSSL_NO_EC)
#ifdef EVP_PKEY_ED448
		else if ((pk_type == EVP_PKEY_EC) || (pk_type == EVP_PKEY_ED25519) || (pk_type == EVP_PKEY_ED448)) {
#else
		else if ((pk_type == EVP_PKEY_EC) || (pk_type == EVP_PKEY_ED25519)) {
#endif
			type = (pk_type == EVP_PKEY_EC) ? CKK_EC : CKK_EC_EDWARDS;

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
		type = CKK_GENERIC_SECRET;

		if (opt_key_type != 0) {
			if (strncasecmp(opt_key_type, "AES:", strlen("AES:")) == 0)
				type = CKK_AES;
			else if (strncasecmp(opt_key_type, "DES3:", strlen("DES3:")) == 0)
				type = CKK_DES3;
			else if (strncasecmp(opt_key_type, "GENERIC:", strlen("GENERIC:")) == 0)
				type = CKK_GENERIC_SECRET;
			else if (strncasecmp(opt_key_type, "HKDF:", strlen("HKDF:")) == 0)
				type = CKK_HKDF;
			else
				util_fatal("Unknown key type: 0x%lX", type);
		}

		FILL_ATTR(seckey_templ[0], CKA_CLASS, &clazz, sizeof(clazz));
		FILL_ATTR(seckey_templ[1], CKA_KEY_TYPE, &type, sizeof(type));
		FILL_ATTR(seckey_templ[2], CKA_TOKEN, &_true, sizeof(_true));
		FILL_ATTR(seckey_templ[3], CKA_VALUE, contents, contents_len);
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
		if (opt_is_extractable != 0) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_EXTRACTABLE, &_true, sizeof(_true));
			n_seckey_attr++;
		}
		else {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_EXTRACTABLE, &_false, sizeof(_false));
			n_seckey_attr++;
		}

		if (opt_key_usage_default || opt_key_usage_decrypt) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_ENCRYPT, &_true, sizeof(_true));
			n_seckey_attr++;
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_DECRYPT, &_true, sizeof(_true));
			n_seckey_attr++;
		}

		if (opt_key_usage_wrap) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_WRAP, &_true, sizeof(_true));
			n_seckey_attr++;
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_UNWRAP, &_true, sizeof(_true));
			n_seckey_attr++;
		}

		if (opt_key_usage_sign != 0) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_SIGN, &_true, sizeof(_true));
			n_seckey_attr++;
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_VERIFY, &_true, sizeof(_true));
			n_seckey_attr++;
		}

		if (opt_key_usage_derive != 0) {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_DERIVE, &_true, sizeof(_true));
			n_seckey_attr++;
		} else {
			FILL_ATTR(seckey_templ[n_seckey_attr], CKA_DERIVE, &_false, sizeof(_false));
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
		FILL_ATTR(data_templ[2], CKA_VALUE, contents, contents_len);

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

#ifdef ENABLE_OPENSSL
	gost_info_free(gost);
	EVP_PKEY_free(evp_key);
#endif /* ENABLE_OPENSSL */

	free(contents);
	free(certdata);
	if (oid_buf)
		free(oid_buf);
	return 1;
}

static void set_id_attr(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE obj;
	CK_ATTRIBUTE templ[] = {{CKA_ID, new_object_id, new_object_id_len}};
	CK_RV rv;

	if (!find_object_id_or_label(session, opt_object_class, &obj, opt_object_id, opt_object_id_len, opt_object_label, 0)) {
		fprintf(stderr, "set_id(): couldn't find the object by id %s label\n", (opt_object_label && opt_object_id_len) ? "and" : "or");
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


static int find_object_id_or_label(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len,
		const char *label,
		int obj_index)
{
	CK_ATTRIBUTE attrs[3];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;
	int i;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id && id_len) {
		attrs[nattrs].type = CKA_ID;
		attrs[nattrs].pValue = (void *) id;
		attrs[nattrs].ulValueLen = id_len;
		nattrs++;
	}
	if (label) {
		attrs[nattrs].type = CKA_LABEL;
		attrs[nattrs].pValue = (void *) label;
		attrs[nattrs].ulValueLen = strlen(label);
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

done:
	if (count == 0)
		*ret = CK_INVALID_HANDLE;
	p11->C_FindObjectsFinal(sess);

	return (int)count;
}

static int find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len, int obj_index)
{
	return find_object_id_or_label(sess, cls, ret, id, id_len, NULL, obj_index);
}

static int find_object_flags(CK_SESSION_HANDLE sess, uint16_t mf_flags,
		CK_OBJECT_HANDLE_PTR ret,
		const unsigned char *id, size_t id_len, int obj_index)
{
	int count;
	char err_key_types[1024] = { 0 };

	if (mf_flags & MF_CKO_SECRET_KEY) {
		count = find_object(sess, CKO_SECRET_KEY, ret, id, id_len, obj_index);
		if (count)
			return count;

		strncat(err_key_types, "Secret", sizeof(err_key_types)-1);
	}

	util_fatal("Could not find key of type: %s", err_key_types);
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


static CK_ULONG
find_mechanism(CK_SLOT_ID slot, CK_FLAGS flags,
		CK_MECHANISM_TYPE_PTR list, size_t list_len,
		CK_MECHANISM_TYPE_PTR result)
{
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_ULONG	count = 0;

	count = get_mechanisms(slot, &mechs, flags);
	if (count)   {
		if (list && list_len)   {
			size_t ii = list_len, jj;

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


static void list_objects(CK_SESSION_HANDLE sess)
{
	CK_OBJECT_HANDLE object;
	CK_ULONG count;
	CK_ATTRIBUTE attrs[10];
	CK_ULONG nn_attrs = 0;
	CK_RV rv;

	if (opt_object_class_str != NULL)   {
		FILL_ATTR(attrs[nn_attrs], CKA_CLASS,
				&opt_object_class, sizeof(opt_object_class));
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

	rv = p11->C_FindObjectsInit(sess, attrs, nn_attrs);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjectsInit", rv);

	while (1) {
		rv = p11->C_FindObjects(sess, &object, 1, &count);
		if (rv != CKR_OK)
			p11_fatal("C_FindObjects", rv);
		if (count == 0)
			break;

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
	case CKO_PROFILE:
		show_profile(sess, obj);
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
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_OBJECT_HANDLE newkey = 0;
	CK_ATTRIBUTE newkey_template[20] = {
		{CKA_TOKEN, &_false, sizeof(_false)}, /* session only object */
		{CKA_CLASS, &newkey_class, sizeof(newkey_class)},
		{CKA_KEY_TYPE, &newkey_type, sizeof(newkey_type)},
		{CKA_SENSITIVE, &_false, sizeof(_false)},
		{CKA_EXTRACTABLE, &_true, sizeof(_true)},
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_DECRYPT, &_true, sizeof(_true)},
		{CKA_WRAP, &_true, sizeof(_true)},
		{CKA_UNWRAP, &_true, sizeof(_true)}
	};
	int n_attrs = 9;
	CK_ECDH1_DERIVE_PARAMS ecdh_parms;
	CK_RV rv;
	BIO *bio_in = NULL;
	unsigned char *buf = NULL;
	size_t buf_size = 0;
	CK_ULONG key_len = 0;
	ASN1_OCTET_STRING *octet = NULL;
	unsigned char * der = NULL;
	unsigned char * derp = NULL;
	size_t  der_size = 0;
	EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	EC_KEY *eckey = NULL;
	const EC_GROUP *ecgroup = NULL;
	const EC_POINT *ecpoint = NULL;
#else
	EC_GROUP *ecgroup = NULL;
	char name[256]; size_t len = 0;
	int nid = 0;
#endif

	printf("Using derive algorithm 0x%8.8lx %s\n", opt_mechanism, p11_mechanism_to_name(mech_mech));
	memset(&mech, 0, sizeof(mech));
	mech.mechanism = mech_mech;

	/*  Use OpenSSL to read the other public key, and get the raw version */
	bio_in = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio_in, opt_input) <= 0)
		util_fatal("Cannot open %s: %m", opt_input);

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
	pkey = d2i_PUBKEY_ex_bio(bio_in, NULL, osslctx, NULL);
#else
	pkey = d2i_PUBKEY_bio(bio_in, NULL);
#endif

	if (!pkey)
		util_fatal("Cannot read EC key from %s", opt_input);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	eckey = EVP_PKEY_get0_EC_KEY(pkey);
	ecpoint = EC_KEY_get0_public_key(eckey);
	ecgroup = EC_KEY_get0_group(eckey);

	if (!ecpoint || !ecgroup)
		util_fatal("Failed to parse other EC key from %s", opt_input);
#else
	if (EVP_PKEY_get_group_name(pkey, name, sizeof(name), &len) != 1
	 || (nid = OBJ_txt2nid(name)) == NID_undef
	 || (ecgroup = EC_GROUP_new_by_curve_name(nid)) == NULL)
		util_fatal("Failed to parse other EC key from %s", opt_input);
#endif

	/* both eckeys must be same curve */
	key_len = BYTES4BITS(EC_GROUP_get_degree(ecgroup));
	FILL_ATTR(newkey_template[n_attrs], CKA_VALUE_LEN, &key_len, sizeof(key_len));
	n_attrs++;

	if (opt_allowed_mechanisms_len > 0) {
		FILL_ATTR(newkey_template[n_attrs],
			CKA_ALLOWED_MECHANISMS, opt_allowed_mechanisms,
			sizeof(CK_MECHANISM_TYPE) * opt_allowed_mechanisms_len);
		n_attrs++;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	buf_size = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, NULL,	    0, NULL);
	buf = (unsigned char *)malloc(buf_size);
	if (buf == NULL)
	    util_fatal("malloc() failure\n");
	buf_size = EC_POINT_point2oct(ecgroup, ecpoint, POINT_CONVERSION_UNCOMPRESSED, buf, buf_size, NULL);
#else
	EC_GROUP_free(ecgroup);
	EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, &buf_size);
	if ((buf = (unsigned char *)malloc(buf_size)) == NULL)
	    util_fatal("malloc() failure\n");

	if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, buf_size, NULL) != 1) {
		free(buf);
		util_fatal("Failed to parse other EC key from %s", opt_input);
	}
#endif

	if (opt_derive_pass_der) {
		octet = ASN1_OCTET_STRING_new();
		if (octet == NULL)
		    util_fatal("ASN1_OCTET_STRING_new failure\n");
		ASN1_OCTET_STRING_set(octet, buf, (int)buf_size);
		der_size = i2d_ASN1_OCTET_STRING(octet, NULL);
		derp = der = (unsigned char *) malloc(der_size);
		if (der == NULL)
			util_fatal("malloc() failure\n");
		der_size = i2d_ASN1_OCTET_STRING(octet, &derp);
	}

	BIO_free(bio_in);
	EVP_PKEY_free(pkey);

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

	free(der);
	free(buf);
	if (octet)
	    ASN1_OCTET_STRING_free(octet);

	return newkey;
#else
	util_fatal("Derive EC key not supported");
	return 0;
#endif /* ENABLE_OPENSSL  && !OPENSSL_NO_EC && !OPENSSL_NO_ECDSA */
}

static CK_BBOOL s_true = TRUE;
static CK_BBOOL s_false = FALSE;

#define FILL_ATTR_EX(attr, index, max, typ, val, len) \
	{ \
		if (*(index) >= max) { \
			util_fatal("Template is too small"); \
		} \
		(attr)[*(index)].type = (typ); \
		(attr)[*(index)].pValue = (val); \
		(attr)[*(index)].ulValueLen = (len); \
		(*(index))++; \
	}

static void
fill_attributes_seckey(CK_ATTRIBUTE *template, int *n_attrs, int max_attrs)
{
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_PRIVATE, opt_is_private ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_SENSITIVE, opt_is_sensitive ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_EXTRACTABLE, opt_is_extractable ? &s_true : &s_false, sizeof(CK_BBOOL));

	if (opt_key_usage_default || opt_key_usage_decrypt) {
		FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_ENCRYPT, &s_true, sizeof(CK_BBOOL));
		FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_DECRYPT, &s_true, sizeof(CK_BBOOL));
	}

	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_WRAP, opt_key_usage_wrap ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_UNWRAP, opt_key_usage_wrap ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_SIGN, opt_key_usage_sign ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_VERIFY, opt_key_usage_sign ? &s_true : &s_false, sizeof(CK_BBOOL));
	FILL_ATTR_EX(template, n_attrs, max_attrs, CKA_DERIVE, opt_key_usage_derive ? &s_true : &s_false, sizeof(CK_BBOOL));
}

static CK_OBJECT_HANDLE
derive_hkdf(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_MECHANISM mech;
	CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
	CK_ULONG key_length = hash_length(opt_hash_alg);
	CK_OBJECT_HANDLE newkey = 0;
	CK_ATTRIBUTE template[13] = {
			{CKA_TOKEN,	    &s_false,    sizeof(s_false)   }, /* session only object */
			{CKA_KEY_TYPE,  &key_type,	  sizeof(key_type)  },
			{CKA_VALUE_LEN, &key_length, sizeof(key_length)}
	};
	int n_attrs = 3;
	CK_RV rv;
	CK_HKDF_PARAMS hkdf_params;
	void *salt = NULL;
	ssize_t salt_len = 0;
	void *info = NULL;
	ssize_t info_len = 0;

	if (opt_key_type != NULL) {
		if (strncasecmp(opt_key_type, "GENERIC:", strlen("GENERIC:")) != 0) {
			util_fatal("Generic key type expected\n");
		}
		const char *size = opt_key_type + strlen("GENERIC:");
		key_length = (unsigned long)atol(size);
		if (key_length == 0)
			util_fatal("Unknown key type %s, expecting GENERIC:<nbytes>", opt_key_type);
	}

	fill_attributes_seckey(template, &n_attrs, ARRAY_SIZE(template));

	if (opt_salt_file != NULL) {
		FILE *f;

		f = fopen(opt_salt_file, "rb");
		if (f == NULL)
			util_fatal("Cannot open %s: %m", opt_salt_file);
		if (fseek(f, 0L, SEEK_END) != 0)
			util_fatal("Couldn't set file position to the end of the file \"%s\"", opt_salt_file);
		salt_len = ftell(f);
		if (salt_len < 0)
			util_fatal("Couldn't get file position \"%s\"", opt_salt_file);
		salt = malloc(salt_len);
		if (salt == NULL)
			util_fatal("malloc() failure\n");
		if (fseek(f, 0L, SEEK_SET) != 0)
			util_fatal("Couldn't set file position to the beginning of the file \"%s\"", opt_salt_file);
		size_t ret = fread(salt, 1, salt_len, f);
		if (ret != (size_t)salt_len)
			util_fatal("Couldn't read from file \"%s\"", opt_salt_file);
		fclose(f);
	}
	if (opt_info_file != NULL) {
		FILE *f;

		f = fopen(opt_info_file, "rb");
		if (f == NULL)
			util_fatal("Cannot open %s: %m", opt_info_file);
		if (fseek(f, 0L, SEEK_END) != 0)
			util_fatal("Couldn't set file position to the end of the file \"%s\"", opt_info_file);
		info_len = ftell(f);
		if (info_len < 0)
			util_fatal("Couldn't get file position \"%s\"", opt_info_file);
		info = malloc(info_len);
		if (info == NULL)
			util_fatal("malloc() failure\n");
		if (fseek(f, 0L, SEEK_SET) != 0)
			util_fatal("Couldn't set file position to the beginning of the file \"%s\"", opt_info_file);
		size_t ret = fread(info, 1, info_len, f);
		if (ret != (size_t)info_len)
			util_fatal("Couldn't read from file \"%s\"", opt_info_file);
		fclose(f);
	}

	memset(&hkdf_params, 0, sizeof(hkdf_params));
	hkdf_params.bExtract = TRUE;
	hkdf_params.bExpand = TRUE;
	hkdf_params.prfHashMechanism = opt_hash_alg;
	if (salt == NULL) {
		hkdf_params.ulSaltType = CKF_HKDF_SALT_NULL;
	} else {
		hkdf_params.ulSaltType = CKF_HKDF_SALT_DATA;
	}
	hkdf_params.pSalt = salt;
	hkdf_params.ulSaltLen = (CK_ULONG)salt_len;
	hkdf_params.hSaltKey = CK_INVALID_HANDLE;
	hkdf_params.pInfo = info;
	hkdf_params.ulInfoLen = (CK_ULONG)info_len;

	mech.mechanism = CKM_HKDF_DERIVE;
	mech.pParameter = &hkdf_params;
	mech.ulParameterLen = sizeof(hkdf_params);

	rv = p11->C_DeriveKey(session, &mech, key, template, n_attrs, &newkey);
	if (rv != CKR_OK)
		p11_fatal("C_DeriveKey", rv);

	free(salt);
	free(info);
	return newkey;
}

static void
derive_key(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	CK_BYTE *value = NULL;
	CK_ULONG value_len = 0;
	CK_OBJECT_HANDLE derived_key = 0;
	int fd;
	ssize_t sz;

	if (!opt_mechanism_used)
		if (!find_mechanism(slot, CKF_DERIVE|opt_allow_sw, NULL, 0, &opt_mechanism))
			util_fatal("Derive mechanism not supported");

	switch(opt_mechanism) {
	case CKM_ECDH1_COFACTOR_DERIVE:
	case CKM_ECDH1_DERIVE:
		derived_key= derive_ec_key(session, key, opt_mechanism);
		break;
	case CKM_HKDF_DERIVE:
		derived_key = derive_hkdf(session, key);
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

		sz = write(fd, value, value_len);
		free(value);
		if (sz < 0)
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
	CK_ULONG size, idsize = 0;
	unsigned char	*id, *oid, *value;
	const char      *sepa;
	char		*label;
	char		*unique_id;
	int		pub = 1;
	int		sec = 0;
	CK_TOKEN_INFO info;

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
		if (sec) {
			/* uninitialized secret key (type 0) */
			printf("\n");
		} else {
			if (pub)
				printf("; RSA %lu bits\n",
						(unsigned long) getMODULUS_BITS(sess, obj));
			else
				printf("; RSA \n");
		}
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
	case CKK_EC:
	case CKK_EC_EDWARDS:
	case CKK_EC_MONTGOMERY:
		if (key_type == CKK_EC_EDWARDS) {
			printf("; EC_EDWARDS");
		} else if (key_type == CKK_EC_MONTGOMERY) {
			printf("; EC_MONTGOMERY");
		} else {
			printf("; EC");
		}
		if (pub) {
			unsigned char *bytes = NULL;
			unsigned long ksize;
			unsigned int n;

			bytes = getEC_POINT(sess, obj, &size);
			if (key_type == CKK_EC) {
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
			} else {
				/* This should be 255 for ed25519 and 448 for ed448 curves so roughly */
				ksize = size * 8;
			}

			printf("  EC_POINT %lu bits\n", ksize);
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
					struct sc_object_id oid;

					printf("  EC_PARAMS:  ");
					for (n = 0; n < size; n++)
						printf("%02x", bytes[n]);

					if (size > 2 && bytes[0] == 0x06) { // OID
						sc_init_oid(&oid);
						if (sc_asn1_decode_object_id(bytes + 2, size - 2, &oid) == SC_SUCCESS) {
							printf(" (OID %i", oid.value[0]);
							if (oid.value[0] >= 0)
								for (n = 1; (n < SC_MAX_OBJECT_ID_OCTETS)
										&& (oid.value[n] >= 0); n++)
									printf(".%i", oid.value[n]);
							printf(")");
						}
					} else if (size > 2 && bytes[0] == 0x13) { // Printable string
						printf(" (PrintableString %.*s)", bytes[1], bytes+2);
					}
					printf("\n");

				}
				free(bytes);
			}
		} else {
			printf("\n");
		}
		break;
	case CKK_GENERIC_SECRET:
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_HKDF:
		if (key_type == CKK_AES)
			printf("; AES");
		else if (key_type == CKK_DES)
			printf("; DES");
		else if (key_type == CKK_DES3)
			printf("; DES3");
		else if (key_type == CKK_HKDF)
			printf("; HKDF");
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
	}

	if ((id = getID(sess, obj, &idsize)) != NULL && idsize) {
		unsigned int	n;

		printf("  ID:         ");
		for (n = 0; n < idsize; n++)
			printf("%02x", id[n]);
		printf("\n");
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
	if ((!pub || sec) && getSIGN(sess, obj)) {
		printf("%ssign", sepa);
		sepa = ", ";
	}
	if (!pub && getSIGN_RECOVER(sess, obj)) {
		printf("%ssignRecover", sepa);
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
	if (pub && getVERIFY_RECOVER(sess, obj)) {
		printf("%sverifyRecover", sepa);
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
	if ((unique_id = getUNIQUE_ID(sess, obj, NULL)) != NULL) {
		printf("  Unique ID:  %s\n", unique_id);
		free(unique_id);
	}
	get_token_info(opt_slot, &info);
	printf("  uri:        %s", get_uri(&info));
	if (id != NULL && idsize) {
		printf(";id=%%");
		for (unsigned int n = 0; n < idsize; n++)
			printf("%02x", id[n]);
		free(id);
	}
	if (label != NULL) {
		const char *pelabel = percent_encode((unsigned char *)label, strlen(label));
		printf(";object=%s", pelabel);
		free(label);
	}
	if (sec) {
		printf(";type=secret-key\n");
	} else if (pub) {
		printf(";type=public\n");
	} else {
		printf(";type=private\n");
	}
	suppress_warn = 0;
}

static void show_cert(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_CERTIFICATE_TYPE	cert_type = getCERTIFICATE_TYPE(sess, obj);
	CK_ULONG	size;
	CK_TOKEN_INFO info;
	unsigned char	*id;
	char		*label;
	char		*unique_id;
#if defined(ENABLE_OPENSSL)
	unsigned char	*subject;
	unsigned char	*serial_number;
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
			X509_NAME_free(name);
		}
		free(subject);
	}
	if ((serial_number = getSERIAL_NUMBER(sess, obj, &size)) != NULL) {
		ASN1_INTEGER* serial = NULL;
		const unsigned char *tmp = serial_number;
		serial = d2i_ASN1_INTEGER(NULL, &tmp, size);
		if (serial) {
			BIO *bio = BIO_new(BIO_s_file());
			BIO_set_fp(bio, stdout, BIO_NOCLOSE);
			BIO_printf(bio, "  serial:     ");
			i2a_ASN1_INTEGER(bio, serial);
			BIO_printf(bio, "\n");
			BIO_free(bio);
			ASN1_INTEGER_free(serial);
		}
		free(serial_number);
	}
#endif /* ENABLE_OPENSSL */

	if ((id = getID(sess, obj, &size)) != NULL && size) {
		unsigned int	n;

		printf("  ID:         ");
		for (n = 0; n < size; n++)
			printf("%02x", id[n]);
		printf("\n");
	}
	if ((unique_id = getUNIQUE_ID(sess, obj, NULL)) != NULL) {
		printf("  Unique ID:  %s\n", unique_id);
		free(unique_id);
	}
	get_token_info(opt_slot, &info);
	printf("  uri:        %s", get_uri(&info));
	if (id != NULL && size) {
		printf(";id=%%");
		for (unsigned int n = 0; n < size; n++)
			printf("%02x", id[n]);
		free(id);
	}
	if (label != NULL) {
		const char *pelabel = percent_encode((unsigned char *)label, strlen(label));
		printf(";object=%s", pelabel);
		free(label);
	}
	printf(";type=cert\n");
}

static void show_dobj(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	unsigned char *oid_buf;
	char *label;
	char *application;
	CK_ULONG    size = 0;
	CK_TOKEN_INFO info;
	CK_BBOOL modifiable = 0;
	CK_BBOOL private = 0;

	suppress_warn = 1;
	printf("Data object %u\n", (unsigned int) obj);
	printf("  label:          ");
	if ((label = getLABEL(sess, obj, NULL)) != NULL) {
		printf("'%s'\n", label);
	} else {
		printf("<empty>\n");
	}

	printf("  application:    ");
	if ((application = getAPPLICATION(sess, obj, NULL)) != NULL) {
		printf("'%s'\n", application);
		free(application);
	} else {
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
	modifiable = getMODIFIABLE(sess, obj);
	if (modifiable)
		printf(" modifiable");
	private = getPRIVATE(sess, obj);
	if (private)
		printf(" private");
	if (!modifiable && !private)
		printf("<empty>");
	printf("\n");

	get_token_info(opt_slot, &info);
	printf("  uri:            %s", get_uri(&info));
	if (label != NULL) {
		const char *pelabel = percent_encode((unsigned char *)label, strlen(label));
		printf(";object=%s", pelabel);
		free(label);
	}
	printf(";type=data\n");
	suppress_warn = 0;
}


static void show_profile(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_ULONG    id = 0;

	printf("Profile object %u\n", (unsigned int) obj);
	printf("  profile_id:          ");
	if ((id = getPROFILE_ID(sess, obj)) != 0) {
		printf("%s (%lu)\n", p11_profile_to_name(id), id);
	} else {
		printf("<empty>\n");
	}
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

	rv = find_object_with_attributes(session, &obj, attrs, nn_attrs, opt_object_index);
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
		EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		EVP_PKEY_CTX *ctx = NULL;
		OSSL_PARAM *params = NULL;
		OSSL_PARAM_BLD *bld = NULL;
#endif

		BIO *pout = BIO_new(BIO_s_mem());
		if (!pout)
			util_fatal("out of memory");

		type = getKEY_TYPE(session, obj);
		if (type == CKK_RSA) {
			BIGNUM *rsa_n = NULL;
			BIGNUM *rsa_e = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			RSA *rsa = RSA_new();
			if (!rsa)
				util_fatal("out of memory");
#endif
			if ((value = getMODULUS(session, obj, &len))) {
				if (!(rsa_n = BN_bin2bn(value, (int)len, NULL)))
					util_fatal("cannot parse MODULUS");
				free(value);
			} else
				util_fatal("cannot obtain MODULUS");

			if ((value = getPUBLIC_EXPONENT(session, obj, &len))) {
				if (!(rsa_e = BN_bin2bn(value, (int)len, NULL)))
					util_fatal("cannot parse PUBLIC_EXPONENT");
				free(value);
			} else
				util_fatal("cannot obtain PUBLIC_EXPONENT");
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			if (RSA_set0_key(rsa, rsa_n, rsa_e, NULL) != 1)
				util_fatal("cannot set RSA values");

			if (!i2d_RSA_PUBKEY_bio(pout, rsa))
				util_fatal("cannot convert RSA public key to DER");
			RSA_free(rsa);
#else
			ctx = EVP_PKEY_CTX_new_from_name(osslctx, "RSA", NULL);
			if (!ctx)
				util_fatal("out of memory");
			if (!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_BN(bld, "n", rsa_n) != 1 ||
				OSSL_PARAM_BLD_push_BN(bld, "e", rsa_e) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
				BN_free(rsa_n);
				BN_free(rsa_e);
				OSSL_PARAM_BLD_free(bld);
				EVP_PKEY_CTX_free(ctx);
				OSSL_PARAM_free(params);
			 	util_fatal("cannot set RSA values");
			}
			BN_free(rsa_n);
			BN_free(rsa_e);
			OSSL_PARAM_BLD_free(bld);
			if (EVP_PKEY_fromdata_init(ctx) != 1 ||
				EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
				EVP_PKEY_CTX_free(ctx);
				OSSL_PARAM_free(params);
			 	util_fatal("cannot set RSA values");
			}
			OSSL_PARAM_free(params);
			if (i2d_PUBKEY_bio(pout, pkey) != 1) {
				EVP_PKEY_CTX_free(ctx);
				util_fatal("cannot convert RSA public key to DER");
			}
			EVP_PKEY_free(pkey);
			EVP_PKEY_CTX_free(ctx);
#endif
#if !defined(OPENSSL_NO_EC)
		} else if (type == CKK_EC) {
			CK_BYTE *params;
			const unsigned char *a;
			size_t a_len = 0;
			ASN1_OCTET_STRING *os;
			int success = 0;
			EC_POINT *point = NULL;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
			const EC_GROUP *group = NULL;
			EC_KEY *ec = EC_KEY_new();
			pkey = EVP_PKEY_new();
#else
			EC_GROUP *group = NULL;
			char group_name[80];
			OSSL_PARAM *old = NULL, *new = NULL, *p = NULL;
			OSSL_PARAM_BLD *bld = NULL;
#endif

			if ((params = getEC_PARAMS(session, obj, &len))) {
				const unsigned char *a = params;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
				if (!d2i_ECParameters(&ec, &a, (long)len))
					util_fatal("cannot parse EC_PARAMS");
				EVP_PKEY_assign_EC_KEY(pkey, ec);
#else
				if (!d2i_KeyParams(EVP_PKEY_EC, &pkey, &a, len))
					util_fatal("cannot parse EC_PARAMS");
#endif
				free(params);
			} else
				util_fatal("cannot obtain EC_PARAMS");

			value = getEC_POINT(session, obj, &len);
			/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
			a = value;
			os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)len);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey));
#else
			if (EVP_PKEY_get_group_name(pkey, group_name, sizeof(group_name), NULL) != 1)
				util_fatal("cannot obtain EC_PARAMS");
			group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(group_name));
#endif
			point = EC_POINT_new(group);
			if (os) {
				a = os->data;
				a_len = os->length;
				success = EC_POINT_oct2point(group, point, a, a_len, NULL);
			}
			if (!success) { /* Workaround for broken PKCS#11 modules */
				ASN1_STRING_free(os);
				a = value;
				a_len = len;
				if (!EC_POINT_oct2point(group, point, a, len, NULL)) {
					free(value);
					util_fatal("cannot obtain and parse EC_POINT");
				}
			}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
			if (success)
				ASN1_STRING_free(os);
			free(value);
			EC_KEY_set_public_key(EVP_PKEY_get0_EC_KEY(pkey), point);
#else
			if (!(bld = OSSL_PARAM_BLD_new()) ||
				EVP_PKEY_todata(pkey, EVP_PKEY_PUBLIC_KEY, &old) != 1 ||
				OSSL_PARAM_BLD_push_octet_string(bld, "pub", a, a_len) != 1 ||
				!(new = OSSL_PARAM_BLD_to_param(bld)) ||
				!(p = OSSL_PARAM_merge(old, new))) {
					OSSL_PARAM_BLD_free(bld);
					OSSL_PARAM_free(old);
					OSSL_PARAM_free(new);
					OSSL_PARAM_free(p);
					if (success)
						ASN1_STRING_free(os);
					free(value);
					util_fatal("cannot set OSSL_PARAM");
			}
			OSSL_PARAM_BLD_free(bld);
			if (success)
				ASN1_STRING_free(os);
			free(value);

			if (!(ctx = EVP_PKEY_CTX_new_from_name(osslctx, "EC", NULL)) ||
				EVP_PKEY_fromdata_init(ctx) != 1) {
					OSSL_PARAM_free(p);
					EVP_PKEY_CTX_free(ctx);
					util_fatal("cannot set CTX");
			}
			EVP_PKEY_free(pkey);
			pkey = NULL;
			if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, p) != 1) {
					OSSL_PARAM_free(p);
					EVP_PKEY_CTX_free(ctx);
					util_fatal("cannot create EVP_PKEY");
			}
			OSSL_PARAM_free(old);
			OSSL_PARAM_free(new);

#endif
			if (!i2d_PUBKEY_bio(pout, pkey))
				util_fatal("cannot convert EC public key to DER");
#endif
#ifdef EVP_PKEY_ED25519
		} else if (type == CKK_EC_EDWARDS) {
			EVP_PKEY *key = NULL;
			CK_BYTE *params = NULL;
			const unsigned char *a;
			ASN1_OCTET_STRING *os;

			if ((params = getEC_PARAMS(session, obj, &len))) {
				ASN1_PRINTABLESTRING *curve = NULL;
				ASN1_OBJECT *obj = NULL;

				a = params;
				if (d2i_ASN1_PRINTABLESTRING(&curve, &a, (long)len) != NULL) {
					if (strcmp((char *)curve->data, "edwards25519")) {
						util_fatal("Unknown curve name, expected edwards25519, got %s",
							curve->data);
					}
					ASN1_PRINTABLESTRING_free(curve);
				} else if (d2i_ASN1_OBJECT(&obj, &a, (long)len) != NULL) {
					int nid = OBJ_obj2nid(obj);
					if (nid != NID_ED25519) {
						util_fatal("Unknown curve OID, expected NID_ED25519 (%d), got %d",
							NID_ED25519, nid);
					}
					ASN1_OBJECT_free(obj);
				} else {
					util_fatal("cannot parse curve name from EC_PARAMS");
				}
				free(params);
			} else {
				util_fatal("cannot obtain EC_PARAMS");
			}


			value = getEC_POINT(session, obj, &len);
			/* PKCS#11-compliant modules should return ASN1_OCTET_STRING */
			a = value;
			os = d2i_ASN1_OCTET_STRING(NULL, &a, (long)len);
			if (!os) {
				util_fatal("cannot decode EC_POINT");
			}
			if (os->length != 32) {
				util_fatal("Invalid length of EC_POINT value");
			}
			key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
				(const uint8_t *)os->data,
				os->length);
			ASN1_STRING_free(os);
			if (key == NULL) {
				util_fatal("out of memory");
			}
			/* Note, that we write PEM here as there is no "native"
			 * representation of EdDSA public keys to use */
			if (!PEM_write_bio_PUBKEY(pout, key)) {
				util_fatal("cannot convert EdDSA public key to PEM");
			}

			EVP_PKEY_free(key);
#endif
		}
		else
			util_fatal("Reading public keys of type 0x%lX not (yet) supported", type);
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
		CKM_RIPEMD160,
		CKM_SHA_1,
		CKM_SHA256,
		0xffffff
	};
	unsigned char  *digests[] = {
		(unsigned char *) "\x7a\x08\xb0\x7e\x84\x64\x17\x03\xe5\xf2\xc8\x36\xaa\x59\xa1\x70",
		(unsigned char *) "\xda\x79\xa5\x8f\xb8\x83\x3d\x61\xf6\x32\x16\x17\xe3\xfd\xf0\x56\x26\x5f\xb7\xcd",
		(unsigned char *) "\x29\xb0\xe7\x87\x82\x71\x64\x5f\xff\xb7\xee\xc7\xdb\x4a\x74\x73\xa1\xc0\x0b\xc1",
		(unsigned char *) "\x9c\xfe\x7f\xaf\xf7\x5\x42\x98\xca\x87\x55\x7e\x15\xa1\x2\x62\xde\x8d\x3e\xee\x77\x82\x74\x17\xfb\xdf\xea\x1c\x41\xb9\xec\x23",
	};
	CK_ULONG        digestLens[] = {
		16,
		20,
		20,
		32,
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

#ifdef ENABLE_OPENSSL
	i = (FIPS_mode() ? 2 : 0);
#else
	i = 0;
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		if (!legacy_provider) {
			printf("Failed to load legacy provider\n");
			return errors;
		}
#endif
	for (; mechTypes[i] != 0xffffff; i++) {
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

static CK_RV test_load_cipher_key(CK_SESSION_HANDLE session, uint8_t *key, size_t keysize,
	CK_KEY_TYPE keytype, CK_OBJECT_HANDLE *hkey)
{
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = keytype;
	CK_UTF8CHAR label[] = "testkey";
	CK_BBOOL _true = CK_TRUE;
	CK_ULONG keylen = (CK_ULONG)keysize;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_LABEL, label, sizeof(label)-1 },
		{ CKA_ENCRYPT, &_true, sizeof(_true) },
		{ CKA_DECRYPT, &_true, sizeof(_true) },
		{ CKA_VALUE, key, keysize },
		{ CKA_VALUE_LEN, &keylen, sizeof(keylen) },
	};

	/* create a session key only */
	return p11->C_CreateObject(session, template, ARRAY_SIZE(template), hkey);
}

static void test_delete_cipher_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hkey)
{
	p11->C_DestroyObject(session, hkey);
}

static int test_cipher(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	CK_SESSION_INFO sessionInfo;
	static struct {
		CK_MECHANISM_TYPE type;
		uint8_t     key[32];
		CK_ULONG    keysz;
		CK_KEY_TYPE keytype;
		uint8_t     iv[16];
		CK_ULONG    ivsz;
		uint8_t     plaintext[128];
		CK_ULONG    ptsz;
		uint8_t     ciphertext[128];
		CK_ULONG    ctsz;
	} cipher_algs[] = {
		{
			.type =       CKM_AES_ECB,
			.key =        {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
			.keysz =      16,
			.keytype =    CKK_AES,
			.plaintext =  {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},
			.ptsz =       16,
			.ciphertext = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
			.ctsz =       16,
		},
		{
			.type =       CKM_AES_CBC,
			.key =        {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c},
			.keysz =      16,
			.keytype =    CKK_AES,
			.iv =         {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d},
			.ivsz =       16,
			.plaintext =  {0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
			.ptsz =       16,
			.ciphertext = {0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2},
			.ctsz =       16,
		},
	};
	int errors = 0;
	int supported = 0;

	rv = p11->C_GetSessionInfo(session, &sessionInfo);
	if (rv != CKR_OK) {
		p11_fatal("C_GetSessionInfo", rv);
	}

	/* encryption */
	for (size_t i = 0; i < ARRAY_SIZE(cipher_algs); ++i) {

		CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE;
		CK_MECHANISM mech = {
			.mechanism = cipher_algs[i].type,
			.pParameter = cipher_algs[i].iv,
			.ulParameterLen = cipher_algs[i].ivsz,
		};
		const char *fct;
		uint8_t ptext1[128] = {0};
		uint8_t ptext2[128] = {0};
		uint8_t ctext1[128] = {0};
		uint8_t ctext2[128] = {0};
		CK_ULONG coff = 0;
		CK_ULONG poff = 0;

		rv = test_load_cipher_key(session, cipher_algs[i].key, cipher_algs[i].keysz, cipher_algs[i].keytype, &hkey);
		if (rv != CKR_OK) {
			continue;
		}

		/* Testing Encryption */

		fct = "C_EncryptInit";
		rv = p11->C_EncryptInit(session, &mech, hkey);
		if (rv == CKR_MECHANISM_INVALID)
			continue;	/* mechanism not implemented, don't test */
		if (rv != CKR_OK) {
			goto cipher_clup;
		}
		++supported;
		if (supported == 1) {
			printf("Ciphers:\n");
		}
		printf("  %s: ", p11_mechanism_to_name(mech.mechanism));

#define CIPHER_CHUNK (13) /* used to split input in sizes which are not block aligned */
		for (CK_ULONG ptlen = 0; ptlen < cipher_algs[i].ptsz;) {

			CK_ULONG isize = MIN(cipher_algs[i].ptsz - ptlen, CIPHER_CHUNK);
			CK_ULONG osize = sizeof(ctext1) - coff;

			fct = "C_EncryptUpdate";
			rv = p11->C_EncryptUpdate(session, cipher_algs[i].plaintext + ptlen, isize,
				ctext1 + coff, &osize);
			if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
				printf("  Note: C_EncryptUpdate(), C_EncryptFinal() not supported\n");
				break;
			}
			if (rv != CKR_OK) {
				goto cipher_clup;
			}

			/* move offsets */
			ptlen += isize;
			coff += osize;
		}

		/* Only do final if update is supported */
		if (rv == CKR_OK) {
			CK_ULONG osize = sizeof(ctext1) - coff;
			fct = "C_EncryptFinal";
			rv = p11->C_EncryptFinal(session, ctext1 + coff, &osize);
			if (rv != CKR_OK) {
				goto cipher_clup;
			}

			/* compare values for match */
			if (memcmp(ctext1, cipher_algs[i].ciphertext, cipher_algs[i].ctsz) != 0) {
				printf("ERR: wrong ciphertext value\n");
				rv = CKR_GENERAL_ERROR;
				goto cipher_clup;
			}
		}

		/* Second test is encrypt one shot */
		fct = "C_EncryptInit";
		rv = p11->C_EncryptInit(session, &mech, hkey);
		if (rv != CKR_OK) {
			goto cipher_clup;
		}

		coff = sizeof(ctext2);
		fct = "C_Encrypt";
		rv = p11->C_Encrypt(session, cipher_algs[i].plaintext, cipher_algs[i].ptsz,
			ctext2, &coff);
		if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
			printf("  Note: C_Encrypt() not supported\n");
			goto cipher_clup;
		}

		/* compare values for match */
		if (memcmp(ctext2, cipher_algs[i].ciphertext, cipher_algs[i].ctsz) != 0) {
			printf("ERR: wrong ciphertext value\n");
			rv = CKR_GENERAL_ERROR;
			goto cipher_clup;
		}

		/* Testing Decryption */

		fct = "C_DecryptInit";
		rv = p11->C_DecryptInit(session, &mech, hkey);
		if (rv == CKR_MECHANISM_INVALID)
			continue;	/* mechanism not implemented, don't test */
		if (rv != CKR_OK) {
			goto cipher_clup;
		}

		for (CK_ULONG ctlen = 0; ctlen < cipher_algs[i].ctsz;) {

			CK_ULONG isize = MIN(cipher_algs[i].ctsz - ctlen, CIPHER_CHUNK);
			CK_ULONG osize = sizeof(ptext1) - poff;

			fct = "C_DecryptUpdate";
			rv = p11->C_DecryptUpdate(session, cipher_algs[i].ciphertext + ctlen, isize,
				ptext1 + poff, &osize);
			if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
				printf("  Note: C_DecryptUpdate(), C_DecryptFinal() not supported\n");
				break;
			}
			if (rv != CKR_OK) {
				goto cipher_clup;
			}

			/* move offsets */
			ctlen += isize;
			poff += osize;
		}

		/* Only do final if update is supported */
		if (rv == CKR_OK) {
			CK_ULONG osize = sizeof(ptext1) - poff;
			fct = "C_DecryptFinal";
			rv = p11->C_DecryptFinal(session, ptext1 + poff, &osize);
			if (rv != CKR_OK) {
				goto cipher_clup;
			}

			/* compare values for match */
			if (memcmp(ptext1, cipher_algs[i].plaintext, cipher_algs[i].ptsz) != 0) {
				printf("ERR: wrong plaintext value\n");
				rv = CKR_GENERAL_ERROR;
				goto cipher_clup;
			}
		}

		/* Second test is decrypt one shot */
		fct = "C_DecryptInit";
		rv = p11->C_DecryptInit(session, &mech, hkey);
		if (rv != CKR_OK) {
			goto cipher_clup;
		}

		poff = sizeof(ptext2);
		fct = "C_Decrypt";
		rv = p11->C_Decrypt(session, cipher_algs[i].ciphertext, cipher_algs[i].ctsz,
			ptext2, &poff);
		if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
			printf("  Note: C_Decrypt() not supported\n");
			goto cipher_clup;
		}

		/* compare values for match */
		if (memcmp(ptext2, cipher_algs[i].plaintext, cipher_algs[i].ptsz) != 0) {
			printf("ERR: wrong plaintext value\n");
			rv = CKR_GENERAL_ERROR;
			goto cipher_clup;
		}

cipher_clup:
		test_delete_cipher_key(session, hkey);
		if (rv != CKR_OK) {
			p11_fatal(fct, rv);
		} else {
			printf("OK\n");
		}
	}

	if (supported == 0) {
		fprintf(stderr, "Ciphers: not implemented\n");
	}

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
	EVP_PKEY       *pkey = NULL;
	BIGNUM *rsa_n, *rsa_e;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA				*rsa;
#else
	EVP_PKEY_CTX 	*ctx = NULL;
	OSSL_PARAM_BLD	*bld = NULL;
	OSSL_PARAM		*params = NULL;
#endif

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
		case CKK_RSA:;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			rsa = RSA_new();
			pkey = EVP_PKEY_new();
			if (!rsa || !pkey) {
			fprintf(stderr, "public key not extractable\n");
				if (pkey)
					EVP_PKEY_free(pkey);
				if (rsa)
					RSA_free(rsa);
			}
#endif
			mod = getMODULUS(session, pubkeyObject, &modLen);
			exp = getPUBLIC_EXPONENT(session, pubkeyObject, &expLen);
			if (!mod || !exp) {
				fprintf(stderr, "public key not extractable\n");
				if (mod)
					free(mod);
				if (exp)
					free(exp);
				return NULL;
			}
			rsa_n = BN_bin2bn(mod, (int)modLen, NULL);
			rsa_e =	BN_bin2bn(exp, (int)expLen, NULL);
			free(mod);
			free(exp);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
			if (RSA_set0_key(rsa, rsa_n, rsa_e, NULL) != 1)
			    return NULL;
			EVP_PKEY_assign_RSA(pkey, rsa);
#else
			if (!(bld = OSSL_PARAM_BLD_new()) ||
				OSSL_PARAM_BLD_push_BN(bld, "n", rsa_n) != 1 ||
				OSSL_PARAM_BLD_push_BN(bld, "e", rsa_e) != 1 ||
				!(params = OSSL_PARAM_BLD_to_param(bld))) {
				fprintf(stderr, "public key not extractable\n");
				OSSL_PARAM_BLD_free(bld);
				OSSL_PARAM_free(params);
				BN_free(rsa_n);
				BN_free(rsa_e);
				return NULL;
			}
			OSSL_PARAM_BLD_free(bld);

			if (!(ctx = EVP_PKEY_CTX_new_from_name(osslctx, "RSA", NULL)) ||
				EVP_PKEY_fromdata_init(ctx) != 1 ||
				EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
				fprintf(stderr, "public key not extractable\n");
				EVP_PKEY_CTX_free(ctx);
				OSSL_PARAM_free(params);
				BN_free(rsa_n);
				BN_free(rsa_e);
				return NULL;
			}
			EVP_PKEY_CTX_free(ctx);
			OSSL_PARAM_free(params);
			BN_free(rsa_n);
			BN_free(rsa_e);
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_NO_RIPEMD)
	if (!legacy_provider) {
		printf("Failed to load legacy provider");
		return errors;
	}
#endif

	rv = p11->C_SignInit(session, ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if ((getCLASS(session, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, privKeyObject))
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
			err = EVP_VerifyFinal(md_ctx, sig1, (unsigned)sigLen1, pkey);
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
	CK_OBJECT_HANDLE pubKeyObject, privKeyObject;
	CK_MECHANISM    ck_mech = { CKM_MD5, NULL, 0 };
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	int i, j;
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

	if (!find_mechanism(sessionInfo.slotID, CKF_SIGN|opt_allow_sw, mechTypes, mechTypes_num, &firstMechType)) {
		printf("Signatures: not implemented\n");
		return errors;
	}

	printf("Signatures (currently only for RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %d ", j);
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

		modLenBytes = BYTES4BITS(get_private_key_length(sess, privKeyObject));
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
		/* make sure our data is smaller than the modulus - 11 */
		memset(data, 0, 11); /* in effect is zero padding */
	}

	ck_mech.mechanism = firstMechType;
	rv = p11->C_SignInit(sess, &ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);
	if ((getCLASS(sess, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(sess, privKeyObject))
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
		if ((getCLASS(sess, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(sess, privKeyObject))
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
	if ((getCLASS(sess, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(sess, privKeyObject))
		login(sess,CKU_CONTEXT_SPECIFIC);

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
	if ((getCLASS(sess, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(sess, privKeyObject))
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
		unsigned char   *id;
		CK_ULONG        idLen;
		CK_ULONG	modLenBits;

		printf("  testing key %d", (int) (j-1));
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf(" (%s)", label);
			free(label);
		}
		if ((int) (j-1) != 0)
			printf(" with 1 mechanism");

		if (getKEY_TYPE(sess, privKeyObject) != CKK_RSA) {
			printf(" -- non-RSA, skipping\n");
			continue;
		}
		if (!getSIGN(sess, privKeyObject)) {
			printf(" -- can't be used to sign/verify, skipping\n");
			continue;
		}
		if ((id = getID(sess, privKeyObject, &idLen)) != NULL) {
			int r;

			r = find_object(sess, CKO_PUBLIC_KEY, &pubKeyObject, id, idLen, 0);
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

		modLenBits = get_private_key_length(sess, privKeyObject);
		modLenBytes = BYTES4BITS(modLenBits);
		if (!modLenBytes)   {
			printf(" -- can't be used to sign/verify, skipping: can't obtain modulus\n");
			continue;
		}
		printf("\n");

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
		if ((getCLASS(session, priv_key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, priv_key))
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
	int i, errors = 0;
	CK_ULONG key_len;
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

		key_len = BYTES4BITS(get_private_key_length(sess, priv_key));
		if (!key_len || key_len > INT_MAX) {
			printf(" -- can't get the modulus length, skipping\n");
			continue;
		}
		printf("\n");

		errors += sign_verify(sess, priv_key, (int)key_len, pub_key, i != 0);
	}

	if (i == 0)
		printf("  No private key found for testing\n");

	return errors;
}

#if OPENSC_VERSION_MAJOR == 0 && OPENSC_VERSION_MINOR <= 25
#else
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
	key_len = (int)key_len_ul;
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
#endif


/*
 * Test unwrap functions
 */
static int test_unwrap(CK_SESSION_HANDLE sess)
{
#if OPENSC_VERSION_MAJOR == 0 && OPENSC_VERSION_MINOR <= 25
	/* temporarily disable test, see https://github.com/OpenSC/OpenSC/issues/1796 */
	return 0;
#else
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	int             j;
	char 		*label;

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if (!(sessionInfo.state & CKS_RW_USER_FUNCTIONS)) {
		printf("Key unwrap: not a R/W session, skipping key unwrap tests\n");
		return errors;
	}

	if (!find_mechanism(sessionInfo.slotID, CKF_UNWRAP|opt_allow_sw, NULL, 0, &firstMechType)) {
		printf("Unwrap: not implemented\n");
		return errors;
	}

	printf("Key unwrap (currently only for RSA)\n");
	for (j = 0; find_object(sess, CKO_PRIVATE_KEY, &privKeyObject, NULL, 0, j); j++) {
		printf("  testing key %d ", j);
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
#endif
}

#ifdef ENABLE_OPENSSL
static int encrypt_decrypt(CK_SESSION_HANDLE session,
		CK_MECHANISM_TYPE mech_type,
		CK_OBJECT_HANDLE privKeyObject,
		char *param, int param_len)
{
	EVP_PKEY       *pkey;
	unsigned char	orig_data[512];
	unsigned char	encrypted[512], data[512];
	CK_MECHANISM	mech;
	CK_ULONG	encrypted_len, data_len;
	int             failed;
	CK_RV           rv;
	int pad;
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;

	printf("    %s: ", p11_mechanism_to_name(mech_type));

	pseudo_randomize(orig_data, sizeof(orig_data));
	orig_data[0] = 0; /* Make sure it is less then modulus */

	pkey = get_public_key(session, privKeyObject);
	if (pkey == NULL)
		return 0;

	if (EVP_PKEY_size(pkey) > (int)sizeof(encrypted)) {
		printf("Ciphertext buffer too small\n");
		EVP_PKEY_free(pkey);
		return 0;
	}
	size_t in_len;
	size_t max_in_len;
	CK_ULONG mod_len = BYTES4BITS(get_private_key_length(session, privKeyObject));
	switch (mech_type) {
	case CKM_RSA_PKCS:
		pad = RSA_PKCS1_PADDING;
		/* input length <= mod_len-11 */
		max_in_len = mod_len-11;
		in_len = 10;
		break;
	case CKM_RSA_PKCS_OAEP:
		build_rsa_oaep_params(&oaep_params, &mech, param, param_len);

		pad = RSA_PKCS1_OAEP_PADDING;
		size_t len = 2 + 2 * hash_length(oaep_params.hashAlg);
		if (len >= mod_len) {
			printf("Incompatible mechanism and key size\n");
			return 0;
		}
		/* input length <= mod_len-2-2*hlen */
		max_in_len = mod_len-len;
		in_len = 10;
		break;
	case CKM_RSA_X_509:
		pad = RSA_NO_PADDING;
		/* input length equals modulus length */
		max_in_len = mod_len;
		in_len = mod_len;
		break;
	default:
		printf("Unsupported mechanism %s, returning\n", p11_mechanism_to_name(mech_type));
		return 0;
	}

	if (in_len > sizeof(orig_data)) {
		printf("Input data is too large\n");
		return 0;
	}
	if (in_len > max_in_len) {
		printf("Input data is too large for this key\n");
		return 0;
	}

	EVP_PKEY_CTX *ctx;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	ctx = EVP_PKEY_CTX_new_from_pkey(osslctx, pkey, NULL);
#else
	ctx = EVP_PKEY_CTX_new(pkey, NULL);
#endif
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
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		const EVP_MD *md;
		switch (oaep_params.hashAlg) {
		case CKM_SHA_1:
			md = EVP_sha1();
			break;
		case CKM_SHA224:
			md = EVP_sha224();
			break;
		default: /* it should not happen, oaep_params.hashAlg is checked earlier */
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
		case CKM_SHA3_224:
			md = EVP_sha3_224();
			break;
		case CKM_SHA3_256:
			md = EVP_sha3_256();
			break;
		case CKM_SHA3_384:
			md = EVP_sha3_384();
			break;
		case CKM_SHA3_512:
			md = EVP_sha3_512();
			break;
		}
		if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(pkey);
			printf("set md failed, returning\n");
			return 0;
		}
		switch (oaep_params.mgf) {
		case CKG_MGF1_SHA1:
			md = EVP_sha1();
			break;
		case CKG_MGF1_SHA224:
			md = EVP_sha224();
			break;
		case CKG_MGF1_SHA256:
			md = EVP_sha256();
			break;
		case CKG_MGF1_SHA384:
			md = EVP_sha384();
			break;
		case CKG_MGF1_SHA512:
			md = EVP_sha512();
			break;
		case CKG_MGF1_SHA3_224:
			md = EVP_sha3_224();
			break;
		case CKG_MGF1_SHA3_256:
			md = EVP_sha3_256();
			break;
		case CKG_MGF1_SHA3_384:
			md = EVP_sha3_384();
			break;
		case CKG_MGF1_SHA3_512:
			md = EVP_sha3_512();
			break;
		}
		if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			EVP_PKEY_free(pkey);
			printf("set mgf1 md failed, returning\n");
			return 0;
		}
		if (param_len != 0 && param != NULL) {
			/* label is in ownership of openssl, do not free this ptr! */
			char *label = malloc(param_len);
			memcpy(label, param, param_len);

			if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, param_len) <= 0) {
				EVP_PKEY_CTX_free(ctx);
				EVP_PKEY_free(pkey);
				printf("set OAEP label failed, returning\n");
				return 0;
			}
		}
#else
		if (oaep_params.hashAlg != CKM_SHA_1) {
			printf("This version of OpenSSL only supports SHA1 for OAEP, returning\n");
			return 0;
		}
#endif
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

	switch (mech_type) {
	case CKM_RSA_PKCS_OAEP:
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
	if ((getCLASS(session, privKeyObject) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, privKeyObject))
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
	unsigned char   *id;
	CK_OBJECT_HANDLE pubKeyObject, privKeyObject;
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        num_mechs = 0, id_len;
	int j;
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
		printf("  testing key %d", j);
		if ((label = getLABEL(sess, privKeyObject, NULL)) != NULL) {
			printf(" (%s)", label);
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

		if ((id = getID(sess, privKeyObject, &id_len)) != NULL) {
			int r;

			r = find_object(sess, CKO_PUBLIC_KEY, &pubKeyObject, id, id_len, 0);
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

		printf("\n");

#ifndef ENABLE_OPENSSL
		printf("No OpenSSL support, unable to validate decryption\n");
#else
		for (n = 0; n < num_mechs; n++) {
			switch (mechs[n]) {
			case CKM_RSA_PKCS_OAEP:
				/* one more OAEP test with param .. */
				errors += encrypt_decrypt(sess, mechs[n], privKeyObject, "ABC", 3);
				/* fall through */
			case CKM_RSA_PKCS:
			case CKM_RSA_X_509:
				errors += encrypt_decrypt(sess, mechs[n], privKeyObject, NULL, 0);
				break;
			default:
				printf(" -- mechanism can't be used to decrypt, skipping\n");
			}
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
		errors++;
	}

	rv = p11->C_GenerateRandom(session, buf1, 10);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom", rv);
		errors++;
	}

	rv = p11->C_GenerateRandom(session, buf1, 100);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf1,100)", rv);
		errors++;
	}

	rv = p11->C_GenerateRandom(session, buf1, 0);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf1,0)", rv);
		errors++;
	}

	rv = p11->C_GenerateRandom(session, buf2, 100);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(buf2,100)", rv);
		errors++;
	}

	if (errors == 0 && memcmp(buf1, buf2, 100) == 0) {
		printf("  ERR: C_GenerateRandom returned twice the same value!!!\n");
		errors++;
	}

	if (!errors)
		printf("  seems to be OK\n");

	return errors;
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

	errors += test_cipher(session);

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
	CK_FUNCTION_LIST_PTR	p11_v2 = NULL;

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

	tmp = getID(session, priv_key, &i);
	if (i == 0) {
		fprintf(stderr, "ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return session;
	}
	opt_object_id_len = (size_t) i;
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
	if ((getCLASS(session, priv_key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, priv_key))
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
	if ((getCLASS(session, priv_key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, priv_key))
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

	module = C_LoadModule(opt_module, &p11_v2);
	if (module == NULL)
		util_fatal("Failed to load pkcs11 module");
	p11 = (CK_FUNCTION_LIST_3_0_PTR ) p11_v2;

	rv = p11->C_Initialize(c_initialize_args_ptr);
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

	tmp = getID(session, priv_key, &i);
	if (i == 0) {
		printf("ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return;
	}
	i = (size_t) opt_object_id_len;
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
	if ((getCLASS(session, priv_key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, priv_key))
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
	if ((getCLASS(session, priv_key) == CKO_PRIVATE_KEY) && getALWAYS_AUTHENTICATE(session, priv_key))
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
		rv = p11->C_Initialize(c_initialize_args_ptr);
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

static CK_BBOOL
p11_is_percent_format_reserved_char(CK_UTF8CHAR c)
{
	switch (c) {
	case ' ':
	case '!':
	case '"':
	case '#':
	case '$':
	case '%':
	case '&':
	case '\'':
	case '(':
	case ')':
	case '*':
	case '+':
	case ',':
	case '/':
	case ':':
	case ';':
	case '=':
	case '?':
	case '@':
	case '[':
	case ']':
		return CK_TRUE;
	}
	return CK_FALSE;
}

static const char *
percent_encode(CK_UTF8CHAR *string, size_t len)
{
	static char buffer[1024];
	memset(buffer, 0, 1024);
	size_t output_index, input_index;

	while (len && string[len - 1] == ' ')
		len--;

	for (output_index = input_index = 0; output_index < sizeof(buffer) - 3;
			output_index++) {
		if (input_index >= len) {
			break;
		}
		if (p11_is_percent_format_reserved_char(string[input_index])) {
			snprintf(&buffer[output_index], 4, "%%%x", string[input_index]);
			output_index += 2;
		} else {
			buffer[output_index] = string[input_index];
		}
		input_index++;
	}
	buffer[output_index] = '\0';
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

#define MAX_HEX_STR_LEN (1U << 16) // Arbitrary, GCM IV and AAD can theoretically be much bigger
static CK_BYTE_PTR
hex_string_to_byte_array(const char *hex_input, size_t *input_size, const char *buffer_name)
{
	CK_BYTE_PTR array;
	size_t size = 0;

	/* no hex string supplied on command line */
	if (!hex_input) {
		*input_size = 0;
		return NULL;
	}

	/* If no length is provided, determine the length of the hex string */
	if (*input_size == 0) {
		size = strnlen(hex_input, MAX_HEX_STR_LEN);
		if (size % 2 != 0) {
			fprintf(stderr, "Odd length, provided %s is an invalid hex string.\n", buffer_name);
			return NULL;
		}
		*input_size = size / 2;
	}

	size = *input_size;

	array = calloc(*input_size, sizeof(CK_BYTE));
	if (!array) {
		fprintf(stderr, "Warning, out of memory, %s will not be used.\n", buffer_name);
		*input_size = 0;
		return NULL;
	}

	if (sc_hex_to_bin(hex_input, array, &size)) {
		fprintf(stderr, "Warning, unable to parse %s, %s will not be used.\n",
				buffer_name, buffer_name);
		*input_size = 0;
		free(array);
		return NULL;
	}

	if (*input_size != size)
		fprintf(stderr, "Warning: %s string is too short, %s will be padded from the right by zeros.\n",
				buffer_name, buffer_name);

	return array;
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

// clang-format off
static struct mech_info	p11_mechanisms[] = {
	{ CKM_RSA_PKCS_KEY_PAIR_GEN,	"RSA-PKCS-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_RSA_PKCS,		"RSA-PKCS",	NULL, MF_UNKNOWN },
	{ CKM_RSA_9796,		"RSA-9796",	NULL, MF_UNKNOWN },
	{ CKM_RSA_X_509,		"RSA-X-509",	NULL, MF_UNKNOWN },
	{ CKM_MD2_RSA_PKCS,	"MD2-RSA-PKCS",	NULL, MF_UNKNOWN },
	{ CKM_MD5_RSA_PKCS,	"MD5-RSA-PKCS",	"rsa-md5", MF_UNKNOWN },
	{ CKM_SHA1_RSA_PKCS,	"SHA1-RSA-PKCS",	"rsa-sha1", MF_UNKNOWN },
	{ CKM_SHA224_RSA_PKCS,	"SHA224-RSA-PKCS",	"rsa-sha224", MF_UNKNOWN },
	{ CKM_SHA256_RSA_PKCS,	"SHA256-RSA-PKCS",	"rsa-sha256", MF_UNKNOWN },
	{ CKM_SHA384_RSA_PKCS,	"SHA384-RSA-PKCS",	"rsa-sha384", MF_UNKNOWN },
	{ CKM_SHA512_RSA_PKCS,	"SHA512-RSA-PKCS",	"rsa-sha512", MF_UNKNOWN },
	{ CKM_SHA3_224_RSA_PKCS,	"SHA3-224-RSA-PKCS",	"rsa-sha3-224", MF_UNKNOWN },
	{ CKM_SHA3_256_RSA_PKCS,	"SHA3-256-RSA-PKCS",	"rsa-sha3-256", MF_UNKNOWN },
	{ CKM_SHA3_384_RSA_PKCS,	"SHA3-384-RSA-PKCS",	"rsa-sha3-384", MF_UNKNOWN },
	{ CKM_SHA3_512_RSA_PKCS,	"SHA3-512-RSA-PKCS",	"rsa-sha3-512", MF_UNKNOWN },
	{ CKM_RIPEMD128_RSA_PKCS,	"RIPEMD128-RSA-PKCS",	NULL, MF_UNKNOWN },
	{ CKM_RIPEMD160_RSA_PKCS,	"RIPEMD160-RSA-PKCS",	"rsa-ripemd160", MF_UNKNOWN },
	{ CKM_RSA_PKCS_OAEP,	"RSA-PKCS-OAEP",	NULL, MF_UNKNOWN },
	{ CKM_RSA_X9_31_KEY_PAIR_GEN,"RSA-X9-31-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_RSA_X9_31,		"RSA-X9-31",	NULL, MF_UNKNOWN },
	{ CKM_SHA1_RSA_X9_31,	"SHA1-RSA-X9-31",	NULL, MF_UNKNOWN },
	{ CKM_RSA_PKCS_PSS,	"RSA-PKCS-PSS",	NULL, MF_UNKNOWN },
	{ CKM_SHA1_RSA_PKCS_PSS,	"SHA1-RSA-PKCS-PSS",	"rsa-pss-sha1", MF_UNKNOWN },
	{ CKM_SHA224_RSA_PKCS_PSS,"SHA224-RSA-PKCS-PSS",	"rsa-pss-sha224", MF_UNKNOWN },
	{ CKM_SHA256_RSA_PKCS_PSS,"SHA256-RSA-PKCS-PSS",	"rsa-pss-sha256", MF_UNKNOWN },
	{ CKM_SHA384_RSA_PKCS_PSS,"SHA384-RSA-PKCS-PSS",	"rsa-pss-sha384", MF_UNKNOWN },
	{ CKM_SHA512_RSA_PKCS_PSS,"SHA512-RSA-PKCS-PSS",	"rsa-pss-sha512", MF_UNKNOWN },
	{ CKM_SHA3_224_RSA_PKCS_PSS,"SHA3-224-RSA-PKCS-PSS",	"rsa-pss-sha3-224", MF_UNKNOWN },
	{ CKM_SHA3_256_RSA_PKCS_PSS,"SHA3-256-RSA-PKCS-PSS",	"rsa-pss-sha3-256", MF_UNKNOWN },
	{ CKM_SHA3_384_RSA_PKCS_PSS,"SHA3-384-RSA-PKCS-PSS",	"rsa-pss-sha3-384", MF_UNKNOWN },
	{ CKM_SHA3_512_RSA_PKCS_PSS,"SHA3-512-RSA-PKCS-PSS",	"rsa-pss-sha3-512", MF_UNKNOWN },
	{ CKM_DSA_KEY_PAIR_GEN,	"DSA-KEY-PAIR-GEN",	NULL, MF_UNKNOWN },
	{ CKM_DSA,		"DSA",	NULL, MF_UNKNOWN },
	{ CKM_DSA_SHA1,		"DSA-SHA1", NULL, MF_UNKNOWN },
	{ CKM_DSA_SHA224,		"DSA-SHA224", NULL, MF_UNKNOWN },
	{ CKM_DSA_SHA256,		"DSA-SHA256", NULL, MF_UNKNOWN },
	{ CKM_DSA_SHA384,		"DSA-SHA384", NULL, MF_UNKNOWN },
	{ CKM_DSA_SHA512,		"DSA-SHA512", NULL, MF_UNKNOWN },
	{ CKM_DH_PKCS_KEY_PAIR_GEN,"DH-PKCS-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_DH_PKCS_DERIVE,	"DH-PKCS-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_X9_42_DH_KEY_PAIR_GEN,"X9-42-DH-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_X9_42_DH_DERIVE,	"X9-42-DH-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_X9_42_DH_HYBRID_DERIVE,"X9-42-DH-HYBRID-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_X9_42_MQV_DERIVE,	"X9-42-MQV-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_RC2_KEY_GEN,	"RC2-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_RC2_ECB,		"RC2-ECB", NULL, MF_UNKNOWN },
	{ CKM_RC2_CBC,		"RC2-CBC", NULL, MF_UNKNOWN },
	{ CKM_RC2_MAC,		"RC2-MAC", NULL, MF_UNKNOWN },
	{ CKM_RC2_MAC_GENERAL,	"RC2-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_RC2_CBC_PAD,	"RC2-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_RC4_KEY_GEN,	"RC4-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_RC4,		"RC4", NULL, MF_UNKNOWN },
	{ CKM_DES_KEY_GEN,	"DES-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_DES_ECB,		"DES-ECB", NULL, MF_UNKNOWN },
	{ CKM_DES_CBC,		"DES-CBC", NULL, MF_UNKNOWN },
	{ CKM_DES_MAC,		"DES-MAC", NULL, MF_UNKNOWN },
	{ CKM_DES_MAC_GENERAL,	"DES-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_DES_CBC_PAD,	"DES-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_DES2_KEY_GEN,	"DES2-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_DES3_KEY_GEN,	"DES3-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_DES3_ECB,		"DES3-ECB", NULL, MF_UNKNOWN },
	{ CKM_DES3_CBC,		"DES3-CBC", NULL, MF_UNKNOWN },
	{ CKM_DES3_MAC,		"DES3-MAC", NULL, MF_UNKNOWN },
	{ CKM_DES3_MAC_GENERAL,	"DES3-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_DES3_CBC_PAD,	"DES3-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_DES3_CMAC,		"DES3-CMAC", NULL, MF_UNKNOWN },
	{ CKM_CDMF_KEY_GEN,	"CDMF-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_CDMF_ECB,		"CDMF-ECB", NULL, MF_UNKNOWN },
	{ CKM_CDMF_CBC,		"CDMF-CBC", NULL, MF_UNKNOWN },
	{ CKM_CDMF_MAC,		"CDMF-MAC", NULL, MF_UNKNOWN },
	{ CKM_CDMF_MAC_GENERAL,	"CDMF-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_CDMF_CBC_PAD,	"CDMF-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_MD2,		"MD2", NULL, MF_UNKNOWN },
	{ CKM_MD2_HMAC,		"MD2-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_MD2_HMAC_GENERAL,	"MD2-HMAC-GENERAL", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_MD5,		"MD5", NULL, MF_UNKNOWN },
	{ CKM_MD5_HMAC,		"MD5-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_MD5_HMAC_GENERAL,	"MD5-HMAC-GENERAL", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA_1,		"SHA-1", NULL, MF_UNKNOWN },
	{ CKM_SHA_1_HMAC,		"SHA-1-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA_1_HMAC_GENERAL,	"SHA-1-HMAC-GENERAL", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA224,		"SHA224", NULL, MF_UNKNOWN },
	{ CKM_SHA224_HMAC,	"SHA224-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA256,		"SHA256", NULL, MF_UNKNOWN },
	{ CKM_SHA256_HMAC,	"SHA256-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA384,		"SHA384", NULL, MF_UNKNOWN },
	{ CKM_SHA384_HMAC,	"SHA384-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA512,		"SHA512", NULL, MF_UNKNOWN },
	{ CKM_SHA512_HMAC,	"SHA512-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA3_224,		"SHA3-224", NULL, MF_UNKNOWN },
	{ CKM_SHA3_224_HMAC,	"SHA3-224-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA3_256,		"SHA3-256", NULL, MF_UNKNOWN },
	{ CKM_SHA3_256_HMAC,	"SHA3-256-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA3_384,		"SHA3-384", NULL, MF_UNKNOWN },
	{ CKM_SHA3_384_HMAC,	"SHA3-384-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_SHA3_512,		"SHA3-512", NULL, MF_UNKNOWN },
	{ CKM_SHA3_512_HMAC,	"SHA3-512-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_RIPEMD128,		"RIPEMD128", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_RIPEMD128_HMAC,	"RIPEMD128-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_RIPEMD128_HMAC_GENERAL,"RIPEMD128-HMAC-GENERAL", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_RIPEMD160,		"RIPEMD160", NULL, MF_UNKNOWN },
	{ CKM_RIPEMD160_HMAC,	"RIPEMD160-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_RIPEMD160_HMAC_GENERAL,"RIPEMD160-HMAC-GENERAL", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_CAST_KEY_GEN,	"CAST-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_CAST_ECB,		"CAST-ECB", NULL, MF_UNKNOWN },
	{ CKM_CAST_CBC,		"CAST-CBC", NULL, MF_UNKNOWN },
	{ CKM_CAST_MAC,		"CAST-MAC", NULL, MF_UNKNOWN },
	{ CKM_CAST_MAC_GENERAL,	"CAST-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_CAST_CBC_PAD,	"CAST-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_CAST3_KEY_GEN,	"CAST3-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_CAST3_ECB,		"CAST3-ECB", NULL, MF_UNKNOWN },
	{ CKM_CAST3_CBC,		"CAST3-CBC", NULL, MF_UNKNOWN },
	{ CKM_CAST3_MAC,		"CAST3-MAC", NULL, MF_UNKNOWN },
	{ CKM_CAST3_MAC_GENERAL,	"CAST3-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_CAST3_CBC_PAD,	"CAST3-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_CAST5_KEY_GEN,	"CAST5-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_CAST5_ECB,		"CAST5-ECB", NULL, MF_UNKNOWN },
	{ CKM_CAST5_CBC,		"CAST5-CBC", NULL, MF_UNKNOWN },
	{ CKM_CAST5_MAC,		"CAST5-MAC", NULL, MF_UNKNOWN },
	{ CKM_CAST5_MAC_GENERAL,	"CAST5-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_CAST5_CBC_PAD,	"CAST5-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_RC5_KEY_GEN,	"RC5-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_RC5_ECB,		"RC5-ECB", NULL, MF_UNKNOWN },
	{ CKM_RC5_CBC,		"RC5-CBC", NULL, MF_UNKNOWN },
	{ CKM_RC5_MAC,		"RC5-MAC", NULL, MF_UNKNOWN },
	{ CKM_RC5_MAC_GENERAL,	"RC5-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_RC5_CBC_PAD,	"RC5-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_IDEA_KEY_GEN,	"IDEA-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_IDEA_ECB,		"IDEA-ECB", NULL, MF_UNKNOWN },
	{ CKM_IDEA_CBC,		"IDEA-CBC", NULL, MF_UNKNOWN },
	{ CKM_IDEA_MAC,		"IDEA-MAC", NULL, MF_UNKNOWN },
	{ CKM_IDEA_MAC_GENERAL,	"IDEA-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_IDEA_CBC_PAD,	"IDEA-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_GENERIC_SECRET_KEY_GEN,"GENERIC-SECRET-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_HKDF_KEY_GEN,	"HKDF-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_HKDF_DATA,	"HKDF-DATA", NULL, MF_UNKNOWN },
	{ CKM_HKDF_DERIVE,	"HKDF-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_CONCATENATE_BASE_AND_KEY,"CONCATENATE-BASE-AND-KEY", NULL, MF_UNKNOWN },
	{ CKM_CONCATENATE_BASE_AND_DATA,"CONCATENATE-BASE-AND-DATA", NULL, MF_UNKNOWN },
	{ CKM_CONCATENATE_DATA_AND_BASE,"CONCATENATE-DATA-AND-BASE", NULL, MF_UNKNOWN },
	{ CKM_XOR_BASE_AND_DATA,	"XOR-BASE-AND-DATA", NULL, MF_UNKNOWN },
	{ CKM_EXTRACT_KEY_FROM_KEY,"EXTRACT-KEY-FROM-KEY", NULL, MF_UNKNOWN },
	{ CKM_SSL3_PRE_MASTER_KEY_GEN,"SSL3-PRE-MASTER-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_SSL3_MASTER_KEY_DERIVE,"SSL3-MASTER-KEY-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_SSL3_KEY_AND_MAC_DERIVE,"SSL3-KEY-AND-MAC-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_SSL3_MASTER_KEY_DERIVE_DH,"SSL3-MASTER-KEY-DERIVE-DH", NULL, MF_UNKNOWN },
	{ CKM_TLS_PRE_MASTER_KEY_GEN,"TLS-PRE-MASTER-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_TLS_MASTER_KEY_DERIVE,"TLS-MASTER-KEY-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_TLS_KEY_AND_MAC_DERIVE,"TLS-KEY-AND-MAC-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_TLS_MASTER_KEY_DERIVE_DH,"TLS-MASTER-KEY-DERIVE-DH", NULL, MF_UNKNOWN },
	{ CKM_SSL3_MD5_MAC,	"SSL3-MD5-MAC", NULL, MF_UNKNOWN },
	{ CKM_SSL3_SHA1_MAC,	"SSL3-SHA1-MAC", NULL, MF_UNKNOWN },
	{ CKM_MD5_KEY_DERIVATION,	"MD5-KEY-DERIVATION", NULL, MF_UNKNOWN },
	{ CKM_MD2_KEY_DERIVATION,	"MD2-KEY-DERIVATION", NULL, MF_UNKNOWN },
	{ CKM_SHA1_KEY_DERIVATION,"SHA1-KEY-DERIVATION", NULL, MF_UNKNOWN },
	{ CKM_PBE_MD2_DES_CBC,	"PBE-MD2-DES-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_MD5_DES_CBC,	"PBE-MD5-DES-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_MD5_CAST_CBC,	"PBE-MD5-CAST-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_MD5_CAST3_CBC,	"PBE-MD5-CAST3-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_MD5_CAST5_CBC,	"PBE-MD5-CAST5-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_CAST5_CBC,	"PBE-SHA1-CAST5-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_RC4_128,	"PBE-SHA1-RC4-128", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_RC4_40,	"PBE-SHA1-RC4-40", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_DES3_EDE_CBC,"PBE-SHA1-DES3-EDE-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_DES2_EDE_CBC,"PBE-SHA1-DES2-EDE-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_RC2_128_CBC,"PBE-SHA1-RC2-128-CBC", NULL, MF_UNKNOWN },
	{ CKM_PBE_SHA1_RC2_40_CBC,"PBE-SHA1-RC2-40-CBC", NULL, MF_UNKNOWN },
	{ CKM_PKCS5_PBKD2,	"PKCS5-PBKD2", NULL, MF_UNKNOWN },
	{ CKM_PBA_SHA1_WITH_SHA1_HMAC,"PBA-SHA1-WITH-SHA1-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_KEY_WRAP_LYNKS,	"KEY-WRAP-LYNKS", NULL, MF_UNKNOWN },
	{ CKM_KEY_WRAP_SET_OAEP,	"KEY-WRAP-SET-OAEP", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_KEY_GEN,	"SKIPJACK-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_ECB64,	"SKIPJACK-ECB64", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_CBC64,	"SKIPJACK-CBC64", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_OFB64,	"SKIPJACK-OFB64", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_CFB64,	"SKIPJACK-CFB64", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_CFB32,	"SKIPJACK-CFB32", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_CFB16,	"SKIPJACK-CFB16", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_CFB8,	"SKIPJACK-CFB8", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_WRAP,	"SKIPJACK-WRAP", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_PRIVATE_WRAP,"SKIPJACK-PRIVATE-WRAP", NULL, MF_UNKNOWN },
	{ CKM_SKIPJACK_RELAYX,	"SKIPJACK-RELAYX", NULL, MF_UNKNOWN },
	{ CKM_KEA_KEY_PAIR_GEN,	"KEA-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_KEA_KEY_DERIVE,	"KEA-KEY-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_FORTEZZA_TIMESTAMP,	"FORTEZZA-TIMESTAMP", NULL, MF_UNKNOWN },
	{ CKM_BATON_KEY_GEN,	"BATON-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_BATON_ECB128,	"BATON-ECB128", NULL, MF_UNKNOWN },
	{ CKM_BATON_ECB96,	"BATON-ECB96", NULL, MF_UNKNOWN },
	{ CKM_BATON_CBC128,	"BATON-CBC128", NULL, MF_UNKNOWN },
	{ CKM_BATON_COUNTER,	"BATON-COUNTER", NULL, MF_UNKNOWN },
	{ CKM_BATON_SHUFFLE,	"BATON-SHUFFLE", NULL, MF_UNKNOWN },
	{ CKM_BATON_WRAP,		"BATON-WRAP", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_KEY_PAIR_GEN,	"ECDSA-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_ECDSA,		"ECDSA", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA1,		"ECDSA-SHA1", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA224,	"ECDSA-SHA224", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA256,	"ECDSA-SHA256", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA384,	"ECDSA-SHA384", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA512,	"ECDSA-SHA512", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA3_224,	"ECDSA-SHA3-224", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA3_256,	"ECDSA-SHA3-256", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA3_384,	"ECDSA-SHA3-384", NULL, MF_UNKNOWN },
	{ CKM_ECDSA_SHA3_512,	"ECDSA-SHA3-512", NULL, MF_UNKNOWN },
	{ CKM_ECDH1_DERIVE,	"ECDH1-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_ECDH1_COFACTOR_DERIVE,"ECDH1-COFACTOR-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_ECMQV_DERIVE,	"ECMQV-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_EC_EDWARDS_KEY_PAIR_GEN,"EC-EDWARDS-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_EC_MONTGOMERY_KEY_PAIR_GEN,"EC-MONTGOMERY-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_EDDSA,		"EDDSA", NULL, MF_UNKNOWN },
	{ CKM_XEDDSA,		"XEDDSA", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_KEY_GEN,	"JUNIPER-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_ECB128,	"JUNIPER-ECB128", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_CBC128,	"JUNIPER-CBC128", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_COUNTER,	"JUNIPER-COUNTER", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_SHUFFLE,	"JUNIPER-SHUFFLE", NULL, MF_UNKNOWN },
	{ CKM_JUNIPER_WRAP,	"JUNIPER-WRAP", NULL, MF_UNKNOWN },
	{ CKM_FASTHASH,		"FASTHASH", NULL, MF_UNKNOWN },
	{ CKM_AES_KEY_GEN,	"AES-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_AES_ECB,		"AES-ECB", NULL, MF_UNKNOWN },
	{ CKM_AES_CBC,		"AES-CBC", NULL, MF_UNKNOWN },
	{ CKM_AES_MAC,		"AES-MAC", NULL, MF_UNKNOWN },
	{ CKM_AES_MAC_GENERAL,	"AES-MAC-GENERAL", NULL, MF_UNKNOWN },
	{ CKM_AES_CBC_PAD,	"AES-CBC-PAD", NULL, MF_UNKNOWN },
	{ CKM_AES_CTR,		"AES-CTR", NULL, MF_UNKNOWN },
	{ CKM_AES_GCM,		"AES-GCM", NULL, MF_UNKNOWN },
	{ CKM_AES_CMAC,		"AES-CMAC", NULL, (MF_SIGN | MF_VERIFY | MF_CKO_SECRET_KEY) },
	{ CKM_AES_CMAC_GENERAL,	"AES-CMAC-GENERAL", NULL, (MF_SIGN | MF_VERIFY | MF_CKO_SECRET_KEY) },
	{ CKM_DES_ECB_ENCRYPT_DATA, "DES-ECB-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_DES_CBC_ENCRYPT_DATA, "DES-CBC-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_DES3_ECB_ENCRYPT_DATA, "DES3-ECB-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_DES3_CBC_ENCRYPT_DATA, "DES3-CBC-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_AES_ECB_ENCRYPT_DATA, "AES-ECB-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_AES_CBC_ENCRYPT_DATA, "AES-CBC-ENCRYPT-DATA", NULL, MF_UNKNOWN },
	{ CKM_GOST28147_KEY_GEN,	"GOST28147-KEY-GEN", NULL, MF_UNKNOWN },
	{ CKM_GOST28147_ECB,	"GOST28147-ECB", NULL, MF_UNKNOWN },
	{ CKM_GOST28147,	"GOST28147", NULL, MF_UNKNOWN },
	{ CKM_GOST28147_MAC,	"GOST28147-MAC", NULL, MF_UNKNOWN },
	{ CKM_GOST28147_KEY_WRAP,	"GOST28147-KEY-WRAP", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_KEY_PAIR_GEN,"GOSTR3410-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410,		"GOSTR3410", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_DERIVE,	"GOSTR3410-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_WITH_GOSTR3411,"GOSTR3410-WITH-GOSTR3411", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_512_KEY_PAIR_GEN,	"GOSTR3410-512-KEY-PAIR-GEN", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_512,	"GOSTR3410_512", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_12_DERIVE,	"GOSTR3410-12-DERIVE", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_WITH_GOSTR3411_12_256,	"GOSTR3410-WITH-GOSTR3411-12-256", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3410_WITH_GOSTR3411_12_512,	"GOSTR3410-WITH-GOSTR3411-12-512", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3411,		"GOSTR3411", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3411_HMAC,	"GOSTR3411-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_GOSTR3411_12_256,	"GOSTR3411-12-256", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3411_12_512,	"GOSTR3411-12-512", NULL, MF_UNKNOWN },
	{ CKM_GOSTR3411_12_256_HMAC,	"GOSTR3411-12-256-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_GOSTR3411_12_512_HMAC,	"GOSTR3411-12-512-HMAC", NULL, MF_GENERIC_HMAC_FLAGS },
	{ CKM_DSA_PARAMETER_GEN,	"DSA-PARAMETER-GEN", NULL, MF_UNKNOWN },
	{ CKM_DH_PKCS_PARAMETER_GEN,"DH-PKCS-PARAMETER-GEN", NULL, MF_UNKNOWN },
	{ CKM_X9_42_DH_PARAMETER_GEN,"X9-42-DH-PARAMETER-GEN", NULL, MF_UNKNOWN },
	{ CKM_AES_KEY_WRAP,	"AES-KEY-WRAP", NULL, MF_UNKNOWN },
	{ CKM_AES_KEY_WRAP_PAD,	"AES-KEY-WRAP-PAD", NULL, MF_UNKNOWN},
	{ 0, NULL, NULL, MF_UNKNOWN },
};

static struct mech_info	p11_mgf[] = {
	{ CKG_MGF1_SHA1,		"MGF1-SHA1", NULL, MF_MGF },
	{ CKG_MGF1_SHA224,	"MGF1-SHA224", NULL, MF_MGF },
	{ CKG_MGF1_SHA256,	"MGF1-SHA256", NULL, MF_MGF },
	{ CKG_MGF1_SHA384,	"MGF1-SHA384", NULL, MF_MGF },
	{ CKG_MGF1_SHA512,	"MGF1-SHA512", NULL, MF_MGF },
	{ CKG_MGF1_SHA3_224,	"MGF1-SHA3_224", NULL, MF_MGF },
	{ CKG_MGF1_SHA3_256,	"MGF1-SHA3_256", NULL, MF_MGF },
	{ CKG_MGF1_SHA3_384,	"MGF1-SHA3_384", NULL, MF_MGF },
	{ CKG_MGF1_SHA3_512,	"MGF1-SHA3_512", NULL, MF_MGF },

	{ 0, NULL, NULL, MF_UNKNOWN }
};

static struct mech_info p11_profile[] = {
	{ CKP_INVALID_ID,                "CKP_INVALID_ID",                NULL, MF_UNKNOWN },
	{ CKP_BASELINE_PROVIDER,         "CKP_BASELINE_PROVIDER",         NULL, MF_UNKNOWN },
	{ CKP_EXTENDED_PROVIDER,         "CKP_EXTENDED_PROVIDER",         NULL, MF_UNKNOWN },
	{ CKP_AUTHENTICATION_TOKEN,      "CKP_AUTHENTICATION_TOKEN",      NULL, MF_UNKNOWN },
	{ CKP_PUBLIC_CERTIFICATES_TOKEN, "CKP_PUBLIC_CERTIFICATES_TOKEN", NULL, MF_UNKNOWN },
	{ CKP_VENDOR_DEFINED,            "CKP_VENDOR_DEFINED",            NULL, MF_UNKNOWN },
	{ 0, NULL, NULL, MF_UNKNOWN }
};
// clang-format on

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

uint16_t p11_mechanism_to_flags(CK_MECHANISM_TYPE mech)
{
	struct mech_info *mi;
	for (mi = p11_mechanisms; mi->name; mi++) {
		if (mi->mech == mech)
			return mi->mf_flags;
	}

	/*
	 * XXX: Since populating the table is underway we won't warn until its done. Existing mechanisms function
	 * as they used to. So guard this on verbose.
	 */
	if (verbose) {
		util_warn("mechanism 0x%lx not found, consider adding it to mechanism table", mech);
	}

	return MF_UNKNOWN;
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

static const char *p11_profile_to_name(CK_ULONG profile)
{
	static char temp[64];
	struct mech_info *mi;

	for (mi = p11_profile; mi->name; mi++) {
		if (mi->mech == profile)
			return mi->name;
	}
	snprintf(temp, sizeof(temp), "profile-0x%lX", (unsigned long) profile);
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

#if defined(_WIN32) || defined(HAVE_PTHREAD)
#ifdef _WIN32
static DWORD WINAPI test_threads_run(_In_ LPVOID pttd)
#else
static void * test_threads_run(void * pttd)
#endif
{
	CK_RV rv = CKR_OK;
	CK_INFO info;
	int l_slots = 0;
	CK_ULONG l_p11_num_slots = 0;
	CK_SLOT_ID_PTR l_p11_slots = NULL;
	char * pctest;
	struct test_threads_data * ttd = (struct test_threads_data *)pttd;

	fprintf(stderr, "Test thread %d started with options:%s\n", ttd->tnum, ttd->tests);
	/* call selected C_* routines with different options */
	pctest = ttd-> tests;

	/* series of two character commands */
	while (pctest && *pctest && *(pctest + 1)) {
		/*  Pn - pause where n is 0 to 9 iseconds */
		if (*pctest == 'P' && *(pctest + 1) >= '0' && *(pctest + 1) <= '9') {
			fprintf(stderr, "Test thread %d pauseing for %d seconds\n", ttd->tnum, (*(pctest + 1) - '0'));
#ifdef _WIN32
			Sleep((*(pctest + 1) - '0') * 1000);
#else
			sleep(*(pctest + 1) - '0');
#endif
		}

		else if (*pctest == 'I') {
			/* IN - C_Initialize with NULL args */
			if (*(pctest + 1) == 'N') {
				fprintf(stderr, "Test thread %d C_Initialize(NULL)\n", ttd->tnum);
				rv = p11->C_Initialize(NULL);
				fprintf(stderr, "Test thread %d C_Initialize returned %s\n", ttd->tnum, CKR2Str(rv));
			}
			/* IL C_Initialize with CKF_OS_LOCKING_OK */
			else if (*(pctest + 1) == 'L') {
				fprintf(stderr, "Test thread %d C_Initialize CKF_OS_LOCKING_OK \n", ttd->tnum);
				rv = p11->C_Initialize(&c_initialize_args_OS);
				fprintf(stderr, "Test thread %d C_Initialize  returned %s\n", ttd->tnum, CKR2Str(rv));
			}
			else
				goto err;
		}

		/* GI - C_GetInfo */
		else if (*pctest == 'G' && *(pctest + 1) == 'I') {
			fprintf(stderr, "Test thread %d C_GetInfo\n", ttd->tnum);
			rv = p11->C_GetInfo(&info);
			fprintf(stderr, "Test thread %d C_GetInfo returned %s\n", ttd->tnum, CKR2Str(rv));
		}

		/* SL - C_GetSlotList */
		else if (*pctest == 'S' && *(pctest + 1) == 'L') {
			fprintf(stderr, "Test thread %d C_GetSlotList to get l_p11_num_slots\n", ttd->tnum);
			rv = p11->C_GetSlotList(1, NULL, &l_p11_num_slots);
			fprintf(stderr, "Test thread %d C_GetSlotList returned %s\n", ttd->tnum, CKR2Str(rv));
			fprintf(stderr, "Test thread %d l_p11_num_slots:%ld\n", ttd->tnum, l_p11_num_slots);
			if (rv == CKR_OK) {
				free(l_p11_slots);
				l_p11_slots = NULL;
				if (l_p11_num_slots > 0) {
					l_p11_slots = calloc(l_p11_num_slots, sizeof(CK_SLOT_ID));
					if (l_p11_slots == NULL) {
						goto err;
					}
					fprintf(stderr, "Test thread %d C_GetSlotList\n", ttd->tnum);
					rv = p11->C_GetSlotList(1, l_p11_slots, &l_p11_num_slots);
					fprintf(stderr, "Test thread %d C_GetSlotList returned %s\n", ttd->tnum, CKR2Str(rv));
					fprintf(stderr, "Test thread %d l_p11_num_slots:%ld\n", ttd->tnum, l_p11_num_slots);
					if (rv == CKR_OK && l_p11_num_slots && l_p11_slots)
						l_slots = 1;
				}
			}
		}

		/* Tn Get token from slot_index n C_GetTokenInfo, where n is 0 to 9 */
		else if (*pctest == 'T' && *(pctest + 1) >= '0' && *(pctest + 1) <= '9') {
			fprintf(stderr, "Test thread %d C_GetTokenInfo from slot_index %d using show_token\n", ttd->tnum, (*(pctest + 1) - '0'));
			if (l_slots && (CK_ULONG)(*(pctest + 1) - '0') < l_p11_num_slots) {
				show_token(l_p11_slots[(*(pctest + 1) - '0')]);
			} else {
				fprintf(stderr, "Test thread %d slot not available, unable to call C_GetTokenInfo\n", ttd->tnum);
				rv = CKR_TOKEN_NOT_PRESENT;
				break;
			}
		}

		/* LT login and test, just like as if `--login --test` was specified.
		 * May be combined with `--pin=123456` */
		else if (*pctest == 'L' && *(pctest + 1) == 'T') {
			CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

			rv = p11->C_OpenSession(opt_slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &session);
			if (rv == CKR_OK) {
				if (opt_login_type == -1)
					opt_login_type = CKU_USER;
				login(session, opt_login_type);

				if (p11_test(session))
					rv = CKR_GENERAL_ERROR;
				else
					rv = CKR_OK;
			}
		}

		else {
		err:
			rv = CKR_GENERAL_ERROR; /* could be vendor error, */
			fprintf(stderr, "Test thread %d Unknown test '%c%c'\n", ttd->tnum, *pctest, *(pctest + 1));
			break;
		}

		pctest ++;
		if (*pctest != 0x00)
			pctest ++;
		if (*pctest == ':')
			pctest++;


		if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		/* IN C_Initialize with NULL args */
			break;
	}

	free(l_p11_slots);
	fprintf(stderr, "Test thread %d returning rv:%s\n", ttd->tnum, CKR2Str(rv));
#ifdef _WIN32
	ExitThread(0);
#else
	pthread_exit(NULL);
#endif
}

static int test_threads_cleanup()
{

	int i;

	fprintf(stderr,"test_threads cleanup starting\n");

	for (i = 0; i < test_threads_num; i++) {
#ifdef _WIN32
		WaitForSingleObject(test_threads_handles[i], INFINITE);
#else
		pthread_join(test_threads_handles[i], NULL);
#endif
	}

	fprintf(stderr,"test_threads cleanup finished\n");
	return 0;
}

static int test_threads_start(int tnum)
{
	int r = 0;

#ifdef _WIN32
	test_threads_handles[tnum] = CreateThread(NULL, 0, test_threads_run, (LPVOID) &test_threads_datas[tnum],
		0, NULL);
	if (test_threads_handles[tnum] == NULL) {
		r = GetLastError();
	}
#else
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	r = pthread_create(&test_threads_handles[tnum], &attr, test_threads_run, (void *) &test_threads_datas[tnum]);
#endif
	if (r != 0) {
		fprintf(stderr,"test_threads pthread_create failed %d for thread %d\n", r, tnum);
		/* system error */
	}
	return r;
}

/*********************************************************************************************/
static void test_threads()
{
	int  i;

	/* call test_threads_start for each --test-thread option */

	/* upon return, C_Initialize will be called, from main code */
	for (i = 0; i < test_threads_num && i < MAX_TEST_THREADS; i++) {
		test_threads_start(i);
	}
}
#endif /* defined(_WIN32) || defined(HAVE_PTHREAD) */
