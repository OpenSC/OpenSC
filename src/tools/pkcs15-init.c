/*
 * Initialize Cards according to PKCS#15.
 *
 * This is a fill in the blanks sort of exercise. You need a
 * profile that describes characteristics of your card, and the
 * application specific layout on the card. This program will
 * set up the card according to this specification (including
 * PIN initialization etc) and create the corresponding PKCS15
 * structure.
 *
 * There are a very few tasks that are too card specific to have
 * a generic implementation; that is how PINs and keys are stored
 * on the card. These should be implemented in pkcs15-<cardname>.c
 *
 * Copyright (C) 2002, Olaf Kirch <okir@suse.de>
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

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <openssl/opensslv.h>
#include "libopensc/sc-ossl-compat.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/opensslconf.h> /* for OPENSSL_NO_EC */
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif /* OPENSSL_NO_EC */

#include "common/compat_strlcpy.h"
#include "libopensc/internal.h"
#include "libopensc/cardctl.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/cards.h"
#include "libopensc/asn1.h"
#include "pkcs15init/pkcs15-init.h"
#include "pkcs15init/profile.h"
#include "util.h"

#undef GET_KEY_ECHO_OFF

static const char *app_name = "pkcs15-init";

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(sc_context_t *,
			struct sc_pkcs15_card *, u8 **, size_t *);

/* Local functions */
static int	open_reader_and_card(char *);
static int	do_assert_pristine(sc_card_t *);
static int	do_erase(sc_card_t *, struct sc_profile *);
static int	do_erase_application(sc_card_t *, struct sc_profile *);
static int	do_delete_objects(struct sc_profile *, unsigned int myopt_delete_flags);
static int	do_change_attributes(struct sc_profile *, unsigned int myopt_type);
static int	do_init_app(struct sc_profile *);
static int	do_store_pin(struct sc_profile *);
static int	do_generate_key(struct sc_profile *, const char *);
static int	do_generate_skey(struct sc_profile *, const char *);
static int	do_store_private_key(struct sc_profile *);
static int	do_store_public_key(struct sc_profile *, EVP_PKEY *);
static int	do_store_secret_key(struct sc_profile *);
static int	do_store_certificate(struct sc_profile *);
static int	do_update_certificate(struct sc_profile *);
static int	do_convert_cert(sc_pkcs15_der_t *, X509 *);
static int	is_cacert_already_present(struct sc_pkcs15init_certargs *);
static int	do_finalize_card(sc_card_t *, struct sc_profile *);

static int	do_read_data_object(const char *name, u8 **out, size_t *outlen, size_t expected);
static int	do_store_data_object(struct sc_profile *profile);
static int	do_sanity_check(struct sc_profile *profile);

static int	init_prkeyargs(struct sc_pkcs15init_prkeyargs *);
static int	init_skeyargs(struct sc_pkcs15init_skeyargs *);
static void	init_gost_params(struct sc_pkcs15init_keyarg_gost_params *, EVP_PKEY *);
static int	get_pin_callback(struct sc_profile *profile,
			int id, const struct sc_pkcs15_auth_info *info,
			const char *label,
			u8 *pinbuf, size_t *pinsize);
static int	get_key_callback(struct sc_profile *,
			int method, int reference,
			const u8 *, size_t, u8 *, size_t *);

static int	do_read_private_key(const char *, const char *, EVP_PKEY **, X509 **, unsigned int);
static int	do_read_public_key(const char *, const char *, EVP_PKEY **);
static int	do_read_certificate(const char *, const char *, X509 **);
static char *	cert_common_name(X509 *x509);
static void	parse_commandline(int argc, char **argv);
static void	ossl_print_errors(void);
static int	verify_pin(struct sc_pkcs15_card *, char *);

enum {
	OPT_PASSPHRASE = 0x100,
	OPT_PUBKEY,
	OPT_SECRKEY,
	OPT_EXTRACTABLE,
	OPT_INSECURE,
	OPT_AUTHORITY,
	OPT_ASSERT_PRISTINE,
	OPT_SECRET,
	OPT_SECRKEY_ALGO,
	OPT_PUBKEY_LABEL,
	OPT_CERT_LABEL,
	OPT_APPLICATION_NAME,
	OPT_APPLICATION_ID,
	OPT_PUK_ID,
	OPT_PUK_LABEL,
	OPT_VERIFY_PIN,
	OPT_SANITY_CHECK,
	OPT_BIND_TO_AID,
	OPT_UPDATE_LAST_UPDATE,
	OPT_ERASE_APPLICATION,
	OPT_IGNORE_CA_CERTIFICATES,
	OPT_UPDATE_EXISTING,
	OPT_MD_CONTAINER_GUID,
	OPT_VERSION,
	OPT_USER_CONSENT,

	OPT_PIN1      = 0x10000,	/* don't touch these values */
	OPT_PUK1      = 0x10001,
	OPT_PIN2      = 0x10002,
	OPT_PUK2      = 0x10003,
	OPT_SERIAL    = 0x10004,
	OPT_NO_SOPIN  = 0x10005,
	OPT_USE_PINPAD= 0x10006,
	OPT_USE_PINPAD_DEPRECATED
};

const struct option	options[] = {
	{ "version",		0, NULL,			OPT_VERSION },
	{ "erase-card",		no_argument, NULL,		'E' },
	{ "create-pkcs15",	no_argument, NULL,		'C' },
	{ "store-pin",		no_argument, NULL,		'P' },
	{ "generate-key",	required_argument, NULL,	'G' },
	{ "store-private-key",	required_argument, NULL,	'S' },
	{ "store-public-key",	required_argument, NULL,	OPT_PUBKEY },
	{ "store-secret-key",	required_argument, NULL,	OPT_SECRKEY },
	{ "store-certificate",	required_argument, NULL,	'X' },
	{ "update-certificate",	required_argument, NULL,	'U' },
	{ "store-data",		required_argument, NULL,	'W' },
	{ "delete-objects",	required_argument, NULL,	'D' },
	{ "change-attributes",	required_argument, NULL,	'A' },
	{ "sanity-check",	no_argument, NULL,		OPT_SANITY_CHECK},
	{ "erase-application",	required_argument, NULL,	OPT_ERASE_APPLICATION},

	{ "reader",		required_argument, NULL,	'r' },
	{ "pin",		required_argument, NULL,	OPT_PIN1 },
	{ "puk",		required_argument, NULL,	OPT_PUK1 },
	{ "so-pin",		required_argument, NULL,	OPT_PIN2 },
	{ "so-puk",		required_argument, NULL,	OPT_PUK2 },
	{ "no-so-pin",		no_argument,	   NULL,	OPT_NO_SOPIN },
	{ "serial",		required_argument, NULL,	OPT_SERIAL },
	{ "auth-id",		required_argument, NULL,	'a' },
	{ "puk-id",		required_argument, NULL,	OPT_PUK_ID },
	{ "verify-pin",         no_argument,	   NULL,	OPT_VERIFY_PIN },
	{ "id",			required_argument, NULL,	'i' },
	{ "label",		required_argument, NULL,	'l' },
	{ "puk-label",		required_argument, NULL,	OPT_PUK_LABEL },
	{ "secret-key-algorithm", required_argument, NULL,	OPT_SECRKEY_ALGO },
	{ "public-key-label",	required_argument, NULL,	OPT_PUBKEY_LABEL },
	{ "cert-label",		required_argument, NULL,	OPT_CERT_LABEL },
	{ "application-name",	required_argument, NULL,	OPT_APPLICATION_NAME },
	{ "application-id",	required_argument, NULL,	OPT_APPLICATION_ID },
	{ "aid",		required_argument, NULL,        OPT_BIND_TO_AID },
	{ "output-file",	required_argument, NULL,	'o' },
	{ "format",		required_argument, NULL,	'f' },
	{ "passphrase",		required_argument, NULL,	OPT_PASSPHRASE },
	{ "authority",		no_argument,	   NULL,	OPT_AUTHORITY },
	{ "key-usage",		required_argument, NULL,	'u' },
	{ "finalize",		no_argument,       NULL,	'F' },
	{ "update-last-update", no_argument,       NULL,        OPT_UPDATE_LAST_UPDATE},
	{ "ignore-ca-certificates",no_argument,    NULL,	OPT_IGNORE_CA_CERTIFICATES},
	{ "update-existing",	no_argument,       NULL,	OPT_UPDATE_EXISTING},

	{ "extractable",	no_argument, NULL,		OPT_EXTRACTABLE },
	{ "user-consent",	required_argument, NULL, OPT_USER_CONSENT},
	{ "insecure",		no_argument, NULL,		OPT_INSECURE },
	{ "use-default-transport-keys",
				no_argument, NULL,		'T' },
	{ "use-pinpad",		no_argument, NULL,		OPT_USE_PINPAD },
	{ "no-prompt",		no_argument, NULL,		OPT_USE_PINPAD_DEPRECATED },

	{ "profile",		required_argument, NULL,	'p' },
	{ "card-profile",	required_argument, NULL,	'c' },
	{ "md-container-guid",	required_argument, NULL,	OPT_MD_CONTAINER_GUID},
	{ "wait",		no_argument, NULL,		'w' },
	{ "help",		no_argument, NULL,		'h' },
	{ "verbose",		no_argument, NULL,		'v' },

	/* Hidden options for testing */
	{ "assert-pristine",	no_argument, NULL,		OPT_ASSERT_PRISTINE },
	{ "secret",		required_argument, NULL,	OPT_SECRET },
	{ NULL, 0, NULL, 0 }
};
static const char *		option_help[] = {
	"Print OpenSC package version",
	"Erase the smart card",
	"Creates a new PKCS #15 structure",
	"Store a new PIN/PUK on the card",
	"Generate a new key and store it on the card",
	"Store private key",
	"Store public key",
	"Store secret key",
	"Store an X.509 certificate",
	"Update an X.509 certificate (careful with mail decryption certs!!)",
	"Store a data object",
	"Delete object(s) (use \"help\" for more information)",
	"Change attribute(s) (use \"help\" for more information)",
	"Card specific sanity check and possibly update procedure",
	"Erase application with AID <arg>",

	"Specify which reader to use",
	"Specify PIN",
	"Specify unblock PIN",
	"Specify security officer (SO) PIN",
	"Specify unblock PIN for SO PIN",
	"Do not install a SO PIN, and do not prompt for it",
	"Specify the serial number of the card",
	"Specify ID of PIN to use/create",
	"Specify ID of PUK to use/create",
	"Verify PIN after card binding (use with --auth-id)",
	"Specify ID of key/certificate",
	"Specify label of PIN/key",
	"Specify label of PUK",
	"Specify secret key algorithm (use with --store-secret-key)",
	"Specify public key label (use with --generate-key)",
	"Specify user cert label (use with --store-private-key)",
	"Specify application name of data object (use with --store-data-object)",
	"Specify application id of data object (use with --store-data-object)",
	"Specify AID of the on-card PKCS#15 application to be binded to (in hexadecimal form)",
	"Output public portion of generated key to file",
	"Specify key/cert file format: PEM (=default), DER or PKCS12",
	"Specify passphrase for unlocking secret key",
	"Mark certificate as a CA certificate",
	"Specify X.509 key usage (use \"--key-usage help\" for more information)",
	"Finish initialization phase of the smart card",
	"Update 'lastUpdate' attribute of tokenInfo",
	"When storing PKCS#12 ignore CA certificates",
	"Store or update existing certificate",

	"Private key stored as an extractable key",
	"Set userConsent. Default = 0",
	"Insecure mode: do not require a PIN for private key",
	"Do not ask for transport keys if the driver thinks it knows the key",
	"Do not prompt the user; if no PINs supplied, pinpad will be used",
	NULL,

	"Specify the general profile to use",
	"Specify the card profile to use",
	"For a new key specify GUID for a MD container",
	"Wait for card insertion",
	"Display this message",
	"Verbose operation. Use several times to enable debug output.",

	NULL,
	NULL,
};

enum {
	ACTION_NONE = 0,
	ACTION_ASSERT_PRISTINE,
	ACTION_ERASE,
	ACTION_INIT,
	ACTION_DELETE_OBJECTS,
	ACTION_STORE_PIN,
	ACTION_GENERATE_KEY,
	ACTION_STORE_PRIVKEY,
	ACTION_STORE_PUBKEY,
	ACTION_STORE_SECRKEY,
	ACTION_STORE_CERT,
	ACTION_UPDATE_CERT,
	ACTION_STORE_DATA,
	ACTION_FINALIZE_CARD,
	ACTION_CHANGE_ATTRIBUTES,
	ACTION_SANITY_CHECK,
	ACTION_UPDATE_LAST_UPDATE,
	ACTION_ERASE_APPLICATION,
	ACTION_PRINT_VERSION,

	ACTION_MAX
};
static const char *action_names[] = {
	"do nothing",
	"verify that card is pristine",
	"erase card",
	"create PKCS #15 meta structure",
	"delete object(s)",
	"store PIN",
	"generate key",
	"store private key",
	"store public key",
	"store secret key",
	"store certificate",
	"update certificate",
	"store data object",
	"finalizing card",
	"change attribute(s)",
	"check card's sanity",
	"update 'last-update'",
	"erase application"
};

#define MAX_CERTS		4
#define MAX_SECRETS		16
struct secret {
	int			type;
	int			reference;
	sc_pkcs15_id_t		id;
	unsigned char		key[64];
	size_t			len;
};

/* Flags for do_delete_crypto_objects() and do_change_attributes() */
#define SC_PKCS15INIT_TYPE_PRKEY	1
#define SC_PKCS15INIT_TYPE_PUBKEY	2
#define SC_PKCS15INIT_TYPE_CERT		4
#define SC_PKCS15INIT_TYPE_CHAIN	(8 | 4)
#define SC_PKCS15INIT_TYPE_DATA		16
#define SC_PKCS15INIT_TYPE_SKEY		32

static sc_context_t *	g_ctx = NULL;
static sc_card_t *		g_card = NULL;
static struct sc_pkcs15_card *	g_p15card = NULL;
static char *			opt_reader = NULL;
static unsigned int		opt_actions;
static int			opt_extractable = 0,
				opt_insecure = 0,
				opt_authority = 0,
				opt_use_pinpad = 0,
				opt_no_sopin = 0,
				opt_use_defkeys = 0,
				opt_wait = 0,
				opt_verify_pin = 0;
static const char *		opt_profile = "pkcs15";
static char *			opt_card_profile = NULL;
static char *			opt_infile = NULL;
static char *			opt_format = NULL;
static char *			opt_authid = NULL;
static char *			opt_objectid = NULL;
static char *			opt_label = NULL;
static char *			opt_puk_label = NULL;
static char *			opt_pubkey_label = NULL;
static char *			opt_secrkey_algo = NULL;
static char *			opt_cert_label = NULL;
static const char *		opt_pins[4];
static char *			pins[4];
static char *			opt_serial = NULL;
static const char *		opt_passphrase = NULL;
static char *			opt_newkey = NULL;
static char *			opt_outkey = NULL;
static char *			opt_application_id = NULL;
static char *			opt_application_name = NULL;
static char *			opt_bind_to_aid = NULL;
static char *			opt_puk_authid = NULL;
static char *			opt_md_container_guid = NULL;
static unsigned int		opt_x509_usage = 0;
static unsigned int		opt_delete_flags = 0;
static unsigned int		opt_type = 0;
static int			ignore_cmdline_pins = 0;
static struct secret		opt_secrets[MAX_SECRETS];
static unsigned int		opt_secret_count;
static int			opt_ignore_ca_certs = 0;
static int			opt_update_existing = 0;
static int			verbose = 0;
static int			opt_user_consent = 0;

static struct sc_pkcs15init_callbacks callbacks = {
	get_pin_callback,	/* get_pin() */
	get_key_callback,	/* get_key() */
};

/*
 * Dialog types for get_pin
 */
#define SC_UI_USAGE_OTHER		0x0000
#define SC_UI_USAGE_NEW_PIN		0x0001
#define SC_UI_USAGE_UNBLOCK_PIN		0x0002
#define SC_UI_USAGE_CHANGE_PIN		0x0003

/*
 * Dialog flags
 */
#define SC_UI_PIN_RETYPE		0x0001	/* new pin, retype */
#define SC_UI_PIN_OPTIONAL		0x0002	/* new pin optional */
#define SC_UI_PIN_CHECK_LENGTH		0x0004	/* check pin length */
#define SC_UI_PIN_MISMATCH_RETRY	0x0008	/* retry if new pin mismatch? */

/* Hints passed to get_pin
 * M marks mandatory fields,
 * O marks optional fields
 */
typedef struct sc_ui_hints {
	const char *		prompt;		/* M: cmdline prompt */
	const char *		dialog_name;	/* M: dialog name */
	unsigned int		usage;		/* M: usage hint */
	unsigned int		flags;		/* M: flags */
	sc_card_t *		card;		/* M: card handle */
	struct sc_pkcs15_card *	p15card;	/* O: pkcs15 handle */

	/* We may not have a pkcs15 object yet when we get
	 * here, but we may have an idea of what it's going to
	 * look like. */
	const char *		obj_label;	/* O: object (PIN) label */
	union {
	    struct sc_pkcs15_auth_info *pin;
	} info;
} sc_ui_hints_t;

/*
 * ask user for a pin
 */
extern int	get_pin(sc_ui_hints_t *hints, char **out);
static int	get_new_pin(sc_ui_hints_t *, const char *, const char *,
			char **);

int
main(int argc, char **argv)
{
	struct sc_profile	*profile = NULL;
	unsigned int		n;
	int			r = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config(NULL);
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !(defined LIBRESSL_VERSION_NUMBER)
	/* Openssl 1.1.0 magic */
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
		| OPENSSL_INIT_ADD_ALL_CIPHERS
		| OPENSSL_INIT_ADD_ALL_DIGESTS
		| OPENSSL_INIT_LOAD_CONFIG,
		NULL);
#else
	/* OpenSSL magic */
	OpenSSL_add_all_algorithms();
	OPENSSL_malloc_init();
#endif

#ifdef RANDOM_POOL
	if (!RAND_load_file(RANDOM_POOL, 32))
		util_fatal("Unable to seed random number pool for key generation");
#endif

	parse_commandline(argc, argv);

	if (optind != argc)
		util_print_usage_and_die(app_name, options, option_help, NULL);
	if (opt_actions == 0) {
		fprintf(stderr, "No action specified.\n");
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}
	if (!opt_profile) {
		fprintf(stderr, "No profile specified.\n");
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}

	/* Connect to the card */
	if (!open_reader_and_card(opt_reader))
		return 1;

	sc_pkcs15init_set_callbacks(&callbacks);

	/* Bind the card-specific operations and load the profile */
	r = sc_pkcs15init_bind(g_card, opt_profile, opt_card_profile, NULL, &profile);
	if (r < 0) {
		printf("Couldn't bind to the card: %s\n", sc_strerror(r));
		return 1;
	}

	for (n = 0; n < sizeof(pins)/sizeof(pins[0]); n++) {
		pins[n] = NULL;
	}

	for (n = 0; n < ACTION_MAX; n++) {
		unsigned int	action = n;

		if (!(opt_actions & (1 << action)))
			continue;

		if (action != ACTION_ERASE
		 && action != ACTION_INIT
		 && action != ACTION_ASSERT_PRISTINE
		 && g_p15card == NULL) {
			/* Read the PKCS15 structure from the card */
			if (opt_bind_to_aid)   {
				struct sc_aid aid;

				aid.len = sizeof(aid.value);
				if (sc_hex_to_bin(opt_bind_to_aid, aid.value, &aid.len))   {
					fprintf(stderr, "Invalid AID value: '%s'\n", opt_bind_to_aid);
					return 1;
				}

				r = sc_pkcs15init_finalize_profile(g_card, profile, &aid);
				if (r < 0)   {
					fprintf(stderr, "Finalize profile error %s\n", sc_strerror(r));
					break;
				}

				r = sc_pkcs15_bind(g_card, &aid, &g_p15card);
			}
			else   {
				r = sc_pkcs15_bind(g_card, NULL, &g_p15card);
			}
			if (r) {
				fprintf(stderr, "PKCS#15 binding failed: %s\n", sc_strerror(r));
				break;
			}

			/* XXX: should compare card to profile here to make
			 * sure we're not messing things up */

			if (verbose)
				printf("Found %s\n", g_p15card->tokeninfo->label);

			sc_pkcs15init_set_p15card(profile, g_p15card);

			if (opt_verify_pin)   {
				r = verify_pin(g_p15card, opt_authid);
				if (r)   {
					fprintf(stderr, "Failed to verify User PIN : %s\n",
						sc_strerror(r));
					break;
				}
			}
		}

		if (verbose && action != ACTION_ASSERT_PRISTINE)
			printf("About to %s.\n", action_names[action]);

		switch (action) {
		case ACTION_PRINT_VERSION:
			printf("%s\n", OPENSC_SCM_REVISION);
			break;
		case ACTION_ASSERT_PRISTINE:
			/* skip printing error message */
			if ((r = do_assert_pristine(g_card)) < 0)
				goto out;
			continue;
		case ACTION_ERASE:
			r = do_erase(g_card, profile);
			break;
		case ACTION_INIT:
			r = do_init_app(profile);
			break;
		case ACTION_STORE_PIN:
			r = do_store_pin(profile);
			break;
		case ACTION_STORE_PRIVKEY:
			r = do_store_private_key(profile);
			break;
		case ACTION_STORE_PUBKEY:
			r = do_store_public_key(profile, NULL);
			break;
		case ACTION_STORE_SECRKEY:
			r = do_store_secret_key(profile);
			break;
		case ACTION_STORE_CERT:
			r = do_store_certificate(profile);
			break;
		case ACTION_UPDATE_CERT:
			r = do_update_certificate(profile);
			break;
		case ACTION_STORE_DATA:
			r = do_store_data_object(profile);
			break;
		case ACTION_DELETE_OBJECTS:
			r = do_delete_objects(profile, opt_delete_flags);
			break;
		case ACTION_CHANGE_ATTRIBUTES:
			r = do_change_attributes(profile, opt_type);
			break;
		case ACTION_GENERATE_KEY:
			r = do_generate_key(profile, opt_newkey);
			if (r == SC_ERROR_INVALID_ARGUMENTS)
				r = do_generate_skey(profile, opt_newkey);
			break;
		case ACTION_FINALIZE_CARD:
			r = do_finalize_card(g_card, profile);
			break;
		case ACTION_SANITY_CHECK:
			r = do_sanity_check(profile);
			break;
		case ACTION_UPDATE_LAST_UPDATE:
			profile->dirty = 1;
			break;
		case ACTION_ERASE_APPLICATION:
			r = do_erase_application(g_card, profile);
			break;
		default:
			util_fatal("Action not yet implemented\n");
		}

		if (r < 0) {
			fprintf(stderr, "Failed to %s: %s\n",
				action_names[action], sc_strerror(r));
			break;
		}
	}

	for (n = 0; n < sizeof(pins)/sizeof(pins[0]); n++) {
		free(pins[n]);
	}

out:
	if (profile) {
		sc_pkcs15init_unbind(profile);
	}
	if (g_p15card) {
		sc_pkcs15_unbind(g_p15card);
	}
	if (g_card) {
		sc_disconnect_card(g_card);
	}
	sc_release_context(g_ctx);
	return r < 0? 1 : 0;
}

static int
open_reader_and_card(char *reader)
{
	int	r;
	sc_context_param_t ctx_param;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&g_ctx, &ctx_param);
	if (r) {
		util_error("Failed to establish context: %s\n", sc_strerror(r));
		return 0;
	}

	if (util_connect_card_ex(g_ctx, &g_card, reader, opt_wait, 0, verbose))
		return 0;

	return 1;
}

/*
 * Make sure there's no pkcs15 structure on the card
 */
static int
do_assert_pristine(sc_card_t *in_card)
{
	sc_path_t	path;
	int		r, ok = 1;

	r = sc_lock(in_card);
	if (r < 0)
		goto end;

	sc_format_path("3F00", &path);
	r = sc_select_file(in_card, &path, NULL);
	if (r)
		goto end;

	sc_format_path("2F00", &path);
	r = sc_select_file(in_card, &path, NULL);
	if (r)
		goto end;

	/* For a while only the presence of OpenSC on-card pkcs#15 is checked.
	   TODO: Parse DIR(2F00) to get know if there is some PKCS#15 applications.*/
	sc_format_path("5015", &path);
	r = sc_select_file(in_card, &path, NULL);
	if (r)
		goto end;

	ok = 0;
end:
	sc_unlock(in_card);
	if (!ok) {
		fprintf(stderr,
			"Card not pristine; detected (possibly incomplete) "
			"PKCS#15 structure\n");
	} else if (verbose) {
		printf("Pristine card.\n");
	}

	return ok ? 0 : -1;
}

/* algorithm spec parsing */
struct alg_spec {
	const char *spec;
	int algorithm;
	unsigned int keybits;
};

static const struct alg_spec alg_types_sym[] = {
	{ "des",	SC_ALGORITHM_DES,	64 },
	{ "3des",	SC_ALGORITHM_3DES,	192 },
	{ "aes",	SC_ALGORITHM_AES,	128 },
	{ NULL, -1, 0 }
};

static const struct alg_spec alg_types_asym[] = {
	{ "rsa",	SC_ALGORITHM_RSA,	1024 },
	{ "dsa",	SC_ALGORITHM_DSA,	1024 },
	{ "gost2001",	SC_ALGORITHM_GOSTR3410,	SC_PKCS15_GOSTR3410_KEYSIZE },
	{ "ec",		SC_ALGORITHM_EC,	0 },
	{ NULL, -1, 0 }
};

static int
parse_alg_spec(const struct alg_spec *types, const char *spec, unsigned int *keybits, struct sc_pkcs15_prkey *prkey)
{
	int i, algorithm = -1;
	char *end;

	for (i = 0; types[i].spec; i++) {
		if (!strncasecmp(spec, types[i].spec, strlen(types[i].spec))) {
			algorithm = types[i].algorithm;
			*keybits = types[i].keybits;
			spec += strlen(types[i].spec);
			break;
		}
	}
	if (algorithm < 0) {
		util_error("Unknown algorithm \"%s\"", spec);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (*spec == '/' || *spec == '-' || *spec == ':')
		spec++;

	if (*spec)   {
		if (isalpha(*spec) && algorithm == SC_ALGORITHM_EC && prkey) {
			prkey->u.ec.params.named_curve = strdup(spec);
		} else {
			*keybits = strtoul(spec, &end, 10);
			if (*end) {
				util_error("Invalid number of key bits \"%s\"", spec);
				return SC_ERROR_INVALID_ARGUMENTS;
			}
		}
	}

	return algorithm;
}

/*
 * Erase card
 */
static int
do_erase(sc_card_t *in_card, struct sc_profile *profile)
{
	int	r;
	struct sc_pkcs15_card *p15card;
	struct sc_aid aid;
	struct sc_aid *paid = NULL;

	p15card = sc_pkcs15_card_new();
	p15card->card = in_card;

	ignore_cmdline_pins++;
	if (opt_bind_to_aid)   {
		aid.len = sizeof(aid.value);
		r = sc_hex_to_bin(opt_bind_to_aid, aid.value, &aid.len);
		if (r < 0)   {
			fprintf(stderr, "Invalid AID value: '%s'\n", opt_bind_to_aid);
			goto err;
		}

		paid = &aid;
	}

	r = sc_lock(p15card->card);
	if (r < 0)
		goto err;
	r = sc_pkcs15init_erase_card(p15card, profile, paid);
	sc_unlock(p15card->card);

	ignore_cmdline_pins--;

err:
	sc_pkcs15_card_free(p15card);
	return r;
}

static int
do_erase_application(sc_card_t *in_card, struct sc_profile *profile)
{
	int r;

	ignore_cmdline_pins--;
	r = do_erase(in_card, profile);
	ignore_cmdline_pins++;
	return r;
}

static int do_finalize_card(sc_card_t *in_card, struct sc_profile *profile)
{
	int r;
	r = sc_lock(in_card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_finalize_card(in_card, profile);
	sc_unlock(in_card);
	return r;
}

/*
 * Initialize pkcs15 application
 */
static int
do_init_app(struct sc_profile *profile)
{
	struct sc_pkcs15init_initargs args;
	sc_pkcs15_auth_info_t	info;
	sc_ui_hints_t		hints;
	const char		*role = "so";
	int			r, so_puk_disabled = 0;

	memset(&hints, 0, sizeof(hints));
	memset(&info, 0, sizeof(info));
	hints.usage	= SC_UI_USAGE_NEW_PIN;
	hints.flags	= SC_UI_PIN_RETYPE
			   | SC_UI_PIN_CHECK_LENGTH
			   | SC_UI_PIN_MISMATCH_RETRY;
	hints.card	= g_card;
	hints.p15card	= NULL;
	hints.info.pin	= &info;

	/* If it's the onepin option, we need the user PIN iso the SO PIN */
	if (opt_profile && strstr(opt_profile, "+onepin")) {
		if (opt_pins[0])
			opt_pins[2] = opt_pins[0];
		if (opt_pins[1])
			opt_pins[3] = opt_pins[1];
	}

	memset(&args, 0, sizeof(args));

	sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_SO_PIN, &info);

	if (!(info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
		role = "user";
	else
		hints.flags |= SC_UI_PIN_OPTIONAL; /* SO PIN is always optional */


	if ((info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED)
			&& (info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
		so_puk_disabled = 1;


	if (!opt_pins[2] && !opt_use_pinpad && !opt_no_sopin) {
		r = get_new_pin(&hints, role, "pin", &pins[2]);
		if (r < 0)
			goto failed;
		opt_pins[2] = pins[2];
	}

	if (!so_puk_disabled && opt_pins[2] && !opt_pins[3] && !opt_use_pinpad) {
		sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_SO_PUK, &info);

		if (!(info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
			role = "user";

		hints.flags |= SC_UI_PIN_OPTIONAL;
		r = get_new_pin(&hints, role, "puk", &pins[3]);
		if (r < 0)
			goto failed;
		opt_pins[3] = pins[3];
	}

	args.so_pin = (const u8 *) opt_pins[2];
	if (args.so_pin)
		args.so_pin_len = strlen((const char *) args.so_pin);

	if (!so_puk_disabled)   {
		args.so_puk = (const u8 *) opt_pins[3];
		if (args.so_puk)
			args.so_puk_len = strlen((const char *) args.so_puk);
	}

	args.serial = (const char *) opt_serial;
	args.label = opt_label;

	r = sc_lock(g_card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_add_app(g_card, profile, &args);
	sc_unlock(g_card);
	return r;

failed:	fprintf(stderr, "Failed to read PIN: %s\n", sc_strerror(r));
	return SC_ERROR_PKCS15INIT;
}

/*
 * Store a PIN/PUK pair
 */
static int
do_store_pin(struct sc_profile *profile)
{
	struct sc_pkcs15init_pinargs args;
	sc_pkcs15_auth_info_t	info;
	sc_ui_hints_t		hints;
	int			r;
	const char 		*pin_id;

	memset(&hints, 0, sizeof(hints));
	hints.usage	= SC_UI_USAGE_NEW_PIN;
	hints.flags	= SC_UI_PIN_RETYPE
			   | SC_UI_PIN_CHECK_LENGTH
			   | SC_UI_PIN_MISMATCH_RETRY;
	hints.card	= g_card;
	hints.p15card	= g_p15card;
	hints.info.pin	= &info;

	pin_id = opt_objectid ? opt_objectid : opt_authid;

	if (!pin_id) {
		util_error("No pin id specified\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_USER_PIN, &info);
	if (opt_pins[0] == NULL) {
		if ((r = get_new_pin(&hints, "user", "pin", &pins[0])) < 0)
			goto failed;
		opt_pins[0] = pins[0];
	}

	if (*opt_pins[0] == '\0') {
		util_error("You must specify a PIN\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	memset(&args, 0, sizeof(args));
	sc_pkcs15_format_id(pin_id, &args.auth_id);
	args.pin = (u8 *) opt_pins[0];
	args.pin_len = strlen(opt_pins[0]);
	args.label = opt_label;

	if (!(info.attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED)
			&& opt_pins[1] == NULL) {
		sc_pkcs15init_get_pin_info(profile, SC_PKCS15INIT_USER_PUK, &info);

		hints.flags |= SC_UI_PIN_OPTIONAL;
		if ((r = get_new_pin(&hints, "user", "puk", &pins[1])) < 0)
			goto failed;
		opt_pins[1] = pins[1];
	}

	if (opt_puk_authid && opt_pins[1])
		sc_pkcs15_format_id(opt_puk_authid, &args.puk_id);
	args.puk_label = opt_puk_label;
	args.puk = (u8 *) opt_pins[1];
	args.puk_len = opt_pins[1]? strlen(opt_pins[1]) : 0;

	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_store_pin(g_p15card, profile, &args);
	sc_unlock(g_p15card->card);
	return r;

failed:	fprintf(stderr, "Failed to read PIN: %s\n", sc_strerror(r));
	return SC_ERROR_PKCS15INIT;
}

static void sc_pkcs15_inc_id(sc_pkcs15_id_t *id)
{
	int len;
	for (len = id->len - 1; len >= 0; len--) {
		if (id->value[len]++ != 0xFF)
			break;
	}
	if (len < 0 && id->len < SC_PKCS15_MAX_ID_SIZE)	{
		memmove(id->value + 1, id->value, id->len++);
		id->value[0] = 1;
	}
}

/*
 * Store a private key
 */
static int
do_store_private_key(struct sc_profile *profile)
{
	struct sc_pkcs15init_prkeyargs args;
	EVP_PKEY	*pkey = NULL;
	X509		*cert[MAX_CERTS];
	int		r, i, ncerts;

	if ((r = init_prkeyargs(&args)) < 0)
		return r;

	r = do_read_private_key(opt_infile, opt_format, &pkey, cert, MAX_CERTS);
	if (r < 0)
		return r;
	ncerts = r;

	if (ncerts) {
		char	namebuf[256];

		printf("Importing %d certificates:\n", opt_ignore_ca_certs ? 1 : ncerts);
		for (i = 0; i < ncerts && !(i && opt_ignore_ca_certs); i++)
			printf("  %d: %s\n", i, X509_NAME_oneline(X509_get_subject_name(cert[i]),
					namebuf, sizeof(namebuf)));
	}

	r = sc_pkcs15_convert_prkey(&args.key, pkey);
	if (r < 0)
		return r;
	init_gost_params(&args.params.gost, pkey);

	if (ncerts) {
		unsigned int	usage;

		/* tell openssl to cache the extensions */
		X509_check_purpose(cert[0], -1, -1);
		usage = X509_get_key_usage(cert[0]);

		/* No certificate usage? Assume ordinary
		 * user cert */
		if (usage == 0)
			usage = KU_NON_REPUDIATION
				| KU_DIGITAL_SIGNATURE
				| KU_KEY_ENCIPHERMENT;

		/* If the user requested a specific key usage on the
		 * command line check if it includes _more_
		 * usage bits than the one specified by the cert,
		 * and complain if it does.
		 * If the usage specified on the command line
		 * is more restrictive, use that.
		 */
		if (~usage & opt_x509_usage) {
			fprintf(stderr,
			    "Warning: requested key usage incompatible with "
			    "key usage specified by X.509 certificate\n");
		}

		args.x509_usage = opt_x509_usage? opt_x509_usage : usage;
	}

	args.access_flags |= SC_PKCS15_PRKEY_ACCESS_SENSITIVE;

	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_store_private_key(g_p15card, profile, &args, NULL);
	if (r < 0) {
		sc_unlock(g_p15card->card);
		return r;
	}

	/* If there are certificate as well (e.g. when reading the
	 * private key from a PKCS #12 file) store them, too.
	 */
	for (i = 0; i < ncerts && r >= 0; i++) {
		struct sc_pkcs15init_certargs cargs;
		char	namebuf[SC_PKCS15_MAX_LABEL_SIZE-1];
		int cargs_label_needs_free = 0;

		if (i && opt_ignore_ca_certs)
			break;

		memset(&cargs, 0, sizeof(cargs));

		/* Encode the cert */
		if ((r = do_convert_cert(&cargs.der_encoded, cert[i])) < 0)
			return r;

		X509_check_purpose(cert[i], -1, -1);
		cargs.x509_usage = X509_get_key_usage(cert[i]);

		cargs.label = cert_common_name(cert[i]);
		if (!cargs.label)
			cargs.label = X509_NAME_oneline(X509_get_subject_name(cert[i]), namebuf, sizeof(namebuf));
		else
			cargs_label_needs_free = 1;

		/* Just the first certificate gets the same ID
		 * as the private key. All others get
		 * an ID of their own */
		if (i == 0) {
			cargs.id = args.id;
			if (opt_cert_label != 0) {
				if (cargs_label_needs_free)
					free((char *) cargs.label);
				cargs.label = opt_cert_label;
				cargs_label_needs_free = 0;
			}
		} else {
			if (is_cacert_already_present(&cargs)) {
				printf("Certificate #%d already present, not stored.\n", i);
				goto next_cert;
			}
			sc_pkcs15_inc_id(&args.id);
			cargs.id = args.id;
			cargs.authority = 1;
		}

		r = sc_pkcs15init_store_certificate(g_p15card, profile, &cargs, NULL);
next_cert:
		if (cargs_label_needs_free)
			free((char *) cargs.label);
		free(cargs.der_encoded.value);
	}

	/* No certificates - store the public key */
	if (ncerts == 0)
		r = do_store_public_key(profile, pkey);

	sc_unlock(g_p15card->card);
	return r;
}

/*
 * Check if the CA certificate is already present
 */
static int
is_cacert_already_present(struct sc_pkcs15init_certargs *args)
{
	sc_pkcs15_object_t	*objs[32];
	sc_pkcs15_cert_info_t	*cinfo;
	sc_pkcs15_cert_t	*cert;
	int			i, count, r;

	r = sc_pkcs15_get_objects(g_p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r <= 0)
		return 0;

	count = r;
	for (i = 0; i < count; i++) {
		cinfo = (sc_pkcs15_cert_info_t *) objs[i]->data;

		if (!cinfo->authority)
			continue;
		if (strncmp(args->label, objs[i]->label, sizeof objs[i]->label))
			continue;
		/* XXX we should also match the usage field here */

		/* Compare the DER representation of the certificates */
		r = sc_pkcs15_read_certificate(g_p15card, cinfo, &cert);
		if (r < 0 || !cert)
			continue;

		if (cert->data.len == args->der_encoded.len
				&& !memcmp(cert->data.value, args->der_encoded.value, cert->data.len)) {
			sc_pkcs15_free_certificate(cert);
			return 1;
		}

		sc_pkcs15_free_certificate(cert);
		cert=NULL;
	}

	return 0;
}

/*
 * Store a public key
 */
static int
do_store_public_key(struct sc_profile *profile, EVP_PKEY *pkey)
{
	struct sc_pkcs15init_pubkeyargs args;
	sc_pkcs15_object_t *dummy;
	int		r = 0;

	memset(&args, 0, sizeof(args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	args.label = (opt_pubkey_label != 0 ? opt_pubkey_label : opt_label);
	args.x509_usage = opt_x509_usage;

	if (pkey == NULL) {
		r = do_read_public_key(opt_infile, opt_format, &pkey);
	}
	if (r >= 0) {
		r = sc_pkcs15_convert_pubkey(&args.key, pkey);
		if (r >= 0)
			init_gost_params(&args.params.gost, pkey);
	}
	if (r >= 0) {
		r = sc_lock(g_p15card->card);
		if (r < 0)
			return r;
		r = sc_pkcs15init_store_public_key(g_p15card, profile, &args, &dummy);
		sc_unlock(g_p15card->card);
	}

	return r;
}

/*
 * Store a secret key
 */
static int
do_store_secret_key(struct sc_profile *profile)
{
	struct sc_pkcs15init_skeyargs args;
	unsigned int keybits;
	int r, algorithm = -1;

	if (!opt_secrkey_algo) {
		util_error("Specify secret key algorithm with --secret-key-algorithm");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if ((r = init_skeyargs(&args)) < 0)
		return r;

	algorithm = parse_alg_spec(alg_types_sym, opt_secrkey_algo, &keybits, 0);
	if (algorithm < 0) {
		util_error("Invalid symmetric key spec: \"%s\"", opt_secrkey_algo);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = do_read_data_object(opt_infile, &args.key.data, &args.key.data_len, (keybits+7) / 8);
	if (r < 0) {
		free(args.key.data);
		return r;
	}

	args.algorithm = algorithm;
	args.value_len = keybits;
	args.access_flags |= SC_PKCS15_PRKEY_ACCESS_SENSITIVE;

	r = sc_lock(g_p15card->card);
	if (r < 0) {
		free(args.key.data);
		return r;
	}
	r = sc_pkcs15init_store_secret_key(g_p15card, profile, &args, NULL);
	sc_unlock(g_p15card->card);
	free(args.key.data);
	return r;
}

/*
 * Download certificate to card
 */
static int
do_store_certificate(struct sc_profile *profile)
{
	struct sc_pkcs15init_certargs args;
	X509	*cert = NULL;
	int	r;

	memset(&args, 0, sizeof(args));

	if (opt_update_existing)
	       args.update = 1;

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);

	args.label = (opt_cert_label != 0 ? opt_cert_label : opt_label);
	args.authority = opt_authority;

	r = do_read_certificate(opt_infile, opt_format, &cert);
	if (r >= 0)
		r = do_convert_cert(&args.der_encoded, cert);
	if (r >= 0) {
		r = sc_lock(g_p15card->card);
		if (r < 0)
			return r;
		r = sc_pkcs15init_store_certificate(g_p15card, profile, &args, NULL);
		sc_unlock(g_p15card->card);
	}

	if (args.der_encoded.value)
		free(args.der_encoded.value);

	return r;
}

static int
do_read_check_certificate(sc_pkcs15_cert_t *sc_oldcert,
	const char *filename, const char *format, sc_pkcs15_der_t *newcert_raw)
{
	X509 *oldcert, *newcert;
	EVP_PKEY *oldpk, *newpk;
	int oldpk_type, newpk_type;
	const u8 *ptr;
	int r;

	/* Get the public key from the old cert */
	ptr = sc_oldcert->data.value;
	oldcert = d2i_X509(NULL, &ptr, sc_oldcert->data.len);

	if (oldcert == NULL)
		return SC_ERROR_INTERNAL;

	/* Read the new cert from file and get it's public key */
	r = do_read_certificate(filename, format, &newcert);
	if (r < 0) {
		X509_free(oldcert);
		return r;
	}

	oldpk = X509_get_pubkey(oldcert);
	newpk = X509_get_pubkey(newcert);

	oldpk_type = EVP_PKEY_base_id(oldpk);
	newpk_type = EVP_PKEY_base_id(newpk);

	/* Compare the public keys, there's no high level openssl function for this(?) */
	/* Yes there is in 1.0.2 and above EVP_PKEY_cmp */


	r = SC_ERROR_INVALID_ARGUMENTS;
	if (oldpk_type == newpk_type)
	{
#if  OPENSSL_VERSION_NUMBER >= 0x10002000L
		if (EVP_PKEY_cmp(oldpk, newpk) == 1)
			r = 0;
#else
		if ((oldpk_type == EVP_PKEY_DSA) &&
			!BN_cmp(EVP_PKEY_get0_DSA(oldpk)->p, EVP_PKEY_get0_DSA(newpk)->p) &&
			!BN_cmp(EVP_PKEY_get0_DSA(oldpk)->q, EVP_PKEY_get0_DSA(newpk)->q) &&
			!BN_cmp(EVP_PKEY_get0_DSA(oldpk)->g, EVP_PKEY_get0_DSA(newpk)->g))
				r = 0;
		else if ((oldpk_type == EVP_PKEY_RSA) &&
			!BN_cmp(EVP_PKEY_get0_RSA(oldpk)->n, EVP_PKEY_get0_RSA(newpk)->n) &&
			!BN_cmp(EVP_PKEY_get0_RSA(oldpk)->e, EVP_PKEY_get0_RSA(newpk)->e))
				r = 0;
#endif
	}

	EVP_PKEY_free(newpk);
	EVP_PKEY_free(oldpk);
	X509_free(oldcert);

	if (r == 0)
		r = do_convert_cert(newcert_raw, newcert);
	else
		util_error("the public keys in the old and new certificate differ");

	X509_free(newcert);

	return r;
}

/*
 * Update an existing certificate with a new certificate having
 * the same public key.
 */
static int
do_update_certificate(struct sc_profile *profile)
{
	sc_pkcs15_id_t id;
	sc_pkcs15_object_t *obj;
	sc_pkcs15_cert_info_t *certinfo;
	sc_pkcs15_cert_t *oldcert = NULL;
	sc_pkcs15_der_t newcert_raw;
	int r;

	if (opt_objectid == NULL) {
		util_error("no ID given for the cert: use --id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_pkcs15_format_id(opt_objectid, &id);

	if (sc_pkcs15_find_cert_by_id(g_p15card, &id, &obj) != 0) {
		util_error("Couldn't find the cert with ID %s\n", opt_objectid);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;

	certinfo = (sc_pkcs15_cert_info_t *) obj->data;
	r = sc_pkcs15_read_certificate(g_p15card, certinfo, &oldcert);
	if (r < 0)
		goto err;

	newcert_raw.value = NULL;
	r = do_read_check_certificate(oldcert, opt_infile, opt_format, &newcert_raw);
	sc_pkcs15_free_certificate(oldcert);
	if (r < 0)
		goto err;

	r = sc_pkcs15init_update_certificate(g_p15card, profile, obj,
		newcert_raw.value, newcert_raw.len);

	if (newcert_raw.value)
		free(newcert_raw.value);

err:
	sc_unlock(g_p15card->card);
	return r;
}

/*
 * Download data object to card
 */
static int
do_store_data_object(struct sc_profile *profile)
{
	struct sc_pkcs15init_dataargs args;
	unsigned char *data = NULL;
	size_t	datalen;
	int	r=0;

	memset(&args, 0, sizeof(args));
	sc_init_oid(&args.app_oid);

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	if (opt_authid)
		sc_pkcs15_format_id(opt_authid, &args.auth_id);
	args.label = opt_label;
	args.app_label = opt_application_name ? opt_application_name : "pkcs15-init";

	sc_format_oid(&args.app_oid, opt_application_id);
	if (opt_application_id && (args.app_oid.value[0] == -1))   {
		util_error("Invalid OID \"%s\"", opt_application_id);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = do_read_data_object(opt_infile, &data, &datalen, 0);
	if (r >= 0) {
		/* der_encoded contains the plain data, nothing DER encoded */
		args.der_encoded.value = data;
		args.der_encoded.len = datalen;
		r = sc_lock(g_p15card->card);
		if (r < 0) {
			free(data);
			return r;
		}
		r = sc_pkcs15init_store_data_object(g_p15card, profile, &args, NULL);
		sc_unlock(g_p15card->card);
	}

	free(data);
	return r;
}

/*
 * Run card specific sanity check procedure
 */
static int
do_sanity_check(struct sc_profile *profile)
{
	int r;
	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_sanity_check(g_p15card, profile);
	sc_unlock(g_p15card->card);
	return r;
}

static int cert_is_root(sc_pkcs15_cert_t *c)
{
	return (c->subject_len == c->issuer_len) &&
		(memcmp(c->subject, c->issuer, c->subject_len) == 0);
}

/* Check if the cert has a 'sibling' and return it's parent cert.
 * Should be made more efficient for long chains by caching the certs.
 */
static int get_cert_info(sc_pkcs15_card_t *myp15card, sc_pkcs15_object_t *certobj,
	int *has_sibling, int *stop, sc_pkcs15_object_t **issuercert)
{
	sc_pkcs15_cert_t *cert = NULL;
	sc_pkcs15_object_t *otherobj;
	sc_pkcs15_cert_t *othercert = NULL;
	int r;

	*issuercert = NULL;
	*has_sibling = 0;
	*stop = 0;

	r = sc_pkcs15_read_certificate(myp15card, (sc_pkcs15_cert_info_t *) certobj->data, &cert);
	if (r < 0)
		return r;

	if (cert_is_root(cert)) {
		*stop = 1; /* root -> no parent and hence no siblings */
		goto done;
	}
	for (otherobj = myp15card->obj_list; otherobj != NULL; otherobj = otherobj->next) {
		if ((otherobj == certobj) ||
			!((otherobj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_CERT))
				continue;
		if (othercert) {
			sc_pkcs15_free_certificate(othercert);
			othercert=NULL;
		}
		r = sc_pkcs15_read_certificate(myp15card, (sc_pkcs15_cert_info_t *) otherobj->data, &othercert);
		if (r < 0 || !othercert)
			goto done;
		if ((cert->issuer_len == othercert->subject_len) &&
			(memcmp(cert->issuer, othercert->subject, cert->issuer_len) == 0)) {
				/* parent cert found */
				*issuercert = otherobj;
				*stop = cert_is_root(othercert);
		}
		else if (!cert_is_root(othercert) && (cert->issuer_len == othercert->issuer_len) &&
			(memcmp(cert->issuer, othercert->issuer, cert->issuer_len) == 0)) {
				*has_sibling = 1;
				break;
		}
	}

done:
	sc_pkcs15_free_certificate(cert);
	if (othercert)
		sc_pkcs15_free_certificate(othercert);

	return r;
}

/* Delete object(s) by ID. The 'which' param can be any combination of
 * SC_PKCS15INIT_TYPE_PRKEY, SC_PKCS15INIT_TYPE_PUBKEY, SC_PKCS15INIT_TYPE_CERT
 * and SC_PKCS15INIT_TYPE_CHAIN. In the last case, every cert in the chain is
 * deleted, starting with the cert with ID 'id' and until a CA cert is
 * reached that certified other remaining certs on the card.
 */
static int do_delete_crypto_objects(sc_pkcs15_card_t *myp15card,
				struct sc_profile *profile,
				const sc_pkcs15_id_t *id,
				unsigned int which)
{
	sc_pkcs15_object_t *objs[10]; /* 1 priv + 1 pub + chain of at most 8 certs, should be enough */
	int i, r = 0, count = 0, del_cert = 0;

	if (which & SC_PKCS15INIT_TYPE_PRKEY) {
		sc_pkcs15_object_t *key_objs[0x10];

		r = sc_pkcs15_get_objects(myp15card, SC_PKCS15_TYPE_PRKEY, key_objs, 0x10);
		if (r < 0) {
			fprintf(stderr, "Private key enumeration failed: %s\n", sc_strerror(r));
			return r;
		}

		for (i = 0; i< r; i++)
			if (sc_pkcs15_compare_id(id, &((struct sc_pkcs15_prkey_info *)key_objs[i]->data)->id))
				objs[count++] = key_objs[i];

		if (!count)
			fprintf(stderr, "NOTE: couldn't find privkey %s to delete\n", sc_pkcs15_print_id(id));
	}

	if (which & SC_PKCS15INIT_TYPE_PUBKEY) {
	    if (sc_pkcs15_find_pubkey_by_id(myp15card, id, &objs[count]) != 0)
			fprintf(stderr, "NOTE: couldn't find pubkey %s to delete\n", sc_pkcs15_print_id(id));
		else
			count++;
	}

	if (which & SC_PKCS15INIT_TYPE_CERT) {
	    if (sc_pkcs15_find_cert_by_id(myp15card, id, &objs[count]) != 0)
			fprintf(stderr, "NOTE: couldn't find cert %s to delete\n", sc_pkcs15_print_id(id));
		else {
			count++;
			del_cert = 1;
		}
	}

	if (which & SC_PKCS15INIT_TYPE_SKEY) {
	    if (sc_pkcs15_find_skey_by_id(myp15card, id, &objs[count]) != 0)
			fprintf(stderr, "NOTE: couldn't find secrkey %s to delete\n", sc_pkcs15_print_id(id));
		else
			count++;
	}

	if (del_cert && ((which & SC_PKCS15INIT_TYPE_CHAIN) == SC_PKCS15INIT_TYPE_CHAIN)) {
		/* Get the cert chain, stop if there's a CA that is the issuer of
		 * other certs on this card */
		int has_sibling; /* siblings: certs having the same issuer */
		int stop;
		for( ; count < 10 ; count++) {
			r = get_cert_info(myp15card, objs[count - 1], &has_sibling, &stop, &objs[count]);
			if (r < 0)
				fprintf(stderr, "get_cert_info() failed: %s\n", sc_strerror(r));
			else if (has_sibling)
				fprintf(stderr, "Chain deletion stops with cert %s\n", sc_pkcs15_print_id(
					&((sc_pkcs15_cert_info_t *) objs[count - 1]->data)->id));
			else if (stop && (objs[count] != NULL))
				count++;
			if (stop || (objs[count] == NULL))
				break;
		}
		if (r < 0)
			count = -1; /* Something wrong -> don't delete anything */
	}

	for (i = 0; i < count; i++) {
		r = sc_pkcs15init_delete_object(myp15card, profile, objs[i]);
		if (r < 0) {
			fprintf(stderr, "Failed to delete object %d: %s\n", i, sc_strerror(r));
			break;
		}
	}

	return r < 0 ? r : count;
}

static int
do_delete_objects(struct sc_profile *profile, unsigned int myopt_delete_flags)
{
	int r = 0, count = 0;

	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;

	if (myopt_delete_flags & SC_PKCS15INIT_TYPE_DATA) {
		struct sc_object_id app_oid;
		sc_pkcs15_object_t *obj = NULL;

		if (opt_application_id != NULL) {
			sc_format_oid(&app_oid, opt_application_id);

			r = sc_pkcs15_find_data_object_by_app_oid(g_p15card, &app_oid, &obj);
		}
		else if (opt_application_name != NULL && opt_label != NULL) {
			r = sc_pkcs15_find_data_object_by_name(g_p15card, opt_application_name, opt_label, &obj);
		}
		else {
			util_fatal("Specify the --application-id or --application-name and --label for the data object to be deleted\n");
		}

		if (r >= 0) {
			r = sc_pkcs15init_delete_object(g_p15card, profile, obj);
			if (r >= 0)
				count++;
		}
	}

	if (myopt_delete_flags & (SC_PKCS15INIT_TYPE_PRKEY | SC_PKCS15INIT_TYPE_PUBKEY | SC_PKCS15INIT_TYPE_CHAIN | SC_PKCS15INIT_TYPE_SKEY)) {
		sc_pkcs15_id_t id;
		if (opt_objectid == NULL)
				util_fatal("Specify the --id for key(s) or cert(s) to be deleted\n");
		sc_pkcs15_format_id(opt_objectid, &id);

		r = do_delete_crypto_objects(g_p15card, profile, &id, myopt_delete_flags);
		if (r >= 0)
			count += r;
	}

	sc_unlock(g_p15card->card);
	printf("Deleted %d objects\n", count);

	return r;
}

static int
do_change_attributes(struct sc_profile *profile, unsigned int myopt_type)
{
	int r = 0;
	sc_pkcs15_id_t id;
	sc_pkcs15_object_t *obj = NULL;

	if (opt_objectid == NULL) {
		printf("You have to specify the --id of the object\n");
		return 0;
	}
	sc_pkcs15_format_id(opt_objectid, &id);

	/* Right now, only changing the label is supported */
	if (opt_label == NULL) {
		printf("You should specify a --label\n");
		return 0;
	}

	switch(myopt_type) {
		case SC_PKCS15INIT_TYPE_PRKEY:
		    if ((r = sc_pkcs15_find_prkey_by_id(g_p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_PUBKEY:
		    if ((r = sc_pkcs15_find_pubkey_by_id(g_p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_CERT:
		    if ((r = sc_pkcs15_find_cert_by_id(g_p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_DATA:
		    if ((r = sc_pkcs15_find_data_object_by_id(g_p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_SKEY:
		    if ((r = sc_pkcs15_find_skey_by_id(g_p15card, &id, &obj)) != 0)
				return r;
			break;
	}

	if (obj == NULL) {
		printf("No object of the specified type and with id = \"%s\" found\n", opt_objectid);
		return 0;
	}

	if (opt_label != NULL) {
		strlcpy(obj->label, opt_label, sizeof(obj->label));
	}

	r = sc_lock(g_p15card->card);
	if (r < 0)
		return r;
	r = sc_pkcs15init_update_any_df(g_p15card, profile, obj->df, 0);
	sc_unlock(g_p15card->card);

	return r;
}

/*
 * Generate a new private key
 */
static int
do_generate_key(struct sc_profile *profile, const char *spec)
{
	struct sc_pkcs15init_keygen_args keygen_args;
	unsigned int keybits = 0;
	int r, algorithm = -1;

	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.pubkey_label = opt_pubkey_label;

	if ((r = init_prkeyargs(&keygen_args.prkey_args)) < 0)
		return r;

	algorithm = parse_alg_spec(alg_types_asym, spec, &keybits, &keygen_args.prkey_args.key);
	if (algorithm < 0) {
		util_error("Invalid key spec: \"%s\"", spec);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	keygen_args.prkey_args.key.algorithm = algorithm;
	keygen_args.prkey_args.access_flags |=
		  SC_PKCS15_PRKEY_ACCESS_SENSITIVE
		| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
		| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
		| SC_PKCS15_PRKEY_ACCESS_LOCAL;

	switch (algorithm) {
	case SC_ALGORITHM_GOSTR3410:
		/* FIXME: now only SC_PKCS15_PARAMSET_GOSTR3410_A */
		keygen_args.prkey_args.params.gost.gostr3410 = SC_PKCS15_PARAMSET_GOSTR3410_A;
		break;
	}

	r = sc_lock(g_p15card->card);
	if (r == 0)
		r = sc_pkcs15init_generate_key(g_p15card, profile, &keygen_args, keybits, NULL);
	sc_unlock(g_p15card->card);
	return r;
}

/*
 * Generate a new secret key
 */
static int
do_generate_skey(struct sc_profile *profile, const char *spec)
{
	struct sc_pkcs15init_skeyargs skey_args;
	unsigned int keybits;
	int r, algorithm = -1;

	if ((r = init_skeyargs(&skey_args)) < 0)
		return r;
	skey_args.algorithm = algorithm;

	algorithm = parse_alg_spec(alg_types_sym, spec, &keybits, 0);
	if (algorithm < 0) {
		util_error("Invalid symmetric key spec: \"%s\"", spec);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	skey_args.value_len = keybits;

	r = sc_lock(g_p15card->card);
	if (r == 0)
		r = sc_pkcs15init_generate_secret_key(g_p15card, profile, &skey_args, NULL);
	sc_unlock(g_p15card->card);
	return r;
}

static int init_prkeyargs(struct sc_pkcs15init_prkeyargs *args)
{
	memset(args, 0, sizeof(*args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args->id);
	if (opt_authid) {
		sc_pkcs15_format_id(opt_authid, &args->auth_id);
	} else if (!opt_insecure) {
		util_error("no PIN given for key - either use --insecure or \n"
				"specify a PIN using --auth-id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_extractable) {
		args->access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
	}
	args->label = opt_label;
	args->x509_usage = opt_x509_usage;

	if (opt_md_container_guid)   {
		args->guid = (unsigned char *)opt_md_container_guid;
		args->guid_len = strlen(opt_md_container_guid);
	}
	args->user_consent = opt_user_consent;

	return 0;
}

static int init_skeyargs(struct sc_pkcs15init_skeyargs *args)
{
	memset(args, 0, sizeof(*args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args->id);
	if (opt_authid) {
		sc_pkcs15_format_id(opt_authid, &args->auth_id);
	} else if (!opt_insecure) {
		util_error("no PIN given for key - either use --insecure or \n"
				"specify a PIN using --auth-id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_extractable) {
		args->access_flags |= SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
	}
	args->label = opt_label;

	if ((opt_x509_usage & SC_PKCS15INIT_X509_DATA_ENCIPHERMENT) == SC_PKCS15INIT_X509_DATA_ENCIPHERMENT) {
	    args->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT | SC_PKCS15_PRKEY_USAGE_DECRYPT;
	}

	if ((opt_x509_usage & SC_PKCS15INIT_X509_KEY_ENCIPHERMENT) == SC_PKCS15INIT_X509_KEY_ENCIPHERMENT) {
	    args->usage |= SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_UNWRAP;
	}
	args->user_consent = opt_user_consent;

	return 0;
}

static void
init_gost_params(struct sc_pkcs15init_keyarg_gost_params *params, EVP_PKEY *pkey)
{
#if !defined(OPENSSL_NO_EC)
	EC_KEY *key;

	assert(pkey);
	if (EVP_PKEY_id(pkey) == NID_id_GostR3410_2001) {
		key = EVP_PKEY_get0(pkey);
		assert(key);
		assert(params);
		assert(EC_KEY_get0_group(key));
		assert(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)) > 0);
		switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(key))) {
		case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
			params->gostr3410 = SC_PKCS15_PARAMSET_GOSTR3410_A;
			break;
		case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
			params->gostr3410 = SC_PKCS15_PARAMSET_GOSTR3410_B;
			break;
		case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
			params->gostr3410 = SC_PKCS15_PARAMSET_GOSTR3410_C;
			break;
		}
	}
#else
	(void)params, (void)pkey; /* no warning */
#endif
}

/*
 * Intern secrets given on the command line (mostly for testing)
 */
static void
parse_secret(struct secret *secret, const char *arg)
{
	char		*copy, *str, *value;
	size_t		len;

	str = copy = strdup(arg);
	if (!(value = strchr(str, '=')))
		goto parse_err;
	*value++ = '\0';

	if (*str == '@') {
		sc_pkcs15_format_id(str+1, &secret->id);
		secret->type = SC_AC_CHV;
		secret->reference = -1;
	} else {
		if (strncasecmp(str, "chv", 3))
			secret->type = SC_AC_CHV;
		else if (strncasecmp(str, "aut", 3))
			secret->type = SC_AC_AUT;
		else if (strncasecmp(str, "pro", 3))
			secret->type = SC_AC_PRO;
		else
			goto parse_err;
		str += 3;
		if (!isdigit(str[3]))
			goto parse_err;
		secret->reference = strtoul(str, &str, 10);
		if (*str != '\0')
			goto parse_err;
	}
	if ((len = strlen(value)) < 3 || value[2] != ':') {
		memcpy(secret->key, value, len);
	} else {
		len = sizeof(secret->key);
		if (sc_hex_to_bin(value, secret->key, &len) < 0)
			goto parse_err;
	}
	secret->len = len;
	free(copy);
	return;

parse_err:
	util_fatal("Cannot parse secret \"%s\"\n", arg);
}


/*
 * Prompt for a new PIN
 * @role can be "user" or "so"
 * @usage can be "pin" or "puk"
 */
static int get_new_pin(sc_ui_hints_t *hints,
		const char *role, const char *usage,
		char **retstr)
{
	char	name[32], prompt[64], label[64];

	snprintf(name, sizeof(name), "pkcs15init.new_%s_%s", role, usage);

	if (!strcmp(role, "user"))
		role = "User";
	else
		role = "Security Officer";

	if (!strcmp(usage, "pin")) {
		snprintf(prompt, sizeof(prompt), "New %s PIN", role);
		snprintf(label, sizeof(label), "%s PIN", role);
	} else {
		snprintf(prompt, sizeof(prompt),
			"Unblock Code for New %s PIN", role);
		snprintf(label, sizeof(label),
			"%s unblocking PIN (PUK)", role);
	}

	hints->dialog_name	= name;
	hints->prompt		= prompt;
	hints->obj_label	= label;

	return get_pin(hints, retstr);
}

/*
 * PIN retrieval callback
 */
static int
get_pin_callback(struct sc_profile *profile,
		int id, const struct sc_pkcs15_auth_info *info,
		const char *label,
		u8 *pinbuf, size_t *pinsize)
{
	char	namebuf[64];
	char	*secret = NULL;
	const char *name = NULL;
	size_t	len = 0;
	int	allocated = 0;

	if (info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_NOT_SUPPORTED;

	if (label)
		snprintf(namebuf, sizeof(namebuf), "PIN [%s]", label);
	else
		snprintf(namebuf, sizeof(namebuf), "Unspecified PIN [reference %u]", info->attrs.pin.reference);

	if (!ignore_cmdline_pins) {
		if (info->auth_method == SC_AC_SYMBOLIC)   {
			switch (id) {
			case SC_PKCS15INIT_USER_PIN:
				name = "User PIN";
				secret = (char *) opt_pins[OPT_PIN1 & 3];
				break;
			case SC_PKCS15INIT_USER_PUK:
				name = "User PIN unlock key";
				secret = (char *) opt_pins[OPT_PUK1 & 3];
				break;
			case SC_PKCS15INIT_SO_PIN:
				name = "Security officer PIN";
				secret = (char *) opt_pins[OPT_PIN2 & 3];
				break;
			case SC_PKCS15INIT_SO_PUK:
				name = "Security officer PIN unlock key";
				secret = (char *) opt_pins[OPT_PUK2 & 3];
				break;
			}
		}
		else if (info->auth_method == SC_AC_CHV)   {
			if (!(info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
					&& !(info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))    {
				name = "User PIN";
				secret = (char *) opt_pins[OPT_PIN1 & 3];
			}
			else if (!(info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
					&& (info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))    {
				name = "User PUK";
				secret = (char *) opt_pins[OPT_PUK1 & 3];
			}
			else if ((info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
					&& !(info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))    {
				name = "Security officer PIN";
				secret = (char *) opt_pins[OPT_PIN2 & 3];
			}
			else if ((info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
					&& (info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))    {
				name = "Security officer PIN unlock key";
				secret = (char *) opt_pins[OPT_PUK2 & 3];
			}
		}
		if (secret)
			len = strlen(secret);
	}

	if (name && label)
		snprintf(namebuf, sizeof(namebuf), "%s [%s]", name, label);
	else if (name)
		snprintf(namebuf, sizeof(namebuf), "%s", name);

	name = namebuf;

	/* See if we were given --secret @ID=.... */
	if (!secret) {
		unsigned int	n;

		for (n = 0; n < opt_secret_count; n++) {
			struct secret	*s = &opt_secrets[n];

			if (sc_pkcs15_compare_id(&info->auth_id, &s->id)) {
				secret = (char *) s->key;
				len = s->len;
				break;
			}
		}
	}

	if (!secret) {
		sc_ui_hints_t	hints;
		char		prompt[128];
		int		r;

		if (opt_use_pinpad)
			return SC_ERROR_OBJECT_NOT_FOUND;

		snprintf(prompt, sizeof(prompt), "%s required", name);

		memset(&hints, 0, sizeof(hints));
		hints.dialog_name = "pkcs15init.get_pin";
		hints.prompt	= prompt;
		hints.obj_label	= name;
		hints.usage	= SC_UI_USAGE_OTHER;
		hints.card	= g_card;
		hints.p15card	= g_p15card;

		if ((r = get_pin(&hints, &secret)) < 0) {
			if (secret) {
				sc_mem_clear(secret, strlen(secret));
				free(secret);
			}
			fprintf(stderr,
				"Failed to read PIN from user: %s\n",
				sc_strerror(r));
			return r;
		}

		len = strlen(secret);
		allocated = 1;
	}

	if (len > *pinsize) {
		if (allocated)
			free(secret);
		return SC_ERROR_BUFFER_TOO_SMALL;
	}
	memcpy(pinbuf, secret, len + 1);
	*pinsize = len;
	if (allocated)
		free(secret);
	return 0;
}


static int
get_key_callback(struct sc_profile *profile,
			int method, int reference,
			const u8 *def_key, size_t def_key_size,
			u8 *key_buf, size_t *buf_size)
{
	const char	*kind, *prompt, *key = NULL;

	if (def_key_size && opt_use_defkeys) {
		if (*buf_size < def_key_size)
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(key_buf, def_key, def_key_size);
		*buf_size = def_key_size;
		return 0;
	}

	switch (method) {
	case SC_AC_PRO:
		kind = "Secure messaging key";
		break;
	case SC_AC_AUT:
		kind = "External authentication key";
		break;
	default: /* don't really know what sort of key */
		kind = "Key";
		break;
	}

	printf("Transport key (%s #%d) required.\n", kind, reference);
	if (opt_use_pinpad) {
		printf("\n"
		"Refusing to prompt for transport key because --use-pinpad\n"
		"was specified on the command line. Please invoke without\n"
		"--no-prompt, or specify the --use-default-transport-keys\n"
		"option to use the default transport keys without being\n"
		"prompted.\n");
		fprintf(stderr, "Aborting.\n");
		exit(1);
	}

	printf("Please enter key in hexadecimal notation "
	       "(e.g. 00:11:22:aa:bb:cc)%s.\n\n",
	       def_key_size? ",\nor press return to accept default" : "");
	printf("To use the default transport keys without being prompted,\n"
	       "specify the --use-default-transport-keys option on the\n"
	       "command line (or -T for short), or press Ctrl-C to abort.\n");

	while (1) {
		char	buffer[256];

		prompt = "Please enter key";
		if (def_key_size && def_key_size < 64) {
			unsigned int	j, k = 0;

			sprintf(buffer, "%s [", prompt);
			k = strlen(buffer);
			for (j = 0; j < def_key_size; j++, k += 2) {
				if (j) buffer[k++] = ':';
				sprintf(buffer+k, "%02x", def_key[j]);
			}
			buffer[k++] = ']';
			buffer[k++] = '\0';
			prompt = buffer;
		}

		printf("%s: ", prompt);
		fflush(stdout);
#ifdef GET_KEY_ECHO_OFF
		do {
			size_t len = 0;
			int r;

			/* Read key with echo off - will users really manage? */
			r = util_getpass(&key, &len, stdin);
			if (r < 0 || !key)
				return SC_ERROR_INTERNAL;
		} while(0);
#else
		key = fgets(buffer, sizeof(buffer), stdin);
		if (key)
			buffer[strcspn(buffer, "\r\n")] = '\0';
#endif
		if (key == NULL)
			return SC_ERROR_INTERNAL;

		if (key[0] == '\0' && def_key_size)   {
			if (*buf_size < def_key_size)
				return SC_ERROR_BUFFER_TOO_SMALL;
			memcpy(key_buf, def_key, def_key_size);
			*buf_size = def_key_size;
			return 0;
		}

		if (sc_hex_to_bin(key, key_buf, buf_size) >= 0)
			return 0;
	}
}

/*
 * Read a private key
 */
static int pass_cb(char *buf, int len, int flags, void *d)
{
	size_t pass_len = 0;
	int  plen, r;
	char *pass = (char *)d;

	if (!pass)   {
		printf("Please enter passphrase to unlock secret key: ");
		r = util_getpass(&pass, &pass_len, stdin);
		if (r < 0 || !pass)
			return 0;
	}

	plen = strlen(pass);
	if (plen <= 0)
		return 0;
	if (plen > len)
		plen = len;
	memcpy(buf, pass, plen);
	return plen;
}

static int
do_read_pem_private_key(const char *filename, const char *passphrase,
			EVP_PKEY **key)
{
	BIO	*bio;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	*key = PEM_read_bio_PrivateKey(bio, NULL, pass_cb, (char *) passphrase);
	BIO_free(bio);
	if (*key == NULL) {
		ossl_print_errors();
		return SC_ERROR_CANNOT_LOAD_KEY;
	}
	return 0;
}

static int
do_read_pkcs12_private_key(const char *filename, const char *passphrase,
			EVP_PKEY **key, X509 **certs, unsigned int max_certs)
{
	BIO		*bio;
	PKCS12		*p12;
	EVP_PKEY	*user_key = NULL;
	X509		*user_cert = NULL;
	STACK_OF(X509)	*cacerts = NULL;
	int		i, ncerts = 0;

	*key = NULL;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);

	if (p12 == NULL
	 || !PKCS12_parse(p12, passphrase, &user_key, &user_cert, &cacerts))
		goto error;

	if (!user_key) {
		util_error("No key in pkcs12 file?!\n");
		return SC_ERROR_CANNOT_LOAD_KEY;
	}

	EVP_PKEY_up_ref(user_key);

	if (user_cert && max_certs)
		certs[ncerts++] = user_cert;

	/* Extract CA certificates, if any */
	for(i = 0; cacerts && ncerts < (int)max_certs && i < sk_X509_num(cacerts); i++)
		certs[ncerts++] = sk_X509_value(cacerts, i);

	/* bump reference counts for certificates */
	for (i = 0; i < ncerts; i++) {
		X509_up_ref(certs[i]);
	}

	if (cacerts)
		sk_X509_free(cacerts);

	*key = user_key;
	return ncerts;

error:	ossl_print_errors();
	return SC_ERROR_CANNOT_LOAD_KEY;
}

static int
do_read_private_key(const char *filename, const char *format,
			EVP_PKEY **pk, X509 **certs, unsigned int max_certs)
{
	size_t len = 0;
	char	*passphrase = NULL;
	int	r;

	if (opt_passphrase)
		passphrase = (char *) opt_passphrase;

	if (!format || !strcasecmp(format, "pem")) {
		r = do_read_pem_private_key(filename, passphrase, pk);
	} else if (!strcasecmp(format, "pkcs12")) {
		r = do_read_pkcs12_private_key(filename,
				passphrase, pk, certs, max_certs);
		if (r < 0 && !passphrase) {
			/* this makes only sense for PKCS#12
			 * PKCS12_parse must support passphrases with
			 * length zero and NULL because of the specification
			 * of PKCS12 - please see the sourcecode of OpenSSL
			 * therefore OpenSSL does not ask for a passphrase like
			 * the PEM interface
			 * see OpenSSL: crypto/pkcs12/p12_kiss.c
			 */
			printf("Please enter passphrase to unlock secret key: ");
			r = util_getpass(&passphrase, &len, stdin);
			if (r < 0 || !passphrase)
				return SC_ERROR_INTERNAL;
			r = do_read_pkcs12_private_key(filename,
					passphrase, pk, certs, max_certs);
		}
	} else {
		util_error("Error when reading private key. "
		      "Key file format \"%s\" not supported.\n", format);
		return SC_ERROR_NOT_SUPPORTED;
	}

	if (NULL == opt_passphrase)
		free(passphrase);

	if (r < 0)
		util_fatal("Unable to read private key from %s\n", filename);

	return r;
}

/*
 * Read a public key
 */
static EVP_PKEY *
do_read_pem_public_key(const char *filename)
{
	BIO		*bio;
	EVP_PKEY	*pk;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	pk = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (pk == NULL)
		ossl_print_errors();
	return pk;
}

static EVP_PKEY *
do_read_der_public_key(const char *filename)
{
	BIO	*bio;
	EVP_PKEY *pk;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	pk = d2i_PUBKEY_bio(bio, NULL);
	BIO_free(bio);
	if (pk == NULL)
		ossl_print_errors();
	return pk;
}

static int
do_read_public_key(const char *name, const char *format, EVP_PKEY **out)
{
	if (!format || !strcasecmp(format, "pem")) {
		*out = do_read_pem_public_key(name);
	} else if (!strcasecmp(format, "der")) {
		*out = do_read_der_public_key(name);
	} else {
		util_fatal("Error when reading public key. "
		      "File format \"%s\" not supported.\n",
		      format);
	}

	if (!*out)
		util_fatal("Unable to read public key from %s\n", name);
	return 0;
}

/*
 * Read a certificate
 */
static X509 *
do_read_pem_certificate(const char *filename)
{
	BIO	*bio;
	X509	*xp;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	xp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (xp == NULL)
		ossl_print_errors();
	return xp;
}

static X509 *
do_read_der_certificate(const char *filename)
{
	BIO	*bio;
	X509	*xp;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) <= 0)
		util_fatal("Unable to open %s: %m", filename);
	xp = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	if (xp == NULL)
		ossl_print_errors();
	return xp;
}

static int
do_read_certificate(const char *name, const char *format, X509 **out)
{
	if (!format || !strcasecmp(format, "pem")) {
		*out = do_read_pem_certificate(name);
	} else if (!strcasecmp(format, "der")) {
		*out = do_read_der_certificate(name);
	} else {
		util_fatal("Error when reading certificate. "
		      "File format \"%s\" not supported.\n",
		      format);
	}

	if (!*out)
		util_fatal("Unable to read certificate from %s\n", name);
	return 0;
}

static size_t determine_filesize(const char *filename)
{
	FILE *fp;
	long ll;

	if ((fp = fopen(filename,"rb")) == NULL)
		util_fatal("Unable to open %s: %m", filename);

	fseek(fp,0L,SEEK_END);
	ll = ftell(fp);
	if (ll == -1l)
		util_fatal("fseek/ftell error");

	fclose(fp);
	return (size_t)ll;
}

static int
do_read_data_object(const char *name, u8 **out, size_t *outlen, size_t expected)
{
	FILE *inf;
	size_t filesize = expected ? expected : determine_filesize(name);
	int c;

	*out = malloc(filesize);
	if (*out == NULL)
		return SC_ERROR_OUT_OF_MEMORY;


        inf = fopen(name, "rb");
        if (inf == NULL) {
                fprintf(stderr, "Unable to open '%s' for reading.\n", name);
                return SC_ERROR_FILE_NOT_FOUND;
        }
        c = fread(*out, 1, filesize, inf);
        fclose(inf);
        if (c < 0) {
                perror("read");
                return SC_ERROR_FILE_NOT_FOUND;
        }

	*outlen = filesize;
	return SC_SUCCESS;
}

static char *
cert_common_name(X509 *x509)
{
	X509_NAME_ENTRY *ne = NULL;
	ASN1_STRING *a_str = NULL;
	char *out = NULL;
	unsigned char *tmp = NULL;
	int idx, out_len = 0;

	idx = X509_NAME_get_index_by_NID(X509_get_subject_name(x509), NID_commonName, -1);
	if (idx < 0)
		return NULL;

	ne = X509_NAME_get_entry(X509_get_subject_name(x509), idx);
	if (!ne)
	       return NULL;

	a_str = X509_NAME_ENTRY_get_data(ne);
	if (!a_str)
		return NULL;

	out_len = ASN1_STRING_to_UTF8(&tmp, a_str);
	if (!tmp)
		return NULL;

	out = calloc(1, out_len + 1);
	if (out)
		memcpy(out, tmp, out_len);
	OPENSSL_free(tmp);

	return out;
}


static int do_convert_cert(sc_pkcs15_der_t *der, X509 *cert)
{
	u8	*p;

	der->len = i2d_X509(cert, NULL);
	der->value = p = malloc(der->len);
	i2d_X509(cert, &p);
	return 0;
}

static unsigned int
parse_objects(const char *list, unsigned int action)
{
	unsigned int res = 0;
	static struct {
		const char	*name;
		unsigned int	flag;
	}	del_flags[] = {
		{"privkey", SC_PKCS15INIT_TYPE_PRKEY},
		{"pubkey", SC_PKCS15INIT_TYPE_PUBKEY},
		{"cert", SC_PKCS15INIT_TYPE_CERT},
		{"chain", SC_PKCS15INIT_TYPE_CHAIN},
		{"data", SC_PKCS15INIT_TYPE_DATA},
		{"secrkey", SC_PKCS15INIT_TYPE_SKEY},
		{NULL, 0}
	};

	while (1) {
		int	len, n;

		while (*list == ',')
			list++;
		if (!*list)
			break;
		len = strcspn(list, ",");
		if (len == 4 && !strncasecmp(list, "help", 4)) {
			if (action == ACTION_DELETE_OBJECTS) {
				printf("\nDelete arguments: a comma-separated list containing any of the following:\n");
				printf("  privkey,pubkey,secrkey,cert,chain,data\n");
				printf("When \"data\" is specified, an --application-id must also be specified,\n");
				printf("  in the other cases an \"--id\" must also be specified\n");
				printf("When \"chain\" is specified, the certificate chain starting with the cert\n");
				printf("  with specified ID will be deleted, until there's a CA cert that certifies\n");
				printf("  another cert on the card\n");
			}
			else {
				printf("\nChange attribute argument: either privkey, pubkey, secrkey, cert or data\n");
				printf("You also have to specify the --id of the object\n");
				printf("For now, you can only change the --label\n");
				printf("E.g. pkcs15-init -A cert --id 45 -a 1 --label Jim\n");
			}
			exit(0);
		}
		for (n = 0; del_flags[n].name; n++) {
			if (!strncasecmp(del_flags[n].name, list, len)) {
				res |= del_flags[n].flag;
				break;
			}
		}
		if (del_flags[n].name == NULL) {
			fprintf(stderr, "Unknown argument for --delete-objects: %.*s\n", len, list);
			exit(0);
		}
		list += len;
	}

	return res;
}

/*
 * Parse X.509 key usage list
 */
static void
parse_x509_usage(const char *list, unsigned int *res)
{
	static struct {
		const char* name;
		unsigned int flag;
	} x509_usage_names[] = {
		{ "digitalSignature", SC_PKCS15INIT_X509_DIGITAL_SIGNATURE },
		{ "nonRepudiation",   SC_PKCS15INIT_X509_NON_REPUDIATION   },
		{ "keyEncipherment",  SC_PKCS15INIT_X509_KEY_ENCIPHERMENT  },
		{ "dataEncipherment", SC_PKCS15INIT_X509_DATA_ENCIPHERMENT },
		{ "keyAgreement",     SC_PKCS15INIT_X509_KEY_AGREEMENT     },
		{ "keyCertSign",      SC_PKCS15INIT_X509_KEY_CERT_SIGN     },
		{ "cRLSign",          SC_PKCS15INIT_X509_CRL_SIGN          },
		{ NULL, 0 }
	};
	static struct {
		const char *	name;
		const char *	list;
	}			x509_usage_aliases[] = {
	 { "sign",	"digitalSignature,keyCertSign,cRLSign" },
	 { "decrypt",	"keyEncipherment,dataEncipherment" },
	 { NULL, NULL }
	};

	while (1) {
		int	len, n, match = 0;

		while (*list == ',')
			list++;
		if (!*list)
			break;
		len = strcspn(list, ",");
		if (len == 4 && !strncasecmp(list, "help", 4)) {
			printf("Valid X.509 usage names (case-insensitive):\n");
			for (n = 0; x509_usage_names[n].name; n++)
				printf("  %s\n", x509_usage_names[n].name);
			printf("\nAliases:\n");
			for (n = 0; x509_usage_aliases[n].name; n++) {
				printf("  %-12s %s\n",
					x509_usage_aliases[n].name,
					x509_usage_aliases[n].list);
			}
			printf("\nUse commas to separate several usage names.\n"
			       "Abbreviated names are okay if unique (e.g. dataEnc)\n");
			exit(0);
		}
		for (n = 0; x509_usage_names[n].name != NULL; n++) {
			if (!strncasecmp(x509_usage_names[n].name, list, len)) {
				*res |= x509_usage_names[n].flag;
				match++;
			}
		}
		for (n = 0; x509_usage_aliases[n].name; n++) {
			if (!strncasecmp(x509_usage_aliases[n].name, list, len)) {
				parse_x509_usage(x509_usage_aliases[n].list, res);
				match++;
			}
		}
		if (match == 0) {
			fprintf(stderr,
				"Unknown X.509 key usage %.*s\n", len, list);
			exit(1);
		}
		if (match > 1) {
			fprintf(stderr,
				"Ambiguous X.509 key usage %.*s\n", len, list);
			exit(1);
		}
		list += len;
	}
}

/*
 * Handle one option
 */
static void
handle_option(const struct option *opt)
{
	unsigned int	this_action = ACTION_NONE;

	switch (opt->val) {
	case 'a':
		opt_authid = optarg;
		break;
	case 'C':
		this_action = ACTION_INIT;
		break;
	case 'E':
		this_action = ACTION_ERASE;
		break;
	case 'G':
		this_action = ACTION_GENERATE_KEY;
		opt_newkey = optarg;
		break;
	case 'S':
		this_action = ACTION_STORE_PRIVKEY;
		opt_infile = optarg;
		break;
	case 'P':
		this_action = ACTION_STORE_PIN;
		break;
	case 'X':
		this_action = ACTION_STORE_CERT;
		opt_infile = optarg;
		break;
	case 'U':
		this_action = ACTION_UPDATE_CERT;
		opt_infile = optarg;
		break;
	case 'W':
		this_action = ACTION_STORE_DATA;
		opt_infile = optarg;
		break;
	case 'D':
		this_action = ACTION_DELETE_OBJECTS;
		opt_delete_flags = parse_objects(optarg, ACTION_DELETE_OBJECTS);
		break;
	case 'A':
		this_action = ACTION_CHANGE_ATTRIBUTES;
		opt_type = parse_objects(optarg, ACTION_CHANGE_ATTRIBUTES);
		break;
	case 'v':
		verbose++;
		break;
	case 'f':
		opt_format = optarg;
		break;
	case 'h':
		util_print_usage_and_die(app_name, options, option_help, NULL);
		/* exit */
	case 'i':
		opt_objectid = optarg;
		break;
	case 'l':
		opt_label = optarg;
		break;
	case 'o':
		opt_outkey = optarg;
		break;
	case 'p':
		opt_profile = optarg;
		break;
	case 'c':
		opt_card_profile = optarg;
		break;
	case 'r':
		opt_reader = optarg;
		break;
	case 'u':
		parse_x509_usage(optarg, &opt_x509_usage);
		break;
	case 'w':
		opt_wait = 1;
		break;
	case OPT_PIN1: case OPT_PUK1:
	case OPT_PIN2: case OPT_PUK2:
		util_get_pin(optarg, &(opt_pins[opt->val & 3]));
		break;
	case OPT_SERIAL:
		opt_serial = optarg;
		break;
	case OPT_PASSPHRASE:
		util_get_pin(optarg, &opt_passphrase);
		break;
	case OPT_PUBKEY:
		this_action = ACTION_STORE_PUBKEY;
		opt_infile = optarg;
		break;
	case OPT_SECRKEY:
		this_action = ACTION_STORE_SECRKEY;
		opt_infile = optarg;
		break;
	case OPT_INSECURE:
		opt_insecure = 1;
		break;
	case OPT_EXTRACTABLE:
		opt_extractable = 1;
		break;
	case OPT_AUTHORITY:
		opt_authority = 1;
		break;
	case OPT_APPLICATION_NAME:
		opt_application_name = optarg;
		break;
	case OPT_APPLICATION_ID:
		opt_application_id = optarg;
		break;
	case OPT_BIND_TO_AID:
		opt_bind_to_aid = optarg;
		break;
	case OPT_PUK_ID:
		opt_puk_authid = optarg;
		break;
	case OPT_PUK_LABEL:
		opt_puk_label = optarg;
		break;
	case 'T':
		opt_use_defkeys = 1;
		break;
	case OPT_NO_SOPIN:
		opt_no_sopin = 1;
		break;
	case OPT_USE_PINPAD_DEPRECATED:
		fprintf(stderr, "'--no-prompt' is deprecated , use '--use-pinpad' instead.\n");
		/* fall through */
	case OPT_USE_PINPAD:
		opt_use_pinpad = 1;
		break;
	case OPT_ASSERT_PRISTINE:
		this_action = ACTION_ASSERT_PRISTINE;
		break;
	case OPT_SECRET:
		parse_secret(&opt_secrets[opt_secret_count], optarg);
		opt_secret_count++;
		break;
	case OPT_SECRKEY_ALGO:
		opt_secrkey_algo = optarg;
		break;
	case OPT_PUBKEY_LABEL:
		opt_pubkey_label = optarg;
		break;
	case 'F':
		this_action = ACTION_FINALIZE_CARD;
		break;
	case OPT_CERT_LABEL:
		opt_cert_label = optarg;
		break;
	case OPT_VERIFY_PIN:
		opt_verify_pin = 1;
		break;
	case OPT_SANITY_CHECK:
		this_action = ACTION_SANITY_CHECK;
		break;
	case OPT_UPDATE_LAST_UPDATE:
		this_action = ACTION_UPDATE_LAST_UPDATE;
		break;
	case OPT_ERASE_APPLICATION:
		opt_bind_to_aid = optarg;
		this_action = ACTION_ERASE_APPLICATION;
		break;
	case OPT_IGNORE_CA_CERTIFICATES:
		opt_ignore_ca_certs = 1;
		break;
	case OPT_UPDATE_EXISTING:
		opt_update_existing = 1;
		break;
	case OPT_MD_CONTAINER_GUID:
		opt_md_container_guid = optarg;
		break;
	case OPT_VERSION:
		this_action = ACTION_PRINT_VERSION;
		break;
	case OPT_USER_CONSENT:
		if (optarg != NULL)
			opt_user_consent = atoi(optarg);
		break;
	default:
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}

	if ((opt_actions & (1 << this_action)) && opt->has_arg != no_argument) {
		fprintf(stderr, "Error: you cannot specify option");
		if (opt->name)
			fprintf(stderr, " --%s", opt->name);
		if (isprint(opt->val))
			fprintf(stderr, " -%c", opt->val);
		fprintf(stderr, " more than once.\n");
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}
	if (this_action)
		opt_actions |= (1 << this_action);

	if ((opt_pins[OPT_PIN2&3] || opt_pins[OPT_PUK2&3]) && opt_no_sopin) {
		fprintf(stderr, "Error: "
		"The --no-so-pin option and --so-pin/--so-puk are mutually"
		"exclusive.\n");
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}

	if ((opt_actions & (1 << ACTION_ERASE)) &&
		(opt_actions != (1 << ACTION_ERASE))) {
		fprintf(stderr, "Error: erasing a card is incompatible with all other actions\n");
		util_print_usage_and_die(app_name, options, option_help, NULL);
	}
}

/*
 * Parse the command line.
 */
static void
parse_commandline(int argc, char **argv)
{
	const struct option *o;
	char	shortopts[64], *sp;
	int	c, i;

	/* We make sure the list of short options is always
	 * consistent with the long options */
	for (o = options, sp = shortopts; o->name; o++) {
		if (o->val <= 0 || o->val >= 256)
			continue;
		*sp++ = o->val;
		switch (o->has_arg) {
		case optional_argument:
			*sp++ = ':';
			/* fall through */
		case required_argument:
			*sp++ = ':';
		case no_argument:
			break;
		default:
			util_fatal("Internal: bad has_arg value");
		}
	}
	sp[0] = 0;

	while ((c = getopt_long(argc, argv, shortopts, options, &i)) != -1) {
		/* The optindex seems to be off with some glibc
		 * getopt implementations */
		for (o = options; o->name; o++) {
			if (o->val == c) {
				handle_option(o);
				goto next;
			}
		}
		util_fatal("Internal error in options handling, option %u\n", c);

next: ;
	}
}

/*
 * OpenSSL helpers
 */
static void
ossl_print_errors(void)
{
	static int	loaded = 0;
	long		err;

	if (!loaded) {
		ERR_load_crypto_strings();
		loaded = 1;
	}

	while ((err = ERR_get_error()) != 0)
		fprintf(stderr, "%s\n", ERR_error_string(err, NULL));
}

/*
 * Retrieve a PIN from the user.
 *
 * @hints	dialog hints
 * @out		PIN entered by the user; must be freed.
 *		NULL if dialog was canceled.
 */
int get_pin(sc_ui_hints_t *hints, char **out)
{
	sc_pkcs15_auth_info_t *pin_info;
	const char	*label;
	int		flags = hints->flags;

	pin_info = hints->info.pin;
	if (pin_info && (pin_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN))
		return SC_ERROR_NOT_SUPPORTED;

	if (!(label = hints->obj_label)) {
		if (pin_info == NULL)
			label = "PIN";
		else if (pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
			label = "Security Officer PIN";
		else
			label = "User PIN";
	}

	if (hints->p15card) {
		/* TBD: get preferredCard from TokenInfo */
	}

	if (hints->prompt) {
		printf("%s", hints->prompt);
		if (flags & SC_UI_PIN_OPTIONAL)
			printf(" (Optional - press return for no PIN)");
		printf(".\n");
	}

	*out = NULL;
	while (1) {
		char	*pin = NULL;
		size_t	len = 0;
		int r;

		printf("Please enter %s: ", label);
		r = util_getpass(&pin, &len, stdin);
		if (r < 0 || !pin)
			return SC_ERROR_INTERNAL;

		if (!strlen(pin) && (flags & SC_UI_PIN_OPTIONAL))
			return 0;

		if (pin_info && (flags & SC_UI_PIN_CHECK_LENGTH)) {
			if (strlen(pin) < pin_info->attrs.pin.min_length) {
				fprintf(stderr,
					"PIN too short (min %lu characters)\n",
					(unsigned long) pin_info->attrs.pin.min_length);
				continue;
			}
			if (pin_info->attrs.pin.max_length
			 && strlen(pin) > pin_info->attrs.pin.max_length) {
				fprintf(stderr,
					"PIN too long (max %lu characters)\n",
					(unsigned long) pin_info->attrs.pin.max_length);
				continue;
			}
		}

		*out = strdup(pin);
		sc_mem_clear(pin, len);

		if (!(flags & SC_UI_PIN_RETYPE))
			break;

		printf("Please type again to verify: ");
		r = util_getpass(&pin, &len, stdin);
		if (r < 0 || !pin)
			return SC_ERROR_INTERNAL;
		if (!strcmp(*out, pin)) {
			sc_mem_clear(pin, len);
			break;
		}

		free(*out);
		*out = NULL;

		if (!(flags & SC_UI_PIN_MISMATCH_RETRY)) {
			fprintf(stderr, "PINs do not match.\n");
			free(pin);
			return SC_ERROR_KEYPAD_PIN_MISMATCH;
		}

		fprintf(stderr,
			"Sorry, the two pins did not match. "
			"Please try again.\n");
		sc_mem_clear(pin, strlen(pin));

		/* Currently, there's no way out of this dialog.
		 * We should allow the user to bail out after n
		 * attempts. */
	}

	return 0;
}

static int verify_pin(struct sc_pkcs15_card *p15card, char *auth_id_str)
{
	struct sc_pkcs15_object	*pin_obj = NULL;
	char pin_label[(sizeof pin_obj->label) + 20];
	char *pin = NULL;
	int r;

	if (!auth_id_str)   {
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
		struct sc_pkcs15_id auth_id;

		sc_pkcs15_hex_string_to_id(auth_id_str, &auth_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &auth_id, &pin_obj);
		if (r) {
			fprintf(stderr, "Unable to find PIN code: %s\n", sc_strerror(r));
			return r;
		}
	}

	if (!pin_obj)   {
		fprintf(stderr, "PIN object '%s' not found\n", auth_id_str);
		return -1;
	}

	if (opt_pins[0] != NULL)   {
		pin = strdup(opt_pins[0]);
	}
	else   {
		sc_ui_hints_t hints;

		if (opt_use_pinpad)
			return SC_ERROR_OBJECT_NOT_FOUND;

		if (pin_obj->label[0])
			snprintf(pin_label, sizeof(pin_label), "User PIN [%.*s]",
					(int) sizeof pin_obj->label, pin_obj->label);
		else
			snprintf(pin_label, sizeof(pin_label), "User PIN");
		memset(&hints, 0, sizeof(hints));
		hints.dialog_name = "pkcs15init.get_pin";
		hints.prompt    = "User PIN required";
		hints.obj_label = pin_label;
		hints.usage     = SC_UI_USAGE_OTHER;
		hints.card      = g_card;
		hints.p15card   = p15card;

		if ((r = get_pin(&hints, &pin)) < 0) {
			if (pin) {
				sc_mem_clear(pin, strlen(pin));
				free(pin);
			}
			fprintf(stderr,
				"Failed to read PIN from user: %s\n",
				sc_strerror(r));
			return r;
		}
	}

	r = sc_pkcs15_verify_pin(p15card, pin_obj, (unsigned char *)pin, pin ? strlen(pin) : 0);
	if (r < 0)
		fprintf(stderr, "Operation failed: %s\n", sc_strerror(r));

	if (pin) {
		sc_mem_clear(pin, strlen(pin));
		free(pin);
	}

	return r;
}
