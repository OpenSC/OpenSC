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
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
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
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <opensc/cardctl.h>
#include <opensc/pkcs15.h>
#include <opensc/pkcs15-init.h>
#include <opensc/keycache.h>
#include <opensc/log.h>
#include <opensc/ui.h>
#include <opensc/cards.h>
#include <compat_getpass.h>
#include "util.h"
#include <compat_strlcpy.h>


#undef GET_KEY_ECHO_OFF

static const char *app_name = "pkcs15-init";

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(sc_context_t *,
			struct sc_pkcs15_card *, u8 **, size_t *);

/* Local functions */
static int	open_reader_and_card(int);
static int	do_assert_pristine(sc_card_t *);
static int	do_erase(sc_card_t *, struct sc_profile *);
static int	do_delete_objects(struct sc_profile *, unsigned int myopt_delete_flags);
static int	do_change_attributes(struct sc_profile *, unsigned int myopt_type);
static int	do_init_app(struct sc_profile *);
static int	do_store_pin(struct sc_profile *);
static int	do_generate_key(struct sc_profile *, const char *);
static int	do_store_private_key(struct sc_profile *);
static int	do_store_public_key(struct sc_profile *, EVP_PKEY *);
static int	do_store_certificate(struct sc_profile *);
static int	do_update_certificate(struct sc_profile *);
static int	do_convert_private_key(struct sc_pkcs15_prkey *, EVP_PKEY *);
static int	do_convert_public_key(struct sc_pkcs15_pubkey *, EVP_PKEY *);
static int	do_convert_cert(sc_pkcs15_der_t *, X509 *);
static int	is_cacert_already_present(struct sc_pkcs15init_certargs *);
static int	do_finalize_card(sc_card_t *, struct sc_profile *);

static int	do_read_data_object(const char *name, u8 **out, size_t *outlen);
static int	do_store_data_object(struct sc_profile *profile);

static void	set_secrets(struct sc_profile *);
static int	init_keyargs(struct sc_pkcs15init_prkeyargs *);
static int	get_new_pin(sc_ui_hints_t *, const char *, const char *,
			char **);
static int	get_pin_callback(struct sc_profile *profile,
			int id, const struct sc_pkcs15_pin_info *info,
			const char *label,
			u8 *pinbuf, size_t *pinsize);
static int	get_key_callback(struct sc_profile *,
			int method, int reference,
			const u8 *, size_t, u8 *, size_t *);

static int	do_generate_key_soft(int, unsigned int, EVP_PKEY **);
static int	do_read_private_key(const char *, const char *,
				EVP_PKEY **, X509 **, unsigned int);
static int	do_read_public_key(const char *, const char *, EVP_PKEY **);
static int	do_read_certificate(const char *, const char *, X509 **);
static void	parse_commandline(int argc, char **argv);
static void	read_options_file(const char *);
static void	ossl_print_errors(void);
static void set_userpin_ref(void);


enum {
	OPT_OPTIONS = 0x100,
	OPT_PASSPHRASE,
	OPT_PUBKEY,
	OPT_EXTRACTABLE,
	OPT_UNPROTECTED,
	OPT_AUTHORITY,
	OPT_SOFT_KEYGEN,
	OPT_SPLIT_KEY,
	OPT_ASSERT_PRISTINE,
	OPT_SECRET,
	OPT_PUBKEY_LABEL,
	OPT_CERT_LABEL,
	OPT_APPLICATION_NAME,
	OPT_APPLICATION_ID,

	OPT_PIN1     = 0x10000,	/* don't touch these values */
	OPT_PUK1     = 0x10001,
	OPT_PIN2     = 0x10002,
	OPT_PUK2     = 0x10003,
	OPT_SERIAL   = 0x10004,
	OPT_NO_SOPIN = 0x10005,
	OPT_NO_PROMPT= 0x10006,
};

const struct option	options[] = {
	{ "erase-card",		no_argument, NULL,		'E' },
	{ "create-pkcs15",	no_argument, NULL,		'C' },
	{ "store-pin",		no_argument, NULL,		'P' },
	{ "generate-key",	required_argument, NULL,	'G' },
	{ "store-private-key",	required_argument, NULL,	'S' },
	{ "store-public-key",	required_argument, NULL,	OPT_PUBKEY },
	{ "store-certificate",	required_argument, NULL,	'X' },
	{ "update-certificate",	required_argument, NULL,	'U' },
	{ "store-data",		required_argument, NULL,	'W' },
	{ "delete-objects",	required_argument, NULL,	'D' },
	{ "change-attributes",	required_argument, NULL,	'A' },

	{ "reader",		required_argument, NULL,	'r' },
	{ "pin",		required_argument, NULL,	OPT_PIN1 },
	{ "puk",		required_argument, NULL,	OPT_PUK1 },
	{ "so-pin",		required_argument, NULL,	OPT_PIN2 },
	{ "so-puk",		required_argument, NULL,	OPT_PUK2 },
	{ "no-so-pin",		no_argument,	   NULL,	OPT_NO_SOPIN },
	{ "serial",		required_argument, NULL,	OPT_SERIAL },
	{ "auth-id",		required_argument, NULL,	'a' },
	{ "id",			required_argument, NULL,	'i' },
	{ "label",		required_argument, NULL,	'l' },
	{ "public-key-label",	required_argument, NULL,	OPT_PUBKEY_LABEL },
	{ "cert-label",		required_argument, NULL,	OPT_CERT_LABEL },
	{ "application-name",	required_argument, NULL,	OPT_APPLICATION_NAME },
	{ "application-id",	required_argument, NULL,	OPT_APPLICATION_ID },
	{ "output-file",	required_argument, NULL,	'o' },
	{ "format",		required_argument, NULL,	'f' },
	{ "passphrase",		required_argument, NULL,	OPT_PASSPHRASE },
	{ "authority",		no_argument,	   NULL,	OPT_AUTHORITY },
	{ "key-usage",		required_argument, NULL,	'u' },
	{ "split-key",		no_argument,	   NULL,	OPT_SPLIT_KEY },
	{ "finalize",		no_argument,       NULL,   'F' },

	{ "extractable",	no_argument, NULL,		OPT_EXTRACTABLE },
	{ "insecure",		no_argument, NULL,		OPT_UNPROTECTED },
	{ "soft",		no_argument, NULL,		OPT_SOFT_KEYGEN },
	{ "use-default-transport-keys",
				no_argument, NULL,		'T' },
	{ "no-prompt",		no_argument, NULL,		OPT_NO_PROMPT },

	{ "profile",		required_argument, NULL,	'p' },
	{ "card-profile",	required_argument, NULL,	'c' },
	{ "options-file",	required_argument, NULL,	OPT_OPTIONS },
	{ "wait",		no_argument, NULL,		'w' },
	{ "help",		no_argument, NULL,		'h' },
	{ "verbose",		no_argument, NULL,		'v' },

	/* Hidden options for testing */
	{ "assert-pristine",	no_argument, NULL,		OPT_ASSERT_PRISTINE },
	{ "secret",		required_argument, NULL,	OPT_SECRET },
	{ NULL, 0, NULL, 0 }
};
static const char *		option_help[] = {
	"Erase the smart card (can be used with --create-pkcs15)",
	"Creates a new PKCS #15 structure",
	"Store a new PIN/PUK on the card",
	"Generate a new key and store it on the card",
	"Store private key",
	"Store public key",
	"Store an X.509 certificate",
	"Update an X.509 certificate (carefull with mail decryption certs!!)",
	"Store a data object",
	"Delete object(s) (use \"help\" for more information)",
	"Change attribute(s) (use \"help\" for more information)",

	"Specify which reader to use",
	"Specify PIN",
	"Specify unblock PIN",
	"Specify security officer (SO) PIN",
	"Specify unblock PIN for SO PIN",
	"Do not install a SO PIN, and dont prompt for it",
	"Specify the serial number of the card",
	"Specify ID of PIN to use/create",
	"Specify ID of key/certificate",
	"Specify label of PIN/key",
	"Specify public key label (use with --generate-key)",
	"Specify user cert label (use with --store-private-key)",
	"Specify application name of data object (use with --store-data-object)",
	"Specify application id of data object (use with --store-data-object)",
	"Output public portion of generated key to file",
	"Specify key/cert file format: PEM (=default), DER or PKCS12",
	"Specify passphrase for unlocking secret key",
	"Mark certificate as a CA certificate",
	"Specify X.509 key usage (use \"--key-usage help\" for more information)",
	"Automatically create two keys with same ID and different usage (sign vs decipher)",
	"Finish initialization phase of the smart card",

	"Private key stored as an extractable key",
	"Insecure mode: do not require PIN/passphrase for private key",
	"Use software key generation, even if the card supports on-board key generation",
	"Always ask for transport keys etc, even if the driver thinks it knows the key",
	"Do not prompt the user, except for PINs",

	"Specify the general profile to use",
	"Specify the card profile to use",
	"Read additional command line options from file",
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
	ACTION_STORE_PIN,
	ACTION_GENERATE_KEY,
	ACTION_STORE_PRIVKEY,
	ACTION_STORE_PUBKEY,
	ACTION_STORE_CERT,
	ACTION_UPDATE_CERT,
	ACTION_STORE_DATA,
	ACTION_FINALIZE_CARD,
	ACTION_DELETE_OBJECTS,
	ACTION_CHANGE_ATTRIBUTES,

	ACTION_MAX
};
static const char *action_names[] = {
	"do nothing",
	"verify that card is pristine",
	"erase card",
	"create PKCS #15 meta structure",
	"store PIN",
	"generate key",
	"store private key",
	"store public key",
	"store certificate",
	"update certificate",
	"store data object",
	"finalizing card",
	"delete object(s)",
	"change attribute(s)",
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

static sc_context_t *	ctx = NULL;
static sc_card_t *		card = NULL;
static struct sc_pkcs15_card *	p15card = NULL;
static unsigned int		opt_actions;
static int			opt_reader = -1,
				opt_extractable = 0,
				opt_unprotected = 0,
				opt_authority = 0,
				opt_softkeygen = 0,
				opt_no_prompt = 0,
				opt_no_sopin = 0,
				opt_use_defkeys = 0,
				opt_split_key = 0,
				opt_wait = 0;
static const char *		opt_profile = "pkcs15";
static char *			opt_card_profile = NULL;
static char *			opt_infile = NULL;
static char *			opt_format = NULL;
static char *			opt_authid = NULL;
static char *			opt_objectid = NULL;
static char *			opt_label = NULL;
static char *			opt_pubkey_label = NULL;
static char *			opt_cert_label = NULL;
static char *			opt_pins[4];
static char *			opt_serial = NULL;
static char *			opt_passphrase = NULL;
static char *			opt_newkey = NULL;
static char *			opt_outkey = NULL;
static char *			opt_application_id = NULL;
static char *			opt_application_name = NULL;
static unsigned int		opt_x509_usage = 0;
static unsigned int		opt_delete_flags = 0;
static unsigned int		opt_type = 0;
static int			ignore_cmdline_pins = 0;
static struct secret		opt_secrets[MAX_SECRETS];
static unsigned int		opt_secret_count;
static int			verbose = 0;

static struct sc_pkcs15init_callbacks callbacks = {
	get_pin_callback,	/* get_pin() */
	get_key_callback,	/* get_key() */
};

int
main(int argc, char **argv)
{
	struct sc_profile	*profile = NULL;
	unsigned int		n;
	int			r = 0;

	/* OpenSSL magic */
	SSLeay_add_all_algorithms();
	CRYPTO_malloc_init();
#ifdef RANDOM_POOL
	if (!RAND_load_file(RANDOM_POOL, 32))
		util_fatal("Unable to seed random number pool for key generation");
#endif

	parse_commandline(argc, argv);

	if (optind != argc)
		util_print_usage_and_die(app_name, options, option_help);
	if (opt_actions == 0) {
		fprintf(stderr, "No action specified.\n");
		util_print_usage_and_die(app_name, options, option_help);
	}
	if (!opt_profile) {
		fprintf(stderr, "No profile specified.\n");
		util_print_usage_and_die(app_name, options, option_help);
	}

	/* Connect to the card */
	if (!open_reader_and_card(opt_reader))
		return 1;

	sc_pkcs15init_set_callbacks(&callbacks);

	/* Bind the card-specific operations and load the profile */
	if ((r = sc_pkcs15init_bind(card, opt_profile,
		opt_card_profile, &profile)) < 0) {
		printf("Couldn't bind to the card: %s\n", sc_strerror(r));
		return 1;
	}

	set_secrets(profile);

	for (n = 0; n < ACTION_MAX; n++) {
		unsigned int	action = n;

		if (!(opt_actions & (1 << action)))
			continue;

		if (action != ACTION_ERASE
		 && action != ACTION_INIT
		 && action != ACTION_ASSERT_PRISTINE
		 && p15card == NULL) {
			/* Read the PKCS15 structure from the card */
			r = sc_pkcs15_bind(card, &p15card);
			if (r) {
				fprintf(stderr,
					"PKCS#15 initialization failed: %s\n",
					sc_strerror(r));
				break;
			}

			/* XXX: should compare card to profile here to make
			 * sure we're not messing things up */

			if (verbose)
				printf("Found %s\n", p15card->label);

			sc_pkcs15init_set_p15card(profile, p15card);
		}

		if (verbose && action != ACTION_ASSERT_PRISTINE)
			printf("About to %s.\n", action_names[action]);
/*
{
	sc_path_t p1, p2, p3, p4;
	sc_format_path("3F0050156666", &p1); p1.index = 0; p1.count = 50;
	sc_format_path("3F0050157777", &p2); p2.index = 50; p2.count = 50;
	sc_format_path("3F0050156666", &p3); p3.index = 200; p3.count = 50;
	sc_format_path("3F0050156666", &p4); p4.index = 50; p4.count = 150;
	r = sc_pkcs15init_remove_unusedspace(p15card, profile, &p1, NULL);
	printf("sc_pkcs15init_add_unusedspace(): %d\n", r);
	//r = sc_pkcs15init_add_unusedspace(p15card, profile, &p3, NULL);
	//printf("sc_pkcs15init_add_unusedspace(): %d\n", r);
}
*/
		switch (action) {
		case ACTION_ASSERT_PRISTINE:
			/* skip printing error message */
			if ((r = do_assert_pristine(card)) < 0)
				goto out;
			continue;
		case ACTION_ERASE:
			r = do_erase(card, profile);
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
			break;
		case ACTION_FINALIZE_CARD:
			r = do_finalize_card(card, profile);
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

out:
	if (profile) {
		sc_pkcs15init_unbind(profile);
	}
	if (p15card) {
		sc_pkcs15_unbind(p15card);
	}
	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	sc_release_context(ctx);
	return r < 0? 1 : 0;
}

static int
open_reader_and_card(int reader)
{
	int	r;
	sc_context_param_t ctx_param;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;

	r = sc_context_create(&ctx, &ctx_param);
	if (r) {
		util_error("Failed to establish context: %s\n", sc_strerror(r));
		return 0;
	}
	if (verbose > 1) {
		ctx->debug = verbose-1;
		ctx->debug_file = stderr;
	}

	if (util_connect_card(ctx, &card, reader, 0, opt_wait, verbose))
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

	/* we need FILE NOT FOUND.
	 * - on starcos card NOT ALLOWED is also ok, as the MF does not exist.
	 * - on setcos 4.4 card, we should get 6F00 (translates to
	  *    SC_ERROR_CARD_CMD_FAILED) to indicate that no MF exists. */

	sc_ctx_suppress_errors_on(in_card->ctx);

	sc_format_path("2F00", &path);
	r = sc_select_file(in_card, &path, NULL);

	if (r != SC_ERROR_FILE_NOT_FOUND) {
		ok &= (r == SC_ERROR_NOT_ALLOWED &&
			strcmp(in_card->name, "STARCOS SPK 2.3") == 0) ||
		      (r == SC_ERROR_CARD_CMD_FAILED &&
			in_card->type == SC_CARD_TYPE_SETCOS_44);
	}

	sc_format_path("5015", &path);
	r = sc_select_file(in_card, &path, NULL);

	if (r != SC_ERROR_FILE_NOT_FOUND) {
		ok &= (r == SC_ERROR_NOT_ALLOWED &&
			strcmp(in_card->name, "STARCOS SPK 2.3") == 0) ||
		      (r == SC_ERROR_CARD_CMD_FAILED &&
			in_card->type == SC_CARD_TYPE_SETCOS_44);
	}


	sc_ctx_suppress_errors_off(in_card->ctx);

	if (!ok) {
		fprintf(stderr,
			"Card not pristine; detected (possibly incomplete) "
			"PKCS#15 structure\n");
	} else if (verbose) {
		printf("Pristine card.\n");
	}

	return ok ? 0 : -1;
}

/*
 * Erase card
 */
static int
do_erase(sc_card_t *in_card, struct sc_profile *profile)
{
	int	r;
	ignore_cmdline_pins++;
	r = sc_pkcs15init_erase_card(in_card, profile);
	ignore_cmdline_pins--;
	return r;
}

static int do_finalize_card(sc_card_t *in_card, struct sc_profile *profile)
{
	return sc_pkcs15init_finalize_card(in_card, profile);
}

/*
 * Initialize pkcs15 application
 */
static int
do_init_app(struct sc_profile *profile)
{
	struct sc_pkcs15init_initargs args;
	sc_pkcs15_pin_info_t	info;
	sc_ui_hints_t		hints;
	const char		*role = "so";
	int			r;

	memset(&hints, 0, sizeof(hints));
	hints.usage	= SC_UI_USAGE_NEW_PIN;
	hints.flags	= SC_UI_PIN_RETYPE
			   | SC_UI_PIN_CHECK_LENGTH
			   | SC_UI_PIN_MISMATCH_RETRY;
	hints.card	= card;
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
	if (!opt_pins[2] && !opt_no_prompt && !opt_no_sopin) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_SO_PIN, &info);

		if (!(info.flags & SC_PKCS15_PIN_FLAG_SO_PIN)) {
			role = "user";
		} else {
			/* SO pin is always optional */
			hints.flags |= SC_UI_PIN_OPTIONAL;
		}

		r = get_new_pin(&hints, role, "pin", &opt_pins[2]);
		if (r < 0)
			goto failed;
	}

	if (opt_pins[2] && !opt_pins[3] && !opt_no_prompt) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_SO_PUK, &info);

		if (!(info.flags & SC_PKCS15_PIN_FLAG_SO_PIN))
			role = "user";

		hints.flags |= SC_UI_PIN_OPTIONAL;
		r = get_new_pin(&hints, role, "puk", &opt_pins[3]);
		if (r < 0)
			goto failed;
	}
	args.so_pin = (const u8 *) opt_pins[2];
	if (args.so_pin)
		args.so_pin_len = strlen((const char *) args.so_pin);
	args.so_puk = (const u8 *) opt_pins[3];
	if (args.so_puk)
		args.so_puk_len = strlen((const char *) args.so_puk);
	args.serial = (const char *) opt_serial;
	args.label = opt_label;

	return sc_pkcs15init_add_app(card, profile, &args);

failed:	sc_error(card->ctx, "Failed to read PIN: %s\n", sc_strerror(r));
	return SC_ERROR_PKCS15INIT;
}

/*
 * Store a PIN/PUK pair
 */
static int
do_store_pin(struct sc_profile *profile)
{
	struct sc_pkcs15init_pinargs args;
	sc_pkcs15_pin_info_t	info;
	sc_ui_hints_t		hints;
	int			r;
	const char 		*pin_id;

	memset(&hints, 0, sizeof(hints));
	hints.usage	= SC_UI_USAGE_NEW_PIN;
	hints.flags	= SC_UI_PIN_RETYPE
			   | SC_UI_PIN_CHECK_LENGTH
			   | SC_UI_PIN_MISMATCH_RETRY;
	hints.card	= card;
	hints.p15card	= p15card;
	hints.info.pin	= &info;

	pin_id = opt_objectid ? opt_objectid : opt_authid;

	if (!pin_id) {
		util_error("No pin id specified\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (opt_pins[0] == NULL) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_USER_PIN, &info);

		if ((r = get_new_pin(&hints, "user", "pin", &opt_pins[0])) < 0)
			goto failed;
	}
	if (*opt_pins[0] == '\0') {
		util_error("You must specify a PIN\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_pins[1] == NULL) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_USER_PUK, &info);

		hints.flags |= SC_UI_PIN_OPTIONAL;
		if ((r = get_new_pin(&hints, "user", "puk", &opt_pins[1])) < 0)
			goto failed;
	}

	memset(&args, 0, sizeof(args));
	sc_pkcs15_format_id(pin_id, &args.auth_id);
	args.pin = (u8 *) opt_pins[0];
	args.pin_len = strlen(opt_pins[0]);
	args.puk = (u8 *) opt_pins[1];
	args.puk_len = opt_pins[1]? strlen(opt_pins[1]) : 0;
	args.label = opt_label;

	return sc_pkcs15init_store_pin(p15card, profile, &args);

failed:	sc_error(card->ctx, "Failed to read PIN: %s\n", sc_strerror(r));
	return SC_ERROR_PKCS15INIT;
}

/*
 * Display split key error message
 */
static void
split_key_error(void)
{
	fprintf(stderr, "\n"
	"Error - this token requires a more restrictive key usage.\n"
	"Keys stored on this token can be used either for signing or decipherment,\n"
	"but not both. You can either specify a more restrictive usage through\n"
	"the --key-usage command line argument, or allow me to transparently\n"
	"create two key objects with separate usage by specifying --split-key\n");
	exit(1);
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

	if ((r = init_keyargs(&args)) < 0)
		return r;

	r = do_read_private_key(opt_infile, opt_format, &pkey, cert, MAX_CERTS);
	if (r < 0)
		return r;
	ncerts = r;

	if (ncerts) {
		char	namebuf[256];

		printf("Importing %d certificates:\n", ncerts);
		for (i = 0; i < ncerts; i++) {
			printf("  %d: %s\n",
				i, X509_NAME_oneline(cert[i]->cert_info->subject,
					namebuf, sizeof(namebuf)));
		}
	}

	if ((r = do_convert_private_key(&args.key, pkey)) < 0)
		return r;
	if (ncerts) {
		unsigned int	usage;

		/* tell openssl to cache the extensions */
		X509_check_purpose(cert[0], -1, -1);
		usage = cert[0]->ex_kusage;

		/* No certificate usage? Assume ordinary
		 * user cert */
		if (usage == 0)
			usage = 0x1F;

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

	if (sc_pkcs15init_requires_restrictive_usage(p15card, &args, 0)) {
		if (!opt_split_key)
			split_key_error();

		r = sc_pkcs15init_store_split_key(p15card, profile,
				&args, NULL, NULL);
	} else {
		r = sc_pkcs15init_store_private_key(p15card, profile, &args, NULL);
	}

	if (r < 0)
		return r;

	/* If there are certificate as well (e.g. when reading the
	 * private key from a PKCS #12 file) store them, too.
	 */
	for (i = 0; i < ncerts; i++) {
		struct sc_pkcs15init_certargs cargs;
		char	namebuf[SC_PKCS15_MAX_LABEL_SIZE-1];

		memset(&cargs, 0, sizeof(cargs));

		/* Encode the cert */
		if ((r = do_convert_cert(&cargs.der_encoded, cert[i])) < 0)
			return r;

		X509_check_purpose(cert[i], -1, -1);
		cargs.x509_usage = cert[i]->ex_kusage;
		cargs.label = X509_NAME_oneline(cert[i]->cert_info->subject,
					namebuf, sizeof(namebuf));

		/* Just the first certificate gets the same ID
		 * as the private key. All others get
		 * an ID of their own */
		if (i == 0) {
			cargs.id = args.id;
			if (opt_cert_label != 0)
				cargs.label = opt_cert_label;
		} else {
			if (is_cacert_already_present(&cargs)) {
				printf("Certificate #%d already present, "
					"not stored.\n", i);
				goto next_cert;
			}
			cargs.authority = 1;
		}

		r = sc_pkcs15init_store_certificate(p15card, profile,
			       	&cargs, NULL);
next_cert:
		free(cargs.der_encoded.value);
	}
	
	/* No certificates - store the public key */
	if (ncerts == 0) {
		r = do_store_public_key(profile, pkey);
	}

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

	r = sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_CERT_X509, objs, 32);
	if (r <= 0)
		return 0;

	count = r;
	for (i = 0; i < count; i++) {
		cinfo = (sc_pkcs15_cert_info_t *) objs[i]->data;

		if (!cinfo->authority)
			continue;
		if (args->label && objs[i]->label
		 && strcmp(args->label, objs[i]->label))
			continue;
		/* XXX we should also match the usage field here */

		/* Compare the DER representation of the certificates */
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r < 0 || !cert)
			continue;

		if (cert->data_len == args->der_encoded.len
		     && !memcmp(cert->data, args->der_encoded.value,
				     cert->data_len)) {
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

	if (pkey == NULL)
		r = do_read_public_key(opt_infile, opt_format, &pkey);
	if (r >= 0)
		r = do_convert_public_key(&args.key, pkey);
	if (r >= 0)
		r = sc_pkcs15init_store_public_key(p15card, profile,
					&args, &dummy);

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

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	args.label = (opt_cert_label != 0 ? opt_cert_label : opt_label);
	args.authority = opt_authority;

	r = do_read_certificate(opt_infile, opt_format, &cert);
	if (r >= 0)
		r = do_convert_cert(&args.der_encoded, cert);
	if (r >= 0)
		r = sc_pkcs15init_store_certificate(p15card, profile,
					&args, NULL);

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
	const u8 *ptr;
	int r;

	/* Get the public key from the old cert */
	ptr = sc_oldcert->data;
	oldcert = d2i_X509(NULL, &ptr, sc_oldcert->data_len);

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

	/* Compare the public keys, there's no high level openssl function for this(?) */
	r = SC_ERROR_INVALID_ARGUMENTS;
	if (oldpk->type == newpk->type)
	{
		if ((oldpk->type == EVP_PKEY_DSA) &&
			!BN_cmp(oldpk->pkey.dsa->p, newpk->pkey.dsa->p) &&
			!BN_cmp(oldpk->pkey.dsa->q, newpk->pkey.dsa->q) &&
			!BN_cmp(oldpk->pkey.dsa->g, newpk->pkey.dsa->g))
				r = 0;
		else if ((oldpk->type == EVP_PKEY_RSA) &&
			!BN_cmp(oldpk->pkey.rsa->n, newpk->pkey.rsa->n) &&
			!BN_cmp(oldpk->pkey.rsa->e, newpk->pkey.rsa->e))
				r = 0;
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

	set_userpin_ref();

	if (opt_objectid == NULL) {
		util_error("no ID given for the cert: use --id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_pkcs15_format_id(opt_objectid, &id);
    if (sc_pkcs15_find_cert_by_id(p15card, &id, &obj) != 0) {
    	util_error("Couldn't find the cert with ID %s\n", opt_objectid);
    	return SC_ERROR_OBJECT_NOT_FOUND;
    }

	certinfo = (sc_pkcs15_cert_info_t *) obj->data;
	r = sc_pkcs15_read_certificate(p15card, certinfo, &oldcert);
	if (r < 0)
		return r;

	newcert_raw.value = NULL;
	r = do_read_check_certificate(oldcert, opt_infile, opt_format, &newcert_raw);
	sc_pkcs15_free_certificate(oldcert);
	if (r < 0)
		return r;

	r = sc_pkcs15init_update_certificate(p15card, profile, obj,
		newcert_raw.value, newcert_raw.len);

	if (newcert_raw.value)
		free(newcert_raw.value);

	return r;
}

/*
 * Download data object to card
 */
static int
do_store_data_object(struct sc_profile *profile)
{
	struct sc_pkcs15init_dataargs args;
	u8	*data;
	size_t	datalen;
	int	r=0;

	memset(&args, 0, sizeof(args));
	args.app_oid.value[0] = -1;

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	if (opt_authid)
		sc_pkcs15_format_id(opt_authid, &args.auth_id);
	args.label = opt_label;
	args.app_label = opt_application_name ? opt_application_name : "pkcs15-init";

	sc_format_oid(&args.app_oid, opt_application_id);

	r = do_read_data_object(opt_infile, &data, &datalen);
	if (r >= 0) {
		/* der_encoded contains the plain data, nothing DER encoded */
		args.der_encoded.value = data;
		args.der_encoded.len = datalen;
		r = sc_pkcs15init_store_data_object(p15card, profile,
					&args, NULL);
	}

	return r;
}

static int cert_is_root(sc_pkcs15_cert_t *c)
{
	return (c->subject_len == c->issuer_len) &&
		(memcmp(c->subject, c->issuer, c->subject_len) == 0);
}

/* Check if the cert has a 'sibling' and return it's parent cert.
 * Should be made more effcicient for long chains by caching the certs.
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
	if (cert)
		sc_pkcs15_free_certificate(cert);
	if (othercert)
		sc_pkcs15_free_certificate(othercert);

	return r;
}

/* Delete object(s) by ID. The 'which' param can be any combination of
 * SC_PKCS15INIT_TYPE_PRKEY, SC_PKCS15INIT_TYPE_PUBKEY, SC_PKCS15INIT_TYPE_CERT
 * and SC_PKCS15INIT_TYPE_CHAIN. In the last case, every cert in the chain is
 * deleted, starting with the cert with ID 'id' and untill a CA cert is
 * reached that certified other remaining certs on the card.
 */
static int do_delete_crypto_objects(sc_pkcs15_card_t *myp15card,
				sc_profile_t *profile,
				const sc_pkcs15_id_t id,
				unsigned int which)
{
	sc_pkcs15_object_t *objs[10]; /* 1 priv + 1 pub + chain of at most 8 certs, should be enough */
	sc_context_t *myctx = myp15card->card->ctx;
	int i, r = 0, count = 0, del_cert = 0;

	if (which & SC_PKCS15INIT_TYPE_PRKEY) {
	    if (sc_pkcs15_find_prkey_by_id(myp15card, &id, &objs[count]) != 0)
			sc_debug(myctx, "NOTE: couldn't find privkey %s to delete\n", sc_pkcs15_print_id(&id));
		else
			count++;
	}

	if (which & SC_PKCS15INIT_TYPE_PUBKEY) {
	    if (sc_pkcs15_find_pubkey_by_id(myp15card, &id, &objs[count]) != 0)
			sc_debug(myctx, "NOTE: couldn't find pubkey %s to delete\n", sc_pkcs15_print_id(&id));
		else
			count++;
	}

	if (which & SC_PKCS15INIT_TYPE_CERT) {
	    if (sc_pkcs15_find_cert_by_id(myp15card, &id, &objs[count]) != 0)
			sc_debug(myctx, "NOTE: couldn't find cert %s to delete\n", sc_pkcs15_print_id(&id));
		else {
			count++;
			del_cert = 1;
		}
	}

	if (del_cert && ((which & SC_PKCS15INIT_TYPE_CHAIN) == SC_PKCS15INIT_TYPE_CHAIN)) {
		/* Get the cert chain, stop if there's a CA that is the issuer of
		 * other certs on this card */
		int has_sibling; /* siblings: certs having the same issuer */
		int stop;
		for( ; count < 10 ; count++) {
			r = get_cert_info(myp15card, objs[count - 1], &has_sibling, &stop, &objs[count]);
			if (r < 0)
				sc_error(myctx, "get_cert_info() failed: %s\n", sc_strerror(r));
			else if (has_sibling)
				sc_debug(myctx, "Chain deletion stops with cert %s\n", sc_pkcs15_print_id(
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
			sc_error(myctx, "Failed to delete object %d: %s\n", i, sc_strerror(r));
			break;
		}
	}

	return r < 0 ? r : count;
}

static int
do_delete_objects(struct sc_profile *profile, unsigned int myopt_delete_flags)
{
	int r = 0, count = 0;

	set_userpin_ref();

	if (myopt_delete_flags & SC_PKCS15INIT_TYPE_DATA) {
		struct sc_object_id app_oid;
		sc_pkcs15_object_t *obj;

		if (opt_application_id != NULL) {
			sc_format_oid(&app_oid, opt_application_id);

			r = sc_pkcs15_find_data_object_by_app_oid(p15card, &app_oid, &obj);
		}
		else if (opt_application_name != NULL && opt_label != NULL) {
			r = sc_pkcs15_find_data_object_by_name(p15card, opt_application_name, opt_label, &obj);
		}
		else {
			util_fatal("Specify the --application-id or --application-name and --label for the data object to be deleted\n");
		}

		if (r >= 0) {
			r = sc_pkcs15init_delete_object(p15card, profile, obj);
			if (r >= 0)
				count++;
		}
	}

	if (myopt_delete_flags & (SC_PKCS15INIT_TYPE_PRKEY | SC_PKCS15INIT_TYPE_PUBKEY | SC_PKCS15INIT_TYPE_CHAIN)) {
		sc_pkcs15_id_t id;
		if (opt_objectid == NULL)
				util_fatal("Specify the --id for key(s) or cert(s) to be deleted\n");
		sc_pkcs15_format_id(opt_objectid, &id);

		r = do_delete_crypto_objects(p15card, profile, id, myopt_delete_flags);
		if (r >= 0)
			count += r;
	}

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
		    if ((r = sc_pkcs15_find_prkey_by_id(p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_PUBKEY:
		    if ((r = sc_pkcs15_find_pubkey_by_id(p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_CERT:
		    if ((r = sc_pkcs15_find_cert_by_id(p15card, &id, &obj)) != 0)
				return r;
			break;
		case SC_PKCS15INIT_TYPE_DATA:
		    if ((r = sc_pkcs15_find_data_object_by_id(p15card, &id, &obj)) != 0)
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

	set_userpin_ref();

	r = sc_pkcs15init_update_any_df(p15card, profile, obj->df, 0);

	return r;
}

/*
 * Generate a new private key
 */
static int
do_generate_key(struct sc_profile *profile, const char *spec)
{
	struct sc_pkcs15init_keygen_args keygen_args;
	unsigned int	evp_algo, keybits = 1024;
	EVP_PKEY	*pkey;
	int		r, split_key = 0;

	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.pubkey_label = opt_pubkey_label;

	if ((r = init_keyargs(&keygen_args.prkey_args)) < 0)
		return r;

	/* Parse the key spec given on the command line */
	if (!strncasecmp(spec, "rsa", 3)) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		evp_algo = EVP_PKEY_RSA;
		spec += 3;
	} else if (!strncasecmp(spec, "dsa", 3)) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_DSA;
		evp_algo = EVP_PKEY_DSA;
		spec += 3;
	} else {
		util_error("Unknown algorithm \"%s\"", spec);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (*spec == '/' || *spec == '-')
		spec++;
	if (*spec) {
		char	*end;

		keybits = strtoul(spec, &end, 10);
		if (*end) {
			util_error("Invalid number of key bits \"%s\"", spec);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}

	/* If the card doesn't support keys that can both sign _and_
	 * decipher, make sure the user specified --split-key */
	if (sc_pkcs15init_requires_restrictive_usage(p15card,
		 &keygen_args.prkey_args, keybits)) {
		if (!opt_split_key)
			split_key_error();
		split_key = 1;
	}

	if (!opt_softkeygen && !split_key) {
		r = sc_pkcs15init_generate_key(p15card, profile, &keygen_args,
			keybits, NULL);
		if (r >= 0 || r != SC_ERROR_NOT_SUPPORTED)
			return r;
		if (verbose)
			printf("Warning: card doesn't support on-board "
			       "key generation.\n"
			       "Trying software generation\n");
	}

	/* Generate the key ourselves */
	if ((r = do_generate_key_soft(evp_algo, keybits, &pkey)) < 0
	 || (r = do_convert_private_key(&keygen_args.prkey_args.key, pkey) ) < 0)
		goto out;

	if (split_key) {
		sc_pkcs15init_store_split_key(p15card,
				profile, &keygen_args.prkey_args, NULL, NULL);
	} else {
		r = sc_pkcs15init_store_private_key(p15card,
				profile, &keygen_args.prkey_args, NULL);
	}

	/* Store public key portion on card */
	if (r >= 0)
		r = do_store_public_key(profile, pkey);

out:
	EVP_PKEY_free(pkey);
	return r;
}

static int init_keyargs(struct sc_pkcs15init_prkeyargs *args)
{
	memset(args, 0, sizeof(*args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args->id);
	if (opt_authid) {
		sc_pkcs15_format_id(opt_authid, &args->auth_id);
	} else if (!opt_unprotected) {
		util_error("no PIN given for key - either use --insecure or \n"
		      "specify a PIN using --auth-id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_extractable) {
		args->flags |= SC_PKCS15INIT_EXTRACTABLE;
		if (opt_passphrase) {
			args->passphrase = opt_passphrase;
		} else {
			if (!opt_unprotected) {
				util_error("no pass phrase given for key - "
				      "either use --insecure or\n"
				      "specify a pass phrase using "
				      "--passphrase");
				return SC_ERROR_PASSPHRASE_REQUIRED;
			}
			args->flags |= SC_PKCS15INIT_NO_PASSPHRASE;
		}
	}
	args->label = opt_label;
	args->x509_usage = opt_x509_usage;
	return 0;
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

static void set_secrets(struct sc_profile *profile)
{
	unsigned int	n;

	for (n = 0; n < opt_secret_count; n++) {
		struct secret	*secret = &opt_secrets[n];

		if (secret->reference < 0)
			continue;
		sc_pkcs15init_set_secret(profile,
				secret->type,
				secret->reference,
				secret->key,
				secret->len);
	}
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

	return sc_ui_get_pin(hints, retstr);
}

/*
 * PIN retrieval callback
 */
static int
get_pin_callback(struct sc_profile *profile,
		int id, const struct sc_pkcs15_pin_info *info,
		const char *label,
		u8 *pinbuf, size_t *pinsize)
{
	char	namebuf[64];
	char	*secret = NULL;
	const char *name;
	size_t	len = 0;
	int	allocated = 0;

	if (label) {
		snprintf(namebuf, sizeof(namebuf), "PIN [%s]", label);
	} else {
		snprintf(namebuf, sizeof(namebuf),
			"Unspecified PIN [reference %u]",
			info->reference);
	}
	name = namebuf;

	if (!ignore_cmdline_pins) {
		switch (id) {
		case SC_PKCS15INIT_USER_PIN:
			name = "User PIN";
			secret = opt_pins[OPT_PIN1 & 3]; break;
		case SC_PKCS15INIT_USER_PUK:
			name = "User PIN unlock key";
			secret = opt_pins[OPT_PUK1 & 3]; break;
		case SC_PKCS15INIT_SO_PIN:
			name = "Security officer PIN";
			secret = opt_pins[OPT_PIN2 & 3]; break;
		case SC_PKCS15INIT_SO_PUK:
			name = "Security officer PIN unlock key";
			secret = opt_pins[OPT_PUK2 & 3]; break;
		}
		if (secret)
			len = strlen(secret);
	}

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

		snprintf(prompt, sizeof(prompt), "%s required", name);

		memset(&hints, 0, sizeof(hints));
		hints.dialog_name = "pkcs15init.get_pin";
		hints.prompt	= prompt;
		hints.obj_label	= name;
		hints.usage	= SC_UI_USAGE_OTHER;
		hints.card	= card;
		hints.p15card	= p15card;

		if ((r = sc_ui_get_pin(&hints, &secret)) < 0) {
			sc_error(card->ctx,
				"Failed to read PIN from user: %s\n",
				sc_strerror(r));
			return r;
		}

		len = strlen(secret);
		allocated = 1;
	}

	if (len > *pinsize)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(pinbuf, secret, len + 1);
	*pinsize = len;
	if (allocated)
		free(secret);
	return 0;
}

static int get_key_callback(struct sc_profile *profile,
			int method, int reference,
			const u8 *def_key, size_t def_key_size,
			u8 *key_buf, size_t *buf_size)
{
	const char	*kind, *prompt, *key;

	if (def_key_size && opt_use_defkeys) {
use_default_key:
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
	if (opt_no_prompt) {
		printf("\n"
		"Refusing to prompt for transport key because --no-prompt\n"
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

#ifdef GET_KEY_ECHO_OFF
		/* Read key with echo off - will users really manage? */
		key = getpass(prompt);
#else
		printf("%s: ", prompt);
		fflush(stdout);
		key = fgets(buffer, sizeof(buffer), stdin);
		if (key)
			buffer[strcspn(buffer, "\r\n")] = '\0';
#endif
		if (key == NULL)
			return SC_ERROR_INTERNAL;

		if (key[0] == '\0' && def_key_size)
			goto use_default_key;

		if (sc_hex_to_bin(key, key_buf, buf_size) >= 0)
			return 0;
	}
}

/*
 * Generate a private key
 */
static int do_generate_key_soft(int algorithm, unsigned int bits,
		EVP_PKEY **res)
{
	*res = EVP_PKEY_new();
	switch (algorithm) {
	case EVP_PKEY_RSA: {
			RSA	*rsa;
			BIO	*err;

			err = BIO_new(BIO_s_mem());
			rsa = RSA_generate_key(bits, 0x10001, NULL, err);
			BIO_free(err);
			if (rsa == 0)
				util_fatal("RSA key generation error");
			EVP_PKEY_assign_RSA(*res, rsa);
			break;
		}
	case EVP_PKEY_DSA: {
			DSA	*dsa;
			int	r = 0;

			dsa = DSA_generate_parameters(bits,
					NULL, 0, NULL,
					NULL, NULL, NULL);
			if (dsa)
				r = DSA_generate_key(dsa);
			if (r == 0 || dsa == 0)
				util_fatal("DSA key generation error");
			EVP_PKEY_assign_DSA(*res, dsa);
			break;
		}
	default:
		util_fatal("Unable to generate key: unsupported algorithm");
	}
	return 0;
}

/*
 * Read a private key
 */
static int pass_cb(char *buf, int len, int flags, void *d)
{
	int  plen;
	char *pass;
	if (d)
		pass = (char *)d;
	else
		pass = getpass("Please enter passphrase "
				"to unlock secret key: ");
	if (!pass)
		return 0;
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

	CRYPTO_add(&user_key->references, 1, CRYPTO_LOCK_EVP_PKEY);
	if (user_cert && max_certs)
		certs[ncerts++] = user_cert;

	/* Extract CA certificates, if any */
	for(i = 0; cacerts && ncerts < (int)max_certs && i < sk_X509_num(cacerts); i++)
		certs[ncerts++] = sk_X509_value(cacerts, i);

	/* bump reference counts for certificates */
	for (i = 0; i < ncerts; i++) {
		CRYPTO_add(&certs[i]->references, 1, CRYPTO_LOCK_X509);
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
	char	*passphrase = NULL;
	int	r;

	if (opt_passphrase)
		passphrase = opt_passphrase;

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
			passphrase = getpass("Please enter passphrase "
					     "to unlock secret key: ");
 			r = do_read_pkcs12_private_key(filename,
 					passphrase, pk, certs, max_certs);
		}
	} else {
		util_error("Error when reading private key. "
		      "Key file format \"%s\" not supported.\n", format);
		return SC_ERROR_NOT_SUPPORTED;
	}

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

#if 0
/*
 * Write a PEM encoded public key
 */
static int
do_write_pem_public_key(const char *filename, EVP_PKEY *pk)
{
	BIO	*bio;
	int	r;

	bio = BIO_new(BIO_s_file());
	if (BIO_write_filename(bio, (char *) filename) < 0)
		util_fatal("Unable to open %s: %m", filename);
	r = PEM_write_bio_PUBKEY(bio, pk);
	BIO_free(bio);
	if (r == 0) {
		ossl_print_errors();
		return -1;
	}
	return 0;
}

static int
do_write_public_key(const char *filename, const char *format, EVP_PKEY *pk)
{
	int	r;

	if (!format || !strcasecmp(format, "pem")) {
		r = do_write_pem_public_key(filename, pk);
	} else {
		error("Error when writing public key. "
		      "Key file format \"%s\" not supported.\n",
		      format);
		r = SC_ERROR_NOT_SUPPORTED;
	}
	return r;
}
#endif

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

static int determine_filesize(const char *filename) {
	FILE *fp;
	size_t size;

	if ((fp = fopen(filename,"rb")) == NULL) {
	  util_fatal("Unable to open %s: %m", filename);
	  }
	fseek(fp,0L,SEEK_END);
	size = ftell(fp);
	fclose(fp);
	return size;
	}

static int
do_read_data_object(const char *name, u8 **out, size_t *outlen)
{
        FILE *inf;
	size_t filesize = determine_filesize(name);
	int c;

	*out = (u8 *) malloc(filesize);
	if (*out == NULL) {
		return SC_ERROR_OUT_OF_MEMORY;
	}
 
        inf = fopen(name, "rb");
        if (inf == NULL) {
                fprintf(stderr, "Unable to open '%s' for reading.\n", name);
                return -1;
        }
        c = fread(*out, 1, filesize, inf);
        fclose(inf);
        if (c < 0) {
                perror("read");
                return -1;
        }

	*outlen = filesize;
	return 0;
}

static int
do_convert_bignum(sc_pkcs15_bignum_t *dst, BIGNUM *src)
{
	if (src == 0)
		return 0;
	dst->len = BN_num_bytes(src);
	dst->data = (u8 *) malloc(dst->len);
	BN_bn2bin(src, dst->data);
	return 1;
}

static int do_convert_private_key(struct sc_pkcs15_prkey *key, EVP_PKEY *pk)
{
	switch (pk->type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_prkey_rsa *dst = &key->u.rsa;
		RSA *src = EVP_PKEY_get1_RSA(pk);

		key->algorithm = SC_ALGORITHM_RSA;
		if (!do_convert_bignum(&dst->modulus, src->n)
		 || !do_convert_bignum(&dst->exponent, src->e)
		 || !do_convert_bignum(&dst->d, src->d)
		 || !do_convert_bignum(&dst->p, src->p)
		 || !do_convert_bignum(&dst->q, src->q))
			util_fatal("Invalid/incomplete RSA key.\n");
		if (src->iqmp && src->dmp1 && src->dmq1) {
			do_convert_bignum(&dst->iqmp, src->iqmp);
			do_convert_bignum(&dst->dmp1, src->dmp1);
			do_convert_bignum(&dst->dmq1, src->dmq1);
		}
		RSA_free(src);
		break;
		}
	case EVP_PKEY_DSA: {
		struct sc_pkcs15_prkey_dsa *dst = &key->u.dsa;
		DSA *src = EVP_PKEY_get1_DSA(pk);

		key->algorithm = SC_ALGORITHM_DSA;
		do_convert_bignum(&dst->pub, src->pub_key);
		do_convert_bignum(&dst->p, src->p);
		do_convert_bignum(&dst->q, src->q);
		do_convert_bignum(&dst->g, src->g);
		do_convert_bignum(&dst->priv, src->priv_key);
		DSA_free(src);
		break;
		}
	default:
		util_fatal("Unsupported key algorithm\n");
	}

	return 0;
}

static int do_convert_public_key(struct sc_pkcs15_pubkey *key, EVP_PKEY *pk)
{
	switch (pk->type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_pubkey_rsa *dst = &key->u.rsa;
		RSA *src = EVP_PKEY_get1_RSA(pk);

		key->algorithm = SC_ALGORITHM_RSA;
		if (!do_convert_bignum(&dst->modulus, src->n)
		 || !do_convert_bignum(&dst->exponent, src->e))
			util_fatal("Invalid/incomplete RSA key.\n");
		RSA_free(src);
		break;
		}
	case EVP_PKEY_DSA: {
		struct sc_pkcs15_pubkey_dsa *dst = &key->u.dsa;
		DSA *src = EVP_PKEY_get1_DSA(pk);

		key->algorithm = SC_ALGORITHM_DSA;
		do_convert_bignum(&dst->pub, src->pub_key);
		do_convert_bignum(&dst->p, src->p);
		do_convert_bignum(&dst->q, src->q);
		do_convert_bignum(&dst->g, src->g);
		DSA_free(src);
		break;
		}
	default:
		util_fatal("Unsupported key algorithm\n");
	}

	return 0;
}

static int do_convert_cert(sc_pkcs15_der_t *der, X509 *cert)
{
	u8	*p;

	der->len = i2d_X509(cert, NULL);
	der->value = p = (u8 *) malloc(der->len);
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
				printf("  privkey,pubkey,cert,chain,data\n");
				printf("When \"data\" is specified, an --application-id must also be specified,\n");
				printf("  in the other cases an \"--id\" must also be specified\n");
				printf("When \"chain\" is specified, the certificate chain starting with the cert\n");
				printf("  with specified ID will be deleted, untill there's a CA cert that certifies\n");
				printf("  another cert on the card\n");
			}
			else {
				printf("\nChange attribute argument: either privkey, pubkey, cert or data\n");
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
			fprintf(stderr, "Unknown argument for --delete_objects: %.*s\n", len, list);
			exit(0);
		}
		list += len;
	}

	return res;
}

/* If the user PIN and it's ID is given, put the pin ref in the keycache */
static void set_userpin_ref(void)
{
	int r;

	if ((opt_pins[0] != NULL) && (opt_authid != 0)) {
		sc_path_t path;
		sc_pkcs15_id_t auth_id;
		sc_pkcs15_object_t *pinobj;
		sc_pkcs15_pin_info_t *pin_info;
		sc_format_path("3F00", &path);
		sc_pkcs15_format_id(opt_authid, &auth_id);
		r = sc_pkcs15_find_pin_by_auth_id(p15card, &auth_id, &pinobj);
		if (r < 0)
			util_fatal("Searching for user PIN %d failed: %s\n", opt_authid, sc_strerror(r));
		pin_info = (sc_pkcs15_pin_info_t *) pinobj->data;
		sc_keycache_set_pin_name(&path, pin_info->reference, SC_PKCS15INIT_USER_PIN);
	}
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
	 { "sign",	"digitalSignature,nonRepudiation,keyCertSign,cRLSign" },
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
		util_print_usage_and_die(app_name, options, option_help);
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
		opt_reader = atoi(optarg);
		break;
	case 'u':
		parse_x509_usage(optarg, &opt_x509_usage);
		break;
	case 'w':
		opt_wait = 1;
		break;
	case OPT_OPTIONS:
		read_options_file(optarg);
		break;
	case OPT_PIN1: case OPT_PUK1:
	case OPT_PIN2: case OPT_PUK2:
		opt_pins[opt->val & 3] = optarg;
		break;
	case OPT_SERIAL:
		opt_serial = optarg;
		break;
	case OPT_PASSPHRASE:
		opt_passphrase = optarg;
		break;
	case OPT_PUBKEY:
		this_action = ACTION_STORE_PUBKEY;
		opt_infile = optarg;
		break;
	case OPT_UNPROTECTED:
		opt_unprotected++;
		break;
	case OPT_EXTRACTABLE:
		opt_extractable++;
		break;
	case OPT_AUTHORITY:
		opt_authority = 1;
		break;
	case OPT_SOFT_KEYGEN:
		opt_softkeygen = 1;
		break;
	case OPT_APPLICATION_NAME:
		opt_application_name = optarg;
		break;
	case OPT_APPLICATION_ID:
		opt_application_id = optarg;
		break;
	case 'T':
		opt_use_defkeys = 1;
		break;
	case OPT_SPLIT_KEY:
		opt_split_key = 1;
		break;
	case OPT_NO_SOPIN:
		opt_no_sopin = 1;
		break;
	case OPT_NO_PROMPT:
		opt_no_prompt = 1;
		break;
	case OPT_ASSERT_PRISTINE:
		this_action = ACTION_ASSERT_PRISTINE;
		break;
	case OPT_SECRET:
		parse_secret(&opt_secrets[opt_secret_count], optarg);
		opt_secret_count++;
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
	default:
		util_print_usage_and_die(app_name, options, option_help);
	}

	if ((opt_actions & (1 << this_action)) && opt->has_arg != no_argument) {
		fprintf(stderr, "Error: you cannot specify option");
		if (opt->name)
			fprintf(stderr, " --%s", opt->name);
		if (isprint(opt->val))
			fprintf(stderr, " -%c", opt->val);
		fprintf(stderr, " more than once.\n");
		util_print_usage_and_die(app_name, options, option_help);
	}
	if (this_action)
		opt_actions |= (1 << this_action);

	if ((opt_pins[OPT_PIN2&3] || opt_pins[OPT_PUK2&3]) && opt_no_sopin) {
		fprintf(stderr, "Error: "
		"The --no-so-pin option and --so-pin/--so-puk are mutually\n"
		"exclusive.\n");
		util_print_usage_and_die(app_name, options, option_help);
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
 * Read a file containing more command line options.
 * This allows you to specify PINs to pkcs15-init without
 * exposing them through ps.
 */
static void
read_options_file(const char *filename)
{
	const struct option	*o;
	char		buffer[1024], *name;
	FILE		*fp;

	if ((fp = fopen(filename, "r")) == NULL)
		util_fatal("Unable to open %s: %m", filename);
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		buffer[strcspn(buffer, "\n")] = '\0';

		name = strtok(buffer, " \t");
		while (name) {
			if (*name == '#')
				break;
			for (o = options; o->name; o++)
				if (!strcmp(o->name, name))
					break;
			if (!o->name) {
				util_error("Unknown option \"%s\"\n", name);
				util_print_usage_and_die(app_name, options, option_help);
			}
			if (o->has_arg != no_argument) {
				optarg = strtok(NULL, "");
				if (optarg) {
					while (isspace((int) *optarg))
						optarg++;
					optarg = strdup(optarg);
				}
			}
			if (o->has_arg == required_argument
			 && (!optarg || !*optarg)) {
				util_error("Option %s: missing argument\n", name);
				util_print_usage_and_die(app_name, options, option_help);
			}
			handle_option(o);
			name = strtok(NULL, " \t");
		}
	}
	fclose(fp);
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
