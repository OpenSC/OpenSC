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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include "opensc-pkcs15.h"
#include "util.h"
#include "profile.h"
#include "pkcs15-init.h"

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

/* Local functions */
static int	connect(int);
static void	bind_operations(struct pkcs15_init_operations *, const char *);
static int	do_generate_key(struct sc_profile *, const char *);
static int	do_store_private_key(struct sc_profile *profile);
static int	do_store_public_key(struct sc_profile *profile);
static int	do_store_certificate(struct sc_profile *profile);

static int	sc_pkcs15init_generate_key_soft(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15init_keyargs *);
struct sc_pkcs15_object *
		sc_pkcs15init_find_key(struct sc_pkcs15_card *p15card,
			unsigned int type,
			struct sc_pkcs15_id *id);
static int	sc_pkcs15init_new_private_key(struct sc_profile *profile,
			unsigned int type,
			struct sc_pkcs15init_keyargs *keyargs,
			struct sc_key_template *out);
static int	sc_pkcs15init_new_public_key(struct sc_profile *profile,
			unsigned int type,
			struct sc_pkcs15init_keyargs *keyargs,
			struct sc_key_template *out);
static int	sc_pkcs15init_new_cert(struct sc_profile *profile,
			unsigned int type, const char *name,
			struct sc_pkcs15_id *id, const char *label,
			struct sc_cert_template *out);

static int	sc_pkcs15init_store_private_key(struct sc_pkcs15_card *,
			struct sc_profile *, struct sc_pkcs15init_keyargs *);
static int	sc_pkcs15init_store_public_key(struct sc_pkcs15_card *p15card,
			struct sc_profile *profile,
			struct sc_pkcs15init_keyargs *keyargs);
static int	sc_pkcs15init_store_certificate(struct sc_pkcs15_card *p15card,
			struct sc_profile *profile,
			struct sc_pkcs15init_certargs *certargs);
static int	sc_pkcs15init_update_dir(struct sc_card *card,
			struct sc_profile *profile,
			struct sc_app_info *app);
static int	sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_odf(struct sc_pkcs15_card *,
			struct sc_profile *profile);
static int	sc_pkcs15init_update_df(struct sc_pkcs15_card *,
			struct sc_profile *profile,
			unsigned int df_type);
static int	do_select_parent(struct sc_profile *, struct sc_file *,
			struct sc_file **);
static int	do_read_pins(struct sc_profile *);
static int	set_pins_from_args(struct sc_profile *);

static int	do_read_private_key(const char *, const char *,
				EVP_PKEY **, X509 **);
static int	do_read_public_key(const char *, const char *, EVP_PKEY **);
static int	do_write_public_key(const char *, const char *, EVP_PKEY *);
static int	do_read_certificate(const char *, const char *, X509 **);
static void	parse_commandline(int argc, char **argv);
static void	read_options_file(const char *);
static void	ossl_print_errors(void);
static void	ossl_seed_random(void);


enum {
	OPT_OPTIONS = 0x100,
	OPT_PASSPHRASE,

	OPT_PIN1 = 0x10000,	/* don't touch these values */
	OPT_PUK1 = 0x10001,
	OPT_PIN2 = 0x10002,
	OPT_PUK2 = 0x10003,
};

const struct option	options[] = {
	{ "erase-card",		no_argument, 0,		'E' },
	{ "create-pkcs15",	no_argument, 0,		'C' },
	{ "pin1",		required_argument, 0,	OPT_PIN1 },
	{ "puk1",		required_argument, 0,	OPT_PUK1 },
	{ "pin2",		required_argument, 0,	OPT_PIN2 },
	{ "puk2",		required_argument, 0,	OPT_PUK2 },
	{ "id",			required_argument, 0,	'i' },
	{ "generate-key",	required_argument, 0,	'G' },
	{ "output-file",	required_argument, 0,	'o' },
	{ "store-private-key",	required_argument, 0,	'S' },
	{ "store-public-key",	required_argument, 0,	'P' },
	{ "format",		required_argument, 0,	'f' },
	{ "passphrase",		required_argument, 0,	OPT_PASSPHRASE },
	{ "store-certificate",	required_argument, 0,	'X' },

	{ "profile",		required_argument, 0,	'p' },
	{ "options-file",	required_argument, 0,	OPT_OPTIONS },
	{ "debug",		no_argument, 0,		'd' },
	{ 0, 0, 0, 0 }
};
const char *		option_help[] = {
	"Erase the smart card",
	"Creates a new PKCS #15 structure",
	"Specify PIN for CHV1",
	"Specify unblock PIN for CHV1",
	"Specify PIN for CHV2",
	"Specify unblock PIN for CHV2",
	"Specify ID of key/certificate",
	"Generate a new key and store it on the card",
	"Output public portion of generated key to file",
	"Store private key",
	"Store public key",
	"Specify key file format (default PEM)",
	"Specify passphrase for unlocking secret key",
	"Store an X.509 certificate",

	"Specify the profile to use",
	"Read additional command line options from file",
	"Enable debugging output",
};

enum {
	ACTION_NONE = 0,
	ACTION_INIT,
	ACTION_GENERATE_KEY,
	ACTION_STORE_PRIVKEY,
	ACTION_STORE_PUBKEY,
	ACTION_STORE_CERT
};

static struct sc_context *	ctx = NULL;
static struct sc_card *		card = NULL;
static struct sc_pkcs15_card *	p15card = NULL;
static int			opt_debug = 0,
				opt_quiet = 0,
				opt_action = 0,
				opt_erase = 0;
static char *			opt_driver = 0;
static char *			opt_profile = "pkcs15";
static char *			opt_infile = 0;
static char *			opt_format = 0;
static char *			opt_objectid = 0;
static char *			opt_objectlabel = 0;
static char *			opt_pins[4];
static char *			opt_passphrase = 0;
static char *			opt_newkey = 0;
static char *			opt_outkey = 0;
static struct pkcs15_init_operations ops;

int
main(int argc, char **argv)
{
	struct sc_profile	profile;
	int			opt_reader = 0;
	int			r = 0;

	/* OpenSSL magic */
	SSLeay_add_all_algorithms();
	CRYPTO_malloc_init();

	parse_commandline(argc, argv);

	if (optind != argc)
		print_usage_and_die("pkcs15-init");
	if (opt_action == ACTION_NONE) {
		fprintf(stderr, "No action specified.\n");
		print_usage_and_die("pkcs15-init");
	}
	if (!opt_profile) {
		fprintf(stderr, "No profile specified.\n");
		print_usage_and_die("pkcs15-init");
	}

	/* Connect to the card */
	if (!connect(opt_reader))
		return 1;

	/* Now bind the card specific operations */
	bind_operations(&ops, opt_driver);

	/* Now load the profile */
	/* When asked to init the card, read the profile first.
	 * This makes people writing new profiles happier because
	 * they don't have to wait for the card to come around */
	sc_profile_init(&profile);
	if (sc_profile_load(&profile, opt_profile)
	 || sc_profile_load(&profile, card->driver->short_name)
	 || sc_profile_finish(&profile))
		return 1;

	/* XXX lousy style */
	profile.ops = &ops;

	/* Associate all PINs given on the command line with the
	 * CHVs used by the profile */
	set_pins_from_args(&profile);

	if (opt_action == ACTION_INIT) {
		if (opt_erase)
			r = ops.erase_card(&profile, card);
		if (r >= 0)
			r = sc_pkcs15init_add_app(card, &profile);
		goto done;
	}

	if (opt_erase)
		fatal("Option --erase can be used only with --create-pkcs15\n");

	/* Read the PKCS15 structure from the card */
	r = sc_pkcs15_bind(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS#15 initialization failed: %s\n",
				sc_strerror(r));
		goto done;
	}
	if (!opt_quiet)
		printf("Found %s\n", p15card->label);

	/* XXX: should compare card to profile here to make sure
	 * we're not messing things up */

	if (opt_action == ACTION_STORE_PRIVKEY)
		r = do_store_private_key(&profile);
	else if (opt_action == ACTION_STORE_PUBKEY)
		r = do_store_public_key(&profile);
	else if (opt_action == ACTION_STORE_CERT)
		r = do_store_certificate(&profile);
	else if (opt_action == ACTION_GENERATE_KEY)
		r = do_generate_key(&profile, opt_newkey);
	else
		fatal("Action not yet implemented\n");

done:	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	sc_destroy_context(ctx);
	return r? 1 : 0;
}

static void
bind_operations(struct pkcs15_init_operations *ops, const char *driver)
{
	if (driver == 0)
		driver = card->driver->short_name;

	if (!strcasecmp(driver, "GPK"))
		bind_gpk_operations(ops);
	else if (!strcasecmp(driver, "MioCOS"))
		bind_miocos_operations(ops);
	else if (!strcasecmp(driver, "flex"))
		bind_cflex_operations(ops);
	else
		fatal("Don't know how to handle %s cards", driver);
}

static int
connect(int reader)
{
	int	r;

	r = sc_establish_context(&ctx);
	if (r) {
		error("Failed to establish context: %s\n", sc_strerror(r));
		return 0;
	}

	ctx->error_file = stderr;
	ctx->debug_file = stdout;
	ctx->debug = opt_debug;
	if (reader >= ctx->reader_count || reader < 0) {
		fprintf(stderr,
			"Illegal reader number. Only %d reader%s configured.\n",
		       	ctx->reader_count,
			ctx->reader_count == 1? "" : "s");
		return 0;
	}
	if (sc_detect_card_presence(ctx->reader[reader], 0) != 1) {
		error("Card not present.\n");
		return 0;
	}
	if (!opt_quiet) {
		printf("Connecting to card in reader %s...\n",
		       	ctx->reader[reader]->name);
	}

	r = sc_connect_card(ctx->reader[reader], 0, &card);
	if (r) {
		error("Failed to connect to card: %s\n", sc_strerror(r));
		return 0;
	}

	printf("Using card driver: %s\n", card->driver->name);
	r = sc_lock(card);
	if (r) {
		error("Unable to lock card: %s\n", sc_strerror(r));
		return 0;
	}
	return 1;
}

/*
 * Store a private key
 */
static int
do_store_private_key(struct sc_profile *profile)
{
	struct sc_pkcs15init_keyargs args;
	int		r;

	memset(&args, 0, sizeof(args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	if (opt_objectlabel)
		args.label = opt_objectlabel;

	r = do_read_private_key(opt_infile, opt_format, &args.pkey, &args.cert);
	if (r < 0)
		return -1;

	r = sc_pkcs15init_store_private_key(p15card, profile, &args);
	if (r < 0)
		goto failed;

	/* If there's a certificate as well (e.g. when reading the
	 * private key from a PKCS #12 file) store it, too.
	 * Otherwise store the public key.
	 */
	if (args.cert) {
		struct sc_pkcs15init_certargs cargs;

		memset(&cargs, 0, sizeof(cargs));
		cargs.id = args.id;
		cargs.cert = args.cert;
		r = sc_pkcs15init_store_certificate(p15card, profile,
				&cargs);
	} else {
		r = sc_pkcs15init_store_public_key(p15card, profile, &args);
	}

	if (r >= 0)
		return 0;

failed:	error("Failed to store private key: %s\n", sc_strerror(r));
	return -1;
}

/*
 * Store a public key
 */
static int
do_store_public_key(struct sc_profile *profile)
{
	struct sc_pkcs15init_keyargs args;
	int		r;

	memset(&args, 0, sizeof(args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	if (opt_objectlabel)
		args.label = opt_objectlabel;

	r = do_read_public_key(opt_infile, opt_format, &args.pkey);
	if (r < 0)
		return r;

	r = sc_pkcs15init_store_public_key(p15card, profile, &args);
	if (r < 0)
		goto failed;

	return 0;

failed:	error("Failed to store public key: %s\n", sc_strerror(r));
	return -1;
}

/*
 * Download certificate to card
 */
static int
do_store_certificate(struct sc_profile *profile)
{
	struct sc_pkcs15init_certargs args;
	int	r;

	memset(&args, 0, sizeof(args));

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	args.label = opt_objectlabel;

	r = do_read_certificate(opt_infile, opt_format, &args.cert);
	if (r < 0)
		return r;

	return sc_pkcs15init_store_certificate(p15card, profile, &args);
}

/*
 * Generate a new private key
 */
static int
do_generate_key(struct sc_profile *profile, const char *spec)
{
	struct sc_pkcs15init_keyargs keyargs;
	const char	*reason;
	int		r;

	/* Parse the key spec given on the command line */
	memset(&keyargs, 0, sizeof(keyargs));
	if (!strncasecmp(spec, "rsa", 3)) {
		keyargs.algorithm = SC_ALGORITHM_RSA;
		spec += 3;
	} else if (!strncasecmp(spec, "dsa", 3)) {
		keyargs.algorithm = SC_ALGORITHM_DSA;
		spec += 3;
	} else {
		reason = "algorithm not supported\n";
		goto failed;
	}

	if (*spec == '/' || *spec == '-')
		spec++;
	if (*spec) {
		keyargs.keybits = strtoul(spec, (char **) &spec, 10);
		if (*spec) {
			reason = "invalid bit number";
			goto failed;
		}
	}

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &keyargs.id);

	while (1) {
		r = sc_pkcs15init_generate_key(p15card, profile,
			       	&keyargs);
		if (r != SC_ERROR_NOT_SUPPORTED || !keyargs.onboard_keygen)
			break;
		if (!opt_quiet)
			printf("Warning: card doesn't support on-board "
			       "key generation; using software generation\n");
		keyargs.onboard_keygen = 0;
	}
	if (r != 0)
		goto sc_failed;

	/* Store public key portion on card */
	r = sc_pkcs15init_store_public_key(p15card, profile, &keyargs);

	if (opt_outkey) {
		if (!opt_quiet)
			printf("Writing public key to %s\n", opt_outkey);
		r = do_write_public_key(opt_outkey, opt_format, keyargs.pkey);
	}
	if (r >= 0)
		return 0;

sc_failed:
	reason = sc_strerror(r);
failed:	error("Unable to generate %s key: %s\n", spec, reason);
	return -1;
}

/*
 * Generic funcions go here.
 * I would like to move these into a separate lib one day (soonishly).
 */
static int
sc_pkcs15init_build_aodf(struct sc_profile *profile)
{
	struct sc_pkcs15_card *p15card;
	struct pin_info	*pi;
	int		r;

	p15card = profile->p15_card;

	/* Loop over all PINs and make sure they're sane */
	for (pi = profile->pin_list; pi; pi = pi->next) {
		r = sc_pkcs15_add_object(p15card,
				&p15card->df[SC_PKCS15_AODF],
				0, &pi->pkcs15_obj);
		if (r) {
			error("Failed to add PIN to AODF: %s\n",
					sc_strerror(r));
			return -1;
		}
	}
	return 0;
}

int
sc_pkcs15init_add_app(struct sc_card *card, struct sc_profile *profile)
{
	struct sc_pkcs15_card *p15card = profile->p15_card;
	struct sc_app_info *app;
	int	r;

	p15card->card = card;

	if (card->app_count >= SC_MAX_CARD_APPS) {
		fprintf(stderr,
			"Too many applications on this card.\n");
		return 1;
	}

	/* Get all necessary PINs from user */
	if (do_read_pins(profile))
		return 1;

	/* Build the AODF */
	if (sc_pkcs15init_build_aodf(profile))
		return 1;

	/* Create the application DF and store the PINs */
	if (ops.init_app(profile, card))
		return 1;

	/* Store the PKCS15 information on the card
	 * We cannot use sc_pkcs15_create() because it makes
	 * all sorts of assumptions about DF and EF names, and
	 * doesn't work if secure messaging is required for the
	 * MF (which is the case with the GPK) */
	app = (struct sc_app_info *) calloc(1, sizeof(*app));
	app->path = p15card->file_app->path;
	if (p15card->file_app->namelen <= SC_MAX_AID_SIZE) {
		app->aid_len = p15card->file_app->namelen;
		memcpy(app->aid, p15card->file_app->name, app->aid_len);
	}
	if (p15card->label)
		app->label = strdup(p15card->label);
	/* XXX: encode the DDO? */

	r = sc_pkcs15init_update_dir(card, profile, app);
	if (r >= 0)
		r = sc_pkcs15init_update_tokeninfo(p15card, profile);
	if (r >= 0)
		r = sc_pkcs15init_update_df(p15card, profile,
				SC_PKCS15_AODF);

	if (r < 0) {
		fprintf(stderr,
			"PKCS #15 structure creation failed: %s\n",
			sc_strerror(r));
			return 1;
	}

	printf("Successfully created PKCS #15 meta structure\n");
	return 0;
}

/*
 * Generate a new private key
 */
int
sc_pkcs15init_generate_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	if (keyargs->onboard_keygen)
		return SC_ERROR_NOT_SUPPORTED;

	/* Fall back to software generated keys */
	return sc_pkcs15init_generate_key_soft(p15card, profile, keyargs);
}

static int
sc_pkcs15init_generate_key_soft(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	int	r;

	ossl_seed_random();

	keyargs->pkey = EVP_PKEY_new();
	switch (keyargs->algorithm) {
	case SC_ALGORITHM_RSA: {
			RSA	*rsa;
			BIO	*err;

			err = BIO_new(BIO_s_mem());
			rsa = RSA_generate_key(keyargs->keybits,
					0x10001, NULL, err);
			BIO_free(err);
			if (rsa == 0) {
				error("RSA key generation error");
				return -1;
			}
			EVP_PKEY_assign_RSA(keyargs->pkey, rsa);
			break;
		}
	case SC_ALGORITHM_DSA: {
			DSA	*dsa;
			int	r = 0;

			dsa = DSA_generate_parameters(keyargs->keybits,
					NULL, 0, NULL,
					NULL, NULL, NULL);
			if (dsa)
				r = DSA_generate_key(dsa);
			if (r == 0 || dsa == 0) {
				error("DSA key generation error");
				return -1;
			}
			EVP_PKEY_assign_DSA(keyargs->pkey, dsa);
			break;
		}
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_pkcs15init_store_private_key(p15card, profile, keyargs);
	if (r < 0)
		return r;

	return 0;
}

/*
 * See if there's a PrKDF or PuKDF entry matching this keyinfo.
 * If not, allocate a file and create a corresponding DF entry.
 */
static int
sc_pkcs15init_setup_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs, int is_private,
		struct sc_key_template *out)
{
	struct sc_pkcs15_object	*found;
	int		r, type;

	memset(out, 0, sizeof(*out));
	switch (keyargs->algorithm | (is_private << 16)) {
	case SC_ALGORITHM_RSA | 0x10000:
		type = SC_PKCS15_TYPE_PRKEY_RSA; break;
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
	case SC_ALGORITHM_DSA | 0x10000:
		type = SC_PKCS15_TYPE_PRKEY_DSA; break;
#endif
	case SC_ALGORITHM_RSA:
		type = SC_PKCS15_TYPE_PUBKEY_RSA; break;
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
	case SC_ALGORITHM_DSA:
		type = SC_PKCS15_TYPE_PUBKEY_DSA; break;
#endif
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}


	/* If a key ID has been given, try to locate the key. */
	found = sc_pkcs15init_find_key(p15card, type, &keyargs->id);

	if (found) {
		/* XXX: TBD set up out */
		r = SC_ERROR_NOT_SUPPORTED; /* we don't support updates yet */
	} else {
		/* If there's no such key on the card yet, allocate an ID,
		 * and a file.
		 */
		switch (type & SC_PKCS15_TYPE_CLASS_MASK) {
		case SC_PKCS15_TYPE_PRKEY:
			r = sc_pkcs15init_new_private_key(profile,
					type, keyargs, out);
			break;
		case SC_PKCS15_TYPE_PUBKEY:
			r = sc_pkcs15init_new_public_key(profile,
					type, keyargs, out);
			break;
		default:
			r = SC_ERROR_NOT_SUPPORTED;
		}

	}

	return r;
}

/*
 * Map X509 keyUsage extension bits to PKCS#15 keyUsage bits
 */
static unsigned int	x509_to_pkcs15_private_key_usage[16] = {
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* digitalSignature */
	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,	/* NonRepudiation */
	SC_PKCS15_PRKEY_USAGE_UNWRAP,		/* keyEncipherment */
	SC_PKCS15_PRKEY_USAGE_DECRYPT,		/* dataEncipherment */
	SC_PKCS15_PRKEY_USAGE_DERIVE,		/* keyAgreement */
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* keyCertSign */
	SC_PKCS15_PRKEY_USAGE_SIGN
	| SC_PKCS15_PRKEY_USAGE_SIGNRECOVER,	/* cRLSign */
};
static unsigned int	x509_to_pkcs15_public_key_usage[16] = {
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* digitalSignature */
	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION,	/* NonRepudiation */
	SC_PKCS15_PRKEY_USAGE_WRAP,		/* keyEncipherment */
	SC_PKCS15_PRKEY_USAGE_ENCRYPT,		/* dataEncipherment */
	SC_PKCS15_PRKEY_USAGE_DERIVE,		/* keyAgreement */
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* keyCertSign */
	SC_PKCS15_PRKEY_USAGE_VERIFY
	| SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,	/* cRLSign */
};

static int
sc_pkcs15init_new_key(struct sc_profile *profile, unsigned int type,
		const char *name, struct sc_pkcs15_id *id,
		const char *label,
		unsigned long x509KeyUsage,
		struct sc_key_template *out)
{
	struct sc_key_template *list, *t;
	struct sc_pkcs15_id *tid;
	unsigned int	*tusage, *bits, n, pkcsKeyUsage;
	int		r, is_private;

	if ((type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY) {
		list = profile->prkey_list;
		is_private = 1;
	} else {
		list = profile->pubkey_list;
		is_private = 0;
	}

	/* If we have a certificate, map the key usage */
	bits = is_private? x509_to_pkcs15_private_key_usage
			 : x509_to_pkcs15_public_key_usage;
	for (n = pkcsKeyUsage = 0; n < 16; n++) {
		if (x509KeyUsage & (1 << n))
			pkcsKeyUsage |= bits[n];
	}

	/* First, see if there's a template with a matching
	 * name. If there is no matching template, fail.
	 * */
	if (name) {
		for (t = list; t; t = t->next) {
			if (!strcasecmp(t->ident, name))
				goto found;
		}
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	/* See if there is a key template with a matching ID */
	for (t = list; t; t = t->next) {
		tid = is_private? &t->pkcs15.priv.id : &t->pkcs15.pub.id;
		if (sc_pkcs15_compare_id(tid, id))
			goto found;
	}

	/* See if there is a key template with a matching key usage */
	for (t = list; t; t = t->next) {
		tusage = is_private? &t->pkcs15.priv.usage
				   : &t->pkcs15.pub.usage;
		if (pkcsKeyUsage == *tusage)
			goto found;
	}

	/* Nope. Just use whatever key template was defined first */
	t = list;

found:	*out = *t;

	/* Set the label */
	if (label)
		strcpy(out->pkcs15_obj.label, label);
	if (!out->pkcs15_obj.label[0])
		sprintf(out->pkcs15_obj.label, "%s Key",
				is_private? "Private" : "Public");

	tid = is_private? &out->pkcs15.priv.id : &out->pkcs15.pub.id;
	if (id->len) {
		/* Override ID with the ID specified by caller */
		*tid = *id;
	} else if (!tid->len) {
		/* error("No keyUsage defined for key %s", out->ident); */
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* If we have a keyUsage, set it */
	tusage = is_private? &out->pkcs15.priv.usage : &out->pkcs15.pub.usage;
	if (pkcsKeyUsage) {
		*tusage = pkcsKeyUsage;
	} else if (*tusage == 0) {
		/* error("No keyUsage defined for key %s", out->ident); */
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Now allocate a file */
	n = sc_pkcs15_get_objects(p15card, type, NULL, 0);
	r = profile->ops->allocate_file(profile,
			p15card->card, type, n,
			&out->file);
	if (r < 0) {
		/* error("Unable to allocate key file"); */
		return r;
	}
	if (is_private) {
		out->pkcs15.priv.path = out->file->path;
	} else {
		out->pkcs15.pub.path = out->file->path;
	}
	out->pkcs15_obj.data = &out->pkcs15;
	out->pkcs15_obj.type = type;

	return 0;
}

int
sc_pkcs15init_new_private_key(struct sc_profile *profile,
		unsigned int type,
		struct sc_pkcs15init_keyargs *keyargs,
		struct sc_key_template *out)
{
	int	r;

	r = sc_pkcs15init_new_key(profile, type, 
			keyargs->template_name, &keyargs->id,
			keyargs->label,
			keyargs->cert? keyargs->cert->ex_kusage : 0,
			out);

	/* Find the PIN used to protect this key */
	if (out->pkcs15_obj.auth_id.len) {
		struct sc_pkcs15_object *obj;

		r = sc_pkcs15_find_pin_by_auth_id(p15card,
				&out->pkcs15_obj.auth_id, &obj);
		if (r < 0) {
			/* error("No PIN matching auth_id of private key"); */
			return SC_ERROR_OBJECT_NOT_FOUND;
		}
		out->key_acl = calloc(1, sizeof(struct sc_acl_entry));
		out->key_acl->method = SC_AC_CHV;
		out->key_acl->key_ref =
			((struct sc_pkcs15_pin_info *) obj->data)->reference;
	} else {
		/* XXX flag this as error/warning? */
	}

	r = sc_pkcs15_add_object(p15card, &p15card->df[SC_PKCS15_PRKDF],
		       	0, &out->pkcs15_obj);
	if (r) {
		/* error("failed to add object to PrKDF"); */
		return r;
	}

	/* Return the ID we selected, for reference
	 * (in case the caller wants to know the ID, so he
	 * can store public key/certificate with a corresponding
	 * ID. */
	keyargs->id = out->pkcs15.priv.id;
	return 0;
}

int
sc_pkcs15init_new_public_key(struct sc_profile *profile,
		unsigned int type,
		struct sc_pkcs15init_keyargs *keyargs,
		struct sc_key_template *out)
{
	int		r;

	r = sc_pkcs15init_new_key(profile, type, 
			keyargs->template_name, &keyargs->id,
			keyargs->label,
			keyargs->cert? keyargs->cert->ex_kusage : 0,
			out);

	r = sc_pkcs15_add_object(p15card, &p15card->df[SC_PKCS15_PUKDF],
		       	0, &out->pkcs15_obj);
	if (r) {
		/* error("failed to add object to PuKDF"); */
		return r;
	}

	/* Return the ID we selected, for reference */
	keyargs->id = out->pkcs15.pub.id;
	return 0;
}

/*
 * See if there's a CDF entry matching this certinfo.
 * If not, allocate a file and create a corresponding DF entry.
 */
static int
sc_pkcs15init_setup_cert(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_certargs *certargs,
		struct sc_cert_template *out)
{
	struct sc_pkcs15_object	*found = NULL;
	int		r;

	memset(out, 0, sizeof(*out));

	/* If a key ID has been given, try to locate the key. */
	r = sc_pkcs15_find_cert_by_id(p15card, &certargs->id, &found);

	if (found) {
		/* XXX: TBD set up out */
		r = SC_ERROR_NOT_SUPPORTED; /* we don't support updates yet */
	} else {
		/* If there's no such key on the card yet, allocate an ID,
		 * and a file.
		 */
		r = sc_pkcs15init_new_cert(profile,
				SC_PKCS15_TYPE_CERT_X509,
				certargs->template_name,
				&certargs->id, certargs->label,
				out);
	}

	return r;
}


int
sc_pkcs15init_new_cert(struct sc_profile *profile,
		unsigned int type,
		const char *name, struct sc_pkcs15_id *id,
		const char *label,
		struct sc_cert_template *out)
{
	struct sc_cert_template *t = NULL;
	int		index, r;

	index = sc_pkcs15_get_objects(p15card, type, NULL, 0);

	/* First, try to find a cert template with the given name.
	 * Fail if a name was given, but no match found */
	if (name) {
		for (t = profile->cert_list; t; t = t->next) {
			if (!strcasecmp(t->ident, name))
				goto found;
		}
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	/* See if there is a key template with a matching ID */
	for (t = profile->cert_list; t; t = t->next) {
		if (sc_pkcs15_compare_id(&t->pkcs15.id, id))
			goto found;
	}

	/* Bummer. Just use the first template defined */
	t = profile->cert_list;

found:	*out = *t;

	if (label)
		strcpy(out->pkcs15_obj.label, label);
	if (!out->pkcs15_obj.label[0])
		strcpy(out->pkcs15_obj.label, "Certificate");

	if (id->len) {
		out->pkcs15.id = *id;
	} else if (!out->pkcs15.id.len) {
		/* error("No ID defined for certificate"); */
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	/* Now allocate a file */
	r = profile->ops->allocate_file(profile,
			p15card->card, type, index,
			&out->file);
	if (r < 0) {
		/* error("Unable to allocate certificate file"); */
		return r;
	}
	out->pkcs15.path = out->file->path;
	out->pkcs15_obj.data = &out->pkcs15;
	out->pkcs15_obj.type = type;

	r = sc_pkcs15_add_object(p15card, &p15card->df[SC_PKCS15_CDF],
		       	0, &out->pkcs15_obj);
	if (r) {
		/* error("failed to add object to CDF"); */
		return r;
	}

	/* Return the ID we selected, for reference */
	*id = out->pkcs15.id;
	return 0;
}

/*
 * Find a key given its ID
 */
static int
compare_id(struct sc_pkcs15_object *obj, void *arg)
{
	struct sc_pkcs15_id	*ida, *idb = (struct sc_pkcs15_id *) arg;

	switch (obj->type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		ida = &((struct sc_pkcs15_prkey_info *) obj->data)->id;
		break;
	case SC_PKCS15_TYPE_PUBKEY_RSA:
		ida = &((struct sc_pkcs15_pubkey_info *) obj->data)->id;
		break;
	default:
		return 0;
	}
	return sc_pkcs15_compare_id(ida, idb);
}

struct sc_pkcs15_object *
sc_pkcs15init_find_key(struct sc_pkcs15_card *p15card,
		unsigned int type,
		struct sc_pkcs15_id *id)
{
	struct sc_pkcs15_object	*ret = NULL;

	if (sc_pkcs15_get_objects_cond(p15card, type,
				compare_id, id, &ret, 1) <= 0)
		return NULL;
	return ret;
}
	

/*
 * Store private key
 */
int
sc_pkcs15init_store_private_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	struct sc_key_template info;
	int		r;

	r = sc_pkcs15init_setup_key(p15card, profile, keyargs, 1, &info);
	if (r < 0)
		return r;

	/* XXX: If the card doesn't have support for native keys of
	 * this type, store this key non-natively */

	r = SC_ERROR_NOT_SUPPORTED;
	switch (keyargs->pkey->type) {
	case EVP_PKEY_RSA:
		if (ops.store_rsa) {
			RSA	*rsa = EVP_PKEY_get1_RSA(keyargs->pkey);

			r = ops.store_rsa(profile, card, &info, rsa);
			info.pkcs15.priv.modulus_length = RSA_size(rsa) * 8;
		}
		break;
	case EVP_PKEY_DSA:
		if (ops.store_dsa) {
			DSA	*dsa = EVP_PKEY_get1_DSA(keyargs->pkey);

			r = ops.store_dsa(profile, card, &info, dsa);
			info.pkcs15.priv.modulus_length = DSA_size(dsa) * 8;
		}
		break;
	}
	if (r < 0)
		return r;

	/* Now update the PrKDF */
	return sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_PRKDF);
}

static int
sc_pkcs15init_store_public_key(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_keyargs *keyargs)
{
	struct sc_key_template info;
	unsigned char	*data, *p;
	size_t		size;
	RSA		*rsa;
	int		r;

	r = sc_pkcs15init_setup_key(p15card, profile, keyargs, 0, &info);
	if (r < 0)
		return r;

	switch (keyargs->pkey->type) {
	case EVP_PKEY_RSA:
		rsa = EVP_PKEY_get1_RSA(keyargs->pkey);
		size = i2d_RSAPublicKey(rsa, NULL);
		data = p = malloc(size);
		i2d_RSAPublicKey(rsa, &p);

		info.pkcs15.pub.modulus_length = RSA_size(rsa) * 8;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	r = sc_pkcs15init_update_file(profile, info.file, data, size);
	free(data);

	if (r < 0)
		return r;

	/* Now update the PuKDF */
	return sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_PUKDF);
}

static int
sc_pkcs15init_store_certificate(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		struct sc_pkcs15init_certargs *args)
{
	struct sc_cert_template info;
	unsigned char	*data, *p;
	size_t		size;
	int		r;

	r = sc_pkcs15init_setup_cert(p15card, profile, args, &info);
	if (r < 0)
		return r;

	size = i2d_X509(args->cert, NULL);
	data = p = malloc(size);
	i2d_X509(args->cert, &p);

	r = sc_pkcs15init_update_file(profile, info.file, data, size);
	free(data);

	if (r < 0)
		return r;

	/* Now update the CDF */
	return sc_pkcs15init_update_df(p15card, profile, SC_PKCS15_CDF);
}

static int
sc_pkcs15init_update_dir(struct sc_card *card,
		struct sc_profile *profile,
		struct sc_app_info *app)
{
	int	r, retry = 1;

	do {
		struct file_info *info;
		struct sc_path	path;

		card->ctx->log_errors = 0;
		r = sc_enum_apps(card);
		card->ctx->log_errors = 1;

		if (r != SC_ERROR_FILE_NOT_FOUND)
			break;

		sc_format_path("3F002F00", &path);
		info = sc_profile_find_file_by_path(profile, &path);
		if (info == NULL)
			return r;
		r = sc_pkcs15init_update_file(profile, info->file, NULL, 0);
	} while (retry--);

	if (r >= 0) {
		card->app[card->app_count++] = app;
		r = sc_update_dir(card, NULL);
	}
	return r;
}

static int
sc_pkcs15init_update_tokeninfo(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_context *ctx = p15card->card->ctx;
	u8		*buf = NULL;
	size_t		size;
	int		r;

	r = sc_pkcs15_encode_tokeninfo(ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile,
			       p15card->file_tokeninfo, buf, size);
	if (buf)
		free(buf);
	return r;
}

static int
sc_pkcs15init_update_odf(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile)
{
	struct sc_context *ctx = p15card->card->ctx;
	u8		*buf = NULL;
	size_t		size;
	int		r;

	r = sc_pkcs15_encode_odf(ctx, p15card, &buf, &size);
	if (r >= 0)
		r = sc_pkcs15init_update_file(profile,
			       p15card->file_odf, buf, size);
	if (buf)
		free(buf);
	return r;
}

static int
sc_pkcs15init_update_df(struct sc_pkcs15_card *p15card,
		struct sc_profile *profile,
		unsigned int df_type)
{
	struct sc_pkcs15_df *df;
	struct sc_file	*file = NULL;
	u8		*buf = NULL;
	size_t		bufsize;
	unsigned int	j;
	int		r = 0;

	df = &p15card->df[df_type];
	if (df->count == 0) {
		file = profile->df[df_type];
		if (file == NULL) {
			/* error("Profile doesn't define a DF file %u",
			 		df_type); */
			return SC_ERROR_NOT_SUPPORTED;
		}
		df->file[df->count++] = file;
		if ((r = sc_pkcs15init_update_odf(p15card, profile)) < 0)
			return r;
	}

	for (j = 0; r >= 0 && j < df->count; j++) {
		struct file_info *info;
		
		file = df->file[j];
		info = sc_profile_find_file_by_path(profile, &file->path);
		if (info != NULL)
			file = info->file;
		r = sc_pkcs15_encode_df(card->ctx, df, j, &buf, &bufsize);
		if (r >= 0) {
			r = sc_pkcs15init_update_file(profile,
					file, buf, bufsize);
			free(buf);
		}
	}

	return r;
}

/*
 * Associate all PINs given on the command line with the
 * CHVs used by the profile
 */
static int
set_pins_from_args(struct sc_profile *pro)
{
	static char	*types[2] = { "CHV1", "CHV2" };
	struct pin_info	*info;
	int		n, i;

	for (n = 0; n < 2; n++) {
		if (!(info = sc_profile_find_pin(pro, types[n])))
			continue;

		for (i = 0; i < 2; i++)
			info->secret[i] = opt_pins[2*n + i];
	}
	return 0;
}

/*
 * Read one PIN/PUK
 */
static int
read_one_pin(struct pin_info *info, unsigned int n)
{
	static char	*names[2] = { "PIN", "PUK" };
	char		prompt[64], *pass;
	int		passlen;

	if (info->pkcs15_obj.label[0]) {
		sprintf(prompt, "Please enter %s for %s (%s):",
				names[n], info->ident,
				info->pkcs15_obj.label);
	} else {
		sprintf(prompt, "Please enter %s for %s:",
				names[n], info->ident);
	}

	while (info->secret[n] == NULL) {
		pass = getpass(prompt);
		passlen = strlen(pass);
		if (passlen < info->pkcs15.min_length) {
			error("Password too short (%u characters min)",
					info->pkcs15.min_length);
			continue;
		}
		if (passlen > info->pkcs15.stored_length) {
			error("Password too long (%u characters max)",
					info->pkcs15.stored_length);
			continue;
		}
		info->secret[n] = strdup(pass);
		memset(pass, 0, passlen);
	}
	return 0;
}

/*
 * Get all the PINs and PUKs we need from the user
 */
static int
do_read_pins(struct sc_profile *pro)
{
	static char	*types[3] = { "CHV1", "CHV2", "CHV3" };
	int		n, r;

	for (n = 0; n < 3; n++) {
		struct pin_info	*info;
		struct sc_file	*file;
		int		i, npins = 2;

		if (!(info = sc_profile_find_pin(pro, types[n])))
			continue;

		/* If the PIN file already exists, read just the PIN */
		file = info->file->file;
		ctx->log_errors = 0;
		if (!sc_select_file(card, &file->path, NULL)) {
			printf("PIN file for %s already exists.\n", info->ident);
			npins = 1;
		}
		ctx->log_errors = 1;

		/* Don't ask for a PUK if there's not supposed to be one */
		if (info->attempt[1] == 0)
			npins = 1;

		/* Loop over all PINs and PUKs */
		for (i = 0; i < npins; i++) {
			if ((r = read_one_pin(info, i)) < 0)
				return r;
		}
	}
	return 0;
}

static int
do_verify_pin(struct sc_profile *pro, unsigned int type, unsigned int reference)
{
	const char	*ident;
	struct auth_info *auth;
	struct pin_info	*info;
	char		*pin;
	int		r;
	u8		pinbuf[32];

	ident = "authentication data";
	if (type == SC_AC_CHV)
		ident = "PIN";
	else if (type == SC_AC_PRO)
		ident = "secure messaging key";
	else if (type == SC_AC_AUT)
		ident = "authentication key";

	if ((auth = sc_profile_find_key(pro, type, reference))
	 || (auth = sc_profile_find_key(pro, type, -1))) {
		r = sc_verify(card, type, reference,
				       	auth->key, auth->key_len, NULL);
		if (r) {
			error("Failed to verify %s (ref=0x%x)",
				ident, reference);
			return r;
		}
		return 0;
	}

	if (type != SC_AC_CHV)
		goto no_secret;

	for (info = pro->pin_list; info; info = info->next) {
		if (info->pkcs15.reference == reference)
			break;
	}
	if (info == NULL)
		goto no_secret;

	if (!info->secret[0] && (r = read_one_pin(info, 0)) < 0)
		return r;

	pin = info->secret[0];
	assert(pro->pin_maxlen < sizeof(pinbuf));
	memset(pinbuf, pro->pin_pad_char, pro->pin_maxlen);
	/* FIXME: shouldn't assume that encoding is ascii-numeric */
	strncpy((char *) pinbuf, pin, strlen(pin));
	
	return sc_verify(card, SC_AC_CHV, reference,
				pinbuf, pro->pin_maxlen, NULL);

no_secret:
	/* No secret found that we could present.
	 * XXX: Should we flag an error here, or let the
	 * operation proceed and then fail? */
	return 0;
}

int
sc_pkcs15init_authenticate(struct sc_profile *pro,
		struct sc_file *file, int op)
{
	const struct sc_acl_entry *acl;
	int		r = 0;

	acl = sc_file_get_acl_entry(file, op);
	for (; r == 0 && acl; acl = acl->next) {
		if (acl->method == SC_AC_NEVER)
			return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		if (acl->method == SC_AC_NONE)
			break;
		r = do_verify_pin(pro, acl->method, acl->key_ref);
	}
	return r;
}

int
do_select_parent(struct sc_profile *pro, struct sc_file *file,
		struct sc_file **parent)
{
	struct sc_path	path;
	struct file_info *info = NULL;
	int		r;

	/* Get the parent's path */
	path = file->path;
	if (path.len >= 2)
		path.len -= 2;
	if (path.len == 0)
		sc_format_path("3F00", &path);

	info = sc_profile_find_file_by_path(pro, &path);
	ctx->log_errors = 0;
	if (info != NULL) {
		sc_file_dup(parent, info->file);
		r = sc_select_file(card, &path, NULL);
	} else {
		/* Select the parent DF. */
		r = sc_select_file(card, &path, parent);
	}
	ctx->log_errors = 1;
	/* If DF doesn't exist, create it (unless it's the MF,
	 * but then something's badly broken anyway :-) */
	if (r == SC_ERROR_FILE_NOT_FOUND && path.len != 2) {
		if (info != NULL
		 && (r = sc_pkcs15init_create_file(pro, info->file)) == 0)
			r = sc_select_file(card, &path, NULL);
	}
	return r;
}

int
sc_pkcs15init_create_file(struct sc_profile *pro, struct sc_file *file)
{
	struct sc_file	*parent = NULL;
	int		r;

	/* Select parent DF and verify PINs/key as necessary */
	if ((r = do_select_parent(pro, file, &parent)) < 0
	 || (r = sc_pkcs15init_authenticate(pro, parent, SC_AC_OP_CREATE)) < 0) 
		goto out;

	r = sc_create_file(card, file);

out:	if (parent)
		sc_file_free(parent);
	return r;
}

int
sc_pkcs15init_update_file(struct sc_profile *profile,
	       	struct sc_file *file, void *data, unsigned int datalen)
{
	int		r;

	ctx->log_errors = 0;
	if ((r = sc_select_file(card, &file->path, NULL)) < 0) {
		ctx->log_errors = 1;
		/* Create file if it doesn't exist */
		if (file->size < datalen)
			file->size = datalen;
		if (r != SC_ERROR_FILE_NOT_FOUND
		 || (r = sc_pkcs15init_create_file(profile, file)) < 0
		 || (r = sc_select_file(card, &file->path, NULL)) < 0)
			return r;
	}
	ctx->log_errors = 1;

	/* Present authentication info needed */
	r = sc_pkcs15init_authenticate(profile, file, SC_AC_OP_UPDATE);
	if (r >= 0 && datalen)
		r = sc_update_binary(card, 0, data, datalen, 0);

	return r;
}

/*
 * Read a private key
 */
static EVP_PKEY *
do_read_pem_private_key(const char *filename, const char *passphrase)
{
	BIO		*bio;
	EVP_PKEY	*pk;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
	pk = PEM_read_bio_PrivateKey(bio, 0, 0, (char *) passphrase);
	BIO_free(bio);
	if (pk == NULL) 
		ossl_print_errors();
	return pk;
}

static EVP_PKEY *
do_read_pkcs12_private_key(const char *filename, const char *passphrase,
		X509 **xp)
{
	BIO		*bio;
	PKCS12		*p12;
	EVP_PKEY	*pk = NULL;

	*xp = NULL;
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
	p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (p12) {
		PKCS12_parse(p12, passphrase, &pk, xp, NULL);
		if (pk)
			CRYPTO_add(&pk->references, 1, CRYPTO_LOCK_EVP_PKEY);
		if (*xp)
			CRYPTO_add(&(*xp)->references, 1, CRYPTO_LOCK_X509);
	}
	PKCS12_free(p12);
	if (pk == NULL) 
		ossl_print_errors();
	return pk;
}

static int
do_read_private_key(const char *filename, const char *format,
			EVP_PKEY **pk, X509 **xp)
{
	char	*passphrase = NULL;

	*xp = NULL;
	while (1) {
		if (!format || !strcasecmp(format, "pem")) {
			*pk = do_read_pem_private_key(filename, passphrase);
		} else if (!strcasecmp(format, "pkcs12")) {
			*pk = do_read_pkcs12_private_key(filename,
					passphrase, xp);
		} else {
			error("Error when reading private key. "
			      "Key file format \"%s\" not supported.\n",
			      format);
			return SC_ERROR_NOT_SUPPORTED;
		}

		if (*pk || passphrase)
			break;
		if ((passphrase = opt_passphrase) != 0)
			continue;
		passphrase = getpass("Please enter passphrase "
				     "to unlock secret key: ");
		if (!passphrase)
			break;
	}
	if (passphrase)
		memset(passphrase, 0, strlen(passphrase));
	if (!*pk)
		fatal("Unable to read private key from %s\n", filename);
	return 0;
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
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
	pk = PEM_read_bio_PUBKEY(bio, 0, 0, NULL);
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
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
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
		fatal("Error when reading public key. "
		      "File format \"%s\" not supported.\n",
		      format);
	}

	if (!*out)
		fatal("Unable to read public key from %s\n", name);
	return 0;
}

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
		fatal("Unable to open %s: %m", filename);
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

/*
 * Read a certificate
 */
static X509 *
do_read_pem_certificate(const char *filename)
{
	BIO	*bio;
	X509	*xp;

	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
	xp = PEM_read_bio_X509(bio, 0, 0, 0);
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
	if (BIO_read_filename(bio, filename) < 0)
		fatal("Unable to open %s: %m", filename);
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
		fatal("Error when reading certificate. "
		      "File format \"%s\" not supported.\n",
		      format);
	}

	if (!*out)
		fatal("Unable to read certificate from %s\n", name);
	return 0;
}

/*
 * Handle one option
 */
static void
handle_option(int c)
{
	switch (c) {
	case 'C':
		opt_action = ACTION_INIT;
		break;
	case 'E':
		opt_erase++;
		break;
	case 'G':
		opt_action = ACTION_GENERATE_KEY;
		opt_newkey = optarg;
		break;
	case 'S':
		opt_action = ACTION_STORE_PRIVKEY;
		opt_infile = optarg;
		break;
	case 'P':
		opt_action = ACTION_STORE_PUBKEY;
		opt_infile = optarg;
		break;
	case 'X':
		opt_action = ACTION_STORE_CERT;
		opt_infile = optarg;
		break;
	case 'd':
		opt_debug++;
		break;
	case 'f':
		opt_format = optarg;
		break;
	case 'i':
		opt_objectid = optarg;
		break;
	case 'o':
		opt_outkey = optarg;
		break;
	case 'p':
		opt_profile = optarg;
		break;
	case OPT_OPTIONS:
		read_options_file(optarg);
		break;
	case OPT_PIN1: case OPT_PUK1:
	case OPT_PIN2: case OPT_PUK2:
		opt_pins[c & 3] = optarg;
		break;
	case OPT_PASSPHRASE:
		opt_passphrase = optarg;
		break;
	default:
		print_usage_and_die("pkcs15-init");
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
			fatal("Internal: bad has_arg value");
		}
	}
	sp[0] = 0;

	while ((c = getopt_long(argc, argv, shortopts, options, &i)) != -1)
		handle_option(c);
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
		fatal("Unable to open %s: %m", filename);
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
				error("Unknown option \"%s\"\n", name);
				print_usage_and_die("pkcs15-init");
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
				error("Option %s: missing argument\n", name);
				print_usage_and_die("pkcs15-init");
			}
			handle_option(o->val);
			name = strtok(NULL, " \t");
		}
	}
	fclose(fp);
}


/*
 * OpenSSL helpers
 */
static void
ossl_print_errors()
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

static void
ossl_seed_random(void)
{
	static int	initialized = 0;

	if (initialized)
		return;

	/* XXX: won't OpenSSL do that itself? */
	if (!RAND_load_file("/dev/urandom", 32))
		fatal("Unable to seed random number pool for key generation");
	initialized = 1;
}
