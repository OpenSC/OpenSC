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
#include <opensc/pkcs15.h>
#include <opensc/pkcs15-init.h>
#include "util.h"

const char *app_name = "pkcs15-init";

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

/* Local functions */
static int	connect(int);
static int	do_init_app(struct sc_profile *);
static int	do_store_pin(struct sc_profile *);
static int	do_generate_key(struct sc_profile *, const char *);
static int	do_store_private_key(struct sc_profile *);
static int	do_store_public_key(struct sc_profile *, EVP_PKEY *);
static int	do_store_certificate(struct sc_profile *);
static int	do_convert_private_key(struct sc_pkcs15_prkey *, EVP_PKEY *);
static int	do_convert_public_key(struct sc_pkcs15_pubkey *, EVP_PKEY *);
static int	do_convert_cert(sc_pkcs15_der_t *, X509 *);


static int	init_keyargs(struct sc_pkcs15init_prkeyargs *);
static int	read_one_pin(struct sc_profile *, const char *,
			const struct sc_pkcs15_pin_info *, int, char **);
static int	get_pin_callback(struct sc_profile *profile,
			int id, const struct sc_pkcs15_pin_info *info,
			u8 *pinbuf, size_t *pinsize);

static int	do_generate_key_soft(int, unsigned int, EVP_PKEY **);
static int	do_read_private_key(const char *, const char *,
				EVP_PKEY **, X509 **);
static int	do_read_public_key(const char *, const char *, EVP_PKEY **);
static int	do_read_certificate(const char *, const char *, X509 **);
static void	parse_commandline(int argc, char **argv);
static void	read_options_file(const char *);
static void	ossl_print_errors(void);


enum {
	OPT_OPTIONS = 0x100,
	OPT_PASSPHRASE,
	OPT_PUBKEY,
	OPT_EXTRACTABLE,
	OPT_UNPROTECTED,

	OPT_PIN1 = 0x10000,	/* don't touch these values */
	OPT_PUK1 = 0x10001,
	OPT_PIN2 = 0x10002,
	OPT_PUK2 = 0x10003,
	OPT_SERIAL=0x10004,
};

const struct option	options[] = {
	{ "erase-card",		no_argument, 0,		'E' },
	{ "create-pkcs15",	no_argument, 0,		'C' },
	{ "store-pin",		no_argument, 0,		'P' },
	{ "pin",		required_argument, 0,	OPT_PIN1 },
	{ "puk",		required_argument, 0,	OPT_PUK1 },
	{ "so-pin",		required_argument, 0,	OPT_PIN2 },
	{ "so-puk",		required_argument, 0,	OPT_PUK2 },
	{ "serial",		required_argument, 0,	OPT_SERIAL },
	{ "auth-id",		required_argument, 0,	'a' },
	{ "id",			required_argument, 0,	'i' },
	{ "label",		required_argument, 0,	'l' },
	{ "generate-key",	required_argument, 0,	'G' },
	{ "output-file",	required_argument, 0,	'o' },
	{ "store-private-key",	required_argument, 0,	'S' },
	{ "store-public-key",	required_argument, 0,	OPT_PUBKEY },
	{ "format",		required_argument, 0,	'f' },
	{ "passphrase",		required_argument, 0,	OPT_PASSPHRASE },
	{ "store-certificate",	required_argument, 0,	'X' },

	{ "extractable",	no_argument, 0,		OPT_EXTRACTABLE },
	{ "insecure",		no_argument, 0,		OPT_UNPROTECTED },

	{ "profile",		required_argument, 0,	'p' },
	{ "options-file",	required_argument, 0,	OPT_OPTIONS },
	{ "debug",		no_argument, 0,		'd' },
	{ 0, 0, 0, 0 }
};
const char *		option_help[] = {
	"Erase the smart card",
	"Creates a new PKCS #15 structure",
	"Store a new PIN/PUK on the card",
	"Specify PIN",
	"Specify unblock PIN",
	"Specify security officer (SO) PIN",
	"Specify unblock PIN for SO PIN",
	"Specify the serial number of the card",
	"Specify ID of PIN to use/create",
	"Specify ID of key/certificate",
	"Specify label of PIN/key",
	"Generate a new key and store it on the card",
	"Output public portion of generated key to file",
	"Store private key",
	"Store public key",
	"Specify key file format (default PEM)",
	"Specify passphrase for unlocking secret key",
	"Store an X.509 certificate",

	"Private key stored as an extractable key",
	"Insecure mode: do not require PIN/passphrase for private key",

	"Specify the profile to use",
	"Read additional command line options from file",
	"Enable debugging output",
};

enum {
	ACTION_NONE = 0,
	ACTION_INIT,
	ACTION_STORE_PIN,
	ACTION_GENERATE_KEY,
	ACTION_STORE_PRIVKEY,
	ACTION_STORE_PUBKEY,
	ACTION_STORE_CERT
};
static char *			action_names[] = {
	"do nothing",
	"create PKCS #15 meta structure",
	"store PIN",
	"generate key",
	"store private key",
	"store public key",
	"store certificate"
};

static struct sc_context *	ctx = NULL;
static struct sc_card *		card = NULL;
static struct sc_pkcs15_card *	p15card = NULL;
static int			opt_debug = 0,
				opt_quiet = 0,
				opt_action = 0,
				opt_erase = 0,
				opt_extractable = 0,
				opt_unprotected = 0;
static char *			opt_profile = "pkcs15";
static char *			opt_infile = 0;
static char *			opt_format = 0;
static char *			opt_authid = 0;
static char *			opt_objectid = 0;
static char *			opt_objectlabel = 0;
static char *			opt_pins[4];
static char *			opt_serial = 0;
static char *			opt_passphrase = 0;
static char *			opt_newkey = 0;
static char *			opt_outkey = 0;

static struct sc_pkcs15init_callbacks callbacks = {
	error,			/* error() */
	NULL,			/* debug() */
	get_pin_callback,	/* get_pin() */
	NULL			/* get_secret() */
};

int
main(int argc, char **argv)
{
	struct sc_profile	*profile;
	int			opt_reader = 0;
	int			r = 0;

	/* OpenSSL magic */
	SSLeay_add_all_algorithms();
	CRYPTO_malloc_init();
#ifdef RANDOM_POOL
	if (!RAND_load_file(RANDOM_POOL, 32))
		fatal("Unable to seed random number pool for key generation");
#endif

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

	sc_pkcs15init_set_callbacks(&callbacks);

	/* Bind the card-specific operations and load the profile */
	if ((r = sc_pkcs15init_bind(card, opt_profile, &profile)) < 0)
		return 1;

	if (opt_action == ACTION_INIT) {
		r = do_init_app(profile);
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

	if (opt_action == ACTION_STORE_PIN)
		r = do_store_pin(profile);
	else if (opt_action == ACTION_STORE_PRIVKEY)
		r = do_store_private_key(profile);
	else if (opt_action == ACTION_STORE_PUBKEY)
		r = do_store_public_key(profile, NULL);
	else if (opt_action == ACTION_STORE_CERT)
		r = do_store_certificate(profile);
	else if (opt_action == ACTION_GENERATE_KEY)
		r = do_generate_key(profile, opt_newkey);
	else
		fatal("Action not yet implemented\n");

done:	if (r < 0) {
		fprintf(stderr, "Failed to %s: %s\n",
				action_names[opt_action],
				sc_strerror(r));
	} else if (!opt_quiet) {
		printf("Was able to %s successfully.\n",
				action_names[opt_action]);
	}

	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card, 0);
	}
	sc_release_context(ctx);
	return r < 0? 1 : 0;
}

static int
connect(int reader)
{
	int	r;

	r = sc_establish_context(&ctx, app_name);
	if (r) {
		error("Failed to establish context: %s\n", sc_strerror(r));
		return 0;
	}
	if (opt_debug) {
		ctx->debug = opt_debug;
		ctx->debug_file = stderr;
	}
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
 * Initialize pkcs15 application
 */
static int
do_init_app(struct sc_profile *profile)
{
	struct sc_pkcs15init_initargs args;
	int	r = 0;

	if (opt_erase)
		r = sc_pkcs15init_erase_card(card, profile);
	if (r < 0)
		return r;

	memset(&args, 0, sizeof(args));
	args.so_pin = (const u8 *) opt_pins[OPT_PIN2 & 3];
	if (args.so_pin)
		args.so_pin_len = strlen((char *) args.so_pin);
	args.so_puk = (const u8 *) opt_pins[OPT_PUK2 & 3];
	if (args.so_puk)
		args.so_puk_len = strlen((char *) args.so_puk);
	args.serial = (const char *) opt_serial;
	
	return sc_pkcs15init_add_app(card, profile, &args);
}

/*
 * Store a PIN/PUK pair
 */
static int
do_store_pin(struct sc_profile *profile)
{
	struct sc_pkcs15init_pinargs args;
	struct sc_pkcs15_pin_info info;

	if (!opt_authid) {
		error("No auth id specified\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (opt_pins[0] == NULL) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_USER_PIN, &info);
		read_one_pin(profile, "New user PIN", &info, 0,
				&opt_pins[0]);
	}
	if (*opt_pins[0] == '\0') {
		error("You must specify a PIN\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_pins[1] == NULL) {
		sc_pkcs15init_get_pin_info(profile,
				SC_PKCS15INIT_SO_PIN, &info);
		read_one_pin(profile, "Unlock code for new user PIN",
				&info, 1, &opt_pins[1]);
	}

	memset(&args, 0, sizeof(args));
	sc_pkcs15_format_id(opt_authid, &args.auth_id);
	args.pin = (u8 *) opt_pins[0];
	args.pin_len = strlen(opt_pins[0]);
	args.puk = (u8 *) opt_pins[1];
	args.puk_len = opt_pins[1]? strlen(opt_pins[1]) : 0;
	args.label = opt_objectlabel;

	return sc_pkcs15init_store_pin(p15card, profile, &args);
}


/*
 * Store a private key
 */
static int
do_store_private_key(struct sc_profile *profile)
{
	struct sc_pkcs15init_prkeyargs args;
	EVP_PKEY	*pkey = NULL;
	X509		*cert = NULL;
	int		r;

	if ((r = init_keyargs(&args)) < 0)
		return r;

	r = do_read_private_key(opt_infile, opt_format, &pkey, &cert);
	if (r < 0)
		return r;

	if ((r = do_convert_private_key(&args.key, pkey)) < 0)
		return r;
	if (cert)
		args.x509_usage = cert->ex_kusage;

	r = sc_pkcs15init_store_private_key(p15card, profile, &args, NULL);
	if (r < 0)
		return r;

	/* If there's a certificate as well (e.g. when reading the
	 * private key from a PKCS #12 file) store it, too.
	 * Otherwise store the public key.
	 */
	if (cert) {
		struct sc_pkcs15init_certargs cargs;

		memset(&cargs, 0, sizeof(cargs));
		cargs.id = args.id;
		cargs.x509_usage = cert->ex_kusage;
		r = do_convert_cert(&cargs.der_encoded, cert);
		if (r >= 0)
			r = sc_pkcs15init_store_certificate(p15card, profile,
			       	&cargs, NULL);
		free(cargs.der_encoded.value);
	} else {
		r = do_store_public_key(profile, pkey);
	}

	return r;
}

/*
 * Store a public key
 */
static int
do_store_public_key(struct sc_profile *profile, EVP_PKEY *pkey)
{
	struct sc_pkcs15init_pubkeyargs args;
	int		r = 0;

	memset(&args, 0, sizeof(args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	if (opt_objectlabel)
		args.label = opt_objectlabel;

	if (pkey == NULL)
		r = do_read_public_key(opt_infile, opt_format, &pkey);
	if (r >= 0)
		r = do_convert_public_key(&args.key, pkey);
	if (r >= 0)
		r = sc_pkcs15init_store_public_key(p15card, profile,
					&args, NULL);

	return r;
}

/*
 * Download certificate to card
 */
static int
do_store_certificate(struct sc_profile *profile)
{
	struct sc_pkcs15init_certargs args;
	X509	*cert;
	int	r;

	memset(&args, 0, sizeof(args));

	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args.id);
	args.label = opt_objectlabel;

	r = do_read_certificate(opt_infile, opt_format, &cert);
	if (r >= 0)
		r = do_convert_cert(&args.der_encoded, cert);
	if (r >= 0)
		r = sc_pkcs15init_store_certificate(p15card, profile,
					&args, NULL);

	return r;
}

/*
 * Generate a new private key
 */
static int
do_generate_key(struct sc_profile *profile, const char *spec)
{
	struct sc_pkcs15init_prkeyargs args;
	unsigned int	evp_algo, keybits = 1024;
	int		r;

	if ((r = init_keyargs(&args)) < 0)
		return r;

	/* Parse the key spec given on the command line */
	if (!strncasecmp(spec, "rsa", 3)) {
		args.key.algorithm = SC_ALGORITHM_RSA;
		evp_algo = EVP_PKEY_RSA;
		spec += 3;
	} else if (!strncasecmp(spec, "dsa", 3)) {
		args.key.algorithm = SC_ALGORITHM_DSA;
		evp_algo = EVP_PKEY_DSA;
		spec += 3;
	} else {
		error("Unknown algorithm \"%s\"", spec);
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (*spec == '/' || *spec == '-')
		spec++;
	if (*spec) {
		char	*end;

		keybits = strtoul(spec, &end, 10);
		if (*end) {
			error("Invalid number of key bits \"%s\"", spec);
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	}

	r = sc_pkcs15init_generate_key(p15card, profile, &args, keybits, NULL);
	if (r < 0) {
		EVP_PKEY	*pkey;

		if (r != SC_ERROR_NOT_SUPPORTED)
			return r;
		if (!opt_quiet)
			printf("Warning: card doesn't support on-board "
			       "key generation; using software generation\n");

		/* Generate the key ourselves */
		r = do_generate_key_soft(evp_algo, keybits, &pkey);
		if (r >= 0) {
			r = do_convert_private_key(&args.key, pkey);
		}

		if (r >= 0)
			r = sc_pkcs15init_store_private_key(p15card, profile,
					&args, NULL);

		/* Store public key portion on card */
		if (r >= 0)
			r = do_store_public_key(profile, pkey);

		EVP_PKEY_free(pkey);
		if (r < 0)
			return r;
	}

	return r;
}

int
init_keyargs(struct sc_pkcs15init_prkeyargs *args)
{
	memset(args, 0, sizeof(*args));
	if (opt_objectid)
		sc_pkcs15_format_id(opt_objectid, &args->id);
	if (opt_authid) {
		sc_pkcs15_format_id(opt_authid, &args->auth_id);
	} else if (!opt_unprotected) {
		error("no PIN given for key - either use --unprotected or \n"
		      "specify a PIN using --auth-id");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	if (opt_extractable) {
		args->extractable |= SC_PKCS15INIT_EXTRACTABLE;
		if (opt_passphrase) {
			args->passphrase = opt_passphrase;
		} else {
			if (!opt_unprotected) {
				error("no pass phrase given for key - "
				      "either use --unprotected or\n"
				      "specify a pass phrase using "
				      "--passphrase");
				return SC_ERROR_PASSPHRASE_REQUIRED;
			}
			args->extractable |= SC_PKCS15INIT_NO_PASSPHRASE;
		}
	}
	args->label = opt_objectlabel;
	return 0;
}

/*
 * Callbacks from the pkcs15init to retrieve PINs
 */
static int
read_one_pin(struct sc_profile *profile, const char *name,
		const struct sc_pkcs15_pin_info *info,
		int optional, char **out)
{
	char	*pin;
	size_t	len;

	printf("%s required.\n", name);
	while (1) {
		pin = getpass("Please enter code: ");
		len = strlen(pin);
		if (info == NULL)
			break;
		if (len == 0 && optional)
			return 0;
		if (len < info->min_length) {
			error("Password too short (%u characters min)",
					info->min_length);
			continue;
		}
		if (len > info->stored_length) {
			error("Password too long (%u characters max)",
					info->stored_length);
			continue;
		}

		break;
	}

	*out = strdup(pin);
	memset(pin, 0, len);
	return 1;
}

static int
get_pin_callback(struct sc_profile *profile,
		int id, const struct sc_pkcs15_pin_info *info,
		u8 *pinbuf, size_t *pinsize)
{
	char	*name = NULL, *secret = NULL;
	size_t	len;

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
	default:
		return SC_ERROR_INTERNAL;
	}

	if (secret == NULL
	 && !read_one_pin(profile, name, NULL, 0, &secret))
		return SC_ERROR_INTERNAL;
	len = strlen(secret);
	if (len + 1 > *pinsize)
		return SC_ERROR_BUFFER_TOO_SMALL;
	memcpy(pinbuf, secret, len + 1);
	*pinsize = len;
	return 0;
}

/*
 * Generate a private key
 */
int
do_generate_key_soft(int algorithm, unsigned int bits, EVP_PKEY **res)
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
				fatal("RSA key generation error");
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
				fatal("DSA key generation error");
			EVP_PKEY_assign_DSA(*res, dsa);
			break;
		}
	default:
		fatal("Unable to generate key: unsupported algorithm");
	}
	return 0;
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

static int
do_convert_bignum(sc_pkcs15_bignum_t *dst, BIGNUM *src)
{
	if (src == 0)
		return 0;
	dst->len = BN_num_bytes(src);
	dst->data = malloc(dst->len);
	BN_bn2bin(src, dst->data);
	return 1;
}

int
do_convert_private_key(struct sc_pkcs15_prkey *key, EVP_PKEY *pk)
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
			fatal("Invalid/incomplete RSA key.\n");
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
		fatal("Unsupported key algorithm\n");
	}

	return 0;
}

int
do_convert_public_key(struct sc_pkcs15_pubkey *key, EVP_PKEY *pk)
{
	switch (pk->type) {
	case EVP_PKEY_RSA: {
		struct sc_pkcs15_pubkey_rsa *dst = &key->u.rsa;
		RSA *src = EVP_PKEY_get1_RSA(pk);

		key->algorithm = SC_ALGORITHM_RSA;
		if (!do_convert_bignum(&dst->modulus, src->n)
		 || !do_convert_bignum(&dst->exponent, src->e))
			fatal("Invalid/incomplete RSA key.\n");
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
		fatal("Unsupported key algorithm\n");
	}

	return 0;
}

int
do_convert_cert(sc_pkcs15_der_t *der, X509 *cert)
{
	unsigned char	*p;

	der->len = i2d_X509(cert, NULL);
	der->value = p = malloc(der->len);
	i2d_X509(cert, &p);
	return 0;
}

/*
 * Handle one option
 */
static void
handle_option(int c)
{
	switch (c) {
	case 'a':
		opt_authid = optarg;
		break;
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
		opt_action = ACTION_STORE_PIN;
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
	case 'l':
		opt_objectlabel = optarg;
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
	case OPT_SERIAL:
		opt_serial = optarg;
		break;
	case OPT_PASSPHRASE:
		opt_passphrase = optarg;
		break;
	case OPT_PUBKEY:
		opt_action = ACTION_STORE_PUBKEY;
		opt_infile = optarg;
		break;
	case OPT_UNPROTECTED:
		opt_unprotected++;
		break;
	case OPT_EXTRACTABLE:
		opt_extractable++;
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
