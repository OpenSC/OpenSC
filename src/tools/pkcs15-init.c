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
 * on the card. These should be implemented in pkcs-<cardname>.c
 *
 * Copyright (C) 2002, Olaf Kirch <okir@lst.de>
 */

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
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
static int	pkcs15_init(struct sc_profile *);
static int	pkcs15_generate_key(struct sc_profile *);
static int	pkcs15_generate_key_soft(struct sc_profile *,
			unsigned int, unsigned int);
static int	pkcs15_store_key(struct sc_profile *, EVP_PKEY *);
static int	pkcs15_write(struct sc_profile *,
			const char *name, pkcs15_encoder, int);
static int	pkcs15_write_df(struct sc_profile *,
			struct sc_pkcs15_df *, unsigned int);
static int	do_read_pins(struct sc_profile *);
static int	do_set_pins(struct sc_profile *);
static int	do_read_private_key(const char *, const char *, EVP_PKEY **);
static int	do_write_public_key(const char *, const char *, EVP_PKEY *);
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
	{ "pubkey-file",	required_argument, 0,	'o' },
	{ "store-key",		required_argument, 0,	'S' },
	{ "key-format",		required_argument, 0,	'f' },
	{ "passphrase",		required_argument, 0,	OPT_PASSPHRASE },

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
	"Specify key file format (default PEM)",

	"Specify the profile to use",
	"Read additional command line options from file",
	"Enable debugging output",
};

enum {
	ACTION_NONE = 0,
	ACTION_INIT,
	ACTION_GENERATE_KEY,
	ACTION_STORE_KEY,
	ACTION_STORE_CERT
};

static struct sc_context *	ctx = NULL;
static struct sc_card *		card = NULL;
static int			opt_debug = 0,
				opt_quiet = 0,
				opt_action = 0,
				opt_erase = 0;
static char *			opt_profile = 0;
static char *			opt_keyfile = 0;
static char *			opt_format = 0;
static char *			opt_objectid = 0;
static char *			opt_pins[4];
static char *			opt_passphrase = 0;
static char *			opt_newkey = 0;
static char *			opt_outkey = 0;
static struct pkcs15_init_operations ops;

int
main(int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card;
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

	/* When asked to init the card, read the profile first.
	 * This makes people writing new profiles happier because
	 * they don't have to wait for the card to come around */
	sc_profile_init(&profile);
	if (sc_profile_load(&profile, opt_profile)
	 || sc_profile_finish(&profile))
		return 1;

	/* Associate all PINs given on the command line with the
	 * CHVs used by the profile */
	do_set_pins(&profile);

	/* Connect to the card */
	if (!connect(opt_reader))
		return 1;

	/* Now bind the card specific operations */
	bind_operations(&ops, profile.driver);

	if (opt_action == ACTION_INIT) {
		if (opt_erase)
			r = ops.erase_card(&profile, card);
		if (r >= 0)
			r = pkcs15_init(&profile);
		goto done;
	}

	if (opt_erase)
		fatal("Option --erase can be used only with --create-pkcs15\n");

	/* Read the PKCS15 structure from the card */
	r = sc_pkcs15_bind(card, &p15card);
	if (r) {
		fprintf(stderr, "PKCS#15 initialization failed: %m\n");
		goto done;
	}
	if (!opt_quiet)
		printf("Found %s\n", p15card->label);

	/* XXX: should compare card to profile here to make sure
	 * we're not messing things up */

	if (opt_action == ACTION_STORE_KEY)
		r = pkcs15_store_key(&profile, NULL);
	else if (opt_action == ACTION_GENERATE_KEY)
		r = pkcs15_generate_key(&profile);
	else
		fatal("Action not yet implemented\n");

done:	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
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
	if (sc_detect_card(ctx, reader) != 1) {
		error("Card not present.\n");
		return 0;
	}
	if (!opt_quiet) {
		printf("Connecting to card in reader %s...\n",
		       	ctx->readers[reader]);
	}

	r = sc_connect_card(ctx, reader, &card);
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

static int
pkcs15_init(struct sc_profile *pro)
{
	int	i, j, r;

	/* Assemble the PKCS15 structure */
	if (sc_profile_build_pkcs15(pro))
		return 1;

	/* Get all necessary PINs from user */
	if (do_read_pins(pro))
		return 1;

	/* Create the application DF and store the PINs */
	if (ops.init_app(pro, card))
		return 1;

	/* Store the PKCS15 information on the card
	 * We cannot use sc_pkcs15_create() because it makes
	 * all sorts of assumptions about DF and EF names, and
	 * doesn't work if secure messaging is required for the
	 * MF (which is the case with the GPK) */
#ifdef notyet
	/* Create the file (what size?) */
	r = ...
	/* Update DIR */
	r = sc_update_dir(pro->p15_card);
#else
	r = 0;
#endif
	if (r >= 0)
		 r = pkcs15_write(pro, "PKCS15-TokenInfo",
				 sc_pkcs15_encode_tokeninfo, 0);
	if (r >= 0)
		r = pkcs15_write(pro, "PKCS15-ODF", sc_pkcs15_encode_odf, 0);

	/* XXX Note we need to fill in the modulus length of PrKEY
	 * objects at some point (is this info optional?).
	 * Now would be a good time. */

	/* Encode all DFs */
	for (i = 0; r >= 0 && i < SC_PKCS15_DF_TYPE_COUNT; i++) {
		struct sc_pkcs15_df *df = &pro->p15_card->df[i];

		for (j = 0; r >= 0 && j < df->count; j++)
			r = pkcs15_write_df(pro, df, j);
	}

	if (r < 0) {
		fprintf(stderr,
			"PKCS #15 structure creation failed: %s\n",
			sc_strerror(r));
			return 1;
	}

	printf("Successfully created PKCS15 meta structure\n");
	return 0;
}

/*
 * Generate a new private key
 */
static int
pkcs15_generate_key(struct sc_profile *profile)
{
	char		*spec, *reason;
	unsigned int	algo, bits = 0;

	/* Parse the key spec given on the command line */
	spec = opt_newkey;
	if (!strncasecmp(spec, "rsa", 3)) {
		algo = SC_ALGORITHM_RSA;
		spec += 3;
	} else if (!strncasecmp(spec, "dsa", 3)) {
		algo = SC_ALGORITHM_DSA;
		spec += 3;
	} else {
		reason = "algorithm not supported\n";
		goto failed;
	}

	if (*spec == '/' || *spec == '-')
		spec++;
	if (*spec) {
		bits = strtoul(spec, &spec, 10);
		if (*spec) {
			reason = "invalid bit number";
			goto failed;
		}
	}

	/* XXX: support on-card key generation */
	/* Fall back to software generated keys */
	return pkcs15_generate_key_soft(profile, algo, bits);

failed:	error("Unable to generate %s key: %s\n", opt_newkey, reason);
	return -1;
}

static int
pkcs15_generate_key_soft(struct sc_profile *profile,
		unsigned int algo, unsigned int bits)
{
	EVP_PKEY	*pkey;
	int		r;

	if (!opt_quiet)
		printf("Warning: card doesn't support on-board "
		       "key generation; using software generation\n");

	ossl_seed_random();

	pkey = EVP_PKEY_new();
	if (algo == SC_ALGORITHM_RSA) {
		RSA	*rsa;
		BIO	*err;

		err = BIO_new(BIO_s_mem());
		rsa = RSA_generate_key(bits, 0x10001, NULL, err);
		BIO_free(err);
		if (rsa == 0) {
			error("RSA key generation error");
			return -1;
		}
		EVP_PKEY_assign_RSA(pkey, rsa);
	} else if (algo == SC_ALGORITHM_DSA) {
		DSA	*dsa;
		int	r = 0;

		dsa = DSA_generate_parameters(bits, NULL, 0, NULL,
				NULL, NULL, NULL);
		if (dsa)
			r = DSA_generate_key(dsa);
		if (r == 0 || dsa == 0) {
			error("DSA key generation error");
			return -1;
		}
		EVP_PKEY_assign_DSA(pkey, dsa);
	}

	r = pkcs15_store_key(profile, pkey);
	if (r < 0)
		return r;

	if (opt_outkey) {
		if (!opt_quiet)
			printf("Writing public key to %s\n", opt_outkey);
		r = do_write_public_key(opt_outkey, opt_format, pkey);
	}
	return r;
}
	

static int
pkcs15_store_key(struct sc_profile *profile, EVP_PKEY *pkey)
{
	struct sc_pkcs15_id id;
	struct prkey_info *pinfo;
	int		r;

	if (opt_objectid == NULL)
		fatal("No key ID specified; please use --id");
	sc_pkcs15_format_id(opt_objectid, &id);

	/* Find the private key file matching the given ID */
	for (pinfo = profile->prkey_list; pinfo; pinfo = pinfo->next) {
		if (!strcasecmp(pinfo->ident, opt_objectid)
		 || sc_pkcs15_compare_id(&id, &pinfo->pkcs15.id) == 1)
			break;
	}
	if (pinfo == NULL) {
		error("Unable to find private key file (id=%s)\n",
				opt_objectid);
		return -1;
	}

	if (pkey == NULL)
		do_read_private_key(opt_keyfile, opt_format, &pkey);

	r = SC_ERROR_NOT_SUPPORTED;
	switch (pkey->type) {
	case EVP_PKEY_RSA:
		if (ops.store_rsa)
			r = ops.store_rsa(profile, card, pinfo,
					EVP_PKEY_get1_RSA(pkey));
		break;
	case EVP_PKEY_DSA:
		if (ops.store_dsa)
			r = ops.store_dsa(profile, card, pinfo,
					EVP_PKEY_get1_DSA(pkey));
		break;
	}
	if (r < 0) {
		error("Failed to store private key: %s",
				sc_strerror(r));
	} else {
		printf("Successfully stored private key\n");
	}

	return r;
}

static int
pkcs15_write(struct sc_profile *pro, const char *name,
			pkcs15_encoder encode, int required)
{
	struct sc_pkcs15_card *p15card = pro->p15_card;
	struct file_info *info;
	struct sc_file	*file;
	u8		*buf = NULL;
	size_t		bufsize;
	int		r;

	info = sc_profile_find_file(pro, name);
	if (info == NULL) {
		if (required)
			fatal("No %s file defined; abort.", name);
		fprintf(stderr, "No %s file defined; not written\n", name);
		return 0;
	}
	file = info->file;

	printf("Creating %s\n", name);
	r = encode(card->ctx, p15card, &buf, &bufsize);
	if (r >= 0)
		r = do_create_and_update_file(pro, file, buf, bufsize);
	if (r < 0) {
		fprintf(stderr,
			"Error creating %s: %s\n", name, sc_strerror(r));
	}

	if (buf)
		free(buf);
	return r;
}

static int
pkcs15_write_df(struct sc_profile *pro, struct sc_pkcs15_df *df,
	       	unsigned int fileno)
{
	struct sc_file	*file = df->file[fileno];
	struct file_info *info;
	const char	*ident;
	u8		*buf;
	size_t		bufsize;
	int		r;

	info = sc_profile_file_info(pro, file);
	ident = info? info->ident : "unknown PKCS15 xDF";

	printf("Creating %s\n", ident);
	r = sc_pkcs15_encode_df(card->ctx, df, fileno, &buf, &bufsize);
	if (r < 0)
		goto out;
	if (buf == 0) {
		fprintf(stderr,
			"Profile doesn't define %s objects, skipped\n",
			ident);
		return 0;
	}

	r = do_create_and_update_file(pro, df->file[fileno], buf, bufsize);
	free(buf);

out:	if (r < 0) {
		fprintf(stderr, "Error creating %s: %s\n",
				info? info->ident : "unknown PKCS15 xDF",
			       	sc_strerror(r));
	}
	return r;
}

/*
 * Find PIN info given the "name" or the reference
 */
static struct pin_info *
do_get_pin_by_name(struct sc_profile *pro, const char *name, int warn)
{
	struct pin_info	*info;

	info = sc_profile_find_pin(pro, name);
	if (info == NULL && warn)
		error("No PIN info for %s", name);
	return info;
}

static struct pin_info *
do_get_pin_by_reference(struct sc_profile *pro, unsigned int reference)
{
	struct pin_info	*info;

	for (info = pro->pin_list; info; info = info->next) {
		if (info->pkcs15.reference == reference)
			return info;
	}
	return NULL;
}

/*
 * Associate all PINs given on the command line with the
 * CHVs used by the profile
 */
static int
do_set_pins(struct sc_profile *pro)
{
	static char	*types[2] = { "CHV1", "CHV2" };
	struct pin_info	*info;
	int		n, i;

	for (n = 0; n < 2; n++) {
		if (!(info = do_get_pin_by_name(pro, types[n], 0)))
			continue;

		for (i = 0; i < 2; i++)
			info->secret[i] = opt_pins[2*n + i];
	}
	return 0;
}

/*
 * Get all the PINs and PUKs we need from the user
 */
static int
do_read_pins(struct sc_profile *pro)
{
	static char	*names[2] = { "PIN", "PUK" };
	static char	*types[2] = { "CHV1", "CHV2" };
	int		n;

	for (n = 0; n < 2; n++) {
		struct pin_info	*info;
		struct sc_file	*file;
		char		prompt[64], *pass;
		int		i, passlen, npins = 2;

		if (!(info = do_get_pin_by_name(pro, types[n], 0)))
			continue;

		/* If the PIN file already exists, read just the PIN */
		file = info->file->file;
		ctx->log_errors = 0;
		if (!sc_select_file(card, &file->path, NULL)) {
			printf("PIN file for %s already exists.", info->ident);
			npins = 1;
		}
		ctx->log_errors = 1;

		/* Don't ask for a PUK if there's not supposed to be one */
		if (info->attempt[1] == 0)
			npins = 1;

		/* Loop over all PINs and PUKs */
		for (i = 0; i < npins; i++) {
			/* Already set from the command line? */
			if (info->secret[i])
				continue;

			sprintf(prompt, "Please enter %s for %s:",
					names[i], info->ident);

		again:	pass = getpass(prompt);
			passlen = strlen(pass);
			if (passlen < info->pkcs15.min_length) {
				error("Password too short (%u characters min)",
						info->pkcs15.min_length);
				goto again;
			}
			if (passlen > info->pkcs15.stored_length) {
				error("Password too long (%u characters max)",
						info->pkcs15.stored_length);
				goto again;
			}
			info->secret[i] = strdup(pass);
			memset(pass, 0, passlen);
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

	info = NULL;
	if (type == SC_AC_CHV)
		info = do_get_pin_by_reference(pro, reference);
	if (!info || !(pin = info->secret[0])) {
		error("Could not find %s (ref=0x%x)", ident, reference);
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
	}

	return sc_verify(card, SC_AC_CHV, reference, pin, strlen(pin), NULL);
}

int
do_verify_authinfo(struct sc_profile *pro, struct sc_file *file, int op)
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

	/* Get the parent's path */
	path = file->path;
	if (path.len >= 2)
		path.len -= 2;
	if (path.len == 0)
		sc_format_path("3F00", &path);

	/* Select the parent DF. */
	return sc_select_file(card, &path, parent);
}

int
do_create_file(struct sc_profile *pro, struct sc_file *file)
{
	struct sc_file	*parent = NULL;
	int		r;

	/* Select parent DF and verify PINs/key as necessary */
	if ((r = do_select_parent(pro, file, &parent)) < 0
	 || (r = do_verify_authinfo(pro, parent, SC_AC_OP_CREATE)) < 0) 
		goto out;

	r = sc_create_file(card, file);

out:	if (parent)
		sc_file_free(parent);
	return r;
}

int
do_create_and_update_file(struct sc_profile *pro, struct sc_file *file,
		void *data, unsigned int datalen)
{
	struct sc_file	copy = *file;
	int		r;

	copy.size += datalen;
	file = &copy;

	if ((r = do_create_file(pro, file)) < 0)
		return r;

	/* Select file and present any authentication info needed */
	if ((r = sc_select_file(card, &file->path, NULL)) < 0
	 || (r = do_verify_authinfo(pro, file, SC_AC_OP_UPDATE)) < 0)
		return r;

	return sc_update_binary(card, 0, data, datalen, 0);
}

/*
 * Read a PEM encoded key
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

static int
do_read_private_key(const char *filename, const char *format, EVP_PKEY **pk)
{
	char	*passphrase = NULL;

	while (1) {
		if (!format || !strcasecmp(format, "pem")) {
			*pk = do_read_pem_private_key(filename, passphrase);
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
 * Write a PEM encoded publci key
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
		opt_action = ACTION_STORE_KEY;
		opt_keyfile = optarg;
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
					while (isspace(*optarg))
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
		fprintf(stderr, "%s", ERR_error_string(err, NULL));
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
