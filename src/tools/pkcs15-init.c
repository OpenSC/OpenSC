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
#include "opensc-pkcs15.h"
#include "util.h"
#include "profile.h"
#include "pkcs15-init.h"

/* Handle encoding of PKCS15 on the card */
typedef int	(*pkcs15_encoder)(struct sc_context *,
			struct sc_pkcs15_card *, u8 **, size_t *);

/* Local functions */
static int	connect(int);
static void	bind_operations(struct sc_profile *);
static int	pkcs15_init(struct sc_profile *);
static int	pkcs15_write(struct sc_profile *,
			const char *name, pkcs15_encoder, int);
static int	pkcs15_write_df(struct sc_profile *,
			struct sc_pkcs15_df *, unsigned int);
static int	do_read_pins(struct sc_profile *);
static void	usage(int);


enum {
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

	{ "debug",		no_argument, 0,		'd' },
	{ 0, 0, 0, 0 }
};
const char *		option_help[] = {
	"Erase the smart card",
	"Creates a new PKCS #15 structure",

	"Enable debugging output",
};

static struct sc_context *	ctx = NULL;
static struct sc_card *		card = NULL;
static int			opt_debug = 0,
				opt_quiet = 0;
static char *			opt_pins[4];

int
main(int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card;
	struct sc_profile	profile;
	int			opt_reader = 0;
	int			do_erase = 0,
				do_init = 0;
	int			c, r = 0, index = -1;

	while ((c = getopt_long(argc, argv, "CEd", options, &index)) != -1) {
		switch (c) {
		case 'C':
			do_init = 1;
			break;
		case 'E':
			do_erase = 1;
			break;
		case 'd':
			opt_debug++;
			break;
		case OPT_PIN1: case OPT_PUK1:
		case OPT_PIN2: case OPT_PUK2:
			opt_pins[c & 3] = optarg;
			break;
		default:
			usage(1);
		}
	}

	if (optind != argc - 1)
		usage(1);

	p15card = sc_pkcs15_card_new();
	if (p15card == NULL)
                return 1;

	sc_profile_init(&profile, p15card);

	if (sc_profile_load(&profile, argv[optind]))
		return 1;

	if (sc_profile_finish(&profile))
		return 1;

	if (!connect(opt_reader))
		return 1;

	/* Now bind the card specific operations */
	bind_operations(&profile);

	if (do_erase) {
		r = profile.erase_card(&profile, card);
		if (r != 0)
			goto done;
	}
	if (do_init) {
		r = pkcs15_init(&profile);
		if (r != 0)
			goto done;
	}

done:	if (card) {
		sc_unlock(card);
		sc_disconnect_card(card);
	}
	sc_destroy_context(ctx);
	return r? 1 : 0;
}

static void
bind_operations(struct sc_profile *profile)
{
	const char	*driver;

	if ((driver = profile->driver) == 0)
		driver = card->driver->short_name;

	if (!strcasecmp(driver, "GPK"))
		bind_gpk_operations(profile);
	else
		fatal("Don't know how to handle %s cards", profile->driver);
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
	if (pro->init_app(pro, card))
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
			sprintf(prompt, "Please enter %s for %s:",
					names[i], info->ident);

		again:	pass = opt_pins[2*n + i];
			opt_pins[2*n + i] = NULL;
			if (pass == NULL)
				pass = getpass(prompt);

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

static void
usage(int exval)
{
	fprintf(stderr,
		"Usage:\n"
		"pkcs15-init -d -E -C profile\n"
		);
	exit(exval);
}
