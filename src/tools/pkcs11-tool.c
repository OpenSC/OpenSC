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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <getopt.h>

#include <opensc/pkcs11.h>
#include "util.h"

#ifdef HAVE_OPENSSL
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/err.h"
#endif

#define NEED_SESSION_RO	0x01
#define NEED_SESSION_RW	0x02
#define NO_SLOT		((CK_SLOT_ID) -1)
#define NO_MECHANISM	((CK_MECHANISM_TYPE) -1)

enum {
	OPT_MODULE = 0x100,
	OPT_SLOT,
	OPT_SLOT_LABEL,
};

const struct option options[] = {
	{ "show-info",		0, 0,		'I' },
	{ "list-slots",		0, 0,		'L' },
	{ "list-mechanisms",	0, 0,		'M' },
	{ "list-objects",	0, 0,		'O' },

	{ "sign",		0, 0,		's' },
	{ "hash",		0, 0,		'h' },
	{ "mechanism",		1, 0,		'm' },

	{ "login",		0, 0,		'l' },
	{ "pin",		1, 0,		'p' },
	{ "change-pin",		0, 0,		'c' },
	{ "keypairgen", 	0, 0, 		'k' },
	{ "write-object",	1, 0, 		'w' },
	{ "type", 		1, 0, 		'y' },
	{ "id", 		1, 0, 		'd' },
	{ "label", 		1, 0, 		'a' },
	{ "slot",		1, 0,		OPT_SLOT },
	{ "slot-label",		1, 0,		OPT_SLOT_LABEL },
	{ "set-id",		1, 0, 		'e' },
	{ "input-file",		1, 0,		'i' },
	{ "output-file",	1, 0,		'o' },
	{ "module",		1, 0,		OPT_MODULE },
	{ "test",		0, 0,		't' },
	{ "moz-cert",		1, 0,		'z' },
	{ "verbose",		0, 0,		'v' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Show global token information",
	"List slots available on the token",
	"Show slot information",
	"List mechanisms supported by the token",

	"Sign some data",
	"Hash some data",
	"Specify mechanism (use -M for a list of supported mechanisms)",

	"Log into the token first (not needed when using --pin)",
	"Supply PIN on the command line (if used in scripts: careful!)",
	"Change your (user) PIN",
	"Key pair generation",
	"Write an object (key, cert) to the card",
	"Specify the type of object (e.g. cert, privkey, pubkey)",
	"Specify the id of the object",
	"Specify the label of the object",
	"Set the CKA_ID of an object, <args>= the (new) CKA_ID",
	"Specify number of the slot to use",
	"Specify label of the slot to use",
	"Specify the input file",
	"Specify the output file",
	"Specify the module to load",

	"Test (best used with the --login or --pin option)",
	"Test Mozilla-like keypair gen and cert req, <arg>=certfile",
	"Verbose operation. Use several times to enable debug output.",
};

const char *		app_name = "pkcs11-tool"; /* for utils.c */

static int		verbose = 0;
static const char *	opt_input = NULL;
static const char *	opt_output = NULL;
static const char *	opt_module = NULL;
static CK_SLOT_ID	opt_slot = NO_SLOT;
static const char *	opt_slot_label = NULL;
static CK_MECHANISM_TYPE opt_mechanism = NO_MECHANISM;
static const char *	opt_file_to_write = NULL;
static const char *	opt_object_class_str = NULL;
static CK_OBJECT_CLASS	opt_object_class = -1;
static CK_BYTE		opt_object_id[100], new_object_id[100];
static size_t		opt_object_id_len = 0, new_object_id_len = 0;
static char *		opt_object_label = NULL;
static char *		opt_pin = NULL;

static void *module = NULL;
static CK_FUNCTION_LIST_PTR p11 = NULL;
static CK_SLOT_ID_PTR p11_slots = NULL;
static CK_ULONG p11_num_slots = 0;

struct flag_info {
	CK_FLAGS	value;
	const char *	name;
};
struct mech_info {
	CK_MECHANISM_TYPE mech;
	const char *	name;
	const char *	short_name;
};

static void		show_cryptoki_info(void);
static void		list_slots(void);
static void		show_token(CK_SLOT_ID);
static void		list_mechs(CK_SLOT_ID);
static void		list_objects(CK_SESSION_HANDLE);
static int		login(CK_SESSION_HANDLE);
static int		change_pin(CK_SLOT_ID, CK_SESSION_HANDLE);
static void		show_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_key(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, int);
static void		show_cert(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		sign_data(CK_SLOT_ID,
				CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		hash_data(CK_SLOT_ID, CK_SESSION_HANDLE);
static int		gen_keypair(CK_SLOT_ID, CK_SESSION_HANDLE,
				CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
static int 		write_object(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static void 		set_id_attr(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static int		find_object(CK_SESSION_HANDLE, CK_OBJECT_CLASS,
				CK_OBJECT_HANDLE_PTR,
				const unsigned char *, size_t id_len, int obj_index);
static CK_MECHANISM_TYPE find_mechanism(CK_SLOT_ID, CK_FLAGS,
			 	int stop_if_not_found);
static CK_SLOT_ID	find_slot_by_label(const char *);
static void		get_token_info(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
static CK_ULONG		get_mechanisms(CK_SLOT_ID,
				CK_MECHANISM_TYPE_PTR *, CK_FLAGS);
static void		p11_fatal(const char *, CK_RV);
static const char *	p11_slot_info_flags(CK_FLAGS);
static const char *	p11_token_info_flags(CK_FLAGS);
static const char *	p11_utf8_to_local(CK_UTF8CHAR *, size_t);
static const char *	p11_flag_names(struct flag_info *, CK_FLAGS);
static const char *	p11_mechanism_to_name(CK_MECHANISM_TYPE);
static CK_MECHANISM_TYPE p11_name_to_mechanism(const char *);
static void		p11_perror(const char *, CK_RV);
static const char *	CKR2Str(CK_ULONG res);
static int		p11_test(CK_SLOT_ID slot, CK_SESSION_HANDLE session);
static int		hex_to_bin(const char *in, CK_BYTE *out, size_t *outlen);
static void		test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session);

/* win32 needs this in open(2) */
#ifndef O_BINARY
# define O_BINARY 0
#endif

int
main(int argc, char * const argv[])
{
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	int err = 0, c, long_optind = 0;
	int do_show_info = 0;
	int do_list_slots = 0;
	int do_list_mechs = 0;
	int do_list_objects = 0;
	int do_sign = 0;
	int do_hash = 0;
	int do_gen_keypair = 0;
	int do_write_object = 0;
	int do_set_id = 0;
	int do_test = 0;
	int do_test_kpgen_certwrite = 0;
	int need_session = 0;
	int opt_login = 0;
	int do_change_pin = 0;
	int action_count = 0;
	CK_RV rv;

	while (1) {
               c = getopt_long(argc, argv, "ILMOa:d:e:hi:klm:o:p:scvty:w:z:",
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
		case 'e':
			need_session |= NEED_SESSION_RW;
			do_set_id = 1;
			new_object_id_len = sizeof(new_object_id);
			if (!hex_to_bin(optarg, new_object_id, &new_object_id_len)) {
				printf("Invalid ID \"%s\"\n", optarg);
				print_usage_and_die();
			}
			action_count++;
			break;
		case 'y':
			opt_object_class_str = optarg;
			if (strcmp(optarg, "cert") == 0)
				opt_object_class = CKO_CERTIFICATE;
			else if (strcmp(optarg, "privkey") == 0)
				opt_object_class = CKO_PRIVATE_KEY;
			else if (strcmp(optarg, "pubkey") == 0)
				opt_object_class = CKO_PUBLIC_KEY;
			else {
				printf("Unsupported object type \"%s\"\n", optarg);
				print_usage_and_die();
			}
			break;
		case 'd':
			opt_object_id_len = sizeof(opt_object_id);
			if (!hex_to_bin(optarg, opt_object_id, &opt_object_id_len)) {
				printf("Invalid ID \"%s\"\n", optarg);
				print_usage_and_die();
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
			opt_mechanism = p11_name_to_mechanism(optarg);
			break;
		case 'o':
			opt_output = optarg;
			break;
		case 'p':
			need_session |= NEED_SESSION_RW;
			opt_login = 1;
			opt_pin = optarg;
			break;
		case 'c':
			do_change_pin = 1;
			need_session |= CKF_SERIAL_SESSION; /* no need for a R/W session */
			action_count++;
			break;
		case 's':
			need_session |= NEED_SESSION_RW;
			do_sign = 1;
			action_count++;
			break;
		case 't':
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
			opt_slot = (CK_SLOT_ID) atoi(optarg);
			break;
		case OPT_SLOT_LABEL:
			opt_slot_label = optarg;
			break;
		case OPT_MODULE:
			opt_module = optarg;
			break;
		default:
			print_usage_and_die();
		}
	}
	if (action_count == 0)
		print_usage_and_die();

	module = C_LoadModule(opt_module, &p11);
	if (module == NULL)
		fatal("Failed to load pkcs11 module");

	rv = p11->C_Initialize(NULL);
	if (rv != CKR_OK)
		p11_fatal("C_Initialize", rv);

	if (do_show_info)
		show_cryptoki_info();

	/* Get the list of slots */
	rv = p11->C_GetSlotList(FALSE, p11_slots, &p11_num_slots);
	if (rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL)
		p11_fatal("C_GetSlotList", rv);
	p11_slots = (CK_SLOT_ID *) calloc(p11_num_slots, sizeof(CK_SLOT_ID));
	if (p11_slots == NULL) {
		perror("calloc failed");
		err = 1;
		goto end;
	}
	rv = p11->C_GetSlotList(FALSE, p11_slots, &p11_num_slots);
	if (rv != CKR_OK)
		p11_fatal("C_GetSlotList", rv);

	if (do_list_slots)
		list_slots();

	if (p11_num_slots == 0) {
		fprintf(stderr, "No slots...\n");
		err = 1;
		goto end;
	}

	if (opt_slot_label) {
		CK_SLOT_ID slot;

		slot = find_slot_by_label(opt_slot_label);
		if (slot == NO_SLOT) {
			fprintf(stderr,
				"No slot named \"%s\"\n", opt_slot_label);
			err = 1;
			goto end;
		}
		if (opt_slot != NO_SLOT && opt_slot != slot) {
			fprintf(stderr,
				"Conflicting slots specified\n");
			err = 1;
			goto end;
		}
		opt_slot = slot;
	}

	if (opt_slot == NO_SLOT)
		opt_slot = p11_slots[0];

	/* XXX: add wait for slot event */

	if (do_list_mechs)
		list_mechs(opt_slot);

	if (do_sign) {
		CK_TOKEN_INFO	info;

		get_token_info(opt_slot, &info);
		if (!(info.flags & CKF_TOKEN_INITIALIZED))
			fatal("Token not initialized\n");
		if (info.flags & CKF_LOGIN_REQUIRED)
			opt_login++;
	}

	if (need_session) {
		int flags = CKF_SERIAL_SESSION;

		if (need_session & NEED_SESSION_RW)
			flags |= CKF_RW_SESSION;
		rv = p11->C_OpenSession(opt_slot, flags,
				NULL, NULL, &session);
		if (rv != CKR_OK)
			p11_fatal("C_OpenSession", rv);
	}

	if (do_change_pin)
		/* To be sure we won't mix things up with the -l or -p options,
		 * we safely stop here. */
		return change_pin(opt_slot, session);

	if (opt_login || opt_pin) {
		int r = login(session);
		if (r != 0)
			return r;
	}

	if (do_sign) {
		if (!find_object(session, CKO_PRIVATE_KEY, &object, NULL, 0, 0))
			fatal("Private key not found");
	}

	if (do_list_objects)
		list_objects(session);

	if (do_sign)
		sign_data(opt_slot, session, object);

	if (do_hash)
		hash_data(opt_slot, session);

	if (do_gen_keypair) {
		CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
		gen_keypair(opt_slot, session, &hPublicKey, &hPrivateKey);
	}

	if (do_write_object) {
		if (opt_object_class_str == NULL)
			fatal("You should specify the object type with the -y option\n");
		write_object(opt_slot, session);
	}

	if (do_set_id) {
		if (opt_object_class_str == NULL)
			fatal("You should specify the object type with the -y option\n");
		if (opt_object_id_len == 0)
			fatal("You should specify the current ID with the -d option\n");
		set_id_attr(opt_slot, session);
	}

	if (do_test)
		p11_test(opt_slot, session);

	if (do_test_kpgen_certwrite)
		test_kpgen_certwrite(opt_slot, session);

end:
	if (session)
		p11->C_CloseSession(session);
	if (p11)
		p11->C_Finalize(NULL_PTR);
	if (module)
		C_UnloadModule(module);

	return err;
}
void
show_cryptoki_info(void)
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

void
list_slots(void)
{
	CK_SLOT_INFO	info;
	CK_ULONG	n;
	CK_RV		rv;

	if (!p11_num_slots) {
		printf("No slots found\n");
		return;
	}

	printf("Available slots:\n");
	for (n = 0; n < p11_num_slots; n++) {
		printf("Slot %-2u          ", (unsigned int) p11_slots[n]);
		rv = p11->C_GetSlotInfo(p11_slots[n], &info);
		if (rv != CKR_OK) {
			printf("(GetSlotInfo failed, error %u)\n", (unsigned int) rv);
			continue;
		}
		if ((!verbose) && !(info.flags & CKF_TOKEN_PRESENT)) {
			printf("(empty)\n");
			continue;
		}
		printf("%s\n", p11_utf8_to_local(info.slotDescription,
					sizeof(info.slotDescription)));
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

void
show_token(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO	info;

	get_token_info(slot, &info);

	if (!(info.flags & CKF_TOKEN_INITIALIZED) && (!verbose)) {
		printf("  token state:   uninitialized\n");
		return;
	}

	printf("  token label:   %s\n",
			p11_utf8_to_local(info.label,
				sizeof(info.label)));
	printf("  token manuf:   %s\n",
			p11_utf8_to_local(info.manufacturerID,
				sizeof(info.manufacturerID)));
	printf("  token model:   %s\n",
			p11_utf8_to_local(info.model,
				sizeof(info.model)));
	printf("  token flags:   %s\n",
			p11_token_info_flags(info.flags));
	printf("  serial num  :  %s\n", p11_utf8_to_local(info.serialNumber,
			sizeof(info.serialNumber)));
}

void
list_mechs(CK_SLOT_ID slot)
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
			if (info.flags & CKF_DIGEST)
				printf(", digest");
			if (info.flags & CKF_SIGN)
				printf(", sign");
			if (info.flags & CKF_VERIFY)
				printf(", verify");
			if (info.flags & CKF_WRAP)
				printf(", wrap");
			if (info.flags & CKF_UNWRAP)
				printf(", unwrap");
			if (info.flags & CKF_ENCRYPT)
				printf(", encrypt");
			if (info.flags & CKF_DECRYPT)
				printf(", decrypt");
			if (info.flags & CKF_GENERATE_KEY_PAIR)
				printf(", keypairgen");
			info.flags &= ~(CKF_DIGEST|CKF_SIGN|CKF_VERIFY|CKF_HW|CKF_UNWRAP|CKF_ENCRYPT|CKF_DECRYPT|CKF_GENERATE_KEY_PAIR);
			if (info.flags)
				printf(", other flags=0x%x", (unsigned int) info.flags);
		}
		printf("\n");
	}
}

void
list_objects(CK_SESSION_HANDLE sess)
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
		show_object(sess, object);
	}
	p11->C_FindObjectsFinal(sess);
}

static int login(CK_SESSION_HANDLE session)
 {
	char		*pin = NULL;
	CK_TOKEN_INFO	info;
	CK_RV		rv;

	get_token_info(opt_slot, &info);

	/* Identify which pin to enter */

	if (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
		if (opt_pin)
			pin = opt_pin;
	} else
	if (info.flags & CKF_LOGIN_REQUIRED) {
		if (opt_pin == NULL)
			pin = getpass("Please enter PIN: ");
		else
			pin = opt_pin;
		if (!pin || !*pin)
			return 1;
	} else {
		return 0;
	}
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR *) pin,
		pin == NULL ? 0 : strlen(pin));
	if (rv != CKR_OK)
		p11_fatal("C_Login", rv);

	return 0;
}

int
change_pin(CK_SLOT_ID slot, CK_SESSION_HANDLE sess)
{
	char old_buf[21], *old_pin = NULL;
	char new_buf[21], *new_pin = NULL;
	CK_TOKEN_INFO	info;
	CK_RV rv;

	get_token_info(slot, &info);

	if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
		old_pin = getpass("Please enter the current PIN: ");
		if (!old_pin || !*old_pin || strlen(old_pin) > 20)
			return 1;
		strcpy(old_buf, old_pin);
		old_pin = old_buf;
		new_pin = getpass("Please enter the new PIN: ");
		if (!new_pin || !*new_pin || strlen(new_pin) > 20)
			return 1;
		strcpy(new_buf, new_pin);
		new_pin = getpass("Please enter the new PIN again: ");
		if (!new_pin || !*new_pin || strcmp(new_buf, new_pin) != 0) {
			printf("  different new PINs, exiting\n");
			return -1;
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

void
sign_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	unsigned char	buffer[512];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, r;

	if (opt_mechanism == NO_MECHANISM) {
		opt_mechanism = find_mechanism(slot, CKF_SIGN|CKF_HW, 1);
		printf("Using signature algorithm %s\n",
				p11_mechanism_to_name(opt_mechanism));
	}

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	rv = p11->C_SignInit(session, &mech, key);
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY|O_BINARY)) < 0)
		fatal("Cannot open %s: %m", opt_input);

	while ((r = read(fd, buffer, sizeof(buffer))) > 0) {
		rv = p11->C_SignUpdate(session, buffer, r);
		if (rv != CKR_OK)
			p11_fatal("C_SignUpdate", rv);
	}
	if (rv < 0)
		fatal("failed to read from %s: %m",
				opt_input? opt_input : "<stdin>");
	if (fd != 0)
		close(fd);

	sig_len = sizeof(buffer);
	rv = p11->C_SignFinal(session, buffer, &sig_len);
	if (rv != CKR_OK)
		p11_fatal("C_SignFinal", rv);

#ifdef _WIN32
	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, 0666)) < 0)
		fatal("failed to open %s: %m", opt_output);
#else
	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY, 0666)) < 0)
		fatal("failed to open %s: %m", opt_output);
#endif /* _WIN32 */

	r = write(fd, buffer, sig_len);
	if (r < 0)
		fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}

void
hash_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	unsigned char	buffer[64];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	hash_len;
	int		fd, r;

	if (opt_mechanism == NO_MECHANISM) {
		opt_mechanism = find_mechanism(slot, CKF_DIGEST, 1);
		printf("Using digest algorithm %s\n",
				p11_mechanism_to_name(opt_mechanism));
	}

	memset(&mech, 0, sizeof(mech));
	mech.mechanism = opt_mechanism;

	rv = p11->C_DigestInit(session, &mech);
	if (rv != CKR_OK)
		p11_fatal("C_DigestInit", rv);

	if (opt_input == NULL)
		fd = 0;
	else if ((fd = open(opt_input, O_RDONLY)) < 0)
		fatal("Cannot open %s: %m", opt_input);

	while ((r = read(fd, buffer, sizeof(buffer))) > 0) {
		rv = p11->C_DigestUpdate(session, buffer, r);
		if (rv != CKR_OK)
			p11_fatal("C_DigestUpdate", rv);
	}
	if (rv < 0)
		fatal("failed to read from %s: %m",
				opt_input? opt_input : "<stdin>");
	if (fd != 0)
		close(fd);

	hash_len = sizeof(buffer);
	rv = p11->C_DigestFinal(session, buffer, &hash_len);
	if (rv != CKR_OK)
		p11_fatal("C_DigestFinal", rv);

	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY, 0666)) < 0)
		fatal("failed to open %s: %m", opt_output);

	r = write(fd, buffer, hash_len);
	if (r < 0)
		fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}

#define FILL_ATTR(attr, typ, val, len) {(attr).type=(typ); (attr).pValue=(val); (attr).ulValueLen=len;}

int
gen_keypair(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
	CK_OBJECT_HANDLE *hPublicKey, CK_OBJECT_HANDLE *hPrivateKey)
{
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_ULONG modulusBits = 768;
	CK_BYTE publicExponent[] = { 3 };
	CK_BBOOL _true = TRUE;
	CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE publicKeyTemplate[20] = {
		{CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_VERIFY, &_true, sizeof(_true)},
		{CKA_WRAP, &_true, sizeof(_true)},
		{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
		{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
	};
	int n_pubkey_attr = 6;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
		{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
		{CKA_TOKEN, &_true, sizeof(_true)},
		{CKA_PRIVATE, &_true, sizeof(_true)},
		{CKA_SENSITIVE, &_true, sizeof(_true)},
		{CKA_DECRYPT, &_true, sizeof(_true)},
		{CKA_SIGN, &_true, sizeof(_true)},
		{CKA_UNWRAP, &_true, sizeof(_true)}
	};
	int n_privkey_attr = 7;
	CK_RV rv;

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

	printf("Key pair generated:\n");
	show_object(session, *hPrivateKey);
	show_object(session, *hPublicKey);

	return 1;
}

/* Currently only for certificates (-type cert) */
int
write_object(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	CK_BBOOL _true = TRUE;
	unsigned char contents[5000];
	int contents_len;
	FILE *f;
	CK_OBJECT_HANDLE cert_obj, pubkey_obj, privkey_obj;
	CK_ATTRIBUTE cert_templ[20], pubkey_templ[20], privkey_templ[20];
	int n_cert_attr = 0, n_pubkey_attr = 0, n_privkey_attr = 0;
	CK_RV rv;

	f = fopen(opt_file_to_write, "rb");
	if (f == NULL)
		fatal("Couldn't open file \"%s\"\n", opt_file_to_write);
	contents_len = fread(contents, 1, sizeof(contents), f);
	if (contents_len < 0)
		fatal("Couldn't read from file \"%s\"\n", opt_file_to_write);
	fclose(f);

	if (opt_object_class == CKO_CERTIFICATE) {
		CK_OBJECT_CLASS clazz = CKO_CERTIFICATE;
		CK_CERTIFICATE_TYPE cert_type = CKC_X_509;

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
	}
	else
		fatal("Writing of a \"%s\" type not (yet) supported\n", opt_object_class_str);

	if (n_cert_attr) {
		rv = p11->C_CreateObject(session, cert_templ, n_cert_attr, &cert_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);
		
		printf("Generated certificate:\n");
		show_object(session, cert_obj);
	}

	if (n_pubkey_attr) {
		rv = p11->C_CreateObject(session, pubkey_templ, n_pubkey_attr, &pubkey_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);
		
		printf("Generated public key:\n");
		show_object(session, pubkey_obj);
	}

	if (n_privkey_attr) {
		rv = p11->C_CreateObject(session, privkey_templ, n_privkey_attr, &privkey_obj);
		if (rv != CKR_OK)
			p11_fatal("C_CreateObject", rv);
		
		printf("Generated private key:\n");
		show_object(session, privkey_obj);
	}

	return 1;
}

void
set_id_attr(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
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

CK_SLOT_ID
find_slot_by_label(const char *label)
{
	CK_TOKEN_INFO	info;
	CK_ULONG	n, len;
	CK_RV		rv;

	if (!p11_num_slots)
		return NO_SLOT;

	len = strlen(label);
	for (n = 0; n < p11_num_slots; n++) {
		const char	*token_label;

		rv = p11->C_GetTokenInfo(n, &info);
		if (rv != CKR_OK)
			continue;
		token_label = p11_utf8_to_local(info.label, sizeof(info.label));
		if (!strncmp(label, token_label, len))
			return n;
	}

	return NO_SLOT;
}

int
find_object(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
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

CK_MECHANISM_TYPE
find_mechanism(CK_SLOT_ID slot, CK_FLAGS flags, int stop_if_not_found)
{
	CK_MECHANISM_TYPE *mechs = NULL, result;
	CK_ULONG	count = 0;

	count = get_mechanisms(slot, &mechs, flags);
	if (count == 0) {
		if (stop_if_not_found)
			fatal("No appropriate mechanism found");
		result = NO_MECHANISM;
	} else {
		result = mechs[0];
		free(mechs);
	}

	return result;
}


#define ATTR_METHOD(ATTR, TYPE) \
TYPE \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj) \
{ \
	TYPE		type; \
	CK_ATTRIBUTE	attr = { CKA_##ATTR, &type, sizeof(type) }; \
	CK_RV		rv; \
 \
	rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
	if (rv != CKR_OK) \
		p11_fatal("C_GetAttributeValue(" #ATTR ")", rv); \
	return type; \
}

#define VARATTR_METHOD(ATTR, TYPE) \
TYPE * \
get##ATTR(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, CK_ULONG_PTR pulCount) \
{ \
	CK_ATTRIBUTE	attr = { CKA_##ATTR, NULL, 0 }; \
	CK_RV		rv; \
 \
	rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
	if (rv == CKR_OK) { \
		if (!(attr.pValue = calloc(1, attr.ulValueLen + 1))) \
			fatal("out of memory in get" #ATTR ": %m"); \
		rv = p11->C_GetAttributeValue(sess, obj, &attr, 1); \
	} \
	if (rv != CKR_OK) \
		p11_fatal("C_GetAttributeValue(" #ATTR ")", rv); \
	if (pulCount) \
		*pulCount = attr.ulValueLen / sizeof(TYPE); \
	return (TYPE *) attr.pValue; \
}

/*
 * Define attribute accessors
 */
ATTR_METHOD(CLASS, CK_OBJECT_CLASS);
ATTR_METHOD(TOKEN, CK_BBOOL);
ATTR_METHOD(LOCAL, CK_BBOOL);
ATTR_METHOD(SENSITIVE, CK_BBOOL);
ATTR_METHOD(ALWAYS_SENSITIVE, CK_BBOOL);
ATTR_METHOD(NEVER_EXTRACTABLE, CK_BBOOL);
ATTR_METHOD(PRIVATE, CK_BBOOL);
ATTR_METHOD(MODIFIABLE, CK_BBOOL);
ATTR_METHOD(ENCRYPT, CK_BBOOL);
ATTR_METHOD(DECRYPT, CK_BBOOL);
ATTR_METHOD(SIGN, CK_BBOOL);
ATTR_METHOD(SIGN_RECOVER, CK_BBOOL);
ATTR_METHOD(VERIFY, CK_BBOOL);
ATTR_METHOD(VERIFY_RECOVER, CK_BBOOL);
ATTR_METHOD(WRAP, CK_BBOOL);
ATTR_METHOD(UNWRAP, CK_BBOOL);
ATTR_METHOD(DERIVE, CK_BBOOL);
ATTR_METHOD(EXTRACTABLE, CK_BBOOL);
ATTR_METHOD(KEY_TYPE, CK_KEY_TYPE);
ATTR_METHOD(CERTIFICATE_TYPE, CK_CERTIFICATE_TYPE);
ATTR_METHOD(MODULUS_BITS, CK_ULONG);
VARATTR_METHOD(LABEL, char);
VARATTR_METHOD(ID, unsigned char);
VARATTR_METHOD(MODULUS, unsigned char);
VARATTR_METHOD(VALUE, unsigned char);

void
show_object(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
{
	CK_OBJECT_CLASS	cls = getCLASS(sess, obj);

	switch (cls) {
	case CKO_PUBLIC_KEY:
		show_key(sess, obj, 1);
		break;
	case CKO_PRIVATE_KEY:
		show_key(sess, obj, 0);
		break;
	case CKO_CERTIFICATE:
		show_cert(sess, obj);
		break;
	default:
		printf("Object %u, type %u\n",
				(unsigned int) obj,
				(unsigned int) cls);
	}
}

void
show_key(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, int pub)
{
	CK_KEY_TYPE	key_type = getKEY_TYPE(sess, obj);
	CK_ULONG	size;
	unsigned char	*id;
	char		*label, *sepa;

	printf("%s Key Object", pub? "Public" : "Private");
	switch (key_type) {
	case CKK_RSA:
		printf("; RSA %lu bits\n", getMODULUS_BITS(sess, obj));
		break;
	default:
		printf("; unknown key algorithm %lu\n", key_type);
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
	if (getENCRYPT(sess, obj)) {
		printf("%sencrypt", sepa);
		sepa = ", ";
	}
	if (getDECRYPT(sess, obj)) {
		printf("%sdecrypt", sepa);
		sepa = ", ";
	}
	if (getSIGN(sess, obj)) {
		printf("%ssign", sepa);
		sepa = ", ";
	}
	if (getVERIFY(sess, obj)) {
		printf("%sverify", sepa);
		sepa = ", ";
	}
	if (getWRAP(sess, obj)) {
		printf("%swrap", sepa);
		sepa = ", ";
	}
	if (getUNWRAP(sess, obj)) {
		printf("%sunwrap", sepa);
		sepa = ", ";
	}
	if (!*sepa)
		printf("none");
	printf("\n");
}

void
show_cert(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj)
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

void
get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV		rv;

	rv = p11->C_GetTokenInfo(slot, info);
	if (rv != CKR_OK)
		p11_fatal("C_GetTokenInfo", rv);
}

CK_ULONG
get_mechanisms(CK_SLOT_ID slot,
		CK_MECHANISM_TYPE_PTR *pList,
		CK_FLAGS flags)
{
	CK_ULONG	m, n, ulCount;
	CK_RV		rv;

	rv = p11->C_GetMechanismList(slot, *pList, &ulCount);
	*pList = (CK_MECHANISM_TYPE *) calloc(ulCount, sizeof(*pList));
	if (*pList == NULL)
		fatal("calloc failed: %m");

	rv = p11->C_GetMechanismList(slot, *pList, &ulCount);
	if (rv != CKR_OK)
		p11_fatal("C_GetMechanismList", rv);

	if (flags != -1) {
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

static int
test_digest(CK_SLOT_ID slot)
{
	int             errors = 0;
	CK_RV           rv;
	CK_SESSION_HANDLE session;
	CK_MECHANISM    ck_mech = { CKM_MD5, NULL, 0 };
	CK_ULONG        i, j;
	unsigned char   data[100];
	unsigned char   hash1[64], hash2[64];
	CK_ULONG        hashLen1, hashLen2;
	CK_MECHANISM_TYPE firstMechType;

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

	firstMechType = find_mechanism(slot, CKF_DIGEST, 0);
	if (firstMechType == NO_MECHANISM) {
		printf("Digests: not implemented\n");
		return errors;
	} else
		printf("Digests:\n");

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
		NULL, NULL, &session);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

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

	rv = p11->C_CloseSession(session);
	if (rv != CKR_OK)
		p11_fatal("C_CloseSession", rv);

	return errors;
}

#ifdef HAVE_OPENSSL
EVP_PKEY *get_public_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE privKeyObject)
{
	unsigned char  *id;
	CK_ULONG        idLen;
	CK_OBJECT_HANDLE pubkeyObject;
	unsigned char  *pubkey, *pubkey_sav;
	CK_ULONG        pubkeyLen;
	EVP_PKEY       *pkey;

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

	pubkey = getVALUE(session, pubkeyObject, &pubkeyLen);
	if (pubkey == NULL) {
		printf("couldn't get the pubkey VALUE attribute, no validation done\n");
		return NULL;
	}

	pubkey_sav = pubkey; /* The function below may change pubkey */
	pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &pubkey, pubkeyLen);
	free(pubkey_sav);

	if (pkey == NULL) {
		printf(" couldn't parse pubkey, no verification done\n");
		/* ERR_print_errors_fp(stderr); */
		return NULL;
	}

	return pkey;
}
#endif

int sign_verify_openssl(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
		CK_MECHANISM *ck_mech, CK_OBJECT_HANDLE privKeyObject,
		unsigned char *data, CK_ULONG dataLen,
		unsigned char *verifyData, CK_ULONG verifyDataLen,
		int modLenBytes, int evp_md_index)
{
	int 		errors = 0;
	CK_RV           rv;
	unsigned char   sig1[1024];
	CK_ULONG        sigLen1;

#ifdef HAVE_OPENSSL
	int             err;
	EVP_PKEY       *pkey;
	EVP_MD_CTX      md_ctx;

	const EVP_MD         *evp_mds[] = {
		EVP_sha1(),
		EVP_sha1(),
		EVP_sha1(),
		EVP_md5(),
		EVP_ripemd160(),
	};
#endif

	rv = p11->C_SignInit(session, ck_mech, privKeyObject);
	/* mechanism not implemented, don't test */
	if (rv == CKR_MECHANISM_INVALID)
		return errors;
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

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
#ifndef HAVE_OPENSSL
	printf("unable to verify signature (compile with HAVE_OPENSSL)\n");
#else

	if (!(pkey = get_public_key(session, privKeyObject)))
		return errors;

	EVP_VerifyInit(&md_ctx, evp_mds[evp_md_index]);
	EVP_VerifyUpdate(&md_ctx, verifyData, verifyDataLen);
	err = EVP_VerifyFinal(&md_ctx, sig1, sigLen1, pkey);
	if (err == 0) {
		printf("ERR: verification failed\n");
		errors++;
	} else if (err != 1) {
		printf("openssl error during verification: 0x%0x (%d)\n", err, err);
		/* ERR_print_errors_fp(stderr); */
	} else
		printf("OK\n");

	/* free(cert); */
#endif

	return errors;
}

/*
 * Test signature functions
 */
static int
test_signature(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_SESSION_HANDLE sess;
	CK_MECHANISM    ck_mech = { CKM_MD5, NULL, 0 };
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        i, j;
	unsigned char   data[256];
	CK_ULONG        modLenBytes;
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
		0xffffff
	};
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
	};
	CK_ULONG        dataLens[] = {
		0,		/* should be modulus length, is done further on */
		35,
		sizeof(verifyData),
		sizeof(verifyData),
		sizeof(verifyData),
	};

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
		NULL, NULL, &sess);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Signatures: not logged in, skipping signature tests\n");
		return errors;
	}

	firstMechType = find_mechanism(slot, CKF_SIGN | CKF_HW, 0);
	if (firstMechType == NO_MECHANISM) {
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
		printf("\n");
		break;
	}
	if (privKeyObject == CK_INVALID_HANDLE) {
		printf("Signatures: no private key found in this slot\n");
		return 0;
	}

	data[0] = 0;
	data[1] = 1;
	modLenBytes = (getMODULUS_BITS(sess, privKeyObject) + 7) / 8;

	/* 1st test */

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
	if (rv != CKR_OK)
		p11_fatal("C_SignInit", rv);

	rv = p11->C_SignUpdate(sess, data, 5);
	if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
		printf("  Note: C_SignUpdate(), SignFinal() not supported\n");
		/* finish the digest operation */
		sigLen2 = sizeof(sig2);
		rv = p11->C_Sign(sess, data, dataLen, sig2, &sigLen2);
		if (rv != CKR_OK)
			p11_fatal("C_Sign", rv);
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
		errors += sign_verify_openssl(slot, sess, &ck_mech, privKeyObject,
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
		modLenBits = getMODULUS_BITS(sess, privKeyObject);
		modLenBytes = (modLenBits + 7) / 8;

		printf("  testing key %d (%u bits%s%s) with 1 signature mechanism\n",
				(int) (j-1),
				(int) modLenBits,
				label? ", label=" : "",
				label? label : "");
		if (label)
			free(label);

		errors += sign_verify_openssl(slot, sess, &ck_mech, privKeyObject,
			datas[i], dataLens[i], verifyData, sizeof(verifyData),
			modLenBytes, i);
	}

	return errors;
}

static int
sign_verify(CK_SLOT_ID slot, CK_SESSION_HANDLE session,	CK_OBJECT_HANDLE priv_key, int key_len,
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

static int
test_verify(CK_SLOT_ID slot, CK_SESSION_HANDLE sess)
{
	int key_len, i, errors = 0;
	CK_OBJECT_HANDLE priv_key, pub_key;
	CK_MECHANISM_TYPE first_mech_type;
	CK_SESSION_INFO sessionInfo;
	CK_RV rv;

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &sess);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Verify: not logged in, skipping verify tests\n");
		return errors;
	}

	first_mech_type = find_mechanism(slot, CKF_VERIFY, 0);
	if (first_mech_type == NO_MECHANISM) {
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

		key_len = (getMODULUS_BITS(sess, priv_key) + 7) / 8;

		errors += sign_verify(slot, sess, priv_key, key_len, pub_key, i != 0);
	}

	if (i == 0)
		printf("  No private key found for testing\n");

	return errors;
}

#ifdef HAVE_OPENSSL
static int
wrap_unwrap(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
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
	CK_ATTRIBUTE	key_template = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };

	pkey = get_public_key(session, privKeyObject);
	if (pkey == NULL)
		return 0;

	printf("    %s: ", OBJ_nid2sn(EVP_CIPHER_nid(algo)));

	EVP_SealInit(&seal_ctx, algo,
			&key, &key_len,
			iv, &pkey, 1);

	/* Encrypt something */
	len = sizeof(ciphered);
	EVP_SealUpdate(&seal_ctx, ciphered, &len, (const unsigned char *) "hello world", 11);
	ciphered_len = len;

	len = sizeof(ciphered) - ciphered_len;
	EVP_SealFinal(&seal_ctx, ciphered + ciphered_len, &len);
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
	key = getVALUE(session, cipherKeyObject, (unsigned long *) &key_len);
	if (key == NULL) {
		printf("Could not get unwrapped key\n");
		return 1;
	}
	if (key_len != EVP_CIPHER_key_length(algo)) {
		printf("Key length mismatch (%d != %d)\n",
				key_len, EVP_CIPHER_key_length(algo));
		return 1;
	}

	EVP_DecryptInit(&seal_ctx, algo, key, iv);

	len = sizeof(cleartext);
	EVP_DecryptUpdate(&seal_ctx, cleartext, &len, ciphered, ciphered_len);

	cleartext_len = len;
	len = sizeof(cleartext) - len;
	EVP_DecryptFinal(&seal_ctx, cleartext + cleartext_len, &len);
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
static int
test_unwrap(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_SESSION_HANDLE sess;
	CK_MECHANISM_TYPE firstMechType;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        j;
	char 		*label;

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &sess);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Key unwrap: not logged in, skipping key unwrap tests\n");
		return errors;
	}

	firstMechType = find_mechanism(slot, CKF_UNWRAP | CKF_HW, 0);
	if (firstMechType == NO_MECHANISM) {
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

#ifndef HAVE_OPENSSL
		printf("No OpenSSL support, unable to validate C_Unwrap\n");
#else
		errors += wrap_unwrap(slot, sess, EVP_des_cbc(), privKeyObject);
		errors += wrap_unwrap(slot, sess, EVP_des_ede3_cbc(), privKeyObject);
		errors += wrap_unwrap(slot, sess, EVP_bf_cbc(), privKeyObject);
		errors += wrap_unwrap(slot, sess, EVP_cast5_cfb(), privKeyObject);
#endif
	}

	return errors;
}

#ifdef HAVE_OPENSSL
static int
encrypt_decrypt(CK_SLOT_ID slot, CK_SESSION_HANDLE session,
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

	if (EVP_PKEY_size(pkey) > sizeof(encrypted)) {
		printf("Ciphertext buffer too small\n");
		EVP_PKEY_free(pkey);
		return 0;
	}
	encrypted_len = EVP_PKEY_encrypt(encrypted, orig_data, sizeof(orig_data), pkey);
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
static int
test_decrypt(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	int             errors = 0;
	CK_RV           rv;
	CK_OBJECT_HANDLE privKeyObject;
	CK_SESSION_HANDLE sess;
	CK_MECHANISM_TYPE *mechs = NULL;
	CK_SESSION_INFO sessionInfo;
	CK_ULONG        j, n, num_mechs = 0;
	char 		*label;

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &sess);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	rv = p11->C_GetSessionInfo(sess, &sessionInfo);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);
	if ((sessionInfo.state & CKS_RO_USER_FUNCTIONS) == 0) {
		printf("Decryption: not logged in, skipping decryption tests\n");
		return errors;
	}

	num_mechs = get_mechanisms(slot, &mechs, CKF_DECRYPT);
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

#ifndef HAVE_OPENSSL
		printf("No OpenSSL support, unable to validate decryption\n");
#else
		for (n = 0; n < num_mechs; n++) {
			errors += encrypt_decrypt(slot, sess,
						mechs[n], privKeyObject);
		}
#endif
	}

	free(mechs);
	return errors;
}

static int
test_random(CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE session;
	CK_BYTE buf1[100], buf2[100];
	CK_BYTE seed1[100];
	CK_RV rv;
	int errors = 0;

	printf("C_SeedRandom() and C_GenerateRandom():\n");

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION,
		NULL, NULL, &session);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	rv = p11->C_SeedRandom(session, seed1, 10);
	if (rv == CKR_RANDOM_NO_RNG || rv == CKR_FUNCTION_NOT_SUPPORTED) {
		printf("  not implemented\n");
		return 0;
	}
	if (rv == CKR_RANDOM_SEED_NOT_SUPPORTED)
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
		p11_perror("C_GenerateRandom", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, buf1, 0);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(,,0)", rv);
		return 1;
	}

	rv = p11->C_GenerateRandom(session, NULL, 100);
	if (rv != CKR_OK) {
		p11_perror("C_GenerateRandom(,NULL,)", rv);
		return 1;
	}

	if (memcmp(buf1, buf2, 100) == 0) {
		printf("  ERR: C_GenerateRandom returned twice the same value!!!\n");
		errors++;
	}

	printf("  seems to be OK\n");

	return 0;
}

static int
test_card_detection(int wait_for_event)
{
	char buffer[256];
	CK_SLOT_ID slot_id;
	CK_RV rv;

	printf("Testing card detection%s\n",
		wait_for_event? " using C_WaitForSlotEvent" : "");

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
			printf("event on slot %u\n", (unsigned int) slot_id);
		}
		list_slots();
	}

	return 0;
}

static int
p11_test(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	int errors = 0;

	errors += test_random(slot);

	errors += test_digest(slot);

	errors += test_signature(slot, session);

	errors += test_verify(slot, session);

	errors += test_unwrap(slot, session);

	errors += test_decrypt(slot, session);

	errors += test_card_detection(0);

	errors += test_card_detection(1);

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
static void
test_kpgen_certwrite(CK_SLOT_ID slot, CK_SESSION_HANDLE session)
{
	CK_MECHANISM		mech = {CKM_RSA_PKCS, NULL_PTR, 0};
	CK_MECHANISM_TYPE	*mech_type = NULL;
	CK_OBJECT_HANDLE	pub_key, priv_key;
	CK_ULONG		i, num_mechs = 0;
	CK_RV			rv;
	CK_BYTE			buf[20], *tmp, *mod;
	CK_BYTE			md5_and_digestinfo[34] = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10";
	CK_BYTE			*data, sig[512];
	CK_ULONG		data_len, sig_len;
	CK_BYTE			*id = (CK_BYTE *) "abcdefghijklmnopqrst";
	CK_ULONG		id_len = 20, mod_len;
	CK_BYTE			*label = (CK_BYTE *) "Just a label";
	CK_ULONG		label_len = 12;
	CK_ATTRIBUTE		attribs[3] = {
		{CKA_ID, id, id_len},
		{CKA_LABEL, label, label_len},
		{CKA_SUBJECT, (void *) "This won't be used in our lib", 29}
	};
	FILE			*f;

	printf("\n*** We allready opened a session and logged in ***\n");

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
		fatal("Couldn't open file \"%s\"\n", opt_file_to_write);
	fclose(f);

	/* Get for a not-yet-existing ID */
	while(find_object(session, CKO_PRIVATE_KEY, &priv_key, id, id_len, 0))
		id[0]++;
	
	printf("\n*** Generating a 1024 bit RSA key pair ***\n");

	if (!gen_keypair(slot, session, &pub_key, &priv_key))
		return;

	tmp = getID(session, priv_key, (CK_ULONG *) &opt_object_id_len);
	if (opt_object_id == NULL || opt_object_id_len == 0) {
		printf("ERR: newly generated private key has no (or an empty) CKA_ID\n");
		return;
	}
	memcpy(opt_object_id, tmp, opt_object_id_len);

	/* This is done in NSS */
	mod = getMODULUS(session, priv_key, &mod_len);
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
		fatal("Failed to load pkcs11 module");

	rv = p11->C_Initialize(NULL);
	if (rv != CKR_OK)
		p11_fatal("C_Initialize", rv);

	rv = p11->C_OpenSession(opt_slot, CKF_SERIAL_SESSION| CKF_RW_SESSION,
			NULL, NULL, &session);
	if (rv != CKR_OK)
		p11_fatal("C_OpenSession", rv);

	login(session);

	printf("\n*** Put a cert on the card (NOTE: doesn't correspond with the key!) ***\n");

	opt_object_class = CKO_CERTIFICATE;
	memcpy(opt_object_id, id, id_len);
	opt_object_id_len = id_len;
	opt_object_label = (char *) label;
	if (!write_object(slot, session))
		return;

	printf("\n==> OK, successfull! Should work with Mozilla\n");	
}

const char *
p11_flag_names(struct flag_info *list, CK_FLAGS value)
{
	static char	buffer[1024];
	const char	*sepa = "";

	buffer[0] = '\0';
	while (list->value) {
		if (list->value & value) {
			strcat(buffer, sepa);
			strcat(buffer, list->name);
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

const char *
p11_slot_info_flags(CK_FLAGS value)
{
	static struct flag_info	slot_flags[] = {
		{ CKF_TOKEN_PRESENT, "token present" },
		{ CKF_REMOVABLE_DEVICE, "removable device" },
		{ CKF_HW_SLOT, "hardware slot" },
		{ 0 }
	};

	return p11_flag_names(slot_flags, value);
}

const char *
p11_token_info_flags(CK_FLAGS value)
{
	static struct flag_info	slot_flags[] = {
		{ CKF_RNG, "rng" },
		{ CKF_WRITE_PROTECTED, "readonly" },
		{ CKF_LOGIN_REQUIRED, "login required" },
		{ CKF_USER_PIN_INITIALIZED, "PIN initialized" },
		{ CKF_PROTECTED_AUTHENTICATION_PATH, "PIN pad present" },
		{ CKF_TOKEN_INITIALIZED, "token initialized" },
		{ 0 }
	};

	return p11_flag_names(slot_flags, value);
}

const char *
p11_utf8_to_local(CK_UTF8CHAR *string, size_t len)
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

void
p11_fatal(const char *func, CK_RV rv)
{
	fatal("PKCS11 function %s failed: rv = %s (0x%0x)\n",
		func, CKR2Str(rv), (unsigned int) rv);
}

void
p11_perror(const char *msg, CK_RV rv)
{
	fprintf(stderr,
		"  ERR: %s failed: %s (0x%0x)\n",
		msg, CKR2Str(rv), (unsigned int) rv);
}

int hex_to_bin(const char *in, unsigned char *out, size_t *outlen)
{
	size_t left, count = 0;

	if (in == NULL || *in == '\0') {
		*outlen = 0;
		return 1;
	}

        left = *outlen;

	while (*in != '\0') {
		int byte = 0, nybbles = 2;
		char c;

		while (nybbles-- && *in && *in != ':') {
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
		c++;
	}

	*outlen = count;
	return 1;
}

static struct mech_info	p11_mechanisms[] = {
      { CKM_RSA_PKCS_KEY_PAIR_GEN,		"RSA-PKCS-KEY-PAIR-GEN" },
      { CKM_RSA_PKCS,		"RSA-PKCS" },
      { CKM_RSA_9796,		"RSA-9796" },
      { CKM_RSA_X_509,		"RSA-X-509" },
      { CKM_MD2_RSA_PKCS,	"MD2-RSA-PKCS" },
      { CKM_MD5_RSA_PKCS,	"MD5-RSA-PKCS",		"rsa-md5" },
      { CKM_SHA1_RSA_PKCS,	"SHA1-RSA-PKCS",	"rsa-sha1" },
      { CKM_RIPEMD128_RSA_PKCS,	"RIPEMD128-RSA-PKCS" },
      { CKM_RIPEMD160_RSA_PKCS,	"RIPEMD160-RSA-PKCS",	"rsa-ripemd160" },
      { CKM_RSA_PKCS_OAEP,	"RSA-PKCS-OAEP" },
      { CKM_RSA_X9_31_KEY_PAIR_GEN,"RSA-X9-31-KEY-PAIR-GEN" },
      { CKM_RSA_X9_31,		"RSA-X9-31" },
      { CKM_SHA1_RSA_X9_31,	"SHA1-RSA-X9-31" },
      { CKM_RSA_PKCS_PSS,	"RSA-PKCS-PSS" },
      { CKM_SHA1_RSA_PKCS_PSS,	"SHA1-RSA-PKCS-PSS" },
      { CKM_DSA_KEY_PAIR_GEN,	"DSA-KEY-PAIR-GEN" },
      { CKM_DSA,		"DSA" },
      { CKM_DSA_SHA1,		"DSA-SHA1" },
      { CKM_DH_PKCS_KEY_PAIR_GEN,"DH-PKCS-KEY-PAIR-GEN" },
      { CKM_DH_PKCS_DERIVE,	"DH-PKCS-DERIVE" },
      { CKM_X9_42_DH_KEY_PAIR_GEN,"X9-42-DH-KEY-PAIR-GEN" },
      { CKM_X9_42_DH_DERIVE,	"X9-42-DH-DERIVE" },
      { CKM_X9_42_DH_HYBRID_DERIVE,"X9-42-DH-HYBRID-DERIVE" },
      { CKM_X9_42_MQV_DERIVE,	"X9-42-MQV-DERIVE" },
      { CKM_RC2_KEY_GEN,	"RC2-KEY-GEN" },
      { CKM_RC2_ECB,		"RC2-ECB" },
      { CKM_RC2_CBC,		"RC2-CBC" },
      { CKM_RC2_MAC,		"RC2-MAC" },
      { CKM_RC2_MAC_GENERAL,	"RC2-MAC-GENERAL" },
      { CKM_RC2_CBC_PAD,	"RC2-CBC-PAD" },
      { CKM_RC4_KEY_GEN,	"RC4-KEY-GEN" },
      { CKM_RC4,		"RC4" },
      { CKM_DES_KEY_GEN,	"DES-KEY-GEN" },
      { CKM_DES_ECB,		"DES-ECB" },
      { CKM_DES_CBC,		"DES-CBC" },
      { CKM_DES_MAC,		"DES-MAC" },
      { CKM_DES_MAC_GENERAL,	"DES-MAC-GENERAL" },
      { CKM_DES_CBC_PAD,	"DES-CBC-PAD" },
      { CKM_DES2_KEY_GEN,	"DES2-KEY-GEN" },
      { CKM_DES3_KEY_GEN,	"DES3-KEY-GEN" },
      { CKM_DES3_ECB,		"DES3-ECB" },
      { CKM_DES3_CBC,		"DES3-CBC" },
      { CKM_DES3_MAC,		"DES3-MAC" },
      { CKM_DES3_MAC_GENERAL,	"DES3-MAC-GENERAL" },
      { CKM_DES3_CBC_PAD,	"DES3-CBC-PAD" },
      { CKM_CDMF_KEY_GEN,	"CDMF-KEY-GEN" },
      { CKM_CDMF_ECB,		"CDMF-ECB" },
      { CKM_CDMF_CBC,		"CDMF-CBC" },
      { CKM_CDMF_MAC,		"CDMF-MAC" },
      { CKM_CDMF_MAC_GENERAL,	"CDMF-MAC-GENERAL" },
      { CKM_CDMF_CBC_PAD,	"CDMF-CBC-PAD" },
      { CKM_MD2,		"MD2" },
      { CKM_MD2_HMAC,		"MD2-HMAC" },
      { CKM_MD2_HMAC_GENERAL,	"MD2-HMAC-GENERAL" },
      { CKM_MD5,		"MD5" },
      { CKM_MD5_HMAC,		"MD5-HMAC" },
      { CKM_MD5_HMAC_GENERAL,	"MD5-HMAC-GENERAL" },
      { CKM_SHA_1,		"SHA-1" },
      { CKM_SHA_1_HMAC,		"SHA-1-HMAC" },
      { CKM_SHA_1_HMAC_GENERAL,	"SHA-1-HMAC-GENERAL" },
      { CKM_RIPEMD128,		"RIPEMD128" },
      { CKM_RIPEMD128_HMAC,	"RIPEMD128-HMAC" },
      { CKM_RIPEMD128_HMAC_GENERAL,"RIPEMD128-HMAC-GENERAL" },
      { CKM_RIPEMD160,		"RIPEMD160" },
      { CKM_RIPEMD160_HMAC,	"RIPEMD160-HMAC" },
      { CKM_RIPEMD160_HMAC_GENERAL,"RIPEMD160-HMAC-GENERAL" },
      { CKM_CAST_KEY_GEN,	"CAST-KEY-GEN" },
      { CKM_CAST_ECB,		"CAST-ECB" },
      { CKM_CAST_CBC,		"CAST-CBC" },
      { CKM_CAST_MAC,		"CAST-MAC" },
      { CKM_CAST_MAC_GENERAL,	"CAST-MAC-GENERAL" },
      { CKM_CAST_CBC_PAD,	"CAST-CBC-PAD" },
      { CKM_CAST3_KEY_GEN,	"CAST3-KEY-GEN" },
      { CKM_CAST3_ECB,		"CAST3-ECB" },
      { CKM_CAST3_CBC,		"CAST3-CBC" },
      { CKM_CAST3_MAC,		"CAST3-MAC" },
      { CKM_CAST3_MAC_GENERAL,	"CAST3-MAC-GENERAL" },
      { CKM_CAST3_CBC_PAD,	"CAST3-CBC-PAD" },
      { CKM_CAST5_KEY_GEN,	"CAST5-KEY-GEN" },
      { CKM_CAST5_ECB,		"CAST5-ECB" },
      { CKM_CAST5_CBC,		"CAST5-CBC" },
      { CKM_CAST5_MAC,		"CAST5-MAC" },
      { CKM_CAST5_MAC_GENERAL,	"CAST5-MAC-GENERAL" },
      { CKM_CAST5_CBC_PAD,	"CAST5-CBC-PAD" },
      { CKM_RC5_KEY_GEN,	"RC5-KEY-GEN" },
      { CKM_RC5_ECB,		"RC5-ECB" },
      { CKM_RC5_CBC,		"RC5-CBC" },
      { CKM_RC5_MAC,		"RC5-MAC" },
      { CKM_RC5_MAC_GENERAL,	"RC5-MAC-GENERAL" },
      { CKM_RC5_CBC_PAD,	"RC5-CBC-PAD" },
      { CKM_IDEA_KEY_GEN,	"IDEA-KEY-GEN" },
      { CKM_IDEA_ECB,		"IDEA-ECB" },
      { CKM_IDEA_CBC,		"IDEA-CBC" },
      { CKM_IDEA_MAC,		"IDEA-MAC" },
      { CKM_IDEA_MAC_GENERAL,	"IDEA-MAC-GENERAL" },
      { CKM_IDEA_CBC_PAD,	"IDEA-CBC-PAD" },
      { CKM_GENERIC_SECRET_KEY_GEN,"GENERIC-SECRET-KEY-GEN" },
      { CKM_CONCATENATE_BASE_AND_KEY,"CONCATENATE-BASE-AND-KEY" },
      { CKM_CONCATENATE_BASE_AND_DATA,"CONCATENATE-BASE-AND-DATA" },
      { CKM_CONCATENATE_DATA_AND_BASE,"CONCATENATE-DATA-AND-BASE" },
      { CKM_XOR_BASE_AND_DATA,	"XOR-BASE-AND-DATA" },
      { CKM_EXTRACT_KEY_FROM_KEY,"EXTRACT-KEY-FROM-KEY" },
      { CKM_SSL3_PRE_MASTER_KEY_GEN,"SSL3-PRE-MASTER-KEY-GEN" },
      { CKM_SSL3_MASTER_KEY_DERIVE,"SSL3-MASTER-KEY-DERIVE" },
      { CKM_SSL3_KEY_AND_MAC_DERIVE,"SSL3-KEY-AND-MAC-DERIVE" },
      { CKM_SSL3_MASTER_KEY_DERIVE_DH,"SSL3-MASTER-KEY-DERIVE-DH" },
      { CKM_TLS_PRE_MASTER_KEY_GEN,"TLS-PRE-MASTER-KEY-GEN" },
      { CKM_TLS_MASTER_KEY_DERIVE,"TLS-MASTER-KEY-DERIVE" },
      { CKM_TLS_KEY_AND_MAC_DERIVE,"TLS-KEY-AND-MAC-DERIVE" },
      { CKM_TLS_MASTER_KEY_DERIVE_DH,"TLS-MASTER-KEY-DERIVE-DH" },
      { CKM_SSL3_MD5_MAC,	"SSL3-MD5-MAC" },
      { CKM_SSL3_SHA1_MAC,	"SSL3-SHA1-MAC" },
      { CKM_MD5_KEY_DERIVATION,	"MD5-KEY-DERIVATION" },
      { CKM_MD2_KEY_DERIVATION,	"MD2-KEY-DERIVATION" },
      { CKM_SHA1_KEY_DERIVATION,"SHA1-KEY-DERIVATION" },
      { CKM_PBE_MD2_DES_CBC,	"PBE-MD2-DES-CBC" },
      { CKM_PBE_MD5_DES_CBC,	"PBE-MD5-DES-CBC" },
      { CKM_PBE_MD5_CAST_CBC,	"PBE-MD5-CAST-CBC" },
      { CKM_PBE_MD5_CAST3_CBC,	"PBE-MD5-CAST3-CBC" },
      { CKM_PBE_MD5_CAST5_CBC,	"PBE-MD5-CAST5-CBC" },
      { CKM_PBE_SHA1_CAST5_CBC,	"PBE-SHA1-CAST5-CBC" },
      { CKM_PBE_SHA1_RC4_128,	"PBE-SHA1-RC4-128" },
      { CKM_PBE_SHA1_RC4_40,	"PBE-SHA1-RC4-40" },
      { CKM_PBE_SHA1_DES3_EDE_CBC,"PBE-SHA1-DES3-EDE-CBC" },
      { CKM_PBE_SHA1_DES2_EDE_CBC,"PBE-SHA1-DES2-EDE-CBC" },
      { CKM_PBE_SHA1_RC2_128_CBC,"PBE-SHA1-RC2-128-CBC" },
      { CKM_PBE_SHA1_RC2_40_CBC,"PBE-SHA1-RC2-40-CBC" },
      { CKM_PKCS5_PBKD2,	"PKCS5-PBKD2" },
      { CKM_PBA_SHA1_WITH_SHA1_HMAC,"PBA-SHA1-WITH-SHA1-HMAC" },
      { CKM_KEY_WRAP_LYNKS,	"KEY-WRAP-LYNKS" },
      { CKM_KEY_WRAP_SET_OAEP,	"KEY-WRAP-SET-OAEP" },
      { CKM_SKIPJACK_KEY_GEN,	"SKIPJACK-KEY-GEN" },
      { CKM_SKIPJACK_ECB64,	"SKIPJACK-ECB64" },
      { CKM_SKIPJACK_CBC64,	"SKIPJACK-CBC64" },
      { CKM_SKIPJACK_OFB64,	"SKIPJACK-OFB64" },
      { CKM_SKIPJACK_CFB64,	"SKIPJACK-CFB64" },
      { CKM_SKIPJACK_CFB32,	"SKIPJACK-CFB32" },
      { CKM_SKIPJACK_CFB16,	"SKIPJACK-CFB16" },
      { CKM_SKIPJACK_CFB8,	"SKIPJACK-CFB8" },
      { CKM_SKIPJACK_WRAP,	"SKIPJACK-WRAP" },
      { CKM_SKIPJACK_PRIVATE_WRAP,"SKIPJACK-PRIVATE-WRAP" },
      { CKM_SKIPJACK_RELAYX,	"SKIPJACK-RELAYX" },
      { CKM_KEA_KEY_PAIR_GEN,	"KEA-KEY-PAIR-GEN" },
      { CKM_KEA_KEY_DERIVE,	"KEA-KEY-DERIVE" },
      { CKM_FORTEZZA_TIMESTAMP,	"FORTEZZA-TIMESTAMP" },
      { CKM_BATON_KEY_GEN,	"BATON-KEY-GEN" },
      { CKM_BATON_ECB128,	"BATON-ECB128" },
      { CKM_BATON_ECB96,	"BATON-ECB96" },
      { CKM_BATON_CBC128,	"BATON-CBC128" },
      { CKM_BATON_COUNTER,	"BATON-COUNTER" },
      { CKM_BATON_SHUFFLE,	"BATON-SHUFFLE" },
      { CKM_BATON_WRAP,		"BATON-WRAP" },
      { CKM_ECDSA_KEY_PAIR_GEN,	"ECDSA-KEY-PAIR-GEN" },
      { CKM_ECDSA,		"ECDSA" },
      { CKM_ECDSA_SHA1,		"ECDSA-SHA1" },
      { CKM_ECDH1_DERIVE,	"ECDH1-DERIVE" },
      { CKM_ECDH1_COFACTOR_DERIVE,"ECDH1-COFACTOR-DERIVE" },
      { CKM_ECMQV_DERIVE,	"ECMQV-DERIVE" },
      { CKM_JUNIPER_KEY_GEN,	"JUNIPER-KEY-GEN" },
      { CKM_JUNIPER_ECB128,	"JUNIPER-ECB128" },
      { CKM_JUNIPER_CBC128,	"JUNIPER-CBC128" },
      { CKM_JUNIPER_COUNTER,	"JUNIPER-COUNTER" },
      { CKM_JUNIPER_SHUFFLE,	"JUNIPER-SHUFFLE" },
      { CKM_JUNIPER_WRAP,	"JUNIPER-WRAP" },
      { CKM_FASTHASH,		"FASTHASH" },
      { CKM_AES_KEY_GEN,	"AES-KEY-GEN" },
      { CKM_AES_ECB,		"AES-ECB" },
      { CKM_AES_CBC,		"AES-CBC" },
      { CKM_AES_MAC,		"AES-MAC" },
      { CKM_AES_MAC_GENERAL,	"AES-MAC-GENERAL" },
      { CKM_AES_CBC_PAD,	"AES-CBC-PAD" },
      { CKM_DSA_PARAMETER_GEN,	"DSA-PARAMETER-GEN" },
      { CKM_DH_PKCS_PARAMETER_GEN,"DH-PKCS-PARAMETER-GEN" },
      { CKM_X9_42_DH_PARAMETER_GEN,"X9-42-DH-PARAMETER-GEN" },
      { NO_MECHANISM, NULL }
};

static const char *
p11_mechanism_to_name(CK_MECHANISM_TYPE mech)
{
	static char temp[64];
	struct mech_info *mi;

	for (mi = p11_mechanisms; mi->name; mi++) {
		if (mi->mech == mech)
			return mi->name;
	}
	snprintf(temp, sizeof(temp), "mechtype-%lu", mech);
	return temp;
}

CK_MECHANISM_TYPE
p11_name_to_mechanism(const char *name)
{
	struct mech_info *mi;

	for (mi = p11_mechanisms; mi->name; mi++) {
		if (!strcasecmp(mi->name, name)
		 || (mi->short_name && !strcasecmp(mi->short_name, name)))
			return mi->mech;
	}
	fatal("Unknown PKCS11 mechanism \"%s\"\n", name);
	return NO_MECHANISM; /* gcc food */
}

static const char *
CKR2Str(CK_ULONG res)
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
