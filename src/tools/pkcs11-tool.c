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

#ifdef _WIN32
char *getpass(const char *prompt); /* in src/common/getpass.c */
#endif

#define NEED_SESSION_RO	0x01
#define NEED_SESSION_RW	0x02
#define NO_SLOT		((CK_SLOT_ID) -1)
#define NO_MECHANISM	((CK_MECHANISM_TYPE) -1)

enum {
	OPT_SLOT,
};

const struct option options[] = {
	{ "show-info",		0, 0,		'I' },
	{ "list-slots",		0, 0,		'L' },
	{ "list-mechanisms",	0, 0,		'M' },
	{ "list-objects",	0, 0,		'O' },

	{ "sign",		1, 0,		's' },
	{ "mechanism",		1, 0,		'm' },

	{ "login",		0, 0,		'l' },
	{ "slot",		1, 0,		OPT_SLOT },
	{ "input-file",		1, 0,		'i' },
	{ "output-file",	1, 0,		'o' },
	{ "verbose",		0, 0,		'v' },
	{ 0, 0, 0, 0 }
};

const char *option_help[] = {
	"Show global token information",
	"List slots available on the token",
	"Show slot information",
	"List mechanisms supported by the token",

	"Sign some data",
	"Specify mechanism (use -M for a list of supported mechanisms)",

	"Log into the token first",
	"Specify the slot to use",
	"Specify the input file",
	"Specify the output file",
	"Verbose output",
};

const char *		app_name = "pkcs11-tool"; /* for utils.c */

static int		opt_verbose = 0;
static const char *	opt_input = NULL;
static const char *	opt_output = NULL;
static CK_SLOT_ID	opt_slot = NO_SLOT;
static CK_MECHANISM_TYPE opt_mechanism = NO_MECHANISM;

static sc_pkcs11_module_t *module = NULL;
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
static void		show_slot(CK_SLOT_ID);
static void		list_mechs(CK_SLOT_ID);
static void		list_objects(CK_SESSION_HANDLE);
static void		show_object(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static void		show_key(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, int);
static void		sign_data(CK_SLOT_ID,
				CK_SESSION_HANDLE, CK_OBJECT_HANDLE);
static int		find_first(CK_SESSION_HANDLE, CK_OBJECT_CLASS,
				CK_OBJECT_HANDLE_PTR, const char *);
static CK_MECHANISM_TYPE find_mechanism(CK_SLOT_ID, CK_FLAGS);
static void		get_token_info(CK_SLOT_ID, CK_TOKEN_INFO_PTR);
static void		get_mechanisms(CK_SLOT_ID,
				CK_MECHANISM_TYPE_PTR *, CK_ULONG_PTR);
static void		p11_fatal(const char *, CK_RV);
static const char *	p11_slot_info_flags(CK_FLAGS);
static const char *	p11_token_info_flags(CK_FLAGS);
static const char *	p11_utf8_to_local(CK_UTF8CHAR *, size_t);
static const char *	p11_flag_names(struct flag_info *, CK_FLAGS);
static const char *	p11_mechanism_to_name(CK_MECHANISM_TYPE);
static CK_MECHANISM_TYPE p11_name_to_mechanism(const char *);

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
	int need_session = 0;
	int opt_login = 0;
	int action_count = 0;
	CK_RV rv;

	while (1) {
		c = getopt_long(argc, argv, "ILMOi:lm:o:sv",
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
		case 's':
			need_session |= NEED_SESSION_RW;
			do_sign = 1;
			action_count++;
			break;
		case 'v':
			opt_verbose++;
			break;
		case OPT_SLOT:
			opt_slot = (CK_SLOT_ID) atoi(optarg);
			break;
		default:
			print_usage_and_die();
		}
	}
	if (action_count == 0)
		print_usage_and_die();

	module = C_LoadModule(NULL, &p11);
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

	if (opt_login) {
		char	*pin;

		/* Identify which pin to enter */
		pin = getpass("Please enter PIN: ");
		if (!pin || !*pin)
			return 1;
		rv = p11->C_Login(session, CKU_USER, pin, strlen(pin));
		if (rv != CKR_OK)
			p11_fatal("C_Login", rv);
	}

	if (do_sign) {
		if (!find_first(session, CKO_PRIVATE_KEY, &object, NULL))
			fatal("Private key not found");
	}

	if (do_list_objects)
		list_objects(session);
	if (do_sign)
		sign_data(opt_slot, session, object);

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
		if (!opt_verbose && !(info.flags & CKF_TOKEN_PRESENT)) {
			printf("(empty)\n");
			continue;
		}
		printf("%s\n", p11_utf8_to_local(info.slotDescription,
					sizeof(info.slotDescription)));
		if (opt_verbose) {
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
		show_slot(p11_slots[n]);
	}
}

void
show_slot(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO	info;

	get_token_info(slot, &info);

	if (!(info.flags & CKF_TOKEN_INITIALIZED) && !opt_verbose) {
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
}

void
list_mechs(CK_SLOT_ID slot)
{
	CK_MECHANISM_TYPE	*mechs = NULL;
	CK_ULONG		n, num_mechs = 0;
	CK_RV			rv;

	get_mechanisms(slot, &mechs, &num_mechs);

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
			if (info.flags & CKF_UNWRAP)
				printf(", unwrap");
			if (info.flags & CKF_HW)
				printf(", hw");
			info.flags &= ~(CKF_DIGEST|CKF_SIGN|CKF_VERIFY|CKF_HW|CKF_UNWRAP);
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

void
sign_data(CK_SLOT_ID slot, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key)
{
	unsigned char	buffer[512];
	CK_MECHANISM	mech;
	CK_RV		rv;
	CK_ULONG	sig_len;
	int		fd, r;

	if (opt_mechanism == NO_MECHANISM) {
		opt_mechanism = find_mechanism(slot, CKF_SIGN|CKF_HW);
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
	else if ((fd = open(opt_input, O_RDONLY)) < 0)
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

	if (opt_output == NULL)
		fd = 1;
	else if ((fd = open(opt_output, O_CREAT|O_TRUNC|O_WRONLY, 0666)) < 0)
		fatal("failed to open %s: %m", opt_output);

	r = write(fd, buffer, sig_len);
	if (r < 0)
		fatal("Failed to write to %s: %m", opt_output);
	if (fd != 1)
		close(fd);
}

int
find_first(CK_SESSION_HANDLE sess, CK_OBJECT_CLASS cls,
		CK_OBJECT_HANDLE_PTR ret, const char *id)
{
	CK_ATTRIBUTE attrs[2];
	unsigned int nattrs = 0;
	CK_ULONG count;
	CK_RV rv;

	attrs[0].type = CKA_CLASS;
	attrs[0].pValue = &cls;
	attrs[0].ulValueLen = sizeof(cls);
	nattrs++;
	if (id) {
		/* Parse the ID and add it to the attrs list */
	}

	rv = p11->C_FindObjectsInit(sess, attrs, nattrs);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjectsInit", rv);

	rv = p11->C_FindObjects(sess, ret, 1, &count);
	if (rv != CKR_OK)
		p11_fatal("C_FindObjects", rv);

	p11->C_FindObjectsFinal(sess);

	return count;
}

CK_MECHANISM_TYPE
find_mechanism(CK_SLOT_ID slot, CK_FLAGS flags)
{
	CK_MECHANISM_TYPE *mechs = NULL, result;
	CK_MECHANISM_INFO info;
	CK_ULONG	n, count = 0;
	CK_RV		rv;

	get_mechanisms(slot, &mechs, &count);

	result = NO_MECHANISM;
	for (n = 0; n < count; n++) {
		rv = p11->C_GetMechanismInfo(slot, mechs[n], &info);
		if (rv != CKR_OK)
			continue;
		if ((info.flags & flags) == flags) {
			result = mechs[n];
			break;
		}
	}
	if (result == NO_MECHANISM)
		fatal("No appropriate mechanism found");
	free(mechs);

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
		if (!(attr.pValue = malloc(attr.ulValueLen))) \
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
ATTR_METHOD(VERIFY, CK_BBOOL);
ATTR_METHOD(VERIFY_RECOVER, CK_BBOOL);
ATTR_METHOD(WRAP, CK_BBOOL);
ATTR_METHOD(DERIVE, CK_BBOOL);
ATTR_METHOD(EXTRACTABLE, CK_BBOOL);
ATTR_METHOD(KEY_TYPE, CK_KEY_TYPE);
ATTR_METHOD(MODULUS_BITS, CK_ULONG);
VARATTR_METHOD(LABEL, char);
VARATTR_METHOD(ID, unsigned char);

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
	char		*label;

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
}

void
get_token_info(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV		rv;

	rv = p11->C_GetTokenInfo(slot, info);
	if (rv != CKR_OK)
		p11_fatal("C_GetTokenInfo", rv);
}

void
get_mechanisms(CK_SLOT_ID slot,
		CK_MECHANISM_TYPE_PTR *pList,
		CK_ULONG_PTR pulCount)
{
	CK_RV	rv;

	rv = p11->C_GetMechanismList(slot, *pList, pulCount);
	*pList = (CK_MECHANISM_TYPE *) calloc(*pulCount, sizeof(*pList));
	if (*pList == NULL)
		fatal("calloc failed: %m");

	rv = p11->C_GetMechanismList(slot, *pList, pulCount);
	if (rv != CKR_OK)
		p11_fatal("C_GetMechanismList", rv);
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
	fatal("PKCS11 function %s failed: rv = %d (0x%x)\n", func, rv, rv);
}

static struct mech_info	p11_mechanisms[] = {
      { CKM_RSA_PKCS_KEY_PAIR_GEN,		"RSA-PKCS-KEY-PAIR-GEN" },
      { CKM_RSA_PKCS,		"RSA-PKCS" },
      { CKM_RSA_9796,		"RSA-9796" },
      { CKM_RSA_X_509,		"RSA-X-509" },
      { CKM_MD2_RSA_PKCS,	"MD2-RSA-PKCS" },
      { CKM_MD5_RSA_PKCS,	"MD5-RSA-PKCS",	"rsa-md5" },
      { CKM_SHA1_RSA_PKCS,	"SHA1-RSA-PKCS",	"rsa-sha1" },
      { CKM_RIPEMD128_RSA_PKCS,	"RIPEMD128-RSA-PKCS" },
      { CKM_RIPEMD160_RSA_PKCS,	"RIPEMD160-RSA-PKCS" },
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
