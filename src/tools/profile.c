/*
 * Initialize Cards according to PKCS#15
 *
 * Copyright (C) 2002 Olaf Kirch <okir@lst.de>
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
#include "util.h"
#include "profile.h"

struct command {
	const char *		name;
	int			section;
	int			min_args, max_args;
	int			(*func)(int, char **);
};

enum { PARSE_HEADER, PARSE_FILE, PARSE_CARDINFO, PARSE_PIN, PARSE_PRKEY };
static struct parser_info {
	const char *		filename;
	unsigned int		lineno;
	struct sc_profile *	profile;
	int			section;
	struct file_info *	cur_file;
	struct pin_info *	cur_pin;
	struct prkey_info *	cur_prkey;
}	parser;

struct map {
	const char *		name;
	unsigned int		val;
};

static struct map		aclnames[] = {
	{ "NONE",	SC_AC_NONE	},
	{ "NEVER",	SC_AC_NEVER	},
	{ "CHV",	SC_AC_CHV	},
	{ "TERM",	SC_AC_TERM	},
	{ "PRO",	SC_AC_PRO	},
	{ "AUT",	SC_AC_AUT	},
	{ "KEY",	SC_AC_AUT	},
	{ 0, 0 }
};
static struct map		keytypenames[] = {
	{ "PRO",	SC_AC_PRO	},
	{ "AUT",	SC_AC_AUT	},
	{ "CHV",	SC_AC_CHV	},
	{ 0, 0 }
};
static struct map		opnames[] = {
	{ "SELECT",	SC_AC_OP_SELECT	},
	{ "LOCK",	SC_AC_OP_LOCK	},
	{ "DELETE",	SC_AC_OP_DELETE	},
	{ "CREATE",	SC_AC_OP_CREATE	},
	{ "REHABILITATE",SC_AC_OP_REHABILITATE	},
	{ "INVALIDATE",	SC_AC_OP_INVALIDATE	},
	{ "FILES",	SC_AC_OP_LIST_FILES	},
	{ "READ",	SC_AC_OP_READ	},
	{ "UPDATE",	SC_AC_OP_UPDATE	},
	{ "WRITE",	SC_AC_OP_WRITE	},
	{ "ERASE",	SC_AC_OP_ERASE	},
	{ 0, 0 }
};
static struct map		efnames[] = {
	{ "TRANSPARENT",	SC_FILE_EF_TRANSPARENT	},
	{ "LINEAR-FIXED",	SC_FILE_EF_LINEAR_FIXED	},
	{ "LINEAR-FIXED-TLV",	SC_FILE_EF_LINEAR_FIXED_TLV	},
	{ "LINEAR-VARIABLE",	SC_FILE_EF_LINEAR_VARIABLE	},
	{ "LINEAR-VARIABLE-TLV",SC_FILE_EF_LINEAR_VARIABLE_TLV	},
	{ "CYCLIC",		SC_FILE_EF_CYCLIC	},
	{ "CYCLIC-TLV",		SC_FILE_EF_CYCLIC_TLV	},
	{ 0, 0 }
};
static struct map		pkcs15dfnames[] = {
	{ "PRKDF",		SC_PKCS15_PRKDF		},
	{ "PUKDF",		SC_PKCS15_PUKDF		},
	{ "PUKDF-TRUSTED",	SC_PKCS15_PUKDF_TRUSTED	},
	{ "SKDF",		SC_PKCS15_SKDF		},
	{ "CDF",		SC_PKCS15_CDF		},
	{ "CDF-TRUSTED",	SC_PKCS15_CDF_TRUSTED	},
	{ "CDF-USEFUL",		SC_PKCS15_CDF_USEFUL	},
	{ "DODF",		SC_PKCS15_DODF		},
	{ "AODF",		SC_PKCS15_AODF		},
	{ 0, 0 }
};
static struct map		pintypenames[] = {
	{ "BCD",		0			},
	{ "ascii-numeric",	1			},
	{ "utf8",		2			},
	{ "half-nibble-bcd",	3			},
	{ "iso9564-1",		4			},
	{ 0, 0 }
};
static struct map		algorithmnames[] = {
	{ "RSA",		SC_PKCS15_TYPE_PRKEY_RSA },
	{ 0, 0 }
};
static struct map		keyusagenames[] = {
	{ "ENCRYPT",		SC_PKCS15_PRKEY_USAGE_ENCRYPT	},
	{ "DECRYPT",		SC_PKCS15_PRKEY_USAGE_DECRYPT	},
	{ "SIGN",		SC_PKCS15_PRKEY_USAGE_SIGN	},
	{ "SIGNRECOVER",	SC_PKCS15_PRKEY_USAGE_SIGNRECOVER},
	{ "WRAP",		SC_PKCS15_PRKEY_USAGE_WRAP	},
	{ "UNWRAP",		SC_PKCS15_PRKEY_USAGE_UNWRAP	},
	{ "VERIFY",		SC_PKCS15_PRKEY_USAGE_VERIFY	},
	{ "VERIFYRECOVER",	SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER},
	{ "DERIVE",		SC_PKCS15_PRKEY_USAGE_DERIVE	},
	{ "NONREPUDIATION",	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION},
	{ 0, 0 }
};

static int	process(int, char **);
static char *	next_word(char **p);
static int	get_authid(const char *, unsigned int *, unsigned int *);
static int	get_uint(const char *, unsigned int *);
static int	map_str2int(const char *, unsigned int *, struct map *);
static int	map_int2str(unsigned int, const char **, struct map *);
static int	setstr(char **strp, const char *value);
static void	parse_error(const char *, ...);
static int	add_object(struct sc_pkcs15_card *, int, int, unsigned int,
			void *, size_t);

static struct sc_file *
init_file(unsigned int type)
{
	struct sc_file	*file;
	unsigned int	op;

	file = sc_file_new();
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
	}
	file->type = type;
	file->status = SC_FILE_STATUS_ACTIVATED;
	return file;
}

/*
 * Initialize profile
 */
void
sc_profile_init(struct sc_profile *pro)
{
	struct sc_pkcs15_card *p15card;
	struct sc_file	*file;

	memset(pro, 0, sizeof(*pro));

	pro->p15_card = p15card = sc_pkcs15_card_new();

	/* set up the MF info */
	pro->mf_info.file = file = init_file(SC_FILE_TYPE_DF);
	sc_format_path("3F00", &file->path);

	/* XXX: set app_df to default AID */
	p15card->file_app = file = init_file(SC_FILE_TYPE_DF);
	file->size = 5000;
	pro->df_info.file = file;
	pro->df_info.ident = "Application DF";

	/* Set up EF(TokenInfo) and EF(ODF) */
	p15card->file_tokeninfo = init_file(SC_FILE_TYPE_WORKING_EF);
	p15card->file_odf = init_file(SC_FILE_TYPE_WORKING_EF);

	if (p15card) {
		p15card->label = strdup("OpenSC Card");
		p15card->manufacturer_id = strdup("OpenSC Project");
		p15card->serial_number = strdup("0000");
		p15card->flags = SC_PKCS15_CARD_FLAG_EID_COMPLIANT;
		p15card->version = 1;
	}
}

int
sc_profile_load(struct sc_profile *pro, const char *filename)
{
	char	buffer[1024];
	int	res = 0;
	FILE	*fp;

	if ((fp = fopen(filename, "r")) == NULL) {
		perror(filename);
		exit(1);
	}

	memset(&parser, 0, sizeof(parser));
	parser.filename	= filename;
	parser.profile	= pro;
	parser.section	= PARSE_HEADER;

	while (!res && fgets(buffer, sizeof(buffer), fp) != NULL) {
		char	*argv[16], *cp;
		int	argc = 0;

		buffer[strcspn(buffer, "\n")] = '\0';
		parser.lineno++;

		cp = buffer;
		while ((argv[argc] = next_word(&cp)) != NULL)
			argc++;

		if (argc != 0)
			res = process(argc, argv);
	}
	fclose(fp);
	return res;
}

/*
 * Fix up a file's ACL references
 */
static void
fix_acl(struct sc_profile *pro, struct sc_acl_entry *acl)
{
	const char	*name;
	struct auth_info *auth;
	struct pin_info	*pin;

	if (!acl || acl->method == SC_AC_NEVER || acl->method == SC_AC_NONE)
		return;

	for (; acl; acl = acl->next) {

		/* Look for any key/pin specified by the profile */
		for (auth = pro->auth_list; auth; auth = auth->next) {
			if (auth->type == acl->method
			 && auth->id == acl->key_ref)
				break;
		}
		if (auth) {
			acl->key_ref = auth->ref;
			continue;
		}

		/* Look for any PIN specified by the profile */
		if (acl->method == SC_AC_CHV) {
			for (pin = pro->pin_list; pin; pin = pin->next) {
				if (pin->id == acl->key_ref)
					break;
			}
			if (pin) {
				acl->key_ref = pin->pkcs15.reference;
				continue;
			}
		}
		
		if (map_int2str(acl->method, &name, keytypenames))
			fatal("ACL with bad or UNKNOWN condition");

		fatal("ACL references %s%u, which is not defined",
				name, acl->key_ref);
	}
}

static void
fix_file_acls(struct sc_profile *pro, struct sc_file *file)
{
	unsigned int	op;

	/* This is not ideal, because sc_file_get_acl_entry
	 * returns a const pointer and we want to modify it.
	 * But it's a lot less work than throwing away the list
	 * and creating a new one. */
	for (op = 0; op < SC_MAX_AC_OPS; op++)
		fix_acl(pro,
		    (struct sc_acl_entry *) sc_file_get_acl_entry(file, op));
}

int
sc_profile_finish(struct sc_profile *pro)
{
	struct file_info *fi;
	struct pin_info	*pi;
	struct prkey_info *pk;
	int		res = 0;

	/* Loop over all PINs and make sure they're sane */
	for (pi = pro->pin_list; pi; pi = pi->next) {
		if (!pi->file) {
			error("No File given for PIN %s", pi->ident);
			res = 1;
		}
		if (!pi->pkcs15.auth_id.len) {
			error("No auth_id set for PIN %s", pi->ident);
			res = 1;
		}
		pi->pkcs15.path = pi->file->file->path;
	}

	/* Loop over all files and fix up their security references */
	for (fi = pro->ef_list; fi; fi = fi->next) {
		fix_file_acls(pro, fi->file);
	}
	fix_file_acls(pro, pro->mf_info.file);
	fix_file_acls(pro, pro->df_info.file);

	/* Make sure all private keys are sane */
	for (pk = pro->prkey_list; pk; pk = pk->next) {
		struct sc_pkcs15_id *id;

		if (!pk->file) {
			error("No File given for private key %s", pk->ident);
			res = 1;
		}
		if (!pk->pkcs15.com_attr.auth_id.len) {
			error("No auth_id set for private key %s", pk->ident);
			res = 1;
		}
		if (!pk->pkcs15.id.len) {
			error("No key ID set for private key %s", pk->ident);
			res = 1;
		}
		if (!pk->pkcs15.usage) {
			error("No keyUsage specified for private key %s",
					pk->ident);
			res = 1;
		}
		pk->pkcs15.path = pk->file->file->path;

		/* Set up the key ACL */
		id = &pk->pkcs15.com_attr.auth_id;
		for (pi = pro->pin_list; pi; pi = pi->next) {
			if (sc_pkcs15_compare_id(&pi->pkcs15.auth_id, id) == 1)
				break;
		}
		if (pi == NULL) {
			error("Invalid or no AuthID on private key %s",
					pk->ident);
			res = 1;
		}
		pk->key_acl = calloc(1, sizeof(struct sc_acl_entry));
		pk->key_acl->method = SC_AC_CHV;
		pk->key_acl->key_ref = pi->pkcs15.reference;
	}

	return res;
}

int
sc_profile_build_pkcs15(struct sc_profile *pro)
{
	struct sc_pkcs15_card *p15card;
	struct pin_info	*pi;
	struct prkey_info *ki;
	int		res = 0;

	p15card = pro->p15_card;
	if (p15card->df[SC_PKCS15_CDF].count == 0)
		warn("No CDF defined in profile");
	if (p15card->df[SC_PKCS15_PRKDF].count == 0)
		warn("No PrKDF defined in profile");

	/* First, build AODF contents */
	if (p15card->df[SC_PKCS15_AODF].count == 0)
		fatal("No AODF defined in profile");

	/* Loop over all PINs and make sure they're sane */
	for (pi = pro->pin_list; pi && !res; pi = pi->next) {
		res = add_object(p15card, SC_PKCS15_AODF,
				pi->file->pkcs15.fileno,
				SC_PKCS15_TYPE_AUTH_PIN,
				&pi->pkcs15, sizeof(pi->pkcs15));
	}

	/* Loop over all private keys and add them to the PrKDF */
	for (ki = pro->prkey_list; ki && !res; ki = ki->next) {
		if (!ki->file)
			fatal("No file for private key \"%s\"\n", ki->ident);
		memcpy(&ki->pkcs15.path, &ki->file->file->path,
			sizeof(struct sc_path));
		res = add_object(p15card, SC_PKCS15_PRKDF,
				ki->file->pkcs15.fileno, ki->type,
				&ki->pkcs15, sizeof(ki->pkcs15));
	}

	return res;
}

static int
do_cardinfo(int argc, char **argv)
{
	parser.section = PARSE_CARDINFO;
	parser.cur_file = NULL;
	return 0;
}

static int
do_card_driver(int argc, char **argv)
{
	parser.profile->driver = strdup(argv[0]);
	return 0;
}

static int
do_key(int argc, char **argv)
{
	struct sc_profile *pro = parser.profile;
	struct auth_info *ai;
	const char	*key = argv[2];

	ai = (struct auth_info *) calloc(1, sizeof(*ai));

	if (get_authid(argv[0], &ai->type, &ai->id))
		return 1;

	if (get_uint(argv[1], &ai->ref))
		return 1;

	if (key[0] == '=') {
		++key;
		ai->key_len = strlen(key);
		memcpy(ai->key, key, ai->key_len);
	} else {
		ai->key_len = sizeof(ai->key);
		if (sc_hex_to_bin(key, ai->key, &ai->key_len)) {
			parse_error("Error parsing PIN/key \"%s\"\n",
				key);
			return 1;
		}
	}

	ai->next = pro->auth_list;
	pro->auth_list = ai;
	return 0;
}

static int
do_maxpinlength(int argc, char **argv)
{
	return get_uint(argv[0], &parser.profile->pin_maxlen);
}

static int
do_minpinlength(int argc, char **argv)
{
	return get_uint(argv[0], &parser.profile->pin_minlen);
}

static int
do_card_label(int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = parser.profile->p15_card;

	return setstr(&p15card->label, argv[0]);
}

static int
do_card_manufacturer(int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = parser.profile->p15_card;

	return setstr(&p15card->manufacturer_id, argv[0]);
}

static int
do_mf(int argc, char **argv)
{
	parser.section = PARSE_FILE;
	parser.cur_file = &parser.profile->mf_info;
	parser.cur_file->ident = strdup("MF");
	return 0;
}

static int
do_df(int argc, char **argv)
{
	parser.section = PARSE_FILE;
	parser.cur_file = &parser.profile->df_info;
	parser.cur_file->ident = strdup("App DF");
	return 0;
}

static int
do_ef(int argc, char **argv)
{
	struct sc_profile *pro = parser.profile;
	struct file_info *info;
	struct sc_file	*file;
	const char	*name = argv[0];
	unsigned int	df_type = 0;

	parser.section = PARSE_FILE;
	if ((info = sc_profile_find_file(pro, name)) != NULL)
		goto out;

	info = (struct file_info *) calloc(1, sizeof(*info));
	info->ident = strdup(name);

	/* Special cases for those EFs handled separately
	 * by the PKCS15 logic */
	if (strncasecmp(name, "PKCS15-", 7)) {
		file = init_file(SC_FILE_TYPE_WORKING_EF);
	} else if (!strcasecmp(name+7, "TokenInfo")) {
		file = parser.profile->p15_card->file_tokeninfo;
	} else if (!strcasecmp(name+7, "ODF")) {
		file = parser.profile->p15_card->file_odf;
	} else if (!strcasecmp(name+7, "DIR")) {
		/* This is gone from the sc_pkcs15_card struct,
		 * and I don't understand how it's supposed to be
		 * handled right now */
#if 0
		file = parser.profile->p15_card->file_dir;
#else
		file = init_file(SC_FILE_TYPE_WORKING_EF);
#endif
	} else {
		struct sc_pkcs15_df *df;

		if (map_str2int(name+7, &df_type, pkcs15dfnames))
			return 1;

		df = &pro->p15_card->df[df_type];
		if (df->count >= SC_PKCS15_MAX_DFS) {
			parse_error("Too many EF(%s) files\n", name + 7);
			return 1;
		}
		info->pkcs15.type = df_type;
		info->pkcs15.fileno = df->count;
		file = (struct sc_file *) calloc(1, sizeof(*file));
		df->file[df->count++] = file;
	}
	assert(file);

	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->status = SC_FILE_STATUS_ACTIVATED;
	info->file = file;

	info->next = parser.profile->ef_list;
	parser.profile->ef_list = info;

out:	parser.cur_file = info;
	return 0;
}

static int
do_path(int argc, char **argv)
{
	struct sc_file	*file = parser.cur_file->file;
	struct sc_path	*path = &file->path;

	/* sc_format_path doesn't return an error indication
	 * when it's unable to parse the path */
	sc_format_path(argv[0], path);
	if (!path->len || (path->len & 1)) {
		parse_error("Invalid path length\n");
		return 1;
	}
	file->id = (path->value[path->len-2] << 8)
		 | path->value[path->len-1];
	return 0;
}

static int
do_structure(int argc, char **argv)
{
	unsigned int	ef_structure;

	if (map_str2int(argv[0], &ef_structure, efnames))
		return 1;
	parser.cur_file->file->ef_structure = ef_structure;
	return 0;
}

static int
do_size(int argc, char **argv)
{
	unsigned int	size;

	if (get_uint(argv[0], &size))
		return 1;
	parser.cur_file->file->size = size;
	return 0;
}

static int
do_reclength(int argc, char **argv)
{
	unsigned int	reclength;

	if (get_uint(argv[0], &reclength))
		return 1;
	parser.cur_file->file->record_length = reclength;
	return 0;
}

static int
do_aid(int argc, char **argv)
{
	struct sc_file	*file = parser.cur_file->file;
	const char	*name = argv[0];
	unsigned int	len;
	int		res = 0;

	if (*name == '=') {
		len = strlen(++name);
		if (len > sizeof(file->name)) {
			parse_error("AID \"%s\" too long\n", name);
			return 1;
		}
		memcpy(file->name, name, len);
		file->namelen = len;
	} else {
		file->namelen = sizeof(file->name);
		res = sc_hex_to_bin(name, file->name, &file->namelen);
	}
	return res;
}

/*
 * Parse ACL list.
 * The way we do this is we first split things like CHV1
 * into a method (SC_AC_CHV) and a reference (1).
 * When we're finished parsing the profile, the fake references
 * are replaced by the real references given in KEY or PIN
 * commands
 */
static int
do_acl(int argc, char **argv)
{
	struct sc_file	*file = parser.cur_file->file;
	char		*oper = 0, *what = 0;

	while (argc--) {
		unsigned int	op, method, id;

		oper = *argv++;
		if ((what = strchr(oper, '=')) == NULL)
			goto bad;
		*what++ = '\0';

		if (get_authid(what, &method, &id))
			goto bad;

		if (!strcmp(oper, "*")) {
			for (op = 0; op < SC_MAX_AC_OPS; op++) {
				sc_file_clear_acl_entries(file, op);
				sc_file_add_acl_entry(file, op, method, id);
			}
		} else {
			const struct sc_acl_entry *acl;

			if (map_str2int(oper, &op, opnames))
				goto bad;
			acl = sc_file_get_acl_entry(file, op);
			if (acl->method == SC_AC_NEVER
			 || acl->method == SC_AC_NONE
			 || acl->method == SC_AC_UNKNOWN)
				sc_file_clear_acl_entries(file, op);
			sc_file_add_acl_entry(file, op, method, id);
		}
	}
	return 0;

bad:	parse_error(
		"Invalid ACL \"%s%s%s\"\n",
		oper, what? "=" : "", what? what : "");
	return 1;
}

static int
do_pin(int argc, char **argv)
{
	struct sc_profile *pro = parser.profile;
	struct pin_info	*pi, **tail;
	unsigned int	method, id;
	const char	*name = argv[0];

	parser.section = PARSE_PIN;
	if ((pi = sc_profile_find_pin(pro, name)) != NULL)
		goto out;

	if (get_authid(name, &method, &id)) {
		parse_error("Invalid PIN name \"%s\", must be CHVn\n", name);
		return 1;
	}

	pi = (struct pin_info *) malloc(sizeof(*pi));
	memset(pi, 0, sizeof(*pi));
	pi->ident = strdup(name);
	pi->id = id;
	pi->attempt[0] = 2;
	pi->pkcs15.type = 1;
	pi->pkcs15.flags = 0x32;
	pi->pkcs15.min_length = pro->pin_minlen;
	pi->pkcs15.stored_length = pro->pin_maxlen;
	pi->pkcs15.pad_char = pro->pin_pad_char;
	pi->pkcs15.com_attr.flags = 0x03; /* XXX */
	pi->pkcs15.magic = SC_PKCS15_PIN_MAGIC;

	for (tail = &pro->pin_list; *tail; tail = &(*tail)->next)
		;
	*tail = pi;

out:	parser.cur_pin = pi;
	return 0;
}

static int
do_pin_file(int argc, char **argv)
{
	struct file_info *fi;
	const char	*name = argv[0];

	if (!(fi = sc_profile_find_file(parser.profile, name))) {
		parse_error("unknown PIN file \"%s\"\n", name);
		return 1;
	}
	parser.cur_pin->file = fi;
	return 0;
}

static int
do_pin_offset(int argc, char **argv)
{
	return get_uint(argv[0], &parser.cur_pin->file_offset);
}

static int
do_pin_attempts(int argc, char **argv)
{
	struct pin_info	*pi = parser.cur_pin;
	int		i;

	memset(pi->attempt, 0, sizeof(pi->attempt));
	for (i = 0; i < argc; i++) {
		if (get_uint(argv[0], &pi->attempt[i]))
			return 1;
	}
	return 0;
}

static int
do_pin_type(int argc, char **argv)
{
	unsigned int	type;

	if (map_str2int(argv[0], &type, pintypenames))
		return 1;
	parser.cur_pin->pkcs15.type = type;
	return 0;
}

static int
do_pin_reference(int argc, char **argv)
{
	unsigned int	reference;

	if (get_uint(argv[0], &reference))
		return 1;
	parser.cur_pin->pkcs15.reference = reference;
	return 0;
}

static int
do_pin_authid(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &parser.cur_pin->pkcs15.auth_id);
	return 0;
}

static int
do_pin_label(int argc, char **argv)
{
	strcpy(parser.cur_pin->pkcs15.com_attr.label, argv[0]);
	return 0;
}

static int
do_prkey(int argc, char **argv)
{
	struct sc_profile	*pro = parser.profile;
	struct prkey_info	*ki, **tail;

	if ((ki = sc_profile_find_prkey(pro, argv[0])) != NULL)
		goto out;

	ki = calloc(1, sizeof(*ki));
	ki->ident = strdup(argv[0]);
	ki->type  = SC_PKCS15_TYPE_PRKEY_RSA;
	ki->pkcs15.access_flags = 0x1D;
	/* We initialize the modulus length at 1024 to make sure
	 * the PrKDF is big enough.
	 * This value will be overwritten later when the keys are
	 * loaded into the card. */
	ki->pkcs15.modulus_length = 1024;

	for (tail = &pro->prkey_list; *tail; tail = &(*tail)->next)
		;
	*tail = ki;

out:	parser.cur_prkey = ki;
	parser.section = PARSE_PRKEY;
	return 0;
}

static int
do_prkey_file(int argc, char **argv)
{
	struct file_info *fi;
	const char	*name = argv[0];

	if (!(fi = sc_profile_find_file(parser.profile, name))) {
		parse_error("unknown private key file \"%s\"\n", name);
		return 1;
	}
	parser.cur_prkey->file = fi;
	return 0;
}

static int
do_prkey_index(int argc, char **argv)
{
	return get_uint(argv[0], &parser.cur_prkey->index);
}

static int
do_prkey_algorithm(int argc, char **argv)
{
	return map_str2int(argv[0], &parser.cur_prkey->type, algorithmnames);
}

static int
do_prkey_label(int argc, char **argv)
{
	strcpy(parser.cur_prkey->pkcs15.com_attr.label, argv[0]);
	return 0;
}

static int
do_prkey_id(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &parser.cur_prkey->pkcs15.id);
	return 0;
}

static int
do_prkey_authid(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &parser.cur_prkey->pkcs15.com_attr.auth_id);
	return 0;
}

static int
do_prkey_usage(int argc, char **argv)
{
	struct sc_pkcs15_prkey_info *ki = &parser.cur_prkey->pkcs15;

	if (map_str2int(argv[0], &ki->usage, keyusagenames)) {
		parse_error("Bad key usage \"%s\"", argv[0]);
		return 1;
	}
	return 0;
}

static int
do_prkey_reference(int argc, char **argv)
{
	struct sc_pkcs15_prkey_info *ki = &parser.cur_prkey->pkcs15;

	return get_uint(argv[0], (unsigned int *) &ki->key_reference);
}

static struct command	commands[] = {
 { "CardInfo",		-1,		0,	0,	do_cardinfo	},
 { "Driver",		PARSE_CARDINFO,	1,	1,	do_card_driver	},
 { "MaxPinLength",	PARSE_CARDINFO,	1,	1,	do_maxpinlength	},
 { "MinPinLength",	PARSE_CARDINFO,	1,	1,	do_minpinlength	},
 { "Key",		PARSE_CARDINFO,	3,	3,	do_key		},
 { "Label",		PARSE_CARDINFO,	1,	1,	do_card_label	},
 { "Manufacturer",	PARSE_CARDINFO,	1,	1,	do_card_manufacturer},
 { "MF",		-1,		0,	0,	do_mf		},
 { "DF",		-1,		0,	0,	do_df		},
 { "EF",		-1,		1,	1,	do_ef		},
 { "Path",		PARSE_FILE,	1,	1,	do_path		},
 { "Structure",		PARSE_FILE,	1,	1,	do_structure	},
 { "Size",		PARSE_FILE,	1,	1,	do_size		},
 { "RecordLength",	PARSE_FILE,	1,	1,	do_reclength	},
 { "AID",		PARSE_FILE,	1,	1,	do_aid		},
 { "ACL",		PARSE_FILE,	1,	-1,	do_acl		},
 { "PIN",		-1,		1,	1,	do_pin		},
 { "File",		PARSE_PIN,	1,	1,	do_pin_file	},
 { "Offset",		PARSE_PIN,	1,	1,	do_pin_offset	},
 { "Attempts",		PARSE_PIN,	1,	2,	do_pin_attempts	},
 { "Type",		PARSE_PIN,	1,	1,	do_pin_type	},
 { "Reference",		PARSE_PIN,	1,	1,	do_pin_reference},
 { "AuthID",		PARSE_PIN,	1,	1,	do_pin_authid	},
 { "Label",		PARSE_PIN,	1,	1,	do_pin_label	},
 { "PrivateKey",	-1,		1,	1,	do_prkey	},
 { "Label",		PARSE_PRKEY,	1,	1,	do_prkey_label	},
 { "Algorithm",		PARSE_PRKEY,	1,	1,	do_prkey_algorithm},
 { "File",		PARSE_PRKEY,	1,	1,	do_prkey_file	},
 { "Index",		PARSE_PRKEY,	1,	1,	do_prkey_index	},
 { "ID",		PARSE_PRKEY,	1,	1,	do_prkey_id	},
 { "AuthID",		PARSE_PRKEY,	1,	1,	do_prkey_authid	},
 { "KeyUsage",		PARSE_PRKEY,	1,	1,	do_prkey_usage	},
 { "Reference",		PARSE_PRKEY,	1,	1,	do_prkey_reference },
#if 0
#endif

 { NULL }
};

static int
process(int argc, char **argv)
{
	struct command	*cp;
	int		badsection = 0;
	char		*cmd;

	cmd = *argv++; argc--;
	for (cp = commands; cp->name; cp++) {
		if (strcasecmp(cp->name, cmd))
			continue;
		if (cp->section >= 0 && cp->section != parser.section) {
			badsection++;
			continue;
		}
		if (argc < cp->min_args) {
			parse_error(
				"%s: not enough arguments\n",
				cmd);
			return 1;
		}
		if (0 <= cp->max_args && cp->max_args < argc) {
			parse_error(
				"%s: too many arguments\n",
				cmd);
			return 1;
		}
		return cp->func(argc, argv);
	}

	if (badsection) {
		parse_error(
			"command \"%s\" not allowed in this context\n",
			cmd);
	} else {
		parse_error("unknown command \"%s\"\n", cmd);
	}
	return 1;
}

struct file_info *
sc_profile_find_file(struct sc_profile *pro, const char *name)
{
	struct file_info	*fi;

	for (fi = pro->ef_list; fi; fi = fi->next) {
		if (!strcasecmp(fi->ident, name)) 
			return fi;
	}
	return NULL;
}

struct file_info *
sc_profile_file_info(struct sc_profile *pro, struct sc_file *file)
{
	struct file_info	*fi;

	for (fi = pro->ef_list; fi; fi = fi->next) {
		if (fi->file == file) 
			return fi;
	}
	return NULL;
}

struct pin_info *
sc_profile_find_pin(struct sc_profile *pro, const char *name)
{
	struct pin_info		*pi;

	for (pi = pro->pin_list; pi; pi = pi->next) {
		if (!strcasecmp(pi->ident, name))
			return pi;
	}
	return NULL;
}

struct auth_info *
sc_profile_find_key(struct sc_profile *pro,
	       unsigned int type, unsigned int reference)
{
	struct auth_info	*ai;

	for (ai = pro->auth_list; ai; ai = ai->next) {
		if (ai->type == type
		 && (reference == -1 || ai->ref == reference))
			return ai;
	}
	return NULL;
}

struct prkey_info *
sc_profile_find_prkey(struct sc_profile *pro, const char *ident)
{
	struct prkey_info	*ki;

	for (ki = pro->prkey_list; ki; ki = ki->next) {
		if (!strcasecmp(ki->ident, ident))
			return ki;
	}
	return NULL;
}

char *
next_word(char **cp)
{
	char	*p = *cp, *ret;

	while (isspace(*p))
		p++;

	if (*p == '\0' || *p == '#') {
		*cp = "";
		return NULL;
	}

	if (*p == '"') {
		ret = ++p;
		while (*p != '"') {
			/* Maybe we should flag a syntax error instead? */
			if (*p == '\0')
				goto out;
			if (p[0] == '\\' && p[1] != '\0')
				p++;
			p++;
		}
	} else {
		ret = p;
		while (*p && !isspace(*p) && *p != '#')
			p++;
	}
out:
	if (*p)
		*p++ = '\0';
	*cp = p;
	return ret;
}

/*
 * Split up KEY0 or CHV1 into SC_AC_XXX and a number
 */
static int
get_authid(const char *value, unsigned int *type, unsigned int *num)
{
	char	temp[16];
	int	n;

	if (isdigit(*value)) {
		*num = 0;
		return get_uint(value, type);
	}

	n = strcspn(value, "0123456789");
	strncpy(temp, value, n);
	temp[n] = '\0';

	if (map_str2int(temp, type, aclnames))
		return 1;
	if (value[n])
		return get_uint(value + n, num);
	*num = 0;
	return 0;
}

static int
get_uint(const char *value, unsigned int *vp)
{
	const char	*ep;

	*vp = strtoul(value, (char **) &ep, 0);
	if (*ep != '\0') {
		parse_error(
			"invalid integer argument \"%s\"\n", value);
		return 1;
	}
	return 0;
}

static int
map_str2int(const char *value, unsigned int *vp, struct map *map)
{
	if (isdigit(*value))
		return get_uint(value, vp);
	for (; map->name; map++) {
		if (!strcasecmp(value, map->name)) {
			*vp = map->val;
			return 0;
		}
	}
	parse_error("invalid argument \"%s\"\n", value);
	return 1;
}

static int
map_int2str(unsigned int value, const char **namep, struct map *map)
{
	for (; map->name; map++) {
		if (map->val == value) {
			*namep = map->name;
			return 0;
		}
	}
	parse_error("no name for value %u", value);
	*namep = NULL;
	return 1;
}

static int
setstr(char **strp, const char *value)
{
	if (*strp)
		free(*strp);
	*strp = strdup(value);
	return 0;
}

static void
parse_error(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s:%d: ", parser.filename, parser.lineno);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static int
add_object(struct sc_pkcs15_card *p15card, int df_type,
		int file_nr, unsigned int type,
		void *data, size_t datalen)
{
	struct sc_pkcs15_object *obj;

	obj = calloc(1, sizeof(*obj));
	obj->type = type;

	/* Note: we assume that objects allocated by sc_profile will
	 * be around as long as the profile is around, so there's
	 * no need to copy them here. What's more, this allows us
	 * to update an object (say, the modulus_length of a prkey
	 * object) and simply rewrite the file, without having to
	 * mess with this object list. */
#if 0
	obj->data = malloc(datalen);
	memcpy(obj->data, data, datalen);
#else
	obj->data = data;
#endif
	return sc_pkcs15_add_object(p15card, &p15card->df[df_type],
			file_nr, obj);
}
