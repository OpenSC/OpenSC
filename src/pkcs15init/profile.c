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
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "pkcs15-init.h"
#include "profile.h"

#define DEF_PRKEY_RSA_ACCESS	0x1D
#define DEF_PRKEY_DSA_ACCESS	0x12
#define DEF_PUBKEY_ACCESS	0x12

struct command {
	const char *		name;
	int			section;
	int			min_args, max_args;
	int			(*func)(int, char **);
};

enum {
       	PARSE_HEADER,
       	PARSE_FILE,
       	PARSE_CARDINFO,
       	PARSE_PIN,
       	PARSE_PRKEY,
	PARSE_PUBKEY,
	PARSE_CERT
};

static struct parser_info {
	const char *		filename;
	unsigned int		lineno;
	struct sc_profile *	profile;
	int			section;
}	parser;

static struct file_info *	cur_file;
static struct sc_file *		cur_parent;
static struct pin_info *	cur_pin;
static struct sc_key_template *	cur_key;
static struct sc_cert_template *cur_cert;

struct map {
	const char *		name;
	unsigned int		val;
};

static struct map		aclNames[] = {
	{ "NONE",	SC_AC_NONE	},
	{ "NEVER",	SC_AC_NEVER	},
	{ "CHV",	SC_AC_CHV	},
	{ "TERM",	SC_AC_TERM	},
	{ "PRO",	SC_AC_PRO	},
	{ "AUT",	SC_AC_AUT	},
	{ "KEY",	SC_AC_AUT	},
	{ 0, 0 }
};
static struct map		fileOpNames[] = {
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
	{ "CRYPTO",	SC_AC_OP_CRYPTO },
	{ 0, 0 }
};
static struct map		efTypeNames[] = {
	{ "TRANSPARENT",	SC_FILE_EF_TRANSPARENT	},
	{ "LINEAR-FIXED",	SC_FILE_EF_LINEAR_FIXED	},
	{ "LINEAR-FIXED-TLV",	SC_FILE_EF_LINEAR_FIXED_TLV	},
	{ "LINEAR-VARIABLE",	SC_FILE_EF_LINEAR_VARIABLE	},
	{ "LINEAR-VARIABLE-TLV",SC_FILE_EF_LINEAR_VARIABLE_TLV	},
	{ "CYCLIC",		SC_FILE_EF_CYCLIC	},
	{ "CYCLIC-TLV",		SC_FILE_EF_CYCLIC_TLV	},
	{ 0, 0 }
};
static struct map		pkcs15DfNames[] = {
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
static struct map		pinTypeNames[] = {
	{ "BCD",		0			},
	{ "ascii-numeric",	1			},
	{ "utf8",		2			},
	{ "half-nibble-bcd",	3			},
	{ "iso9564-1",		4			},
	{ 0, 0 }
};
static struct map		algorithmNames[] = {
	{ "RSA",		SC_PKCS15_TYPE_PRKEY_RSA },
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
	{ "DSA",		SC_PKCS15_TYPE_PRKEY_DSA },
#endif
	{ 0, 0 }
};
static struct map		keyUsageNames[] = {
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
static struct map		keyAccessFlags[] = {
	{ "SENSITIVE",		0x01	},
	{ "EXTRACTABLE",	0x02	},
	{ "ALWAYSSENSITIVE",	0x04	},
	{ "NEVEREXTRACTABLE",	0x08	},
	{ "LOCAL",		0x10	},
	{ 0, 0 }
};

static const char *sc_profile_locate(const char *);
static struct pin_info *get_pin(unsigned int);
static int	process(int, char **);
static char *	next_word(char **p);
static int	get_authid(const char *, unsigned int *, unsigned int *);
static int	get_uint(const char *, unsigned int *);
static int	map_str2int(const char *, unsigned int *, struct map *);
static int	setstr(char **strp, const char *value);
static void	parse_error(const char *, ...);

static struct file_info *	sc_profile_find_file(struct sc_profile *,
					const char *);
static struct file_info *	sc_profile_find_file_by_path(
					struct sc_profile *,
					const struct sc_path *);
static struct sc_key_template *	sc_profile_find_private_key(struct sc_profile *,
					const char *);
static struct sc_key_template *	sc_profile_find_public_key(struct sc_profile *,
					const char *);
static struct sc_cert_template *sc_profile_find_cert(struct sc_profile *,
					const char *);

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
	pro->df_info.ident = "PKCS15-AppDF";

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

	/* Assume card does RSA natively, but no DSA */
	pro->rsa_access_flags = DEF_PRKEY_RSA_ACCESS;
	pro->dsa_access_flags = DEF_PRKEY_DSA_ACCESS;
	pro->pin_encoding = 0x01;
	pro->pin_minlen = 4;
	pro->pin_maxlen = 8;
}

int
sc_profile_load(struct sc_profile *pro, const char *filename)
{
	char	buffer[1024];
	int	res = 0;
	FILE	*fp;

	if (!(filename = sc_profile_locate(filename)))
		return SC_ERROR_FILE_NOT_FOUND;
	if ((fp = fopen(filename, "r")) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;

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

static const char *
sc_profile_locate(const char *name)
{
	static char	path[1024];

	/* Unchanged name? */
	if (access(name, R_OK) == 0)
		return name;

	/* Name with suffix tagged onto it? */
	snprintf(path, sizeof(path), "%s.%s", name, SC_PKCS15_PROFILE_SUFFIX);
	if (access(path, R_OK) == 0)
		return path;

	/* If it's got slashes, don't mess with it any further */
	if (strchr(path, '/'))
		return path;

	/* Try directory */
	snprintf(path, sizeof(path), "%s/%s",
			SC_PKCS15_PROFILE_DIRECTORY, name);
	if (access(path, R_OK) == 0)
		return path;

	snprintf(path, sizeof(path), "%s/%s.%s",
			SC_PKCS15_PROFILE_DIRECTORY, name,
			SC_PKCS15_PROFILE_SUFFIX);
	if (access(path, R_OK) == 0)
		return path;

	return NULL;
}

void
sc_profile_set_pin_info(struct sc_profile *profile,
		unsigned int id, const struct sc_pkcs15_pin_info *info)
{
	struct pin_info	*pi;

	pi = get_pin(id);
	pi->pin = *info;
}

void
sc_profile_get_pin_info(struct sc_profile *profile,
		unsigned int id, struct sc_pkcs15_pin_info *info)
{
	struct pin_info	*pi;

	pi = get_pin(id);
	*info = pi->pin;
}

int
sc_profile_get_pin_id(struct sc_profile *profile,
		unsigned int reference, unsigned int *id)
{
	struct pin_info	*pi;

	for (pi = profile->pin_list; pi; pi = pi->next) {
		if (pi->pin.reference == reference) {
			*id = pi->id;
			return 0;
		}

	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}

int
sc_profile_get_file(struct sc_profile *profile,
		const char *name, struct sc_file **ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file(profile, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	sc_file_dup(ret, fi->file);
	return 0;
}

int
sc_profile_get_path(struct sc_profile *profile,
		const char *name, struct sc_path *ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file(profile, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	*ret = fi->file->path;
	return 0;
}

int
sc_profile_get_file_by_path(struct sc_profile *profile,
		const struct sc_path *path, struct sc_file **ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file_by_path(profile, path)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	sc_file_dup(ret, fi->file);
	return 0;
}

static int
do_cardinfo(int argc, char **argv)
{
	parser.section = PARSE_CARDINFO;
	cur_file = NULL;
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
	unsigned int	type, id;
	size_t		key_len;
	const char	*key = argv[1];
	unsigned char	keybuf[32];

	if (get_authid(argv[0], &type, &id))
		return 1;

	if (key[0] == '=') {
		++key;
		key_len = strlen(key);
		memcpy(keybuf, key, key_len);
	} else {
		key_len = sizeof(keybuf);
		if (sc_hex_to_bin(key, keybuf, &key_len)) {
			parse_error("Error parsing PIN/key \"%s\"\n", key);
			return 1;
		}
	}
	
	sc_profile_set_secret(parser.profile, type, id, keybuf, key_len);
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
do_default_pin_type(int argc, char **argv)
{
	return map_str2int(argv[0],
		       	&parser.profile->pin_encoding, pinTypeNames);
}

static int
do_pin_pad_char(int argc, char **argv)
{
	return get_uint(argv[0], &parser.profile->pin_pad_char);
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
do_default_access_flags(int argc, char **argv)
{
	unsigned int	*flags, access;

	if (!strcasecmp(argv[0], "RSA")) {
		flags = &parser.profile->rsa_access_flags;
	} else
	if (!strcasecmp(argv[0], "DSA")) {
		flags = &parser.profile->dsa_access_flags;
	} else {
		parse_error("Unknown algorithm \"%s\"", argv[0]);
		return 1;
	}
	argc--, argv++;
	*flags = 0;
	while (argc--) {
		if (map_str2int(argv[0], &access, keyAccessFlags))
			return 1;
		*flags |= access;
	}
	return 0;
}

static int
do_mf(int argc, char **argv)
{
	parser.section = PARSE_FILE;
	cur_file = &parser.profile->mf_info;
	cur_file->ident = strdup("MF");
	cur_parent = NULL;
	return 0;
}

static void
find_parent(struct file_info *fi)
{
	struct sc_path path = fi->file->path;
	
	fi->parent = NULL;
	if (path.len > 2) {
		path.len -= 2;
		fi->parent = sc_profile_find_file_by_path(parser.profile, &path);
	}
}

static int
do_df(int argc, char **argv)
{
	const char	*ident;

	parser.section = PARSE_FILE;
	ident = argc? argv[0] : "PKCS15-AppDF";
	if (!strcasecmp(ident, "PKCS15-AppDF")) {
		cur_file = &parser.profile->df_info;
	} else {
		cur_file = (struct file_info *) calloc(1, sizeof(*cur_file));
		cur_file->ident = strdup(ident);
		cur_file->file = init_file(SC_FILE_TYPE_DF);

		cur_file->next = parser.profile->ef_list;
		parser.profile->ef_list = cur_file;
	}
	find_parent(cur_file);
	cur_parent = NULL;
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
		file = init_file(SC_FILE_TYPE_WORKING_EF);
	} else {
		if (map_str2int(name+7, &df_type, pkcs15DfNames))
			return 1;

		file = init_file(SC_FILE_TYPE_WORKING_EF);
		pro->df[df_type] = file;
	}
	assert(file);

	file->type = SC_FILE_TYPE_WORKING_EF;
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	file->status = SC_FILE_STATUS_ACTIVATED;
	info->file = file;

	info->next = parser.profile->ef_list;
	parser.profile->ef_list = info;
	find_parent(info);

out:	cur_file = info;
	cur_parent = NULL;
	return 0;
}

static int
do_path(int argc, char **argv)
{
	struct sc_file	*file = cur_file->file;
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
do_parent(int argc, char **argv)
{
	struct sc_profile *profile = parser.profile;
	struct file_info *info;
	struct sc_file	*df;
	const char	*name;

	name = argv[0];
	if (!strcasecmp(name, "PKCS15-AppDF")) {
		df = profile->df_info.file;
	} else {
		if ((info = sc_profile_find_file(profile, name)) == NULL) {
			parse_error("Unknown parent DF \"%s\"\n", name);
			return 1;
		}
		df = info->file;
	}
	if (df->type != SC_FILE_TYPE_DF) {
		parse_error("File \"%s\" is not a DF\n", name);
		return 1;
	}
	cur_parent = df;
	return 0;
}

static int
do_fileid(int argc, char **argv)
{
	struct sc_file	*df, *file = cur_file->file;
	struct sc_path	temp, *path = &file->path;

	/* sc_format_path doesn't return an error indication
	 * when it's unable to parse the path */
	sc_format_path(argv[0], &temp);
	if (temp.len != 2) {
		parse_error("Invalid file ID length\n");
		return 1;
	}

	/* Get the DF. Must be specified using the "Parent" keyword. */
	if ((df = cur_parent) == NULL) {
		parse_error("Profile uses FileID, but didn't specify Parent\n");
		return 1;
	}
	if (df->path.len == 0) {
		parse_error("No path set for Parent DF\n");
		return 1;
	}
	if (df->path.len + 2 > sizeof(df->path)) {
		parse_error("File path too long\n");
		return 1;
	}
	*path = df->path;
	memcpy(path->value + path->len, temp.value, 2);
	path->len += 2;

	file->id = (path->value[path->len-2] << 8)
		 | path->value[path->len-1];
	return 0;
}

static int
do_structure(int argc, char **argv)
{
	unsigned int	ef_structure;

	if (map_str2int(argv[0], &ef_structure, efTypeNames))
		return 1;
	cur_file->file->ef_structure = ef_structure;
	return 0;
}

static int
do_size(int argc, char **argv)
{
	unsigned int	size;

	if (get_uint(argv[0], &size))
		return 1;
	cur_file->file->size = size;
	return 0;
}

static int
do_reclength(int argc, char **argv)
{
	unsigned int	reclength;

	if (get_uint(argv[0], &reclength))
		return 1;
	cur_file->file->record_length = reclength;
	return 0;
}

static int
do_aid(int argc, char **argv)
{
	struct sc_file	*file = cur_file->file;
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
	struct sc_file	*file = cur_file->file;
	char		*oper = 0, *what = 0;

	while (argc--) {
		unsigned int	op, method, id;

		oper = *argv++;
		if ((what = strchr(oper, '=')) == NULL)
			goto bad;
		*what++ = '\0';

		if (!strcasecmp(what, "$sopin")) {
			method = SC_AC_SYMBOLIC;
			id = SC_PKCS15INIT_SO_PIN;
		} else
		if (!strcasecmp(what, "$pin")) {
			method = SC_AC_SYMBOLIC;
			id = SC_PKCS15INIT_USER_PIN;
		} else
		if (get_authid(what, &method, &id))
			goto bad;

		if (!strcmp(oper, "*")) {
			for (op = 0; op < SC_MAX_AC_OPS; op++) {
				sc_file_clear_acl_entries(file, op);
				sc_file_add_acl_entry(file, op, method, id);
			}
		} else {
			const struct sc_acl_entry *acl;

			if (map_str2int(oper, &op, fileOpNames))
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
	const char	*ident = argv[0];
	unsigned int	id;

	if (!strcasecmp(ident, "sopin")) {
		id = SC_PKCS15INIT_SO_PIN;
	} else if (!strcasecmp(ident, "pin")) {
		id = SC_PKCS15INIT_USER_PIN;
	} else {
		parse_error("Invalid PIN \"%s\"", ident);
		return 1;
	}

	parser.section = PARSE_PIN;
	cur_pin = get_pin(id);
	return 1;
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
	cur_pin->file = fi;
	return 0;
}

static int
do_pin_offset(int argc, char **argv)
{
	return get_uint(argv[0], &cur_pin->file_offset);
}

static int
do_pin_attempts(int argc, char **argv)
{
	struct pin_info	*pi = cur_pin;

	if (get_uint(argv[0], (unsigned int *) &pi->pin.tries_left))
		return 1;
	/*
	pi->puk.tries_left = 0;
	if (argc == 2 && get_uint(argv[1], &pi->puk.tries_left))
		return 1;
	 */
	return 0;
}

static int
do_pin_type(int argc, char **argv)
{
	unsigned int	type;

	if (map_str2int(argv[0], &type, pinTypeNames))
		return 1;
	cur_pin->pin.type = type;
	return 0;
}

static int
do_pin_reference(int argc, char **argv)
{
	unsigned int	reference;

	if (get_uint(argv[0], &reference))
		return 1;
	cur_pin->pin.reference = reference;
	return 0;
}

static int
do_pin_authid(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_pin->pin.auth_id);
	return 0;
}

static int
do_pin_label(int argc, char **argv)
{
	//strcpy(cur_pin->pkcs15_obj.label, argv[0]);
	return 0;
}

static int
do_prkey(int argc, char **argv)
{
	struct sc_profile	*pro = parser.profile;
	struct sc_key_template	*ki, **tail;

	if ((ki = sc_profile_find_private_key(pro, argv[0])) != NULL)
		goto out;

	ki = calloc(1, sizeof(*ki));
	ki->ident = strdup(argv[0]);

	/* We initialize the modulus length at 1024 to make sure
	 * the PrKDF is big enough.
	 * This value will be overwritten later when the keys are
	 * loaded into the card. */
	ki->pkcs15.priv.modulus_length = 1024;
	ki->pkcs15.priv.access_flags = pro->rsa_access_flags;

	ki->pkcs15_obj.type = SC_PKCS15_TYPE_PRKEY_RSA;
	ki->pkcs15_obj.data = &ki->pkcs15;

	for (tail = &pro->prkey_list; *tail; tail = &(*tail)->next)
		;
	*tail = ki;

out:	parser.section = PARSE_PRKEY;
	cur_key = ki;
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
	cur_key->file = fi->file;
	return 0;
}

static int
do_prkey_index(int argc, char **argv)
{
	return get_uint(argv[0], &cur_key->index);
}

static int
do_prkey_algorithm(int argc, char **argv)
{
	struct sc_key_template	*ki = cur_key;

	if (map_str2int(argv[0], (unsigned int *) &ki->pkcs15_obj.type, algorithmNames))
		return 1;
	switch (ki->pkcs15_obj.type) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		ki->pkcs15.priv.access_flags = parser.profile->rsa_access_flags;
		break;
#ifdef SC_PKCS15_TYPE_PRKEY_DSA
	case SC_PKCS15_TYPE_PRKEY_DSA:
		ki->pkcs15.priv.access_flags = parser.profile->dsa_access_flags;
		break;
#endif
	}
	return 0;
}

static int
do_prkey_label(int argc, char **argv)
{
	strcpy(cur_key->pkcs15_obj.label, argv[0]);
	return 0;
}

static int
do_prkey_id(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_key->pkcs15.priv.id);
	return 0;
}

static int
do_prkey_authid(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_key->pkcs15_obj.auth_id);
	return 0;
}

static int
do_prkey_usage(int argc, char **argv)
{
	struct sc_pkcs15_prkey_info *ki = &cur_key->pkcs15.priv;

	if (map_str2int(argv[0], &ki->usage, keyUsageNames)) {
		parse_error("Bad key usage \"%s\"", argv[0]);
		return 1;
	}
	return 0;
}

static int
do_prkey_access_flags(int argc, char **argv)
{
	struct sc_pkcs15_prkey_info *ki = &cur_key->pkcs15.priv;
	unsigned int	access;

	ki->access_flags = 0;
	while (argc--) {
		if (map_str2int(argv[0], &access, keyAccessFlags))
			return 1;
		ki->access_flags |= access;
	}
	return 0;
}

static int
do_prkey_reference(int argc, char **argv)
{
	struct sc_pkcs15_prkey_info *ki = &cur_key->pkcs15.priv;

	return get_uint(argv[0], (unsigned int *) &ki->key_reference);
}

static int
do_pubkey(int argc, char **argv)
{
	struct sc_profile	*pro = parser.profile;
	struct sc_key_template	*ki, **tail;

	if ((ki = sc_profile_find_public_key(pro, argv[0])) != NULL)
		goto out;

	ki = calloc(1, sizeof(*ki));
	ki->ident = strdup(argv[0]);

	/* We initialize the modulus length at 1024 to make sure
	 * the PrKDF is big enough.
	 * This value will be overwritten later when the keys are
	 * loaded into the card. */
	ki->pkcs15.pub.modulus_length = 1024;
	ki->pkcs15.pub.access_flags = DEF_PUBKEY_ACCESS;

	ki->pkcs15_obj.type = SC_PKCS15_TYPE_PUBKEY_RSA;
	ki->pkcs15_obj.data = &ki->pkcs15;

	for (tail = &pro->pubkey_list; *tail; tail = &(*tail)->next)
		;
	*tail = ki;

out:	cur_key = ki;
	parser.section = PARSE_PUBKEY;
	return 0;
}

static int
do_pubkey_file(int argc, char **argv)
{
	struct file_info *fi;
	const char	*name = argv[0];

	if (!(fi = sc_profile_find_file(parser.profile, name))) {
		parse_error("unknown private key file \"%s\"\n", name);
		return 1;
	}
	cur_key->file = fi->file;
	return 0;
}

static int
do_pubkey_index(int argc, char **argv)
{
	return get_uint(argv[0], &cur_key->index);
}

static int
do_pubkey_algorithm(int argc, char **argv)
{
	struct sc_key_template	*ki = cur_key;

	if (map_str2int(argv[0], (unsigned int *) &ki->pkcs15_obj.type, algorithmNames))
		return 1;
	ki->pkcs15.pub.access_flags = DEF_PUBKEY_ACCESS;
	return 0;
}

static int
do_pubkey_label(int argc, char **argv)
{
	strcpy(cur_key->pkcs15_obj.label, argv[0]);
	return 0;
}

static int
do_pubkey_id(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_key->pkcs15.pub.id);
	return 0;
}

static int
do_pubkey_authid(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_key->pkcs15_obj.auth_id);
	return 0;
}

static int
do_pubkey_usage(int argc, char **argv)
{
	struct sc_pkcs15_pubkey_info *ki = &cur_key->pkcs15.pub;

	if (map_str2int(argv[0], &ki->usage, keyUsageNames)) {
		parse_error("Bad key usage \"%s\"", argv[0]);
		return 1;
	}
	return 0;
}

static int
do_pubkey_access_flags(int argc, char **argv)
{
	struct sc_pkcs15_pubkey_info *ki = &cur_key->pkcs15.pub;
	unsigned int	access;

	ki->access_flags = 0;
	while (argc--) {
		if (map_str2int(argv[0], &access, keyAccessFlags))
			return 1;
		ki->access_flags |= access;
	}
	return 0;
}

static int
do_pubkey_reference(int argc, char **argv)
{
	struct sc_pkcs15_pubkey_info *ki = &cur_key->pkcs15.pub;

	return get_uint(argv[0], (unsigned int *) &ki->key_reference);
}

static int
do_cert(int argc, char **argv)
{
	struct sc_profile	*pro = parser.profile;
	struct sc_cert_template	*ci, **tail;

	if ((ci = sc_profile_find_cert(pro, argv[0])) != NULL)
		goto out;

	ci = calloc(1, sizeof(*ci));
	ci->ident = strdup(argv[0]);

	ci->pkcs15_obj.type = SC_PKCS15_TYPE_CERT_X509;
	ci->pkcs15_obj.data = &ci->pkcs15;

	for (tail = &pro->cert_list; *tail; tail = &(*tail)->next)
		;
	*tail = ci;

out:	parser.section = PARSE_CERT;
	cur_cert = ci;
	return 0;
}

static int
do_cert_file(int argc, char **argv)
{
	struct file_info *fi;
	const char	*name = argv[0];

	if (!(fi = sc_profile_find_file(parser.profile, name))) {
		parse_error("unknown certificate file \"%s\"\n", name);
		return 1;
	}
	cur_cert->file = fi->file;
	return 0;
}

static int
do_cert_label(int argc, char **argv)
{
	strcpy(cur_cert->pkcs15_obj.label, argv[0]);
	return 0;
}

static int
do_cert_id(int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur_cert->pkcs15.id);
	return 0;
}

static struct command	commands[] = {
 { "CardInfo",		-1,		0,	0,	do_cardinfo	},
 { "Driver",		PARSE_CARDINFO,	1,	1,	do_card_driver	},
 { "MaxPinLength",	PARSE_CARDINFO,	1,	1,	do_maxpinlength	},
 { "MinPinLength",	PARSE_CARDINFO,	1,	1,	do_minpinlength	},
 { "PinEncoding",	PARSE_CARDINFO,	1,	1,	do_default_pin_type },
 { "PinPadChar",	PARSE_CARDINFO, 1,	1,	do_pin_pad_char },
 { "Key",		PARSE_CARDINFO,	2,	2,	do_key		},
 { "Label",		PARSE_CARDINFO,	1,	1,	do_card_label	},
 { "Manufacturer",	PARSE_CARDINFO,	1,	1,	do_card_manufacturer},
 { "PrKeyAccessFlags",	PARSE_CARDINFO,	2,	-1,	do_default_access_flags },
 { "MF",		-1,		0,	0,	do_mf		},
 { "DF",		-1,		0,	1,	do_df		},
 { "EF",		-1,		1,	1,	do_ef		},
 { "Path",		PARSE_FILE,	1,	1,	do_path		},
 { "Parent",		PARSE_FILE,	1,	1,	do_parent	},
 { "FileID",		PARSE_FILE,	1,	1,	do_fileid	},
 { "Structure",		PARSE_FILE,	1,	1,	do_structure	},
 { "Size",		PARSE_FILE,	1,	1,	do_size		},
 { "RecordLength",	PARSE_FILE,	1,	1,	do_reclength	},
 { "AID",		PARSE_FILE,	1,	1,	do_aid		},
 { "ACL",		PARSE_FILE,	1,	-1,	do_acl		},
 { "PIN",		-1,		1,	1,	do_pin		},
 { "File",		PARSE_PIN,	1,	1,	do_pin_file	},
 { "Offset",		PARSE_PIN,	1,	1,	do_pin_offset	},
 { "Attempts",		PARSE_PIN,	1,	2,	do_pin_attempts	},
 { "Encoding",		PARSE_PIN,	1,	1,	do_pin_type	},
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
 { "AccessFlags",	PARSE_PRKEY,	1,	-1,	do_prkey_access_flags },
 { "Reference",		PARSE_PRKEY,	1,	1,	do_prkey_reference },
 { "PublicKey",		-1,		1,	1,	do_pubkey	},
 { "Label",		PARSE_PUBKEY,	1,	1,	do_pubkey_label	},
 { "Algorithm",		PARSE_PUBKEY,	1,	1,	do_pubkey_algorithm},
 { "File",		PARSE_PUBKEY,	1,	1,	do_pubkey_file	},
 { "Index",		PARSE_PUBKEY,	1,	1,	do_pubkey_index	},
 { "ID",		PARSE_PUBKEY,	1,	1,	do_pubkey_id	},
 { "AuthID",		PARSE_PUBKEY,	1,	1,	do_pubkey_authid },
 { "KeyUsage",		PARSE_PUBKEY,	1,	1,	do_pubkey_usage	},
 { "AccessFlags",	PARSE_PUBKEY,	1,	-1,	do_pubkey_access_flags },
 { "Reference",		PARSE_PUBKEY,	1,	1,	do_pubkey_reference },
 { "Certificate",	-1,		1,	1,	do_cert		},
 { "Label",		PARSE_CERT,	1,	1,	do_cert_label	},
 { "File",		PARSE_CERT,	1,	1,	do_cert_file	},
 { "ID",		PARSE_CERT,	1,	1,	do_cert_id	},
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

static struct file_info *
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
sc_profile_find_file_by_path(struct sc_profile *pro, const struct sc_path *path)
{
	struct file_info *fi;
	struct sc_file	*fp;

	for (fi = pro->ef_list; fi; fi = fi->next) {
		fp = fi->file;
		if (fp->path.len == path->len
		 && !memcmp(fp->path.value, path->value, path->len))
			return fi;
	}
	return NULL;
}

void
sc_profile_set_secret(struct sc_profile *profile,
		unsigned int type, unsigned int ref,
		const u8 *key, size_t key_len)
{
	struct auth_info *ai, **aip;

	for (aip = &profile->auth_list; (ai = *aip); aip = &ai->next) {
		if (ai->type == type && ai->ref == ref)
			goto found;
	}

	ai = (struct auth_info *) calloc(1, sizeof(*ai));
	*aip = ai;
	ai->type = type;
	ai->ref = ref;

found:	if (key_len)
		memcpy(ai->key, key, key_len);
	ai->key_len = key_len;
}

int
sc_profile_get_secret(struct sc_profile *profile,
		unsigned int type, unsigned int ref,
		u8 *key, size_t *len)
{
	struct auth_info *ai, **aip;

	for (aip = &profile->auth_list; (ai = *aip); aip = &ai->next) {
		if (ai->type == type && ai->ref == ref) {
			if (ai->key_len > *len)
				return SC_ERROR_BUFFER_TOO_SMALL;
			memcpy(key, ai->key, ai->key_len);
			*len = ai->key_len;
			return 0;
		}
	}

	return SC_ERROR_OBJECT_NOT_FOUND;
}

void
sc_profile_set_so_pin(struct sc_profile *profile, const char *value)
{
	if (!value)
		return;
	sc_profile_set_secret(profile, SC_AC_SYMBOLIC,
			SC_PKCS15INIT_SO_PIN, (u8 *) value, strlen(value));
}

void
sc_profile_set_user_pin(struct sc_profile *profile, const char *value)
{
	if (!value)
		return;
	sc_profile_set_secret(profile, SC_AC_SYMBOLIC,
			SC_PKCS15INIT_USER_PIN, (u8 *) value, strlen(value));
}

struct sc_key_template *
sc_profile_find_private_key(struct sc_profile *pro, const char *ident)
{
	struct sc_key_template	*ki;

	for (ki = pro->prkey_list; ki; ki = ki->next) {
		if (!strcasecmp(ki->ident, ident))
			return ki;
	}
	return NULL;
}

struct sc_key_template *
sc_profile_find_public_key(struct sc_profile *pro, const char *ident)
{
	struct sc_key_template	*ki;

	for (ki = pro->pubkey_list; ki; ki = ki->next) {
		if (!strcasecmp(ki->ident, ident))
			return ki;
	}
	return NULL;
}

struct sc_cert_template *
sc_profile_find_cert(struct sc_profile *profile, const char *ident)
{
	struct sc_cert_template *ci;

	for (ci = profile->cert_list; ci; ci = ci->next) {
		if (!strcasecmp(ci->ident, ident))
			return ci;
	}
	return NULL;
}

static struct pin_info *
get_pin(unsigned int id)
{
	struct sc_profile *pro = parser.profile;
	struct pin_info	*pi, **tail;

	for (tail = &pro->pin_list; (pi = *tail); tail = &pi->next) {
		if (pi->id == id)
			return pi;
	}

	pi = (struct pin_info *) calloc(1, sizeof(*pi));
	pi->id = id;
	pi->pin.type = pro->pin_encoding;
	pi->pin.flags = 0x32;
	pi->pin.min_length = pro->pin_minlen;
	pi->pin.stored_length = pro->pin_maxlen;
	pi->pin.pad_char = pro->pin_pad_char;
	pi->pin.magic = SC_PKCS15_PIN_MAGIC;
	pi->pin.reference = -1;
	pi->pin.tries_left = 2;
//	pi->puk = pi->pin;

	*tail = pi;
	return pi;
}

char *
next_word(char **cp)
{
	char	*p = *cp, *ret;

	while (isspace((int) *p))
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
		while (*p && !isspace((int) *p) && *p != '#')
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

	if (isdigit((int) *value)) {
		*num = 0;
		return get_uint(value, type);
	}

	n = strcspn(value, "0123456789");
	strncpy(temp, value, n);
	temp[n] = '\0';

	if (map_str2int(temp, type, aclNames))
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
	if (isdigit((int) *value))
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
	char	buffer[1024];
	va_list	ap;

	va_start(ap, fmt);
	snprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (parser.profile->cbs)
		parser.profile->cbs->error("%s:%d: %s\n",
			parser.filename, parser.lineno, buffer);
}
