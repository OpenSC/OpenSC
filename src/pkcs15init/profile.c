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
#include <limits.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <opensc/scconf.h>
#include "pkcs15-init.h"
#include "profile.h"

#define DEF_PRKEY_RSA_ACCESS	0x1D
#define DEF_PRKEY_DSA_ACCESS	0x12
#define DEF_PUBKEY_ACCESS	0x12

/*
 * Parser state
 */
struct state {
	struct state *		frame;
	const char *		filename;
	struct sc_profile *	profile;
	struct file_info *	file;
	struct pin_info *	pin;
	struct auth_info *	key;
};


struct command {
	const char *		name;
	int			min_args, max_args;
	int			(*func)(struct state *, int, char **);
};

struct block {
	const char *		name;
	int			(*handler)(struct state *,
					struct block *,
					const char *,
					scconf_block *);
	struct command *	cmd_info;
	struct block *		blk_info;
};

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
static struct map		fileTypeNames[] = {
	{ "EF",		SC_FILE_TYPE_WORKING_EF		},
	{ "INTERNAL-EF",SC_FILE_TYPE_INTERNAL_EF	},
	{ "DF",		SC_FILE_TYPE_DF			},
	{ 0, 0 }
};
static struct map		fileStructureNames[] = {
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
static struct map		pinIdNames[] = {
	{ "pin",		SC_PKCS15INIT_USER_PIN	},
	{ "puk",		SC_PKCS15INIT_USER_PUK	},
	{ "user-pin",		SC_PKCS15INIT_USER_PIN	},
	{ "user-puk",		SC_PKCS15INIT_USER_PUK	},
	{ "sopin",		SC_PKCS15INIT_SO_PIN	},
	{ "sopuk",		SC_PKCS15INIT_SO_PUK	},
	{ "so-pin",		SC_PKCS15INIT_SO_PIN	},
	{ "so-puk",		SC_PKCS15INIT_SO_PUK	},
	{ 0, 0 }
};
static struct map		pinFlagNames[] = {
	{ "case-sensitive",		0x0001			},
	{ "local",			0x0002			},
	{ "change-disabled",		0x0004			},
	{ "unblock-disabled",		0x0008			},
	{ "initialized",		0x0010			},
	{ "needs-padding",		0x0020			},
	{ "unblockingPin",		0x0040			},
	{ "soPin",			0x0080			},
	{ "disable-allowed",		0x0100			},
	{ "integrity-protected",	0x0200			},
	{ "confidentiality-protected",	0x0400			},
	{ "exchangeRefData",		0x0800			},
	{ 0, 0 }
};
static struct {
	const char *		name;
	struct map *		addr;
} mapNames[] = {
	{ "file ACL",		aclNames	},
	{ "file operation",	fileOpNames	},
	{ "file type",		fileTypeNames	},
	{ "file structure",	fileStructureNames},
	{ "PKCS#15 file name",	pkcs15DfNames	},
	{ "pin encoding",	pinTypeNames	},
	{ "pin name",		pinIdNames	},
	{ "pin flag",		pinFlagNames	},
	{ NULL, NULL }
};

typedef struct pin_info pin_info;
typedef struct file_info file_info;
typedef struct auth_info auth_info;

static const char *	sc_profile_locate(const char *);
static int		process_conf(struct sc_profile *, scconf_context *);
static int		process_block(struct state *, struct block *,
				const char *, scconf_block *);
static void		init_state(struct state *, struct state *);
static int		get_authid(struct state *, const char *,
				unsigned int *, unsigned int *);
static int		get_uint(struct state *, const char *, unsigned int *);
static int		map_str2int(struct state *, const char *,
				unsigned int *, struct map *);
static int		setstr(char **strp, const char *value);
static void		parse_error(struct state *, const char *, ...);

static file_info *	sc_profile_find_file(struct sc_profile *,
				const char *);
static file_info *	sc_profile_find_file_by_path(
				struct sc_profile *,
				const struct sc_path *);

static pin_info *	new_pin(struct sc_profile *, unsigned int);
static file_info *	new_file(struct state *, const char *,
				unsigned int);
static auth_info *	new_key(struct sc_profile *,
				unsigned int, unsigned int);
static void		set_pin_defaults(struct sc_profile *,
				struct pin_info *);

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
	file->ef_structure = SC_FILE_EF_TRANSPARENT;
	return file;
}

/*
 * Initialize profile
 */
struct sc_profile *
sc_profile_new()
{
	struct sc_pkcs15_card *p15card;
	struct sc_profile *pro;

	pro = (struct sc_profile *) calloc(1, sizeof(*pro));
	pro->p15_card = p15card = sc_pkcs15_card_new();

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

	return pro;
}

int
sc_profile_load(struct sc_profile *profile, const char *filename)
{
	scconf_context	*conf;
	int		res = 0;

	if (!(filename = sc_profile_locate(filename)))
		return SC_ERROR_FILE_NOT_FOUND;
	conf = scconf_new(filename);
	res = scconf_parse(conf);
	if (res < 0)
		return SC_ERROR_FILE_NOT_FOUND;
	if (res == 0)
		return SC_ERROR_SYNTAX_ERROR;

	res = process_conf(profile, conf);
	scconf_free(conf);
	return res;
}

int
sc_profile_finish(struct sc_profile *profile)
{
	struct file_info *fi;
	struct pin_info	*pi;
	const char	*reason, *name;

	reason = "Profile doesn't define a MF";
	if (!(profile->mf_info = sc_profile_find_file(profile, "MF")))
		goto whine;
	reason = "Profile doesn't define a PKCS15-AppDF";
	if (!(profile->df_info = sc_profile_find_file(profile, "PKCS15-AppDF")))
		goto whine;
	profile->p15_card->file_app = profile->df_info->file;
	profile->df_info->dont_free = 1;

	for (pi = profile->pin_list; pi; pi = pi->next) {
		set_pin_defaults(profile, pi);
		if (!(name = pi->file_name))
			continue;
		if (!(fi = sc_profile_find_file(profile, name))) {
			if (profile->cbs)
				profile->cbs->error(
					"unknown PIN file \"%s\"\n", name);
			return SC_ERROR_INCONSISTENT_PROFILE;
		}
		pi->file = fi;
	}
	return 0;

whine:	if (profile->cbs)
		profile->cbs->error("%s\n", reason);
	return SC_ERROR_INCONSISTENT_PROFILE;
}

void
sc_profile_free(struct sc_profile *profile)
{
	struct file_info *fi;
	struct auth_info *ai;
	struct pin_info *pi;

	while ((fi = profile->ef_list) != NULL) {
		profile->ef_list = fi->next;
		if (fi->dont_free == 0)
			sc_file_free(fi->file);
		free(fi->ident);
		free(fi);
	}

	while ((ai = profile->auth_list) != NULL) {
		profile->auth_list = ai->next;
		free(ai);
	}

	while ((pi = profile->pin_list) != NULL) {
		if (pi->file_name)
			free(pi->file_name);
		profile->pin_list = pi->next;
		free(pi);
	}

	if (profile->p15_card)
		sc_pkcs15_card_free(profile->p15_card);
	memset(profile, 0, sizeof(*profile));
	free(profile);
}

static const char *
sc_profile_locate(const char *name)
{
	static char	path[1024];
	char            profile_dir[PATH_MAX];

	/* append ".profile" unless already in the name */
	if (strstr(name, SC_PKCS15_PROFILE_SUFFIX)) {
		snprintf(path, sizeof(path), "%s", name);
	} else {
		snprintf(path, sizeof(path), "%s.%s", name,
				SC_PKCS15_PROFILE_SUFFIX);
	}
		
	/* Unchanged name? */
	if (access(path, R_OK) == 0)
		return path;

	/* If it's got slashes, don't mess with it any further */
	if (strchr(path, '/'))
		return path;

#ifndef _WIN32
	strncpy(profile_dir, SC_PKCS15_PROFILE_DIRECTORY, sizeof(profile_dir));
#else
	if (!strncmp(SC_PKCS15_PROFILE_DIRECTORY, "%windir%", 8)) {
		GetWindowsDirectory(profile_dir, sizeof(profile_dir));
		strncat(profile_dir, SC_PKCS15_PROFILE_DIRECTORY + 8,
			sizeof(profile_dir) - strlen(profile_dir));
	}
	else
		strncpy(profile_dir, SC_PKCS15_PROFILE_DIRECTORY, sizeof(profile_dir));
#endif

	/* Try directory */
	/* append ".profile" unless already in the name */
	if (strstr(name, SC_PKCS15_PROFILE_SUFFIX)) {
		snprintf(path, sizeof(path), "%s/%s",
			profile_dir, name);
	} else {
		snprintf(path, sizeof(path), "%s/%s.%s",
			profile_dir, name,
			SC_PKCS15_PROFILE_SUFFIX);
	}
	if (access(path, R_OK) == 0)
		return path;

	/* Unchanged name? */
	if (access(name, R_OK) == 0)
		return name;

	return NULL;
}

void
sc_profile_set_pin_info(struct sc_profile *profile,
		unsigned int id, const struct sc_pkcs15_pin_info *info)
{
	struct pin_info	*pi;

	pi = new_pin(profile, id);
	pi->pin = *info;
}

void
sc_profile_get_pin_info(struct sc_profile *profile,
		unsigned int id, struct sc_pkcs15_pin_info *info)
{
	struct pin_info	*pi;

	pi = new_pin(profile, id);
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

/*
 * Configuration file parser
 */
static void
init_state(struct state *cur, struct state *new_state)
{
	memset(new_state, 0, sizeof(*new_state));
	new_state->filename = cur->filename;
	new_state->profile = cur->profile;
	new_state->frame = cur;
}

static int
do_card_driver(struct state *cur, int argc, char **argv)
{
	cur->profile->driver = strdup(argv[0]);
	return 0;
}

static int
do_maxpinlength(struct state *cur, int argc, char **argv)
{
	return get_uint(cur, argv[0], &cur->profile->pin_maxlen);
}

static int
do_minpinlength(struct state *cur, int argc, char **argv)
{
	return get_uint(cur, argv[0], &cur->profile->pin_minlen);
}

static int
do_default_pin_type(struct state *cur, int argc, char **argv)
{
	return map_str2int(cur, argv[0],
		       	&cur->profile->pin_encoding, pinTypeNames);
}

static int
do_pin_pad_char(struct state *cur, int argc, char **argv)
{
	return get_uint(cur, argv[0], &cur->profile->pin_pad_char);
}

static int
do_card_label(struct state *cur, int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = cur->profile->p15_card;

	return setstr(&p15card->label, argv[0]);
}

static int
do_card_manufacturer(struct state *cur, int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = cur->profile->p15_card;

	return setstr(&p15card->manufacturer_id, argv[0]);
}

/*
 * Process a key block
 */
static int
process_key(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	unsigned int	type, id;
	struct state	state;

	if (get_authid(cur, name, &type, &id))
		return 1;

	init_state(cur, &state);
	state.key = new_key(cur->profile, type, id);
	return process_block(&state, info, name, blk);
}

static struct auth_info *
new_key(struct sc_profile *profile, unsigned int type, unsigned int ref)
{
	struct auth_info *ai, **aip;

	for (aip = &profile->auth_list; (ai = *aip); aip = &ai->next) {
		if (ai->type == type && ai->ref == ref)
			return ai;
	}

	ai = (struct auth_info *) calloc(1, sizeof(*ai));
	ai->type = type;
	ai->ref = ref;
	*aip = ai;
	return ai;
}

int
do_key_value(struct state *cur, int argc, char **argv)
{
	struct auth_info *ai = cur->key;
	const char	*key = argv[0];
	size_t		key_len;
	unsigned char	keybuf[32];

	if (key[0] == '=') {
		++key;
		key_len = strlen(key);
		memcpy(keybuf, key, key_len);
	} else {
		key_len = sizeof(keybuf);
		if (sc_hex_to_bin(key, keybuf, &key_len)) {
			parse_error(cur, "Error parsing PIN/key \"%s\"\n", key);
			return 1;
		}
	}

	memcpy(ai->key, keybuf, key_len);
	ai->key_len = key_len;
	return 0;
}

/*
 * This function is called when the parser finds a block with an unknown
 * name in the filesystem block. This will create a new filesystem
 * object as the child of the current object.
 */
static int
process_df(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	struct state	state;

	init_state(cur, &state);
	if (name == NULL) {
		parse_error(cur, "No name given for DF object.");
		return 1;
	}
	if (!(state.file = new_file(cur, name, SC_FILE_TYPE_DF)))
		return 1;
	return process_block(&state, info, name, blk);
}

static int
process_ef(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	struct state	state;

	init_state(cur, &state);
	if (name == NULL) {
		parse_error(cur, "No name given for EF object.");
		return 1;
	}
	if (!(state.file = new_file(cur, name, SC_FILE_TYPE_WORKING_EF)))
		return 1;
	return process_block(&state, info, name, blk);
}

static struct file_info *
new_file(struct state *cur, const char *name, unsigned int type)
{
	struct sc_profile *profile = cur->profile;
	struct file_info *info;
	struct sc_file	*file;
	unsigned int	df_type = 0, dont_free = 0;

	if ((info = sc_profile_find_file(profile, name)) != NULL)
		return info;

	info = (struct file_info *) calloc(1, sizeof(*info));
	info->ident = strdup(name);

	/* Special cases for those EFs handled separately
	 * by the PKCS15 logic */
	if (strncasecmp(name, "PKCS15-", 7)) {
		file = init_file(type);
	} else if (!strcasecmp(name+7, "TokenInfo")) {
		file = profile->p15_card->file_tokeninfo;
		dont_free = 1;
	} else if (!strcasecmp(name+7, "ODF")) {
		file = profile->p15_card->file_odf;
		dont_free = 1;
	} else if (!strcasecmp(name+7, "AppDF")) {
		file = init_file(SC_FILE_TYPE_DF);
	} else {
		if (map_str2int(cur, name+7, &df_type, pkcs15DfNames))
			return NULL;

		file = init_file(SC_FILE_TYPE_WORKING_EF);
		profile->df[df_type] = file;
	}
	assert(file);
	if (file->type != type) {
		parse_error(cur, "inconsistent file type (should be %s)",
			(file->type == SC_FILE_TYPE_DF)? "DF" : "EF");
		return NULL;
	}

	info->parent = cur->file;
	info->file = file;
	info->dont_free = dont_free;

	info->next = profile->ef_list;
	profile->ef_list = info;

	return info;
}

static int
do_file_type(struct state *cur, int argc, char **argv)
{
	unsigned int	type;

	if (map_str2int(cur, argv[0], &type, fileTypeNames))
		return 1;
	cur->file->file->type = type;
	return 0;
}

static int
do_file_path(struct state *cur, int argc, char **argv)
{
	struct sc_file	*file = cur->file->file;
	struct sc_path	*path = &file->path;

	/* sc_format_path doesn't return an error indication
	 * when it's unable to parse the path */
	sc_format_path(argv[0], path);
	if (!path->len || (path->len & 1)) {
		parse_error(cur, "Invalid path length\n");
		return 1;
	}
	file->id = (path->value[path->len-2] << 8)
		  | path->value[path->len-1];
	return 0;
}

static int
do_fileid(struct state *cur, int argc, char **argv)
{
	struct file_info *fi;
	struct sc_file	*df, *file = cur->file->file;
	struct sc_path	temp, *path = &file->path;

	/* sc_format_path doesn't return an error indication
	 * when it's unable to parse the path */
	sc_format_path(argv[0], &temp);
	if (temp.len != 2) {
		parse_error(cur, "Invalid file ID length\n");
		return 1;
	}

	/* Get the DF, if any */
	if ((fi = cur->file->parent) && (df = fi->file)) {
		if (df->path.len == 0) {
			parse_error(cur, "No path/fileid set for parent DF\n");
			return 1;
		}
		if (df->path.len + 2 > sizeof(df->path)) {
			parse_error(cur, "File path too long\n");
			return 1;
		}
		*path = df->path;
	}
	memcpy(path->value + path->len, temp.value, 2);
	path->len += 2;

	file->id = (temp.value[0] << 8) | temp.value[1];
	return 0;
}

static int
do_structure(struct state *cur, int argc, char **argv)
{
	unsigned int	ef_structure;

	if (map_str2int(cur, argv[0], &ef_structure, fileStructureNames))
		return 1;
	cur->file->file->ef_structure = ef_structure;
	return 0;
}

static int
do_size(struct state *cur, int argc, char **argv)
{
	unsigned int	size;

	if (get_uint(cur, argv[0], &size))
		return 1;
	cur->file->file->size = size;
	return 0;
}

static int
do_reclength(struct state *cur, int argc, char **argv)
{
	unsigned int	reclength;

	if (get_uint(cur, argv[0], &reclength))
		return 1;
	cur->file->file->record_length = reclength;
	return 0;
}

static int
do_aid(struct state *cur, int argc, char **argv)
{
	struct sc_file	*file = cur->file->file;
	const char	*name = argv[0];
	unsigned int	len;
	int		res = 0;

	if (*name == '=') {
		len = strlen(++name);
		if (len > sizeof(file->name)) {
			parse_error(cur, "AID \"%s\" too long\n", name);
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
do_acl(struct state *cur, int argc, char **argv)
{
	struct sc_file	*file = cur->file->file;
	char		*oper = 0, *what = 0;

	while (argc--) {
		unsigned int	op, method, id;

		oper = *argv++;
		if ((what = strchr(oper, '=')) == NULL)
			goto bad;
		*what++ = '\0';

		if (*what == '$') {
			method = SC_AC_SYMBOLIC;
			if (map_str2int(cur, what+1, &id, pinIdNames))
				return 1;
		} else
		if (get_authid(cur, what, &method, &id))
			goto bad;

		if (!strcmp(oper, "*")) {
			for (op = 0; op < SC_MAX_AC_OPS; op++) {
				sc_file_clear_acl_entries(file, op);
				sc_file_add_acl_entry(file, op, method, id);
			}
		} else {
			const struct sc_acl_entry *acl;

			if (map_str2int(cur, oper, &op, fileOpNames))
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

bad:	parse_error(cur, 
		"Invalid ACL \"%s%s%s\"\n",
		oper, what? "=" : "", what? what : "");
	return 1;
}

static int
process_pin(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	struct state	state;
	unsigned int	id;

	if (map_str2int(cur, name, &id, pinIdNames))
		return 1;

	init_state(cur, &state);
	state.pin = new_pin(cur->profile, id);

	return process_block(&state, info, name, blk);
}

static struct pin_info *
new_pin(struct sc_profile *profile, unsigned int id)
{
	struct pin_info	*pi, **tail;

	for (tail = &profile->pin_list; (pi = *tail); tail = &pi->next) {
		if (pi->id == id)
			return pi;
	}

	/* Create pin info object. Most values are
	 * set to their defaults in set_pin_defaults later
	 * We can't do this here because these pin info objects
	 * are usually created before we've read the card specific
	 * profile
	 */
	pi = (struct pin_info *) calloc(1, sizeof(*pi));
	pi->id = id;
	pi->pin.type = -1;
	pi->pin.flags = 0x32;
	pi->pin.max_length = 0;
	pi->pin.min_length = 0;
	pi->pin.stored_length = 0;
	pi->pin.pad_char = 0xA5;
	pi->pin.magic = SC_PKCS15_PIN_MAGIC;
	pi->pin.reference = -1;
	pi->pin.tries_left = 3;

	*tail = pi;
	return pi;
}

void
set_pin_defaults(struct sc_profile *profile, struct pin_info *pi)
{
	struct sc_pkcs15_pin_info *info = &pi->pin;

	if (info->type < 0)
		info->type = profile->pin_encoding;
	if (info->max_length == 0)
		info->max_length = profile->pin_maxlen;
	if (info->min_length == 0)
		info->min_length = profile->pin_minlen;
	if (info->stored_length == 0) {
		info->stored_length = profile->pin_maxlen;
		/* BCD encoded PIN takes half the space */
		if (info->type == SC_PKCS15_PIN_TYPE_BCD)
			info->stored_length = (info->stored_length + 1) / 2;
	}
	if (info->pad_char == 0xA5)
		info->pad_char = profile->pin_pad_char;
}

static int
do_pin_file(struct state *cur, int argc, char **argv)
{
	cur->pin->file_name = strdup(argv[0]);
	return 0;
}

static int
do_pin_offset(struct state *cur, int argc, char **argv)
{
	return get_uint(cur, argv[0], &cur->pin->file_offset);
}

static int
do_pin_attempts(struct state *cur, int argc, char **argv)
{
	struct pin_info	*pi = cur->pin;
	unsigned int	count;

	if (get_uint(cur, argv[0], &count))
		return 1;
	pi->pin.tries_left = count;
	return 0;
}

static int
do_pin_type(struct state *cur, int argc, char **argv)
{
	unsigned int	type;

	if (map_str2int(cur, argv[0], &type, pinTypeNames))
		return 1;
	cur->pin->pin.type = type;
	return 0;
}

static int
do_pin_reference(struct state *cur, int argc, char **argv)
{
	unsigned int	reference;

	if (get_uint(cur, argv[0], &reference))
		return 1;
	cur->pin->pin.reference = reference;
	return 0;
}

static int
do_pin_authid(struct state *cur, int argc, char **argv)
{
	sc_pkcs15_format_id(argv[0], &cur->pin->pin.auth_id);
	return 0;
}

static int
do_pin_minlength(struct state *cur, int argc, char **argv)
{
	unsigned int	len;

	if (get_uint(cur, argv[0], &len))
		return 1;
	cur->pin->pin.min_length = len;
	return 0;
}

static int
do_pin_maxlength(struct state *cur, int argc, char **argv)
{
	unsigned int	len;

	if (get_uint(cur, argv[0], &len))
		return 1;
	cur->pin->pin.stored_length = len;
	return 0;
}

static int
do_pin_flags(struct state *cur, int argc, char **argv)
{
	unsigned int	flags;

	if (map_str2int(cur, argv[0], &flags, pinTypeNames))
		return 1;
	cur->pin->pin.flags = flags;
	return 0;
}


/*
 * Key section
 */
static struct command	key_commands[] = {
 { "value",		1,	1,	do_key_value	},
 { NULL }
};

/*
 * Cardinfo section
 */
static struct command	ci_commands[] = {
 { "driver",		1,	1,	do_card_driver	},
 { "max-pin-length",	1,	1,	do_maxpinlength	},
 { "min-pin-length",	1,	1,	do_minpinlength	},
 { "pin-encoding",	1,	1,	do_default_pin_type },
 { "pin-pad-char",	1,	1,	do_pin_pad_char },
 { "label",		1,	1,	do_card_label	},
 { "manufacturer",	1,	1,	do_card_manufacturer},

 { NULL, 0, 0, NULL }
};

static struct block	ci_blocks[] = {
 { "key",		process_key,	key_commands,	NULL	},

 { NULL }
};

/*
 * Filesystem section
 */
static struct command	fs_commands[] = {
 { "type",		1,	1,	do_file_type	},
 { "path",		1,	1,	do_file_path	},
 { "file-id",		1,	1,	do_fileid	},
 { "structure",		1,	1,	do_structure	},
 { "size",		1,	1,	do_size		},
 { "record-length",	1,	1,	do_reclength	},
 { "AID",		1,	1,	do_aid		},
 { "ACL",		1,	-1,	do_acl		},

 { NULL, 0, 0, NULL }
};

static struct block	fs_blocks[] = {
 { "DF",		process_df,	fs_commands,	fs_blocks },
 { "EF",		process_ef,	fs_commands,	fs_blocks },

 { NULL, NULL, NULL, NULL }
};

/*
 * Pin section
 */
static struct command	pi_commands[] = {
 { "file",		1,	1,	do_pin_file	},
 { "offset",		1,	1,	do_pin_offset	},
 { "attempts",		1,	2,	do_pin_attempts	},
 { "encoding",		1,	1,	do_pin_type	},
 { "reference",		1,	1,	do_pin_reference},
 { "auth-id",		1,	1,	do_pin_authid	},
 { "max-length",	1,	1,	do_pin_maxlength},
 { "min-length",	1,	1,	do_pin_minlength},
 { "flags",		1,	1,	do_pin_flags	},
 { NULL, 0, 0, NULL }
};

static struct block	root_blocks[] = {
 { "filesystem",	process_block,	NULL,		fs_blocks },
 { "cardinfo",		process_block,	ci_commands,	ci_blocks },
 { "pin",		process_pin,	pi_commands,	NULL	},

 { NULL, NULL , NULL }
};

static struct block	root_ops = {
   "root",		process_block,	NULL,		root_blocks
};

static int
process_command(struct state *cur, struct command *cmd_info, scconf_list *list)
{
	const char	*cmd = cmd_info->name;
	char		*argv[16];
	unsigned int	argc, max = 16;

	/* count arguments first */
	for (argc = 0; list; list = list->next) {
		if (argc >= max)
			goto toomany;
		argv[argc++] = list->data;
	}

	if (argc < cmd_info->min_args) {
		parse_error(cur, "%s: not enough arguments\n", cmd);
		return 1;
	}
	if (0 <= cmd_info->max_args && cmd_info->max_args < argc) {
toomany:	parse_error(cur, "%s: too many arguments\n", cmd);
		return 1;
	}
	return cmd_info->func(cur, argc, argv);
}

static struct block *
find_block_handler(struct block *bp, const char *name)
{
	if (bp == NULL)
		return NULL;
	for (; bp->name; bp++) {
		if (!strcasecmp(bp->name, name))
			return bp;
	}
	return NULL;
}

static struct command *
find_cmd_handler(struct command *cp, const char *name)
{
	if (cp == NULL)
		return NULL;
	for (; cp->name; cp++) {
		if (!strcasecmp(cp->name, name))
			return cp;
	}
	return NULL;
}

static int
process_block(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	scconf_item	*item;
	struct command	*cp;
	struct block	*bp;
	const char	*cmd, *ident;
	int		res = 0;

	for (item = blk->items; res == 0 && item; item = item->next) {
		cmd = item->key;
		if (item->type == SCCONF_ITEM_TYPE_COMMENT)
			continue;
		if (item->type == SCCONF_ITEM_TYPE_BLOCK) {
			scconf_list *nlist;

			ident = NULL;
			if ((nlist = item->value.block->name) != NULL) {
				if (nlist->next) {
					parse_error(cur,
						"Too many name components "
						"in block name.");
					return SC_ERROR_SYNTAX_ERROR;
				}
				ident = nlist->data;
			}
#if 0
			printf("Processing %s %s\n",
				cmd, ident? ident : "");
#endif
			if ((bp = find_block_handler(info->blk_info, cmd))) {
				res = bp->handler(cur, bp, ident,
						item->value.block);
				continue;
			}
		} else
		if (item->type == SCCONF_ITEM_TYPE_VALUE) {
			if ((cp = find_cmd_handler(info->cmd_info, cmd))) {
				res = process_command(cur, cp,
						item->value.list);
				continue;
			}
		}
		parse_error(cur,
			"Command \"%s\" not understood in this context.", cmd);
		return SC_ERROR_SYNTAX_ERROR;
	}

	if (res > 0)
		res = SC_ERROR_SYNTAX_ERROR;
	return res;
}

static int
process_conf(struct sc_profile *profile, scconf_context *conf)
{
	struct state	state;

	memset(&state, 0, sizeof(state));
	state.filename = conf->filename;
	state.profile = profile;
	return process_block(&state, &root_ops, "root", conf->root);
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
	struct auth_info *ai;

	ai = new_key(profile, type, ref);
	if (key_len)
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
sc_profile_forget_secrets(struct sc_profile *profile,
		unsigned int type, int ref)
{
	struct auth_info *ai, **aip;

	aip = &profile->auth_list;
	while ((ai = *aip) != NULL) {
		if (ai->type == type
		 && (ref < 0 || ai->ref == (unsigned int) ref)) {
			*aip = ai->next;
			free(ai);
		} else {
			aip = &ai->next;
		}
	}
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

/*
 * Split up KEY0 or CHV1 into SC_AC_XXX and a number
 */
static int
get_authid(struct state *cur, const char *value,
		unsigned int *type, unsigned int *num)
{
	char	temp[16];
	int	n;

	if (isdigit((int) *value)) {
		*num = 0;
		return get_uint(cur, value, type);
	}

	n = strcspn(value, "0123456789");
	strncpy(temp, value, n);
	temp[n] = '\0';

	if (map_str2int(cur, temp, type, aclNames))
		return 1;
	if (value[n])
		return get_uint(cur, value + n, num);
	*num = 0;
	return 0;
}

static int
get_uint(struct state *cur, const char *value, unsigned int *vp)
{
	const char	*ep;

	*vp = strtoul(value, (char **) &ep, 0);
	if (*ep != '\0') {
		parse_error(cur, 
			"invalid integer argument \"%s\"\n", value);
		return 1;
	}
	return 0;
}

static int
map_str2int(struct state *cur, const char *value,
		unsigned int *vp, struct map *map)
{
	unsigned int	n;
	const char	*what;

	if (isdigit((int) *value))
		return get_uint(cur, value, vp);
	for (n = 0; map[n].name; n++) {
		if (!strcasecmp(value, map[n].name)) {
			*vp = map[n].val;
			return 0;
		}
	}

	/* Try to print a meaningful error message */
	what = "argument";
	for (n = 0; mapNames[n].name; n++) {
		if (mapNames[n].addr == map) {
			what = mapNames[n].name;
			break;
		}
	}

	parse_error(cur, "invalid %s \"%s\"\n", what, value);
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
parse_error(struct state *cur, const char *fmt, ...)
{
	char	buffer[1024], *sp;
	va_list	ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if ((sp = strchr(buffer, '\n')) != NULL)
		*sp = '\0';

	if (cur->profile->cbs)
		cur->profile->cbs->error("%s: %s",
			cur->filename, buffer);
}
