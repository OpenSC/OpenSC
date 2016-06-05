/*
 * Initialize Cards according to PKCS#15
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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
 *
 * Random notes
 *  -	the "key" command should go away, it's obsolete
 */

#include "config.h"

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

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#endif

#include "common/compat_strlcpy.h"
#include "scconf/scconf.h"
#include "libopensc/log.h"
#include "libopensc/pkcs15.h"
#include "pkcs15-init.h"
#include "profile.h"

#define DEF_PRKEY_RSA_ACCESS	0x1D
#define DEF_PRKEY_DSA_ACCESS	0x12
#define DEF_PUBKEY_ACCESS	0x12

#define TEMPLATE_FILEID_MIN_DIFF	0x20

/*
#define DEBUG_PROFILE
*/

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
	{ "SEN",	SC_AC_SEN	},
	{ "IDA",	SC_AC_IDA	},
	{ "SCB",	SC_AC_SCB	},
	{ NULL, 0 }
};
static struct map		fileOpNames[] = {
	{ "SELECT",	SC_AC_OP_SELECT	},
	{ "LOCK",	SC_AC_OP_LOCK	},
	{ "DELETE",	SC_AC_OP_DELETE	},
	{ "DELETE-SELF",SC_AC_OP_DELETE_SELF },
	{ "CREATE",	SC_AC_OP_CREATE	},
	{ "CREATE-EF",	SC_AC_OP_CREATE_EF	},
	{ "CREATE-DF",	SC_AC_OP_CREATE_DF	},
	{ "REHABILITATE",SC_AC_OP_REHABILITATE	},
	{ "INVALIDATE",	SC_AC_OP_INVALIDATE	},
	{ "FILES",	SC_AC_OP_LIST_FILES	},
	{ "READ",	SC_AC_OP_READ	},
	{ "UPDATE",	SC_AC_OP_UPDATE	},
	{ "WRITE",	SC_AC_OP_WRITE	},
	{ "ERASE",	SC_AC_OP_ERASE	},
	{ "CRYPTO",     SC_AC_OP_CRYPTO },
        { "PIN-DEFINE", SC_AC_OP_PIN_DEFINE },
        { "PIN-CHANGE", SC_AC_OP_PIN_CHANGE },
        { "PIN-RESET",  SC_AC_OP_PIN_RESET },
        { "PIN-USE",	SC_AC_OP_PIN_USE },
	{ "GENERATE",	SC_AC_OP_GENERATE },
	{ "PSO-COMPUTE-SIGNATURE",	SC_AC_OP_PSO_COMPUTE_SIGNATURE },
	{ "INTERNAL-AUTHENTICATE",	SC_AC_OP_INTERNAL_AUTHENTICATE },
	{ "PSO-DECRYPT",		SC_AC_OP_PSO_DECRYPT },
	{ "RESIZE",	SC_AC_OP_RESIZE },
	{ "ADMIN",	SC_AC_OP_ADMIN	},
	{ "ACTIVATE",	SC_AC_OP_ACTIVATE },
	{ "DEACTIVATE",	SC_AC_OP_DEACTIVATE },
	{ NULL, 0 }
};
static struct map		fileTypeNames[] = {
	{ "EF",		SC_FILE_TYPE_WORKING_EF		},
	{ "INTERNAL-EF",SC_FILE_TYPE_INTERNAL_EF	},
	{ "DF",		SC_FILE_TYPE_DF			},
	{ "BSO",	SC_FILE_TYPE_BSO		},
	{ NULL, 0 }
};
static struct map		fileStructureNames[] = {
	{ "TRANSPARENT",	SC_FILE_EF_TRANSPARENT	},
	{ "LINEAR-FIXED",	SC_FILE_EF_LINEAR_FIXED	},
	{ "LINEAR-FIXED-TLV",	SC_FILE_EF_LINEAR_FIXED_TLV	},
	{ "LINEAR-VARIABLE",	SC_FILE_EF_LINEAR_VARIABLE	},
	{ "LINEAR-VARIABLE-TLV",SC_FILE_EF_LINEAR_VARIABLE_TLV	},
	{ "CYCLIC",		SC_FILE_EF_CYCLIC	},
	{ "CYCLIC-TLV",		SC_FILE_EF_CYCLIC_TLV	},
	{ NULL, 0 }
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
	{ NULL, 0 }
};
static struct map		pinTypeNames[] = {
	{ "BCD",		SC_PKCS15_PIN_TYPE_BCD	},
	{ "ascii-numeric",	SC_PKCS15_PIN_TYPE_ASCII_NUMERIC	},
	{ "utf8",		SC_PKCS15_PIN_TYPE_UTF8	},
	{ "half-nibble-bcd",	SC_PKCS15_PIN_TYPE_HALFNIBBLE_BCD	},
	{ "iso9564-1",		SC_PKCS15_PIN_TYPE_ISO9564_1	},
	{ NULL, 0 }
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
	{ NULL, 0 }
};
static struct map		pinFlagNames[] = {
	{ "case-sensitive",		SC_PKCS15_PIN_FLAG_CASE_SENSITIVE		},
	{ "local",			SC_PKCS15_PIN_FLAG_LOCAL			},
	{ "change-disabled",		SC_PKCS15_PIN_FLAG_CHANGE_DISABLED		},
	{ "unblock-disabled",		SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED		},
	{ "initialized",		SC_PKCS15_PIN_FLAG_INITIALIZED			},
	{ "needs-padding",		SC_PKCS15_PIN_FLAG_NEEDS_PADDING		},
	{ "unblockingPin",		SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN		},
	{ "soPin",			SC_PKCS15_PIN_FLAG_SO_PIN			},
	{ "disable-allowed",		SC_PKCS15_PIN_FLAG_DISABLE_ALLOW		},
	{ "integrity-protected",	SC_PKCS15_PIN_FLAG_INTEGRITY_PROTECTED		},
	{ "confidentiality-protected",	SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED	},
	{ "exchangeRefData",		SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA		},
	{ NULL, 0 }
};
static struct map		idStyleNames[] = {
	{ "native",		SC_PKCS15INIT_ID_STYLE_NATIVE },
	{ "mozilla",		SC_PKCS15INIT_ID_STYLE_MOZILLA },
	{ "rfc2459",		SC_PKCS15INIT_ID_STYLE_RFC2459 },
	{ NULL, 0 }
};
static struct map              mdStyleNames[] = {
	{ "none",               SC_PKCS15INIT_MD_STYLE_NONE },
	{ "gemalto",            SC_PKCS15INIT_MD_STYLE_GEMALTO },
	{ NULL, 0 }
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

static int		process_conf(struct sc_profile *, scconf_context *);
static int		process_block(struct state *, struct block *,
				const char *, scconf_block *);
static void		init_state(struct state *, struct state *);
static int		get_authid(struct state *, const char *,
				unsigned int *, unsigned int *);
static int		get_uint(struct state *, const char *, unsigned int *);
static int		get_bool(struct state *, const char *, unsigned int *);
static int		get_uint_eval(struct state *, int, char **,
				unsigned int *);
static int		map_str2int(struct state *, const char *,
				unsigned int *, struct map *);
static int		setstr(char **strp, const char *value);
static void		parse_error(struct state *, const char *, ...);

static struct file_info *	sc_profile_instantiate_file(sc_profile_t *,
				struct file_info *, struct file_info *,
				unsigned int);
static struct file_info *	sc_profile_find_file(struct sc_profile *,
				const sc_path_t *, const char *);
static struct file_info *	sc_profile_find_file_by_path(
				struct sc_profile *,
				const sc_path_t *);

static struct pin_info *	new_pin(struct sc_profile *, int);
static struct file_info *	new_file(struct state *, const char *,
				unsigned int);
static struct file_info *	add_file(sc_profile_t *, const char *,
				sc_file_t *, struct file_info *);
static void		free_file_list(struct file_info **);
static void		append_file(sc_profile_t *, struct file_info *);
static struct auth_info *	new_key(struct sc_profile *,
				unsigned int, unsigned int);
static void		set_pin_defaults(struct sc_profile *,
				struct pin_info *);
static void		new_macro(sc_profile_t *, const char *, scconf_list *);
static sc_macro_t *	find_macro(sc_profile_t *, const char *);

static sc_file_t *
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
	if (file->type != SC_FILE_TYPE_DF && file->type != SC_FILE_TYPE_BSO)
		file->ef_structure = SC_FILE_EF_TRANSPARENT;
	return file;
}

/*
 * Initialize profile
 */
struct sc_profile *
sc_profile_new(void)
{
	struct sc_pkcs15_card *p15card;
	struct sc_profile *pro;

	pro = calloc(1, sizeof(*pro));
	if (pro == NULL)
		return NULL;
	pro->p15_spec = p15card = sc_pkcs15_card_new();

	pro->pkcs15.do_last_update = 1;

	if (p15card) {
		p15card->tokeninfo->label = strdup("OpenSC Card");
		p15card->tokeninfo->manufacturer_id = strdup("OpenSC Project");
		p15card->tokeninfo->serial_number = strdup("0000");
		p15card->tokeninfo->flags = SC_PKCS15_TOKEN_EID_COMPLIANT;
		p15card->tokeninfo->version = 0;

		/* Set up EF(TokenInfo) and EF(ODF) */
		p15card->file_tokeninfo = init_file(SC_FILE_TYPE_WORKING_EF);
		p15card->file_odf = init_file(SC_FILE_TYPE_WORKING_EF);
		p15card->file_unusedspace = init_file(SC_FILE_TYPE_WORKING_EF);
	}

	/* Assume card does RSA natively, but no DSA */
	pro->rsa_access_flags = DEF_PRKEY_RSA_ACCESS;
	pro->dsa_access_flags = DEF_PRKEY_DSA_ACCESS;
	pro->pin_encoding = SC_PKCS15_PIN_TYPE_ASCII_NUMERIC;
	pro->pin_minlen = 4;
	pro->pin_maxlen = 8;
	pro->id_style = SC_PKCS15INIT_ID_STYLE_NATIVE;

	return pro;
}

int
sc_profile_load(struct sc_profile *profile, const char *filename)
{
	struct sc_context *ctx = profile->card->ctx;
	scconf_context	*conf;
	const char *profile_dir = NULL;
	char path[PATH_MAX];
	int res = 0, i;
#ifdef _WIN32
	char temp_path[PATH_MAX];
	size_t temp_len;
#endif

	LOG_FUNC_CALLED(ctx);
	for (i = 0; ctx->conf_blocks[i]; i++) {
		profile_dir = scconf_get_str(ctx->conf_blocks[i], "profile_dir", NULL);
		if (profile_dir)
			break;
	}

	if (!profile_dir) {
#ifdef _WIN32
		temp_len = PATH_MAX;
		res = sc_ctx_win32_get_config_value(NULL, "ProfileDir", "Software\\OpenSC Project\\OpenSC",
				temp_path, &temp_len);
		if (res)
			LOG_FUNC_RETURN(ctx, res);
		profile_dir = temp_path;
#else
		profile_dir = SC_PKCS15_PROFILE_DIRECTORY;
#endif
	}
	sc_log(ctx, "Using profile directory '%s'.", profile_dir);

#ifdef _WIN32
	snprintf(path, sizeof(path), "%s\\%s.%s", profile_dir, filename, SC_PKCS15_PROFILE_SUFFIX);
#else /* _WIN32 */
	snprintf(path, sizeof(path), "%s/%s.%s", profile_dir, filename, SC_PKCS15_PROFILE_SUFFIX);
#endif /* _WIN32 */

	sc_log(ctx, "Trying profile file %s", path);

	conf = scconf_new(path);
	res = scconf_parse(conf);

	sc_log(ctx, "profile %s loaded ok", path);

	if (res < 0) {
		scconf_free(conf);
		LOG_FUNC_RETURN(ctx, SC_ERROR_FILE_NOT_FOUND);
	}

	if (res == 0) {
		scconf_free(conf);
		LOG_FUNC_RETURN(ctx, SC_ERROR_SYNTAX_ERROR);
	}

	res = process_conf(profile, conf);
	scconf_free(conf);
	LOG_FUNC_RETURN(ctx, res);
}


int
sc_profile_finish(struct sc_profile *profile, const struct sc_app_info *app_info)
{
	struct sc_context *ctx = profile->card->ctx;
	struct file_info *fi;
	struct pin_info	*pi;
	char		reason[64];

	LOG_FUNC_CALLED(ctx);
	profile->mf_info = sc_profile_find_file(profile, NULL, "MF");
	if (!profile->mf_info)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_PROFILE, "Profile doesn't define a MF");

	if (app_info && app_info->aid.len)   {
		struct sc_path path;

		sc_log(ctx, "finish profile with '%s' application profile", app_info->label);
		memset(&path, 0, sizeof(struct sc_path));
		path.type = SC_PATH_TYPE_DF_NAME;
		path.aid = app_info->aid;

		sc_log(ctx, "Look for file by path '%s'", sc_print_path(&path));
		profile->df_info = sc_profile_find_file_by_path(profile, &path);
		sc_log(ctx, "returned DF info %p", profile->df_info);
		if (profile->df_info && profile->df_info->profile_extension)   {
			sc_log(ctx, "application profile extension '%s'", profile->df_info->profile_extension);
			if (sc_profile_load(profile, profile->df_info->profile_extension))
				LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_PROFILE, "Cannot load application profile extension");
		}
	}

	profile->df_info = sc_profile_find_file(profile, NULL, "PKCS15-AppDF");
	if (!profile->df_info)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_PROFILE, "Profile doesn't define a PKCS15-AppDF");

	profile->p15_spec->file_app = profile->df_info->file;
	profile->df_info->dont_free = 1;

	for (pi = profile->pin_list; pi; pi = pi->next) {
		const char	*name;

		set_pin_defaults(profile, pi);
		if (!(name = pi->file_name))
			continue;
		if (!(fi = sc_profile_find_file(profile, NULL, name))) {
			snprintf(reason, sizeof(reason), "unknown PIN file \"%s\"\n", name);
			goto whine;
		}

		pi->file = fi;
	}
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);

whine:
	sc_log(ctx, "%s", reason);
	LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
}

void
sc_profile_free(struct sc_profile *profile)
{
	struct auth_info *ai;
	struct pin_info *pi;
	sc_macro_t	*mi;
	sc_template_t	*ti;

	if (profile->name)
		free(profile->name);

	free_file_list(&profile->ef_list);

	while ((ai = profile->auth_list) != NULL) {
		profile->auth_list = ai->next;
		free(ai);
	}

	while ((ti = profile->template_list) != NULL) {
		profile->template_list = ti->next;
		if (ti->data)
			sc_profile_free(ti->data);
		if (ti->name)
			free(ti->name);
		free(ti);
	}

	while ((mi = profile->macro_list) != NULL) {
		profile->macro_list = mi->next;
		if (mi->name)
			free(mi->name);
		free(mi);
	}

	while ((pi = profile->pin_list) != NULL) {
		profile->pin_list = pi->next;
		if (pi->file_name)
			free(pi->file_name);
		free(pi);
	}

	if (profile->p15_spec)
		sc_pkcs15_card_free(profile->p15_spec);
	memset(profile, 0, sizeof(*profile));
	free(profile);
}

void
sc_profile_get_pin_info(struct sc_profile *profile,
		int id, struct sc_pkcs15_auth_info *info)
{
	struct pin_info	*pi;

	pi = new_pin(profile, id);
	if (pi == NULL)
		return;

	pi->pin.max_tries = pi->pin.tries_left;
	*info = pi->pin;
}

int
sc_profile_get_pin_retries(sc_profile_t *profile, int id)
{
	struct pin_info	*pi;

	pi = new_pin(profile, id);
	if (pi == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	return pi->pin.tries_left;
}

int
sc_profile_get_pin_id(struct sc_profile *profile,
		unsigned int reference, int *id)
{
	struct pin_info	*pi;

	for (pi = profile->pin_list; pi; pi = pi->next) {
		if (pi->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
			continue;
		if (pi->pin.attrs.pin.reference == (int)reference) {
			*id = pi->id;
			return 0;
		}

	}
	return SC_ERROR_OBJECT_NOT_FOUND;
}

int
sc_profile_get_file_in(sc_profile_t *profile,
		const sc_path_t *path, const char *name, sc_file_t **ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file(profile, path, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	sc_file_dup(ret, fi->file);
	if (*ret == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	return 0;
}

int
sc_profile_get_file(struct sc_profile *profile,
		const char *name, sc_file_t **ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file(profile, NULL, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	sc_file_dup(ret, fi->file);
	if (*ret == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	return 0;
}

int
sc_profile_get_file_instance(struct sc_profile *profile, const char *name,
		int index, sc_file_t **ret)
{
	struct sc_context *ctx = profile->card->ctx;
	struct file_info *fi;
	struct sc_file *file;
	int r;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "try to get '%s' file instance", name);

	if ((fi = sc_profile_find_file(profile, NULL, name)) == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_FILE_NOT_FOUND);
	sc_file_dup(&file, fi->file);
	sc_log(ctx, "ident '%s'; parent '%s'", fi->ident, fi->parent->ident);
	if (file == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	sc_log(ctx, "file (type:%X, path:'%s')", file->type, sc_print_path(&file->path));

	file->id += index;
        if(file->type == SC_FILE_TYPE_BSO) {
		r = sc_profile_add_file(profile, name, file);
		if (r < 0)
			sc_file_free(file);
		LOG_TEST_RET(ctx, r, "Profile error: cannot add BSO file");
	}
	else if (file->path.len)   {
		file->path.value[file->path.len - 2] = (file->id >> 8) & 0xFF;
		file->path.value[file->path.len - 1] = file->id & 0xFF;

		r = sc_profile_add_file(profile, name, file);
		if (r < 0)
			sc_file_free(file);
		LOG_TEST_RET(ctx, r, "Profile error: cannot add file");
	}

	if (ret)
		*ret = file;
	else
		sc_file_free(file);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int
sc_profile_get_path(struct sc_profile *profile,
		const char *name, sc_path_t *ret)
{
	struct file_info *fi;

	if ((fi = sc_profile_find_file(profile, NULL, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;
	*ret = fi->file->path;
	return 0;
}

int
sc_profile_get_file_by_path(struct sc_profile *profile,
		const sc_path_t *path, sc_file_t **ret)
{
	struct sc_context *ctx = profile->card->ctx;
	struct file_info *fi;

	LOG_FUNC_CALLED(ctx);
	if ((fi = sc_profile_find_file_by_path(profile, path)) == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_FILE_NOT_FOUND);
	sc_file_dup(ret, fi->file);
	LOG_FUNC_RETURN(ctx, *ret ? SC_SUCCESS : SC_ERROR_OUT_OF_MEMORY);
}

int
sc_profile_add_file(sc_profile_t *profile, const char *name, sc_file_t *file)
{
	struct sc_context *ctx = profile->card->ctx;
	sc_path_t	path = file->path;
	struct file_info	*parent;

	LOG_FUNC_CALLED(ctx);
	if (!path.len)   {
		parent = profile->df_info;
		        }
        else   {
		path.len -= 2;
		parent = sc_profile_find_file_by_path(profile, &path);
	}
	if (!parent)
		LOG_FUNC_RETURN(ctx, SC_ERROR_FILE_NOT_FOUND);
	sc_log(ctx, "Parent path:%s", sc_print_path(&parent->file->path));

	sc_file_dup(&file, file);
	if (file == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	add_file(profile, name, file, parent);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Instantiate template
 */
int
sc_profile_instantiate_template(sc_profile_t *profile,
		const char *template_name, const sc_path_t *base_path,
		const char *file_name, const sc_pkcs15_id_t *id,
		sc_file_t **ret)
{
	struct sc_context *ctx = profile->card->ctx;
	struct sc_profile	*tmpl;
	struct sc_template	*info;
	unsigned int	idx;
	struct file_info *fi, *base_file, *match = NULL;

#ifdef DEBUG_PROFILE
	printf("Instantiate %s in template %s\n", file_name, template_name);
	sc_profile_find_file_by_path(profile, base_path);
#endif
	for (info = profile->template_list; info; info = info->next)
		if (!strcmp(info->name, template_name))
			break;
	if (info == NULL)   {
		sc_log(ctx, "Template %s not found", template_name);
		return SC_ERROR_TEMPLATE_NOT_FOUND;
	}

	tmpl = info->data;
	idx = id->value[id->len-1];
	for (fi = profile->ef_list; fi; fi = fi->next) {
		if (fi->base_template == tmpl
		 && fi->inst_index == idx
		 && sc_compare_path(&fi->inst_path, base_path)
		 && !strcmp(fi->ident, file_name)) {
			sc_file_dup(ret, fi->file);
			if (*ret == NULL)
				return SC_ERROR_OUT_OF_MEMORY;
			return 0;
		}
	}

	sc_log(ctx, "Instantiating template %s at %s", template_name, sc_print_path(base_path));

	base_file = sc_profile_find_file_by_path(profile, base_path);
	if (base_file == NULL) {
		sc_log(ctx, "Directory %s not defined in profile", sc_print_path(base_path));
		return SC_ERROR_OBJECT_NOT_FOUND;
	}

	/* This loop relies on the fact that new files are always
	 * appended to the list, after the parent files they refer to
	 */
	assert(base_file->instance);
	for (fi = tmpl->ef_list; fi; fi = fi->next) {
		struct file_info	*parent, *instance;
		unsigned int	skew = 0;

		fi->instance = NULL;
		if ((parent = fi->parent) == NULL) {
			parent = base_file;
			skew = idx;
		}
		parent = parent->instance;

		instance = sc_profile_instantiate_file(profile, fi, parent, skew);
		if (instance == NULL)
			return SC_ERROR_OUT_OF_MEMORY;
		instance->base_template = tmpl;
		instance->inst_index = idx;
		instance->inst_path = *base_path;

		if (!strcmp(instance->ident, file_name))
			match = instance;
	}

	if (match == NULL) {
		sc_log(ctx, "No file named \"%s\" in template \"%s\"",
				file_name, template_name);
		return SC_ERROR_OBJECT_NOT_FOUND;
	}
	sc_file_dup(ret, match->file);
	if (*ret == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
#ifdef DEBUG_PROFILE
	printf("Template instantiated\n");
#endif
	return 0;
}

static struct file_info *
sc_profile_instantiate_file(sc_profile_t *profile, struct file_info *ft,
		struct file_info *parent, unsigned int skew)
{
	struct sc_context *ctx = profile->card->ctx;
	struct file_info *fi;

	fi = calloc(1, sizeof(*fi));
	if (fi == NULL)
		return NULL;
	fi->instance = fi;
	fi->parent = parent;
	fi->ident = strdup(ft->ident);
	if (fi->ident == NULL) {
		free(fi);
		return NULL;
	}
	sc_file_dup(&fi->file, ft->file);
	if (fi->file == NULL) {
		free(fi->ident);
		free(fi);
		return NULL;
	}
	fi->file->path = parent->file->path;
	fi->file->id += skew;

	if (fi->file->type == SC_FILE_TYPE_INTERNAL_EF
			|| fi->file->type == SC_FILE_TYPE_WORKING_EF
			|| (fi->file->type == SC_FILE_TYPE_DF && fi->file->id))
		sc_append_file_id(&fi->file->path, fi->file->id);

	append_file(profile, fi);

	ft->instance = fi;

	sc_log(ctx, "Instantiated %s at %s", ft->ident, sc_print_path(&fi->file->path));
	sc_log(ctx, "  parent=%s@%s", parent->ident, sc_print_path(&parent->file->path));

	return fi;
}

int
sc_profile_get_pin_id_by_reference(struct sc_profile *profile,
		unsigned auth_method, int reference,
		struct sc_pkcs15_auth_info *auth_info)
{
	struct pin_info *pinfo;

	for (pinfo = profile->pin_list; pinfo; pinfo = pinfo->next)  {
		if (auth_method == SC_AC_SYMBOLIC)   {
			if (pinfo->id != reference)
				continue;
		}
		else   {
			if (pinfo->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
				continue;
			if (pinfo->pin.auth_method != auth_method)
				continue;
			if (pinfo->pin.attrs.pin.reference != reference)
				continue;
		}

		if (auth_info)
			*auth_info = pinfo->pin;
		return pinfo->id;
	}

	return -1;
}

/*
 * Configuration file parser
 */
static void
init_state(struct state *cur_state, struct state *new_state)
{
	memset(new_state, 0, sizeof(*new_state));
	new_state->filename = cur_state->filename;
	new_state->profile = cur_state->profile;
	new_state->frame = cur_state;
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
do_pin_domains(struct state *cur, int argc, char **argv)
{
	return get_bool(cur, argv[0], &cur->profile->pin_domains);
}

static int
do_card_label(struct state *cur, int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = cur->profile->p15_spec;

	return setstr(&p15card->tokeninfo->label, argv[0]);
}

static int
do_card_manufacturer(struct state *cur, int argc, char **argv)
{
	struct sc_pkcs15_card	*p15card = cur->profile->p15_spec;

	return setstr(&p15card->tokeninfo->manufacturer_id, argv[0]);
}

/*
 * Command related to the pkcs15 we generate
 */
static int
do_direct_certificates(struct state *cur, int argc, char **argv)
{
	return get_bool(cur, argv[0], &cur->profile->pkcs15.direct_certificates);
}

static int
do_encode_df_length(struct state *cur, int argc, char **argv)
{
	return get_bool(cur, argv[0], &cur->profile->pkcs15.encode_df_length);
}

static int
do_encode_update_field(struct state *cur, int argc, char **argv)
{
	return get_bool(cur, argv[0], &cur->profile->pkcs15.do_last_update);
}

static int
do_pkcs15_id_style(struct state *cur, int argc, char **argv)
{
	return map_str2int(cur, argv[0], &cur->profile->id_style, idStyleNames);
}

static int
do_minidriver_support_style(struct state *cur, int argc, char **argv)
{
	return map_str2int(cur, argv[0], &cur->profile->md_style, mdStyleNames);
}

/*
 * Process an option block
 */
static int
process_option(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	sc_profile_t	*profile = cur->profile;
	int		match = 0, i;

	for (i = 0; profile->options[i]; i++)
		match |= !strcmp(profile->options[i], name);
	if (!match && strcmp("default", name))
		return 0;
	return process_block(cur, info, name, blk);
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

	ai = calloc(1, sizeof(*ai));
	if (ai == NULL)
		return NULL;
	ai->type = type;
	ai->ref = ref;
	*aip = ai;
	return ai;
}

static int
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


static int
process_bso(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	struct state	state;

	init_state(cur, &state);
	if (name == NULL) {
		parse_error(cur, "No name given for BSO object.");
		return 1;
	}
	if (!(state.file = new_file(cur, name, SC_FILE_TYPE_BSO)))
		return 1;
	return process_block(&state, info, name, blk);
}

/*
 * In the template the difference between any two file-ids
 * should be greater then TEMPLATE_FILEID_MIN_DIFF.
 */
static int
template_sanity_check(struct state *cur, struct sc_profile *templ)
{
	struct file_info *fi, *ffi;

	for (fi = templ->ef_list; fi; fi = fi->next) {
		struct sc_path fi_path =  fi->file->path;
		int fi_id = fi_path.value[fi_path.len - 2] * 0x100
			+ fi_path.value[fi_path.len - 1];

		if (fi->file->type == SC_FILE_TYPE_BSO)
			continue;
		for (ffi = templ->ef_list; ffi; ffi = ffi->next) {
			struct sc_path ffi_path =  ffi->file->path;
			int dlt, ffi_id = ffi_path.value[ffi_path.len - 2] * 0x100
				+ ffi_path.value[ffi_path.len - 1];

			if (ffi->file->type == SC_FILE_TYPE_BSO)
				continue;

			dlt = fi_id > ffi_id ? fi_id - ffi_id : ffi_id - fi_id;
			if (strcmp(ffi->ident, fi->ident))   {
				if (dlt >= TEMPLATE_FILEID_MIN_DIFF)
					continue;

				parse_error(cur, "Template insane: file-ids should be substantially different");
				return 1;
			}
		}
	}

	return SC_SUCCESS;
}


static int
process_tmpl(struct state *cur, struct block *info,
		const char *name, scconf_block *blk)
{
	struct state	state;
	sc_template_t	*tinfo;
	sc_profile_t	*templ;
	int r;

#ifdef DEBUG_PROFILE
	printf("Process template:%s; block:%s\n", name, info->name);
#endif
	if (name == NULL) {
		parse_error(cur, "No name given for template.");
		return 1;
	}

	templ = calloc(1, sizeof(*templ));
	if (templ == NULL) {
		parse_error(cur, "memory allocation failed");
		return 1;
	}

	tinfo = calloc(1, sizeof(*tinfo));
	if (tinfo == NULL) {
		parse_error(cur, "memory allocation failed");
		free(templ);
		return 1;
	}
	tinfo->name = strdup(name);
	tinfo->data = templ;

	tinfo->next = cur->profile->template_list;
	cur->profile->template_list = tinfo;

	init_state(cur, &state);
	state.profile = tinfo->data;
	state.file = NULL;

	r = process_block(&state, info, name, blk);
	if (!r)
		r = template_sanity_check(cur, templ);

#ifdef DEBUG_PROFILE
	printf("Template %s processed; returns %i\n", name, r);
#endif
	return r;
}

/*
 * Append new file at the end of the ef_list.
 * This is crucial; the profile instantiation code relies on it
 */
static void append_file(sc_profile_t *profile, struct file_info *nfile)
{
	struct file_info	**list, *fi;

	list = &profile->ef_list;
	while ((fi = *list) != NULL)
		list = &fi->next;
	*list = nfile;
}

/*
 * Add a new file to the profile.
 * This function is called by sc_profile_add_file.
 */
static struct file_info *
add_file(sc_profile_t *profile, const char *name,
		sc_file_t *file, struct file_info *parent)
{
	struct file_info	*info;

	info = calloc(1, sizeof(*info));
	if (info == NULL)
		return NULL;
	info->instance = info;
	info->ident = strdup(name);

	info->parent = parent;
	info->file = file;

	append_file(profile, info);
	return info;
}

/*
 * Free file_info list
 */
static void
free_file_list(struct file_info **list)
{
	struct file_info	*fi;

	while ((fi = *list) != NULL) {
		*list = fi->next;

		if (fi->dont_free == 0)
			sc_file_free(fi->file);
		free(fi->ident);
		free(fi);
	}
}

/*
 * Create a new file info object.
 * This function is called by the profile parser.
 */
static struct file_info *
new_file(struct state *cur, const char *name, unsigned int type)
{
	sc_profile_t	*profile = cur->profile;
	struct file_info	*info;
	sc_file_t	*file;
	unsigned int	df_type = 0, dont_free = 0;

	if ((info = sc_profile_find_file(profile, NULL, name)) != NULL)
		return info;

	/* Special cases for those EFs handled separately
	 * by the PKCS15 logic */
	if (strncasecmp(name, "PKCS15-", 7)) {
		file = init_file(type);
	} else if (!strcasecmp(name+7, "TokenInfo")) {
		file = profile->p15_spec->file_tokeninfo;
		dont_free = 1;
	} else if (!strcasecmp(name+7, "ODF")) {
		file = profile->p15_spec->file_odf;
		dont_free = 1;
	} else if (!strcasecmp(name+7, "UnusedSpace")) {
		file = profile->p15_spec->file_unusedspace;
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
			file->type == SC_FILE_TYPE_DF
				? "DF" : file->type == SC_FILE_TYPE_BSO
					? "BS0" : "EF");
		if (strncasecmp(name, "PKCS15-", 7) ||
			!strcasecmp(name+7, "AppDF"))
			sc_file_free(file);
		return NULL;
	}

	info = add_file(profile, name, file, cur->file);
	if (info == NULL) {
		parse_error(cur, "memory allocation failed");
		return NULL;
	}
	info->dont_free = dont_free;
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
	file->id = (path->value[path->len-2] << 8) | path->value[path->len-1];
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
		if (!df->path.len && !df->path.aid.len) {
			parse_error(cur, "No path/fileid set for parent DF\n");
			return 1;
		}
		if (df->path.len + 2 > sizeof(df->path.value)) {
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

	if (get_uint_eval(cur, argc, argv, &size))
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
do_content(struct state *cur, int argc, char **argv)
{
	struct sc_file *file = cur->file->file;
	size_t len = (strlen(argv[0]) + 1) / 2;
	int rv = 0;

	file->encoded_content = malloc(len);
	if (!file->encoded_content)
		return 1;
	rv = sc_hex_to_bin(argv[0], file->encoded_content, &len);
	file->encoded_content_len = len;
	return rv;
}

static int
do_prop_attr(struct state *cur, int argc, char **argv)
{
	struct sc_file *file = cur->file->file;
	size_t len = (strlen(argv[0]) + 1) / 2;
	int rv = 0;

	file->prop_attr = malloc(len);
	if (!file->prop_attr)
		return 1;
	rv = sc_hex_to_bin(argv[0], file->prop_attr, &len);
	file->prop_attr_len = len;
	return rv;
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
	}
	else {
		file->namelen = sizeof(file->name);
		res = sc_hex_to_bin(name, file->name, &file->namelen);
	}
	return res;
}

static int
do_exclusive_aid(struct state *cur, int argc, char **argv)
{
	struct sc_file	*file = cur->file->file;
	const char	*name = argv[0];
	unsigned int	len;
	int		res = 0;

#ifdef DEBUG_PROFILE
	printf("do_exclusive_aid(): exclusive-aid '%s'\n", name);
	printf("do_exclusive_aid(): current file '%s' (path:%s)\n", cur->file->ident, sc_print_path(&file->path));
#endif
	sc_format_path(name, &file->path);
	if (file->path.len > SC_MAX_AID_SIZE)   {
		parse_error(cur, "Path length is too big\n");
		return 1;
	}

	memcpy(file->path.aid.value, file->path.value, file->path.len);
	file->path.aid.len = file->path.len;

	file->path.len = 0;
	file->path.type = SC_PATH_TYPE_DF_NAME;

#ifdef DEBUG_PROFILE
	printf("do_exclusive_aid(): '%s' exclusive-aid path %s\n", cur->file->ident, sc_print_path(&file->path));
#endif
	if (*name == '=') {
		len = strlen(++name);
		if (len > sizeof(file->name)) {
			parse_error(cur, "AID \"%s\" too long\n", name);
			return 1;
		}
		memcpy(file->name, name, len);
		file->namelen = len;
	}
	else {
		file->namelen = sizeof(file->name);
		res = sc_hex_to_bin(name, file->name, &file->namelen);
	}
	return res;
}

static int
do_profile_extension(struct state *cur, int argc, char **argv)
{
	return setstr(&cur->file->profile_extension, argv[0]);
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
	char		oper[64], *what = NULL;

	memset(oper, 0, sizeof(oper));
	while (argc--) {
		unsigned int	op, method, id;

		strlcpy(oper, *argv++, sizeof(oper));
		if ((what = strchr(oper, '=')) == NULL)
			goto bad;
		*what++ = '\0';

		if (*what == '$') {
			method = SC_AC_SYMBOLIC;
			if (map_str2int(cur, what+1, &id, pinIdNames))
				return 1;
		}
		else if (get_authid(cur, what, &method, &id))
			goto bad;


		if (!strcmp(oper, "*")) {
			for (op = 0; op < SC_MAX_AC_OPS; op++) {
				sc_file_clear_acl_entries(file, op);
				sc_file_add_acl_entry(file, op, method, id);
			}
		} else {
			const sc_acl_entry_t *acl;

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
	state.pin = new_pin(cur->profile, (int)id);

	return process_block(&state, info, name, blk);
}

static struct pin_info *
new_pin(struct sc_profile *profile, int id)
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
	pi = calloc(1, sizeof(*pi));
	if (pi == NULL)
		return NULL;
	pi->id = id;
	pi->pin.auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;
	pi->pin.auth_method = SC_AC_CHV;
	pi->pin.attrs.pin.type = (unsigned int)-1;
	pi->pin.attrs.pin.flags = 0x32;
	pi->pin.attrs.pin.max_length = 0;
	pi->pin.attrs.pin.min_length = 0;
	pi->pin.attrs.pin.stored_length = 0;
	pi->pin.attrs.pin.pad_char = 0xA5;
	pi->pin.attrs.pin.reference = -1;
	pi->pin.tries_left = 3;

	*tail = pi;
	return pi;
}

static void set_pin_defaults(struct sc_profile *profile, struct pin_info *pi)
{
	struct sc_pkcs15_auth_info *info = &pi->pin;
	struct sc_pkcs15_pin_attributes *pin_attrs = &info->attrs.pin;

	info->auth_type = SC_PKCS15_PIN_AUTH_TYPE_PIN;

	if (pin_attrs->type == (unsigned int) -1)
		pin_attrs->type = profile->pin_encoding;
	if (pin_attrs->max_length == 0)
		pin_attrs->max_length = profile->pin_maxlen;
	if (pin_attrs->min_length == 0)
		pin_attrs->min_length = profile->pin_minlen;
	if (pin_attrs->stored_length == 0) {
		pin_attrs->stored_length = profile->pin_maxlen;
		/* BCD encoded PIN takes half the space */
		if (pin_attrs->type == SC_PKCS15_PIN_TYPE_BCD)
			pin_attrs->stored_length = (pin_attrs->stored_length + 1) / 2;
	}
	if (pin_attrs->pad_char == 0xA5)
		pin_attrs->pad_char = profile->pin_pad_char;
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
do_pin_maxunlocks(struct state *cur, int argc, char **argv)
{
	struct pin_info	*pi = cur->pin;
	unsigned int	count;

	if (get_uint(cur, argv[0], &count))
		return 1;
	pi->pin.max_unlocks = count;
	return 0;
}

static int
do_pin_type(struct state *cur, int argc, char **argv)
{
	unsigned int	type;

	if (map_str2int(cur, argv[0], &type, pinTypeNames))
		return 1;
	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;
	cur->pin->pin.attrs.pin.type = type;
	return 0;
}

static int
do_pin_reference(struct state *cur, int argc, char **argv)
{
	unsigned int	reference;

	if (get_uint(cur, argv[0], &reference))
		return 1;
	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;
	cur->pin->pin.attrs.pin.reference = reference;
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
	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;
	cur->pin->pin.attrs.pin.min_length = len;
	return 0;
}

static int
do_pin_maxlength(struct state *cur, int argc, char **argv)
{
	unsigned int	len;

	if (get_uint(cur, argv[0], &len))
		return 1;
	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;
	cur->pin->pin.attrs.pin.max_length = len;
	return 0;
}

static int
do_pin_storedlength(struct state *cur, int argc, char **argv)
{
	unsigned int	len;

	if (get_uint(cur, argv[0], &len))
		return 1;
	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return 1;
	cur->pin->pin.attrs.pin.stored_length = len;
	return 0;
}

static int
do_pin_flags(struct state *cur, int argc, char **argv)
{
	unsigned int	flags;
	int		i, r;

	if (cur->pin->pin.auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return -1;

	cur->pin->pin.attrs.pin.flags = 0;
	for (i = 0; i < argc; i++) {
		if ((r = map_str2int(cur, argv[i], &flags, pinFlagNames)) < 0)
			return r;
		cur->pin->pin.attrs.pin.flags |= flags;
	}

	return 0;
}

static int
process_macros(struct state *cur, struct block *info,
		const char *dummy, scconf_block *blk)
{
	scconf_item	*item;
	const char	*name;

	for (item = blk->items; item; item = item->next) {
		name = item->key;
		if (item->type != SCCONF_ITEM_TYPE_VALUE)
			continue;
#ifdef DEBUG_PROFILE
		printf("Defining %s\n", name);
#endif
		new_macro(cur->profile, name, item->value.list);
	}

	return 0;
}

static void
new_macro(sc_profile_t *profile, const char *name, scconf_list *value)
{
	sc_macro_t	*mac;

	if ((mac = find_macro(profile, name)) == NULL) {
		mac = calloc(1, sizeof(*mac));
		if (mac == NULL)
			return;
		mac->name = strdup(name);
		mac->next = profile->macro_list;
		profile->macro_list = mac;
	}

	mac->value = value;
}

static sc_macro_t *
find_macro(sc_profile_t *profile, const char *name)
{
	sc_macro_t	*mac;

	for (mac = profile->macro_list; mac; mac = mac->next) {
		if (!strcmp(mac->name, name))
			return mac;
	}
	return NULL;
}

/*
 * Key section
 */
static struct command	key_commands[] = {
 { "value",		1,	1,	do_key_value	},
 { NULL, 0, 0, NULL }
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
 { "pin-domains",	1,	1,	do_pin_domains	},
 { "label",		1,	1,	do_card_label	},
 { "manufacturer",	1,	1,	do_card_manufacturer},

 { NULL, 0, 0, NULL }
};

static struct block	ci_blocks[] = {
 { "key",		process_key,	key_commands,	NULL	},

 { NULL, NULL, NULL, NULL }
};

/*
 * Filesystem section
 */
static struct command	fs_commands[] = {
 { "type",		1,	1,	do_file_type	},
 { "path",		1,	1,	do_file_path	},
 { "file-id",		1,	1,	do_fileid	},
 { "structure",		1,	1,	do_structure	},
 { "size",		1,	-1,	do_size		},
 { "record-length",	1,	1,	do_reclength	},
 { "AID",		1,	1,	do_aid		},
 { "ACL",		1,	-1,	do_acl		},
/* AID dependent sub-profile */
 { "profile-extension",	1,	1,	do_profile_extension	},
/* AID of the DFs without file-id */
 { "exclusive-aid",	1,	1,	do_exclusive_aid	},
 { "content",		1,	1,	do_content	},
 { "prop-attr",		1,	1,	do_prop_attr	},

 { NULL, 0, 0, NULL }
};

static struct block	fs_blocks[] = {
 { "DF",		process_df,	fs_commands,	fs_blocks },
 { "EF",		process_ef,	fs_commands,	fs_blocks },
 { "BSO",		process_bso,	fs_commands,	fs_blocks },
 { "template",		process_tmpl,	fs_commands,	fs_blocks },

 { NULL, NULL, NULL, NULL }
};

/*
 * Pin section
 */
static struct command	pi_commands[] = {
 { "file",		1,	1,	do_pin_file		},
 { "offset",		1,	1,	do_pin_offset		},
 { "attempts",		1,	2,	do_pin_attempts		},
 { "encoding",		1,	1,	do_pin_type		},
 { "reference",		1,	1,	do_pin_reference	},
 { "auth-id",		1,	1,	do_pin_authid		},
 { "max-length",	1,	1,	do_pin_maxlength	},
 { "min-length",	1,	1,	do_pin_minlength	},
 { "stored-length",	1,	1,	do_pin_storedlength	},
 { "max-unlocks",	1,	1,	do_pin_maxunlocks	},
 { "flags",		1,	-1,	do_pin_flags		},
 { NULL, 0, 0, NULL }
};

/*
 * pkcs15 dialect section
 */
static struct command	p15_commands[] = {
 { "direct-certificates",	1,	1,	do_direct_certificates },
 { "encode-df-length",		1,	1,	do_encode_df_length },
 { "do-last-update",		1,	1,	do_encode_update_field },
 { "pkcs15-id-style",		1,	1,	do_pkcs15_id_style },
 { "minidriver-support-style",	1,	1,	do_minidriver_support_style },
 { NULL, 0, 0, NULL }
};

static struct block	root_blocks[] = {
 { "filesystem",	process_block,	NULL,		fs_blocks },
 { "cardinfo",		process_block,	ci_commands,	ci_blocks },
 { "pin",		process_pin,	pi_commands,	NULL	},
 { "option",		process_option,	NULL,		root_blocks },
 { "macros",		process_macros,	NULL,		NULL	},
 { "pkcs15",		process_block,	p15_commands,	NULL	},

 { NULL, NULL, NULL, NULL }
};

static struct block	root_ops = {
   "root",		process_block,	NULL,		root_blocks
};

static int
build_argv(struct state *cur, const char *cmdname,
		scconf_list *list, char **argv, unsigned int max)
{
	unsigned int	argc;
	const char	*str;
	sc_macro_t	*mac;
	int		r;

	for (argc = 0; list; list = list->next) {
		if (argc >= max) {
			parse_error(cur, "%s: too many arguments", cmdname);
			return SC_ERROR_INVALID_ARGUMENTS;
		}

		str = list->data;
		if (str[0] != '$') {
			argv[argc++] = list->data;
			continue;
		}

		/* Expand macro reference */
		if (!(mac = find_macro(cur->profile, str + 1))) {
			parse_error(cur, "%s: unknown macro \"%s\"",
					cmdname, str);
			return SC_ERROR_SYNTAX_ERROR;
		}

#ifdef DEBUG_PROFILE
		{
			scconf_list *list;

			printf("Expanding macro %s:", mac->name);
			for (list = mac->value; list; list = list->next)
				printf(" %s", list->data);
			printf("\n");
		}
#endif
		r = build_argv(cur, cmdname, mac->value,
				argv + argc, max - argc);
		if (r < 0)
			return r;

		argc += r;
	}

	return argc;
}

static int
process_command(struct state *cur, struct command *cmd_info, scconf_list *list)
{
	const char	*cmd = cmd_info->name;
	char		*argv[32];
	int		argc, max = 32;

	if (cmd_info->max_args >= 0 && max > cmd_info->max_args)
		max = cmd_info->max_args;

	if ((argc = build_argv(cur, cmd, list, argv, max)) < 0)
		return argc;

	if (argc < cmd_info->min_args) {
		parse_error(cur, "%s: not enough arguments\n", cmd);
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
					parse_error(cur, "Too many name components in block name.");
					return SC_ERROR_SYNTAX_ERROR;
				}
				ident = nlist->data;
			}
#ifdef DEBUG_PROFILE
			printf("Processing %s %s\n", cmd, ident? ident : "");
#endif
			if ((bp = find_block_handler(info->blk_info, cmd))) {
				res = bp->handler(cur, bp, ident, item->value.block);
				continue;
			}
		}
		else if (item->type == SCCONF_ITEM_TYPE_VALUE) {
#ifdef DEBUG_PROFILE
			printf("Processing %s\n", cmd);
#endif
			if ((cp = find_cmd_handler(info->cmd_info, cmd))) {
				res = process_command(cur, cp, item->value.list);
				continue;
			}
		}
		parse_error(cur, "Command \"%s\" not understood in this context.", cmd);
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
sc_profile_find_file(struct sc_profile *pro,
		const sc_path_t *path, const char *name)
{
	struct file_info	*fi;
	unsigned int		len;

	len = path? path->len : 0;
	for (fi = pro->ef_list; fi; fi = fi->next) {
		sc_path_t *fpath = &fi->file->path;

		if (!strcasecmp(fi->ident, name) && fpath->len >= len && !memcmp(fpath->value, path->value, len))
			return fi;
	}
	return NULL;
}


static struct file_info *
sc_profile_find_file_by_path(struct sc_profile *pro, const sc_path_t *path)
{
	struct file_info *fi, *out = NULL;
	struct sc_path *fp_path, *fpp_path;

#ifdef DEBUG_PROFILE
	struct sc_context *ctx = pro->card->ctx;

	sc_log(ctx, "profile's EF list:");
	for (fi = pro->ef_list; fi; fi = fi->next)   {
		sc_log(ctx, "'%s' (path:%s)",  fi->ident, sc_print_path(&fi->file->path));
		sc_log(ctx, "fi parent %p", fi->parent);
		if (fi->parent && fi->parent->file)
			sc_log(ctx, "fi parent path %s", sc_print_path(&fi->parent->file->path));
	}
	sc_log(ctx, "find profile file by path:%s", sc_print_path(path));
#endif

	if (!path || (!path->len && !path->aid.len))
		return NULL;

	for (fi = pro->ef_list; fi; fi = fi->next) {
		fp_path = &fi->file->path;
		fpp_path = fi->parent ? &fi->parent->file->path : NULL;

		if (fp_path->len != path->len)
			continue;
		if (fp_path->len && memcmp(fp_path->value, path->value, path->len))
			continue;

		if (path->aid.len && fp_path->aid.len)   {
			if (memcmp(fp_path->aid.value, path->aid.value, path->aid.len))
				continue;
		}
		else if (path->aid.len && !fp_path->aid.len && fpp_path)   {
			if (fpp_path->type == SC_PATH_TYPE_DF_NAME && fpp_path->len)   {
				if (fpp_path->len != path->aid.len)
					continue;
				if (memcmp(fpp_path->value, path->aid.value, path->aid.len))
					continue;
			}
			else if (fpp_path->aid.len)   {
				if (fpp_path->aid.len != path->aid.len)
					continue;
				if (memcmp(fpp_path->aid.value, path->aid.value, path->aid.len))
					continue;
			}
		}

		out = fi;
	}

#ifdef DEBUG_PROFILE
	sc_log(ctx, "returns (%s)", out ? out->ident: "<null>");
#endif
	return out;
}

int
sc_profile_get_parent(struct sc_profile *profile,
		const char *name, sc_file_t **ret)
{
	struct file_info *fi = NULL;

	if ((fi = sc_profile_find_file(profile, NULL, name)) == NULL)
		return SC_ERROR_FILE_NOT_FOUND;

	if (!fi->parent)
		return SC_ERROR_FILE_NOT_FOUND;

	sc_file_dup(ret, fi->parent->file);
	if (*ret == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	return 0;
}

/*
 * Split up KEY0 or CHV1 into SC_AC_XXX and a number
 */
static int
get_authid(struct state *cur, const char *value,
		unsigned int *type, unsigned int *num)
{
	char	temp[16];
	size_t	n;

	if (isdigit((int) *value)) {
		*num = 0;
		return get_uint(cur, value, type);
	}

	n = strcspn(value, "0123456789x");
	strlcpy(temp, value, (sizeof(temp) > n) ? n + 1 : sizeof(temp));

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
	char	*ep;

	if (strstr(value, "0x") == value)
		*vp = strtoul(value + 2, &ep, 16);
	else if (strstr(value, "x") == value)
		*vp = strtoul(value + 1, &ep, 16);
	else
		*vp = strtoul(value, &ep, 0);
	if (*ep != '\0') {
		parse_error(cur, "invalid integer argument \"%s\"\n", value);
		return 1;
	}
	return 0;
}

static int
get_bool(struct state *cur, const char *value, unsigned int *vp)
{
	if (!strcasecmp(value, "on")
	 || !strcasecmp(value, "yes")
	 || !strcasecmp(value, "true")) {
		*vp = 1;
	} else
	if (!strcasecmp(value, "off")
	 || !strcasecmp(value, "no")
	 || !strcasecmp(value, "false")) {
		*vp = 0;
	} else {
		parse_error(cur, "invalid boolean argument \"%s\"\n", value);
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
	return SC_ERROR_SYNTAX_ERROR;
}

static int
setstr(char **strp, const char *value)
{
	if (*strp)
		free(*strp);
	*strp = strdup(value);
	return 0;
}

/*
 * Evaluate numeric expressions
 */
#include <setjmp.h>

struct num_exp_ctx {
	struct state *	state;
	jmp_buf		error;

	int		j;
	char		word[64];

	char *		unget;
	char *		str;
	int		argc;
	char **		argv;
};

static void	expr_eval(struct num_exp_ctx *, unsigned int *, unsigned int);

static void
expr_fail(struct num_exp_ctx *ctx)
{
	longjmp(ctx->error, 1);
}

static void
expr_put(struct num_exp_ctx *ctx, int c)
{
	if (ctx->j >= (int)sizeof(ctx->word))
		expr_fail(ctx);
	ctx->word[ctx->j++] = (char)c;
}

static char *
__expr_get(struct num_exp_ctx *ctx, int eof_okay)
{
	char	*s;

	if ((s = ctx->unget) != NULL) {
		ctx->unget = NULL;
		return s;
	}

	ctx->j = 0;
	do {
		if ((s = ctx->str) == NULL || *s == '\0') {
			if (ctx->argc == 0) {
				if (eof_okay)
					return NULL;
				expr_fail(ctx);
			}
			ctx->str = s = *(ctx->argv++);
			ctx->argc--;
		}

		while (isspace(*s))
			s++;
	} while (*s == '\0');

	if (isdigit(*s)) {
		while (isdigit(*s))
			expr_put(ctx, *s++);
	}
	else if (*s == '$') {
		expr_put(ctx, *s++);
		while (isalnum(*s) || *s == '-' || *s == '_')
			expr_put(ctx, *s++);
	}
	else if (strchr("*/+-()|&", *s)) {
		expr_put(ctx, *s++);
	}
	else {
		expr_fail(ctx);
	}
	ctx->str = s;

	expr_put(ctx, '\0');
	return ctx->word;
}

static char *
expr_get(struct num_exp_ctx *ctx)
{
	return __expr_get(ctx, 0);
}

static void
expr_unget(struct num_exp_ctx *ctx, char *s)
{
	if (ctx->unget)
		expr_fail(ctx);
	ctx->unget = s;
}

static void
expr_expect(struct num_exp_ctx *ctx, int c)
{
	char	*tok;

	tok = expr_get(ctx);
	if (tok[0] != (char)c || tok[1])
		expr_fail(ctx);
}

static void
expr_term(struct num_exp_ctx *ctx, unsigned int *vp)
{
	char	*tok;

	tok = expr_get(ctx);
	if (*tok == '(') {
		expr_eval(ctx, vp, 1);
		expr_expect(ctx, ')');
	}
	else if (isdigit(*tok)) {
		char	*ep;

		*vp = strtoul(tok, &ep, 0);
		if (*ep)
			expr_fail(ctx);
	}
	else if (*tok == '$') {
		sc_macro_t	*mac;
		char		*argv[32];
		int		argc;

		if (!(mac = find_macro(ctx->state->profile, tok + 1)))
			expr_fail(ctx);
		argc = build_argv(ctx->state, "<expr>", mac->value, argv, 32);
		if (argc < 0 || get_uint_eval(ctx->state, argc, argv, vp) < 0)
			expr_fail(ctx);
	}
	else {
		parse_error(ctx->state, "Unexpected token \"%s\" in expression", tok);
		expr_fail(ctx);
	}
}

static void
expr_eval(struct num_exp_ctx *ctx, unsigned int *vp, unsigned int pri)
{
	unsigned int	left, right, new_pri;
	char		*tok, op;

	expr_term(ctx, &left);

	while (1) {
		tok = __expr_get(ctx, 1);
		if (tok == NULL)
			break;

		op = tok[0];

		new_pri = 0;
		switch (op) {
		case '*':
		case '/':
			new_pri++;
			/* fall through */
		case '+':
		case '-':
			new_pri++;
			/* fall through */
		case '&':
			new_pri++;
			/* fall through */
		case '|':
			new_pri++;
			/* fall through */
		case ')':
			break;
		default:
			expr_fail(ctx);
		}

		if (new_pri < pri) {
			expr_unget(ctx, tok);
			break;
		}
		pri = new_pri;

		expr_eval(ctx, &right, new_pri + 1);
		switch (op) {
		case '*': left *= right; break;
		case '/': left /= right; break;
		case '+': left += right; break;
		case '-': left -= right; break;
		case '&': left &= right; break;
		case '|': left |= right; break;
		default: expr_fail(ctx);
		}
	}

	*vp = left;
}

static int
get_uint_eval(struct state *cur, int argc, char **argv, unsigned int *vp)
{
	struct num_exp_ctx	ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.state = cur;
	ctx.argc  = argc;
	ctx.argv  = argv;

	if (setjmp(ctx.error)) {
		parse_error(cur, "invalid numeric expression\n");
		return SC_ERROR_SYNTAX_ERROR;
	}

	expr_eval(&ctx, vp, 0);
	if (ctx.str[0] || ctx.argc)
		expr_fail(&ctx);

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

	if (cur->profile->card && cur->profile->card->ctx)
		sc_log(cur->profile->card->ctx, "%s: %s", cur->filename, buffer);
	else
		fprintf(stdout, "%s: %s\n", cur->filename, buffer);
}
