/*
 * ctx.c: Context related functions
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

int _sc_add_reader(struct sc_context *ctx, struct sc_reader *reader)
{
	assert(reader != NULL);
	reader->ctx = ctx;
	if (ctx->reader_count == SC_MAX_READERS)
		return SC_ERROR_TOO_MANY_OBJECTS;
	ctx->reader[ctx->reader_count] = reader;
	ctx->reader_count++;
	
	return 0;
}

struct _sc_driver_entry {
	char *name;
	void *func;
	char *libpath;
	struct sc_atr_table *atrs;
	unsigned int natrs;
};

static const struct _sc_driver_entry internal_card_drivers[] = {
	{ "emv", (void *) sc_get_emv_driver, NULL },
	{ "etoken", (void *) sc_get_etoken_driver, NULL },
	{ "flex", (void *) sc_get_flex_driver, NULL },
#ifdef HAVE_OPENSSL
	{ "gpk", (void *) sc_get_gpk_driver, NULL },
#endif
	{ "miocos", (void *) sc_get_miocos_driver, NULL },
	{ "mcrd", (void *) sc_get_mcrd_driver, NULL },
	{ "setcos", (void *) sc_get_setcos_driver, NULL },
	{ "starcos", (void *) sc_get_starcos_driver, NULL },
	{ "tcos", (void *) sc_get_tcos_driver, NULL },
	/* The default driver should be last, as it handles all the
	 * unrecognized cards. */
	{ "default", (void *) sc_get_default_driver, NULL },
	{ NULL, NULL, NULL }
};

static const struct _sc_driver_entry internal_reader_drivers[] = {
#if defined(HAVE_PCSC)
	{ "pcsc", (void *) sc_get_pcsc_driver, NULL },
#endif
#ifndef _WIN32
	{ "ctapi", (void *) sc_get_ctapi_driver, NULL },
#ifdef HAVE_OPENCT
	{ "openct", (void *) sc_get_openct_driver, NULL },
#endif
#ifdef HAVE_USBTOKEN
	{ "usbtoken", (void *) sc_get_usbtoken_driver, NULL },
#endif
#endif
	{ NULL, NULL, NULL }
};

struct _sc_ctx_options {
	struct _sc_driver_entry rdrv[16];
	int rcount;
	struct _sc_driver_entry cdrv[16];
	int ccount;
	char *forced_card_driver;
};


static void del_drvs(struct _sc_ctx_options *opts, int type)
{
	struct _sc_driver_entry *lst;
	int *cp, i;
	
	if (type == 0) {
		lst = opts->rdrv;
		cp = &opts->rcount;
	} else {
		lst = opts->cdrv;
		cp = &opts->ccount;
	}
	for (i = 0; i < *cp; i++) {
		free(lst[i].name);
		if (lst[i].libpath)
			free(lst[i].libpath);
	}
	*cp = 0;
}

static void add_drv(struct _sc_ctx_options *opts, int type, const char *name)
{
	struct _sc_driver_entry *lst;
	int *cp, i;
	
	if (type == 0) {
		lst = opts->rdrv;
		cp = &opts->rcount;
	} else {
		lst = opts->cdrv;
		cp = &opts->ccount;
	}
	if (*cp == 16) /* No space for more drivers... */
		return;
	for (i = 0; i < *cp; i++)
		if (strcmp(name, lst[i].name) == 0)
			return;
	lst[*cp].name = strdup(name);

	*cp = *cp + 1;
}

static void add_internal_drvs(struct _sc_ctx_options *opts, int type)
{
	const struct _sc_driver_entry *lst;
	int i;
	
	if (type == 0)
		lst = internal_reader_drivers;
	else
		lst = internal_card_drivers;
	i = 0;
	while (lst[i].name != NULL) {
		add_drv(opts, type, lst[i].name);
		i++;
	}
}

static void set_defaults(struct sc_context *ctx, struct _sc_ctx_options *opts)
{
	ctx->debug = 0;
	if (ctx->debug_file && ctx->debug_file != stdout)
		fclose(ctx->debug_file);
	ctx->debug_file = stdout;
	ctx->log_errors = 1;
	if (ctx->error_file && ctx->error_file != stderr)
		fclose(ctx->error_file);
	ctx->error_file = stderr;
	ctx->forced_driver = NULL;
	add_internal_drvs(opts, 0);
	add_internal_drvs(opts, 1);
}

static int load_parameters(struct sc_context *ctx, scconf_block *block,
			   struct _sc_ctx_options *opts)
{
	int err = 0;
	const scconf_list *list;
	const char *val;
	const char *s_internal = "internal";
 
	ctx->debug = scconf_get_int(block, "debug", ctx->debug);
	val = scconf_get_str(block, "debug_file", NULL);
	if (val) {
		if (ctx->debug_file && ctx->debug_file != stdout)
			fclose(ctx->debug_file);
		if (strcmp(val, "stdout") != 0)
			ctx->debug_file = fopen(val, "a");
		else
			ctx->debug_file = stdout;
	}
	val = scconf_get_str(block, "error_file", NULL);
	if (val) {
		if (ctx->error_file && ctx->error_file != stderr)
			fclose(ctx->error_file);
		if (strcmp(val, "stderr") != 0)
			ctx->error_file = fopen(val, "a");
		else
			ctx->error_file = stderr;
	}
	val = scconf_get_str(block, "force_card_driver", NULL);
	if (val) {
		if (opts->forced_card_driver)
			free(opts->forced_card_driver);
		opts->forced_card_driver = strdup(val);
	}
	list = scconf_find_list(block, "reader_drivers");
	if (list != NULL)
		del_drvs(opts, 0);
	while (list != NULL) {
		if (strcmp(list->data, s_internal) == 0)
			add_internal_drvs(opts, 1);
		else
			add_drv(opts, 0, list->data);
		list = list->next;
	}

	list = scconf_find_list(block, "card_drivers");
	if (list != NULL)
		del_drvs(opts, 1);
	while (list != NULL) {
		if (strcmp(list->data, s_internal) == 0)
			add_internal_drvs(opts, 1);
		else
			add_drv(opts, 1, list->data);
		list = list->next;
	}

	return err;
}

static int load_reader_drivers(struct sc_context *ctx,
			       struct _sc_ctx_options *opts)
{
	const struct _sc_driver_entry *ent;
	int drv_count;
	int i;

	for (drv_count = 0; ctx->reader_drivers[drv_count] != NULL; drv_count++);

	for (i = 0; i < opts->rcount; i++) {
		const struct sc_reader_driver * (* func)(void) = NULL;
		int j;

		ent = &opts->rdrv[i];
		for (j = 0; internal_reader_drivers[j].name != NULL; j++)
			if (strcmp(ent->name, internal_reader_drivers[j].name) == 0) {
				func = (const struct sc_reader_driver * (*)(void)) internal_reader_drivers[j].func;
				break;
			}
		if (func == NULL) {
			/* External driver */
			/* FIXME: Load shared library */
			sc_error(ctx, "Unable to load '%s'. External drivers not supported yet.\n",
			      ent->name);
			continue;
		}
		ctx->reader_drivers[drv_count] = func();
		ctx->reader_drivers[drv_count]->ops->init(ctx, &ctx->reader_drv_data[i]);
                drv_count++;
	}
	return 0;	
}			     

static int load_card_driver_options(struct sc_context *ctx,
				    struct sc_card_driver *driver)
{
	scconf_block **blocks, *blk;
	const scconf_list *list;
	int i, r;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		u8	atr_buf[SC_MAX_ATR_SIZE];
		size_t	atr_len;

		blocks = scconf_find_blocks(ctx->conf,
					ctx->conf_blocks[i],
					"card_driver", driver->short_name);
		blk = blocks[0];
		free(blocks);

		if (blk == NULL)
			continue;

		list = scconf_find_list(blk, "atr");
		while (list != NULL) {
			atr_len = sizeof(atr_buf);
			r = sc_hex_to_bin(list->data,
					atr_buf, &atr_len);
			if (r < 0) {
				sc_error(ctx,
				      "Unable to parse ATR '%s'.\n",
				      list->data);
				continue;
			}
			_sc_add_atr(driver, atr_buf, atr_len, 0);
			list = list->next;
		}
	}

	return 0;
}

static int load_card_drivers(struct sc_context *ctx,
			     struct _sc_ctx_options *opts)
{
	const struct _sc_driver_entry *ent;
	int drv_count;
	int i;

	for (drv_count = 0; ctx->card_drivers[drv_count] != NULL; drv_count++);

	for (i = 0; i < opts->ccount; i++) {
		struct sc_card_driver * (* func)(void) = NULL;
		int j;

		ent = &opts->cdrv[i];
		for (j = 0; internal_card_drivers[j].name != NULL; j++)
			if (strcmp(ent->name, internal_card_drivers[j].name) == 0) {
				func = (struct sc_card_driver * (*)(void)) internal_card_drivers[j].func;
				break;
			}
		if (func == NULL) {
			/* External driver */
			/* FIXME: Load shared library */
			sc_error(ctx, "Unable to load '%s'. External drivers not supported yet.\n",
			      ent->name);
			continue;
		}
		ctx->card_drivers[drv_count] = func();

		load_card_driver_options(ctx, ctx->card_drivers[drv_count]);
                drv_count++;
	}
	return 0;	
}

void process_config_file(struct sc_context *ctx, struct _sc_ctx_options *opts)
{
	int i, r, count = 0;
	scconf_block **blocks;
	char *conf_path = OPENSC_CONF_PATH;
#ifdef _WIN32
	char temp_path[PATH_MAX];
#endif

	memset(ctx->conf_blocks, 0, sizeof(ctx->conf_blocks));
#ifdef _WIN32
	if (!strncmp(conf_path, "%windir%", 8)) {
		GetWindowsDirectory(temp_path, sizeof(temp_path));
		strncat(temp_path, conf_path + 8, sizeof(temp_path) - strlen(temp_path));
		conf_path = temp_path;
	}
#endif
	ctx->conf = scconf_new(conf_path);
	if (ctx->conf == NULL)
		return;
	r = scconf_parse(ctx->conf);
#ifdef OPENSC_CONFIG_STRING
	if (r < 1)
		r = scconf_parse_string(ctx->conf, OPENSC_CONFIG_STRING);
#endif
	if (r < 1) {
		scconf_free(ctx->conf);
		ctx->conf = NULL;
		return;
	}
	blocks = scconf_find_blocks(ctx->conf, NULL, "app", ctx->app_name);
	if (blocks[0])
	    	ctx->conf_blocks[count++] = blocks[0];
	free(blocks);
	if (strcmp(ctx->app_name, "default") != 0) {
		blocks = scconf_find_blocks(ctx->conf, NULL, "app", "default");
		if (blocks[0])
		    	ctx->conf_blocks[count++] = blocks[0];
		free(blocks);
	}
	/* Above we add 2 blocks at most, but conf_blocks has 3 elements,
	 * so at least one is NULL */
	for (i = 0; ctx->conf_blocks[i]; i++)
		load_parameters(ctx, ctx->conf_blocks[i], opts);
}

int sc_establish_context(struct sc_context **ctx_out, const char *app_name)
{
	const char *default_app = "default";
	struct sc_context *ctx;
	struct _sc_ctx_options opts;

	assert(ctx_out != NULL);
	ctx = (struct sc_context *) malloc(sizeof(struct sc_context));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(ctx, 0, sizeof(struct sc_context));
	memset(&opts, 0, sizeof(opts));
	set_defaults(ctx, &opts);
	ctx->app_name = app_name ? strdup(app_name) : strdup(default_app);
	process_config_file(ctx, &opts);
	ctx->mutex = sc_mutex_new();
	sc_debug(ctx, "===================================\n"); /* first thing in the log */
	load_reader_drivers(ctx, &opts);
	load_card_drivers(ctx, &opts);
	if (opts.forced_card_driver) {
		sc_set_card_driver(ctx, opts.forced_card_driver);
		free(opts.forced_card_driver);
	}		
	del_drvs(&opts, 0);
	del_drvs(&opts, 1);
	if (ctx->reader_count == 0) {
		sc_release_context(ctx);
		return SC_ERROR_NO_READERS_FOUND;
	}
	*ctx_out = ctx;
	return 0;
}

int sc_release_context(struct sc_context *ctx)
{
	int i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, 1);
	for (i = 0; i < ctx->reader_count; i++) {
		struct sc_reader *rdr = ctx->reader[i];
		
		if (rdr->ops->release != NULL)
			rdr->ops->release(rdr);
		free(rdr->name);
		free(rdr);
	}
	for (i = 0; ctx->reader_drivers[i] != NULL; i++) {
		const struct sc_reader_driver *drv = ctx->reader_drivers[i];
		
		if (drv->ops->finish != NULL)
			drv->ops->finish(ctx, ctx->reader_drv_data[i]);
	}
	ctx->debug_file = ctx->error_file = NULL;
	if (ctx->conf)
		scconf_free(ctx->conf);
	sc_mutex_free(ctx->mutex);
	free(ctx->app_name);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

int sc_set_card_driver(struct sc_context *ctx, const char *short_name)
{
	int i = 0, match = 0;
	
	sc_mutex_lock(ctx->mutex);
	if (short_name == NULL) {
		ctx->forced_driver = NULL;
		match = 1;
	} else while (ctx->card_drivers[i] != NULL && i < SC_MAX_CARD_DRIVERS) {
		struct sc_card_driver *drv = ctx->card_drivers[i];

		if (strcmp(short_name, drv->short_name) == 0) {
			ctx->forced_driver = drv;
			match = 1;
			break;
		}
		i++;
	}
	sc_mutex_unlock(ctx->mutex);
	if (match == 0)
		return SC_ERROR_OBJECT_NOT_FOUND; /* FIXME: invent error */
	return 0;
}

int sc_get_cache_dir(struct sc_context *ctx, char *buf, size_t bufsize)
{
	char *homedir;
	const char *cache_dir;
#ifdef _WIN32
	char temp_path[PATH_MAX];
#endif

#ifndef _WIN32
	cache_dir = ".eid/cache";
	homedir = getenv("HOME");
#else
	cache_dir = "eid-cache";
	homedir = getenv("USERPROFILE");
	/* If USERPROFILE isn't defined, assume it's a single-user OS
	 * and put the cache dir in the Windows dir (usually C:\\WINDOWS) */
	if (homedir == NULL || homedir[0] == '\0') {
		GetWindowsDirectory(temp_path, sizeof(temp_path));
		homedir = temp_path;
	}
#endif
	if (homedir == NULL)
		return SC_ERROR_INTERNAL;
	if (snprintf(buf, bufsize, "%s/%s", homedir, cache_dir) < 0)
		return SC_ERROR_BUFFER_TOO_SMALL;
	return 0;
}

int sc_make_cache_dir(struct sc_context *ctx)
{
	char dirname[PATH_MAX], *sp;
	int r, j, namelen;

	if ((r = sc_get_cache_dir(ctx, dirname, sizeof(dirname))) < 0)
		return r;
	namelen = strlen(dirname);

	while (1) {
		if (mkdir(dirname, 0700) >= 0)
			break;
		if (errno != ENOENT
		 || (sp = strrchr(dirname, '/')) == NULL
		 || sp == dirname)
			goto failed;
		*sp = '\0';
	}

	/* We may have stripped one or more path components from
	 * the directory name. Restore them */
	while (1) {
		j = strlen(dirname);
		if (j >= namelen)
			break;
		dirname[j] = '/';
		if (mkdir(dirname, 0700) < 0)
			goto failed;
	}
	return 0;

	/* for lack of a better return code */
failed:	sc_error(ctx, "failed to create cache directory\n");
	return SC_ERROR_INTERNAL;
}
