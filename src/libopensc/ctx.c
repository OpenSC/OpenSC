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
#include <ltdl.h>

#ifdef _WIN32
#include <winreg.h>
#endif

int _sc_add_reader(sc_context_t *ctx, sc_reader_t *reader)
{
	assert(reader != NULL);
	reader->ctx = ctx;
	if (ctx->reader_count == SC_MAX_READERS)
		return SC_ERROR_TOO_MANY_OBJECTS;
	ctx->reader[ctx->reader_count] = reader;
	ctx->reader_count++;

	return SC_SUCCESS;
}

struct _sc_driver_entry {
	char *name;
	void *(*func)(void);
};

static const struct _sc_driver_entry internal_card_drivers[] = {
	/* legacy, the old name was "etoken", so we keep that for a while */
	{ "cardos",	(void *(*)(void)) sc_get_cardos_driver },
	{ "etoken",	(void *(*)(void)) sc_get_cardos_driver },
	{ "flex",	(void *(*)(void)) sc_get_cryptoflex_driver },
	{ "cyberflex",	(void *(*)(void)) sc_get_cyberflex_driver },
#ifdef ENABLE_OPENSSL
	{ "gpk",	(void *(*)(void)) sc_get_gpk_driver },
#endif
	{ "gemsafeV1",	(void *(*)(void)) sc_get_gemsafeV1_driver },
	{ "miocos",	(void *(*)(void)) sc_get_miocos_driver },
	{ "mcrd",	(void *(*)(void)) sc_get_mcrd_driver },
	{ "asepcos",	(void *(*)(void)) sc_get_asepcos_driver },
	{ "setcos",	(void *(*)(void)) sc_get_setcos_driver },
	{ "starcos",	(void *(*)(void)) sc_get_starcos_driver },
	{ "tcos",	(void *(*)(void)) sc_get_tcos_driver },
	{ "opengpg",	(void *(*)(void)) sc_get_openpgp_driver },
	{ "jcop",	(void *(*)(void)) sc_get_jcop_driver },
#ifdef ENABLE_OPENSSL
	{ "oberthur",	(void *(*)(void)) sc_get_oberthur_driver },
#endif
	{ "belpic",	(void *(*)(void)) sc_get_belpic_driver },
	{ "atrust-acos",(void *(*)(void)) sc_get_atrust_acos_driver },
	{ "muscle", (void *(*)(void)) sc_get_muscle_driver },
	{ "incrypto34", (void *(*)(void)) sc_get_incrypto34_driver },
#ifdef ENABLE_OPENSSL
	{ "PIV-II",	(void *(*)(void)) sc_get_piv_driver },
#endif
	{ "acos5",	(void *(*)(void)) sc_get_acos5_driver },
	{ "akis",	(void *(*)(void)) sc_get_akis_driver },
#ifdef ENABLE_OPENSSL
	{ "entersafe",(void *(*)(void)) sc_get_entersafe_driver },
#endif
	{ "rutoken",	(void *(*)(void)) sc_get_rutoken_driver }, 
	{ "rutoken_ecp",(void *(*)(void)) sc_get_rtecp_driver },
	/* emv is not really used, not sure if it works, but it conflicts with
           muscle and rutoken driver, thus has to be after them */
	{ "emv",	(void *(*)(void)) sc_get_emv_driver },
	/* The default driver should be last, as it handles all the
	 * unrecognized cards. */
	{ "default",	(void *(*)(void)) sc_get_default_driver },
	{ NULL, NULL }
};

static const struct _sc_driver_entry internal_reader_drivers[] = {
#if defined(ENABLE_PCSC)
	{ "pcsc",	(void *(*)(void)) sc_get_pcsc_driver },
#endif
	{ "ctapi",	(void *(*)(void)) sc_get_ctapi_driver },
#ifndef _WIN32
#ifdef ENABLE_OPENCT
	{ "openct",	(void *(*)(void)) sc_get_openct_driver },
#endif
#endif
	{ NULL, NULL }
};

struct _sc_ctx_options {
	struct _sc_driver_entry rdrv[SC_MAX_READER_DRIVERS];
	int rcount;
	struct _sc_driver_entry cdrv[SC_MAX_CARD_DRIVERS];
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
	}
	*cp = 0;
}

static void add_drv(struct _sc_ctx_options *opts, int type, const char *name)
{
	struct _sc_driver_entry *lst;
	int *cp, max, i;

	if (type == 0) {
		lst = opts->rdrv;
		cp = &opts->rcount;
		max = SC_MAX_READER_DRIVERS;
	} else {
		lst = opts->cdrv;
		cp = &opts->ccount;
		max = SC_MAX_CARD_DRIVERS;
	}
	if (*cp == max) /* No space for more drivers... */
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

static void set_defaults(sc_context_t *ctx, struct _sc_ctx_options *opts)
{
	ctx->debug = 0;
	if (ctx->debug_file && ctx->debug_file != stdout)
		fclose(ctx->debug_file);
	ctx->debug_file = stdout;
	ctx->suppress_errors = 0;
	if (ctx->error_file && ctx->error_file != stderr)
		fclose(ctx->error_file);
	ctx->error_file = stderr;
	ctx->forced_driver = NULL;
	add_internal_drvs(opts, 0);
	add_internal_drvs(opts, 1);
}

static int load_parameters(sc_context_t *ctx, scconf_block *block,
			   struct _sc_ctx_options *opts)
{
	int err = 0;
	const scconf_list *list;
	const char *val, *s_internal = "internal";
    const char *debug = NULL;

	ctx->debug = scconf_get_int(block, "debug", ctx->debug);
	debug = getenv("OPENSC_DEBUG");
	if (debug)
		ctx->debug = atoi(debug);

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
			add_internal_drvs(opts, 0);
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

	val = scconf_get_str(block, "preferred_language", "en");
	if (val)
		sc_ui_set_language(ctx, val);

	return err;
}

static void load_reader_driver_options(sc_context_t *ctx,
			struct sc_reader_driver *driver)
{
	const char	*name = driver->short_name;
	scconf_block	*conf_block = NULL;
	int		i;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		scconf_block **blocks;

		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					    "reader_driver", name);
		if (blocks) {
			conf_block = blocks[0];
			free(blocks);
		}
		if (conf_block != NULL)
			break;
	}

	driver->max_send_size = SC_DEFAULT_MAX_SEND_SIZE;
	driver->max_recv_size = SC_DEFAULT_MAX_RECV_SIZE;
	if (conf_block != NULL) {
		driver->max_send_size = scconf_get_int(conf_block,
			"max_send_size", SC_DEFAULT_MAX_SEND_SIZE);
		driver->max_recv_size = scconf_get_int(conf_block,
			"max_recv_size", SC_DEFAULT_MAX_RECV_SIZE);
	}
}

/**
 * find library module for provided driver in configuration file
 * if not found assume library name equals to module name
 */
static const char *find_library(sc_context_t *ctx, const char *name, int type)
{
	int          i;
	const char   *libname = NULL;
	scconf_block **blocks, *blk;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
			(type==0) ? "reader_driver" : "card_driver", name);
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;
		libname = scconf_get_str(blk, "module", name);
#ifdef _WIN32
		if (libname && libname[0] != '\\' ) {
#else
		if (libname && libname[0] != '/' ) {
#endif
			sc_debug(ctx, "warning: relative path to driver '%s' used\n",
				 libname);
		}
		break;
	}

	return libname;
}

/**
 * load card/reader driver modules
 * Every module should contain a function " void * sc_module_init(char *) "
 * that returns a pointer to the function _sc_get_xxxx_driver()
 * used to initialize static modules
 * Also, an exported "char *sc_module_version" variable should exist in module
 *
 * type == 0 -> reader driver
 * type == 1 -> card driver
 */
static void *load_dynamic_driver(sc_context_t *ctx, void **dll,
	const char *name, int type)
{
	const char *version, *libname;
	lt_dlhandle handle;
	void *(*modinit)(const char *) = NULL;
	void *(**tmodi)(const char *) = &modinit;
	const char *(*modversion)(void) = NULL;
	const char *(**tmodv)(void) = &modversion;

	if (name == NULL) { /* should not occurr, but... */
		sc_error(ctx,"No module specified\n",name);
		return NULL;
	}
	libname = find_library(ctx, name, type);
	if (libname == NULL)
		return NULL;
	handle = lt_dlopen(libname);
	if (handle == NULL) {
		sc_error(ctx, "Module %s: cannot load %s library: %s\n", name, libname, lt_dlerror());
		return NULL;
	}

	/* verify correctness of module */
	*(void **)tmodi = lt_dlsym(handle, "sc_module_init");
	*(void **)tmodv = lt_dlsym(handle, "sc_driver_version");
	if (modinit == NULL || modversion == NULL) {
		sc_error(ctx, "dynamic library '%s' is not a OpenSC module\n",libname);
		lt_dlclose(handle);
		return NULL;
	}
	/* verify module version */
	version = modversion();
	/* XXX: We really need to have ABI version for each interface */
	if (version == NULL || strncmp(version, PACKAGE_VERSION, strlen(PACKAGE_VERSION)) != 0) {
		sc_error(ctx,"dynamic library '%s': invalid module version\n",libname);
		lt_dlclose(handle);
		return NULL;
	}
	*dll = handle;
	sc_debug(ctx, "successfully loaded %s driver '%s'\n",
		type ? "card" : "reader", name);
	return modinit(name);
}

static int load_reader_drivers(sc_context_t *ctx,
			       struct _sc_ctx_options *opts)
{
	const struct _sc_driver_entry *ent;
	int drv_count;
	int i;

	for (drv_count = 0; ctx->reader_drivers[drv_count] != NULL; drv_count++);

	for (i = 0; i < opts->rcount; i++) {
		struct sc_reader_driver *driver;
		struct sc_reader_driver *(*func)(void) = NULL;
		struct sc_reader_driver *(**tfunc)(void) = &func;
		int  j;
		void *dll = NULL;

		ent = &opts->rdrv[i];
		for (j = 0; internal_reader_drivers[j].name != NULL; j++)
			if (strcmp(ent->name, internal_reader_drivers[j].name) == 0) {
				func = (struct sc_reader_driver *(*)(void)) internal_reader_drivers[j].func;
				break;
			}
		/* if not initialized assume external module */
		if (func == NULL)
			*(void**)(tfunc) = load_dynamic_driver(ctx, &dll, ent->name, 0);
		/* if still null, assume driver not found */
		if (func == NULL) {
			sc_error(ctx, "Unable to load '%s'.\n", ent->name);
			continue;
		}
		driver = func();
		driver->dll = dll;
		load_reader_driver_options(ctx, driver);
		driver->ops->init(ctx, &ctx->reader_drv_data[i]);

		ctx->reader_drivers[drv_count] = driver;
		drv_count++;
	}
	return SC_SUCCESS;
}

static int load_card_driver_options(sc_context_t *ctx,
				    struct sc_card_driver *driver)
{
	scconf_block **blocks, *blk;
	int i;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf,
					ctx->conf_blocks[i],
					"card_driver", driver->short_name);
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);

		if (blk == NULL)
			continue;

		/* no options at the moment */
	}
	return SC_SUCCESS;
}

static int load_card_drivers(sc_context_t *ctx,
			     struct _sc_ctx_options *opts)
{
	const struct _sc_driver_entry *ent;
	int drv_count;
	int i;

	for (drv_count = 0; ctx->card_drivers[drv_count] != NULL; drv_count++);

	for (i = 0; i < opts->ccount; i++) {
		struct sc_card_driver *(*func)(void) = NULL;
		struct sc_card_driver *(**tfunc)(void) = &func;
		void *dll = NULL;
		int  j;

		ent = &opts->cdrv[i];
		for (j = 0; internal_card_drivers[j].name != NULL; j++)
			if (strcmp(ent->name, internal_card_drivers[j].name) == 0) {
				func = (struct sc_card_driver *(*)(void)) internal_card_drivers[j].func;
				break;
			}
		/* if not initialized assume external module */
		if (func == NULL)
			*(void **)(tfunc) = load_dynamic_driver(ctx, &dll, ent->name, 1);
		/* if still null, assume driver not found */
		if (func == NULL) {
			sc_error(ctx, "Unable to load '%s'.\n", ent->name);
			continue;
		}

		ctx->card_drivers[drv_count] = func();
		ctx->card_drivers[drv_count]->dll = dll;

		ctx->card_drivers[drv_count]->atr_map = NULL;
		ctx->card_drivers[drv_count]->natrs = 0;

		load_card_driver_options(ctx, ctx->card_drivers[drv_count]);
		drv_count++;
	}
	return SC_SUCCESS;
}

static int load_card_atrs(sc_context_t *ctx,
			  struct _sc_ctx_options *opts)
{
	struct sc_card_driver *driver;
	scconf_block **blocks;
	int i, j, k;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], "card_atr", NULL);
		if (!blocks)
			continue;
		for (j = 0; blocks[j] != NULL; j++) {
			scconf_block *b = blocks[j];
			char *atr = b->name->data;
			const scconf_list *list;
			struct sc_atr_table t;
			const char *dname;

			driver = NULL;

			if (strlen(atr) < 4)
				continue;

			/* The interesting part. If there's no card
			 * driver assigned for the ATR, add it to
			 * the default driver. This will reduce the
			 * amount of code required to process things
			 * related to card_atr blocks in situations,
			 * where the code is not exactly related to
			 * card driver settings, but for example
			 * forcing a protocol at the reader driver.
			 */
			dname = scconf_get_str(b, "driver", "default");

			/* Find the card driver structure according to dname */
			for (k = 0; ctx->card_drivers[k] != NULL; k++) {
				driver = ctx->card_drivers[k];
				if (!strcmp(dname, driver->short_name))
					break;
				driver = NULL;
			}

			if (!driver)
				continue;

			memset(&t, 0, sizeof(struct sc_atr_table));
			t.atr = atr;
			t.atrmask = (char *) scconf_get_str(b, "atrmask", NULL);
			t.name = (char *) scconf_get_str(b, "name", NULL);
			t.type = scconf_get_int(b, "type", -1);
			list = scconf_find_list(b, "flags");
			while (list != NULL) {
				unsigned int flags;

				if (!list->data) {
					list = list->next;
					continue;
				}
				flags = 0;
				if (!strcmp(list->data, "keygen")) {
					flags = SC_CARD_FLAG_ONBOARD_KEY_GEN;
				} else if (!strcmp(list->data, "rng")) {
					flags = SC_CARD_FLAG_RNG;
				} else {
					if (sscanf(list->data, "%x", &flags) != 1)
						flags = 0;
				}
				t.flags |= flags;
				list = list->next;
			}
			t.card_atr = b;
			_sc_add_atr(ctx, driver, &t);
		}
		free(blocks);
	}
	return SC_SUCCESS;
}

static void process_config_file(sc_context_t *ctx, struct _sc_ctx_options *opts)
{
	int i, r, count = 0;
	scconf_block **blocks;
	const char *conf_path = NULL;
#ifdef _WIN32
	char temp_path[PATH_MAX];
	DWORD temp_len;
	long rc;
	HKEY hKey;
#endif

	memset(ctx->conf_blocks, 0, sizeof(ctx->conf_blocks));
#ifdef _WIN32
        conf_path = getenv("OPENSC_CONF");
	if (!conf_path) {
        	rc = RegOpenKeyEx( HKEY_CURRENT_USER, "Software\\OpenSC",
                	0, KEY_QUERY_VALUE, &hKey );
        	if( rc == ERROR_SUCCESS ) {
                	temp_len = PATH_MAX;
                	rc = RegQueryValueEx( hKey, "ConfigFile", NULL, NULL,
                        	(LPBYTE) temp_path, &temp_len);
                	if( (rc == ERROR_SUCCESS) && (temp_len < PATH_MAX) )
                        	conf_path = temp_path;
                	RegCloseKey( hKey );
        	}
	}

        if (! conf_path) {
                rc = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\OpenSC",
                        0, KEY_QUERY_VALUE, &hKey );
                if( rc == ERROR_SUCCESS ) {
                        temp_len = PATH_MAX;
                        rc = RegQueryValueEx( hKey, "ConfigFile", NULL, NULL,
                                (LPBYTE) temp_path, &temp_len);
                        if( (rc == ERROR_SUCCESS) && (temp_len < PATH_MAX) )
                                conf_path = temp_path;
                        RegCloseKey( hKey );
                }
        }

	if (! conf_path) {
		sc_debug(ctx, "process_config_file doesn't find opensc config file. Please set the registry key.");
		return;
	}

#else
        conf_path = getenv("OPENSC_CONF");
        if (!conf_path)
                conf_path = OPENSC_CONF_PATH;
#endif
	ctx->conf = scconf_new(conf_path);
	if (ctx->conf == NULL)
		return;
	r = scconf_parse(ctx->conf);
#ifdef OPENSC_CONFIG_STRING
	/* Parse the string if config file didn't exist */
	if (r < 0)
		r = scconf_parse_string(ctx->conf, OPENSC_CONFIG_STRING);
#endif
	if (r < 1) {
		/* A negative return value means the config file isn't
		 * there, which is not an error. Nevertheless log this
		 * fact. */
		if (r < 0)
			sc_debug(ctx, "scconf_parse failed: %s", ctx->conf->errmsg);
		else
			sc_error(ctx, "scconf_parse failed: %s", ctx->conf->errmsg);
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

int sc_ctx_detect_readers(sc_context_t *ctx)
{
	int i;

	sc_mutex_lock(ctx, ctx->mutex);

	for (i = 0; ctx->reader_drivers[i] != NULL; i++) {
		const struct sc_reader_driver *drv = ctx->reader_drivers[i];

		if (drv->ops->detect_readers != NULL)
			drv->ops->detect_readers(ctx, ctx->reader_drv_data[i]);
	}

	sc_mutex_unlock(ctx, ctx->mutex);

	/* XXX: Do not ignore erros? */
	return SC_SUCCESS;
}

sc_reader_t *sc_ctx_get_reader(sc_context_t *ctx, unsigned int i)
{
	if (i >= (unsigned int)ctx->reader_count || i >= SC_MAX_READERS)
		return NULL;
	return ctx->reader[i];
}

unsigned int sc_ctx_get_reader_count(sc_context_t *ctx)
{
	return (unsigned int)ctx->reader_count;
}

void sc_ctx_suppress_errors_on(sc_context_t *ctx)
{
	ctx->suppress_errors++;
}

void sc_ctx_suppress_errors_off(sc_context_t *ctx)
{
	ctx->suppress_errors--;
}

int sc_establish_context(sc_context_t **ctx_out, const char *app_name)
{
	sc_context_param_t ctx_param;

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	return sc_context_create(ctx_out, &ctx_param);
}

int sc_context_create(sc_context_t **ctx_out, const sc_context_param_t *parm)
{
	sc_context_t		*ctx;
	struct _sc_ctx_options	opts;
	int			r;

	if (ctx_out == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = calloc(1, sizeof(sc_context_t));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(&opts, 0, sizeof(opts));
	set_defaults(ctx, &opts);

	/* set the application name if set in the parameter options */
	if (parm != NULL && parm->app_name != NULL)
		ctx->app_name = strdup(parm->app_name);
	else
		ctx->app_name = strdup("default");
	if (ctx->app_name == NULL) {
		sc_release_context(ctx);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	/* set thread context and create mutex object (if specified) */
	if (parm != NULL && parm->thread_ctx != NULL)
		ctx->thread_ctx = parm->thread_ctx;
	r = sc_mutex_create(ctx, &ctx->mutex);
	if (r != SC_SUCCESS) {
		sc_release_context(ctx);
		return r;
	}

	process_config_file(ctx, &opts);
	sc_debug(ctx, "===================================\n"); /* first thing in the log */
	sc_debug(ctx, "opensc version: %s\n", sc_get_version());

        /* initialize ltdl */
	if (lt_dlinit() != 0) {
		sc_debug(ctx, "lt_dlinit failed\n");
		sc_release_context(ctx);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	load_reader_drivers(ctx, &opts);
	load_card_drivers(ctx, &opts);
	load_card_atrs(ctx, &opts);
	if (opts.forced_card_driver) {
		/* FIXME: check return value? */
		sc_set_card_driver(ctx, opts.forced_card_driver);
		free(opts.forced_card_driver);
	}
	del_drvs(&opts, 0);
	del_drvs(&opts, 1);
	sc_ctx_detect_readers(ctx);
	*ctx_out = ctx;
	return SC_SUCCESS;
}

int sc_release_context(sc_context_t *ctx)
{
	int i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, 1);
	for (i = 0; i < ctx->reader_count; i++) {
		sc_reader_t *rdr = ctx->reader[i];

		if (rdr->ops->release != NULL)
			rdr->ops->release(rdr);
		free(rdr->name);
		free(rdr);
	}
	for (i = 0; ctx->reader_drivers[i] != NULL; i++) {
		const struct sc_reader_driver *drv = ctx->reader_drivers[i];

		if (drv->ops->finish != NULL)
			drv->ops->finish(ctx, ctx->reader_drv_data[i]);
		if (drv->dll)
			lt_dlclose(drv->dll);
	}
	for (i = 0; ctx->card_drivers[i]; i++) {
		struct sc_card_driver *drv = ctx->card_drivers[i];

		if (drv->atr_map)
			_sc_free_atr(ctx, drv);
		if (drv->dll)
			lt_dlclose(drv->dll);
	}
	if (ctx->preferred_language != NULL)
		free(ctx->preferred_language);
	if (ctx->mutex != NULL) {
		int r = sc_mutex_destroy(ctx, ctx->mutex);
		if (r != SC_SUCCESS) {
			sc_error(ctx, "unable to destroy mutex\n");
			return r;
		}
	}
	if (ctx->conf != NULL)
		scconf_free(ctx->conf);
	if (ctx->debug_file && ctx->debug_file != stdout)
		fclose(ctx->debug_file);
	if (ctx->error_file && ctx->error_file != stderr)
		fclose(ctx->error_file);
	if (ctx->app_name != NULL)
		free(ctx->app_name);
	sc_mem_clear(ctx, sizeof(*ctx));
	free(ctx);
	return SC_SUCCESS;
}

int sc_set_card_driver(sc_context_t *ctx, const char *short_name)
{
	int i = 0, match = 0;

	sc_mutex_lock(ctx, ctx->mutex);
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
	sc_mutex_unlock(ctx, ctx->mutex);
	if (match == 0)
		return SC_ERROR_OBJECT_NOT_FOUND; /* FIXME: invent error */
	return SC_SUCCESS;
}

int sc_get_cache_dir(sc_context_t *ctx, char *buf, size_t bufsize)
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
	return SC_SUCCESS;
}

int sc_make_cache_dir(sc_context_t *ctx)
{
	char dirname[PATH_MAX], *sp;
	int    r;
	size_t j, namelen;

	if ((r = sc_get_cache_dir(ctx, dirname, sizeof(dirname))) < 0)
		return r;
	namelen = strlen(dirname);

	while (1) {
#ifdef _WIN32
		if (mkdir(dirname) >= 0)
#else
		if (mkdir(dirname, 0700) >= 0)
#endif
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
#ifdef _WIN32
		if (mkdir(dirname) < 0)
#else
		if (mkdir(dirname, 0700) < 0)
#endif
			goto failed;
	}
	return SC_SUCCESS;

	/* for lack of a better return code */
failed:	sc_error(ctx, "failed to create cache directory\n");
	return SC_ERROR_INTERNAL;
}
