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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#endif

#include "common/libscdl.h"
#include "internal.h"

int _sc_add_reader(sc_context_t *ctx, sc_reader_t *reader)
{
	assert(reader != NULL);
	reader->ctx = ctx;
	list_append(&ctx->readers, reader);
	return SC_SUCCESS;
}

int _sc_delete_reader(sc_context_t *ctx, sc_reader_t *reader)
{
	assert(reader != NULL);
	if (reader->ops->release)
			reader->ops->release(reader);
	if (reader->name)
		free(reader->name);
	list_delete(&ctx->readers, reader);
	free(reader);
	return SC_SUCCESS;
}

struct _sc_driver_entry {
	const char *name;
	void *(*func)(void);
};

static const struct _sc_driver_entry internal_card_drivers[] = {
	{ "cardos",	(void *(*)(void)) sc_get_cardos_driver },
	{ "flex",	(void *(*)(void)) sc_get_cryptoflex_driver },
	{ "cyberflex",	(void *(*)(void)) sc_get_cyberflex_driver },
#ifdef ENABLE_OPENSSL
	{ "gpk",	(void *(*)(void)) sc_get_gpk_driver },
#endif
	{ "gemsafeV1",	(void *(*)(void)) sc_get_gemsafeV1_driver },
	{ "miocos",	(void *(*)(void)) sc_get_miocos_driver },
	{ "asepcos",	(void *(*)(void)) sc_get_asepcos_driver },
	{ "starcos",	(void *(*)(void)) sc_get_starcos_driver },
	{ "tcos",	(void *(*)(void)) sc_get_tcos_driver },
	{ "openpgp",	(void *(*)(void)) sc_get_openpgp_driver },
	{ "jcop",	(void *(*)(void)) sc_get_jcop_driver },
#ifdef ENABLE_OPENSSL
	{ "oberthur",	(void *(*)(void)) sc_get_oberthur_driver },
	{ "authentic",	(void *(*)(void)) sc_get_authentic_driver },
	{ "iasecc",	(void *(*)(void)) sc_get_iasecc_driver },
#endif
	{ "belpic",	(void *(*)(void)) sc_get_belpic_driver },
	{ "ias",		(void *(*)(void)) sc_get_ias_driver },
	{ "incrypto34", (void *(*)(void)) sc_get_incrypto34_driver },
	{ "acos5",	(void *(*)(void)) sc_get_acos5_driver },
	{ "akis",	(void *(*)(void)) sc_get_akis_driver },
#ifdef ENABLE_OPENSSL
	{ "entersafe",(void *(*)(void)) sc_get_entersafe_driver },
#ifdef ENABLE_SM
	{ "epass2003",(void *(*)(void)) sc_get_epass2003_driver },
#endif
#endif
	{ "rutoken",	(void *(*)(void)) sc_get_rutoken_driver },
	{ "rutoken_ecp",(void *(*)(void)) sc_get_rtecp_driver },
	{ "westcos",	(void *(*)(void)) sc_get_westcos_driver },
	{ "myeid",      (void *(*)(void)) sc_get_myeid_driver },
	{ "sc-hsm",		(void *(*)(void)) sc_get_sc_hsm_driver },
#ifdef ENABLE_OPENSSL
	{ "dnie",       (void *(*)(void)) sc_get_dnie_driver },
#endif
	{ "masktech",	(void *(*)(void)) sc_get_masktech_driver },

/* Here should be placed drivers that need some APDU transactions to
 * recognise its cards. */
	{ "mcrd",	(void *(*)(void)) sc_get_mcrd_driver },
	{ "setcos",	(void *(*)(void)) sc_get_setcos_driver },
	{ "muscle",	(void *(*)(void)) sc_get_muscle_driver },
	{ "atrust-acos",(void *(*)(void)) sc_get_atrust_acos_driver },
	{ "PIV-II",	(void *(*)(void)) sc_get_piv_driver },
	{ "itacns",	(void *(*)(void)) sc_get_itacns_driver },
	{ "isoApplet",	(void *(*)(void)) sc_get_isoApplet_driver },
	/* The default driver should be last, as it handles all the
	 * unrecognized cards. */
	{ "default",	(void *(*)(void)) sc_get_default_driver },
	{ NULL, NULL }
};

struct _sc_ctx_options {
	struct _sc_driver_entry cdrv[SC_MAX_CARD_DRIVERS];
	int ccount;
	char *forced_card_driver;
};


/* Simclist helper to locate readers by name */
static int reader_list_seeker(const void *el, const void *key) {
	const struct sc_reader *reader = (struct sc_reader *)el;
	if ((el == NULL) || (key == NULL))
		return 0;
	if (strcmp(reader->name, (char*)key) == 0)
		return 1;
	return 0;
}

static void del_drvs(struct _sc_ctx_options *opts)
{
	struct _sc_driver_entry *lst;
	int *cp, i;

	lst = opts->cdrv;
	cp = &opts->ccount;

	for (i = 0; i < *cp; i++) {
		free((void *)lst[i].name);
	}
	*cp = 0;
}

static void add_drv(struct _sc_ctx_options *opts, const char *name)
{
	struct _sc_driver_entry *lst;
	int *cp, max, i;

	lst = opts->cdrv;
	cp = &opts->ccount;
	max = SC_MAX_CARD_DRIVERS;
	if (*cp == max) /* No space for more drivers... */
		return;
	for (i = 0; i < *cp; i++)
		if (strcmp(name, lst[i].name) == 0)
			return;
	lst[*cp].name = strdup(name);

	*cp = *cp + 1;
}

static void add_internal_drvs(struct _sc_ctx_options *opts)
{
	const struct _sc_driver_entry *lst;
	int i;

	lst = internal_card_drivers;
	i = 0;
	while (lst[i].name != NULL) {
		add_drv(opts, lst[i].name);
		i++;
	}
}

static void set_defaults(sc_context_t *ctx, struct _sc_ctx_options *opts)
{
	ctx->debug = 0;
	if (ctx->debug_file && (ctx->debug_file != stderr && ctx->debug_file != stdout))
		fclose(ctx->debug_file);
	ctx->debug_file = stderr;
	ctx->paranoid_memory = 0;
	ctx->enable_default_driver = 0;

#ifdef __APPLE__
	/* Override the default debug log for OpenSC.tokend to be different from PKCS#11.
	 * TODO: Could be moved to OpenSC.tokend */
	if (!strcmp(ctx->app_name, "tokend"))
		ctx->debug_file = fopen("/tmp/opensc-tokend.log", "a");
#endif
	ctx->forced_driver = NULL;
	add_internal_drvs(opts);
}

/* In Windows, file handles can not be shared between DLL-s,
 * each DLL has a separate file handle table. Thus tools and utilities
 * can not set the file handle themselves when -v is specified on command line.
 */
int sc_ctx_log_to_file(sc_context_t *ctx, const char* filename)
{
	/* Close any existing handles */
	if (ctx->debug_file && (ctx->debug_file != stderr && ctx->debug_file != stdout))   {
		fclose(ctx->debug_file);
		ctx->debug_file = NULL;
	}

	/* Handle special names */
	if (!strcmp(filename, "stdout"))
		ctx->debug_file = stdout;
	else if (!strcmp(filename, "stderr"))
		ctx->debug_file = stderr;
	else {
		ctx->debug_file = fopen(filename, "a");
		if (ctx->debug_file == NULL)
			return SC_ERROR_INTERNAL;
	}
	return SC_SUCCESS;
}


static int
load_parameters(sc_context_t *ctx, scconf_block *block, struct _sc_ctx_options *opts)
{
	int err = 0;
	const scconf_list *list;
	const char *val, *s_internal = "internal";
	int debug;
	int reopen;
#ifdef _WIN32
	char expanded_val[PATH_MAX];
	DWORD expanded_len;
#endif

	reopen = scconf_get_bool(block, "reopen_debug_file", 1);

	debug = scconf_get_int(block, "debug", ctx->debug);
	if (debug > ctx->debug)
		ctx->debug = debug;

	val = scconf_get_str(block, "debug_file", NULL);
	if (val)   {
#ifdef _WIN32
		expanded_len = PATH_MAX;
		expanded_len = ExpandEnvironmentStringsA(val, expanded_val, expanded_len);
		if (expanded_len > 0)
			val = expanded_val;
#endif
		if (reopen)
			ctx->debug_filename = strdup(val);

		sc_ctx_log_to_file(ctx, val);
	}

	ctx->paranoid_memory = scconf_get_bool (block, "paranoid-memory",
		ctx->paranoid_memory);

	ctx->enable_default_driver = scconf_get_bool (block, "enable_default_driver",
			ctx->enable_default_driver);

	val = scconf_get_str(block, "force_card_driver", NULL);
	if (val) {
		if (opts->forced_card_driver)
			free(opts->forced_card_driver);
		opts->forced_card_driver = strdup(val);
	}

	list = scconf_find_list(block, "card_drivers");
	if (list != NULL)
		del_drvs(opts);
	while (list != NULL) {
		if (strcmp(list->data, s_internal) == 0)
			add_internal_drvs(opts);
		else
			add_drv(opts, list->data);
		list = list->next;
	}

	return err;
}

static void load_reader_driver_options(sc_context_t *ctx)
{
	struct sc_reader_driver *driver = ctx->reader_driver;
	scconf_block *conf_block = NULL;

	driver->max_send_size = 0;
	driver->max_recv_size = 0;

	conf_block = sc_get_conf_block(ctx, "reader_driver", driver->short_name, 1);

	if (conf_block != NULL) {
		driver->max_send_size = scconf_get_int(conf_block, "max_send_size", driver->max_send_size);
		driver->max_recv_size = scconf_get_int(conf_block, "max_recv_size", driver->max_recv_size);
	}
}

/**
 * find library module for provided driver in configuration file
 * if not found assume library name equals to module name
 */
static const char *find_library(sc_context_t *ctx, const char *name)
{
	int          i;
	const char   *libname = NULL;
	scconf_block **blocks, *blk;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], "card_driver", name);
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == NULL)
			continue;
		libname = scconf_get_str(blk, "module", name);
#ifdef _WIN32
		if (libname && libname[0] != '\\' )
#else
		if (libname && libname[0] != '/' )
#endif
			sc_log(ctx, "warning: relative path to driver '%s' used", libname);
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
 */
static void *load_dynamic_driver(sc_context_t *ctx, void **dll, const char *name)
{
	const char *version, *libname;
	void *handle;
	void *(*modinit)(const char *) = NULL;
	void *(**tmodi)(const char *) = &modinit;
	const char *(*modversion)(void) = NULL;
	const char *(**tmodv)(void) = &modversion;

	if (name == NULL) { /* should not occurr, but... */
		sc_log(ctx, "No module specified", name);
		return NULL;
	}
	libname = find_library(ctx, name);
	if (libname == NULL)
		return NULL;
	handle = sc_dlopen(libname);
	if (handle == NULL) {
		sc_log(ctx, "Module %s: cannot load %s library: %s", name, libname, sc_dlerror());
		return NULL;
	}

	/* verify correctness of module */
	*(void **)tmodi = sc_dlsym(handle, "sc_module_init");
	*(void **)tmodv = sc_dlsym(handle, "sc_driver_version");
	if (modinit == NULL || modversion == NULL) {
		sc_log(ctx, "dynamic library '%s' is not a OpenSC module",libname);
		sc_dlclose(handle);
		return NULL;
	}
	/* verify module version */
	version = modversion();
	/* XXX: We really need to have ABI version for each interface */
	if (version == NULL || strncmp(version, PACKAGE_VERSION, strlen(PACKAGE_VERSION)) != 0) {
		sc_log(ctx, "dynamic library '%s': invalid module version", libname);
		sc_dlclose(handle);
		return NULL;
	}
	if (dll)
		*dll = handle;
	sc_log(ctx, "successfully loaded card driver '%s'", name);
	return modinit(name);
}

static int load_card_driver_options(sc_context_t *ctx,
				    struct sc_card_driver *driver)
{
	scconf_block **blocks, *blk;
	int i;

	for (i = 0; ctx->conf_blocks[i]; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
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

	for (drv_count = 0; ctx->card_drivers[drv_count] != NULL; drv_count++)
		;

	for (i = 0; i < opts->ccount; i++) {
		struct sc_card_driver *(*func)(void) = NULL;
		struct sc_card_driver *(**tfunc)(void) = &func;
		void *dll = NULL;
		int  j;

		if (drv_count >= SC_MAX_CARD_DRIVERS - 1)   {
			sc_log(ctx, "Not more then %i card drivers allowed.", SC_MAX_CARD_DRIVERS);
			break;
		}

		ent = &opts->cdrv[i];
		for (j = 0; internal_card_drivers[j].name != NULL; j++)
			if (strcmp(ent->name, internal_card_drivers[j].name) == 0) {
				func = (struct sc_card_driver *(*)(void)) internal_card_drivers[j].func;
				break;
			}
		/* if not initialized assume external module */
		if (func == NULL)
			*(void **)(tfunc) = load_dynamic_driver(ctx, &dll, ent->name);
		/* if still null, assume driver not found */
		if (func == NULL) {
			sc_log(ctx, "Unable to load '%s'.", ent->name);
			if (dll)
				sc_dlclose(dll);
			continue;
		}

		ctx->card_drivers[drv_count] = func();
		ctx->card_drivers[drv_count]->dll = dll;

		ctx->card_drivers[drv_count]->atr_map = NULL;
		ctx->card_drivers[drv_count]->natrs = 0;

		load_card_driver_options(ctx, ctx->card_drivers[drv_count]);

		/* Ensure that the list is always terminated by NULL */
		ctx->card_drivers[drv_count + 1] = NULL;

		drv_count++;
	}
	return SC_SUCCESS;
}

static int load_card_atrs(sc_context_t *ctx)
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
			t.type = scconf_get_int(b, "type", SC_CARD_TYPE_UNKNOWN);
			list = scconf_find_list(b, "flags");
			while (list != NULL) {
				unsigned int flags = 0;

				if (!list->data) {
					list = list->next;
					continue;
				}

				if (!strcmp(list->data, "rng"))
					flags = SC_CARD_FLAG_RNG;
				else if (sscanf(list->data, "%x", &flags) != 1)
					flags = 0;

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
	const char *debug = NULL;
#ifdef _WIN32
	char temp_path[PATH_MAX];
	DWORD temp_len;
	long rc;
	HKEY hKey;
#endif

	/* Takes effect even when no config around */
	debug = getenv("OPENSC_DEBUG");
	if (debug)
		ctx->debug = atoi(debug);

	memset(ctx->conf_blocks, 0, sizeof(ctx->conf_blocks));
#ifdef _WIN32
	conf_path = getenv("OPENSC_CONF");
	if (!conf_path) {
		rc = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\OpenSC Project\\OpenSC", 0, KEY_QUERY_VALUE, &hKey);
		if (rc == ERROR_SUCCESS) {
			temp_len = PATH_MAX;
			rc = RegQueryValueEx( hKey, "ConfigFile", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if ((rc == ERROR_SUCCESS) && (temp_len < PATH_MAX))
				conf_path = temp_path;
			RegCloseKey(hKey);
		}
	}

	if (!conf_path) {
		rc = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Software\\OpenSC Project\\OpenSC", 0, KEY_QUERY_VALUE, &hKey );
		if (rc == ERROR_SUCCESS) {
			temp_len = PATH_MAX;
			rc = RegQueryValueEx( hKey, "ConfigFile", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if ((rc == ERROR_SUCCESS) && (temp_len < PATH_MAX))
				conf_path = temp_path;
			RegCloseKey(hKey);
		}
	}

	if (!conf_path) {
		sc_log(ctx, "process_config_file doesn't find opensc config file. Please set the registry key.");
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
			sc_log(ctx, "scconf_parse failed: %s", ctx->conf->errmsg);
		else
			sc_log(ctx, "scconf_parse failed: %s", ctx->conf->errmsg);
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
			ctx->conf_blocks[count] = blocks[0];
		free(blocks);
	}
	/* Above we add 2 blocks at most, but conf_blocks has 3 elements,
	 * so at least one is NULL */
	for (i = 0; ctx->conf_blocks[i]; i++)
		load_parameters(ctx, ctx->conf_blocks[i], opts);
}

int sc_ctx_detect_readers(sc_context_t *ctx)
{
	int r = 0;
	const struct sc_reader_driver *drv = ctx->reader_driver;

	sc_mutex_lock(ctx, ctx->mutex);

	if (drv->ops->detect_readers != NULL)
		r = drv->ops->detect_readers(ctx);

	sc_mutex_unlock(ctx, ctx->mutex);

	return r;
}

sc_reader_t *sc_ctx_get_reader(sc_context_t *ctx, unsigned int i)
{
	return list_get_at(&ctx->readers, i);
}

sc_reader_t *sc_ctx_get_reader_by_id(sc_context_t *ctx, unsigned int id)
{
	return list_get_at(&ctx->readers, id);
}

sc_reader_t *sc_ctx_get_reader_by_name(sc_context_t *ctx, const char * name)
{
	return list_seek(&ctx->readers, name);
}

unsigned int sc_ctx_get_reader_count(sc_context_t *ctx)
{
	return list_size(&ctx->readers);
}

int sc_establish_context(sc_context_t **ctx_out, const char *app_name)
{
	sc_context_param_t ctx_param;

	memset(&ctx_param, 0, sizeof(sc_context_param_t));
	ctx_param.ver      = 0;
	ctx_param.app_name = app_name;
	return sc_context_create(ctx_out, &ctx_param);
}

/* For multithreaded issues */
int sc_context_repair(sc_context_t **ctx_out)
{
	/* Must already exist */
	if ((ctx_out == NULL) || (*ctx_out == NULL) ||
	    ((*ctx_out)->app_name == NULL))
		return SC_ERROR_INVALID_ARGUMENTS;

	/* The only thing that should be shared across different contexts are the
	 * card drivers - so rebuild the ATR's
	 */
	load_card_atrs(*ctx_out);

	/* TODO: May need to re-open any card driver DLL's */

	return SC_SUCCESS;
}

int sc_context_create(sc_context_t **ctx_out, const sc_context_param_t *parm)
{
	sc_context_t		*ctx;
	struct _sc_ctx_options	opts;
	int			r;

	if (ctx_out == NULL || parm == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = calloc(1, sizeof(sc_context_t));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(&opts, 0, sizeof(opts));

	/* set the application name if set in the parameter options */
	if (parm->app_name != NULL)
		ctx->app_name = strdup(parm->app_name);
	else
		ctx->app_name = strdup("default");
	if (ctx->app_name == NULL) {
		sc_release_context(ctx);
		return SC_ERROR_OUT_OF_MEMORY;
	}

	set_defaults(ctx, &opts);
	list_init(&ctx->readers);
	list_attributes_seeker(&ctx->readers, reader_list_seeker);
	/* set thread context and create mutex object (if specified) */
	if (parm->thread_ctx != NULL)
		ctx->thread_ctx = parm->thread_ctx;
	r = sc_mutex_create(ctx, &ctx->mutex);
	if (r != SC_SUCCESS) {
		sc_release_context(ctx);
		return r;
	}

	process_config_file(ctx, &opts);
	sc_log(ctx, "==================================="); /* first thing in the log */
	sc_log(ctx, "opensc version: %s", sc_get_version());

#ifdef ENABLE_PCSC
	ctx->reader_driver = sc_get_pcsc_driver();
/* XXX: remove cardmod pseudoreader driver */
#ifdef ENABLE_MINIDRIVER
	if(strcmp(ctx->app_name, "cardmod") == 0)
		ctx->reader_driver = sc_get_cardmod_driver();
#endif
#elif defined(ENABLE_CTAPI)
	ctx->reader_driver = sc_get_ctapi_driver();
#elif defined(ENABLE_OPENCT)
	ctx->reader_driver = sc_get_openct_driver();
#endif

	load_reader_driver_options(ctx);
	r = ctx->reader_driver->ops->init(ctx);
	if (r != SC_SUCCESS)   {
		sc_release_context(ctx);
		return r;
	}

	load_card_drivers(ctx, &opts);
	load_card_atrs(ctx);
	if (opts.forced_card_driver) {
		/* FIXME: check return value? */
		sc_set_card_driver(ctx, opts.forced_card_driver);
		free(opts.forced_card_driver);
	}
	del_drvs(&opts);
	sc_ctx_detect_readers(ctx);
	*ctx_out = ctx;

	return SC_SUCCESS;
}

/* Used by minidriver to pass in provided handles to reader-pcsc */
int sc_ctx_use_reader(sc_context_t *ctx, void *pcsc_context_handle, void *pcsc_card_handle)
{
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	if (ctx->reader_driver->ops->use_reader != NULL)
		return ctx->reader_driver->ops->use_reader(ctx, pcsc_context_handle, pcsc_card_handle);

	return SC_ERROR_NOT_SUPPORTED;
}

/* Following two are only implemented with internal PC/SC and don't consume a reader object */
int sc_cancel(sc_context_t *ctx)
{
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	if (ctx->reader_driver->ops->cancel != NULL)
		return ctx->reader_driver->ops->cancel(ctx);

	return SC_ERROR_NOT_SUPPORTED;
}


int sc_wait_for_event(sc_context_t *ctx, unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event, int timeout, void **reader_states)
{
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	if (ctx->reader_driver->ops->wait_for_event != NULL)
		return ctx->reader_driver->ops->wait_for_event(ctx, event_mask, event_reader, event, timeout, reader_states);

	return SC_ERROR_NOT_SUPPORTED;
}


int sc_release_context(sc_context_t *ctx)
{
	unsigned int i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	while (list_size(&ctx->readers)) {
		sc_reader_t *rdr = (sc_reader_t *) list_get_at(&ctx->readers, 0);
		_sc_delete_reader(ctx, rdr);
	}

	if (ctx->reader_driver->ops->finish != NULL)
		ctx->reader_driver->ops->finish(ctx);

	for (i = 0; ctx->card_drivers[i]; i++) {
		struct sc_card_driver *drv = ctx->card_drivers[i];

		if (drv->atr_map)
			_sc_free_atr(ctx, drv);
		if (drv->dll)
			sc_dlclose(drv->dll);
	}
	if (ctx->preferred_language != NULL)
		free(ctx->preferred_language);
	if (ctx->mutex != NULL) {
		int r = sc_mutex_destroy(ctx, ctx->mutex);
		if (r != SC_SUCCESS) {
			sc_log(ctx, "unable to destroy mutex");
			return r;
		}
	}
	if (ctx->conf != NULL)
		scconf_free(ctx->conf);
	if (ctx->debug_file && (ctx->debug_file != stdout && ctx->debug_file != stderr))
		fclose(ctx->debug_file);
	if (ctx->debug_filename != NULL)
		free(ctx->debug_filename);
	if (ctx->app_name != NULL)
		free(ctx->app_name);
	list_destroy(&ctx->readers);
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
	} else while (i < SC_MAX_CARD_DRIVERS && ctx->card_drivers[i] != NULL) {
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
		GetWindowsDirectoryA(temp_path, sizeof(temp_path));
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

		if (errno != ENOENT || (sp = strrchr(dirname, '/')) == NULL
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
failed:
	sc_log(ctx, "failed to create cache directory");
	return SC_ERROR_INTERNAL;
}
