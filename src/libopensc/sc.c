/*
 * sc.c: General functions
 *
 * Copyright (C) 2001  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "config.h"
#endif
#include "sc-internal.h"
#include "sc-log.h"
#include "sc-asn1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#ifdef VERSION
const char *sc_version = VERSION;
#else
#warning FIXME: version info undefined
const char *sc_version = "(undef)";
#endif

int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen)
{
	int err = 0;
	size_t left, c = 0;

	assert(in != NULL && out != NULL && outlen != NULL);
        left = *outlen;

	while (*in != (char) 0) {
		int byte;

		if (sscanf(in, "%02X", &byte) != 1) {
                        err = SC_ERROR_INVALID_ARGUMENTS;
			break;
		}
		in += 2;
		if (*in == ':')
			in++;
		if (left <= 0) {
                        err = SC_ERROR_BUFFER_TOO_SMALL;
			break;
		}
		*out++ = (u8) byte;
		left--;
		c++;
	}
	*outlen = c;
	return err;
}

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

struct sc_slot_info * _sc_get_slot_info(struct sc_reader *reader, int slot_id)
{
	assert(reader != NULL);
	if (slot_id > reader->slot_count)
		return NULL;
	return &reader->slot[slot_id];
}

int sc_detect_card_presence(struct sc_reader *reader, int slot_id)
{
	int r;
	struct sc_slot_info *slot = _sc_get_slot_info(reader, slot_id);
	
	if (slot == NULL)
		SC_FUNC_RETURN(reader->ctx, 0, SC_ERROR_SLOT_NOT_FOUND);
	SC_FUNC_CALLED(reader->ctx, 1);
	if (reader->ops->detect_card_presence == NULL)
		SC_FUNC_RETURN(reader->ctx, 0, SC_ERROR_NOT_SUPPORTED);
	
	r = reader->ops->detect_card_presence(reader, slot);
	SC_FUNC_RETURN(reader->ctx, 1, r);
}

#if 0
int sc_wait_for_card(struct sc_context *ctx, int reader, int timeout)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	int count = 0, i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, 1);
	if (reader >= ctx->reader_count)
		SC_FUNC_RETURN(ctx, 1, SC_ERROR_INVALID_ARGUMENTS);

	if (reader < 0) {
		if (ctx->reader_count == 0)
			SC_FUNC_RETURN(ctx, 1, SC_ERROR_NO_READERS_FOUND);
		for (i = 0; i < ctx->reader_count; i++) {
			rgReaderStates[i].szReader = ctx->readers[i];
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
			rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
		}
		count = ctx->reader_count;
	} else {
		rgReaderStates[0].szReader = ctx->readers[reader];
		rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates[0].dwEventState = SCARD_STATE_UNAWARE;
		count = 1;
	}
	ret = SCardGetStatusChange(ctx->pcsc_ctx, timeout, rgReaderStates, count);
	if (ret != 0) {
		error(ctx, "SCardGetStatusChange failed: %s\n", pcsc_stringify_error(ret));
		SC_FUNC_RETURN(ctx, 1, -1);
	}
	for (i = 0; i < count; i++) {
		if (rgReaderStates[i].dwEventState & SCARD_STATE_CHANGED)
			SC_FUNC_RETURN(ctx, 1, 1);
	}
	SC_FUNC_RETURN(ctx, 1, 0);
}
#endif

static void set_defaults(struct sc_context *ctx)
{
	ctx->debug = 0;
	if (ctx->debug_file)
		fclose(ctx->debug_file);
	ctx->debug_file = NULL;
	ctx->log_errors = 1;
	ctx->error_file = stderr;
}

static int load_parameters(struct sc_context *ctx, const char *app)
{
	scconf_block **blocks = NULL;
	const char *val;
	unsigned int i;

	blocks = scconf_find_blocks(ctx->conf, NULL, "app");
	for (i = 0; blocks[i]; i++) {
		scconf_block *block = blocks[i];

		if (!block->name && strcmp(block->name->data, app))
			continue;
		val = scconf_find_value_first(block, "debug");
		sscanf(val, "%d", &ctx->debug);
		val = scconf_find_value_first(block, "debug_file");
		if (ctx->debug_file)
			fclose(ctx->debug_file);
		if (strcmp(val, "stdout") == 0)
			ctx->debug_file = fopen(val, "a");
		val = scconf_find_value_first(block, "error_file");
		if (ctx->error_file)
			fclose(ctx->error_file);
		if (strcmp(val, "stderr") != 0)
			ctx->error_file = fopen(val, "a");
	}
	free(blocks);
	return 0;
}

int sc_establish_context(struct sc_context **ctx_out, const char *app_name)
{
	const char *default_app = "default";
	struct sc_context *ctx;
	int i, r;

	assert(ctx_out != NULL);
	ctx = malloc(sizeof(struct sc_context));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(ctx, 0, sizeof(struct sc_context));
	set_defaults(ctx);
	ctx->app_name = app_name ? strdup(app_name) : strdup(default_app);
	ctx->conf = scconf_init(OPENSC_CONF_PATH);
	if (ctx->conf != NULL) {
		r = scconf_parse(ctx->conf);
		if (scconf_parse(ctx->conf) < 1) {
			scconf_deinit(ctx->conf);
			ctx->conf = NULL;
		} else {
			load_parameters(ctx, default_app);
			if (strcmp(default_app, ctx->app_name)) {
				load_parameters(ctx, ctx->app_name);
			}
		}
	}
#ifdef HAVE_PTHREAD
	pthread_mutex_init(&ctx->mutex, NULL);
#endif
	for (i = 0; i < SC_MAX_READER_DRIVERS+1; i++)
		ctx->reader_drivers[i] = NULL;
	i = 0;
#if 1 && defined(HAVE_LIBPCSCLITE)
	ctx->reader_drivers[i++] = sc_get_pcsc_driver();
#endif
	i = 0;
	while (ctx->reader_drivers[i] != NULL) {
		ctx->reader_drivers[i]->ops->init(ctx, &ctx->reader_drv_data[i]);
		i++;
	}

	ctx->forced_driver = NULL;
	for (i = 0; i < SC_MAX_CARD_DRIVERS+1; i++)
		ctx->card_drivers[i] = NULL;
	i = 0;
#if 1
	ctx->card_drivers[i++] = sc_get_setcos_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_miocos_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_flex_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_emv_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_tcos_driver();
#endif
#if defined(HAVE_OPENSSL)
	ctx->card_drivers[i++] = sc_get_gpk_driver();
#endif
#if 1
	/* this should be last in line */
	ctx->card_drivers[i++] = sc_get_default_driver();
#endif

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
			drv->ops->finish(ctx->reader_drv_data[i]);
	}
	ctx->debug_file = ctx->error_file = NULL;
	if (ctx->conf)
		scconf_deinit(ctx->conf);
	free(ctx->app_name);
	free(ctx);
	return 0;
}

int sc_set_card_driver(struct sc_context *ctx, const char *short_name)
{
	int i = 0, match = 0;
	
#ifdef HAVE_PTHREAD
	pthread_mutex_lock(&ctx->mutex);
#endif
	if (short_name == NULL) {
		ctx->forced_driver = NULL;
		match = 1;
	} else while (ctx->card_drivers[i] != NULL && i < SC_MAX_CARD_DRIVERS) {
		const struct sc_card_driver *drv = ctx->card_drivers[i];

		if (strcmp(short_name, drv->short_name) == 0) {
			ctx->forced_driver = drv;
			match = 1;
			break;
		}
		i++;
	}
#ifdef HAVE_PTHREAD
	pthread_mutex_unlock(&ctx->mutex);
#endif
	if (match == 0)
		return SC_ERROR_OBJECT_NOT_FOUND; /* FIXME: invent error */
	return 0;
}

void sc_format_path(const char *str, struct sc_path *path)
{
	int len = 0;
	int type = SC_PATH_TYPE_PATH;
	u8 *p = path->value;

	if (*str == 'i' || *str == 'I') {
		type = SC_PATH_TYPE_FILE_ID;
		str++;
	}
	while (*str) {
		int byte;
		
		if (sscanf(str, "%02X", &byte) != 1)
			break;
		*p++ = byte;
		len++;
		str += 2;
	}
	path->len = len;
	path->type = type;
	path->index = 0;
	return;
}

int sc_append_path(struct sc_path *dest, const struct sc_path *src)
{
	assert(dest != NULL && src != NULL);
	if (dest->len + src->len > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(dest->value + dest->len, src->value, src->len);
	dest->len += src->len;
	return 0;
}

int sc_append_path_id(struct sc_path *dest, const u8 *id, size_t idlen)
{
	if (dest->len + idlen > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(dest->value + dest->len, id, idlen);
	dest->len += idlen;
	return 0;
}

int sc_get_cache_dir(struct sc_context *ctx, char *buf, size_t bufsize)
{
	char *homedir;
	const char *cache_dir = ".eid/cache";

	homedir = getenv("HOME");
	if (homedir == NULL)
		return SC_ERROR_INTERNAL;
	if (snprintf(buf, bufsize, "%s/%s", homedir, cache_dir) < 0)
		return SC_ERROR_BUFFER_TOO_SMALL;
	return 0;
}

const char *sc_strerror(int error)
{
	const char *errors[] = {
		"Unknown error",
		"Command too short",
		"Command too long",
		"Not supported",
		"Transmit failed",
		"File not found",
		"Invalid arguments",
		"PKCS#15 compatible SmartCard not found",
		"Required parameter not found on SmartCard",
		"Out of memory",
		"No readers found",
		"Object not valid",
		"Unknown response",
		"PIN code incorrect",
		"Security status not satisfied",
		"Error connecting to Resource Manager",
		"Invalid ASN.1 object",
		"Buffer too small",
		"Card not present",
		"Error with Resource Manager",
		"Card removed",
		"Invalid PIN length",
		"Unknown SmartCard",
		"Unknown reply from SmartCard",
		"Requested object not found",
		"Card reset",
		"Required ASN.1 object not found",
		"Premature end of ASN.1 stream",
		"Too many objects",
		"Card is invalid or cannot be handled",
		"Wrong length",
		"Record not found",
		"Internal error",
		"Invalid CLA byte in APDU",
		"Slot not found",
		"Slot already connected",
		"Authentication method blocked",
	};
	int nr_errors = sizeof(errors) / sizeof(errors[0]);

	error -= SC_ERROR_MIN;
	if (error < 0)
		error = -error;

	if (error >= nr_errors)
		return errors[0];
	return errors[error];
}

int sc_file_add_acl_entry(struct sc_file *file, unsigned int operation,
                          unsigned int method, unsigned long key_ref)
{
	struct sc_acl_entry *p, *new;

	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	switch (method) {
	case SC_AC_NEVER:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 1;
		return 0;
	case SC_AC_NONE:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 2;
		return 0;
	case SC_AC_UNKNOWN:
		sc_file_clear_acl_entries(file, operation);
		file->acl[operation] = (struct sc_acl_entry *) 3;
		return 0;
	default:
		/* NONE and UNKNOWN get zapped when a new AC is added.
		 * If the ACL is NEVER, additional entries will be
		 * dropped silently. */
		if (file->acl[operation] == (struct sc_acl_entry *) 1)
			return 0;
		if (file->acl[operation] == (struct sc_acl_entry *) 2
		 || file->acl[operation] == (struct sc_acl_entry *) 3)
			file->acl[operation] = NULL;
	}
	
	new = malloc(sizeof(struct sc_acl_entry));
	if (new == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	new->method = method;
	new->key_ref = key_ref;
	new->next = NULL;

	p = file->acl[operation];
	if (p == NULL) {
		file->acl[operation] = new;
		return 0;
	}
	while (p->next != NULL)
		p = p->next;
	p->next = new;

	return 0;
}

const struct sc_acl_entry * sc_file_get_acl_entry(const struct sc_file *file,
						  unsigned int operation)
{
	struct sc_acl_entry *p;
	static const struct sc_acl_entry e_never = {
		SC_AC_NEVER, SC_AC_KEY_REF_NONE, NULL
	};
	static const struct sc_acl_entry e_none = {
		SC_AC_NONE, SC_AC_KEY_REF_NONE, NULL
	};
	static const struct sc_acl_entry e_unknown = {
		SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE, NULL
	};

	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	p = file->acl[operation];
	if (p == (struct sc_acl_entry *) 1)
		return &e_never;
	if (p == (struct sc_acl_entry *) 2)
		return &e_none;
	if (p == (struct sc_acl_entry *) 3)
		return &e_unknown;

	return file->acl[operation];
}

void sc_file_clear_acl_entries(struct sc_file *file, unsigned int operation)
{
	struct sc_acl_entry *e;
	
	assert(file != NULL);
	assert(operation < SC_MAX_AC_OPS);

	e = file->acl[operation];
	if (e == (struct sc_acl_entry *) 1 || 
	    e == (struct sc_acl_entry *) 2 ||
	    e == (struct sc_acl_entry *) 3) {
		file->acl[operation] = NULL;
		return;
	}

	while (e != NULL) {
		struct sc_acl_entry *tmp = e->next;
		free(e);
		e = tmp;
	}
	file->acl[operation] = NULL;
}

struct sc_file * sc_file_new()
{
	struct sc_file *file = malloc(sizeof(struct sc_file));
	
	if (file == NULL)
		return NULL;
	memset(file, 0, sizeof(struct sc_file));
	file->magic = SC_FILE_MAGIC;
	return file;
}

void sc_file_free(struct sc_file *file)
{
	int i;
	assert(sc_file_valid(file));
	file->magic = 0;
	for (i = 0; i < SC_MAX_AC_OPS; i++)
		sc_file_clear_acl_entries(file, i);
	free(file);
}

void sc_file_dup(struct sc_file **dest, const struct sc_file *src)
{
	struct sc_file *newf;
	const struct sc_acl_entry *e;
	int op;
	
	assert(sc_file_valid(src));
	*dest = NULL;
	newf = sc_file_new();
	if (newf == NULL)
		return;
	*dest = newf;
	
	*newf = *src;
	for (op = 0; op < SC_MAX_AC_OPS; op++) {
		newf->acl[op] = NULL;
		e = sc_file_get_acl_entry(src, op);
		if (e != NULL)
			sc_file_add_acl_entry(newf, op, e->method, e->key_ref);
	}
}

inline int sc_file_valid(const struct sc_file *file) {
#ifndef NDEBUG
	assert(file != NULL);
#endif
	return file->magic == SC_FILE_MAGIC;
}
