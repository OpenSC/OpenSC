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
#warning FIXME: version info
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

int sc_detect_card(struct sc_context *ctx, int reader)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, 1);
	if (reader >= ctx->reader_count || reader < 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	rgReaderStates[0].szReader = ctx->readers[reader];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
	rgReaderStates[0].dwEventState = SCARD_STATE_UNAWARE;
	ret = SCardGetStatusChange(ctx->pcsc_ctx, SC_STATUS_TIMEOUT, rgReaderStates, 1);
	if (ret != 0) {
		error(ctx, "SCardGetStatusChange failed: %s\n", pcsc_stringify_error(ret));
		SC_FUNC_RETURN(ctx, 1, -1);	/* FIXME */
	}
	if (rgReaderStates[0].dwEventState & SCARD_STATE_PRESENT) {
		if (ctx->debug >= 1)
			debug(ctx, "card present\n");
		return 1;
	}
	if (ctx->debug >= 1)
		debug(ctx, "card absent\n");
	return 0;
}

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

int sc_establish_context(struct sc_context **ctx_out)
{
	struct sc_context *ctx;
	LONG rv;
	DWORD reader_buf_size;
	char *reader_buf, *p;
	LPCSTR mszGroups = NULL;
	int i;

	assert(ctx_out != NULL);
	ctx = malloc(sizeof(struct sc_context));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(ctx, sizeof(struct sc_context), 0);
	ctx->use_cache = 1;
	rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL, "localhost", NULL,
				   &ctx->pcsc_ctx);
	if (rv != SCARD_S_SUCCESS)
		return SC_ERROR_CONNECTING_TO_RES_MGR;
	SCardListReaders(ctx->pcsc_ctx, NULL, NULL,
			 (LPDWORD) &reader_buf_size);
	if (reader_buf_size < 2) {
		free(ctx);
		return SC_ERROR_NO_READERS_FOUND;
	}
	reader_buf = (char *) malloc(sizeof(char) * reader_buf_size);
	SCardListReaders(ctx->pcsc_ctx, mszGroups, reader_buf,
			 (LPDWORD) &reader_buf_size);
	p = reader_buf;
	ctx->reader_count = 0;
	do {
		ctx->readers[ctx->reader_count] = strdup(p);
		ctx->reader_count++;
		while (*p++ != 0);
		if (ctx->reader_count == SC_MAX_READERS)
			break;
	} while (p < (reader_buf + reader_buf_size - 1));
	free(reader_buf);
	pthread_mutex_init(&ctx->mutex, NULL);
	ctx->forced_driver = NULL;
	for (i = 0; i < SC_MAX_CARD_DRIVERS+1; i++)
		ctx->card_drivers[i] = NULL;
	i = 0;
#if 1
	ctx->card_drivers[i++] = sc_get_setec_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_flex_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_iso7816_driver();
#endif
#if 1
	ctx->card_drivers[i++] = sc_get_emv_driver();
#endif
#if 1
	/* this should be last in line */
	ctx->card_drivers[i++] = sc_get_default_driver();
#endif

	*ctx_out = ctx;
	return 0;
}

int sc_destroy_context(struct sc_context *ctx)
{
	int i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx, 1);
	for (i = 0; i < ctx->reader_count; i++)
		free(ctx->readers[i]);
	free(ctx);
	return 0;
}

int sc_set_card_driver(struct sc_context *ctx, const char *short_name)
{
	int i = 0, match = 0;
	
	pthread_mutex_lock(&ctx->mutex);
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
	pthread_mutex_unlock(&ctx->mutex);
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
	return;
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
		"Record not found"
	};
	int nr_errors = sizeof(errors) / sizeof(errors[0]);

	error -= SC_ERROR_MIN;
	if (error < 0)
		error = -error;

	if (error >= nr_errors)
		return errors[0];
	return errors[error];
}

inline int sc_file_valid(const struct sc_file *file) {
#ifndef NDEBUG
	assert(file != NULL);
#endif
	return file->magic == SC_FILE_MAGIC;
}
