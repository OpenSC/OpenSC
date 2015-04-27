/*
 * card.c: General smart card functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#include <assert.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "common/compat_strlcpy.h"

/*
#define INVALIDATE_CARD_CACHE_IN_UNLOCK
*/

#ifdef ENABLE_SM
static int sc_card_sm_load(sc_card_t *card, const char *path, const char *module);
static int sc_card_sm_unload(sc_card_t *card);
static int sc_card_sm_check(sc_card_t *card);
#endif

int sc_check_sw(sc_card_t *card, unsigned int sw1, unsigned int sw2)
{
	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->ops->check_sw == NULL)
		return SC_ERROR_NOT_SUPPORTED;
	return card->ops->check_sw(card, sw1, sw2);
}

void sc_format_apdu(sc_card_t *card, sc_apdu_t *apdu,
		    int cse, int ins, int p1, int p2)
{
	assert(card != NULL && apdu != NULL);
	memset(apdu, 0, sizeof(*apdu));
	apdu->cla = (u8) card->cla;
	apdu->cse = cse;
	apdu->ins = (u8) ins;
	apdu->p1 = (u8) p1;
	apdu->p2 = (u8) p2;
}

static sc_card_t * sc_card_new(sc_context_t *ctx)
{
	sc_card_t *card;

	if (ctx == NULL)
		return NULL;

	card = calloc(1, sizeof(struct sc_card));
	if (card == NULL)
		return NULL;
	card->ops = malloc(sizeof(struct sc_card_operations));
	if (card->ops == NULL) {
		free(card);
		return NULL;
	}

	card->ctx = ctx;
	if (sc_mutex_create(ctx, &card->mutex) != SC_SUCCESS) {
		free(card->ops);
		free(card);
		return NULL;
	}

	card->type = -1;
	card->app_count = -1;

	return card;
}

static void sc_card_free(sc_card_t *card)
{
	sc_free_apps(card);
	sc_free_ef_atr(card);

	if (card->ef_dir != NULL)
		sc_file_free(card->ef_dir);

	free(card->ops);

	if (card->algorithms != NULL)   {
		int i;
		for (i=0; i<card->algorithm_count; i++)   {
			struct sc_algorithm_info *info = (card->algorithms + i);
			if (info->algorithm == SC_ALGORITHM_EC)   {
				struct sc_ec_parameters ep = info->u._ec.params;

				free(ep.named_curve);
				free(ep.der.value);
			}
		}
		free(card->algorithms);

		card->algorithms = NULL;
		card->algorithm_count = 0;
	}

	if (card->cache.current_ef)
		sc_file_free(card->cache.current_ef);

	if (card->cache.current_df)
		sc_file_free(card->cache.current_df);

	if (card->mutex != NULL) {
		int r = sc_mutex_destroy(card->ctx, card->mutex);
		if (r != SC_SUCCESS)
			sc_log(card->ctx, "unable to destroy mutex");
	}
	sc_mem_clear(card, sizeof(*card));
	free(card);
}

int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out)
{
	sc_card_t *card;
	sc_context_t *ctx;
	struct sc_card_driver *driver;
	int i, r = 0, idx, connected = 0;

	if (card_out == NULL || reader == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	ctx = reader->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);
	if (reader->ops->connect == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	card = sc_card_new(ctx);
	if (card == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	r = reader->ops->connect(reader);
	if (r)
		goto err;

	connected = 1;
	card->reader = reader;
	card->ctx = ctx;

	memcpy(&card->atr, &reader->atr, sizeof(card->atr));

	_sc_parse_atr(reader);

	/* See if the ATR matches any ATR specified in the config file */
	if ((driver = ctx->forced_driver) == NULL) {
		sc_log(ctx, "matching configured ATRs");
		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			driver = ctx->card_drivers[i];

			if (driver->atr_map == NULL ||
			    !strcmp(driver->short_name, "default")) {
				driver = NULL;
				continue;
			}
			sc_log(ctx, "trying driver '%s'", driver->short_name);
			idx = _sc_match_atr(card, driver->atr_map, NULL);
			if (idx >= 0) {
				struct sc_atr_table *src = &driver->atr_map[idx];

				sc_log(ctx, "matched driver '%s'", driver->name);
				/* It's up to card driver to notice these correctly */
				card->name = src->name;
				card->type = src->type;
				card->flags = src->flags;
				break;
			}
			driver = NULL;
		}
	}

	if (driver != NULL) {
		/* Forced driver, or matched via ATR mapping from config file */
		card->driver = driver;

		memcpy(card->ops, card->driver->ops, sizeof(struct sc_card_operations));
		if (card->ops->match_card != NULL)
			if (card->ops->match_card(card) != 1)
				sc_log(ctx, "driver '%s' match_card() failed: %s (will continue anyway)", card->driver->name, sc_strerror(r));

		if (card->ops->init != NULL) {
			r = card->ops->init(card);
			if (r) {
				sc_log(ctx, "driver '%s' init() failed: %s", card->driver->name, sc_strerror(r));
				goto err;
			}
		}
	}
	else {
		sc_log(ctx, "matching built-in ATRs");
		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			struct sc_card_driver *drv = ctx->card_drivers[i];
			const struct sc_card_operations *ops = drv->ops;

			sc_log(ctx, "trying driver '%s'", drv->short_name);
			if (ops == NULL || ops->match_card == NULL)   {
				continue;
			}
			else if (!ctx->enable_default_driver && !strcmp("default", drv->short_name))   {
				sc_log(ctx , "ignore 'default' card driver");
				continue;
			}

			/* Needed if match_card() needs to talk with the card (e.g. card-muscle) */
			*card->ops = *ops;
			if (ops->match_card(card) != 1)
				continue;
			sc_log(ctx, "matched: %s", drv->name);
			memcpy(card->ops, ops, sizeof(struct sc_card_operations));
			card->driver = drv;
			r = ops->init(card);
			if (r) {
				sc_log(ctx, "driver '%s' init() failed: %s", drv->name, sc_strerror(r));
				if (r == SC_ERROR_INVALID_CARD) {
					card->driver = NULL;
					continue;
				}
				goto err;
			}
			break;
		}
	}
	if (card->driver == NULL) {
		sc_log(ctx, "unable to find driver for inserted card");
		r = SC_ERROR_INVALID_CARD;
		goto err;
	}
	if (card->name == NULL)
		card->name = card->driver->name;

	/*  Override card limitations with reader limitations.
	 *  Note that zero means no limitations at all.
	 */
	if ((card->max_recv_size == 0) ||
			((reader->driver->max_recv_size != 0) && (reader->driver->max_recv_size < card->max_recv_size)))
		card->max_recv_size = reader->driver->max_recv_size;

	if ((card->max_send_size == 0) ||
			((reader->driver->max_send_size != 0) && (reader->driver->max_send_size < card->max_send_size)))
		card->max_send_size = reader->driver->max_send_size;

	sc_log(ctx, "card info name:'%s', type:%i, flags:0x%X, max_send/recv_size:%i/%i",
		card->name, card->type, card->flags, card->max_send_size, card->max_recv_size);

#ifdef ENABLE_SM
        /* Check, if secure messaging module present. */
	r = sc_card_sm_check(card);
	if (r)   {
		sc_log(ctx, "cannot load secure messaging module");
		goto err;
	}
#endif
	*card_out = card;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
err:
	if (connected)
		reader->ops->disconnect(reader);
	if (card != NULL)
		sc_card_free(card);
	LOG_FUNC_RETURN(ctx, r);
}

int sc_disconnect_card(sc_card_t *card)
{
	sc_context_t *ctx;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);

	assert(card->lock_count == 0);
	if (card->ops->finish) {
		int r = card->ops->finish(card);
		if (r)
			sc_log(ctx, "card driver finish() failed: %s", sc_strerror(r));
	}

	if (card->reader->ops->disconnect) {
		int r = card->reader->ops->disconnect(card->reader);
		if (r)
			sc_log(ctx, "disconnect() failed: %s", sc_strerror(r));
	}

#ifdef ENABLE_SM
	/* release SM related resources */
	sc_card_sm_unload(card);
#endif

	sc_card_free(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

int sc_reset(sc_card_t *card, int do_cold_reset)
{
	int r, r2;

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;
	if (card->reader->ops->reset == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		return r;

	r = card->reader->ops->reset(card->reader, do_cold_reset);
	/* invalidate cache */
	memset(&card->cache, 0, sizeof(card->cache));
	card->cache.valid = 0;

	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release lock");
		r = r != SC_SUCCESS ? r : r2;
	}

	return r;
}

int sc_lock(sc_card_t *card)
{
	int r = 0, r2 = 0;

	if (card == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		return r;
	if (card->lock_count == 0) {
		if (card->reader->ops->lock != NULL) {
			r = card->reader->ops->lock(card->reader);
			if (r == SC_ERROR_CARD_RESET || r == SC_ERROR_READER_REATTACHED) {
				/* invalidate cache */
				memset(&card->cache, 0, sizeof(card->cache));
				card->cache.valid = 0;
#ifdef ENABLE_SM
				if (card->sm_ctx.ops.open)
					card->sm_ctx.ops.open(card);
#endif
				r = card->reader->ops->lock(card->reader);
			}
		}
		if (r == 0)
			card->cache.valid = 1;
	}
	if (r == 0)
		card->lock_count++;
	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release lock");
		r = r != SC_SUCCESS ? r : r2;
	}

	return r;
}

int sc_unlock(sc_card_t *card)
{
	int r, r2;

	if (!card)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	r = sc_mutex_lock(card->ctx, card->mutex);
	if (r != SC_SUCCESS)
		return r;

	assert(card->lock_count >= 1);
	if (--card->lock_count == 0) {
#ifdef INVALIDATE_CARD_CACHE_IN_UNLOCK
		/* invalidate cache */
		memset(&card->cache, 0, sizeof(card->cache));
		card->cache.valid = 0;
		sc_log(card->ctx, "cache invalidated");
#endif
		/* release reader lock */
		if (card->reader->ops->unlock != NULL)
			r = card->reader->ops->unlock(card->reader);
	}
	r2 = sc_mutex_unlock(card->ctx, card->mutex);
	if (r2 != SC_SUCCESS) {
		sc_log(card->ctx, "unable to release lock");
		r = (r == SC_SUCCESS) ? r2 : r;
	}

	return r;
}

int sc_list_files(sc_card_t *card, u8 *buf, size_t buflen)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->list_files == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->list_files(card, buf, buflen);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_create_file(sc_card_t *card, sc_file_t *file)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];
	const sc_path_t *in_path;

	assert(card != NULL && file != NULL);

	in_path = &file->path;
	r = sc_path_print(pbuf, sizeof(pbuf), in_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "called; type=%d, path=%s, size=%u",  in_path->type, pbuf, file->size);
	/* ISO 7816-4: "Number of data bytes in the file, including structural information if any"
	 * can not be bigger than two bytes */
	if (file->size > 0xFFFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (card->ops->create_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->create_file(card, file);
	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_delete_file(sc_card_t *card, const sc_path_t *path)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	assert(card != NULL);

	r = sc_path_print(pbuf, sizeof(pbuf), path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "called; type=%d, path=%s", path->type, pbuf);
	if (card->ops->delete_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->delete_file(card, path);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_read_binary(sc_card_t *card, unsigned int idx,
		   unsigned char *buf, size_t count, unsigned long flags)
{
	size_t max_le = card->max_recv_size > 0 ? card->max_recv_size : 256;
	int r;

	assert(card != NULL && card->ops != NULL && buf != NULL);
	sc_log(card->ctx, "called; %d bytes at index %d", count, idx);
	if (count == 0)
		return 0;

#ifdef ENABLE_SM
	if (card->sm_ctx.ops.read_binary)   {
		r = card->sm_ctx.ops.read_binary(card, idx, buf, count);
		if (r)
			LOG_FUNC_RETURN(card->ctx, r);
	}
#endif
	if (card->ops->read_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (count > max_le) {
		int bytes_read = 0;
		unsigned char *p = buf;

		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		while (count > 0) {
			size_t n = count > max_le ? max_le : count;
			r = sc_read_binary(card, idx, p, n, flags);
			if (r < 0) {
				sc_unlock(card);
				LOG_TEST_RET(card->ctx, r, "sc_read_binary() failed");
			}
			p += r;
			idx += r;
			bytes_read += r;
			count -= r;
			if (r == 0) {
				sc_unlock(card);
				LOG_FUNC_RETURN(card->ctx, bytes_read);
			}
		}
		sc_unlock(card);
		LOG_FUNC_RETURN(card->ctx, bytes_read);
	}
	r = card->ops->read_binary(card, idx, buf, count, flags);
	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_write_binary(sc_card_t *card, unsigned int idx,
		    const u8 *buf, size_t count, unsigned long flags)
{
	size_t max_lc = card->max_send_size > 0 ? card->max_send_size : 255;
	int r;

	assert(card != NULL && card->ops != NULL && buf != NULL);
	sc_log(card->ctx, "called; %d bytes at index %d", count, idx);
	if (count == 0)
		LOG_FUNC_RETURN(card->ctx, 0);
	if (card->ops->write_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (count > max_lc) {
		int bytes_written = 0;
		const u8 *p = buf;

		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		while (count > 0) {
			size_t n = count > max_lc? max_lc : count;
			r = sc_write_binary(card, idx, p, n, flags);
			if (r < 0) {
				sc_unlock(card);
				LOG_TEST_RET(card->ctx, r, "sc_write_binary() failed");
			}
			p += r;
			idx += r;
			bytes_written += r;
			count -= r;
			if (r == 0) {
				sc_unlock(card);
				LOG_FUNC_RETURN(card->ctx, bytes_written);
			}
		}
		sc_unlock(card);
		LOG_FUNC_RETURN(card->ctx, bytes_written);
	}

	r = card->ops->write_binary(card, idx, buf, count, flags);
	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_update_binary(sc_card_t *card, unsigned int idx,
		     const u8 *buf, size_t count, unsigned long flags)
{
	size_t max_lc = card->max_send_size > 0 ? card->max_send_size : 255;
	int r;

	assert(card != NULL && card->ops != NULL && buf != NULL);
	sc_log(card->ctx, "called; %d bytes at index %d", count, idx);
	if (count == 0)
		return 0;

#ifdef ENABLE_SM
	if (card->sm_ctx.ops.update_binary)   {
		r = card->sm_ctx.ops.update_binary(card, idx, buf, count);
		if (r)
			LOG_FUNC_RETURN(card->ctx, r);
	}
#endif

	if (card->ops->update_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	if (count > max_lc) {
		int bytes_written = 0;
		const u8 *p = buf;

		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		while (count > 0) {
			size_t n = count > max_lc? max_lc : count;
			r = sc_update_binary(card, idx, p, n, flags);
			if (r < 0) {
				sc_unlock(card);
				LOG_TEST_RET(card->ctx, r, "sc_update_binary() failed");
			}
			p += r;
			idx += r;
			bytes_written += r;
			count -= r;
			if (r == 0) {
				sc_unlock(card);
				LOG_FUNC_RETURN(card->ctx, bytes_written);
			}
		}
		sc_unlock(card);
		LOG_FUNC_RETURN(card->ctx, bytes_written);
	}

	r = card->ops->update_binary(card, idx, buf, count, flags);
	LOG_FUNC_RETURN(card->ctx, r);
}


int sc_erase_binary(struct sc_card *card, unsigned int offs, size_t count,  unsigned long flags)
{
	int r;

	assert(card != NULL && card->ops != NULL);
	sc_log(card->ctx, "called; erase %d bytes from offset %d", count, offs);

	if (card->ops->erase_binary == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = card->ops->erase_binary(card, offs, count, flags);
	LOG_FUNC_RETURN(card->ctx, r);
}


int sc_select_file(sc_card_t *card, const sc_path_t *in_path,  sc_file_t **file)
{
	int r;
	char pbuf[SC_MAX_PATH_STRING_SIZE];

	assert(card != NULL && in_path != NULL);

	r = sc_path_print(pbuf, sizeof(pbuf), in_path);
	if (r != SC_SUCCESS)
		pbuf[0] = '\0';

	sc_log(card->ctx, "called; type=%d, path=%s", in_path->type, pbuf);
	if (in_path->len > SC_MAX_PATH_SIZE)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (in_path->type == SC_PATH_TYPE_PATH) {
		/* Perform a sanity check */
		size_t i;

		if ((in_path->len & 1) != 0)
			LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

		for (i = 0; i < in_path->len/2; i++) {
			u8 p1 = in_path->value[2*i],
			   p2 = in_path->value[2*i+1];

			if ((p1 == 0x3F && p2 == 0x00) && i != 0)
				LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	if (card->ops->select_file == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->select_file(card, in_path, file);
	LOG_TEST_RET(card->ctx, r, "'SELECT' error");

	/* Remember file path */
	if (file && *file)
		(*file)->path = *in_path;

	LOG_FUNC_RETURN(card->ctx, r);
}


int sc_get_data(sc_card_t *card, unsigned int tag, u8 *buf, size_t len)
{
	int	r;

	sc_log(card->ctx, "called, tag=%04x", tag);
	if (card->ops->get_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->get_data(card, tag, buf, len);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_put_data(sc_card_t *card, unsigned int tag, const u8 *buf, size_t len)
{
	int	r;

	sc_log(card->ctx,"called, tag=%04x", tag);

	if (card->ops->put_data == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->put_data(card, tag, buf, len);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_get_challenge(sc_card_t *card, u8 *rnd, size_t len)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->get_challenge == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->get_challenge(card, rnd, len);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_read_record(sc_card_t *card, unsigned int rec_nr, u8 *buf,
		   size_t count, unsigned long flags)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->read_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->read_record(card, rec_nr, buf, count, flags);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_write_record(sc_card_t *card, unsigned int rec_nr, const u8 * buf,
		    size_t count, unsigned long flags)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->write_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->write_record(card, rec_nr, buf, count, flags);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_append_record(sc_card_t *card, const u8 * buf, size_t count,
		     unsigned long flags)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->append_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->append_record(card, buf, count, flags);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_update_record(sc_card_t *card, unsigned int rec_nr, const u8 * buf,
		     size_t count, unsigned long flags)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->update_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->update_record(card, rec_nr, buf, count, flags);

	LOG_FUNC_RETURN(card->ctx, r);
}

int sc_delete_record(sc_card_t *card, unsigned int rec_nr)
{
	int r;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->delete_record == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->delete_record(card, rec_nr);

	LOG_FUNC_RETURN(card->ctx, r);
}

int
sc_card_ctl(sc_card_t *card, unsigned long cmd, void *args)
{
	int r = SC_ERROR_NOT_SUPPORTED;

	assert(card != NULL);
	LOG_FUNC_CALLED(card->ctx);

	if (card->ops->card_ctl != NULL)
		r = card->ops->card_ctl(card, cmd, args);

	/* suppress "not supported" error messages */
	if (r == SC_ERROR_NOT_SUPPORTED) {
		sc_log(card->ctx, "card_ctl(%lu) not supported", cmd);
		return r;
	}
	LOG_FUNC_RETURN(card->ctx, r);
}

int _sc_card_add_algorithm(sc_card_t *card, const sc_algorithm_info_t *info)
{
	sc_algorithm_info_t *p;

	assert(info != NULL);
	p = (sc_algorithm_info_t *) realloc(card->algorithms, (card->algorithm_count + 1) * sizeof(*info));
	if (!p) {
		if (card->algorithms)
			free(card->algorithms);
		card->algorithms = NULL;
		card->algorithm_count = 0;
		return SC_ERROR_OUT_OF_MEMORY;
	}
	card->algorithms = p;
	p += card->algorithm_count;
	card->algorithm_count++;
	*p = *info;
	return SC_SUCCESS;
}

int  _sc_card_add_ec_alg(sc_card_t *card, unsigned int key_length,
			unsigned long flags, unsigned long ext_flags,
			struct sc_object_id *curve_oid)
{
	sc_algorithm_info_t info;

	memset(&info, 0, sizeof(info));
	sc_init_oid(&info.u._ec.params.id);

	info.algorithm = SC_ALGORITHM_EC;
	info.key_length = key_length;
	info.flags = flags;

	info.u._ec.ext_flags = ext_flags;
	if (curve_oid)
		info.u._ec.params.id = *curve_oid;

	return _sc_card_add_algorithm(card, &info);
}

static sc_algorithm_info_t * sc_card_find_alg(sc_card_t *card,
		unsigned int algorithm, unsigned int key_length, void *param)
{
	int i;

	for (i = 0; i < card->algorithm_count; i++) {
		sc_algorithm_info_t *info = &card->algorithms[i];

		if (info->algorithm != algorithm)
			continue;
		if (info->key_length != key_length)
			continue;
		if (param)   {
			if (info->algorithm == SC_ALGORITHM_EC)
				if(!sc_compare_oid((struct sc_object_id *)param, &info->u._ec.params.id))
					continue;
		}
		return info;
	}
	return NULL;
}

sc_algorithm_info_t * sc_card_find_ec_alg(sc_card_t *card,
		unsigned int key_length, struct sc_object_id *curve_name)
{
	return sc_card_find_alg(card, SC_ALGORITHM_EC, key_length, curve_name);
}

int _sc_card_add_rsa_alg(sc_card_t *card, unsigned int key_length,
			 unsigned long flags, unsigned long exponent)
{
	sc_algorithm_info_t info;

	memset(&info, 0, sizeof(info));
	info.algorithm = SC_ALGORITHM_RSA;
	info.key_length = key_length;
	info.flags = flags;
	info.u._rsa.exponent = exponent;

	return _sc_card_add_algorithm(card, &info);
}

sc_algorithm_info_t * sc_card_find_rsa_alg(sc_card_t *card,
		unsigned int key_length)
{
	return sc_card_find_alg(card, SC_ALGORITHM_RSA, key_length, NULL);
}

sc_algorithm_info_t * sc_card_find_gostr3410_alg(sc_card_t *card,
		unsigned int key_length)
{
	return sc_card_find_alg(card, SC_ALGORITHM_GOSTR3410, key_length, NULL);
}

static int match_atr_table(sc_context_t *ctx, struct sc_atr_table *table, struct sc_atr *atr)
{
	u8 *card_atr_bin;
	size_t card_atr_bin_len;
	char card_atr_hex[3 * SC_MAX_ATR_SIZE];
	size_t card_atr_hex_len;
	unsigned int i = 0;

	if (ctx == NULL || table == NULL || atr == NULL)
		return -1;
	card_atr_bin = atr->value;
	card_atr_bin_len = atr->len;
	sc_bin_to_hex(card_atr_bin, card_atr_bin_len, card_atr_hex, sizeof(card_atr_hex), ':');
	card_atr_hex_len = strlen(card_atr_hex);

	sc_log(ctx, "ATR     : %s", card_atr_hex);

	for (i = 0; table[i].atr != NULL; i++) {
		const char *tatr = table[i].atr;
		const char *matr = table[i].atrmask;
		size_t tatr_len = strlen(tatr);
		u8 mbin[SC_MAX_ATR_SIZE], tbin[SC_MAX_ATR_SIZE];
		size_t mbin_len, tbin_len, s, matr_len;
		size_t fix_hex_len = card_atr_hex_len;
		size_t fix_bin_len = card_atr_bin_len;

		sc_log(ctx, "ATR try : %s", tatr);

		if (tatr_len != fix_hex_len) {
			sc_log(ctx, "ignored - wrong length");
			continue;
		}
		if (matr != NULL) {
			sc_log(ctx, "ATR mask: %s", matr);

			matr_len = strlen(matr);
			if (tatr_len != matr_len)
				continue;
			tbin_len = sizeof(tbin);
			sc_hex_to_bin(tatr, tbin, &tbin_len);
			mbin_len = sizeof(mbin);
			sc_hex_to_bin(matr, mbin, &mbin_len);
			if (mbin_len != fix_bin_len) {
				sc_log(ctx, "length of atr and atr mask do not match - ignored: %s - %s", tatr, matr);
				continue;
			}
			for (s = 0; s < tbin_len; s++) {
				/* reduce tatr with mask */
				tbin[s] = (tbin[s] & mbin[s]);
				/* create copy of card_atr_bin masked) */
				mbin[s] = (card_atr_bin[s] & mbin[s]);
			}
			if (memcmp(tbin, mbin, tbin_len) != 0)
				continue;
		} else {
			if (strncasecmp(tatr, card_atr_hex, tatr_len) != 0)
				continue;
		}
		return i;
	}
	return -1;
}

int _sc_match_atr(sc_card_t *card, struct sc_atr_table *table, int *type_out)
{
	int res;

	if (card == NULL)
		return -1;
	res = match_atr_table(card->ctx, table, &card->atr);
	if (res < 0)
		return res;
	if (type_out != NULL)
		*type_out = table[res].type;
	return res;
}

scconf_block *_sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr)
{
	struct sc_card_driver *drv;
	struct sc_atr_table *table;
	int res;

	if (ctx == NULL)
		return NULL;
	if (driver) {
		drv = driver;
		table = drv->atr_map;
		res = match_atr_table(ctx, table, atr);
		if (res < 0)
			return NULL;
		return table[res].card_atr;
	} else {
		unsigned int i;

		for (i = 0; ctx->card_drivers[i] != NULL; i++) {
			drv = ctx->card_drivers[i];
			table = drv->atr_map;
			res = match_atr_table(ctx, table, atr);
			if (res < 0)
				continue;
			return table[res].card_atr;
		}
	}
	return NULL;
}

int _sc_add_atr(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr_table *src)
{
	struct sc_atr_table *map, *dst;

	map = (struct sc_atr_table *) realloc(driver->atr_map,
			(driver->natrs + 2) * sizeof(struct sc_atr_table));
	if (!map)
		return SC_ERROR_OUT_OF_MEMORY;
	driver->atr_map = map;

	dst = &driver->atr_map[driver->natrs++];
	memset(dst, 0, sizeof(*dst));
	memset(&driver->atr_map[driver->natrs], 0, sizeof(struct sc_atr_table));
	dst->atr = strdup(src->atr);
	if (!dst->atr)
		return SC_ERROR_OUT_OF_MEMORY;

	if (src->atrmask) {
		dst->atrmask = strdup(src->atrmask);
		if (!dst->atrmask)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	else {
		dst->atrmask = NULL;
	}

	if (src->name) {
		dst->name = strdup(src->name);
		if (!dst->name)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	else {
		dst->name = NULL;
	}

	dst->type = src->type;
	dst->flags = src->flags;
	dst->card_atr = src->card_atr;

	return SC_SUCCESS;
}


int _sc_free_atr(sc_context_t *ctx, struct sc_card_driver *driver)
{
	unsigned int i;

	for (i = 0; i < driver->natrs; i++) {
		struct sc_atr_table *src = &driver->atr_map[i];

		if (src->atr)
			free((void *)src->atr);
		if (src->atrmask)
			free((void *)src->atrmask);
		if (src->name)
			free((void *)src->name);
		src->card_atr = NULL;
		src = NULL;
	}
	if (driver->atr_map)
		free(driver->atr_map);
	driver->atr_map = NULL;
	driver->natrs = 0;

	return SC_SUCCESS;
}


scconf_block *sc_get_conf_block(sc_context_t *ctx, const char *name1, const char *name2, int priority)
{
	int i;
	scconf_block *conf_block = NULL;

	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		scconf_block **blocks;

		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i], name1, name2);
		if (blocks != NULL) {
			conf_block = blocks[0];
			free(blocks);
		}
		if (conf_block != NULL && priority)
			break;
	}
	return conf_block;
}

void sc_print_cache(struct sc_card *card)   {
	struct sc_context *ctx = NULL;

	assert(card != NULL);
	ctx = card->ctx;

	if (!card->cache.valid || (!card->cache.current_ef && !card->cache.current_df))   {
		sc_log(ctx, "card cache invalid");
		return;
	}

	if (card->cache.current_ef)
		sc_log(ctx, "current_ef(type=%i) %s", card->cache.current_ef->path.type,
				sc_print_path(&card->cache.current_ef->path));

	if (card->cache.current_df)
		sc_log(ctx, "current_df(type=%i, aid_len=%i) %s", card->cache.current_df->path.type,
				card->cache.current_df->path.aid.len,
				sc_print_path(&card->cache.current_df->path));
}

int sc_copy_ec_params(struct sc_ec_parameters *dst, struct sc_ec_parameters *src)
{
	if (!dst || !src)
		return SC_ERROR_INVALID_ARGUMENTS;

	memset(dst, 0, sizeof(*dst));
	if (src->named_curve)   {
		dst->named_curve = strdup(src->named_curve);
		if (!dst->named_curve)
			return SC_ERROR_OUT_OF_MEMORY;
	}
	dst->id = src->id;
	if (src->der.value && src->der.len)   {
		dst->der.value = malloc(src->der.len);
		if (!dst->der.value)
			return SC_ERROR_OUT_OF_MEMORY;
		memcpy(dst->der.value, src->der.value, src->der.len);
		dst->der.len = src->der.len;
	}
	src->type = dst->type;
	src->field_length = dst->field_length;

	return SC_SUCCESS;
}

scconf_block *
sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr)
{
	return _sc_match_atr_block(ctx, driver, atr);
}

#ifdef ENABLE_SM
static int
sc_card_sm_unload(struct sc_card *card)
{
	if (card->sm_ctx.module.ops.module_cleanup)
		card->sm_ctx.module.ops.module_cleanup(card->ctx);

	if (card->sm_ctx.module.handle)
		sc_dlclose(card->sm_ctx.module.handle);
	card->sm_ctx.module.handle = NULL;
	return 0;
}


static int
sc_card_sm_load(struct sc_card *card, const char *module_path, const char *in_module)
{
	struct sc_context *ctx = NULL;
	int rv = SC_ERROR_INTERNAL;
	char *module = NULL;
#ifdef _WIN32
	char temp_path[PATH_MAX];
	int temp_len;
	long rc;
	HKEY hKey;
	const char path_delim = '\\';
#else
	const char path_delim = '/';
#endif

	assert(card != NULL);
	ctx = card->ctx;
	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	if (!in_module)
		return sc_card_sm_unload(card);

#ifdef _WIN32
	if (!module_path) {
		rc = RegOpenKeyExA( HKEY_CURRENT_USER, "Software\\OpenSC Project\\OpenSC", 0, KEY_QUERY_VALUE, &hKey );
		if( rc == ERROR_SUCCESS ) {
			temp_len = PATH_MAX;
			rc = RegQueryValueExA( hKey, "SmDir", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if( (rc == ERROR_SUCCESS) && (temp_len < PATH_MAX) )
				module_path = temp_path;
			RegCloseKey( hKey );
		}
	}
	if (!module_path) {
		rc = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Software\\OpenSC Project\\OpenSC", 0, KEY_QUERY_VALUE, &hKey );
		if( rc == ERROR_SUCCESS ) {
			temp_len = PATH_MAX;
			rc = RegQueryValueExA( hKey, "SmDir", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if(rc == ERROR_SUCCESS && temp_len < PATH_MAX)
				module_path = temp_path;
			RegCloseKey( hKey );
		}
	}
#endif
	sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "SM module '%s' located in '%s'", in_module, module_path);
	if (module_path)   {
		int sz = strlen(in_module) + strlen(module_path) + 3;
		module = malloc(sz);
		if (module)
			snprintf(module, sz, "%s%c%s", module_path, path_delim, in_module);
	}
	else   {
		module = strdup(in_module);
	}

	if (!module)
		return SC_ERROR_OUT_OF_MEMORY;

	sc_log(ctx, "try to load SM module '%s'", module);
	do  {
		struct sm_module_operations *mod_ops = &card->sm_ctx.module.ops;
		void *mod_handle;

		card->sm_ctx.module.handle = sc_dlopen(module);
		if (!card->sm_ctx.module.handle)   {
			sc_log(ctx, "cannot open dynamic library '%s': %s", module, sc_dlerror());
			break;
		}
		mod_handle = card->sm_ctx.module.handle;

		mod_ops->initialize = sc_dlsym(mod_handle, "initialize");
		if (!mod_ops->initialize)   {
			sc_log(ctx, "SM handler 'initialize' not exported: %s", sc_dlerror());
			break;
		}

		mod_ops->get_apdus  = sc_dlsym(mod_handle, "get_apdus");
		if (!mod_ops->get_apdus)   {
			sc_log(ctx, "SM handler 'get_apdus' not exported: %s", sc_dlerror());
			break;
		}

		mod_ops->finalize  = sc_dlsym(mod_handle, "finalize");
		if (!mod_ops->finalize)
			sc_log(ctx, "SM handler 'finalize' not exported -- ignored");

		mod_ops->module_init  = sc_dlsym(mod_handle, "module_init");
		if (!mod_ops->module_init)
			sc_log(ctx, "SM handler 'module_init' not exported -- ignored");

		mod_ops->module_cleanup  = sc_dlsym(mod_handle, "module_cleanup");
		if (!mod_ops->module_cleanup)
			sc_log(ctx, "SM handler 'module_cleanup' not exported -- ignored");

		mod_ops->test  = sc_dlsym(mod_handle, "test");
		if (mod_ops->test)
			sc_log(ctx, "SM handler 'test' not exported -- ignored");

		rv = 0;
		break;
	} while(0);

	if (rv)
		sc_card_sm_unload(card);

	card->sm_ctx.sm_mode = SM_MODE_ACL;
	if (module)
		free(module);

	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}


/* get SM related configuration settings and initialize SM session, SM module, ... */
static int
sc_card_sm_check(struct sc_card *card)
{
	const char *sm = NULL, *module_name = NULL, *module_path = NULL, *module_data = NULL, *sm_mode = NULL;
	struct sc_context *ctx = card->ctx;
	scconf_block *atrblock = NULL, *sm_conf_block = NULL;
	int rv, ii;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
	sc_log(ctx, "card->sm_ctx.ops.open %p", card->sm_ctx.ops.open);

	/* get the name of card specific SM configuration section */
	atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
	if (atrblock == NULL)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	sm = scconf_get_str(atrblock, "secure_messaging", NULL);
	if (!sm)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	/* get SM configuration section by the name */
	sc_log(ctx, "secure_messaging configuration block '%s'", sm);
        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
		scconf_block **blocks;

                blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}
                if (sm_conf_block != NULL)
			break;
	}

	if (!sm_conf_block)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "SM configuration block not preset");

	/* check if an external SM module has to be used */
	module_path = scconf_get_str(sm_conf_block, "module_path", NULL);
	module_name = scconf_get_str(sm_conf_block, "module_name", NULL);
	sc_log(ctx, "SM module '%s' in  '%s'", module_name, module_path);
	if (!module_name)
		LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "Invalid SM configuration: module not defined");

	rv = sc_card_sm_load(card, module_path, module_name);
	LOG_TEST_RET(ctx, rv, "Failed to load SM module");

	strlcpy(card->sm_ctx.module.filename, module_name, sizeof(card->sm_ctx.module.filename));
	strlcpy(card->sm_ctx.config_section, sm, sizeof(card->sm_ctx.config_section));

	/* allocate resources for the external SM module */
	sc_log(ctx, "'module_init' handler %p", card->sm_ctx.module.ops.module_init);
	if (card->sm_ctx.module.ops.module_init)   {
		module_data = scconf_get_str(sm_conf_block, "module_data", NULL);
		sc_log(ctx, "module_data '%s'", module_data);

		rv = card->sm_ctx.module.ops.module_init(ctx, module_data);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, rv, "Cannot initialize SM module");
	}

	/* initialize SM session in the case of 'APDU TRANSMIT' SM mode */
	sm_mode = scconf_get_str(sm_conf_block, "mode", NULL);
	sc_log(ctx, "SM mode '%s'; 'open' handler %p", sm_mode, card->sm_ctx.ops.open);
	if (sm_mode && !strcasecmp("Transmit", sm_mode))   {
		if (!card->sm_ctx.ops.open || !card->sm_ctx.ops.get_sm_apdu || !card->sm_ctx.ops.free_sm_apdu)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "'Transmit' SM asked but not supported by card driver");

		card->sm_ctx.sm_mode = SM_MODE_TRANSMIT;
		rv = card->sm_ctx.ops.open(card);
		LOG_TEST_RET(ctx, rv, "Cannot initialize SM");
	}

	sc_log(ctx, "SM mode:%X", card->sm_ctx.sm_mode);
	SC_FUNC_RETURN(ctx, SC_LOG_DEBUG_VERBOSE, rv);
}
#endif
