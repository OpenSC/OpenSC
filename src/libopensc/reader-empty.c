/*
 * reader-none.c: Reader driver stub with no functionality
 *
 * Copyright (C) 2026  Vyacheslav Yurkov <uvv.mail@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "internal.h"

static int
empty_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	return 0;
}

static int
empty_detect_card_presence(sc_reader_t *reader)
{
	return SC_SUCCESS;
}

static int
empty_connect(sc_reader_t *reader)
{
	return SC_SUCCESS;
}

static int
empty_disconnect(sc_reader_t * reader)
{
	return SC_SUCCESS;
}

static int
empty_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	return SC_SUCCESS;
}

static int
empty_lock(sc_reader_t *reader)
{
	return SC_SUCCESS;
}

static int
empty_unlock(sc_reader_t *reader)
{
	return SC_SUCCESS;
}

static int
empty_release(sc_reader_t *reader)
{
	return SC_SUCCESS;
}

static int
empty_reset(sc_reader_t *reader, int do_cold_reset)
{
	return SC_SUCCESS;
}

static int
empty_cancel(sc_context_t *ctx)
{
	return SC_SUCCESS;
}

static int
empty_init(sc_context_t *ctx)
{
	return SC_SUCCESS;
}

static int
empty_finish(sc_context_t *ctx)
{
	return SC_SUCCESS;
}

static int
empty_detect_readers(sc_context_t *ctx)
{
	return SC_SUCCESS;
}

static int
empty_wait_for_event(sc_context_t *ctx, unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event,
		int timeout, void **reader_states)
{
	return SC_SUCCESS;
}

int
empty_perform_pace(struct sc_reader *reader, void *input_pace, void *output_pace)
{
	return SC_SUCCESS;
}

int
empty_use_reader(sc_context_t *ctx, void *empty_context_handle, void *empty_card_handle)
{
	return SC_SUCCESS;
}

static struct sc_reader_operations empty_ops;

static struct sc_reader_driver empty_drv = {
	"Empty reader",
	"none",
	&empty_ops,
	NULL
};

struct sc_reader_driver *
sc_get_empty_driver(void)
{
	empty_ops.init = empty_init;
	empty_ops.finish = empty_finish;
	empty_ops.detect_readers = empty_detect_readers;
	empty_ops.transmit = empty_transmit;
	empty_ops.detect_card_presence = empty_detect_card_presence;
	empty_ops.lock = empty_lock;
	empty_ops.unlock = empty_unlock;
	empty_ops.release = empty_release;
	empty_ops.connect = empty_connect;
	empty_ops.disconnect = empty_disconnect;
	empty_ops.perform_verify = empty_pin_cmd;
	empty_ops.wait_for_event = empty_wait_for_event;
	empty_ops.cancel = empty_cancel;
	empty_ops.reset = empty_reset;
	empty_ops.use_reader = empty_use_reader;
	empty_ops.perform_pace = empty_perform_pace;

	return &empty_drv;
}
