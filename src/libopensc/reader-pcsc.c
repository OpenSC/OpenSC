/*
 * reader-pcsc.c: Reader driver for PC/SC interface
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
#ifdef HAVE_PCSC
#include "ctbcs.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

/* Default timeout value for SCardGetStatusChange
 * Needs to be increased for some broken PC/SC
 * Lite implementations.
 */
#ifndef SC_CUSTOM_STATUS_TIMEOUT
#define SC_STATUS_TIMEOUT 0
#else
#define SC_STATUS_TIMEOUT SC_CUSTOM_STATUS_TIMEOUT
#endif

/* Some windows specific kludge */
#undef SCARD_PROTOCOL_ANY
#define SCARD_PROTOCOL_ANY (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
#ifdef _WIN32
#define SCARD_SCOPE_GLOBAL SCARD_SCOPE_USER

/* Error printing */
#define PCSC_ERROR(ctx, desc, rv) sc_error(ctx, desc ": %lx\n", rv);

#else

#define PCSC_ERROR(ctx, desc, rv) sc_error(ctx, desc ": %s\n", pcsc_stringify_error(rv));

#endif

#define GET_SLOT_PTR(s, i) (&(s)->slot[(i)])
#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct pcsc_slot_data *) (r)->drv_data)

struct pcsc_global_private_data {
	SCARDCONTEXT pcsc_ctx;
};

struct pcsc_private_data {
	SCARDCONTEXT pcsc_ctx;
	char *reader_name;
	struct pcsc_global_private_data *gpriv;
};

struct pcsc_slot_data {
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE_A readerState;
};

static int pcsc_detect_card_presence(struct sc_reader *reader, struct sc_slot_info *slot);

static int pcsc_ret_to_error(long rv)
{
	switch (rv) {
	case SCARD_W_REMOVED_CARD:
		return SC_ERROR_CARD_REMOVED;
	case SCARD_W_RESET_CARD:
		return SC_ERROR_CARD_RESET;
	case SCARD_E_NOT_TRANSACTED:
		return SC_ERROR_TRANSMIT_FAILED;
	case SCARD_W_UNRESPONSIVE_CARD:
		return SC_ERROR_CARD_UNRESPONSIVE;
	default:
		return SC_ERROR_UNKNOWN;
	}
}

static unsigned int pcsc_proto_to_opensc(DWORD proto)
{
	switch (proto) {
	case SCARD_PROTOCOL_T0:
		return SC_PROTO_T0;
	case SCARD_PROTOCOL_T1:
		return SC_PROTO_T1;
	case SCARD_PROTOCOL_RAW:
		return SC_PROTO_RAW;
	default:
		return 0;
	}
}

static DWORD opensc_proto_to_pcsc(unsigned int proto)
{
	switch (proto) {
	case SC_PROTO_T0:
		return SCARD_PROTOCOL_T0;
	case SC_PROTO_T1:
		return SCARD_PROTOCOL_T1;
	case SC_PROTO_RAW:
		return SCARD_PROTOCOL_RAW;
	default:
		return 0;
	}
}

static int pcsc_transmit(struct sc_reader *reader, struct sc_slot_info *slot,
			 const u8 *sendbuf, size_t sendsize,
			 u8 *recvbuf, size_t *recvsize,
			 int control)
{
	SCARD_IO_REQUEST sSendPci, sRecvPci;
	DWORD dwSendLength, dwRecvLength;
	LONG rv;
	SCARDHANDLE card;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

	assert(pslot != NULL);
	card = pslot->pcsc_card;

	sSendPci.dwProtocol = opensc_proto_to_pcsc(slot->active_protocol);
	sSendPci.cbPciLength = sizeof(sSendPci);
	sRecvPci.dwProtocol = opensc_proto_to_pcsc(slot->active_protocol);
	sRecvPci.cbPciLength = sizeof(sRecvPci);
	
	dwSendLength = sendsize;
	dwRecvLength = *recvsize;

        if (dwRecvLength > 258)
		dwRecvLength = 258;

	if (!control) {
		rv = SCardTransmit(card, &sSendPci, sendbuf, dwSendLength,
				   &sRecvPci, recvbuf, &dwRecvLength);
	} else {
#ifdef HAVE_PCSC_OLD
		rv = SCardControl(card, sendbuf, dwSendLength,
				  recvbuf, &dwRecvLength);
#else
		rv = SCardControl(card, 0, sendbuf, dwSendLength,
				  recvbuf, dwRecvLength, &dwRecvLength);
#endif
	}

	if (rv != SCARD_S_SUCCESS) {
		switch (rv) {
		case SCARD_W_REMOVED_CARD:
			return SC_ERROR_CARD_REMOVED;
		case SCARD_W_RESET_CARD:
			return SC_ERROR_CARD_RESET;
		case SCARD_E_NOT_TRANSACTED:
			if ((pcsc_detect_card_presence(reader, slot) &
			    SC_SLOT_CARD_PRESENT) == 0)
				return SC_ERROR_CARD_REMOVED;
			return SC_ERROR_TRANSMIT_FAILED;
                default:
                	/* Windows' PC/SC returns 0x8010002f (??) if a card is removed */
			if (pcsc_detect_card_presence(reader, slot) != 1)
				return SC_ERROR_CARD_REMOVED;
                        PCSC_ERROR(reader->ctx, "SCardTransmit failed", rv);
			return SC_ERROR_TRANSMIT_FAILED;
		}
	}
	if (dwRecvLength < 2)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	*recvsize = dwRecvLength;
	
	return 0;
}

static int refresh_slot_attributes(struct sc_reader *reader, struct sc_slot_info *slot)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	LONG ret;

	if (pslot->readerState.szReader == NULL) {
		pslot->readerState.szReader = priv->reader_name;
		pslot->readerState.dwCurrentState = SCARD_STATE_UNAWARE;
		pslot->readerState.dwEventState = SCARD_STATE_UNAWARE;
	} else {
		pslot->readerState.dwCurrentState = pslot->readerState.dwEventState;
	}

	ret = SCardGetStatusChange(priv->pcsc_ctx, SC_STATUS_TIMEOUT, &pslot->readerState, 1);
	if (ret == SCARD_E_TIMEOUT) { /* timeout: nothing changed */
		slot->flags &= ~SCARD_STATE_CHANGED;
		return 0;
	}
	if (ret != 0) {
		PCSC_ERROR(reader->ctx, "SCardGetStatusChange failed", ret);
		return pcsc_ret_to_error(ret);
	}
	if (pslot->readerState.dwEventState & SCARD_STATE_PRESENT) {
		int old_flags = slot->flags;
		int maybe_changed = 0;

		slot->flags |= SC_SLOT_CARD_PRESENT;
		slot->atr_len = pslot->readerState.cbAtr;
		if (slot->atr_len > SC_MAX_ATR_SIZE)
			slot->atr_len = SC_MAX_ATR_SIZE;
		memcpy(slot->atr, pslot->readerState.rgbAtr, slot->atr_len);

#ifndef _WIN32
		/* On Linux, SCARD_STATE_CHANGED always means there was an
		 * insert or removal. But we may miss events that way. */ 
		if (pslot->readerState.dwEventState & SCARD_STATE_CHANGED) {
			slot->flags |= SC_SLOT_CARD_CHANGED; 
		} else { 
			maybe_changed = 1; 
		} 
#else
		/* On windows, SCARD_STATE_CHANGED is turned on by lots of 
		 * other events, so it gives us a lot of false positives. 
		 * But if it's off, there really no change */ 
		if (pslot->readerState.dwEventState & SCARD_STATE_CHANGED) { 
			maybe_changed = 1; 
		} 
#endif
		/* If we aren't sure if the card state changed, check if 
		 * the card handle is still valid. If the card changed, 
		 * the handle will be invalid. */
		slot->flags &= ~SC_SLOT_CARD_CHANGED;
		if (maybe_changed && (old_flags & SC_SLOT_CARD_PRESENT)) {
			DWORD readers_len = 0, state, prot, atr_len = 32;
			unsigned char atr[32];
			int rv = SCardStatus(pslot->pcsc_card, NULL, &readers_len,
				&state,	&prot, atr, &atr_len);
			if (rv == SCARD_W_REMOVED_CARD)
				slot->flags |= SC_SLOT_CARD_CHANGED;
		}
	} else {
		slot->flags &= ~(SC_SLOT_CARD_PRESENT|SC_SLOT_CARD_CHANGED);
	}
	return 0;
}

static int pcsc_detect_card_presence(struct sc_reader *reader, struct sc_slot_info *slot)
{
	int rv;

	if ((rv = refresh_slot_attributes(reader, slot)) < 0)
		return rv;
	return slot->flags;
}

/* Wait for an event to occur.
 * This function ignores the list of slots, because with
 * pcsc we have a 1:1 mapping of readers and slots anyway
 */
static int pcsc_wait_for_event(struct sc_reader **readers,
			       struct sc_slot_info **slots,
			       size_t nslots,
                               unsigned int event_mask,
                               int *reader,
			       unsigned int *event, int timeout)
{
	struct sc_context *ctx;
	SCARDCONTEXT pcsc_ctx;
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	unsigned long on_bits, off_bits;
	time_t end_time, now, delta;
	int i;

	/* Prevent buffer overflow */
	if (nslots >= SC_MAX_READERS)
	       return SC_ERROR_INVALID_ARGUMENTS;

	on_bits = off_bits = 0;
	if (event_mask & SC_EVENT_CARD_INSERTED) {
		event_mask &= ~SC_EVENT_CARD_INSERTED;
		on_bits |= SCARD_STATE_PRESENT;
	}
	if (event_mask & SC_EVENT_CARD_REMOVED) {
		event_mask &= ~SC_EVENT_CARD_REMOVED;
		off_bits |= SCARD_STATE_PRESENT;
	}
	if (event_mask != 0)
	       return SC_ERROR_INVALID_ARGUMENTS;

	/* Find out the current status */
	ctx = readers[0]->ctx;
	pcsc_ctx = GET_PRIV_DATA(readers[0])->pcsc_ctx;
	for (i = 0; i < nslots; i++) {
		struct pcsc_private_data *priv = GET_PRIV_DATA(readers[i]);

		rgReaderStates[i].szReader = priv->reader_name;
		rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;

		/* Can we handle readers from different PCSC contexts? */
		if (priv->pcsc_ctx != pcsc_ctx)
			return SC_ERROR_INVALID_ARGUMENTS;
	}

	ret = SCardGetStatusChange(pcsc_ctx, 0, rgReaderStates, nslots);
	if (ret != 0) {
		PCSC_ERROR(ctx, "SCardGetStatusChange(1) failed", ret);
		return pcsc_ret_to_error(ret);
	}

	time(&now);
	end_time = now + (timeout + 999) / 1000;

	/* Wait for a status change and return if it's a card insert/removal
	 */
	for( ; ; ) {
		SCARD_READERSTATE_A *rsp;

		/* Scan the current state of all readers to see if they
		 * match any of the events we're polling for */
		*event = 0;
	       	for (i = 0, rsp = rgReaderStates; i < nslots; i++, rsp++) {
			unsigned long state, prev_state;

			prev_state = rsp->dwCurrentState;
			state = rsp->dwEventState;
			if ((state & on_bits & SCARD_STATE_PRESENT) &&
			    (prev_state & SCARD_STATE_EMPTY))
				*event |= SC_EVENT_CARD_INSERTED;
			if ((~state & off_bits & SCARD_STATE_PRESENT) &&
			    (prev_state & SCARD_STATE_PRESENT))
				*event |= SC_EVENT_CARD_REMOVED;
			if (*event) {
				*reader = i;
			       	return 0;
		       	}

			/* No match - copy the state so pcscd knows
			 * what to watch out for */
			rsp->dwCurrentState = rsp->dwEventState;
	       	}

		/* Set the timeout if caller wants to time out */
		if (timeout == 0)
			return SC_ERROR_EVENT_TIMEOUT;
		if (timeout > 0) {
			time(&now);
			if (now >= end_time)
				return SC_ERROR_EVENT_TIMEOUT;
			delta = end_time - now;
		} else {
			delta = 3600;
		}

		ret = SCardGetStatusChange(pcsc_ctx, 1000 * delta,
				rgReaderStates, nslots);
	       	if (ret == SCARD_E_TIMEOUT) {
			if (timeout < 0)
				continue;
		       	return SC_ERROR_EVENT_TIMEOUT;
		}
	       	if (ret != 0) {
		       	PCSC_ERROR(ctx, "SCardGetStatusChange(2) failed", ret);
		       	return pcsc_ret_to_error(ret);
	       	}

	}
}

static int pcsc_connect(struct sc_reader *reader, struct sc_slot_info *slot)
{
	DWORD active_proto, protocol;
	SCARDHANDLE card_handle;
	LONG rv;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	int r;

	r = refresh_slot_attributes(reader, slot);
	if (r)
		return r;
	if (!(slot->flags & SC_SLOT_CARD_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	/* force a protocol, addon by -mp */	
	if (reader->driver->forced_protocol) {
		protocol = opensc_proto_to_pcsc(reader->driver->forced_protocol);
	} else
		protocol = SCARD_PROTOCOL_ANY;
		
	rv = SCardConnect(priv->pcsc_ctx, priv->reader_name,
		SCARD_SHARE_SHARED, protocol, &card_handle, &active_proto);
	if (rv != 0) {
		PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
		return pcsc_ret_to_error(rv);
	}
	slot->active_protocol = pcsc_proto_to_opensc(active_proto);
	pslot->pcsc_card = card_handle;

	return 0;
}

static int pcsc_disconnect(struct sc_reader *reader, struct sc_slot_info *slot,
			   int action)
{
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

	/* FIXME: check action */
	SCardDisconnect(pslot->pcsc_card, SCARD_LEAVE_CARD);
	memset(pslot, 0, sizeof(*pslot));
	slot->flags = 0;
	return 0;
}
                                          
static int pcsc_lock(struct sc_reader *reader, struct sc_slot_info *slot)
{
	long rv;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

	assert(pslot != NULL);
        rv = SCardBeginTransaction(pslot->pcsc_card);
        if (rv != SCARD_S_SUCCESS) {
		PCSC_ERROR(reader->ctx, "SCardBeginTransaction failed", rv);
                return pcsc_ret_to_error(rv);
        }
	return 0;
}

static int pcsc_unlock(struct sc_reader *reader, struct sc_slot_info *slot)
{
	long rv;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

	assert(pslot != NULL);
	rv = SCardEndTransaction(pslot->pcsc_card, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_ERROR(reader->ctx, "SCardEndTransaction failed", rv);
                return pcsc_ret_to_error(rv);
	}
	return 0;
}

static int pcsc_release(struct sc_reader *reader)
{
	int i;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	free(priv->reader_name);
	free(priv);
	for (i = 0; i < reader->slot_count; i++) {
		if (reader->slot[i].drv_data != NULL) {
			free(reader->slot[i].drv_data);
			reader->slot[i].drv_data = NULL;
		}
	}
	return 0;
}

static struct sc_reader_operations pcsc_ops;

static struct sc_reader_driver pcsc_drv = {
	"PC/SC reader",
	"pcsc",
	&pcsc_ops
};

static int pcsc_init(struct sc_context *ctx, void **reader_data)
{
	LONG rv;
	DWORD reader_buf_size;
	char *reader_buf, *p;
	const char *mszGroups = NULL;
	SCARDCONTEXT pcsc_ctx;
	int r, i;
	struct pcsc_global_private_data *gpriv;
	scconf_block **blocks = NULL, *conf_block = NULL;

        rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL,
                                   NULL,
                                   NULL,
				   &pcsc_ctx);
	if (rv != SCARD_S_SUCCESS)
		return pcsc_ret_to_error(rv);
	rv = SCardListReaders(pcsc_ctx, NULL, NULL,
			 (LPDWORD) &reader_buf_size);
	if (rv != SCARD_S_SUCCESS || reader_buf_size < 2) {
		SCardReleaseContext(pcsc_ctx);
		return pcsc_ret_to_error(rv);	/* No readers configured */
	}
	gpriv = (struct pcsc_global_private_data *) malloc(sizeof(struct pcsc_global_private_data));
	if (gpriv == NULL) {
		SCardReleaseContext(pcsc_ctx);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	gpriv->pcsc_ctx = pcsc_ctx;
	*reader_data = gpriv;
	
	reader_buf = (char *) malloc(sizeof(char) * reader_buf_size);
	if (!reader_buf) {
		free(gpriv);
		*reader_data = NULL;
		SCardReleaseContext(pcsc_ctx);
		return SC_ERROR_OUT_OF_MEMORY;
	}
	rv = SCardListReaders(pcsc_ctx, mszGroups, reader_buf,
				(LPDWORD) &reader_buf_size);
	if (rv != SCARD_S_SUCCESS) {
		free(reader_buf);
		free(gpriv);
		*reader_data = NULL;
		SCardReleaseContext(pcsc_ctx);
		return pcsc_ret_to_error(rv);
	}
	p = reader_buf;
	do {
		struct sc_reader *reader = (struct sc_reader *) malloc(sizeof(struct sc_reader));
		struct pcsc_private_data *priv = (struct pcsc_private_data *) malloc(sizeof(struct pcsc_private_data));
		struct pcsc_slot_data *pslot = (struct pcsc_slot_data *) malloc(sizeof(struct pcsc_slot_data));
		struct sc_slot_info *slot;
		
		if (reader == NULL || priv == NULL || pslot == NULL) {
			if (reader)
				free(reader);
			if (priv)
				free(priv);
			if (pslot)
				free(pslot);
			break;
		}

		memset(reader, 0, sizeof(*reader));
		reader->drv_data = priv;
		reader->ops = &pcsc_ops;
		reader->driver = &pcsc_drv;
		reader->slot_count = 1;
		reader->name = strdup(p);
		priv->gpriv = gpriv;
		priv->pcsc_ctx = pcsc_ctx;
		priv->reader_name = strdup(p);
		r = _sc_add_reader(ctx, reader);
		if (r) {
			free(priv->reader_name);
			free(priv);
			free(reader->name);
			free(reader);
			free(pslot);
			break;
		}
		slot = &reader->slot[0];
		memset(slot, 0, sizeof(*slot));
		slot->drv_data = pslot;
		memset(pslot, 0, sizeof(*pslot));
		refresh_slot_attributes(reader, slot);

		while (*p++ != 0);
	} while (p < (reader_buf + reader_buf_size - 1));
	free(reader_buf);
	
	for (i = 0; ctx->conf_blocks[i] != NULL; i++) {
		blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[i],
					    "reader_driver", "pcsc");
		conf_block = blocks[0];
		free(blocks);
		if (conf_block != NULL)
			break;
	}

	return 0;
}

static int pcsc_finish(struct sc_context *ctx, void *prv_data)
{
	struct pcsc_global_private_data *priv = (struct pcsc_global_private_data *) prv_data;

	if (priv) {
		SCardReleaseContext(priv->pcsc_ctx);
		free(priv);
	}
	
	return 0;
}

struct sc_reader_driver * sc_get_pcsc_driver(void)
{
	pcsc_ops.init = pcsc_init;
	pcsc_ops.finish = pcsc_finish;
	pcsc_ops.transmit = pcsc_transmit;
	pcsc_ops.detect_card_presence = pcsc_detect_card_presence;
	pcsc_ops.lock = pcsc_lock;
	pcsc_ops.unlock = pcsc_unlock;
	pcsc_ops.release = pcsc_release;
	pcsc_ops.connect = pcsc_connect;
	pcsc_ops.disconnect = pcsc_disconnect;
	pcsc_ops.perform_verify = ctbcs_pin_cmd;
	pcsc_ops.wait_for_event = pcsc_wait_for_event;
	
	return &pcsc_drv;
}

#endif	/* HAVE_PCSC */
