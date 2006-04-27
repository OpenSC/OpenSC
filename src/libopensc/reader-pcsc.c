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
#ifdef PCSC_INCLUDES_IN_PCSC
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#ifdef HAVE_READER_H
#include <reader.h>
#ifdef HOST_TO_CCID_32
#define PINPAD_ENABLED
#endif
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

/* Utility for handling big endian IOCTL codes. */
#define dw2i_be(a, x) ((((((a[x] << 8) + a[x+1]) << 8) + a[x+2]) << 8) + a[x+3])

#define GET_SLOT_PTR(s, i) (&(s)->slot[(i)])
#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)
#define GET_SLOT_DATA(r) ((struct pcsc_slot_data *) (r)->drv_data)

static int part10_pin_cmd(sc_reader_t *reader, sc_slot_info_t *slot,
                          struct sc_pin_cmd_data *data);

struct pcsc_global_private_data {
	SCARDCONTEXT pcsc_ctx;
	int enable_pinpad;
	int connect_exclusive;
	int connect_reset;
	int transaction_reset;
	
};

struct pcsc_private_data {
	SCARDCONTEXT pcsc_ctx;
	char *reader_name;
	struct pcsc_global_private_data *gpriv;
};

struct pcsc_slot_data {
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE_A reader_state;
	DWORD verify_ioctl;
	DWORD modify_ioctl;
	int locked;
};

static int pcsc_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot);

static int pcsc_ret_to_error(long rv)
{
	switch (rv) {
	case SCARD_W_REMOVED_CARD:
		return SC_ERROR_CARD_REMOVED;
	case SCARD_E_NOT_TRANSACTED:
		return SC_ERROR_TRANSMIT_FAILED;
	case SCARD_W_UNRESPONSIVE_CARD:
		return SC_ERROR_CARD_UNRESPONSIVE;
	case SCARD_E_SHARING_VIOLATION:
		return SC_ERROR_READER;
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

static int pcsc_internal_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
			 const u8 *sendbuf, size_t sendsize,
			 u8 *recvbuf, size_t *recvsize,
			 unsigned long control)
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
		rv = SCardControl(card, (DWORD) control, sendbuf, dwSendLength,
				  recvbuf, dwRecvLength, &dwRecvLength);
#endif
	}

	if (rv != SCARD_S_SUCCESS) {
		switch (rv) {
		case SCARD_W_REMOVED_CARD:
			return SC_ERROR_CARD_REMOVED;
		case SCARD_E_NOT_TRANSACTED:
			if (!(pcsc_detect_card_presence(reader, slot) & SC_SLOT_CARD_PRESENT))
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

static int pcsc_transmit(sc_reader_t *reader, sc_slot_info_t *slot,
	sc_apdu_t *apdu)
{
	size_t       ssize, rsize, rbuflen = 0;
	u8           *sbuf = NULL, *rbuf = NULL;
	int          r;

	/* we always use a at least 258 byte size big return buffer
	 * to mimic the behaviour of the old implementation (some readers
	 * seems to require a larger than necessary return buffer).
	 * The buffer for the returned data needs to be at least 2 bytes
	 * larger than the expected data length to store SW1 and SW2. */
	rsize = rbuflen = apdu->resplen <= 256 ? 258 : apdu->resplen + 2;
	rbuf     = malloc(rbuflen);
	if (rbuf == NULL) {
		r = SC_ERROR_MEMORY_FAILURE;
		goto out;
	}
	/* encode and log the APDU */
	r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, slot->active_protocol);
	if (r != SC_SUCCESS)
		goto out;
	/* log data if DEBUG is defined */
#ifdef DEBUG
	sc_apdu_log(reader->ctx, sbuf, ssize, 1);
#endif

	r = pcsc_internal_transmit(reader, slot, sbuf, ssize,
				rbuf, &rsize, apdu->control);
	if (r < 0) {
		/* unable to transmit ... most likely a reader problem */
		sc_error(reader->ctx, "unable to transmit");
		goto out;
	}
	/* log data if DEBUG is defined */
#ifdef DEBUG
	sc_apdu_log(reader->ctx, rbuf, rsize, 0);
#endif
	/* set response */
	r = sc_apdu_set_resp(reader->ctx, apdu, rbuf, rsize);
out:
	if (sbuf != NULL) {
		sc_mem_clear(sbuf, ssize);
		free(sbuf);
	}
	if (rbuf != NULL) {
		sc_mem_clear(rbuf, rbuflen);
		free(rbuf);
	}
	
	return r;
}


static int refresh_slot_attributes(sc_reader_t *reader, sc_slot_info_t *slot)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	LONG ret;

	if (pslot->reader_state.szReader == NULL) {
		pslot->reader_state.szReader = priv->reader_name;
		pslot->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
		pslot->reader_state.dwEventState = SCARD_STATE_UNAWARE;
	} else {
		pslot->reader_state.dwCurrentState = pslot->reader_state.dwEventState;
	}

	ret = SCardGetStatusChange(priv->pcsc_ctx, SC_STATUS_TIMEOUT, &pslot->reader_state, 1);
	if (ret == (LONG)SCARD_E_TIMEOUT) { /* timeout: nothing changed */
		slot->flags &= ~SCARD_STATE_CHANGED;
		return 0;
	}
	if (ret != 0) {
		PCSC_ERROR(reader->ctx, "SCardGetStatusChange failed", ret);
		return pcsc_ret_to_error(ret);
	}
	if (pslot->reader_state.dwEventState & SCARD_STATE_PRESENT) {
		int old_flags = slot->flags;
		int maybe_changed = 0;

		slot->flags |= SC_SLOT_CARD_PRESENT;
		slot->atr_len = pslot->reader_state.cbAtr;
		if (slot->atr_len > SC_MAX_ATR_SIZE)
			slot->atr_len = SC_MAX_ATR_SIZE;
		memcpy(slot->atr, pslot->reader_state.rgbAtr, slot->atr_len);

#ifndef _WIN32
		/* On Linux, SCARD_STATE_CHANGED always means there was an
		 * insert or removal. But we may miss events that way. */
		if (pslot->reader_state.dwEventState & SCARD_STATE_CHANGED) {
			slot->flags |= SC_SLOT_CARD_CHANGED;
		} else {
			maybe_changed = 1;
		}
#else
		/* On windows, SCARD_STATE_CHANGED is turned on by lots of
		 * other events, so it gives us a lot of false positives.
		 * But if it's off, there really no change */
		if (pslot->reader_state.dwEventState & SCARD_STATE_CHANGED) {
			maybe_changed = 1;
		}
#endif
		/* If we aren't sure if the card state changed, check if
		 * the card handle is still valid. If the card changed,
		 * the handle will be invalid. */
		slot->flags &= ~SC_SLOT_CARD_CHANGED;
		if (maybe_changed) {
			if (old_flags & SC_SLOT_CARD_PRESENT) {
				DWORD readers_len = 0, state, prot, atr_len = 32;
				unsigned char atr[32];
				LONG rv = SCardStatus(pslot->pcsc_card, NULL, &readers_len,
					&state,	&prot, atr, &atr_len);
				if (rv == (LONG)SCARD_W_REMOVED_CARD)
					slot->flags |= SC_SLOT_CARD_CHANGED;
			}
			else
				slot->flags |= SC_SLOT_CARD_CHANGED;
		}
	} else {
		slot->flags &= ~(SC_SLOT_CARD_PRESENT|SC_SLOT_CARD_CHANGED);
	}
	return 0;
}

static int pcsc_detect_card_presence(sc_reader_t *reader, sc_slot_info_t *slot)
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
static int pcsc_wait_for_event(sc_reader_t **readers,
			       sc_slot_info_t **slots,
			       size_t nslots,
                               unsigned int event_mask,
                               int *reader,
			       unsigned int *event, int timeout)
{
	sc_context_t *ctx;
	SCARDCONTEXT pcsc_ctx;
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	unsigned long on_bits, off_bits;
	time_t end_time, now, delta;
	size_t i;

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
		if (ret == (LONG) SCARD_E_TIMEOUT) {
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

static int pcsc_reconnect(sc_reader_t * reader, sc_slot_info_t * slot, int reset)
{
	DWORD active_proto, protocol;
	LONG rv;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int r;

	sc_debug(reader->ctx, "Reconnecting to the card...");

	r = refresh_slot_attributes(reader, slot);
	if (r)
		return r;
	if (!(slot->flags & SC_SLOT_CARD_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	if (_sc_check_forced_protocol
	    (reader->ctx, slot->atr, slot->atr_len,
	     (unsigned int *)&protocol)) {
		protocol = opensc_proto_to_pcsc(protocol);
	} else {
		protocol = slot->active_protocol;
	}

	/* reconnect always unlocks transaction */
	pslot->locked = 0;
	
	rv = SCardReconnect(pslot->pcsc_card,
			    priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED, protocol,
			    reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD, &active_proto);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_ERROR(reader->ctx, "SCardReconnect failed", rv);
		return pcsc_ret_to_error(rv);
	}
	slot->active_protocol = pcsc_proto_to_opensc(active_proto);
	return SC_SUCCESS;
}

static int pcsc_connect(sc_reader_t *reader, sc_slot_info_t *slot)
{
	DWORD active_proto, protocol;
	SCARDHANDLE card_handle;
	LONG rv;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	int r;
#ifdef PINPAD_ENABLED
	int i;
	u8 feature_buf[256];
	DWORD feature_len;
	PCSC_TLV_STRUCTURE *pcsc_tlv;
#endif

	r = refresh_slot_attributes(reader, slot);
	if (r)
		return r;
	if (!(slot->flags & SC_SLOT_CARD_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	if (_sc_check_forced_protocol(reader->ctx, slot->atr, slot->atr_len, (unsigned int *) &protocol)) {
		protocol = opensc_proto_to_pcsc(protocol);
	} else {
		protocol = SCARD_PROTOCOL_ANY;
	}

	rv = SCardConnect(priv->pcsc_ctx, priv->reader_name,
			  priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
			  protocol, &card_handle, &active_proto);
	if (rv != 0) {
		PCSC_ERROR(reader->ctx, "SCardConnect failed", rv);
		return pcsc_ret_to_error(rv);
	}
	slot->active_protocol = pcsc_proto_to_opensc(active_proto);
	pslot->pcsc_card = card_handle;

	/* after connect reader is not locked yet */
	pslot->locked = 0;
	
	/* check for pinpad support */
#ifdef PINPAD_ENABLED
	sc_debug(reader->ctx, "Requesting reader features ... ");

	rv = SCardControl(pslot->pcsc_card, CM_IOCTL_GET_FEATURE_REQUEST, NULL,
	                  0, feature_buf, sizeof(feature_buf), &feature_len);
	if (rv == SCARD_S_SUCCESS) {
		
		if (!(feature_len % sizeof(PCSC_TLV_STRUCTURE))) {
			/* get the number of elements instead of the complete size */
			feature_len /= sizeof(PCSC_TLV_STRUCTURE);

			pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
			for (i = 0; i < feature_len; i++) {
				if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_DIRECT) {
					sc_debug(reader->ctx, "Reader supports pinpad PIN verification");
					pslot->verify_ioctl = pcsc_tlv[i].value;
					if (priv->gpriv->enable_pinpad) {
						slot->capabilities |= SC_SLOT_CAP_PIN_PAD;
					}
				} else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_DIRECT) {
					sc_debug(reader->ctx, "Reader supports pinpad PIN modification");
					pslot->modify_ioctl = pcsc_tlv[i].value;
					if (priv->gpriv->enable_pinpad) {
						slot->capabilities |= SC_SLOT_CAP_PIN_PAD;
					}
				} else {
					sc_debug(reader->ctx, "Reader pinpad feature: %02x not recognized", pcsc_tlv[i].tag);
				}
			}
		} else
			sc_debug(reader->ctx, "Inconsistent TLV from reader!");
	} else {
		sc_debug(reader->ctx, "SCardControl failed %d", rv);
	}
#endif /* PINPAD_ENABLED */
	return SC_SUCCESS;
}

static int pcsc_disconnect(sc_reader_t * reader, sc_slot_info_t * slot)
{
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	SCardDisconnect(pslot->pcsc_card, priv->gpriv->transaction_reset ?
                  SCARD_RESET_CARD : SCARD_LEAVE_CARD);
	memset(pslot, 0, sizeof(*pslot));
	slot->flags = 0;
	return 0;
}

static int pcsc_lock(sc_reader_t *reader, sc_slot_info_t *slot)
{
	long rv;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);

	assert(pslot != NULL);

	rv = SCardBeginTransaction(pslot->pcsc_card);

	if ((unsigned int)rv == SCARD_W_RESET_CARD) {
		/* try to reconnect if the card was reset by some other application */
		rv = pcsc_reconnect(reader, slot, 0);
		if (rv != SCARD_S_SUCCESS) {
			PCSC_ERROR(reader->ctx, "SCardReconnect failed", rv);
			return pcsc_ret_to_error(rv);
		}
		/* Now try to begin a new transaction after we reconnected and we fail if
		 some other program was faster to lock the reader */
		rv = SCardBeginTransaction(pslot->pcsc_card);
	}

	if (rv != SCARD_S_SUCCESS) {
		PCSC_ERROR(reader->ctx, "SCardBeginTransaction failed", rv);
		return pcsc_ret_to_error(rv);
	}

	pslot->locked = 1;
	
	return SC_SUCCESS;
}

static int pcsc_unlock(sc_reader_t *reader, sc_slot_info_t *slot)
{
	long rv;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	assert(pslot != NULL);

	rv = SCardEndTransaction(pslot->pcsc_card, priv->gpriv->transaction_reset ?
                           SCARD_RESET_CARD : SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_ERROR(reader->ctx, "SCardEndTransaction failed", rv);
		return pcsc_ret_to_error(rv);
	}

	pslot->locked = 0;
	
	return 0;
}

static int pcsc_release(sc_reader_t *reader)
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

static int pcsc_reset(sc_reader_t *reader, sc_slot_info_t *slot)
{
	int r;
	struct pcsc_slot_data *pslot = GET_SLOT_DATA(slot);
	int old_locked = pslot->locked;

	r = pcsc_reconnect(reader, slot, 1);
	if(r != SC_SUCCESS)
		return r;

	/* pcsc_reconnect unlocks card... try to lock it again if it was locked */
	if(old_locked)
		r = pcsc_lock(reader, slot);
	
	return r;
}
	
static struct sc_reader_operations pcsc_ops;

static struct sc_reader_driver pcsc_drv = {
	"PC/SC reader",
	"pcsc",
	&pcsc_ops,
	0, 0, NULL
};

static int pcsc_init(sc_context_t *ctx, void **reader_data)
{
	LONG rv;
	DWORD reader_buf_size;
	char *reader_buf, *p;
	const char *mszGroups = NULL;
	SCARDCONTEXT pcsc_ctx;
	int r;
	struct pcsc_global_private_data *gpriv;
	scconf_block *conf_block;

	rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL,
                              NULL, NULL, &pcsc_ctx);
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
	
	conf_block = sc_get_conf_block(ctx, "reader_driver", "pcsc", 1);
	if (conf_block) {
		gpriv->connect_reset =
		    scconf_get_bool(conf_block, "connect_reset", 1);
		gpriv->connect_exclusive =
		    scconf_get_bool(conf_block, "connect_exclusive", 0);
		gpriv->transaction_reset =
		    scconf_get_bool(conf_block, "transaction_reset", 0);
		gpriv->enable_pinpad =
		    scconf_get_bool(conf_block, "enable_pinpad", 0);		    
	}
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
		sc_reader_t *reader = (sc_reader_t *) calloc(1, sizeof(sc_reader_t));
		struct pcsc_private_data *priv = (struct pcsc_private_data *) malloc(sizeof(struct pcsc_private_data));
		struct pcsc_slot_data *pslot = (struct pcsc_slot_data *) malloc(sizeof(struct pcsc_slot_data));
		sc_slot_info_t *slot;

		if (reader == NULL || priv == NULL || pslot == NULL) {
			if (reader)
				free(reader);
			if (priv)
				free(priv);
			if (pslot)
				free(pslot);
			break;
		}

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

	return 0;
}

static int pcsc_finish(sc_context_t *ctx, void *prv_data)
{
	struct pcsc_global_private_data *priv = (struct pcsc_global_private_data *) prv_data;

	if (priv) {
		SCardReleaseContext(priv->pcsc_ctx);
		free(priv);
	}

	return 0;
}

static int
pcsc_pin_cmd(sc_reader_t *reader, sc_slot_info_t * slot, struct sc_pin_cmd_data *data)
{
	/* XXX: temporary */
	if (slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
		return part10_pin_cmd(reader, slot, data);
	} else {
		return ctbcs_pin_cmd(reader, slot, data);
	}
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
	pcsc_ops.perform_verify = pcsc_pin_cmd;
	pcsc_ops.wait_for_event = pcsc_wait_for_event;
	pcsc_ops.reset = pcsc_reset;

	return &pcsc_drv;
}

/*
 * Pinpad support, based on PC/SC v2 Part 10 interface
 * Similar to CCID in spirit.
 */

#ifdef PINPAD_ENABLED
/* Local definitions */
#define SC_CCID_PIN_TIMEOUT        30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

/* Build a pin verification block + APDU */
static int part10_build_verify_pin_block(u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
	int offset = 0, count = 0;
	sc_apdu_t *apdu = data->apdu;
	u8 tmp;
	unsigned int tmp16;
	PIN_VERIFY_STRUCTURE *pin_verify  = (PIN_VERIFY_STRUCTURE *)buf; 
	
	/* PIN verification control message */
	pin_verify->bTimerOut = SC_CCID_PIN_TIMEOUT;
	pin_verify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;
	
	/* bmFormatString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII) {
		tmp |= SC_CCID_PIN_ENCODING_ASCII;

		/* if the effective pin length offset is specified, use it */
		if (data->pin1.length_offset > 4) {
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (data->pin1.length_offset - 5) << 3;
		}
	} else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) {
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* see comment about GLP pins in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x04 << 3;
	} else
		return SC_ERROR_NOT_SUPPORTED;

	pin_verify->bmFormatString = tmp;

	/* bmPINBlockString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP pin length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	}
	pin_verify->bmPINBlockString = tmp;

	/* bmPINLengthFormat */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP pins expect the effective pin length from bit 4 */
		tmp |= 0x04;
	}
	pin_verify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */

	if (!data->pin1.min_length || !data->pin1.max_length)
		return SC_ERROR_INVALID_ARGUMENTS;

	tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length;
	pin_verify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */
	
	pin_verify->bEntryValidationCondition = 0x02; /* Keypress only */
	
	/* Ignore language and T=1 parameters. */
	pin_verify->bNumberMessage = 0x00;
	pin_verify->wLangId = HOST_TO_CCID_16(0x0000);
	pin_verify->bMsgIndex = 0x00;
	pin_verify->bTeoPrologue[0] = 0x00;
	pin_verify->bTeoPrologue[1] = 0x00;
	pin_verify->bTeoPrologue[2] = 0x00;
	                
	/* APDU itself */
	pin_verify->abData[offset++] = apdu->cla;
	pin_verify->abData[offset++] = apdu->ins;
	pin_verify->abData[offset++] = apdu->p1;
	pin_verify->abData[offset++] = apdu->p2;

	/* Copy data if not Case 1 */
	if (data->pin1.length_offset != 4) {
		memcpy(&pin_verify->abData[offset], apdu->data, apdu->datalen);
		offset += apdu->datalen;
	}

	pin_verify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_VERIFY_STRUCTURE) + offset -1;
	*size = count;
	return SC_SUCCESS;
}



/* Build a pin modification block + APDU */
static int part10_build_modify_pin_block(u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
	int offset = 0, count = 0;
	sc_apdu_t *apdu = data->apdu;
	u8 tmp;
	unsigned int tmp16;
	PIN_MODIFY_STRUCTURE *pin_modify  = (PIN_MODIFY_STRUCTURE *)buf;

	/* PIN verification control message */
	pin_modify->bTimerOut = SC_CCID_PIN_TIMEOUT;	/* bTimeOut */
	pin_modify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;	/* bTimeOut2 */

	/* bmFormatString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII) {
		tmp |= SC_CCID_PIN_ENCODING_ASCII;

		/* if the effective pin length offset is specified, use it */
		if (data->pin1.length_offset > 4) {
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (data->pin1.length_offset - 5) << 3;
		}
	} else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) {
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* see comment about GLP pins in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x04 << 3;
	} else
		return SC_ERROR_NOT_SUPPORTED;

	pin_modify->bmFormatString = tmp;	/* bmFormatString */

	/* bmPINBlockString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP pin length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	}
	pin_modify->bmPINBlockString = tmp; /* bmPINBlockString */

	/* bmPINLengthFormat */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP pins expect the effective pin length from bit 4 */
		tmp |= 0x04;
	}
	pin_modify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */

	pin_modify->bInsertionOffsetOld = 0x00;  /* bOffsetOld */
	pin_modify->bInsertionOffsetNew = 0x00;  /* bOffsetNew */

	if (!data->pin1.min_length || !data->pin1.max_length)
		return SC_ERROR_INVALID_ARGUMENTS;
		
	tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length;
	pin_modify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */

	pin_modify->bConfirmPIN = 0x03;	/* bConfirmPIN, all */
	pin_modify->bEntryValidationCondition = 0x02;	/* bEntryValidationCondition, keypress only */

	/* Ignore language and T=1 parameters. */
	pin_modify->bNumberMessage = 0x00;
	pin_modify->wLangId = HOST_TO_CCID_16(0x0000);
	pin_modify->bMsgIndex1 = 0x00;
	pin_modify->bMsgIndex2 = 0x00;
	pin_modify->bMsgIndex3 = 0x00;
	pin_modify->bTeoPrologue[0] = 0x00;
	pin_modify->bTeoPrologue[1] = 0x00;
	pin_modify->bTeoPrologue[2] = 0x00;
	                
	/* APDU itself */
	pin_modify->abData[offset++] = apdu->cla;
	pin_modify->abData[offset++] = apdu->ins;
	pin_modify->abData[offset++] = apdu->p1;
	pin_modify->abData[offset++] = apdu->p2;

	/* Copy data if not Case 1 */
	if (data->pin1.length_offset != 4) {
		memcpy(&pin_modify->abData[offset], apdu->data, apdu->datalen);
		offset += apdu->datalen;
	}

	pin_modify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_MODIFY_STRUCTURE) + offset -1;
	*size = count;
	return SC_SUCCESS;
}

#endif
/* Do the PIN command */
static int
part10_pin_cmd(sc_reader_t *reader, sc_slot_info_t *slot,
	     struct sc_pin_cmd_data *data)
{
#ifdef PINPAD_ENABLED
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], sbuf[SC_MAX_APDU_BUFFER_SIZE];
	char dbuf[SC_MAX_APDU_BUFFER_SIZE * 3];
	size_t rcount = sizeof(rbuf), scount = 0;
	int r;
	DWORD ioctl = 0;
	sc_apdu_t *apdu;
	struct pcsc_slot_data *pslot = (struct pcsc_slot_data *) slot->drv_data;

	SC_FUNC_CALLED(reader->ctx, 3);
	assert(pslot != NULL);

	/* The APDU must be provided by the card driver */
	if (!data->apdu) {
		sc_error(reader->ctx, "No APDU provided for Part 10 pinpad verification!");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* Only T=0 is currently supported */
	if (slot->active_protocol != SC_PROTO_T0) {
		sc_error(reader->ctx, "Only T=0 is currently supported!");
		return SC_ERROR_NOT_SUPPORTED;
	}

	apdu = data->apdu;
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		if (!pslot->verify_ioctl) {
			sc_error(reader->ctx, "Pinpad reader does not support verification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		r = part10_build_verify_pin_block(sbuf, &scount, data);
		ioctl = pslot->verify_ioctl;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		if (!pslot->modify_ioctl) {
			sc_error(reader->ctx, "Pinpad reader does not support modification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		r = part10_build_modify_pin_block(sbuf, &scount, data);
		ioctl = pslot->modify_ioctl;
		break;
	default:
		sc_error(reader->ctx, "Unknown PIN command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* If PIN block building failed, we fail too */
	SC_TEST_RET(reader->ctx, r, "Part10 PIN block building failed!");
	/* If not, debug it, just for fun */
	sc_bin_to_hex(sbuf, scount, dbuf, sizeof(dbuf), ':');
	sc_debug(reader->ctx, "Part 10 block: %s", dbuf);

	r = pcsc_internal_transmit(reader, slot, sbuf, scount, rbuf, &rcount, ioctl);

	SC_TEST_RET(reader->ctx, r, "Part 10: block transmit failed!");

	/* We expect only two bytes of result data (SW1 and SW2) */
	if (rcount != 2) {
		SC_FUNC_RETURN(reader->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	/* Extract the SWs for the result APDU */
	apdu->sw1 = (unsigned int) rbuf[rcount - 2];
	apdu->sw2 = (unsigned int) rbuf[rcount - 1];

	r = SC_SUCCESS;
	switch (((unsigned int) apdu->sw1 << 8) | apdu->sw2) {
	case 0x6400: /* Input timed out */
		r = SC_ERROR_KEYPAD_TIMEOUT;   
		break;
	case 0x6401: /* Input cancelled */
		r = SC_ERROR_KEYPAD_CANCELLED; 
		break;
	case 0x6402: /* PINs don't match */
		r = SC_ERROR_KEYPAD_PIN_MISMATCH;
		break;
	}

	SC_TEST_RET(reader->ctx, r, "PIN command failed");

	/* PIN command completed, all is good */
	return SC_SUCCESS;
#else
	return SC_ERROR_NOT_SUPPORTED;
#endif /* PINPAD_ENABLED */
}
#endif   /* HAVE_PCSC */

