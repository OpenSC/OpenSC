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
#ifdef ENABLE_PCSC
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ltdl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "internal-winscard.h"

/* Some windows specific kludge */
#undef SCARD_PROTOCOL_ANY
#define SCARD_PROTOCOL_ANY (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)

/* Logging */
#define PCSC_TRACE(reader, desc, rv) do { if (reader->ctx->debug >= 3) sc_debug(reader->ctx, "%s:" desc ": 0x%08lx\n", reader->name, rv); } while (0)
#define PCSC_LOG(ctx, desc, rv) do { if (ctx->debug >= 3) sc_debug(ctx, desc ": 0x%08lx\n", rv); } while (0)                         

/* Utility for handling big endian IOCTL codes. */
#define dw2i_be(a, x) ((((((a[x] << 8) + a[x+1]) << 8) + a[x+2]) << 8) + a[x+3])

#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)

struct pcsc_global_private_data {
	SCARDCONTEXT pcsc_ctx;
	SCARDCONTEXT pcsc_wait_ctx;
	int enable_pinpad;
	int connect_exclusive;
	int connect_reset;
	int transaction_reset;
	const char *provider_library;
	lt_dlhandle dlhandle;
	SCardEstablishContext_t SCardEstablishContext;
	SCardReleaseContext_t SCardReleaseContext;
	SCardConnect_t SCardConnect;
	SCardReconnect_t SCardReconnect;
	SCardDisconnect_t SCardDisconnect;
	SCardBeginTransaction_t SCardBeginTransaction;
	SCardEndTransaction_t SCardEndTransaction;
	SCardStatus_t SCardStatus;
	SCardGetStatusChange_t SCardGetStatusChange;
	SCardCancel_t SCardCancel;
	SCardControlOLD_t SCardControlOLD;
	SCardControl_t SCardControl;
	SCardTransmit_t SCardTransmit;
	SCardListReaders_t SCardListReaders;
};

struct pcsc_private_data {
	struct pcsc_global_private_data *gpriv;
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE_A reader_state;
	DWORD verify_ioctl;
	DWORD verify_ioctl_start;
	DWORD verify_ioctl_finish;
	
	DWORD modify_ioctl;
	DWORD modify_ioctl_start;
	DWORD modify_ioctl_finish;
	int locked;
};

static int pcsc_detect_card_presence(sc_reader_t *reader);

static int pcsc_to_opensc_error(LONG rv)
{
	switch (rv) {
	case SCARD_S_SUCCESS:
		return SC_SUCCESS;
	case SCARD_W_REMOVED_CARD:
		return SC_ERROR_CARD_REMOVED;
	case SCARD_E_NOT_TRANSACTED:
		return SC_ERROR_TRANSMIT_FAILED;
	case SCARD_W_UNRESPONSIVE_CARD:
		return SC_ERROR_CARD_UNRESPONSIVE;
	case SCARD_W_UNPOWERED_CARD:
		return SC_ERROR_CARD_UNRESPONSIVE;
	case SCARD_E_SHARING_VIOLATION:
		return SC_ERROR_READER_LOCKED;
#ifdef SCARD_E_NO_READERS_AVAILABLE /* Older pcsc-lite does not have it */
	case SCARD_E_NO_READERS_AVAILABLE:
		return SC_ERROR_NO_READERS_FOUND;
#endif
	case SCARD_E_NO_SERVICE:
		/* If the service is (auto)started, there could be readers later */
		return SC_ERROR_NO_READERS_FOUND;
	case SCARD_E_NO_SMARTCARD:
		return SC_ERROR_CARD_NOT_PRESENT;
	case SCARD_E_PROTO_MISMATCH: /* Should not happen */
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

static int pcsc_internal_transmit(sc_reader_t *reader,
			 const u8 *sendbuf, size_t sendsize,
			 u8 *recvbuf, size_t *recvsize,
			 unsigned long control)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	SCARD_IO_REQUEST sSendPci, sRecvPci;
	DWORD dwSendLength, dwRecvLength;
	LONG rv;
	SCARDHANDLE card;

	SC_FUNC_CALLED(reader->ctx, 3);
	card = priv->pcsc_card;

	sSendPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
	sSendPci.cbPciLength = sizeof(sSendPci);
	sRecvPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
	sRecvPci.cbPciLength = sizeof(sRecvPci);

	dwSendLength = sendsize;
	dwRecvLength = *recvsize;

	if (!control) {
		rv = priv->gpriv->SCardTransmit(card, &sSendPci, sendbuf, dwSendLength,
				   &sRecvPci, recvbuf, &dwRecvLength);
	} else {
		if (priv->gpriv->SCardControlOLD != NULL) {
			rv = priv->gpriv->SCardControlOLD(card, sendbuf, dwSendLength,
				  recvbuf, &dwRecvLength);
		}
		else {
			rv = priv->gpriv->SCardControl(card, (DWORD) control, sendbuf, dwSendLength,
				  recvbuf, dwRecvLength, &dwRecvLength);
		}
	}

	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardTransmit/Control failed", rv);
		switch (rv) {
		case SCARD_W_REMOVED_CARD:
			return SC_ERROR_CARD_REMOVED;
		default:
			/* Translate strange errors from card removal to a proper return code */
			pcsc_detect_card_presence(reader);
			if (!(pcsc_detect_card_presence(reader) & SC_READER_CARD_PRESENT))
				return SC_ERROR_CARD_REMOVED;
			return SC_ERROR_TRANSMIT_FAILED;
		}
	}
	if (!control && dwRecvLength < 2)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	*recvsize = dwRecvLength;

	return SC_SUCCESS;
}

static int pcsc_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
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
		r = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	/* encode and log the APDU */
	r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, reader->active_protocol);
	if (r != SC_SUCCESS)
		goto out;
	if (reader->ctx->debug >= 6)   {
		if (reader->name)
			sc_debug(reader->ctx, "reader '%s'", reader->name);
		sc_apdu_log(reader->ctx, sbuf, ssize, 1);
	}

	r = pcsc_internal_transmit(reader, sbuf, ssize,
				rbuf, &rsize, apdu->control);
	if (r < 0) {
		/* unable to transmit ... most likely a reader problem */
		sc_debug(reader->ctx, "unable to transmit");
		goto out;
	}
	if (reader->ctx->debug >= 6)
		sc_apdu_log(reader->ctx, rbuf, rsize, 0);
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


static int refresh_attributes(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	LONG rv;


	sc_debug(reader->ctx, "%s status check", reader->name);	
	if (priv->reader_state.szReader == NULL) {
		priv->reader_state.szReader = reader->name;
		priv->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
		priv->reader_state.dwEventState = SCARD_STATE_UNAWARE;
	} else {
		priv->reader_state.dwCurrentState = priv->reader_state.dwEventState;
	}

	rv = priv->gpriv->SCardGetStatusChange(priv->gpriv->pcsc_ctx, 0, &priv->reader_state, 1);
	
	if (rv != SCARD_S_SUCCESS && rv != (LONG)SCARD_E_TIMEOUT) {
		if (rv == (LONG)SCARD_E_TIMEOUT) {
			reader->flags &= ~SCARD_STATE_CHANGED;
			SC_FUNC_RETURN(reader->ctx, 4, SC_SUCCESS);
		}
		PCSC_TRACE(reader, "SCardGetStatusChange failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	sc_debug(reader->ctx, "event: 0x%04X", priv->reader_state.dwEventState);
	sc_debug(reader->ctx, "state: 0x%04X", priv->reader_state.dwCurrentState);

	if (priv->reader_state.dwEventState & SCARD_STATE_UNKNOWN) {
		/* State means "reader unknown", but we have listed it at least once */
		return SC_ERROR_READER_DETACHED;
	}
	
	if (priv->reader_state.dwEventState & SCARD_STATE_PRESENT) {
		int old_flags = reader->flags;
		int maybe_changed = 0;
		sc_debug(reader->ctx, "card present");
		reader->flags |= SC_READER_CARD_PRESENT;
		reader->atr_len = priv->reader_state.cbAtr;
		if (reader->atr_len > SC_MAX_ATR_SIZE)
			reader->atr_len = SC_MAX_ATR_SIZE;
		memcpy(reader->atr, priv->reader_state.rgbAtr, reader->atr_len);

#ifndef _WIN32
		/* On Linux, SCARD_STATE_CHANGED always means there was an
		 * insert or removal. But we may miss events that way. */
		if (priv->reader_state.dwEventState & SCARD_STATE_CHANGED) {
			reader->flags |= SC_READER_CARD_CHANGED;
		} else {
			maybe_changed = 1;
		}
#else
		/* On windows, SCARD_STATE_CHANGED is turned on by lots of
		 * other events, so it gives us a lot of false positives.
		 * But if it's off, there really was no change */
		if (priv->reader_state.dwEventState & SCARD_STATE_CHANGED) {
			maybe_changed = 1;
		}
#endif
		/* If we aren't sure if the card state changed, check if
		 * the card handle is still valid. If the card changed,
		 * the handle will be invalid. */
		reader->flags &= ~SC_READER_CARD_CHANGED;
		if (maybe_changed) {
			if (old_flags & SC_READER_CARD_PRESENT) {
				DWORD readers_len = 0, state, prot, atr_len = SC_MAX_ATR_SIZE;
				unsigned char atr[SC_MAX_ATR_SIZE];
				LONG rv = priv->gpriv->SCardStatus(priv->pcsc_card, NULL, &readers_len,
					&state,	&prot, atr, &atr_len);
				if (rv == (LONG)SCARD_W_REMOVED_CARD)
					reader->flags |= SC_READER_CARD_CHANGED;
			}
			else
				reader->flags |= SC_READER_CARD_CHANGED;
		}
	} else {
		reader->flags &= ~(SC_READER_CARD_PRESENT|SC_READER_CARD_CHANGED);
	}
	return SC_SUCCESS;
}

static int pcsc_detect_card_presence(sc_reader_t *reader)
{
	int rv;
	SC_FUNC_CALLED(reader->ctx, 3);

	rv = refresh_attributes(reader);
	if (rv != SC_SUCCESS)
		SC_FUNC_RETURN(reader->ctx, 3, rv);
	SC_FUNC_RETURN(reader->ctx, 3, reader->flags);
}


static int pcsc_reconnect(sc_reader_t * reader, int reset)
{
	DWORD active_proto, protocol;
	LONG rv;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int r;

	sc_debug(reader->ctx, "Reconnecting to the card...");

	r = refresh_attributes(reader);
	if (r!= SC_SUCCESS)
		return r;

	if (!(reader->flags & SC_READER_CARD_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	/* reconnect always unlocks transaction */
	priv->locked = 0;
	
	rv = priv->gpriv->SCardReconnect(priv->pcsc_card,
			    priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
			    SCARD_PROTOCOL_ANY, reset ? SCARD_UNPOWER_CARD : SCARD_LEAVE_CARD, &active_proto);

	/* Check for protocol difference */
	if (rv == SCARD_S_SUCCESS && _sc_check_forced_protocol
	    (reader->ctx, reader->atr, reader->atr_len,
	     (unsigned int *)&protocol)) {
		protocol = opensc_proto_to_pcsc(protocol);
		if (pcsc_proto_to_opensc(active_proto) != protocol) {
		 rv = priv->gpriv->SCardReconnect(priv->pcsc_card,
		 		     priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
		 		     protocol, SCARD_UNPOWER_CARD, &active_proto);
		}
	}

	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardReconnect failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	
	reader->active_protocol = pcsc_proto_to_opensc(active_proto);
	return pcsc_to_opensc_error(rv);
}

static int pcsc_connect(sc_reader_t *reader)
{
	DWORD active_proto, protocol;
	SCARDHANDLE card_handle;
	LONG rv;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int r;

	SC_FUNC_CALLED(reader->ctx, 3);
	        
	r = refresh_attributes(reader);
	if (r != SC_SUCCESS)
		SC_FUNC_RETURN(reader->ctx, 4, r);

	if (!(reader->flags & SC_READER_CARD_PRESENT))
		SC_FUNC_RETURN(reader->ctx, 4, SC_ERROR_CARD_NOT_PRESENT);

	/* Always connect with whatever protocol possible */
	rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, reader->name,
			  priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
			  SCARD_PROTOCOL_ANY, &card_handle, &active_proto);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardConnect failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	reader->active_protocol = pcsc_proto_to_opensc(active_proto);
	priv->pcsc_card = card_handle;

	/* after connect reader is not locked yet */
	priv->locked = 0;
	sc_debug(reader->ctx, "After connect protocol = %d", reader->active_protocol);
	
	/* If we need a specific protocol, reconnect if needed */
	if (_sc_check_forced_protocol(reader->ctx, reader->atr, reader->atr_len, (unsigned int *) &protocol)) {
		/* If current protocol differs from the protocol we want to force */
		if (reader->active_protocol != protocol) {
			sc_debug(reader->ctx, "Protocol difference, forcing protocol (%d)", protocol);
			/* Reconnect with a reset. pcsc_reconnect figures out the right forced protocol */
			r = pcsc_reconnect(reader, 1);
			if (r != SC_SUCCESS) {
				sc_debug(reader->ctx, "pcsc_reconnect (to force protocol) failed", r);
				return r;
			}
			sc_debug(reader->ctx, "Proto after reconnect = %d", reader->active_protocol);
		}
	}
	return SC_SUCCESS;
}

static int pcsc_disconnect(sc_reader_t * reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SC_FUNC_CALLED(reader->ctx, 3);
	        
	priv->gpriv->SCardDisconnect(priv->pcsc_card, priv->gpriv->connect_reset ?
	          SCARD_RESET_CARD : SCARD_LEAVE_CARD);
	reader->flags = 0;
	return SC_SUCCESS;
}

static int pcsc_lock(sc_reader_t *reader)
{
	LONG rv;
	int r;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	SC_FUNC_CALLED(reader->ctx, 3);

	rv = priv->gpriv->SCardBeginTransaction(priv->pcsc_card);

	switch (rv) {
		case SCARD_E_INVALID_HANDLE:
		case SCARD_E_READER_UNAVAILABLE:
			r = pcsc_connect(reader);
			if (r != SC_SUCCESS) {
				sc_debug(reader->ctx, "pcsc_connect failed", r);
				return r;
			}
			/* return failure so that upper layers will be notified and try to lock again */
			return SC_ERROR_READER_REATTACHED;
		case SCARD_W_RESET_CARD:
			/* try to reconnect if the card was reset by some other application */
			r = pcsc_reconnect(reader, 0);
			if (r != SC_SUCCESS) {
				sc_debug(reader->ctx, "pcsc_reconnect failed", r);
				return r;
			}
			/* return failure so that upper layers will be notified and try to lock again */
			return SC_ERROR_CARD_RESET;
		case SCARD_S_SUCCESS:
			priv->locked = 1;
			return SC_SUCCESS;
		default:
			PCSC_TRACE(reader, "SCardBeginTransaction failed", rv);
			return pcsc_to_opensc_error(rv);
	}
}

static int pcsc_unlock(sc_reader_t *reader)
{
	LONG rv;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	SC_FUNC_CALLED(reader->ctx, 3);

	rv = priv->gpriv->SCardEndTransaction(priv->pcsc_card, priv->gpriv->transaction_reset ?
                           SCARD_RESET_CARD : SCARD_LEAVE_CARD);

	priv->locked = 0;
	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardEndTransaction failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	return SC_SUCCESS;
}

static int pcsc_release(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);

	free(priv);
	return SC_SUCCESS;
}

static int pcsc_reset(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int r;
	int old_locked = priv->locked;

	r = pcsc_reconnect(reader, 1);
	if(r != SC_SUCCESS)
		return r;

	/* pcsc_reconnect unlocks card... try to lock it again if it was locked */
	if(old_locked)
		r = pcsc_lock(reader);

	return r;
}


static int pcsc_cancel(sc_context_t *ctx, void *reader_data)
{
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)reader_data;

	SC_FUNC_CALLED(ctx, 3);
#ifndef _WIN32
	if (gpriv->pcsc_wait_ctx != -1) {
		rv = gpriv->SCardCancel(gpriv->pcsc_wait_ctx);
		if (rv == SCARD_S_SUCCESS) 
			 /* Also close and clear the waiting context */
			 rv = gpriv->SCardReleaseContext(gpriv->pcsc_wait_ctx);
	}
#else
	rv = gpriv->SCardCancel(gpriv->pcsc_ctx);
#endif
	if (rv != SCARD_S_SUCCESS) {
		PCSC_LOG(ctx, "SCardCancel/SCardReleaseContext failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	return SC_SUCCESS;
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
	struct pcsc_global_private_data *gpriv;
	scconf_block *conf_block = NULL;
	int ret = SC_ERROR_INTERNAL;

	*reader_data = NULL;

	gpriv = (struct pcsc_global_private_data *) calloc(1, sizeof(struct pcsc_global_private_data));
	if (gpriv == NULL) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Defaults */
	gpriv->connect_reset = 1;
	gpriv->connect_exclusive = 0;
	gpriv->transaction_reset = 0;
	gpriv->enable_pinpad = 1;
	gpriv->provider_library = DEFAULT_PCSC_PROVIDER;
	gpriv->pcsc_ctx = -1;
	gpriv->pcsc_wait_ctx = -1;
	
	conf_block = sc_get_conf_block(ctx, "reader_driver", "pcsc", 1);
	if (conf_block) {
		gpriv->connect_reset =
		    scconf_get_bool(conf_block, "connect_reset", gpriv->connect_reset);
		gpriv->connect_exclusive =
		    scconf_get_bool(conf_block, "connect_exclusive", gpriv->connect_exclusive);
		gpriv->transaction_reset =
		    scconf_get_bool(conf_block, "transaction_reset", gpriv->transaction_reset);
		gpriv->enable_pinpad =
		    scconf_get_bool(conf_block, "enable_pinpad", gpriv->enable_pinpad);
		gpriv->provider_library =
		    scconf_get_str(conf_block, "provider_library", gpriv->provider_library);
	}
	sc_debug(ctx, "PC/SC options: connect_reset=%d connect_exclusive=%d transaction_reset=%d enable_pinpad=%d",
		gpriv->connect_reset, gpriv->connect_exclusive, gpriv->transaction_reset, gpriv->enable_pinpad);

	gpriv->dlhandle = lt_dlopen(gpriv->provider_library);
	if (gpriv->dlhandle == NULL) {
		ret = SC_ERROR_CANNOT_LOAD_MODULE;
		goto out;
	}

	gpriv->SCardEstablishContext = (SCardEstablishContext_t)lt_dlsym(gpriv->dlhandle, "SCardEstablishContext");
	gpriv->SCardReleaseContext = (SCardReleaseContext_t)lt_dlsym(gpriv->dlhandle, "SCardReleaseContext");
	gpriv->SCardConnect = (SCardConnect_t)lt_dlsym(gpriv->dlhandle, "SCardConnect");
	gpriv->SCardReconnect = (SCardReconnect_t)lt_dlsym(gpriv->dlhandle, "SCardReconnect");
	gpriv->SCardDisconnect = (SCardDisconnect_t)lt_dlsym(gpriv->dlhandle, "SCardDisconnect");
	gpriv->SCardBeginTransaction = (SCardBeginTransaction_t)lt_dlsym(gpriv->dlhandle, "SCardBeginTransaction");
	gpriv->SCardEndTransaction = (SCardEndTransaction_t)lt_dlsym(gpriv->dlhandle, "SCardEndTransaction");
	gpriv->SCardStatus = (SCardStatus_t)lt_dlsym(gpriv->dlhandle, "SCardStatus");
	gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)lt_dlsym(gpriv->dlhandle, "SCardGetStatusChange");
	gpriv->SCardCancel = (SCardCancel_t)lt_dlsym(gpriv->dlhandle, "SCardCancel");
	gpriv->SCardTransmit = (SCardTransmit_t)lt_dlsym(gpriv->dlhandle, "SCardTransmit");
	gpriv->SCardListReaders = (SCardListReaders_t)lt_dlsym(gpriv->dlhandle, "SCardListReaders");

	if (gpriv->SCardConnect == NULL)
		gpriv->SCardConnect = (SCardConnect_t)lt_dlsym(gpriv->dlhandle, "SCardConnectA");
	if (gpriv->SCardStatus == NULL)
		gpriv->SCardStatus = (SCardStatus_t)lt_dlsym(gpriv->dlhandle, "SCardStatusA");
	if (gpriv->SCardGetStatusChange == NULL)
		gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)lt_dlsym(gpriv->dlhandle, "SCardGetStatusChangeA");
	if (gpriv->SCardListReaders == NULL)
		gpriv->SCardListReaders = (SCardListReaders_t)lt_dlsym(gpriv->dlhandle, "SCardListReadersA");
	
	/* If we have SCardGetAttrib it is correct API */
	if (lt_dlsym(gpriv->dlhandle, "SCardGetAttrib") != NULL) {
#ifdef __APPLE__
		gpriv->SCardControl = (SCardControl_t)lt_dlsym(gpriv->dlhandle, "SCardControl132");
#endif
		if (gpriv->SCardControl == NULL) {
			gpriv->SCardControl = (SCardControl_t)lt_dlsym(gpriv->dlhandle, "SCardControl");
		}
	}
	else {
		gpriv->SCardControlOLD = (SCardControlOLD_t)lt_dlsym(gpriv->dlhandle, "SCardControl");
	}

	if (
		gpriv->SCardReleaseContext == NULL ||
		gpriv->SCardConnect == NULL ||
		gpriv->SCardReconnect == NULL ||
		gpriv->SCardDisconnect == NULL ||
		gpriv->SCardBeginTransaction == NULL ||
		gpriv->SCardEndTransaction == NULL ||
		gpriv->SCardStatus == NULL ||
		gpriv->SCardGetStatusChange == NULL ||
		gpriv->SCardCancel == NULL ||
		(gpriv->SCardControl == NULL && gpriv->SCardControlOLD == NULL) ||
		gpriv->SCardTransmit == NULL ||
		gpriv->SCardListReaders == NULL
	) {
		ret = SC_ERROR_CANNOT_LOAD_MODULE;
		goto out;
	}

	*reader_data = gpriv;
	gpriv = NULL;
	ret = SC_SUCCESS;

out:
	if (gpriv != NULL) {
		if (gpriv->dlhandle != NULL)
			lt_dlclose(gpriv->dlhandle);
		free(gpriv);
	}

	return ret;
}

static int pcsc_finish(sc_context_t *ctx, void *prv_data)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) prv_data;

	if (gpriv) {
		if (gpriv->pcsc_ctx != -1)
			gpriv->SCardReleaseContext(gpriv->pcsc_ctx);
		if (gpriv->dlhandle != NULL)
			lt_dlclose(gpriv->dlhandle);
		free(gpriv);
	}

	return SC_SUCCESS;
}

static int pcsc_detect_readers(sc_context_t *ctx, void *prv_data)
{
	DWORD active_proto;
	SCARDHANDLE card_handle;
	u8 feature_buf[256], rbuf[SC_MAX_APDU_BUFFER_SIZE];
	PCSC_TLV_STRUCTURE *pcsc_tlv;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) prv_data;
	LONG rv;
	DWORD reader_buf_size, rcount, feature_len, display_ioctl = 0x0;
	char *reader_buf = NULL, *reader_name;
	const char *mszGroups = NULL;
	int ret = SC_ERROR_INTERNAL;

	SC_FUNC_CALLED(ctx, 3);

	if (!gpriv) {
		ret = SC_ERROR_NO_READERS_FOUND;
		goto out;
	}

	sc_debug(ctx, "Probing pcsc readers");

	do {
		if (gpriv->pcsc_ctx == -1) {
			/*
			 * Cannot call SCardListReaders with -1
			 * context as in Windows ERROR_INVALID_HANDLE
			 * is returned instead of SCARD_E_INVALID_HANDLE
			 */
			rv = SCARD_E_INVALID_HANDLE;
		}
		else {
			rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, NULL, NULL,
					      (LPDWORD) &reader_buf_size);
		}
		if (rv != SCARD_S_SUCCESS) {
			if (rv != (LONG)SCARD_E_INVALID_HANDLE) {
				PCSC_LOG(ctx, "SCardListReaders failed", rv);
				ret = pcsc_to_opensc_error(rv);
				goto out;
			}

			sc_debug(ctx, "Establish pcsc context");

			rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER,
					      NULL, NULL, &gpriv->pcsc_ctx);
			if (rv != SCARD_S_SUCCESS) {
				PCSC_LOG(ctx, "SCardEstablishContext failed", rv);
				ret = pcsc_to_opensc_error(rv);
				goto out;
			}

			rv = SCARD_E_INVALID_HANDLE;
		}
	} while (rv != SCARD_S_SUCCESS);

	reader_buf = (char *) malloc(sizeof(char) * reader_buf_size);
	if (!reader_buf) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, mszGroups, reader_buf,
	                      (LPDWORD) &reader_buf_size);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_LOG(ctx, "SCardListReaders failed", rv);
		ret = pcsc_to_opensc_error(rv);
		goto out;
	}
	for (reader_name = reader_buf; *reader_name != '\x0'; reader_name += strlen (reader_name) + 1) {
		sc_reader_t *reader = NULL;
		struct pcsc_private_data *priv = NULL;
		unsigned int i;
		int found = 0;

		for (i=0;i < sc_ctx_get_reader_count (ctx) && !found;i++) {
			sc_reader_t *reader2 = sc_ctx_get_reader (ctx, i);
			if (reader2 == NULL) {
				ret = SC_ERROR_INTERNAL;
				goto err1;
			}
			if (reader2->ops == &pcsc_ops && !strcmp (reader2->name, reader_name)) {
				found = 1;
			}
		}

		/* Reader already available, skip */
		if (found) {
			continue;
		}

		sc_debug(ctx, "Found new pcsc reader '%s'", reader_name);

		if ((reader = (sc_reader_t *) calloc(1, sizeof(sc_reader_t))) == NULL) {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err1;
		}
			if ((priv = (struct pcsc_private_data *) calloc(1, sizeof(struct pcsc_private_data))) == NULL) {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err1;
		}

		reader->drv_data = priv;
		reader->ops = &pcsc_ops;
		reader->driver = &pcsc_drv;
		if ((reader->name = strdup(reader_name)) == NULL) {
			ret = SC_ERROR_OUT_OF_MEMORY;
			goto err1;
		}
		priv->gpriv = gpriv;
		if (_sc_add_reader(ctx, reader)) {
			ret = SC_SUCCESS;	/* silent ignore */
			goto err1;
		}

		/* check for pinpad support */
		if (gpriv->SCardControl != NULL) {
			sc_debug(ctx, "Requesting reader features ... ");
#ifndef _WIN32	/* Apple 10.5.7 and pcsc-lite previous to v1.5.5 do not support 0 as protocol identifier */
			rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_ANY, &card_handle, &active_proto);
#else
			rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, 0, &card_handle, &active_proto);
#endif
			PCSC_TRACE(reader, "SCardConnect", rv);
			if (rv == (LONG)SCARD_E_SHARING_VIOLATION) { /* Assume that there is a card in the reader in shared mode if direct communcation failed */
				rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, &card_handle, &active_proto);
				PCSC_TRACE(reader, "SCardConnect", rv);		
			}
			if (rv == SCARD_S_SUCCESS) {
				rv = gpriv->SCardBeginTransaction(card_handle);
				PCSC_TRACE(reader, "SCardBeginTransaction", rv);
				if (rv == (LONG)SCARD_W_RESET_CARD) { /* can only happen in indirect mode */
					rv = gpriv->SCardReconnect(card_handle, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY, SCARD_LEAVE_CARD, &active_proto);
					PCSC_TRACE(reader, "SCardReconnect", rv);
					rv = gpriv->SCardBeginTransaction(card_handle);
					PCSC_TRACE(reader, "SCardBeginTransaction", rv);
				}
			}

			if (rv == SCARD_S_SUCCESS) {
				rv = gpriv->SCardControl(card_handle, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, feature_buf, sizeof(feature_buf), &feature_len);
				if (rv != (LONG)SCARD_S_SUCCESS) {
					PCSC_TRACE(reader, "SCardControl failed", rv);
				}
				else {
					if ((feature_len % sizeof(PCSC_TLV_STRUCTURE)) != 0) {
						sc_debug(ctx, "Inconsistent TLV from reader!");
					}
					else {
						char *log_disabled = "but it's disabled in configuration file";
						/* get the number of elements instead of the complete size */
						feature_len /= sizeof(PCSC_TLV_STRUCTURE);

						pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
						for (i = 0; i < feature_len; i++) {
							sc_debug(ctx, "Reader feature %02x detected", pcsc_tlv[i].tag);
							if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_DIRECT) {
								priv->verify_ioctl = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_START) {
								priv->verify_ioctl_start = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_FINISH) {
								priv->verify_ioctl_finish = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_DIRECT) {
								priv->modify_ioctl = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_START) {
								priv->modify_ioctl_start = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_FINISH) {
								priv->modify_ioctl_finish = ntohl(pcsc_tlv[i].value);
							} else if (pcsc_tlv[i].tag == FEATURE_IFD_PIN_PROPERTIES) {
								display_ioctl = ntohl(pcsc_tlv[i].value);
							} else {
								sc_debug(ctx, "Reader feature %02x is not supported", pcsc_tlv[i].tag);
							}
						}
						
						/* Set reader capabilities based on detected IOCTLs */
						if (priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish)) {
							char *log_text = "Reader supports pinpad PIN verification";
							if (priv->gpriv->enable_pinpad) {
								sc_debug(ctx, log_text);
								reader->capabilities |= SC_READER_CAP_PIN_PAD;
							} else {
								sc_debug(ctx, "%s %s", log_text, log_disabled);
							}
						}
						
						if (priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish)) {
							char *log_text = "Reader supports pinpad PIN modification";
							if (priv->gpriv->enable_pinpad) {
								sc_debug(ctx, log_text);
								reader->capabilities |= SC_READER_CAP_PIN_PAD;
							} else {
								sc_debug(ctx, "%s %s", log_text, log_disabled);
							}
						}

						if (display_ioctl) {
							rcount = sizeof(rbuf);
							rv = gpriv->SCardControl(card_handle, display_ioctl, NULL, 0, rbuf, sizeof(rbuf), &rcount);
							if (rv == SCARD_S_SUCCESS) {
								if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE)) {
									PIN_PROPERTIES_STRUCTURE *caps = (PIN_PROPERTIES_STRUCTURE *)rbuf;
									if (caps->wLcdLayout > 0) {
										sc_debug(ctx, "Reader has a display: %04X", caps->wLcdLayout);
										reader->capabilities |= SC_READER_CAP_DISPLAY;
									} else
										sc_debug(ctx, "Reader does not have a display.");
								} else {
									sc_debug(ctx, "Returned PIN properties structure has bad length (%d/%d)", rcount, sizeof(PIN_PROPERTIES_STRUCTURE));
								}
							}
						}
					}
				}
				gpriv->SCardEndTransaction(card_handle, SCARD_LEAVE_CARD);
				gpriv->SCardDisconnect(card_handle, SCARD_LEAVE_CARD);
			}
			else {
				PCSC_TRACE(reader, "SCardConnect failed", rv);
			}			
		}
		refresh_attributes(reader);
		continue;
	
	err1:
		if (priv != NULL) {
			free(priv);
		}
		if (reader != NULL) {
			if (reader->name)
				free(reader->name);
			free(reader);
		}
		goto out;
	}

	ret = SC_SUCCESS;

out:

	if (reader_buf != NULL)
		free (reader_buf);

	SC_FUNC_RETURN(ctx, 3, ret);
}


/* Wait for an event to occur.
 */
static int pcsc_wait_for_event(sc_context_t *ctx,
			       void *reader_data,
                               unsigned int event_mask,
                               sc_reader_t **event_reader,
			       unsigned int *event, int timeout)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)reader_data;
	LONG rv;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS + 1];
	unsigned long on_bits, off_bits;
	size_t i;
	unsigned int num_watch;

	SC_FUNC_CALLED(ctx, 3);
	on_bits = off_bits = 0;

	if (event_mask & SC_EVENT_CARD_INSERTED) {
		event_mask &= ~SC_EVENT_CARD_INSERTED;
		on_bits |= SCARD_STATE_PRESENT;
	}
	if (event_mask & SC_EVENT_CARD_REMOVED) {
		event_mask &= ~SC_EVENT_CARD_REMOVED;
		off_bits |= SCARD_STATE_PRESENT;
	}

/* FIXME check for unhandled masks?
	if (event_mask != 0)
		return SC_ERROR_INVALID_ARGUMENTS; */

	/* Find out the current status */
	num_watch = sc_ctx_get_reader_count(ctx);
	sc_debug(ctx, "Watching %d readers\n", num_watch);
	for (i = 0; i < num_watch; i++) {
		rgReaderStates[i].szReader = sc_ctx_get_reader(ctx, i)->name;
		rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
	}
#ifndef __APPLE__
	if (event_mask & SC_EVENT_READER_ATTACHED) {
		rgReaderStates[i].szReader = "\\\\?PnP?\\Notification";
		rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
		num_watch++;
	}
#endif
#ifndef _WIN32
	/* Establish a new context, assuming that it is called from a different thread with pcsc-lite */
	if (gpriv->pcsc_wait_ctx == -1) {
		rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_wait_ctx);
		if (rv != SCARD_S_SUCCESS) {
			PCSC_LOG(ctx, "SCardEstablishContext(wait) failed", rv);
			return pcsc_to_opensc_error(rv);
		}
	}
#else
	gpriv->pcsc_wait_ctx = gpriv->pcsc_ctx;
#endif

	rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, 0, rgReaderStates, num_watch);
	if (rv != SCARD_S_SUCCESS) {
		if (rv != (LONG)SCARD_E_TIMEOUT) {
			PCSC_LOG(ctx, "SCardGetStatusChange(1) failed", rv);
			return pcsc_to_opensc_error(rv);
		}
	}

	/* Wait for a status change
	 */
	for( ; ; ) {
		SCARD_READERSTATE_A *rsp;
		sc_debug(ctx, "Looping...");

		/* Scan the current state of all readers to see if they
		 * match any of the events we're polling for */
		*event = 0;
		for (i = 0, rsp = rgReaderStates; i < num_watch; i++, rsp++) {
			unsigned long state, prev_state;
			sc_debug(ctx, "%s before=0x%04X now=0x%04X", rsp->szReader, rsp->dwCurrentState, rsp->dwEventState);
			prev_state = rsp->dwCurrentState;
			state = rsp->dwEventState;
			if ((state & on_bits & SCARD_STATE_PRESENT) &&
			    (prev_state & SCARD_STATE_EMPTY))
				*event |= SC_EVENT_CARD_INSERTED;
			if ((~state & off_bits & SCARD_STATE_PRESENT) &&
			    (prev_state & SCARD_STATE_PRESENT))
				*event |= SC_EVENT_CARD_REMOVED;
			if (*event) {
				sc_debug(ctx, "Event 0x%02X in reader %s", *event, rsp->szReader);
				*event_reader = sc_ctx_get_reader_by_name(ctx, rsp->szReader);
				SC_FUNC_RETURN(ctx, 3, SC_SUCCESS);
			} 

			/* check for hotplug event  */
			if (strcmp(rgReaderStates[i].szReader, "\\\\?PnP?\\Notification") == 0 && event_mask & SC_EVENT_READER_ATTACHED) {
				if (state & SCARD_STATE_CHANGED) {
					sc_debug(ctx, "detected hotplug event");
					*event = SC_EVENT_READER_ATTACHED;
					*event_reader = NULL;
					SC_FUNC_RETURN(ctx, 3, SC_SUCCESS);
				}
			}

			/* No match - copy the state so pcscd knows
			 * what to watch out for */
			rsp->dwCurrentState = rsp->dwEventState;
		}

		/* Set the timeout if caller wants to time out */
		if (timeout == 0)
			return SC_ERROR_EVENT_TIMEOUT;

		if (timeout == -1) {
			timeout = INFINITE;
		}
		
		sc_debug(ctx, "Sleeping call, timeout 0x%lx", timeout);
		rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, timeout, rgReaderStates, num_watch);
		if (rv == (LONG) SCARD_E_CANCELLED) {
			/* C_Finalize was called, events don't matter */
			return SC_ERROR_EVENT_TIMEOUT;
		}
		if (rv == (LONG) SCARD_E_TIMEOUT) {
			return SC_ERROR_EVENT_TIMEOUT;
		}

		if (rv != SCARD_S_SUCCESS) {
			PCSC_LOG(ctx, "SCardGetStatusChange(2) failed", rv);
			return pcsc_to_opensc_error(rv);
		}
	}
}



/*
 * Pinpad support, based on PC/SC v2 Part 10 interface
 * Similar to CCID in spirit.
 */

/* Local definitions */
#define SC_CCID_PIN_TIMEOUT	30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

/* Build a PIN verification block + APDU */
static int part10_build_verify_pin_block(struct sc_reader *reader, u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
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

		/* if the effective PIN length offset is specified, use it */
		if (data->pin1.length_offset > 4) {
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (data->pin1.length_offset - 5) << 3;
		}
	} else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) {
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* see comment about GLP PINs in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x08 << 3;
	} else
		return SC_ERROR_NOT_SUPPORTED;

	pin_verify->bmFormatString = tmp;

	/* bmPINBlockString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_ASCII && data->flags & SC_PIN_CMD_NEED_PADDING) {
		tmp |= data->pin1.pad_length;
	}
	pin_verify->bmPINBlockString = tmp;

	/* bmPINLengthFormat */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PINs expect the effective PIN length from bit 4 */
		tmp |= 0x04;
	}
	pin_verify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */

	if (!data->pin1.min_length || !data->pin1.max_length)
		return SC_ERROR_INVALID_ARGUMENTS;

	tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length;
	pin_verify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */
	
	pin_verify->bEntryValidationCondition = 0x02; /* Keypress only */

	if (reader->capabilities & SC_READER_CAP_DISPLAY)
		pin_verify->bNumberMessage = 0xFF; /* Default message */
	else
		pin_verify->bNumberMessage = 0x00; /* No messages */

	/* Ignore language and T=1 parameters. */
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
		pin_verify->abData[offset++] = apdu->lc;
		memcpy(&pin_verify->abData[offset], apdu->data, apdu->datalen);
		offset += apdu->datalen;
	}

	pin_verify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_VERIFY_STRUCTURE) + offset -1;
	*size = count;
	return SC_SUCCESS;
}



/* Build a PIN modification block + APDU */
static int part10_build_modify_pin_block(struct sc_reader *reader, u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
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

		/* if the effective PIN length offset is specified, use it */
		if (data->pin1.length_offset > 4) {
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (data->pin1.length_offset - 5) << 3;
		}
	} else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) {
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* see comment about GLP PINs in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x08 << 3;
	} else
		return SC_ERROR_NOT_SUPPORTED;

	pin_modify->bmFormatString = tmp;	/* bmFormatString */

	/* bmPINBlockString */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	} else if (data->pin1.encoding == SC_PIN_ENCODING_ASCII && data->pin1.pad_length) {
		tmp |= data->pin1.pad_length;
	}
	pin_modify->bmPINBlockString = tmp; /* bmPINBlockString */

	/* bmPINLengthFormat */
	tmp = 0x00;
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PINs expect the effective PIN length from bit 4 */
		tmp |= 0x04;
	}
	pin_modify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */

	/* Set offsets if not Case 1 APDU */
	if (data->pin1.length_offset != 4) {
		pin_modify->bInsertionOffsetOld = data->pin1.offset - 5;
		pin_modify->bInsertionOffsetNew = data->pin2.offset - 5;
	} else {
		pin_modify->bInsertionOffsetOld = 0x00;
		pin_modify->bInsertionOffsetNew = 0x00;
	}

	if (!data->pin1.min_length || !data->pin1.max_length)
		return SC_ERROR_INVALID_ARGUMENTS;
		
	tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length;
	pin_modify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */

	/* bConfirmPIN flags
	 * 0x01: New Pin, Confirm Pin
	 * 0x03: Enter Old Pin, New Pin, Confirm Pin
	 */
	pin_modify->bConfirmPIN = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x01 : 0x03;
	pin_modify->bEntryValidationCondition = 0x02;	/* bEntryValidationCondition, keypress only */
	
	/* bNumberMessage flags
	 * 0x02: Messages seen on Pinpad display: New Pin, Confirm Pin
	 * 0x03: Messages seen on Pinpad display: Enter Old Pin, New Pin, Confirm Pin
	 * Could be 0xFF too.
	 */
	if (reader->capabilities & SC_READER_CAP_DISPLAY)
		pin_modify->bNumberMessage = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x02 : 0x03;
	else
		pin_modify->bNumberMessage = 0x00; /* No messages */

	/* Ignore language and T=1 parameters. */
	pin_modify->wLangId = HOST_TO_CCID_16(0x0000);
	pin_modify->bMsgIndex1 = 0x00; /* Default message indexes */
	pin_modify->bMsgIndex2 = 0x01;
	pin_modify->bMsgIndex3 = 0x02;
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
		pin_modify->abData[offset++] = apdu->lc;
		memcpy(&pin_modify->abData[offset], apdu->data, apdu->datalen);
		offset += apdu->datalen;
	}

	pin_modify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_MODIFY_STRUCTURE) + offset -1;
	*size = count;
	return SC_SUCCESS;
}

/* Do the PIN command */
static int
pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE], sbuf[SC_MAX_APDU_BUFFER_SIZE];
	char dbuf[SC_MAX_APDU_BUFFER_SIZE * 3];
	size_t rcount = sizeof(rbuf), scount = 0;
	int r;
	DWORD ioctl = 0;
	sc_apdu_t *apdu;

	SC_FUNC_CALLED(reader->ctx, 3);

	if (priv->gpriv->SCardControl == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	/* The APDU must be provided by the card driver */
	if (!data->apdu) {
		sc_debug(reader->ctx, "No APDU provided for PC/SC v2 pinpad verification!");
		return SC_ERROR_NOT_SUPPORTED;
	}

	apdu = data->apdu;
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		if (!(priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish))) {
			sc_debug(reader->ctx, "Pinpad reader does not support verification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		r = part10_build_verify_pin_block(reader, sbuf, &scount, data);
		ioctl = priv->verify_ioctl ? priv->verify_ioctl : priv->verify_ioctl_start;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		if (!(priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish))) {
			sc_debug(reader->ctx, "Pinpad reader does not support modification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		r = part10_build_modify_pin_block(reader, sbuf, &scount, data);
		ioctl = priv->modify_ioctl ? priv->modify_ioctl : priv->modify_ioctl_start;
		break;
	default:
		sc_debug(reader->ctx, "Unknown PIN command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* If PIN block building failed, we fail too */
	SC_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad block building failed!");
	/* If not, debug it, just for fun */
	sc_bin_to_hex(sbuf, scount, dbuf, sizeof(dbuf), ':');
	sc_debug(reader->ctx, "PC/SC v2 pinpad block: %s", dbuf);

	r = pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount, ioctl);

	SC_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad: block transmit failed!");
	/* finish the call if it was a two-phase operation */
	if ((ioctl == priv->verify_ioctl_start)
	    || (ioctl == priv->modify_ioctl_start)) {
		if (rcount != 0) {
			SC_FUNC_RETURN(reader->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
		ioctl = (ioctl == priv->verify_ioctl_start) ? priv->verify_ioctl_finish : priv->modify_ioctl_finish;

		rcount = sizeof(rbuf);
		r = pcsc_internal_transmit(reader, sbuf, 0, rbuf, &rcount, ioctl);
		SC_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad: finish operation failed!");
	}

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
	case 0x6B80: /* Wrong data in the buffer, rejected by firmware */
		r = SC_ERROR_READER;
		break;
	}

	SC_TEST_RET(reader->ctx, r, "PIN command failed");

	/* PIN command completed, all is good */
	return SC_SUCCESS;
}

struct sc_reader_driver * sc_get_pcsc_driver(void)
{
	pcsc_ops.init = pcsc_init;
	pcsc_ops.finish = pcsc_finish;
	pcsc_ops.detect_readers = pcsc_detect_readers;
	pcsc_ops.transmit = pcsc_transmit;
	pcsc_ops.detect_card_presence = pcsc_detect_card_presence;
	pcsc_ops.lock = pcsc_lock;
	pcsc_ops.unlock = pcsc_unlock;
	pcsc_ops.release = pcsc_release;
	pcsc_ops.connect = pcsc_connect;
	pcsc_ops.disconnect = pcsc_disconnect;
	pcsc_ops.perform_verify = pcsc_pin_cmd;
	pcsc_ops.wait_for_event = pcsc_wait_for_event;
	pcsc_ops.cancel = pcsc_cancel;
	pcsc_ops.reset = pcsc_reset;

	return &pcsc_drv;
}

#endif   /* HAVE_PCSC */

