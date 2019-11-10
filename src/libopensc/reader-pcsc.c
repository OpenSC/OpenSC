/*
 * reader-pcsc.c: Reader driver for PC/SC interface
 *
 * Copyright (C) 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2009,2010 Martin Paljak <martin@martinpaljak.net>
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

#ifdef ENABLE_PCSC	/* empty file without pcsc */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "common/libscdl.h"
#include "internal.h"
#include "internal-winscard.h"
#include "card-sc-hsm.h"

#include "pace.h"

#ifdef HAVE_PCSCLITE_H
#if !defined (__MAC_OS_X_VERSION_MIN_REQUIRED) || __MAC_OS_X_VERSION_MIN_REQUIRED < 101000
#define HAVE_PCSCLITE 1
#endif
#endif

#define SCARD_CLASS_SYSTEM     0x7fff
#define SCARD_ATTR_VALUE(Class, Tag) ((((ULONG)(Class)) << 16) | ((ULONG)(Tag)))

#ifndef SCARD_ATTR_DEVICE_FRIENDLY_NAME_A
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0003)
#endif

#ifndef SCARD_ATTR_DEVICE_SYSTEM_NAME_A
#define SCARD_ATTR_DEVICE_SYSTEM_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0004)
#endif

#define SCARD_CLASS_VENDOR_INFO 1

#ifndef SCARD_ATTR_VENDOR_NAME
#define SCARD_ATTR_VENDOR_NAME SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0100) /**< Vendor name. */
#endif

#ifndef SCARD_ATTR_VENDOR_IFD_TYPE
#define SCARD_ATTR_VENDOR_IFD_TYPE SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0101) /**< Vendor-supplied interface device type (model designation of reader). */
#endif

#ifndef SCARD_ATTR_VENDOR_IFD_VERSION
#define SCARD_ATTR_VENDOR_IFD_VERSION SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0102) /**< Vendor-supplied interface device version (DWORD in the form 0xMMmmbbbb where MM = major version, mm = minor version, and bbbb = build number). */
#endif

/* Logging */
#define PCSC_TRACE(reader, desc, rv) do { sc_log(reader->ctx, "%s:" desc ": 0x%08lx\n", reader->name, (unsigned long)((ULONG)rv)); } while (0)
#define PCSC_LOG(ctx, desc, rv) do { sc_log(ctx, desc ": 0x%08lx\n", (unsigned long)((ULONG)rv)); } while (0)

/* #define APDU_LOG_FILE "apdulog" */
#ifdef APDU_LOG_FILE
void APDU_LOG(u8 *rbuf, uint16_t rsize)
{
	static FILE *fd = NULL;
	u8 *lenb = (u8*)&rsize;

	if (fd == NULL) {
		fd = fopen(APDU_LOG_FILE, "w");
	}
	/* First two bytes denote the length */
	(void) fwrite(lenb, 2, 1, fd);
	(void) fwrite(rbuf, rsize, 1, fd);
	fflush(fd);
}
#else
#define APDU_LOG(rbuf, rsize)
#endif

struct pcsc_global_private_data {
	int cardmod;
	SCARDCONTEXT pcsc_ctx;
	SCARDCONTEXT pcsc_wait_ctx;
	int enable_pinpad;
	int fixed_pinlength;
	int enable_pace;
	size_t force_max_recv_size;
	size_t force_max_send_size;
	int connect_exclusive;
	DWORD disconnect_action;
	DWORD transaction_end_action;
	DWORD reconnect_action;
	const char *provider_library;
	void *dlhandle;
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
	SCardGetAttrib_t SCardGetAttrib;
};

struct pcsc_private_data {
	struct pcsc_global_private_data *gpriv;
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE reader_state;
	DWORD verify_ioctl;
	DWORD verify_ioctl_start;
	DWORD verify_ioctl_finish;

	DWORD modify_ioctl;
	DWORD modify_ioctl_start;
	DWORD modify_ioctl_finish;

	DWORD pace_ioctl;

	DWORD pin_properties_ioctl;

	DWORD get_tlv_properties;

	int locked;
};

static int pcsc_detect_card_presence(sc_reader_t *reader);
static int pcsc_reconnect(sc_reader_t * reader, DWORD action);
static int pcsc_connect(sc_reader_t *reader);

static DWORD pcsc_reset_action(const char *str)
{
	if (!strcmp(str, "reset"))
		return SCARD_RESET_CARD;
	else if (!strcmp(str, "unpower"))
		return SCARD_UNPOWER_CARD;
	else
		return SCARD_LEAVE_CARD;
}

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
	case SCARD_E_NO_READERS_AVAILABLE:
		return SC_ERROR_NO_READERS_FOUND;
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
	struct pcsc_private_data *priv = reader->drv_data;
	SCARD_IO_REQUEST sSendPci, sRecvPci;
	DWORD dwSendLength, dwRecvLength;
	LONG rv;
	SCARDHANDLE card;

	LOG_FUNC_CALLED(reader->ctx);
	card = priv->pcsc_card;

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

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
		case SCARD_E_INVALID_HANDLE:
		case SCARD_E_INVALID_VALUE:
		case SCARD_E_READER_UNAVAILABLE:
			pcsc_connect(reader);
			/* return failure so that upper layers will be notified */
			return SC_ERROR_READER_REATTACHED;
		case SCARD_W_RESET_CARD:
			pcsc_reconnect(reader, SCARD_LEAVE_CARD);
			/* return failure so that upper layers will be notified */
			return SC_ERROR_CARD_RESET;
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
	size_t ssize, rsize, rbuflen = 0;
	u8 *sbuf = NULL, *rbuf = NULL;
	int r;

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
	if (reader->name)
		sc_log(reader->ctx, "reader '%s'", reader->name);
	sc_apdu_log(reader->ctx, sbuf, ssize, 1);

	r = pcsc_internal_transmit(reader, sbuf, ssize,
				rbuf, &rsize, apdu->control);
	if (r < 0) {
		/* unable to transmit ... most likely a reader problem */
		sc_log(reader->ctx, "unable to transmit");
		goto out;
	}
	sc_apdu_log(reader->ctx, rbuf, rsize, 0);
	APDU_LOG(rbuf, (uint16_t)rsize);
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

/* Calls SCardGetStatusChange on the reader to set ATR and associated flags
 * (card present/changed) */
static int refresh_attributes(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = reader->drv_data;
	int old_flags = reader->flags;
	DWORD state, prev_state;
	LONG rv;

	sc_log(reader->ctx, "%s check", reader->name);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

	if (priv->reader_state.szReader == NULL) {
		priv->reader_state.szReader = reader->name;
		priv->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
		priv->reader_state.dwEventState = SCARD_STATE_UNAWARE;
	} else {
		priv->reader_state.dwCurrentState = priv->reader_state.dwEventState;
	}

	rv = priv->gpriv->SCardGetStatusChange(priv->gpriv->pcsc_ctx, 0, &priv->reader_state, 1);

	if (rv != SCARD_S_SUCCESS) {
		if (rv == (LONG)SCARD_E_TIMEOUT) {
			/* Timeout, no change from previous recorded state. Make sure that
			 * changed flag is not set. */
			reader->flags &= ~SC_READER_CARD_CHANGED;
			/* Make sure to preserve the CARD_PRESENT flag if the reader was
			 * reattached and we called the refresh_attributes too recently */
			if (priv->reader_state.dwEventState & SCARD_STATE_PRESENT) {
				reader->flags |= SC_READER_CARD_PRESENT;
			}
			LOG_FUNC_RETURN(reader->ctx, SC_SUCCESS);
		}
		
		/* the system could not detect the reader. It means, the prevoiusly attached reader is disconnected. */
		if (
#ifdef SCARD_E_NO_READERS_AVAILABLE
			(rv == (LONG)SCARD_E_NO_READERS_AVAILABLE) ||
#endif
			(rv == (LONG)SCARD_E_UNKNOWN_READER) || (rv == (LONG)SCARD_E_SERVICE_STOPPED)) {

 			if (old_flags & SC_READER_CARD_PRESENT) {
 				reader->flags |= SC_READER_CARD_CHANGED;
 			}
			
 			SC_FUNC_RETURN(reader->ctx, SC_LOG_DEBUG_VERBOSE, SC_SUCCESS);
 		}

		PCSC_TRACE(reader, "SCardGetStatusChange failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	state = priv->reader_state.dwEventState;
	prev_state = priv->reader_state.dwCurrentState;

	sc_log(reader->ctx, "current  state: 0x%08X", (unsigned int)state);
	sc_log(reader->ctx, "previous state: 0x%08X", (unsigned int)prev_state);

	if (state & SCARD_STATE_UNKNOWN) {
		/* State means "reader unknown", but we have listed it at least once.
		 * There can be no cards in this reader.
		 * XXX: We'll hit it again, as no readers are removed currently.
		 */
		reader->flags &= ~(SC_READER_CARD_PRESENT);
		return SC_ERROR_READER_DETACHED;
	}

	reader->flags &= ~(SC_READER_CARD_CHANGED|SC_READER_CARD_INUSE|SC_READER_CARD_EXCLUSIVE);

	if (state & SCARD_STATE_PRESENT) {
		reader->flags |= SC_READER_CARD_PRESENT;

		if (priv->reader_state.cbAtr > SC_MAX_ATR_SIZE)
			return SC_ERROR_INTERNAL;

		/* Some cards have a different cold (after a powerup) and warm (after a reset) ATR  */
		if (memcmp(priv->reader_state.rgbAtr, reader->atr.value, priv->reader_state.cbAtr) != 0) {
			reader->atr.len = priv->reader_state.cbAtr;
			memcpy(reader->atr.value, priv->reader_state.rgbAtr, reader->atr.len);
			APDU_LOG(reader->atr.value, (uint16_t) reader->atr.len);
		}

		/* Is the reader in use by some other application ? */
		if (state & SCARD_STATE_INUSE)
			reader->flags |= SC_READER_CARD_INUSE;
		if (state & SCARD_STATE_EXCLUSIVE)
			reader->flags |= SC_READER_CARD_EXCLUSIVE;

		if (old_flags & SC_READER_CARD_PRESENT) {
			/* Requires pcsc-lite 1.6.5+ to function properly */
			if ((state & 0xFFFF0000) != (prev_state & 0xFFFF0000)) {
				reader->flags |= SC_READER_CARD_CHANGED;
			} else {
				/* Check if the card handle is still valid. If the card changed,
				 * the handle will be invalid. */
				DWORD readers_len = 0, cstate, prot, atr_len = SC_MAX_ATR_SIZE;
				unsigned char atr[SC_MAX_ATR_SIZE];
				rv = priv->gpriv->SCardStatus(priv->pcsc_card, NULL,
						&readers_len, &cstate, &prot, atr, &atr_len);
				if (rv == (LONG)SCARD_W_REMOVED_CARD || rv == (LONG)SCARD_E_INVALID_VALUE)
					reader->flags |= SC_READER_CARD_CHANGED;
			}
		} else {
			reader->flags |= SC_READER_CARD_CHANGED;
		}
	} else {
		reader->flags &= ~SC_READER_CARD_PRESENT;
		if (old_flags & SC_READER_CARD_PRESENT)
			reader->flags |= SC_READER_CARD_CHANGED;
	}
	sc_log(reader->ctx, "card %s%s",
			reader->flags & SC_READER_CARD_PRESENT ? "present" : "absent",
			reader->flags & SC_READER_CARD_CHANGED ? ", changed": "");

	return SC_SUCCESS;
}

static int pcsc_detect_card_presence(sc_reader_t *reader)
{
	int rv;
	LOG_FUNC_CALLED(reader->ctx);

	rv = refresh_attributes(reader);
	if (rv != SC_SUCCESS)
		LOG_FUNC_RETURN(reader->ctx, rv);
	LOG_FUNC_RETURN(reader->ctx, reader->flags);
}

static int check_forced_protocol(sc_reader_t *reader, DWORD *protocol)
{
	scconf_block *atrblock = NULL;
	int forced = 0;

	atrblock = _sc_match_atr_block(reader->ctx, NULL, &reader->atr);
	if (atrblock != NULL) {
		const char *forcestr;

		forcestr = scconf_get_str(atrblock, "force_protocol", "unknown");
		if (!strcmp(forcestr, "t0")) {
			*protocol = SCARD_PROTOCOL_T0;
			forced = 1;
		} else if (!strcmp(forcestr, "t1")) {
			*protocol = SCARD_PROTOCOL_T1;
			forced = 1;
		} else if (!strcmp(forcestr, "raw")) {
			*protocol = SCARD_PROTOCOL_RAW;
			forced = 1;
		}
		if (forced)
			sc_log(reader->ctx, "force_protocol: %s", forcestr);
	}

	if (!forced && reader->uid.len) {
		/* We identify contactless cards by their UID. Communication
		 * defined by ISO/IEC 14443 is identical to T=1. */
		*protocol = SCARD_PROTOCOL_T1;
		forced = 1;
	}

	if (!forced) {
		sc_card_t card;
		memset(&card, 0, sizeof card);
		card.ctx = reader->ctx;
		card.atr = reader->atr;
		if (0 <= _sc_match_atr(&card, sc_hsm_atrs, NULL)) {
			*protocol = SCARD_PROTOCOL_T1;
			forced = 1;
		}
	}

	return forced;
}


static int pcsc_reconnect(sc_reader_t * reader, DWORD action)
{
	DWORD active_proto = opensc_proto_to_pcsc(reader->active_protocol),
		  tmp, protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
	LONG rv;
	struct pcsc_private_data *priv = reader->drv_data;
	int r;

	sc_log(reader->ctx, "Reconnecting to the card...");

	r = refresh_attributes(reader);
	if (r!= SC_SUCCESS)
		return r;

	if (!(reader->flags & SC_READER_CARD_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	/* Check if we need a specific protocol. refresh_attributes above already sets the ATR */
	if (check_forced_protocol(reader, &tmp))
		protocol = tmp;

#ifndef HAVE_PCSCLITE
	/* reconnect unlocks transaction everywhere but in PCSC-lite */
	priv->locked = 0;
#endif

	rv = priv->gpriv->SCardReconnect(priv->pcsc_card,
			priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
			protocol, action, &active_proto);

	
	PCSC_TRACE(reader, "SCardReconnect returned", rv);
	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardReconnect failed", rv);
		return pcsc_to_opensc_error(rv);
	}

	reader->active_protocol = pcsc_proto_to_opensc(active_proto);
	return pcsc_to_opensc_error(rv);
}

static void initialize_uid(sc_reader_t *reader)
{
	if (reader->flags & SC_READER_ENABLE_ESCAPE) {
		sc_apdu_t apdu;
		/* though we only expect 10 bytes max, we want to set the Le to 0x00 to not
		 * get 0x6282 as SW in case of a UID variant shorter than 10 bytes */
		u8 rbuf[256];

		memset(&apdu, 0, sizeof(apdu));
		apdu.cse = SC_APDU_CASE_2_SHORT;
		apdu.cla = 0xFF;
		apdu.ins = 0xCA;
		apdu.p1 = 0x00;
		apdu.p2 = 0x00;
		apdu.le = 0x00;
		apdu.resp = rbuf;
		apdu.resplen = sizeof rbuf;

		if (SC_SUCCESS == pcsc_transmit(reader, &apdu)
				&& apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			reader->uid.len = apdu.resplen;
			memcpy(reader->uid.value, apdu.resp, reader->uid.len);
			sc_log_hex(reader->ctx, "UID",
					reader->uid.value, reader->uid.len);
		} else {
			sc_log(reader->ctx,  "unable to get UID");
		}
	}
}

static int pcsc_connect(sc_reader_t *reader)
{
	DWORD active_proto, tmp, protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
	SCARDHANDLE card_handle;
	LONG rv;
	struct pcsc_private_data *priv = reader->drv_data;
	int r;

	LOG_FUNC_CALLED(reader->ctx);

	r = refresh_attributes(reader);
	if (r != SC_SUCCESS)
		LOG_FUNC_RETURN(reader->ctx, r);

	if (!(reader->flags & SC_READER_CARD_PRESENT))
		LOG_FUNC_RETURN(reader->ctx, SC_ERROR_CARD_NOT_PRESENT);


	if (!priv->gpriv->cardmod) {
		rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, reader->name,
				priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
				protocol, &card_handle, &active_proto);
#ifdef __APPLE__
		if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
			sleep(1); /* Try again to compete with Tokend probes */
			rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, reader->name,
					priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED,
					protocol, &card_handle, &active_proto);
		}
#endif
		if (rv != SCARD_S_SUCCESS) {
			PCSC_TRACE(reader, "SCardConnect failed", rv);
			return pcsc_to_opensc_error(rv);
		}

		reader->active_protocol = pcsc_proto_to_opensc(active_proto);
		priv->pcsc_card = card_handle;

		initialize_uid(reader);

		sc_log(reader->ctx, "Initial protocol: %s", reader->active_protocol == SC_PROTO_T1 ? "T=1" : "T=0");

		/* Check if we need a specific protocol. refresh_attributes above already sets the ATR */
		if (check_forced_protocol(reader, &tmp)) {
			if (active_proto != tmp) {
				sc_log(reader->ctx, "Reconnecting to force protocol");
				r = pcsc_reconnect(reader, SCARD_UNPOWER_CARD);
				if (r != SC_SUCCESS) {
					sc_log(reader->ctx,
							"pcsc_reconnect (to force protocol) failed (%d)",
							r);
					return r;
				}
			}
			sc_log(reader->ctx, "Final protocol: %s", reader->active_protocol == SC_PROTO_T1 ? "T=1" : "T=0");
		}
	} else {
		initialize_uid(reader);
	}

	/* After connect reader is not locked yet */
	priv->locked = 0;

	return SC_SUCCESS;
}

static int pcsc_disconnect(sc_reader_t * reader)
{
	struct pcsc_private_data *priv = reader->drv_data;

	if (!priv->gpriv->cardmod && !(reader->ctx->flags & SC_CTX_FLAG_TERMINATE)) {
		LONG rv = priv->gpriv->SCardDisconnect(priv->pcsc_card, priv->gpriv->disconnect_action);
		PCSC_TRACE(reader, "SCardDisconnect returned", rv);
	}
	reader->flags = 0;
	return SC_SUCCESS;
}

static int pcsc_lock(sc_reader_t *reader)
{
	LONG rv;
	int r;
	struct pcsc_private_data *priv = reader->drv_data;

	if (priv->gpriv->cardmod)
		return SC_SUCCESS;

	LOG_FUNC_CALLED(reader->ctx);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

	rv = priv->gpriv->SCardBeginTransaction(priv->pcsc_card);


	if (rv != SCARD_S_SUCCESS)
		PCSC_TRACE(reader, "SCardBeginTransaction returned", rv);

	switch (rv) {
		case SCARD_E_INVALID_VALUE:
			/* This is retuned in case of the same reader was re-attached */
		case SCARD_E_INVALID_HANDLE:
		case SCARD_E_READER_UNAVAILABLE:
			r = pcsc_connect(reader);
			if (r != SC_SUCCESS) {
				sc_log(reader->ctx, "pcsc_connect failed (%d)",
						r);
				return r;
			}
			/* return failure so that upper layers will be notified and try to lock again */
			return SC_ERROR_READER_REATTACHED;
		case SCARD_W_RESET_CARD:
			/* try to reconnect if the card was reset by some other application */
			PCSC_TRACE(reader, "SCardBeginTransaction calling pcsc_reconnect", rv);
			r = pcsc_reconnect(reader, SCARD_LEAVE_CARD);
			if (r != SC_SUCCESS) {
				sc_log(reader->ctx,
						"pcsc_reconnect failed (%d)", r);
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
	struct pcsc_private_data *priv = reader->drv_data;

	if (priv->gpriv->cardmod)
		return SC_SUCCESS;

	LOG_FUNC_CALLED(reader->ctx);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

	rv = priv->gpriv->SCardEndTransaction(priv->pcsc_card, priv->gpriv->transaction_end_action);

	priv->locked = 0;
	if (rv != SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardEndTransaction failed", rv);
		return pcsc_to_opensc_error(rv);
	}
	return SC_SUCCESS;
}

static int pcsc_release(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = reader->drv_data;

	free(priv);
	return SC_SUCCESS;
}

static int pcsc_reset(sc_reader_t *reader, int do_cold_reset)
{
	int r;
#ifndef HAVE_PCSCLITE
	struct pcsc_private_data *priv = reader->drv_data;
	int old_locked = priv->locked;
#endif

	r = pcsc_reconnect(reader, do_cold_reset ? SCARD_UNPOWER_CARD : SCARD_RESET_CARD);
	if(r != SC_SUCCESS)
		return r;

#ifndef HAVE_PCSCLITE
	/* reconnect unlocks transaction everywhere but in PCSC-lite */
	if(old_locked)
		r = pcsc_lock(reader);
#endif

	return r;
}


static int pcsc_cancel(sc_context_t *ctx)
{
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)ctx->reader_drv_data;

	LOG_FUNC_CALLED(ctx);

	if (ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

#ifndef _WIN32
	if (gpriv->pcsc_wait_ctx != (SCARDCONTEXT)-1) {
		rv = gpriv->SCardCancel(gpriv->pcsc_wait_ctx);
		if (rv == SCARD_S_SUCCESS) {
			 /* Also close and clear the waiting context */
			 rv = gpriv->SCardReleaseContext(gpriv->pcsc_wait_ctx);
			 gpriv->pcsc_wait_ctx = -1;
		}
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
	NULL
};

static int pcsc_init(sc_context_t *ctx)
{
	struct pcsc_global_private_data *gpriv;
	scconf_block *conf_block = NULL;
	int ret = SC_ERROR_INTERNAL;


	gpriv = calloc(1, sizeof(struct pcsc_global_private_data));
	if (gpriv == NULL) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if(strcmp(ctx->app_name, "cardmod") == 0) {
		gpriv->cardmod = 1;
	}

	/* PC/SC Defaults */
	gpriv->provider_library = DEFAULT_PCSC_PROVIDER;
	gpriv->connect_exclusive = 0;
	gpriv->disconnect_action = SCARD_LEAVE_CARD;
	gpriv->transaction_end_action = SCARD_LEAVE_CARD;
	gpriv->reconnect_action = SCARD_LEAVE_CARD;
	gpriv->enable_pinpad = 1;
	gpriv->fixed_pinlength = 0;
	gpriv->enable_pace = 1;
	gpriv->pcsc_ctx = -1;
	gpriv->pcsc_wait_ctx = -1;
	/* max send/receive sizes: if exist in configuration these options overwrite
	 *			   the values by default and values declared by reader */
	gpriv->force_max_send_size = 0;
	gpriv->force_max_recv_size = 0;

	conf_block = sc_get_conf_block(ctx, "reader_driver", "pcsc", 1);
	if (conf_block) {
		gpriv->provider_library =
			scconf_get_str(conf_block, "provider_library", gpriv->provider_library);
		gpriv->connect_exclusive =
			scconf_get_bool(conf_block, "connect_exclusive", gpriv->connect_exclusive);
		gpriv->disconnect_action =
			pcsc_reset_action(scconf_get_str(conf_block, "disconnect_action", "leave"));
		gpriv->transaction_end_action =
			pcsc_reset_action(scconf_get_str(conf_block, "transaction_end_action", "leave"));
		gpriv->reconnect_action =
			pcsc_reset_action(scconf_get_str(conf_block, "reconnect_action", "leave"));
		gpriv->enable_pinpad = scconf_get_bool(conf_block, "enable_pinpad",
				gpriv->enable_pinpad);
		gpriv->fixed_pinlength = scconf_get_bool(conf_block, "fixed_pinlength",
				gpriv->fixed_pinlength);
		gpriv->enable_pace = scconf_get_bool(conf_block, "enable_pace",
				gpriv->enable_pace);
		gpriv->force_max_send_size = scconf_get_int(conf_block,
				"max_send_size", gpriv->force_max_send_size);
		gpriv->force_max_recv_size = scconf_get_int(conf_block,
				"max_recv_size", gpriv->force_max_recv_size);
	}

	if (gpriv->cardmod) {
		/* for cardmod, don't manipulate winscard.dll or the OS's builtin
		 * management of SCARDHANDLEs */
		gpriv->provider_library = DEFAULT_PCSC_PROVIDER;
		gpriv->connect_exclusive = 0;
		gpriv->disconnect_action = SCARD_LEAVE_CARD;
		gpriv->transaction_end_action = SCARD_LEAVE_CARD;
		gpriv->reconnect_action = SCARD_LEAVE_CARD;
	}
	sc_log(ctx,
			"PC/SC options: connect_exclusive=%d disconnect_action=%u transaction_end_action=%u"
			" reconnect_action=%u enable_pinpad=%d enable_pace=%d",
			gpriv->connect_exclusive,
			(unsigned int)gpriv->disconnect_action,
			(unsigned int)gpriv->transaction_end_action,
			(unsigned int)gpriv->reconnect_action, gpriv->enable_pinpad,
			gpriv->enable_pace);

	gpriv->dlhandle = sc_dlopen(gpriv->provider_library);
	if (gpriv->dlhandle == NULL) {
		ret = SC_ERROR_CANNOT_LOAD_MODULE;
		goto out;
	}

	gpriv->SCardEstablishContext = (SCardEstablishContext_t)sc_dlsym(gpriv->dlhandle, "SCardEstablishContext");
	gpriv->SCardReleaseContext = (SCardReleaseContext_t)sc_dlsym(gpriv->dlhandle, "SCardReleaseContext");
	gpriv->SCardConnect = (SCardConnect_t)sc_dlsym(gpriv->dlhandle, "SCardConnect");
	gpriv->SCardReconnect = (SCardReconnect_t)sc_dlsym(gpriv->dlhandle, "SCardReconnect");
	gpriv->SCardDisconnect = (SCardDisconnect_t)sc_dlsym(gpriv->dlhandle, "SCardDisconnect");
	gpriv->SCardBeginTransaction = (SCardBeginTransaction_t)sc_dlsym(gpriv->dlhandle, "SCardBeginTransaction");
	gpriv->SCardEndTransaction = (SCardEndTransaction_t)sc_dlsym(gpriv->dlhandle, "SCardEndTransaction");
	gpriv->SCardStatus = (SCardStatus_t)sc_dlsym(gpriv->dlhandle, "SCardStatus");
	gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(gpriv->dlhandle, "SCardGetStatusChange");
	gpriv->SCardCancel = (SCardCancel_t)sc_dlsym(gpriv->dlhandle, "SCardCancel");
	gpriv->SCardTransmit = (SCardTransmit_t)sc_dlsym(gpriv->dlhandle, "SCardTransmit");
	gpriv->SCardListReaders = (SCardListReaders_t)sc_dlsym(gpriv->dlhandle, "SCardListReaders");

	if (gpriv->SCardConnect == NULL)
		gpriv->SCardConnect = (SCardConnect_t)sc_dlsym(gpriv->dlhandle, "SCardConnectA");
	if (gpriv->SCardStatus == NULL)
		gpriv->SCardStatus = (SCardStatus_t)sc_dlsym(gpriv->dlhandle, "SCardStatusA");
	if (gpriv->SCardGetStatusChange == NULL)
		gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(gpriv->dlhandle, "SCardGetStatusChangeA");
	if (gpriv->SCardListReaders == NULL)
		gpriv->SCardListReaders = (SCardListReaders_t)sc_dlsym(gpriv->dlhandle, "SCardListReadersA");

	/* If we have SCardGetAttrib it is correct API */
	gpriv->SCardGetAttrib = (SCardGetAttrib_t)sc_dlsym(gpriv->dlhandle, "SCardGetAttrib");
	if (gpriv->SCardGetAttrib != NULL) {
#ifdef __APPLE__
		gpriv->SCardControl = (SCardControl_t)sc_dlsym(gpriv->dlhandle, "SCardControl132");
#endif
		if (gpriv->SCardControl == NULL) {
			gpriv->SCardControl = (SCardControl_t)sc_dlsym(gpriv->dlhandle, "SCardControl");
		}
	}
	else {
		gpriv->SCardControlOLD = (SCardControlOLD_t)sc_dlsym(gpriv->dlhandle, "SCardControl");
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

	ctx->reader_drv_data = gpriv;
	gpriv = NULL;
	ret = SC_SUCCESS;

out:
	if (gpriv != NULL) {
		if (gpriv->dlhandle != NULL)
			sc_dlclose(gpriv->dlhandle);
		free(gpriv);
	}

	return ret;
}


static int pcsc_finish(sc_context_t *ctx)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) ctx->reader_drv_data;

	LOG_FUNC_CALLED(ctx);

	if (gpriv) {
		if (!gpriv->cardmod && gpriv->pcsc_ctx != (SCARDCONTEXT)-1 &&
				!(ctx->flags & SC_CTX_FLAG_TERMINATE))
			gpriv->SCardReleaseContext(gpriv->pcsc_ctx);
		if (gpriv->dlhandle != NULL)
			sc_dlclose(gpriv->dlhandle);
		free(gpriv);
	}

	return SC_SUCCESS;
}


/**
 * @brief Detects reader's PACE capabilities
 *
 * @param reader reader to probe (\c pace_ioctl must be initialized)
 *
 * @return Bitmask of \c SC_READER_CAP_PACE_GENERIC, \c SC_READER_CAP_PACE_EID and \c * SC_READER_CAP_PACE_ESIGN logically OR'ed if supported
 */
static unsigned long part10_detect_pace_capabilities(sc_reader_t *reader, SCARDHANDLE card_handle)
{
	u8 pace_capabilities_buf[] = {
		PACE_FUNCTION_GetReaderPACECapabilities,/* idxFunction */
		0, 0,					/* lengthInputData */
	};
	u8 rbuf[7];
	u8 *p = rbuf;
	DWORD rcount = sizeof rbuf;
	struct pcsc_private_data *priv;
	unsigned long flags = 0;

	if (!reader)
		goto err;
	priv = reader->drv_data;
	if (!priv)
		goto err;

	if (priv->pace_ioctl && priv->gpriv) {
		if (SCARD_S_SUCCESS != priv->gpriv->SCardControl(card_handle,
					priv->pace_ioctl, pace_capabilities_buf,
					sizeof pace_capabilities_buf, rbuf, sizeof(rbuf),
					&rcount)) {
			sc_log(reader->ctx, "PC/SC v2 part 10 amd1: Get PACE properties failed!");
			goto err;
		}

	if (rcount != 7)
		goto err;
	/* Result */
	if ((uint32_t) *p != 0)
		goto err;
	p += sizeof(uint32_t);
	/* length_OutputData */
	if ((uint16_t) *p != 1)
		goto err;
	p += sizeof(uint16_t);

	if (*p & PACE_CAPABILITY_eSign)
		flags |= SC_READER_CAP_PACE_ESIGN;
	if (*p & PACE_CAPABILITY_eID)
		flags |= SC_READER_CAP_PACE_EID;
	if (*p & PACE_CAPABILITY_generic)
		flags |= SC_READER_CAP_PACE_GENERIC;
	if (*p & PACE_CAPABILITY_DestroyPACEChannel)
		flags |= SC_READER_CAP_PACE_DESTROY_CHANNEL;
	}

err:
	return flags;
}

static int
part10_find_property_by_tag(unsigned char buffer[], int length,
	int tag_searched);
/**
 * @brief Detects reader's maximum data size
 *
 * @param reader reader to probe (\c get_tlv_properties must be initialized)
 *
 * @return maximum data size
 */
static size_t part10_detect_max_data(sc_reader_t *reader, SCARDHANDLE card_handle)
{
	u8 rbuf[256];
	DWORD rcount = sizeof rbuf;
	struct pcsc_private_data *priv = NULL;
	/* 0 means extended APDU not supported */
	size_t max_data = 0;
	int r;

	if (!reader)
		goto err;
	priv = reader->drv_data;
	if (!priv)
		goto err;

	if (priv->get_tlv_properties && priv->gpriv) {
		if (SCARD_S_SUCCESS != priv->gpriv->SCardControl(card_handle,
				priv->get_tlv_properties, NULL, 0, rbuf, sizeof(rbuf), &rcount)) {
			sc_log(reader->ctx, "PC/SC v2 part 10: Get TLV properties failed!");
			goto err;
		}

		r = part10_find_property_by_tag(rbuf, rcount,
				PCSCv2_PART10_PROPERTY_dwMaxAPDUDataSize);
		sc_log(reader->ctx, "get dwMaxAPDUDataSize property returned %i", r);

		/* 256 < X <= 0x10000: short and extended APDU of up to X bytes of data */
		if (r > 0x100 && r <= 0x10000)
			max_data = r;
	}
err:
	return max_data;
}

static int part10_get_vendor_product(struct sc_reader *reader,
		SCARDHANDLE card_handle, int *id_vendor, int *id_product)
{
	u8 rbuf[256];
	DWORD rcount = sizeof rbuf;
	struct pcsc_private_data *priv;
	int this_vendor = -1, this_product = -1;

	if (!reader)
		return SC_ERROR_INVALID_ARGUMENTS;
	priv = reader->drv_data;
	if (!priv)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (priv->get_tlv_properties && priv->gpriv) {
		if (SCARD_S_SUCCESS != priv->gpriv->SCardControl(card_handle,
					priv->get_tlv_properties, NULL, 0, rbuf, sizeof(rbuf),
					&rcount)) {
			sc_log(reader->ctx,
					"PC/SC v2 part 10: Get TLV properties failed!");
			return SC_ERROR_TRANSMIT_FAILED;
		}

		this_vendor = part10_find_property_by_tag(rbuf, rcount,
				PCSCv2_PART10_PROPERTY_wIdVendor);
		this_product = part10_find_property_by_tag(rbuf, rcount,
				PCSCv2_PART10_PROPERTY_wIdProduct);
	}

	sc_log(reader->ctx, "id_vendor=%04x id_product=%04x", this_vendor, this_product);

	if (id_vendor)
		*id_vendor = this_vendor;
	if (id_product)
		*id_product = this_product;

	return SC_SUCCESS;
}

static void detect_reader_features(sc_reader_t *reader, SCARDHANDLE card_handle) {
	sc_context_t *ctx = reader->ctx;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) ctx->reader_drv_data;
	struct pcsc_private_data *priv = reader->drv_data;
	u8 feature_buf[256], rbuf[SC_MAX_APDU_BUFFER_SIZE];
	DWORD rcount, feature_len, i;
	PCSC_TLV_STRUCTURE *pcsc_tlv;
	LONG rv;
	const char *log_disabled = "but it's disabled in configuration file";
	int id_vendor = 0, id_product = 0;

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx, "Requesting reader features ... ");

	if (gpriv->SCardControl == NULL)
		return;

	rv = gpriv->SCardControl(card_handle, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, feature_buf, sizeof(feature_buf), &feature_len);
	if (rv != (LONG)SCARD_S_SUCCESS) {
		PCSC_TRACE(reader, "SCardControl failed", rv);
		return;
	}

	if ((feature_len % sizeof(PCSC_TLV_STRUCTURE)) != 0) {
		sc_log(ctx, "Inconsistent TLV from reader!");
		return;
	}

	/* get the number of elements instead of the complete size */
	feature_len /= sizeof(PCSC_TLV_STRUCTURE);

	pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
	for (i = 0; i < feature_len; i++) {
		sc_log(ctx, "Reader feature %02x found", pcsc_tlv[i].tag);
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
			priv->pin_properties_ioctl = ntohl(pcsc_tlv[i].value);
		} else if (pcsc_tlv[i].tag == FEATURE_GET_TLV_PROPERTIES)  {
			priv->get_tlv_properties = ntohl(pcsc_tlv[i].value);
		} else if (pcsc_tlv[i].tag == FEATURE_EXECUTE_PACE) {
			priv->pace_ioctl = ntohl(pcsc_tlv[i].value);
		} else {
			sc_log(ctx, "Reader feature %02x is not supported", pcsc_tlv[i].tag);
		}
	}

	/* Set reader capabilities based on detected IOCTLs */
	if (priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish)) {
		const char *log_text = "Reader supports pinpad PIN verification";
		if (priv->gpriv->enable_pinpad) {
			sc_log(ctx, "%s", log_text);
			reader->capabilities |= SC_READER_CAP_PIN_PAD;
		} else {
			sc_log(ctx, "%s %s", log_text, log_disabled);
		}
	}

	if (priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish)) {
		const char *log_text = "Reader supports pinpad PIN modification";
		if (priv->gpriv->enable_pinpad) {
			sc_log(ctx, "%s", log_text);
			reader->capabilities |= SC_READER_CAP_PIN_PAD;
		} else {
			sc_log(ctx, "%s %s", log_text, log_disabled);
		}
	}

	/* Some readers claim to have PinPAD support even if they have not */
	if ((reader->capabilities & SC_READER_CAP_PIN_PAD) &&
		part10_get_vendor_product(reader, card_handle, &id_vendor, &id_product) == SC_SUCCESS) {
		/* HID Global OMNIKEY 3x21/6121 Smart Card Reader, fixed in libccid 1.4.29 (remove when last supported OS is using 1.4.29) */
		if ((id_vendor == 0x076B && id_product == 0x3031) ||
			(id_vendor == 0x076B && id_product == 0x6632)) {
			sc_log(ctx, "%s is not pinpad reader, ignoring", reader->name);
			reader->capabilities &= ~SC_READER_CAP_PIN_PAD;
		}
	}

	/* Detect display */
	if (priv->pin_properties_ioctl) {
		rcount = sizeof(rbuf);
		rv = gpriv->SCardControl(card_handle, priv->pin_properties_ioctl, NULL, 0, rbuf, sizeof(rbuf), &rcount);
		if (rv == SCARD_S_SUCCESS) {
#ifdef PIN_PROPERTIES_v5
			if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE_v5)) {
				PIN_PROPERTIES_STRUCTURE_v5 *caps = (PIN_PROPERTIES_STRUCTURE_v5 *)rbuf;
				if (caps->wLcdLayout > 0) {
					sc_log(ctx, "Reader has a display: %04X", caps->wLcdLayout);
					reader->capabilities |= SC_READER_CAP_DISPLAY;
				} else
					sc_log(ctx, "Reader does not have a display.");
			}
#endif
			if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE)) {
				PIN_PROPERTIES_STRUCTURE *caps = (PIN_PROPERTIES_STRUCTURE *)rbuf;
				if (caps->wLcdLayout > 0) {
					sc_log(ctx, "Reader has a display: %04X", caps->wLcdLayout);
					reader->capabilities |= SC_READER_CAP_DISPLAY;
				}
				else   {
					sc_log(ctx, "Reader does not have a display.");
				}
			}
			else   {
				sc_log(ctx,
						"Returned PIN properties structure has bad length (%lu/%"SC_FORMAT_LEN_SIZE_T"u)",
						(unsigned long)rcount,
						sizeof(PIN_PROPERTIES_STRUCTURE));
			}
		}
	}

	if (priv->pace_ioctl) {
		const char *log_text = "Reader supports PACE";
		if (priv->gpriv->enable_pace) {
			reader->capabilities |= part10_detect_pace_capabilities(reader, card_handle);

			if (reader->capabilities & SC_READER_CAP_PACE_GENERIC)
				sc_log(ctx, "%s", log_text);
		}
		else {
			sc_log(ctx, "%s %s", log_text, log_disabled);
		}
	}

	if (priv->get_tlv_properties) {
		/* Try to set reader max_send_size and max_recv_size based on
		 * detected max_data */
		int max_data = part10_detect_max_data(reader, card_handle);

		if (max_data > 0) {
			sc_log(ctx, "Reader supports transceiving %d bytes of data",
					max_data);
			if (!priv->gpriv->force_max_send_size)
				reader->max_send_size = max_data;
			else
				sc_log(ctx, "Sending is limited to %"SC_FORMAT_LEN_SIZE_T"u bytes of data"
						" in configuration file", reader->max_send_size);
			if (!priv->gpriv->force_max_recv_size)
				reader->max_recv_size = max_data;
			else
				sc_log(ctx, "Receiving is limited to %"SC_FORMAT_LEN_SIZE_T"u bytes of data"
						" in configuration file", reader->max_recv_size);
		} else {
			sc_log(ctx, "Assuming that the reader supports transceiving "
					"short length APDUs only");
		}

		/* debug the product and vendor ID of the reader */
		part10_get_vendor_product(reader, card_handle, NULL, NULL);
	}

	if(gpriv->SCardGetAttrib != NULL) {
		rcount = sizeof(rbuf);
		if (gpriv->SCardGetAttrib(card_handle, SCARD_ATTR_VENDOR_NAME,
					rbuf, &rcount) == SCARD_S_SUCCESS
				&& rcount > 0) {
			/* add NUL termination, just in case... */
			rbuf[(sizeof rbuf)-1] = '\0';
			reader->vendor = strdup((char *) rbuf);
		}

		rcount = sizeof i;
		if(gpriv->SCardGetAttrib(card_handle, SCARD_ATTR_VENDOR_IFD_VERSION,
					(u8 *) &i, &rcount) == SCARD_S_SUCCESS
				&& rcount == sizeof i) {
			reader->version_major = (i >> 24) & 0xFF;
			reader->version_minor = (i >> 16) & 0xFF;
		}
	}
}

int pcsc_add_reader(sc_context_t *ctx,
	   	char *reader_name, size_t reader_name_len,
		sc_reader_t **out_reader)
{
	int ret = SC_ERROR_INTERNAL;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) ctx->reader_drv_data;
	struct pcsc_private_data *priv;
	sc_reader_t *reader;

	sc_log(ctx, "Adding new PC/SC reader '%s'", reader_name);

	if ((reader = calloc(1, sizeof(sc_reader_t))) == NULL) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto err1;
	}
	*out_reader = reader;
	if ((priv = calloc(1, sizeof(struct pcsc_private_data))) == NULL) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto err1;
	}

	priv->gpriv = gpriv;

	reader->drv_data = priv;
	reader->ops = &pcsc_ops;
	reader->driver = &pcsc_drv;
	if ((reader->name = strdup(reader_name)) == NULL) {
		ret = SC_ERROR_OUT_OF_MEMORY;
		goto err1;
	}

	/* max send/receive sizes: with default values only short APDU supported */
	reader->max_send_size = priv->gpriv->force_max_send_size ?
		priv->gpriv->force_max_send_size :
		SC_READER_SHORT_APDU_MAX_SEND_SIZE;
	reader->max_recv_size = priv->gpriv->force_max_recv_size ?
		priv->gpriv->force_max_recv_size :
		SC_READER_SHORT_APDU_MAX_RECV_SIZE;

	ret = _sc_add_reader(ctx, reader);

	if (ret == SC_SUCCESS) {
		refresh_attributes(reader);
	}

err1:
	return ret;
}

static int pcsc_detect_readers(sc_context_t *ctx)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) ctx->reader_drv_data;
	DWORD active_proto, reader_buf_size = 0;
	SCARDHANDLE card_handle;
	LONG rv;
	char *reader_buf = NULL, *reader_name;
	const char *mszGroups = NULL;
	int ret = SC_ERROR_INTERNAL;
	size_t i;

	LOG_FUNC_CALLED(ctx);

	if (!gpriv) {
		/* FIXME: this is not the correct error */
		ret = SC_ERROR_NO_READERS_FOUND;
		goto out;
	}

	if (gpriv->cardmod) {
		ret = SC_ERROR_NOT_ALLOWED;
		goto out;
	}

	sc_log(ctx, "Probing PC/SC readers");

	do {
		if (gpriv->pcsc_ctx == (SCARDCONTEXT)-1) {
			/*
			 * Cannot call SCardListReaders with -1
			 * context as in Windows ERROR_INVALID_HANDLE
			 * is returned instead of SCARD_E_INVALID_HANDLE
			 */
			rv = SCARD_E_INVALID_HANDLE;
		} else {
			rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, NULL,
					NULL, (LPDWORD) &reader_buf_size);

			/*
			 * All readers have disappeared, so mark them as
			 * such so we don't keep polling them over and over.
			 */
			if (
#ifdef SCARD_E_NO_READERS_AVAILABLE
				(rv == (LONG)SCARD_E_NO_READERS_AVAILABLE) ||
#endif
				(rv == (LONG)SCARD_E_NO_SERVICE) || (rv == (LONG)SCARD_E_SERVICE_STOPPED)) {

				for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
					sc_reader_t *reader = sc_ctx_get_reader(ctx, i);

					if (!reader) {
						ret = SC_ERROR_INTERNAL;
						goto out;
					}

					reader->flags |= SC_READER_REMOVED;
				}
			}

			if ((rv == (LONG)SCARD_E_NO_SERVICE) || (rv == (LONG)SCARD_E_SERVICE_STOPPED)) {
				gpriv->SCardReleaseContext(gpriv->pcsc_ctx);
				gpriv->pcsc_ctx = 0;
				gpriv->pcsc_wait_ctx = -1;
				/* reconnecting below may may restart PC/SC service */
				rv = SCARD_E_INVALID_HANDLE;
			}
		}
		if (rv != SCARD_S_SUCCESS) {
			if (rv != (LONG)SCARD_E_INVALID_HANDLE) {
				PCSC_LOG(ctx, "SCardListReaders failed", rv);
				ret = pcsc_to_opensc_error(rv);
				goto out;
			}

			sc_log(ctx, "Establish PC/SC context");

			rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_ctx);
			if (rv != SCARD_S_SUCCESS) {
				PCSC_LOG(ctx, "SCardEstablishContext failed", rv);
				ret = pcsc_to_opensc_error(rv);
				goto out;
			}

			/* try to fetch the list of readers again */
			rv = SCARD_E_INVALID_HANDLE;
		}
	} while (rv != SCARD_S_SUCCESS);

	reader_buf = malloc(sizeof(char) * reader_buf_size);
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

	/* check if existing readers were returned in the list */
	for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
		sc_reader_t *reader = sc_ctx_get_reader(ctx, i);

		if (!reader) {
			ret = SC_ERROR_INTERNAL;
			goto out;
		}

		for (reader_name = reader_buf; *reader_name != '\x0';
				reader_name += strlen(reader_name) + 1) {
			if (!strcmp(reader->name, reader_name))
				break;
		}

		if (*reader_name != '\x0') {
			/* existing reader found; remove it from the list */
			char *next_reader_name = reader_name + strlen(reader_name) + 1;

			memmove(reader_name, next_reader_name,
					(reader_buf + reader_buf_size) - next_reader_name);
			reader_buf_size -= (next_reader_name - reader_name);
		} else {
			/* existing reader not found */
			reader->flags |= SC_READER_REMOVED;
		}
	}

	/* add readers remaining in the list */
	for (reader_name = reader_buf; *reader_name != '\x0';
		   	reader_name += strlen(reader_name) + 1) {
		sc_reader_t *reader = NULL;
		struct pcsc_private_data *priv = NULL;

		ret = pcsc_add_reader(ctx, reader_name, strlen(reader_name), &reader);
		if (ret != SC_SUCCESS) {
			_sc_delete_reader(ctx, reader);
			continue;
		}

		/* check for pinpad support early, to allow opensc-tool -l display accurate information */
		priv = reader->drv_data;
		if (priv->reader_state.dwEventState & SCARD_STATE_EXCLUSIVE)
			continue;

		rv = SCARD_E_SHARING_VIOLATION;
		/* Use DIRECT mode only if there is no card in the reader */
		if (!(reader->flags & SC_READER_CARD_PRESENT)) {
#ifndef _WIN32	/* Apple 10.5.7 and pcsc-lite previous to v1.5.5 do not support 0 as protocol identifier */
			rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card_handle, &active_proto);
#else
			rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, 0, &card_handle, &active_proto);
#endif
			PCSC_TRACE(reader, "SCardConnect(DIRECT)", rv);
		}
		if (rv == (LONG)SCARD_E_SHARING_VIOLATION) {
			/* Assume that there is a card in the reader in shared mode if
			 * direct communication failed */
			rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name,
					SCARD_SHARE_SHARED,
					SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card_handle,
					&active_proto);
			PCSC_TRACE(reader, "SCardConnect(SHARED)", rv);
			reader->active_protocol = pcsc_proto_to_opensc(active_proto);
		}

		if (rv == SCARD_S_SUCCESS) {
			detect_reader_features(reader, card_handle);
			gpriv->SCardDisconnect(card_handle, SCARD_LEAVE_CARD);
		}
	}

	ret = SC_SUCCESS;

out:
	free(reader_buf);

	LOG_FUNC_RETURN(ctx, ret);
}


/* Wait for an event to occur.
 */
static int pcsc_wait_for_event(sc_context_t *ctx, unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event,
		int timeout, void **reader_states)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)ctx->reader_drv_data;
	LONG rv;
	SCARD_READERSTATE *rgReaderStates;
	size_t i;
	unsigned int num_watch;
	int r = SC_ERROR_INTERNAL;
	DWORD dwtimeout;

	LOG_FUNC_CALLED(ctx);

	if (!event_reader && !event && reader_states)   {
		sc_log(ctx, "free allocated reader states");
		free(*reader_states);
		*reader_states = NULL;
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	if (reader_states == NULL || *reader_states == NULL) {
		rgReaderStates = calloc(sc_ctx_get_reader_count(ctx) + 2, sizeof(SCARD_READERSTATE));
		if (!rgReaderStates)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

		/* Find out the current status */
		num_watch = sc_ctx_get_reader_count(ctx);
		sc_log(ctx, "Trying to watch %d readers", num_watch);
		for (i = 0; i < num_watch; i++) {
			rgReaderStates[i].szReader = sc_ctx_get_reader(ctx, i)->name;
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
			rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
		}
#ifndef __APPLE__
	   	/* OS X 10.6.2 - 10.12.6 do not support PnP notification */
		if (event_mask & SC_EVENT_READER_ATTACHED) {
			rgReaderStates[i].szReader = "\\\\?PnP?\\Notification";
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
			rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
			num_watch++;
		}
#endif
	}
	else {
		rgReaderStates = (SCARD_READERSTATE *)(*reader_states);
		for (num_watch = 0; rgReaderStates[num_watch].szReader; num_watch++)
			sc_log(ctx, "re-use reader '%s'", rgReaderStates[num_watch].szReader);
	}
#ifndef _WIN32
	/* Establish a new context, assuming that it is called from a different thread with pcsc-lite */
	if (gpriv->pcsc_wait_ctx == (SCARDCONTEXT)-1) {
		rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_wait_ctx);
		if (rv != SCARD_S_SUCCESS) {
			PCSC_LOG(ctx, "SCardEstablishContext(wait) failed", rv);
			r = pcsc_to_opensc_error(rv);
			goto out;
		}
	}
#else
	gpriv->pcsc_wait_ctx = gpriv->pcsc_ctx;
#endif
	if (!event_reader || !event)
	{
		r = SC_ERROR_INTERNAL;
		goto out;
	}

#ifdef __APPLE__
	if (num_watch == 0) {
		sc_log(ctx, "No readers available, PnP notification not supported");
		*event_reader = NULL;
		r = SC_ERROR_NO_READERS_FOUND;
		goto out;
	}
#endif

	rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, 0, rgReaderStates, num_watch);
	if (rv != SCARD_S_SUCCESS) {
		if (rv != (LONG)SCARD_E_TIMEOUT) {
			PCSC_LOG(ctx, "SCardGetStatusChange(1) failed", rv);
			r = pcsc_to_opensc_error(rv);
			goto out;
		}
	}

	/* Wait for a status change
	 */
	for( ; ; ) {
		SCARD_READERSTATE *rsp;
		sc_log(ctx, "Looping...");

		/* Scan the current state of all readers to see if they
		 * match any of the events we're polling for */
		*event = 0;
		for (i = 0, rsp = rgReaderStates; i < num_watch; i++, rsp++) {
			DWORD state, prev_state;
			sc_log(ctx, "'%s' before=0x%08X now=0x%08X",
					rsp->szReader,
					(unsigned int)rsp->dwCurrentState,
					(unsigned int)rsp->dwEventState);
			prev_state = rsp->dwCurrentState;
			state = rsp->dwEventState;
			rsp->dwCurrentState = rsp->dwEventState;
			if (state & SCARD_STATE_CHANGED) {

				/* check for hotplug events  */
				if (!strcmp(rgReaderStates[i].szReader, "\\\\?PnP?\\Notification")) {
					sc_log(ctx, "detected hotplug event");
					*event |= SC_EVENT_READER_ATTACHED;
					*event_reader = NULL;
				}

				if ((state & SCARD_STATE_PRESENT) && !(prev_state & SCARD_STATE_PRESENT)) {
					sc_log(ctx, "card inserted event");
					*event |= SC_EVENT_CARD_INSERTED;
				}

				if ((prev_state & SCARD_STATE_PRESENT) && !(state & SCARD_STATE_PRESENT)) {
					sc_log(ctx, "card removed event");
					*event |= SC_EVENT_CARD_REMOVED;
				}

				if ((state & SCARD_STATE_UNKNOWN) && !(prev_state & SCARD_STATE_UNKNOWN)) {
					sc_log(ctx, "reader detached event");
					*event |= SC_EVENT_READER_DETACHED;
				}

				if ((prev_state & SCARD_STATE_UNKNOWN) && !(state & SCARD_STATE_UNKNOWN)) {
					sc_log(ctx, "reader re-attached event");
					*event |= SC_EVENT_READER_ATTACHED;
				}

				if (*event & event_mask) {
					sc_log(ctx, "Matching event 0x%02X in reader %s", *event, rsp->szReader);
					*event_reader = sc_ctx_get_reader_by_name(ctx, rsp->szReader);
					r = SC_SUCCESS;
					goto out;
				}

			}

			/* No match - copy the state so pcscd knows
			 * what to watch out for */
			/* rsp->dwCurrentState = rsp->dwEventState; */
		}

		if (timeout == 0) {
			r = SC_ERROR_EVENT_TIMEOUT;
			goto out;
		}

		/* Set the timeout if caller wants to time out */
		if (timeout == -1) {
			dwtimeout = INFINITE;
		}
		else
			dwtimeout = timeout;

		rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, dwtimeout, rgReaderStates, num_watch);

		if (rv == (LONG) SCARD_E_CANCELLED) {
			/* C_Finalize was called, events don't matter */
			r = SC_ERROR_EVENT_TIMEOUT;
			goto out;
		}

		if (rv == (LONG) SCARD_E_TIMEOUT) {
			r = SC_ERROR_EVENT_TIMEOUT;
			goto out;
		}

		if (rv != SCARD_S_SUCCESS) {
			PCSC_LOG(ctx, "SCardGetStatusChange(2) failed", rv);
			r = pcsc_to_opensc_error(rv);
			goto out;
		}
	}
out:
	if (!reader_states)   {
		free(rgReaderStates);
	}
	else if (*reader_states == NULL)   {
		sc_log(ctx, "return allocated 'reader states'");
		*reader_states = rgReaderStates;
	}

	LOG_FUNC_RETURN(ctx, r);
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
	LOG_TEST_RET(reader->ctx,
			sc_apdu2bytes(reader->ctx, apdu,
				reader->active_protocol, pin_verify->abData,
				SC_MAX_APDU_BUFFER_SIZE),
			"Could not encode PIN APDU");
	offset += sc_apdu_get_length(apdu, reader->active_protocol);

	pin_verify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */

	count = sizeof(PIN_VERIFY_STRUCTURE) + offset;
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
	struct sc_pin_cmd_pin *pin_ref =
		data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ?
		&data->pin2 : &data->pin1;

	/* PIN verification control message */
	pin_modify->bTimerOut = SC_CCID_PIN_TIMEOUT;	/* bTimeOut */
	pin_modify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;	/* bTimeOut2 */

	/* bmFormatString */
	tmp = 0x00;
	if (pin_ref->encoding == SC_PIN_ENCODING_ASCII) {
		tmp |= SC_CCID_PIN_ENCODING_ASCII;

		/* if the effective PIN length offset is specified, use it */
		if (pin_ref->length_offset > 4) {
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (pin_ref->length_offset - 5) << 3;
		}
	} else if (pin_ref->encoding == SC_PIN_ENCODING_BCD) {
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} else if (pin_ref->encoding == SC_PIN_ENCODING_GLP) {
		/* see comment about GLP PINs in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x08 << 3;
	} else
		return SC_ERROR_NOT_SUPPORTED;

	pin_modify->bmFormatString = tmp;	/* bmFormatString */

	/* bmPINBlockString */
	tmp = 0x00;
	if (pin_ref->encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	} else if (pin_ref->encoding == SC_PIN_ENCODING_ASCII && pin_ref->pad_length) {
		tmp |= pin_ref->pad_length;
	}
	pin_modify->bmPINBlockString = tmp; /* bmPINBlockString */

	/* bmPINLengthFormat */
	tmp = 0x00;
	if (pin_ref->encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PINs expect the effective PIN length from bit 4 */
		tmp |= 0x04;
	}
	pin_modify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */

	/* Set offsets if not Case 1 APDU */
	if (pin_ref->length_offset != 4) {
		pin_modify->bInsertionOffsetOld = data->pin1.offset - 5;
		pin_modify->bInsertionOffsetNew = data->pin2.offset - 5;
	} else {
		pin_modify->bInsertionOffsetOld = 0x00;
		pin_modify->bInsertionOffsetNew = 0x00;
	}

	if (!pin_ref->min_length || !pin_ref->max_length)
		return SC_ERROR_INVALID_ARGUMENTS;

	tmp16 = (pin_ref->min_length << 8 ) + pin_ref->max_length;
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
	pin_modify->bMsgIndex1 = (data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x01: 0x00); /* Default message indexes */
	pin_modify->bMsgIndex2 = (data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x02: 0x01);
	pin_modify->bMsgIndex3 = 0x02;
	pin_modify->bTeoPrologue[0] = 0x00;
	pin_modify->bTeoPrologue[1] = 0x00;
	pin_modify->bTeoPrologue[2] = 0x00;

	/* APDU itself */
	LOG_TEST_RET(reader->ctx,
			sc_apdu2bytes(reader->ctx, apdu,
				reader->active_protocol, pin_modify->abData,
				SC_MAX_APDU_BUFFER_SIZE),
			"Could not encode PIN APDU");
	offset += sc_apdu_get_length(apdu, reader->active_protocol);

	pin_modify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */

	count = sizeof(PIN_MODIFY_STRUCTURE) + offset;
	*size = count;
	return SC_SUCCESS;
}

/* Find a given PCSC v2 part 10 property */
static int
part10_find_property_by_tag(unsigned char buffer[], int length,
	int tag_searched)
{
	unsigned char *p;
	int found = 0, len, value = -1;

	p = buffer;
	while (p-buffer < length)
	{
		if (*p++ == tag_searched)
		{
			found = 1;
			break;
		}

		/* go to next tag */
		len = *p++;
		p += len;
	}

	if (found)
	{
		len = *p++;

		switch(len)
		{
			case 1:
				value = *p;
				break;
			case 2:
				value = *p + (*(p+1)<<8);
				break;
			case 4:
				value = *p + (*(p+1)<<8) + (*(p+2)<<16) + (*(p+3)<<24);
				break;
			default:
				value = -1;
		}
	}

	return value;
} /* part10_find_property_by_tag */

/* Make sure the pin min and max are supported by the reader
 * and fix the values if needed */
static int
part10_check_pin_min_max(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	int r;
	unsigned char buffer[256];
	size_t length = sizeof buffer;
	struct pcsc_private_data *priv = reader->drv_data;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) reader->ctx->reader_drv_data;
	struct sc_pin_cmd_pin *pin_ref =
		data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ?
		&data->pin1 : &data->pin2;

	if (gpriv->fixed_pinlength != 0) {
		pin_ref->min_length = gpriv->fixed_pinlength;
		pin_ref->max_length = gpriv->fixed_pinlength;
		return 0;
	}

	if (!priv->get_tlv_properties)
		return 0;

	r = pcsc_internal_transmit(reader, NULL, 0, buffer, &length,
		priv->get_tlv_properties);
	LOG_TEST_RET(reader->ctx, r,
		"PC/SC v2 part 10: Get TLV properties failed!");

	/* minimum pin size */
	r = part10_find_property_by_tag(buffer, length,
		PCSCv2_PART10_PROPERTY_bMinPINSize);
	if (r >= 0)
	{
		unsigned int value = r;

		if (pin_ref->min_length < value)
			pin_ref->min_length = r;
	}

	/* maximum pin size */
	r = part10_find_property_by_tag(buffer, length,
		PCSCv2_PART10_PROPERTY_bMaxPINSize);
	if (r >= 0)
	{
		unsigned int value = r;

		if (pin_ref->max_length > value)
			pin_ref->max_length = r;
	}

	return 0;
}

/* Do the PIN command */
static int
pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	struct pcsc_private_data *priv = reader->drv_data;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	/* sbuf holds a pin verification/modification structure plus an APDU. */
	u8 sbuf[sizeof(PIN_VERIFY_STRUCTURE)>sizeof(PIN_MODIFY_STRUCTURE)?
		sizeof(PIN_VERIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE:
		sizeof(PIN_MODIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE];
	size_t rcount = sizeof(rbuf), scount = 0;
	int r;
	DWORD ioctl = 0;
	sc_apdu_t *apdu;

	LOG_FUNC_CALLED(reader->ctx);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

	if (priv->gpriv->SCardControl == NULL)
		return SC_ERROR_NOT_SUPPORTED;

	/* The APDU must be provided by the card driver */
	if (!data->apdu) {
		sc_log(reader->ctx, "No APDU provided for PC/SC v2 pinpad verification!");
		return SC_ERROR_NOT_SUPPORTED;
	}

	apdu = data->apdu;
	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		if (!(priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish))) {
			sc_log(reader->ctx, "Pinpad reader does not support verification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		part10_check_pin_min_max(reader, data);
		r = part10_build_verify_pin_block(reader, sbuf, &scount, data);
		ioctl = priv->verify_ioctl ? priv->verify_ioctl : priv->verify_ioctl_start;
		break;
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		if (!(priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish))) {
			sc_log(reader->ctx, "Pinpad reader does not support modification!");
			return SC_ERROR_NOT_SUPPORTED;
		}
		part10_check_pin_min_max(reader, data);
		r = part10_build_modify_pin_block(reader, sbuf, &scount, data);
		ioctl = priv->modify_ioctl ? priv->modify_ioctl : priv->modify_ioctl_start;
		break;
	default:
		sc_log(reader->ctx, "Unknown PIN command %d", data->cmd);
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* If PIN block building failed, we fail too */
	LOG_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad block building failed!");
	/* If not, debug it, just for fun */
	sc_log_hex(reader->ctx, "PC/SC v2 pinpad block", sbuf, scount);

	r = pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount, ioctl);

	LOG_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad: block transmit failed!");
	/* finish the call if it was a two-phase operation */
	if ((ioctl == priv->verify_ioctl_start)
			|| (ioctl == priv->modify_ioctl_start)) {
		if (rcount != 0) {
			LOG_FUNC_RETURN(reader->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
		}
		ioctl = (ioctl == priv->verify_ioctl_start) ? priv->verify_ioctl_finish : priv->modify_ioctl_finish;

		rcount = sizeof(rbuf);
		r = pcsc_internal_transmit(reader, sbuf, 0, rbuf, &rcount, ioctl);
		LOG_TEST_RET(reader->ctx, r, "PC/SC v2 pinpad: finish operation failed!");
	}

	/* We expect only two bytes of result data (SW1 and SW2) */
	if (rcount != 2) {
		LOG_FUNC_RETURN(reader->ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
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
	case 0x6403: /* Entered PIN is not in length limits */
		r = SC_ERROR_INVALID_PIN_LENGTH; /* XXX: designed to be returned when PIN is in API call */
		break;
	case 0x6B80: /* Wrong data in the buffer, rejected by firmware */
		r = SC_ERROR_READER;
		break;
	}

	LOG_TEST_RET(reader->ctx, r, "PIN command failed");

	/* PIN command completed, all is good */
	return SC_SUCCESS;
}

static int transform_pace_input(struct establish_pace_channel_input *pace_input,
		u8 *sbuf, size_t *scount)
{
	u8 *p = sbuf;
	uint16_t lengthInputData, lengthCertificateDescription;
	uint8_t lengthCHAT, lengthPIN;

	if (!pace_input || !sbuf || !scount)
		return SC_ERROR_INVALID_ARGUMENTS;

	lengthInputData = 5 + pace_input->pin_length + pace_input->chat_length
		+ pace_input->certificate_description_length;

	if ((unsigned)(lengthInputData + 3) > *scount)
		return SC_ERROR_OUT_OF_MEMORY;

	/* idxFunction */
	*(p++) = PACE_FUNCTION_EstablishPACEChannel;

	/* lengthInputData */
	memcpy(p, &lengthInputData, sizeof lengthInputData);
	p += sizeof lengthInputData;

	*(p++) = pace_input->pin_id;

	/* length CHAT */
	lengthCHAT = pace_input->chat_length;
	*(p++) = lengthCHAT;
	/* CHAT */
	memcpy(p, pace_input->chat, lengthCHAT);
	p += lengthCHAT;

	/* length PIN */
	lengthPIN = pace_input->pin_length;
	*(p++) = lengthPIN;

	/* PIN */
	memcpy(p, pace_input->pin, lengthPIN);
	p += lengthPIN;

	/* lengthCertificateDescription */
	lengthCertificateDescription = pace_input->certificate_description_length;
	memcpy(p, &lengthCertificateDescription,
			sizeof lengthCertificateDescription);
	p += sizeof lengthCertificateDescription;

	/* certificate description */
	memcpy(p, pace_input->certificate_description,
			lengthCertificateDescription);

	*scount = lengthInputData + 3;

	return SC_SUCCESS;
}

static int transform_pace_output(u8 *rbuf, size_t rbuflen,
		struct establish_pace_channel_output *pace_output)
{
	size_t parsed = 0;

	uint8_t ui8;
	uint16_t ui16;

	if (!rbuf || !pace_output)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* Result */
	if (parsed+4 > rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	memcpy(&pace_output->result, &rbuf[parsed], 4);
	parsed += 4;

	/* length_OutputData */
	if (parsed+2 > rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	memcpy(&ui16, &rbuf[parsed], 2);
	if ((size_t)ui16+6 != rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	parsed += 2;

	/* MSE:Set AT Statusbytes */
	if (parsed+2 > rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	pace_output->mse_set_at_sw1 = rbuf[parsed+0];
	pace_output->mse_set_at_sw2 = rbuf[parsed+1];
	parsed += 2;

	/* length_CardAccess */
	if (parsed+2 > rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	memcpy(&ui16, &rbuf[parsed], 2);
	/* do not just yet copy ui16 to pace_output->ef_cardaccess_length */
	parsed += 2;

	/* EF_CardAccess */
	if (parsed+ui16 > rbuflen)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	if (pace_output->ef_cardaccess) {
		/* caller wants EF.CardAccess */
		if (pace_output->ef_cardaccess_length < ui16)
			return SC_ERROR_OUT_OF_MEMORY;

		/* now save ui16 to pace_output->ef_cardaccess_length */
		pace_output->ef_cardaccess_length = ui16;
		memcpy(pace_output->ef_cardaccess, &rbuf[parsed], ui16);
	} else {
		/* caller does not want EF.CardAccess */
		pace_output->ef_cardaccess_length = 0;
	}
	parsed += ui16;

	if (parsed < rbuflen) {
		/* The following elements are only present if the execution of PACE is
		 * to be followed by an execution of Terminal Authentication Version 2
		 * as defined in [TR-03110]. These data are needed to perform the
		 * Terminal Authentication. */

		/* length_CARcurr */
		ui8 = rbuf[parsed];
		/* do not just yet copy ui8 to pace_output->recent_car_length */
		parsed += 1;

		/* CARcurr */
		if (parsed+ui8 > rbuflen)
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		if (pace_output->recent_car) {
			/* caller wants most recent certificate authority reference */
			if (pace_output->recent_car_length < ui8)
				return SC_ERROR_OUT_OF_MEMORY;
			/* now save ui8 to pace_output->recent_car_length */
			pace_output->recent_car_length = ui8;
			memcpy(pace_output->recent_car, &rbuf[parsed], ui8);
		} else {
			/* caller does not want most recent certificate authority reference */
			pace_output->recent_car_length = 0;
		}
		parsed += ui8;

		/* length_CARprev */
		ui8 = rbuf[parsed];
		/* do not just yet copy ui8 to pace_output->previous_car_length */
		parsed += 1;

		/* length_CCARprev */
		if (parsed+ui8 > rbuflen)
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		if (pace_output->previous_car) {
			/* caller wants previous certificate authority reference */
			if (pace_output->previous_car_length < ui8)
				return SC_ERROR_OUT_OF_MEMORY;
			/* now save ui8 to pace_output->previous_car_length */
			pace_output->previous_car_length = ui8;
			memcpy(pace_output->previous_car, &rbuf[parsed], ui8);
		} else {
			/* caller does not want previous certificate authority reference */
			pace_output->previous_car_length = 0;
		}
		parsed += ui8;

		/* length_IDicc */
		if (parsed+2 > rbuflen)
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		memcpy(&ui16, &rbuf[parsed], 2);
		/* do not just yet copy ui16 to pace_output->id_icc_length */
		parsed += 2;

		/* IDicc */
		if (parsed+ui16 > rbuflen)
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
		if (pace_output->id_icc) {
			/* caller wants Ephemeral PACE public key of the IFD */
			if (pace_output->id_icc_length < ui16)
				return SC_ERROR_OUT_OF_MEMORY;

			/* now save ui16 to pace_output->id_icc_length */
			pace_output->id_icc_length = ui16;
			memcpy(pace_output->id_icc, &rbuf[parsed], ui16);
		} else {
			/* caller does not want Ephemeral PACE public key of the IFD */
			pace_output->id_icc_length = 0;
		}
		parsed += ui16;

		if (parsed < rbuflen)
			return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	} else {
		pace_output->recent_car_length = 0;
		pace_output->previous_car_length = 0;
		pace_output->id_icc_length = 0;
	}

	return SC_SUCCESS;
}


static int
pcsc_perform_pace(struct sc_reader *reader, void *input_pace, void *output_pace)
{
	struct establish_pace_channel_input *pace_input = (struct establish_pace_channel_input *) input_pace;
	struct establish_pace_channel_output *pace_output = (struct establish_pace_channel_output *) output_pace;
	struct pcsc_private_data *priv;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE], sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE];
	size_t rcount = sizeof rbuf, scount = sizeof sbuf;

	if (!reader || !(reader->capabilities & SC_READER_CAP_PACE_GENERIC))
		return SC_ERROR_INVALID_ARGUMENTS;

	priv = reader->drv_data;
	if (!priv)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_TEST_RET(reader->ctx,
			transform_pace_input(pace_input, sbuf, &scount),
			"Creating EstabishPACEChannel input data");

	LOG_TEST_RET(reader->ctx,
			pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount,
				priv->pace_ioctl),
			"Executing EstabishPACEChannel");

	LOG_TEST_RET(reader->ctx,
			transform_pace_output(rbuf, rcount, pace_output),
			"Parsing EstabishPACEChannel output data");

	return SC_SUCCESS;
}

static void detect_protocol(sc_reader_t *reader, SCARDHANDLE card_handle)
{
	DWORD readers_len = 0, state, prot, atr_len = SC_MAX_ATR_SIZE;
	unsigned char atr[SC_MAX_ATR_SIZE];
	struct pcsc_private_data *priv = reader->drv_data;
	/* attempt to detect protocol in use T0/T1/RAW */
	DWORD rv = priv->gpriv->SCardStatus(card_handle, NULL,
			&readers_len, &state, &prot, atr, &atr_len);
	if (rv != SCARD_S_SUCCESS) {
		prot = SCARD_PROTOCOL_T0;
	}
	reader->active_protocol = pcsc_proto_to_opensc(prot);
}

int pcsc_use_reader(sc_context_t *ctx, void * pcsc_context_handle, void * pcsc_card_handle)
{
	SCARDHANDLE card_handle;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) ctx->reader_drv_data;
	char reader_name[128];
	DWORD reader_name_size = sizeof(reader_name);
	int ret = SC_ERROR_INTERNAL;

	LOG_FUNC_CALLED(ctx);

	if (!gpriv) {
		ret = SC_ERROR_NO_READERS_FOUND;
		goto out;
	}

	if (!gpriv->cardmod) {
		ret = SC_ERROR_INTERNAL;
		goto out;
	}

	/* Only minidriver calls this and only uses one reader */
	/* if we already have a reader, update it */
	if (sc_ctx_get_reader_count(ctx) > 0) {
		sc_log(ctx, "Reusing the reader");
		sc_reader_t *reader = list_get_at(&ctx->readers, 0);

		if (reader) {
			struct pcsc_private_data *priv = reader->drv_data;
			priv->pcsc_card =*(SCARDHANDLE *)pcsc_card_handle;
			gpriv->pcsc_ctx = *(SCARDCONTEXT *)pcsc_context_handle;
			ret = SC_SUCCESS;
			goto out;
		} else {
			ret = SC_ERROR_INTERNAL;
			goto out;
		}
	}

	sc_log(ctx, "Probing PC/SC reader");

	gpriv->pcsc_ctx = *(SCARDCONTEXT *)pcsc_context_handle;
	card_handle =  *(SCARDHANDLE *)pcsc_card_handle;

	if(SCARD_S_SUCCESS == gpriv->SCardGetAttrib(card_handle,
				SCARD_ATTR_DEVICE_SYSTEM_NAME_A, (LPBYTE)
				reader_name, &reader_name_size)) {
		sc_reader_t *reader = NULL;

		ret = pcsc_add_reader(ctx, reader_name, reader_name_size, &reader);
		if (ret == SC_SUCCESS) {
			struct pcsc_private_data *priv = reader->drv_data;
			priv->pcsc_card = card_handle;
			detect_protocol(reader, card_handle);
			detect_reader_features(reader, card_handle);
		} else {
			_sc_delete_reader(ctx, reader);
		}
	}

out:
	LOG_FUNC_RETURN(ctx, ret);
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
	pcsc_ops.use_reader = pcsc_use_reader;
	pcsc_ops.perform_pace = pcsc_perform_pace;

	return &pcsc_drv;
}

#endif   /* ENABLE_PCSC */
