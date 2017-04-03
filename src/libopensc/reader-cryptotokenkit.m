/*
 * reader-cryptotokenkit.m: Reader driver for CryptoTokenKit interface
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
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

#ifdef ENABLE_CRYPTOTOKENKIT /* empty file without cryptotokenkit */

#import <CryptoTokenKit/CryptoTokenKit.h>
#include "internal.h"
#include "log.h"
#include "opensc.h"

struct cryptotokenkit_private_data {
	TKSmartCardSlot* tksmartcardslot;
	TKSmartCard* tksmartcard;
};

static struct sc_reader_operations cryptotokenkit_ops;

static struct sc_reader_driver cryptotokenkit_reader_driver = {
	"CryptoTokenKit pseudo reader",
	"cryptotokenkit",
	&cryptotokenkit_ops,
	NULL
};

static int cryptotokenkit_init(sc_context_t *ctx)
{
	return SC_SUCCESS;
}

static int cryptotokenkit_release(sc_reader_t *reader)
{
	struct cryptotokenkit_private_data *priv = reader->drv_data;

	free(priv);
	return SC_SUCCESS;
}

static int cryptotokenkit_detect_card_presence(sc_reader_t *reader)
{
	struct cryptotokenkit_private_data *priv = reader->drv_data;
	int r = SC_SUCCESS;
	int old_flags = reader->flags;

	LOG_FUNC_CALLED(reader->ctx);

	reader->flags &= ~(SC_READER_CARD_INUSE);

	switch (priv->tksmartcardslot.state) {
	 	case TKSmartCardSlotStateMuteCard:
	  		// The card inserted in the slot does not answer.
	  		r = SC_ERROR_CARD_UNRESPONSIVE;
	  		// fall through */
	 	case TKSmartCardSlotStateProbing:
	  		// The card was inserted into the slot and an initial probe is in progress.
	  		reader->flags |= SC_READER_CARD_INUSE;
	  		// fall through */
	 	case TKSmartCardSlotStateValidCard:
	  		// Card properly answered to reset.
	  		reader->flags |= SC_READER_CARD_PRESENT;
	  		if ([priv->tksmartcardslot.ATR.bytes length] > SC_MAX_ATR_SIZE)
	   			return SC_ERROR_INTERNAL;
	  		reader->atr.len = [priv->tksmartcardslot.ATR.bytes length];
	  		memcpy(reader->atr.value, (unsigned char*) [priv->tksmartcardslot.ATR.bytes bytes], reader->atr.len);
	  		break;
	 	case TKSmartCardSlotStateMissing:
	  		// Slot is no longer known to the system.
	  		reader->flags &= ~(SC_READER_CARD_PRESENT);
	  		reader->flags |= SC_READER_REMOVED;
	  		r = SC_ERROR_READER_DETACHED;
	  		break;
	 	case TKSmartCardSlotStateEmpty:
	  		/// The slot is empty, no card is inserted.
	  		reader->flags &= ~SC_READER_CARD_PRESENT;
	  		break;
	 	default:
	  		r = SC_ERROR_UNKNOWN;
	  		break;
	}

	if ((old_flags & SC_READER_CARD_PRESENT) == (reader->flags & SC_READER_CARD_PRESENT))
	 	reader->flags &= ~SC_READER_CARD_CHANGED;
	else
	 	reader->flags |= SC_READER_CARD_CHANGED;

	sc_log(reader->ctx, "card %s%s",
			reader->flags & SC_READER_CARD_PRESENT ? "present" : "absent",
		   reader->flags & SC_READER_CARD_CHANGED ? ", changed": "");

	if (r == SC_SUCCESS)
	 	r = reader->flags;

	LOG_FUNC_RETURN(reader->ctx, r);
}

static int ctk_proto_to_opensc(TKSmartCardProtocol proto)
{
	switch (proto) {
	   	case TKSmartCardProtocolT0:
			return SC_PROTO_T0;
	   	case TKSmartCardProtocolT1:
			/* fall through */
	   	case TKSmartCardProtocolT15:
			return SC_PROTO_T1;
	   	case TKSmartCardProtocolAny:
			return SC_PROTO_ANY;
	   	default:
			return 0;
	}
}

static void ctk_set_proto(sc_reader_t *reader)
{
 	struct cryptotokenkit_private_data *priv = reader->drv_data;
 	if (priv->tksmartcard) {
  		reader->active_protocol = ctk_proto_to_opensc(priv->tksmartcard.currentProtocol);
  		if (priv->tksmartcard.allowedProtocols & TKSmartCardProtocolAny) {
   			reader->supported_protocols = ctk_proto_to_opensc(TKSmartCardProtocolAny);
  		} else {
   			if (priv->tksmartcard.allowedProtocols & TKSmartCardProtocolT0)
				reader->supported_protocols |= ctk_proto_to_opensc(TKSmartCardProtocolT0);
   			if (priv->tksmartcard.allowedProtocols & TKSmartCardProtocolT1)
				reader->supported_protocols |= ctk_proto_to_opensc(TKSmartCardProtocolT1);
   			if (priv->tksmartcard.allowedProtocols & TKSmartCardProtocolT15)
				reader->supported_protocols |= ctk_proto_to_opensc(TKSmartCardProtocolT1);
  		}
 	}
}

static int cryptotokenkit_connect(sc_reader_t *reader)
{
	struct cryptotokenkit_private_data *priv = reader->drv_data;

	if (!priv->tksmartcard) {
		priv->tksmartcard = [priv->tksmartcardslot makeSmartCard];
	}

	if (!priv->tksmartcard || ![priv->tksmartcard valid])
		return SC_ERROR_CARD_NOT_PRESENT;

	/* attempt to detect protocol in use T0/T1/RAW */
	ctk_set_proto(reader);

	return SC_SUCCESS;
}

static int cryptotokenkit_disconnect(sc_reader_t * reader)
{
	struct cryptotokenkit_private_data *priv = reader->drv_data;

	priv->tksmartcard = NULL;

	reader->flags = 0;
	return SC_SUCCESS;
}

static int cryptotokenkit_lock(sc_reader_t *reader)
{
	__block int r = SC_ERROR_NOT_ALLOWED;
	struct cryptotokenkit_private_data *priv = reader->drv_data;
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);

	LOG_FUNC_CALLED(reader->ctx);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		goto err;

	[priv->tksmartcard beginSessionWithReply:^(BOOL success, NSError *error) {
		if (success != TRUE) {
			NSLog(@"Error locking card <%@>", error);
			r = SC_ERROR_UNKNOWN;
		} else {
			r = SC_SUCCESS;
		}
		dispatch_semaphore_signal(sema);
	}];
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

err:
	LOG_FUNC_RETURN(reader->ctx, r);
}

static int cryptotokenkit_unlock(sc_reader_t *reader)
{
	struct cryptotokenkit_private_data *priv = reader->drv_data;

	LOG_FUNC_CALLED(reader->ctx);

	if (reader->ctx->flags & SC_CTX_FLAG_TERMINATE)
		return SC_ERROR_NOT_ALLOWED;

	[priv->tksmartcard endSession];

	LOG_FUNC_RETURN(reader->ctx, SC_SUCCESS);
}

static int cryptotokenkit_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	size_t ssize = 0;
	__block u8 *rbuf = NULL;
	__block int r;
	__block size_t rsize;
	u8 *sbuf = NULL;
	struct cryptotokenkit_private_data *priv = reader->drv_data;
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);

	LOG_FUNC_CALLED(reader->ctx);

	r = sc_apdu_get_octets(reader->ctx, apdu, &sbuf, &ssize, reader->active_protocol);
	if (r != SC_SUCCESS)
		goto err;

	if (reader->name)
		sc_log(reader->ctx, "reader '%s'", reader->name);
	sc_apdu_log(reader->ctx, SC_LOG_DEBUG_NORMAL, sbuf, ssize, 1);

	[priv->tksmartcard transmitRequest:
			[NSData dataWithBytes: sbuf length: ssize]
			reply:^(NSData *response, NSError *error) {
		if (response) {
			rsize = [response length];
			rbuf = malloc(rsize);
			if (!rbuf)
				r = SC_ERROR_OUT_OF_MEMORY;
			else
				memcpy(rbuf, (unsigned char*) [response bytes], rsize);
		}
		if (r == SC_SUCCESS) {
			if (error) {
				NSLog(@"Error transmitting to card <%@>", error);
				r = SC_ERROR_TRANSMIT_FAILED;
			} else {
				r = SC_SUCCESS;
			}
		}
		dispatch_semaphore_signal(sema);
	}];
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
	if (r != SC_SUCCESS)
		goto err;

	sc_apdu_log(reader->ctx, SC_LOG_DEBUG_NORMAL, rbuf, rsize, 0);
	r = sc_apdu_set_resp(reader->ctx, apdu, rbuf, rsize);

err:
	if (sbuf != NULL) {
		sc_mem_clear(sbuf, ssize);
		free(sbuf);
	}
	if (rbuf != NULL) {
		sc_mem_clear(rbuf, rsize);
		free(rbuf);
	}

	LOG_FUNC_RETURN(reader->ctx, r);
}

int cryptotokenkit_use_reader(sc_context_t *ctx, void *pcsc_context_handle, void *pcsc_card_handle)
{
	int r;
	struct cryptotokenkit_private_data *priv;
	sc_reader_t *reader = NULL;
	scconf_block *conf_block = NULL;
	TKSmartCardSlot* tksmartcardslot = (__bridge TKSmartCardSlot *)(pcsc_context_handle);
	TKSmartCard* tksmartcard = (__bridge TKSmartCard *)(pcsc_card_handle);
	const char* utf8String;

	if (!pcsc_context_handle) {
		if (!pcsc_card_handle)
			return SC_ERROR_INVALID_ARGUMENTS;
		tksmartcardslot = tksmartcard.slot;
	}

	if ((reader = calloc(1, sizeof(sc_reader_t))) == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	if ((priv = calloc(1, sizeof(struct cryptotokenkit_private_data))) == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	[priv->tksmartcard autorelease];
	priv->tksmartcard = [tksmartcard retain];
	[priv->tksmartcardslot autorelease];
	priv->tksmartcardslot = [tksmartcardslot retain];

	reader->drv_data = priv;
	reader->ops = &cryptotokenkit_ops;
	reader->driver = &cryptotokenkit_reader_driver;
	utf8String = [tksmartcardslot.name UTF8String];
	if ((reader->name = strdup(utf8String)) == NULL) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/* By testing we found that maxInputLength/maxOutputLength are
	 * most likely initialized badly. We still take this value as is
	 * and leave it up to the user to overwrite the reader's
	 * capabilities */
	reader->max_send_size = tksmartcardslot.maxInputLength;
	reader->max_recv_size = tksmartcardslot.maxOutputLength;

	conf_block = sc_get_conf_block(ctx, "reader_driver", "cryptotokenkit", 1);
	if (conf_block) {
		reader->max_send_size = scconf_get_int(conf_block, "max_send_size", reader->max_send_size);
		reader->max_recv_size = scconf_get_int(conf_block, "max_recv_size", reader->max_recv_size);
	}

	/* attempt to detect protocol in use T0/T1/RAW */
	ctk_set_proto(reader);

	r = _sc_add_reader(ctx, reader);

err:
	if (r != SC_SUCCESS) {
		free(priv);
		if (reader != NULL) {
			free(reader->name);
			free(reader->vendor);
			free(reader);
		}
	}

	return r;
}

static int cryptotokenkit_detect_readers(sc_context_t *ctx)
{
	size_t i;
	int r;
	TKSmartCardSlotManager *mngr = [TKSmartCardSlotManager defaultManager];

	LOG_FUNC_CALLED(ctx);

	if (!mngr) {
	 	/* com.apple.security.smartcard entitlement is disabled */
	 	r = SC_ERROR_NOT_ALLOWED;
	 	goto err;
	}

	/* temporarily mark all readers as removed */
	for (i=0; i < sc_ctx_get_reader_count(ctx); i++) {
		sc_reader_t *reader = sc_ctx_get_reader(ctx, i);
		reader->flags |= SC_READER_REMOVED;
	}

	sc_log(ctx, "Probing CryptoTokenKit readers");

	for (NSString *slotName in [mngr slotNames]) {
		sc_reader_t *old_reader;
		int found = 0;
		const char *reader_name = [slotName UTF8String];
		dispatch_semaphore_t sema = dispatch_semaphore_create(0);

		for (i=0; i < sc_ctx_get_reader_count(ctx) && !found; i++) {
			old_reader = sc_ctx_get_reader(ctx, i);
			if (old_reader == NULL) {
				r = SC_ERROR_INTERNAL;
				goto err;
			}
			if (!strcmp(old_reader->name, reader_name)) {
				found = 1;
			}
		}

		/* Reader already available, skip */
		if (found) {
			old_reader->flags &= ~SC_READER_REMOVED;
			continue;
		}

		sc_log(ctx, "Found new CryptoTokenKit reader '%s'", reader_name);
		[mngr getSlotWithName:slotName reply:^(TKSmartCardSlot *slot) {
			cryptotokenkit_use_reader(ctx, slot, NULL);
		 	dispatch_semaphore_signal(sema);
		}];
		dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
	}

	r = SC_SUCCESS;

err:
	LOG_FUNC_RETURN(ctx, r);
}

struct sc_reader_driver *sc_get_cryptotokenkit_driver(void)
{
	cryptotokenkit_ops.init = cryptotokenkit_init;
	cryptotokenkit_ops.finish = NULL;
	cryptotokenkit_ops.release = cryptotokenkit_release;
	cryptotokenkit_ops.detect_card_presence = cryptotokenkit_detect_card_presence;
	cryptotokenkit_ops.connect = cryptotokenkit_connect;
	cryptotokenkit_ops.disconnect = cryptotokenkit_disconnect;
	cryptotokenkit_ops.lock = cryptotokenkit_lock;
	cryptotokenkit_ops.unlock = cryptotokenkit_unlock;
	cryptotokenkit_ops.transmit = cryptotokenkit_transmit;
	cryptotokenkit_ops.perform_verify = NULL;
	cryptotokenkit_ops.perform_pace = NULL;
	cryptotokenkit_ops.use_reader = cryptotokenkit_use_reader;
	cryptotokenkit_ops.detect_readers = cryptotokenkit_detect_readers;

	return &cryptotokenkit_reader_driver;
}
#endif
