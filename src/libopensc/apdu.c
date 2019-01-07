/*
 * apdu.c: basic APDU handling functions
 *
 * Copyright (C) 2005 Nils Larsch <nils@larsch.net>
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
#include <assert.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"

/*********************************************************************/
/*   low level APDU handling functions                               */
/*********************************************************************/

/** Calculates the length of the encoded APDU in octets.
 *  @param  apdu   the APDU
 *  @param  proto  the desired protocol
 *  @return length of the encoded APDU
 */
size_t sc_apdu_get_length(const sc_apdu_t *apdu, unsigned int proto)
{
	size_t ret = 4;

	switch (apdu->cse) {
	case SC_APDU_CASE_1:
		if (proto == SC_PROTO_T0)
			ret++;
		break;
	case SC_APDU_CASE_2_SHORT:
		ret++;
		break;
	case SC_APDU_CASE_2_EXT:
		ret += (proto == SC_PROTO_T0 ? 1 : 3);
		break;
	case SC_APDU_CASE_3_SHORT:
		ret += 1 + apdu->lc;
		break;
	case SC_APDU_CASE_3_EXT:
		ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 3);
		break;
	case SC_APDU_CASE_4_SHORT:
		ret += apdu->lc + (proto != SC_PROTO_T0 ? 2 : 1);
		break;
	case SC_APDU_CASE_4_EXT:
		ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 5);
		break;
	default:
		return 0;
	}
	return ret;
}

/** Encodes a APDU as an octet string
 *  @param  ctx     sc_context_t object (used for logging)
 *  @param  apdu    APDU to be encoded as an octet string
 *  @param  proto   protocol version to be used
 *  @param  out     output buffer of size outlen.
 *  @param  outlen  size of hte output buffer
 *  @return SC_SUCCESS on success and an error code otherwise
 */
int sc_apdu2bytes(sc_context_t *ctx, const sc_apdu_t *apdu,
	unsigned int proto, u8 *out, size_t outlen)
{
	u8     *p = out;

	size_t len = sc_apdu_get_length(apdu, proto);

	if (out == NULL || outlen < len)
		return SC_ERROR_INVALID_ARGUMENTS;
	/* CLA, INS, P1 and P2 */
	*p++ = apdu->cla;
	*p++ = apdu->ins;
	*p++ = apdu->p1;
	*p++ = apdu->p2;
	/* case depend part */
	switch (apdu->cse) {
	case SC_APDU_CASE_1:
		/* T0 needs an additional 0x00 byte */
		if (proto == SC_PROTO_T0)
			*p = (u8)0x00;
		break;
	case SC_APDU_CASE_2_SHORT:
		*p = (u8)apdu->le;
		break;
	case SC_APDU_CASE_2_EXT:
		if (proto == SC_PROTO_T0)
			/* T0 extended APDUs look just like short APDUs */
			*p = (u8)apdu->le;
		else {
			/* in case of T1 always use 3 bytes for length */
			*p++ = (u8)0x00;
			*p++ = (u8)(apdu->le >> 8);
			*p = (u8)apdu->le;
		}
		break;
	case SC_APDU_CASE_3_SHORT:
		*p++ = (u8)apdu->lc;
		memcpy(p, apdu->data, apdu->lc);
		break;
	case SC_APDU_CASE_3_EXT:
		if (proto == SC_PROTO_T0) {
			/* in case of T0 the command is transmitted in chunks
			 * < 255 using the ENVELOPE command ... */
			if (apdu->lc > 255) {
				/* ... so if Lc is greater than 255 bytes
				 * an error has occurred on a higher level */
				sc_log(ctx, "invalid Lc length for CASE 3 extended APDU (need ENVELOPE)");
				return SC_ERROR_INVALID_ARGUMENTS;
			}
		}
		else {
			/* in case of T1 always use 3 bytes for length */
			*p++ = (u8)0x00;
			*p++ = (u8)(apdu->lc >> 8);
			*p++ = (u8)apdu->lc;
		}
		memcpy(p, apdu->data, apdu->lc);
		break;
	case SC_APDU_CASE_4_SHORT:
		*p++ = (u8)apdu->lc;
		memcpy(p, apdu->data, apdu->lc);
		p += apdu->lc;
		/* in case of T0 no Le byte is added */
		if (proto != SC_PROTO_T0)
			*p = (u8)apdu->le;
		break;
	case SC_APDU_CASE_4_EXT:
		if (proto == SC_PROTO_T0) {
			/* again a T0 extended case 4 APDU looks just
			 * like a short APDU, the additional data is
			 * transferred using ENVELOPE and GET RESPONSE */
			*p++ = (u8)apdu->lc;
			memcpy(p, apdu->data, apdu->lc);
		}
		else {
			*p++ = (u8)0x00;
			*p++ = (u8)(apdu->lc >> 8);
			*p++ = (u8)apdu->lc;
			memcpy(p, apdu->data, apdu->lc);
			p += apdu->lc;
			/* only 2 bytes are use to specify the length of the
			 * expected data */
			*p++ = (u8)(apdu->le >> 8);
			*p = (u8)apdu->le;
		}
		break;
	}

	return SC_SUCCESS;
}

int sc_apdu_get_octets(sc_context_t *ctx, const sc_apdu_t *apdu, u8 **buf,
	size_t *len, unsigned int proto)
{
	size_t	nlen;
	u8	*nbuf;

	if (apdu == NULL || buf == NULL || len == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* get the estimated length of encoded APDU */
	nlen = sc_apdu_get_length(apdu, proto);
	if (nlen == 0)
		return SC_ERROR_INTERNAL;
	nbuf = malloc(nlen);
	if (nbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	/* encode the APDU in the buffer */
	if (sc_apdu2bytes(ctx, apdu, proto, nbuf, nlen) != SC_SUCCESS) {
		free(nbuf);
		return SC_ERROR_INTERNAL;
	}
	*buf = nbuf;
	*len = nlen;

	return SC_SUCCESS;
}

int sc_apdu_set_resp(sc_context_t *ctx, sc_apdu_t *apdu, const u8 *buf,
	size_t len)
{
	if (len < 2) {
		/* no SW1 SW2 ... something went terrible wrong */
		sc_log(ctx, "invalid response: SW1 SW2 missing");
		return SC_ERROR_INTERNAL;
	}
	/* set the SW1 and SW2 status bytes (the last two bytes of
	 * the response */
	apdu->sw1 = (unsigned int)buf[len - 2];
	apdu->sw2 = (unsigned int)buf[len - 1];
	len -= 2;
	/* set output length and copy the returned data if necessary */
	if (len <= apdu->resplen)
		apdu->resplen = len;

	if (apdu->resplen != 0)
		memcpy(apdu->resp, buf, apdu->resplen);

	return SC_SUCCESS;
}


/*********************************************************************/
/*   higher level APDU transfer handling functions                   */
/*********************************************************************/
/*   +------------------+
 *   | sc_transmit_apdu |
 *   +------------------+
 *         |  |  |
 *         |  |  |     detect APDU cse               +--------------------+
 *         |  |  +---------------------------------> | sc_detect_apdu_cse |
 *         |  |                                      +--------------------+
 *         |  |        check consistency of APDU     +--------------------+
 *         |  +------------------------------------> | sc_check_apdu      |
 *         |                                         +--------------------+
 *         |           send single APDU              +--------------------+
 *         +---------------------------------------> | sc_transmit        |
 *                        ^                          +--------------------+
 *                        |                               |
 *                        |  re-transmit if wrong length  |
 *                        |       or GET RESPONSE         |
 *                        +-------------------------------+
 *                                                        |
 *                                                        v
 *                                               card->reader->ops->transmit
 */

/** basic consistency check of the sc_apdu_t object
 *  @param  ctx   sc_context_t object for error messages
 *  @param  apdu  sc_apdu_t object to check
 *  @return SC_SUCCESS on success and an error code otherwise
 */
int
sc_check_apdu(sc_card_t *card, const sc_apdu_t *apdu)
{
	if ((apdu->cse & ~SC_APDU_SHORT_MASK) == 0) {
		/* length check for short APDU */
		if (apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & SC_APDU_FLAGS_CHAINING) == 0))   {
			sc_log(card->ctx, "failed length check for short APDU");
			goto error;
		}
	}
	else if ((apdu->cse & SC_APDU_EXT) != 0) {
		/* check if the card supports extended APDUs */
		if ((card->caps & SC_CARD_CAP_APDU_EXT) == 0) {
			sc_log(card->ctx, "card doesn't support extended APDUs");
			goto error;
		}
		/* length check for extended APDU */
		if (apdu->le > 65536 || apdu->lc > 65535)   {
			sc_log(card->ctx, "failed length check for extended APDU");
			goto error;
		}
	}
	else   {
		goto error;
	}

	switch (apdu->cse & SC_APDU_SHORT_MASK) {
	case SC_APDU_CASE_1:
		/* no data is sent or received */
		if (apdu->datalen != 0 || apdu->lc != 0 || apdu->le != 0)
			goto error;
		break;
	case SC_APDU_CASE_2_SHORT:
		/* no data is sent */
		if (apdu->datalen != 0 || apdu->lc != 0)
			goto error;
		/* data is expected       */
		if (apdu->resplen == 0 || apdu->resp == NULL)
			goto error;
		break;
	case SC_APDU_CASE_3_SHORT:
		/* data is sent */
		if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
			goto error;
		/* no data is expected    */
		if (apdu->le != 0)
			goto error;
		/* inconsistent datalen   */
		if (apdu->datalen != apdu->lc)
			goto error;
		break;
	case SC_APDU_CASE_4_SHORT:
		/* data is sent */
		if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
			goto error;
		/* data is expected       */
		if (apdu->resplen == 0 || apdu->resp == NULL)
			goto error;
		/* inconsistent datalen   */
		if (apdu->datalen != apdu->lc)
			goto error;
		break;
	default:
		sc_log(card->ctx, "Invalid APDU case %d", apdu->cse);
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	return SC_SUCCESS;
error:
	sc_log(card->ctx, "Invalid Case %d %s APDU:\n"
		"cse=%02x cla=%02x ins=%02x p1=%02x p2=%02x lc=%lu le=%lu\n"
		"resp=%p resplen=%lu data=%p datalen=%lu",
		apdu->cse & SC_APDU_SHORT_MASK,
		(apdu->cse & SC_APDU_EXT) != 0 ? "extended" : "short",
		apdu->cse, apdu->cla, apdu->ins, apdu->p1, apdu->p2,
		(unsigned long) apdu->lc, (unsigned long) apdu->le,
		apdu->resp, (unsigned long) apdu->resplen,
		apdu->data, (unsigned long) apdu->datalen);
	return SC_ERROR_INVALID_ARGUMENTS;
}

/** Tries to determine the APDU type (short or extended) of the supplied
 *  APDU if one of the SC_APDU_CASE_? types is used.
 *  @param  apdu  APDU object
 */
static void
sc_detect_apdu_cse(const sc_card_t *card, sc_apdu_t *apdu)
{
	if (apdu->cse == SC_APDU_CASE_2 || apdu->cse == SC_APDU_CASE_3 ||
	    apdu->cse == SC_APDU_CASE_4) {
		int btype = apdu->cse & SC_APDU_SHORT_MASK;
		/* if either Lc or Le is bigger than the maximum for
		 * short APDUs and the card supports extended APDUs
		 * use extended APDUs (unless Lc is greater than
		 * 255 and command chaining is activated) */
		if ((apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & SC_APDU_FLAGS_CHAINING) == 0)) &&
		    (card->caps & SC_CARD_CAP_APDU_EXT) != 0)
			btype |= SC_APDU_EXT;
		apdu->cse = btype;
	}
}


static int
sc_single_transmit(struct sc_card *card, struct sc_apdu *apdu)
{
	struct sc_context *ctx  = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->reader->ops->transmit == NULL)
		LOG_TEST_RET(card->ctx, SC_ERROR_NOT_SUPPORTED, "cannot transmit APDU");

	sc_log(ctx,
	       "CLA:%X, INS:%X, P1:%X, P2:%X, data(%"SC_FORMAT_LEN_SIZE_T"u) %p",
	       apdu->cla, apdu->ins, apdu->p1, apdu->p2, apdu->datalen,
	       apdu->data);
#ifdef ENABLE_SM
	if (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT
		   	&& (apdu->flags & SC_APDU_FLAGS_NO_SM) == 0) {
		LOG_FUNC_RETURN(ctx, sc_sm_single_transmit(card, apdu));
	}
#endif

	/* send APDU to the reader driver */
	rv = card->reader->ops->transmit(card->reader, apdu);
	LOG_TEST_RET(ctx, rv, "unable to transmit APDU");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_set_le_and_transmit(struct sc_card *card, struct sc_apdu *apdu, size_t olen)
{
	struct sc_context *ctx  = card->ctx;
	size_t nlen = apdu->sw2 ? (size_t)apdu->sw2 : 256;
	int rv;

	LOG_FUNC_CALLED(ctx);
	/* we cannot re-transmit the APDU with the demanded Le value
	 * as the buffer is too small => error */
	if (olen < nlen)
		LOG_TEST_RET(ctx, SC_ERROR_WRONG_LENGTH, "wrong length: required length exceeds resplen");

	/* don't try again if it doesn't work this time */
	apdu->flags  |= SC_APDU_FLAGS_NO_RETRY_WL;
	/* set the new expected length */
	apdu->resplen = olen;
	apdu->le      = nlen;
	/* Belpic V1 applets have a problem: if the card sends a 6C XX (only XX bytes available), 
	 * and we resend the command too soon (i.e. the reader is too fast), the card doesn't respond. 
	 * So we build in a delay. */
	if (card->type == SC_CARD_TYPE_BELPIC_EID)
		msleep(40);

	/* re-transmit the APDU with new Le length */
	rv = sc_single_transmit(card, apdu);
	LOG_TEST_RET(ctx, rv, "cannot re-transmit APDU");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
sc_get_response(struct sc_card *card, struct sc_apdu *apdu, size_t olen)
{
	struct sc_context *ctx  = card->ctx;
	size_t le, minlen, buflen;
	unsigned char *buf;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (apdu->le == 0) {
		/* no data is requested => change return value to 0x9000 and ignore the remaining data */
		apdu->sw1 = 0x90;
		apdu->sw2 = 0x00;
		return SC_SUCCESS;
	}

	/* this should _never_ happen */
	if (!card->ops->get_response)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "no GET RESPONSE command");

	/* call GET RESPONSE until we have read all data requested or until the card returns 0x9000,
	 * whatever happens first. */

	/* if there are already data in response append a new data to the end of the buffer */
	buf = apdu->resp + apdu->resplen;

	/* read as much data as fits in apdu->resp (i.e. min(apdu->resplen, amount of data available)). */
	buflen = olen - apdu->resplen;

	/* 0x6100 means at least 256 more bytes to read */
	le = apdu->sw2 != 0 ? (size_t)apdu->sw2 : 256;
	/* we try to read at least as much as bytes as promised in the response bytes */
	minlen = le;

	do {
		unsigned char resp[256];
		size_t resp_len = le;

		/* call GET RESPONSE to get more date from the card;
		 * note: GET RESPONSE returns the left amount of data (== SW2) */
		memset(resp, 0, sizeof(resp));
		rv = card->ops->get_response(card, &resp_len, resp);
		if (rv < 0)   {
#ifdef ENABLE_SM
			if (resp_len)   {
				sc_log_hex(ctx, "SM response data", resp, resp_len);
				sc_sm_update_apdu_response(card, resp, resp_len, rv, apdu);
			}
#endif
			LOG_TEST_RET(ctx, rv, "GET RESPONSE error");
		}

		le = resp_len;
		/* copy as much as will fit in requested buffer */
		if (buflen < le)
			le = buflen;

		memcpy(buf, resp, le);
		buf    += le;
		buflen -= le;

		/* we have all the data the caller requested even if the card has more data */
		if (buflen == 0)
			break;

		minlen -= le;
		if (rv != 0)
			le = minlen = (size_t)rv;
		else
			/* if the card has returned 0x9000 but we still expect data ask for more
			 * until we have read enough bytes */
			le = minlen;
	} while (rv != 0 && minlen != 0);

	/* we've read all data, let's return 0x9000 */
	apdu->resplen = buf - apdu->resp;
	apdu->sw1 = 0x90;
	apdu->sw2 = 0x00;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/** Sends a single APDU to the card reader and calls GET RESPONSE to get the return data if necessary.
 *  @param  card  sc_card_t object for the smartcard
 *  @param  apdu  APDU to be sent
 *  @return SC_SUCCESS on success and an error value otherwise
 */
static int
sc_transmit(sc_card_t *card, sc_apdu_t *apdu)
{
	struct sc_context *ctx  = card->ctx;
	size_t       olen  = apdu->resplen;
	int          r;

	LOG_FUNC_CALLED(ctx);

	r = sc_single_transmit(card, apdu);
	LOG_TEST_RET(ctx, r, "transmit APDU failed");

	/* ok, the APDU was successfully transmitted. Now we have two special cases:
	 * 1. the card returned 0x6Cxx: in this case APDU will be re-transmitted with Le set to SW2
	 * (possible only if response buffer size is larger than new Le = SW2)
	 */
	if (apdu->sw1 == 0x6C && (apdu->flags & SC_APDU_FLAGS_NO_RETRY_WL) == 0)
		r = sc_set_le_and_transmit(card, apdu, olen);
	LOG_TEST_RET(ctx, r, "cannot re-transmit APDU ");

	/* 2. the card returned 0x61xx: more data can be read from the card
	 *    using the GET RESPONSE command (mostly used in the T0 protocol).
	 *    Unless the SC_APDU_FLAGS_NO_GET_RESP is set we try to read as
	 *    much data as possible using GET RESPONSE.
	 */
	if (apdu->sw1 == 0x61 && (apdu->flags & SC_APDU_FLAGS_NO_GET_RESP) == 0)
		r = sc_get_response(card, apdu, olen);
	LOG_TEST_RET(ctx, r, "cannot get all data with 'GET RESPONSE'");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


int sc_transmit_apdu(sc_card_t *card, sc_apdu_t *apdu)
{
	int r = SC_SUCCESS;

	if (card == NULL || apdu == NULL)
		return SC_ERROR_INVALID_ARGUMENTS;

	LOG_FUNC_CALLED(card->ctx);

	/* determine the APDU type if necessary, i.e. to use
	 * short or extended APDUs  */
	sc_detect_apdu_cse(card, apdu);
	/* basic APDU consistency check */
	r = sc_check_apdu(card, apdu);
	if (r != SC_SUCCESS)
		return SC_ERROR_INVALID_ARGUMENTS;

	r = sc_lock(card);	/* acquire card lock*/
	if (r != SC_SUCCESS) {
		sc_log(card->ctx, "unable to acquire lock");
		return r;
	}

	if ((apdu->flags & SC_APDU_FLAGS_CHAINING) != 0) {
		/* divide et impera: transmit APDU in chunks with Lc <= max_send_size
		 * bytes using command chaining */
		size_t    len  = apdu->datalen;
		const u8  *buf = apdu->data;
		size_t    max_send_size = sc_get_max_send_size(card);

		while (len != 0) {
			size_t    plen;
			sc_apdu_t tapdu;
			int       last = 0;

			tapdu = *apdu;
			/* clear chaining flag */
			tapdu.flags &= ~SC_APDU_FLAGS_CHAINING;
			if (len > max_send_size) {
				/* adjust APDU case: in case of CASE 4 APDU
				 * the intermediate APDU are of CASE 3 */
				if ((tapdu.cse & SC_APDU_SHORT_MASK) == SC_APDU_CASE_4_SHORT)
					tapdu.cse--;
				/* XXX: the chunk size must be adjusted when
				 *      secure messaging is used */
				plen          = max_send_size;
				tapdu.cla    |= 0x10;
				tapdu.le      = 0;
				/* the intermediate APDU don't expect data */
				tapdu.lc      = 0;
				tapdu.resplen = 0;
				tapdu.resp    = NULL;
			} else {
				plen = len;
				last = 1;
			}
			tapdu.data    = buf;
			tapdu.datalen = tapdu.lc = plen;

			r = sc_check_apdu(card, &tapdu);
			if (r != SC_SUCCESS) {
				sc_log(card->ctx, "inconsistent APDU while chaining");
				break;
			}

			r = sc_transmit(card, &tapdu);
			if (r != SC_SUCCESS)
				break;
			if (last != 0) {
				/* in case of the last APDU set the SW1
				 * and SW2 bytes in the original APDU */
				apdu->sw1 = tapdu.sw1;
				apdu->sw2 = tapdu.sw2;
				apdu->resplen = tapdu.resplen;
			} else {
				/* otherwise check the status bytes */
				r = sc_check_sw(card, tapdu.sw1, tapdu.sw2);
				if (r != SC_SUCCESS)
					break;
			}
			len -= plen;
			buf += plen;
		}
	} else
		/* transmit single APDU */
		r = sc_transmit(card, apdu);
	/* all done => release lock */
	if (sc_unlock(card) != SC_SUCCESS)
		sc_log(card->ctx, "sc_unlock failed");

	return r;
}


int
sc_bytes2apdu(sc_context_t *ctx, const u8 *buf, size_t len, sc_apdu_t *apdu)
{
	const unsigned char *p;
	size_t len0;

	if (!buf || !apdu)
		return SC_ERROR_INVALID_ARGUMENTS;

	len0 = len;
	if (len < 4) {
		sc_log(ctx, "APDU too short (must be at least 4 bytes)");
		return SC_ERROR_INVALID_DATA;
	}

	memset(apdu, 0, sizeof *apdu);
	p = buf;
	apdu->cla = *p++;
	apdu->ins = *p++;
	apdu->p1 = *p++;
	apdu->p2 = *p++;
	len -= 4;

	if (!len) {
		apdu->cse = SC_APDU_CASE_1;
		sc_log(ctx,
		       "CASE_1 APDU: %"SC_FORMAT_LEN_SIZE_T"u bytes:\tins=%02x p1=%02x p2=%02x lc=%04"SC_FORMAT_LEN_SIZE_T"x le=%04"SC_FORMAT_LEN_SIZE_T"x",
		       len0, apdu->ins, apdu->p1, apdu->p2, apdu->lc, apdu->le);
		return SC_SUCCESS;
	}

	if (*p == 0 && len >= 3) {
		/* ...must be an extended APDU */
		p++;
		if (len == 3) {
			apdu->le = (*p++)<<8;
			apdu->le += *p++;
			if (apdu->le == 0)
				apdu->le = 0xffff+1;
			len -= 3;
			apdu->cse = SC_APDU_CASE_2_EXT;
		}
		else {
			/* len > 3 */
			apdu->lc = (*p++)<<8;
			apdu->lc += *p++;
			len -= 3;
			if (len < apdu->lc) {
				sc_log(ctx,
				       "APDU too short (need %"SC_FORMAT_LEN_SIZE_T"u more bytes)",
				       apdu->lc - len);
				return SC_ERROR_INVALID_DATA;
			}
			apdu->data = p;
			apdu->datalen = apdu->lc;
			len -= apdu->lc;
			p += apdu->lc;
			if (!len) {
				apdu->cse = SC_APDU_CASE_3_EXT;
			}
			else {
				/* at this point the apdu has a Lc, so Le is on 2 bytes */
				if (len < 2) {
					sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "APDU too short (need 2 more bytes)\n");
					return SC_ERROR_INVALID_DATA;
				}
				apdu->le = (*p++)<<8;
				apdu->le += *p++;
				if (apdu->le == 0)
					apdu->le = 0xffff+1;
				len -= 2;
				apdu->cse = SC_APDU_CASE_4_EXT;
			}
		}
	}
	else {
		/* ...must be a short APDU */
		if (len == 1) {
			apdu->le = *p++;
			if (apdu->le == 0)
				apdu->le = 0xff+1;
			len--;
			apdu->cse = SC_APDU_CASE_2_SHORT;
		}
		else {
			apdu->lc = *p++;
			len--;
			if (len < apdu->lc) {
				sc_log(ctx,
				       "APDU too short (need %"SC_FORMAT_LEN_SIZE_T"u more bytes)",
				       apdu->lc - len);
				return SC_ERROR_INVALID_DATA;
			}
			apdu->data = p;
			apdu->datalen = apdu->lc;
			len -= apdu->lc;
			p += apdu->lc;
			if (!len) {
				apdu->cse = SC_APDU_CASE_3_SHORT;
			}
			else {
				apdu->le = *p++;
				if (apdu->le == 0)
					apdu->le = 0xff+1;
				len--;
				apdu->cse = SC_APDU_CASE_4_SHORT;
			}
		}
	}
	if (len) {
		sc_log(ctx, "APDU too long (%lu bytes extra)",(unsigned long) len);
		return SC_ERROR_INVALID_DATA;
	}

	sc_log(ctx,
	       "Case %d %s APDU, %"SC_FORMAT_LEN_SIZE_T"u bytes:\tins=%02x p1=%02x p2=%02x lc=%04"SC_FORMAT_LEN_SIZE_T"x le=%04"SC_FORMAT_LEN_SIZE_T"x",
	       apdu->cse & SC_APDU_SHORT_MASK,
	       (apdu->cse & SC_APDU_EXT) != 0 ? "extended" : "short",
	       len0, apdu->ins, apdu->p1, apdu->p2, apdu->lc,
	       apdu->le);

	return SC_SUCCESS;
}
