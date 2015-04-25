/*
 * sm.c: Secure Messaging helper functions
 *
 * Copyright (C) 2013 Viktor Tarasov <viktor.tarasov@gmail.com>
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
#include "sm.h"

static const struct sc_asn1_entry c_asn1_sm_response[4] = {
	{ "encryptedData",	SC_ASN1_OCTET_STRING,   SC_ASN1_CTX | 7,        SC_ASN1_OPTIONAL,       NULL, NULL },
	{ "statusWord",		SC_ASN1_OCTET_STRING,   SC_ASN1_CTX | 0x19,     0,                      NULL, NULL },
	{ "mac",		SC_ASN1_OCTET_STRING,   SC_ASN1_CTX | 0x0E,     0,                      NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

#ifdef ENABLE_SM
int
sc_sm_parse_answer(struct sc_card *card, unsigned char *resp_data, size_t resp_len,
		struct sm_card_response *out)
{
	struct sc_asn1_entry asn1_sm_response[4];
	unsigned char data[SC_MAX_APDU_BUFFER_SIZE];
	size_t data_len = sizeof(data);
	unsigned char status[2] = {0, 0};
	size_t status_len = sizeof(status);
	unsigned char mac[8];
	size_t mac_len = sizeof(mac);
	int rv;

	if (!resp_data || !resp_len || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_copy_asn1_entry(c_asn1_sm_response, asn1_sm_response);

	sc_format_asn1_entry(asn1_sm_response + 0, data, &data_len, 0);
	sc_format_asn1_entry(asn1_sm_response + 1, status, &status_len, 0);
	sc_format_asn1_entry(asn1_sm_response + 2, mac, &mac_len, 0);

	rv = sc_asn1_decode(card->ctx, asn1_sm_response, resp_data, resp_len, NULL, NULL);
	if (rv)
		return rv;

	if (asn1_sm_response[0].flags & SC_ASN1_PRESENT)   {
		if (data_len > sizeof(out->data))
			return SC_ERROR_BUFFER_TOO_SMALL;
		memcpy(out->data, data, data_len);
		out->data_len = data_len;
	}
	if (asn1_sm_response[1].flags & SC_ASN1_PRESENT)   {
		if (!status[0])
			return SC_ERROR_INVALID_DATA;
		out->sw1 = status[0];
		out->sw2 = status[1];
	}
	if (asn1_sm_response[2].flags & SC_ASN1_PRESENT)   {
		memcpy(out->mac, mac, mac_len);
		out->mac_len = mac_len;
	}

	return SC_SUCCESS;
}

/**  parse answer of SM protected APDU returned by APDU or by 'GET RESPONSE'
 *  @param  card 'sc_card' smartcard object
 *  @param  resp_data 'raw data returned by SM protected APDU
 *  @param  resp_len 'length of raw data returned by SM protected APDU
 *  @param  ref_rv 'status word returned by APDU or 'GET RESPONSE' (can be different from status word encoded into SM response date)
 *  @param  apdu 'sc_apdu' object to update
 *  @return SC_SUCCESS on success and an error code otherwise
 */
int
sc_sm_update_apdu_response(struct sc_card *card, unsigned char *resp_data, size_t resp_len,
		int ref_rv, struct sc_apdu *apdu)
{
	struct sm_card_response sm_resp;
	int r;

	if (!apdu)
		return SC_ERROR_INVALID_ARGUMENTS;
	else if (!resp_data || !resp_len)
		return SC_SUCCESS;

	memset(&sm_resp, 0, sizeof(sm_resp));
	r = sc_sm_parse_answer(card, resp_data, resp_len, &sm_resp);
	if (r)
		return r;

	if (sm_resp.mac_len)   {
		if (sm_resp.mac_len > sizeof(apdu->mac))
			return SC_ERROR_INVALID_DATA;
		memcpy(apdu->mac, sm_resp.mac, sm_resp.mac_len);
		apdu->mac_len = sm_resp.mac_len;
	}

	apdu->sw1 = sm_resp.sw1;
	apdu->sw2 = sm_resp.sw2;

	return SC_SUCCESS;
}

int
sc_sm_single_transmit(struct sc_card *card, struct sc_apdu *apdu)
{
	struct sc_context *ctx  = card->ctx;
	struct sc_apdu *sm_apdu = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SM_MODE:%X", card->sm_ctx.sm_mode);
	if (!card->sm_ctx.ops.get_sm_apdu || !card->sm_ctx.ops.free_sm_apdu)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	/* get SM encoded APDU */
	rv = card->sm_ctx.ops.get_sm_apdu(card, apdu, &sm_apdu);
	if (rv == SC_ERROR_SM_NOT_APPLIED)   {
		/* SM wrap of this APDU is ignored by card driver.
		 * Send plain APDU to the reader driver */
		rv = card->reader->ops->transmit(card->reader, apdu);
		LOG_FUNC_RETURN(ctx, rv);
	} else {
		if (rv < 0)
			sc_sm_stop(card);
	}
	LOG_TEST_RET(ctx, rv, "get SM APDU error");

	/* check if SM APDU is still valid */
	rv = sc_check_apdu(card, sm_apdu);
	if (rv < 0)   {
		card->sm_ctx.ops.free_sm_apdu(card, apdu, &sm_apdu);
		sc_sm_stop(card);
		LOG_TEST_RET(ctx, rv, "cannot validate SM encoded APDU");
	}

	/* send APDU to the reader driver */
	rv = card->reader->ops->transmit(card->reader, sm_apdu);
	if (rv < 0) {
		card->sm_ctx.ops.free_sm_apdu(card, apdu, &sm_apdu);
		sc_sm_stop(card);
		LOG_TEST_RET(ctx, rv, "unable to transmit APDU");
	}

	/* decode SM answer and free temporary SM related data */
	rv = card->sm_ctx.ops.free_sm_apdu(card, apdu, &sm_apdu);
	if (rv < 0)
		sc_sm_stop(card);

	LOG_FUNC_RETURN(ctx, rv);
}

int
sc_sm_stop(struct sc_card *card)
{
    int r = SC_SUCCESS;

    if (card) {
        if (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT
                && card->sm_ctx.ops.close)
            r = card->sm_ctx.ops.close(card);
        card->sm_ctx.sm_mode = SM_MODE_NONE;
    }

    return r;
}

#else

int
sc_sm_parse_answer(struct sc_card *card, unsigned char *resp_data, size_t resp_len,
		struct sm_card_response *out)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_sm_update_apdu_response(struct sc_card *card, unsigned char *resp_data, size_t resp_len,
		int ref_rv, struct sc_apdu *apdu)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_sm_single_transmit(struct sc_card *card, struct sc_apdu *apdu)
{
	return SC_ERROR_NOT_SUPPORTED;
}

int
sc_sm_stop(struct sc_card *card)
{
    return SC_ERROR_NOT_SUPPORTED;
}
#endif
