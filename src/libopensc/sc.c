/*
 * sc.c: General SmartCard functions
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

#include "config.h"
#include "opensc.h"
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
int sc_debug = 0;

int sc_sw_to_errorcode(struct sc_card *card, int sw1, int sw2)
{
	switch (sw1) {
	case 0x69:
		switch (sw2) {
		case 0x82:
			return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		default:
		}
	case 0x6A:
		switch (sw2) {
		case 0x81:
			return SC_ERROR_NOT_SUPPORTED;
		case 0x82:
		case 0x83:
			return SC_ERROR_FILE_NOT_FOUND;
		case 0x86:
		case 0x87:
			return SC_ERROR_INVALID_ARGUMENTS;
		default:
		}
	case 0x6D:
		return SC_ERROR_NOT_SUPPORTED;
	case 0x6E:
		return SC_ERROR_UNKNOWN_SMARTCARD;
	case 0x90:
		if (sw2 == 0)
			return 0;
	}
	error(card->ctx, "Unknown SW's: SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_UNKNOWN_REPLY;
}

void sc_print_binary(FILE *f, const u8 *buf, int count)
{
	int i;
	
	for (i = 0; i < count; i++) {
		unsigned char c = buf[i];
		const char *format;
		if (!isalnum(c) && !ispunct(c) && !isspace(c))
			format = "\\x%02X";
		else
			format = "%c";
		fprintf(f, format, c);
	}
	fflush(f);
}

int sc_hex_to_bin(const char *in, u8 *out, int *outlen)
{
	int c = 0, err = 0, left;

	assert(in != NULL && out != NULL && outlen != NULL);
        left = *outlen;

	while (*in) {
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
		*out++ = byte;
		left--;
		c++;
	}
	*outlen = c;
	return err;
}

int sc_check_apdu(struct sc_context *ctx, const struct sc_apdu *apdu)
{
	switch (apdu->cse) {
	case SC_APDU_CASE_1:
		if (apdu->datalen)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	case SC_APDU_CASE_2_SHORT:
		if (apdu->datalen)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		if (apdu->resplen < apdu->le)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	case SC_APDU_CASE_3_SHORT:
		if (apdu->datalen == 0 || apdu->data == NULL)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	case SC_APDU_CASE_4_SHORT:
		if (apdu->datalen == 0 || apdu->data == NULL)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		if (apdu->resplen < apdu->le)
			SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
		break;
	case SC_APDU_CASE_2_EXT:
	case SC_APDU_CASE_3_EXT:
	case SC_APDU_CASE_4_EXT:
		SC_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	return 0;
}

static int sc_transceive_t0(struct sc_card *card, struct sc_apdu *apdu)
{
	SCARD_IO_REQUEST sSendPci, sRecvPci;
	BYTE s[SC_MAX_APDU_BUFFER_SIZE], r[SC_MAX_APDU_BUFFER_SIZE];
	DWORD dwSendLength, dwRecvLength;
	LONG rv;
	u8 *data = s;
	int data_bytes = apdu->lc;

	if (data_bytes == 0)
		data_bytes = 256;
	*data++ = apdu->cla;
	*data++ = apdu->ins;
	*data++ = apdu->p1;
	*data++ = apdu->p2;
	switch (apdu->cse) {
	case SC_APDU_CASE_1:
		break;
	case SC_APDU_CASE_2_SHORT:
		*data++ = apdu->le;
		break;
	case SC_APDU_CASE_2_EXT:
		*data++ = 0;
		*data++ = apdu->le >> 8;
		*data++ = apdu->le & 0xFF;
		break;
	case SC_APDU_CASE_3_SHORT:
		*data++ = apdu->lc;
		if (apdu->datalen != data_bytes)
			return SC_ERROR_INVALID_ARGUMENTS;
		memcpy(data, apdu->data, data_bytes);
		data += data_bytes;
		break;
	case SC_APDU_CASE_4_SHORT:
		*data++ = apdu->lc;
		if (apdu->datalen != data_bytes)
			return SC_ERROR_INVALID_ARGUMENTS;
		memcpy(data, apdu->data, data_bytes);
		data += data_bytes;
		*data++ = apdu->le;
		break;
	}

	sSendPci.dwProtocol = SCARD_PROTOCOL_T0;
	sSendPci.cbPciLength = 0;
	sRecvPci.dwProtocol = SCARD_PROTOCOL_T0;
	sRecvPci.cbPciLength = 0;

	dwSendLength = data - s;
	dwRecvLength = apdu->resplen + 2;
	if (dwRecvLength > 255)		/* FIXME: PC/SC Lite quirk */
		dwRecvLength = 255;
	if (sc_debug > 3) {
		char buf[2048];
		
		sc_hex_dump(card->ctx, s, dwSendLength, buf, sizeof(buf));
		debug(card->ctx, "Sending %d bytes (resp. %d bytes):\n%s",
			dwSendLength, dwRecvLength, buf);
	}
	rv = SCardTransmit(card->pcsc_card, &sSendPci, s, dwSendLength,
			   &sRecvPci, r, &dwRecvLength);
	if (rv != SCARD_S_SUCCESS) {
		switch (rv) {
		case SCARD_W_REMOVED_CARD:
			return SC_ERROR_CARD_REMOVED;
		case SCARD_W_RESET_CARD:
			return SC_ERROR_CARD_RESET;
		case SCARD_E_NOT_TRANSACTED:
			if (sc_detect_card(card->ctx, card->reader) != 1)
				return SC_ERROR_CARD_REMOVED;
			return SC_ERROR_TRANSMIT_FAILED;
		default:
			error(card->ctx, "SCardTransmit failed: %s\n", pcsc_stringify_error(rv));
			return SC_ERROR_TRANSMIT_FAILED;
		}
	}
	if (dwRecvLength < 2)
		return SC_ERROR_UNKNOWN_RESPONSE;
	apdu->sw1 = r[dwRecvLength-2];
	apdu->sw2 = r[dwRecvLength-1];
	dwRecvLength -= 2;
	if (dwRecvLength > apdu->resplen)
		dwRecvLength = apdu->resplen;
	else
		apdu->resplen = dwRecvLength;
	if (dwRecvLength)
		memcpy(apdu->resp, r, dwRecvLength);

	return 0;
}

int sc_transmit_apdu(struct sc_card *card, struct sc_apdu *apdu)
{
	int r;
	
	SC_FUNC_CALLED(card->ctx);
	r = sc_check_apdu(card->ctx, apdu);
	SC_TEST_RET(card->ctx, r, "APDU sanity check failed");
	r = sc_transceive_t0(card, apdu);
	SC_TEST_RET(card->ctx, r, "transceive_t0() failed");
	if (sc_debug > 3) {
		char buf[2048];

		buf[0] = 0;
		if (apdu->resplen) {
			sc_hex_dump(card->ctx, apdu->resp, apdu->resplen,
				    buf, sizeof(buf));
		}
		debug(card->ctx, "Received %d bytes (SW1=%02X SW2=%02X)\n%s",
		      apdu->resplen, apdu->sw1, apdu->sw2, buf);
	}
	if (apdu->sw1 == 0x61 && apdu->resplen == 0) {
		struct sc_apdu rspapdu;
		BYTE rsp[SC_MAX_APDU_BUFFER_SIZE];

		if (apdu->no_response)
			return 0;

		sc_format_apdu(card, &rspapdu, SC_APDU_CASE_2_SHORT,
			       0xC0, 0, 0);
		rspapdu.le = apdu->sw2;
		rspapdu.resp = rsp;
		rspapdu.resplen = apdu->sw2;
		r = sc_transceive_t0(card, &rspapdu);
		if (r) {
			error(card->ctx, "error while getting response: %s\n",
			      sc_strerror(r));
			return r;
		}
		if (sc_debug > 3) {
			char buf[2048];
			buf[0] = 0;
			if (rspapdu.resplen) {
				sc_hex_dump(card->ctx, rspapdu.resp,
					    rspapdu.resplen,
					    buf, sizeof(buf));
			}
			debug(card->ctx, "Response %d bytes (SW1=%02X SW2=%02X)\n%s",
			      rspapdu.resplen, rspapdu.sw1, rspapdu.sw2, buf);
		}
		/* FIXME: Check apdu->resplen */
		memcpy(apdu->resp, rspapdu.resp, rspapdu.resplen);
		apdu->resplen = rspapdu.resplen;
		apdu->sw1 = rspapdu.sw1;
		apdu->sw2 = rspapdu.sw2;
	}
	return 0;
}

static void process_fci(struct sc_context *ctx, struct sc_file *file,
			const u8 *buf, int buflen)
{
	int taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	if (sc_debug > 2)
		debug(ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (sc_debug > 2)
			debug(ctx, "  file identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (sc_debug > 2)
			debug(ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	tag = sc_asn1_find_tag(p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (sc_debug > 2)
				debug(ctx, "  shareable: %s\n",
				       (byte & 0x40) ? "yes" : "no");
			file->type = (byte >> 3) & 7;
			file->ef_structure = byte & 0x07;
			if (sc_debug > 2) {
				switch ((byte >> 3) & 7) {
				case 0:
					type = "working EF";
					break;
				case 1:
					type = "internal EF";
					break;
				case 7:
					type = "DF";
					break;
				default:
					type = "unknown";
					break;
				}
				debug(ctx, "  type: %s\n", type);
				debug(ctx, "  EF structure: %d\n",
				       byte & 0x07);
			}
		}
	}
	tag = sc_asn1_find_tag(p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char name[17];
		int i;

		memcpy(file->name, tag, taglen);
		file->namelen = taglen;

		for (i = 0; i < taglen; i++) {
			if (isalnum(tag[i]) || ispunct(tag[i])
			    || isspace(tag[i]))
				name[i] = tag[i];
			else
				name[i] = '?';
		}
		name[taglen] = 0;
		if (sc_debug > 2)
			debug(ctx, "File name: %s\n", name);
	}
	tag = sc_asn1_find_tag(p, len, 0x85, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_PROP_ATTR_SIZE) {
		memcpy(file->prop_attr, tag, taglen);
		file->prop_attr_len = taglen;
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(p, len, 0x86, &taglen);
	if (tag != NULL && taglen && taglen <= SC_MAX_SEC_ATTR_SIZE) {
		memcpy(file->sec_attr, tag, taglen);
		file->sec_attr_len = taglen;
	} else
		file->sec_attr_len = 0;
	file->magic = SC_FILE_MAGIC;
}

int sc_select_file(struct sc_card *card,
		   struct sc_file *file,
		   const struct sc_path *in_path, int pathtype)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	char buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;

	assert(card != NULL && in_path != NULL);
	SC_FUNC_CALLED(card->ctx);
	ctx = card->ctx;

	if (in_path->len > SC_MAX_PATH_SIZE)
		SC_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	if (in_path->len == 0)
		SC_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
	apdu.resp = buf;
	apdu.resplen = sizeof(buf);
	
	switch (pathtype) {
	case SC_SELECT_FILE_BY_FILE_ID:
		apdu.p1 = 0;
		break;
	case SC_SELECT_FILE_BY_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_SELECT_FILE_BY_PATH:
		apdu.p1 = 8;
		if (pathlen >= 2 && memcmp(path, "\x3F\x00", 2) == 0) {
			if (pathlen == 2) {	/* only 3F00 supplied */
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	default:
		SC_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0;		/* record */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file != NULL) {
		memset(file, 0, sizeof(*file));
		memcpy(&file->path.value, path, pathlen);
		file->path.len = pathlen;
	}
	if (file == NULL || sc_file_valid(file))
		apdu.no_response = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	
	if (apdu.no_response) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, 0);
		SC_FUNC_RETURN(card->ctx, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
	}

	r = sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, r);

	switch (apdu.resp[0]) {
	case 0x6F:
		if (file != NULL && apdu.resp[1] <= apdu.resplen)
			process_fci(card->ctx, file, apdu.resp+2, apdu.resp[1]);
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, 0);
	default:
		SC_FUNC_RETURN(card->ctx, SC_ERROR_UNKNOWN_RESPONSE);
	}
	SC_FUNC_RETURN(card->ctx, 0);
}

int sc_read_binary(struct sc_card *card,
		   int idx, unsigned char *buf, int count)
{
#define RB_BUF_SIZE 250
	struct sc_apdu apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	assert(card != NULL && buf != NULL);
	if (sc_debug > 2)
		debug(card->ctx, "sc_read_binary: %d bytes at index %d\n", count, idx);
	if (count == 0)
		SC_FUNC_RETURN(card->ctx, 0);
	if (count > RB_BUF_SIZE) {
		int bytes_read = 0;
		unsigned char *p = buf;

		while (count > 0) {
			int n = count > RB_BUF_SIZE ? RB_BUF_SIZE : count;
			r = sc_read_binary(card, idx, p, n);
			SC_TEST_RET(card->ctx, r, "READ BINARY failed");
			p += r;
			idx += r;
			bytes_read += r;
			count -= r;
			if (r == 0)
				SC_FUNC_RETURN(card->ctx, bytes_read);
		}
		SC_FUNC_RETURN(card->ctx, bytes_read);
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, apdu.resplen);
}

int sc_format_apdu(struct sc_card *card, struct sc_apdu *apdu,
		   unsigned char cse, unsigned char ins,
		   unsigned char p1, unsigned char p2)
{
	assert(card != NULL && apdu != NULL);
	memset(apdu, 0, sizeof(*apdu));
	apdu->cla = card->cla;
	apdu->cse = cse;
	apdu->ins = ins;
	apdu->p1 = p1;
	apdu->p2 = p2;
	apdu->no_response = 0;
	
	return 0;
}

int sc_detect_card(struct sc_context *ctx, int reader)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx);
	if (reader >= ctx->reader_count || reader < 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	rgReaderStates[0].szReader = ctx->readers[reader];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
	ret = SCardGetStatusChange(ctx->pcsc_ctx, 0, rgReaderStates, 1);
	if (ret != 0) {
		error(ctx, "SCardGetStatusChange failed: %s\n", pcsc_stringify_error(ret));
		SC_FUNC_RETURN(ctx, -1);	/* FIXME */
	}
	if (rgReaderStates[0].dwEventState & SCARD_STATE_PRESENT)
		SC_FUNC_RETURN(ctx, 1);
	SC_FUNC_RETURN(ctx, 0);
}

int sc_wait_for_card(struct sc_context *ctx, int reader, int timeout)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	int count = 0, i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx);
	if (reader >= ctx->reader_count)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (reader < 0) {
		if (ctx->reader_count == 0)
			SC_FUNC_RETURN(ctx, SC_ERROR_NO_READERS_FOUND);
		for (i = 0; i < ctx->reader_count; i++) {
			rgReaderStates[i].szReader = ctx->readers[i];
			rgReaderStates[i].dwCurrentState =
			    SCARD_STATE_EMPTY;
		}
		count = ctx->reader_count;
	} else {
		rgReaderStates[0].szReader = ctx->readers[reader];
		rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;
		count = 1;
	}
	ret = SCardGetStatusChange(ctx->pcsc_ctx, timeout, rgReaderStates,
				   count);
	if (ret != 0) {
		error(ctx, "SCardGetStatusChange failed: %s\n", pcsc_stringify_error(ret));
		SC_FUNC_RETURN(ctx, -1);
	}
	for (i = 0; i < count; i++) {
		if (rgReaderStates[i].dwEventState & SCARD_STATE_CHANGED)
			SC_FUNC_RETURN(ctx, 1);
	}
	SC_FUNC_RETURN(ctx, 0);
}

int sc_establish_context(struct sc_context **ctx_out)
{
	struct sc_context *ctx;
	LONG rv;
	DWORD reader_buf_size;
	char *reader_buf, *p;
	LPCSTR mszGroups = NULL;

	assert(ctx_out != NULL);
	ctx = malloc(sizeof(struct sc_context));
	if (ctx == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	ctx->use_std_output = 0;
	ctx->use_cache = 1;
	rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL, "localhost", NULL,
				   &ctx->pcsc_ctx);
	if (rv != SCARD_S_SUCCESS)
		return SC_ERROR_CONNECTING_TO_RES_MGR;
	SCardListReaders(ctx->pcsc_ctx, NULL, NULL,
			 (LPDWORD) & reader_buf_size);
	if (reader_buf_size < 2) {
		free(ctx);
		return SC_ERROR_NO_READERS_FOUND;
	}
	reader_buf = (char *) malloc(sizeof(char) * reader_buf_size);
	SCardListReaders(ctx->pcsc_ctx, mszGroups, reader_buf,
			 (LPDWORD) & reader_buf_size);
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

	*ctx_out = ctx;
	return 0;
}

int sc_destroy_context(struct sc_context *ctx)
{
	int i;

	assert(ctx != NULL);
	SC_FUNC_CALLED(ctx);
	for (i = 0; i < ctx->reader_count; i++)
		free(ctx->readers[i]);
	free(ctx);
	return 0;
}

static const struct sc_defaults * find_defaults(const u8 *atr, int atrlen)
{
	int i = 0;
	const struct sc_defaults *match = NULL;

	while (sc_card_table[i].atr != NULL) {
		u8 defatr[SC_MAX_ATR_SIZE];
		int len = sizeof(defatr);
		const struct sc_defaults *def = &sc_card_table[i];
		const char *atrp = def->atr;
		i++;

		if (atrp == NULL)
			break;
		if (sc_hex_to_bin(atrp, defatr, &len))
			continue;
		if (len != atrlen)
			continue;
		if (memcmp(atr, defatr, len) != 0)
			continue;
		match = def;
		break;
	}
	return match;
}

int sc_connect_card(struct sc_context *ctx,
		    int reader, struct sc_card **card_out)
{
	struct sc_card *card;
	DWORD active_proto;
	SCARDHANDLE card_handle;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	LONG rv;
	int i;
	const struct sc_defaults *defaults;

	assert(card_out != NULL);
	SC_FUNC_CALLED(ctx);
	if (reader >= ctx->reader_count || reader < 0)
		SC_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);
	
	rgReaderStates[0].szReader = ctx->readers[reader];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
	rv = SCardGetStatusChange(ctx->pcsc_ctx, 0, rgReaderStates, 1);
	if (rv != 0) {
		error(ctx, "SCardGetStatusChange failed: %s\n", pcsc_stringify_error(rv));
		SC_FUNC_RETURN(ctx, SC_ERROR_RESOURCE_MANAGER);	/* FIXME */
	}
	if (!(rgReaderStates[0].dwEventState & SCARD_STATE_PRESENT))
		SC_FUNC_RETURN(ctx, SC_ERROR_CARD_NOT_PRESENT);

	card = malloc(sizeof(struct sc_card));
	if (card == NULL)
		SC_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	memset(card, 0, sizeof(struct sc_card));
	rv = SCardConnect(ctx->pcsc_ctx, ctx->readers[reader],
			  SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0,
			  &card_handle, &active_proto);
	if (rv != 0) {
		error(ctx, "SCardConnect failed: %s\n", pcsc_stringify_error(rv));
		free(card);
		return -1;	/* FIXME */
	}
	card->reader = reader;
	card->ctx = ctx;
	card->pcsc_card = card_handle;
	i = rgReaderStates[0].cbAtr;
	if (i >= SC_MAX_ATR_SIZE)
		i = SC_MAX_ATR_SIZE;
	memcpy(card->atr, rgReaderStates[0].rgbAtr, i);
	card->atr_len = i;

	defaults = find_defaults(card->atr, card->atr_len);
	if (defaults != NULL && defaults->defaults_func != NULL) {
		defaults->defaults_func(card);
	} else {
		card->cla = 0;	/* FIXME */
	}
	pthread_mutex_init(&card->mutex, NULL);
	*card_out = card;

	return 0;
}

int sc_disconnect_card(struct sc_card *card)
{
	assert(card != NULL);
	SCardDisconnect(card->pcsc_card, SCARD_LEAVE_CARD);
	pthread_mutex_destroy(&card->mutex);
	return 0;
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
		"Card reset"
		"Required ASN.1 object not found",
		"Premature end of ASN.1 stream",
		"Too many objects",
	};
	int nr_errors = sizeof(errors) / sizeof(errors[0]);

	error -= SC_ERROR_MIN;
	if (error < 0)
		error = -error;

	if (error >= nr_errors)
		return errors[0];
	return errors[error];
}

int _sc_lock_int(struct sc_card *card)
{
	long rv;

	rv = SCardBeginTransaction(card->pcsc_card);
	
	if (rv != SCARD_S_SUCCESS) {
		error(card->ctx, "SCardBeginTransaction failed: %s\n", pcsc_stringify_error(rv));
		return -1;
	}
	return 0;
}

int sc_lock(struct sc_card *card)
{
	pthread_mutex_lock(&card->mutex);
	return _sc_lock_int(card);
}

int _sc_unlock_int(struct sc_card *card)
{
	long rv;
	
	rv = SCardEndTransaction(card->pcsc_card, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS) {
		error(card->ctx, "SCardEndTransaction failed: %s\n", pcsc_stringify_error(rv));
		return -1;
	}
	return 0;
}

int sc_unlock(struct sc_card *card)
{
	pthread_mutex_unlock(&card->mutex);
	return _sc_unlock_int(card);
}

int sc_get_random(struct sc_card *card, u8 *rnd, int len)
{
	int r;
	struct sc_apdu apdu;
	u8 buf[10];

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT,
		       0x84, 0x00, 0x00);
	apdu.le = 8;
	apdu.resp = buf;
	apdu.resplen = 8;	/* include SW's */

	while (len > 0) {
		int n = len > 8 ? 8 : len;
		
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return r;
		if (apdu.resplen != 8)
			return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
		memcpy(rnd, apdu.resp, n);
		len -= n;
		rnd += n;
	}	
	return 0;
}

int sc_list_files(struct sc_card *card, u8 *buf, int buflen)
{
	struct sc_apdu apdu;
	int r;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xAA, 0, 0);
	apdu.resp = buf;
	apdu.resplen = buflen;
	apdu.le = 0;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	if (apdu.resplen == 0)
		return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
	return apdu.resplen;
}

static int construct_fci(const struct sc_file *file, u8 *out, int *outlen)
{
	u8 *p = out;
	u8 buf[32];
	
	*p++ = 0x6F;
	p++;
	
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, 16, &p);
	buf[0] = file->shareable ? 0x40 : 0;
	buf[0] |= (file->type & 7) << 3;
	buf[0] |= file->ef_structure & 7;
	sc_asn1_put_tag(0x82, buf, 1, p, 16, &p);
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, 16, &p);
	/* 0x84 = DF name */
	if (file->prop_attr_len) {
		memcpy(buf, file->prop_attr, file->prop_attr_len);
		sc_asn1_put_tag(0x85, buf, file->prop_attr_len, p, 18, &p);
	}
	if (file->sec_attr_len) {
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len, p, 18, &p);
	}
	*p++ = 0xDE;
	*p++ = 0;
	*outlen = p - out;
	out[1] = p - out - 2;
	return 0;
}

int sc_create_file(struct sc_card *card, const struct sc_file *file)
{
	int r, len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;
	r = construct_fci(file, sbuf, &len);
	if (r)
		return r;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;

	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

int sc_delete_file(struct sc_card *card, int file_id)
{
	int r;
	u8 sbuf[2];
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	sbuf[0] = (file_id >> 8) & 0xFF;
	sbuf[1] = file_id & 0xFF;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.resp = rbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	if (apdu.resplen != 2)
		return -1;
	return sc_sw_to_errorcode(card, apdu.sw1, apdu.sw2);
}

int sc_file_valid(const struct sc_file *file)
{
	assert(file != NULL);
	
	return file->magic == SC_FILE_MAGIC;
}
