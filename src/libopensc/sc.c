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

#include "sc.h"
#include "sc-asn1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

const char *sc_version = LIBSC_VERSION;
int sc_debug = 0;

static int convert_sw_to_errorcode(u8 * sw)
{
	switch (sw[0]) {
	case 0x69:
		switch (sw[1]) {
		case 0x82:
			return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
		}
	case 0x6A:
		switch (sw[1]) {
		case 0x81:
			return SC_ERROR_NOT_SUPPORTED;
		case 0x82:
		case 0x83:
			return SC_ERROR_FILE_NOT_FOUND;
		case 0x86:
		case 0x87:
			return SC_ERROR_INVALID_ARGUMENTS;
		}
	case 0x6D:
		return SC_ERROR_NOT_SUPPORTED;
	}
	return SC_ERROR_UNKNOWN;
}

void sc_hex_dump(const u8 *buf, int count)
{
	int i;
	
	for (i = 0; i < count; i++) {
		unsigned char c = buf[i];

		printf("%02X", c);
	}
	printf("\n");
	fflush(stdout);
}

void sc_print_binary(const u8 *buf, int count)
{
	int i;
	
	for (i = 0; i < count; i++) {
		unsigned char c = buf[i];
		const char *format;
		if (!isalnum(c) && !ispunct(c) && !isspace(c))
			format = "\\x%02X";
		else
			format = "%c";
		printf(format, c);
	}
	fflush(stdout);
}

int sc_check_apdu(const struct sc_apdu *apdu)
{
	switch (apdu->cse) {
	case SC_APDU_CASE_1:
		if (apdu->datalen)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_APDU_CASE_2_SHORT:
		if (apdu->datalen)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (apdu->resplen < apdu->le)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_APDU_CASE_3_SHORT:
		if (apdu->datalen == 0 || apdu->data == NULL)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_APDU_CASE_4_SHORT:
		if (apdu->datalen == 0 || apdu->data == NULL)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (apdu->resplen < apdu->le)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_APDU_CASE_2_EXT:
	case SC_APDU_CASE_3_EXT:
	case SC_APDU_CASE_4_EXT:
		return SC_ERROR_NOT_SUPPORTED;
	}
	return 0;
}

static int sc_transceive_t0(struct sc_card *card, struct sc_apdu *apdu)
{
	SCARD_IO_REQUEST sSendPci, sRecvPci;
	BYTE s[MAX_BUFFER_SIZE], r[MAX_BUFFER_SIZE];
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
	dwRecvLength = apdu->resplen;
	if (sc_debug) {
		printf("Sending: ");
		sc_hex_dump(s, dwSendLength);
	}
	rv = SCardTransmit(card->pcsc_card, &sSendPci, s, dwSendLength,
			   &sRecvPci, r, &dwRecvLength);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr, "SCardTransmit failed with 0x%08x\n",
			(int) rv);
		return SC_ERROR_TRANSMIT_FAILED;
	}
	apdu->resplen = dwRecvLength;
	memcpy(apdu->resp, r, dwRecvLength);

	return 0;
}

int sc_transmit_apdu(struct sc_card *card, struct sc_apdu *apdu)
{
	int r;

	r = sc_check_apdu(apdu);
	if (r)
		return r;
	r = sc_transceive_t0(card, apdu);
	if (r)
		return r;
	if (sc_debug) {
		printf("Received: ");
		sc_hex_dump(apdu->resp, apdu->resplen);
	}
	if (apdu->resp[0] == 0x61 && apdu->resplen == 2) {
		struct sc_apdu rspapdu;
		BYTE rsp[MAX_BUFFER_SIZE];

		rspapdu.cla = apdu->cla;
		rspapdu.cse = SC_APDU_CASE_2_SHORT;
		rspapdu.ins = 0xC0;
		rspapdu.p1 = rspapdu.p2 = 0;
		rspapdu.le = apdu->resp[1];
		rspapdu.resp = rsp;
		rspapdu.resplen = apdu->resp[1] + 2;
		if (sc_debug)
			printf("Sending response request with %d bytes\n", rspapdu.resplen);
		r = sc_transceive_t0(card, &rspapdu);
		if (r) {
			fprintf(stderr, "Error %d when getting response\n",
				r);
			return r;
		}
		if (sc_debug) {
			printf("Response: ");
			sc_hex_dump(rspapdu.resp, rspapdu.resplen);
		}
		memcpy(apdu->resp, rspapdu.resp, rspapdu.resplen);
		apdu->resplen = rspapdu.resplen;
	}
	return 0;
}

static void sc_process_fci(struct sc_file *file,
			   const u8 *buf, int buflen)
{
	int taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	tag = sc_asn1_find_tag(p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (sc_debug)
			printf("File identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (sc_debug)
			printf("Bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	tag = sc_asn1_find_tag(p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (sc_debug)
				printf("\tShareable: %s\n",
				       (byte & 0x40) ? "yes" : "no");
			file->type = (byte >> 3) & 7;
			file->ef_structure = byte & 0x07;
			if (sc_debug) {
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
				printf("\tType: %s\n", type);
				printf("\tEF structure: %d\n",
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
		if (sc_debug)
			printf("\tFile name: %s\n", name);
	}
	file->magic = SC_FILE_MAGIC;
}

int sc_select_file(struct sc_card *card,
		   struct sc_file *file,
		   const struct sc_path *in_path, int pathtype)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	char buf[MAX_BUFFER_SIZE], cmd[15];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;

	assert(card != NULL && in_path != NULL);
	ctx = card->context;

	if (in_path->len > SC_MAX_PATH_SIZE)
		return SC_ERROR_INVALID_ARGUMENTS;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.cla = card->class;
	apdu.ins = 0xA4;
	apdu.resp = buf;
	apdu.resplen = 2;
	memcpy(cmd, "\x00\xA4", 2);
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
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.p2 = 0;		/* record */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	if (apdu.resplen < 2)
		return SC_ERROR_UNKNOWN_RESPONSE;
	if (file != NULL)
		memset(file, 0, sizeof(*file));
	switch (apdu.resp[0]) {
	case 0x6A:
		switch (apdu.resp[1]) {
		case 0x82:
			return SC_ERROR_FILE_NOT_FOUND;
		default:
			return SC_ERROR_UNKNOWN_RESPONSE;
		}
	case 0x6F:
		break;
	case 0x90:
	case 0x00:	/* proprietary coding */
		return 0;
	default:
		fprintf(stderr,
			"SELECT FILE returned SW1=%02X, SW2=%02X.\n",
			apdu.resp[0], apdu.resp[1]);
		/* FIXME */
		return SC_ERROR_UNKNOWN_RESPONSE;
	}
	if (file == NULL)
		return 0;
	if (pathtype == SC_SELECT_FILE_BY_PATH) {
		memcpy(&file->path.value, path, pathlen);
		file->path.len = pathlen;
	}
	if (apdu.resp[0] == 0x6F) {
//              int l1 = apdu.resplen - 2, l2 = apdu.resp[1];
		int l1 = apdu.resplen, l2 = apdu.resp[1];
		int len = l1 > l2 ? l2 : l1;

		sc_process_fci(file, apdu.resp + 2, len);
	}
	return 0;
}

int sc_read_binary(struct sc_card *card,
		   int idx, unsigned char *buf, int count)
{
#define RB_BUF_SIZE 250
	struct sc_apdu apdu;
	struct sc_context *ctx;
	u8 recvbuf[MAX_BUFFER_SIZE];
	int r;

	assert(card != NULL && buf != NULL);
	ctx = card->context;

	memset(&apdu, 0, sizeof(apdu));
	if (count > RB_BUF_SIZE) {
		int bytes_read = 0;
		unsigned char *p = buf;

		while (count > 0) {
			int n = count > RB_BUF_SIZE ? RB_BUF_SIZE : count;
			r = sc_read_binary(card, idx, p, n);
			if (r < 0)
				return r;
			p += r;
			idx += r;
			bytes_read += r;
			count -= r;
			if (r == 0)
				return bytes_read;
		}
		return bytes_read;
	}
	apdu.cse = SC_APDU_CASE_2_SHORT;
	apdu.cla = 0;
	apdu.ins = 0xB0;
	apdu.p1 = (idx >> 8) & 0x7f;
	apdu.p2 = idx & 0xFF;
	apdu.le = count;
	apdu.resplen = count + 2;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	if (apdu.resplen == 2) {
		return convert_sw_to_errorcode(apdu.resp);
	}
	if (apdu.resplen == count + 2)
		apdu.resplen = count;
	memcpy(buf, recvbuf, apdu.resplen);
	if (sc_debug == 2) {
		FILE *file = fopen("sc_recv", "w");
		if (file != NULL) {
			fwrite(buf, apdu.resplen, 1, file);
			fclose(file);
		}
	}
	return apdu.resplen;
}

int sc_format_apdu(struct sc_card *card,
		   struct sc_apdu *apdu,
		   unsigned char cse,
		   unsigned char ins, unsigned char p1, unsigned char p2)
{
	assert(card != NULL && apdu != NULL);
	memset(apdu, 0, sizeof(*apdu));
	apdu->cla = card->class;
	apdu->cse = cse;
	apdu->ins = ins;
	apdu->p1 = p1;
	apdu->p2 = p2;
	return 0;
}

int sc_detect_card(struct sc_context *ctx, int reader)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];

	assert(ctx != NULL);
	if (reader >= ctx->reader_count || reader < 0)
		return SC_ERROR_INVALID_ARGUMENTS;

	rgReaderStates[0].szReader = ctx->readers[reader];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
	ret = SCardGetStatusChange(ctx->pcsc_ctx, 0, rgReaderStates, 1);
	if (ret != 0)
		return -1;	/* FIXME */
	if (rgReaderStates[0].dwEventState & SCARD_STATE_PRESENT)
		return 1;
	return 0;
}

int sc_wait_for_card(struct sc_context *ctx, int reader, int timeout)
{
	LONG ret;
	SCARD_READERSTATE_A rgReaderStates[SC_MAX_READERS];
	int count = 0, i;

	assert(ctx != NULL);
	if (reader >= ctx->reader_count)
		return SC_ERROR_INVALID_ARGUMENTS;

	if (reader < 0) {
		if (ctx->reader_count == 0)
			return SC_ERROR_NO_READERS_FOUND;
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
	if (ret != 0)
		return -1;	/* FIXME */
	for (i = 0; i < count; i++) {
		if (rgReaderStates[i].dwEventState & SCARD_STATE_CHANGED)
			return 1;
	}
	return 0;
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
	rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL, "localhost", NULL,
				   &ctx->pcsc_ctx);
	if (rv != SCARD_S_SUCCESS) {
		fprintf(stderr,
			"ERROR: Cannot connect to Resource Manager\n");
		return SC_ERROR_CONNECTING_TO_RES_MGR;
	}
	SCardListReaders(ctx->pcsc_ctx, NULL, NULL,
			 (LPDWORD) & reader_buf_size);
	if (reader_buf_size == 0) {
		fprintf(stderr, "No readers found!\n");
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
	for (i = 0; i < ctx->reader_count; i++)
		free(ctx->readers[i]);
	free(ctx);
	return 0;
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

	assert(card_out != NULL);
	if (reader >= ctx->reader_count || reader < 0)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	rgReaderStates[0].szReader = ctx->readers[reader];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
	rv = SCardGetStatusChange(ctx->pcsc_ctx, 0, rgReaderStates, 1);
	if (rv != 0)
		return SC_ERROR_RESOURCE_MANAGER;	/* FIXME */
	if (!(rgReaderStates[0].dwEventState & SCARD_STATE_PRESENT))
		return SC_ERROR_CARD_NOT_PRESENT;

	card = malloc(sizeof(struct sc_card));
	if (card == NULL)
		return SC_ERROR_OUT_OF_MEMORY;
	memset(card, 0, sizeof(struct sc_card));
	rv = SCardConnect(ctx->pcsc_ctx, ctx->readers[reader],
			  SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0,
			  &card_handle, &active_proto);
	if (rv != 0) {
		free(card);
		return -1;	/* FIXME */
	}
	card->pcsc_card = card_handle;
	i = rgReaderStates[0].cbAtr;
	if (i >= SC_MAX_ATR_SIZE)
		i = SC_MAX_ATR_SIZE;
	memcpy(card->atr, rgReaderStates[0].rgbAtr, i);
	card->atr_len = i;
	card->class = 0;	/* FIXME */
	card->reader = ctx->readers[reader];
	*card_out = card;

	return 0;
}

int sc_disconnect_card(struct sc_card *card)
{
	assert(card != NULL);
	SCardDisconnect(card->pcsc_card, SCARD_LEAVE_CARD);
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
		"Buffer too small",

	};
	int nr_errors = sizeof(errors) / sizeof(errors[0]);

	error -= SC_ERROR_MIN;
	if (error < 0)
		error = -error;

	if (error >= nr_errors)
		return errors[0];
	return errors[error];
}

int sc_set_security_env(struct sc_card *card,
			const struct sc_security_env *env)
{
	struct sc_apdu apdu;
	u8 recv[MAX_BUFFER_SIZE], send[MAX_BUFFER_SIZE];
	u8 *p;
	int r;
	struct sc_file file;

	assert(card != NULL && env != NULL);
	r = sc_select_file(card, &file, &env->app_df_path,
			   SC_SELECT_FILE_BY_PATH);
	if (r)
		return r;
	apdu.cla = card->class;
	apdu.cse = SC_APDU_CASE_3_SHORT;
	apdu.ins = 0x22;
	if (env->signature) {
		apdu.p1 = 0x81;
		apdu.p2 = 0xB6;
	} else {
		apdu.p1 = 0x41;
		apdu.p2 = 0xB8;
	}
	apdu.le = 0;
	p = send;
	*p++ = 0x80;		/* algorithm reference */
	*p++ = 1;
	*p++ = env->algorithm_ref;
	*p++ = 0x81;
	*p++ = env->key_file_id.len;
	memcpy(p, env->key_file_id.value, env->key_file_id.len);
	p += env->key_file_id.len;
	*p++ = 0x84;
	*p++ = 1;
	*p++ = env->key_ref;
	r = p - send;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = send;
	apdu.resplen = 2;
	apdu.resp = recv;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	if (apdu.resp[0] != 0x90) {
		fprintf(stderr, "Set sec env: SWs=%02X%02X\n",
			apdu.resp[0], apdu.resp[1]);
		return -1;
	}
	return 0;
}

int sc_decipher(struct sc_card *card,
		const u8 * crgram, int crgram_len, u8 * out, int outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 recv[MAX_BUFFER_SIZE];
	u8 send[MAX_BUFFER_SIZE], *p;

	assert(card != NULL && crgram != NULL && out != NULL);
	if (crgram_len > 255)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80,
		       0x86);
	apdu.resp = recv;
	apdu.resplen = 2;

	send[0] = 0; /* padding indicator byte */ ;
	memcpy(send + 1, crgram, crgram_len);
	apdu.data = send;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	p = apdu.resp + apdu.resplen - 2;
	if (p[0] == 0x90 && p[1] == 0x00) {	/* FIXME */
		int l1 = apdu.resplen - 2, l2 = outlen;
		int len = l1 > l2 ? l2 : l1;

		memcpy(out, apdu.resp, len);
		return len;
	}
	fprintf(stderr, "sc_decipher(): SW1=%02X, SW2=%02X\n", p[0], p[1]);
	return convert_sw_to_errorcode(p);
}

int sc_compute_signature(struct sc_card *card,
			 const u8 * data,
			 int datalen, u8 * out, int outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 recv[MAX_BUFFER_SIZE], *p;
	u8 send[MAX_BUFFER_SIZE];

	assert(card != NULL && data != NULL && out != NULL);
	if (datalen > 255)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x9E,
		       0x9A);
	apdu.resp = recv;
	apdu.resplen = 2;

	memcpy(send, data, datalen);
	apdu.data = send;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	p = apdu.resp + apdu.resplen - 2;
	if (p[0] == 0x90 && p[1] == 0x00) {	/* FIXME */
		int l1 = apdu.resplen - 2, l2 = outlen;
		int len = l1 > l2 ? l2 : l1;

		memcpy(out, apdu.resp, len);
		return len;
	}
	fprintf(stderr, "sc_compute_signature(): SW1=%02X, SW2=%02X\n",
		p[0], p[1]);
	return convert_sw_to_errorcode(p);
}

int sc_lock(struct sc_card *card)
{
	long rv;
	
	rv = SCardBeginTransaction(card->pcsc_card);
	
	if (rv != SCARD_S_SUCCESS)
		return -1;
	
	return 0;
}

int sc_unlock(struct sc_card *card)
{
	long rv;
	
	rv = SCardEndTransaction(card->pcsc_card, SCARD_LEAVE_CARD);
	if (rv != SCARD_S_SUCCESS)
		return -1;
	return 0;
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
	apdu.resplen = 10;	/* include SW's */

	while (len > 0) {
		int n = len > 8 ? 8 : len;
		
		r = sc_transmit_apdu(card, &apdu);
		if (r)
			return r;
		if (apdu.resplen != 10) {
			if (apdu.resplen == 2)
				return convert_sw_to_errorcode(apdu.resp);
			return SC_ERROR_UNKNOWN;
		}
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
	if (apdu.resplen < 2)
		return -1; /* FIXME */
	if (apdu.resplen == 2)
		return convert_sw_to_errorcode(apdu.resp);
	apdu.resplen -= 2;

	return apdu.resplen;
}

int sc_file_valid(const struct sc_file *file)
{
	assert(file != NULL);
	
	return file->magic == SC_FILE_MAGIC;
}
