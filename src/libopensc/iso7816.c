/*
 * iso7816.c: Functions specified by the ISO 7816 standard
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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
#include "asn1.h"
#include <assert.h>
#include <ctype.h>
#include <string.h>

const static struct sc_card_error iso7816_errors[] = {
	{ 0x6200, SC_ERROR_MEMORY_FAILURE,	"State of non-volatile memory unchanged" },
	{ 0x6281, SC_ERROR_MEMORY_FAILURE,	"Part of returned data may be corrupted" },
	{ 0x6282, SC_ERROR_CARD_CMD_FAILED,	"End of file/record reached before reading Le bytes" },
	{ 0x6283, SC_ERROR_CARD_CMD_FAILED,	"Selected file invalidated" },
	{ 0x6284, SC_ERROR_CARD_CMD_FAILED,	"FCI not formatted according to ISO 7816-4" },

	{ 0x6300, SC_ERROR_MEMORY_FAILURE,	"State of non-volatile memory changed" },
	{ 0x6381, SC_ERROR_CARD_CMD_FAILED,	"File filled up by last write" },

	{ 0x6581, SC_ERROR_MEMORY_FAILURE,	"Memory failure" },

	{ 0x6700, SC_ERROR_WRONG_LENGTH,	"Wrong length" },

	{ 0x6800, SC_ERROR_NO_CARD_SUPPORT,	"Functions in CLA not supported" },
	{ 0x6881, SC_ERROR_NO_CARD_SUPPORT,	"Logical channel not supported" },
	{ 0x6882, SC_ERROR_NO_CARD_SUPPORT,	"Secure messaging not supported" },

	{ 0x6900, SC_ERROR_NOT_ALLOWED,		"Command not allowed" },
	{ 0x6981, SC_ERROR_CARD_CMD_FAILED,	"Command incompatible with file structure" },
	{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied" },
	{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED,	"Authentication method blocked" },
	{ 0x6984, SC_ERROR_CARD_CMD_FAILED,	"Referenced data invalidated" },
	{ 0x6985, SC_ERROR_NOT_ALLOWED,		"Conditions of use not satisfied" },
	{ 0x6986, SC_ERROR_NOT_ALLOWED,		"Command not allowed (no current EF)" },
	{ 0x6987, SC_ERROR_INCORRECT_PARAMETERS,"Expected SM data objects missing" },
	{ 0x6988, SC_ERROR_INCORRECT_PARAMETERS,"SM data objects incorrect" },

	{ 0x6A00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
	{ 0x6A80, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters in the data field" },
	{ 0x6A81, SC_ERROR_NO_CARD_SUPPORT,	"Function not supported" },
	{ 0x6A82, SC_ERROR_FILE_NOT_FOUND,	"File not found" },
	{ 0x6A83, SC_ERROR_RECORD_NOT_FOUND,	"Record not found" },
	{ 0x6A84, SC_ERROR_CARD_CMD_FAILED,	"Not enough memory space in the file" },
	{ 0x6A85, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with TLV structure" },
	{ 0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters P1-P2" },
	{ 0x6A87, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with P1-P2" },
	{ 0x6A88, SC_ERROR_DATA_OBJECT_NOT_FOUND,"Referenced data not found" },

	{ 0x6B00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
	{ 0x6D00, SC_ERROR_INS_NOT_SUPPORTED,	"Instruction code not supported or invalid" },
	{ 0x6E00, SC_ERROR_CLASS_NOT_SUPPORTED,	"Class not supported" },
	{ 0x6F00, SC_ERROR_CARD_CMD_FAILED,	"No precise diagnosis" },

	/* Possibly TCOS / Micardo specific errors */
	{ 0x6600, SC_ERROR_INCORRECT_PARAMETERS, "Error setting the security env"},
	{ 0x66F0, SC_ERROR_INCORRECT_PARAMETERS, "No space left for padding"},
	{ 0x69F0, SC_ERROR_NOT_ALLOWED,          "Command not allowed"},
	{ 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS,  "Files exists"},
	{ 0x6A8A, SC_ERROR_FILE_ALREADY_EXISTS,  "Application exists"},
};

int iso7816_check_sw(struct sc_card *card, int sw1, int sw2)
{
	const int err_count = sizeof(iso7816_errors)/sizeof(iso7816_errors[0]);
	int i;
	
	/* Handle special cases here */
	if (sw1 == 0x6C) {
		sc_error(card->ctx, "Wrong length; correct length is %d\n", sw2);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (sw1 == 0x90)
		return SC_NO_ERROR;
        if (sw1 == 0x63 && (sw2 & ~0x0f) == 0xc0 ) {
             sc_error(card->ctx, "Verification failed (remaining tries: %d)\n",
                   (sw2 & 0x0f));
             return SC_ERROR_PIN_CODE_INCORRECT;
        }
	for (i = 0; i < err_count; i++)
		if (iso7816_errors[i].SWs == ((sw1 << 8) | sw2)) {
			sc_error(card->ctx, "%s\n", iso7816_errors[i].errorstr);
			return iso7816_errors[i].errorno;
		}
	sc_error(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}

static int iso7816_read_binary(struct sc_card *card,
			       unsigned int idx, u8 *buf, size_t count,
			       unsigned long flags)
{
	struct sc_apdu apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	assert(count <= card->max_recv_size);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, 3, apdu.resplen);
}

static int iso7816_read_record(struct sc_card *card,
			       unsigned int rec_nr, u8 *buf, size_t count,
			       unsigned long flags)
{
	struct sc_apdu apdu;
	u8 recvbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB2, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = recvbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
	memcpy(buf, recvbuf, apdu.resplen);

	SC_FUNC_RETURN(card->ctx, 3, apdu.resplen);
}

static int iso7816_write_record(struct sc_card *card, unsigned int rec_nr,
			        const u8 *buf, size_t count,
			        unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (count > 256) {
		sc_error(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD2, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static int iso7816_append_record(struct sc_card *card,
				 const u8 *buf, size_t count,
				 unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (count > 256) {
		sc_error(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE2, 0, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static int iso7816_update_record(struct sc_card *card, unsigned int rec_nr,
				 const u8 *buf, size_t count,
				 unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (count > 256) {
		sc_error(card->ctx, "Trying to send too many bytes\n");
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDC, rec_nr, 0);
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;
	
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static int iso7816_write_binary(struct sc_card *card,
				unsigned int idx, const u8 *buf,
				size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	assert(count <= card->max_send_size);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

static int iso7816_update_binary(struct sc_card *card,
				 unsigned int idx, const u8 *buf,
				size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	assert(count <= card->max_send_size);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xD6,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	SC_TEST_RET(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2),
		    "Card returned error");
	SC_FUNC_RETURN(card->ctx, 3, count);
}

int iso7816_process_fci(struct sc_card *card, struct sc_file *file,
		       const u8 *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen, len = buflen;
	const u8 *tag = NULL, *p = buf;

	if (ctx->debug >= 3)
		sc_debug(ctx, "processing FCI bytes\n");
	tag = sc_asn1_find_tag(ctx, p, len, 0x83, &taglen);
	if (tag != NULL && taglen == 2) {
		file->id = (tag[0] << 8) | tag[1];
		if (ctx->debug >= 3)
			sc_debug(ctx, "  file identifier: 0x%02X%02X\n", tag[0],
			       tag[1]);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x81, &taglen);
	if (tag != NULL && taglen >= 2) {
		int bytes = (tag[0] << 8) + tag[1];
		if (ctx->debug >= 3)
			sc_debug(ctx, "  bytes in file: %d\n", bytes);
		file->size = bytes;
	}
	if (tag == NULL) {
		tag = sc_asn1_find_tag(ctx, p, len, 0x80, &taglen);
		if (tag != NULL && taglen >= 2) {
			int bytes = (tag[0] << 8) + tag[1];
			if (ctx->debug >= 3)
				sc_debug(ctx, "  bytes in file: %d\n", bytes);
			file->size = bytes;
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x82, &taglen);
	if (tag != NULL) {
		if (taglen > 0) {
			unsigned char byte = tag[0];
			const char *type;

			file->shareable = byte & 0x40 ? 1 : 0;
			if (ctx->debug >= 3)
				sc_debug(ctx, "  shareable: %s\n",
				       (byte & 0x40) ? "yes" : "no");
			file->ef_structure = byte & 0x07;
			switch ((byte >> 3) & 7) {
			case 0:
				type = "working EF";
				file->type = SC_FILE_TYPE_WORKING_EF;
				break;
			case 1:
				type = "internal EF";
				file->type = SC_FILE_TYPE_INTERNAL_EF;
				break;
			case 7:
				type = "DF";
				file->type = SC_FILE_TYPE_DF;
				break;
			default:
				type = "unknown";
				break;
			}
			if (ctx->debug >= 3) {
				sc_debug(ctx, "  type: %s\n", type);
				sc_debug(ctx, "  EF structure: %d\n",
				       byte & 0x07);
			}
		}
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x84, &taglen);
	if (tag != NULL && taglen > 0 && taglen <= 16) {
		char name[17];
		size_t i;

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
		if (ctx->debug >= 3)
			sc_debug(ctx, "File name: %s\n", name);
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x85, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	} else
		file->prop_attr_len = 0;
	tag = sc_asn1_find_tag(ctx, p, len, 0xA5, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_prop_attr(file, tag, taglen); 
	}
	tag = sc_asn1_find_tag(ctx, p, len, 0x86, &taglen);
	if (tag != NULL && taglen) {
		sc_file_set_sec_attr(file, tag, taglen); 
	}
	file->magic = SC_FILE_MAGIC;

	return 0;
}

static int iso7816_select_file(struct sc_card *card,
			       const struct sc_path *in_path,
			       struct sc_file **file_out)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	u8 buf[SC_MAX_APDU_BUFFER_SIZE];
	u8 pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathlen;
	struct sc_file *file = NULL;

	assert(card != NULL && in_path != NULL);
	ctx = card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);
	
	switch (in_path->type) {
	case SC_PATH_TYPE_FILE_ID:
		apdu.p1 = 0;
		if (pathlen != 2)
			return SC_ERROR_INVALID_ARGUMENTS;
		break;
	case SC_PATH_TYPE_DF_NAME:
		apdu.p1 = 4;
		break;
	case SC_PATH_TYPE_PATH:
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
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.p2 = 0;		/* first record, return FCI */
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = 256;
	} else {
		apdu.resplen = 0;
		apdu.le = 0;
		apdu.cse = SC_APDU_CASE_3_SHORT;
	}
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (file_out == NULL) {
		if (apdu.sw1 == 0x61)
			SC_FUNC_RETURN(card->ctx, 2, 0);
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		SC_FUNC_RETURN(card->ctx, 2, r);

	switch (apdu.resp[0]) {
	case 0x6F:
		file = sc_file_new();
		if (file == NULL)
			SC_FUNC_RETURN(card->ctx, 0, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		if (card->ops->process_fci == NULL)
			SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
		if (apdu.resp[1] <= apdu.resplen)
			card->ops->process_fci(card, file, apdu.resp+2, apdu.resp[1]);
		*file_out = file;
		break;
	case 0x00:	/* proprietary coding */
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	default:
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}
	return 0;
}

static int iso7816_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
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
		SC_TEST_RET(card->ctx, r, "APDU transmit failed");
		if (apdu.resplen != 8)
			return sc_check_sw(card, apdu.sw1, apdu.sw2);
		memcpy(rnd, apdu.resp, n);
		len -= n;
		rnd += n;
	}	
	return 0;
}

static int iso7816_construct_fci(struct sc_card *card, const struct sc_file *file,
	u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];
	
	*p++ = 0x6F;
	p++;
	
	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, 16, &p);

	if (file->type_attr_len) {
		memcpy(buf, file->type_attr, file->type_attr_len);
		sc_asn1_put_tag(0x82, buf, file->type_attr_len, p, 16, &p);
	} else {
		buf[0] = file->shareable ? 0x40 : 0;
		switch (file->type) {
		case SC_FILE_TYPE_WORKING_EF:
			break;
		case SC_FILE_TYPE_INTERNAL_EF:
			buf[0] |= 0x08;
			break;
		case SC_FILE_TYPE_DF:
			buf[0] |= 0x38;
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		buf[0] |= file->ef_structure & 7;
		sc_asn1_put_tag(0x82, buf, 1, p, 16, &p);
	}
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
	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}

static int iso7816_create_file(struct sc_card *card, struct sc_file *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;

	if (card->ops->construct_fci == NULL)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->construct_fci(card, file, sbuf, &len);
	SC_TEST_RET(card->ctx, r, "construct_fci() failed");
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int iso7816_get_response(struct sc_card *card, sc_apdu_t *orig_apdu, size_t count)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xC0, 0x00, 0x00);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = orig_apdu->resp;

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.resplen == 0)
		SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));

	if (apdu.resplen != count) {
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_WRONG_LENGTH);
	}

	orig_apdu->resplen = apdu.resplen;
	orig_apdu->sw1 = 0x90;
	orig_apdu->sw2 = 0x00;

	SC_FUNC_RETURN(card->ctx, 3, apdu.resplen);
}

static int iso7816_delete_file(struct sc_card *card, const struct sc_path *path)
{
	int r;
	u8 sbuf[2];
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, 1);
	if (path->type != SC_PATH_TYPE_FILE_ID && path->len != 2) {
		sc_error(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID\n");
		SC_FUNC_RETURN(card->ctx, 1, SC_ERROR_INVALID_ARGUMENTS);
	}
	sbuf[0] = path->value[0];
	sbuf[1] = path->value[1];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	apdu.lc = 2;
	apdu.datalen = 2;
	apdu.data = sbuf;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int iso7816_set_security_env(struct sc_card *card,
				    const struct sc_security_env *env,
				    int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	assert(card != NULL && env != NULL);
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p1 = 0x81;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p1 = 0x41;
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	apdu.le = 0;
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		*p++ = 0x81;
		*p++ = env->file_ref.len;
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env->flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env->key_ref_len;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = p - sbuf;
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	apdu.resplen = 0;
	if (se_num > 0) {
		r = sc_lock(card);
		SC_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_perror(card->ctx, r, "APDU transmit failed");
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_perror(card->ctx, r, "Card returned error");
			goto err;
		}
	}
	if (se_num <= 0)
		return 0;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}

static int iso7816_restore_security_env(struct sc_card *card, int se_num)
{
	struct sc_apdu apdu;
	int r;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	
	assert(card != NULL);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0xF3, se_num);
	apdu.resplen = sizeof(rbuf) > 250 ? 250 : sizeof(rbuf);
	apdu.resp = rbuf;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	return sc_check_sw(card, apdu.sw1, apdu.sw2);
}

static int iso7816_compute_signature(struct sc_card *card,
				     const u8 * data, size_t datalen,
				     u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && data != NULL && out != NULL);
	if (datalen > 255)
		SC_FUNC_RETURN(card->ctx, 4, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E,
		       0x9A);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf); /* FIXME */
	apdu.le = 256;

	memcpy(sbuf, data, datalen);
	apdu.data = sbuf;
	apdu.lc = datalen;
	apdu.datalen = datalen;
	apdu.sensitive = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		int len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 4, len);
	}
	SC_FUNC_RETURN(card->ctx, 4, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int iso7816_decipher(struct sc_card *card,
			    const u8 * crgram, size_t crgram_len,
			    u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];

	assert(card != NULL && crgram != NULL && out != NULL);
	SC_FUNC_CALLED(card->ctx, 2);
	if (crgram_len > 255)
		SC_FUNC_RETURN(card->ctx, 2, SC_ERROR_INVALID_ARGUMENTS);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf); /* FIXME */
	apdu.le = crgram_len;
	apdu.sensitive = 1;
	
	sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		int len = apdu.resplen > outlen ? outlen : apdu.resplen;

		memcpy(out, apdu.resp, len);
		SC_FUNC_RETURN(card->ctx, 2, len);
	}
	SC_FUNC_RETURN(card->ctx, 2, sc_check_sw(card, apdu.sw1, apdu.sw2));
}

static int iso7816_build_pin_apdu(struct sc_card *card,
		struct sc_apdu *apdu,
		struct sc_pin_cmd_data *data)
{
	static u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int r, len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0;
	
	switch (data->pin_type) {
	case SC_AC_CHV:
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (data->flags & SC_PIN_CMD_NEED_PADDING)
		pad = 1;
	if (data->flags & SC_PIN_CMD_USE_PINPAD)
		use_pin_pad = 1;

	data->pin1.offset = 5;

	switch (data->cmd) {
	case SC_PIN_CMD_VERIFY:
		ins = 0x20;
		if ((r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
			return r;
		len = r;
		break;
	case SC_PIN_CMD_CHANGE:
		ins = 0x24;
		if (data->pin1.len != 0 || use_pin_pad) {
			if ((r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			/* implicit test */
			p1 = 1;
		}

		data->pin2.offset = data->pin1.offset + len;
		if ((r = sc_build_pin(sbuf+len, sizeof(sbuf)-len, &data->pin2, pad)) < 0)
			return r;
		len += r;
		break;
	case SC_PIN_CMD_UNBLOCK:
		ins = 0x2C;
		if (data->pin1.len != 0 || use_pin_pad) {
			if ((r = sc_build_pin(sbuf, sizeof(sbuf), &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x02;
		}

		if (data->pin2.len != 0 || use_pin_pad) {
			data->pin2.offset = data->pin1.offset + len;
			if ((r = sc_build_pin(sbuf+len, sizeof(sbuf)-len, &data->pin2, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x01;
		}
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT,
				ins, p1, data->pin_reference);

	apdu->lc = len;
	apdu->datalen = len;
	apdu->data = sbuf;
	apdu->resplen = 0;
	apdu->sensitive = 1;

	return 0;
}

static int iso7816_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data,
			   int *tries_left)
{
	struct sc_apdu local_apdu, *apdu;
	int r;

	if (tries_left)
		*tries_left = -1;

	/* See if we've been called from another card driver, which is
	 * passing an APDU to us (this allows to write card drivers
	 * whose PIN functions behave "mostly like ISO" except in some
	 * special circumstances.
	 */
	if (data->apdu == NULL) {
		r = iso7816_build_pin_apdu(card, &local_apdu, data);
		if (r < 0)
			return r;
		data->apdu = &local_apdu;
	}
	apdu = data->apdu;

	if (!(data->flags & SC_PIN_CMD_USE_PINPAD)) {
		/* Transmit the APDU to the card */
		r = sc_transmit_apdu(card, apdu);

		/* Clear the buffer - it may contain pins */
		memset((void *) apdu->data, 0, apdu->datalen);
	} else {
		/* Call the reader driver to collect
		 * the PIN and pass on the APDU to the card */
		if (data->pin1.offset == 0) {
			sc_error(card->ctx,
				"Card driver didn't set PIN offset");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (card->reader
		 && card->reader->ops
		 && card->reader->ops->perform_verify) {
			r = card->reader->ops->perform_verify(card->reader,
					card->slot,
					data);
			/* sw1/sw2 filled in by reader driver */
		} else {
			sc_error(card->ctx,
				"Card reader driver does not support "
				"PIN entry through reader key pad");
			r = SC_ERROR_NOT_SUPPORTED;
		}
	}

	/* Don't pass references to local variables up to the caller. */
	if (data->apdu == &local_apdu)
		data->apdu = NULL;

	SC_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu->sw1 == 0x63) {
		if ((apdu->sw2 & 0xF0) == 0xC0 && tries_left != NULL)
			*tries_left = apdu->sw2 & 0x0F;
		return SC_ERROR_PIN_CODE_INCORRECT;
	}
	return sc_check_sw(card, apdu->sw1, apdu->sw2);
}

/*
 * For some cards, selecting the MF clears all access rights gained
 */
static int iso7816_logout(struct sc_card *card)
{
	struct sc_path in_path;
	in_path.value[0] = 0x3F;
	in_path.value[1] = 0x00;
	in_path.len = 2;
	in_path.index = 0;
	in_path.count = 2;
	in_path.type = SC_PATH_TYPE_PATH;

	/* Force the SELECT FILE even if the card thinks
	 * it's already inside the MF */
	card->cache_valid = 0;

	return sc_select_file(card, &in_path, NULL);
}

static struct sc_card_operations iso_ops = {
	NULL,
};

static struct sc_card_driver iso_driver = {
	"ISO 7816 reference driver",
	"iso7816",
	&iso_ops
};

static int no_match(struct sc_card *card)
{
	return 0;
}

struct sc_card_driver * sc_get_iso7816_driver(void)
{
	if (iso_ops.match_card == NULL) {
		memset(&iso_ops, 0, sizeof(iso_ops));
		iso_ops.match_card    = no_match;
		iso_ops.read_binary   = iso7816_read_binary;
		iso_ops.read_record   = iso7816_read_record;
		iso_ops.write_record  = iso7816_write_record;
		iso_ops.append_record = iso7816_append_record;
		iso_ops.update_record = iso7816_update_record;
		iso_ops.write_binary  = iso7816_write_binary;
		iso_ops.update_binary = iso7816_update_binary;
		iso_ops.select_file   = iso7816_select_file;
		iso_ops.get_challenge = iso7816_get_challenge;
		iso_ops.create_file   = iso7816_create_file;
		iso_ops.get_response   = iso7816_get_response;
		iso_ops.delete_file   = iso7816_delete_file;
		iso_ops.set_security_env	= iso7816_set_security_env;
		iso_ops.restore_security_env	= iso7816_restore_security_env;
		iso_ops.compute_signature	= iso7816_compute_signature;
		iso_ops.decipher		= iso7816_decipher;
		iso_ops.check_sw      = iso7816_check_sw;
		iso_ops.pin_cmd	      = iso7816_pin_cmd;
		iso_ops.logout        = iso7816_logout;
		iso_ops.process_fci   = iso7816_process_fci;
		iso_ops.construct_fci   = iso7816_construct_fci;
	}
	return &iso_driver;
}
