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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "asn1.h"
#include "iso7816.h"
#include "sm/sm-iso.h"

void
iso7816_fixup_transceive_length(const struct sc_card *card,
		struct sc_apdu *apdu)
{
	if (card == NULL || apdu == NULL) {
		return;
	}

	if (apdu->lc > sc_get_max_send_size(card)) {
		/* The lower layers will automatically do chaining */
		apdu->flags |= SC_APDU_FLAGS_CHAINING;
	}

	if (apdu->le > sc_get_max_recv_size(card)) {
		/* The lower layers will automatically do a GET RESPONSE, if possible.
		 * All other workarounds must be carried out by the upper layers. */
		apdu->le = sc_get_max_recv_size(card);
	}
}


static const struct sc_card_error iso7816_errors[] = {
	{ 0x6200, SC_ERROR_CARD_CMD_FAILED,	"Warning: no information given, non-volatile memory is unchanged" },
	{ 0x6281, SC_ERROR_CORRUPTED_DATA,	"Part of returned data may be corrupted" },
	{ 0x6282, SC_ERROR_FILE_END_REACHED,	"End of file/record reached before reading Le bytes" },
	{ 0x6283, SC_ERROR_CARD_CMD_FAILED,	"Selected file invalidated" },
	{ 0x6284, SC_ERROR_CARD_CMD_FAILED,	"FCI not formatted according to ISO 7816-4" },
	{ 0x6285, SC_ERROR_CARD_CMD_FAILED,	"Selected file in termination state" },
	{ 0x6286, SC_ERROR_CARD_CMD_FAILED,	"No input data available from a sensor on the card" },

	{ 0x6300, SC_ERROR_CARD_CMD_FAILED,	"Warning: no information given, non-volatile memory has changed" },
	{ 0x6381, SC_ERROR_CARD_CMD_FAILED,	"Warning: file filled up by last write" },

	{ 0x6400, SC_ERROR_CARD_CMD_FAILED,	"Execution error" },
	{ 0x6401, SC_ERROR_CARD_CMD_FAILED,	"Immediate response required by the card" },

	{ 0x6581, SC_ERROR_MEMORY_FAILURE,	"Memory failure" },

	{ 0x6700, SC_ERROR_WRONG_LENGTH,	"Wrong length" },

	{ 0x6800, SC_ERROR_NO_CARD_SUPPORT,	"Functions in CLA not supported" },
	{ 0x6881, SC_ERROR_NO_CARD_SUPPORT,	"Logical channel not supported" },
	{ 0x6882, SC_ERROR_NO_CARD_SUPPORT,	"Secure messaging not supported" },
	{ 0x6883, SC_ERROR_CARD_CMD_FAILED,	"Last command of the chain expected" },
	{ 0x6884, SC_ERROR_NO_CARD_SUPPORT,	"Command chaining not supported" },

	{ 0x6900, SC_ERROR_NOT_ALLOWED,		"Command not allowed" },
	{ 0x6981, SC_ERROR_CARD_CMD_FAILED,	"Command incompatible with file structure" },
	{ 0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,"Security status not satisfied" },
	{ 0x6983, SC_ERROR_AUTH_METHOD_BLOCKED,	"Authentication method blocked" },
	{ 0x6984, SC_ERROR_REF_DATA_NOT_USABLE,	"Referenced data not usable" },
	{ 0x6985, SC_ERROR_NOT_ALLOWED,		"Conditions of use not satisfied" },
	{ 0x6986, SC_ERROR_NOT_ALLOWED,		"Command not allowed (no current EF)" },
	{ 0x6987, SC_ERROR_INCORRECT_PARAMETERS,"Expected SM data objects missing" },
	{ 0x6988, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect SM data objects" },

	{ 0x6A00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
	{ 0x6A80, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters in the data field" },
	{ 0x6A81, SC_ERROR_NO_CARD_SUPPORT,	"Function not supported" },
	{ 0x6A82, SC_ERROR_FILE_NOT_FOUND,	"File or application not found" },
	{ 0x6A83, SC_ERROR_RECORD_NOT_FOUND,	"Record not found" },
	{ 0x6A84, SC_ERROR_NOT_ENOUGH_MEMORY,	"Not enough memory space in the file" },
	{ 0x6A85, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with TLV structure" },
	{ 0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters P1-P2" },
	{ 0x6A87, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with P1-P2" },
	{ 0x6A88, SC_ERROR_DATA_OBJECT_NOT_FOUND,"Referenced data not found" },
	{ 0x6A89, SC_ERROR_FILE_ALREADY_EXISTS,	"File already exists"},
	{ 0x6A8A, SC_ERROR_FILE_ALREADY_EXISTS,	"DF name already exists"},

	{ 0x6B00, SC_ERROR_INCORRECT_PARAMETERS,"Wrong parameter(s) P1-P2" },
	{ 0x6D00, SC_ERROR_INS_NOT_SUPPORTED,	"Instruction code not supported or invalid" },
	{ 0x6E00, SC_ERROR_CLASS_NOT_SUPPORTED,	"Class not supported" },
	{ 0x6F00, SC_ERROR_CARD_CMD_FAILED,	"No precise diagnosis" },
};


static int
iso7816_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	const int err_count = sizeof(iso7816_errors)/sizeof(iso7816_errors[0]);
	int i;

	/* Handle special cases here */
	if (sw1 == 0x6C) {
		sc_log(card->ctx, "Wrong length; correct length is %d", sw2);
		return SC_ERROR_WRONG_LENGTH;
	}
	if (sw1 == 0x90 && sw2 == 0x00)
		return SC_SUCCESS;
	if (sw1 == 0x63U && (sw2 & ~0x0fU) == 0xc0U) {
		sc_log(card->ctx, "PIN not verified (remaining tries: %d)", (sw2 & 0x0f));
		return SC_ERROR_PIN_CODE_INCORRECT;
	}
	for (i = 0; i < err_count; i++)   {
		if (iso7816_errors[i].SWs == ((sw1 << 8) | sw2)) {
			sc_log(card->ctx, "%s", iso7816_errors[i].errorstr);
			return iso7816_errors[i].errorno;
		}
	}

	sc_log(card->ctx, "Unknown SWs; SW1=%02X, SW2=%02X", sw1, sw2);
	return SC_ERROR_CARD_CMD_FAILED;
}


static int
iso7816_read_binary(struct sc_card *card, unsigned int idx, u8 *buf, size_t count, unsigned long *flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int r;

	if (idx > 0x7FFF) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xB0, (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.le = count;
	apdu.resplen = count;
	apdu.resp = buf;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r == SC_ERROR_FILE_END_REACHED)
		LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
	LOG_TEST_RET(ctx, r, "Check SW error");

	LOG_FUNC_RETURN(ctx, (int)apdu.resplen);
}


const struct sc_asn1_entry c_asn1_do_data[] = {
	{ "Offset Data Object", SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x14, SC_ASN1_OPTIONAL, NULL, NULL },
	{ "Discretionary Data Object", SC_ASN1_OCTET_STRING, SC_ASN1_APP|0x13, SC_ASN1_ALLOC|SC_ASN1_UNSIGNED|SC_ASN1_OPTIONAL, NULL, NULL },
	{ NULL, 0, 0, 0, NULL, NULL }
};

int encode_do_data(struct sc_context *ctx,
		unsigned int idx, const unsigned char *data, size_t data_len,
		u8 **out, size_t *outlen)
{
	unsigned char offset_buffer[2];
	size_t offset_buffer_len = sizeof offset_buffer;
	struct sc_asn1_entry asn1_do_data[sizeof c_asn1_do_data / sizeof *c_asn1_do_data];
	sc_copy_asn1_entry(c_asn1_do_data, asn1_do_data);

	if (idx > 0xFFFF)
		LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "Offset beyond 0xFFFF not supported");
	offset_buffer[0] = (u8) (idx >> 8);
	offset_buffer[1] = (u8) (idx & 0x00FF);
	sc_format_asn1_entry(asn1_do_data + 0, offset_buffer, &offset_buffer_len, 1);

	if (data && data_len) {
		sc_format_asn1_entry(asn1_do_data + 1, (void *) &data, &data_len, 1);
	} else {
		sc_format_asn1_entry(asn1_do_data + 1, NULL, NULL, 0);
	}

	LOG_TEST_RET(ctx,
			sc_asn1_encode(ctx, asn1_do_data, out, outlen),
			"sc_asn1_encode() failed");

	return SC_SUCCESS;
}

int decode_do_data(struct sc_context *ctx,
		const unsigned char *encoded_data, size_t encoded_data_len,
		u8 **out, size_t *outlen)
{
	struct sc_asn1_entry asn1_do_data[sizeof c_asn1_do_data / sizeof *c_asn1_do_data];
	sc_copy_asn1_entry(c_asn1_do_data, asn1_do_data);

	sc_format_asn1_entry(asn1_do_data + 0, NULL, NULL, 0);
	sc_format_asn1_entry(asn1_do_data + 1, out, outlen, 0);

	LOG_TEST_RET(ctx,
			sc_asn1_decode(ctx, asn1_do_data, encoded_data, encoded_data_len, NULL, NULL),
			"sc_asn1_decode() failed");

	if (!(asn1_do_data[1].flags & SC_ASN1_PRESENT))
		return SC_ERROR_INVALID_ASN1_OBJECT;

	return SC_SUCCESS;
}

static int
iso7816_read_record(struct sc_card *card, unsigned int rec_nr, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;
	/* XXX maybe use some bigger buffer */
	unsigned char resp[SC_MAX_APDU_RESP_SIZE];
	unsigned char *encoded_data = NULL, *decoded_data = NULL;
	size_t encoded_data_len = 0, decoded_data_len = 0;

	if (rec_nr > 0xFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (idx == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xB2, rec_nr, 0);
		apdu.le = count;
		apdu.resplen = count;
		apdu.resp = buf;
	} else {
		r = encode_do_data(card->ctx, idx, NULL, 0, &encoded_data, &encoded_data_len);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not encode data objects");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0xB3, rec_nr, 0);
		apdu.lc = encoded_data_len;
		apdu.datalen = encoded_data_len;
		apdu.data = encoded_data;
		apdu.le = sizeof resp;
		apdu.resplen = sizeof resp;
		apdu.resp = resp;
	}
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Card returned error");

	if (idx == 0) {
		r = (int)apdu.resplen;
	} else {
		r = decode_do_data(card->ctx, apdu.resp, apdu.resplen,
				&decoded_data, &decoded_data_len);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not decode data objects");
		if (decoded_data_len <= count) {
			count = decoded_data_len;
		}
		memcpy(buf, decoded_data, count);
		r = (int)count;
	}

err:
	free(encoded_data);
	free(decoded_data);
	LOG_FUNC_RETURN(card->ctx, r);
}


static int
iso7816_write_record(struct sc_card *card, unsigned int rec_nr,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xD2, rec_nr, 0);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)count);
}


static int
iso7816_append_record(struct sc_card *card,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xE2, 0, 0);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)count);
}


static int
iso7816_update_record(struct sc_card *card, unsigned int rec_nr, unsigned int idx,
		const u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;
	unsigned char *encoded_data = NULL;
	size_t encoded_data_len = 0;

	if (rec_nr > 0xFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (idx == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xDC, rec_nr, 0);
		apdu.lc = count;
		apdu.datalen = count;
		apdu.data = buf;
	} else {
		r = encode_do_data(card->ctx, idx, buf, count, &encoded_data, &encoded_data_len);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Could not encode data objects");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xDD, rec_nr, 0);
		apdu.lc = encoded_data_len;
		apdu.datalen = encoded_data_len;
		apdu.data = encoded_data;
	}
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Card returned error");
	r = (int)count;

err:
	free(encoded_data);
	LOG_FUNC_RETURN(card->ctx, r);
}

static int
iso7816_write_binary(struct sc_card *card,
		unsigned int idx, const u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (idx > 0x7fff) {
		sc_log(card->ctx, "invalid EF offset: 0x%X > 0x7FFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xD0,
		       (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)count);
}


static int
iso7816_update_binary(struct sc_card *card,
		unsigned int idx, const u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;

	if (idx > 0x7fff) {
		sc_log(card->ctx, "invalid EF offset: 0x%X > 0x7FFF", idx);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3, 0xD6, (idx >> 8) & 0x7F, idx & 0xFF);
	apdu.lc = count;
	apdu.datalen = count;
	apdu.data = buf;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, (int)count);
}


static int
iso7816_process_fci(struct sc_card *card, struct sc_file *file,
		const unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	const unsigned char *p, *end;
	unsigned int cla = 0, tag = 0;
	size_t length;

	file->status = SC_FILE_STATUS_UNKNOWN;

	for (p = buf, length = buflen, end = buf + buflen;
			p < end;
			p += length, length = end - p) {

		if (SC_SUCCESS != sc_asn1_read_tag(&p, length, &cla, &tag, &length)
				|| p == NULL) {
			break;
		}
		switch (cla | tag) {
			case 0x81:
				if (file->size != 0) {
					/* don't overwrite existing file size excluding structural information */
					break;
				}
				/* fall through */
			case 0x80:
				/* determine the file size */
				file->size = 0;
				if (p && length <= sizeof(size_t)) {
					size_t size = 0, i;
					for (i = 0; i < length; i++) {
						size <<= 8;
						size |= p[i];
					}
					if (size > MAX_FILE_SIZE) {
						file->size = MAX_FILE_SIZE;
						sc_log(ctx, "  file size truncated, encoded length: %"SC_FORMAT_LEN_SIZE_T"u", size);
					} else {
						file->size = size;
					}
				}

				sc_log(ctx, "  bytes in file: %"SC_FORMAT_LEN_SIZE_T"u", file->size);
				break;

			case 0x82:
				if (length > 0) {
					unsigned char byte = p[0];
					const char *type;

					file->shareable = byte & 0x40 ? 1 : 0;
					sc_log(ctx, "  shareable: %s", (byte & 0x40) ? "yes" : "no");
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
							file->type = SC_FILE_TYPE_UNKNOWN;
							type = "unknown";
							break;
					}
					sc_log(ctx, "  type: %s", type);
					sc_log(ctx, "  EF structure: %d", byte & 0x07);
					sc_log(ctx, "  tag 0x82: 0x%02x", byte);

					/* if possible, get additional information for non-DFs */
					if (file->type != SC_FILE_TYPE_DF) {
						/* max. record length for fixed- & variable-sized records */
						if (length > 2 && byte & 0x06) {
							file->record_length = (length > 3)
								? bebytes2ushort(p+2)
								: p[2];
							sc_log(ctx, "  record length: %"SC_FORMAT_LEN_SIZE_T"u",
								file->record_length);
						}

						/* number of records */
						if (length > 4) {
							file->record_count = (length > 5)
								? bebytes2ushort(p+4)
								: p[4];
							sc_log(ctx, "  records: %"SC_FORMAT_LEN_SIZE_T"u",
								file->record_count);
						}
					}

					if (SC_SUCCESS != sc_file_set_type_attr(file, p, length))
						sc_log(ctx, "Warning: Could not set file attributes");
				}
				break;

			case 0x83:
				if (length == 2) {
					file->id = (p[0] << 8) | p[1];
					sc_log(ctx, "  file identifier: 0x%02X%02X", p[0], p[1]);
				}
				break;

			case 0x84:
				if (length > 0 && length <= 16) {
					memcpy(file->name, p, length);
					file->namelen = length;

					sc_log_hex(ctx, "  File name:", file->name, file->namelen);
					if (!file->type)
						file->type = SC_FILE_TYPE_DF;
				}
				break;

			case 0x85:
			case 0xA5:
				if (SC_SUCCESS != sc_file_set_prop_attr(file, p, length)) {
					sc_log(ctx, "Warning: Could not set proprietary file properties");
				}
				break;

			case 0x86:
				if (SC_SUCCESS != sc_file_set_sec_attr(file, p, length)) {
					sc_log(ctx, "Warning: Could not set file security properties");
				}
				break;

			case 0x88:
				if (length == 1) {
					file->sid = *p;
					sc_log(ctx, "  short file identifier: 0x%02X", *p);
				}
				break;

			case 0x8A:
				if (length == 1) {
					switch (p[0]) {
						case 0:
							file->status =SC_FILE_STATUS_NO_INFO;
							break;
						case 1:
							file->status = SC_FILE_STATUS_CREATION;
							break;
						case 3:
							file->status = SC_FILE_STATUS_INITIALISATION;
							break;
						case 4:
						case 6:
							file->status = SC_FILE_STATUS_INVALIDATED;
							break;
						case 5:
						case 7:
							file->status = SC_FILE_STATUS_ACTIVATED;
							break;
						case 12:
						case 13:
						case 14:
						case 15:
							file->status = SC_FILE_STATUS_TERMINATION;
							break;
						case 2:
							file->status = SC_FILE_STATUS_RFU_2;
							break;
						case 8:
							file->status = SC_FILE_STATUS_RFU_8;
							break;
						case 9:
							file->status = SC_FILE_STATUS_RFU_9;
							break;
						case 10:
							file->status = SC_FILE_STATUS_RFU_10;
							break;
						case 11:
							file->status = SC_FILE_STATUS_RFU_11;
							break;
						default:
							file->status = SC_FILE_STATUS_PROPRIETARY;
					}
				}
				break;

			case 0x62:
			case 0x64:
			case 0x6F:
				/* allow nested FCP/FMD/FCI templates */
				iso7816_process_fci(card, file, p, length);
		}
	}

	file->magic = SC_FILE_MAGIC;

	return SC_SUCCESS;
}


static int
iso7816_select_file(struct sc_card *card, const struct sc_path *in_path, struct sc_file **file_out)
{
	struct sc_context *ctx;
	struct sc_apdu apdu;
	unsigned char buf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char pathbuf[SC_MAX_PATH_SIZE], *path = pathbuf;
	int r, pathtype;
	size_t pathlen;
	int select_mf = 0;
	struct sc_file *file = NULL;
	const u8 *buffer;
	size_t buffer_len;
	unsigned int cla, tag;

	if (card == NULL || in_path == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	ctx = card->ctx;
	memcpy(path, in_path->value, in_path->len);
	pathlen = in_path->len;
	pathtype = in_path->type;

	if (in_path->aid.len) {
		if (!pathlen) {
			memcpy(path, in_path->aid.value, in_path->aid.len);
			pathlen = in_path->aid.len;
			pathtype = SC_PATH_TYPE_DF_NAME;
		} else {
			/* First, select the application */
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
			apdu.data = in_path->aid.value;
			apdu.datalen = in_path->aid.len;
			apdu.lc = in_path->aid.len;

			r = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(ctx, r, "APDU transmit failed");
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r)
				LOG_FUNC_RETURN(ctx, r);

			if (pathtype == SC_PATH_TYPE_PATH
					|| pathtype == SC_PATH_TYPE_DF_NAME)
				pathtype = SC_PATH_TYPE_FROM_CURRENT;
		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0);

	switch (pathtype) {
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
				select_mf = 1;
				apdu.p1 = 0;
				break;
			}
			path += 2;
			pathlen -= 2;
		}
		break;
	case SC_PATH_TYPE_FROM_CURRENT:
		apdu.p1 = 9;
		break;
	case SC_PATH_TYPE_PARENT:
		apdu.p1 = 3;
		pathlen = 0;
		apdu.cse = SC_APDU_CASE_2_SHORT;
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}
	apdu.lc = pathlen;
	apdu.data = path;
	apdu.datalen = pathlen;

	if (file_out != NULL) {
		apdu.p2 = 0;		/* first record, return FCI */
		apdu.resp = buf;
		apdu.resplen = sizeof(buf);
		apdu.le = sc_get_max_recv_size(card) < 256 ? sc_get_max_recv_size(card) : 256;
	}
	else {
		apdu.p2 = 0x0C;		/* first record, return nothing */
		apdu.cse = (apdu.lc == 0) ? SC_APDU_CASE_1 : SC_APDU_CASE_3_SHORT;
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, r, "APDU transmit failed");
	if (file_out == NULL) {
		/* For some cards 'SELECT' can be only with request to return FCI/FCP. */
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x86)   {
			apdu.p2 = 0x00;
			if (sc_transmit_apdu(card, &apdu) == SC_SUCCESS)
				r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		}
		if (apdu.sw1 == 0x61)
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		LOG_FUNC_RETURN(ctx, r);
	}

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		LOG_FUNC_RETURN(ctx, r);

	if (file_out && (apdu.resplen == 0))   {
		/* For some cards 'SELECT' MF or DF_NAME do not return FCI. */
		if (select_mf || pathtype == SC_PATH_TYPE_DF_NAME)   {
			file = sc_file_new();
			if (file == NULL)
				LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
			file->path = *in_path;

			*file_out = file;
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
	}

	if (apdu.resplen < 2)
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	switch (apdu.resp[0]) {
	case ISO7816_TAG_FCI:
	case ISO7816_TAG_FCP:
		file = sc_file_new();
		if (file == NULL)
			LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
		file->path = *in_path;
		if (card->ops->process_fci == NULL) {
			sc_file_free(file);
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
		}
		buffer = apdu.resp;
		r = sc_asn1_read_tag(&buffer, apdu.resplen, &cla, &tag, &buffer_len);
		if (r == SC_SUCCESS)
			card->ops->process_fci(card, file, buffer, buffer_len);
		*file_out = file;
		break;
	case 0x00: /* proprietary coding */
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	}

	return SC_SUCCESS;
}


static int
iso7816_get_challenge(struct sc_card *card, u8 *rnd, size_t len)
{
	int r;
	struct sc_apdu apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x84, 0x00, 0x00);
	apdu.le = len;
	apdu.resp = rnd;
	apdu.resplen = len;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE failed");

	if (len < apdu.resplen) {
		return (int) len;
	}

	return (int) apdu.resplen;
}


static int
iso7816_construct_fci(struct sc_card *card, const sc_file_t *file,
		u8 *out, size_t *outlen)
{
	u8 *p = out;
	u8 buf[64];

	if (*outlen < 2)
		return SC_ERROR_BUFFER_TOO_SMALL;
	*p++ = 0x6F;
	p++;

	buf[0] = (file->size >> 8) & 0xFF;
	buf[1] = file->size & 0xFF;
	sc_asn1_put_tag(0x81, buf, 2, p, *outlen - (p - out), &p);

	if (file->type_attr_len) {
		assert(sizeof(buf) >= file->type_attr_len);
		memcpy(buf, file->type_attr, file->type_attr_len);
		sc_asn1_put_tag(0x82, buf, file->type_attr_len,
				p, *outlen - (p - out), &p);
	} else {
		buf[0] = file->shareable ? 0x40 : 0;
		switch (file->type) {
		case SC_FILE_TYPE_INTERNAL_EF:
			buf[0] |= 0x08;
			/* fall through */
		case SC_FILE_TYPE_WORKING_EF:
			buf[0] |= file->ef_structure & 7;
			break;
		case SC_FILE_TYPE_DF:
			buf[0] |= 0x38;
			break;
		default:
			return SC_ERROR_NOT_SUPPORTED;
		}
		sc_asn1_put_tag(0x82, buf, 1, p, *outlen - (p - out), &p);
	}
	buf[0] = (file->id >> 8) & 0xFF;
	buf[1] = file->id & 0xFF;
	sc_asn1_put_tag(0x83, buf, 2, p, *outlen - (p - out), &p);
	/* 0x84 = DF name */
	if (file->prop_attr_len) {
		assert(sizeof(buf) >= file->prop_attr_len);
		memcpy(buf, file->prop_attr, file->prop_attr_len);
		sc_asn1_put_tag(0x85, buf, file->prop_attr_len,
				p, *outlen - (p - out), &p);
	}
	if (file->sec_attr_len) {
		assert(sizeof(buf) >= file->sec_attr_len);
		memcpy(buf, file->sec_attr, file->sec_attr_len);
		sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
				p, *outlen - (p - out), &p);
	}
	out[1] = p - out - 2;

	*outlen = p - out;
	return 0;
}


static int
iso7816_create_file(struct sc_card *card, sc_file_t *file)
{
	int r;
	size_t len;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	struct sc_apdu apdu;

	len = SC_MAX_APDU_BUFFER_SIZE;

	if (card->ops->construct_fci == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);
	r = card->ops->construct_fci(card, file, sbuf, &len);
	LOG_TEST_RET(card->ctx, r, "construct_fci() failed");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0x00, 0x00);
	apdu.lc = len;
	apdu.datalen = len;
	apdu.data = sbuf;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}


static int
iso7816_get_response(struct sc_card *card, size_t *count, u8 *buf)
{
	struct sc_apdu apdu = {0};
	int r;
	size_t rlen;

	/* request at most max_recv_size bytes */
	if (*count > sc_get_max_recv_size(card))
		rlen = sc_get_max_recv_size(card);
	else
		rlen = *count;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xC0, 0x00, 0x00);
	apdu.le      = rlen;
	apdu.resplen = rlen;
	apdu.resp    = buf;
	/* don't call GET RESPONSE recursively */
	apdu.flags  |= SC_APDU_FLAGS_NO_GET_RESP;

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	*count = apdu.resplen;

	if (apdu.resplen == 0) {
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
	}
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		r = 0;					/* no more data to read */
	else if (apdu.sw1 == 0x61)
		r = apdu.sw2 == 0 ? 256 : apdu.sw2;	/* more data to read    */
	else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
		r = 0; /* Le not reached but file/record ended */
	else
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	return r;
}


static int
iso7816_delete_file(struct sc_card *card, const sc_path_t *path)
{
	int r;
	u8 sbuf[2];
	struct sc_apdu apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);
	if (path->type != SC_PATH_TYPE_FILE_ID || (path->len != 0 && path->len != 2)) {
		sc_log(card->ctx, "File type has to be SC_PATH_TYPE_FILE_ID");
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (path->len == 2) {
		sbuf[0] = path->value[0];
		sbuf[1] = path->value[1];
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
		apdu.lc = 2;
		apdu.datalen = 2;
		apdu.data = sbuf;
	}
	else   {
		/* No file ID given: means currently selected file */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);
	}

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}


static int
iso7816_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)
{
	struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r, locked = 0;

	if (card == NULL || env == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, 0);
	switch (env->operation) {
	case SC_SEC_OPERATION_DECIPHER:
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		apdu.p2 = 0xB6;
		break;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	p = sbuf;
	if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	/* algorithm reference */
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
	}
	if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		if (env->file_ref.len > SC_MAX_PATH_SIZE)
			return SC_ERROR_INVALID_ARGUMENTS;
		if (sizeof(sbuf) - (p - sbuf) < env->file_ref.len + 2)
			return SC_ERROR_OFFSET_TOO_LARGE;

		*p++ = 0x81;
		*p++ = (u8) env->file_ref.len;
		memcpy(p, env->file_ref.value, env->file_ref.len);
		p += env->file_ref.len;
	}
	if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (sizeof(sbuf) - (p - sbuf) < env->key_ref_len + 2)
			return SC_ERROR_OFFSET_TOO_LARGE;

		if (env->flags & SC_SEC_ENV_KEY_REF_SYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		if (env->key_ref_len > SC_MAX_KEYREF_SIZE)
			return SC_ERROR_INVALID_ARGUMENTS;
		*p++ = env->key_ref_len & 0xFF;
		memcpy(p, env->key_ref, env->key_ref_len);
		p += env->key_ref_len;
	}
	r = (int)(p - sbuf);
	apdu.lc = r;
	apdu.datalen = r;
	apdu.data = sbuf;
	if (se_num > 0) {
		r = sc_lock(card);
		LOG_TEST_RET(card->ctx, r, "sc_lock() failed");
		locked = 1;
	}
	if (apdu.datalen != 0) {
		r = sc_transmit_apdu(card, &apdu);
		if (r) {
			sc_log(card->ctx, "%s: APDU transmit failed", sc_strerror(r));
			goto err;
		}
		r = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (r) {
			sc_log(card->ctx, "%s: Card returned error", sc_strerror(r));
			goto err;
		}
	}
	if (se_num <= 0) {
		r = SC_SUCCESS;
		goto err;
	}
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num);
	r = sc_transmit_apdu(card, &apdu);
	sc_unlock(card);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return r;
}


static int
iso7816_restore_security_env(struct sc_card *card, int se_num)
{
	struct sc_apdu apdu;
	int r;

	if (card == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x22, 0xF3, se_num);

	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	return r;
}


static int
iso7816_compute_signature(struct sc_card *card,
		const u8 * data, size_t datalen,
		u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;

	if (card == NULL || data == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "ISO7816 compute signature: in-len %"SC_FORMAT_LEN_SIZE_T"u, out-len %"SC_FORMAT_LEN_SIZE_T"u",
	       datalen, outlen);

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x9E  Resp: Digital Signature
	 * P2:  0x9A  Cmd: Input for Digital Signature */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x9E, 0x9A);
	apdu.resp = out;
	apdu.resplen = outlen;
	apdu.le = outlen;

	apdu.data = data;
	apdu.lc = datalen;
	apdu.datalen = datalen;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "Card returned error");

	LOG_FUNC_RETURN(card->ctx, r);
}


static int
iso7816_decipher(struct sc_card *card,
		const u8 * crgram, size_t crgram_len,
		u8 * out, size_t outlen)
{
	int r;
	struct sc_apdu apdu;
	u8 *sbuf = NULL;

	if (card == NULL || crgram == NULL || out == NULL) {
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	LOG_FUNC_CALLED(card->ctx);
	sc_log(card->ctx,
	       "ISO7816 decipher: in-len %"SC_FORMAT_LEN_SIZE_T"u, out-len %"SC_FORMAT_LEN_SIZE_T"u",
	       crgram_len, outlen);

	sbuf = malloc(crgram_len + 1);
	if (sbuf == NULL)
		return SC_ERROR_OUT_OF_MEMORY;

	/* INS: 0x2A  PERFORM SECURITY OPERATION
	 * P1:  0x80  Resp: Plain value
	 * P2:  0x86  Cmd: Padding indicator byte followed by cryptogram */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
	apdu.resp    = out;
	apdu.resplen = outlen;
	apdu.le      = outlen;

	sbuf[0] = 0; /* padding indicator byte, 0x00 = No further indication */
	memcpy(sbuf + 1, crgram, crgram_len);
	apdu.data = sbuf;
	apdu.lc = crgram_len + 1;
	apdu.datalen = crgram_len + 1;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	sc_mem_clear(sbuf, crgram_len + 1);
	free(sbuf);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
	else
		LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
}


int
iso7816_build_pin_apdu(struct sc_card *card, struct sc_apdu *apdu,
		struct sc_pin_cmd_data *data, u8 *buf, size_t buf_len)
{
	int r, len = 0, pad = 0, use_pin_pad = 0, ins, p1 = 0;
	int cse = SC_APDU_CASE_3_SHORT;

	switch (data->pin_type) {
	case SC_AC_CHV:
		/* fall through */
	case SC_AC_SESSION:
	case SC_AC_CONTEXT_SPECIFIC:
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
		/* detect overloaded APDU with SC_PIN_CMD_GET_INFO */
		if (data->pin1.len == 0 && !use_pin_pad)
			return SC_ERROR_INVALID_PIN_LENGTH;
		if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
			return r;
		len = r;
		break;
	case SC_PIN_CMD_CHANGE:
		ins = 0x24;
		if (data->pin1.len != 0 || (use_pin_pad && !( data->flags & SC_PIN_CMD_IMPLICIT_CHANGE))) {
			if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
				return r;
			len += r;
		}
		else {
			/* implicit test */
			p1 = 1;
		}

		data->pin2.offset = data->pin1.offset + len;
		if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)
			return r;
		/* Special case - where provided the old PIN on the command line
		 * but expect the new one to be entered on the keypad.
		 */
		if (data->pin1.len && data->pin2.len == 0) {
			sc_log(card->ctx, "Special case - initial pin provided - but new pin asked on keypad");
			data->flags |= SC_PIN_CMD_IMPLICIT_CHANGE;
		};
		len += r;
		break;
	case SC_PIN_CMD_UNBLOCK:
		ins = 0x2C;
		if (data->pin1.len != 0 || (use_pin_pad && !( data->flags & SC_PIN_CMD_IMPLICIT_CHANGE))) {
			if ((r = sc_build_pin(buf, buf_len, &data->pin1, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x02;
		}

		if (data->pin2.len != 0 || use_pin_pad) {
			data->pin2.offset = data->pin1.offset + len;
			if ((r = sc_build_pin(buf+len, buf_len-len, &data->pin2, pad)) < 0)
				return r;
			len += r;
		} else {
			p1 |= 0x01;
		}
		if (p1 == 0x03) {
			/* No data to send or to receive */
			cse = SC_APDU_CASE_1;
		}
		break;
	case SC_PIN_CMD_GET_INFO:
		ins = 0x20;
		/* No data to send or to receive */
		cse = SC_APDU_CASE_1;
		break;
	default:
		return SC_ERROR_NOT_SUPPORTED;
	}

	sc_format_apdu(card, apdu, cse, ins, p1, data->pin_reference);
	apdu->lc = len;
	apdu->datalen = len;
	apdu->data = buf;
	apdu->resplen = 0;

	return 0;
}


static int
iso7816_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_apdu local_apdu, *apdu;
	int r;
	u8  sbuf[SC_MAX_APDU_BUFFER_SIZE];

	data->pin1.tries_left = -1;
	if (tries_left != NULL) {
		*tries_left = data->pin1.tries_left;
	}

	/* Many cards do support PIN status queries, but some cards don't and
	 * mistakenly count the command as a failed PIN attempt, so for now we
	 * allow cards with this flag.  In future this may be reduced to a
	 * blocklist, subject to testing more cards. */
	if (data->cmd == SC_PIN_CMD_GET_INFO &&
	    !(card->caps & SC_CARD_CAP_ISO7816_PIN_INFO)) {
		sc_log(card->ctx, "Card does not support PIN status queries");
		return SC_ERROR_NOT_SUPPORTED;
	}

	/* See if we've been called from another card driver, which is
	 * passing an APDU to us (this allows to write card drivers
	 * whose PIN functions behave "mostly like ISO" except in some
	 * special circumstances.
	 */
	if (data->apdu == NULL) {
		r = iso7816_build_pin_apdu(card, &local_apdu, data, sbuf, sizeof(sbuf));
		if (r < 0)
			return r;
		data->apdu = &local_apdu;
	}
	apdu = data->apdu;

	if (!(data->flags & SC_PIN_CMD_USE_PINPAD) || data->cmd == SC_PIN_CMD_GET_INFO) {
		/* Transmit the APDU to the card */
		r = sc_transmit_apdu(card, apdu);

		/* Clear the buffer - it may contain pins */
		sc_mem_clear(sbuf, sizeof(sbuf));
	}
	else {
		/* Call the reader driver to collect
		 * the PIN and pass on the APDU to the card */
		if (data->pin1.offset == 0) {
			sc_log(card->ctx, "Card driver didn't set PIN offset");
			return SC_ERROR_INVALID_ARGUMENTS;
		}
		if (card->reader && card->reader->ops && card->reader->ops->perform_verify) {
			r = card->reader->ops->perform_verify(card->reader, data);
			/* sw1/sw2 filled in by reader driver */
		}
		else {
			sc_log(card->ctx, "Card reader driver does not support "
					"PIN entry through reader key pad");
			r = SC_ERROR_NOT_SUPPORTED;
		}
	}

	/* Don't pass references to local variables up to the caller. */
	if (data->apdu == &local_apdu)
		data->apdu = NULL;

	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu->sw1, apdu->sw2);

	if (r == SC_SUCCESS) {
		data->pin1.logged_in = SC_PIN_STATE_LOGGED_IN;
	} else if (r == SC_ERROR_PIN_CODE_INCORRECT) {
		data->pin1.tries_left = apdu->sw2 & 0xF;
		data->pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
		if (data->cmd == SC_PIN_CMD_GET_INFO)
			r = SC_SUCCESS;
	} else if (r == SC_ERROR_AUTH_METHOD_BLOCKED) {
		data->pin1.tries_left = 0;
		data->pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
		if (data->cmd == SC_PIN_CMD_GET_INFO)
			r = SC_SUCCESS;
	}
	if (tries_left != NULL) {
		*tries_left = data->pin1.tries_left;
	}

	return r;
}


static int iso7816_get_data(struct sc_card *card, unsigned int tag,  u8 *buf, size_t len)
{
	int                             r, cse;
	struct sc_apdu                  apdu;

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_VERBOSE);

	if (buf && len)
		cse = SC_APDU_CASE_2;
	else
		cse = SC_APDU_CASE_1;

	sc_format_apdu(card, &apdu, cse, 0xCA, (tag >> 8) & 0xff, tag & 0xff);
	apdu.le = len;
	apdu.resp = buf;
	apdu.resplen = len;
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "GET_DATA returned error");

	if (apdu.resplen > len)
		r = SC_ERROR_WRONG_LENGTH;
	else
		r = (int)apdu.resplen;

	LOG_FUNC_RETURN(card->ctx, r);
}

int
iso7816_select_aid(struct sc_card *card, const u8 *req,
		size_t reqlen, u8 *resp, size_t *resplen)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;

	SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_VERBOSE);

	sc_format_apdu(card, &apdu, resp == NULL ? SC_APDU_CASE_3_SHORT : SC_APDU_CASE_4_SHORT, 0xA4, 0x04, resp == NULL ? 0x0C : 0x00);
	apdu.lc = reqlen;
	apdu.data = req;
	apdu.datalen = reqlen;
	apdu.resp = resp;
	apdu.resplen = resp == NULL ? 0 : *resplen;
	apdu.le = resp == NULL ? 0 : 256;

	rv = sc_transmit_apdu(card, &apdu);
	if (resplen)
		*resplen = apdu.resplen;
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iso7816_init(struct sc_card *card)
{
#if ENABLE_SM
	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
#endif
	return SC_SUCCESS;
}


static int
no_match(struct sc_card *card)
{
	return 0;
}

static struct sc_card_operations iso_ops = {
	no_match,
	iso7816_init,	/* init   */
	NULL,			/* finish */
	iso7816_read_binary,
	iso7816_write_binary,
	iso7816_update_binary,
	NULL,			/* erase_binary */
	iso7816_read_record,
	iso7816_write_record,
	iso7816_append_record,
	iso7816_update_record,
	iso7816_select_file,
	iso7816_get_response,
	iso7816_get_challenge,
	NULL,			/* verify */
	NULL,			/* logout */
	iso7816_restore_security_env,
	iso7816_set_security_env,
	iso7816_decipher,
	iso7816_compute_signature,
	NULL,			/* change_reference_data */
	NULL,			/* reset_retry_counter   */
	iso7816_create_file,
	iso7816_delete_file,
	NULL,			/* list_files */
	iso7816_check_sw,
	NULL,			/* card_ctl */
	iso7816_process_fci,
	iso7816_construct_fci,
	iso7816_pin_cmd,
	iso7816_get_data,
	NULL,			/* put_data */
	NULL,			/* delete_record */
	NULL,			/* read_public_key */
	NULL,			/* card_reader_lock_obtained */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* encrypt_sym */
	NULL			/* decrypt_sym */
};

static struct sc_card_driver iso_driver = {
	"ISO 7816 reference driver",
	"iso7816",
	&iso_ops,
	NULL, 0, NULL
};

struct sc_card_driver * sc_get_iso7816_driver(void)
{
	return &iso_driver;
}

#define ISO_READ_BINARY  0xB0
#define ISO_P1_FLAG_SFID 0x80
int iso7816_read_binary_sfid(sc_card_t *card, unsigned char sfid,
		u8 **ef, size_t *ef_len)
{
	int r;
	size_t read;
	sc_apdu_t apdu;
	u8 *p;

	if (!card || !ef || !ef_len) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}
	*ef_len = 0;

	read = card->max_recv_size;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2,
			ISO_READ_BINARY, ISO_P1_FLAG_SFID|sfid, 0);
	p = realloc(*ef, read);
	if (!p) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	*ef = p;
	apdu.resp = *ef;
	apdu.resplen = read;
	apdu.le = read;

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		goto err;
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r < 0 && r != SC_ERROR_FILE_END_REACHED)
		goto err;
	/* emulate the behaviour of iso7816_read_binary */
	r = (int)apdu.resplen;

	while(1) {
		if (r >= 0 && ((size_t) r) != read) {
			*ef_len += r;
			break;
		}
		if (r <= 0) {
			if (*ef_len > 0)
				break;
			else {
				sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not read EF.");
				goto err;
			}
		}
		*ef_len += r;

		p = realloc(*ef, *ef_len + read);
		if (!p) {
			r = SC_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		*ef = p;

		r = iso7816_read_binary(card, (unsigned)*ef_len, *ef + *ef_len, read, 0);
	}

	r = (int)*ef_len;

err:
	return r;
}

#define ISO_WRITE_BINARY  0xD0
int iso7816_write_binary_sfid(sc_card_t *card, unsigned char sfid,
		u8 *ef, size_t ef_len)
{
	int r;
	size_t write, wrote = 0;
	sc_apdu_t apdu;

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	write = card->max_send_size;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3,
			ISO_WRITE_BINARY, ISO_P1_FLAG_SFID|sfid, 0);

	if (write > ef_len) {
		apdu.datalen = ef_len;
		apdu.lc = ef_len;
	} else {
		apdu.datalen = write;
		apdu.lc = write;
	}
	apdu.data = ef;


	r = sc_transmit_apdu(card, &apdu);
	/* emulate the behaviour of sc_write_binary */
	if (r >= 0)
		r = (int)apdu.datalen;

	while (1) {
		if (r < 0 || ((size_t) r) > ef_len) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not write EF.");
			goto err;
		}
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		wrote += r;
		apdu.data += r;
		if (wrote >= ef_len)
			break;

		r = sc_write_binary(card, (unsigned)wrote, ef, write, 0);
	}

	r = (int)wrote;

err:
	return r;
}

#define ISO_UPDATE_BINARY  0xD6
int iso7816_update_binary_sfid(sc_card_t *card, unsigned char sfid,
		u8 *ef, size_t ef_len)
{
	int r;
	size_t write = MAX_SM_APDU_DATA_SIZE, wrote = 0;
	sc_apdu_t apdu;
#ifdef ENABLE_SM
	struct iso_sm_ctx *iso_sm_ctx;
#endif

	if (!card) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

#ifdef ENABLE_SM
	iso_sm_ctx = card->sm_ctx.info.cmd_data;
	if (write > SC_MAX_APDU_BUFFER_SIZE-2
			|| (card->sm_ctx.sm_mode == SM_MODE_TRANSMIT
				&& write > (((SC_MAX_APDU_BUFFER_SIZE-2
					/* for encrypted APDUs we usually get authenticated status
					 * bytes (4B), a MAC (11B) and a cryptogram with padding
					 * indicator (3B without data).  The cryptogram is always
					 * padded to the block size. */
					-18) / iso_sm_ctx->block_length)
					* iso_sm_ctx->block_length - 1)))
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_EXT,
				ISO_UPDATE_BINARY, ISO_P1_FLAG_SFID|sfid, 0);
	else
#endif
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT,
				ISO_UPDATE_BINARY, ISO_P1_FLAG_SFID|sfid, 0);

	if (write > ef_len) {
		apdu.datalen = ef_len;
		apdu.lc = ef_len;
	} else {
		apdu.datalen = write;
		apdu.lc = write;
	}
	apdu.data = ef;


	r = sc_transmit_apdu(card, &apdu);
	/* emulate the behaviour of sc_write_binary */
	if (r >= 0)
		r = (int)apdu.datalen;

	while (1) {
		if (r < 0 || ((size_t) r) > ef_len) {
			sc_debug(card->ctx, SC_LOG_DEBUG_VERBOSE, "Could not update EF.");
			goto err;
		}
		if (r == 0 || r == SC_ERROR_FILE_END_REACHED)
			break;
		wrote += r;
		apdu.data += r;
		if (wrote >= ef_len)
			break;

		r = sc_update_binary(card, (unsigned)wrote, ef, write, 0);
	}

	r = (int)wrote;

err:
	return r;
}

int iso7816_logout(sc_card_t *card, unsigned char pin_reference)
{
	int r;
	sc_apdu_t apdu;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0xFF, pin_reference);

	r = sc_transmit_apdu(card, &apdu);
	if (r < 0)
		return r;

	r = sc_check_sw(card, apdu.sw1, apdu.sw2);

	return r;
}
