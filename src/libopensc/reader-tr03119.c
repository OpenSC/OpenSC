/*
 * reader-escape.c: implementation related to escape commands with pseudo APDUs
 *
 * Copyright (C) 2013-2018  Frank Morgner
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

#include "reader-tr03119.h"
#include "ccid-types.h"
#include "internal.h"
#include "libopensc/asn1.h"
#include "libopensc/log.h"
#include "libopensc/opensc.h"
#include "libopensc/pace.h"
#include <stdlib.h>
#include <string.h>

#if _WIN32
/* FIXME might not always work */
#define htole16(x) (x)
#define htole32(x) (x)
#elif __APPLE__
#include <libkern/OSByteOrder.h>
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#else
#ifndef _BSD_SOURCE
#define _BSD_SOURCE             /* See feature_test_macros(7) */
#endif
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif
#endif

int get_pace_capabilities(u8 *bitmap)
{
	if (!bitmap)
		return SC_ERROR_INVALID_ARGUMENTS;

	/* BitMap */
	*bitmap = EAC_BITMAP_PACE|EAC_BITMAP_EID|EAC_BITMAP_ESIGN;

	return SC_SUCCESS;
}

const u8 escape_cla                          = 0xff;
const u8 escape_ins                          = 0x9a;

const u8 escape_p1_PIN                       = 0x04;
const u8 escape_p2_GetReaderPACECapabilities = 0x01;
const u8 escape_p2_EstablishPACEChannel      = 0x02;
/*const u8 escape_p2_DestroyPACEChannel        = 0x03;*/
const u8 escape_p2_PC_to_RDR_Secure          = 0x10;

const u8 escape_p1_IFD                       = 0x01;
const u8 escape_p2_vendor                    = 0x01;
/*const u8 escape_p2_product                   = 0x03;*/
const u8 escape_p2_version_firmware          = 0x06;
/*const u8 escape_p2_version_driver            = 0x07;*/

struct sc_asn1_entry g_boolean[] = {
	{ "boolean",
		SC_ASN1_BOOLEAN, SC_ASN1_TAG_BOOLEAN, 0, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
struct sc_asn1_entry g_int_as_octet_string[] = {
	{ "int as octet string",
		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_INTEGER, 0, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
struct sc_asn1_entry g_octet_string[] = {
	{ "octet string",
		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_OCTET_STRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
struct sc_asn1_entry g_numeric_string_as_octet_string[] = {
	{ "utf8string",
		SC_ASN1_OCTET_STRING, SC_ASN1_TAG_NUMERICSTRING, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};

const struct sc_asn1_entry g_EstablishPACEChannelInput_data[] = {
	{ "passwordID",
		/* use an OCTET STRING to avoid a conversion to int */
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x01|SC_ASN1_CONS, 0, NULL, NULL },
	{ "transmittedPassword",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x02|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ "cHAT",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x03|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ "certificateDescription",
		SC_ASN1_OCTET_STRING, SC_ASN1_CTX|0x04|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ "hashOID",
		/* use an OCTET STRING to avoid a conversion to struct sc_object_id */
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x05|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
const struct sc_asn1_entry g_EstablishPACEChannelOutput_data[] = {
	{ "errorCode",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x01|SC_ASN1_CONS, 0, NULL, NULL },
	{ "statusMSESetAT",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x02|SC_ASN1_CONS, 0, NULL, NULL },
	{ "efCardAccess",
		SC_ASN1_OCTET_STRING, SC_ASN1_CTX|0x03|SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
	{ "idPICC",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x04|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ "curCAR",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x05|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ "prevCAR",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x06|SC_ASN1_CONS, SC_ASN1_OPTIONAL|SC_ASN1_ALLOC, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
const struct sc_asn1_entry g_EstablishPACEChannel[] = {
	{ "EstablishPACEChannel",
		SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE|SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};

int escape_pace_input_to_buf(sc_context_t *ctx,
		const struct establish_pace_channel_input *input,
		unsigned char **asn1, size_t *asn1_len)
{
	size_t pin_id_len = sizeof input->pin_id;
	struct sc_asn1_entry EstablishPACEChannelInput_data[
		sizeof g_EstablishPACEChannelInput_data/
		sizeof *g_EstablishPACEChannelInput_data];
	struct sc_asn1_entry EstablishPACEChannel[
		sizeof g_EstablishPACEChannel/
		sizeof *g_EstablishPACEChannel];
	struct sc_asn1_entry passwordID[
		sizeof g_int_as_octet_string/
		sizeof *g_int_as_octet_string];
	struct sc_asn1_entry transmittedPassword[
		sizeof g_numeric_string_as_octet_string/
		sizeof *g_numeric_string_as_octet_string];
	struct sc_asn1_entry cHAT[
		sizeof g_octet_string/
		sizeof *g_octet_string];

	sc_copy_asn1_entry(g_EstablishPACEChannel,
			EstablishPACEChannel);
	sc_format_asn1_entry(EstablishPACEChannel,
			EstablishPACEChannelInput_data, 0, 1);

	sc_copy_asn1_entry(g_EstablishPACEChannelInput_data,
			EstablishPACEChannelInput_data);

	sc_format_asn1_entry(EstablishPACEChannelInput_data+0,
			passwordID, 0, 1);
	sc_copy_asn1_entry(g_int_as_octet_string,
			passwordID);
	sc_format_asn1_entry(passwordID,
			(unsigned char *) &input->pin_id, &pin_id_len, 1);

	if (input->pin) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+1,
				transmittedPassword,
				0, 1);
		sc_copy_asn1_entry(g_numeric_string_as_octet_string,
				transmittedPassword);
		sc_format_asn1_entry(transmittedPassword,
				(unsigned char *) input->pin,
				(size_t *) &input->pin_length, 1);
	}

	if (input->chat) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+2,
				cHAT,
				0, 1);
		sc_copy_asn1_entry(g_octet_string,
				cHAT);
		sc_format_asn1_entry(cHAT,
				(unsigned char *) input->chat,
				(size_t *) &input->chat_length, 1);
	}

	if (input->certificate_description) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+3,
				(unsigned char *) input->certificate_description,
				(size_t *) &input->certificate_description_length, 1);
	}

	return sc_asn1_encode(ctx, EstablishPACEChannel, asn1, asn1_len);
}

int escape_buf_to_pace_input(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		struct establish_pace_channel_input *input)
{
	size_t pin_id_len = sizeof input->pin_id;
	struct sc_asn1_entry EstablishPACEChannelInput_data[
		sizeof g_EstablishPACEChannelInput_data/
		sizeof *g_EstablishPACEChannelInput_data];
	struct sc_asn1_entry EstablishPACEChannel[
		sizeof g_EstablishPACEChannel/
		sizeof *g_EstablishPACEChannel];
	struct sc_asn1_entry passwordID[
		sizeof g_int_as_octet_string/
		sizeof *g_int_as_octet_string];
	struct sc_asn1_entry transmittedPassword[
		sizeof g_numeric_string_as_octet_string/
		sizeof *g_numeric_string_as_octet_string];
	struct sc_asn1_entry cHAT[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	/* FIXME handle hashOID */

	sc_copy_asn1_entry(g_EstablishPACEChannel,
			EstablishPACEChannel);
	sc_format_asn1_entry(EstablishPACEChannel,
			EstablishPACEChannelInput_data, 0, 0);

	sc_copy_asn1_entry(g_EstablishPACEChannelInput_data,
			EstablishPACEChannelInput_data);

	sc_format_asn1_entry(EstablishPACEChannelInput_data+0,
			passwordID, 0, 0);
	sc_copy_asn1_entry(g_int_as_octet_string,
			passwordID);
	sc_format_asn1_entry(passwordID,
			&input->pin_id, &pin_id_len, 0);

	if (input->pin) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+1,
				transmittedPassword, 0, 0);
		sc_copy_asn1_entry(g_numeric_string_as_octet_string,
				transmittedPassword);
		sc_format_asn1_entry(transmittedPassword,
				(unsigned char *) &input->pin, &input->pin_length, 0);
	}

	if (input->chat) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+2,
				cHAT, 0, 0);
		sc_copy_asn1_entry(g_octet_string,
				cHAT);
		sc_format_asn1_entry(cHAT,
				(unsigned char *) &input->chat, &input->chat_length, 0);
	}

	if (input->certificate_description) {
		sc_format_asn1_entry(EstablishPACEChannelInput_data+3,
				(unsigned char *) &input->certificate_description,
				&input->certificate_description_length, 0);
	}

	LOG_TEST_RET(ctx,
			sc_asn1_decode(ctx, EstablishPACEChannel, asn1, asn1_len, NULL, NULL),
			"Error decoding EstablishPACEChannel");

	if (pin_id_len != sizeof input->pin_id)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;

	return SC_SUCCESS;
}

int escape_pace_output_to_buf(sc_context_t *ctx,
		const struct establish_pace_channel_output *output,
		unsigned char **asn1, size_t *asn1_len)
{
	uint16_t status_mse_set_at = ((output->mse_set_at_sw1 & 0xff) << 8) | output->mse_set_at_sw2;
	size_t result_len = sizeof output->result,
		   status_mse_set_at_len = sizeof status_mse_set_at;
	struct sc_asn1_entry EstablishPACEChannelOutput_data[
		sizeof g_EstablishPACEChannelOutput_data/
		sizeof *g_EstablishPACEChannelOutput_data];
	struct sc_asn1_entry EstablishPACEChannel[
		sizeof g_EstablishPACEChannel/
		sizeof *g_EstablishPACEChannel];
	struct sc_asn1_entry errorCode[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry statusMSESetAT[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry idPICC[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry curCAR[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry prevCAR[
		sizeof g_octet_string/
		sizeof *g_octet_string];

	sc_copy_asn1_entry(g_EstablishPACEChannel,
			EstablishPACEChannel);
	sc_format_asn1_entry(EstablishPACEChannel,
			EstablishPACEChannelOutput_data, 0, 1);

	sc_copy_asn1_entry(g_EstablishPACEChannelOutput_data,
			EstablishPACEChannelOutput_data);

	sc_format_asn1_entry(EstablishPACEChannelOutput_data+0,
			errorCode, 0, 1);
	sc_copy_asn1_entry(g_octet_string,
			errorCode);
	sc_format_asn1_entry(errorCode,
			(unsigned char *) &output->result, &result_len, 1);

	sc_format_asn1_entry(EstablishPACEChannelOutput_data+1,
			statusMSESetAT, 0, 1);
	sc_copy_asn1_entry(g_octet_string,
			statusMSESetAT);
	sc_format_asn1_entry(statusMSESetAT,
			&status_mse_set_at, &status_mse_set_at_len, 1);

	if (output->ef_cardaccess) {
		sc_format_asn1_entry(EstablishPACEChannelOutput_data+2,
				output->ef_cardaccess, (size_t *) &output->ef_cardaccess_length, 1);
	}

	if (output->id_icc) {
		sc_format_asn1_entry(EstablishPACEChannelOutput_data+3,
				idPICC, 0, 1);
		sc_copy_asn1_entry(g_octet_string,
				idPICC);
		sc_format_asn1_entry(idPICC,
				output->id_icc, (size_t *) &output->id_icc_length, 1);
	}

	if (output->recent_car) {
		sc_format_asn1_entry(EstablishPACEChannelOutput_data+4,
				curCAR, 0, 1);
		sc_copy_asn1_entry(g_octet_string,
				curCAR);
		sc_format_asn1_entry(curCAR,
				output->recent_car, (size_t *) &output->recent_car_length, 1);
	}

	if (output->previous_car) {
		sc_format_asn1_entry(EstablishPACEChannelOutput_data+5,
			prevCAR, 0, 1);
		sc_copy_asn1_entry(g_octet_string,
				prevCAR);
		sc_format_asn1_entry(prevCAR,
			output->previous_car, (size_t *) &output->previous_car_length, 1);
	}

	return sc_asn1_encode(ctx, EstablishPACEChannel, asn1, asn1_len);
}

int escape_buf_to_pace_output(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		struct establish_pace_channel_output *output)
{
	uint16_t status_mse_set_at;
	size_t result_len = sizeof output->result,
		   status_mse_set_at_len = sizeof status_mse_set_at;
	struct sc_asn1_entry EstablishPACEChannelOutput_data[
		sizeof g_EstablishPACEChannelOutput_data/
		sizeof *g_EstablishPACEChannelOutput_data];
	struct sc_asn1_entry EstablishPACEChannel[
		sizeof g_EstablishPACEChannel/
		sizeof *g_EstablishPACEChannel];
	struct sc_asn1_entry errorCode[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry statusMSESetAT[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry idPICC[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry curCAR[
		sizeof g_octet_string/
		sizeof *g_octet_string];
	struct sc_asn1_entry prevCAR[
		sizeof g_octet_string/
		sizeof *g_octet_string];

	sc_copy_asn1_entry(g_EstablishPACEChannel,
			EstablishPACEChannel);
	sc_format_asn1_entry(EstablishPACEChannel,
			EstablishPACEChannelOutput_data, 0, 0);

	sc_copy_asn1_entry(g_EstablishPACEChannelOutput_data,
			EstablishPACEChannelOutput_data);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+0,
			errorCode, 0, 0);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+1,
			statusMSESetAT, 0, 0);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+2,
			&output->ef_cardaccess, &output->ef_cardaccess_length, 0);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+3,
			idPICC, 0, 0);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+4,
			curCAR, 0, 0);
	sc_format_asn1_entry(EstablishPACEChannelOutput_data+5,
			prevCAR, 0, 0);

	sc_copy_asn1_entry(g_octet_string,
			errorCode);
	sc_format_asn1_entry(errorCode,
			&output->result, &result_len, 0);
	/* we already allocated memory for the result */
	errorCode->flags = 0;

	sc_copy_asn1_entry(g_octet_string,
			statusMSESetAT);
	sc_format_asn1_entry(statusMSESetAT,
			&status_mse_set_at, &status_mse_set_at_len, 0);
	/* we already allocated memory for the result */
	statusMSESetAT->flags = 0;

	sc_copy_asn1_entry(g_octet_string,
			idPICC);
	sc_format_asn1_entry(idPICC,
			&output->id_icc, &output->id_icc_length, 0);

	sc_copy_asn1_entry(g_octet_string,
			curCAR);
	sc_format_asn1_entry(curCAR,
			&output->recent_car, &output->recent_car_length, 0);

	sc_copy_asn1_entry(g_octet_string,
			prevCAR);
	sc_format_asn1_entry(prevCAR,
			&output->previous_car, &output->previous_car_length, 0);

	LOG_TEST_RET(ctx,
			sc_asn1_decode(ctx, EstablishPACEChannel,
				asn1, asn1_len, NULL, NULL),
			"Error decoding EstablishPACEChannel");

	if (status_mse_set_at_len != sizeof status_mse_set_at
			|| result_len != sizeof output->result)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;

	output->mse_set_at_sw1 = (status_mse_set_at >> 8) & 0xff;
	output->mse_set_at_sw2 =  status_mse_set_at       & 0xff;

	return SC_SUCCESS;
}

#define CCID_PIN_TIMEOUT	30
#define CCID_DISPLAY_DEFAULT    0xff
static int escape_pin_cmd_to_buf(sc_context_t *ctx,
		const struct sc_pin_cmd_data *data,
		unsigned char **pc_to_rdr_secure, size_t *pc_to_rdr_secure_len)
{
	PC_to_RDR_Secure_t *secure;
	abPINDataStucture_Modification_t *modify;
	abPINDataStucture_Verification_t *verify;
	uint16_t wLangId = 0,
			 bTeoPrologue2 = 0,
			 wPINMaxExtraDigit;
	uint8_t bTimeOut = CCID_PIN_TIMEOUT,
			bNumberMessage = CCID_DISPLAY_DEFAULT,
			bTeoPrologue1 = 0,
			bMsgIndex = 0,
			bMessageType = 0x69,
			bSlot = 0,
			bSeq = 0,
			bBWI = 0xff,
			wLevelParameter = 0,
			bEntryValidationCondition = CCID_ENTRY_VALIDATE,
			bmFormatString, bmPINLengthFormat, bmPINBlockString;
	const struct sc_pin_cmd_pin *pin_ref;
	int r;
	unsigned char *pinapdu = NULL;
	size_t pinapdu_len = 0;

	if (!data || !pc_to_rdr_secure || !pc_to_rdr_secure_len) {
		r = SC_ERROR_INVALID_ARGUMENTS;
		goto err;
	}

	pin_ref = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ?
		&data->pin2 : &data->pin1;

	wPINMaxExtraDigit = htole16(
			(0xff & pin_ref->min_length) << 8)
			| (pin_ref->max_length & 0xff);

	bmFormatString = CCID_PIN_UNITS_BYTES
		| ((pin_ref->offset & 0xf) << 3);
	switch (pin_ref->encoding) {
		case SC_PIN_ENCODING_ASCII:
			bmFormatString |= CCID_PIN_ENCODING_ASCII;
			break;
		case SC_PIN_ENCODING_BCD:
			bmFormatString |= CCID_PIN_ENCODING_BCD;
			break;
		default:
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
	}

	/* GLP PINs expect the effective PIN length from bit 4 */
	bmPINLengthFormat = pin_ref->encoding == SC_PIN_ENCODING_GLP ?
		0x04 : 0x00;

	if (pin_ref->encoding == SC_PIN_ENCODING_GLP) {
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		bmPINBlockString = 0x40 | 0x08;
	} else if (pin_ref->encoding == SC_PIN_ENCODING_ASCII && data->flags & SC_PIN_CMD_NEED_PADDING) {
		bmPINBlockString = (uint8_t) pin_ref->pad_length;
	} else {
		bmPINBlockString = 0x00;
	}

	r = sc_apdu_get_octets(ctx, data->apdu, &pinapdu, &pinapdu_len,
			SC_PROTO_T1);
	if (r < 0)
		goto err;

	switch (data->cmd) {
		case SC_PIN_CMD_VERIFY:
			*pc_to_rdr_secure_len = sizeof *secure + 1
				+ sizeof *verify + pinapdu_len;
			break;

		case SC_PIN_CMD_CHANGE:
			*pc_to_rdr_secure_len = sizeof *secure + 1
				+ sizeof *modify + 3 + pinapdu_len;
			break;

		default:
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
	}

	*pc_to_rdr_secure = malloc(*pc_to_rdr_secure_len);
	if (!*pc_to_rdr_secure) {
		r = SC_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	secure = (PC_to_RDR_Secure_t *) *pc_to_rdr_secure;
	secure->bMessageType = bMessageType;
	secure->dwLength = htole32((*pc_to_rdr_secure_len) - sizeof *secure);
	secure->bSlot = bSlot;
	secure->bSeq = bSeq;
	secure->bBWI = bBWI;
	secure->wLevelParameter = wLevelParameter;

	switch (data->cmd) {
		case SC_PIN_CMD_VERIFY:
			/* bPINOperation */
			*((*pc_to_rdr_secure) + sizeof *secure) = CCID_OPERATION_VERIFY;
			verify = (abPINDataStucture_Verification_t *)
				((*pc_to_rdr_secure) + sizeof *secure + 1);
			verify->bTimeOut = bTimeOut;
			verify->bmFormatString = bmFormatString;
			verify->bmPINBlockString = bmPINBlockString;
			verify->bmPINLengthFormat = bmPINLengthFormat;
			verify->wPINMaxExtraDigit = wPINMaxExtraDigit;
			verify->bEntryValidationCondition = bEntryValidationCondition;
			verify->bNumberMessage = bNumberMessage;
			verify->wLangId = wLangId;
			verify->bMsgIndex = bMsgIndex;
			verify->bTeoPrologue1 = bTeoPrologue1;
			verify->bTeoPrologue2 = bTeoPrologue2;

			memcpy((*pc_to_rdr_secure) + sizeof *secure + 1 + sizeof *verify,
					pinapdu, pinapdu_len);
			break;

		case SC_PIN_CMD_CHANGE:
			/* bPINOperation */
			*((*pc_to_rdr_secure) + sizeof *secure) = CCID_OPERATION_MODIFY;
			modify = (abPINDataStucture_Modification_t *)
				((*pc_to_rdr_secure) + sizeof *secure + 1);
			modify->bTimeOut = bTimeOut;
			modify->bmFormatString = bmFormatString;
			modify->bmPINBlockString = bmPINBlockString;
			modify->bmPINLengthFormat = bmPINLengthFormat;
			if (!(data->flags & SC_PIN_CMD_IMPLICIT_CHANGE)
					&& data->pin1.offset) {
				modify->bInsertionOffsetOld = (uint8_t) data->pin1.offset - 5;
			} else {
				modify->bInsertionOffsetOld = 0;
			}
			modify->bInsertionOffsetNew = data->pin2.offset ? (uint8_t) data->pin2.offset - 5 : 0;
			modify->wPINMaxExtraDigit = wPINMaxExtraDigit;
			modify->bConfirmPIN = CCID_PIN_CONFIRM_NEW
				| (data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0 : CCID_PIN_INSERT_OLD);
			modify->bEntryValidationCondition = bEntryValidationCondition;
			modify->bNumberMessage = bNumberMessage;
			modify->wLangId = wLangId;
			modify->bMsgIndex1 = bMsgIndex;
			*((*pc_to_rdr_secure) + sizeof *secure + 1 + sizeof *modify + 0) =
				bTeoPrologue1;
			*((*pc_to_rdr_secure) + sizeof *secure + 1 + sizeof *modify + 1) =
				bTeoPrologue1;
			*((*pc_to_rdr_secure) + sizeof *secure + 1 + sizeof *modify + 2) =
				bTeoPrologue1;

			memcpy((*pc_to_rdr_secure) + sizeof *secure + 1 + sizeof *modify + 3,
					pinapdu, pinapdu_len);
			break;

		default:
			r = SC_ERROR_INVALID_ARGUMENTS;
			goto err;
	}

	r = SC_SUCCESS;

err:
	free(pinapdu);
	if (r < 0 && pc_to_rdr_secure && *pc_to_rdr_secure) {
		free(*pc_to_rdr_secure);
		*pc_to_rdr_secure = NULL;
	}

	return r;
}

#define CCID_BSTATUS_OK_ACTIVE 0x00 /** No error. An ICC is present and active */
static int escape_buf_to_verify_result(sc_context_t *ctx,
		const unsigned char *rdr_to_pc_datablock,
		size_t rdr_to_pc_datablock_len,
		sc_apdu_t *apdu)
{
	RDR_to_PC_DataBlock_t *datablock =
		(RDR_to_PC_DataBlock_t *) rdr_to_pc_datablock;

	if (!rdr_to_pc_datablock
			|| rdr_to_pc_datablock_len < sizeof *datablock
			|| datablock->bMessageType != 0x80)
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;

	if (datablock->bStatus != CCID_BSTATUS_OK_ACTIVE)
		return SC_ERROR_TRANSMIT_FAILED;

	return sc_apdu_set_resp(ctx, apdu,
			rdr_to_pc_datablock + sizeof *datablock,
			htole32(datablock->dwLength));
}

static int escape_perform_verify(struct sc_reader *reader,
		struct sc_pin_cmd_data *data)
{
	u8 rbuf[0xff];
	sc_apdu_t apdu;
	int r;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse     = SC_APDU_CASE_4_SHORT;
	apdu.cla     = escape_cla;
	apdu.ins     = escape_ins;
	apdu.p1      = escape_p1_PIN;
	apdu.p2      = escape_p2_PC_to_RDR_Secure;
	apdu.resp    = rbuf;
	apdu.resplen = sizeof rbuf;
	apdu.le      = sizeof rbuf;

	if (!reader || !reader->ops || !reader->ops->transmit) {
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	r = escape_pin_cmd_to_buf(reader->ctx, data,
			(unsigned char **) &apdu.data, &apdu.datalen);
	if (r < 0) {
		sc_log(reader->ctx, 
				"Error encoding PC_to_RDR_Secure");
		goto err;
	}
	apdu.lc = apdu.datalen;

	r = reader->ops->transmit(reader, &apdu);
	if (r < 0) {
		sc_log(reader->ctx, 
				"Error performing PC_to_RDR_Secure");
		goto err;
	}

	if (apdu.sw1 != 0x90 && apdu.sw2 != 0x00) {
		sc_log(reader->ctx, 
				"Error decoding PC_to_RDR_Secure");
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	r = escape_buf_to_verify_result(reader->ctx, apdu.resp, apdu.resplen,
			data->apdu);

err:
	free((unsigned char *) apdu.data);

	return r;
}

static int escape_perform_pace(struct sc_reader *reader,
		void *establish_pace_channel_input,
		void *establish_pace_channel_output)
{
	u8 rbuf[0xffff];
	sc_apdu_t apdu;
	int r;
	struct establish_pace_channel_input  *input  =
		establish_pace_channel_input;
	struct establish_pace_channel_output *output =
		establish_pace_channel_output;

	memset(&apdu, 0, sizeof(apdu));
	apdu.cse     = SC_APDU_CASE_4_EXT;
	apdu.cla     = escape_cla;
	apdu.ins     = escape_ins;
	apdu.p1      = escape_p1_PIN;
	apdu.p2      = escape_p2_EstablishPACEChannel;
	apdu.resp    = rbuf;
	apdu.resplen = sizeof rbuf;
	apdu.le      = sizeof rbuf;

	if (!reader || !reader->ops || !reader->ops->transmit) {
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	r = escape_pace_input_to_buf(reader->ctx, input,
			(unsigned char **) &apdu.data, &apdu.datalen);
	if (r < 0) {
		sc_log(reader->ctx, 
				"Error encoding EstablishPACEChannel");
		goto err;
	}
	apdu.lc = apdu.datalen;

	r = reader->ops->transmit(reader, &apdu);
	if (r < 0) {
		sc_log(reader->ctx, 
				"Error performing EstablishPACEChannel");
		goto err;
	}

	if (apdu.sw1 != 0x90 && apdu.sw2 != 0x00) {
		sc_log(reader->ctx, 
				"Error decoding EstablishPACEChannel");
		r = SC_ERROR_NOT_SUPPORTED;
		goto err;
	}

	r = escape_buf_to_pace_output(reader->ctx, apdu.resp, apdu.resplen,
			output);

err:
	free((unsigned char *) apdu.data);

	return r;
}

struct sc_asn1_entry g_PACECapabilities_data[] = {
	{ "capabilityPACE",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x01|SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
	{ "capabilityEID",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x02|SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
	{ "capabilityESign",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x03|SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
	{ "capabilityDestroy",
		SC_ASN1_STRUCT, SC_ASN1_CTX|0x04|SC_ASN1_CONS, SC_ASN1_ALLOC, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};
struct sc_asn1_entry g_PACECapabilities[] = {
	{ "PACECapabilities",
		SC_ASN1_STRUCT, SC_ASN1_TAG_SEQUENCE|SC_ASN1_CONS, 0, NULL, NULL },
	{ NULL , 0 , 0 , 0 , NULL , NULL }
};

int escape_buf_to_pace_capabilities(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		unsigned long *sc_reader_t_capabilities)
{
	int pace = 0, eid = 0, esign = 0, destroy = 0;
	struct sc_asn1_entry PACECapabilities_data[
		sizeof g_PACECapabilities_data/
		sizeof *g_PACECapabilities_data];
	struct sc_asn1_entry PACECapabilities[
		sizeof g_PACECapabilities/
		sizeof *g_PACECapabilities];
	struct sc_asn1_entry capabilityPACE[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityEID[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityESign[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityDestroy[
		sizeof g_boolean/
		sizeof *g_boolean];

	sc_copy_asn1_entry(g_PACECapabilities,
			PACECapabilities);
	sc_format_asn1_entry(PACECapabilities,
			PACECapabilities_data, 0, 1);

	sc_copy_asn1_entry(g_PACECapabilities_data,
			PACECapabilities_data);
	sc_format_asn1_entry(PACECapabilities_data+0,
			&capabilityPACE, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+1,
			&capabilityEID, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+2,
			&capabilityESign, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+3,
			&capabilityDestroy, NULL, 1);

	sc_copy_asn1_entry(g_boolean,
			capabilityPACE);
	sc_format_asn1_entry(capabilityPACE+0,
			&pace, NULL, 0);

	sc_copy_asn1_entry(g_boolean,
			capabilityEID);
	sc_format_asn1_entry(capabilityEID+0,
			&eid, NULL, 0);

	sc_copy_asn1_entry(g_boolean,
			capabilityESign);
	sc_format_asn1_entry(capabilityESign+0,
			&esign, NULL, 0);

	sc_copy_asn1_entry(g_boolean,
			capabilityDestroy);
	sc_format_asn1_entry(capabilityDestroy+0,
			&destroy, NULL, 0);

	LOG_TEST_RET(ctx,
			sc_asn1_decode(ctx, PACECapabilities,
				asn1, asn1_len, NULL, NULL),
			"Error decoding PACECapabilities");

	/* We got a valid PACE Capabilities reply. There is currently no mechanism
	 * to determine support PIN verification/modification with a escape
	 * command. Since the reader implements this mechanism it is reasonable to
	 * assume that PIN verification/modification is available. */
	*sc_reader_t_capabilities = SC_READER_CAP_PIN_PAD;

	if (pace)
		*sc_reader_t_capabilities |= SC_READER_CAP_PACE_GENERIC;
	if (eid)
		*sc_reader_t_capabilities |= SC_READER_CAP_PACE_EID;
	if (esign)
		*sc_reader_t_capabilities |= SC_READER_CAP_PACE_ESIGN;
	if (destroy)
		*sc_reader_t_capabilities |= SC_READER_CAP_PACE_DESTROY_CHANNEL;

	return SC_SUCCESS;
}

int escape_pace_capabilities_to_buf(sc_context_t *ctx,
		const unsigned long sc_reader_t_capabilities,
		unsigned char **asn1, size_t *asn1_len)
{
	int yes = 1, no = 0;
	struct sc_asn1_entry PACECapabilities_data[
		sizeof g_PACECapabilities_data/
		sizeof *g_PACECapabilities_data];
	struct sc_asn1_entry PACECapabilities[
		sizeof g_PACECapabilities/
		sizeof *g_PACECapabilities];
	struct sc_asn1_entry capabilityPACE[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityEID[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityESign[
		sizeof g_boolean/
		sizeof *g_boolean];
	struct sc_asn1_entry capabilityDestroy[
		sizeof g_boolean/
		sizeof *g_boolean];

	sc_copy_asn1_entry(g_EstablishPACEChannel,
			PACECapabilities);
	sc_format_asn1_entry(PACECapabilities,
			PACECapabilities_data, 0, 1);

	sc_copy_asn1_entry(g_PACECapabilities_data,
			PACECapabilities_data);
	sc_format_asn1_entry(PACECapabilities_data+0,
			&capabilityPACE, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+1,
			&capabilityEID, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+2,
			&capabilityESign, NULL, 1);
	sc_format_asn1_entry(PACECapabilities_data+3,
			&capabilityDestroy, NULL, 1);

	sc_copy_asn1_entry(g_boolean,
			capabilityPACE);
	sc_format_asn1_entry(capabilityPACE,
			sc_reader_t_capabilities & SC_READER_CAP_PACE_GENERIC
			? &yes : &no, NULL, 1);

	sc_copy_asn1_entry(g_boolean,
			capabilityEID);
	sc_format_asn1_entry(capabilityEID,
			sc_reader_t_capabilities & SC_READER_CAP_PACE_EID
			? &yes : &no, NULL, 1);

	sc_copy_asn1_entry(g_boolean,
			capabilityESign);
	sc_format_asn1_entry(capabilityESign,
			sc_reader_t_capabilities & SC_READER_CAP_PACE_ESIGN
			? &yes : &no, NULL, 1);

	sc_copy_asn1_entry(g_boolean,
			capabilityDestroy);
	sc_format_asn1_entry(capabilityDestroy,
			sc_reader_t_capabilities & SC_READER_CAP_PACE_DESTROY_CHANNEL
			? &yes : &no, NULL, 1);

	return sc_asn1_encode(ctx, PACECapabilities, asn1, asn1_len);
}

void sc_detect_escape_cmds(sc_reader_t *reader)
{
	int error = 0;
	u8 rbuf[0xff+1];
	sc_apdu_t apdu;
	unsigned long capabilities;

	if (reader && reader->ops && reader->ops->transmit) {
		memset(&apdu, 0, sizeof(apdu));
		apdu.cse     = SC_APDU_CASE_2_SHORT;
		apdu.cla     = escape_cla;
		apdu.ins     = escape_ins;
		apdu.p1      = escape_p1_PIN;
		apdu.p2      = escape_p2_GetReaderPACECapabilities;
		apdu.resp    = rbuf;
		apdu.resplen = sizeof rbuf;
		apdu.le      = sizeof rbuf;

		if (reader->ops->transmit(reader, &apdu) == SC_SUCCESS
				&& apdu.sw1 == 0x90 && apdu.sw2 == 0x00
				&& escape_buf_to_pace_capabilities(reader->ctx,
					apdu.resp, apdu.resplen, &capabilities) == SC_SUCCESS) {
			if (capabilities & SC_READER_CAP_PIN_PAD
					&& !(reader->capabilities & SC_READER_CAP_PIN_PAD)) {
				((struct sc_reader_operations *) reader->ops)->perform_verify =
					escape_perform_verify;
				sc_log(reader->ctx, 
						"Added escape command wrappers for PIN verification/modification to '%s'", reader->name);
			}

			if (capabilities & SC_READER_CAP_PACE_GENERIC
					&& !(reader->capabilities & SC_READER_CAP_PACE_GENERIC)) {
				((struct sc_reader_operations *) reader->ops)->perform_pace =
					escape_perform_pace;
				sc_log(reader->ctx, 
						"Added escape command wrappers for PACE to '%s'", reader->name);
			}

			reader->capabilities |= capabilities;
		} else {
			error++;
			sc_log(reader->ctx, 
					"%s does not support escape commands", reader->name);
		}

		apdu.p1      = escape_p1_IFD;
		apdu.p2      = escape_p2_vendor;
		apdu.resplen = sizeof rbuf;
		if (reader->ops->transmit(reader, &apdu) == SC_SUCCESS
				&& apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			if (!reader->vendor) {
				/* add NUL termination, just in case... */
				rbuf[apdu.resplen] = '\0';
				reader->vendor = strdup((const char *) rbuf);
			}
		} else {
			error++;
		}

		apdu.p1      = escape_p1_IFD;
		apdu.p2      = escape_p2_version_firmware;
		apdu.resplen = sizeof rbuf;
		if (reader->ops->transmit(reader, &apdu) == SC_SUCCESS
				&& apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			if (!reader->version_major && !reader->version_minor) {
				unsigned int major = 0, minor = 0;
				/* add NUL termination, just in case... */
				rbuf[apdu.resplen] = '\0';
				sscanf((const char *) rbuf, "%u.%u", &major, &minor);
				reader->version_major = major>0xff ? 0xff : major;
				reader->version_minor = minor>0xff ? 0xff : minor;
			}
		} else {
			error++;
		}
	}

	if (error && reader) {
		sc_log(reader->ctx, 
				"%d escape command%s failed, need to reset the card",
				error, error == 1 ? "" : "s");
		if (reader->ops && reader->ops->transmit) {
			memset(&apdu, 0, sizeof(apdu));
			apdu.cse     = SC_APDU_CASE_3_SHORT;
			apdu.cla     = 0x00;
			apdu.ins     = 0xA4;
			apdu.p1      = 8;
			apdu.p2      = 0x0C;
			apdu.data    = rbuf;
			rbuf[0] = 0x3F;
			rbuf[1] = 0x00;
			apdu.datalen = 2;
			apdu.lc      = 2;
			apdu.resp    = NULL;
			apdu.resplen = 0;
			apdu.le      = 0;
			reader->ops->transmit(reader, &apdu);
		}
	}
}
