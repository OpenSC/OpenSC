/*
 * muscle.c: Support for MuscleCard Applet from musclecard.com 
 *
 * Copyright (C) 2006, Identity Alliance, Thomas Harning <support@identityalliance.com>
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

#include <string.h>

#include "internal.h"
#include "muscle.h"

#define MSC_RSA_PUBLIC		0x01
#define MSC_RSA_PRIVATE 	0x02
#define MSC_RSA_PRIVATE_CRT	0x03
#define MSC_DSA_PUBLIC		0x04
#define MSC_DSA_PRIVATE 	0x05

static msc_id inputId = { { 0xFF, 0xFF, 0xFF, 0xFF } };
static msc_id outputId = { { 0xFF, 0xFF, 0xFF, 0xFE } };

int msc_list_objects(sc_card_t* card, u8 next, mscfs_file_t* file) {
	sc_apdu_t apdu;
	u8 fileData[14];
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x58, next, 0x00);
	apdu.le = 14;
	apdu.resplen = 14;
	apdu.resp = fileData;
	r = sc_transmit_apdu(card, &apdu);
	if (r)
		return r;
	
	if(apdu.sw1 == 0x9C && apdu.sw2 == 0x12) {
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r)
		return r;
	if(apdu.resplen == 0) /* No more left */
		return 0;
	if (apdu.resplen != 14) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "expected 14 bytes, got %d.\n", apdu.resplen);
		return SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}
	memcpy(file->objectId.id, fileData, 4);
	file->size = bebytes2ulong(fileData + 4);
	file->read = bebytes2ushort(fileData + 8);
	file->write = bebytes2ushort(fileData + 10);
	file->delete = bebytes2ushort(fileData + 12);

	return 1;
}

int msc_partial_read_object(sc_card_t *card, msc_id objectId, int offset, u8 *data, size_t dataLength)
{
	u8 buffer[9];
	sc_apdu_t apdu;
	int r;
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x56, 0x00, 0x00);
	
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"READ: Offset: %x\tLength: %i\n", offset, dataLength);
	memcpy(buffer, objectId.id, 4);
	ulong2bebytes(buffer + 4, offset);
	buffer[8] = (u8)dataLength;
	apdu.data = buffer;
	apdu.datalen = 9;
	apdu.lc = 9;
	apdu.le = dataLength;
	apdu.resplen = dataLength;
	apdu.resp = data; 
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return dataLength;
	if(apdu.sw1 == 0x9C) {
		if(apdu.sw2 == 0x07) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_FILE_NOT_FOUND);
		} else if(apdu.sw2 == 0x06) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_ALLOWED);
		} else if(apdu.sw2 == 0x0F) {
			/* GUESSED */
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
		"got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
	return dataLength;
	
}

int msc_read_object(sc_card_t *card, msc_id objectId, int offset, u8 *data, size_t dataLength)
{
	int r;
	size_t i;
	size_t max_read_unit = MSC_MAX_READ;

	for(i = 0; i < dataLength; i += max_read_unit) {
		r = msc_partial_read_object(card, objectId, offset + i, data + i, MIN(dataLength - i, max_read_unit));
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Error in partial object read");
	}
	return dataLength;
}

int msc_zero_object(sc_card_t *card, msc_id objectId, size_t dataLength)
{
	u8 zeroBuffer[MSC_MAX_APDU];
	size_t i;
	size_t max_write_unit = MSC_MAX_SEND - 9; /* - 9 for object ID+length */

	memset(zeroBuffer, 0, max_write_unit);
	for(i = 0; i < dataLength; i += max_write_unit) {
		int r = msc_partial_update_object(card, objectId, i, zeroBuffer, MIN(dataLength - i, max_write_unit));
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Error in zeroing file update");
	}
	return 0;
}

int msc_create_object(sc_card_t *card, msc_id objectId, size_t objectSize, unsigned short readAcl, unsigned short writeAcl, unsigned short deleteAcl)
{
	u8 buffer[14];
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x5A, 0x00, 0x00);
	apdu.lc = 14;
	apdu.data = buffer,
	apdu.datalen = 14;
	
	memcpy(buffer, objectId.id, 4);
	ulong2bebytes(buffer + 4, objectSize);
	ushort2bebytes(buffer + 8, readAcl);
	ushort2bebytes(buffer + 10, writeAcl);
	ushort2bebytes(buffer + 12, deleteAcl);
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return objectSize;
	if(apdu.sw1 == 0x9C) {
		if(apdu.sw2 == 0x01) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_MEMORY_FAILURE);
		} else if(apdu.sw2 == 0x08) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_FILE_ALREADY_EXISTS);
		} else if(apdu.sw2 == 0x06) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_ALLOWED);
		}
	}
	if (card->ctx->debug >= 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
		     apdu.sw1, apdu.sw2);
	}
	msc_zero_object(card, objectId, objectSize);
	return objectSize;
}

/* Update up to MSC_MAX_READ - 9 bytes */
int msc_partial_update_object(sc_card_t *card, msc_id objectId, int offset, const u8 *data, size_t dataLength)
{
	u8 buffer[MSC_MAX_APDU];
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x54, 0x00, 0x00);
	apdu.lc = dataLength + 9;
	if (card->ctx->debug >= 2)
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "WRITE: Offset: %x\tLength: %i\n", offset, dataLength);
	
	memcpy(buffer, objectId.id, 4);
	ulong2bebytes(buffer + 4, offset);
	buffer[8] = (u8)dataLength;
	memcpy(buffer + 9, data, dataLength);
	apdu.data = buffer;
	apdu.datalen = apdu.lc;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return dataLength;
	if(apdu.sw1 == 0x9C) {
		if(apdu.sw2 == 0x07) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_FILE_NOT_FOUND);
		} else if(apdu.sw2 == 0x06) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_ALLOWED);
		} else if(apdu.sw2 == 0x0F) {
			/* GUESSED */
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
		}
	}
	if (card->ctx->debug >= 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
		     apdu.sw1, apdu.sw2);
	}
	return dataLength;
}

int msc_update_object(sc_card_t *card, msc_id objectId, int offset, const u8 *data, size_t dataLength)
{
	int r;
	size_t i;
	size_t max_write_unit = MSC_MAX_SEND - 9;
	for(i = 0; i < dataLength; i += max_write_unit) {
		r = msc_partial_update_object(card, objectId, offset + i, data + i, MIN(dataLength - i, max_write_unit));
		SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "Error in partial object update");
	}
	return dataLength;
}

int msc_delete_object(sc_card_t *card, msc_id objectId, int zero)
{
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x52, 0x00, zero ? 0x01 : 0x00);
	apdu.lc = 4;
	apdu.data = objectId.id;
	apdu.datalen = 4;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return 0;
	if(apdu.sw1 == 0x9C) {
		if(apdu.sw2 == 0x07) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_FILE_NOT_FOUND);
		} else if(apdu.sw2 == 0x06) {
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_NOT_ALLOWED);
		}
	}
	if (card->ctx->debug >= 2) {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
		     apdu.sw1, apdu.sw2);
	}
	return 0;
}

int msc_select_applet(sc_card_t *card, u8 *appletId, size_t appletIdLength)
{
	sc_apdu_t apdu;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
	apdu.lc = appletIdLength;
	apdu.data = appletId;
	apdu.datalen = appletIdLength;
	apdu.resplen = 0;
	apdu.le = 0;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		return 1;
	
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  SC_ERROR_CARD_CMD_FAILED);
}

/* Truncate the nulls at the end of a PIN, useful in padding is unnecessarily added */
static void truncatePinNulls(const u8* pin, int *pinLength) {
	for(; *pinLength > 0; (*pinLength)--) {
		if(pin[*pinLength - 1]) break;
	}
}

int msc_verify_pin(sc_card_t *card, int pinNumber, const u8 *pinValue, int pinLength, int *tries)
{
	sc_apdu_t apdu;
	int r;

	const int bufferLength = MSC_MAX_PIN_LENGTH;
	u8 buffer[MSC_MAX_PIN_LENGTH];
	assert(pinLength <= MSC_MAX_PIN_LENGTH);

	msc_verify_pin_apdu(card, &apdu, buffer, bufferLength, pinNumber, pinValue, pinLength);
	if(tries)
		*tries = -1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		return 0;
	} else if(apdu.sw1 == 0x63) { /* Invalid auth */
		if(tries)
			*tries = apdu.sw2 & 0x0F;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x9C && apdu.sw2 == 0x02) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_AUTH_METHOD_BLOCKED);
	}
	
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  SC_ERROR_PIN_CODE_INCORRECT);
}

/* USE ISO_VERIFY due to tries return */
void msc_verify_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pinValue, int pinLength)
{
	assert(buffer);
	assert(bufferLength >= (size_t)pinLength);
	assert(pinLength <= MSC_MAX_PIN_LENGTH);

	truncatePinNulls(pinValue, &pinLength);

	memcpy(buffer, pinValue, pinLength);
	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x42, pinNumber, 0);
	apdu->lc = pinLength;
	apdu->data = buffer;
	apdu->datalen = pinLength;
}

int msc_unblock_pin(sc_card_t *card, int pinNumber, const u8 *pukValue, int pukLength, int *tries)
{
	sc_apdu_t apdu;
	int r;
	const int bufferLength = MSC_MAX_PIN_LENGTH;
	u8 buffer[MSC_MAX_PIN_LENGTH];

	assert(pukLength <= MSC_MAX_PIN_LENGTH);

	msc_unblock_pin_apdu(card, &apdu, buffer, bufferLength, pinNumber, pukValue, pukLength);
	if(tries)
		*tries = -1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		return 0;
	} else if(apdu.sw1 == 0x63) { /* Invalid auth */
		if(tries)
			*tries = apdu.sw2 & 0x0F;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x9C && apdu.sw2 == 0x02) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_AUTH_METHOD_BLOCKED);
	}
	
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  SC_ERROR_PIN_CODE_INCORRECT);
}

void msc_unblock_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pukValue, int pukLength)
{
	assert(buffer);
	assert(bufferLength >= (size_t)pukLength);
	assert(pukLength <= MSC_MAX_PIN_LENGTH);

	truncatePinNulls(pukValue, &pukLength);

	memcpy(buffer, pukValue, pukLength);
	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x46, pinNumber, 0);
	apdu->lc = pukLength;
	apdu->data = buffer;
	apdu->datalen = pukLength;
}

int msc_change_pin(sc_card_t *card, int pinNumber, const u8 *pinValue, int pinLength, const u8 *newPin, int newPinLength, int *tries)
{
	sc_apdu_t apdu;
	int r;
	const int bufferLength = (MSC_MAX_PIN_LENGTH + 1) * 2;
	u8 buffer[(MSC_MAX_PIN_LENGTH + 1) * 2];

	msc_change_pin_apdu(card, &apdu, buffer, bufferLength, pinNumber, pinValue, pinLength, newPin, newPinLength);
	if(tries)
		*tries = -1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		return 0;
	} else if(apdu.sw1 == 0x63) { /* Invalid auth */
		if(tries)
			*tries = apdu.sw2 & 0x0F;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x9C && apdu.sw2 == 0x02) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL,  SC_ERROR_PIN_CODE_INCORRECT);
	} else if(apdu.sw1 == 0x69 && apdu.sw2 == 0x83) {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_AUTH_METHOD_BLOCKED);
	}
	
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE,  SC_ERROR_PIN_CODE_INCORRECT);
}

/* USE ISO_VERIFY due to tries return */
void msc_change_pin_apdu(sc_card_t *card, sc_apdu_t *apdu, u8* buffer, size_t bufferLength, int pinNumber, const u8 *pinValue, int pinLength, const u8 *newPin, int newPinLength)
{
	u8 *ptr;
	assert(pinLength <= MSC_MAX_PIN_LENGTH);
	assert(newPinLength <= MSC_MAX_PIN_LENGTH);
	assert(buffer);
	assert(bufferLength >= pinLength + newPinLength + 2UL);

	truncatePinNulls(pinValue, &pinLength);
	truncatePinNulls(newPin, &newPinLength);

	ptr = buffer;

	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT, 0x44, pinNumber, 0);
	*ptr = pinLength;
	ptr++;
	memcpy(ptr, pinValue, pinLength);
	ptr += pinLength;
	*ptr = newPinLength;
	ptr++;
	memcpy(ptr, newPin, newPinLength);
	apdu->lc = pinLength + newPinLength + 2;
	apdu->datalen = apdu->lc;
	apdu->data = buffer;
}

int msc_get_challenge(sc_card_t *card, unsigned short dataLength, unsigned short seedLength, u8 *seedData, u8 *outputData)
{
	sc_apdu_t apdu;
	int r, location, cse;
	size_t len;
	u8 *buffer, *ptr;
	
	location = (dataLength < MSC_MAX_READ) ? 1 : 2; /* 1 == APDU, 2 == (seed in 0xFFFFFFFE, out in 0xFFFFFFFF) */
	cse = (location == 1) ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT;
	len = seedLength + 4;
	
	assert(seedLength < MSC_MAX_SEND - 4);
	assert(dataLength < MSC_MAX_READ - 9); /* Output buffer doesn't seem to operate as desired.... nobody can read/delete */
	
	buffer = malloc(len);
	if(!buffer) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	ptr = buffer;
	ushort2bebytes(ptr, dataLength);
	ptr+=2;
	ushort2bebytes(ptr, seedLength);
	ptr+=2;
	if(seedLength > 0) {
		memcpy(ptr, seedData, seedLength);
	}
	sc_format_apdu(card, &apdu, cse, 0x62, 0x00, location);
	apdu.data = buffer;
	apdu.datalen = len;
	apdu.lc = len;
	
	if(location == 1) {
		u8* outputBuffer = malloc(dataLength + 2);
		if(outputBuffer == NULL) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
		apdu.le = dataLength + 2;
		apdu.resp = outputBuffer;
		apdu.resplen = dataLength + 2;
	}
	r = sc_transmit_apdu(card, &apdu);
	if(location == 1) {
		memcpy(outputData, apdu.resp + 2, dataLength);
		free(apdu.resp);
	}
	free(buffer);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(location == 1) {
		if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
			return SC_SUCCESS;
		} else {
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r) {
				if (card->ctx->debug >= 2) {
					sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
					     apdu.sw1, apdu.sw2);
				}
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
			}
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
		}
	} else {
		if(apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
			r = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (r) {
				if (card->ctx->debug >= 2) {
					sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
					     apdu.sw1, apdu.sw2);
				}
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
			}
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
		}
		r = msc_read_object(card, inputId, 2, outputData, dataLength);
		if(r < 0)
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
		msc_delete_object(card, inputId,0);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
}

int msc_generate_keypair(sc_card_t *card, int privateKey, int publicKey, int algorithm, int keySize, int options)
{
	sc_apdu_t apdu;
	u8 buffer[16]; /* Keypair payload length */
	u8 *ptr = buffer;
	int r;
	unsigned short prRead = 0xFFFF, prWrite = 0x0002, prCompute = 0x0002,
		puRead = 0x0000, puWrite = 0x0002, puCompute = 0x0000;

	assert(privateKey <= 0x0F && publicKey <= 0x0F);
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x30, privateKey, publicKey);

	*ptr = algorithm; ptr++;
	
	ushort2bebytes(ptr, keySize);
	ptr+=2;
	
	ushort2bebytes(ptr, prRead);
	ptr+=2;
	ushort2bebytes(ptr, prWrite);
	ptr+=2;
	ushort2bebytes(ptr, prCompute);
	ptr+=2;
	
	ushort2bebytes(ptr, puRead);
	ptr+=2;
	ushort2bebytes(ptr, puWrite);
	ptr+=2;
	ushort2bebytes(ptr, puCompute);
	ptr+=2;
	
	*ptr = 0; /* options; -- no options for now, they need extra data */
	
	apdu.data = buffer;
	apdu.datalen = 16;
	apdu.lc = 16;
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
}

int msc_extract_key(sc_card_t *card, 
			int keyLocation)
{
	sc_apdu_t apdu;
	u8 encoding = 0;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x34, keyLocation, 0x00);
	apdu.data = &encoding;
	apdu.datalen = 1;
	apdu.lc = 1;
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
}

int msc_extract_rsa_public_key(sc_card_t *card, 
			int keyLocation,
			int* modLength, 
			u8** modulus,
			int* expLength,
			u8** exponent)
{
	int r;
	u8 buffer[1024]; /* Should be plenty... */
	int fileLocation = 1;

	r = msc_extract_key(card, keyLocation);
	if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	
	/* Read keyType, keySize, and what should be the modulus size */
	r = msc_read_object(card, inputId, fileLocation, buffer, 5);
	fileLocation += 5;
	if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	
	if(buffer[0] != MSC_RSA_PUBLIC) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_UNKNOWN_DATA_RECEIVED);
	*modLength = (buffer[3] << 8) | buffer[4];
	/* Read the modulus and the exponent length */
	
	r = msc_read_object(card, inputId, fileLocation, buffer, *modLength + 2);
	fileLocation += *modLength + 2;
	if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	
	*modulus = malloc(*modLength);
	if(!*modulus) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	memcpy(*modulus, buffer, *modLength);
	*expLength = (buffer[*modLength] << 8) | buffer[*modLength + 1];
	r = msc_read_object(card, inputId, fileLocation, buffer, *expLength);
	if(r < 0) {
		free(*modulus); *modulus = NULL;
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	*exponent = malloc(*expLength);
	if(!*exponent) {
		free(*modulus);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	}
	memcpy(*exponent, buffer, *expLength);
	return 0;
}



/* For the moment, only support streaming data to the card 
	in blocks, not through file IO */
int msc_compute_crypt_init(sc_card_t *card, 
			int keyLocation,
			int cipherMode,
			int cipherDirection,
			const u8* initData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength)
{
	sc_apdu_t apdu;
	u8 buffer[MSC_MAX_APDU];
	u8 *ptr;
	int r;

	u8 outputBuffer[MSC_MAX_APDU + 2];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x36, keyLocation, 0x01); /* Init */
	apdu.data = buffer;
	apdu.datalen = dataLength + 5;
	apdu.lc = dataLength + 5;

	memset(outputBuffer, 0, sizeof(outputBuffer));
	apdu.resp = outputBuffer;
	apdu.resplen = dataLength + 2;
	apdu.le = dataLength + 2;
	ptr = buffer;
	*ptr = cipherMode; ptr++;
	*ptr = cipherDirection; ptr++;
	*ptr = 0x01; ptr++; /* DATA LOCATION: APDU */
	*ptr = (dataLength >> 8) & 0xFF; ptr++;
	*ptr = dataLength & 0xFF; ptr++;
	memcpy(ptr, initData, dataLength);

	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		short receivedData = outputBuffer[0] << 8 | outputBuffer[1];
		*outputDataLength = receivedData;

		assert(receivedData <= MSC_MAX_APDU);
		memcpy(outputData, outputBuffer + 2, receivedData);
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "init: got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
}

int msc_compute_crypt_final(
			sc_card_t *card, 
			int keyLocation,
			const u8* inputData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength)
{
	sc_apdu_t apdu;
	u8 buffer[MSC_MAX_APDU];
	u8 outputBuffer[MSC_MAX_APDU + 2];
	u8 *ptr;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x36, keyLocation, 0x03); /* Final */
	
	apdu.data = buffer;
	apdu.datalen = dataLength + 3;
	apdu.lc = dataLength + 3;
	
	memset(outputBuffer, 0, sizeof(outputBuffer));
	apdu.resp = outputBuffer;
	apdu.resplen = dataLength + 2;
	apdu.le = dataLength +2;
	ptr = buffer;
	*ptr = 0x01; ptr++; /* DATA LOCATION: APDU */
	*ptr = (dataLength >> 8) & 0xFF; ptr++;
	*ptr = dataLength & 0xFF; ptr++;
	memcpy(ptr, inputData, dataLength);
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		short receivedData = outputBuffer[0] << 8 | outputBuffer[1];
		*outputDataLength = receivedData;
		assert(receivedData <= MSC_MAX_APDU);
		memcpy(outputData, outputBuffer + 2, receivedData);
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "final: got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
}

/* Stream data to the card through file IO */
static int msc_compute_crypt_final_object(
			sc_card_t *card, 
			int keyLocation,
			const u8* inputData,
			u8* outputData,
			size_t dataLength,
			size_t* outputDataLength)
{
	sc_apdu_t apdu;
	u8 buffer[MSC_MAX_APDU];
	u8 *ptr;
	int r;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x36, keyLocation, 0x03); /* Final */
	
	apdu.data = buffer;
	apdu.datalen = 1;
	apdu.lc = 1;
	
	ptr = buffer;
	*ptr = 0x02;
	ptr++; /* DATA LOCATION: OBJECT */
	*ptr = (dataLength >> 8) & 0xFF;
	ptr++;
	*ptr = dataLength & 0xFF;
	ptr++;
	memcpy(ptr, inputData, dataLength);

	r = msc_create_object(card, outputId, dataLength + 2, 0x02, 0x02, 0x02);
	if(r < 0) { 
		if(r == SC_ERROR_FILE_ALREADY_EXISTS) {
			r = msc_delete_object(card, outputId, 0);
			if(r < 0) {
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
			}
			r = msc_create_object(card, outputId, dataLength + 2, 0x02, 0x02, 0x02);
			if(r < 0) {
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
			}
		}
	}

	r = msc_update_object(card, outputId, 0, buffer + 1, dataLength + 2);
	if(r < 0) return r; 
	
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		r = msc_read_object(card, inputId, 2, outputData, dataLength);
		*outputDataLength = dataLength;
		msc_delete_object(card, outputId, 0);
		msc_delete_object(card, inputId, 0);
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "final: got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
	} else {
		r = SC_ERROR_CARD_CMD_FAILED;
	}
	/* this is last ditch cleanup */	
	msc_delete_object(card, outputId, 0);
	
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
}

int msc_compute_crypt(sc_card_t *card, 
			int keyLocation,
			int cipherMode,
			int cipherDirection,
			const u8* data,
			u8* outputData,
			size_t dataLength,
			size_t outputDataLength)
{
	size_t left = dataLength;
	const u8* inPtr = data;
	u8* outPtr = outputData;
	int toSend;
	int r;

	size_t received = 0;
	assert(outputDataLength >= dataLength);
	
	/* Don't send data during init... apparently current version does not support it */
	toSend = 0;
	r = msc_compute_crypt_init(card, 
		keyLocation, 
		cipherMode, 
		cipherDirection, 
		inPtr, 
		outPtr, 
		toSend,
		&received);
	if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	left -= toSend;
	inPtr += toSend;
	outPtr += received;

	toSend = MIN(left, MSC_MAX_APDU - 5);
	/* If the card supports extended APDUs, or the data fits in
           one normal APDU, use it for the data exchange */
	if (left < (MSC_MAX_SEND - 4) || (card->caps & SC_CARD_CAP_APDU_EXT) != 0) {
		r = msc_compute_crypt_final(card,
			keyLocation,
			inPtr,
			outPtr,
			toSend,
			&received);
		if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	} else { /* Data is too big: use objects */
		r = msc_compute_crypt_final_object(card,
			keyLocation,
			inPtr,
			outPtr,
			toSend,
			&received);
		if(r < 0) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}	
	outPtr += received;

	return outPtr - outputData; /* Amt received */
}

/* USED IN KEY ITEM WRITING */
#define CPYVAL(valName) \
	ushort2bebytes(p, data->valName ## Length); p+= 2; \
	memcpy(p, data->valName ## Value, data->valName ## Length); p+= data->valName ## Length

int msc_import_key(sc_card_t *card,
	int keyLocation,
	sc_cardctl_muscle_key_info_t *data)
{
	unsigned short readAcl = 0xFFFF,
		writeAcl = 0x0002,
		use = 0x0002,
		keySize = data->keySize;
	int bufferSize = 0;
	u8 *buffer, *p;
	u8 apduBuffer[6];
	sc_apdu_t apdu;
	int r;

	assert(data->keyType == 0x02 || data->keyType == 0x03);
	if(data->keyType == 0x02) {
		if( (data->pLength == 0 || !data->pValue)
		|| (data->modLength == 0 || !data->modValue))
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS); 
	} else if(data->keyType == 0x03) {
		if( (data->pLength == 0 || !data->pValue)
		|| (data->qLength == 0 || !data->qValue)
		|| (data->pqLength == 0 || !data->pqValue)
		|| (data->dp1Length == 0 || !data->dp1Value)
		|| (data->dq1Length == 0 || !data->dq1Value))
			SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS); 
	} else {
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, SC_ERROR_INVALID_ARGUMENTS);
	}
	
	if(data->keyType == 0x02) {
		bufferSize = 4 + 4 + data->pLength + data->modLength;
	} else if(data->keyType == 0x03) {
		bufferSize = 4 + 10
			+ data->pLength + data->qLength + data->pqLength
			+ data->dp1Length + data->dq1Length;
	}
	buffer = malloc(bufferSize);
	if(!buffer) SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_OUT_OF_MEMORY);
	p = buffer;
	*p = 0x00; p++; /* Encoding plain */
	*p = data->keyType; p++; /* RSA_PRIVATE */
	ushort2bebytes(p, keySize); p+=2; /* key size */
	
	if(data->keyType == 0x02) {
		CPYVAL(mod);
		CPYVAL(p);
	} else if(data->keyType == 0x03) {
		CPYVAL(p);
		CPYVAL(q);
		CPYVAL(pq);
		CPYVAL(dp1);
		CPYVAL(dq1);
	}
	
	r = msc_create_object(card, outputId, bufferSize, 0x02, 0x02, 0x02);
	if(r < 0) { 
		if(r == SC_ERROR_FILE_ALREADY_EXISTS) {
			r = msc_delete_object(card, outputId, 0);
			if(r < 0) {
				free(buffer);
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
			}
			r = msc_create_object(card, outputId, bufferSize, 0x02, 0x02, 0x02);
			if(r < 0) {
				free(buffer);
				SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_VERBOSE, r);
			}
		}
	}
	
	r = msc_update_object(card, outputId, 0, buffer, bufferSize);
	free(buffer);
	if(r < 0) return r;
	
	
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x32, keyLocation, 0x00);
	apdu.lc = 6;
	apdu.data = apduBuffer;
	apdu.datalen = 6;
	p = apduBuffer;
	ushort2bebytes(p, readAcl); p+=2;
	ushort2bebytes(p, writeAcl); p+=2;
	ushort2bebytes(p, use); 
	r = sc_transmit_apdu(card, &apdu);
	SC_TEST_RET(card->ctx, SC_LOG_DEBUG_NORMAL, r, "APDU transmit failed");
	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
		msc_delete_object(card, outputId, 0);
		return 0;
	}
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	if (r) {
		if (card->ctx->debug >= 2) {
			sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL, "keyimport: got strange SWs: 0x%02X 0x%02X\n",
			     apdu.sw1, apdu.sw2);
		}
		/* this is last ditch cleanup */
		msc_delete_object(card, outputId, 0);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, r);
	}
	/* this is last ditch cleanup */
	msc_delete_object(card, outputId, 0);

	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_CARD_CMD_FAILED);
}
#undef CPYVAL
