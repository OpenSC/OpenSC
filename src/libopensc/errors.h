/*
 * errors.h: OpenSC error codes
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 */

#ifndef _OPENSC_ERRORS_H
#define _OPENSC_ERRORS_H

#ifdef __cplusplus
extern "C" {
#endif

#define SC_SUCCESS				0

/* Errors related to reader operation */
#define SC_ERROR_READER				-1100
#define SC_ERROR_NO_READERS_FOUND		-1101
/* Unused: -1102 */
/* Unused: -1103 */
#define SC_ERROR_CARD_NOT_PRESENT		-1104
#define SC_ERROR_CARD_REMOVED			-1105
#define SC_ERROR_CARD_RESET			-1106
#define SC_ERROR_TRANSMIT_FAILED		-1107
#define SC_ERROR_KEYPAD_TIMEOUT			-1108
#define SC_ERROR_KEYPAD_CANCELLED		-1109
#define SC_ERROR_KEYPAD_PIN_MISMATCH		-1110
#define SC_ERROR_KEYPAD_MSG_TOO_LONG		-1111
#define SC_ERROR_EVENT_TIMEOUT			-1112
#define SC_ERROR_CARD_UNRESPONSIVE		-1113
#define SC_ERROR_READER_DETACHED		-1114
#define SC_ERROR_READER_REATTACHED		-1115
#define SC_ERROR_READER_LOCKED			-1116

/* Resulting from a card command or related to the card*/
#define SC_ERROR_CARD_CMD_FAILED		-1200
#define SC_ERROR_FILE_NOT_FOUND			-1201
#define SC_ERROR_RECORD_NOT_FOUND		-1202
#define SC_ERROR_CLASS_NOT_SUPPORTED		-1203
#define SC_ERROR_INS_NOT_SUPPORTED		-1204
#define SC_ERROR_INCORRECT_PARAMETERS		-1205
#define SC_ERROR_WRONG_LENGTH			-1206
#define SC_ERROR_MEMORY_FAILURE			-1207
#define SC_ERROR_NO_CARD_SUPPORT		-1208
#define SC_ERROR_NOT_ALLOWED			-1209
#define SC_ERROR_INVALID_CARD			-1210
#define SC_ERROR_SECURITY_STATUS_NOT_SATISFIED	-1211
#define SC_ERROR_AUTH_METHOD_BLOCKED		-1212
#define SC_ERROR_UNKNOWN_DATA_RECEIVED		-1213
#define SC_ERROR_PIN_CODE_INCORRECT		-1214
#define SC_ERROR_FILE_ALREADY_EXISTS		-1215
#define SC_ERROR_DATA_OBJECT_NOT_FOUND		-1216
#define SC_ERROR_NOT_ENOUGH_MEMORY		-1217
#define SC_ERROR_CORRUPTED_DATA			-1218
#define SC_ERROR_FILE_END_REACHED		-1219
#define SC_ERROR_REF_DATA_NOT_USABLE	-1220

/* Returned by OpenSC library when called with invalid arguments */
#define SC_ERROR_INVALID_ARGUMENTS		-1300
/* Unused: -1301 */
/* Unused: -1302 */
#define SC_ERROR_BUFFER_TOO_SMALL		-1303
#define SC_ERROR_INVALID_PIN_LENGTH		-1304
#define SC_ERROR_INVALID_DATA			-1305

/* Resulting from OpenSC internal operation */
#define SC_ERROR_INTERNAL			-1400
#define SC_ERROR_INVALID_ASN1_OBJECT		-1401
#define SC_ERROR_ASN1_OBJECT_NOT_FOUND		-1402
#define SC_ERROR_ASN1_END_OF_CONTENTS		-1403
#define SC_ERROR_OUT_OF_MEMORY			-1404
#define SC_ERROR_TOO_MANY_OBJECTS		-1405
#define SC_ERROR_OBJECT_NOT_VALID		-1406
#define SC_ERROR_OBJECT_NOT_FOUND		-1407
#define SC_ERROR_NOT_SUPPORTED			-1408
#define SC_ERROR_PASSPHRASE_REQUIRED		-1409
#define SC_ERROR_INCONSISTENT_CONFIGURATION	-1410
#define SC_ERROR_DECRYPT_FAILED			-1411
#define SC_ERROR_WRONG_PADDING			-1412
#define SC_ERROR_WRONG_CARD			-1413
#define SC_ERROR_CANNOT_LOAD_MODULE		-1414
#define SC_ERROR_OFFSET_TOO_LARGE		-1415
#define SC_ERROR_NOT_IMPLEMENTED		-1416

/* Relating to PKCS #15 init stuff */
#define SC_ERROR_PKCS15INIT			-1500
#define SC_ERROR_SYNTAX_ERROR			-1501
#define SC_ERROR_INCONSISTENT_PROFILE		-1502
#define SC_ERROR_INCOMPATIBLE_KEY		-1503
#define SC_ERROR_NO_DEFAULT_KEY			-1504
#define SC_ERROR_NON_UNIQUE_ID			-1505
#define SC_ERROR_CANNOT_LOAD_KEY		-1506
/* Unused: -1007 */
#define SC_ERROR_TEMPLATE_NOT_FOUND		-1508
#define SC_ERROR_INVALID_PIN_REFERENCE		-1509
#define SC_ERROR_FILE_TOO_SMALL			-1510

/* Related to secure messaging */
#define SC_ERROR_SM				-1600
#define SC_ERROR_SM_ENCRYPT_FAILED		-1601
#define SC_ERROR_SM_INVALID_LEVEL		-1602
#define SC_ERROR_SM_NO_SESSION_KEYS		-1603
#define SC_ERROR_SM_INVALID_SESSION_KEY		-1604
#define SC_ERROR_SM_NOT_INITIALIZED		-1605
#define SC_ERROR_SM_AUTHENTICATION_FAILED	-1606
#define SC_ERROR_SM_RAND_FAILED			-1607
#define SC_ERROR_SM_KEYSET_NOT_FOUND		-1608
#define SC_ERROR_SM_IFD_DATA_MISSING		-1609
#define SC_ERROR_SM_NOT_APPLIED			-1610
#define SC_ERROR_SM_SESSION_ALREADY_ACTIVE	-1611
#define SC_ERROR_SM_INVALID_CHECKSUM		-1612

/* Errors that do not fit the categories above */
#define SC_ERROR_UNKNOWN			-1900
#define SC_ERROR_PKCS15_APP_NOT_FOUND		-1901

const char *sc_strerror(int sc_errno);

#ifdef __cplusplus
}
#endif

#endif
