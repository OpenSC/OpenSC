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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OPENSC_ERRORS_H
#define _OPENSC_ERRORS_H

#define SC_SUCCESS				0
#define SC_NO_ERROR				0

#define SC_ERROR_MIN				-1000
#define SC_ERROR_UNKNOWN			-1000
#define SC_ERROR_CMD_TOO_SHORT			-1001
#define SC_ERROR_CMD_TOO_LONG			-1002
#define SC_ERROR_NOT_SUPPORTED			-1003
#define SC_ERROR_TRANSMIT_FAILED		-1004
#define SC_ERROR_FILE_NOT_FOUND			-1005
#define SC_ERROR_INVALID_ARGUMENTS		-1006
#define SC_ERROR_PKCS15_APP_NOT_FOUND		-1007
#define SC_ERROR_REQUIRED_PARAMETER_NOT_FOUND	-1008
#define SC_ERROR_OUT_OF_MEMORY			-1009
#define SC_ERROR_NO_READERS_FOUND		-1010
#define SC_ERROR_OBJECT_NOT_VALID		-1011
#define SC_ERROR_ILLEGAL_RESPONSE		-1012
#define SC_ERROR_PIN_CODE_INCORRECT		-1013
#define SC_ERROR_SECURITY_STATUS_NOT_SATISFIED	-1014
#define SC_ERROR_CONNECTING_TO_RES_MGR		-1015
#define SC_ERROR_INVALID_ASN1_OBJECT		-1016
#define SC_ERROR_BUFFER_TOO_SMALL		-1017
#define SC_ERROR_CARD_NOT_PRESENT		-1018
#define SC_ERROR_RESOURCE_MANAGER		-1019
#define SC_ERROR_CARD_REMOVED			-1020
#define SC_ERROR_INVALID_PIN_LENGTH		-1021
#define SC_ERROR_UNKNOWN_SMARTCARD		-1022
#define SC_ERROR_UNKNOWN_REPLY			-1023
#define SC_ERROR_OBJECT_NOT_FOUND		-1024
#define SC_ERROR_CARD_RESET			-1025
#define SC_ERROR_ASN1_OBJECT_NOT_FOUND		-1026
#define SC_ERROR_ASN1_END_OF_CONTENTS		-1027
#define SC_ERROR_TOO_MANY_OBJECTS		-1028
#define SC_ERROR_INVALID_CARD			-1029
#define SC_ERROR_WRONG_LENGTH			-1030
#define SC_ERROR_RECORD_NOT_FOUND		-1031
#define SC_ERROR_INTERNAL			-1032
#define SC_ERROR_CLASS_NOT_SUPPORTED		-1033
#define SC_ERROR_SLOT_NOT_FOUND			-1034
#define SC_ERROR_SLOT_ALREADY_CONNECTED		-1035
#define SC_ERROR_AUTH_METHOD_BLOCKED		-1036
#define SC_ERROR_SYNTAX_ERROR			-1037
#define SC_ERROR_INCONSISTENT_PROFILE		-1038
#define SC_ERROR_FILE_ALREADY_EXISTS		-1039

#endif
