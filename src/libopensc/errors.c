/*
 * errors.c: The textual representation of errors
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include "errors.h"

#define DIM(v)		(sizeof(v)/(sizeof((v)[0])))

const char *sc_strerror(int error)
{
	unsigned int error_index = 0;
	const char *rdr_errors[] = {
		"Generic reader error",
		"No readers found",
		"UNUSED",
		"UNUSED",
		"Card not present",
		"Card removed",
		"Card reset",
		"Transmit failed",
		"Timed out while waiting for user input",
		"Input operation cancelled by user",
		"The two PINs did not match",
		"Message too long (keypad)",
		"Timeout while waiting for event from card reader",
		"Unresponsive card (correctly inserted?)",
		"Reader detached",
		"Reader reattached",
		"Reader in use by another application"
	};
	const unsigned int rdr_base = -SC_ERROR_READER;

	const char *card_errors[] = {
		"Card command failed",
		"File not found",
		"Record not found",
		"Unsupported CLA byte in APDU",
		"Unsupported INS byte in APDU",
		"Incorrect parameters in APDU",
		"Wrong length",
		"Card memory failure",
		"Card does not support the requested operation",
		"Not allowed",
		"Card is invalid or cannot be handled",
		"Security status not satisfied",
		"Authentication method blocked",
		"Unknown data received from card",
		"PIN code or key incorrect",
		"File already exists",
		"Data object not found",
		"Not enough memory on card",
		"Part of returned data may be corrupted",
		"End of file/record reached before reading Le bytes",
		"Reference data not usable"
	};
	const unsigned int card_base = -SC_ERROR_CARD_CMD_FAILED;

	const char *arg_errors[] = {
		"Invalid arguments",
		"UNUSED",
		"UNUSED",
		"Buffer too small",
		"Invalid PIN length",
		"Invalid data",
	};
	const unsigned int arg_base = -SC_ERROR_INVALID_ARGUMENTS;

	const char *int_errors[] = {
		"Internal error",
		"Invalid ASN.1 object",
		"Required ASN.1 object not found",
		"Premature end of ASN.1 stream",
		"Out of memory",
		"Too many objects",
		"Object not valid",
		"Requested object not found",
		"Not supported",
		"Passphrase required",
		"Inconsistent configuration",
		"Decryption failed",
		"Wrong padding",
		"Unsupported card",
		"Unable to load external module",
		"EF offset too large",
		"Not implemented",
		"Invalid Simple TLV object",
		"Premature end of Simple TLV stream",
	};
	const unsigned int int_base = -SC_ERROR_INTERNAL;

	const char *p15i_errors[] = {
		"Generic PKCS#15 initialization error",
		"Syntax error",
		"Inconsistent or incomplete PKCS#15 profile",
		"Key length/algorithm not supported by card",
		"No default (transport) key available",
		"Non unique object ID",
		"Unable to load key and certificate(s) from file",
		"UNUSED",
		"File template not found",
		"Invalid PIN reference",
		"File too small",
	};
	const unsigned int p15i_base = -SC_ERROR_PKCS15INIT;

	const char *sm_errors[] = {
		"Generic Secure Messaging error",
		"Data enciphering error",
		"Invalid secure messaging level",
		"No session keys",
		"Invalid session keys",
		"Secure Messaging not initialized",
		"Cannot authenticate card",
		"Random generation error",
		"Secure messaging keyset not found",
		"IFD data missing",
		"SM not applied",
		"SM session already active",
		"Invalid checksum"
	};
	const unsigned int sm_base = -SC_ERROR_SM;

	const char *misc_errors[] = {
		"Unknown error",
		"PKCS#15 compatible smart card not found",
	};
	const unsigned int misc_base = -SC_ERROR_UNKNOWN;

	const char *no_errors = "Success";
	const char **errors = NULL;
	unsigned int count = 0, err_base = 0;

	if (!error)
		return no_errors;
	error_index = error < 0 ? -((long long int) error) : error;

	if (error_index >= misc_base) {
		errors = misc_errors;
		count = DIM(misc_errors);
		err_base = misc_base;
	} else if (error_index >= sm_base) {
		errors = sm_errors;
		count = DIM(sm_errors);
		err_base = sm_base;
	} else if (error_index >= p15i_base) {
		errors = p15i_errors;
		count = DIM(p15i_errors);
		err_base = p15i_base;
	} else if (error_index >= int_base) {
		errors = int_errors;
		count = DIM(int_errors);
		err_base = int_base;
	} else if (error_index >= arg_base) {
		errors = arg_errors;
		count = DIM(arg_errors);
		err_base = arg_base;
	} else if (error_index >= card_base) {
		errors = card_errors;
		count = DIM(card_errors);
		err_base = card_base;
	} else if (error_index >= rdr_base) {
		errors = rdr_errors;
		count = DIM(rdr_errors);
		err_base = rdr_base;
	}
	error_index -= err_base;
	if (error_index >= count)
		return misc_errors[0];
	return errors[error_index];
}
