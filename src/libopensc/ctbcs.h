/*
    CT-BCS commands, responses and parameters for terminals 
    without keypad and display.

    This file is part of the Unix driver for Towitoko smart card readers
    Copyright (C) 1998 1999 2000 Carlos Prados <cprados@yahoo.com>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _CTBCS_
#define _CTBCS_

/*
 * Command and response size 
 */
#define CTBCS_MIN_COMMAND_SIZE		2
#define CTBCS_MIN_RESPONSE_SIZE		2

/*
 * Class byte of all CTBCS commands
 */
#define	CTBCS_CLA 			0x20

/*
 * Mandatory CT-BCS commands
 */
#define	CTBCS_INS_RESET			0x11	/* Reset CT */
#define	CTBCS_INS_REQUEST		0x12	/* Request ICC */
#define CTBCS_INS_STATUS		0x13	/* Get reader status */
#define CTBCS_INS_EJECT			0x15	/* Eject ICC */

/*
 * Additional CT-BCS commands
 */
#define CTBCS_INS_INPUT			0x16	/* Input from pin pad */
#define CTBCS_INS_OUTPUT		0x17	/* Output to pad pad display */
#define CTBCS_INS_PERFORM_VERIFICATION	0x18	/* Verify PIN from pin pad */
#define CTBCS_INS_MODIFY_VERIFICATION	0x19	/* Perform a change/unblock PIN op */

/* 
 * P1 parameter: functional units 
 */

#define CTBCS_P1_CT_KERNEL		0x00
#define CTBCS_P1_INTERFACE1		0x01
#define CTBCS_P1_INTERFACE2		0x02
#define CTBCS_P1_INTERFACE3		0x03
#define CTBCS_P1_INTERFACE4		0x04
#define CTBCS_P1_INTERFACE5		0x05
#define CTBCS_P1_INTERFACE6		0x06
#define CTBCS_P1_INTERFACE7		0x07
#define CTBCS_P1_INTERFACE8		0x08
#define CTBCS_P1_INTERFACE9		0x09
#define CTBCS_P1_INTERFACE10		0x0A
#define CTBCS_P1_INTERFACE11		0x0B
#define CTBCS_P1_INTERFACE12		0x0C
#define CTBCS_P1_INTERFACE13		0x0D
#define CTBCS_P1_INTERFACE14		0x0E
#define CTBCS_P1_DISPLAY		0x40
#define CTBCS_P1_KEYPAD			0x50
#define CTBCS_P1_PRINTER		0x60 /* New CT-BCS 1.0 */
#define CTBCS_P1_FINGERPRINT		0x70 /* New CT-BCS 1.0 */
#define CTBCS_P1_VOICEPRINT		0x71 /* New CT-BCS 1.0 */
#define CTBCS_P1_DSV			0x72 /* "Dynamic Signature Verification" New CT-BCS 1.0 */
#define CTBCS_P1_FACE_RECOGNITION	0x73 /* New CT-BCS 1.0 */
#define CTBCS_P1_IRISSCAN		0x74 /* New CT-BCS 1.0 */
/* Other biometric units may use values up to 0x7F */

/*
 * P2 parameter for Reset CT: data to be returned
 */
#define CTBCS_P2_RESET_NO_RESP		0x00	/* Return no data */
#define CTBCS_P2_RESET_GET_ATR		0x01	/* Return complete ATR */
#define CTBCS_P2_RESET_GET_HIST		0x02	/* Return historical bytes */

/*
 * P2 parameter for Request ICC: data to be returned 
 */
#define CTBCS_P2_REQUEST_NO_RESP	0x00	/* Return no data */
#define CTBCS_P2_REQUEST_GET_ATR	0x01	/* Return complete ATR */
#define CTBCS_P2_REQUEST_GET_HIST	0x02	/* Return historical bytes */

/*
 * P2 parameter for Get status: TAG of data object to return
 */
#define CTBCS_P2_STATUS_MANUFACTURER	0x46	/* Return manufacturer DO */
#define CTBCS_P2_STATUS_ICC		0x80	/* Return ICC DO */
#define CTBCS_P2_STATUS_TFU		0x81	/* Return Functional Units, new in Version 1.0 */

/*
 * P2 parameter for Input
 */
#define CTBCS_P2_INPUT_ECHO		0x01	/* Echo input on display */
#define CTBCS_P2_INPUT_ASTERISKS	0x02	/* Echo input as asterisks */

/*
 * Tags for paramaters to input, output et al.
 */
#define CTBCS_TAG_PROMPT		0x50
#define CTBCS_TAG_VERIFY_CMD		0x52
#define CTBCS_TAG_TIMEOUT		0x80

/*
 * PIN command control flags
 */
#define CTBCS_PIN_CONTROL_LEN_SHIFT	4
#define CTBCS_PIN_CONTROL_LEN_MASK	0x0F
#define CTBCS_PIN_CONTROL_ENCODE_ASCII	0x01

/*
 * General return codes
 */
#define CTBCS_SW1_OK			0x90	/* Command successful */
#define CTBCS_SW2_OK			0x00
#define CTBCS_SW1_WRONG_LENGTH		0x67	/* Wrong length */
#define CTBCS_SW2_WRONG_LENGTH		0x00
#define CTBCS_SW1_COMMAND_NOT_ALLOWED	0x69	/* Command not allowed */
#define CTBCS_SW2_COMMAND_NOT_ALLOWED	0x00
#define CTBCS_SW1_WRONG_PARAM		0x6A	/* Wrong parameters P1, P2 */
#define CTBCS_SW2_WRONG_PARAM		0x00
#define CTBCS_SW1_WRONG_INS		0x6D	/* Wrong Instruction */
#define CTBCS_SW2_WRONG_INS		0x00
#define CTBCS_SW1_WRONG_CLA		0x6E	/* Class not supported */
#define CTBCS_SW2_WRONG_CLA		0x00
#define CTBCS_SW1_ICC_ERROR		0x6F	/* ICC removed, defective or */
#define CTBCS_SW2_ICC_ERROR		0x00	/* no longer reacts */

/*
 * Return codes for Reset CT 
 */
#define CTBCS_SW1_RESET_CT_OK		0x90	/* Reset CT successful */
#define CTBCS_SW2_RESET_CT_OK		0x00
#define CTBCS_SW1_RESET_SYNC_OK		0x90	/* Synchoronous ICC, */
#define CTBCS_SW2_RESET_SYNC_OK		0x00	/* reset successful */
#define CTBCS_SW1_RESET_ASYNC_OK	0x90	/* Asynchoronous ICC, */
#define CTBCS_SW2_RESET_ASYNC_OK	0x01	/* reset successful */
#define CTBCS_SW1_RESET_ERROR		0x64	/* Reset not successful */
#define CTBCS_SW2_RESET_ERROR		0x00

/*
 * Return codes for Request ICC
 */
#define CTBCS_SW1_REQUEST_SYNC_OK 	0x90	/* Synchoronous ICC, */
#define CTBCS_SW2_REQUEST_SYNC_OK 	0x00	/* reset successful */
#define CTBCS_SW1_REQUEST_ASYNC_OK 	0x90	/* Asynchoronous ICC, */
#define CTBCS_SW2_REQUEST_ASYNC_OK 	0x01	/* reset successful */
#define CTBCS_SW1_REQUEST_NO_CARD	0x62	/* No card present */
#define CTBCS_SW2_REQUEST_NO_CARD	0x00
#define CTBCS_SW1_REQUEST_CARD_PRESENT 	0x62	/* Card already present */
#define CTBCS_SW2_REQUEST_CARD_PRESENT 	0x01
#define CTBCS_SW1_REQUEST_ERROR		0x64	/* Reset not successful */
#define CTBCS_SW2_REQUEST_ERROR		0x00
#define CTBCS_SW1_REQUEST_TIMER_ERROR	0x69	/* Timer not supported */
#define CTBCS_SW2_REQUEST_TIMER_ERROR	0x00

/*
 * Return codes for Eject ICC
 */
#define CTBCS_SW1_EJECT_OK		0x90	/* Command succesful, */
#define CTBCS_SW2_EJECT_OK		0x00
#define CTBCS_SW1_EJECT_REMOVED		0x90	/* Command succesful, */
#define CTBCS_SW2_EJECT_REMOVED		0x01	/* Card removed */
#define CTBCS_SW1_EJECT_NOT_REMOVED	0x62	/* Card not removed */
#define CTBCS_SW2_EJECT_NOT_REMOVED	0x00

/*
 * Data returned on Get Status command
 */
#define CTBCS_DATA_STATUS_NOCARD	0x00	/* No card present */
#define CTBCS_DATA_STATUS_CARD		0x01	/* Card present */
#define CTBCS_DATA_STATUS_CARD_CONNECT	0x05	/* Card present */

/*
 * Functions for building CTBCS commands
 */
int ctbcs_pin_cmd(struct sc_reader *, struct sc_pin_cmd_data *);

#endif /* _CTBCS_ */
