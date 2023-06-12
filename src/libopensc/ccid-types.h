/*
 * Copyright (C) 2009-2015 Frank Morgner
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
/**
 * @file
 */
#ifndef _CCID_TYPES_H
#define _CCID_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#define PACKED
#pragma pack(push,1)
#elif defined(__GNUC__)
#define PACKED __attribute__ ((__packed__))
#endif

#define USB_REQ_CCID        0xA1

#define CCID_CONTROL_ABORT                  0x01
#define CCID_CONTROL_GET_CLOCK_FREQUENCIES  0x02
#define CCID_CONTROL_GET_DATA_RATES 0x03

#define CCID_OPERATION_VERIFY   0x00;
#define CCID_OPERATION_MODIFY   0x01;
#define CCID_ENTRY_VALIDATE     0x02

#define CCID_BERROR_CMD_ABORTED 0xff /** Host aborted the current activity */
#define CCID_BERROR_ICC_MUTE 0xfe /** CCID timed out while talking to the ICC */
#define CCID_BERROR_XFR_PARITY_ERROR 0xfd /** Parity error while talking to the ICC */
#define CCID_BERROR_XFR_OVERRUN 0xfc /** Overrun error while talking to the ICC */
#define CCID_BERROR_HW_ERROR 0xfb /** An all inclusive hardware error occurred */
#define CCID_BERROR_BAD_ATR_TS 0xf
#define CCID_BERROR_BAD_ATR_TCK 0xf
#define CCID_BERROR_ICC_PROTOCOL_NOT_SUPPORTED 0xf6
#define CCID_BERROR_ICC_CLASS_NOT_SUPPORTED 0xf5
#define CCID_BERROR_PROCEDURE_BYTE_CONFLICT 0xf4
#define CCID_BERROR_DEACTIVATED_PROTOCOL 0xf3
#define CCID_BERROR_BUSY_WITH_AUTO_SEQUENCE 0xf2 /** Automatic Sequence Ongoing */
#define CCID_BERROR_PIN_TIMEOUT 0xf0
#define CCID_BERROR_PIN_CANCELLED 0xef
#define CCID_BERROR_CMD_SLOT_BUSY 0xe0 /** A second command was sent to a slot which was already processing a command. */
#define CCID_BERROR_CMD_NOT_SUPPORTED 0x00
#define CCID_BERROR_OK 0x00

#define CCID_BSTATUS_OK_ACTIVE 0x00 /** No error. An ICC is present and active */
#define CCID_BSTATUS_OK_INACTIVE 0x01 /** No error. ICC is present and inactive */
#define CCID_BSTATUS_OK_NOICC 0x02 /** No error. No ICC is present */
#define CCID_BSTATUS_ERROR_ACTIVE 0x40 /** Failed. An ICC is present and active */
#define CCID_BSTATUS_ERROR_INACTIVE 0x41 /** Failed. ICC is present and inactive */
#define CCID_BSTATUS_ERROR_NOICC 0x42 /** Failed. No ICC is present */

#define CCID_WLEVEL_DIRECT __constant_cpu_to_le16(0) /** APDU begins and ends with this command */
#define CCID_WLEVEL_CHAIN_NEXT_XFRBLOCK __constant_cpu_to_le16(1) /** APDU begins with this command, and continue in the next PC_to_RDR_XfrBlock */
#define CCID_WLEVEL_CHAIN_END __constant_cpu_to_le16(2) /** abData field continues a command APDU and ends the APDU command */
#define CCID_WLEVEL_CHAIN_CONTINUE __constant_cpu_to_le16(3) /** abData field continues a command APDU and another block is to follow */
#define CCID_WLEVEL_RESPONSE_IN_DATABLOCK __constant_cpu_to_le16(0x10) /** empty abData field, continuation of response APDU is expected in the next RDR_to_PC_DataBlock */

#define CCID_PIN_ENCODING_BIN   0x00
#define CCID_PIN_ENCODING_BCD   0x01
#define CCID_PIN_ENCODING_ASCII 0x02
#define CCID_PIN_UNITS_BYTES    0x80
#define CCID_PIN_JUSTIFY_RIGHT  0x04
#define CCID_PIN_CONFIRM_NEW    0x01
#define CCID_PIN_INSERT_OLD     0x02
#define CCID_PIN_NO_MSG         0x00
#define CCID_PIN_MSG1           0x01
#define CCID_PIN_MSG2           0x02
#define CCID_PIN_MSG_REF        0x03
#define CCID_PIN_MSG_DEFAULT    0xff

#define CCID_SLOTS_UNCHANGED    0x00
#define CCID_SLOT1_CARD_PRESENT 0x01
#define CCID_SLOT1_CHANGED      0x02
#define CCID_SLOT2_CARD_PRESENT 0x04
#define CCID_SLOT2_CHANGED      0x08
#define CCID_SLOT3_CARD_PRESENT 0x10
#define CCID_SLOT3_CHANGED      0x20
#define CCID_SLOT4_CARD_PRESENT 0x40
#define CCID_SLOT4_CHANGED      0x80

#define CCID_EXT_APDU_MAX       (4 + 3 + 0xffff + 3)
#define CCID_SHORT_APDU_MAX     (4 + 1 + 0xff + 1)

struct ccid_class_descriptor {
	uint8_t  bLength;
	uint8_t  bDescriptorType;
	uint16_t bcdCCID;
	uint8_t  bMaxSlotIndex;
	uint8_t  bVoltageSupport;
	uint32_t dwProtocols;
	uint32_t dwDefaultClock;
	uint32_t dwMaximumClock;
	uint8_t  bNumClockSupport;
	uint32_t dwDataRate;
	uint32_t dwMaxDataRate;
	uint8_t  bNumDataRatesSupported;
	uint32_t dwMaxIFSD;
	uint32_t dwSynchProtocols;
	uint32_t dwMechanical;
	uint32_t dwFeatures;
	uint32_t dwMaxCCIDMessageLength;
	uint8_t  bClassGetResponse;
	uint8_t  bclassEnvelope;
	uint16_t wLcdLayout;
	uint8_t  bPINSupport;
	uint8_t  bMaxCCIDBusySlots;
} PACKED;

typedef struct {
	uint8_t  bmFindexDindex;
	uint8_t  bmTCCKST0;
	uint8_t  bGuardTimeT0;
	uint8_t  bWaitingIntegerT0;
	uint8_t  bClockStop;
} PACKED abProtocolDataStructure_T0_t;
typedef struct {
	uint8_t  bmFindexDindex;
	uint8_t  bmTCCKST1;
	uint8_t  bGuardTimeT1;
	uint8_t  bWaitingIntegersT1;
	uint8_t  bClockStop;
	uint8_t  bIFSC;
	uint8_t  bNadValue;
} PACKED abProtocolDataStructure_T1_t;

typedef struct {
	uint8_t  bTimeOut;
	uint8_t  bmFormatString;
	uint8_t  bmPINBlockString;
	uint8_t  bmPINLengthFormat;
	uint16_t wPINMaxExtraDigit;
	uint8_t  bEntryValidationCondition;
	uint8_t  bNumberMessage;
	uint16_t wLangId;
	uint8_t  bMsgIndex;
	uint8_t  bTeoPrologue1;
	uint16_t bTeoPrologue2;
} PACKED abPINDataStucture_Verification_t;
typedef struct {
	uint8_t  bTimeOut;
	uint8_t  bmFormatString;
	uint8_t  bmPINBlockString;
	uint8_t  bmPINLengthFormat;
	uint8_t  bInsertionOffsetOld;
	uint8_t  bInsertionOffsetNew;
	uint16_t wPINMaxExtraDigit;
	uint8_t  bConfirmPIN;
	uint8_t  bEntryValidationCondition;
	uint8_t  bNumberMessage;
	uint16_t wLangId;
	uint8_t  bMsgIndex1;
} PACKED abPINDataStucture_Modification_t;

typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bBWI;
	uint16_t wLevelParameter;
} PACKED PC_to_RDR_XfrBlock_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU1;
	uint16_t abRFU2;
} PACKED PC_to_RDR_IccPowerOff_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU1;
	uint16_t abRFU2;
} PACKED PC_to_RDR_GetSlotStatus_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU1;
	uint16_t abRFU2;
} PACKED PC_to_RDR_GetParameters_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  abRFU1;
	uint16_t abRFU2;
} PACKED PC_to_RDR_ResetParameters_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bProtocolNum;
	uint16_t abRFU;
} PACKED PC_to_RDR_SetParameters_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bBWI;
	uint16_t wLevelParameter;
} PACKED PC_to_RDR_Secure_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bPowerSelect;
	uint16_t abRFU;
} PACKED PC_to_RDR_IccPowerOn_t;

typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bStatus;
	uint8_t  bError;
	uint8_t  bClockStatus;
} PACKED RDR_to_PC_SlotStatus_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bStatus;
	uint8_t  bError;
	uint8_t  bChainParameter;
} PACKED RDR_to_PC_DataBlock_t;
typedef struct {
	uint8_t  bMessageType;
	uint32_t dwLength;
	uint8_t  bSlot;
	uint8_t  bSeq;
	uint8_t  bStatus;
	uint8_t  bError;
	uint8_t  bProtocolNum;
} PACKED RDR_to_PC_Parameters_t;
typedef struct {
	uint8_t  bMessageType;
	uint8_t  bmSlotICCState; /* we support 1 slots, so we need 2*1 bits = 1 byte */
} PACKED RDR_to_PC_NotifySlotChange_t;

#ifdef _MSC_VER
#undef PACKED
#pragma pack(pop)
#elif defined(__GNUC__)
#undef PACKED
#endif

#ifdef  __cplusplus
}
#endif
#endif
