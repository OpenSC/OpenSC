/*
 * reader-tr03119.h: interface related to escape commands with pseudo APDUs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _READER_TR03119_H
#define _READER_TR03119_H

#include "libopensc/opensc.h"
#include "libopensc/pace.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief NPA capabilities (TR-03119): PACE */
#define EAC_BITMAP_PACE  0x40
/** @brief NPA capabilities (TR-03119): EPA: eID */
#define EAC_BITMAP_EID   0x20
/** @brief NPA capabilities (TR-03119): EPA: eSign */
#define EAC_BITMAP_ESIGN 0x10

/** 
 * @brief Get the PACE capabilities
 * 
 * @param[in,out] bitmap where to store capabilities bitmap
 * @note Since this code offers no support for terminal certificate, the bitmap is always \c PACE_BITMAP_PACE|PACE_BITMAP_EID
 * 
 * @return \c SC_SUCCESS or error code if an error occurred
 */
int get_pace_capabilities(u8 *bitmap);

/** @brief NPA result (TR-03119): Kein Fehler */
#define EAC_SUCCESS                            0x00000000
/** @brief NPA result (TR-03119): Längen im Input sind inkonsistent */
#define EAC_ERROR_LENGTH_INCONSISTENT          0xD0000001
/** @brief NPA result (TR-03119): Unerwartete Daten im Input */
#define EAC_ERROR_UNEXPECTED_DATA              0xD0000002
/** @brief NPA result (TR-03119): Unerwartete Kombination von Daten im Input */
#define EAC_ERROR_UNEXPECTED_DATA_COMBINATION  0xD0000003
/** @brief NPA result (TR-03119): Die Karte unterstützt das PACE – Verfahren nicht.  (Unerwartete Struktur in Antwortdaten der Karte) */
#define EAC_ERROR_CARD_NOT_SUPPORTED           0xE0000001
/** @brief NPA result (TR-03119): Der Kartenleser unterstützt den angeforderten bzw. den ermittelten Algorithmus nicht.  */
#define EAC_ERROR_ALGORITH_NOT_SUPPORTED       0xE0000002
/** @brief NPA result (TR-03119): Der Kartenleser kennt die PIN – ID nicht. */
#define EAC_ERROR_PINID_NOT_SUPPORTED          0xE0000003
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf Select EF_CardAccess (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_SELECT_EF_CARDACCESS         0xF0000000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf Read Binary (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_READ_BINARY                  0xF0010000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf MSE: Set AT (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_MSE_SET_AT                   0xF0020000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf General Authenticate Step 1 (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_GENERAL_AUTHENTICATE_1       0xF0030000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf General Authenticate Step 2 (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_GENERAL_AUTHENTICATE_2       0xF0040000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf General Authenticate Step 3 (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_GENERAL_AUTHENTICATE_3       0xF0050000
/** @brief NPA result (TR-03119): Negative Antwort der Karte auf General Authenticate Step 4 (needs to be OR-ed with SW1|SW2) */
#define EAC_ERROR_GENERAL_AUTHENTICATE_4       0xF0060000
/** @brief NPA result (TR-03119): Kommunikationsabbruch mit Karte. */
#define EAC_ERROR_COMMUNICATION                0xF0100001
/** @brief NPA result (TR-03119): Keine Karte im Feld. */
#define EAC_ERROR_NO_CARD                      0xF0100002
/** @brief NPA result (TR-03119): Benutzerabbruch. */
#define EAC_ERROR_ABORTED                      0xF0200001
/** @brief NPA result (TR-03119): Benutzer – Timeout */
#define EAC_ERROR_TIMEOUT                      0xF0200002

void sc_detect_escape_cmds(sc_reader_t *reader);

int escape_pace_input_to_buf(sc_context_t *ctx,
		const struct establish_pace_channel_input *input,
		unsigned char **asn1, size_t *asn1_len);
int escape_buf_to_pace_input(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		struct establish_pace_channel_input *input);
int escape_pace_output_to_buf(sc_context_t *ctx,
		const struct establish_pace_channel_output *output,
		unsigned char **asn1, size_t *asn1_len);
int escape_buf_to_pace_output(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		struct establish_pace_channel_output *output);
int escape_pace_capabilities_to_buf(sc_context_t *ctx,
		const unsigned long sc_reader_t_capabilities,
		unsigned char **asn1, size_t *asn1_len);
int escape_buf_to_pace_capabilities(sc_context_t *ctx,
		const unsigned char *asn1, size_t asn1_len,
		unsigned long *sc_reader_t_capabilities);

#ifdef __cplusplus
}
#endif

#endif

