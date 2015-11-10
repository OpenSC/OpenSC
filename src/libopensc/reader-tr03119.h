/*
 * reader-tr03119.h: interface related to escape commands with pseudo APDUs
 *
 * Copyright (C) 2013-2015  Frank Morgner
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

#ifndef _READER_TR03119_H
#define _READER_TR03119_H

#include "libopensc/opensc.h"
#include "libopensc/pace.h"

#ifdef __cplusplus
extern "C" {
#endif

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

