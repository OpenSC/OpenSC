/*
 * boxing.c: interface related to boxing commands with pseudo APDUs
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

#ifndef _BOXING_CMDS_H
#define _BOXING_CMDS_H

#include "libopensc/opensc.h"
#include "libopensc/pace.h"

#ifdef __cplusplus
extern "C" {
#endif

void sc_detect_boxing_cmds(sc_reader_t *reader);

int boxing_pace_input_to_buf(sc_context_t *ctx,
        const struct establish_pace_channel_input *input,
        unsigned char **asn1, size_t *asn1_len);
int boxing_buf_to_pace_input(sc_context_t *ctx,
        const unsigned char *asn1, size_t asn1_len,
        struct establish_pace_channel_input *input);
int boxing_pace_output_to_buf(sc_context_t *ctx,
        const struct establish_pace_channel_output *output,
        unsigned char **asn1, size_t *asn1_len);
int boxing_buf_to_pace_output(sc_context_t *ctx,
        const unsigned char *asn1, size_t asn1_len,
        struct establish_pace_channel_output *output);
int boxing_pace_capabilities_to_buf(sc_context_t *ctx,
        const unsigned long sc_reader_t_capabilities,
        unsigned char **asn1, size_t *asn1_len);
int boxing_buf_to_pace_capabilities(sc_context_t *ctx,
        const unsigned char *asn1, size_t asn1_len,
        unsigned long *sc_reader_t_capabilities);

#ifdef __cplusplus
}
#endif

#endif

