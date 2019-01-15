/*
 * simpletlv.h: Simple TLV header file
 *
 * Copyright (C) 2016  Red Hat, Inc.
 *
 * Authors: Robert Relyea <rrelyea@redhat.com>
 *          Jakub Jelen <jjelen@redhat.com>
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

#ifndef _OPENSC_SIMPLETLV_H
#define _OPENSC_SIMPLETLV_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"

/*
 * Create a tag/length file in Simple TLV based on the  val_len  content length
 * @param  tag       Tag to store into the TL file
 * @param  datalen   Data length to store into the TL file
 * @param  out       TL byte array to write into
 * @param  outlen    The length of the output array
 * @param  ptr       The end of the TL record written
 * @return           SC_SUCCESS for correct input
 */
int sc_simpletlv_put_tag(u8 tag, size_t datalen, u8 *out, size_t outlen, u8 **ptr);

/* get the Simple TLV tag and length.
 * @param  buf       Pointer to the TL file
 * @param  buflen    The length of TL file
 * @param  tag_out   The tag from the TL file
 * @param  taglen    The length of the V record
 * @return           SC_SUCCESS on valid input
 */
int sc_simpletlv_read_tag(const u8 **buf, size_t buflen, u8 *tag_out, size_t *taglen);

#endif
