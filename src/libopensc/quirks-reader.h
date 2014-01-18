/*
 * quirks-reader.h: Reader quirks header file
 *
 * Copyright (C) 2014  Javier Serrano Polo <javier@jasp.net>
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

#ifndef _OPENSC_QUIRKS_READER_H
#define _OPENSC_QUIRKS_READER_H

#ifdef __cplusplus
extern "C" {
#endif

struct sc_pkcs15_auth_info;
struct sc_reader;

int sc_reader_can_handle_pin(struct sc_reader *reader,
                             struct sc_pkcs15_auth_info *pkcs15_pin_info);

#ifdef __cplusplus
}
#endif

#endif
