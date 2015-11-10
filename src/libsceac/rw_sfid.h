/*
 * Copyright (C) 2010-2015 Frank Morgner
 *
 * This file is part of OpenSC.
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
/**
 * @file
 * @addtogroup scutil Wrappers around OpenSC
 * @{
 */
#ifndef _SC_SCUTIL_H
#define _SC_SCUTIL_H

#include "libopensc/opensc.h"

/** 
 * @brief Read a complete EF by short file identifier.
 *
 * @param[in]     card
 * @param[in]     sfid   Short file identifier
 * @param[in,out] ef     Where to safe the file. the buffer will be allocated
 *                       using \c realloc() and should be set to NULL, if
 *                       empty.
 * @param[in,out] ef_len Length of \a *ef
 *
 * @note The appropriate directory must be selected before calling this function.
 * */
int read_binary_sfid(sc_card_t *card, unsigned char sfid,
        u8 **ef, size_t *ef_len);

/**
 * @brief Write a complete EF by short file identifier.
 *
 * @param[in] card
 * @param[in] sfid   Short file identifier
 * @param[in] ef     Date to write
 * @param[in] ef_len Length of \a ef
 *
 * @note The appropriate directory must be selected before calling this function.
 * */
int write_binary_sfid(sc_card_t *card, unsigned char sfid,
        u8 *ef, size_t ef_len);

#endif
/* @} */
