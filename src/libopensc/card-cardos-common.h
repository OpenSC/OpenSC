/*
 * card-cardos-common.c: Common code for CardOS based cards
 *
 * Copyright (C) 2024 Mario Haustein <mario.haustein@hrz.tu-chemnitz.de>
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

#ifndef HAVE_CARD_CARDOS_COMMON_H
#define HAVE_CARD_CARDOS_COMMON_H

#include "libopensc/opensc.h"

/**
 * @brief compute a shared value from the peers public ECC key
 *
 * Key agreement on ECC keys requires a CardOS-specific command.
 *
 * @param  card[in]       struct sc_card object on which to issue the command
 * @param  crgram[in]     public key point coordinates of the peer party in uncompressed format
 * @param  crgram_len[in] size of the public key point
 * @param  out[out]       output buffer for the shared value
 * @param  outlen[in]     size of the output buffer
 * @return number of bytes of the shared value or an error code
 */
int
cardos_ec_compute_shared_value(struct sc_card *card,
		const u8 *crgram, size_t crgram_len,
		u8 *out, size_t outlen);

#endif /* HAVE_CARD_CARDOS_COMMON_H */
