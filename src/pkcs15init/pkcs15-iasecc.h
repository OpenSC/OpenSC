/*
 * pkcs15-iasecc.h Support for IAS/ECC smart cards
 *
 * Copyright (C) 2021  Vincent JARDIN <vjardin/AT\free.fr>
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

#ifndef pkcs15_iasecc_h
#define pkcs15_iasecc_h

extern int iasecc_pkcs15_encode_supported_algos(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *object);
#endif /* #ifndef pkcs15_iasecc_h*/
