/*
 * Common functions and constants for Polish eID cards.
 *
 * Copyright (C) 2025 Piotr Wegrzyn <piotro@piotro.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "libopensc/opensc.h"
#include "libopensc/pace.h"

int edo_unlock(sc_card_t *card);
int edo_logout(sc_card_t *card);
int edo_card_reader_lock_obtained(sc_card_t *card, int was_reset);
