/*
 * compat_overflow.h: Reimplementation of GCC/Clang's built-in
 * functions to perform arithmetic with overflow checking
 *
 * Copyright (C) Frank Morgner <frankmorgner@gmail.com>
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
#ifndef __COMPAT_OVERFLOW_H
#define __COMPAT_OVERFLOW_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_BUILTIN_OVERFLOW
#include <stdbool.h>

bool __builtin_uadd_overflow  (unsigned x, unsigned y, unsigned *sum);
bool __builtin_uaddl_overflow (unsigned long x, unsigned long y, unsigned long *sum);
bool __builtin_uaddll_overflow(unsigned long long x, unsigned long long y, unsigned long long *sum);
#endif
/* TODO
bool __builtin_usub_overflow  (unsigned x, unsigned y, unsigned *diff);
bool __builtin_usubl_overflow (unsigned long x, unsigned long y, unsigned long *diff);
bool __builtin_usubll_overflow(unsigned long long x, unsigned long long y, unsigned long long *diff);
bool __builtin_umul_overflow  (unsigned x, unsigned y, unsigned *prod);
bool __builtin_umull_overflow (unsigned long x, unsigned long y, unsigned long *prod);
bool __builtin_umulll_overflow(unsigned long long x, unsigned long long y, unsigned long long *prod);
bool __builtin_sadd_overflow  (int x, int y, int *sum);
bool __builtin_saddl_overflow (long x, long y, long *sum);
bool __builtin_saddll_overflow(long long x, long long y, long long *sum);
bool __builtin_ssub_overflow  (int x, int y, int *diff);
bool __builtin_ssubl_overflow (long x, long y, long *diff);
bool __builtin_ssubll_overflow(long long x, long long y, long long *diff);
bool __builtin_smul_overflow  (int x, int y, int *prod);
bool __builtin_smull_overflow (long x, long y, long *prod);
bool __builtin_smulll_overflow(long long x, long long y, long long *prod);
*/

#endif
