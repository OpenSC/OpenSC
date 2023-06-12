/*
 * compat_overflow.c: Reimplementation of GCC/Clang's built-in
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_BUILTIN_OVERFLOW
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#define ADD_OVERFLOW(func, type, max) \
    bool func  (type x, type y, type *sum) \
    { \
        if (NULL == sum || max - x < y) \
            return true; \
        *sum = x + y; \
        return false; \
    }

ADD_OVERFLOW(__builtin_uadd_overflow,   unsigned,           UINT_MAX)
ADD_OVERFLOW(__builtin_uaddl_overflow,  unsigned long,      ULONG_MAX)
ADD_OVERFLOW(__builtin_uaddll_overflow, unsigned long long, ULLONG_MAX)
ADD_OVERFLOW(__builtin_zuadd_overflow,  size_t,             SIZE_MAX)
#endif
