/*
 * cardmod-mingw-compat.h: Compat defines to make minidriver with cardmod.h
 *			   buildable under mingw
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

#define __deref
#define __deref_opt_inout_bcount_part_opt(x,y)
#define __deref_opt_out_bcount(x)
#define __deref_out_bcount(x)
#define __deref_out_bcount_opt(x)
#define __in
#define __in_bcount_opt(x)
#define __in_opt
#define __inout
#define __inout_bcount_opt(x)
#define __out
#define __out_bcount_part_opt(x,y)
#define __out_bcount_part_opt(x,y)
#define __out_opt
#define __struct_bcount(x)
#define __success(x)
#define _Printf_format_string_

#ifndef NTE_BUFFER_TOO_SMALL
#define NTE_BUFFER_TOO_SMALL _HRESULT_TYPEDEF_(0x80090028)
#endif
