/*
 * Copyright (C) 2015 Vincent Le Toux <vincent.letoux@gmail.com>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_RANGECHECKFAILURE	/* empty file if __report_rangecheckfailure is available */

// do not fail when linked with /GS dll and when /GS is not available
#ifdef _WIN32
#if defined(_MSC_VER) && (_MSC_VER < 1700)
// only for vs 2012 or later

#include <Windows.h>

__declspec(noreturn) void __cdecl __report_rangecheckfailure()
{
	ExitProcess(1);
}

#endif
#endif
#endif
