/*
 * opensc-setup-custom-action.c: OpenSC setup custom action
 *
 * Copyright (C) 2015 vincent.letoux@mysmartlogon.com
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

/*
 * This module requires the WIX SDK to build.
 */

#include "config.h"
#ifdef ENABLE_MINIDRIVER

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

// WiX Header Files:
#include <wcautil.h>

// first version - do nothing - see if it can compile

// DllMain - Initialize and cleanup WiX custom action utils.
BOOL APIENTRY DllMain(
	__in HINSTANCE hInst,
	__in ULONG ulReason,
	__in LPVOID
	)
{
	switch(ulReason)
	{
	case DLL_PROCESS_ATTACH:
		WcaGlobalInitialize(hInst);
		break;

	case DLL_PROCESS_DETACH:
		WcaGlobalFinalize();
		break;
	}

	return TRUE;
}

#endif