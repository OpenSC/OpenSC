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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
#include <tchar.h>
#include <strsafe.h>

#include <msiquery.h>

// WiX Header Files:
#include <wcautil.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
// only for VS 2015 or later
// WiX 3.10 was built for older versions of VS and needs this for compatibility
#pragma comment(lib, "legacy_stdio_definitions.lib")
#endif

#define X86onX64_SC_DATABASE TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards")
#define SC_DATABASE TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards")
#define BASE_CSP TEXT("Microsoft Base Smart Card Crypto Provider")
#define BASE_KSP TEXT("Microsoft Smart Card Key Storage Provider")
#define BASE_INSTALLED_BY_KEY TEXT("InstalledBy")
#define BASE_INSTALLED_BY_VALUE TEXT("OpenSC")

typedef struct _MD_REGISTRATION
{
	TCHAR szName[256];
	BYTE pbAtr[256];
	DWORD dwAtrSize;
	BYTE pbAtrMask[256];
} MD_REGISTRATION, *PMD_REGISTRATION;

/* note: we could have added the minidriver registration data directly in OpenSC.wxs but coding it allows for more checks.
For example, do not uninstall the minidriver for a card if a middleware is already installed */

/*
 * In order to compute the proper ATRMask, see:
 *   https://github.com/OpenSC/OpenSC/wiki/Adding-a-new-card-driver#windows-minidriver-support
 */

// clang-format off
MD_REGISTRATION minidriver_registration[] = {
    {TEXT("Swissbit iShield Key Pro"),        {0x3b,0x97,0x11,0x81,0x21,0x75,0x69,0x53,0x68,0x69,0x65,0x6c,0x64,0x05},
                                          14, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
    {TEXT("Swissbit iShield Key Pro CL"),     {0x3b,0x87,0x80,0x01,0x69,0x53,0x68,0x69,0x65,0x6c,0x64,0x50},
                                          12, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
    {TEXT("Swissbit iShield Key 2"),          {0x3b,0xd5,0x18,0xff,0x81,0xb1,0xfe,0x45,0x1f,0xc3,0x80,0x73,0xc8,0x21,0x10,0x6f},
	                                      16, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
    {TEXT("Swissbit iShield Key 2 CL"),       {0x3b,0x85,0x80,0x01,0x80,0x73,0xc8,0x21,0x10,0x0e},
	                                      10, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}},
};
// clang-format on

/* remove a card in the database if and only if the BASE_INSTALLED_BY_KEY is present and has value of BASE INSTALLED_BY_VALUE
It also will not install drivers installed by other or modified by a user (who should have changed the BASE INSTALLED_BY_VALUE
The program try to avoid any failure to not break the uninstall process */
VOID RemoveKey(PTSTR szSubKey)
{
	HKEY hKey = NULL;
	LONG lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, szSubKey, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS)
	{
		WcaLog(LOGMSG_STANDARD, "RegOpenKeyEx %S 0x%08X", szSubKey, lResult);
		return;
	}
	TCHAR szName[MAX_PATH];
	DWORD dwSize = MAX_PATH;
	FILETIME ftWrite;
	lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
							NULL, NULL, &ftWrite);

	if (lResult == ERROR_SUCCESS)
	{
		DWORD dwIndex = 0;
		do {
			HKEY hTempKey = NULL;
			dwIndex++;
			lResult = RegOpenKeyEx (hKey, szName, 0, KEY_READ, &hTempKey);
			if (lResult == ERROR_SUCCESS)
			{
				TCHAR szIB[MAX_PATH] = {0};
				dwSize = MAX_PATH;
				lResult = RegQueryValueEx(hTempKey, BASE_INSTALLED_BY_KEY, NULL, NULL, (PBYTE) szIB, &dwSize);
				RegCloseKey(hTempKey);
				if (lResult == ERROR_SUCCESS)
				{
					if ( _tcsstr(szIB, BASE_INSTALLED_BY_VALUE) != 0)
					{
						lResult = RegDeleteKey(hKey, szName);
						if (lResult != ERROR_SUCCESS)
						{
							WcaLog(LOGMSG_STANDARD, "RegDeleteKey %S 0x%08X", szName, lResult);
						}
						else
						{
							dwIndex--;
						}
					}
				}
				else
				{
					WcaLog(LOGMSG_STANDARD, "RegQueryValueEx %S 0x%08X", szName, lResult);
				}
			}
			dwSize = MAX_PATH;
			lResult = RegEnumKeyEx(hKey,dwIndex, szName, &dwSize, NULL,
									NULL, NULL, &ftWrite);

		} while (lResult == ERROR_SUCCESS);
	}
	RegCloseKey(hKey);
}

UINT WINAPI RemoveSmartCardConfiguration(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "RemoveSmartCardConfiguration");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	/* clean a smart card database. As today the x64 setup doesn't handle x86 installation on x64 machine */
	RemoveKey(SC_DATABASE);
	/* when this happens, just uncomment the following line:
#ifdef _M_X64
	RemoveKey(X86onX64_SC_DATABASE);
#endif
	*/

	/* never fails or only if the msi uninstall didn't work. If the uninstall custom action trigger a failure, the user is unable to uninstall the software */
LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

/* note: szKey is here in case the card has to be registered in the Calais and WOW3264node\Calais databases */
void RegisterCardWithKey(PTSTR szKey, PTSTR szCard, PTSTR szPath, PBYTE pbATR, DWORD dwATRSize, PBYTE pbAtrMask)
{
	HKEY hKey = NULL;
	HKEY hTempKey = NULL;
	LONG lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE, szKey, 0, KEY_READ, &hKey);

	if (lResult != ERROR_SUCCESS)
	{
		WcaLog(LOGMSG_STANDARD, "unable to open the calais database.");
		return;
	}
	lResult = RegCreateKeyEx(hKey, szCard, 0,NULL,0,KEY_WRITE, NULL,&hTempKey,NULL);
	if(!lResult)
	{
		RegSetValueEx( hTempKey,TEXT("Crypto Provider"),0, REG_SZ, (PBYTE)BASE_CSP,sizeof(BASE_CSP) - sizeof(TCHAR));
		RegSetValueEx( hTempKey,TEXT("Smart Card Key Storage Provider"),0, REG_SZ, (PBYTE)BASE_KSP,sizeof(BASE_KSP) - sizeof(TCHAR));
		RegSetValueEx( hTempKey,TEXT("80000001"),0, REG_SZ, (PBYTE)szPath,(DWORD) (sizeof(TCHAR) * _tcslen(szPath)));
		RegSetValueEx( hTempKey,TEXT("ATR"),0, REG_BINARY, (PBYTE)pbATR, dwATRSize);
		RegSetValueEx( hTempKey,TEXT("ATRMask"),0, REG_BINARY, (PBYTE)pbAtrMask, dwATRSize);
		RegSetValueEx( hTempKey,BASE_INSTALLED_BY_KEY,0, REG_SZ, (PBYTE)BASE_INSTALLED_BY_VALUE,
			sizeof(BASE_INSTALLED_BY_VALUE) - sizeof(TCHAR));
		RegCloseKey(hTempKey);
	}
	else
	{
		WcaLog(LOGMSG_STANDARD, "unable to create the card entry");
	}
	RegCloseKey(hKey);
}

VOID RegisterSmartCard(PMD_REGISTRATION registration)
{
	DWORD expanded_len = PATH_MAX;
	TCHAR expanded_val[PATH_MAX];
	BYTE  pbAtrReduced[256];
	DWORD i;
	PTSTR szPath = TEXT("C:\\Program Files\\Swissbit AG\\OpenSC\\minidriver\\opensc-minidriver.dll");

	/* cope with x86 installation on x64 */
	expanded_len = ExpandEnvironmentStrings(
			TEXT("%ProgramFiles%\\Swissbit AG\\OpenSC\\minidriver\\opensc-minidriver.dll"),
			expanded_val, expanded_len);
	if (0 < expanded_len && expanded_len < sizeof expanded_val)
		szPath = expanded_val;

	/*
	 * OpenSC definitions of ATR have been lax in "sc_atr_table" entries by allowing
	 * 1 bits in the ATR that need to be 0 bits when used with Windows compare
	 * Do the equivalent reduction of the table ATR done in card.c by "tbin[s] = (tbin[s] & mbin[s]);"
	 * before adding to registry.
	 */
	for (i = 0; i < registration->dwAtrSize; i++) {
		pbAtrReduced[i] = (registration->pbAtr[i] & registration->pbAtrMask[i]);
	}

	RegisterCardWithKey(SC_DATABASE, registration->szName, szPath, pbAtrReduced, registration->dwAtrSize, registration->pbAtrMask );
}

UINT WINAPI AddSmartCardConfiguration(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;
	int i ;

	hr = WcaInitialize(hInstall, "AddSmartCardConfiguration");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	for (i = 0; i < sizeof(minidriver_registration) / sizeof(MD_REGISTRATION); i++)
	{
		RegisterSmartCard(minidriver_registration + i);
	}

	/* never fails or only if the msi install functions didn't work. If the install custom action trigger a failure, the user is unable to install the software */
LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

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
#else

UINT WINAPI AddSmartCardConfiguration(unsigned long hInstall)
{
	return 0;
}

UINT WINAPI RemoveSmartCardConfiguration(unsigned long hInstall)
{
	return 0;
}
#endif
