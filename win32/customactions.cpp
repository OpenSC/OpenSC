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
#include <tchar.h>
#include <strsafe.h>

#include <msiquery.h>

// WiX Header Files:
#include <wcautil.h>

#define X86onX64_SC_DATABASE TEXT("SOFTWARE\\Wow6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards")
#define SC_DATABASE TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards")
#define BASE_CSP TEXT("OpenSC CSP")
#define BASE_KSP TEXT("Microsoft Smart Card Key Storage Provider")

typedef struct _MD_REGISTRATION
{
	TCHAR szName[256];
	BYTE pbAtr[256];
	DWORD dwAtrSize;
	BYTE pbAtrMask[256];
} MD_REGISTRATION, *PMD_REGISTRATION;

/* note: we could have added the minidriver registration data directly in OpenSC.wxs but coding it allows for more checks.
For example, do not uninstall the minidriver for a card if a middleware is already installed */

MD_REGISTRATION minidriver_registration[] = {
	/* from minidriver-feitian.reg */
	{TEXT("ePass2003"),                       {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0x00,0x66,0x46,0x53,0x05,0x01,0x00,0x11,0x71,0xdf,0x00,0x00,0x03,0x6a,0x82,0xf8},
                                          23, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}},
	{TEXT("FTCOS/PK-01C"),                    {0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0x00,0x65,0x46,0x53,0x05,0x00,0x06,0x71,0xdf,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                                          23, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00}},
	/* from minidriver-sc-hsm.reg */
	{TEXT("SmartCard-HSM"),                   {0x3b,0xfe,0x18,0x00,0x00,0x81,0x31,0xfe,0x45,0x80,0x31,0x81,0x54,0x48,0x53,0x4d,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0xfa},
                                          24, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}},
	{TEXT("SmartCard-HSM-CL"),                {0x3B,0x8E,0x80,0x01,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x18},
                                          19, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}},
	/* from minidriver-westcos.reg */
	{TEXT("CEV WESTCOS"),                     {0x3f,0x69,0x00,0x00,0x00,0x64,0x01,0x00,0x00,0x00,0x80,0x90,0x00},
                                          13, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0xf0,0xff,0xff}},
	/* from card-openpgp.c */
	{TEXT("OpenPGP card v1.0/1.1"),           {0x3b,0xfa,0x13,0x00,0xff,0x81,0x31,0x80,0x45,0x00,0x31,0xc1,0x73,0xc0,0x01,0x00,0x00,0x90,0x00,0xb1},
                                          20, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}},
	{TEXT("CryptoStick v1.2 (OpenPGP v2.0)"), {0x3b,0xda,0x18,0xff,0x81,0xb1,0xfe,0x75,0x1f,0x03,0x00,0x31,0xc5,0x73,0xc0,0x01,0x40,0x00,0x90,0x00,0x0c},
                                          21, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}},
	/* from card-masktech.c */
	/* note: the card name MUST be unique */
	{TEXT("MaskTech smart card (a)"),         {0x3b,0x89,0x80,0x01,0x4d,0x54,0x43,0x4f,0x53,0x70,0x02,0x00,0x04,0x31},
                                          14, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0xff,0xfc,0xf4,0xf5}},
	{TEXT("MaskTech smart card (b)"),         {0x3B,0x9D,0x13,0x81,0x31,0x60,0x35,0x80,0x31,0xC0,0x69,0x4D,0x54,0x43,0x4F,0x53,0x73,0x02,0x00,0x00,0x40},
                                          21, {0xff,0xff,0xff,0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfc,0xf0,0xf0}},
	{TEXT("MaskTech smart card (c)"),         {0x3B,0x88,0x80,0x01,0x00,0x00,0x00,0x00,0x77,0x81,0x80,0x00,0x6E},
                                          13, {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xee,0xff,0xee}},
};


/* remove a card in the database if and only if the CSP match the OpenSC CSP
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
				TCHAR szCSP[MAX_PATH] = {0};
				dwSize = MAX_PATH;
				lResult = RegQueryValueEx(hTempKey, TEXT("Crypto Provider"), NULL, NULL, (PBYTE) szCSP, &dwSize);
				RegCloseKey(hTempKey);
				if (lResult == ERROR_SUCCESS)
				{
					if ( _tcsstr(szCSP, TEXT("OpenSC CSP")) != 0)
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
	RegisterCardWithKey(SC_DATABASE, registration->szName, TEXT("opensc-minidriver.dll"),registration->pbAtr, registration->dwAtrSize, registration->pbAtrMask );

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
